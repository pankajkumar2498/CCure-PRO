"""
orchestrator/web_orchestrator.py
────────────────────────────────────────────────────────────────────────────
Web Application Scan Orchestrator — manages the DAST pipeline state machine.

Pipeline Phases:
    RECON  → Subdomain enum, WAF detection, tech fingerprinting
    CRAWL  → Playwright spidering, ffuf directory brute, API discovery
    DETECT → Nuclei templates, SQLMap injection, custom checks
    AUDIT  → TLS/SSL audit, compliance mapping, risk scoring

State Machine:
    queued → recon → crawl → detect → audit → complete
                                             ↘ failed (at any phase)

Design Decisions:
  - This orchestrator is SEPARATE from scan_orchestrator.py (network scans).
    Web scans target URLs (not IPs), have different phase lifecycles, and
    run different tools. Combining them would violate single-responsibility.
  - Each phase writes intermediate results to PostgreSQL immediately.
    If a worker crashes, completed phases are preserved.
  - Phase chaining uses Celery task dispatch (same pattern as network pipeline).
  - WAF detection in RECON adjusts rate limits for all subsequent phases.
"""

import logging
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from config import WebScanConfig

log = logging.getLogger("ccure.web.orchestrator")

#: What each external tool is responsible for. Named here so a phase that
#: could not run one can say what was therefore not looked for, rather than
#: leaving the reader to infer it from a gap.
TOOL_PURPOSE = {
    "nuclei": "Template-based vulnerability detection (the primary web check)",
    "sqlmap": "SQL injection testing on parameterised endpoints",
    "xss": "Active cross-site scripting testing (reflected, DOM and stored)",
    "injection": "Active server-side injection testing (command, SSTI, XXE, LDAP, XPath)",
    "access_control": "Authorization testing (IDOR, horizontal/vertical privilege escalation)",
    "http_methods": "HTTP method/verb security testing (TRACE, method-based auth bypass)",
    "js_deps": "Vulnerable JavaScript dependency detection (OSV npm intelligence)",
    "sslyze": "TLS/SSL configuration and certificate audit",
    "ffuf": "Content and directory discovery",
    "subfinder": "Subdomain enumeration",
    "playwright": "Browser-driven crawling of client-rendered pages",
}

#: Tools without which the phase has not meaningfully assessed the target.
#: A scan missing these has produced an empty result, not a clean one — the
#: same distinction the credentialed audit draws about its package inventory.
ESSENTIAL_TOOLS = {"nuclei"}

#: How much of the template corpus a scan runs, and against what.
#:
#: Depth is a policy the operator chooses, not something that emerges from
#: defaults nobody wrote down. Each profile records what it did so a short scan
#: cannot be mistaken for a thorough one that found nothing.
#:
#: "standard" is the default and narrows nothing. "quick" trades coverage for
#: time by selecting templates from the technology fingerprint — offered
#: because a fast pass has real operational value, kept opt-in because a
#: partial or wrong fingerprint turns that trade into false negatives.
SCAN_DEPTHS = {
    "quick": {
        "severity": ["high", "critical"],
        "use_tech_tags": True,
        "label": "Quick — high/critical templates, selected from the detected stack",
        "caveat": (
            "Template selection was narrowed to the technologies fingerprinted "
            "during reconnaissance. A technology the fingerprint missed was not "
            "tested for, and medium-severity checks did not run. Use standard "
            "depth before concluding a target is clean."
        ),
    },
    "standard": {
        "severity": ["medium", "high", "critical"],
        "use_tech_tags": False,
        "label": "Standard — all medium, high and critical templates",
        "caveat": "",
    },
    "deep": {
        "severity": ["info", "low", "medium", "high", "critical"],
        "use_tech_tags": False,
        "label": "Deep — every template, including low and informational",
        "caveat": "",
    },
}
DEFAULT_SCAN_DEPTH = "standard"

#: How many injection candidates one scan will hand to sqlmap. Each target is
#: a multi-minute run, so this bounds the phase; the number not tested is
#: reported rather than dropped.
MAX_SQLMAP_TARGETS = 20


def resolve_scan_depth(options: dict) -> tuple[str, dict]:
    """The depth this scan runs at, falling back to full coverage."""
    requested = str((options or {}).get("scan_depth") or "").strip().lower()
    if requested in SCAN_DEPTHS:
        return requested, SCAN_DEPTHS[requested]
    if requested:
        log.warning(
            "Unknown scan_depth '%s' — using '%s'", requested, DEFAULT_SCAN_DEPTH
        )
    return DEFAULT_SCAN_DEPTH, SCAN_DEPTHS[DEFAULT_SCAN_DEPTH]


def tech_tags(tech_stack: list) -> list[str]:
    """
    Nuclei template tags implied by the detected technology stack.

    Only used by the quick profile. The generic tags are always included so a
    narrowed scan still covers the checks that apply to any web target, rather
    than only those matching a fingerprint that may be wrong.
    """
    tags = {"exposure", "misconfiguration", "default-login", "cve"}
    for entry in tech_stack or []:
        name = entry.get("name") if isinstance(entry, dict) else entry
        for token in str(name or "").lower().replace("-", " ").split():
            if len(token) > 2 and token.isalnum():
                tags.add(token)
    return sorted(tags)


class ToolCoverage:
    """
    Which external tools ran, and which did not.

    A web scan is only as complete as the tools available to it, and every
    call site here is guarded by ``if tool.is_available()``. Without this
    record those guards fail silently: nuclei missing from the image produces
    a scan that finishes successfully, reports nothing, and looks exactly like
    a clean result. Coverage has to be reported alongside findings for the
    findings to mean anything.
    """

    STATUS_RAN = "ran"
    STATUS_UNAVAILABLE = "unavailable"
    STATUS_FAILED = "failed"
    STATUS_SKIPPED = "skipped"

    def __init__(self) -> None:
        self.tools: Dict[str, Dict[str, Any]] = {}

    def record(self, name: str, status: str, detail: str = "") -> None:
        self.tools[name] = {
            "tool": name,
            "status": status,
            "purpose": TOOL_PURPOSE.get(name, ""),
            "detail": detail,
        }

    def ran(self, name: str, detail: str = "") -> None:
        self.record(name, self.STATUS_RAN, detail)

    def unavailable(self, name: str) -> None:
        self.record(
            name,
            self.STATUS_UNAVAILABLE,
            f"{name} is not installed on the scanner. "
            f"{TOOL_PURPOSE.get(name, 'This check')} was not performed.",
        )

    def failed(self, name: str, exc: Any) -> None:
        self.record(name, self.STATUS_FAILED, f"{name} failed: {exc}")

    def skipped(self, name: str, reason: str) -> None:
        self.record(name, self.STATUS_SKIPPED, reason)

    def check(self, wrapper, name: str) -> bool:
        """Test availability and record the outcome in one step."""
        try:
            if wrapper.is_available():
                return True
        except Exception as exc:  # noqa: BLE001 — treated as unavailable
            self.failed(name, exc)
            return False
        self.unavailable(name)
        return False

    @property
    def missing_essential(self) -> List[str]:
        return sorted(
            name
            for name, row in self.tools.items()
            if name in ESSENTIAL_TOOLS and row["status"] != self.STATUS_RAN
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "tools": [self.tools[name] for name in sorted(self.tools)],
            "tools_run": sorted(
                n for n, r in self.tools.items() if r["status"] == self.STATUS_RAN
            ),
            "tools_unavailable": sorted(
                n
                for n, r in self.tools.items()
                if r["status"] == self.STATUS_UNAVAILABLE
            ),
            "missing_essential": self.missing_essential,
            "assessment_complete": not self.missing_essential,
        }


def tool_unavailable_finding(target_url: str, missing: List[str]) -> Dict[str, Any]:
    """
    A finding stating that the scan did not assess the target.

    Recorded as a finding rather than a log line for the same reason the
    credentialed audit does it: a log nobody reads cannot stop "0
    vulnerabilities" from being taken as the conclusion.
    """
    names = ", ".join(missing)
    # Shape matches every other web finding — `title` and `matched_at`, which
    # are what the WebFinding row and the report read. `title` is NOT NULL, so
    # a finding built on the wrong keys does not merely display badly: it fails
    # to persist, and the warning is lost precisely when it matters.
    return {
        "finding_type": "misconfig",
        "title": "Web assessment incomplete — required scanner unavailable",
        "severity": "medium",
        "cvss_score": 0.0,
        "detected_by": "custom",
        "matched_at": target_url,
        "description": (
            f"The scan completed, but {names} could not be run on this scanner, "
            f"so the checks it performs were not carried out against "
            f"{target_url}. This target is unassessed for those checks, not "
            f"clean. Install the missing tool and re-run before treating an "
            f"empty result as a clean one."
        ),
        "remediation": f"Install {names} on the scanning host and re-run this scan.",
    }


#: Form fields that carry no injectable value and only add noise (or, in the
#: case of CSRF tokens, break the request when replaced with a probe).
_NON_INJECTABLE_INPUT_TYPES = {"submit", "button", "reset", "image", "file", "hidden"}


def build_injection_targets(
    endpoints: List[Dict[str, Any]], forms: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    The set of request shapes worth handing to an injection tester.

    Two things this has to get right, both of which were previously wrong.

    Forms were discovered by the crawl and then never used. Injection lives
    disproportionately in form parameters — login, search, feedback — so a
    scanner that tests only URLs carrying a query string skips the richest part
    of the surface it just spent a phase mapping.

    A POST endpoint with no body is not a test. sqlmap given ``-u`` and a POST
    method with nothing to inject probes no parameter at all and returns clean,
    which is indistinguishable from a target that has no flaw. Each target here
    carries the data that makes it testable, or it is not emitted.
    """
    targets: List[Dict[str, Any]] = []
    seen: set = set()

    def _add(url: str, method: str, data: str | None) -> None:
        url = str(url or "").strip()
        # A fragment is resolved in the browser and never reaches the server,
        # so a client-side route has no server-side parameter to inject into.
        if not url.lower().startswith(("http://", "https://")) or "#" in url:
            return
        key = f"{method}:{url}:{data or ''}"
        if key in seen:
            return
        seen.add(key)
        targets.append({"url": url, "method": method, "data": data})

    for ep in endpoints or []:
        if not isinstance(ep, dict):
            continue
        url = ep.get("url", "")
        if "?" in url and urlparse(url).query:
            _add(url, "GET", None)

    for form in forms or []:
        if not isinstance(form, dict):
            continue
        method = str(form.get("method") or "GET").upper()
        fields = [
            inp.get("name")
            for inp in form.get("inputs") or []
            if isinstance(inp, dict)
            and inp.get("name")
            and str(inp.get("type", "")).lower() not in _NON_INJECTABLE_INPUT_TYPES
        ]
        if not fields:
            continue
        body = "&".join(f"{name}=1" for name in fields)
        if method == "POST":
            _add(form.get("url", ""), "POST", body)
        else:
            url = form.get("url", "")
            _add(f"{url}{'&' if urlparse(url).query else '?'}{body}", "GET", None)

    return targets


def _redis_or_none():
    """
    The Redis client used to share one login across the pipeline's phases.

    Each phase authenticates independently. Without a shared session that is a
    fresh login per phase against the target — enough, on an application with
    lockout or login throttling, for the scan itself to lock out the account it
    was given. Redis being unavailable is not fatal; it just costs extra logins.
    """
    try:
        from core.redis_client import get_redis_client

        return get_redis_client()
    except Exception as exc:  # noqa: BLE001 — caching is an optimisation
        log.debug("Redis unavailable for session sharing: %s", exc)
        return None


def _emit_web_progress(web_scan_id: str, phase: str, data: dict) -> None:
    """
    Publish an intra-phase progress event on the same Redis channel the web
    scan's progress WebSocket subscribes to (``scan_progress:{id}``), in the
    same envelope ``core/web/tasks.py`` uses.

    This is what stops a working scan reading as stuck. Without it the pipeline
    emits one event at each phase boundary, so the DETECT phase — which can run
    for well over an hour — shows a single "Scanning for vulnerabilities"
    message and a progress bar frozen at 75% for its whole duration. Best
    effort: a publish failure must never disturb the scan.
    """
    if not web_scan_id:
        return
    try:
        import json as _json

        from core.redis_client import get_redis_client

        get_redis_client().publish(
            f"scan_progress:{web_scan_id}",
            _json.dumps(
                {
                    "scan_id": web_scan_id,
                    "scan_type": "web",
                    "phase": phase,
                    "progress": {"phase": phase, **data},
                }
            ),
        )
    except Exception as exc:  # noqa: BLE001 — progress is advisory
        log.debug("web progress publish failed: %s", exc)


def auth_failure_finding(target_url: str, error: str) -> Dict[str, Any]:
    """
    A finding stating the scan ran without the credentials it was given.

    Recorded as a finding for the same reason a missing scanner is: an
    authenticated scan that silently fell back to anonymous produces a short,
    clean-looking report of the public surface, and nothing in it says the
    protected surface was never reached.
    """
    return {
        "finding_type": "misconfig",
        "title": "Authenticated scan incomplete — login did not succeed",
        "severity": "medium",
        "cvss_score": 0.0,
        "detected_by": "custom",
        "matched_at": target_url,
        "description": (
            f"This scan was configured to authenticate to {target_url}, but the "
            f"login did not succeed: {error or 'no session was established'}. "
            f"The scan continued as an anonymous user, so every page, API and "
            f"function behind the login was never requested. Those areas are "
            f"unassessed, not clean — and they are usually where the findings "
            f"that matter are. Treat this report as covering the public surface "
            f"only."
        ),
        "remediation": (
            "Correct the scan's authentication settings — login URL, field "
            "names, credentials, and for token-based logins the token_path — "
            "then re-run. Confirm the report shows the login succeeded before "
            "relying on the result."
        ),
    }


def open_redirect_findings(
    out_of_scope: List[Dict[str, Any]], target_url: str
) -> List[Dict[str, Any]]:
    """
    Turn the crawler's scope departures into findings.

    The crawler blocks these to stay within the authorisation the scan has.
    But a request to an in-scope URL that lands the browser on a host the
    operator never named is the definition of an unvalidated redirect
    (OWASP A01 / CWE-601) — it is used to lend a phishing link the target's
    domain. The crawler is the only component that observes it, so if it does
    not report it, nothing does.
    """
    findings: List[Dict[str, Any]] = []
    seen: set = set()
    for entry in out_of_scope or []:
        source = str(entry.get("from") or "")
        destination = str(entry.get("to") or "")
        if not source or not destination:
            continue
        host = urlparse(destination).netloc
        if not host or host in seen:
            continue
        seen.add(host)
        findings.append(
            {
                "finding_type": "open_redirect",
                "title": "Open Redirect — request redirected to an external host",
                "severity": "medium",
                "cvss_score": 6.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "detected_by": "crawler",
                "matched_at": source,
                "request_url": source,
                "request_method": "GET",
                "payload_used": destination,
                "description": (
                    f"Requesting {source} caused the browser to be redirected to "
                    f"{destination}, a host outside the scanned target. The "
                    f"redirect destination is taken from the request without "
                    f"validation, so an attacker can craft a link that carries "
                    f"the trust of this domain and lands the victim on a site "
                    f"they control — the standard setup for credential phishing "
                    f"and for laundering malicious links past filters that "
                    f"allowlist this domain."
                ),
                "remediation": (
                    "Do not take redirect destinations from user-controllable "
                    "input. Where a redirect parameter is required, validate it "
                    "against an allowlist of permitted paths or hosts, and "
                    "reject absolute URLs pointing off-site."
                ),
                "is_verified": True,
            }
        )
    return findings


class WebScanOrchestrator:
    """
    Orchestrates the web application scan pipeline.

    Each method (run_recon, run_crawl, run_detect, run_audit) is designed
    to be called from a Celery task and returns a result dict.
    """

    def __init__(self, silent: bool = False):
        self.silent = silent

    # ── Phase 1: RECON ────────────────────────────────────────────────────────

    async def run_recon(
        self,
        web_scan_id: str,
        target_url: str,
        scan_scope: dict,
        options: dict,
    ) -> dict:
        """
        Phase 1: Reconnaissance.

        1. Parse and validate target URL
        2. Subdomain enumeration (if include_subdomains=True)
        3. WAF/CDN detection
        4. Technology fingerprinting
        5. Robots.txt / Sitemap.xml parsing

        Returns:
            {
                "success": bool,
                "subdomains": [...],
                "waf_detected": str or None,
                "tech_stack": [...],
                "sitemap_urls": [...],
                "robots_disallow": [...],
            }
        """
        self._log(f"[RECON] Starting for {target_url}")
        t0 = time.monotonic()
        result: dict[str, Any] = {"success": False}

        try:
            parsed = urlparse(target_url)
            domain = parsed.netloc or parsed.hostname or ""
            coverage = ToolCoverage()

            # 1. Subdomain Enumeration
            subdomains: list[str] = []
            if scan_scope.get("include_subdomains", False):
                subdomains = await self._run_subdomain_enum(domain, coverage)
            else:
                coverage.skipped(
                    "subfinder", "Subdomain enumeration not requested for this scan"
                )
            result["subdomains"] = subdomains

            # 2. WAF Detection
            waf_result = await self._run_waf_detection(target_url)
            result["waf_detected"] = waf_result.get("waf_name")
            result["waf_details"] = waf_result

            # 3. Technology Detection
            tech_stack = await self._run_tech_detection(target_url, coverage)
            result["tech_stack"] = tech_stack

            # 4. Robots.txt & Sitemap
            sitemap_data = await self._parse_robots_sitemap(target_url)
            result["sitemap_urls"] = sitemap_data.get("sitemap_urls", [])
            result["robots_disallow"] = sitemap_data.get("disallow", [])

            result["tool_coverage"] = coverage.as_dict()
            result["success"] = True
            result["duration"] = round(time.monotonic() - t0, 2)

            self._log(
                f"[RECON] Complete: {len(subdomains)} subdomains, "
                f"WAF={result['waf_detected'] or 'None'}, "
                f"{len(tech_stack)} technologies"
            )

        except Exception as exc:
            log.exception("[RECON] Failed for %s", target_url)
            result["error"] = str(exc)

        return result

    # ── Phase 2: CRAWL ────────────────────────────────────────────────────────

    async def run_crawl(
        self,
        web_scan_id: str,
        target_url: str,
        scan_scope: dict,
        options: dict,
        auth_config: dict,
        sitemap_urls: list[str] | None = None,
        waf_detected: str | None = None,
    ) -> dict:
        """
        Phase 2: Crawling & Content Discovery.

        1. Playwright browser crawling (handles SPAs)
        2. ffuf directory/file bruteforcing
        3. API endpoint discovery from JS
        4. Sitemap URL inclusion

        Returns:
            {
                "success": bool,
                "endpoints": [...],       # Discovered URLs
                "forms": [...],           # Discovered forms
                "sensitive_files": [...], # Exposed sensitive files
            }
        """
        self._log(f"[CRAWL] Starting for {target_url}")
        t0 = time.monotonic()
        result: dict[str, Any] = {"success": False}

        try:
            all_endpoints: list[dict] = []
            all_forms: list[dict] = []
            sensitive_findings: list[dict] = []
            crawl_stats: dict[str, Any] = {}

            # 1. Authenticate if needed. A single session manager is retained
            #    for the phase so its bounded re-auth counter persists across
            #    any session-loss events the crawl detects.
            from core.web.auth.secrets import decrypt_auth_config
            from core.web.auth.session_manager import WebSessionManager

            auth_mgr = WebSessionManager(redis_client=_redis_or_none())
            auth_headers, auth_cookies, auth_status = await self._authenticate(
                auth_config, web_scan_id, target_url, session_mgr=auth_mgr
            )
            result["auth_status"] = auth_status
            if auth_status.get("requested") and not auth_status.get("authenticated"):
                sensitive_findings.append(
                    auth_failure_finding(target_url, auth_status.get("error", ""))
                )

            # A re-auth callback for authenticated crawling: if the session is
            # lost mid-crawl the crawler calls this to recover it (bounded by
            # max_reauth in the manager) and returns fresh cookies. Only the
            # decrypted config lives in this closure — the crawler is handed a
            # secret-free detection config (login_url + failure_indicator only).
            reauth_cb = None
            crawl_auth_cfg: dict = {}
            if auth_status.get("authenticated"):
                _usable_cfg = decrypt_auth_config(auth_config or {})
                crawl_auth_cfg = {
                    "login_url": _usable_cfg.get("login_url"),
                    "failure_indicator": _usable_cfg.get("failure_indicator"),
                }

                async def _reauth():
                    s = await auth_mgr.reauthenticate(_usable_cfg, web_scan_id)
                    if s.is_authenticated:
                        return s.get_cookies_for_playwright(target_url)
                    return None

                reauth_cb = _reauth

            # 2. Playwright Crawling
            try:
                from core.web.crawling.browser import PlaywrightCrawler

                crawler = PlaywrightCrawler(
                    max_depth=scan_scope.get(
                        "max_depth", WebScanConfig.MAX_CRAWL_DEPTH
                    ),
                    max_urls=WebScanConfig.MAX_CRAWL_URLS,
                )

                def _crawl_progress(pages: int, endpoints: int) -> None:
                    _emit_web_progress(
                        web_scan_id,
                        "crawl",
                        {
                            "status": "running",
                            "percentage": 50,
                            "message": (
                                f"Crawling — {pages} page(s) visited, "
                                f"{endpoints} endpoint(s) found…"
                            ),
                            "total_endpoints": endpoints,
                        },
                    )

                crawl_result = await crawler.crawl(
                    start_url=target_url,
                    auth_cookies=auth_cookies or None,
                    auth_headers=auth_headers or None,
                    exclude_patterns=scan_scope.get("exclude_paths", []),
                    progress_cb=_crawl_progress,
                    auth_config=crawl_auth_cfg,
                    reauth_cb=reauth_cb,
                )
                all_endpoints.extend(crawl_result.endpoints)
                all_endpoints.extend(crawl_result.js_endpoints)
                all_forms.extend(crawl_result.forms)
                crawl_stats = {
                    "pages_visited": crawl_result.pages_visited,
                    "soft_404s_discarded": len(crawl_result.soft_404s),
                    "off_scope_blocked": len(crawl_result.out_of_scope),
                    "auth_events": list(crawl_result.auth_events),
                }
                # A target that redirects the browser to an arbitrary external
                # host is an open redirect. The crawler has to detect this to
                # stay in scope; discarding what it learned would throw away a
                # real finding that the crawl is uniquely placed to observe.
                sensitive_findings.extend(
                    open_redirect_findings(crawl_result.out_of_scope, target_url)
                )
            except ImportError:
                log.warning("Playwright not available — skipping browser crawling")
            except Exception as exc:
                log.warning("[CRAWL] Playwright crawling failed: %s", exc)

            # 3. ffuf Directory Bruteforcing
            try:
                from core.web.ffuf.wrapper import FfufWrapper

                ffuf = FfufWrapper()
                if ffuf.is_available():
                    # ffuf runs a whole wordlist as one subprocess and can take
                    # several minutes on its own — the single longest unlit
                    # stretch of the CRAWL phase. Announce it so the phase does
                    # not read as frozen while content discovery is running.
                    _emit_web_progress(
                        web_scan_id,
                        "crawl",
                        {
                            "status": "running",
                            "percentage": 60,
                            "message": (
                                f"Crawl found {len(all_endpoints)} endpoint(s); "
                                f"brute-forcing content paths with ffuf…"
                            ),
                            "total_endpoints": len(all_endpoints),
                        },
                    )
                    rate = (
                        WebScanConfig.STEALTH_RATE_LIMIT
                        if waf_detected
                        else WebScanConfig.SCAN_RATE_LIMIT
                    )
                    ffuf_result = ffuf.run(
                        target=target_url,
                        rate_limit=rate,
                        auth_headers=auth_headers or None,
                    )
                    # Convert discovered paths to endpoints
                    for path_info in ffuf_result.get("discovered_paths", []):
                        all_endpoints.append(
                            {
                                "url": path_info["url"],
                                "method": "GET",
                                "content_type": path_info.get("content_type", ""),
                                "response_code": path_info.get("status"),
                                "source": "ffuf",
                            }
                        )
                    sensitive_findings.extend(ffuf_result.get("sensitive_findings", []))
            except Exception as exc:
                log.warning("[CRAWL] ffuf failed: %s", exc)

            # 4. Include sitemap URLs
            if sitemap_urls:
                for url in sitemap_urls[:100]:  # Cap at 100 sitemap URLs
                    all_endpoints.append(
                        {
                            "url": url,
                            "method": "GET",
                            "source": "sitemap",
                        }
                    )

            # 5. API surface import (Phase 5): OpenAPI/Swagger + GraphQL. The
            #    imported operations are added as ordinary endpoints/forms so
            #    the existing DETECT engines (sqlmap, XSS, injection, access
            #    control) test API parameters and bodies with no changes; only
            #    API-specific conditions are raised here.
            if options.get("enable_api_scan", True):
                try:
                    from core.web.api_scan import ApiScanEngine

                    api = ApiScanEngine(
                        same_origin_only=True,
                        discover=bool(options.get("api_discover", True)),
                    )
                    api_res = await api.run(
                        target_url,
                        options=options,
                        auth_headers={
                            k: v
                            for k, v in (auth_headers or {}).items()
                            if k.lower() != "cookie"
                        },
                        auth_cookies={
                            c["name"]: c.get("value", "")
                            for c in (auth_cookies or [])
                            if c.get("name")
                        },
                    )
                    all_endpoints.extend(api_res.get("endpoints", []))
                    all_forms.extend(api_res.get("forms", []))
                    sensitive_findings.extend(api_res.get("sensitive_findings", []))
                    sensitive_findings.extend(api_res.get("findings", []))
                    result["api_inventory"] = api_res.get("inventory", {})
                    result["api_stats"] = api_res.get("stats", {})
                    st = api_res.get("stats", {})
                    if st.get("spec_source") or st.get("graphql"):
                        self._log(
                            f"[CRAWL] API import: spec={st.get('spec_source')}, "
                            f"{st.get('operations', 0)} operation(s), "
                            f"graphql={st.get('graphql')}, "
                            f"{st.get('findings', 0)} API finding(s)"
                        )
                except Exception as exc:
                    log.warning("[CRAWL] API import failed: %s", exc)

            # Deduplicate endpoints
            all_endpoints = self._deduplicate_endpoints(all_endpoints)

            result["endpoints"] = all_endpoints
            result["forms"] = all_forms
            result["sensitive_findings"] = sensitive_findings
            result["crawl_stats"] = crawl_stats
            result["success"] = True
            result["duration"] = round(time.monotonic() - t0, 2)

            self._log(
                f"[CRAWL] Complete: {len(all_endpoints)} endpoints, "
                f"{len(all_forms)} forms, {len(sensitive_findings)} sensitive files"
            )

        except Exception as exc:
            log.exception("[CRAWL] Failed for %s", target_url)
            result["error"] = str(exc)

        return result

    # ── Phase 3: DETECT ───────────────────────────────────────────────────────

    async def run_detect(
        self,
        web_scan_id: str,
        target_url: str,
        endpoints: list[dict],
        forms: list[dict],
        options: dict,
        auth_config: dict,
        waf_detected: str | None = None,
    ) -> dict:
        """
        Phase 3: Vulnerability Detection.

        1. Nuclei template scanning (main engine)
        2. SQLMap injection testing (parameterized endpoints only)
        3. Custom checks (CORS, security headers, etc.)

        Returns:
            {
                "success": bool,
                "findings": [...],
            }
        """
        self._log(f"[DETECT] Starting for {target_url} ({len(endpoints)} endpoints)")
        t0 = time.monotonic()
        result: dict[str, Any] = {"success": False}

        try:
            all_findings: list[dict] = []

            # Build auth headers
            auth_headers, auth_cookies, auth_status = await self._authenticate(
                auth_config, web_scan_id, target_url
            )

            is_waf = bool(waf_detected)
            effective_rate = (
                WebScanConfig.STEALTH_RATE_LIMIT
                if is_waf
                else WebScanConfig.SCAN_RATE_LIMIT
            )

            coverage = ToolCoverage()
            depth_name, depth = resolve_scan_depth(options)

            # The attack surface the crawl found. Scanning only the root URL
            # leaves every discovered endpoint untested unless a template
            # happens to guess the same path — the crawl's whole purpose is to
            # tell the detector where to look.
            scan_targets = [target_url] + [
                ep.get("url")
                for ep in (endpoints or [])
                if isinstance(ep, dict) and ep.get("url")
            ]

            # 1. Nuclei Scanning
            try:
                from core.web.nuclei.wrapper import NucleiWrapper

                nuclei = NucleiWrapper()
                if coverage.check(nuclei, "nuclei"):
                    _emit_web_progress(
                        web_scan_id,
                        "detect",
                        {
                            "status": "running",
                            "percentage": 76,
                            "message": (
                                f"Running Nuclei templates against "
                                f"{len(set(scan_targets))} target(s)…"
                            ),
                        },
                    )
                    severity = options.get("nuclei_severity") or depth["severity"]
                    tags = (
                        tech_tags(options.get("tech_stack") or [])
                        if depth["use_tech_tags"]
                        else None
                    )
                    nuclei_result = nuclei.run(
                        target=target_url,
                        targets=scan_targets,
                        severity=severity,
                        tags=tags,
                        auth_headers=auth_headers or None,
                        rate_limit=effective_rate,
                        waf_detected=is_waf,
                    )
                    all_findings.extend(nuclei_result.get("findings", []))
                    stats = nuclei_result.get("stats") or {}
                    scanned = stats.get("targets_scanned", 1)
                    oast = stats.get("oast") or {}
                    detail = (
                        f"{depth['label']}; severity {', '.join(severity)}; "
                        f"{scanned} target(s) from the discovered surface"
                    )
                    if tags:
                        detail += f"; templates narrowed to tags: {', '.join(tags)}"
                    detail += "; out-of-band testing " + (
                        "enabled" if oast.get("enabled") else "disabled"
                    )
                    if oast.get("caveat"):
                        detail += f". {oast['caveat']}"
                    coverage.ran("nuclei", detail)
            except Exception as exc:
                log.warning("[DETECT] Nuclei scan failed: %s", exc)
                coverage.failed("nuclei", exc)

            # 2. SQLMap Testing (only parameterized endpoints)
            if options.get("enable_sqli", True):
                try:
                    from core.web.sqlmap.wrapper import SqlmapWrapper

                    sqlmap = SqlmapWrapper()
                    if coverage.check(sqlmap, "sqlmap"):
                        injectable = build_injection_targets(endpoints, forms)
                        tested = injectable[:MAX_SQLMAP_TARGETS]
                        outcomes = {
                            "clean": 0,
                            "vulnerable": 0,
                            "timeout": 0,
                            "error": 0,
                            "skipped": 0,
                        }
                        total_tested = len(tested)
                        for idx, candidate in enumerate(tested, start=1):
                            # Each SQLMap run can take up to SQLMAP_TIMEOUT
                            # (10 min) on its own, so emit before each one — a
                            # silent injection sweep of twenty endpoints is the
                            # longest unlit stretch in the whole pipeline.
                            _emit_web_progress(
                                web_scan_id,
                                "detect",
                                {
                                    "status": "running",
                                    "percentage": 80
                                    + int(15 * (idx - 1) / max(total_tested, 1)),
                                    "message": (
                                        f"SQL injection testing endpoint "
                                        f"{idx}/{total_tested}…"
                                    ),
                                    "total_findings": len(all_findings),
                                },
                            )
                            try:
                                sqlmap_result = sqlmap.run(
                                    target=candidate["url"],
                                    method=candidate["method"],
                                    post_data=candidate.get("data"),
                                    auth_headers=auth_headers or None,
                                )
                                all_findings.extend(sqlmap_result.get("findings", []))
                                outcomes[sqlmap_result.get("status", "error")] = (
                                    outcomes.get(
                                        sqlmap_result.get("status", "error"), 0
                                    )
                                    + 1
                                )
                            except Exception as exc:
                                outcomes["error"] += 1
                                log.debug(
                                    "SQLMap failed for %s: %s",
                                    candidate["url"][:80],
                                    exc,
                                )
                        detail = (
                            f"{len(tested)} of {len(injectable)} injectable "
                            f"candidate(s) tested: {outcomes['vulnerable']} "
                            f"vulnerable, {outcomes['clean']} clean"
                        )
                        # A timed-out or errored candidate is inconclusive, not
                        # clean. Naming the count keeps an incomplete injection
                        # test from reading as a target proven free of it.
                        inconclusive = outcomes["timeout"] + outcomes["error"]
                        if inconclusive:
                            detail += (
                                f", {inconclusive} inconclusive "
                                f"({outcomes['timeout']} timed out) — these "
                                f"endpoints are not confirmed safe"
                            )
                        if len(injectable) > len(tested):
                            # A truncated candidate list bounds what could have
                            # been found; saying so keeps the untested remainder
                            # from reading as tested-and-clean.
                            detail += (
                                f"; {len(injectable) - len(tested)} candidate(s) "
                                f"were not tested due to the per-scan cap"
                            )
                        coverage.ran("sqlmap", detail)
                except Exception as exc:
                    log.warning("[DETECT] SQLMap setup failed: %s", exc)
                    coverage.failed("sqlmap", exc)
            else:
                coverage.skipped("sqlmap", "Disabled in scan options")

            # 2b. Active XSS engine (reflected / DOM / stored)
            #
            # nuclei's templates miss reflected and DOM XSS a browser-driven
            # active test catches (measured on Juice Shop). This runs on the
            # same discovered surface and the same authenticated session, and
            # reports only proven execution — a reflected-but-encoded value is
            # inert and never raised.
            if options.get("enable_xss", True):
                try:
                    from core.web.xss import XssEngine

                    xss = XssEngine(
                        rate_limit=effective_rate,
                        max_targets=WebScanConfig.XSS_MAX_TARGETS,
                        max_params_per_target=WebScanConfig.XSS_MAX_PARAMS_PER_TARGET,
                        max_payloads_per_param=WebScanConfig.XSS_MAX_PAYLOADS_PER_PARAM,
                        timeout_ms=WebScanConfig.XSS_TIMEOUT_MS,
                        same_origin_only=WebScanConfig.XSS_SAME_ORIGIN_ONLY,
                        test_reflected=True,
                        test_dom=WebScanConfig.XSS_TEST_DOM,
                        test_stored=WebScanConfig.XSS_TEST_STORED,
                    )
                    if coverage.check(xss, "xss"):
                        _emit_web_progress(
                            web_scan_id,
                            "detect",
                            {
                                "status": "running",
                                "percentage": 90,
                                "message": "Active XSS testing (reflected/DOM/stored)…",
                                "total_findings": len(all_findings),
                            },
                        )

                        def _xss_cancelled() -> bool:
                            return self._scan_is_cancelled(web_scan_id)

                        def _xss_progress(msg: str) -> None:
                            _emit_web_progress(
                                web_scan_id,
                                "detect",
                                {"status": "running", "percentage": 92, "message": msg},
                            )

                        xss_result = await xss.scan(
                            target_url=target_url,
                            endpoints=endpoints,
                            forms=forms,
                            auth_headers=auth_headers or None,
                            auth_cookies=auth_cookies or None,
                            options=options,
                            waf_detected=waf_detected,
                            progress_cb=_xss_progress,
                            cancel_cb=_xss_cancelled,
                        )
                        xss_findings = xss_result.get("findings", [])
                        all_findings.extend(xss_findings)
                        s = xss_result.get("stats", {})
                        coverage.ran(
                            "xss",
                            (
                                f"{s.get('parameters_tested', 0)} parameter(s) and "
                                f"{s.get('dom', 0) + s.get('reflected', 0) + s.get('stored', 0)} "
                                f"finding(s) across reflected/DOM/stored; "
                                f"{s.get('payloads_sent', 0)} payloads, "
                                f"{s.get('requests', 0)} requests, "
                                f"{s.get('duration_s', 0)}s. Detection is by proof of "
                                f"execution in a real browser."
                            ),
                        )
                except Exception as exc:
                    log.warning("[DETECT] XSS engine failed: %s", exc)
                    coverage.failed("xss", exc)
            else:
                coverage.skipped("xss", "Disabled in scan options")

            # 2c. Active injection engine (command / SSTI / XXE / LDAP / XPath)
            #
            # Extends injection coverage beyond sqlmap's SQLi. Server-side, so
            # tested over HTTP (not a browser), on the same discovered surface
            # and session. Evidence-based — differential timing, computed value,
            # canary expansion or a parser-error signature — never reflection.
            if options.get("enable_injection", True):
                try:
                    from core.web.injection import InjectionEngine

                    classes = tuple(
                        c.strip()
                        for c in str(WebScanConfig.INJECTION_CLASSES).split(",")
                        if c.strip()
                    )
                    inj = InjectionEngine(
                        rate_limit=effective_rate,
                        max_targets=WebScanConfig.INJECTION_MAX_TARGETS,
                        max_params_per_target=WebScanConfig.INJECTION_MAX_PARAMS_PER_TARGET,
                        timeout_s=WebScanConfig.INJECTION_TIMEOUT_S,
                        cmdi_delay_1=WebScanConfig.INJECTION_CMDI_DELAY_1,
                        cmdi_delay_2=WebScanConfig.INJECTION_CMDI_DELAY_2,
                        same_origin_only=WebScanConfig.INJECTION_SAME_ORIGIN_ONLY,
                        classes=classes or None,
                    )
                    if coverage.check(inj, "injection"):
                        _emit_web_progress(
                            web_scan_id,
                            "detect",
                            {
                                "status": "running",
                                "percentage": 93,
                                "message": "Active injection testing (command/SSTI/XXE/LDAP/XPath)…",
                                "total_findings": len(all_findings),
                            },
                        )

                        def _inj_cancelled() -> bool:
                            return self._scan_is_cancelled(web_scan_id)

                        def _inj_progress(msg: str) -> None:
                            _emit_web_progress(
                                web_scan_id,
                                "detect",
                                {"status": "running", "percentage": 94, "message": msg},
                            )

                        inj_result = await inj.scan(
                            target_url=target_url,
                            endpoints=endpoints,
                            forms=forms,
                            auth_headers=auth_headers or None,
                            auth_cookies=auth_cookies or None,
                            options=options,
                            waf_detected=waf_detected,
                            progress_cb=_inj_progress,
                            cancel_cb=_inj_cancelled,
                        )
                        inj_findings = inj_result.get("findings", [])
                        all_findings.extend(inj_findings)
                        st = inj_result.get("stats", {})
                        per_class = ", ".join(
                            f"{c}={st.get(c, 0)}"
                            for c in (
                                "command_injection",
                                "ssti",
                                "xxe",
                                "ldap_injection",
                                "xpath_injection",
                            )
                            if st.get(c)
                        )
                        coverage.ran(
                            "injection",
                            (
                                f"{st.get('parameters_tested', 0)} parameter(s), "
                                f"{st.get('requests', 0)} requests, "
                                f"{st.get('duration_s', 0)}s; "
                                f"{len(inj_findings)} finding(s)"
                                + (f" ({per_class})" if per_class else "")
                                + ". Detection is by timing/computed-value/canary/"
                                "parser-error evidence, not reflection."
                            ),
                        )
                except Exception as exc:
                    log.warning("[DETECT] Injection engine failed: %s", exc)
                    coverage.failed("injection", exc)
            else:
                coverage.skipped("injection", "Disabled in scan options")

            # 2d. Access-control engine (IDOR / privilege escalation)
            #
            # Multi-user and read-only by default. Runs only when the scan
            # configures access_control users (isolated sessions, never mixed),
            # and is evidence-based: a finding requires the owner's protected,
            # resource-specific content to be seen by another identity.
            ac_cfg = {}
            try:
                from core.web.auth.secrets import decrypt_auth_config

                ac_cfg = (decrypt_auth_config(auth_config or {}) or {}).get(
                    "access_control"
                ) or {}
            except Exception as exc:
                log.debug("access_control config decrypt failed: %s", exc)
            ac_users = ac_cfg.get("users") or []
            if options.get("enable_access_control", True) and ac_users:
                try:
                    from core.web.access_control import AccessControlEngine
                    from core.web.auth.session_manager import WebSessionManager

                    ac_mgr = WebSessionManager(redis_client=_redis_or_none())
                    # Owner = the main authenticated session (its crawl produced
                    # the candidate resources). If the scan is anonymous, the
                    # first non-privileged configured user becomes the owner.
                    owner = None
                    peers = []
                    if auth_status.get("authenticated"):
                        owner = {
                            "label": ac_cfg.get("owner_label", "A"),
                            "headers": {
                                k: v
                                for k, v in (auth_headers or {}).items()
                                if k.lower() != "cookie"
                            },
                            "cookies": {
                                c["name"]: c.get("value", "")
                                for c in (auth_cookies or [])
                                if c.get("name")
                            },
                        }
                    pending = list(ac_users)
                    if owner is None:
                        for i, u in enumerate(pending):
                            if not u.get("privileged"):
                                s = await ac_mgr.authenticate(
                                    u.get("auth") or {},
                                    f"{web_scan_id}:{u.get('label')}",
                                )
                                if s.is_authenticated:
                                    owner = {
                                        "label": u.get("label", "A"),
                                        "headers": dict(s.headers),
                                        "cookies": s.get_cookies(),
                                    }
                                    pending.pop(i)
                                    break
                    for u in pending:
                        s = await ac_mgr.authenticate(
                            u.get("auth") or {}, f"{web_scan_id}:{u.get('label')}"
                        )
                        if s.is_authenticated:
                            peers.append(
                                {
                                    "label": u.get("label"),
                                    "headers": dict(s.headers),
                                    "cookies": s.get_cookies(),
                                    "privileged": bool(u.get("privileged")),
                                }
                            )
                        else:
                            log.warning(
                                "access-control user %s did not authenticate: %s",
                                u.get("label"),
                                s.auth_error,
                            )

                    admin_paths = ac_cfg.get("admin_paths") or []
                    if owner and (peers or admin_paths):
                        _emit_web_progress(
                            web_scan_id,
                            "detect",
                            {
                                "status": "running",
                                "percentage": 95,
                                "message": "Access-control testing (IDOR / privilege escalation)…",
                                "total_findings": len(all_findings),
                            },
                        )
                        ac_engine = AccessControlEngine(
                            rate_limit=effective_rate,
                            max_candidates=WebScanConfig.ACCESS_CONTROL_MAX_CANDIDATES,
                            timeout_s=WebScanConfig.ACCESS_CONTROL_TIMEOUT_S,
                            same_origin_only=WebScanConfig.ACCESS_CONTROL_SAME_ORIGIN_ONLY,
                            similarity_same=WebScanConfig.ACCESS_CONTROL_SIMILARITY,
                            allow_write_testing=bool(ac_cfg.get("allow_write_testing")),
                        )

                        def _ac_cancelled() -> bool:
                            return self._scan_is_cancelled(web_scan_id)

                        ac_result = await ac_engine.scan(
                            target_url=target_url,
                            endpoints=endpoints,
                            owner=owner,
                            peers=peers,
                            admin_paths=admin_paths,
                            cancel_cb=_ac_cancelled,
                        )
                        ac_findings = ac_result.get("findings", [])
                        all_findings.extend(ac_findings)
                        st = ac_result.get("stats", {})
                        coverage.ran(
                            "access_control",
                            (
                                f"{len(peers)} peer identit(y/ies) + anon vs "
                                f"'{owner['label']}'; {st.get('candidates', 0)} "
                                f"candidate resource(s), {st.get('requests', 0)} "
                                f"requests, {st.get('duration_s', 0)}s; "
                                f"{len(ac_findings)} finding(s) "
                                f"(idor={st.get('idor', 0)}, "
                                f"priv_esc={st.get('privilege_escalation', 0)}, "
                                f"bac={st.get('broken_access_control', 0)}). "
                                f"Evidence-based cross-identity comparison."
                            ),
                        )
                    else:
                        coverage.skipped(
                            "access_control",
                            "no additional identity authenticated for comparison",
                        )
                except Exception as exc:
                    log.warning("[DETECT] Access-control engine failed: %s", exc)
                    coverage.failed("access_control", exc)

            # 2e. HTTP method / verb security testing (Phase 6)
            #
            # Read-only and safe by default (OPTIONS/HEAD/GET/TRACE only). Uses
            # the main authenticated session, when present, to establish which
            # endpoints require auth for GET so a HEAD/verb bypass can be proven.
            if options.get("enable_http_methods", True):
                try:
                    from core.web.http_methods import HttpMethodEngine

                    hm = HttpMethodEngine(
                        rate_limit=effective_rate,
                        same_origin_only=True,
                        allow_write_testing=bool(options.get("allow_write_testing")),
                    )
                    if coverage.check(hm, "http_methods"):
                        _emit_web_progress(
                            web_scan_id,
                            "detect",
                            {
                                "status": "running",
                                "percentage": 97,
                                "message": "HTTP method/verb security testing…",
                                "total_findings": len(all_findings),
                            },
                        )
                        hm_owner = None
                        if auth_status.get("authenticated"):
                            hm_owner = {
                                "headers": {
                                    k: v
                                    for k, v in (auth_headers or {}).items()
                                    if k.lower() != "cookie"
                                },
                                "cookies": {
                                    c["name"]: c.get("value", "")
                                    for c in (auth_cookies or [])
                                    if c.get("name")
                                },
                            }

                        def _hm_cancelled() -> bool:
                            return self._scan_is_cancelled(web_scan_id)

                        hm_result = await hm.scan(
                            target_url=target_url,
                            endpoints=endpoints,
                            owner=hm_owner,
                            cancel_cb=_hm_cancelled,
                        )
                        hm_findings = hm_result.get("findings", [])
                        all_findings.extend(hm_findings)
                        st = hm_result.get("stats", {})
                        coverage.ran(
                            "http_methods",
                            (
                                f"{st.get('endpoints_tested', 0)} endpoint(s), "
                                f"{st.get('requests', 0)} requests, "
                                f"{st.get('duration_s', 0)}s; "
                                f"{len(hm_findings)} finding(s) "
                                f"(insecure_method={st.get('insecure_http_method', 0)}, "
                                f"auth_bypass={st.get('http_method_auth_bypass', 0)}). "
                                f"Read-only verbs unless write testing was enabled."
                            ),
                        )
                except Exception as exc:
                    log.warning("[DETECT] HTTP-method engine failed: %s", exc)
                    coverage.failed("http_methods", exc)

            # 2f. Vulnerable JavaScript dependency detection (Phase 7)
            #
            # Identifies front-end libraries + versions from <script src> and
            # banners, and matches them against the OSV npm feed CCureAudit
            # already carries, enriching CVSS/CWE from the NVD catalogue. Invents
            # no CVEs; bounded network use.
            if options.get("enable_js_deps", True):
                try:
                    from core.web.js_deps import JsDependencyEngine

                    jsd = JsDependencyEngine()
                    if coverage.check(jsd, "js_deps"):
                        _emit_web_progress(
                            web_scan_id,
                            "detect",
                            {
                                "status": "running",
                                "percentage": 98,
                                "message": "Checking JavaScript dependencies for known vulnerabilities…",
                                "total_findings": len(all_findings),
                            },
                        )

                        def _jsd_cancelled() -> bool:
                            return self._scan_is_cancelled(web_scan_id)

                        jsd_result = await jsd.scan(
                            target_url=target_url,
                            endpoints=endpoints,
                            auth_headers=auth_headers or None,
                            auth_cookies={
                                c["name"]: c.get("value", "")
                                for c in (auth_cookies or [])
                                if c.get("name")
                            },
                            cancel_cb=_jsd_cancelled,
                        )
                        jsd_findings = jsd_result.get("findings", [])
                        all_findings.extend(jsd_findings)
                        st = jsd_result.get("stats", {})
                        coverage.ran(
                            "js_deps",
                            (
                                f"{st.get('libraries', 0)} JS librar(y/ies) "
                                f"identified from {st.get('scripts', 0)} script(s) "
                                f"across {st.get('pages', 0)} page(s); "
                                f"{len(jsd_findings)} vulnerable-dependency "
                                f"finding(s) via OSV. {st.get('requests', 0)} "
                                f"request(s)."
                            ),
                        )
                except Exception as exc:
                    log.warning("[DETECT] JS-dependency engine failed: %s", exc)
                    coverage.failed("js_deps", exc)

            # 3. Custom Security Header Checks
            _emit_web_progress(
                web_scan_id,
                "detect",
                {
                    "status": "running",
                    "percentage": 96,
                    "message": "Checking security headers and CORS…",
                    "total_findings": len(all_findings),
                },
            )
            header_findings = await self._check_security_headers(target_url)
            all_findings.extend(header_findings)

            # 4. CORS Misconfiguration Check
            cors_findings = await self._check_cors(target_url)
            all_findings.extend(cors_findings)

            # A scan whose primary detector never ran has not assessed this
            # target. Say so as a finding, so an empty result cannot be read
            # as a clean one.
            if coverage.missing_essential:
                all_findings.append(
                    tool_unavailable_finding(target_url, coverage.missing_essential)
                )
                log.warning(
                    "[DETECT] %s unavailable — %s was not assessed for those checks",
                    ", ".join(coverage.missing_essential),
                    target_url,
                )

            result["findings"] = all_findings
            result["tool_coverage"] = {
                **coverage.as_dict(),
                # The depth policy travels with the results, so a short scan is
                # a stated choice on the report rather than an unexplained
                # difference in how much was found.
                "scan_depth": depth_name,
                "scan_depth_label": depth["label"],
                "scan_depth_caveat": depth["caveat"],
                "targets_scanned": len(set(scan_targets)),
            }
            result["success"] = True
            result["duration"] = round(time.monotonic() - t0, 2)

            self._log(
                f"[DETECT] Complete: {len(all_findings)} findings | "
                f"depth={depth_name} | targets={len(set(scan_targets))} | "
                f"tools run: {', '.join(coverage.as_dict()['tools_run']) or 'none'}"
            )

        except Exception as exc:
            log.exception("[DETECT] Failed for %s", target_url)
            result["error"] = str(exc)

        return result

    # ── Phase 4: AUDIT ────────────────────────────────────────────────────────

    async def run_audit(
        self,
        web_scan_id: str,
        target_url: str,
        findings: list[dict],
        endpoints: list[dict],
        options: dict,
    ) -> dict:
        """
        Phase 4: TLS Audit, Compliance Mapping, Risk Scoring.

        1. SSLyze TLS/SSL audit
        2. Compliance mapping (OWASP, PCI-DSS)
        3. Finding deduplication and correlation
        4. Final risk scoring

        Returns:
            {
                "success": bool,
                "findings": [...],      # All findings with compliance tags
                "tls_audit": {...},     # TLS audit results
                "compliance": {...},    # Compliance scorecard
                "risk_score": float,
            }
        """
        self._log(f"[AUDIT] Starting for {target_url}")
        t0 = time.monotonic()
        result: dict[str, Any] = {"success": False}

        try:
            all_findings = list(findings)

            # 1. TLS Audit
            tls_audit = {}
            coverage = ToolCoverage()
            parsed = urlparse(target_url)
            if parsed.scheme == "https":
                try:
                    from core.web.sslyze.wrapper import SSLyzeWrapper

                    sslyze = SSLyzeWrapper()
                    if coverage.check(sslyze, "sslyze"):
                        tls_result = sslyze.run(target_url)
                        tls_audit = tls_result
                        all_findings.extend(tls_result.get("findings", []))
                        coverage.ran("sslyze")
                except Exception as exc:
                    log.warning("[AUDIT] SSLyze failed: %s", exc)
                    coverage.failed("sslyze", exc)
            else:
                coverage.skipped(
                    "sslyze", "Target is plain HTTP — there is no TLS to audit"
                )

            # 2. Compliance Mapping
            from core.web.standards_mapping import map_compliance, resolve_cwe

            for finding in all_findings:
                compliance = map_compliance(finding.get("finding_type", ""))
                finding["owasp_category"] = compliance.get("owasp", "")
                finding["compliance_tags"] = compliance.get("tags", [])
                # Same resolution as the persist path: keep an engine/tool CWE,
                # else the centralized default, else None. Filling it here means
                # the copy embedded in the report carries the CWE too.
                finding["cwe_id"] = resolve_cwe(finding)

            # 3. Deduplication
            from core.web.correlation import deduplicate_findings

            all_findings = deduplicate_findings(all_findings)

            # 4. Risk Scoring
            risk_score = self._calculate_web_risk_score(all_findings)

            result["findings"] = all_findings
            result["tls_audit"] = tls_audit
            result["risk_score"] = risk_score
            result["tool_coverage"] = coverage.as_dict()
            result["success"] = True
            result["duration"] = round(time.monotonic() - t0, 2)

            self._log(
                f"[AUDIT] Complete: {len(all_findings)} findings, "
                f"risk_score={risk_score}"
            )

        except Exception as exc:
            log.exception("[AUDIT] Failed for %s", target_url)
            result["error"] = str(exc)

        return result

    # ── Internal Helpers ──────────────────────────────────────────────────────

    async def _authenticate(
        self, auth_config: dict, web_scan_id: str, target_url: str, session_mgr=None
    ) -> tuple[dict, list, dict]:
        """
        Establish the session every later step runs under.

        Returns ``(headers, playwright_cookies, status)``. The status is
        returned, and not merely logged, because a failed login does not stop a
        scan — it quietly turns an authenticated assessment into an anonymous
        one. Every protected page then goes untested and the scan reports
        nothing wrong with them. The caller uses this to say so.
        """
        status = {
            "requested": bool(
                auth_config and auth_config.get("type", "none") != "none"
            ),
            "type": (auth_config or {}).get("type", "none"),
            "authenticated": False,
            "error": "",
        }
        if not status["requested"]:
            return {}, [], status

        try:
            from core.web.auth.secrets import decrypt_auth_config
            from core.web.auth.session_manager import WebSessionManager

            # Credentials are stored and transported encrypted; this is the one
            # place they are needed in the clear.
            usable_config = decrypt_auth_config(auth_config)

            session_mgr = session_mgr or WebSessionManager(
                redis_client=_redis_or_none()
            )
            session = await session_mgr.authenticate(usable_config, web_scan_id)
            if session.is_authenticated:
                status["authenticated"] = True
                status["verified"] = session.verified
                return (
                    session.get_auth_headers(),
                    session.get_cookies_for_playwright(target_url),
                    status,
                )
            status["error"] = session.auth_error or "Authentication produced no session"
        except Exception as exc:
            log.exception("Authentication failed for scan %s", web_scan_id)
            status["error"] = str(exc)

        log.error(
            "Authentication was configured for %s but did not succeed: %s — "
            "the scan continues unauthenticated and will not assess any "
            "protected area",
            target_url,
            status["error"],
        )
        return {}, [], status

    async def _run_subdomain_enum(
        self, domain: str, coverage: "ToolCoverage | None" = None
    ) -> list[str]:
        """Run subdomain enumeration."""
        try:
            from core.web.subfinder.wrapper import SubfinderWrapper

            sf = SubfinderWrapper()
            available = (
                coverage.check(sf, "subfinder") if coverage else sf.is_available()
            )
            if available:
                result = sf.run(domain)
                if coverage:
                    coverage.ran("subfinder")
                return result.get("subdomains", [])
        except Exception as exc:
            log.warning("Subdomain enumeration failed: %s", exc)
            if coverage:
                coverage.failed("subfinder", exc)
        return []

    async def _run_waf_detection(self, target_url: str) -> dict:
        """Run WAF detection."""
        try:
            from core.web.waf.detector import WAFDetector

            detector = WAFDetector()
            return await detector.detect(target_url)
        except Exception as exc:
            log.warning("WAF detection failed: %s", exc)
            return {"waf_detected": False, "waf_name": None}

    async def _run_tech_detection(
        self, target_url: str, coverage: "ToolCoverage | None" = None
    ) -> list[dict]:
        """Run technology fingerprinting via Nuclei tech templates."""
        try:
            from core.web.nuclei.wrapper import NucleiWrapper

            nuclei = NucleiWrapper()
            available = (
                coverage.check(nuclei, "nuclei") if coverage else nuclei.is_available()
            )
            if available:
                found = nuclei.run_tech_detect(target_url)
                if coverage:
                    coverage.ran("nuclei", "technology fingerprinting")
                return found
        except Exception as exc:
            log.warning("Tech detection failed: %s", exc)
            if coverage:
                coverage.failed("nuclei", exc)
        return []

    async def _parse_robots_sitemap(self, target_url: str) -> dict:
        """Parse robots.txt and sitemap.xml."""
        result = {"sitemap_urls": [], "disallow": []}
        try:
            import httpx

            parsed = urlparse(target_url)
            base = f"{parsed.scheme}://{parsed.netloc}"

            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                # robots.txt
                try:
                    resp = await client.get(f"{base}/robots.txt")
                    if resp.status_code == 200:
                        for line in resp.text.splitlines():
                            line = line.strip()
                            if line.lower().startswith("disallow:"):
                                path = line.split(":", 1)[1].strip()
                                if path:
                                    result["disallow"].append(path)
                            elif line.lower().startswith("sitemap:"):
                                sitemap_url = line.split(":", 1)[1].strip()
                                # Prefix with scheme if missing
                                if sitemap_url.startswith("//"):
                                    sitemap_url = f"{parsed.scheme}:{sitemap_url}"
                                result["sitemap_urls"].append(sitemap_url)
                except Exception:
                    pass

                # sitemap.xml
                try:
                    resp = await client.get(f"{base}/sitemap.xml")
                    if resp.status_code == 200 and "<urlset" in resp.text[:1000]:
                        import re

                        urls = re.findall(r"<loc>(.*?)</loc>", resp.text)
                        result["sitemap_urls"].extend(urls[:200])  # Cap at 200
                except Exception:
                    pass

        except ImportError:
            log.debug("httpx not available — skipping robots/sitemap parsing")
        except Exception as exc:
            log.debug("robots/sitemap parsing failed: %s", exc)

        return result

    async def _check_security_headers(self, target_url: str) -> list[dict]:
        """Check for missing security headers."""
        findings = []
        try:
            import httpx

            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                resp = await client.get(target_url)
                headers = {k.lower(): v for k, v in resp.headers.items()}

                required_headers = {
                    "strict-transport-security": {
                        "title": "Missing HSTS Header",
                        "severity": "medium",
                        "cvss_score": 5.0,
                    },
                    "x-content-type-options": {
                        "title": "Missing X-Content-Type-Options Header",
                        "severity": "low",
                        "cvss_score": 3.0,
                    },
                    "x-frame-options": {
                        "title": "Missing X-Frame-Options Header (Clickjacking)",
                        "severity": "medium",
                        "cvss_score": 4.0,
                    },
                    "content-security-policy": {
                        "title": "Missing Content-Security-Policy Header",
                        "severity": "medium",
                        "cvss_score": 5.0,
                    },
                    "x-xss-protection": {
                        "title": "Missing X-XSS-Protection Header",
                        "severity": "low",
                        "cvss_score": 2.0,
                    },
                }

                for header_name, meta in required_headers.items():
                    if header_name not in headers:
                        findings.append(
                            {
                                "finding_type": "misconfig",
                                "title": meta["title"],
                                "description": f"The response is missing the {header_name} security header.",
                                "severity": meta["severity"],
                                "cvss_score": meta["cvss_score"],
                                "detected_by": "custom",
                                "matched_at": target_url,
                                # "misconfig" is a nuclei catch-all with no
                                # single defensible CWE, but a *missing security
                                # header* specifically is a protection-mechanism
                                # failure. Set it explicitly so resolve_cwe
                                # preserves it rather than leaving it blank.
                                "cwe_id": "CWE-693",
                            }
                        )
        except Exception as exc:
            log.debug("Security header check failed: %s", exc)
        return findings

    async def _check_cors(self, target_url: str) -> list[dict]:
        """Check for CORS misconfiguration."""
        findings = []
        try:
            import httpx

            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                # Send request with a malicious Origin header
                resp = await client.get(
                    target_url,
                    headers={"Origin": "https://evil-attacker.com"},
                )
                acao = resp.headers.get("access-control-allow-origin", "")

                if acao == "*":
                    findings.append(
                        {
                            "finding_type": "cors",
                            "title": "CORS Wildcard: Access-Control-Allow-Origin: *",
                            "description": "Server allows any origin to make cross-origin requests. This may expose sensitive data.",
                            "severity": "medium",
                            "cvss_score": 5.3,
                            "detected_by": "custom",
                            "matched_at": target_url,
                        }
                    )
                elif "evil-attacker.com" in acao:
                    creds = resp.headers.get(
                        "access-control-allow-credentials", ""
                    ).lower()
                    severity = "critical" if creds == "true" else "high"
                    findings.append(
                        {
                            "finding_type": "cors",
                            "title": "CORS Origin Reflection Vulnerability",
                            "description": "Server reflects arbitrary Origin in ACAO header, enabling cross-origin data theft.",
                            "severity": severity,
                            "cvss_score": 9.1 if creds == "true" else 7.5,
                            "detected_by": "custom",
                            "matched_at": target_url,
                        }
                    )
        except Exception as exc:
            log.debug("CORS check failed: %s", exc)
        return findings

    @staticmethod
    def _scan_is_cancelled(web_scan_id: str) -> bool:
        """
        Best-effort cancellation check for long in-phase work (the XSS engine).

        Reads the scan's status through a short-lived session so a user pressing
        Cancel stops the active testing promptly, rather than only at the phase
        boundary. Never raises — a failed check simply does not cancel.
        """
        if not web_scan_id:
            return False
        try:
            from db.base import SessionLocal
            from db.models.web_scans import WebScan

            db = SessionLocal()
            try:
                row = db.query(WebScan.status).filter(WebScan.id == web_scan_id).first()
                return bool(row and str(row[0]).lower() == "cancelled")
            finally:
                db.close()
        except Exception:
            return False

    @staticmethod
    def _calculate_web_risk_score(findings: list[dict]) -> float:
        """Calculate aggregate risk score from findings."""
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
        total = 0
        for f in findings:
            sev = f.get("severity", "info").lower()
            total += weights.get(sev, 0)
        return min(100.0, float(total))

    @staticmethod
    def _deduplicate_endpoints(endpoints: list[dict]) -> list[dict]:
        seen = set()
        unique = []
        for ep in endpoints:
            key = f"{ep.get('method', 'GET')}:{ep.get('url', '')}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        return unique

    def _log(self, msg: str) -> None:
        if not self.silent:
            log.info(msg)
