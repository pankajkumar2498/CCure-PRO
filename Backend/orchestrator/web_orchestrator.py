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

import asyncio
import logging
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from config import WebScanConfig
from db.base import (
    SessionLocal, utcnow,
    gen_web_scan_id, gen_web_asset_id, gen_web_finding_id,
)

log = logging.getLogger("ccure.web.orchestrator")


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
        scan_scope: Dict,
        options: Dict,
    ) -> Dict:
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
        result: Dict[str, Any] = {"success": False}

        try:
            parsed = urlparse(target_url)
            domain = parsed.netloc or parsed.hostname or ""

            # 1. Subdomain Enumeration
            subdomains: List[str] = []
            if scan_scope.get("include_subdomains", False):
                subdomains = await self._run_subdomain_enum(domain)
            result["subdomains"] = subdomains

            # 2. WAF Detection
            waf_result = await self._run_waf_detection(target_url)
            result["waf_detected"] = waf_result.get("waf_name")
            result["waf_details"] = waf_result

            # 3. Technology Detection
            tech_stack = await self._run_tech_detection(target_url)
            result["tech_stack"] = tech_stack

            # 4. Robots.txt & Sitemap
            sitemap_data = await self._parse_robots_sitemap(target_url)
            result["sitemap_urls"] = sitemap_data.get("sitemap_urls", [])
            result["robots_disallow"] = sitemap_data.get("disallow", [])

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
        scan_scope: Dict,
        options: Dict,
        auth_config: Dict,
        sitemap_urls: Optional[List[str]] = None,
        waf_detected: Optional[str] = None,
    ) -> Dict:
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
        result: Dict[str, Any] = {"success": False}

        try:
            all_endpoints: List[Dict] = []
            all_forms: List[Dict] = []
            sensitive_findings: List[Dict] = []

            # 1. Authenticate if needed
            auth_headers = {}
            auth_cookies = []
            if auth_config and auth_config.get("type") != "none":
                from core.web.auth.session_manager import WebSessionManager
                session_mgr = WebSessionManager()
                session = await session_mgr.authenticate(auth_config, web_scan_id)
                if session.is_authenticated:
                    auth_headers = session.get_auth_headers()
                    auth_cookies = session.get_cookies_for_playwright()

            # 2. Playwright Crawling
            try:
                from core.web.crawling.browser import PlaywrightCrawler

                crawler = PlaywrightCrawler(
                    max_depth=scan_scope.get("max_depth", WebScanConfig.MAX_CRAWL_DEPTH),
                    max_urls=WebScanConfig.MAX_CRAWL_URLS,
                )
                crawl_result = await crawler.crawl(
                    start_url=target_url,
                    auth_cookies=auth_cookies or None,
                    auth_headers=auth_headers or None,
                    exclude_patterns=scan_scope.get("exclude_paths", []),
                )
                all_endpoints.extend(crawl_result.endpoints)
                all_endpoints.extend(crawl_result.js_endpoints)
                all_forms.extend(crawl_result.forms)
            except ImportError:
                log.warning("Playwright not available — skipping browser crawling")
            except Exception as exc:
                log.warning("[CRAWL] Playwright crawling failed: %s", exc)

            # 3. ffuf Directory Bruteforcing
            try:
                from core.web.ffuf.wrapper import FfufWrapper

                ffuf = FfufWrapper()
                if ffuf.is_available():
                    rate = WebScanConfig.STEALTH_RATE_LIMIT if waf_detected else WebScanConfig.SCAN_RATE_LIMIT
                    ffuf_result = ffuf.run(
                        target=target_url,
                        rate_limit=rate,
                        auth_headers=auth_headers or None,
                    )
                    # Convert discovered paths to endpoints
                    for path_info in ffuf_result.get("discovered_paths", []):
                        all_endpoints.append({
                            "url": path_info["url"],
                            "method": "GET",
                            "content_type": path_info.get("content_type", ""),
                            "response_code": path_info.get("status"),
                            "source": "ffuf",
                        })
                    sensitive_findings.extend(ffuf_result.get("sensitive_findings", []))
            except Exception as exc:
                log.warning("[CRAWL] ffuf failed: %s", exc)

            # 4. Include sitemap URLs
            if sitemap_urls:
                for url in sitemap_urls[:100]:  # Cap at 100 sitemap URLs
                    all_endpoints.append({
                        "url": url,
                        "method": "GET",
                        "source": "sitemap",
                    })

            # Deduplicate endpoints
            all_endpoints = self._deduplicate_endpoints(all_endpoints)

            result["endpoints"] = all_endpoints
            result["forms"] = all_forms
            result["sensitive_findings"] = sensitive_findings
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
        endpoints: List[Dict],
        forms: List[Dict],
        options: Dict,
        auth_config: Dict,
        waf_detected: Optional[str] = None,
    ) -> Dict:
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
        result: Dict[str, Any] = {"success": False}

        try:
            all_findings: List[Dict] = []

            # Build auth headers
            auth_headers = {}
            if auth_config and auth_config.get("type") != "none":
                from core.web.auth.session_manager import WebSessionManager
                session_mgr = WebSessionManager()
                session = await session_mgr.authenticate(auth_config, web_scan_id)
                if session.is_authenticated:
                    auth_headers = session.get_auth_headers()

            is_waf = bool(waf_detected)
            effective_rate = WebScanConfig.STEALTH_RATE_LIMIT if is_waf else WebScanConfig.SCAN_RATE_LIMIT

            # 1. Nuclei Scanning
            try:
                from core.web.nuclei.wrapper import NucleiWrapper

                nuclei = NucleiWrapper()
                if nuclei.is_available():
                    severity = options.get("nuclei_severity", ["medium", "high", "critical"])
                    nuclei_result = nuclei.run(
                        target=target_url,
                        severity=severity,
                        auth_headers=auth_headers or None,
                        rate_limit=effective_rate,
                        waf_detected=is_waf,
                    )
                    all_findings.extend(nuclei_result.get("findings", []))
            except Exception as exc:
                log.warning("[DETECT] Nuclei scan failed: %s", exc)

            # 2. SQLMap Testing (only parameterized endpoints)
            if options.get("enable_sqli", True):
                try:
                    from core.web.sqlmap.wrapper import SqlmapWrapper

                    sqlmap = SqlmapWrapper()
                    if sqlmap.is_available():
                        injectable_urls = [
                            ep for ep in endpoints
                            if "?" in ep.get("url", "")
                            or ep.get("method", "GET") == "POST"
                        ]
                        # Limit SQLMap to top 20 injectable URLs
                        for ep in injectable_urls[:20]:
                            try:
                                sqlmap_result = sqlmap.run(
                                    target=ep["url"],
                                    method=ep.get("method", "GET"),
                                    auth_headers=auth_headers or None,
                                )
                                all_findings.extend(sqlmap_result.get("findings", []))
                            except Exception as exc:
                                log.debug("SQLMap failed for %s: %s", ep["url"][:80], exc)
                except Exception as exc:
                    log.warning("[DETECT] SQLMap setup failed: %s", exc)

            # 3. Custom Security Header Checks
            header_findings = await self._check_security_headers(target_url)
            all_findings.extend(header_findings)

            # 4. CORS Misconfiguration Check
            cors_findings = await self._check_cors(target_url)
            all_findings.extend(cors_findings)

            result["findings"] = all_findings
            result["success"] = True
            result["duration"] = round(time.monotonic() - t0, 2)

            self._log(f"[DETECT] Complete: {len(all_findings)} findings")

        except Exception as exc:
            log.exception("[DETECT] Failed for %s", target_url)
            result["error"] = str(exc)

        return result

    # ── Phase 4: AUDIT ────────────────────────────────────────────────────────

    async def run_audit(
        self,
        web_scan_id: str,
        target_url: str,
        findings: List[Dict],
        endpoints: List[Dict],
        options: Dict,
    ) -> Dict:
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
        result: Dict[str, Any] = {"success": False}

        try:
            all_findings = list(findings)

            # 1. TLS Audit
            tls_audit = {}
            parsed = urlparse(target_url)
            if parsed.scheme == "https":
                try:
                    from core.web.sslyze.wrapper import SSLyzeWrapper

                    sslyze = SSLyzeWrapper()
                    if sslyze.is_available():
                        tls_result = sslyze.run(target_url)
                        tls_audit = tls_result
                        all_findings.extend(tls_result.get("findings", []))
                except Exception as exc:
                    log.warning("[AUDIT] SSLyze failed: %s", exc)

            # 2. Compliance Mapping
            from core.web.compliance import map_compliance
            for finding in all_findings:
                compliance = map_compliance(finding.get("finding_type", ""))
                finding["owasp_category"] = compliance.get("owasp", "")
                finding["compliance_tags"] = compliance.get("tags", [])

            # 3. Deduplication
            from core.web.correlation import deduplicate_findings
            all_findings = deduplicate_findings(all_findings)

            # 4. Risk Scoring
            risk_score = self._calculate_web_risk_score(all_findings)

            result["findings"] = all_findings
            result["tls_audit"] = tls_audit
            result["risk_score"] = risk_score
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

    async def _run_subdomain_enum(self, domain: str) -> List[str]:
        """Run subdomain enumeration."""
        try:
            from core.web.subfinder.wrapper import SubfinderWrapper
            sf = SubfinderWrapper()
            if sf.is_available():
                result = sf.run(domain)
                return result.get("subdomains", [])
        except Exception as exc:
            log.warning("Subdomain enumeration failed: %s", exc)
        return []

    async def _run_waf_detection(self, target_url: str) -> Dict:
        """Run WAF detection."""
        try:
            from core.web.waf.detector import WAFDetector
            detector = WAFDetector()
            return await detector.detect(target_url)
        except Exception as exc:
            log.warning("WAF detection failed: %s", exc)
            return {"waf_detected": False, "waf_name": None}

    async def _run_tech_detection(self, target_url: str) -> List[Dict]:
        """Run technology fingerprinting via Nuclei tech templates."""
        try:
            from core.web.nuclei.wrapper import NucleiWrapper
            nuclei = NucleiWrapper()
            if nuclei.is_available():
                return nuclei.run_tech_detect(target_url)
        except Exception as exc:
            log.warning("Tech detection failed: %s", exc)
        return []

    async def _parse_robots_sitemap(self, target_url: str) -> Dict:
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

    async def _check_security_headers(self, target_url: str) -> List[Dict]:
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
                        findings.append({
                            "finding_type": "misconfig",
                            "title": meta["title"],
                            "description": f"The response is missing the {header_name} security header.",
                            "severity": meta["severity"],
                            "cvss_score": meta["cvss_score"],
                            "detected_by": "custom",
                            "matched_at": target_url,
                        })
        except Exception as exc:
            log.debug("Security header check failed: %s", exc)
        return findings

    async def _check_cors(self, target_url: str) -> List[Dict]:
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
                    findings.append({
                        "finding_type": "cors",
                        "title": "CORS Wildcard: Access-Control-Allow-Origin: *",
                        "description": "Server allows any origin to make cross-origin requests. This may expose sensitive data.",
                        "severity": "medium",
                        "cvss_score": 5.3,
                        "detected_by": "custom",
                        "matched_at": target_url,
                    })
                elif "evil-attacker.com" in acao:
                    creds = resp.headers.get("access-control-allow-credentials", "").lower()
                    severity = "critical" if creds == "true" else "high"
                    findings.append({
                        "finding_type": "cors",
                        "title": "CORS Origin Reflection Vulnerability",
                        "description": "Server reflects arbitrary Origin in ACAO header, enabling cross-origin data theft.",
                        "severity": severity,
                        "cvss_score": 9.1 if creds == "true" else 7.5,
                        "detected_by": "custom",
                        "matched_at": target_url,
                    })
        except Exception as exc:
            log.debug("CORS check failed: %s", exc)
        return findings

    @staticmethod
    def _calculate_web_risk_score(findings: List[Dict]) -> float:
        """Calculate aggregate risk score from findings."""
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
        total = 0
        for f in findings:
            sev = f.get("severity", "info").lower()
            total += weights.get(sev, 0)
        return min(100.0, float(total))

    @staticmethod
    def _deduplicate_endpoints(endpoints: List[Dict]) -> List[Dict]:
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
