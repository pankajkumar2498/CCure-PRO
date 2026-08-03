"""
core/web/nuclei/wrapper.py
────────────────────────────────────────────────────────────────────────────
Nuclei vulnerability scanner wrapper — the primary DAST detection engine.

Nuclei is a template-based vulnerability scanner from ProjectDiscovery.
It handles ~80% of web vulnerability detection:
  - Exposed panels and admin interfaces
  - Default credentials
  - SSRF, XSS (template-based)
  - Known CVEs (thousands of templates)
  - Misconfigurations
  - Technology detection

This wrapper:
  1. Builds the nuclei CLI command with correct flags
  2. Supports auth header injection for authenticated scanning
  3. Adjusts rate-limiting when WAF is detected
  4. Parses JSONL output into WebFinding-compatible records
  5. Handles template severity filtering
"""

import logging
import os
from typing import Dict, List, Optional

from config import WebScanConfig
from core.web.base_wrapper import ToolWrapper

log = logging.getLogger("ccure.web.nuclei")

# Severity mapping: nuclei severity → our DB severity
_SEVERITY_MAP = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "unknown": "info",
}

#: Upper bound on URLs handed to one nuclei invocation. Nuclei runs every
#: selected template against every target, so a crawl that found ten thousand
#: paginated URLs would multiply the work by ten thousand. Capping keeps the
#: scan finite; the cap being hit is recorded rather than passed over, because
#: a truncated target list bounds what the scan could have found.
MAX_NUCLEI_TARGETS = 2000


def _dedupe_targets(targets: list[str] | None, fallback: str) -> list[str]:
    """
    Normalise the crawl's output into a stable, de-duplicated target list.

    Crawlers emit the same page many times over — with tracking parameters, with
    and without a trailing slash, through several links. Scanning each variant
    separately multiplies runtime without testing anything new.
    """
    seen: dict[str, str] = {}
    for raw in targets or []:
        url = str(raw or "").strip()
        if not url or not url.lower().startswith(("http://", "https://")):
            continue
        # Query strings matter for injection testing, so they are preserved;
        # only the trailing-slash variant is folded away.
        key = url.rstrip("/") or url
        seen.setdefault(key, url)

    ordered = list(seen.values())
    if not ordered:
        return [fallback]
    if len(ordered) > MAX_NUCLEI_TARGETS:
        log.warning(
            "Crawl produced %d targets; scanning the first %d",
            len(ordered),
            MAX_NUCLEI_TARGETS,
        )
        ordered = ordered[:MAX_NUCLEI_TARGETS]
    return ordered


class NucleiWrapper(ToolWrapper):
    """
    Wrapper around ProjectDiscovery's nuclei vulnerability scanner.

    Usage:
        nuclei = NucleiWrapper()
        if nuclei.is_available():
            results = nuclei.run(
                target="https://example.com",
                severity=["medium", "high", "critical"],
                auth_headers={"Cookie": "session=abc123"},
                rate_limit=10,
            )
            for finding in results["findings"]:
                print(finding["title"], finding["severity"])
    """

    def __init__(
        self,
        binary_path: str | None = None,
        templates_dir: str | None = None,
        timeout: int | None = None,
    ):
        super().__init__(
            binary_path=binary_path or WebScanConfig.NUCLEI_BINARY,
            timeout=timeout or WebScanConfig.NUCLEI_TIMEOUT,
            name="nuclei",
        )
        self.templates_dir = templates_dir or WebScanConfig.NUCLEI_TEMPLATES_DIR

    def _is_acceptable_exit_code(self, code: int) -> bool:
        """Nuclei returns 1 when it finds vulnerabilities — that's success."""
        return code in (0, 1)

    def run(
        self,
        target: str,
        severity: list[str] | None = None,
        auth_headers: dict[str, str] | None = None,
        rate_limit: int | None = None,
        tags: list[str] | None = None,
        exclude_tags: list[str] | None = None,
        template_ids: list[str] | None = None,
        waf_detected: bool = False,
        targets: list[str] | None = None,
        **kwargs,
    ) -> dict:
        """
        Run nuclei against a target URL, or against a discovered attack surface.

        Args:
            target: URL to scan (e.g., "https://example.com")
            severity: Severity filter (default: medium,high,critical)
            auth_headers: HTTP headers for authenticated scanning
            rate_limit: Requests per second (lowered when WAF detected)
            tags: Nuclei template tags to include
            exclude_tags: Nuclei template tags to exclude
            template_ids: Specific template IDs to run
            waf_detected: If True, enables stealth mode
            targets: Every URL the crawl found. Scanning only the root URL
                means an endpoint the crawler discovered — ``/admin/login``,
                an API route, an upload form — is never tested unless a
                template happens to guess that same path. Passing the list
                switches nuclei to ``-l``, so the work is proportional to the
                attack surface actually found rather than to the root page.

        Returns:
            {"findings": [...], "stats": {...}}
        """
        self.require_available()

        # Build command. A discovered attack surface is passed as a list file;
        # a single target still goes through -u so the common case is unchanged.
        target_list = _dedupe_targets(targets, fallback=target)
        target_file = None
        if len(target_list) > 1:
            target_file = self._create_temp_file(
                suffix=".txt", prefix="nuclei_targets_"
            )
            with open(target_file, "w", encoding="utf-8") as fh:
                fh.write("\n".join(target_list))
            args = [self.binary, "-l", target_file, "-jsonl", "-silent", "-nc"]
            log.info("Nuclei scanning %d discovered target(s)", len(target_list))
        else:
            args = [self.binary, "-u", target_list[0], "-jsonl", "-silent", "-nc"]

        # Severity filter
        sev = severity or WebScanConfig.NUCLEI_SEVERITY.split(",")
        args.extend(["-severity", ",".join(sev)])

        # Rate limiting — reduce when WAF detected
        effective_rate = rate_limit or WebScanConfig.SCAN_RATE_LIMIT
        if waf_detected:
            effective_rate = min(effective_rate, WebScanConfig.STEALTH_RATE_LIMIT)
            log.info(
                "WAF detected — reducing nuclei rate limit to %d req/s", effective_rate
            )
        args.extend(["-rate-limit", str(effective_rate)])

        # Concurrency
        args.extend(["-concurrency", str(WebScanConfig.NUCLEI_CONCURRENCY)])
        args.extend(["-bulk-size", str(WebScanConfig.NUCLEI_BULK_SIZE)])

        # Template filters
        if tags:
            args.extend(["-tags", ",".join(tags)])
        if exclude_tags:
            args.extend(["-exclude-tags", ",".join(exclude_tags)])
        if template_ids:
            args.extend(["-template-id", ",".join(template_ids)])

        # Custom templates directory
        if self.templates_dir and os.path.isdir(self.templates_dir):
            args.extend(["-t", self.templates_dir])

        # Out-of-band detection. Templates for blind SSRF, blind SQLi and OOB
        # RCE rely on this; with it off they run and can never match, so the
        # state is reported alongside the findings rather than assumed.
        oast = self._configure_oast(args)

        # Auth headers for authenticated scanning
        if auth_headers:
            for header_name, header_value in auth_headers.items():
                args.extend(["-H", f"{header_name}: {header_value}"])

        # Output to temp file for large results
        output_file = self._create_temp_file(suffix=".jsonl", prefix="nuclei_")
        args.extend(["-o", output_file])

        try:
            self._run_subprocess(args)

            # Parse output
            with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                raw_output = f.read()

            raw_findings = self._parse_jsonl(raw_output)
            findings = [self._normalize_finding(f) for f in raw_findings]

            # Filter out None (failed to parse)
            findings = [f for f in findings if f is not None]

            stats = {
                "total_findings": len(findings),
                "by_severity": self._count_by_severity(findings),
                "templates_matched": len(
                    set(f.get("template_id", "") for f in findings)
                ),
                # What was actually scanned, so the report can bound its own
                # coverage instead of implying the whole application was.
                "targets_scanned": len(target_list),
                "oast": oast,
            }

            log.info(
                "Nuclei scan complete: %d findings across %d target(s) (%s)",
                len(findings),
                len(target_list),
                ", ".join(f"{k}={v}" for k, v in stats["by_severity"].items() if v > 0),
            )

            return {"findings": findings, "stats": stats}

        finally:
            self._cleanup_path(output_file)
            if target_file:
                self._cleanup_path(target_file)

    @staticmethod
    def _configure_oast(args: list[str]) -> dict:
        """
        Set up out-of-band interaction, and describe what was set up.

        Returns a record of the OAST state for the scan's coverage. The record
        matters as much as the setting: blind SSRF, blind SQL injection and
        out-of-band command execution are invisible in the HTTP response, so a
        scan without OAST has not tested for them. Reported as "enabled: false"
        that is a stated limit; left unreported it is a silent false negative in
        the classes an attacker reaches for first.
        """
        if not WebScanConfig.OAST_ENABLED:
            args.append("-no-interactsh")
            return {
                "enabled": False,
                "server": None,
                "caveat": (
                    "Out-of-band interaction testing was disabled, so blind SSRF, "
                    "blind SQL injection and out-of-band command execution were "
                    "not tested for. Those classes are unassessed on this target."
                ),
            }

        server = WebScanConfig.OAST_SERVER
        if server:
            args.extend(["-iserver", server])
            if WebScanConfig.OAST_TOKEN:
                args.extend(["-itoken", WebScanConfig.OAST_TOKEN])
            return {
                "enabled": True,
                "server": server,
                "self_hosted": True,
                "caveat": "",
            }

        return {
            "enabled": True,
            "server": "interact.sh (ProjectDiscovery public)",
            "self_hosted": False,
            "caveat": (
                "Out-of-band testing used the public interact.sh service. It "
                "requires outbound internet access from the scanner — if the "
                "scanner is egress-restricted the out-of-band checks cannot "
                "resolve and those classes are effectively untested. Set "
                "OAST_SERVER to a self-hosted interactsh for reliable results."
            ),
        }

    def run_tech_detect(self, target: str, **kwargs) -> list[dict]:
        """
        Run nuclei with tech-detect templates only.
        Returns detected technologies for fingerprinting.
        """
        if not self.is_available():
            return []

        args = [
            self.binary,
            "-u",
            target,
            "-jsonl",
            "-silent",
            "-nc",
            "-tags",
            "tech",
            "-severity",
            "info",
            "-rate-limit",
            "20",
        ]

        output_file = self._create_temp_file(suffix=".jsonl", prefix="nuclei_tech_")
        args.extend(["-o", output_file])

        try:
            self._run_subprocess(args, timeout=300)

            with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                raw_output = f.read()

            raw_results = self._parse_jsonl(raw_output)
            technologies = []
            for r in raw_results:
                info = r.get("info", {})
                name = info.get("name", r.get("template-id", "unknown"))
                technologies.append(
                    {
                        "name": name,
                        "category": self._infer_tech_category(info),
                        "version": r.get("matched-at", ""),
                        "template_id": r.get("template-id", ""),
                    }
                )
            return technologies
        except Exception as exc:
            log.warning("Nuclei tech detection failed: %s", exc)
            return []
        finally:
            self._cleanup_path(output_file)

    def run_waf_detect(self, target: str) -> str | None:
        """
        Run nuclei with WAF detection templates.
        Returns WAF name if detected, None otherwise.
        """
        if not self.is_available():
            return None

        args = [
            self.binary,
            "-u",
            target,
            "-jsonl",
            "-silent",
            "-nc",
            "-tags",
            "waf",
            "-severity",
            "info",
            "-rate-limit",
            "5",
        ]

        try:
            result = self._run_subprocess(args, timeout=120)
            findings = self._parse_jsonl(result.stdout or "")
            for f in findings:
                info = f.get("info", {})
                waf_name = info.get("name", "")
                if waf_name:
                    log.info("WAF detected: %s", waf_name)
                    return waf_name
        except Exception as exc:
            log.debug("WAF detection via nuclei failed: %s", exc)

        return None

    # ── Finding Normalization ─────────────────────────────────────────────────

    @staticmethod
    def _normalize_finding(raw: dict) -> dict | None:
        """
        Convert raw nuclei JSONL output into a normalized finding dict
        compatible with the WebFinding model.
        """
        try:
            info = raw.get("info", {})
            severity_raw = info.get("severity", "info").lower()

            # Extract HTTP evidence
            request = raw.get("request", "") or ""
            response = raw.get("response", "") or ""
            # Truncate response body to prevent DB bloat
            max_resp = WebScanConfig.MAX_RESPONSE_BODY_SIZE
            if len(response) > max_resp:
                response = response[:max_resp] + "\n... [TRUNCATED]"

            # Parse matcher info
            matched_at = raw.get("matched-at", raw.get("host", ""))
            curl_command = raw.get("curl-command", "")

            # Determine finding type from nuclei classification
            classification = info.get("classification", {})
            cve_id = None
            finding_type = "misconfig"

            cve_ids = classification.get("cve-id") or []
            if cve_ids:
                cve_id = cve_ids[0] if isinstance(cve_ids, list) else str(cve_ids)
                finding_type = "cve"
            elif any(
                t in (info.get("tags") or []) for t in ["xss", "sqli", "ssrf", "rce"]
            ):
                for tag in ["xss", "sqli", "ssrf", "rce", "lfi", "rfi", "xxe", "idor"]:
                    if tag in (info.get("tags") or []):
                        finding_type = tag
                        break
            elif "default-login" in (info.get("tags") or []):
                finding_type = "default_creds"
            elif "panel" in (info.get("tags") or []) or "exposure" in (
                info.get("tags") or []
            ):
                finding_type = "exposed_panel"
            elif "tech" in (info.get("tags") or []):
                finding_type = "technology_detected"

            # CVSS extraction
            cvss_score = None
            cvss_vector = None
            cvss_metrics = classification.get("cvss-metrics")
            cvss_score_raw = classification.get("cvss-score")
            if cvss_score_raw:
                try:
                    cvss_score = float(cvss_score_raw)
                except (ValueError, TypeError):
                    pass
            if cvss_metrics:
                cvss_vector = str(cvss_metrics)

            # No score is substituted when the template publishes none. A
            # severity-to-score table ("high" → 7.5) manufactures a measurement:
            # it reads downstream as a computed CVSS, aggregates into risk
            # scores, and lands in compliance evidence as if it had been
            # derived from a vector. The severity below is a real rating
            # supplied by the template; the score, when absent, stays absent.
            return {
                "finding_type": finding_type,
                "title": info.get("name", raw.get("template-id", "Unknown Finding")),
                "description": info.get("description", ""),
                "severity": _SEVERITY_MAP.get(severity_raw, "info"),
                "cvss_score": cvss_score,
                "cvss_scored": cvss_score is not None,
                "cvss_vector": cvss_vector,
                "detected_by": "nuclei",
                "template_id": raw.get("template-id", ""),
                "matched_at": matched_at,
                "request_evidence": request[:5000] if request else None,
                "response_evidence": response if response else None,
                "payload_used": raw.get(
                    "extracted-results", raw.get("matcher-name", "")
                ),
                "cve_id": cve_id,
                "tags": info.get("tags", []),
                "reference": info.get("reference", []),
                "is_verified": severity_raw in ("high", "critical"),
            }
        except Exception as exc:
            log.debug("Failed to normalize nuclei finding: %s", exc)
            return None

    @staticmethod
    def _count_by_severity(findings: list[dict]) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @staticmethod
    def _infer_tech_category(info: dict) -> str:
        """Infer technology category from nuclei template metadata."""
        tags = info.get("tags") or []
        if "cms" in tags:
            return "cms"
        if "framework" in tags:
            return "framework"
        if "server" in tags or "web-server" in tags:
            return "server"
        if "database" in tags or "db" in tags:
            return "database"
        if "cloud" in tags:
            return "cloud"
        return "other"
