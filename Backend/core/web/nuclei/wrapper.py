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
    "info":     "info",
    "low":      "low",
    "medium":   "medium",
    "high":     "high",
    "critical": "critical",
    "unknown":  "info",
}

# CVSS score approximation by severity (when nuclei doesn't provide exact CVSS)
_CVSS_APPROX = {
    "info":     0.0,
    "low":      3.0,
    "medium":   5.5,
    "high":     7.5,
    "critical": 9.5,
}


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
        binary_path: Optional[str] = None,
        templates_dir: Optional[str] = None,
        timeout: Optional[int] = None,
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
        severity: Optional[List[str]] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        rate_limit: Optional[int] = None,
        tags: Optional[List[str]] = None,
        exclude_tags: Optional[List[str]] = None,
        template_ids: Optional[List[str]] = None,
        waf_detected: bool = False,
        **kwargs,
    ) -> Dict:
        """
        Run nuclei against a target URL or domain.

        Args:
            target: URL to scan (e.g., "https://example.com")
            severity: Severity filter (default: medium,high,critical)
            auth_headers: HTTP headers for authenticated scanning
            rate_limit: Requests per second (lowered when WAF detected)
            tags: Nuclei template tags to include
            exclude_tags: Nuclei template tags to exclude
            template_ids: Specific template IDs to run
            waf_detected: If True, enables stealth mode

        Returns:
            {"findings": [...], "stats": {...}}
        """
        self.require_available()

        # Build command
        args = [self.binary, "-u", target, "-jsonl", "-silent", "-nc"]

        # Severity filter
        sev = severity or WebScanConfig.NUCLEI_SEVERITY.split(",")
        args.extend(["-severity", ",".join(sev)])

        # Rate limiting — reduce when WAF detected
        effective_rate = rate_limit or WebScanConfig.SCAN_RATE_LIMIT
        if waf_detected:
            effective_rate = min(effective_rate, WebScanConfig.STEALTH_RATE_LIMIT)
            log.info("WAF detected — reducing nuclei rate limit to %d req/s", effective_rate)
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
                "templates_matched": len(set(f.get("template_id", "") for f in findings)),
            }

            log.info(
                "Nuclei scan complete: %d findings (%s)",
                len(findings),
                ", ".join(f"{k}={v}" for k, v in stats["by_severity"].items() if v > 0),
            )

            return {"findings": findings, "stats": stats}

        finally:
            self._cleanup_path(output_file)

    def run_tech_detect(self, target: str, **kwargs) -> List[Dict]:
        """
        Run nuclei with tech-detect templates only.
        Returns detected technologies for fingerprinting.
        """
        if not self.is_available():
            return []

        args = [
            self.binary, "-u", target, "-jsonl", "-silent", "-nc",
            "-tags", "tech",
            "-severity", "info",
            "-rate-limit", "20",
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
                technologies.append({
                    "name": name,
                    "category": self._infer_tech_category(info),
                    "version": r.get("matched-at", ""),
                    "template_id": r.get("template-id", ""),
                })
            return technologies
        except Exception as exc:
            log.warning("Nuclei tech detection failed: %s", exc)
            return []
        finally:
            self._cleanup_path(output_file)

    def run_waf_detect(self, target: str) -> Optional[str]:
        """
        Run nuclei with WAF detection templates.
        Returns WAF name if detected, None otherwise.
        """
        if not self.is_available():
            return None

        args = [
            self.binary, "-u", target, "-jsonl", "-silent", "-nc",
            "-tags", "waf",
            "-severity", "info",
            "-rate-limit", "5",
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
    def _normalize_finding(raw: Dict) -> Optional[Dict]:
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
            elif any(t in (info.get("tags") or []) for t in ["xss", "sqli", "ssrf", "rce"]):
                for tag in ["xss", "sqli", "ssrf", "rce", "lfi", "rfi", "xxe", "idor"]:
                    if tag in (info.get("tags") or []):
                        finding_type = tag
                        break
            elif "default-login" in (info.get("tags") or []):
                finding_type = "default_creds"
            elif "panel" in (info.get("tags") or []) or "exposure" in (info.get("tags") or []):
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

            if cvss_score is None:
                cvss_score = _CVSS_APPROX.get(severity_raw, 0.0)

            return {
                "finding_type": finding_type,
                "title": info.get("name", raw.get("template-id", "Unknown Finding")),
                "description": info.get("description", ""),
                "severity": _SEVERITY_MAP.get(severity_raw, "info"),
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "detected_by": "nuclei",
                "template_id": raw.get("template-id", ""),
                "matched_at": matched_at,
                "request_evidence": request[:5000] if request else None,
                "response_evidence": response if response else None,
                "payload_used": raw.get("extracted-results", raw.get("matcher-name", "")),
                "cve_id": cve_id,
                "tags": info.get("tags", []),
                "reference": info.get("reference", []),
                "is_verified": severity_raw in ("high", "critical"),
            }
        except Exception as exc:
            log.debug("Failed to normalize nuclei finding: %s", exc)
            return None

    @staticmethod
    def _count_by_severity(findings: List[Dict]) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @staticmethod
    def _infer_tech_category(info: Dict) -> str:
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
