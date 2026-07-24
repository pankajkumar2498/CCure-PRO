"""
core/web/sqlmap/wrapper.py
────────────────────────────────────────────────────────────────────────────
SQLMap SQL injection detection wrapper.

IMPORTANT: SQLMap is a targeted tool — it should NOT run against every URL.
Only endpoints with dynamic parameters (query params, POST body params)
discovered by the crawler should be tested.

This wrapper:
  1. Only accepts URLs with parameters (enforced)
  2. Runs in --batch mode (no interactive prompts)
  3. Parses output for injection points
  4. Captures request/response evidence
"""

import logging
from typing import Dict, Optional

from config import WebScanConfig
from core.web.base_wrapper import ToolWrapper

log = logging.getLogger("ccure.web.sqlmap")


class SqlmapWrapper(ToolWrapper):
    """
    Wrapper around sqlmap for SQL injection detection.

    SAFETY: Only runs against endpoints with dynamic parameters.
    Uses --batch mode to avoid any interactive prompts.

    Usage:
        sqlmap = SqlmapWrapper()
        result = sqlmap.run("https://example.com/api/users?id=1")
        for vuln in result["findings"]:
            print(vuln["title"], vuln["injection_type"])
    """

    def __init__(
        self,
        binary_path: str | None = None,
        timeout: int | None = None,
    ):
        super().__init__(
            binary_path=binary_path or WebScanConfig.SQLMAP_BINARY,
            timeout=timeout or WebScanConfig.SQLMAP_TIMEOUT,
            name="sqlmap",
        )

    def _is_acceptable_exit_code(self, code: int) -> bool:
        """sqlmap returns various exit codes; 0 and 1 are acceptable."""
        return code in (0, 1)

    def run(
        self,
        target: str,
        method: str = "GET",
        post_data: str | None = None,
        auth_headers: dict[str, str] | None = None,
        level: int | None = None,
        risk: int | None = None,
        **kwargs,
    ) -> dict:
        """
        Test a URL for SQL injection vulnerabilities.

        Args:
            target: URL with parameters (e.g., "https://example.com/api?id=1")
            method: HTTP method (GET or POST)
            post_data: POST request body data
            auth_headers: Authentication headers
            level: sqlmap testing level (1-5, default 2)
            risk: sqlmap risk level (1-3, default 2)

        Returns:
            {"findings": [...], "vulnerable": bool, "injection_points": [...]}
        """
        self.require_available()

        # Safety check: only test URLs with parameters
        if method.upper() == "GET" and "?" not in target and not post_data:
            log.info("Skipping SQLMap for %s — no dynamic parameters", target[:80])
            return {"findings": [], "vulnerable": False, "injection_points": []}

        output_dir = self._create_temp_dir(prefix="sqlmap_")

        args = [
            self.binary,
            "-u",
            target,
            "--batch",  # Non-interactive
            f"--level={level or WebScanConfig.SQLMAP_LEVEL}",
            f"--risk={risk or WebScanConfig.SQLMAP_RISK}",
            f"--output-dir={output_dir}",
            "--flush-session",
            "--disable-coloring",
            "--answers=crack=N,dict=N",  # Skip cracking
        ]

        if method.upper() == "POST" and post_data:
            args.extend(["--data", post_data])

        if auth_headers:
            header_strs = [f"{k}: {v}" for k, v in auth_headers.items()]
            args.extend(["--headers", "\n".join(header_strs)])

        # Timeout protection per target
        args.extend(["--timeout", "30"])
        args.extend(["--retries", "2"])

        try:
            result = self._run_subprocess(args)
            stdout = result.stdout or ""

            findings = []
            injection_points = []
            vulnerable = False

            # Parse stdout for injection indicators
            if "is vulnerable" in stdout.lower() or "parameter" in stdout.lower():
                vulnerable = "is vulnerable" in stdout.lower()

            # Extract injection point details from stdout
            for line in stdout.splitlines():
                line_lower = line.strip().lower()

                if "type:" in line_lower and "payload:" in line_lower:
                    injection_points.append(line.strip())

                if "is vulnerable" in line_lower:
                    vulnerable = True

            if vulnerable:
                findings.append(
                    {
                        "finding_type": "sqli",
                        "title": f"SQL Injection detected: {target[:100]}",
                        "description": (
                            "SQLMap confirmed SQL injection vulnerability at this endpoint. "
                            "An attacker could extract, modify, or delete database contents."
                        ),
                        "severity": "critical",
                        "cvss_score": 9.8,
                        "detected_by": "sqlmap",
                        "matched_at": target,
                        "request_url": target,
                        "request_method": method.upper(),
                        "request_body": post_data,
                        "payload_used": "\n".join(injection_points[:5]),
                        "response_evidence": (
                            stdout[-2000:] if len(stdout) > 2000 else stdout
                        ),
                        "is_verified": True,
                    }
                )

            log.info(
                "SQLMap complete for %s: vulnerable=%s, %d injection points",
                target[:80],
                vulnerable,
                len(injection_points),
            )

            return {
                "findings": findings,
                "vulnerable": vulnerable,
                "injection_points": injection_points,
            }

        except Exception as exc:
            log.warning("SQLMap failed for %s: %s", target[:80], exc)
            return {
                "findings": [],
                "vulnerable": False,
                "injection_points": [],
                "error": str(exc),
            }
        finally:
            self._cleanup_path(output_dir)
