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
            return {
                "findings": [],
                "vulnerable": False,
                "injection_points": [],
                "status": "skipped",
            }

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

        # Per-request network timeout and retries.
        args.extend(["--timeout", "30"])
        args.extend(["--retries", "2"])

        import subprocess

        try:
            result = self._run_subprocess(args, timeout=self.timeout)
            stdout = result.stdout or ""

            vulnerable, injection_points, dbms = self._parse_output(stdout)

            findings = []
            if vulnerable:
                findings.append(
                    {
                        "finding_type": "sqli",
                        "title": f"SQL Injection detected: {target[:100]}",
                        "description": (
                            "SQLMap confirmed a SQL injection vulnerability at "
                            "this endpoint"
                            + (f" (back-end DBMS: {dbms})" if dbms else "")
                            + ". An attacker could read, modify or delete "
                            "database contents, and depending on privileges "
                            "read local files or achieve code execution."
                        ),
                        "severity": "critical",
                        "cvss_score": 9.8,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "detected_by": "sqlmap",
                        "matched_at": target,
                        "request_url": target,
                        "request_method": method.upper(),
                        "request_body": post_data,
                        "payload_used": "\n".join(injection_points[:8]),
                        "response_evidence": (
                            stdout[-2000:] if len(stdout) > 2000 else stdout
                        ),
                        "remediation": (
                            "Use parameterised queries / prepared statements for "
                            "all database access. Never build SQL by string "
                            "concatenation with request data. Apply least-"
                            "privilege to the database account the application "
                            "uses."
                        ),
                        "is_verified": True,
                    }
                )

            log.info(
                "SQLMap complete for %s: vulnerable=%s, %d injection type(s)",
                target[:80],
                vulnerable,
                len(injection_points),
            )

            # "clean" here means sqlmap ran to completion and found nothing —
            # a real negative, distinct from the timeout case below.
            return {
                "findings": findings,
                "vulnerable": vulnerable,
                "injection_points": injection_points,
                "status": "vulnerable" if vulnerable else "clean",
            }

        except subprocess.TimeoutExpired:
            # sqlmap did not finish within its budget. This is NOT a clean
            # result — the parameter is untested past the point it was cut off,
            # and reporting it as clean would be a false negative on the class
            # the whole tool exists to catch. Surfaced as its own status so the
            # phase can record the endpoint as inconclusive rather than safe.
            log.warning(
                "SQLMap timed out for %s after %ss — endpoint left inconclusive",
                target[:80],
                self.timeout,
            )
            return {
                "findings": [],
                "vulnerable": False,
                "injection_points": [],
                "status": "timeout",
                "error": f"sqlmap exceeded its {self.timeout}s budget",
            }
        except Exception as exc:
            log.warning("SQLMap failed for %s: %s", target[:80], exc)
            return {
                "findings": [],
                "vulnerable": False,
                "injection_points": [],
                "status": "error",
                "error": str(exc),
            }
        finally:
            self._cleanup_path(output_dir)

    @staticmethod
    def _parse_output(stdout: str) -> tuple[bool, list[str], str]:
        """
        Read sqlmap's console output for a confirmed injection.

        sqlmap prints the injection details as a block of separate ``Type:`` /
        ``Title:`` / ``Payload:`` lines. The previous parser looked for Type and
        Payload on a single line, which never matches, so a confirmed injection
        was recorded with no evidence of what was injected. Each line is
        collected on its own here.
        """
        vulnerable = False
        details: list[str] = []
        dbms = ""
        for line in stdout.splitlines():
            stripped = line.strip()
            low = stripped.lower()
            if (
                "is vulnerable" in low
                or "sqlmap identified the following injection" in low
            ):
                vulnerable = True
            if stripped.startswith(("Type:", "Title:", "Payload:")):
                details.append(stripped)
                if stripped.startswith("Type:"):
                    vulnerable = True
            if "back-end dbms:" in low:
                dbms = stripped.split(":", 1)[1].strip()
        return vulnerable, details, dbms
