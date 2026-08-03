"""
core/web/ffuf/wrapper.py
────────────────────────────────────────────────────────────────────────────
ffuf directory/file bruteforcing wrapper.

Discovers hidden directories, backup files, exposed config files (.env, .git),
and admin panels using wordlist-based fuzzing.
"""

import logging
import os
from typing import Dict, List, Optional

from config import WebScanConfig
from core.web.base_wrapper import ToolWrapper

log = logging.getLogger("ccure.web.ffuf")

# Interesting findings that should be flagged as security issues
_SENSITIVE_PATHS = {
    ".git",
    ".git/config",
    ".git/HEAD",
    ".env",
    ".env.bak",
    ".env.local",
    ".env.production",
    ".htaccess",
    ".htpasswd",
    "wp-admin",
    "wp-login.php",
    "admin",
    "administrator",
    "phpmyadmin",
    "backup",
    "backup.zip",
    "backup.tar.gz",
    "backup.sql",
    "server-status",
    "server-info",
    ".DS_Store",
    "Thumbs.db",
    "web.config",
    "crossdomain.xml",
}

#: Deliberately NOT in the set above: robots.txt and sitemap.xml. Both are
#: standard, intentionally public files present on most of the web. Reporting
#: them as "sensitive file exposed" produced a medium-severity finding on
#: essentially every target scanned — the kind of guaranteed false positive
#: that trains readers to skim past this category, taking the real .git and
#: .env findings with it.


class FfufWrapper(ToolWrapper):
    """
    Wrapper around ffuf for directory and file bruteforcing.

    Usage:
        ffuf = FfufWrapper()
        result = ffuf.run("https://example.com")
        for path in result["discovered_paths"]:
            print(path["url"], path["status"])
    """

    def __init__(
        self,
        binary_path: str | None = None,
        wordlist: str | None = None,
        timeout: int = 600,
    ):
        super().__init__(
            binary_path=binary_path or WebScanConfig.FFUF_BINARY,
            timeout=timeout,
            name="ffuf",
        )
        self.wordlist = wordlist or WebScanConfig.FFUF_WORDLIST

    def _is_acceptable_exit_code(self, code: int) -> bool:
        """ffuf returns 0 on success regardless of findings count."""
        return code == 0

    def run(
        self,
        target: str,
        wordlist: str | None = None,
        rate_limit: int | None = None,
        extensions: list[str] | None = None,
        auth_headers: dict[str, str] | None = None,
        match_codes: list[int] | None = None,
        filter_codes: list[int] | None = None,
        **kwargs,
    ) -> dict:
        """
        Run ffuf directory bruteforcing against a target.

        Args:
            target: Base URL (e.g., "https://example.com")
            wordlist: Path to wordlist file
            rate_limit: Requests per second
            extensions: File extensions to append (e.g., [".php", ".bak"])
            auth_headers: HTTP headers for authenticated fuzzing
            match_codes: HTTP status codes to match (default: 200,301,302,403)
            filter_codes: HTTP status codes to filter out

        Returns:
            {"discovered_paths": [...], "sensitive_findings": [...], "stats": {...}}
        """
        self.require_available()

        effective_wordlist = wordlist or self.wordlist
        if not os.path.isfile(effective_wordlist):
            log.warning("ffuf wordlist not found: %s", effective_wordlist)
            return {"discovered_paths": [], "sensitive_findings": [], "stats": {}}

        # Ensure target URL ends without trailing slash for FUZZ placement
        base_url = target.rstrip("/")
        fuzz_url = f"{base_url}/FUZZ"

        output_file = self._create_temp_file(suffix=".json", prefix="ffuf_")

        args = [
            self.binary,
            "-u",
            fuzz_url,
            "-w",
            effective_wordlist,
            "-o",
            output_file,
            "-of",
            "json",
            "-s",  # silent mode
            "-noninteractive",
        ]

        # Status code matching
        if match_codes:
            args.extend(["-mc", ",".join(str(c) for c in match_codes)])
        else:
            args.extend(["-mc", "200,204,301,302,307,401,403,405"])

        if filter_codes:
            args.extend(["-fc", ",".join(str(c) for c in filter_codes)])

        # Rate limiting
        effective_rate = rate_limit or WebScanConfig.SCAN_RATE_LIMIT
        args.extend(["-rate", str(effective_rate)])

        # Extensions
        if extensions:
            args.extend(["-e", ",".join(extensions)])

        # Auth headers
        if auth_headers:
            for name, value in auth_headers.items():
                args.extend(["-H", f"{name}: {value}"])

        # Auto-calibration to filter noise
        args.append("-ac")

        try:
            self._run_subprocess(args)

            # Parse JSON output
            with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()

            data = self._parse_json(raw)
            results = data.get("results", [])

            discovered_paths = []
            sensitive_findings = []

            for r in results:
                path_info = {
                    "url": r.get("url", ""),
                    "path": r.get("input", {}).get("FUZZ", ""),
                    "status": r.get("status", 0),
                    "length": r.get("length", 0),
                    "words": r.get("words", 0),
                    "lines": r.get("lines", 0),
                    "content_type": r.get("content-type", ""),
                    "redirectlocation": r.get("redirectlocation", ""),
                }
                discovered_paths.append(path_info)

                # Check if this is a sensitive path
                fuzz_value = path_info["path"].lower().strip("/")
                if fuzz_value in _SENSITIVE_PATHS or any(
                    fuzz_value.endswith(ext)
                    for ext in [".bak", ".sql", ".tar.gz", ".zip"]
                ):
                    high_risk = fuzz_value.startswith((".git", ".env", ".htpasswd"))
                    sensitive_findings.append(
                        {
                            **path_info,
                            "finding_type": "information_disclosure",
                            "title": f"Sensitive file/directory exposed: {path_info['path']}",
                            "severity": "high" if high_risk else "medium",
                            # matched_at and detected_by are what the WebFinding
                            # row is keyed and attributed by. Without them the
                            # finding persists with no location and no source
                            # tool, so the report can say something was exposed
                            # but not where, or how that was determined.
                            "matched_at": path_info["url"],
                            "request_url": path_info["url"],
                            "request_method": "GET",
                            "response_code": path_info["status"],
                            "detected_by": "ffuf",
                            "description": (
                                f"Content discovery found {path_info['path']} "
                                f"responding with HTTP {path_info['status']} at "
                                f"{path_info['url']}. Files of this kind commonly "
                                f"expose source history, credentials or "
                                f"configuration that is not intended to be "
                                f"reachable over the web."
                            ),
                            "remediation": (
                                "Confirm whether this path should be reachable. "
                                "If not, remove it from the web root or block it "
                                "at the server or proxy."
                            ),
                        }
                    )

            stats = {
                "total_discovered": len(discovered_paths),
                "sensitive_count": len(sensitive_findings),
                "wordlist": effective_wordlist,
            }

            log.info(
                "ffuf complete: %d paths discovered, %d sensitive",
                len(discovered_paths),
                len(sensitive_findings),
            )

            return {
                "discovered_paths": discovered_paths,
                "sensitive_findings": sensitive_findings,
                "stats": stats,
            }

        except Exception as exc:
            log.warning("ffuf failed for %s: %s", target, exc)
            return {
                "discovered_paths": [],
                "sensitive_findings": [],
                "stats": {},
                "error": str(exc),
            }
        finally:
            self._cleanup_path(output_file)
