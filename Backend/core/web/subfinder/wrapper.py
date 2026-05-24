"""
core/web/subfinder/wrapper.py
────────────────────────────────────────────────────────────────────────────
Subfinder passive subdomain enumeration wrapper.

Discovers subdomains using passive sources (certificate transparency logs,
search engines, DNS databases) without sending any traffic to the target.
"""

import logging
from typing import Dict, List, Optional

from config import WebScanConfig
from core.web.base_wrapper import ToolWrapper

log = logging.getLogger("ccure.web.subfinder")


class SubfinderWrapper(ToolWrapper):
    """
    Wrapper around ProjectDiscovery's subfinder for subdomain enumeration.

    Usage:
        sf = SubfinderWrapper()
        result = sf.run("example.com")
        for sub in result["subdomains"]:
            print(sub)
    """

    def __init__(self, binary_path: Optional[str] = None, timeout: int = 300):
        super().__init__(
            binary_path=binary_path or WebScanConfig.SUBFINDER_BINARY,
            timeout=timeout,
            name="subfinder",
        )

    def run(self, target: str, **kwargs) -> Dict:
        """
        Enumerate subdomains for a domain.

        Args:
            target: Root domain (e.g., "example.com")

        Returns:
            {"subdomains": ["sub1.example.com", ...], "count": N}
        """
        self.require_available()

        output_file = self._create_temp_file(suffix=".json", prefix="subfinder_")

        args = [
            self.binary,
            "-d", target,
            "-json",
            "-silent",
            "-o", output_file,
        ]

        try:
            self._run_subprocess(args)

            with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()

            # Subfinder JSON output: one JSON object per line with "host" key
            raw_results = self._parse_jsonl(raw)
            subdomains = list(set(
                r.get("host", "").strip().lower()
                for r in raw_results
                if r.get("host", "").strip()
            ))
            subdomains.sort()

            log.info("Subfinder found %d subdomains for %s", len(subdomains), target)
            return {"subdomains": subdomains, "count": len(subdomains)}

        except Exception as exc:
            log.warning("Subfinder failed for %s: %s", target, exc)
            return {"subdomains": [], "count": 0, "error": str(exc)}
        finally:
            self._cleanup_path(output_file)
