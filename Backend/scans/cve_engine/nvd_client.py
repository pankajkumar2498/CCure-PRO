"""
NVD 2.0 API client with incremental sync for NIST NVD REST API.
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator, Dict, List, Optional

import httpx

from .models import (
    CveRecord,
    CvssVector,
    CpeMatch,
    CveReference,
    ReferenceTag,
)

logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000

# Transient HTTP status codes that warrant a retry.
_RETRY_STATUSES = {429, 500, 502, 503, 504}
# Maximum number of retry attempts per page request.
_MAX_RETRIES = 3
# Back-off delays (seconds) between successive retry attempts.
_RETRY_BACKOFF = [5.0, 15.0, 30.0]


class NvdClient:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self._headers = {"apiKey": self.api_key} if self.api_key else {}
        self._min_interval = 6.0 if not self.api_key else 0.65
        self._last_call = 0.0

    async def _throttle(self):
        loop_time = asyncio.get_event_loop().time()
        elapsed = loop_time - self._last_call
        if elapsed < self._min_interval:
            await asyncio.sleep(self._min_interval - elapsed)
        self._last_call = asyncio.get_event_loop().time()

    async def fetch_modified_since(
        self, since: datetime, until: Optional[datetime] = None
    ) -> AsyncIterator[CveRecord]:
        """
        Pull every CVE modified in [since, until]. NVD caps each window to 120 days.

        Each page request is retried up to _MAX_RETRIES times on transient
        failures (429, 5xx, timeouts).  Permanent errors (4xx other than 429)
        stop the iteration and are logged.
        """
        until = until or datetime.now(timezone.utc)
        start_index = 0

        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                await self._throttle()
                params: Dict[str, object] = {
                    "lastModStartDate": since.isoformat(),
                    "lastModEndDate": until.isoformat(),
                    "resultsPerPage": RESULTS_PER_PAGE,
                    "startIndex": start_index,
                }
                payload = await self._fetch_with_retry(client, params)
                if payload is None:
                    # Permanent failure or retries exhausted — abort this window.
                    break

                for item in payload.get("vulnerabilities", []):
                    record = self._parse_cve_item(item["cve"])
                    if record:
                        yield record

                total = payload.get("totalResults", 0)
                start_index += RESULTS_PER_PAGE
                if start_index >= total:
                    break

    async def _fetch_with_retry(
        self, client: httpx.AsyncClient, params: Dict[str, object]
    ) -> Optional[dict]:
        """
        GET the NVD endpoint with automatic retry for transient HTTP errors.

        Retries (up to _MAX_RETRIES) on:
          - 429 Too Many Requests  (honours ``Retry-After`` header when present)
          - 5xx server errors
          - network / timeout exceptions

        Returns the parsed JSON payload on success, or ``None`` on permanent
        failure so the caller can stop pagination gracefully.
        """
        for attempt in range(_MAX_RETRIES):
            try:
                resp = await client.get(
                    NVD_BASE_URL, params=params, headers=self._headers
                )

                if resp.status_code in _RETRY_STATUSES:
                    wait = _RETRY_BACKOFF[min(attempt, len(_RETRY_BACKOFF) - 1)]
                    if resp.status_code == 429:
                        # Honour the server's own back-off instruction if present.
                        retry_after = resp.headers.get("Retry-After")
                        if retry_after:
                            try:
                                wait = float(retry_after)
                            except ValueError:
                                pass
                    logger.warning(
                        "NVD API returned HTTP %d — retrying in %.1fs "
                        "(attempt %d/%d, startIndex=%s).",
                        resp.status_code,
                        wait,
                        attempt + 1,
                        _MAX_RETRIES,
                        params.get("startIndex"),
                    )
                    await asyncio.sleep(wait)
                    continue

                resp.raise_for_status()
                return resp.json()

            except httpx.TimeoutException as exc:
                wait = _RETRY_BACKOFF[min(attempt, len(_RETRY_BACKOFF) - 1)]
                logger.warning(
                    "NVD API request timed out — retrying in %.1fs "
                    "(attempt %d/%d): %s",
                    wait,
                    attempt + 1,
                    _MAX_RETRIES,
                    exc,
                )
                await asyncio.sleep(wait)

            except httpx.HTTPStatusError as exc:
                # Non-retryable 4xx (e.g. 403 bad API key, 400 bad params).
                logger.error(
                    "NVD API permanent HTTP error %d: %s",
                    exc.response.status_code,
                    exc,
                )
                return None

            except Exception as exc:
                logger.error("NVD API unexpected error: %s", exc)
                return None

        logger.error(
            "NVD API failed after %d retries (startIndex=%s).",
            _MAX_RETRIES,
            params.get("startIndex"),
        )
        return None

    def _parse_cve_item(self, cve_json: dict) -> Optional[CveRecord]:
        cve_id = cve_json.get("id")
        if not cve_id:
            return None

        metrics = cve_json.get("metrics", {})
        cvss = self._extract_best_cvss(metrics)
        if cvss is None:
            return None  # skip CVEs NVD hasn't scored yet

        description = next(
            (
                d["value"]
                for d in cve_json.get("descriptions", [])
                if d.get("lang") == "en"
            ),
            "",
        )

        cpe_matches = self._extract_cpe_matches(cve_json.get("configurations", []))
        references = self._extract_references(cve_json.get("references", []))
        # NVD writes "NVD-CWE-noinfo" / "NVD-CWE-Other" when no CWE was assigned.
        # Those are placeholders, not weaknesses, and storing them makes a report
        # claim a classification the feed never made. Order is preserved so the
        # primary weakness stays first.
        cwe_ids: List[str] = []
        for weakness in cve_json.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") != "en":
                    continue
                value = str(desc.get("value", "")).strip()
                if not value.upper().startswith("CWE-"):
                    continue
                if value not in cwe_ids:
                    cwe_ids.append(value)

        pub_str = cve_json.get("published", "")
        mod_str = cve_json.get("lastModified", "")
        pub_dt = (
            datetime.fromisoformat(pub_str) if pub_str else datetime.now(timezone.utc)
        )
        mod_dt = (
            datetime.fromisoformat(mod_str) if mod_str else datetime.now(timezone.utc)
        )

        return CveRecord(
            cve_id=cve_id,
            title=self._derive_title(cve_id, description, cpe_matches),
            description=description,
            published_date=pub_dt,
            last_modified_date=mod_dt,
            cvss=cvss,
            cpe_matches=cpe_matches,
            references=references,
            cwe_ids=cwe_ids,
        )

    @staticmethod
    def _extract_best_cvss(metrics: dict) -> Optional[CvssVector]:
        for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
            entries = metrics.get(key, [])
            if entries:
                d = entries[0].get("cvssData", {})
                if d:
                    return CvssVector(
                        version=version,
                        vector_string=d.get("vectorString", ""),
                        base_score=float(d.get("baseScore", 0.0)),
                        attack_vector=d.get("attackVector", "N")[0],
                        attack_complexity=d.get("attackComplexity", "L")[0],
                        privileges_required=d.get("privilegesRequired", "N")[0],
                        user_interaction=d.get("userInteraction", "N")[0],
                        scope=d.get("scope", "U")[0],
                        confidentiality=d.get("confidentialityImpact", "N")[0],
                        integrity=d.get("integrityImpact", "N")[0],
                        availability=d.get("availabilityImpact", "N")[0],
                    )
        entries = metrics.get("cvssMetricV2", [])
        if entries:
            d = entries[0].get("cvssData", {})
            if d:
                return CvssVector(
                    version="2.0",
                    vector_string=d.get("vectorString", ""),
                    base_score=float(d.get("baseScore", 0.0)),
                    attack_vector="N" if "AV:N" in d.get("vectorString", "") else "L",
                    attack_complexity="L",
                    privileges_required="N",
                    user_interaction="N",
                    scope="U",
                    confidentiality="N",
                    integrity="N",
                    availability="N",
                )
        return None

    @staticmethod
    def _extract_cpe_matches(configurations: list) -> list[CpeMatch]:
        out = []
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable", False):
                        continue
                    uri = cpe_match.get("criteria", "")
                    parts = uri.split(":")
                    vendor = parts[3] if len(parts) > 3 else "*"
                    product = parts[4] if len(parts) > 4 else "*"
                    out.append(
                        CpeMatch(
                            cpe23_uri=uri,
                            vendor=vendor,
                            product=product,
                            version_start_including=cpe_match.get(
                                "versionStartIncluding"
                            ),
                            version_start_excluding=cpe_match.get(
                                "versionStartExcluding"
                            ),
                            version_end_including=cpe_match.get("versionEndIncluding"),
                            version_end_excluding=cpe_match.get("versionEndExcluding"),
                            vulnerable=True,
                        )
                    )
        return out

    @staticmethod
    def _extract_references(refs: list) -> list[CveReference]:
        out = []
        for r in refs:
            tags = []
            for t in r.get("tags", []):
                try:
                    tags.append(ReferenceTag(t))
                except ValueError:
                    pass
            out.append(
                CveReference(url=r.get("url", ""), tags=tags, source=r.get("source"))
            )
        return out

    @staticmethod
    def _derive_title(
        cve_id: str, description: str, cpe_matches: list[CpeMatch]
    ) -> str:
        vuln_classes = [
            ("buffer overflow", "Buffer Overflow"),
            ("sql injection", "SQL Injection"),
            ("directory traversal", "Directory Traversal"),
            ("denial of service", "Denial of Service"),
            ("cross-site scripting", "Cross-Site Scripting"),
            ("format string", "Format String Vulnerability"),
            ("integer overflow", "Integer Overflow"),
            ("null pointer dereference", "NULL Pointer Dereference"),
            ("use-after-free", "Use-After-Free"),
            ("privilege escalation", "Privilege Escalation"),
            ("remote code execution", "Remote Code Execution"),
            ("information disclosure", "Information Disclosure"),
            ("authentication bypass", "Authentication Bypass"),
        ]
        desc_lower = description.lower()
        vuln_class = next(
            (label for key, label in vuln_classes if key in desc_lower),
            "Vulnerability",
        )
        if cpe_matches:
            vendor = cpe_matches[0].vendor.replace("_", " ").title()
            product = cpe_matches[0].product.replace("_", " ").title()
            return f"{vendor} {product} {vuln_class}"
        return f"{cve_id} {vuln_class}"
