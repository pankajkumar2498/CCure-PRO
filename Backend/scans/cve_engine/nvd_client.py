"""
NVD 2.0 API client with incremental sync for NIST NVD REST API.
"""

import asyncio
import os
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator, List, Optional

import httpx

from .models import (
    CveRecord,
    CvssVector,
    CpeMatch,
    CveReference,
    ReferenceTag,
)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000


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
        """
        until = until or datetime.now(timezone.utc)
        start_index = 0

        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                await self._throttle()
                params = {
                    "lastModStartDate": since.isoformat(),
                    "lastModEndDate": until.isoformat(),
                    "resultsPerPage": RESULTS_PER_PAGE,
                    "startIndex": start_index,
                }
                try:
                    resp = await client.get(
                        NVD_BASE_URL, params=params, headers=self._headers
                    )
                    resp.raise_for_status()
                    payload = resp.json()
                except Exception as e:
                    break

                for item in payload.get("vulnerabilities", []):
                    record = self._parse_cve_item(item["cve"])
                    if record:
                        yield record

                total = payload.get("totalResults", 0)
                start_index += RESULTS_PER_PAGE
                if start_index >= total:
                    break

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
