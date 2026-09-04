"""
NVD 2.0 API client with incremental sync for NIST NVD REST API.
"""

import asyncio
import logging
import os
import ssl
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator, Dict, List, Optional, Tuple

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

#: Transport failures that are retried rather than treated as permanent.
#:
#: A real 420-day backfill died on ``[SSL: WRONG_VERSION_NUMBER]`` at page 12 of
#: 187. The checkpoint held — the window was reported incomplete and the mark did
#: not move, which is what that design is for — but a momentary TLS fault should
#: not cost a window at all when the requests either side of it succeeded. Before
#: this, every connection and TLS error reached the catch-all below and was
#: permanent on its first occurrence.
#:
#: httpx wraps a handshake ``ssl.SSLError`` as ``ConnectError`` and a mid-stream
#: one as ``ReadError``, both ``NetworkError``. ``ssl.SSLError`` is listed as
#: well because an unwrapped one would otherwise reach the permanent branch, and
#: the log line the real failure produced cannot distinguish the two.
#:
#: Deliberately **not** retried, because a second identical request only repeats
#: the fault:
#:
#: * ``HTTPStatusError`` — a 4xx from NVD: a bad API key, or a window wider than
#:   ``NVD_MAX_WINDOW_DAYS``. 429 and 5xx never reach it; they are retried above
#:   by status code, where ``Retry-After`` is honoured.
#: * ``LocalProtocolError`` — *this client* built an invalid request.
#: * ``UnsupportedProtocol`` — the URL scheme is wrong. A configuration error.
#: * ``DecodingError`` / ``TooManyRedirects`` — the response is broken in a way
#:   retrying cannot change.
#:
#: The last two httpx entries are why this is an explicit tuple rather than the
#: parent ``TransportError``: ``LocalProtocolError`` and ``UnsupportedProtocol``
#: are ``TransportError`` subclasses too, and both are permanent.
_RETRYABLE_TRANSPORT_ERRORS = (
    httpx.TimeoutException,  # connect / read / write / pool timeouts
    httpx.NetworkError,  # ConnectError, ReadError, WriteError, CloseError
    httpx.RemoteProtocolError,  # server closed or framed the response badly
    httpx.ProxyError,  # an intermediary failed to establish the tunnel
    ssl.SSLError,  # any TLS error httpx did not wrap
)

#: NVD refuses a ``lastModStartDate``/``lastModEndDate`` pair spanning more than
#: 120 days. That refusal is a 4xx, which used to end pagination silently while
#: the caller still advanced its checkpoint — so asking for a year of history
#: returned nothing *and* lost the sync's place. ``split_window`` divides any
#: range into pieces the API will accept instead of failing on the whole.
NVD_MAX_WINDOW_DAYS = 120


class NvdFetchError(RuntimeError):
    """
    A modification window could not be paginated to completion.

    Raised rather than signalled by a sentinel return, and the difference is the
    caller's checkpoint. The previous contract returned ``None`` and
    ``fetch_modified_since`` answered it with a bare ``break``: an aborted window
    ended the ``async for`` normally, the sync reported SUCCESS, and
    ``nvd_sync_meta.last_sync_date`` advanced past CVEs that had never been
    fetched — which are then never requested again, because the next window
    starts after them. An exception cannot be ignored by accident. A sentinel
    can, and was.
    """

    def __init__(
        self,
        message: str,
        *,
        start_index: Optional[int] = None,
        status_code: Optional[int] = None,
        window_start: Optional[str] = None,
        window_end: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.start_index = start_index
        self.status_code = status_code
        self.window_start = window_start
        self.window_end = window_end


def split_window(
    since: datetime, until: datetime, max_days: int = NVD_MAX_WINDOW_DAYS
) -> List[Tuple[datetime, datetime]]:
    """
    Divide ``[since, until]`` into consecutive pieces NVD will accept.

    Adjacent pieces **share** their boundary instant rather than abutting it.
    NVD treats both bounds as inclusive, so an overlap re-fetches at most one
    record — an idempotent upsert — whereas a gap silently loses every CVE
    modified in the instant between two windows.
    """
    if until <= since:
        return []
    span = timedelta(days=max(1, int(max_days)))
    windows: List[Tuple[datetime, datetime]] = []
    start = since
    while start < until:
        end = min(start + span, until)
        windows.append((start, end))
        start = end
    return windows


def _first_letter(value: object, default: str) -> str:
    """
    First character of an NVD enum value, or ``default`` when there is none.

    ``d.get("attackVector", "N")[0]`` raises IndexError when the key is present
    but empty — the default only covers an *absent* key, not an empty one.
    """
    text = str(value or "").strip()
    return text[0] if text else default


def _window_of(params: Dict[str, object]) -> Tuple[Optional[str], Optional[str]]:
    """The requested window, for an error message that names what was lost."""
    start = params.get("lastModStartDate")
    end = params.get("lastModEndDate")
    return (str(start) if start else None, str(end) if end else None)


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
        Pull every CVE modified in [since, until]. NVD caps each window to
        ``NVD_MAX_WINDOW_DAYS``; use ``split_window`` for anything longer.

        Each page request is retried up to _MAX_RETRIES times on transient
        failures (429, 5xx, timeouts). Anything that cannot be retrieved raises
        ``NvdFetchError`` — the generator never ends early and quietly, because
        exhausting it is the only signal the caller has that the window is
        complete and its checkpoint may advance.
        """
        until = until or datetime.now(timezone.utc)
        start_index = 0
        pages = 0

        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                await self._throttle()
                params: Dict[str, object] = {
                    "lastModStartDate": since.isoformat(),
                    "lastModEndDate": until.isoformat(),
                    "resultsPerPage": RESULTS_PER_PAGE,
                    "startIndex": start_index,
                }
                # Raises NvdFetchError rather than returning a sentinel: an
                # incomplete window must not be able to look like a finished one.
                payload = await self._fetch_with_retry(client, params)
                pages += 1

                for item in payload.get("vulnerabilities", []):
                    record = self._parse_cve_item(item["cve"])
                    if record:
                        yield record

                total = payload.get("totalResults", 0)
                start_index += RESULTS_PER_PAGE
                if start_index >= total:
                    break

        logger.debug(
            "NVD window %s..%s paginated to completion (%d page(s)).",
            since.isoformat(),
            until.isoformat(),
            pages,
        )

    async def _fetch_with_retry(
        self, client: httpx.AsyncClient, params: Dict[str, object]
    ) -> dict:
        """
        GET the NVD endpoint with automatic retry for transient HTTP errors.

        Retries (up to _MAX_RETRIES) on:
          - 429 Too Many Requests  (honours ``Retry-After`` header when present)
          - 5xx server errors
          - network / timeout exceptions

        Returns the parsed JSON payload. Raises ``NvdFetchError`` on a permanent
        failure or once the retries are exhausted — never a sentinel, because
        the caller's sync checkpoint is decided by whether this page arrived.
        """
        last_transport_error: Optional[BaseException] = None

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

            except _RETRYABLE_TRANSPORT_ERRORS as exc:
                last_transport_error = exc
                wait = _RETRY_BACKOFF[min(attempt, len(_RETRY_BACKOFF) - 1)]
                logger.warning(
                    "NVD API transport failure (%s: %s) — retrying in %.1fs "
                    "(attempt %d/%d, startIndex=%s).",
                    type(exc).__name__,
                    exc,
                    wait,
                    attempt + 1,
                    _MAX_RETRIES,
                    params.get("startIndex"),
                )
                await asyncio.sleep(wait)

            except httpx.HTTPStatusError as exc:
                # Non-retryable 4xx: 403 for a bad API key, 400/404 for a window
                # wider than NVD_MAX_WINDOW_DAYS. Both used to end the window
                # silently; both now stop the caller advancing past it.
                window_start, window_end = _window_of(params)
                logger.error(
                    "NVD API permanent HTTP error %d for window %s..%s "
                    "(startIndex=%s): %s",
                    exc.response.status_code,
                    window_start,
                    window_end,
                    params.get("startIndex"),
                    exc,
                )
                raise NvdFetchError(
                    f"NVD API permanent HTTP error {exc.response.status_code}",
                    start_index=params.get("startIndex"),
                    status_code=exc.response.status_code,
                    window_start=window_start,
                    window_end=window_end,
                ) from exc

            except Exception as exc:
                window_start, window_end = _window_of(params)
                logger.error(
                    "NVD API unexpected error for window %s..%s (startIndex=%s): %s",
                    window_start,
                    window_end,
                    params.get("startIndex"),
                    exc,
                )
                raise NvdFetchError(
                    f"NVD API unexpected error: {exc}",
                    start_index=params.get("startIndex"),
                    window_start=window_start,
                    window_end=window_end,
                ) from exc

        window_start, window_end = _window_of(params)
        # Name the fault that exhausted the retries. Before connection and TLS
        # errors were retryable the catch-all reported them verbatim, which is
        # how the SSL failure on the real backfill was identified at all;
        # folding them into the retry loop without carrying the cause here would
        # replace that with a bare "failed after 3 retries".
        cause = (
            f": last error was {type(last_transport_error).__name__}: "
            f"{last_transport_error}"
            if last_transport_error is not None
            else ""
        )
        logger.error(
            "NVD API failed after %d retries for window %s..%s (startIndex=%s)%s.",
            _MAX_RETRIES,
            window_start,
            window_end,
            params.get("startIndex"),
            cause,
        )
        raise NvdFetchError(
            f"NVD API failed after {_MAX_RETRIES} retries{cause}",
            start_index=params.get("startIndex"),
            window_start=window_start,
            window_end=window_end,
        ) from last_transport_error

    def _parse_cve_item(self, cve_json: dict) -> Optional[CveRecord]:
        cve_id = cve_json.get("id")
        if not cve_id:
            return None

        metrics = cve_json.get("metrics", {})
        cvss = self._extract_best_cvss(metrics)
        cvss_v4 = self._extract_cvss_v40(metrics)
        if cvss is None:
            # A CVE carrying only CVSS 4.0 metrics *is* scored — just not in a
            # revision the selection above knows. Returning None here discarded
            # the whole record, and unlike a genuinely unanalysed CVE it never
            # recovered: re-fetching yields the same v4-only metrics and drops
            # it again, every run, forever.
            cvss = cvss_v4
        if cvss is None:
            return None  # genuinely unscored — NVD has not analysed it yet

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
            cvss_v4=cvss_v4,
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
    def _extract_cvss_v40(metrics: dict) -> Optional[CvssVector]:
        """
        The CVSS 4.0 metric, when NVD publishes one.

        Deliberately a separate method rather than another branch inside
        ``_extract_best_cvss``: that function's v3.1 → v3.0 → v2.0 order decides
        which score every catalogue row already reports, and re-ordering it would
        silently rewrite scores across the estate. This is additive — the v4
        score is stored beside the primary one, and only *becomes* the primary
        score for a CVE that has no other.

        Two mappings are not one-to-one, and are recorded here rather than left
        for a reader to infer from the field names:

        * **CVSS 4.0 has no Scope.** v3's Scope=Changed was replaced by explicit
          subsequent-system impacts, so ``scope`` is derived: "C" when the
          vulnerability reaches anything beyond the vulnerable system, else "U".
        * **The impact fields are the vulnerable-system ones** (VC/VI/VA). The
          subsequent-system impacts feed the scope derivation above and nothing
          else, because the model's three impact fields describe one system.
        """
        entries = metrics.get("cvssMetricV40", [])
        if not entries:
            return None
        d = entries[0].get("cvssData", {})
        if not d:
            return None

        subsequent = (
            _first_letter(d.get("subConfidentialityImpact"), "N"),
            _first_letter(d.get("subIntegrityImpact"), "N"),
            _first_letter(d.get("subAvailabilityImpact"), "N"),
        )
        return CvssVector(
            version="4.0",
            vector_string=d.get("vectorString", ""),
            base_score=float(d.get("baseScore", 0.0)),
            attack_vector=_first_letter(d.get("attackVector"), "N"),
            attack_complexity=_first_letter(d.get("attackComplexity"), "L"),
            privileges_required=_first_letter(d.get("privilegesRequired"), "N"),
            user_interaction=_first_letter(d.get("userInteraction"), "N"),
            scope="C" if any(x != "N" for x in subsequent) else "U",
            confidentiality=_first_letter(d.get("vulnConfidentialityImpact"), "N"),
            integrity=_first_letter(d.get("vulnIntegrityImpact"), "N"),
            availability=_first_letter(d.get("vulnAvailabilityImpact"), "N"),
        )

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
