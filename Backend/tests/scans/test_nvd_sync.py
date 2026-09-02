"""
test_nvd_sync.py
─────────────────────────────────────────────────────────────────────────────
Unit tests covering:
  1. Severity mapping — every CVSS score boundary produces a value accepted by
     the ck_vuln_def_severity_canonical DB constraint.
  2. _flush_batch resilience — bad rows are isolated, good rows are saved, and
     a wholesale failure is reported as fatal rather than as bad data.
  3. NVD client retry logic — 429 / 5xx cause retries; 4xx are permanent;
     exhausted retries raise NvdFetchError.
  4. Telemetry — _SYNC_STATE exposes cves_skipped; lock helper is usable.
"""

from __future__ import annotations

import asyncio
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from db.models.findings import SEVERITY_VALUES
from scans.cvss import severity_from_score


# ─── 1. Severity mapping ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "score,expected",
    [
        (9.8, "critical"),
        (9.0, "critical"),
        (8.5, "high"),
        (7.0, "high"),
        (6.5, "medium"),
        (4.0, "medium"),
        (3.5, "low"),
        (0.1, "low"),
        (0.0, "none"),
        (None, "unscored"),
    ],
)
def test_severity_from_score_maps_to_canonical_db_values(score, expected):
    """Every CVSS boundary must map to a value accepted by ck_vuln_def_severity_canonical."""
    mapped = severity_from_score(score).lower()
    assert mapped == expected, f"Score {score!r} → {mapped!r}, expected {expected!r}"
    assert (
        mapped in SEVERITY_VALUES
    ), f"Mapped severity {mapped!r} is not in SEVERITY_VALUES ({SEVERITY_VALUES})"


def test_severity_from_score_never_returns_info():
    """'info' is not a valid DB severity and must never be produced."""
    for score in [9.8, 7.0, 4.0, 0.1, 0.0, None]:
        mapped = severity_from_score(score).lower()
        assert mapped != "info", (
            f"severity_from_score({score!r}).lower() returned 'info' "
            "which violates ck_vuln_def_severity_canonical"
        )


# ─── Shared test helpers for _flush_batch ─────────────────────────────────────


class _TrackingConn:
    """Fake connection that records successful writes and raises on bad IDs."""

    def __init__(self, fail_ids: set):
        self._fail_ids = fail_ids
        self.written: List[str] = []

    def execute(self, sql, params):
        for row in params:
            if row.get("id") in self._fail_ids:
                raise Exception(f"CheckViolation on {row['id']}")
            self.written.append(row["id"])

    def commit(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


class _TrackingEngine:
    def __init__(self, fail_ids: set):
        self._conn = _TrackingConn(fail_ids)

    def connect(self):
        return self._conn


def _make_upsert_sql():
    from sqlalchemy import text

    return text("SELECT 1")  # content irrelevant for unit tests


# `_flush_batch` used to be a closure inside the async sync function, so this
# file carried a hand-written copy of its logic and tested that. The copy is why
# nothing caught the accounting defect it had: `bad_ids` was shared across the
# two write targets, so a row committed to the application catalogue but
# rejected by the second database counted as skipped. It is a module-level
# function now and the tests call it directly.
from scans.nvd_sync import _flush_batch  # noqa: E402


# ─── 2. _flush_batch resilience ──────────────────────────────────────────────


def test_flush_batch_all_rows_succeed():
    """Happy path: bulk upsert succeeds, flushed == len(batch), skipped == 0."""
    sql = _make_upsert_sql()
    eng = _TrackingEngine(fail_ids=set())
    batch = [{"id": f"CVE-2026-{i:04d}"} for i in range(5)]

    flushed, skipped, fatal = _flush_batch(eng, batch, sql)

    assert flushed == 5
    assert skipped == 0
    assert fatal is False
    assert eng._conn.written == [r["id"] for r in batch]


def test_flush_batch_single_bad_row_does_not_lose_good_rows():
    """One constraint-violating row must be skipped; all others must be written."""
    good_ids = [f"CVE-2026-{i:04d}" for i in range(1, 6)]
    bad_id = "CVE-2026-BAD0"
    sql = _make_upsert_sql()
    eng = _TrackingEngine(fail_ids={bad_id})
    batch = [{"id": bid} for bid in good_ids + [bad_id]]

    flushed, skipped, fatal = _flush_batch(eng, batch, sql)

    assert skipped == 1, f"Expected 1 skipped, got {skipped}"
    assert flushed == len(good_ids), f"Expected {len(good_ids)} flushed, got {flushed}"
    assert fatal is False, "Isolated bad data must not block the checkpoint"
    assert bad_id not in eng._conn.written
    for gid in good_ids:
        assert gid in eng._conn.written, f"{gid} was not written"


def test_flush_batch_multiple_bad_rows():
    """Multiple bad rows in the same batch are each individually skipped."""
    bad_ids = {"CVE-2026-BAD1", "CVE-2026-BAD2"}
    good_ids = [f"CVE-2026-{i:04d}" for i in range(3)]
    sql = _make_upsert_sql()
    eng = _TrackingEngine(fail_ids=bad_ids)
    batch = [{"id": bid} for bid in good_ids] + [{"id": b} for b in bad_ids]

    flushed, skipped, fatal = _flush_batch(eng, batch, sql)

    assert skipped == 2
    assert flushed == len(good_ids)
    assert fatal is False
    for bad in bad_ids:
        assert bad not in eng._conn.written


def test_flush_batch_reports_wholesale_failure_as_fatal():
    """
    Every row failing is a database problem, not bad data, and must be told
    apart from it — the checkpoint may advance over rows Postgres rejected on
    their content, because re-fetching them can only produce the same
    rejection, but never over rows that were never stored at all.
    """
    sql = _make_upsert_sql()
    ids = [f"CVE-2026-{i:04d}" for i in range(4)]
    eng = _TrackingEngine(fail_ids=set(ids))
    batch = [{"id": i} for i in ids]

    flushed, skipped, fatal = _flush_batch(eng, batch, sql)

    assert flushed == 0
    assert skipped == len(ids)
    assert fatal is True, "A batch that saved nothing must be reported as fatal"


def test_flush_batch_empty_returns_zero():
    """Empty batch must short-circuit and return (0, 0) without touching any engine."""
    sql = _make_upsert_sql()
    eng = _TrackingEngine(fail_ids=set())

    flushed, skipped, fatal = _flush_batch(eng, [], sql)

    assert flushed == 0
    assert skipped == 0
    assert fatal is False
    assert eng._conn.written == []


# ─── 3. NVD client retry logic ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_nvd_client_retries_on_429():
    """A 429 response must be retried (up to _MAX_RETRIES), then raise."""
    from scans.cve_engine.nvd_client import NvdClient, NvdFetchError, _MAX_RETRIES

    client = NvdClient(api_key="test-key")

    mock_resp_429 = MagicMock()
    mock_resp_429.status_code = 429
    mock_resp_429.headers = {}

    call_count = 0

    async def fake_get(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return mock_resp_429

    with patch("asyncio.sleep", new_callable=AsyncMock):
        async with __import__("httpx").AsyncClient() as http_client:
            http_client.get = fake_get
            with pytest.raises(NvdFetchError) as excinfo:
                await client._fetch_with_retry(http_client, {"startIndex": 0})

    # Exhausted retries must raise, not return a sentinel. Returning None let
    # `fetch_modified_since` break out of pagination normally, which the sync
    # could not tell from a finished window — so it advanced its checkpoint
    # past CVEs it had never fetched.
    assert excinfo.value.start_index == 0
    assert (
        call_count == _MAX_RETRIES
    ), f"Expected {_MAX_RETRIES} attempts, got {call_count}"


@pytest.mark.asyncio
async def test_nvd_client_does_not_retry_on_4xx():
    """A non-retryable 4xx (e.g. 403) must raise immediately without retrying."""
    import httpx
    from scans.cve_engine.nvd_client import NvdClient, NvdFetchError

    client = NvdClient(api_key="test-key")
    call_count = 0

    async def fake_get(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        mock_request = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 403
        raise httpx.HTTPStatusError(
            "403 Forbidden", request=mock_request, response=mock_response
        )

    with patch("asyncio.sleep", new_callable=AsyncMock):
        async with httpx.AsyncClient() as http_client:
            http_client.get = fake_get
            with pytest.raises(NvdFetchError) as excinfo:
                await client._fetch_with_retry(http_client, {"startIndex": 0})

    assert excinfo.value.status_code == 403
    assert (
        call_count == 1
    ), f"Non-retryable error should not retry; got {call_count} calls"


@pytest.mark.asyncio
async def test_nvd_client_succeeds_after_transient_error():
    """A 500 on attempt-1 followed by a 200 on attempt-2 must return the payload."""
    import httpx
    from scans.cve_engine.nvd_client import NvdClient

    client = NvdClient(api_key="test-key")
    attempt = 0

    async def fake_get(*args, **kwargs):
        nonlocal attempt
        attempt += 1
        if attempt == 1:
            mock_resp = MagicMock()
            mock_resp.status_code = 500
            mock_resp.headers = {}
            return mock_resp
        # Second attempt succeeds
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(
            return_value={"vulnerabilities": [], "totalResults": 0}
        )
        return mock_resp

    with patch("asyncio.sleep", new_callable=AsyncMock):
        async with httpx.AsyncClient() as http_client:
            http_client.get = fake_get
            result = await client._fetch_with_retry(http_client, {"startIndex": 0})

    assert result is not None
    assert result == {"vulnerabilities": [], "totalResults": 0}
    assert attempt == 2


# â”€â”€â”€ 3b. Transient connection / TLS errors are retried â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#
# A real 420-day backfill died at page 12 of 187 on
# `[SSL: WRONG_VERSION_NUMBER]`. The checkpoint correctly held, but the window
# was lost to a fault that cleared by itself â€” the requests either side of it
# succeeded. These pin the classification rather than the symptom.


def _always_raising_client(exc):
    """An httpx client whose every request raises `exc`, counting attempts."""
    calls = {"n": 0}

    async def fake_get(*_args, **_kwargs):
        calls["n"] += 1
        raise exc

    return fake_get, calls


@pytest.mark.parametrize(
    "exc",
    [
        __import__("httpx").ConnectError("connection refused"),
        __import__("httpx").ReadError("connection reset by peer"),
        __import__("httpx").RemoteProtocolError("server disconnected"),
        __import__("httpx").ProxyError("tunnel failed"),
        __import__("httpx").ConnectError(
            "[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1016)"
        ),
        __import__("ssl").SSLError(
            "[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1016)"
        ),
    ],
    ids=["connect", "read", "remote-protocol", "proxy", "tls-wrapped", "tls-raw"],
)
@pytest.mark.asyncio
async def test_transient_transport_errors_are_retried(exc):
    """Each of these clears by itself; one occurrence must not cost the window."""
    import httpx
    from scans.cve_engine.nvd_client import NvdClient, NvdFetchError, _MAX_RETRIES

    client = NvdClient(api_key="test-key")
    fake_get, calls = _always_raising_client(exc)

    with patch("asyncio.sleep", new_callable=AsyncMock):
        async with httpx.AsyncClient() as http_client:
            http_client.get = fake_get
            with pytest.raises(NvdFetchError):
                await client._fetch_with_retry(http_client, {"startIndex": 0})

    assert calls["n"] == _MAX_RETRIES, (
        f"{type(exc).__name__} should be retried {_MAX_RETRIES} times, "
        f"got {calls['n']} attempt(s)"
    )


@pytest.mark.asyncio
async def test_client_recovers_when_a_transient_tls_error_clears():
    """Retry succeeding must return the page, not merely fail more slowly."""
    import httpx
    from scans.cve_engine.nvd_client import NvdClient

    client = NvdClient(api_key="test-key")
    attempt = 0

    async def fake_get(*_args, **_kwargs):
        nonlocal attempt
        attempt += 1
        if attempt == 1:
            raise httpx.ConnectError("[SSL: WRONG_VERSION_NUMBER] wrong version number")
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        resp.raise_for_status = MagicMock()
        resp.json = MagicMock(return_value={"vulnerabilities": [], "totalResults": 0})
        return resp

    with patch("asyncio.sleep", new_callable=AsyncMock):
        async with httpx.AsyncClient() as http_client:
            http_client.get = fake_get
            result = await client._fetch_with_retry(http_client, {"startIndex": 0})

    assert result == {"vulnerabilities": [], "totalResults": 0}
    assert attempt == 2


@pytest.mark.parametrize(
    "exc,label",
    [
        (__import__("httpx").LocalProtocolError("illegal header"), "local-protocol"),
        (__import__("httpx").UnsupportedProtocol("unknown scheme"), "unsupported"),
    ],
    ids=["local-protocol", "unsupported-protocol"],
)
@pytest.mark.asyncio
async def test_permanent_transport_errors_are_not_retried(exc, label):
    """
    Both are `TransportError` subclasses, which is why the retryable set is an
    explicit tuple and not the parent class. A malformed request this client
    built, or a wrong URL scheme, is repeated verbatim by a retry.
    """
    import httpx
    from scans.cve_engine.nvd_client import NvdClient, NvdFetchError

    client = NvdClient(api_key="test-key")
    fake_get, calls = _always_raising_client(exc)

    with patch("asyncio.sleep", new_callable=AsyncMock):
        async with httpx.AsyncClient() as http_client:
            http_client.get = fake_get
            with pytest.raises(NvdFetchError):
                await client._fetch_with_retry(http_client, {"startIndex": 0})

    assert calls["n"] == 1, f"{label} is permanent and must not be retried"


def test_retryable_set_excludes_permanent_errors():
    """The classification itself, asserted rather than left to the handlers."""
    import httpx
    from scans.cve_engine.nvd_client import _RETRYABLE_TRANSPORT_ERRORS

    for permanent in (
        httpx.HTTPStatusError,
        httpx.LocalProtocolError,
        httpx.UnsupportedProtocol,
        httpx.DecodingError,
        httpx.TooManyRedirects,
    ):
        assert not issubclass(
            permanent, _RETRYABLE_TRANSPORT_ERRORS
        ), f"{permanent.__name__} is permanent â€” retrying only repeats the fault"

    for transient in (
        httpx.ConnectError,
        httpx.ReadError,
        httpx.WriteError,
        httpx.ConnectTimeout,
        httpx.ReadTimeout,
        httpx.RemoteProtocolError,
        httpx.ProxyError,
    ):
        assert issubclass(
            transient, _RETRYABLE_TRANSPORT_ERRORS
        ), f"{transient.__name__} clears by itself and should be retried"


@pytest.mark.asyncio
async def test_exhausted_transport_retries_name_the_cause():
    """
    Folding connection errors into the retry loop must not cost the diagnostic
    the catch-all used to give. "failed after 3 retries" alone would not have
    identified the TLS fault on the real backfill.
    """
    import httpx
    from scans.cve_engine.nvd_client import NvdClient, NvdFetchError

    client = NvdClient(api_key="test-key")
    fake_get, _ = _always_raising_client(
        httpx.ConnectError("[SSL: WRONG_VERSION_NUMBER] wrong version number")
    )

    with patch("asyncio.sleep", new_callable=AsyncMock):
        async with httpx.AsyncClient() as http_client:
            http_client.get = fake_get
            with pytest.raises(NvdFetchError) as excinfo:
                await client._fetch_with_retry(http_client, {"startIndex": 4000})

    message = str(excinfo.value)
    assert "WRONG_VERSION_NUMBER" in message
    assert "ConnectError" in message
    assert excinfo.value.start_index == 4000


@pytest.mark.asyncio
async def test_retry_after_header_is_still_honoured():
    """The 429 path is untouched by the transport-error change."""
    import httpx
    from scans.cve_engine.nvd_client import NvdClient, NvdFetchError

    client = NvdClient(api_key="test-key")
    resp = MagicMock()
    resp.status_code = 429
    resp.headers = {"Retry-After": "1"}

    async def fake_get(*_args, **_kwargs):
        return resp

    sleeper = AsyncMock()
    with patch("asyncio.sleep", sleeper):
        async with httpx.AsyncClient() as http_client:
            http_client.get = fake_get
            with pytest.raises(NvdFetchError):
                await client._fetch_with_retry(http_client, {"startIndex": 0})

    waits = [call.args[0] for call in sleeper.call_args_list]
    assert waits and all(
        w == 1.0 for w in waits
    ), f"Retry-After: 1 must drive the back-off, got {waits}"


# ─── 4. Telemetry & lock ─────────────────────────────────────────────────────


def test_sync_state_has_required_telemetry_keys():
    """_SYNC_STATE must expose all keys the Admin API depends on."""
    from scans.nvd_sync import _SYNC_STATE

    required = {
        "status",
        "last_sync_start",
        "last_sync_finish",
        "cves_added",
        "cves_skipped",
        "last_error",
    }
    missing = required - set(_SYNC_STATE.keys())
    assert not missing, f"_SYNC_STATE is missing keys: {missing}"


def test_get_sync_lock_returns_asyncio_lock():
    """_get_sync_lock must return an asyncio.Lock (lazily created, idempotent)."""
    # Reset for test isolation
    import scans.nvd_sync as mod

    mod._SYNC_LOCK = None

    from scans.nvd_sync import _get_sync_lock

    lock1 = _get_sync_lock()
    lock2 = _get_sync_lock()

    assert isinstance(lock1, asyncio.Lock)
    assert lock1 is lock2, "_get_sync_lock must return the same instance"
