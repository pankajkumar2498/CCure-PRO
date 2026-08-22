"""
test_nvd_sync.py
─────────────────────────────────────────────────────────────────────────────
Unit tests covering:
  1. Severity mapping — every CVSS score boundary produces a value accepted by
     the ck_vuln_def_severity_canonical DB constraint.
  2. _flush_batch resilience — bad rows are isolated; good rows are saved;
     each engine is handled independently.
  3. NVD client retry logic — 429 / 5xx cause retries; 4xx are permanent;
     exhausted retries return None.
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


def _simulate_flush(batch: list, engines: list, sql) -> tuple:
    """
    Reproduce the _flush_batch logic locally so we can unit-test it without
    importing the closure from inside the async function.
    """
    import logging

    log = logging.getLogger("test_flush")

    if not batch:
        return 0, 0

    bad_ids: set = set()

    for eng in engines:
        try:
            with eng.connect() as conn:
                conn.execute(sql, batch)
                conn.commit()
        except Exception as bulk_err:
            log.warning("Bulk failed (%s), falling back row-by-row.", bulk_err)
            for row in batch:
                try:
                    with eng.connect() as conn:
                        conn.execute(sql, [row])
                        conn.commit()
                except Exception as row_err:
                    bad_ids.add(row.get("id"))
                    log.error("Skipping %s: %s", row.get("id"), row_err)

    skipped = len(bad_ids)
    flushed = len(batch) - skipped
    return flushed, skipped


# ─── 2. _flush_batch resilience ──────────────────────────────────────────────


def test_flush_batch_all_rows_succeed():
    """Happy path: bulk upsert succeeds, flushed == len(batch), skipped == 0."""
    sql = _make_upsert_sql()
    eng = _TrackingEngine(fail_ids=set())
    batch = [{"id": f"CVE-2026-{i:04d}"} for i in range(5)]

    flushed, skipped = _simulate_flush(batch, [eng], sql)

    assert flushed == 5
    assert skipped == 0
    assert eng._conn.written == [r["id"] for r in batch]


def test_flush_batch_single_bad_row_does_not_lose_good_rows():
    """One constraint-violating row must be skipped; all others must be written."""
    good_ids = [f"CVE-2026-{i:04d}" for i in range(1, 6)]
    bad_id = "CVE-2026-BAD0"
    sql = _make_upsert_sql()
    eng = _TrackingEngine(fail_ids={bad_id})
    batch = [{"id": bid} for bid in good_ids + [bad_id]]

    flushed, skipped = _simulate_flush(batch, [eng], sql)

    assert skipped == 1, f"Expected 1 skipped, got {skipped}"
    assert flushed == len(good_ids), f"Expected {len(good_ids)} flushed, got {flushed}"
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

    flushed, skipped = _simulate_flush(batch, [eng], sql)

    assert skipped == 2
    assert flushed == len(good_ids)
    for bad in bad_ids:
        assert bad not in eng._conn.written


def test_flush_batch_engines_handled_independently():
    """
    A batch failing on engine-0 must fall back to row-by-row on engine-0 only.
    Engine-1 (clean) should also receive and accept the full batch.
    The bad row's ID must appear in bad_ids only once (set deduplication).
    """
    bad_id = "CVE-2026-MULTI"
    good_id = "CVE-2026-GOOD"
    sql = _make_upsert_sql()

    eng0 = _TrackingEngine(fail_ids={bad_id})  # engine that will reject bad_id
    eng1 = _TrackingEngine(fail_ids=set())  # clean engine, accepts everything

    batch = [{"id": good_id}, {"id": bad_id}]
    flushed, skipped = _simulate_flush(batch, [eng0, eng1], sql)

    # bad_id skipped on eng0; good_id written on eng0
    assert good_id in eng0._conn.written
    assert bad_id not in eng0._conn.written

    # eng1 gets the bulk and succeeds for both rows
    assert good_id in eng1._conn.written
    assert bad_id in eng1._conn.written  # eng1 has no constraint on bad_id

    # Reported skipped is 1 (unique bad ID), not 2
    assert skipped == 1
    assert flushed == 1  # only good_id counted as flushed (bad_id was in bad_ids)


def test_flush_batch_empty_returns_zero():
    """Empty batch must short-circuit and return (0, 0) without touching any engine."""
    sql = _make_upsert_sql()
    eng = _TrackingEngine(fail_ids=set())

    flushed, skipped = _simulate_flush([], [eng], sql)

    assert flushed == 0
    assert skipped == 0
    assert eng._conn.written == []


# ─── 3. NVD client retry logic ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_nvd_client_retries_on_429():
    """A 429 response must be retried (up to _MAX_RETRIES) before giving up."""
    from scans.cve_engine.nvd_client import NvdClient, _MAX_RETRIES

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
            result = await client._fetch_with_retry(http_client, {"startIndex": 0})

    assert result is None, "Should return None after exhausting retries"
    assert (
        call_count == _MAX_RETRIES
    ), f"Expected {_MAX_RETRIES} attempts, got {call_count}"


@pytest.mark.asyncio
async def test_nvd_client_does_not_retry_on_4xx():
    """A non-retryable 4xx (e.g. 403) must return None immediately without retrying."""
    import httpx
    from scans.cve_engine.nvd_client import NvdClient

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
            result = await client._fetch_with_retry(http_client, {"startIndex": 0})

    assert result is None
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
