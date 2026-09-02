"""
test_nvd_checkpoint.py
─────────────────────────────────────────────────────────────────────────────
The NVD sync's checkpoint, window splitting, backfill mode and write target.

The defect these exist for: `_fetch_with_retry` returned None on a permanent
error or exhausted retries, `fetch_modified_since` answered that with a bare
`break`, and the sync's `finally` advanced `nvd_sync_meta.last_sync_date`
regardless. An aborted window therefore logged `status=SUCCESS` and the next run
started *after* CVEs that had never been fetched — which are never requested
again, because nothing revisits a window behind the checkpoint.

Every test here drives the real `sync_nvd_to_vuln_intel` against a fake engine
and a fake client, so the assertions are about the shipped control flow rather
than a reimplementation of it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import pytest

from scans.cve_engine.models import CveRecord, CvssVector
from scans.cve_engine.nvd_client import NVD_MAX_WINDOW_DAYS, NvdFetchError, split_window


# ── Fakes ─────────────────────────────────────────────────────────────────────


class _Result:
    def __init__(self, row=None, scalar=None):
        self._row = row
        self._scalar = scalar

    def fetchone(self):
        return self._row

    def scalar(self):
        return self._scalar


class _Store:
    """Everything the fake engine remembers, so a test can assert on it."""

    def __init__(self, checkpoint: Optional[str] = None, reject_ids=None):
        self.rows: Dict[str, Dict[str, Any]] = {}
        self.checkpoint = checkpoint
        self.checkpoint_writes = 0
        self.reject_ids = set(reject_ids or ())
        self.statements: List[str] = []


class _Conn:
    def __init__(self, store: _Store):
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def commit(self):
        pass

    def execute(self, sql, params=None):
        q = " ".join(str(sql).split())
        self.store.statements.append(q)

        if "SELECT value FROM nvd_sync_meta" in q:
            row = (self.store.checkpoint,) if self.store.checkpoint else None
            return _Result(row=row)

        if "INSERT INTO nvd_sync_meta" in q:
            self.store.checkpoint = params["val"]
            self.store.checkpoint_writes += 1
            return _Result()

        if "COUNT(*)" in q:
            return _Result(scalar=len(self.store.rows))

        if "INSERT INTO vulnerability_definitions" in q:
            rows = params if isinstance(params, list) else [params]
            for row in rows:
                if row["id"] in self.store.reject_ids:
                    raise RuntimeError(f"CheckViolation on {row['id']}")
                self.store.rows[row["id"]] = row
            return _Result()

        return _Result()


class _Engine:
    def __init__(self, store: _Store):
        self.store = store

    def connect(self):
        return _Conn(self.store)


def _client_class(plan: List[Tuple[List[CveRecord], Optional[Exception]]]):
    """
    A stand-in for ``NvdClient``.

    ``plan`` carries one entry per window the sync is expected to open: the
    records that window yields, and an exception to raise afterwards (or None
    for a window that paginates to completion).
    """
    captured: List[Any] = []

    class _Client:
        def __init__(self, *_args, **_kwargs):
            self.windows: List[Tuple[datetime, datetime]] = []
            captured.append(self)

        def fetch_modified_since(self, since, until=None):
            index = len(self.windows)
            self.windows.append((since, until))
            records, error = plan[index] if index < len(plan) else ([], None)

            async def _gen():
                for record in records:
                    yield record
                if error is not None:
                    raise error

            return _gen()

    return _Client, captured


def _record(cve_id: str, score: float = 7.5, version: str = "3.1") -> CveRecord:
    now = datetime(2026, 8, 1, tzinfo=timezone.utc)
    return CveRecord(
        cve_id=cve_id,
        title=f"{cve_id} title",
        description="description",
        published_date=now,
        last_modified_date=now,
        cvss=CvssVector(
            version=version,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_score=score,
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        ),
    )


def _fetch_error(start_index: int = 2000, message: str = "boom") -> NvdFetchError:
    return NvdFetchError(message, start_index=start_index, status_code=403)


@pytest.fixture(autouse=True)
def _reset_sync_state():
    """The sync state is a module global; a leaked SYNCING wedges every test."""
    from scans.nvd_sync import _SYNC_STATE

    _SYNC_STATE["status"] = "IDLE"
    yield
    _SYNC_STATE["status"] = "IDLE"


def _install(monkeypatch, store: _Store, plan):
    import scans.nvd_sync as ns

    client_cls, captured = _client_class(plan)
    monkeypatch.setattr(ns, "NvdClient", client_cls)
    monkeypatch.setattr(ns, "_catalogue_engine", lambda: _Engine(store))
    return captured


# ── Checkpoint ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_successful_sync_advances_checkpoint(monkeypatch):
    from scans.nvd_sync import sync_nvd_to_vuln_intel

    started = datetime.now(timezone.utc) - timedelta(days=2)
    store = _Store(checkpoint=started.isoformat())
    captured = _install(monkeypatch, store, [([_record("CVE-2026-0001")], None)])

    state = await sync_nvd_to_vuln_intel()

    assert state["status"] == "SUCCESS"
    assert state["pagination_complete"] is True
    assert store.checkpoint_writes == 1
    assert "CVE-2026-0001" in store.rows
    # The mark advances to the window's own end, not to "now" — anything
    # modified while the run was in flight stays inside the next window.
    window_end = captured[0].windows[0][1]
    assert store.checkpoint == window_end.isoformat()


@pytest.mark.asyncio
async def test_page_failure_does_not_advance_checkpoint(monkeypatch):
    """The defect this file exists for, in its original shape."""
    from scans.nvd_sync import sync_nvd_to_vuln_intel

    original = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    store = _Store(checkpoint=original)
    _install(monkeypatch, store, [([_record("CVE-2026-0001")], _fetch_error())])

    state = await sync_nvd_to_vuln_intel()

    assert store.checkpoint == original, "An aborted window must not move the mark"
    assert store.checkpoint_writes == 0
    assert state["status"] != "SUCCESS"
    assert state["pagination_complete"] is False


@pytest.mark.asyncio
async def test_retry_exhaustion_does_not_advance_checkpoint(monkeypatch):
    from scans.nvd_sync import sync_nvd_to_vuln_intel

    original = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    store = _Store(checkpoint=original)
    _install(
        monkeypatch,
        store,
        [([], _fetch_error(start_index=0, message="failed after 3 retries"))],
    )

    state = await sync_nvd_to_vuln_intel()

    assert store.checkpoint == original
    assert store.checkpoint_writes == 0
    assert state["status"] == "FAILED", "Nothing fetched and nothing saved is a failure"
    assert "failed after 3 retries" in (state["last_error"] or "")


@pytest.mark.asyncio
async def test_incomplete_window_is_never_reported_as_success(monkeypatch):
    from scans.nvd_sync import sync_nvd_to_vuln_intel

    store = _Store()
    _install(monkeypatch, store, [([_record("CVE-2026-0002")], _fetch_error())])

    state = await sync_nvd_to_vuln_intel()

    assert state["status"] == "PARTIAL", "Records were saved, so not FAILED"
    assert state["pagination_complete"] is False
    assert state["last_error"], "The failure must be named, not merely implied"


@pytest.mark.asyncio
async def test_records_fetched_before_the_failure_are_still_persisted(monkeypatch):
    """A window that broke halfway is still worth what it retrieved."""
    from scans.nvd_sync import sync_nvd_to_vuln_intel

    store = _Store()
    records = [_record(f"CVE-2026-{i:04d}") for i in range(5)]
    _install(monkeypatch, store, [(records, _fetch_error())])

    await sync_nvd_to_vuln_intel()

    assert len(store.rows) == 5
    assert store.checkpoint_writes == 0


@pytest.mark.asyncio
async def test_fatal_persistence_failure_does_not_advance_checkpoint(monkeypatch):
    """
    Pagination completing is not enough — the records have to have landed.
    Every row failing is an unreachable or mis-migrated database, and advancing
    over it loses CVEs nothing ever stored.
    """
    from scans.nvd_sync import sync_nvd_to_vuln_intel

    original = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    ids = [f"CVE-2026-{i:04d}" for i in range(3)]
    store = _Store(checkpoint=original, reject_ids=ids)
    _install(monkeypatch, store, [([_record(i) for i in ids], None)])

    state = await sync_nvd_to_vuln_intel()

    assert store.checkpoint == original
    assert store.checkpoint_writes == 0
    assert state["status"] == "FAILED"


@pytest.mark.asyncio
async def test_isolated_bad_row_still_advances_checkpoint(monkeypatch):
    """
    The deliberate other half of the rule above. A row Postgres rejects on its
    content will be rejected identically on every retry, so refusing to advance
    would wedge the sync on it permanently. It is counted, reported as PARTIAL,
    and the window still closes.
    """
    from scans.nvd_sync import sync_nvd_to_vuln_intel

    store = _Store(reject_ids={"CVE-2026-BAD0"})
    records = [_record("CVE-2026-0001"), _record("CVE-2026-BAD0")]
    _install(monkeypatch, store, [(records, None)])

    state = await sync_nvd_to_vuln_intel()

    assert state["status"] == "PARTIAL"
    assert state["cves_skipped"] == 1
    assert store.checkpoint_writes == 1
    assert "CVE-2026-0001" in store.rows


@pytest.mark.asyncio
async def test_multi_window_advances_only_the_completed_windows(monkeypatch):
    """
    A long catch-up is several requests. Each one that completes is progress
    worth keeping, and the first that fails stops the run — going on would
    leave a hole behind the checkpoint that nothing revisits.
    """
    from scans.nvd_sync import sync_nvd_to_vuln_intel

    since = datetime.now(timezone.utc) - timedelta(days=300)
    store = _Store(checkpoint=since.isoformat())
    plan = [
        ([_record("CVE-2026-0001")], None),
        ([_record("CVE-2026-0002")], _fetch_error()),
        ([_record("CVE-2026-0003")], None),  # must never be requested
    ]
    captured = _install(monkeypatch, store, plan)

    state = await sync_nvd_to_vuln_intel()

    client = captured[0]
    assert len(client.windows) == 2, "The run must stop at the first failed window"
    assert store.checkpoint_writes == 1
    assert store.checkpoint == client.windows[0][1].isoformat()
    assert state["windows_completed"] == 1
    assert state["windows_total"] == 3
    assert "CVE-2026-0003" not in store.rows


# ── Window splitting ─────────────────────────────────────────────────────────


def test_split_window_respects_the_api_maximum():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = start + timedelta(days=365)

    windows = split_window(start, end, NVD_MAX_WINDOW_DAYS)

    assert len(windows) == 4
    assert all(
        (w_end - w_start) <= timedelta(days=NVD_MAX_WINDOW_DAYS)
        for w_start, w_end in windows
    )
    assert windows[0][0] == start
    assert windows[-1][1] == end


def test_split_window_pieces_share_their_boundary():
    """NVD's bounds are inclusive: an overlap re-upserts one row, a gap loses it."""
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    windows = split_window(start, start + timedelta(days=200), NVD_MAX_WINDOW_DAYS)

    for earlier, later in zip(windows, windows[1:]):
        assert earlier[1] == later[0]


def test_split_window_is_empty_when_there_is_nothing_to_fetch():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert split_window(now, now) == []
    assert split_window(now, now - timedelta(days=1)) == []


# ── days_back / backfill ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_incremental_sync_resumes_from_the_checkpoint(monkeypatch):
    from scans.nvd_sync import sync_nvd_to_vuln_intel

    checkpoint = datetime.now(timezone.utc) - timedelta(days=3)
    store = _Store(checkpoint=checkpoint.isoformat())
    captured = _install(monkeypatch, store, [([], None)])

    await sync_nvd_to_vuln_intel(days_back=90)

    requested_start = captured[0].windows[0][0]
    assert requested_start == checkpoint, "days_back must not override the checkpoint"


@pytest.mark.asyncio
async def test_cold_start_uses_days_back(monkeypatch):
    from scans.nvd_sync import sync_nvd_to_vuln_intel

    store = _Store(checkpoint=None)
    captured = _install(monkeypatch, store, [([], None)])

    await sync_nvd_to_vuln_intel(days_back=7)

    start, end = captured[0].windows[0]
    assert abs((end - start) - timedelta(days=7)) < timedelta(minutes=1)


@pytest.mark.asyncio
async def test_backfill_uses_the_requested_window_not_the_checkpoint(monkeypatch):
    """
    The bug in its own right: the API accepted days_back between 1 and 3650 and
    the checkpoint overrode it on every deployment that had ever synced, so an
    operator asking for history got the last few hours and a 202.
    """
    from scans.nvd_sync import sync_nvd_to_vuln_intel

    checkpoint = datetime.now(timezone.utc) - timedelta(hours=1)
    store = _Store(checkpoint=checkpoint.isoformat())
    captured = _install(monkeypatch, store, [([], None)])

    await sync_nvd_to_vuln_intel(days_back=30, backfill=True)

    start, end = captured[0].windows[0]
    assert abs((end - start) - timedelta(days=30)) < timedelta(minutes=1)
    assert start < checkpoint


@pytest.mark.asyncio
async def test_successful_backfill_never_writes_the_checkpoint(monkeypatch):
    from scans.nvd_sync import sync_nvd_to_vuln_intel

    original = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    store = _Store(checkpoint=original)
    _install(monkeypatch, store, [([_record("CVE-2026-0001")], None)])

    state = await sync_nvd_to_vuln_intel(days_back=10, backfill=True)

    assert state["status"] == "SUCCESS"
    assert "CVE-2026-0001" in store.rows, "A backfill still stores what it fetches"
    assert store.checkpoint == original
    assert store.checkpoint_writes == 0


@pytest.mark.asyncio
async def test_failed_backfill_leaves_the_incremental_checkpoint_intact(monkeypatch):
    from scans.nvd_sync import sync_nvd_to_vuln_intel

    original = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    store = _Store(checkpoint=original)
    _install(monkeypatch, store, [([], _fetch_error())])

    await sync_nvd_to_vuln_intel(days_back=365, backfill=True)

    assert store.checkpoint == original
    assert store.checkpoint_writes == 0


@pytest.mark.asyncio
async def test_backfill_longer_than_the_api_maximum_is_split(monkeypatch):
    from scans.nvd_sync import sync_nvd_to_vuln_intel

    store = _Store()
    captured = _install(monkeypatch, store, [([], None)] * 5)

    state = await sync_nvd_to_vuln_intel(days_back=365, backfill=True)

    windows = captured[0].windows
    assert len(windows) == 4, "365 days is four requests, not one 4xx"
    assert state["status"] == "SUCCESS"
    for start, end in windows:
        assert (end - start) <= timedelta(days=NVD_MAX_WINDOW_DAYS)


# ── Write target ─────────────────────────────────────────────────────────────


def test_sync_module_does_not_reach_the_intelligence_database():
    """
    The dual write is gone and must not come back. The second copy of
    `vulnerability_definitions` had no reader anywhere in the product, never
    received the migrations Alembic applies to the application database, and was
    the copy the status endpoint reported.
    """
    from pathlib import Path

    import scans.nvd_sync as ns

    source = Path(ns.__file__).read_text(encoding="utf-8")
    code = "\n".join(
        line for line in source.splitlines() if not line.strip().startswith("#")
    )
    assert "get_vuln_engine" not in code, (
        "nvd_sync must not open the vulnerability-intelligence database: "
        "it writes the application catalogue only."
    )


@pytest.mark.asyncio
async def test_sync_writes_the_application_catalogue_only(monkeypatch):
    from scans.nvd_sync import sync_nvd_to_vuln_intel

    store = _Store()
    _install(monkeypatch, store, [([_record("CVE-2026-0001")], None)])

    await sync_nvd_to_vuln_intel()

    inserts = [
        s for s in store.statements if "INSERT INTO vulnerability_definitions" in s
    ]
    assert len(inserts) == 1, "Exactly one write target, exercised exactly once"
    assert "CVE-2026-0001" in store.rows


# ── Status ───────────────────────────────────────────────────────────────────


def test_status_counts_the_application_catalogue(monkeypatch):
    """
    It used to try the intelligence database first and break on the first
    answer, so it reported a duplicate table nothing read in place of the
    catalogue behind every finding.
    """
    import core.vuln_intel as vi
    import scans.nvd_sync as ns

    store = _Store()
    store.rows = {f"CVE-2026-{i:04d}": {} for i in range(7)}
    monkeypatch.setattr(ns, "_catalogue_engine", lambda: _Engine(store))
    monkeypatch.setattr(
        vi, "get_feed_freshness", lambda: {"cve_count": 366591, "last_modified": None}
    )

    state = ns.get_nvd_sync_status()

    assert state["database_total_cves"] == 7
    assert state["catalogue_database"] == "application"
    # The intelligence feed is reported beside it, never in place of it.
    assert state["scanner_feed_total_cves"] == 366591
    assert state["scanner_feed_database"] == "vuln_intel"


@pytest.mark.asyncio
async def test_total_cves_synced_is_populated(monkeypatch):
    """It was declared in _SYNC_STATE and never assigned — permanently 0."""
    from scans.nvd_sync import sync_nvd_to_vuln_intel

    store = _Store()
    records = [_record(f"CVE-2026-{i:04d}") for i in range(4)]
    _install(monkeypatch, store, [(records, None)])

    state = await sync_nvd_to_vuln_intel()

    assert state["total_cves_synced"] == 4
    assert state["cves_added"] == 4
    assert state["cves_skipped"] == 0
