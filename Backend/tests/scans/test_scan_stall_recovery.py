"""
tests/scans/test_scan_stall_recovery.py
─────────────────────────────────────────────────────────────────────────────
A scan always reaches a terminal state, even when the ORM is the thing that
broke.

Why this file exists
────────────────────
On 4 Sep 2026 a scanner worker was holding a `Scan` mapper from before GAP-14
added `asset_vulnerabilities.verified_scan_id`. Every scan task raised
`InvalidRequestError` on its first query — and then `mark_scan_failed`, called
from the task's own `except` handler, raised the identical error on *its* first
query. The handler died, nothing was written, and three scans against a host
that was up the whole time (33 ms ICMP, ARP-resolved) sat in `running`
indefinitely. The UI showed a live scan stuck at 10% for as long as anyone
cared to watch.

The lesson generalises past that one mapper: **a failure path that shares a
dependency with the thing it is recovering from is not a failure path.** So the
properties defended here are

  1. `force_terminal_status` settles a scan without touching a mapper, and
  2. it refuses to overwrite an outcome that was already recorded, and
  3. `reap_stalled_scans` settles what nothing else did, on a deadline, and
     leaves everything inside that deadline alone.

Note (3) is what makes this a *timeout* rather than a cleanup script:
`task_time_limit` in `core/celery_app.py` reads like a scan timeout and cannot
act as one here — Celery's hard limit signals a billiard process, so it is
inert under the `--pool=threads` host worker, and it can do nothing at all
about a worker that has already died.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from core.scan_control import force_terminal_status, read_status
from db.models.rbac import Organization
from db.models.scans import Scan


def _utc(minutes_ago: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)


@pytest.fixture()
def org(db_session):
    org_id = f"org_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Organization(
            id=org_id,
            name="Stall",
            slug=f"stall-{uuid.uuid4().hex[:8]}",
            max_assets=100,
            max_users=10,
            is_active=True,
            settings={},
        )
    )
    db_session.commit()
    return org_id


def _scan(db_session, org_id, *, status: str, started_minutes_ago: int) -> Scan:
    row = Scan(
        id=f"scn_{uuid.uuid4().hex[:12]}",
        org_id=org_id,
        target_str="10.180.5.83",
        scan_type="adaptive",
        pipeline_mode="basic",
        status=status,
        created_at=_utc(started_minutes_ago),
        queued_at=_utc(started_minutes_ago),
        started_at=_utc(started_minutes_ago),
    )
    db_session.add(row)
    db_session.commit()
    return row


# ── force_terminal_status ────────────────────────────────────────────────────


def test_a_running_scan_is_settled_with_its_reason(db_session, org):
    scan = _scan(db_session, org, status="running", started_minutes_ago=120)
    scan_id = scan.id

    assert force_terminal_status(scan_id, "failed", "worker went away") is True

    db_session.expire_all()
    row = db_session.query(Scan).filter(Scan.id == scan_id).first()
    assert row.status == "failed"
    assert row.failure_reason == "worker went away"
    assert row.completed_at is not None
    # The operator asks "how long did it run for" of a failed scan too.
    assert row.duration_seconds is not None and row.duration_seconds > 0


def test_an_already_settled_scan_is_never_overwritten(db_session, org):
    """
    The first outcome recorded is the true one.

    A watchdog that overwrote a real verdict would replace "unreachable — the
    host did not answer", which is a finding, with "timed out", which is an
    apology. It would also make a completed scan's report unreachable.
    """
    scan = _scan(db_session, org, status="unreachable", started_minutes_ago=300)
    scan_id = scan.id
    db_session.query(Scan).filter(Scan.id == scan_id).update(
        {"failure_reason": "No host responded."}
    )
    db_session.commit()

    assert force_terminal_status(scan_id, "failed", "timed out") is False

    db_session.expire_all()
    row = db_session.query(Scan).filter(Scan.id == scan_id).first()
    assert row.status == "unreachable"
    assert row.failure_reason == "No host responded."


def test_it_reports_honestly_when_there_is_no_such_scan(db_session):
    assert force_terminal_status("scn_does_not_exist", "failed", "x") is False


def test_it_does_not_raise_on_a_missing_scan_id(db_session):
    """The handler of last resort must never itself become the exception."""
    assert force_terminal_status("", "failed", "x") is False
    assert force_terminal_status(None, "failed", "x") is False  # type: ignore[arg-type]


# ── the watchdog ─────────────────────────────────────────────────────────────


def test_the_watchdog_settles_a_scan_past_its_deadline(db_session, org, monkeypatch):
    from config import AppConfig
    from core.tasks import reap_stalled_scans

    monkeypatch.setattr(AppConfig, "SCAN_STALL_TIMEOUT_MINUTES", 90, raising=False)
    stalled = _scan(db_session, org, status="running", started_minutes_ago=200)
    scan_id = stalled.id

    result = reap_stalled_scans()

    assert result["success"] is True
    assert scan_id in {s["scan_id"] for s in result["scans"]}
    assert read_status(scan_id) == "failed"


def test_a_scan_inside_its_deadline_is_left_alone(db_session, org, monkeypatch):
    """
    The cost of reaping too eagerly is worse than reaping late: a long but
    healthy scan would be killed off in the UI while its worker was still
    happily probing, and the operator would have no way to tell that from a
    real fault.
    """
    from config import AppConfig
    from core.tasks import reap_stalled_scans

    monkeypatch.setattr(AppConfig, "SCAN_STALL_TIMEOUT_MINUTES", 90, raising=False)
    healthy = _scan(db_session, org, status="running", started_minutes_ago=10)
    scan_id = healthy.id

    reap_stalled_scans()

    assert read_status(scan_id) == "running"


def test_a_queued_scan_gets_its_own_shorter_deadline_and_message(
    db_session, org, monkeypatch
):
    """
    "No scanner is running" and "the scan hung" send the operator to different
    places, so they are separate deadlines with separate wording.
    """
    from config import AppConfig
    from core.tasks import reap_stalled_scans

    monkeypatch.setattr(AppConfig, "SCAN_STALL_TIMEOUT_MINUTES", 90, raising=False)
    monkeypatch.setattr(AppConfig, "SCAN_QUEUE_TIMEOUT_MINUTES", 15, raising=False)

    # Old enough for the queue deadline, far short of the running one.
    queued = _scan(db_session, org, status="queued", started_minutes_ago=40)
    scan_id = queued.id

    result = reap_stalled_scans()

    reaped = {s["scan_id"]: s["reason"] for s in result["scans"]}
    assert scan_id in reaped
    assert "never picked up by a scanner worker" in reaped[scan_id]


def test_the_watchdog_can_be_switched_off(db_session, org, monkeypatch):
    from config import AppConfig
    from core.tasks import reap_stalled_scans

    monkeypatch.setattr(AppConfig, "SCAN_STALL_TIMEOUT_MINUTES", 0, raising=False)
    monkeypatch.setattr(AppConfig, "SCAN_QUEUE_TIMEOUT_MINUTES", 0, raising=False)
    stalled = _scan(db_session, org, status="running", started_minutes_ago=9999)
    scan_id = stalled.id

    result = reap_stalled_scans()

    assert result.get("disabled") is True
    assert read_status(scan_id) == "running"


# ── the failure path that started all this ───────────────────────────────────


def test_a_broken_mark_scan_failed_still_settles_the_scan(db_session, org, monkeypatch):
    """
    The regression test for 4 Sep 2026.

    `mark_scan_failed` is made to raise exactly as the stale mapper made it
    raise. The scan must still end up settled — because the alternative,
    demonstrated in production, is a row that stays `running` for ever with a
    UI reporting a live scan against a host that was never probed.
    """
    import core.tasks as tasks

    scan = _scan(db_session, org, status="running", started_minutes_ago=1)
    scan_id = scan.id

    def _boom(*_a, **_kw):
        raise RuntimeError("mappers failed to initialize")

    monkeypatch.setattr(tasks, "mark_scan_failed", _boom)

    # Must not propagate: this is the handler of last resort.
    tasks._settle_failure(db_session, scan_id, "usr_x", "engine exploded")

    assert read_status(scan_id) == "failed"
