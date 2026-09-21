"""
Watchdog for stranded web-application scans.

Web scans live in their own table with a four-phase lifecycle and, until
`reap_stalled_web_scans` existed, nothing settled one whose worker died or whose
phase hung — twelve sat 'running'/'queued' for weeks, each a live scan in the UI
that would never end. These tests pin the reaper's contract:

* a queued scan no web-worker ever collected is failed after the queue timeout;
* a phase doing legitimate work inside its budget is left alone;
* a phase past its own hard time-limit (its task is gone) is failed;
* a terminal scan is never overwritten — the first recorded outcome wins.

They use a real session directly rather than the shared TestClient session, and
clean up the rows they create, for the reason recorded in the finding-comparison
tests: a committed fixture row otherwise survives the per-test rollback.
"""

from datetime import timedelta

import pytest

from core.scan_control import force_terminal_web_scan_status
from core.tasks import reap_stalled_web_scans
from db.base import SessionLocal, utcnow
from db.models.web_scans import WebScan

_PREFIX = "wsc_stalltest_"


def _org_id(session):
    """Any existing organisation — web_scans.org_id is a FK into it."""
    from db.models.rbac import Organization

    org = session.query(Organization).first()
    assert org is not None, "test DB has no organisation to attach the scan to"
    return org.id


def _mk(session, suffix, **fields):
    scan = WebScan(
        id=f"{_PREFIX}{suffix}",
        org_id=_org_id(session),
        target_url="http://target.invalid/",
        target_domain="target.invalid",
        authorization_confirmed=True,
        scan_name="stall test",
        **fields,
    )
    session.add(scan)
    session.commit()
    return scan.id


@pytest.fixture
def session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.query(WebScan).filter(WebScan.id.like(f"{_PREFIX}%")).delete(
            synchronize_session=False
        )
        db.commit()
        db.close()


def _status(db, scan_id):
    db.expire_all()
    return db.query(WebScan).filter(WebScan.id == scan_id).first().status


def test_queued_web_scan_never_collected_is_reaped(session):
    now = utcnow()
    sid = _mk(
        session,
        "queued_old",
        status="queued",
        pipeline_phase="queued",
        queued_at=now - timedelta(minutes=45),
        created_at=now - timedelta(minutes=45),
    )
    out = reap_stalled_web_scans()
    assert sid in [r["web_scan_id"] for r in out["web_scans"]]
    assert _status(session, sid) == "failed"


def test_running_phase_within_budget_is_left_alone(session):
    now = utcnow()
    # DETECT running for 30 minutes — well inside its 140-minute hard limit.
    sid = _mk(
        session,
        "detect_ok",
        status="running",
        pipeline_phase="detect",
        recon_started_at=now - timedelta(minutes=35),
        detect_started_at=now - timedelta(minutes=30),
        started_at=now - timedelta(minutes=35),
        created_at=now - timedelta(minutes=35),
    )
    reap_stalled_web_scans()
    assert _status(session, sid) == "running"


def test_running_phase_past_hard_limit_is_reaped(session):
    now = utcnow()
    # DETECT running for 3 hours — past its 140-minute hard limit, so its task
    # was SIGKILLed and the row was orphaned.
    sid = _mk(
        session,
        "detect_stuck",
        status="running",
        pipeline_phase="detect",
        recon_started_at=now - timedelta(minutes=190),
        detect_started_at=now - timedelta(minutes=180),
        started_at=now - timedelta(minutes=190),
        created_at=now - timedelta(minutes=190),
    )
    out = reap_stalled_web_scans()
    assert sid in [r["web_scan_id"] for r in out["web_scans"]]
    assert _status(session, sid) == "failed"


def test_terminal_web_scan_is_never_overwritten(session):
    now = utcnow()
    sid = _mk(
        session,
        "done",
        status="complete",
        pipeline_phase="complete",
        failure_reason=None,
        started_at=now - timedelta(hours=9),
        completed_at=now - timedelta(hours=8),
        created_at=now - timedelta(hours=9),
    )
    reap_stalled_web_scans()
    assert _status(session, sid) == "complete"
    # And the settler itself refuses a terminal row.
    assert force_terminal_web_scan_status(sid, "failed", "should not apply") is False
    assert _status(session, sid) == "complete"
