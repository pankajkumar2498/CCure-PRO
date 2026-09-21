"""
Phase 12 — global wall-clock timeout for web scans.

The global clock begins when the scan starts executing (its started_at, stamped
at RECON), caps total wall-clock time at WEB_SCAN_TIMEOUT, settles the scan
terminal on expiry while preserving findings, and never overwrites a result a
task already wrote (the completion/cancellation races). Enforcement is unit
tested through the pure helpers, the orchestrator's deadline-aware stop check,
and enforce_global_timeout against a real DB row for each phase.
"""

from datetime import timedelta, timezone

import pytest

from config import WebScanConfig
from core.web import timeout as T
from db.base import SessionLocal, utcnow
from db.models.web_scans import WebFinding, WebScan

_PREFIX = "wsc_timeout_"


@pytest.fixture
def session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.query(WebFinding).filter(WebFinding.web_scan_id.like(f"{_PREFIX}%")).delete(
            synchronize_session=False
        )
        db.query(WebScan).filter(WebScan.id.like(f"{_PREFIX}%")).delete(
            synchronize_session=False
        )
        db.commit()
        db.close()


def _now():
    return utcnow()


# ── pure helpers ─────────────────────────────────────────────────────────────
def test_deadline_and_timeout_math(monkeypatch):
    monkeypatch.setattr(WebScanConfig, "WEB_SCAN_TIMEOUT", 3600, raising=False)
    started = _now() - timedelta(minutes=30)
    assert T.configured_timeout() == 3600
    dl = T.deadline_from(started)
    assert dl is not None and dl > started  # a real deadline, after the start
    # within budget
    assert T.is_timed_out(_now() - timedelta(minutes=30)) is False
    # past budget
    assert T.is_timed_out(_now() - timedelta(minutes=90)) is True
    # remaining is positive within budget, negative past it
    assert T.remaining_seconds(_now() - timedelta(minutes=30)) > 0
    assert T.remaining_seconds(_now() - timedelta(minutes=90)) < 0


def test_global_clock_begins_at_execution_start(monkeypatch):
    # A scan that has not started executing is never globally timed out — the
    # queue timeout covers the waiting period, not this.
    monkeypatch.setattr(WebScanConfig, "WEB_SCAN_TIMEOUT", 1, raising=False)
    assert T.is_timed_out(None) is False
    assert T.deadline_from(None) is None
    assert T.remaining_seconds(None) is None


def test_timeout_disabled_when_zero(monkeypatch):
    monkeypatch.setattr(WebScanConfig, "WEB_SCAN_TIMEOUT", 0, raising=False)
    assert T.is_timed_out(_now() - timedelta(days=5)) is False
    assert T.deadline_from(_now() - timedelta(days=5)) is None


# ── orchestrator deadline-aware stop check ───────────────────────────────────
def _mk_scan(session, suffix, status="running", started_delta_min=1):
    from db.models.rbac import Organization

    org = session.query(Organization).first()
    assert org is not None
    scan = WebScan(
        id=f"{_PREFIX}{suffix}",
        org_id=org.id,
        target_url="http://target.invalid/",
        target_domain="target.invalid",
        authorization_confirmed=True,
        scan_name="timeout test",
        status=status,
        created_at=utcnow(),
        started_at=utcnow() - timedelta(minutes=started_delta_min),
    )
    session.add(scan)
    session.commit()
    return scan, org.id


def test_scan_is_cancelled_is_deadline_aware(session, monkeypatch):
    from orchestrator.web_orchestrator import WebScanOrchestrator

    monkeypatch.setattr(WebScanConfig, "WEB_SCAN_TIMEOUT", 3600, raising=False)
    # within budget → not stopped
    s1, _ = _mk_scan(session, "ora_ok", started_delta_min=10)
    assert WebScanOrchestrator._scan_is_cancelled(s1.id) is False
    # past deadline → stopped
    s2, _ = _mk_scan(session, "ora_to", started_delta_min=120)
    assert WebScanOrchestrator._scan_is_cancelled(s2.id) is True
    # explicit cancel → stopped regardless of time
    s3, _ = _mk_scan(session, "ora_cancel", status="cancelled", started_delta_min=1)
    assert WebScanOrchestrator._scan_is_cancelled(s3.id) is True


def test_bounded_timeout_clamps_to_remaining(session, monkeypatch):
    from orchestrator.web_orchestrator import WebScanOrchestrator

    monkeypatch.setattr(WebScanConfig, "WEB_SCAN_TIMEOUT", 3600, raising=False)
    orch = WebScanOrchestrator(silent=True)
    s, _ = _mk_scan(session, "bound", started_delta_min=59)  # ~60s left
    bounded = orch._bounded_timeout(s.id, base_timeout=7200)
    assert 1 <= bounded <= 120  # clamped to the ~60s that remain, not 7200


# ── enforce_global_timeout against a real row, per phase ─────────────────────
@pytest.mark.parametrize("phase", ["recon", "crawl", "detect", "audit"])
def test_enforce_settles_terminal_per_phase(session, monkeypatch, phase):
    monkeypatch.setattr(WebScanConfig, "WEB_SCAN_TIMEOUT", 3600, raising=False)
    scan, _ = _mk_scan(session, f"phase_{phase}", started_delta_min=120)
    info = T.enforce_global_timeout(scan.id, phase=phase)
    assert info is not None
    assert info["timed_out"] is True
    assert phase.upper() in info["reason"]
    # the row is now terminal, with the timeout reason recorded
    session.expire_all()
    row = session.query(WebScan).filter(WebScan.id == scan.id).first()
    assert row.status == "failed"
    assert "global time limit" in (row.failure_reason or "").lower()


def test_enforce_preserves_findings(session, monkeypatch):
    monkeypatch.setattr(WebScanConfig, "WEB_SCAN_TIMEOUT", 3600, raising=False)
    scan, org_id = _mk_scan(session, "preserve", started_delta_min=120)
    session.add(
        WebFinding(
            id=f"{_PREFIX}preserve_f1",
            web_scan_id=scan.id,
            org_id=org_id,
            finding_type="xss",
            title="partial finding before timeout",
            severity="high",
            status="open",
        )
    )
    session.commit()
    T.enforce_global_timeout(scan.id, phase="detect")
    session.expire_all()
    # findings collected before the timeout survive
    f = session.query(WebFinding).filter(WebFinding.web_scan_id == scan.id).all()
    assert len(f) == 1
    assert f[0].title == "partial finding before timeout"


def test_enforce_noop_within_budget(session, monkeypatch):
    monkeypatch.setattr(WebScanConfig, "WEB_SCAN_TIMEOUT", 3600, raising=False)
    scan, _ = _mk_scan(session, "ok", started_delta_min=5)
    assert T.enforce_global_timeout(scan.id, phase="detect") is None
    session.expire_all()
    assert (
        session.query(WebScan).filter(WebScan.id == scan.id).first().status == "running"
    )


def test_enforce_does_not_overwrite_completed(session, monkeypatch):
    """Completion race: a scan that already finished is never re-marked."""
    monkeypatch.setattr(WebScanConfig, "WEB_SCAN_TIMEOUT", 3600, raising=False)
    scan, _ = _mk_scan(session, "done", status="complete", started_delta_min=999)
    assert T.enforce_global_timeout(scan.id, phase="audit") is None
    session.expire_all()
    assert (
        session.query(WebScan).filter(WebScan.id == scan.id).first().status
        == "complete"
    )


def test_enforce_does_not_overwrite_cancelled(session, monkeypatch):
    """Cancellation race: a cancelled scan is terminal and left alone."""
    monkeypatch.setattr(WebScanConfig, "WEB_SCAN_TIMEOUT", 3600, raising=False)
    scan, _ = _mk_scan(session, "cx", status="cancelled", started_delta_min=999)
    assert T.enforce_global_timeout(scan.id, phase="crawl") is None
    session.expire_all()
    assert (
        session.query(WebScan).filter(WebScan.id == scan.id).first().status
        == "cancelled"
    )


def test_enforce_noop_when_never_started(session, monkeypatch):
    """Timeout while queued is not a global timeout — that clock hasn't started."""
    monkeypatch.setattr(WebScanConfig, "WEB_SCAN_TIMEOUT", 1, raising=False)
    from db.models.rbac import Organization

    org = session.query(Organization).first()
    scan = WebScan(
        id=f"{_PREFIX}queued",
        org_id=org.id,
        target_url="http://target.invalid/",
        target_domain="target.invalid",
        authorization_confirmed=True,
        scan_name="queued",
        status="queued",
        created_at=utcnow() - timedelta(hours=1),
        started_at=None,
    )
    session.add(scan)
    session.commit()
    assert T.enforce_global_timeout(scan.id, phase=None) is None
    session.expire_all()
    assert (
        session.query(WebScan).filter(WebScan.id == scan.id).first().status == "queued"
    )
