"""
Phase 18 — fault-injection reliability.

Proves a web scan cannot stay permanently stuck when infrastructure or a
subprocess fails, and that a real completed result is never overwritten by a
watchdog. Each failure is injected in isolation and the terminal-state,
cleanup, no-silent-clean and race guarantees are asserted. Race tests run
repeatedly.
"""

from datetime import timedelta

import pytest

from config import WebScanConfig
from db.base import SessionLocal, utcnow
from db.models.web_scans import WebFinding, WebScan

_PREFIX = "wsc_fault_"


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


def _mk(session, suffix, status="running", started_min_ago=1, phase="detect"):
    from db.models.rbac import Organization

    org = session.query(Organization).first()
    scan = WebScan(
        id=f"{_PREFIX}{suffix}",
        org_id=org.id,
        target_url="http://target.invalid/",
        target_domain="target.invalid",
        authorization_confirmed=True,
        scan_name="fault test",
        status=status,
        pipeline_phase=phase,
        created_at=utcnow(),
        started_at=utcnow() - timedelta(minutes=started_min_ago),
    )
    session.add(scan)
    session.commit()
    return scan, org.id


def _status(session, sid):
    session.expire_all()
    return session.query(WebScan).filter(WebScan.id == sid).first().status


class _DeadSession:
    """A session whose queries fail — how a down database actually surfaces
    (SessionLocal() itself is lazy and does not connect)."""

    def execute(self, *a, **k):
        raise ConnectionError("database down")

    def query(self, *a, **k):
        raise ConnectionError("database down")

    def commit(self):
        raise ConnectionError("database down")

    def rollback(self):
        pass

    def close(self):
        pass


# ── 2. Celery task failure → terminal + reason + findings preserved ──────────
def test_task_failure_settles_terminal_and_preserves_findings(session):
    from core.web.tasks import _settle_web_scan_failed

    scan, org_id = _mk(session, "taskfail")
    session.add(
        WebFinding(
            id=f"{_PREFIX}taskfail_f1",
            web_scan_id=scan.id,
            org_id=org_id,
            finding_type="xss",
            title="partial finding",
            severity="high",
            status="open",
        )
    )
    session.commit()
    _settle_web_scan_failed(session, scan.id, "detect", "boom in detect")
    assert _status(session, scan.id) == "failed"
    row = session.query(WebScan).filter(WebScan.id == scan.id).first()
    assert "boom in detect" in (row.failure_reason or "")
    # findings already collected survive
    assert (
        session.query(WebFinding).filter(WebFinding.web_scan_id == scan.id).count() == 1
    )


# ── 2b. Task failure when the ORM itself is broken → plain-SQL fallback ───────
def test_task_failure_falls_back_to_force_terminal_when_orm_breaks(
    session, monkeypatch
):
    import core.web.tasks as T

    scan, _ = _mk(session, "ormbroke")
    # Simulate the ORM being the failure (the documented incident shape).
    monkeypatch.setattr(
        T,
        "_update_scan_phase_status",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("mapper is broken")),
    )
    T._settle_web_scan_failed(session, scan.id, "detect", "orm-caused failure")
    # force_terminal (plain SQL) still settled it terminal.
    assert _status(session, scan.id) == "failed"


# ── 3. Redis unavailable → scan still settles (settle uses SQL, not Redis) ───
def test_redis_down_does_not_block_terminal_settle(session, monkeypatch):
    import core.web.tasks as T

    scan, _ = _mk(session, "redisdown")
    monkeypatch.setattr(
        T,
        "_emit_progress",
        lambda *a, **k: (_ for _ in ()).throw(ConnectionError("redis down")),
    )
    # Even though the UI frame publish raises, the DB settle must succeed.
    try:
        T._settle_web_scan_failed(session, scan.id, "detect", "reason")
    except Exception as e:
        pytest.fail(f"settle raised on redis failure: {e}")
    assert _status(session, scan.id) == "failed"


def test_global_timeout_settles_with_redis_down(session, monkeypatch):
    from core.web import timeout as TO

    monkeypatch.setattr(WebScanConfig, "WEB_SCAN_TIMEOUT", 3600, raising=False)
    # Inject Redis being down at the realistic layer — the client factory the
    # UI-frame publish and session-release both call. Their internal try/except
    # must absorb it so the DB settle (plain SQL) is never blocked.
    import core.redis_client as RC

    monkeypatch.setattr(
        RC,
        "get_redis_client",
        lambda *a, **k: (_ for _ in ()).throw(ConnectionError("redis down")),
    )
    scan, _ = _mk(session, "to_redis", started_min_ago=120)
    try:
        info = TO.enforce_global_timeout(scan.id, phase="detect")
    except Exception as e:
        pytest.fail(f"enforce raised on redis failure: {e}")
    assert _status(session, scan.id) == "failed"  # settled despite redis down
    assert info is not None and info["timed_out"] is True


# ── 4. PostgreSQL unavailable → force_terminal never raises ──────────────────
def test_force_terminal_never_raises_when_db_down(monkeypatch):
    import core.scan_control as SC

    # A down database surfaces as the query raising (SessionLocal() itself is
    # lazy and does not connect), so inject a session whose execute() fails.
    monkeypatch.setattr(SC, "SessionLocal", lambda: _DeadSession())
    # Must return False, not raise, so an except handler is never re-broken.
    assert SC.force_terminal_web_scan_status("nope", "failed", "x") is False


def test_reaper_survives_db_listing_failure(monkeypatch):
    import core.tasks as CT

    monkeypatch.setattr(CT, "SessionLocal", lambda: _DeadSession())
    res = CT.reap_stalled_web_scans()
    assert res.get("success") is False  # reported, not crashed


# ── 6/7/8. Subprocess failures are not silent-clean ──────────────────────────
def test_missing_essential_tool_flags_incomplete():
    from orchestrator.web_orchestrator import ToolCoverage

    for tool in ("nuclei", "sqlmap"):
        cov = ToolCoverage()
        cov.failed(tool, RuntimeError("process died"))
        assert tool in cov.missing_essential
        assert cov.as_dict()["assessment_complete"] is False


def test_sqlmap_timeout_is_not_reported_clean(monkeypatch):
    import subprocess

    from core.web.sqlmap.wrapper import SqlmapWrapper

    monkeypatch.setattr(SqlmapWrapper, "require_available", lambda self: None)

    def boom(self, args, timeout=None, **k):
        raise subprocess.TimeoutExpired(cmd="sqlmap", timeout=timeout or 1)

    monkeypatch.setattr(SqlmapWrapper, "_run_subprocess", boom)
    res = SqlmapWrapper().run(target="http://t/?id=1")
    assert res["status"] == "timeout"  # never "clean"
    assert res["vulnerable"] is False


def test_ffuf_failure_returns_cleanly(monkeypatch, tmp_path):
    from core.web.ffuf.wrapper import FfufWrapper

    wl = tmp_path / "w.txt"
    wl.write_text("a\nb\n")
    monkeypatch.setattr(FfufWrapper, "require_available", lambda self: None)
    monkeypatch.setattr(
        FfufWrapper,
        "_run_subprocess",
        lambda self, args, **k: (_ for _ in ()).throw(RuntimeError("ffuf died")),
    )
    # ffuf is not an essential tool, so a subprocess failure degrades to an
    # empty result rather than hanging or crashing the phase.
    res = FfufWrapper().run(target="http://t/", wordlist=str(wl))
    assert res["discovered_paths"] == []
    assert res["sensitive_findings"] == []


# ── 5/9/10. Browser failure, target gone, network timeout → graceful ─────────
def test_crawler_without_playwright_returns_gracefully(monkeypatch):
    import asyncio
    import sys

    import core.web.crawling.browser as B

    # Force the ImportError path deterministically: a None entry in sys.modules
    # makes `from playwright.async_api import ...` raise ImportError, whether or
    # not Playwright is actually installed in this environment.
    monkeypatch.setitem(sys.modules, "playwright.async_api", None)

    crawler = B.PlaywrightCrawler(max_urls=3)
    res = asyncio.run(crawler.crawl(start_url="http://target.invalid/"))
    # The failure is recorded and the crawl returns rather than hanging.
    assert any("laywright" in e for e in res.errors)


def test_config_checks_survive_a_dead_target():
    import asyncio

    from orchestrator.web_orchestrator import WebScanOrchestrator

    orch = WebScanOrchestrator(silent=True)
    # 127.0.0.1:9 is the discard port — connection refused / no response.
    dead = "http://127.0.0.1:9/"
    assert asyncio.run(orch._check_cookies(dead)) == []
    assert asyncio.run(orch._check_cors(dead)) == []
    # security headers: a dead target yields no crash (empty or handled)
    asyncio.run(orch._check_security_headers(dead))


# ── 11. Cancellation reaches terminal in any phase ───────────────────────────
@pytest.mark.parametrize("phase", ["recon", "crawl", "detect", "audit"])
def test_cancellation_is_detected_in_every_phase(session, phase):
    from core.web.tasks import _check_cancelled
    from orchestrator.web_orchestrator import WebScanOrchestrator

    scan, _ = _mk(session, f"cancel_{phase}", status="cancelled", phase=phase)
    assert _check_cancelled(session, scan.id) is True
    assert WebScanOrchestrator._scan_is_cancelled(scan.id) is True


# ── RACES: a real terminal result is never overwritten ───────────────────────
@pytest.mark.parametrize("terminal", ["complete", "failed", "cancelled"])
def test_watchdog_never_overwrites_a_terminal_result(session, monkeypatch, terminal):
    from core.scan_control import force_terminal_web_scan_status
    from core.web import timeout as TO
    from core.web.tasks import _settle_web_scan_failed

    monkeypatch.setattr(WebScanConfig, "WEB_SCAN_TIMEOUT", 1, raising=False)
    # run each race a few times
    for i in range(5):
        scan, _ = _mk(
            session, f"race_{terminal}_{i}", status=terminal, started_min_ago=999
        )
        # every watchdog path must leave a real terminal result untouched
        assert force_terminal_web_scan_status(scan.id, "failed", "watchdog") is False
        assert TO.enforce_global_timeout(scan.id, phase="detect") is None
        _settle_web_scan_failed(session, scan.id, "detect", "late error")
        assert _status(session, scan.id) == terminal
        session.query(WebScan).filter(WebScan.id == scan.id).delete(
            synchronize_session=False
        )
        session.commit()
