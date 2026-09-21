"""
Phase 15 — SQLi provisioning, runtime self-check, and no-silent-clean.

Verifies the readiness self-check classifies correctly and leaks no secret, the
sqlmap subprocess timeout can be bounded by the caller, and — the core Phase 14
guarantee — a missing/failed sqlmap marks the scan incomplete (an essential
tool) so a SQL-injectable app can never read as clean, while a *deliberately
disabled* sqlmap does not.
"""

import json

from core.web import self_check as SC


# ── self-check classification ────────────────────────────────────────────────
def _all_ok(monkeypatch):
    def ok(*a, **k):
        return {"status": "ok", "detail": "ok", "required": False}

    for fn in (
        "_check_sqlmap",
        "_check_nuclei_templates",
        "_check_playwright",
        "_check_sslyze",
        "_check_redis",
        "_check_postgres",
    ):
        monkeypatch.setattr(
            SC, fn, lambda *a, **k: {"status": "ok", "detail": "ok", "required": True}
        )
    monkeypatch.setattr(SC, "_binary_version", ok)


def test_ready_when_all_ok(monkeypatch):
    _all_ok(monkeypatch)
    rep = SC.run_self_check()
    assert rep["status"] == SC.READY
    assert rep["required_missing"] == []


def test_not_ready_when_required_missing(monkeypatch):
    _all_ok(monkeypatch)
    monkeypatch.setattr(
        SC,
        "_check_sqlmap",
        lambda *a, **k: {
            "status": "missing",
            "detail": "sqlmap gone",
            "required": True,
        },
    )
    rep = SC.run_self_check()
    assert rep["status"] == SC.NOT_READY
    assert "sqlmap" in rep["required_missing"]


def test_degraded_when_recommended_missing(monkeypatch):
    _all_ok(monkeypatch)

    # ffuf is recommended; _binary_version drives ffuf/nuclei/subfinder.
    def fake_bin(name, args):
        if name == "ffuf":
            return {"status": "missing", "detail": "no ffuf", "required": False}
        return {"status": "ok", "detail": "ok", "required": name in SC.REQUIRED}

    monkeypatch.setattr(SC, "_binary_version", fake_bin)
    rep = SC.run_self_check()
    assert rep["status"] == SC.DEGRADED
    assert "ffuf" in rep["recommended_missing"]
    assert rep["required_missing"] == []


def test_self_check_runs_and_leaks_no_secret():
    # A real invocation must never raise and must not contain DB/redis secrets.
    from config import DatabaseConfig

    rep = SC.run_self_check()
    blob = json.dumps(rep)
    # the DB password (if any is set) must not appear anywhere in the report
    url = DatabaseConfig.DATABASE_URL or ""
    if "@" in url and "://" in url:
        creds = url.split("://", 1)[1].split("@", 1)[0]
        if ":" in creds:
            pw = creds.split(":", 1)[1]
            if pw:
                assert pw not in blob
    assert rep["status"] in (SC.READY, SC.DEGRADED, SC.NOT_READY)


def test_sqlmap_check_uses_the_wrapper(monkeypatch):
    # The check must resolve sqlmap the way the engine does (wrapper), not a
    # login shell — that was the Phase 14 false negative.
    import core.web.sqlmap.wrapper as W

    monkeypatch.setattr(W.SqlmapWrapper, "is_available", lambda self: False)
    r = SC._check_sqlmap()
    assert r["status"] == "missing" and r["required"] is True


# ── no-silent-clean: sqlmap is an essential tool ─────────────────────────────
def test_missing_sqlmap_marks_scan_incomplete():
    from orchestrator.web_orchestrator import ESSENTIAL_TOOLS, ToolCoverage

    assert "sqlmap" in ESSENTIAL_TOOLS
    cov = ToolCoverage()
    cov.ran("nuclei")
    cov.unavailable("sqlmap")  # not installed
    assert "sqlmap" in cov.missing_essential
    assert cov.as_dict()["assessment_complete"] is False


def test_disabled_sqlmap_does_not_mark_incomplete():
    from orchestrator.web_orchestrator import ToolCoverage

    cov = ToolCoverage()
    cov.ran("nuclei")
    cov.skipped("sqlmap", "Disabled in scan options")  # a deliberate choice
    assert "sqlmap" not in cov.missing_essential


def test_failed_sqlmap_marks_scan_incomplete():
    from orchestrator.web_orchestrator import ToolCoverage

    cov = ToolCoverage()
    cov.ran("nuclei")
    cov.failed("sqlmap", RuntimeError("boom"))
    assert "sqlmap" in cov.missing_essential


# ── sqlmap subprocess timeout can be bounded by the caller ───────────────────
def test_sqlmap_run_timeout_is_bounded(monkeypatch):
    from core.web.sqlmap.wrapper import SqlmapWrapper

    captured = {}

    class _Done:
        returncode = 0
        stdout = "no injection point"
        stderr = ""

    monkeypatch.setattr(SqlmapWrapper, "require_available", lambda self: None)
    monkeypatch.setattr(SqlmapWrapper, "is_available", lambda self: True)

    def fake_sub(self, args, timeout=None, **kw):
        captured["timeout"] = timeout
        return _Done()

    monkeypatch.setattr(SqlmapWrapper, "_run_subprocess", fake_sub)
    w = SqlmapWrapper()
    base = w.timeout
    # a shorter caller budget wins
    w.run(target="http://t/?id=1", run_timeout=5)
    assert captured["timeout"] == 5
    # no caller budget → the tool's own timeout
    w.run(target="http://t/?id=1")
    assert captured["timeout"] == base
