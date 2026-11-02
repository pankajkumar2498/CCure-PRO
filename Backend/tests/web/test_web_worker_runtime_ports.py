"""
The web worker's self-check and the web scan reaper, at web DAST's boundary
(2 Nov 2026).

* **The self-check's database and Redis probes are the host's.** Audit's
  composition root (``ccure_audit/web_settings.py``) registers the reads the
  self-check used to make itself; a probe nothing registered is a missing
  required component, so NOT_READY, never "reachable"; a failing one reports
  only its exception class.
* **The reaper's table and deadlines are web DAST's.** The beat task in the
  scans capability (``scans.tasks.reapers.reap_stalled_web_scans``) lists the
  live web scans through ``core.web.scan_status`` and asks
  ``core.web.timeout.stalled_web_scans`` which have stalled — a pure decision,
  pinned here without a database. The end-to-end reaper runs against
  PostgreSQL in ``test_web_scan_stall_recovery.py``.
"""

import ast
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import core.redis_client
import pytest
from core.web import self_check as SC
from core.web import timeout as T
from testpaths import BACKEND_ROOT

# ── The self-check's probes ───────────────────────────────────────────────────


def _others_ok(monkeypatch):
    ok = {"status": "ok", "detail": "ok", "required": True}
    for fn in ("_check_sqlmap", "_check_nuclei_templates", "_check_playwright"):
        monkeypatch.setattr(SC, fn, lambda *a, **k: dict(ok))
    monkeypatch.setattr(SC, "_check_sslyze", lambda: {**ok, "required": False})
    monkeypatch.setattr(
        SC,
        "_binary_version",
        lambda name, args: {**ok, "required": name in SC.REQUIRED},
    )


def test_audit_registers_its_own_probes():
    from ccure_audit import web_settings

    assert SC._probes == {
        "postgres": web_settings._postgres,
        "redis": web_settings._redis,
    }


def test_an_unregistered_probe_is_missing_and_the_worker_not_ready(monkeypatch):
    _others_ok(monkeypatch)
    monkeypatch.setattr(SC, "_probes", {})

    report = SC.run_self_check()

    assert report["status"] == SC.NOT_READY
    assert sorted(report["required_missing"]) == ["postgres", "redis"]
    assert report["checks"]["postgres"] == {
        "status": "missing",
        "detail": "no postgres probe registered by the host",
        "required": True,
    }


def test_a_failing_probe_reports_only_its_exception_class(monkeypatch):
    _others_ok(monkeypatch)

    def down():
        raise ConnectionError("postgresql://user:s3cret@db/ccure")

    monkeypatch.setattr(SC, "_probes", {"postgres": down, "redis": lambda: True})

    report = SC.run_self_check()

    assert report["checks"]["postgres"]["detail"] == (
        "postgres unreachable (ConnectionError)"
    )
    assert "s3cret" not in json.dumps(report)
    assert report["checks"]["redis"]["detail"] == "redis reachable"
    assert report["required_missing"] == ["postgres"]


def test_registration_refuses_a_second_probe_and_an_unknown_component(monkeypatch):
    monkeypatch.setattr(SC, "_probes", {})
    first = lambda: None  # noqa: E731
    SC.register_infrastructure_probes({"postgres": first})
    SC.register_infrastructure_probes({"postgres": first})
    with pytest.raises(ValueError):
        SC.register_infrastructure_probes({"postgres": lambda: None})
    with pytest.raises(ValueError):
        SC.register_infrastructure_probes({"mysql": lambda: None})


def _imports_outside_main(path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    main = [
        node
        for node in tree.body
        if isinstance(node, ast.If) and "__main__" in ast.unparse(node.test)
    ]
    skipped = {id(n) for block in main for n in ast.walk(block)}
    found = set()
    for node in ast.walk(tree):
        if id(node) in skipped:
            continue
        if isinstance(node, ast.Import):
            found |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


def test_the_self_check_imports_neither_the_database_nor_redis():
    imported = _imports_outside_main(BACKEND_ROOT / "core" / "web" / "self_check.py")
    refused = ("db", "core.redis_client", "sqlalchemy", "redis", "config")
    assert (
        sorted(n for n in imported if n.split(".")[0] in refused or n in refused) == []
    )


# ── The reaper's decision ─────────────────────────────────────────────────────

NOW = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)
SETTINGS = SimpleNamespace(WEB_SCAN_QUEUE_TIMEOUT_MINUTES=15, WEB_SCAN_TIMEOUT=14400)


def _row(scan_id, phase="queued", *, queued=None, created=None, started=None, **at):
    """A non_terminal_web_scans() tuple; ``at`` holds the phase starts."""

    def ago(minutes):
        return None if minutes is None else NOW - timedelta(minutes=minutes)

    return (
        scan_id,
        "running" if phase != "queued" else "queued",
        phase,
        ago(queued),
        ago(created if created is not None else 1),
        ago(started),
        ago(at.get("recon")),
        ago(at.get("crawl")),
        ago(at.get("detect")),
        ago(at.get("audit")),
        ago(at.get("updated")),
    )


def test_a_scan_never_picked_up_is_reaped_after_the_queue_deadline():
    rows = [_row("wsc_waiting", queued=20), _row("wsc_fresh", queued=5)]

    (stalled,) = T.stalled_web_scans(rows, NOW, SETTINGS)

    assert stalled["web_scan_id"] == "wsc_waiting"
    assert stalled["phase"] == "queued"
    assert stalled["reason"].startswith(
        "Web scan was never picked up by a web-scanner worker after 20 minutes "
        "(limit 15)."
    )


def test_a_phase_inside_its_budget_is_left_alone_and_one_past_it_is_not():
    rows = [
        _row("wsc_working", "detect", started=101, recon=100, detect=100),
        _row("wsc_hung", "crawl", started=101, recon=100, crawl=81),
    ]

    (stalled,) = T.stalled_web_scans(rows, NOW, SETTINGS)

    assert stalled["web_scan_id"] == "wsc_hung"
    assert stalled["reason"].startswith(
        "Web scan timed out in the CRAWL phase: no progress for 81 minutes "
        "(limit 80)."
    )


def test_the_global_cap_is_the_backstop_for_a_dead_worker():
    settings = SimpleNamespace(WEB_SCAN_QUEUE_TIMEOUT_MINUTES=15, WEB_SCAN_TIMEOUT=3600)
    rows = [_row("wsc_long", "detect", started=75, recon=74, detect=5)]

    (stalled,) = T.stalled_web_scans(rows, NOW, settings)

    assert "exceeded the global time limit (70 min): running for 75 minutes" in (
        stalled["reason"]
    )


def test_zero_disables_the_queue_deadline_and_the_global_cap():
    settings = SimpleNamespace(WEB_SCAN_QUEUE_TIMEOUT_MINUTES=0, WEB_SCAN_TIMEOUT=0)
    rows = [
        _row("wsc_waiting", queued=500),
        _row("wsc_long", "detect", started=900, recon=899, detect=5),
    ]
    assert T.stalled_web_scans(rows, NOW, settings) == []


def test_the_registered_settings_are_read_when_none_are_given(monkeypatch):
    from config import WebScanConfig

    monkeypatch.setattr(WebScanConfig, "WEB_SCAN_QUEUE_TIMEOUT_MINUTES", 30)
    rows = [_row("wsc_waiting", queued=20)]
    assert T.stalled_web_scans(rows, NOW) == []


class _Recorder:
    def __init__(self):
        self.published = []

    def publish(self, channel, message):
        self.published.append((channel, json.loads(message)))


@pytest.mark.parametrize("timed_out", [False, True])
def test_the_terminal_frame_is_the_one_each_path_sent(monkeypatch, timed_out):
    recorder = _Recorder()
    monkeypatch.setattr(core.redis_client, "get_redis_client", lambda: recorder)

    T.publish_terminal_frame("wsc_x", "gone", timed_out=timed_out)

    progress = {
        "status": "failed",
        "message": "gone",
        "error": "gone",
        "reason": "gone",
    }
    if timed_out:
        progress["timed_out"] = True
    assert recorder.published == [
        (
            "scan_progress:wsc_x",
            {
                "scan_id": "wsc_x",
                "scan_type": "web",
                "phase": "failed",
                "progress": progress,
            },
        )
    ]


def test_only_web_dast_names_its_scan_table():
    """The ratchet's own measurement: the reaper's reference was the scans
    capability's one reference to ``web_scans``."""
    from scripts.architecture import capability_map as cm

    referrers = {
        capability
        for capability, table in cm.measure()["foreign_table_references"]
        if table == "web_scans"
    }
    assert "scans" not in referrers
    source = (BACKEND_ROOT / "scans" / "tasks" / "reapers.py").read_text(
        encoding="utf-8"
    )
    assert "WebScanConfig" not in source
