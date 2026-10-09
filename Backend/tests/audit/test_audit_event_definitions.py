"""
Audit-event definitions are the module's, not the platform's (follow-up 6).

The audit log is the platform's. Which severity an *Audit* event carries is
Audit's call, registered by ``ccure_audit/audit_events.py`` and loaded by name
from Audit's manifest. Severity is stored on the row when the event is written,
so the one thing that must not happen is a process classifying an Audit event
without the definitions — and writing the wrong value permanently. These pin:

* no severity changed: the merged table equals a fingerprint of the single table
  that existed before the split (the one action that was unclassified is now
  named at the severity it already took);
* the split: 47 platform events and 63 Audit events, none in both;
* every process gets the definitions — a fresh interpreter that never imports
  ``main`` (a Celery worker, the web worker, a script) classifies Audit events
  correctly on first use;
* declared-but-unloadable definitions raise rather than falling back to the
  default, and the failure is not cached;
* registration refuses conflicts and unknown levels.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys

import pytest

from ccure_platform.audit_log import taxonomy
from testpaths import BACKEND_ROOT

#: sha256 of ``sorted(SEVERITY_BY_ACTION.items())`` of the 109-entry table that
#: held every event before it was split (Oct 2026).
PRE_SPLIT_FINGERPRINT = (
    "2be5c1b809946abd07d79aa762081b360180307fe8a55ba613229ef3b7a5759e"
)
#: The action that was emitted but unclassified, and took the default.
NEWLY_NAMED = {"service.token_issued": "medium"}


def _registered_by_rbac() -> set[str]:
    """RBAC registers its own events lazily, on the first one it emits (RBAC-2), so
    in a process that ran RBAC tests first they are in the merged table. They belong
    to neither the platform's table nor Audit's, and these tests pin those two."""
    return {a for a, source in taxonomy._sources.items() if source == "rbac"}


def _run(code: str):
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=str(BACKEND_ROOT),
    )


# ── nothing changed ──────────────────────────────────────────────────────────


def test_every_pre_split_severity_is_unchanged():
    merged = {
        k: v
        for k, v in taxonomy.all_severities().items()
        if k not in NEWLY_NAMED and k not in _registered_by_rbac()
    }
    assert len(merged) == 109
    digest = hashlib.sha256(json.dumps(sorted(merged.items())).encode()).hexdigest()
    assert digest == PRE_SPLIT_FINGERPRINT


def test_the_newly_named_action_has_the_severity_it_already_took():
    for action, level in NEWLY_NAMED.items():
        assert taxonomy.all_severities()[action] == level == taxonomy.DEFAULT_SEVERITY


# ── the split ────────────────────────────────────────────────────────────────


def test_platform_and_audit_events_are_disjoint_and_complete():
    from ccure_audit.audit_events import AUDIT_EVENT_SEVERITIES

    platform = taxonomy.SEVERITY_BY_ACTION
    assert len(platform) == 47 and len(AUDIT_EVENT_SEVERITIES) == 63
    assert not set(platform) & set(AUDIT_EVENT_SEVERITIES)
    assert set(platform) | set(AUDIT_EVENT_SEVERITIES) == (
        set(taxonomy.all_severities()) - _registered_by_rbac()
    )


def test_the_platform_table_names_no_audit_event():
    audit_words = ("scan.", "web_scan", "finding", "credential", "remediation")
    names = [
        a
        for a in taxonomy.SEVERITY_BY_ACTION
        if a.startswith(audit_words) or "_schedule" in a or "evidence" in a
    ]
    # organization.scan_scope_changed is the platform's plan feature, not Audit's
    assert names == []


# ── every process that can write an event gets the definitions ───────────────


@pytest.mark.parametrize(
    "boot",
    [
        # a script
        "",
        # a Celery worker or the web worker: the app, its task modules, no main
        "from core.celery_app import celery_app\ncelery_app.loader.import_default_modules()\n",
        # the scan helpers a worker raises scan events from
        "import scans.db_helpers\n",
    ],
    ids=["script", "celery-worker", "scan-helpers"],
)
def test_a_process_that_never_imports_main_classifies_audit_events(boot):
    code = (
        boot
        + "import sys\n"
        + "from ccure_platform.audit_log.taxonomy import severity_for\n"
        + "assert 'main' not in sys.modules\n"
        + "print(severity_for('scan.completed'), severity_for('scan.failed'),"
        + " severity_for('credential.created'), severity_for('user.login'))\n"
    )
    out = _run(code)
    assert out.returncode == 0, out.stderr[-1000:]
    assert out.stdout.strip().splitlines()[-1] == "info medium high info"


def test_the_writer_resolves_through_the_same_path_in_a_fresh_process():
    code = (
        "from ccure_platform.audit_log import writer\n"
        "print(writer.severity_for('scan.created'))\n"
    )
    out = _run(code)
    assert out.returncode == 0, out.stderr[-1000:]
    assert out.stdout.strip().splitlines()[-1] == "low"


def test_declared_definitions_that_cannot_load_raise_and_are_not_cached():
    code = (
        "import sys\n"
        "sys.modules['ccure_audit.audit_events'] = None  # the import now fails\n"
        "from ccure_platform.audit_log import taxonomy\n"
        "def attempt():\n"
        "    try:\n"
        "        taxonomy.severity_for('scan.completed')\n"
        "        return 'classified'\n"
        "    except taxonomy.AuditDefinitionsUnavailable:\n"
        "        return 'raised'\n"
        "print(attempt(), attempt())\n"  # twice: the failure is not remembered as loaded
        "print(taxonomy.severity_for(None))\n"  # no action needs no definitions
    )
    out = _run(code)
    assert out.returncode == 0, out.stderr[-1000:]
    lines = out.stdout.strip().splitlines()
    assert lines[-2] == "raised raised"  # never the default, never MEDIUM
    assert lines[-1] == taxonomy.DEFAULT_SEVERITY


def test_an_unclassified_action_still_takes_the_default_and_says_so(caplog):
    import logging

    taxonomy._warned.discard("zz.never.classified")
    with caplog.at_level(logging.WARNING, logger=taxonomy.logger.name):
        assert taxonomy.severity_for("zz.never.classified") == taxonomy.DEFAULT_SEVERITY
    assert any("zz.never.classified" in r.message for r in caplog.records)
    assert taxonomy.logger.name == "core.audit_taxonomy"  # the legacy logger name


# ── registration rules ───────────────────────────────────────────────────────


def test_registration_refuses_conflicts_and_unknown_levels():
    with pytest.raises(ValueError):  # an unknown level
        taxonomy.register_event_severities("probe", {"probe.x": "severe"})
    with pytest.raises(ValueError):  # a platform event with another level
        taxonomy.register_event_severities("probe", {"user.login": "critical"})
    with pytest.raises(ValueError):  # Audit's event with another level
        taxonomy.register_event_severities("probe", {"scan.completed": "critical"})
    assert "probe.x" not in taxonomy.all_severities()


def test_registering_the_same_definitions_again_is_a_no_op():
    from ccure_audit.audit_events import AUDIT_EVENT_SEVERITIES

    before = dict(taxonomy.all_severities())
    taxonomy.register_event_severities("audit", AUDIT_EVENT_SEVERITIES)
    assert taxonomy.all_severities() == before


# ── the manifest ─────────────────────────────────────────────────────────────


def test_audits_manifest_declares_its_definitions_module():
    from ccure_platform.modules import registry

    assert registry.audit_event_modules() == ["ccure_audit.audit_events"]


def test_a_manifest_cannot_declare_definitions_outside_its_package():
    from ccure_platform.modules.manifest import ManifestError, ModuleManifest

    base = dict(
        key="demo",
        title="Demo",
        description="d",
        entry_path="/demo-dashboard",
        package="ccure_demo",
        db_schema="demo",
        route_prefix="/demo",
        task_prefix="ccure.demo",
    )
    ModuleManifest(**base, audit_event_modules=("ccure_demo.events",))
    with pytest.raises(ManifestError, match="outside"):
        ModuleManifest(**base, audit_event_modules=("core.audit",))
