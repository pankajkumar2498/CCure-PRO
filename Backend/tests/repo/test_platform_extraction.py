"""
Backend alignment, step 2: the platform extraction.

What the extraction must leave true, in one place:

* ``ccure_platform`` depends on no Audit code and names no Audit model — not by
  import, not by an ORM relationship;
* what a purge does to a module's records is the module's, through the
  offboarding contract, and Audit has registered its half;
* every legacy path the extraction moved is an alias of the new module and
  holds no implementation of its own;
* the moved routers keep their legacy ``__name__`` (limiter keys, loggers);
* the audit-log service and the notifications service live in the platform.
"""

from __future__ import annotations

import ast
import importlib
from unittest.mock import MagicMock

import pytest

from ccure_platform._legacy import MOVED_MODULES
from scripts.architecture.import_graph import Edge
from testpaths import BACKEND_ROOT

from test_architecture_guardrails import violations

EXTRACTED = {
    "core.audit": "ccure_platform.audit_log.writer",
    "core.audit_taxonomy": "ccure_platform.audit_log.taxonomy",
    "core.audit_retention": "ccure_platform.audit_log.retention",
    "reporting.audit_export": "ccure_platform.audit_log.export",
    "routers.audit": "ccure_platform.audit_log.router",
    "core.notifications": "ccure_platform.notifications.service",
    "routers.notifications": "ccure_platform.notifications.router",
    "routers.admin_users": "ccure_platform.administration.users",
    "routers.admin_orgs": "ccure_platform.administration.organizations",
    "routers.admin_email_domains": "ccure_platform.administration.email_domains",
    "routers.user_profile": "ccure_platform.identity.profile",
}

AUDIT_MODEL_NAMES = {
    "Scan",
    "ScanPhase",
    "Asset",
    "AssetNote",
    "AssetTag",
    "AssetVulnerability",
    "Service",
    "WebScan",
    "ComplianceFramework",
}


# ── the extraction is recorded, and the stubs are only stubs ─────────────────


@pytest.mark.parametrize("legacy, new", sorted(EXTRACTED.items()))
def test_each_extracted_module_is_recorded_and_aliased(legacy, new):
    assert MOVED_MODULES[legacy] == new
    assert importlib.import_module(legacy) is importlib.import_module(new)
    assert importlib.import_module(new).__name__ == legacy


@pytest.mark.parametrize("legacy", sorted(EXTRACTED))
def test_a_legacy_stub_holds_no_implementation(legacy):
    path = BACKEND_ROOT / (legacy.replace(".", "/") + ".py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    defs = [
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    assert not defs, f"{legacy} defines {[d.name for d in defs]}; a stub aliases only"
    assert len(path.read_text().splitlines()) < 20


# ── the platform depends on no Audit code ────────────────────────────────────


@pytest.mark.parametrize(
    "dst",
    [
        "core.audit",
        "core.audit_retention",
        "core.notifications",
        "scan_helpers",
        "routers.scan_history",
        "ccure_audit.offboarding",
        "db.models.scans",
        "db.models.assets",
    ],
)
def test_the_platform_may_not_import_these(dst):
    assert violations([Edge("ccure_platform.administration.users", dst, lazy=False)])


def test_the_platform_has_no_audit_exemption_left_for_the_audit_log():
    from scripts.architecture import layer_rules

    rule = next(
        r for r in layer_rules.RULES if r.name == "platform-is-shared-foundation"
    )
    assert "core.audit" not in rule.exempt_targets
    assert "core.audit_retention" not in rule.exempt_targets


def test_no_platform_model_has_a_relationship_into_a_module_table():
    for name in ("users", "rbac"):
        tree = ast.parse(
            (BACKEND_ROOT / f"ccure_platform/models/{name}.py").read_text("utf-8")
        )
        targets = {
            n.args[0].value
            for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and getattr(n.func, "id", "") == "relationship"
            and n.args
            and isinstance(n.args[0], ast.Constant)
        }
        assert not (targets & AUDIT_MODEL_NAMES), (name, targets & AUDIT_MODEL_NAMES)


def test_no_platform_source_names_an_audit_model():
    offenders = []
    for path in (BACKEND_ROOT / "ccure_platform").rglob("*.py"):
        tree = ast.parse(path.read_text("utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "db.models":
                if any(a.name in AUDIT_MODEL_NAMES for a in node.names):
                    offenders.append(str(path.relative_to(BACKEND_ROOT)))
    assert not offenders, offenders


# ── offboarding ──────────────────────────────────────────────────────────────


def test_audit_registers_its_purge_hook_when_the_application_loads():
    import main  # noqa: F401  (the composition root imports ccure_audit.offboarding)
    from ccure_platform.offboarding import registered_user_purge_hooks

    assert "audit" in registered_user_purge_hooks()


def test_purge_hooks_run_in_order_on_the_callers_session():
    from ccure_platform import offboarding

    calls = []
    saved = dict(offboarding._user_purge_hooks)
    offboarding._user_purge_hooks.clear()
    try:
        offboarding.register_user_purge_hook(
            "a", lambda db, uid: calls.append(("a", uid))
        )
        offboarding.register_user_purge_hook(
            "b", lambda db, uid: calls.append(("b", uid))
        )
        db = MagicMock()
        offboarding.run_user_purge_hooks(db, "u-1")
        assert calls == [("a", "u-1"), ("b", "u-1")]
        db.commit.assert_not_called()
    finally:
        offboarding._user_purge_hooks.clear()
        offboarding._user_purge_hooks.update(saved)


def test_a_second_hook_cannot_take_a_registered_name():
    from ccure_platform import offboarding

    first = lambda db, uid: None  # noqa: E731
    offboarding.register_user_purge_hook("probe", first)
    try:
        offboarding.register_user_purge_hook("probe", first)  # the same one: a no-op
        with pytest.raises(ValueError):
            offboarding.register_user_purge_hook("probe", lambda db, uid: None)
    finally:
        offboarding._user_purge_hooks.pop("probe", None)


def test_audits_hook_detaches_exactly_what_the_route_used_to():
    from ccure_audit.offboarding import detach_user_from_audit_data
    from db.models import AssetNote, AssetTag, AssetVulnerability, Scan

    db = MagicMock()
    detach_user_from_audit_data(db, "u-9")
    queried = [c.args[0] for c in db.query.call_args_list]
    assert queried == [AssetNote, AssetTag, Scan, AssetVulnerability]
    assert db.query.return_value.filter.return_value.update.call_count == 4
    db.commit.assert_not_called()


def test_purge_user_asks_the_platform_not_audits_tables():
    source = (BACKEND_ROOT / "ccure_platform/administration/users.py").read_text()
    assert "run_user_purge_hooks(db, target_user_id)" in source
    for name in ("Scan", "AssetVulnerability", "AssetNote", "AssetTag"):
        assert f"{name}." not in source


# ── ownership of the moved pieces ────────────────────────────────────────────


def test_the_platform_api_exposes_what_modules_use():
    import ccure_platform.api as api

    for name in (
        "log_audit_event",
        "create_notification",
        "fan_out_notification",
        "NotificationType",
        "NotificationCategory",
        "register_user_purge_hook",
    ):
        assert name in api.__all__ and hasattr(api, name)


def test_the_audit_log_service_is_one_package():
    for name in ("writer", "taxonomy", "retention", "export", "router", "tasks"):
        assert (BACKEND_ROOT / f"ccure_platform/audit_log/{name}.py").is_file()


def test_the_health_root_and_scan_progress_are_separate_routers():
    health = (BACKEND_ROOT / "routers/health.py").read_text()
    progress = (BACKEND_ROOT / "routers/scan_progress.py").read_text()
    assert "/scan/progress" not in health and "/api/pipeline-modes" not in health
    assert "/scan/progress/{scan_id}" in progress
