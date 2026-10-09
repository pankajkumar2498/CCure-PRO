"""
Role-identity ratchets — RBAC-1.

RBAC-0 (frozen): authorization never depends on a role's identity. Not its display
name, not its key, not a legacy role name — only permissions and scope. These
tests hold that line:

* the **new RBAC implementation** (``ccure_platform/rbac/``, minus the legacy
  ``dependencies.py``) has **zero** such sites, with two named seed-time
  exceptions;
* the **legacy authorization code** keeps the checks it has until RBAC-4, so its
  count is recorded per file and may only **fall**: a new site fails, and a
  recorded one that disappears fails too, so a removed check cannot return.

The measurement is shown to bite on synthetic source below — a ratchet that cannot
fail proves nothing. Measured from source with ``ast``; nothing is imported.
"""

from __future__ import annotations

import textwrap

import pytest

from scripts.architecture import rbac_guardrails as rg
from testpaths import BACKEND_ROOT


def legacy(source, path="routers/example.py"):
    return [
        (s.kind, s.what) for s in rg.scan_legacy_source(path, textwrap.dedent(source))
    ]


def new(source, path="ccure_platform/rbac/example.py"):
    return [(s.kind, s.what) for s in rg.scan_new_source(path, textwrap.dedent(source))]


# ── the new implementation: zero ─────────────────────────────────────────────


def test_the_new_rbac_implementation_makes_no_role_identity_decision():
    sites = rg.measure_new()
    assert not sites, "\n".join(f"{s.path}:{s.line} [{s.kind}] {s.what}" for s in sites)


def test_the_measurement_covers_the_whole_new_package():
    files = sorted(
        p.name for p in (BACKEND_ROOT / "ccure_platform" / "rbac").glob("*.py")
    )
    assert {
        "engine.py",
        "governance.py",
        "resolver.py",
        "administration.py",
        "audit.py",
    } <= set(files)
    assert (
        "dependencies.py" in files
    )  # the engine-only guards: measured strictly as new
    assert not {
        "shadow.py",
        "shadow_runtime.py",
        "authority.py",
        "legacy_scope.py",
    } & set(
        files
    )  # the shadow and the legacy authority are gone (RBAC-8)


# ── the ratchet bites (synthetic source) ─────────────────────────────────────


@pytest.mark.parametrize(
    "src",
    [
        'if role.name == "superadmin": pass',
        'if user.role.name == "org_admin": pass',
        'if role_name in ("superadmin", "org_admin"): pass',
        'if (getattr(role, "name", "") or "").lower() == "viewer": pass',
        'if "analyst" == current.role.name: pass',
        'x = user.role.name.lower() in {"scanner"}',
    ],
)
def test_legacy_role_name_comparisons_are_detected(src):
    assert legacy(src), src


@pytest.mark.parametrize(
    "src",
    [
        "@router.get('/x', dependencies=[Depends(require_role('superadmin'))])\ndef f(): pass",
        "guard = require_role(['superadmin', 'org_admin'])",
    ],
)
def test_require_role_calls_are_detected(src):
    assert ("require_role", "require_role(...)") in legacy(src)


@pytest.mark.parametrize(
    "src",
    [
        "def require_role(allowed): pass",  # a definition is not a call
        "if role.state == 'retired': pass",
        "if user.name == 'alice': pass",
        "ROLES = ['viewer', 'analyst']",
        "if kind == 'scanner': pass",
        "name = 'superadmin'",
    ],
)
def test_what_is_not_a_role_decision_is_not_flagged(src):
    assert legacy(src) == [], src


@pytest.mark.parametrize(
    "src",
    [
        'if role.key == "platform.viewer": pass',
        "if role.display_name == other: pass",
        'x = "superadmin"',
        'KEYS = {"platform.scanner"}',
        "if self.role.name == name: pass",
        "if r.key in granted: pass",
    ],
)
def test_the_new_implementation_refuses_role_identity_in_any_form(src):
    assert new(src, "ccure_platform/rbac/governance.py"), src


def test_contract_may_hold_role_keys_as_seed_data_and_catalogue_may_reconcile_them():
    assert (
        new('SEED = ("platform.viewer", "viewer")', "ccure_platform/rbac/contract.py")
        == []
    )
    assert new("ok = role.key in desired", "ccure_platform/rbac/catalogue.py") == []
    # but the literal rule still applies to the catalogue
    assert new('x = "platform.viewer"', "ccure_platform/rbac/catalogue.py")


def test_role_state_scope_and_ids_may_be_compared():
    assert (
        new(
            "if role.state != 'active' or role.assignable_scope == scope or role.id == other: pass",
            "ccure_platform/rbac/governance.py",
        )
        == []
    )


# ── the legacy ratchet ───────────────────────────────────────────────────────


def test_legacy_role_identity_sites_only_fall():
    measured = rg.measure_legacy()
    known = rg.KNOWN_LEGACY_ROLE_IDENTITY_SITES
    added, removed = [], []
    for path in sorted(set(measured) | set(known)):
        for kind in sorted(set(measured.get(path, {})) | set(known.get(path, {}))):
            now, was = (
                measured.get(path, {}).get(kind, 0),
                known.get(path, {}).get(kind, 0),
            )
            if now > was:
                added.append(f"{path} [{kind}]: {was} -> {now}")
            elif now < was:
                removed.append(f"{path} [{kind}]: {was} -> {now}")
    assert not added, (
        "new role-identity authorization checks (RBAC-0: authorize on permissions and "
        "scope, never on a role's name or key):\n  " + "\n  ".join(added)
    )
    assert not removed, (
        "legacy role-identity checks were removed — good. Lower "
        "KNOWN_LEGACY_ROLE_IDENTITY_SITES in scripts/architecture/rbac_guardrails.py "
        "(`python -m scripts.architecture.rbac_guardrails --baseline`):\n  "
        + "\n  ".join(removed)
    )


def test_the_legacy_baseline_is_empty_and_stays_empty():
    """RBAC-8: no runtime code decides by a role's name. The ratchet can no longer fall."""
    assert rg.KNOWN_LEGACY_ROLE_IDENTITY_SITES == {}
    assert rg.measure_legacy() == {}


def test_seed_migration_tooling_and_test_contexts_are_exempt_by_design():
    assert {"alembic", "tests", "scripts"} <= rg.EXEMPT_DIRS
    assert "db/migrate_production_schema.py" not in rg.EXEMPT_FILES
    assert "ccure_platform/rbac/contract.py" in rg.RBAC_SEED_FILES


def test_no_file_of_the_package_is_exempt_as_legacy_authority():
    assert rg.RBAC_LEGACY_FILES == frozenset()
    assert rg.measure_new() == []


# ── helper-mediated, named-set and legacy-relationship decisions ──────────────
# routers/topology.py decided by `_role_name(user) == "superadmin"` and
# `_role_name(user) not in _ORG_WIDE_ROLES`, reading a `user.role` relationship that
# native accounts no longer have. The ratchet was blind to both shapes and reported 0.


@pytest.mark.parametrize(
    "src",
    [
        # the helper returns a role's name; comparing its result is the same decision
        'if _role_name(user) == "superadmin": pass',
        'if get_role_name(u) in ("org_admin", "superadmin"): pass',
        # a named set of roles, tested from anywhere
        '_WIDE = {"superadmin", "org_admin"}\nif who not in _WIDE: pass',
        '_WIDE: frozenset = frozenset({"platform.org_admin"})\nok = x in _WIDE',
        # the removed legacy relationship
        "n = user.role.name",
        "r = current_user.role",
        'r = getattr(user, "role", None)',
    ],
)
def test_helper_mediated_and_named_set_role_decisions_are_detected(src):
    assert legacy(src), src


@pytest.mark.parametrize(
    "src",
    [
        # a word list that happens to hold one role-like word is not a role set
        '_WORDS = {"viewer", "home", "pro"}\nok = t in _WORDS',
        "x = message.role",  # a chat message's role, not an account's
        'if _role_name_of_field(x) == "a": pass',
    ],
)
def test_the_wider_detection_does_not_flag_unrelated_code(src):
    assert legacy(src) == [], src


def test_the_old_topology_helpers_would_have_been_caught():
    old = """
_ORG_WIDE_ROLES = {"superadmin", "org_admin"}
def _role_name(user):
    return (getattr(getattr(user, "role", None), "name", "") or "").lower()
def _resolve_org(user, requested_org):
    if _role_name(user) == "superadmin" and requested_org:
        return requested_org
def _authorize_scan(user, scan):
    if _role_name(user) not in _ORG_WIDE_ROLES and scan.created_by != user.id:
        raise PermissionError
"""
    kinds = {k for k, _ in legacy(old, "routers/topology.py")}
    assert {"role_identity_compare", "role_set_compare", "legacy_role_read"} <= kinds


def test_the_inventory_derives_the_role_name_decision_count_from_source():
    import json

    from scripts.rbac import build_migration_inventory as inv

    built = inv.build()["final_state"]["role_name_decisions_remaining"]
    assert built == len(rg.legacy_sites()) == 0
    assert (
        json.loads(inv.INVENTORY.read_text())["final_state"][
            "role_name_decisions_remaining"
        ]
        == built
    )
