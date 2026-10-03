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
        "shadow.py",
        "audit.py",
    } <= set(files)
    assert "dependencies.py" in files  # present, and deliberately not measured as new


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
            now, was = measured.get(path, {}).get(kind, 0), known.get(path, {}).get(
                kind, 0
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


def test_the_legacy_baseline_is_what_rbac_4_has_to_remove():
    total = sum(sum(v.values()) for v in rg.KNOWN_LEGACY_ROLE_IDENTITY_SITES.values())
    # recorded 3 Oct 2026: 40 sites in 22 files. It can only get smaller.
    assert 0 < total <= 40
    assert len(rg.KNOWN_LEGACY_ROLE_IDENTITY_SITES) <= 22


def test_seed_migration_tooling_and_test_contexts_are_exempt_by_design():
    assert {"alembic", "tests", "scripts"} <= rg.EXEMPT_DIRS
    assert "db/migrate_production_schema.py" in rg.EXEMPT_FILES
    assert "ccure_platform/rbac/contract.py" in rg.RBAC_SEED_FILES


def test_the_legacy_authority_is_measured_as_legacy_not_as_new():
    assert "ccure_platform/rbac/dependencies.py" in rg.RBAC_LEGACY_FILES
    assert "ccure_platform/rbac/dependencies.py" in rg.KNOWN_LEGACY_ROLE_IDENTITY_SITES
