"""
RBAC-2 — the populated permission catalogue.

The platform declares ``platform.*``, Audit declares ``audit.*``, both as data
through the module registration seam; Policy Pro, Rank and IR declare nothing and
keep their namespaces reserved. These tests hold the catalogue's shape — every key
valid, owned, documented — and that syncing it produces exactly the roles and grants
the frozen mapping says.

**RBAC-2 is prepared, not live**: nothing here touches a legacy table or a route.
"""

from __future__ import annotations

import re

import pytest

from ccure_platform import composition
from ccure_platform.modules import registry
from ccure_platform.rbac import contract as c
import json
from pathlib import Path
from ccure_platform.rbac.catalogue import (
    declaration_problems,
    sync,
    validate_declarations,
)
from ccure_platform.rbac.model import RbacPermission, RbacRolePermission
from rbac_testing import rbac_db_fixture, role, source  # noqa: F401
from testpaths import BACKEND_ROOT, REPO_ROOT

KNOWN = {s.key: s.assignable_scope for s in c.SYSTEM_ROLE_SEEDS}
DOC = REPO_ROOT / "docs" / "architecture" / "RBAC_PERMISSION_CATALOG.md"


@pytest.fixture(scope="module")
def sources():
    return composition.load_permission_sources()


@pytest.fixture(scope="module")
def decls(sources):
    return [d for s in sources for d in s.permissions]


@pytest.fixture(scope="module")
def frozen():
    return json.loads(
        (Path(__file__).parents[1] / "fixtures/rbac_catalogue.json").read_text()
    )


# ── every declaration loads and is valid ─────────────────────────────────────


def test_the_platform_and_audit_declare_and_nobody_else_does(sources):
    assert [(s.module_key, s.namespace) for s in sources] == [
        ("platform", "platform"),
        ("audit", "audit"),
    ]
    assert [len(s.permissions) for s in sources] == [30, 37]


def test_every_declaration_is_valid_with_no_problems(sources):
    assert validate_declarations(sources, known_roles=KNOWN) == []


def test_all_67_keys_are_distinct_three_segment_keys(decls):
    keys = [d.key for d in decls]
    assert len(keys) == len(set(keys)) == 67
    for key in keys:
        assert c.PERMISSION_KEY.match(key), key


def test_no_wildcard_and_no_role_name_inside_a_key(decls):
    from scripts.architecture.rbac_guardrails import FORBIDDEN_LITERALS

    for d in decls:
        assert "*" not in d.key
        for segment in d.key.split("."):
            assert segment not in FORBIDDEN_LITERALS, d.key
        assert "role_name" not in d.key and "display" not in d.key


def test_namespace_ownership_the_platform_owns_platform_and_audit_owns_audit(sources):
    for src in sources:
        for d in src.permissions:
            assert d.key.split(".")[0] == src.namespace == src.module_key


def test_a_declaration_in_another_namespace_is_refused(sources):
    stolen = c.PermissionDecl(
        key="audit.sneaky.read", description="d", scope_kind="organization"
    )
    out = validate_declarations(
        [
            c.ModuleDeclarations(
                module_key="platform", namespace="platform", permissions=(stolen,)
            )
        ],
        known_roles=KNOWN,
    )
    assert any("declaring namespace" in p for p in out)


def test_policy_pro_rank_and_ir_keep_their_namespaces_but_declare_nothing():
    held = registry.permission_namespaces()
    assert {held["policy"], held["rank"], held["ir"]} == {"policy_pro", "rank", "ir"}
    declaring = {m.key for m in registry.enabled_modules() if m.permission_modules}
    assert declaring == {"audit"}
    assert not any(
        d.key.startswith(("policy.", "rank.", "ir."))
        for s in composition.load_permission_sources()
        for d in s.permissions
    )


def test_every_key_has_a_description_a_scope_and_explicit_metadata(decls):
    for d in decls:
        assert d.description.strip() and d.description.endswith(".")
        assert d.scope_kind in c.SCOPE_KINDS
        assert d.sensitivity in c.SENSITIVITIES
        assert isinstance(d.delegable_to_org_roles, bool) and isinstance(
            d.continuity, bool
        )


def test_platform_scope_keys_are_never_delegable_and_organisation_scope_keys_always_are(
    decls,
):
    for d in decls:
        assert d.delegable_to_org_roles == (d.scope_kind == "organization"), d.key


def test_the_four_frozen_continuity_keys_are_flagged_and_nothing_else(decls):
    flagged = {d.key for d in decls if d.continuity}
    assert flagged == set(c.CONTINUITY_KEYS)


def test_default_grants_name_only_real_non_superadmin_system_roles(decls):
    for d in decls:
        for role_key in d.default_grants:
            assert role_key in KNOWN
            assert KNOWN[role_key] == "organization", (
                d.key,
                role_key,
            )  # superadmin is materialised
            assert d.scope_kind == "organization" and d.delegable_to_org_roles


def test_the_catalogue_is_deterministic(sources):
    again = composition.load_permission_sources()
    assert [(s.module_key, [d.key for d in s.permissions]) for s in again] == [
        (s.module_key, [d.key for d in s.permissions]) for s in sources
    ]


def test_keys_are_sorted_within_each_source_group_by_capability(decls):
    """Keys appear grouped by resource, so a diff of the catalogue reads."""
    seen = []
    for d in decls:
        resource = ".".join(d.key.split(".")[:2])
        if not seen or seen[-1] != resource:
            assert resource not in seen, f"{resource} is split across the file"
            seen.append(resource)


# ── permission governance (RBAC-2 §14) ───────────────────────────────────────


@pytest.mark.parametrize(
    "kwargs,fragment",
    [
        (dict(key="platform.user"), "three-segment"),
        (dict(scope_kind="galaxy"), "scope_kind"),
        (dict(sensitivity="secret"), "sensitivity"),
        (
            dict(scope_kind="platform", delegable_to_org_roles=True),
            "cannot be delegable",
        ),
        (dict(default_grants=("platform.nonexistent",)), "does not exist"),
        (dict(default_grants=("platform.viewer", "platform.viewer")), "twice"),
        (dict(continuity=True), "not a frozen continuity key"),
    ],
)
def test_invalid_declarations_are_rejected(kwargs, fragment):
    base = dict(key="platform.thing.read", description="d", scope_kind="organization")
    d = c.PermissionDecl(**{**base, **kwargs})
    assert any(fragment in p for p in declaration_problems("platform", d, KNOWN))


def test_a_duplicate_key_is_rejected(sources):
    twice = source("platform", *sources[0].permissions, sources[0].permissions[0])
    assert any(
        "declared by both" in p
        for p in validate_declarations([twice], known_roles=KNOWN)
    )


def test_administrators_cannot_invent_a_permission_there_is_no_write_path(rbac_db):
    """Permission definitions are developer-owned: the only writer of
    ``rbac_permissions`` is catalogue sync, and the stable API exposes no way to
    declare one at run time beyond handing ``PermissionDecl`` to a module's own
    declaration module."""
    import ccure_platform.api as api

    assert not [
        n
        for n in api.__all__
        if n.lower().startswith(
            ("register_permission", "create_permission", "define_permission")
        )
    ]
    writers = []
    for path in (BACKEND_ROOT / "ccure_platform").rglob("*.py"):
        if re.search(r"(?<!class )RbacPermission\(", path.read_text(encoding="utf-8")):
            writers.append(path.relative_to(BACKEND_ROOT).as_posix())
    assert writers == ["ccure_platform/rbac/catalogue.py"]


def test_a_retired_permission_cannot_be_newly_assigned_by_the_database(
    rbac_db, sources
):
    from datetime import datetime, timezone

    sync(rbac_db, sources, audit=False)
    row = rbac_db.get(RbacPermission, "audit.dashboard.read")
    row.status, row.retired_at = "retired", datetime.now(timezone.utc)
    rbac_db.flush()
    from sqlalchemy.exc import DBAPIError

    with pytest.raises(DBAPIError):
        with rbac_db.begin_nested():
            rbac_db.add(
                RbacRolePermission(
                    role_id=role(rbac_db, "platform.analyst").id,
                    permission_key="audit.dashboard.read",
                )
            )
            rbac_db.flush()


def test_an_undeclared_permission_cannot_be_granted_the_database_has_a_foreign_key(
    rbac_db, sources
):
    from sqlalchemy.exc import DBAPIError

    sync(rbac_db, sources, audit=False)
    with pytest.raises(DBAPIError):
        with rbac_db.begin_nested():
            rbac_db.add(
                RbacRolePermission(
                    role_id=role(rbac_db, "platform.analyst").id,
                    permission_key="audit.never.declared",
                )
            )
            rbac_db.flush()


# ── syncing the populated catalogue ──────────────────────────────────────────


def test_syncing_registers_all_67_active_permissions_and_is_idempotent(
    rbac_db, sources
):
    report = sync(rbac_db, sources, audit=False)
    assert len(report.registered) == 67
    rows = rbac_db.query(RbacPermission).all()
    assert len(rows) == 67 and {r.status for r in rows} == {"active"}
    assert not sync(rbac_db, sources, audit=False).changed


def test_the_synced_catalogue_matches_every_declaration_exactly(
    rbac_db, sources, decls
):
    sync(rbac_db, sources, audit=False)
    stored = {r.key: r for r in rbac_db.query(RbacPermission).all()}
    for d in decls:
        row = stored[d.key]
        assert (
            row.scope_kind,
            row.sensitivity,
            row.delegable_to_org_roles,
            row.continuity,
        ) == (
            d.scope_kind,
            d.sensitivity,
            d.delegable_to_org_roles,
            d.continuity,
        ), d.key
        assert row.module == d.key.split(".")[0]


def test_every_stored_grant_is_of_a_declared_permission(rbac_db, sources, decls):
    sync(rbac_db, sources, audit=False)
    declared = {d.key for d in decls}
    granted = {g.permission_key for g in rbac_db.query(RbacRolePermission).all()}
    assert granted <= declared and granted


# ── every key is documented ──────────────────────────────────────────────────


def test_every_key_has_an_owner_and_a_documented_reason(decls, frozen):
    entries = {p["key"]: p for p in frozen["permissions"]}
    for d in decls:
        entry = entries[d.key]
        assert entry["owner"] == d.key.split(".")[0]
        assert len(entry["reason"]) > 20, d.key


def test_the_catalogue_document_lists_every_key_with_its_owner_and_scope(decls):
    text = DOC.read_text(encoding="utf-8")
    for d in decls:
        assert f"`{d.key}`" in text, f"{d.key} is missing from {DOC.name}"
    assert "67" in text and "native rbac is authoritative" in text.lower()
