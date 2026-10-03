"""
RBAC-2 — the populated role model: the five system roles with the real catalogue,
their permission matrices, scope, the default role, lifecycle, custom organisation
roles, and the property that a role's display name changes nothing.

Everything runs in a rolled-back transaction. No user in a real database is assigned
to a new role, and nothing here reads or changes a legacy table.
"""

from __future__ import annotations

import random

import pytest
from sqlalchemy.exc import DBAPIError

import ccure_platform.api as api
from ccure_platform import composition
from ccure_platform.rbac import contract as c
from ccure_platform.rbac import governance as g
from ccure_platform.rbac import legacy_map as lm
from ccure_platform.rbac import resolver
from ccure_platform.rbac.catalogue import (
    ensure_default_roles,
    sync,
)
from ccure_platform.rbac.model import (
    RbacDefaultRole,
    RbacPermission,
    RbacRole,
    RbacRolePermission,
    RbacRoleRevision,
    RbacUserRole,
)
from rbac_testing import (
    assign,
    force_state,
    make_org,
    make_user,
    platform_custom_role,
    rbac_db_fixture,  # noqa: F401
    role,
)

GOLDEN = lm.load_golden()
ORG_ROLES = (
    "platform.org_admin",
    "platform.analyst",
    "platform.viewer",
    "platform.scanner",
)


def held(db, role_key):
    return {
        r.permission_key
        for r in db.query(RbacRolePermission).filter_by(role_id=role(db, role_key).id)
    }


@pytest.fixture
def world(rbac_db):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    w = type("World", (), {})()
    w.db = rbac_db
    w.a, w.b = make_org(rbac_db), make_org(rbac_db)
    w.root = make_user(rbac_db, w.a)
    assign(rbac_db, w.root, role(rbac_db, "platform.superadmin"))
    for name, key in (
        ("oa", "platform.org_admin"),
        ("an", "platform.analyst"),
        ("vw", "platform.viewer"),
        ("sc", "platform.scanner"),
    ):
        u = make_user(rbac_db, w.a)
        assign(rbac_db, u, role(rbac_db, key))
        setattr(w, f"{name}_a", u)
    w.oa_b = make_user(rbac_db, w.b)
    assign(rbac_db, w.oa_b, role(rbac_db, "platform.org_admin"))
    return w


def keys_of(world, user, org=None):
    return set(api.effective_permissions(world.db, user, org_id=org).permissions)


# ── the five roles ───────────────────────────────────────────────────────────


def test_the_five_system_roles_have_stable_keys_labels_and_scopes(world):
    rows = {r.key: r for r in world.db.query(RbacRole).filter_by(kind="system")}
    assert set(rows) == set(c.LEGACY_ROLE_NAMES.values())
    assert rows["platform.superadmin"].assignable_scope == "platform"
    for key in ORG_ROLES:
        assert rows[key].assignable_scope == "organization" and rows[key].org_id is None
    assert all(r.managed_by == "code" and r.state == "active" for r in rows.values())
    assert {k: r.display_name for k, r in rows.items()} == {
        s.key: s.display_name for s in c.SYSTEM_ROLE_SEEDS
    }


def test_superadmin_holds_every_active_permission_as_rows_and_there_is_no_wildcard(
    world,
):
    active = {p.key for p in world.db.query(RbacPermission).filter_by(status="active")}
    assert len(active) == 67
    rows = held(world.db, "platform.superadmin")
    assert rows == active
    assert all(c.PERMISSION_KEY.match(k) for k in rows)  # every row is a real key
    assert role(world.db, "platform.superadmin").auto_grant_new_permissions is True


def test_each_organisation_role_holds_exactly_the_golden_set(world):
    for key in ORG_ROLES:
        assert held(world.db, key) == set(GOLDEN["role_grants"][key]), key


def test_the_role_hierarchy_is_the_one_the_legacy_roles_had(world):
    sc, vw, an, oa = (
        held(world.db, k)
        for k in (
            "platform.scanner",
            "platform.viewer",
            "platform.analyst",
            "platform.org_admin",
        )
    )
    assert sc < an < oa and vw < an
    assert not (sc | vw | an | oa) & {
        p["key"] for p in GOLDEN["permissions"] if p["scope_kind"] == "platform"
    }


def test_org_admin_holds_only_what_the_delegation_and_scope_rules_allow(world):
    perms = {p.key: p for p in world.db.query(RbacPermission)}
    for key in held(world.db, "platform.org_admin"):
        assert (
            perms[key].scope_kind == "organization"
            and perms[key].delegable_to_org_roles
        ), key
    # of the continuity keys it holds exactly one: assigning roles within its organisation
    assert {k for k in held(world.db, "platform.org_admin") if perms[k].continuity} == {
        c.ASSIGN_ROLE_KEY
    }


def test_org_admin_does_not_hold_role_governance_or_organisation_administration(world):
    oa = held(world.db, "platform.org_admin")
    for key in (
        "platform.role.create",
        "platform.role.update",
        "platform.role.retire",
        "platform.role.assign_platform",
        "platform.organization.create",
        "platform.organization.switch",
        "platform.email_domain.manage",
        "platform.audit_log.retention",
        "audit.vuln_feed.manage",
    ):
        assert key not in oa, key
    assert {
        "platform.role.read",
        "platform.permission.read",
        c.ASSIGN_ROLE_KEY,
    } <= oa  # as the legacy role


def test_audit_capabilities_are_not_given_to_platform_roles_by_accident(world):
    """The legacy vocabulary mixed product and platform concerns (``users:*`` beside
    ``scans:*``). The platform-only keys reach no organisation role, and every key an
    organisation role holds is in the namespace that owns the capability."""
    for key in ORG_ROLES:
        for permission in held(world.db, key):
            assert permission.split(".")[0] in ("platform", "audit")
    assert not any(
        k.startswith("audit.")
        for k in held(world.db, "platform.org_admin")
        if k.startswith("platform.")
    )
    # the viewer, scanner and analyst hold no platform administration at all
    for key in ("platform.viewer", "platform.scanner", "platform.analyst"):
        assert not [k for k in held(world.db, key) if k.startswith("platform.")], key


def test_scanner_remains_the_existing_human_role_and_is_not_a_service_identity(world):
    sc = role(world.db, "platform.scanner")
    assert (sc.kind, sc.assignable_scope, sc.managed_by) == (
        "system",
        "organization",
        "code",
    )
    assert keys_of(world, world.sc_a) == set(GOLDEN["role_grants"]["platform.scanner"])
    # a service identity resolves from token scopes, never from a role
    svc = c.Principal(kind="service", principal_id="svc:x", home_org_id=world.a.id)
    cat = resolver.load_catalogue(world.db)
    grants = resolver.service_grants(
        svc, ["audit.scan.read", "platform.user.read"], cat
    )
    assert {g_.permission_key for g_ in grants} == {
        "audit.scan.read",
        "platform.user.read",
    }


def test_the_matrix_is_deterministic_across_syncs_and_orders(rbac_db):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    first = {k: held(rbac_db, k) for k in (*ORG_ROLES, "platform.superadmin")}
    sources = list(reversed(composition.load_permission_sources()))
    assert not sync(rbac_db, sources, audit=False).changed
    assert {k: held(rbac_db, k) for k in first} == first


# ── scope ────────────────────────────────────────────────────────────────────


def test_an_organisation_role_holds_a_permission_only_in_its_own_organisation(world):
    own = api.ScopeContext(resource_org_id=world.a.id)
    other = api.ScopeContext(resource_org_id=world.b.id)
    assert api.can(world.db, world.oa_a, "platform.user.read", scope=own)
    out = api.authorize(world.db, world.oa_a, "platform.user.read", scope=other)
    assert not out.allowed and out.reason == c.CROSS_ORG
    assert api.can(world.db, world.oa_b, "platform.user.read", scope=other)
    assert not api.can(world.db, world.oa_b, "platform.user.read", scope=own)


def test_a_platform_scope_permission_is_refused_to_every_organisation_role(world):
    for user in (world.oa_a, world.an_a, world.vw_a, world.sc_a):
        out = api.authorize(world.db, user, "platform.organization.read")
        assert not out.allowed and out.reason == c.MISSING_PERMISSION


def test_superadmin_holds_platform_scope_permissions_and_reaches_other_organisations_only_through_the_switch(
    world,
):
    assert api.can(world.db, world.root, "platform.organization.read")
    assert api.can(world.db, world.root, "audit.scan.read")  # home organisation
    there = api.ScopeContext(resource_org_id=world.b.id)
    assert api.can(
        world.db, world.root, "audit.scan.read", scope=there
    )  # holds the switch
    # take the switch away (a platform role without it): the same request is refused
    no_switch = platform_custom_role(world.db, "ops", "Ops", "audit.scan.read")
    ops = make_user(world.db, world.a)
    assign(world.db, ops, no_switch)
    assert api.can(world.db, ops, "audit.scan.read")
    out = api.authorize(world.db, ops, "audit.scan.read", scope=there)
    assert not out.allowed and out.reason == c.ORG_SWITCH_REQUIRED


def test_every_organisation_role_decision_matches_its_golden_set_for_every_permission(
    world,
):
    perms = [p.key for p in world.db.query(RbacPermission)]
    for key, user in (
        ("platform.org_admin", world.oa_a),
        ("platform.analyst", world.an_a),
        ("platform.viewer", world.vw_a),
        ("platform.scanner", world.sc_a),
    ):
        expected = set(GOLDEN["role_grants"][key])
        for permission in perms:
            assert api.can(world.db, user, permission) == (permission in expected), (
                key,
                permission,
            )


def test_the_superadmin_is_allowed_every_active_permission_at_home_through_grants_alone(
    world,
):
    for permission in (p.key for p in world.db.query(RbacPermission)):
        assert api.can(world.db, world.root, permission), permission


# ── the default role ─────────────────────────────────────────────────────────


def test_the_default_role_is_viewer_and_viewer_is_a_safe_default(world):
    world.db.query(RbacDefaultRole).delete()
    world.db.flush()
    assert ensure_default_roles(world.db) == ("self_registration",)
    default = world.db.get(RbacDefaultRole, "self_registration")
    assert str(default.role_id) == str(role(world.db, "platform.viewer").id)
    assert g.default_role_violations(world.db, default.role_id) == ()
    perms = {p.key: p for p in world.db.query(RbacPermission)}
    for key in held(world.db, "platform.viewer"):
        p = perms[key]
        assert p.scope_kind == "organization" and p.delegable_to_org_roles
        assert not p.continuity and p.sensitivity == "normal", key
        assert not key.startswith("platform."), key


def test_no_other_system_role_is_a_safe_default_where_it_holds_continuity_or_platform_keys(
    world,
):
    assert g.default_role_violations(world.db, role(world.db, "platform.superadmin").id)
    assert g.default_role_violations(
        world.db, role(world.db, "platform.org_admin").id
    )  # holds assign_role


def test_a_continuity_permission_can_never_be_added_to_the_default_role(world):
    world.db.query(RbacDefaultRole).delete()
    world.db.flush()
    ensure_default_roles(world.db)
    with pytest.raises(DBAPIError):
        with world.db.begin_nested():
            world.db.add(
                RbacRolePermission(
                    role_id=role(world.db, "platform.viewer").id,
                    permission_key=c.ASSIGN_ROLE_KEY,
                )
            )
            world.db.flush()


# ── display names change nothing ─────────────────────────────────────────────

LABELS = [
    "CISO",
    "Manager",
    "Viewer",
    "platform.superadmin",
    "Superadmin",
    "Security Analyst",
    "Department Admin",
    "platform.viewer",
    "admin",
    "root",
]


def snapshot(world):
    return (
        {k: held(world.db, k) for k in (*ORG_ROLES, "platform.superadmin")},
        {
            n: keys_of(world, getattr(world, n))
            for n in ("root", "oa_a", "an_a", "vw_a", "sc_a", "oa_b")
        },
    )


def test_renaming_the_roles_to_arbitrary_labels_changes_no_grant_and_no_effective_permission(
    world,
):
    before = snapshot(world)
    rng = random.Random(42)
    roles = world.db.query(RbacRole).filter_by(kind="system").all()
    for round_ in range(15):
        for i, r in enumerate(roles):
            r.display_name = f"tmp-{round_}-{i}"
        world.db.flush()
        pool = rng.sample(LABELS, len(roles))
        for r, label in zip(roles, pool):
            r.display_name = label
        world.db.flush()
        assert snapshot(world) == before, pool
    # keys and ids never moved
    assert {r.key for r in roles} == set(c.LEGACY_ROLE_NAMES.values())


def test_the_roles_named_ciso_and_manager_are_the_same_roles_with_the_same_authority(
    world,
):
    root_role = role(world.db, "platform.superadmin")
    oa_role = role(world.db, "platform.org_admin")
    ids = (root_role.id, oa_role.id)
    before = snapshot(world)
    root_role.display_name, oa_role.display_name = "CISO", "Manager"
    world.db.flush()
    assert (root_role.id, oa_role.id) == ids
    assert (root_role.key, oa_role.key) == ("platform.superadmin", "platform.org_admin")
    assert snapshot(world) == before


# ── lifecycle ────────────────────────────────────────────────────────────────


def custom(world, slug="lead", name="Lead", *keys):
    row = RbacRole(
        key=f"custom.{world.a.id}.{slug}",
        display_name=name,
        kind="custom",
        assignable_scope="organization",
        org_id=world.a.id,
        managed_by="admin",
    )
    world.db.add(row)
    world.db.flush()
    from ccure_platform.rbac.model import append_revision

    append_revision(world.db, row, "created")
    for k in keys:
        world.db.add(RbacRolePermission(role_id=row.id, permission_key=k))
    world.db.flush()
    return row


def test_a_role_moves_active_retiring_retired_and_each_step_leaves_a_revision(world):
    row = custom(world, "lead", "Lead", "audit.scan.read")
    draft = g.transition_role(world.db, row, "retiring", changed_by="admin")
    assert row.state == "retiring" and draft.action == "rbac.role.retiring"
    draft = g.transition_role(
        world.db, row, "retired", changed_by="admin", reason="no longer needed"
    )
    assert row.state == "retired" and row.retired_at and row.retired_by == "admin"
    assert (
        row.retirement_reason == "no longer needed"
        and draft.action == "rbac.role.retired"
    )
    revs = [
        (r.revision, r.state, r.change_kind)
        for r in world.db.query(RbacRoleRevision)
        .filter_by(role_id=row.id)
        .order_by(RbacRoleRevision.revision)
    ]
    assert revs == [
        (1, "active", "created"),
        (2, "retiring", "state_changed"),
        (3, "retired", "retired"),
    ]
    assert row.revision == 3


def test_an_invalid_transition_is_refused_and_changes_nothing(world):
    row = custom(world)
    with pytest.raises(g.GovernanceError, match="invalid_transition"):
        g.transition_role(world.db, row, "retired")
    assert (row.state, row.revision) == ("active", 1)


def test_a_state_change_cannot_be_silent_the_database_refuses_it_without_a_revision(
    world,
):
    row = custom(world)
    with pytest.raises(DBAPIError, match="advance the revision"):
        with world.db.begin_nested():
            row.state = "retiring"  # no revision bump
            world.db.flush()


def test_a_retired_role_cannot_receive_a_new_assignment(world):
    row = custom(world, "lead", "Lead", "audit.scan.read")
    g.transition_role(world.db, row, "retiring")
    g.transition_role(world.db, row, "retired")
    with pytest.raises(DBAPIError, match="cannot be assigned"):
        with world.db.begin_nested():
            assign(world.db, make_user(world.db, world.a), row)


def test_a_retiring_role_cannot_receive_new_assignments_but_existing_ones_still_work(
    world,
):
    row = custom(world, "lead", "Lead", "audit.scan.read")
    user = make_user(world.db, world.a)
    assign(world.db, user, row)
    g.transition_role(world.db, row, "retiring")
    assert api.can(world.db, user, "audit.scan.read")  # no outage during retirement
    with pytest.raises(DBAPIError):
        with world.db.begin_nested():
            assign(world.db, make_user(world.db, world.a), row)


def test_the_retirement_gate_blocks_a_role_with_live_assignments_and_names_them(world):
    row = custom(world, "lead", "Lead", "audit.scan.read")
    assign(world.db, make_user(world.db, world.a), row)
    g.transition_role(world.db, row, "retiring")
    with pytest.raises(g.GovernanceError, match="active_assignments"):
        g.transition_role(world.db, row, "retired")
    assert row.state == "retiring"


def test_the_default_role_cannot_be_retired(world):
    world.db.query(RbacDefaultRole).delete()
    world.db.flush()
    ensure_default_roles(world.db)
    viewer = role(world.db, "platform.viewer")
    g.transition_role(world.db, viewer, "retiring")
    with pytest.raises(g.GovernanceError, match="default_role"):
        g.transition_role(world.db, viewer, "retired")


def test_a_retired_role_does_not_silently_become_active_again(world):
    row = custom(world, "lead", "Lead", "audit.scan.read")
    g.transition_role(world.db, row, "retiring")
    g.transition_role(world.db, row, "retired")
    # catalogue sync and seeding do not touch it
    sync(world.db, composition.load_permission_sources(), audit=False)
    assert row.state == "retired"
    # reactivating is a deliberate transition that leaves history
    draft = g.transition_role(world.db, row, "active", changed_by="admin")
    assert (
        row.state == "active"
        and row.retired_at is None
        and draft.action == "rbac.role.reactivated"
    )
    last = (
        world.db.query(RbacRoleRevision)
        .filter_by(role_id=row.id)
        .order_by(RbacRoleRevision.revision.desc())
        .first()
    )
    assert (last.change_kind, last.state) == ("reactivated", "active")


def test_reactivation_is_refused_when_the_display_name_is_taken(world):
    row = custom(world, "lead", "Lead", "audit.scan.read")
    g.transition_role(world.db, row, "retiring")
    g.transition_role(world.db, row, "retired")
    custom(world, "lead2", "Lead")  # the name is free once retired
    with pytest.raises(g.GovernanceError, match="display_name_in_use"):
        g.transition_role(world.db, row, "active")


def test_authority_for_a_lifecycle_change_follows_the_kind_of_role(world):
    cat = resolver.load_catalogue(world.db)
    actor_oa = resolver.principal_for_user(world.oa_a)
    oa_grants = resolver.resolve_grants(world.db, actor_oa)
    row = custom(world, "lead", "Lead", "audit.scan.read")
    from ccure_platform.rbac.model import to_role as view

    # the legacy org_admin holds no role-governance, so cannot retire (RBAC-0 D12)
    assert "missing_authority" in {
        v.code
        for v in g.check_role_lifecycle(
            actor_oa, oa_grants, cat, role=view(row), target="retiring"
        )
    }
    root = resolver.principal_for_user(world.root)
    root_grants = resolver.resolve_grants(world.db, root)
    assert (
        g.check_role_lifecycle(
            root, root_grants, cat, role=view(row), target="retiring"
        )
        == ()
    )
    system = view(role(world.db, "platform.viewer"))
    assert (
        g.check_role_lifecycle(root, root_grants, cat, role=system, target="retiring")
        == ()
    )
    assert "missing_authority" in {
        v.code
        for v in g.check_role_lifecycle(
            actor_oa, oa_grants, cat, role=system, target="retiring"
        )
    }


# ── replacement: a new role, migrate, retire ─────────────────────────────────


def test_replacing_a_role_is_a_new_role_then_a_migration_then_a_retirement(world):
    old = custom(
        world, "lead", "Security Lead", "audit.scan.read", "audit.finding.read"
    )
    people = [make_user(world.db, world.a) for _ in range(2)]
    old_rows = [assign(world.db, p, old) for p in people]
    new = custom(
        world,
        "lead_v2",
        "Security Lead (v2)",
        "audit.scan.read",
        "audit.finding.read",
        "audit.report.read",
    )
    g.transition_role(world.db, old, "retiring")
    from datetime import datetime, timezone

    for person, row in zip(people, old_rows):
        row.revoked_at, row.revoked_by, row.revoke_reason = (
            datetime.now(timezone.utc),
            "admin",
            "migrated",
        )
        assign(world.db, person, new)
    world.db.flush()
    g.transition_role(
        world.db, old, "retired", changed_by="admin", replaced_by_role_id=new.id
    )
    assert old.replaced_by_role_id == new.id and old.state == "retired"
    for person in people:
        assert keys_of(world, person) == {
            "audit.scan.read",
            "audit.finding.read",
            "audit.report.read",
        }
    # the old assignments are history, not gone
    history = world.db.query(RbacUserRole).filter_by(role_id=old.id).all()
    assert len(history) == 2 and {h.revoke_reason for h in history} == {"migrated"}
    # and the old role is no longer assignable
    with pytest.raises(DBAPIError):
        with world.db.begin_nested():
            assign(world.db, make_user(world.db, world.a), old)


def test_replacing_superadmin_with_a_ciso_role_needs_continuity_to_hold_first(world):
    """RBAC-0 R4-B on the real catalogue: create a platform role, assign it, verify
    continuity, retire the old one. Retiring while the old role is the only holder
    is refused."""
    sa = role(world.db, "platform.superadmin")
    g.transition_role(world.db, sa, "retiring")
    with pytest.raises(g.GovernanceError) as err:
        g.transition_role(world.db, sa, "retired")
    assert "active_assignments" in str(err.value)
    ciso = platform_custom_role(
        world.db,
        "ciso",
        "CISO",
        *sorted(
            p.key for p in world.db.query(RbacPermission).filter_by(status="active")
        ),
    )
    successor = make_user(world.db, world.a)
    assign(world.db, successor, ciso)
    from datetime import datetime, timezone

    root_row = (
        world.db.query(RbacUserRole)
        .filter_by(user_id=world.root.id, role_id=sa.id)
        .one()
    )
    root_row.revoked_at, root_row.revoke_reason = datetime.now(timezone.utc), "migrated"
    world.db.flush()
    # a new platform holder exists through the new role, so retiring the old one is allowed
    assert g.continuity_regressions(world.db, exclude_role_ids=(sa.id,)) == ()
    g.transition_role(
        world.db, sa, "retired", changed_by="admin", replaced_by_role_id=ciso.id
    )
    assert sa.state == "retired" and sa.replaced_by_role_id == ciso.id
    assert api.can(
        world.db, successor, "platform.organization.create"
    )  # same authority, new name
    assert not api.can(world.db, world.root, "platform.organization.create")  # revoked


def test_historical_records_survive_a_retirement(world):
    row = custom(world, "lead", "Lead", "audit.scan.read")
    user = make_user(world.db, world.a)
    a = assign(world.db, user, row)
    from datetime import datetime, timezone

    g.transition_role(world.db, row, "retiring")
    a.revoked_at, a.revoke_reason = datetime.now(timezone.utc), "role_retired"
    world.db.flush()
    g.transition_role(world.db, row, "retired")
    assert world.db.query(RbacUserRole).filter_by(user_id=user.id).count() == 1
    assert world.db.query(RbacRoleRevision).filter_by(role_id=row.id).count() == 3
    with pytest.raises(DBAPIError):  # a role is never deleted
        with world.db.begin_nested():
            world.db.delete(row)
            world.db.flush()


# ── custom organisation roles ────────────────────────────────────────────────


def actor_for(world, user):
    principal = resolver.principal_for_user(user)
    return (
        principal,
        resolver.resolve_grants(world.db, principal),
        resolver.load_catalogue(world.db),
    )


def test_a_custom_organisation_role_is_defined_with_only_delegable_permissions(world):
    principal, grants, cat = actor_for(world, world.root)
    row, draft = g.define_custom_org_role(
        world.db,
        principal,
        grants,
        cat,
        org_id=world.a.id,
        slug="soc_lead",
        display_name="SOC Lead",
        permission_keys=["audit.scan.read", "audit.finding.read"],
    )
    assert (row.kind, row.managed_by, row.assignable_scope, row.org_id) == (
        "custom",
        "admin",
        "organization",
        world.a.id,
    )
    assert row.key == f"custom.{world.a.id}.soc_lead" and row.state == "active"
    assert held(world.db, row.key) == {"audit.scan.read", "audit.finding.read"}
    assert (
        draft.action == "rbac.role.created" and draft.org_id == world.a.id
    )  # owned by the organisation
    assert (
        world.db.query(RbacRoleRevision)
        .filter_by(role_id=row.id, change_kind="created")
        .count()
        == 1
    )


def test_a_custom_role_can_never_hold_a_platform_only_capability_even_for_a_platform_actor(
    world,
):
    principal, grants, cat = actor_for(world, world.root)
    for key in (
        "platform.organization.create",
        "audit.vuln_feed.manage",
        "platform.role.assign_platform",
    ):
        with pytest.raises(g.GovernanceError, match="not_delegable"):
            g.define_custom_org_role(
                world.db,
                principal,
                grants,
                cat,
                org_id=world.a.id,
                slug="bad",
                display_name="Bad",
                permission_keys=[key],
            )


def test_an_administrator_cannot_put_a_permission_in_a_custom_role_that_they_lack(
    world,
):
    delegate = platform_custom_role(world.db, "role_manager", "Role Manager")
    # a delegated "Role Manager": may create org roles, holds only scan reading
    manager = make_user(world.db, world.a)
    from rbac_testing import custom_org_role

    mgr_role = custom_org_role(
        world.db, world.a, "mgr", "Manager", "platform.role.create", "audit.scan.read"
    )
    assign(world.db, manager, mgr_role)
    principal, grants, cat = actor_for(world, manager)
    ok, _ = g.define_custom_org_role(
        world.db,
        principal,
        grants,
        cat,
        org_id=world.a.id,
        slug="reader",
        display_name="Reader",
        permission_keys=["audit.scan.read"],
    )
    assert ok.state == "active"
    with pytest.raises(g.GovernanceError, match="escalation_ceiling"):
        g.define_custom_org_role(
            world.db,
            principal,
            grants,
            cat,
            org_id=world.a.id,
            slug="more",
            display_name="More",
            permission_keys=["audit.scan.read", "audit.finding.read"],
        )
    del delegate


def test_org_admin_cannot_create_a_role_until_role_governance_is_delegated_to_it(world):
    principal, grants, cat = actor_for(world, world.oa_a)
    with pytest.raises(g.GovernanceError, match="missing_authority"):
        g.define_custom_org_role(
            world.db,
            principal,
            grants,
            cat,
            org_id=world.a.id,
            slug="x",
            display_name="X",
            permission_keys=["audit.scan.read"],
        )


def test_a_custom_role_cannot_modify_a_system_role_or_be_one(world):
    principal, grants, cat = actor_for(world, world.root)
    assert "system_role_immutable" in {
        v.code
        for v in g.check_role_permissions(
            principal,
            grants,
            cat,
            operation="update",
            kind="system",
            assignable_scope="organization",
            org_id=None,
            permission_keys=["audit.scan.read"],
        )
    }
    with pytest.raises(g.GovernanceError, match="invalid_key"):
        g.define_custom_org_role(
            world.db,
            principal,
            grants,
            cat,
            org_id=world.a.id,
            slug="Bad Slug!",
            display_name="X",
            permission_keys=[],
        )
    # a custom role's key can never be platform.* (the database refuses it too)
    with pytest.raises(DBAPIError):
        with world.db.begin_nested():
            world.db.add(
                RbacRole(
                    key="platform.sneaky",
                    display_name="Sneaky",
                    kind="custom",
                    assignable_scope="organization",
                    org_id=world.a.id,
                    managed_by="admin",
                )
            )
            world.db.flush()


def test_a_custom_role_never_crosses_organisations(world):
    principal, grants, cat = actor_for(world, world.root)
    row, _ = g.define_custom_org_role(
        world.db,
        principal,
        grants,
        cat,
        org_id=world.a.id,
        slug="local",
        display_name="Local",
        permission_keys=["audit.scan.read"],
    )
    outsider = make_user(world.db, world.b)
    with pytest.raises(DBAPIError, match="outside its organisation"):
        with world.db.begin_nested():
            assign(world.db, outsider, row, "organization", world.b.id)
    insider = make_user(world.db, world.a)
    assign(world.db, insider, row)
    assert api.can(world.db, insider, "audit.scan.read")
    assert not api.can(
        world.db,
        insider,
        "audit.scan.read",
        scope=api.ScopeContext(resource_org_id=world.b.id),
    )


def test_the_database_independently_refuses_a_non_delegable_grant_to_a_custom_role(
    world,
):
    row = custom(world)
    for key in ("platform.organization.read", "audit.vuln_feed.manage"):
        with pytest.raises(DBAPIError, match="organisation-scope role"):
            with world.db.begin_nested():
                world.db.add(RbacRolePermission(role_id=row.id, permission_key=key))
                world.db.flush()


def test_a_custom_roles_display_name_is_a_label_the_key_and_grants_do_not_move(world):
    principal, grants, cat = actor_for(world, world.root)
    row, _ = g.define_custom_org_role(
        world.db,
        principal,
        grants,
        cat,
        org_id=world.a.id,
        slug="soc",
        display_name="SOC Lead",
        permission_keys=["audit.scan.read"],
    )
    user = make_user(world.db, world.a)
    assign(world.db, user, row)
    before, key = keys_of(world, user), row.key
    row.display_name = "CISO"
    world.db.flush()
    assert (keys_of(world, user), row.key) == (before, key)
