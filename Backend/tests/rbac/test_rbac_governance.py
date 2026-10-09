"""
RBAC-1 — governance primitives: escalation ceiling, assignment and role-definition
checks, lifecycle, continuity, retirement gate and the default role.

The checks are pure functions over a principal, its grants and the catalogue, so
most of this needs no database. Continuity, retirement and the default role read
the tables and run in a rolled-back transaction.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ccure_platform.rbac import contract as c
from ccure_platform.rbac import governance as g
from ccure_platform.rbac.catalogue import sync
from ccure_platform.rbac.model import RbacDefaultRole, RbacUserRole, to_role
from rbac_testing import (
    assign,
    custom_org_role,
    decl,
    grant,
    make_org,
    make_user,
    platform_custom_role,
    rbac_db_fixture,  # noqa: F401  (registers the rbac_db fixture)
    role,
    source,
)

A, B = "org_a", "org_b"


def perm(key, scope_kind="organization", delegable=None, status="active"):
    module, resource, action = key.split(".")
    return c.Permission(
        key=key,
        module=module,
        resource=resource,
        action=action,
        description="d",
        scope_kind=scope_kind,
        sensitivity="normal",
        delegable_to_org_roles=(
            (scope_kind == "organization") if delegable is None else delegable
        ),
        continuity=False,
        status=status,
    )


CAT = {
    p.key: p
    for p in (
        perm("t.scan.read"),
        perm("t.scan.run"),
        perm("t.secret.read", delegable=False),
        perm("t.org.manage", scope_kind="platform"),
        perm("t.old.read", status="retired"),
        perm(c.ASSIGN_ROLE_KEY),
        perm(c.ASSIGN_PLATFORM_ROLE_KEY, scope_kind="platform"),
        perm(c.CREATE_ROLE_KEY),
        perm(c.UPDATE_ROLE_KEY),
        perm(c.CREATE_PLATFORM_ROLE_KEY, scope_kind="platform"),
    )
}


def human(pid="admin", home=A):
    return c.Principal(kind="human", principal_id=pid, home_org_id=home)


def og(key, org=A):
    return c.Grant(
        assignment_scope="organization", scope_org_id=org, permission_key=key
    )


def pg(key):
    return c.Grant(assignment_scope="platform", permission_key=key)


def role_view(**kw):
    base = dict(
        id="r1",
        key="custom.org_a.lead",
        display_name="Lead",
        kind="custom",
        assignable_scope="organization",
        org_id=A,
        managed_by="admin",
        state="active",
        auto_grant_new_permissions=False,
        replaced_by_role_id=None,
        revision=1,
    )
    base.update(kw)
    return c.Role(**base)


def codes(violations):
    return {v.code for v in violations}


def assignment(
    actor_grants,
    *,
    role=None,
    keys=("t.scan.read",),
    actor=None,
    scope_type="organization",
    scope_org=A,
    target="u2",
    target_org=A,
):
    return g.check_assignment(
        actor or human(),
        actor_grants,
        CAT,
        target_user_id=target,
        target_user_org_id=target_org,
        role=role or role_view(),
        role_permission_keys=keys,
        scope_type=scope_type,
        scope_org_id=scope_org,
    )


ADMIN_GRANTS = [og(c.ASSIGN_ROLE_KEY), og("t.scan.read"), og("t.scan.run")]


# ── lifecycle ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "current,target,ok",
    [
        ("active", "retiring", True),
        ("retiring", "retired", True),
        ("retiring", "active", True),
        ("retired", "active", True),
        ("active", "retired", False),
        ("retired", "retiring", False),
        ("active", "active", False),
        ("active", "banana", False),
    ],
)
def test_lifecycle_transitions(current, target, ok):
    assert (g.validate_transition(current, target) is None) is ok


def test_an_invalid_transition_says_what_is_allowed():
    v = g.validate_transition("active", "retired")
    assert v.code == "invalid_transition" and "retiring" in v.message


# ── assignment: the escalation ceiling and its neighbours ────────────────────


def test_an_authorised_assignment_has_no_violations():
    assert assignment(ADMIN_GRANTS) == ()


def test_an_administrator_cannot_grant_a_permission_they_do_not_hold():
    out = assignment(ADMIN_GRANTS, keys=("t.scan.read", "t.scan.run", "t.secret.read"))
    assert "escalation_ceiling" in codes(out)
    assert (
        "t.secret.read" in [v for v in out if v.code == "escalation_ceiling"][0].message
    )


def test_the_ceiling_is_the_actors_reach_in_that_organisation_not_elsewhere():
    only_in_b = [og(c.ASSIGN_ROLE_KEY, B), og("t.scan.read", B)]
    assert "missing_authority" in codes(assignment(only_in_b))
    held_elsewhere = [og(c.ASSIGN_ROLE_KEY), og("t.scan.read", B)]
    assert "escalation_ceiling" in codes(assignment(held_elsewhere))


def test_assigning_requires_the_assign_permission_itself():
    out = assignment([og("t.scan.read")])
    assert "missing_authority" in codes(out)


def test_an_account_cannot_assign_its_own_roles():
    assert "self_assignment" in codes(assignment(ADMIN_GRANTS, target="admin"))


def test_a_service_identity_cannot_assign_roles():
    svc = c.Principal(kind="service", principal_id="svc:x", home_org_id=A)
    assert "service_actor" in codes(assignment(ADMIN_GRANTS, actor=svc))


@pytest.mark.parametrize("state", ["retiring", "retired"])
def test_a_role_that_is_not_active_cannot_be_assigned(state):
    assert "role_not_assignable" in codes(
        assignment(ADMIN_GRANTS, role=role_view(state=state))
    )


def test_scope_must_match_what_the_role_declares():
    assert "scope_mismatch" in codes(
        assignment(
            ADMIN_GRANTS, role=role_view(assignable_scope="platform", org_id=None)
        )
    )


def test_cross_organisation_assignment_is_refused():
    assert "cross_org_assignment" in codes(assignment(ADMIN_GRANTS, target_org=B))
    assert "role_org_mismatch" in codes(
        assignment(ADMIN_GRANTS, role=role_view(org_id=B))
    )


def test_a_platform_scope_role_needs_the_platform_authority_and_platform_reach():
    r = role_view(assignable_scope="platform", org_id=None, key="custom.platform.ciso")
    org_only = assignment(ADMIN_GRANTS, role=r, scope_type="platform", scope_org=None)
    assert "missing_authority" in codes(org_only)
    platform_actor = [
        pg(c.ASSIGN_PLATFORM_ROLE_KEY),
        pg("t.scan.read"),
        pg("t.org.manage"),
    ]
    ok = assignment(
        platform_actor,
        role=r,
        keys=("t.scan.read", "t.org.manage"),
        scope_type="platform",
        scope_org=None,
    )
    assert ok == ()
    beyond = assignment(
        platform_actor,
        role=r,
        keys=("t.scan.read", "t.scan.run"),
        scope_type="platform",
        scope_org=None,
    )
    assert "escalation_ceiling" in codes(beyond)


def test_a_platform_assignment_names_no_organisation():
    r = role_view(assignable_scope="platform", org_id=None, key="custom.platform.ciso")
    out = assignment(
        [pg(c.ASSIGN_PLATFORM_ROLE_KEY)],
        role=r,
        keys=(),
        scope_type="platform",
        scope_org=A,
    )
    assert "scope_org_unexpected" in codes(out)


def test_a_retired_or_unknown_permission_in_a_role_is_reported():
    out = assignment(ADMIN_GRANTS, keys=("t.old.read", "t.never.heard"))
    assert {"retired_permission", "unknown_permission"} <= codes(out)


def test_the_ceiling_is_computed_without_asking_which_role_the_actor_has():
    """Two actors with the same grants but different roles behind them get the
    same answer: the ceiling is a function of grants only."""
    assert assignment(ADMIN_GRANTS) == assignment(list(reversed(ADMIN_GRANTS)))


# ── role definition ──────────────────────────────────────────────────────────


def define(actor_grants, **kw):
    base = dict(
        operation="create",
        kind="custom",
        assignable_scope="organization",
        org_id=A,
        permission_keys=("t.scan.read",),
    )
    base.update(kw)
    return g.check_role_permissions(human(), actor_grants, CAT, **base)


CREATOR = [
    og(c.CREATE_ROLE_KEY),
    og(c.UPDATE_ROLE_KEY),
    og("t.scan.read"),
    og("t.scan.run"),
]


def test_an_authorised_role_definition_has_no_violations():
    assert define(CREATOR) == ()


def test_creating_a_role_needs_the_create_permission_and_updating_needs_update():
    assert "missing_authority" in codes(define([og("t.scan.read")]))
    assert "missing_authority" in codes(
        define([og(c.CREATE_ROLE_KEY), og("t.scan.read")], operation="update")
    )


def test_a_system_role_is_immutable_to_administrators():
    assert "system_role_immutable" in codes(
        define(CREATOR, kind="system", operation="update")
    )


def test_a_creator_cannot_put_a_permission_in_a_role_that_they_do_not_hold():
    assert "escalation_ceiling" in codes(
        define(CREATOR, permission_keys=("t.scan.read", "t.secret.read"))
    )


def test_an_organisation_role_cannot_hold_a_platform_scope_or_non_delegable_permission():
    wide = CREATOR + [og("t.secret.read"), pg("t.org.manage")]
    out = define(wide, permission_keys=("t.secret.read", "t.org.manage"))
    assert [v.code for v in out].count("not_delegable") == 2


def test_an_account_cannot_add_permissions_to_a_role_it_holds_but_may_remove():
    assert "self_modification" in codes(
        define(CREATOR, operation="update", actor_holds_this_role=True)
    )
    assert (
        define(
            CREATOR, operation="update", actor_holds_this_role=True, permission_keys=()
        )
        == ()
    )


def test_a_platform_custom_role_is_first_class_and_obeys_the_same_ceiling():
    platform_actor = [
        pg(c.CREATE_PLATFORM_ROLE_KEY),
        pg("t.org.manage"),
        pg("t.scan.read"),
    ]
    ok = define(
        platform_actor,
        assignable_scope="platform",
        org_id=None,
        permission_keys=("t.org.manage", "t.scan.read"),
    )
    assert ok == ()
    over = define(
        platform_actor,
        assignable_scope="platform",
        org_id=None,
        permission_keys=("t.scan.run",),
    )
    assert "escalation_ceiling" in codes(over)
    nope = define(CREATOR, assignable_scope="platform", org_id=None, permission_keys=())
    assert "missing_authority" in codes(nope)


def test_an_organisation_role_names_its_organisation():
    assert "scope_org_missing" in codes(define(CREATOR, org_id=None))


def test_an_unknown_operation_is_a_programming_error():
    with pytest.raises(ValueError):
        define(CREATOR, operation="delete")


# ── continuity ───────────────────────────────────────────────────────────────


def catalogue_with_continuity(db):
    sync(
        db,
        [
            source(
                "platform",
                *[
                    c.PermissionDecl(
                        key=k,
                        description="d",
                        scope_kind=(
                            "organization" if k == c.ASSIGN_ROLE_KEY else "platform"
                        ),
                        continuity=True,
                        delegable_to_org_roles=(k == c.ASSIGN_ROLE_KEY),
                        default_grants=(
                            ("platform.org_admin",) if k == c.ASSIGN_ROLE_KEY else ()
                        ),
                    )
                    for k in sorted(c.CONTINUITY_KEYS)
                ],
            )
        ],
    )


def test_continuity_is_not_assessable_when_nothing_is_declared_never_ok(rbac_db):
    report = g.continuity_report(rbac_db)
    assert report.status == "not_assessable"
    assert report.undeclared_keys == tuple(sorted(c.CONTINUITY_KEYS))


def test_continuity_is_violated_with_no_holder_then_satisfied_per_organisation(rbac_db):
    catalogue_with_continuity(rbac_db)
    assert g.continuity_report(rbac_db).status == "violated"
    org = make_org(rbac_db)
    boss = make_user(rbac_db, org)
    assign(rbac_db, boss, role(rbac_db, "platform.superadmin"))
    report = g.continuity_report(rbac_db)
    assert report.platform_violations == ()
    # a platform holder covers the organisation they belong to ...
    assert org.id not in report.org_violations
    # ... and a new organisation with nobody is a violation until someone is assigned
    other = make_org(rbac_db)
    assert other.id in g.continuity_report(rbac_db).org_violations
    assign(rbac_db, make_user(rbac_db, other), role(rbac_db, "platform.org_admin"))
    assert other.id not in g.continuity_report(rbac_db).org_violations


def test_a_partially_declared_catalogue_is_incomplete_not_ok(rbac_db):
    sync(
        rbac_db,
        [
            source(
                "platform",
                c.PermissionDecl(
                    key=c.ASSIGN_PLATFORM_ROLE_KEY,
                    description="d",
                    scope_kind="platform",
                    continuity=True,
                    delegable_to_org_roles=False,
                ),
            )
        ],
    )
    org = make_org(rbac_db)
    assign(rbac_db, make_user(rbac_db, org), role(rbac_db, "platform.superadmin"))
    report = g.continuity_report(rbac_db)
    assert report.status in ("incomplete", "violated")
    assert report.status != "ok"
    assert c.ASSIGN_ROLE_KEY in report.undeclared_keys
    assert report.org_assessable is False


@pytest.mark.parametrize(
    "kw",
    [
        dict(active=False),
        dict(verified=False),
        dict(approved=False),
        dict(deleted=True),
    ],
)
def test_only_active_verified_humans_count_as_holders(rbac_db, kw):
    catalogue_with_continuity(rbac_db)
    org = make_org(rbac_db)
    ghost = make_user(rbac_db, org, **kw)
    assign(rbac_db, ghost, role(rbac_db, "platform.superadmin"))
    assert g.holders(rbac_db, c.ASSIGN_PLATFORM_ROLE_KEY, platform=True) == frozenset()
    real = make_user(rbac_db, org)
    assign(rbac_db, real, role(rbac_db, "platform.superadmin"))
    assert g.holders(rbac_db, c.ASSIGN_PLATFORM_ROLE_KEY, platform=True) == {real.id}


def test_revoked_and_expired_assignments_do_not_count(rbac_db):
    catalogue_with_continuity(rbac_db)
    org = make_org(rbac_db)
    u1, u2 = make_user(rbac_db, org), make_user(rbac_db, org)
    a1 = assign(rbac_db, u1, role(rbac_db, "platform.superadmin"))
    a2 = RbacUserRole(
        user_id=u2.id,
        role_id=role(rbac_db, "platform.superadmin").id,
        scope_type="platform",
        granted_at=datetime.now(timezone.utc) - timedelta(days=2),
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    rbac_db.add(a2)
    rbac_db.flush()
    assert g.holders(rbac_db, c.ASSIGN_PLATFORM_ROLE_KEY, platform=True) == {u1.id}
    a1.revoked_at, a1.revoke_reason = datetime.now(timezone.utc), "manual"
    rbac_db.flush()
    assert g.holders(rbac_db, c.ASSIGN_PLATFORM_ROLE_KEY, platform=True) == frozenset()


def test_the_exclusions_simulate_a_change(rbac_db):
    catalogue_with_continuity(rbac_db)
    org = make_org(rbac_db)
    only = make_user(rbac_db, org)
    sa_role = role(rbac_db, "platform.superadmin")
    row = assign(rbac_db, only, sa_role)
    regress = g.continuity_regressions(rbac_db, exclude_role_ids=(sa_role.id,))
    assert any(r.startswith("platform:") for r in regress)
    assert g.continuity_regressions(rbac_db, exclude_user_ids=(only.id,))
    assert g.continuity_regressions(rbac_db, exclude_assignment_ids=(row.id,))
    # a second holder makes the same change safe
    assign(rbac_db, make_user(rbac_db, org), sa_role)
    assert not [
        r
        for r in g.continuity_regressions(rbac_db, exclude_user_ids=(only.id,))
        if r.startswith("platform:")
    ]


def test_a_system_that_is_already_broken_does_not_block_a_change_that_does_not_worsen_it(
    rbac_db,
):
    catalogue_with_continuity(rbac_db)  # nobody holds anything: already violated
    assert g.continuity_report(rbac_db).status == "violated"
    custom = custom_org_role(rbac_db, make_org(rbac_db), "x", "X")
    assert g.continuity_regressions(rbac_db, exclude_role_ids=(custom.id,)) == ()


def test_the_organisation_invariant_counts_a_platform_holder_in_their_home_organisation(
    rbac_db,
):
    catalogue_with_continuity(rbac_db)
    org = make_org(rbac_db)
    boss = make_user(rbac_db, org)
    assign(rbac_db, boss, role(rbac_db, "platform.superadmin"))
    assert g.holders(rbac_db, c.ASSIGN_ROLE_KEY, platform=False, org_id=org.id) == {
        boss.id
    }
    other = make_org(rbac_db)
    assert (
        g.holders(rbac_db, c.ASSIGN_ROLE_KEY, platform=False, org_id=other.id)
        == frozenset()
    )


# ── retirement gate ──────────────────────────────────────────────────────────


def test_a_role_with_live_assignments_cannot_be_retired(rbac_db):
    org = make_org(rbac_db)
    custom = custom_org_role(rbac_db, org, "lead", "Lead")
    assert g.retirement_blockers(rbac_db, custom.id) == ()
    row = assign(rbac_db, make_user(rbac_db, org), custom)
    assert codes(g.retirement_blockers(rbac_db, custom.id)) == {"active_assignments"}
    row.revoked_at, row.revoke_reason = datetime.now(timezone.utc), "migrated"
    rbac_db.flush()
    assert g.retirement_blockers(rbac_db, custom.id) == ()


def test_the_default_role_cannot_be_retired(rbac_db):
    from ccure_platform.rbac.catalogue import ensure_default_roles

    role(rbac_db, "platform.viewer")
    rbac_db.query(RbacDefaultRole).delete()
    rbac_db.flush()
    ensure_default_roles(rbac_db)
    blockers = g.retirement_blockers(rbac_db, role(rbac_db, "platform.viewer").id)
    assert "default_role" in codes(blockers)


def test_retiring_the_last_holder_of_a_continuity_permission_is_blocked(rbac_db):
    catalogue_with_continuity(rbac_db)
    org = make_org(rbac_db)
    custom_platform = platform_custom_role(
        rbac_db, "keeper", "Keeper", *sorted(c.CONTINUITY_KEYS)
    )
    assign(rbac_db, make_user(rbac_db, org), custom_platform)
    assign(rbac_db, make_user(rbac_db, org), role(rbac_db, "platform.org_admin"))
    blockers = g.retirement_blockers(rbac_db, custom_platform.id)
    assert {"active_assignments", "continuity"} <= codes(blockers)


# ── default role ─────────────────────────────────────────────────────────────


def test_default_role_violations_are_readable(rbac_db):
    assert codes(
        g.default_role_violations(rbac_db, "00000000-0000-0000-0000-000000000000")
    ) == {"unknown_role"}
    assert codes(
        g.default_role_violations(rbac_db, role(rbac_db, "platform.superadmin").id)
    ) == {"not_org_assignable"}
    ok = role(rbac_db, "platform.viewer")
    assert g.default_role_violations(rbac_db, ok.id) == ()


def test_configure_default_role_changes_the_reference_and_returns_the_event(rbac_db):
    from ccure_platform.rbac.catalogue import ensure_default_roles

    role(rbac_db, "platform.viewer")
    rbac_db.query(RbacDefaultRole).delete()
    rbac_db.flush()
    ensure_default_roles(rbac_db)
    custom = custom_org_role(rbac_db, make_org(rbac_db), "starter", "Starter")
    draft = g.configure_default_role(
        rbac_db, "self_registration", custom.id, updated_by="admin"
    )
    assert draft.action == "rbac.default_role.changed"
    assert draft.changes["to_role_id"] == custom.id
    assert str(rbac_db.get(RbacDefaultRole, "self_registration").role_id) == str(
        custom.id
    )


def test_configure_default_role_refuses_and_changes_nothing(rbac_db):
    role(rbac_db, "platform.viewer")
    from ccure_platform.rbac.catalogue import ensure_default_roles

    rbac_db.query(RbacDefaultRole).delete()
    rbac_db.flush()
    ensure_default_roles(rbac_db)
    before = str(rbac_db.get(RbacDefaultRole, "self_registration").role_id)
    with pytest.raises(g.GovernanceError) as err:
        g.configure_default_role(
            rbac_db, "self_registration", role(rbac_db, "platform.superadmin").id
        )
    assert "not_org_assignable" in str(err.value)
    with pytest.raises(g.GovernanceError, match="unknown_purpose"):
        g.configure_default_role(
            rbac_db, "sso_jit", role(rbac_db, "platform.viewer").id
        )
    assert str(rbac_db.get(RbacDefaultRole, "self_registration").role_id) == before


def test_to_role_view_carries_identity_for_display_only(rbac_db):
    view = to_role(role(rbac_db, "platform.viewer"))
    assert (view.key, view.display_name, view.kind) == (
        "platform.viewer",
        "Viewer",
        "system",
    )
