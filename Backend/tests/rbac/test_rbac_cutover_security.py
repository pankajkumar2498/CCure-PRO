"""
RBAC-8 — security cutover: Platform RBAC is the only authority, so nothing a client, a
column or a name can claim moves a decision. Each test drives the real engine (and, for
escalation, the governed administration service) against a rolled-back database.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ccure_platform import composition
from ccure_platform.rbac import administration as admin
from ccure_platform.rbac import provisioning
from ccure_platform.rbac.catalogue import sync
from ccure_platform.rbac.dependencies import has_permission
from ccure_platform.rbac.governance import GovernanceError
from db.models import Role
from rbac_testing import (
    assign,
    custom_org_role,
    force_state,
    make_org,
    make_user,
    rbac_db_fixture,  # noqa: F401
    role,
)

SCAN_READ = "audit.scan.read"
SWITCH = "platform.organization.switch"


@pytest.fixture
def w(rbac_db):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    w = type("W", (), {})()
    w.db, w.a, w.b = rbac_db, make_org(rbac_db), make_org(rbac_db)
    return w


def person(w, org, system_role=None):
    user = make_user(w.db, org)
    if system_role:
        assign(w.db, user, role(w.db, system_role))
    return user


# ── what is never an authority ───────────────────────────────────────────────


def test_a_user_with_no_role_holds_nothing(w):
    nobody = person(w, w.a)
    assert not has_permission(w.db, nobody, SCAN_READ)
    assert not has_permission(w.db, nobody, SWITCH)


def test_the_legacy_role_column_is_not_an_authority(w):
    user = person(w, w.a)
    user.role_id = w.db.query(Role).filter(Role.name == "superadmin").one().id
    w.db.flush()
    assert not has_permission(w.db, user, SCAN_READ)
    assert not has_permission(w.db, user, SWITCH)


@pytest.mark.parametrize("label", ["Superadmin", "superadmin", "CISO", "root"])
def test_a_display_name_grants_nothing(w, label):
    role(w.db, "platform.superadmin").display_name = "Chief"  # free the name first
    w.db.flush()
    viewer = role(w.db, "platform.viewer")
    viewer.display_name = label
    w.db.flush()
    user = person(w, w.a, "platform.viewer")
    assert has_permission(w.db, user, SCAN_READ)
    assert not has_permission(w.db, user, SWITCH)
    assert not has_permission(w.db, user, "platform.user.delete")


def test_renaming_the_superadmin_role_takes_nothing_away(w):
    sa = person(w, w.a, "platform.superadmin")
    role(w.db, "platform.superadmin").display_name = "Chief"
    w.db.flush()
    assert has_permission(w.db, sa, SWITCH)


def test_a_forged_organisation_proves_nothing(w):
    admin_a = person(w, w.a, "platform.org_admin")
    assert has_permission(w.db, admin_a, SCAN_READ, org_id=w.a.id)
    assert not has_permission(w.db, admin_a, SCAN_READ, org_id=w.b.id)


def test_cross_organisation_reach_is_only_the_switch_grant(w):
    org_admin = person(w, w.a, "platform.org_admin")
    assert not has_permission(w.db, org_admin, SWITCH)
    custom = custom_org_role(w.db, w.a, "c", "C", SCAN_READ)
    assert not has_permission(w.db, person_with(w, custom), SWITCH)


def person_with(w, role_row):
    user = make_user(w.db, w.a)
    assign(w.db, user, role_row)
    return user


# ── account and assignment state ─────────────────────────────────────────────


@pytest.mark.parametrize("kwargs", [{"active": False}, {"deleted": True}])
def test_a_disabled_or_deleted_account_holds_nothing(w, kwargs):
    user = make_user(w.db, w.a, **kwargs)
    assign(w.db, user, role(w.db, "platform.org_admin"))
    assert not has_permission(w.db, user, SCAN_READ)


def test_a_revoked_assignment_holds_nothing_on_the_next_call(w):
    user = make_user(w.db, w.a)
    row = assign(w.db, user, role(w.db, "platform.viewer"))
    assert has_permission(w.db, user, SCAN_READ)
    row.revoked_at = datetime.now(timezone.utc)
    row.revoke_reason, row.revoked_by = "manual", "usr_operator"
    w.db.flush()
    assert not has_permission(w.db, user, SCAN_READ)


def test_a_retired_role_holds_nothing(w):
    custom = custom_org_role(w.db, w.a, "r", "R", SCAN_READ)
    user = person_with(w, custom)
    assert has_permission(w.db, user, SCAN_READ)
    force_state(w.db, custom, "retiring")
    force_state(w.db, custom, "retired")
    assert not has_permission(w.db, user, SCAN_READ)


def test_several_roles_union_and_nothing_more(w):
    user = make_user(w.db, w.a)
    assign(w.db, user, role(w.db, "platform.viewer"))
    assign(w.db, user, custom_org_role(w.db, w.a, "x", "X", "audit.scan.read_all"))
    assert has_permission(w.db, user, SCAN_READ)
    assert has_permission(w.db, user, "audit.scan.read_all")
    assert not has_permission(w.db, user, "platform.user.delete")


# ── escalation through the governed administration ───────────────────────────


def test_nobody_assigns_themselves_a_role(w):
    actor = person(w, w.a, "platform.org_admin")
    with pytest.raises(GovernanceError):
        admin.assign(
            w.db,
            admin.actor_for(w.db, actor),
            actor.id,
            str(role(w.db, "platform.org_admin").id),
        )


def test_an_org_admin_cannot_assign_the_superadmin_role(w):
    actor = person(w, w.a, "platform.org_admin")
    target = person(w, w.a)
    with pytest.raises(GovernanceError):
        admin.assign(
            w.db,
            admin.actor_for(w.db, actor),
            target.id,
            str(role(w.db, "platform.superadmin").id),
        )
    assert not has_permission(w.db, target, SWITCH)


def test_an_org_admin_cannot_assign_in_another_organisation(w):
    actor = person(w, w.a, "platform.org_admin")
    outsider = person(w, w.b)
    with pytest.raises(GovernanceError):
        admin.assign(
            w.db,
            admin.actor_for(w.db, actor),
            outsider.id,
            str(role(w.db, "platform.viewer").id),
        )


def test_a_custom_role_cannot_exceed_its_creators_own_permissions(w):
    actor = person(w, w.a, "platform.org_admin")
    assert not has_permission(w.db, actor, SWITCH)
    with pytest.raises(GovernanceError):
        admin.create_custom_role(
            w.db,
            admin.actor_for(w.db, actor),
            org_id=w.a.id,
            display_name="Sneaky",
            description=None,
            permission_keys=[SWITCH],
        )


# ── losing the last administrator is not permanent ───────────────────────────


def test_the_last_administrator_cannot_be_removed_through_the_api(w):
    sa = person(w, w.a, "platform.superadmin")
    other = person(w, w.a, "platform.superadmin")
    actor = admin.actor_for(w.db, other)
    first = [r for r in admin.user_assignments(w.db, actor, sa.id)][0]
    # two administrators: one may go
    admin.revoke(w.db, actor, first["id"], reason="manual")
    # the last one may not
    last = [
        r for r in admin.user_assignments(w.db, admin.actor_for(w.db, other), other.id)
    ][0]
    with pytest.raises(GovernanceError):
        admin.revoke(w.db, admin.actor_for(w.db, other), last["id"], reason="manual")


def test_an_operator_can_recover_a_system_with_no_administrator(w):
    # the platform has no administrator: the governed API cannot be used, the
    # explicit, audited operator path can
    assert not provisioning.active_administrators(w.db)
    user = person(w, w.a)
    row, created = provisioning.grant_platform_administrator(
        w.db, user.id, reason="recovery drill", recovery=True
    )
    assert created and user.id in provisioning.active_administrators(w.db)
    assert has_permission(w.db, user, SWITCH)
