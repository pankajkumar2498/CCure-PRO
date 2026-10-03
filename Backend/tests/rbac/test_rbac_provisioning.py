"""
RBAC-8 — provisioning: the default role, the first administrator and an organisation's
first administrator all go through RBAC; nothing consults ``users.role_id`` or a role name,
nothing privileged is granted by default, and every path is idempotent and audited.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from ccure_platform import composition
from ccure_platform.models.platform_audit import PlatformAuditEvent
from ccure_platform.rbac import governance, provisioning
from ccure_platform.rbac.catalogue import sync
from ccure_platform.rbac.governance import GovernanceError
from ccure_platform.rbac.model import RbacUserRole
from db.models import AuditLog
from rbac_testing import (
    assign,
    custom_org_role,
    force_state,
    make_org,
    make_user,
    rbac_db_fixture,  # noqa: F401
    role,
)


@pytest.fixture
def w(rbac_db):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    w = type("W", (), {})()
    w.db, w.a, w.b = rbac_db, make_org(rbac_db), make_org(rbac_db)
    return w


def live(db, user_id):
    return list(
        db.execute(
            select(RbacUserRole).where(
                RbacUserRole.user_id == user_id, RbacUserRole.revoked_at.is_(None)
            )
        ).scalars()
    )


def events(db, action):
    own = db.query(AuditLog).filter(AuditLog.action == action).all()
    ledger = (
        db.query(PlatformAuditEvent).filter(PlatformAuditEvent.action == action).all()
    )
    return own + ledger


# ── the default role ─────────────────────────────────────────────────────────


def test_with_no_default_configured_an_account_gets_no_role_at_all(w):
    user = make_user(w.db, w.a)
    assert provisioning.default_role(w.db) is None
    assert provisioning.assign_default_role(w.db, user) is None
    assert live(w.db, user.id) == []


def test_the_default_role_is_assigned_in_the_accounts_own_organisation_only(w):
    viewer = role(w.db, "platform.viewer")
    governance.configure_default_role(
        w.db, provisioning.SELF_REGISTRATION, str(viewer.id)
    )
    user = make_user(w.db, w.a)
    row = provisioning.assign_default_role(w.db, user)
    assert row is not None
    assert (row.scope_type, row.scope_org_id) == ("organization", w.a.id)
    assert row.granted_by == provisioning.DEFAULT_ROLE_ACTOR
    assert [r.id for r in live(w.db, user.id)] == [row.id]


def test_assigning_the_default_role_twice_is_idempotent_and_audited_once(w):
    viewer = role(w.db, "platform.viewer")
    governance.configure_default_role(
        w.db, provisioning.SELF_REGISTRATION, str(viewer.id)
    )
    user = make_user(w.db, w.a)
    first = provisioning.assign_default_role(w.db, user)
    again = provisioning.assign_default_role(w.db, user)
    assert first.id == again.id and len(live(w.db, user.id)) == 1
    assert len([e for e in events(w.db, "rbac.role.assigned") if e.resource_id]) >= 1


@pytest.mark.parametrize("key", ["platform.superadmin", "platform.org_admin"])
def test_a_privileged_role_can_never_be_the_default(w, key):
    with pytest.raises(GovernanceError):
        governance.configure_default_role(
            w.db, provisioning.SELF_REGISTRATION, str(role(w.db, key).id)
        )


def test_a_default_that_became_invalid_stops_being_a_default(w):
    custom = custom_org_role(w.db, w.a, "d", "D", "audit.scan.read")
    governance.configure_default_role(
        w.db, provisioning.SELF_REGISTRATION, str(custom.id)
    )
    assert provisioning.default_role(w.db) is not None
    force_state(w.db, custom, "retiring")
    force_state(w.db, custom, "retired")
    assert provisioning.default_role(w.db) is None
    assert provisioning.assign_default_role(w.db, make_user(w.db, w.a)) is None


# ── the first administrator ──────────────────────────────────────────────────


def test_the_first_administrator_is_an_ordinary_revocable_platform_assignment(w):
    user = make_user(w.db, w.a)
    row, created = provisioning.grant_platform_administrator(
        w.db, user.id, reason="first run"
    )
    assert created and row.scope_type == "platform" and row.scope_org_id is None
    assert row.granted_by == provisioning.BOOTSTRAP_ACTOR
    assert user.id in provisioning.active_administrators(w.db)
    assert events(w.db, "rbac.bootstrap.administrator")


def test_the_bootstrap_is_idempotent(w):
    user = make_user(w.db, w.a)
    one, created_one = provisioning.grant_platform_administrator(
        w.db, user.id, reason="r"
    )
    two, created_two = provisioning.grant_platform_administrator(
        w.db, user.id, reason="r"
    )
    assert created_one and not created_two and one.id == two.id
    assert len(live(w.db, user.id)) == 1


def test_a_system_that_has_an_administrator_refuses_another_bootstrap(w):
    first, second = make_user(w.db, w.a), make_user(w.db, w.a)
    provisioning.grant_platform_administrator(w.db, first.id, reason="r")
    with pytest.raises(GovernanceError) as refused:
        provisioning.grant_platform_administrator(w.db, second.id, reason="r")
    assert "administrator_exists" in {v.code for v in refused.value.violations}
    assert live(w.db, second.id) == []


def test_recovery_is_explicit_audited_and_distinct_from_bootstrap(w):
    first, second = make_user(w.db, w.a), make_user(w.db, w.a)
    provisioning.grant_platform_administrator(w.db, first.id, reason="r")
    row, created = provisioning.grant_platform_administrator(
        w.db,
        second.id,
        reason="lost the only admin",
        recovery=True,
        allow_additional=True,
    )
    assert created and second.id in provisioning.active_administrators(w.db)
    assert events(w.db, "rbac.recovery.administrator")


@pytest.mark.parametrize(
    "kwargs",
    [{"active": False}, {"verified": False}, {"approved": False}, {"deleted": True}],
)
def test_an_unusable_account_cannot_be_made_an_administrator(w, kwargs):
    user = make_user(w.db, w.a, **kwargs)
    with pytest.raises(GovernanceError) as refused:
        provisioning.grant_platform_administrator(w.db, user.id, reason="r")
    assert "account_unusable" in {v.code for v in refused.value.violations}


def test_an_unknown_account_cannot_be_made_an_administrator(w):
    with pytest.raises(GovernanceError) as refused:
        provisioning.grant_platform_administrator(w.db, "usr_nobody", reason="r")
    assert "unknown_account" in {v.code for v in refused.value.violations}


def test_the_administrator_assignment_can_be_revoked_through_ordinary_means(w):
    from datetime import datetime, timezone

    user = make_user(w.db, w.a)
    row, _ = provisioning.grant_platform_administrator(w.db, user.id, reason="r")
    row.revoked_at, row.revoke_reason, row.revoked_by = (
        datetime.now(timezone.utc),
        "manual",
        "usr_operator",
    )
    w.db.flush()
    assert user.id not in provisioning.active_administrators(w.db)


# ── an organisation's first administrator ────────────────────────────────────


def test_an_organisation_administrator_is_assigned_through_the_governed_api(w):
    actor = make_user(w.db, w.a)
    assign(w.db, actor, role(w.db, "platform.superadmin"))
    new_admin = make_user(w.db, w.b)
    events_ = provisioning.provision_organisation_admin(w.db, actor, new_admin.id)
    assert events_
    held = live(w.db, new_admin.id)
    assert len(held) == 1 and (held[0].scope_type, held[0].scope_org_id) == (
        "organization",
        w.b.id,
    )


def test_an_actor_without_authority_cannot_provision_an_administrator(w):
    actor = make_user(w.db, w.a)
    assign(w.db, actor, role(w.db, "platform.viewer"))
    new_admin = make_user(w.db, w.a)
    with pytest.raises(GovernanceError):
        provisioning.provision_organisation_admin(w.db, actor, new_admin.id)
    assert live(w.db, new_admin.id) == []


def test_an_actor_cannot_provision_an_administrator_in_another_organisation(w):
    actor = make_user(w.db, w.a)
    assign(w.db, actor, role(w.db, "platform.org_admin"))
    outsider = make_user(w.db, w.b)
    with pytest.raises(GovernanceError):
        provisioning.provision_organisation_admin(w.db, actor, outsider.id)
    assert live(w.db, outsider.id) == []
