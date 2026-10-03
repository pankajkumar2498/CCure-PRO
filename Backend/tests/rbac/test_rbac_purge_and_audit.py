"""
RBAC-2 — the two follow-ups RBAC-1 left open.

**User purge.** ``purge_user`` hard-deletes an account and ``rbac_user_roles.user_id``
is ``ON DELETE RESTRICT``. The platform's offboarding contract is how RBAC cleans its
own rows first: the hook records each assignment in the audit trail and removes the
row, leaving role history intact and the foreign key exactly as strict as before.

**Audit attribution.** ``audit_logs`` is tenant-bound, so an event no organisation
owns cannot be written there without borrowing one. An event with an owning
organisation goes to that organisation's trail; one without goes to the platform
ledger. Nothing here invents an organisation.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from ccure_platform import composition
from ccure_platform.audit_log.writer import log_platform_event
from ccure_platform.models.platform_audit import PlatformAuditEvent
from ccure_platform.offboarding import registered_user_purge_hooks, run_user_purge_hooks
from ccure_platform.rbac import audit as ra
from ccure_platform.rbac import contract as c
from ccure_platform.rbac import governance as g
from ccure_platform.rbac import resolver
from ccure_platform.rbac.catalogue import sync
from ccure_platform.rbac.model import (
    RbacRole,
    RbacRoleRevision,
    RbacUserRole,
    append_revision,
)
from db.models import AuditLog, User
from rbac_testing import (
    assign,
    custom_org_role,
    make_org,
    make_user,
    platform_custom_role,
    rbac_db_fixture,  # noqa: F401
    role,
)


def audit_rows(db, org_id, like="rbac.%"):
    return (
        db.query(AuditLog)
        .filter(AuditLog.org_id == org_id, AuditLog.action.like(like))
        .order_by(AuditLog.created_at)
        .all()
    )


def ledger(db, like="rbac.%"):
    return (
        db.query(PlatformAuditEvent).filter(PlatformAuditEvent.action.like(like)).all()
    )


# ── the purge hook ───────────────────────────────────────────────────────────


def test_the_rbac_purge_hook_is_registered_by_the_route_that_needs_it():
    import ccure_platform.administration.users  # noqa: F401  (the purge route's module)

    assert "rbac" in registered_user_purge_hooks()
    assert "audit" in registered_user_purge_hooks()  # Audit's is unchanged


def test_a_purge_removes_the_users_assignments_so_the_foreign_key_lets_the_user_go(
    rbac_db,
):
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    assign(rbac_db, user, role(rbac_db, "platform.viewer"))
    assign(rbac_db, user, role(rbac_db, "platform.analyst"))
    run_user_purge_hooks(rbac_db, user.id)
    assert rbac_db.query(RbacUserRole).filter_by(user_id=user.id).count() == 0
    rbac_db.delete(user)
    rbac_db.flush()  # no foreign-key violation
    assert rbac_db.query(User).filter_by(id=user.id).count() == 0


def test_the_foreign_key_is_not_weakened_a_user_with_assignments_still_cannot_be_deleted(
    rbac_db,
):
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    assign(rbac_db, user, role(rbac_db, "platform.viewer"))
    with pytest.raises(DBAPIError):
        with rbac_db.begin_nested():
            rbac_db.delete(user)  # without the hook
            rbac_db.flush()
    rows = (
        rbac_db.execute(
            text(
                "SELECT confdeltype FROM pg_constraint WHERE conrelid = 'rbac_user_roles'::regclass "
                "AND confrelid = 'users'::regclass"
            )
        )
        .scalars()
        .all()
    )
    assert rows == ["r"]  # still ON DELETE RESTRICT


def test_the_purge_preserves_assignment_history_in_the_audit_trail(rbac_db):
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    viewer = role(rbac_db, "platform.viewer")
    viewer.display_name = "Read Only"
    rbac_db.flush()
    row = assign(rbac_db, user, viewer)
    run_user_purge_hooks(rbac_db, user.id)
    (event,) = audit_rows(rbac_db, org.id, "rbac.role.revoked")
    changes = event.changes
    assert event.org_id == org.id and event.actor_username == "system:user-purge"
    assert changes["reason"] == "user_purged" and changes["user_id"] == user.id
    assert changes["role_key"] == "platform.viewer" and changes["role_id"] == str(
        viewer.id
    )
    # the display name *at that moment*, because it is mutable
    assert changes["role_display_name_at_event"] == "Read Only"
    assert changes["assignment_id"] == str(row.id) and changes["was_live"] is True
    assert changes["scope_type"] == "organization" and changes["scope_org_id"] == org.id


def test_revoked_assignments_are_recorded_too_and_marked_as_not_live(rbac_db):
    from datetime import datetime, timezone

    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    row = assign(rbac_db, user, role(rbac_db, "platform.viewer"))
    row.revoked_at, row.revoke_reason = datetime.now(timezone.utc), "manual"
    rbac_db.flush()
    run_user_purge_hooks(rbac_db, user.id)
    (event,) = audit_rows(rbac_db, org.id, "rbac.role.revoked")
    assert (
        event.changes["was_live"] is False
        and event.changes["revoked_reason"] == "manual"
    )


def test_a_platform_scope_assignment_is_recorded_against_the_members_own_organisation(
    rbac_db,
):
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    assign(rbac_db, user, role(rbac_db, "platform.superadmin"))
    run_user_purge_hooks(rbac_db, user.id)
    (event,) = audit_rows(rbac_db, org.id, "rbac.platform_role.revoked")
    assert event.org_id == org.id and event.severity == "critical"
    assert (
        event.changes["scope_type"] == "platform"
        and event.changes["scope_org_id"] is None
    )


def test_the_roles_and_their_history_are_untouched_by_a_purge(rbac_db):
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    custom = custom_org_role(rbac_db, org, "lead", "Lead")
    assign(rbac_db, user, custom)
    before_revisions = (
        rbac_db.query(RbacRoleRevision).filter_by(role_id=custom.id).count()
    )
    run_user_purge_hooks(rbac_db, user.id)
    rbac_db.delete(user)
    rbac_db.flush()
    still = rbac_db.query(RbacRole).filter_by(id=custom.id).one()
    assert (still.key, still.state, still.display_name) == (
        custom.key,
        "active",
        "Lead",
    )
    assert (
        rbac_db.query(RbacRoleRevision).filter_by(role_id=custom.id).count()
        == before_revisions
    )


def test_another_users_assignments_are_not_touched(rbac_db):
    org = make_org(rbac_db)
    gone, stays = make_user(rbac_db, org), make_user(rbac_db, org)
    assign(rbac_db, gone, role(rbac_db, "platform.viewer"))
    keep = assign(rbac_db, stays, role(rbac_db, "platform.viewer"))
    run_user_purge_hooks(rbac_db, gone.id)
    assert rbac_db.query(RbacUserRole).filter_by(user_id=stays.id).one().id == keep.id


def test_a_user_with_no_assignments_writes_no_events(rbac_db):
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    before = rbac_db.query(AuditLog).filter(AuditLog.action.like("rbac.%")).count()
    run_user_purge_hooks(rbac_db, user.id)
    assert (
        rbac_db.query(AuditLog).filter(AuditLog.action.like("rbac.%")).count() == before
    )


# ── attribution: who owns an event ───────────────────────────────────────────


def snapshot(role_row, org_id=None):
    return ra.RoleSnapshot(
        role_id=str(role_row.id),
        role_key=role_row.key,
        display_name=role_row.display_name,
        org_id=org_id,
    )


def test_an_event_no_organisation_owns_goes_to_the_platform_ledger_and_invents_no_organisation(
    rbac_db,
):
    before_org = rbac_db.execute(text("SELECT count(*) FROM audit_logs")).scalar()
    draft = ra.role_event(
        "rbac.role.created", snapshot(role(rbac_db, "platform.viewer"))
    )
    assert draft.org_id is None and not draft.owned
    result = ra.emit(rbac_db, [draft], system_actor="system:test")
    assert (result.organization, result.platform) == (0, 1)
    assert (
        rbac_db.execute(text("SELECT count(*) FROM audit_logs")).scalar() == before_org
    )
    (row,) = ledger(rbac_db, "rbac.role.created")
    assert not hasattr(
        row, "org_id"
    )  # the table has no owner column to fill with a guess
    assert row.actor_kind == "system" and row.actor_label == "system:test"
    assert row.changes["role_key"] == "platform.viewer"


def test_an_organisation_role_event_belongs_to_that_organisation(rbac_db):
    org = make_org(rbac_db)
    other = make_org(rbac_db)
    custom = custom_org_role(rbac_db, org, "lead", "Lead")
    draft = ra.role_event(
        "rbac.role.renamed", snapshot(custom, custom.org_id), old="Lead", new="Chief"
    )
    assert draft.org_id == org.id
    result = ra.emit(rbac_db, [draft], system_actor="system:test")
    assert (result.organization, result.platform) == (1, 0)
    assert [r.org_id for r in audit_rows(rbac_db, org.id, "rbac.role.renamed")] == [
        org.id
    ]
    assert (
        audit_rows(rbac_db, other.id) == []
        and ledger(rbac_db, "rbac.role.renamed") == []
    )


def test_an_organisation_scope_assignment_event_records_the_assignments_organisation(
    rbac_db,
):
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    draft = ra.assignment_event(
        "rbac.role.assigned",
        snapshot(role(rbac_db, "platform.viewer")),
        user_id=user.id,
        user_org_id=org.id,
        scope_type="organization",
        scope_org_id=org.id,
    )
    assert draft.org_id == org.id
    ra.emit(rbac_db, [draft], system_actor="system:test")
    (row,) = audit_rows(rbac_db, org.id, "rbac.role.assigned")
    assert row.changes["user_id"] == user.id and row.changes["scope_org_id"] == org.id


def test_a_platform_scope_assignment_event_records_the_members_organisation_not_a_made_up_one(
    rbac_db,
):
    home, elsewhere = make_org(rbac_db), make_org(rbac_db)
    user = make_user(rbac_db, home)
    draft = ra.assignment_event(
        "rbac.platform_role.assigned",
        snapshot(role(rbac_db, "platform.superadmin")),
        user_id=user.id,
        user_org_id=home.id,
        scope_type="platform",
    )
    assert draft.org_id == home.id
    ra.emit(rbac_db, [draft], system_actor="system:test")
    assert len(audit_rows(rbac_db, home.id, "rbac.platform_role.assigned")) == 1
    assert (
        audit_rows(rbac_db, elsewhere.id) == []
        and ledger(rbac_db, "rbac.platform_role.assigned") == []
    )


def test_a_platform_scope_role_event_has_no_owner_even_when_a_human_does_it(rbac_db):
    org = make_org(rbac_db)
    human = make_user(rbac_db, org)
    custom = platform_custom_role(rbac_db, "ciso", "CISO")
    draft = ra.role_event("rbac.role.created", snapshot(custom))
    ra.emit(rbac_db, [draft], actor=human)
    (row,) = ledger(rbac_db, "rbac.role.created")
    # the actor's organisation is recorded as information, never as the owner
    assert (row.actor_kind, row.actor_user_id, row.actor_org_id) == (
        "user",
        human.id,
        org.id,
    )
    assert audit_rows(rbac_db, org.id, "rbac.role.created") == []


def test_one_emit_routes_each_draft_to_its_own_sink(rbac_db):
    org = make_org(rbac_db)
    custom = custom_org_role(rbac_db, org, "lead", "Lead")
    drafts = [
        ra.role_event("rbac.role.created", snapshot(custom, org.id)),
        ra.role_event("rbac.role.created", snapshot(role(rbac_db, "platform.viewer"))),
        ra.EventDraft(
            action="rbac.default_role.changed", resource_type="rbac_default_role"
        ),
    ]
    result = ra.emit(rbac_db, drafts, system_actor="system:test")
    assert (result.organization, result.platform, result.total) == (1, 2, 3)


def test_no_draft_defaults_to_an_organisation():
    draft = ra.EventDraft(action="rbac.role.created", resource_type="rbac_role")
    assert draft.org_id is None and not draft.owned


def test_emit_refuses_an_event_nobody_can_be_blamed_for(rbac_db):
    draft = ra.EventDraft(action="rbac.role.created", resource_type="rbac_role")
    with pytest.raises(ValueError, match="exactly one"):
        ra.emit(rbac_db, [draft])
    with pytest.raises(ValueError, match="exactly one"):
        ra.emit(rbac_db, [draft], actor=object(), system_actor="x")
    with pytest.raises(ValueError):
        log_platform_event(rbac_db, "rbac.role.created")


def test_an_event_that_is_not_an_rbac_event_is_refused():
    with pytest.raises(ValueError):
        ra.EventDraft(action="user.login", resource_type="x")


def test_an_unknown_assignment_scope_is_refused():
    with pytest.raises(ValueError):
        ra.assignment_event(
            "rbac.role.assigned",
            ra.RoleSnapshot(role_id="r", role_key="platform.viewer", display_name="V"),
            user_id="u",
            user_org_id="o",
            scope_type="galaxy",
        )


def test_the_platform_ledger_is_append_only(rbac_db):
    log_platform_event(rbac_db, "rbac.role.created", system_actor="system:test")
    row = rbac_db.query(PlatformAuditEvent).one()
    with pytest.raises(DBAPIError, match="append-only"):
        with rbac_db.begin_nested():
            row.action = "tampered"
            rbac_db.flush()
    with pytest.raises(DBAPIError, match="append-only"):
        with rbac_db.begin_nested():
            rbac_db.execute(text("DELETE FROM platform_audit_events"))


def test_the_platform_ledger_keeps_actor_attribution_honest(rbac_db):
    with pytest.raises(DBAPIError):  # a system event with no label
        with rbac_db.begin_nested():
            rbac_db.add(
                PlatformAuditEvent(action="x", severity="low", actor_kind="system")
            )
            rbac_db.flush()
    with pytest.raises(DBAPIError):  # a user event with no account
        with rbac_db.begin_nested():
            rbac_db.add(
                PlatformAuditEvent(action="x", severity="low", actor_kind="user")
            )
            rbac_db.flush()
    with pytest.raises(DBAPIError):  # an unknown severity
        with rbac_db.begin_nested():
            rbac_db.add(
                PlatformAuditEvent(
                    action="x", severity="severe", actor_kind="system", actor_label="s"
                )
            )
            rbac_db.flush()


def test_platform_events_are_redacted_like_tenant_events(rbac_db):
    log_platform_event(
        rbac_db,
        "rbac.role.created",
        system_actor="system:test",
        changes={"password": "hunter2", "role_key": "platform.viewer"},
    )
    row = rbac_db.query(PlatformAuditEvent).one()
    assert (
        row.changes["password"] != "hunter2"
        and row.changes["role_key"] == "platform.viewer"
    )


def test_the_severity_of_an_rbac_event_comes_from_the_shared_taxonomy(rbac_db):
    log_platform_event(rbac_db, "rbac.default_role.changed", system_actor="system:test")
    ra.register_severities()
    (row,) = ledger(rbac_db, "rbac.default_role.changed")
    assert row.severity == "high"


def test_a_failed_platform_write_raises_like_a_failed_tenant_write(rbac_db):
    with pytest.raises(DBAPIError):
        with rbac_db.begin_nested():
            log_platform_event(rbac_db, "x" * 200, system_actor="system:test")


# ── attribution is wired into the real operations ────────────────────────────


def test_the_default_role_change_is_a_platform_event(rbac_db):
    from ccure_platform.rbac.catalogue import ensure_default_roles
    from ccure_platform.rbac.model import RbacDefaultRole

    sync(rbac_db, composition.load_permission_sources(), audit=False)
    rbac_db.query(RbacDefaultRole).delete()
    rbac_db.flush()
    ensure_default_roles(rbac_db)
    org = make_org(rbac_db)
    other = custom_org_role(rbac_db, org, "starter", "Starter", "audit.scan.read")
    draft = g.configure_default_role(rbac_db, "self_registration", other.id)
    assert draft.org_id is None and draft.action == "rbac.default_role.changed"


def test_defining_a_custom_role_yields_an_event_owned_by_its_organisation(rbac_db):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    org = make_org(rbac_db)
    boss = make_user(rbac_db, org)
    assign(rbac_db, boss, role(rbac_db, "platform.superadmin"))
    principal = resolver.principal_for_user(boss)
    _, draft = g.define_custom_org_role(
        rbac_db,
        principal,
        resolver.resolve_grants(rbac_db, principal),
        resolver.load_catalogue(rbac_db),
        org_id=org.id,
        slug="lead",
        display_name="Lead",
        permission_keys=["audit.scan.read"],
    )
    assert draft.org_id == org.id
    ra.emit(rbac_db, [draft], actor=boss)
    assert len(audit_rows(rbac_db, org.id, "rbac.role.created")) == 1


def test_a_lifecycle_event_for_a_platform_role_is_a_platform_event_and_for_an_org_role_is_owned(
    rbac_db,
):
    org = make_org(rbac_db)
    org_role = custom_org_role(rbac_db, org, "lead", "Lead")
    platform_role = platform_custom_role(rbac_db, "ops", "Ops")
    assert g.transition_role(rbac_db, org_role, "retiring").org_id == org.id
    assert g.transition_role(rbac_db, platform_role, "retiring").org_id is None


def test_the_catalogue_sync_writes_only_to_the_platform_ledger_with_a_system_actor(
    rbac_db,
):
    before = rbac_db.execute(text("SELECT count(*) FROM audit_logs")).scalar()
    report = sync(rbac_db, composition.load_permission_sources())
    assert report.events_written == len(report.events) > 0
    assert rbac_db.execute(text("SELECT count(*) FROM audit_logs")).scalar() == before
    actions = {r.action for r in ledger(rbac_db)}
    assert {
        "rbac.catalogue.permission_registered",
        "rbac.system_role.synced",
    } <= actions
    assert {r.actor_label for r in ledger(rbac_db)} == {"system:rbac-sync"}
