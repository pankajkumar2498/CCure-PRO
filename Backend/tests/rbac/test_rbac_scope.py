"""
RBAC-5 — scope: WHERE a principal may act, kept apart from WHAT it may do.

Everything here drives the real seams (``ccure_platform.api``'s
``resolve_active_organisation`` / ``acts_across_organisations`` /
``resource_organisation_allowed`` / ``check_role_assignment`` and the organisation-aware
``user_has_permission``) against a rolled-back database, with the scope paths switched
on for the test only. The default (off) is proved first.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException

import ccure_platform.api as api
from ccure_platform import composition
from ccure_platform.rbac import authority as au
from ccure_platform.rbac import scope
from ccure_platform.rbac.catalogue import sync
from config import AppConfig
from db.models import AuditLog, Organization, Role
from rbac_testing import (
    assign,
    custom_org_role,
    force_state,
    make_org,
    make_user,
    rbac_db_fixture,  # noqa: F401
    role,
)


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    au.recorder.reset()
    au.restore()
    au.set_migrated_paths(None)
    monkeypatch.setattr(AppConfig, "RBAC_AUTHORITY_MODE", "off")
    monkeypatch.setattr(AppConfig, "RBAC_AUTHORITY_PATHS", "")
    yield
    au.set_migrated_paths(None)


def on(monkeypatch):
    monkeypatch.setattr(AppConfig, "RBAC_AUTHORITY_MODE", "enforce")
    monkeypatch.setattr(AppConfig, "RBAC_AUTHORITY_PATHS", "*")


@pytest.fixture
def w(rbac_db):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    w = type("W", (), {})()
    w.db = rbac_db
    w.a, w.b = make_org(rbac_db), make_org(rbac_db)
    w.dead = make_org(rbac_db)
    w.dead.is_active = False
    rbac_db.flush()

    def person(org, legacy_role, rbac_role=None):
        user = make_user(rbac_db, org)
        user.role_id = rbac_db.query(Role).filter(Role.name == legacy_role).one().id
        rbac_db.flush()
        rbac_db.refresh(user)
        if rbac_role:
            assign(rbac_db, user, role(rbac_db, rbac_role))
        return user

    w.person = person
    w.superadmin = person(w.a, "superadmin", "platform.superadmin")
    w.admin_a = person(w.a, "org_admin", "platform.org_admin")
    w.analyst_a = person(w.a, "analyst", "platform.analyst")
    return w


def events(db, action, org_id=None):
    q = db.query(AuditLog).filter(AuditLog.action == action)
    if org_id:
        q = q.filter(AuditLog.org_id == org_id)
    return q.all()


# ── off by default ───────────────────────────────────────────────────────────


def test_off_by_default_is_exactly_the_legacy_rule(w):
    assert api.resolve_active_organisation(w.superadmin, w.b.id) == w.b.id
    assert api.resolve_active_organisation(w.admin_a, w.b.id) == w.a.id
    assert api.resolve_active_organisation(w.admin_a, None) == w.a.id
    assert api.acts_across_organisations(w.superadmin) is True
    assert api.acts_across_organisations(w.admin_a) is False
    # legacy trusted the name outright, unvalidated
    assert api.resolve_active_organisation(w.superadmin, "org_nowhere") == "org_nowhere"
    assert au.recorder.snapshot()["by_path"] == {}


# ── organisation switching ───────────────────────────────────────────────────


def test_a_superadmin_enters_another_organisation_and_it_is_audited(w, monkeypatch):
    on(monkeypatch)
    with scope.use_audit_session(w.db):
        assert api.resolve_active_organisation(w.superadmin, w.b.id) == w.b.id
    found = events(w.db, "rbac.org_switch.entered", w.b.id)
    assert len(found) == 1
    e = found[0]
    # owned by the entered organisation; the actor is real; nothing invented
    assert e.org_id == w.b.id and e.actor_user_id == w.superadmin.id
    assert e.changes["from_org_id"] == w.a.id and e.changes["to_org_id"] == w.b.id


def test_naming_your_own_organisation_is_not_a_switch(w, monkeypatch):
    on(monkeypatch)
    with scope.use_audit_session(w.db):
        assert api.resolve_active_organisation(w.superadmin, w.a.id) == w.a.id
        assert api.resolve_active_organisation(w.superadmin, None) == w.a.id
    assert events(w.db, "rbac.org_switch.entered") == []


def test_an_org_admin_cannot_cross_its_boundary_and_the_attempt_is_recorded(
    w, monkeypatch
):
    on(monkeypatch)
    with scope.use_audit_session(w.db):
        assert api.resolve_active_organisation(w.admin_a, w.b.id) == w.a.id
    assert events(w.db, "rbac.org_switch.entered") == []
    denied = events(w.db, "rbac.scope.denied", w.a.id)
    assert len(denied) == 1 and denied[0].changes["requested_org_id"] == w.b.id
    assert denied[0].actor_user_id == w.admin_a.id


def test_a_forged_organisation_id_proves_nothing(w, monkeypatch):
    on(monkeypatch)
    with scope.use_audit_session(w.db):
        for forged in (w.b.id, "org_default", "' OR 1=1 --", "../" + w.b.id):
            assert api.resolve_active_organisation(w.analyst_a, forged) == w.a.id


def test_missing_and_inactive_organisations_fail_closed(w, monkeypatch):
    on(monkeypatch)
    with scope.use_audit_session(w.db):
        with pytest.raises(HTTPException) as missing:
            api.resolve_active_organisation(w.superadmin, "org_" + uuid.uuid4().hex)
        assert missing.value.status_code == 404
        with pytest.raises(HTTPException) as inactive:
            api.resolve_active_organisation(w.superadmin, w.dead.id)
        assert inactive.value.status_code == 403
    assert events(w.db, "rbac.org_switch.entered") == []
    assert len(events(w.db, "rbac.scope.denied", w.a.id)) == 2


def test_an_account_in_an_inactive_home_organisation_acts_nowhere(w, monkeypatch):
    on(monkeypatch)
    u = w.person(w.dead, "analyst", "platform.analyst")
    with scope.use_audit_session(w.db):
        with pytest.raises(HTTPException) as e:
            api.resolve_active_organisation(u, None)
    assert e.value.status_code == 403


def test_the_switch_needs_the_grant_not_the_legacy_name(w, monkeypatch):
    on(monkeypatch)
    spoof = w.person(w.a, "superadmin", "platform.viewer")  # legacy name, no grant
    with scope.use_audit_session(w.db):
        assert api.resolve_active_organisation(spoof, w.b.id) == w.a.id
    assert api.acts_across_organisations(spoof) is False


def test_a_display_name_never_confers_reach(w, monkeypatch):
    on(monkeypatch)
    role(w.db, "platform.superadmin").display_name = "Chief"
    w.db.flush()
    role(w.db, "platform.viewer").display_name = "Superadmin"
    w.db.flush()
    viewer = w.person(w.a, "viewer", "platform.viewer")
    assert api.acts_across_organisations(viewer) is False
    assert api.acts_across_organisations(w.superadmin) is True  # renamed, same grants


def test_a_revoked_or_retired_role_loses_reach_immediately(w, monkeypatch):
    from datetime import datetime, timezone

    from ccure_platform.rbac.model import RbacUserRole

    on(monkeypatch)
    assert api.acts_across_organisations(w.superadmin) is True
    row = w.db.query(RbacUserRole).filter_by(user_id=w.superadmin.id).one()
    row.revoked_at, row.revoke_reason = datetime.now(timezone.utc), "manual"
    w.db.flush()
    assert api.acts_across_organisations(w.superadmin) is False  # legacy would say True
    # a custom platform role carrying the switch, then retired
    from rbac_testing import platform_custom_role

    carrier = platform_custom_role(
        w.db, "carrier", "Carrier", "platform.organization.switch"
    )
    u = w.person(w.a, "analyst")
    assign(w.db, u, carrier)
    assert api.acts_across_organisations(u) is True
    force_state(w.db, carrier, "retiring")
    force_state(w.db, carrier, "retired")
    assert api.acts_across_organisations(u) is False


def test_an_unprovisioned_account_falls_back_to_legacy(w, monkeypatch):
    on(monkeypatch)
    legacy_only = w.person(w.a, "superadmin")
    with scope.use_audit_session(w.db):
        assert api.resolve_active_organisation(legacy_only, w.b.id) == w.b.id
    assert api.acts_across_organisations(legacy_only) is True
    assert {k.split("|")[1] for k in au.recorder.snapshot()["by_path"]} == {"legacy"}


def test_a_failed_audit_write_refuses_the_switch(w, monkeypatch):
    on(monkeypatch)
    monkeypatch.setattr(scope, "_audit", lambda *a, **k: False)
    with pytest.raises(HTTPException) as e:
        api.resolve_active_organisation(w.superadmin, w.b.id)
    assert e.value.status_code == 503


# ── resources: the organisation is resolved server-side ─────────────────────


def test_resource_organisation_is_checked_against_reach_and_state(w, monkeypatch):
    on(monkeypatch)
    with scope.use_audit_session(w.db):
        assert api.resource_organisation_allowed(w.admin_a, w.a.id) is True
        assert api.resource_organisation_allowed(w.admin_a, w.b.id) is False  # IDOR
        assert api.resource_organisation_allowed(w.superadmin, w.b.id) is True
        assert api.resource_organisation_allowed(w.superadmin, w.dead.id) is False
        assert api.resource_organisation_allowed(w.superadmin, "org_ghost") is False
        assert api.resource_organisation_allowed(w.superadmin, None) is False
        assert api.resource_organisation_allowed(w.superadmin, "") is False
    assert events(w.db, "rbac.scope.denied", w.a.id)


# ── read_all: organisation-wide visibility, never cross-organisation ────────


def test_read_all_is_evaluated_for_the_target_organisation(w, monkeypatch):
    on(monkeypatch)
    has = lambda u, org: api.user_has_permission(  # noqa: E731
        w.db, u, "scans", "read_all", authoritative=True, org_id=org
    )
    assert has(w.admin_a, w.a.id) is True
    assert has(w.analyst_a, w.a.id) is True
    assert has(w.admin_a, w.b.id) is False  # holding it does not reach another tenant
    assert has(w.analyst_a, w.b.id) is False
    assert has(w.superadmin, w.b.id) is True  # platform grant + switch
    scanner = w.person(w.a, "scanner", "platform.scanner")
    assert has(scanner, w.a.id) is False  # the scanner role never held it


def test_read_all_from_a_custom_role_applies_in_its_organisation_only(w, monkeypatch):
    on(monkeypatch)
    custom = custom_org_role(w.db, w.a, "reader", "Reader", "audit.scan.read_all")
    scanner = w.person(w.a, "scanner")
    assign(w.db, scanner, custom)
    got = lambda org: api.user_has_permission(  # noqa: E731
        w.db, scanner, "scans", "read_all", authoritative=True, org_id=org
    )
    assert got(w.a.id) is True and got(w.b.id) is False


def test_multiple_roles_union_for_read_all(w, monkeypatch):
    on(monkeypatch)
    scanner = w.person(w.a, "scanner", "platform.scanner")
    assign(w.db, scanner, custom_org_role(w.db, w.a, "r2", "R2", "audit.scan.read_all"))
    assert api.user_has_permission(
        w.db, scanner, "scans", "read_all", authoritative=True, org_id=w.a.id
    )


def test_legacy_off_read_all_for_another_org_needs_legacy_reach(w):
    f = lambda u, org: api.user_has_permission(  # noqa: E731
        w.db, u, "scans", "read_all", authoritative=True, org_id=org
    )
    assert f(w.admin_a, w.a.id) is True
    assert f(w.admin_a, w.b.id) is False
    assert f(w.superadmin, w.b.id) is True


# ── assignment hierarchy ─────────────────────────────────────────────────────


def target_role(db, name):
    return db.query(Role).filter(Role.name == name).one()


def verdict(w, actor, legacy_role, target, org):
    return api.check_role_assignment(
        actor, target_role(w.db, legacy_role), target_user_id=target, target_org_id=org
    )


def test_hierarchy_off_is_the_legacy_rule(w):
    assert verdict(w, w.admin_a, "superadmin", "someone", w.a.id).allowed is False
    assert verdict(w, w.admin_a, "analyst", "someone", w.a.id).allowed is True
    assert verdict(w, w.superadmin, "superadmin", "someone", w.a.id).allowed is True


def test_an_org_admin_cannot_assign_the_platform_superadmin_role(w, monkeypatch):
    on(monkeypatch)
    with scope.use_audit_session(w.db):
        v = verdict(w, w.admin_a, "superadmin", "someone", w.a.id)
    assert not v.allowed and v.source == "new"
    assert {"escalation_ceiling", "missing_authority"} <= set(v.violations)
    refused = events(w.db, "rbac.escalation.refused", w.a.id)
    assert len(refused) == 1 and refused[0].actor_user_id == w.admin_a.id


def test_an_org_admin_assigns_within_its_organisation_only(w, monkeypatch):
    on(monkeypatch)
    with scope.use_audit_session(w.db):
        assert verdict(w, w.admin_a, "analyst", "someone", w.a.id).allowed
        cross = verdict(w, w.admin_a, "analyst", "someone", w.b.id)
    # nothing the actor holds in organisation B reaches there
    assert not cross.allowed and "missing_authority" in cross.violations


def test_nobody_assigns_roles_to_themselves(w, monkeypatch):
    on(monkeypatch)
    with scope.use_audit_session(w.db):
        v = verdict(w, w.admin_a, "viewer", w.admin_a.id, w.a.id)
    assert not v.allowed and "self_assignment" in v.violations


def test_an_account_without_assign_authority_cannot_assign(w, monkeypatch):
    on(monkeypatch)
    with scope.use_audit_session(w.db):
        v = verdict(w, w.analyst_a, "viewer", "someone", w.a.id)
    assert not v.allowed and "missing_authority" in v.violations


def test_the_ceiling_blocks_handing_out_what_the_actor_lacks(w, monkeypatch):
    on(monkeypatch)
    narrow = custom_org_role(
        w.db, w.a, "narrow", "Narrow", "platform.user.assign_role", "audit.scan.read"
    )
    actor = w.person(w.a, "org_admin")
    assign(w.db, actor, narrow)
    with scope.use_audit_session(w.db):
        v = verdict(w, actor, "analyst", "someone", w.a.id)
    assert not v.allowed and "escalation_ceiling" in v.violations


def test_a_superadmin_may_assign_organisation_roles_in_another_organisation(
    w, monkeypatch
):
    on(monkeypatch)
    with scope.use_audit_session(w.db):
        assert verdict(w, w.superadmin, "org_admin", "someone", w.b.id).allowed
        assert verdict(w, w.superadmin, "superadmin", "someone", w.b.id).allowed


def test_an_unprovisioned_actor_gets_the_legacy_hierarchy_answer(w, monkeypatch):
    on(monkeypatch)
    legacy_admin = w.person(w.a, "org_admin")
    assert verdict(w, legacy_admin, "superadmin", "someone", w.a.id).allowed is False
    assert verdict(w, legacy_admin, "analyst", "someone", w.a.id).allowed is True


def test_custom_role_governance_is_intact_across_organisations(w):
    """RBAC-2: an organisation's role cannot be assigned in another organisation."""
    from ccure_platform.rbac import governance, resolver
    from ccure_platform.rbac.model import granted_keys, to_role

    foreign = custom_org_role(w.db, w.b, "x", "X", "audit.scan.read")
    principal = resolver.principal_for_user(w.superadmin)
    v = governance.check_assignment(
        principal,
        resolver.resolve_grants(w.db, principal),
        resolver.load_catalogue(w.db),
        target_user_id="u",
        target_user_org_id=w.a.id,
        role=to_role(foreign),
        role_permission_keys=granted_keys(w.db, foreign.id),
        scope_type="organization",
        scope_org_id=w.a.id,
    )
    assert "role_org_mismatch" in {x.code for x in v}


# ── the backend does not read client claims ──────────────────────────────────


def test_the_seam_takes_no_header_or_body_input():
    import inspect

    for fn in (
        api.resolve_active_organisation,
        api.acts_across_organisations,
        api.resource_organisation_allowed,
        api.check_role_assignment,
    ):
        params = set(inspect.signature(fn).parameters)
        assert not params & {
            "request",
            "headers",
            "body",
            "claims",
            "role",
            "role_name",
        }
