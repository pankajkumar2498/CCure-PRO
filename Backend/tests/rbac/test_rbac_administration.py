"""
RBAC-7 — the Platform RBAC administration API, through real HTTP requests and the real
governance rules. Every refusal is backend-enforced; the database triggers sit behind.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ccure_platform import composition
from ccure_platform.identity import reauth
from ccure_platform.identity.dependencies import get_current_user
from ccure_platform.rbac import scope
from ccure_platform.rbac.authorization_view import build_authorization
from ccure_platform.rbac.catalogue import sync
from ccure_platform.rbac.model import RbacRole, RbacUserRole
from ccure_platform.administration.rbac_admin import router
from config import AppConfig
from db.base import get_db
from db.models import AuditLog, Role
from rbac_testing import (
    assign,
    custom_org_role,
    make_org,
    make_user,
    rbac_db_fixture,  # noqa: F401
    role,
)


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.setattr(AppConfig, "RBAC_REAUTH_MODE", "off")
    yield


@pytest.fixture
def w(rbac_db):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    w = type("W", (), {})()
    w.db = rbac_db
    w.a, w.b = make_org(rbac_db), make_org(rbac_db)
    w.cur = {}
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_current_user] = lambda: w.cur["u"]
    app.dependency_overrides[get_db] = lambda: rbac_db
    w.client = TestClient(app)

    def person(org, legacy_role, rbac_role=None):
        u = make_user(rbac_db, org)
        u.role_id = rbac_db.query(Role).filter(Role.name == legacy_role).one().id
        rbac_db.flush()
        rbac_db.refresh(u)
        if rbac_role:
            assign(rbac_db, u, role(rbac_db, rbac_role))
        return u

    w.person = person
    w.sa = person(w.a, "superadmin", "platform.superadmin")
    w.admin = person(w.a, "org_admin", "platform.org_admin")
    w.analyst = person(w.a, "analyst", "platform.analyst")

    def call(user, method, path, **kw):
        w.cur["u"] = user
        with scope.use_audit_session(rbac_db):
            return w.client.request(method, path, **kw)

    w.call = call
    return w


def events(db, action):
    return db.query(AuditLog).filter(AuditLog.action == action).all()


def platform_events(db, action):
    """Events no organisation owns (a system or platform role) go to the ledger."""
    from ccure_platform.models.platform_audit import PlatformAuditEvent

    return (
        db.query(PlatformAuditEvent).filter(PlatformAuditEvent.action == action).all()
    )


def role_id(db, key):
    return str(role(db, key).id)


# ── reading ──────────────────────────────────────────────────────────────────


def test_an_account_without_an_rbac_assignment_administers_nothing(w):
    legacy_only = w.person(w.a, "superadmin")
    r = w.call(legacy_only, "GET", "/platform/rbac/roles")
    assert r.status_code == 403 and "RBAC role assignment" in r.json()["detail"]


def test_permissions_come_from_the_catalogue_with_scope_and_delegability(w):
    r = w.call(w.admin, "GET", "/platform/rbac/permissions")
    assert r.status_code == 200
    perms = {p["key"]: p for p in r.json()["permissions"]}
    assert perms["audit.scan.read"]["module"] == "audit"
    assert perms["platform.organization.switch"]["scope"] == "platform"
    assert perms["platform.organization.switch"]["delegable"] is False
    assert {"description", "sensitivity", "status", "resource", "action"} <= set(
        perms["audit.scan.read"]
    )
    assert w.call(w.analyst, "GET", "/platform/rbac/permissions").status_code == 403


def test_roles_list_and_detail_hide_structure_and_scope_by_organisation(w):
    mine = custom_org_role(w.db, w.a, "mine", "Mine", "audit.scan.read")
    theirs = custom_org_role(w.db, w.b, "theirs", "Theirs", "audit.scan.read")
    r = w.call(w.admin, "GET", "/platform/rbac/roles")
    names = {x["display_name"] for x in r.json()["roles"]}
    assert {"Mine", "Superadmin", "Org Admin"} <= names and "Theirs" not in names
    d = w.call(w.admin, "GET", f"/platform/rbac/roles/{mine.id}")
    assert d.status_code == 200 and d.json()["permissions"] == ["audit.scan.read"]
    assert (
        w.call(w.admin, "GET", f"/platform/rbac/roles/{theirs.id}").status_code == 404
    )
    assert (
        w.call(w.admin, "GET", f"/platform/rbac/roles?org_id={w.b.id}").json()["org_id"]
        == w.a.id
    )
    assert "rbac_" not in str(d.json())


# ── custom roles ─────────────────────────────────────────────────────────────


def test_a_superadmin_creates_a_custom_organisation_role(w):
    r = w.call(
        w.sa,
        "POST",
        "/platform/rbac/roles",
        json={
            "display_name": "Auditor",
            "permission_keys": ["audit.scan.read"],
            "org_id": w.a.id,
        },
    )
    assert r.status_code == 201
    body = r.json()
    assert body["kind"] == "custom" and body["org_id"] == w.a.id
    assert body["key"].startswith(f"custom.{w.a.id}.") and body["permissions"] == [
        "audit.scan.read"
    ]
    assert events(w.db, "rbac.role.created")


def test_a_custom_role_cannot_hold_platform_or_non_delegable_permissions(w):
    r = w.call(
        w.sa,
        "POST",
        "/platform/rbac/roles",
        json={
            "display_name": "Bad",
            "permission_keys": ["platform.organization.switch"],
            "org_id": w.a.id,
        },
    )
    assert r.status_code == 403
    assert "not_delegable" in {v["code"] for v in r.json()["detail"]["violations"]}
    assert events(w.db, "rbac.escalation.refused")


def test_arbitrary_permission_keys_cannot_be_invented(w):
    r = w.call(
        w.sa,
        "POST",
        "/platform/rbac/roles",
        json={
            "display_name": "Made up",
            "permission_keys": ["audit.scan.anything"],
            "org_id": w.a.id,
        },
    )
    assert r.status_code == 403
    assert "unknown_permission" in {v["code"] for v in r.json()["detail"]["violations"]}


def test_the_delegation_ceiling_bounds_what_a_creator_can_grant(w):
    lead = custom_org_role(
        w.db, w.a, "lead", "Lead", "platform.role.create", "audit.scan.read"
    )
    actor = w.person(w.a, "analyst")
    assign(w.db, actor, lead)
    ok = w.call(
        actor,
        "POST",
        "/platform/rbac/roles",
        json={"display_name": "Small", "permission_keys": ["audit.scan.read"]},
    )
    assert ok.status_code == 201
    over = w.call(
        actor,
        "POST",
        "/platform/rbac/roles",
        json={"display_name": "Big", "permission_keys": ["audit.scan.run"]},
    )
    assert over.status_code == 403
    assert "escalation_ceiling" in {
        v["code"] for v in over.json()["detail"]["violations"]
    }


def test_an_org_admin_without_role_authority_cannot_create_roles(w):
    r = w.call(
        w.analyst,
        "POST",
        "/platform/rbac/roles",
        json={"display_name": "X", "permission_keys": []},
    )
    assert r.status_code == 403


def test_a_role_cannot_be_created_in_another_organisation(w):
    r = w.call(
        w.admin,
        "POST",
        "/platform/rbac/roles",
        json={"display_name": "Elsewhere", "permission_keys": [], "org_id": w.b.id},
    )
    # org_admin has no switch grant: the organisation is the admin's own, and the
    # role authority is missing there
    assert r.status_code == 403


# ── permissions of a role ────────────────────────────────────────────────────


def test_permissions_of_a_custom_role_change_within_the_ceiling(w):
    r = custom_org_role(w.db, w.a, "ed", "Ed", "audit.scan.read")
    ok = w.call(
        w.sa,
        "PUT",
        f"/platform/rbac/roles/{r.id}/permissions",
        json={"permission_keys": ["audit.scan.read", "audit.scan.run"]},
    )
    assert ok.status_code == 200 and ok.json()["change"]["added"] == ["audit.scan.run"]
    gone = w.call(
        w.sa,
        "PUT",
        f"/platform/rbac/roles/{r.id}/permissions",
        json={"permission_keys": ["audit.scan.run"]},
    )
    assert gone.json()["change"]["removed"] == ["audit.scan.read"]
    ev = events(w.db, "rbac.role.permissions_changed")
    assert len(ev) == 2 and ev[0].changes["added"] == ["audit.scan.run"]


def test_a_system_role_permissions_do_not_change_here(w):
    r = w.call(
        w.sa,
        "PUT",
        f"/platform/rbac/roles/{role_id(w.db, 'platform.viewer')}/permissions",
        json={"permission_keys": ["audit.scan.run"]},
    )
    assert r.status_code == 403
    assert "system_role_immutable" in {
        v["code"] for v in r.json()["detail"]["violations"]
    }


def test_nobody_adds_permissions_to_a_role_they_hold(w):
    mine = custom_org_role(
        w.db, w.a, "mine2", "Mine2", "platform.role.update", "audit.scan.read"
    )
    actor = w.person(w.a, "analyst")
    assign(w.db, actor, mine)
    r = w.call(
        actor,
        "PUT",
        f"/platform/rbac/roles/{mine.id}/permissions",
        json={"permission_keys": ["platform.role.update", "audit.scan.read"]},
    )
    assert r.status_code == 403  # nothing to change
    r2 = w.call(
        actor,
        "PUT",
        f"/platform/rbac/roles/{mine.id}/permissions",
        json={
            "permission_keys": [
                "platform.role.update",
                "audit.scan.read",
                "audit.scan.run",
            ]
        },
    )
    assert r2.status_code == 403
    assert {"self_modification", "escalation_ceiling"} & {
        v["code"] for v in r2.json()["detail"]["violations"]
    }


# ── display names ────────────────────────────────────────────────────────────


def keys(a):
    return set(a["permissions"]["platform"]) | set(a["permissions"]["organization"])


def test_renaming_a_system_role_changes_no_authorization(w):
    before_sa = build_authorization(w.db, w.sa)
    before_admin = build_authorization(w.db, w.admin)
    for key, name, back in (
        ("platform.superadmin", "CISO", "Superadmin"),
        ("platform.org_admin", "Manager", "Org Admin"),
    ):
        rid = role_id(w.db, key)
        assert (
            w.call(
                w.sa,
                "PATCH",
                f"/platform/rbac/roles/{rid}",
                json={"display_name": name},
            ).status_code
            == 200
        )
        assert keys(build_authorization(w.db, w.sa)) == keys(before_sa)
        assert keys(build_authorization(w.db, w.admin)) == keys(before_admin)
        assert w.call(w.sa, "GET", "/platform/rbac/roles").status_code == 200
        assert (
            w.call(
                w.sa,
                "PATCH",
                f"/platform/rbac/roles/{rid}",
                json={"display_name": back},
            ).status_code
            == 200
        )
    assert keys(build_authorization(w.db, w.sa)) == keys(before_sa)
    assert len(platform_events(w.db, "rbac.role.renamed")) == 4


def test_a_role_named_superadmin_gains_nothing(w):
    sa_id = role_id(w.db, "platform.superadmin")
    w.call(
        w.sa, "PATCH", f"/platform/rbac/roles/{sa_id}", json={"display_name": "Chief"}
    )
    viewer = role_id(w.db, "platform.viewer")
    r = w.call(
        w.sa,
        "PATCH",
        f"/platform/rbac/roles/{viewer}",
        json={"display_name": "Superadmin"},
    )
    assert r.status_code == 200
    v = w.person(w.a, "viewer", "platform.viewer")
    assert "platform.organization.switch" not in keys(build_authorization(w.db, v))


def test_only_the_system_rename_authority_may_rename_a_system_role(w):
    r = w.call(
        w.admin,
        "PATCH",
        f"/platform/rbac/roles/{role_id(w.db, 'platform.viewer')}",
        json={"display_name": "Reader"},
    )
    assert r.status_code == 403
    assert "missing_authority" in {v["code"] for v in r.json()["detail"]["violations"]}


def test_a_display_name_clash_is_refused(w):
    custom_org_role(w.db, w.a, "one", "Shared Name", "audit.scan.read")
    two = custom_org_role(w.db, w.a, "two", "Other", "audit.scan.read")
    r = w.call(
        w.sa,
        "PATCH",
        f"/platform/rbac/roles/{two.id}",
        json={"display_name": "shared name"},
    )
    assert r.status_code == 403
    assert "display_name_in_use" in {
        v["code"] for v in r.json()["detail"]["violations"]
    }


def test_a_system_role_identity_cannot_be_changed_through_the_api(w):
    sa_id = role_id(w.db, "platform.superadmin")
    r = w.call(
        w.sa,
        "PATCH",
        f"/platform/rbac/roles/{sa_id}",
        json={"key": "platform.hacked", "kind": "custom"},
    )
    assert r.status_code == 422  # unknown fields are refused
    assert (
        w.db.query(RbacRole).filter_by(key="platform.superadmin").one().kind == "system"
    )


# ── lifecycle and replacement ────────────────────────────────────────────────


def test_retirement_needs_the_role_to_be_empty_and_replacement_migrates_users(w):
    old = custom_org_role(w.db, w.a, "old", "Old", "audit.scan.read")
    new = custom_org_role(w.db, w.a, "new", "New", "audit.scan.read")
    u1, u2 = w.person(w.a, "viewer"), w.person(w.a, "viewer")
    assign(w.db, u1, old)
    assign(w.db, u2, old)
    blocked = w.call(
        w.sa,
        "POST",
        f"/platform/rbac/roles/{old.id}/transition",
        json={"target": "retiring"},
    )
    assert blocked.status_code == 200 and blocked.json()["state"] == "retiring"
    refused = w.call(
        w.sa,
        "POST",
        f"/platform/rbac/roles/{old.id}/transition",
        json={"target": "retired"},
    )
    assert refused.status_code == 403
    assert "active_assignments" in {
        v["code"] for v in refused.json()["detail"]["violations"]
    }
    moved = w.call(
        w.sa,
        "POST",
        f"/platform/rbac/roles/{old.id}/replace",
        json={"to_role_id": str(new.id)},
    )
    assert moved.status_code == 200 and moved.json()["migrated_assignments"] == 2
    done = w.call(
        w.sa,
        "POST",
        f"/platform/rbac/roles/{old.id}/transition",
        json={"target": "retired", "replacement_role_id": str(new.id)},
    )
    assert done.status_code == 200 and done.json()["state"] == "retired"
    assert len(events(w.db, "rbac.role.reassigned")) == 2
    assert events(w.db, "rbac.role.replaced") and events(w.db, "rbac.role.retired")
    # history is preserved: the old assignments are revoked, not deleted
    rows = w.db.query(RbacUserRole).filter_by(user_id=u1.id).all()
    assert {r.revoke_reason for r in rows if r.revoked_at} == {"migrated"} and len(
        rows
    ) == 2
    # a retired role cannot be newly assigned
    r = w.call(
        w.sa,
        "POST",
        f"/platform/rbac/users/{u1.id}/assignments",
        json={"role_id": str(old.id)},
    )
    assert r.status_code == 403
    assert "role_not_assignable" in {
        v["code"] for v in r.json()["detail"]["violations"]
    }


def test_a_retired_role_can_be_reactivated_within_the_ceiling(w):
    r = custom_org_role(w.db, w.a, "tmp", "Tmp", "audit.scan.read")
    w.call(
        w.sa,
        "POST",
        f"/platform/rbac/roles/{r.id}/transition",
        json={"target": "retiring"},
    )
    w.call(
        w.sa,
        "POST",
        f"/platform/rbac/roles/{r.id}/transition",
        json={"target": "retired"},
    )
    back = w.call(
        w.sa,
        "POST",
        f"/platform/rbac/roles/{r.id}/transition",
        json={"target": "active"},
    )
    assert back.status_code == 200 and back.json()["state"] == "active"
    assert events(w.db, "rbac.role.reactivated")


def test_a_system_role_cannot_be_retired_by_an_organisation_admin(w):
    r = w.call(
        w.admin,
        "POST",
        f"/platform/rbac/roles/{role_id(w.db, 'platform.viewer')}/transition",
        json={"target": "retiring"},
    )
    assert r.status_code == 403


# ── assignments ──────────────────────────────────────────────────────────────


def assign_call(w, actor, target, key):
    return w.call(
        actor,
        "POST",
        f"/platform/rbac/users/{target.id}/assignments",
        json={"role_id": role_id(w.db, key)},
    )


def test_an_org_admin_assigns_within_its_organisation(w):
    target = w.person(w.a, "viewer")
    r = assign_call(w, w.admin, target, "platform.analyst")
    assert r.status_code == 201
    a = r.json()["assignments"][0]
    assert (
        a["role"]["display_name"] == "Analyst"
        and a["scope_type"] == "organization"
        and a["status"] == "active"
    )
    assert events(w.db, "rbac.role.assigned")


def test_an_org_admin_cannot_assign_the_superadmin_role(w):
    target = w.person(w.a, "viewer")
    r = assign_call(w, w.admin, target, "platform.superadmin")
    assert r.status_code == 403
    assert {"missing_authority", "escalation_ceiling"} & {
        v["code"] for v in r.json()["detail"]["violations"]
    }
    assert events(w.db, "rbac.escalation.refused")


def test_nobody_assigns_themselves_a_role(w):
    r = assign_call(w, w.admin, w.admin, "platform.viewer")
    assert r.status_code == 403
    assert "self_assignment" in {v["code"] for v in r.json()["detail"]["violations"]}


def test_organisation_a_cannot_assign_in_organisation_b(w):
    outsider = w.person(w.b, "viewer")
    r = assign_call(w, w.admin, outsider, "platform.viewer")
    assert r.status_code == 403
    assert events(w.db, "rbac.assignment.denied") or events(
        w.db, "rbac.escalation.refused"
    )
    foreign = custom_org_role(w.db, w.b, "fr", "FR", "audit.scan.read")
    mine = w.person(w.a, "viewer")
    r2 = w.call(
        w.sa,
        "POST",
        f"/platform/rbac/users/{mine.id}/assignments",
        json={"role_id": str(foreign.id)},
    )
    assert r2.status_code == 403
    assert "role_org_mismatch" in {v["code"] for v in r2.json()["detail"]["violations"]}


def test_a_second_live_assignment_of_the_same_role_is_refused(w):
    target = w.person(w.a, "viewer")
    assert assign_call(w, w.admin, target, "platform.viewer").status_code == 201
    r = assign_call(w, w.admin, target, "platform.viewer")
    assert r.status_code == 403 and "already_assigned" in {
        v["code"] for v in r.json()["detail"]["violations"]
    }


def test_revoking_ends_the_assignment_and_keeps_history(w):
    target = w.person(w.a, "viewer")
    aid = assign_call(w, w.admin, target, "platform.viewer").json()["assignment_id"]
    r = w.call(w.admin, "DELETE", f"/platform/rbac/assignments/{aid}")
    assert r.status_code == 200
    row = r.json()["assignments"][0]
    assert row["status"] == "revoked" and row["revoke_reason"] == "manual"
    assert events(w.db, "rbac.role.revoked")
    assert w.call(
        w.analyst, "DELETE", f"/platform/rbac/assignments/{aid}"
    ).status_code in (403, 404)


def test_the_last_superadmin_cannot_be_removed(w):
    row = w.db.query(RbacUserRole).filter_by(user_id=w.sa.id).one()
    r = w.call(w.sa, "DELETE", f"/platform/rbac/assignments/{row.id}")
    assert r.status_code == 403
    assert "continuity" in {v["code"] for v in r.json()["detail"]["violations"]}
    w.db.refresh(row)
    assert row.revoked_at is None


def test_the_last_organisation_role_administrator_cannot_be_removed(w):
    row = w.db.query(RbacUserRole).filter_by(user_id=w.admin.id).one()
    # org A's role administrators: this org_admin and the platform superadmin (home org A)
    # — removing the org_admin alone is fine because the superadmin still holds it
    assert (
        w.call(w.sa, "DELETE", f"/platform/rbac/assignments/{row.id}").status_code
        == 200
    )


def test_assignable_roles_come_from_governance_not_a_label(w):
    r = w.call(
        w.admin, "GET", f"/platform/rbac/assignable-roles?org_id={w.a.id}"
    ).json()
    by = {x["display_name"]: x for x in r["roles"]}
    assert by["Analyst"]["assignable"] is True
    assert by["Superadmin"]["assignable"] is False and by["Superadmin"]["reasons"]
    assert r["delegation"]["can_assign_platform_roles"] is False
    role(w.db, "platform.superadmin").display_name = "Chief"
    w.db.flush()
    again = w.call(w.admin, "GET", "/platform/rbac/assignable-roles").json()
    assert {x["display_name"]: x["assignable"] for x in again["roles"]}[
        "Chief"
    ] is False
    sa = w.call(w.sa, "GET", "/platform/rbac/assignable-roles").json()
    assert {x["display_name"]: x["assignable"] for x in sa["roles"]}["Chief"] is True


def test_the_user_role_view_shows_labels_states_and_scope(w):
    custom = custom_org_role(w.db, w.a, "sv", "Shown", "audit.scan.read")
    t = w.person(w.a, "viewer", "platform.viewer")
    assign(w.db, t, custom)
    rows = w.call(w.admin, "GET", f"/platform/rbac/users/{t.id}/assignments").json()[
        "assignments"
    ]
    assert {x["role"]["display_name"] for x in rows} == {"Viewer", "Shown"}
    assert all({"status", "scope_type", "scope_org_id"} <= set(x) for x in rows)
    assert (
        w.call(
            w.admin,
            "GET",
            f"/platform/rbac/users/{w.person(w.b, 'viewer').id}/assignments",
        ).status_code
        == 404
    )


# ── step-up ──────────────────────────────────────────────────────────────────


def test_sensitive_operations_need_a_current_code_from_an_enrolled_account(
    w, monkeypatch
):
    monkeypatch.setattr(AppConfig, "RBAC_REAUTH_MODE", "enforce")
    w.sa.mfa_enabled, w.sa.totp_secret = True, "enc"
    monkeypatch.setattr(reauth, "_verify", lambda user, code: code == "123456")
    rid = role_id(w.db, "platform.org_admin")
    body = {"display_name": "Manager"}
    none = w.call(w.sa, "PATCH", f"/platform/rbac/roles/{rid}", json=body)
    assert (
        none.status_code == 403 and none.json()["detail"]["code"] == "reauth_required"
    )
    bad = w.call(
        w.sa,
        "PATCH",
        f"/platform/rbac/roles/{rid}",
        json=body,
        headers={"X-Reauth-Code": "000000"},
    )
    assert bad.status_code == 403 and events(w.db, "rbac.reauth.failed")
    good = w.call(
        w.sa,
        "PATCH",
        f"/platform/rbac/roles/{rid}",
        json=body,
        headers={"X-Reauth-Code": "123456"},
    )
    assert good.status_code == 200
    assert (
        platform_events(w.db, "rbac.role.renamed")[-1].changes["reauth"] == "verified"
    )


def test_an_account_without_mfa_is_recorded_not_blocked_unless_enrolment_is_required(
    w, monkeypatch
):
    monkeypatch.setattr(AppConfig, "RBAC_REAUTH_MODE", "enforce")
    rid = role_id(w.db, "platform.org_admin")
    ok = w.call(
        w.sa, "PATCH", f"/platform/rbac/roles/{rid}", json={"display_name": "Manager"}
    )
    assert ok.status_code == 200
    assert (
        platform_events(w.db, "rbac.role.renamed")[-1].changes["reauth"]
        == "not_enrolled"
    )
    monkeypatch.setattr(AppConfig, "RBAC_REAUTH_MODE", "require_enrolment")
    blocked = w.call(
        w.sa, "PATCH", f"/platform/rbac/roles/{rid}", json={"display_name": "Org Admin"}
    )
    assert (
        blocked.status_code == 403
        and blocked.json()["detail"]["code"] == "mfa_enrolment_required"
    )


def test_a_non_sensitive_change_needs_no_step_up(w, monkeypatch):
    monkeypatch.setattr(AppConfig, "RBAC_REAUTH_MODE", "enforce")
    w.sa.mfa_enabled, w.sa.totp_secret = True, "enc"
    r = custom_org_role(w.db, w.a, "plain", "Plain", "audit.scan.read")
    ok = w.call(
        w.sa, "PATCH", f"/platform/rbac/roles/{r.id}", json={"display_name": "Plainer"}
    )
    assert ok.status_code == 200
