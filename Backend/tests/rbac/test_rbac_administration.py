"""
RBAC-7 — the Platform RBAC administration API, through real HTTP requests and the real
governance rules. Every refusal is backend-enforced; the database triggers sit behind.
"""

from __future__ import annotations

import pytest
import re
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ccure_platform import composition
from ccure_platform.identity import reauth
from ccure_platform.identity.dependencies import get_current_user
from ccure_platform.rbac import scope
from ccure_platform.rbac import administration as admin
from ccure_platform.rbac import contract as c
from ccure_platform.rbac.authorization_view import build_authorization
from ccure_platform.rbac.catalogue import sync
from ccure_platform.rbac.model import RbacRole, RbacUserRole
from ccure_platform.administration.rbac_admin import router
from config import AppConfig
from db.base import get_db
from db.models import AuditLog
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

    def person(org, rbac_role=None):
        u = make_user(rbac_db, org)
        rbac_db.flush()
        rbac_db.refresh(u)
        if rbac_role:
            assign(rbac_db, u, role(rbac_db, rbac_role))
        return u

    w.person = person
    w.sa = person(w.a, "platform.superadmin")
    w.admin = person(w.a, "platform.org_admin")
    w.analyst = person(w.a, "platform.analyst")

    def call(user, method, path, **kw):
        auto_revision = kw.pop("auto_revision", True)
        if (
            auto_revision
            and method == "PUT"
            and "/permissions" in path
            and "json" in kw
        ):
            row = rbac_db.get(RbacRole, path.split("/roles/")[1].split("/")[0])
            if row is not None:
                kw["json"].setdefault("expected_revision", row.revision)
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
    legacy_only = w.person(w.a)
    r = w.call(legacy_only, "GET", "/platform/rbac/roles")
    assert r.status_code == 403 and "RBAC role assignment" in r.json()["detail"]


def test_permissions_come_from_the_catalogue_with_scope_and_delegability(w):
    r = w.call(w.sa, "GET", "/platform/rbac/permissions")
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


ROLE_LABELS = (
    ("Rehearsal Asset Reader", "rehearsal_asset_reader"),
    ("Asset Reader / Scanner", "asset_reader_scanner"),
    ("R&D: Asset (Reader)!", "r_d_asset_reader"),
    ("Asset   Reader__///Scanner", "asset_reader_scanner"),
    ("--- Asset.Reader !!!", "asset_reader"),
    ("mIxEd CASE Label", "mixed_case_label"),
    ("!!!@@@###", "role"),
    ("123 Asset Reader", "role_123_asset_reader"),
    ("___42___", "role_42"),
    ("___", "role"),
    ("ÖÄ💥", "role"),
    ("a" * 39 + " / b", "a" * 39),
    ("99 " + "A" * 90, "role_99_" + "a" * 32),
)


@pytest.mark.parametrize("label,expected", ROLE_LABELS)
def test_native_role_slug_is_deterministic_and_matches_existing_grammar(
    label, expected
):
    slug = admin._slug(label)
    assert slug == expected == admin._slug(label)
    assert len(slug) <= 40
    assert re.fullmatch(r"[a-z][a-z0-9_]*", slug)
    assert c.role_key_kind(f"custom.org_development.{slug}") == "org_custom"


@pytest.mark.parametrize("label,expected", ROLE_LABELS)
def test_authorized_administrator_persists_normalized_role_labels(w, label, expected):
    response = w.call(
        w.sa,
        "POST",
        "/platform/rbac/roles",
        json={"display_name": label, "permission_keys": ["audit.asset.read"]},
    )
    assert response.status_code == 201, response.json()
    detail = response.json()
    assert detail["key"] == f"custom.{w.a.id}.{expected}"
    assert c.role_key_kind(detail["key"]) == "org_custom"
    persisted = w.db.get(RbacRole, detail["id"])
    assert persisted is not None and persisted.display_name == label
    assert detail["permissions"] == ["audit.asset.read"]


def test_native_role_key_collisions_use_valid_numeric_suffixes(w):
    for label, slug in (
        ("Asset Reader", "asset_reader"),
        ("Asset/Reader", "asset_reader_2"),
        ("Asset---Reader", "asset_reader_3"),
    ):
        response = w.call(
            w.sa,
            "POST",
            "/platform/rbac/roles",
            json={"display_name": label, "permission_keys": []},
        )
        assert response.status_code == 201, response.json()
        assert response.json()["key"] == f"custom.{w.a.id}.{slug}"
        assert c.role_key_kind(response.json()["key"]) == "org_custom"
    duplicate = w.call(
        w.sa,
        "POST",
        "/platform/rbac/roles",
        json={"display_name": "asset reader", "permission_keys": []},
    )
    assert duplicate.status_code == 403
    assert "display_name_in_use" in {
        violation["code"] for violation in duplicate.json()["detail"]["violations"]
    }
    assert w.db.query(RbacRole).filter_by(org_id=w.a.id, kind="custom").count() == 3


def test_multiword_custom_role_permissions_assignment_rename_revocation_and_retirement(
    w,
):
    created = w.call(
        w.sa,
        "POST",
        "/platform/rbac/roles",
        json={"display_name": "Rehearsal Asset Reader", "permission_keys": []},
    )
    assert created.status_code == 201
    detail = created.json()
    rid, original_key = detail["id"], detail["key"]
    assert original_key == f"custom.{w.a.id}.rehearsal_asset_reader"
    changed = w.call(
        w.sa,
        "PUT",
        f"/platform/rbac/roles/{rid}/permissions",
        json={"permission_keys": ["audit.asset.read"]},
    )
    assert changed.status_code == 200
    target = w.person(w.a)
    assigned = w.call(
        w.sa,
        "POST",
        f"/platform/rbac/users/{target.id}/assignments",
        json={"role_id": rid},
    )
    assert assigned.status_code == 201
    assert keys(build_authorization(w.db, target)) == {"audit.asset.read"}
    renamed = w.call(
        w.sa,
        "PATCH",
        f"/platform/rbac/roles/{rid}",
        json={
            "display_name": "Updated Reader / Scanner",
            "description": "Updated label",
        },
    )
    assert renamed.status_code == 200 and renamed.json()["key"] == original_key
    assert renamed.json()["display_name"] == "Updated Reader / Scanner"
    assert keys(build_authorization(w.db, target)) == {"audit.asset.read"}
    updated = w.call(
        w.sa,
        "PATCH",
        f"/platform/rbac/roles/{rid}",
        json={"description": "Description updated separately"},
    )
    assert updated.status_code == 200 and updated.json()["key"] == original_key
    # A renamed role keeps its identity; recreating the former label collides
    # with that permanent key and receives the next valid suffix.
    recreated = w.call(
        w.sa,
        "POST",
        "/platform/rbac/roles",
        json={"display_name": "Rehearsal Asset Reader", "permission_keys": []},
    )
    assert recreated.status_code == 201
    assert recreated.json()["key"] == original_key + "_2"
    revoked = w.call(
        w.sa, "DELETE", f"/platform/rbac/assignments/{assigned.json()['assignment_id']}"
    )
    assert revoked.status_code == 200
    assert keys(build_authorization(w.db, target)) == set()
    for state in ("retiring", "retired"):
        transition = w.call(
            w.sa,
            "POST",
            f"/platform/rbac/roles/{rid}/transition",
            json={"target": state, "reason": "Normalization regression verification"},
        )
        assert transition.status_code == 200 and transition.json()["state"] == state
        assert transition.json()["key"] == original_key
    assert events(w.db, "rbac.role.permissions_changed")
    assert events(w.db, "rbac.role.renamed")
    assert events(w.db, "rbac.role.updated")
    assert events(w.db, "rbac.role.assigned")
    assert events(w.db, "rbac.role.revoked")
    assert events(w.db, "rbac.role.retired")


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
    actor = w.person(w.a)
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
    actor = w.person(w.a)
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
    v = w.person(w.a, "platform.viewer")
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
    u1, u2 = w.person(w.a), w.person(w.a)
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
    target = w.person(w.a)
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
    target = w.person(w.a)
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
    outsider = w.person(w.b)
    r = assign_call(w, w.admin, outsider, "platform.viewer")
    assert r.status_code == 403
    assert events(w.db, "rbac.assignment.denied") or events(
        w.db, "rbac.escalation.refused"
    )
    foreign = custom_org_role(w.db, w.b, "fr", "FR", "audit.scan.read")
    mine = w.person(w.a)
    r2 = w.call(
        w.sa,
        "POST",
        f"/platform/rbac/users/{mine.id}/assignments",
        json={"role_id": str(foreign.id)},
    )
    assert r2.status_code == 403
    assert "role_org_mismatch" in {v["code"] for v in r2.json()["detail"]["violations"]}


def test_a_second_live_assignment_of_the_same_role_is_refused(w):
    target = w.person(w.a)
    assert assign_call(w, w.admin, target, "platform.viewer").status_code == 201
    r = assign_call(w, w.admin, target, "platform.viewer")
    assert r.status_code == 403 and "already_assigned" in {
        v["code"] for v in r.json()["detail"]["violations"]
    }


def test_revoking_ends_the_assignment_and_keeps_history(w):
    target = w.person(w.a)
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
    t = w.person(w.a, "platform.viewer")
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
            f"/platform/rbac/users/{w.person(w.b).id}/assignments",
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


# Security regressions: denied operations leave assignments, grants and history intact.


def test_removing_last_viable_role_administrator_permission_is_atomic(w):
    r = custom_org_role(
        w.db, w.b, "last_manager", "Last Manager", c.ASSIGN_ROLE_KEY, "audit.scan.read"
    )
    member = w.person(w.b)
    assign(w.db, member, r)
    revision = r.revision
    denied = w.call(
        w.sa,
        "PUT",
        f"/platform/rbac/roles/{r.id}/permissions?org_id={w.b.id}",
        json={"permission_keys": ["audit.scan.read"]},
    )
    assert denied.status_code == 403
    assert "continuity" in {v["code"] for v in denied.json()["detail"]["violations"]}
    assert set(admin.granted_keys(w.db, r.id)) == {c.ASSIGN_ROLE_KEY, "audit.scan.read"}
    assert r.revision == revision
    assert not events(w.db, "rbac.role.permissions_changed")


def test_removal_is_allowed_when_another_viable_administrator_remains(w):
    r = custom_org_role(
        w.db, w.b, "one_manager", "One Manager", c.ASSIGN_ROLE_KEY, "audit.scan.read"
    )
    assign(w.db, w.person(w.b), r)
    w.person(w.b, "platform.org_admin")
    ok = w.call(
        w.sa,
        "PUT",
        f"/platform/rbac/roles/{r.id}/permissions?org_id={w.b.id}",
        json={"permission_keys": ["audit.scan.read"]},
    )
    assert ok.status_code == 200
    assert ok.json()["permissions"] == ["audit.scan.read"]


def test_authorized_role_creator_cannot_silently_create_in_home_tenant(w):
    creator = custom_org_role(w.db, w.a, "creator", "Creator", c.CREATE_ROLE_KEY)
    assign(w.db, w.admin, creator)
    denied = w.call(
        w.admin,
        "POST",
        f"/platform/rbac/roles?org_id={w.b.id}",
        json={"display_name": "Misplaced", "permission_keys": []},
    )
    assert denied.status_code == 403
    assert (
        w.db.query(RbacRole).filter(RbacRole.display_name == "Misplaced").count() == 0
    )
    assert events(w.db, "rbac.scope.denied")


def test_creation_honours_query_tenant_and_refuses_conflicting_body(w):
    ok = w.call(
        w.sa,
        "POST",
        f"/platform/rbac/roles?org_id={w.b.id}",
        json={"display_name": "In Selected Tenant", "permission_keys": []},
    )
    assert ok.status_code == 201 and ok.json()["org_id"] == w.b.id
    bad = w.call(
        w.sa,
        "POST",
        f"/platform/rbac/roles?org_id={w.b.id}",
        json={"display_name": "Conflict", "permission_keys": [], "org_id": w.a.id},
    )
    assert bad.status_code == 400


@pytest.mark.parametrize(
    "operation", ["rename", "permissions", "transition", "replace", "revoke"]
)
def test_cross_tenant_custom_role_operations_require_step_up(w, monkeypatch, operation):
    monkeypatch.setattr(AppConfig, "RBAC_REAUTH_MODE", "enforce")
    w.sa.mfa_enabled, w.sa.totp_secret = True, "enc"
    r = custom_org_role(w.db, w.b, "remote", "Remote", "audit.scan.read")
    new = custom_org_role(w.db, w.b, "replacement", "Replacement", "audit.scan.read")
    a = assign(w.db, w.person(w.b), r)
    paths = {
        "rename": ("PATCH", f"/roles/{r.id}", {"display_name": "Changed"}),
        "permissions": ("PUT", f"/roles/{r.id}/permissions", {"permission_keys": []}),
        "transition": ("POST", f"/roles/{r.id}/transition", {"target": "retiring"}),
        "replace": ("POST", f"/roles/{r.id}/replace", {"to_role_id": str(new.id)}),
        "revoke": ("DELETE", f"/assignments/{a.id}", None),
    }
    method, path, body = paths[operation]
    denied = w.call(
        w.sa,
        method,
        f"/platform/rbac{path}?org_id={w.b.id}",
        **({"json": body} if body else {}),
    )
    assert (
        denied.status_code == 403
        and denied.json()["detail"]["code"] == "reauth_required"
    )
    assert r.display_name == "Remote" and r.state == "active" and a.revoked_at is None
    assert events(w.db, "rbac.reauth.failed")


@pytest.mark.parametrize(
    "operation", ["create_user", "replace_role", "create_organisation"]
)
def test_compatibility_assignment_paths_cannot_bypass_step_up(
    w, monkeypatch, operation
):
    from ccure_platform.administration.users import router as users_router
    from ccure_platform.administration.organizations import router as orgs_router

    w.client.app.include_router(users_router)
    w.client.app.include_router(orgs_router)
    monkeypatch.setattr(AppConfig, "RBAC_REAUTH_MODE", "enforce")
    w.sa.mfa_enabled, w.sa.totp_secret = True, "enc"
    target = w.person(w.a, "platform.viewer")
    rid = role_id(w.db, "platform.org_admin")
    paths = {
        "create_user": (
            "POST",
            "/admin/users",
            {
                "username": "stepup_new",
                "email": "stepup@example.org",
                "password": "Str0ng!Password42",
                "organization_id": w.a.id,
                "rbac_role_id": rid,
            },
        ),
        "replace_role": (
            "PATCH",
            f"/admin/users/{target.id}/role",
            {"rbac_role_id": rid},
        ),
        "create_organisation": (
            "POST",
            "/admin/organizations",
            {
                "name": "Stepup Org",
                "slug": "stepup-org",
                "admin_username": "stepup_admin",
                "admin_email": "stepup-admin@example.org",
                "admin_password": "Str0ng!Password42",
            },
        ),
    }
    method, path, body = paths[operation]
    denied = w.call(w.sa, method, path, json=body)
    assert (
        denied.status_code == 403
        and denied.json()["detail"]["code"] == "reauth_required"
    )
    assert events(w.db, "rbac.reauth.failed")


@pytest.mark.parametrize("operation", ["deactivate", "delete"])
def test_account_lifecycle_cannot_remove_last_viable_administrator(w, operation):
    from ccure_platform.administration.users import router as users_router

    w.client.app.include_router(users_router)
    target = w.person(w.b, "platform.org_admin")
    path = f"/admin/users/{target.id}"
    denied = w.call(
        w.sa,
        "PATCH" if operation == "deactivate" else "DELETE",
        path + ("/status" if operation == "deactivate" else ""),
        **({"json": {"is_active": False}} if operation == "deactivate" else {}),
    )
    assert denied.status_code == 403
    assert target.is_active and not target.is_deleted
    assert events(w.db, "rbac.assignment.denied")


@pytest.mark.parametrize("operation", ["deactivate", "archive"])
def test_tenant_lifecycle_cannot_remove_last_platform_administrator(w, operation):
    from ccure_platform.administration.organizations import router as orgs_router
    from rbac_testing import platform_custom_role

    w.client.app.include_router(orgs_router)
    # The operator may end a tenancy but does not provide recovery authority.
    operator = w.person(w.b)
    assign(
        w.db,
        operator,
        platform_custom_role(
            w.db,
            "tenant_operator",
            "Tenant Operator",
            "platform.organization.update",
            "platform.organization.archive",
            "platform.organization.switch",
        ),
    )
    denied = w.call(
        operator,
        "PATCH" if operation == "deactivate" else "DELETE",
        f"/admin/organizations/{w.a.id}"
        + ("/status" if operation == "deactivate" else ""),
        **({"json": {"is_active": False}} if operation == "deactivate" else {}),
    )
    assert denied.status_code == 403, denied.json()
    w.db.refresh(w.a)
    w.db.refresh(w.sa)
    assert w.a.is_active and w.a.archived_at is None
    assert w.sa.is_active and not w.sa.is_deleted
    assert events(w.db, "rbac.assignment.denied")
    assert not events(w.db, "organization.archived")
    assert not events(w.db, "organization.deactivated")


@pytest.mark.parametrize("operation", ["deactivate", "archive"])
def test_tenant_lifecycle_allows_another_viable_platform_administrator(w, operation):
    from ccure_platform.administration.organizations import router as orgs_router

    w.client.app.include_router(orgs_router)
    target = w.person(w.b, "platform.superadmin")
    allowed = w.call(
        w.sa,
        "PATCH" if operation == "deactivate" else "DELETE",
        f"/admin/organizations/{w.b.id}"
        + ("/status" if operation == "deactivate" else ""),
        **({"json": {"is_active": False}} if operation == "deactivate" else {}),
    )
    assert allowed.status_code == 200, allowed.json()
    assert not w.b.is_active
    assert w.sa.is_active and not w.sa.is_deleted
    if operation == "archive":
        assert w.b.archived_at is not None and target.is_deleted
        assert events(w.db, "organization.archived")
    else:
        assert w.b.archived_at is None and not target.is_deleted
        assert events(w.db, "organization.deactivated")


def test_tenant_continuity_uses_membership_after_waiting_for_the_lock(w, monkeypatch):
    from ccure_platform.administration import rbac_security
    from fastapi import HTTPException

    original_lock = rbac_security.governance.lock_continuity
    moved = False

    def preceding_transfer(db):
        nonlocal moved
        if not moved:
            moved = True
            w.sa.org_id = w.b.id
            db.flush()
        original_lock(db)

    monkeypatch.setattr(rbac_security.governance, "lock_continuity", preceding_transfer)
    with scope.use_audit_session(w.db), pytest.raises(HTTPException) as denied:
        rbac_security.retain_organisation_administrators(w.db, w.admin, w.b.id)
    assert denied.value.status_code == 403
    assert events(w.db, "rbac.assignment.denied")


def test_audit_failure_rolls_back_permission_update_and_revision(w, monkeypatch):
    from ccure_platform.administration import rbac_admin as api

    created = w.call(
        w.sa,
        "POST",
        "/platform/rbac/roles",
        json={"display_name": "Atomic Role", "permission_keys": ["audit.scan.read"]},
    ).json()

    def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(api, "emit", fail)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        w.call(
            w.sa,
            "PUT",
            f"/platform/rbac/roles/{created['id']}/permissions",
            json={"permission_keys": []},
        )
    r = w.db.get(RbacRole, created["id"])
    assert r.revision == created["revision"]
    assert admin.granted_keys(w.db, r.id) == frozenset({"audit.scan.read"})
    assert not events(w.db, "rbac.role.permissions_changed")


def test_continuity_lock_serializes_independent_database_transactions():
    from sqlalchemy import text
    from sqlalchemy.orm import Session
    from db.base import engine
    from ccure_platform.rbac.governance import lock_continuity

    with engine.connect() as first, engine.connect() as second:
        with Session(bind=first) as session:
            lock_continuity(session)
            assert (
                second.execute(
                    text("SELECT pg_try_advisory_xact_lock(1128486226, 1)")
                ).scalar()
                is False
            )
            session.rollback()
            assert (
                second.execute(
                    text("SELECT pg_try_advisory_xact_lock(1128486226, 1)")
                ).scalar()
                is True
            )
        second.rollback()


def test_permission_update_requires_revision_and_audits_refusal(w):
    r = custom_org_role(w.db, w.a, "precondition", "Precondition", "audit.scan.read")
    denied = w.call(
        w.sa,
        "PUT",
        f"/platform/rbac/roles/{r.id}/permissions",
        json={"permission_keys": []},
        auto_revision=False,
    )
    assert denied.status_code == 428
    assert denied.json()["detail"]["code"] == "revision_required"
    assert admin.granted_keys(w.db, r.id) == frozenset({"audit.scan.read"})
    assert events(w.db, "rbac.role.denied")[-1].changes["violations"] == [
        "revision_required"
    ]


def test_two_editors_cannot_overwrite_a_role_from_the_same_revision(w):
    r = custom_org_role(w.db, w.a, "conflict", "Conflict", "audit.scan.read")
    revision = r.revision
    first = w.call(
        w.sa,
        "PUT",
        f"/platform/rbac/roles/{r.id}/permissions",
        json={"permission_keys": ["audit.asset.read"], "expected_revision": revision},
    )
    assert first.status_code == 200
    stale = w.call(
        w.sa,
        "PUT",
        f"/platform/rbac/roles/{r.id}/permissions",
        json={"permission_keys": ["audit.scan.run"], "expected_revision": revision},
    )
    assert (
        stale.status_code == 409
        and stale.json()["detail"]["code"] == "revision_conflict"
    )
    assert admin.granted_keys(w.db, r.id) == frozenset({"audit.asset.read"})
    assert r.revision == revision + 1
    assert len(events(w.db, "rbac.role.permissions_changed")) == 1
    assert events(w.db, "rbac.role.denied")[-1].changes["violations"] == [
        "stale_revision"
    ]


def test_revision_append_failure_rolls_back_grants(w, monkeypatch):
    created = w.call(
        w.sa,
        "POST",
        "/platform/rbac/roles",
        json={
            "display_name": "Revision Atomic",
            "permission_keys": ["audit.scan.read"],
        },
    ).json()

    def fail(*args, **kwargs):
        raise RuntimeError("revision unavailable")

    monkeypatch.setattr(admin, "append_revision", fail)
    with pytest.raises(RuntimeError, match="revision unavailable"):
        w.call(
            w.sa,
            "PUT",
            f"/platform/rbac/roles/{created['id']}/permissions",
            json={"permission_keys": []},
        )
    assert admin.granted_keys(w.db, created["id"]) == frozenset({"audit.scan.read"})
    assert w.db.get(RbacRole, created["id"]).revision == created["revision"]
    assert not events(w.db, "rbac.role.permissions_changed")


def test_denial_audit_failure_never_turns_refusal_into_success(w, monkeypatch):
    from ccure_platform.administration import rbac_admin as api

    monkeypatch.setattr(api, "audit_isolated", lambda *args: False)
    r = custom_org_role(w.db, w.a, "audit_denied", "Audit Denied", "audit.scan.read")
    response = w.call(
        w.analyst,
        "PUT",
        f"/platform/rbac/roles/{r.id}/permissions",
        json={"permission_keys": []},
    )
    assert response.status_code == 503
    assert admin.granted_keys(w.db, r.id) == frozenset({"audit.scan.read"})


def test_immutable_system_role_refusals_are_audited(w):
    r = role(w.db, "platform.viewer")
    response = w.call(
        w.sa,
        "PUT",
        f"/platform/rbac/roles/{r.id}/permissions",
        json={"permission_keys": []},
    )
    assert response.status_code == 403
    assert (
        "system_role_immutable"
        in events(w.db, "rbac.role.denied")[-1].changes["violations"]
    )


def test_existing_role_changes_immediately_update_assigned_users_authorization(w):
    r = custom_org_role(w.db, w.a, "effective", "Effective", "audit.scan.read")
    member = w.person(w.a)
    assignment = assign(w.db, member, r)
    assignment_id = assignment.id

    def held():
        view = build_authorization(w.db, member)
        return set(view["permissions"]["organization"])

    assert held() == {"audit.scan.read"}
    changed = w.call(
        w.sa,
        "PUT",
        f"/platform/rbac/roles/{r.id}/permissions",
        json={"permission_keys": ["audit.asset.read"]},
    )
    assert changed.status_code == 200
    assert held() == {"audit.asset.read"}
    assert assignment.id == assignment_id and assignment.revoked_at is None
    assert changed.json()["id"] == str(r.id)


@pytest.mark.parametrize(
    "key",
    [
        "platform.superadmin",
        "platform.org_admin",
        "platform.analyst",
        "platform.viewer",
        "platform.scanner",
    ],
)
def test_every_predefined_role_remains_immutable_even_for_platform_administrators(
    w, key
):
    r = role(w.db, key)
    before = admin.granted_keys(w.db, r.id)
    revision = r.revision
    denied = w.call(
        w.sa,
        "PUT",
        f"/platform/rbac/roles/{r.id}/permissions",
        json={"permission_keys": []},
    )
    assert denied.status_code == 403
    assert "system_role_immutable" in {
        v["code"] for v in denied.json()["detail"]["violations"]
    }
    assert admin.granted_keys(w.db, r.id) == before and r.revision == revision
    assert events(w.db, "rbac.role.denied")


def test_organisation_catalogue_covers_all_org_permissions_without_platform_grants(w):
    from ccure_platform.rbac.model import RbacPermission

    visible = w.call(w.admin, "GET", "/platform/rbac/permissions").json()["permissions"]
    expected = {
        p.key for p in w.db.query(RbacPermission).filter_by(scope_kind="organization")
    }
    assert {p["key"] for p in visible} == expected
    assert all(p["scope"] == "organization" for p in visible)
    assert all(not p["grantable_to_platform_role"] for p in visible)


def test_catalogue_delegation_flags_follow_current_grants_and_scope(w):
    limited = custom_org_role(
        w.db,
        w.a,
        "limited_manager",
        "Limited Manager",
        "platform.permission.read",
        c.CREATE_ROLE_KEY,
        "audit.scan.read",
    )
    member = w.person(w.a)
    assign(w.db, member, limited)
    perms = {
        p["key"]: p
        for p in w.call(member, "GET", "/platform/rbac/permissions").json()[
            "permissions"
        ]
    }
    assert perms["audit.scan.read"]["grantable_to_org_role"] is True
    assert perms["audit.scan.run"]["grantable_to_org_role"] is False
    assert all(not p["grantable_to_platform_role"] for p in perms.values())


def test_empty_role_replacement_still_requires_assignment_authority(w):
    old = custom_org_role(w.db, w.a, "empty_old", "Empty Old", "audit.scan.read")
    new = custom_org_role(w.db, w.a, "empty_new", "Empty New", "audit.scan.read")
    denied = w.call(
        w.analyst,
        "POST",
        f"/platform/rbac/roles/{old.id}/replace",
        json={"to_role_id": str(new.id)},
    )
    assert denied.status_code == 403
    assert not events(w.db, "rbac.role.replaced")
    assert events(w.db, "rbac.assignment.denied")


def test_role_creation_and_user_assignment_require_separate_authority(w):
    creator = custom_org_role(
        w.db, w.a, "create_only", "Create Only", c.CREATE_ROLE_KEY, "audit.scan.read"
    )
    member = w.person(w.a)
    assign(w.db, member, creator)
    target = w.person(w.a)
    candidate = custom_org_role(
        w.db, w.a, "reader_only", "Reader Only", "audit.scan.read"
    )
    created = w.call(
        member,
        "POST",
        "/platform/rbac/roles",
        json={
            "display_name": "Created Separately",
            "permission_keys": ["audit.scan.read"],
        },
    )
    assert created.status_code == 201
    denied = w.call(
        member,
        "POST",
        f"/platform/rbac/users/{target.id}/assignments",
        json={"role_id": str(candidate.id)},
    )
    assert denied.status_code == 403
    assert w.db.query(RbacUserRole).filter_by(user_id=target.id).count() == 0


def test_moving_an_account_revokes_old_tenant_assignments_with_history(w):
    from ccure_platform.administration.users import router as users_router

    w.client.app.include_router(users_router)
    target = w.person(w.a, "platform.viewer")
    old = w.db.query(RbacUserRole).filter_by(user_id=target.id).one()
    response = w.call(
        w.sa,
        "PATCH",
        f"/admin/users/{target.id}/organization",
        json={"organization_id": w.b.id},
    )
    assert response.status_code == 200
    assert target.org_id == w.b.id
    assert old.revoked_at is not None and old.revoke_reason == "manual"
    assert build_authorization(w.db, target)["permissions"]["organization"] == []
    assert (
        events(w.db, "rbac.role.revoked")[-1].changes["reason"]
        == "organization_changed"
    )


def test_membership_mismatch_cannot_retain_old_tenant_grants(w):
    from ccure_platform.rbac import resolver

    target = w.person(w.a, "platform.viewer")
    target.org_id = w.b.id
    w.db.flush()
    assert resolver.resolve_grants(w.db, resolver.principal_for_user(target)) == ()


def test_inactive_tenant_cannot_receive_new_role_assignments(w):
    target = w.person(w.b)
    w.b.is_active = False
    denied = w.call(
        w.sa,
        "POST",
        f"/platform/rbac/users/{target.id}/assignments",
        json={"role_id": role_id(w.db, "platform.viewer")},
    )
    assert denied.status_code == 403
    assert w.db.query(RbacUserRole).filter_by(user_id=target.id).count() == 0
    assert events(w.db, "rbac.assignment.denied")


def test_account_transfer_requires_authority_to_revoke_existing_roles(w):
    from ccure_platform.administration.users import router as users_router
    from rbac_testing import platform_custom_role

    w.client.app.include_router(users_router)
    mover = platform_custom_role(
        w.db,
        "move_only",
        "Move Only",
        "platform.user.move_org",
        "platform.user.read",
        c.ORG_SWITCH_KEY,
    )
    actor = w.person(w.a)
    assign(w.db, actor, mover)
    target = w.person(w.a, "platform.viewer")
    old = w.db.query(RbacUserRole).filter_by(user_id=target.id).one()
    denied = w.call(
        actor,
        "PATCH",
        f"/admin/users/{target.id}/organization",
        json={"organization_id": w.b.id},
    )
    assert denied.status_code == 403
    assert target.org_id == w.a.id and old.revoked_at is None
    assert events(w.db, "rbac.assignment.denied")


def test_platform_catalogue_contains_every_enabled_module_declaration(w):
    from ccure_platform.rbac.model import RbacPermission

    sources = composition.load_permission_sources()
    declared = {p.key for source in sources for p in source.permissions}
    stored = {p.key for p in w.db.query(RbacPermission).filter_by(status="active")}
    displayed = {
        p["key"]
        for p in w.call(w.sa, "GET", "/platform/rbac/permissions").json()["permissions"]
        if p["status"] == "active"
    }
    assert declared == stored == displayed
    assert {source.namespace for source in sources} == {"platform", "audit"}


def test_role_write_without_effective_grants_is_denied_and_audited(w):
    unassigned = w.person(w.a)
    denied = w.call(
        unassigned,
        "POST",
        "/platform/rbac/roles",
        json={"display_name": "Denied", "permission_keys": []},
    )
    assert denied.status_code == 403
    assert events(w.db, "rbac.role.denied")[-1].changes["violations"] == [
        "no_effective_grants"
    ]
    assert w.db.query(RbacRole).filter_by(display_name="Denied").count() == 0


def test_continuity_audit_failure_keeps_the_account_active(w, monkeypatch):
    from ccure_platform.administration import rbac_security
    from ccure_platform.administration.users import router as users_router

    w.client.app.include_router(users_router)
    target = w.person(w.b, "platform.org_admin")
    monkeypatch.setattr(rbac_security, "audit_isolated", lambda *args: False)
    denied = w.call(
        w.sa, "PATCH", f"/admin/users/{target.id}/status", json={"is_active": False}
    )
    assert denied.status_code == 503
    assert target.is_active and not target.is_deleted
