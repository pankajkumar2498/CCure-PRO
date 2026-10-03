"""
RBAC-6 — the authorization payload the UI consumes (``/auth/me`` → ``authorization``).
Advisory, derived from the same engine and mapping the backend enforces with; no role
name is an input and nothing structural is exposed.
"""

from __future__ import annotations

import json

import pytest

from ccure_platform import composition
from ccure_platform.identity import router as identity
from ccure_platform.rbac import authority as au
from ccure_platform.rbac import legacy_map, scope
from ccure_platform.rbac.authorization_view import CONTRACT_VERSION, build_authorization
from ccure_platform.rbac.catalogue import sync
from config import AppConfig
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


@pytest.fixture
def w(rbac_db, monkeypatch):
    au.set_migrated_paths(None)
    monkeypatch.setattr(AppConfig, "RBAC_AUTHORITY_MODE", "off")
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    w = type("W", (), {})()
    w.db, w.a, w.b = rbac_db, make_org(rbac_db), make_org(rbac_db)

    def person(org, legacy_role, rbac_role=None):
        u = make_user(rbac_db, org)
        u.role_id = rbac_db.query(Role).filter(Role.name == legacy_role).one().id
        rbac_db.flush()
        rbac_db.refresh(u)
        if rbac_role:
            assign(rbac_db, u, role(rbac_db, rbac_role))
        return u

    w.person = person
    return w


def keys(a):
    return set(a["permissions"]["platform"]) | set(a["permissions"]["organization"])


def test_shape_is_stable_and_exposes_no_structure(w):
    u = w.person(w.a, "analyst", "platform.analyst")
    a = build_authorization(w.db, u)
    assert set(a) == {
        "contract",
        "source",
        "home_org_id",
        "active_org_id",
        "permissions",
        "can_switch_organisation",
        "assignments",
        "atoms",
    }
    assert a["contract"] == CONTRACT_VERSION == 1
    blob = json.dumps(a)
    assert (
        "role_id" not in blob and "rbac_" not in blob and "platform.analyst" not in blob
    )
    assert all(set(x) == {"display_name", "scope_type"} for x in a["assignments"])


def test_platform_source_is_the_engines_answer_split_by_scope(w):
    sa = w.person(w.a, "superadmin", "platform.superadmin")
    a = build_authorization(w.db, sa)
    assert a["source"] == "platform" and a["can_switch_organisation"] is True
    assert "platform.organization.switch" in a["permissions"]["platform"]
    assert "audit.scan.read" in a["permissions"]["organization"]
    admin = build_authorization(w.db, w.person(w.a, "org_admin", "platform.org_admin"))
    assert admin["can_switch_organisation"] is False
    assert not keys(admin) & {
        "platform.organization.switch",
        "platform.email_domain.read",
    }


def test_a_legacy_only_account_gets_the_same_keys_through_the_golden_mapping(w):
    for name, entry in {
        e["legacy_role"]: e for e in legacy_map.load_golden()["roles"]
    }.items():
        legacy_only = build_authorization(w.db, w.person(w.a, name))
        provisioned = build_authorization(w.db, w.person(w.a, name, entry["role_key"]))
        assert legacy_only["source"] == "legacy_mapped"
        assert provisioned["source"] == "platform"
        assert keys(legacy_only) == keys(provisioned), name
        assert (
            legacy_only["can_switch_organisation"]
            == provisioned["can_switch_organisation"]
        )


def test_a_role_rename_changes_nothing_and_a_display_name_grants_nothing(w):
    u = w.person(w.a, "viewer", "platform.viewer")
    before = keys(build_authorization(w.db, u))
    role(w.db, "platform.superadmin").display_name = "Chief"
    w.db.flush()
    role(w.db, "platform.viewer").display_name = "Superadmin"
    w.db.flush()
    a = build_authorization(w.db, u)
    assert keys(a) == before and a["can_switch_organisation"] is False
    assert a["assignments"][0]["display_name"] == "Superadmin"  # a label only


def test_multiple_roles_union_and_revocation_or_retirement_removes(w):
    from datetime import datetime, timezone

    from ccure_platform.rbac.model import RbacUserRole

    u = w.person(w.a, "scanner", "platform.scanner")
    extra = custom_org_role(w.db, w.a, "x", "X", "audit.scan.read_all")
    row = assign(w.db, u, extra)
    assert "audit.scan.read_all" in keys(build_authorization(w.db, u))
    row.revoked_at, row.revoke_reason = datetime.now(timezone.utc), "manual"
    w.db.flush()
    assert "audit.scan.read_all" not in keys(build_authorization(w.db, u))
    row2 = assign(w.db, u, custom_org_role(w.db, w.a, "y", "Y", "audit.scan.read_all"))
    r = w.db.query(RbacUserRole).filter_by(id=row2.id).one().role_id
    from ccure_platform.rbac.model import RbacRole

    force_state(w.db, w.db.get(RbacRole, r), "retiring")
    force_state(w.db, w.db.get(RbacRole, r), "retired")
    assert "audit.scan.read_all" not in keys(build_authorization(w.db, u))


def test_active_organisation_comes_from_the_backend_not_the_request(w, monkeypatch):
    admin = w.person(w.a, "org_admin", "platform.org_admin")
    got = identity._authorization_for(w.db, admin, w.b.id)
    assert got["active_org_id"] == w.a.id  # a forged id is not honoured
    monkeypatch.setattr(AppConfig, "RBAC_AUTHORITY_MODE", "enforce")
    monkeypatch.setattr(AppConfig, "RBAC_AUTHORITY_PATHS", "*")
    sa = w.person(w.a, "superadmin", "platform.superadmin")
    with scope.use_audit_session(w.db):
        assert identity._authorization_for(w.db, sa, w.b.id)["active_org_id"] == w.b.id
        assert identity._authorization_for(w.db, sa, None)["active_org_id"] == w.a.id


def test_the_legacy_vocabulary_is_served_not_copied(w):
    atoms = build_authorization(w.db, w.person(w.a, "viewer"))["atoms"]
    assert atoms["scans:read"] == ["audit.scan.read"]
    assert "users:update" in atoms and len(atoms["users:update"]) == 4
