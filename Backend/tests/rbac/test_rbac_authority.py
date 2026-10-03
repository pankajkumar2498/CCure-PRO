"""
RBAC-4 — the new engine decides, per migrated path, with legacy as the fallback.

Every test drives the *real* guards (``require_permission``, ``require_authorized``,
``user_has_permission``) on a real route. Authority is switched on for the test only
(``RBAC_AUTHORITY_MODE`` / ``RBAC_AUTHORITY_PATHS``); the default is off and legacy
decides, which the first tests prove. RBAC data lives in a rolled-back transaction.
"""

from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import ccure_platform.rbac.dependencies as legacy
from ccure_platform import composition
from ccure_platform.identity.dependencies import get_current_user
from ccure_platform.rbac import authority as au
from ccure_platform.rbac import shadow_runtime as rt
from ccure_platform.rbac.catalogue import sync
from ccure_platform.rbac.model import RbacRolePermission
from config import AppConfig
from db.base import get_db
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

SCAN_EXECUTE = "audit.scan.run"


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    au.recorder.reset()
    au.restore()
    au.set_migrated_paths(None)
    monkeypatch.setattr(AppConfig, "RBAC_AUTHORITY_MODE", "off")
    monkeypatch.setattr(AppConfig, "RBAC_AUTHORITY_PATHS", "")
    monkeypatch.setattr(AppConfig, "RBAC_SHADOW_MODE", "off")
    yield
    au.restore()
    au.set_migrated_paths(None)


def authority_on(monkeypatch, paths="*"):
    monkeypatch.setattr(AppConfig, "RBAC_AUTHORITY_MODE", "enforce")
    monkeypatch.setattr(AppConfig, "RBAC_AUTHORITY_PATHS", paths)


def with_legacy_role(db, user, name):
    user.role_id = db.query(Role).filter(Role.name == name).one().id
    db.flush()
    db.refresh(user)
    return user


@pytest.fixture
def world(rbac_db):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    w = type("World", (), {})()
    w.db, w.org = rbac_db, make_org(rbac_db)
    w.current = {}
    app = FastAPI()

    @app.post("/scan")
    def scan(who=Depends(legacy.require_permission("scans", "execute"))):
        return {"ok": True}

    @app.get("/scans")
    def scans(who=Depends(legacy.require_permission("scans", "read"))):
        return {"ok": True}

    @app.get("/users")
    def users(who=Depends(legacy.require_permission("users", "read"))):
        return {"ok": True}

    @app.get("/domains")
    def domains(who=Depends(legacy.require_authorized("platform.email_domain.read"))):
        return {"ok": True}

    @app.get("/shared-rules")
    def shared(db=Depends(get_db), who=Depends(get_current_user)):
        return {
            "ok": legacy.has_permission(db, who, "audit.compliance.manage_shared_rules")
        }

    app.dependency_overrides[get_current_user] = lambda: w.current["user"]
    app.dependency_overrides[get_db] = lambda: rbac_db
    w.client = TestClient(app)

    def person(legacy_role, rbac_role=None, org=None):
        user = with_legacy_role(rbac_db, make_user(rbac_db, org or w.org), legacy_role)
        if rbac_role:
            assign(rbac_db, user, role(rbac_db, rbac_role))
        return user

    w.person = person
    return w


def call(world, user, method, path, **kw):
    world.current["user"] = user
    r = world.client.request(method, path, **kw)
    return r.status_code


# ── off by default ───────────────────────────────────────────────────────────


def test_off_by_default_legacy_decides_even_when_the_new_model_disagrees(world):
    # legacy analyst may execute scans; the new model (viewer) would deny
    u = world.person("analyst", "platform.viewer")
    assert call(world, u, "POST", "/scan") == 200
    # legacy viewer may not; the new model (analyst) would allow
    v = world.person("viewer", "platform.analyst")
    assert call(world, v, "POST", "/scan") == 403
    assert au.recorder.snapshot()["by_path"] == {}


def test_mode_enforce_with_no_paths_switches_nothing_on(world, monkeypatch):
    authority_on(monkeypatch, paths="")
    v = world.person("viewer", "platform.analyst")
    assert call(world, v, "POST", "/scan") == 403
    assert not au.enabled_for("scans:execute")


def test_an_unknown_mode_is_off(monkeypatch):
    monkeypatch.setattr(AppConfig, "RBAC_AUTHORITY_MODE", "enabled")
    monkeypatch.setattr(AppConfig, "RBAC_AUTHORITY_PATHS", "*")
    assert au.mode() == "off" and not au.enabled_for("scans:execute")


def test_configuration_cannot_switch_on_a_path_the_inventory_defers(monkeypatch):
    authority_on(monkeypatch, paths="users:read,scans:execute")
    assert au.enabled_for("scans:execute")
    assert not au.enabled_for("users:read")


# ── the new engine decides ───────────────────────────────────────────────────


def test_authorized_user_succeeds(world, monkeypatch):
    authority_on(monkeypatch)
    u = world.person("analyst", "platform.analyst")
    assert call(world, u, "POST", "/scan") == 200
    assert au.recorder.snapshot()["by_path"] == {"scans:execute|new": 1}


def test_unauthorized_user_is_denied(world, monkeypatch):
    authority_on(monkeypatch)
    v = world.person("viewer", "platform.viewer")
    assert call(world, v, "POST", "/scan") == 403


def test_the_new_model_can_deny_what_legacy_allows(world, monkeypatch):
    authority_on(monkeypatch)
    u = world.person("analyst", "platform.viewer")  # legacy analyst, new viewer
    assert call(world, u, "POST", "/scan") == 403


def test_the_new_model_can_allow_what_legacy_denies(world, monkeypatch):
    authority_on(monkeypatch)
    v = world.person("viewer", "platform.analyst")
    assert call(world, v, "POST", "/scan") == 200
    assert au.recorder.snapshot()["divergences"]


def test_removing_a_permission_removes_access_immediately(world, monkeypatch):
    authority_on(monkeypatch)
    custom = custom_org_role(
        world.db, world.org, "runner", "Runner", SCAN_EXECUTE, "audit.scan.read"
    )
    u = world.person("analyst")
    assign(world.db, u, custom)
    assert call(world, u, "POST", "/scan") == 200
    world.db.query(RbacRolePermission).filter(
        RbacRolePermission.role_id == custom.id,
        RbacRolePermission.permission_key == SCAN_EXECUTE,
    ).delete()
    world.db.flush()
    assert call(world, u, "POST", "/scan") == 403  # legacy would still allow


def test_a_display_name_change_changes_nothing(world, monkeypatch):
    authority_on(monkeypatch)
    u = world.person("analyst", "platform.analyst")
    assert call(world, u, "POST", "/scan") == 200
    r = role(world.db, "platform.analyst")
    r.display_name = "Chief Information Security Officer"
    world.db.flush()
    assert call(world, u, "POST", "/scan") == 200
    v = world.person("viewer", "platform.viewer")
    role(world.db, "platform.superadmin").display_name = "Chief"
    world.db.flush()
    role(world.db, "platform.viewer").display_name = "Superadmin"
    world.db.flush()
    assert call(world, v, "POST", "/scan") == 403


def test_multiple_roles_union(world, monkeypatch):
    authority_on(monkeypatch)
    a = custom_org_role(world.db, world.org, "a", "A", SCAN_EXECUTE)
    b = custom_org_role(world.db, world.org, "b", "B", "audit.scan.read")
    u = world.person("viewer")
    assign(world.db, u, a)
    assert call(world, u, "POST", "/scan") == 200
    assert call(world, u, "GET", "/scans") == 403
    assign(world.db, u, b)
    assert call(world, u, "GET", "/scans") == 200
    assert call(world, u, "POST", "/scan") == 200


def test_a_retired_role_cannot_authorize(world, monkeypatch):
    authority_on(monkeypatch)
    custom = custom_org_role(world.db, world.org, "old", "Old", SCAN_EXECUTE)
    u = world.person("analyst")
    assign(world.db, u, custom)
    assert call(world, u, "POST", "/scan") == 200
    force_state(world.db, custom, "retiring")
    force_state(world.db, custom, "retired")
    assert call(world, u, "POST", "/scan") == 403


def test_a_custom_role_grants_only_what_it_holds(world, monkeypatch):
    authority_on(monkeypatch)
    custom = custom_org_role(world.db, world.org, "narrow", "Narrow", "audit.scan.read")
    u = world.person("org_admin")  # legacy org_admin holds everything in the org
    assign(world.db, u, custom)
    assert call(world, u, "GET", "/scans") == 200
    assert call(world, u, "POST", "/scan") == 403


def test_a_role_cannot_be_assigned_into_another_organisation(world, monkeypatch):
    """The database refuses an organisation-scope assignment outside the user's own
    organisation, so a wrong-organisation grant cannot exist to be honoured."""
    authority_on(monkeypatch)
    other = make_org(world.db)
    u = world.person("analyst")
    with pytest.raises(Exception, match="own organisation"):
        with world.db.begin_nested():
            assign(
                world.db,
                u,
                role(world.db, "platform.analyst"),
                "organization",
                other.id,
            )
    assert call(world, u, "POST", "/scan") == 200  # legacy fallback, unprovisioned


def test_another_organisations_custom_role_does_not_authorize_here(world, monkeypatch):
    authority_on(monkeypatch)
    other = make_org(world.db)
    foreign = custom_org_role(world.db, other, "x", "X", SCAN_EXECUTE)
    u = world.person("viewer")
    with pytest.raises(Exception):
        with world.db.begin_nested():
            assign(world.db, u, foreign)
    assert call(world, u, "POST", "/scan") == 403


def test_client_supplied_claims_cannot_grant(world, monkeypatch):
    authority_on(monkeypatch)
    v = world.person("viewer", "platform.viewer")
    headers = {
        "X-Permissions": "audit.scan.run,scans:execute",
        "X-Role": "superadmin",
        "Authorization": "Bearer forged",
    }
    assert (
        call(world, v, "POST", "/scan", headers=headers, json={"role": "superadmin"})
        == 403
    )


# ── fallback when the new model cannot answer ────────────────────────────────


def test_an_unprovisioned_account_keeps_its_legacy_answer(world, monkeypatch):
    authority_on(monkeypatch)
    assert call(world, world.person("analyst"), "POST", "/scan") == 200
    assert call(world, world.person("viewer"), "POST", "/scan") == 403
    snap = au.recorder.snapshot()["by_path"]
    assert snap == {"scans:execute|legacy": 2}


def test_an_unsynced_catalogue_falls_back_to_legacy(rbac_db, monkeypatch):
    authority_on(monkeypatch)
    org = make_org(rbac_db)
    u = with_legacy_role(rbac_db, make_user(rbac_db, org), "analyst")
    out = au.decide_atom(rbac_db, u, "scans", "execute", True)
    assert out.source == au.SOURCE_LEGACY and out.allowed


def test_an_evaluator_error_falls_back_to_legacy(world, monkeypatch):
    authority_on(monkeypatch)
    u = world.person("analyst", "platform.viewer")

    def boom(*a, **k):
        raise RuntimeError("down")

    monkeypatch.setattr("ccure_platform.rbac.shadow.shadow_compare", boom)
    out = au.decide_atom(world.db, u, "scans", "execute", True)
    assert out.source == au.SOURCE_LEGACY and out.allowed


# ── rollback ─────────────────────────────────────────────────────────────────


def test_rollback_of_one_path_restores_legacy_without_touching_data(world, monkeypatch):
    authority_on(monkeypatch)
    u = world.person("analyst", "platform.viewer")
    assert call(world, u, "POST", "/scan") == 403
    au.roll_back("scans:execute")
    assert call(world, u, "POST", "/scan") == 200
    assert call(world, u, "GET", "/scans") == 200
    au.restore("scans:execute")
    assert call(world, u, "POST", "/scan") == 403


def test_a_deferred_atom_stays_legacy_whatever_is_configured(world, monkeypatch):
    authority_on(monkeypatch, paths="*")
    # users:read is deferred; legacy org_admin allowed, an RBAC viewer would deny
    u = world.person("org_admin", "platform.viewer")
    assert call(world, u, "GET", "/users") == 200


# ── shadow still works beside authority ──────────────────────────────────────


def test_shadow_mode_still_records_beside_authority(world, monkeypatch):
    authority_on(monkeypatch)
    monkeypatch.setattr(AppConfig, "RBAC_SHADOW_MODE", "observe")
    rt.reset_recorder()
    u = world.person("viewer", "platform.analyst")
    with rt.use_session(world.db):
        assert call(world, u, "POST", "/scan") == 200
    assert rt.recorder().total() >= 1
    rt.reset_recorder()


# ── role-name guards replaced by permission keys ─────────────────────────────


def test_a_key_guard_is_the_legacy_role_check_when_authority_is_off(world):
    assert call(world, world.person("superadmin"), "GET", "/domains") == 200
    assert call(world, world.person("org_admin"), "GET", "/domains") == 403


def test_a_key_guard_uses_grants_not_the_role_name_when_on(world, monkeypatch):
    authority_on(monkeypatch)
    spoof = world.person("superadmin", "platform.viewer")  # legacy name says superadmin
    assert call(world, spoof, "GET", "/domains") == 403
    real = world.person("org_admin", "platform.superadmin")
    assert call(world, real, "GET", "/domains") == 200


def test_no_superadmin_shortcut_in_the_new_decision(world, monkeypatch):
    authority_on(monkeypatch)
    # a superadmin whose role holds nothing for this key is denied
    custom_platform = world.person("superadmin")
    assign(world.db, custom_platform, role(world.db, "platform.viewer"))
    assert call(world, custom_platform, "GET", "/domains") == 403


def test_in_handler_key_check(world, monkeypatch):
    su = world.person("superadmin")
    world.current["user"] = su
    assert world.client.get("/shared-rules").json() == {"ok": True}
    oa = world.person("org_admin")
    world.current["user"] = oa
    assert world.client.get("/shared-rules").json() == {"ok": False}
