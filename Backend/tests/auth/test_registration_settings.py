"""Registration policy: authorization, immediate enforcement, durability and races."""

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from ccure_platform import composition
from ccure_platform.administration import registration_settings as settings
from ccure_platform.identity import reauth
from ccure_platform.identity.dependencies import get_current_user
from ccure_platform.identity.router import router as auth_router
from ccure_platform.rbac import scope
from ccure_platform.rbac.catalogue import sync
from config import AppConfig
from db.base import get_db
from db.models import PlatformAuditEvent, RegistrationPolicy
from rbac_testing import (
    assign,
    make_org,
    make_user,
    rbac_db_fixture,  # noqa: F401
    role,
)  # noqa: F401

PATH = "/admin/registration-settings"


@pytest.fixture
def w(rbac_db, monkeypatch):
    monkeypatch.setattr(AppConfig, "ALLOW_SELF_REGISTRATION", False)
    monkeypatch.setattr(AppConfig, "RBAC_REAUTH_MODE", "off")
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    rbac_db.query(RegistrationPolicy).delete()
    org = make_org(rbac_db)
    people = {}
    for key in ("platform.superadmin", "platform.org_admin", "platform.viewer"):
        user = make_user(rbac_db, org)
        assign(rbac_db, user, role(rbac_db, key))
        people[key] = user
    application = FastAPI()
    application.include_router(settings.router)
    application.include_router(auth_router)
    current = {"user": people["platform.superadmin"]}
    application.dependency_overrides[get_current_user] = lambda: current["user"]
    application.dependency_overrides[get_db] = lambda: rbac_db
    client = TestClient(application, raise_server_exceptions=False)
    world = SimpleNamespace(db=rbac_db, client=client, current=current, people=people)

    def call(method, path=PATH, **kwargs):
        with scope.use_audit_session(rbac_db):
            return client.request(method, path, **kwargs)

    world.call = call
    yield world
    client.close()


def patch(w, value, revision=0, **kwargs):
    return w.call(
        "PATCH",
        json={"self_registration_enabled": value, "revision": revision},
        **kwargs
    )


def test_default_preserves_disabled_deployment_and_first_save_initializes_policy(w):
    assert w.call("GET").json()["source"] == "deployment"
    assert w.call("GET", "/auth/config").json() == {"self_registration_enabled": False}
    result = patch(w, True)
    assert result.status_code == 200
    assert result.json()["source"] == "administrator"
    assert result.json()["revision"] == 1
    w.db.expire_all()
    assert w.db.get(RegistrationPolicy, 1).self_registration_enabled is True


def test_ui_and_all_signup_routes_follow_saved_policy_immediately(w, monkeypatch):
    monkeypatch.setattr(AppConfig, "ALLOW_SELF_REGISTRATION", True)
    assert patch(w, False).status_code == 200
    assert w.call("GET", "/auth/config").json() == {"self_registration_enabled": False}
    for method, path, kwargs in (
        ("GET", "/auth/check-email?q=person@example.com", {}),
        ("GET", "/auth/check-username?q=person", {}),
        ("POST", "/auth/register", {"json": {}}),
        (
            "POST",
            "/auth/resend-verification",
            {"json": {"email": "person@example.com"}},
        ),
    ):
        assert w.call(method, path, **kwargs).status_code == 404
    assert patch(w, True, 1).status_code == 200
    assert w.call("GET", "/auth/config").json() == {"self_registration_enabled": True}
    assert w.call("POST", "/auth/register", json={}).status_code == 422


def test_reset_follows_environment_again_and_never_changes_approval(w, monkeypatch):
    monkeypatch.setattr(AppConfig, "SELF_REGISTRATION_AUTO_APPROVE", False)
    assert patch(w, True).json()["administrator_approval_required"] is True
    reset = patch(w, None, 1)
    assert reset.status_code == 200
    assert reset.json()["source"] == "deployment"
    assert reset.json()["self_registration_enabled"] is False
    monkeypatch.setattr(AppConfig, "ALLOW_SELF_REGISTRATION", True)
    assert w.call("GET", "/auth/config").json()["self_registration_enabled"] is True
    assert AppConfig.SELF_REGISTRATION_AUTO_APPROVE is False


@pytest.mark.parametrize("key", ["platform.org_admin", "platform.viewer"])
def test_tenant_roles_cannot_read_or_change_platform_policy(w, key):
    w.current["user"] = w.people[key]
    assert w.call("GET").status_code == 403
    assert patch(w, True).status_code == 403
    assert w.call("GET", "/auth/config").json()["self_registration_enabled"] is False


def test_role_label_does_not_grant_access(w):
    role(w.db, "platform.superadmin").display_name = "Chief"
    w.db.flush()
    role(w.db, "platform.viewer").display_name = "Superadmin"
    w.db.flush()
    w.current["user"] = w.people["platform.viewer"]
    assert patch(w, True).status_code == 403


def test_stale_revision_cannot_overwrite_another_administrators_change(w):
    assert patch(w, True).status_code == 200
    assert patch(w, False).status_code == 409
    assert w.call("GET", "/auth/config").json()["self_registration_enabled"] is True
    assert patch(w, False, 1).status_code == 200


def test_changes_and_resets_are_audited_with_actor_and_before_after(w):
    assert patch(w, True).status_code == 200
    assert patch(w, None, 1).status_code == 200
    events = (
        w.db.query(PlatformAuditEvent)
        .filter_by(action="registration.policy_changed")
        .all()
    )
    assert len(events) == 2
    # PostgreSQL now() is shared by this fixture's rollback transaction;
    # equal timestamps cannot order the two changes. Revisions can.
    events.sort(key=lambda event: event.changes["after"]["revision"])
    assert [event.changes["after"]["revision"] for event in events] == [1, 2]
    assert all(e.actor_user_id == w.current["user"].id for e in events)
    assert events[0].changes["before"]["self_registration_enabled"] is False
    assert events[0].changes["after"]["self_registration_enabled"] is True
    assert events[1].changes["after"]["source"] == "deployment"


def test_audit_failure_rolls_back_policy(w, monkeypatch):
    assert patch(w, False).status_code == 200

    def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(settings, "log_platform_event", fail)
    assert patch(w, True, 1).status_code == 500
    assert w.call("GET").json()["revision"] == 1
    assert w.call("GET", "/auth/config").json()["self_registration_enabled"] is False


def test_sensitive_change_requires_current_authenticator_when_enrolled(w, monkeypatch):
    monkeypatch.setattr(AppConfig, "RBAC_REAUTH_MODE", "enforce")
    user = w.current["user"]
    user.mfa_enabled, user.totp_secret = True, "fixture-encrypted"
    w.db.flush()
    monkeypatch.setattr(reauth, "_verify", lambda user, code: code == "123456")
    assert patch(w, True).json()["detail"]["code"] == "reauth_required"
    assert patch(w, True, headers={"X-Reauth-Code": "bad"}).status_code == 403
    assert w.call("GET", "/auth/config").json()["self_registration_enabled"] is False
    assert patch(w, True, headers={"X-Reauth-Code": "123456"}).status_code == 200
    event = (
        w.db.query(PlatformAuditEvent)
        .filter_by(action="registration.policy_changed")
        .one()
    )
    assert event.changes["reauth"] == "verified"
    assert "123456" not in str(event.changes)


@pytest.mark.parametrize("value", ["true", 1, "false", {}])
def test_non_boolean_values_are_rejected(w, value):
    assert patch(w, value).status_code == 422


@pytest.mark.parametrize("revision", [True, "0", -1, 0.5])
def test_invalid_revisions_cannot_bypass_conflict_protection(w, revision):
    assert patch(w, True, revision).status_code == 422


def test_unknown_fields_cannot_change_other_account_access_settings(w):
    response = w.call(
        "PATCH",
        json={
            "self_registration_enabled": True,
            "revision": 0,
            "self_registration_auto_approve": True,
        },
    )
    assert response.status_code == 422
    assert w.call("GET", "/auth/config").json()["self_registration_enabled"] is False


def test_anonymous_requests_cannot_read_or_update_administrator_settings(client):
    assert client.get(PATH).status_code in (401, 403)
    assert client.patch(
        PATH, json={"self_registration_enabled": True, "revision": 0}
    ).status_code in (401, 403)


def test_unavailable_policy_never_falls_back_to_enabled_environment(w, monkeypatch):
    monkeypatch.setattr(AppConfig, "ALLOW_SELF_REGISTRATION", True)

    def fail(*args, **kwargs):
        raise OperationalError("policy read", {}, RuntimeError("unavailable"))

    monkeypatch.setattr(w.db, "query", fail)
    assert w.call("GET", "/auth/config").status_code == 503
    assert w.call("POST", "/auth/register", json={}).status_code == 503
