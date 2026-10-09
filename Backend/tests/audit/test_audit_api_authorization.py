"""
tests/audit/test_audit_api_authorization.py
─────────────────────────────────────────────────────────────────────────────
Phase 2: server-side authorization on the audit API, including the new
event-detail route.

Spec §16 is explicit that route protection in the SPA is not a control. Every
assertion here talks to the API directly with no browser involved.

The detail endpoint is the new surface and the one worth being careful about:
it takes an opaque id, so an unscoped implementation would happily hand any
tenant's event to any caller who can guess or capture an id — and audit rows
carry usernames, email addresses and source IPs.
"""

from native_rbac import system_role, create_user, fixture_role


from datetime import datetime, timezone

import pytest
from auth.jwt_handler import create_access_token, hash_password
from db.base import gen_user_id, gen_uuid, utcnow
from db.models import AuditLog, Organization, User

BASE = "/admin/audit-logs/"


def _event(db_session, org_id, **kw):
    row = AuditLog(
        id=gen_uuid(),
        org_id=org_id,
        action=kw.get("action", "user.login"),
        resource_type="user",
        resource_id="res-1",
        status="success",
        severity=kw.get("severity", "info"),
        ip_address="10.180.6.14",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(row)
    db_session.commit()
    return row


def _headers(user: User) -> dict:
    token = create_access_token(
        user.id,
        user.username,
        org_id=user.org_id,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def other_tenant(db_session):
    """A second organisation with its own admin and its own audit event."""
    uid = gen_uuid()[:8]
    org = Organization(
        id=f"org_other_{uid}",
        name=f"Other Org {uid}",
        slug=f"other-org-{uid}",
        max_assets=10,
        max_users=5,
        is_active=True,
    )
    db_session.add(org)
    db_session.flush()

    role = system_role(db_session, "platform.org_admin")
    admin = create_user(
        db_session,
        id=gen_user_id(org.slug, "otheradmin"),
        username=f"otheradmin_{uid}",
        email=f"otheradmin_{uid}@other.test",
        full_name="Other Admin",
        password_hash=hash_password("securepassword123"),
        org_id=org.id,
        role=role,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
        approved_by="fixture",
    )
    db_session.add(admin)
    db_session.commit()
    db_session.refresh(admin)

    event = _event(db_session, org.id, action="organization.updated", severity="medium")
    return {"org": org, "admin": admin, "event": event}


@pytest.fixture
def no_audit_user(db_session, test_org):
    """A user in the caller's tenant whose role lacks `audit:read` entirely."""
    uid = gen_uuid()[:8]
    role = fixture_role(db_session, f"no_audit_{uid}")
    db_session.add(role)
    db_session.flush()

    user = create_user(
        db_session,
        id=gen_user_id(test_org.slug, f"noaudit{uid}"),
        username=f"noaudit_{uid}",
        email=f"noaudit_{uid}@test.com",
        full_name="No Audit",
        password_hash=hash_password("securepassword123"),
        org_id=test_org.id,
        role=role,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
        approved_by="fixture",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


# ─── Authentication ──────────────────────────────────────────────────────────


def test_list_requires_authentication(client):
    assert client.get(BASE).status_code in (401, 403)


def test_detail_requires_authentication(client, db_session, test_user):
    row = _event(db_session, test_user.org_id)
    assert client.get(f"{BASE}{row.id}").status_code in (401, 403)


# ─── Permission ──────────────────────────────────────────────────────────────


def test_list_refused_without_audit_read(client, no_audit_user):
    res = client.get(BASE, headers=_headers(no_audit_user))
    assert res.status_code == 403, res.text


def test_detail_refused_without_audit_read(client, db_session, no_audit_user):
    """
    The detail route must carry its own permission check. A route added beside
    a protected one does not inherit its dependency.
    """
    row = _event(db_session, no_audit_user.org_id)
    res = client.get(f"{BASE}{row.id}", headers=_headers(no_audit_user))
    assert res.status_code == 403, res.text


def test_analyst_and_viewer_cannot_read_the_audit_trail(client, db_session, test_org):
    """`audit:read` is held by org_admin and superadmin only."""
    for role_name in ("platform.analyst", "platform.viewer"):
        role = system_role(db_session, role_name)
        uid = gen_uuid()[:8]
        user = create_user(
            db_session,
            id=gen_user_id(test_org.slug, f"{role_name}{uid}"),
            username=f"{role_name}_{uid}",
            email=f"{role_name}_{uid}@test.com",
            password_hash=hash_password("securepassword123"),
            org_id=test_org.id,
            role=role,
            is_active=True,
            is_verified=True,
            approved_at=utcnow(),
            approved_by="fixture",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        res = client.get(BASE, headers=_headers(user))
        assert res.status_code == 403, f"{role_name} reached the audit trail"


# ─── Tenant isolation ────────────────────────────────────────────────────────


def test_list_does_not_leak_another_tenants_events(
    client, auth_headers, db_session, test_user, other_tenant
):
    _event(db_session, test_user.org_id, action="user.role_changed")

    res = client.get(BASE, headers=auth_headers, params={"limit": 1000})
    assert res.status_code == 200
    ids = {row["id"] for row in res.json()["logs"]}
    assert other_tenant["event"].id not in ids


def test_detail_of_another_tenants_event_is_404_not_403(
    client, auth_headers, other_tenant
):
    """
    404, deliberately. 403 would confirm the id exists somewhere, which is an
    existence oracle over other tenants' audit trails.
    """
    res = client.get(f"{BASE}{other_tenant['event'].id}", headers=auth_headers)
    assert res.status_code == 404, res.text


def test_a_tenant_can_read_its_own_event_detail(client, other_tenant):
    """The mirror of the test above: the owning tenant does get it."""
    res = client.get(
        f"{BASE}{other_tenant['event'].id}", headers=_headers(other_tenant["admin"])
    )
    assert res.status_code == 200, res.text
    assert res.json()["id"] == other_tenant["event"].id


def test_search_cannot_be_used_to_reach_another_tenant(
    client, auth_headers, other_tenant
):
    """
    Search adds a join and a new set of OR'd conditions. If it were applied
    outside the tenant filter it would OR *past* it — the classic way a scoped
    query is accidentally widened.
    """
    res = client.get(BASE, headers=auth_headers, params={"q": other_tenant["event"].id})
    assert res.status_code == 200
    assert res.json()["logs"] == []


def test_filters_cannot_be_used_to_reach_another_tenant(
    client, auth_headers, other_tenant
):
    for params in (
        {"severity": "medium"},
        {"action": "organization.updated"},
        {"ip_address": "10.180.6.14"},
        {"range": "30d"},
    ):
        res = client.get(BASE, headers=auth_headers, params={**params, "limit": 1000})
        assert res.status_code == 200, res.text
        ids = {row["id"] for row in res.json()["logs"]}
        assert other_tenant["event"].id not in ids, f"leaked via {params}"


# ─── No write surface ────────────────────────────────────────────────────────


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_audit_api_exposes_no_write_methods(
    client, auth_headers, db_session, test_user, method
):
    """
    Spec §4/§16: the trail must be append-only through the application. This is
    the API-layer half — Phase 3 adds the grant- and trigger-level enforcement
    that also covers a direct database connection.
    """
    row = _event(db_session, test_user.org_id)

    # httpx's `delete()` takes no body, so the request is built explicitly
    # rather than through the per-verb helpers.
    for path in (BASE, f"{BASE}{row.id}"):
        response = client.request(
            method.upper(), path, headers=auth_headers, json={"action": "tampered"}
        )
        assert response.status_code in (
            404,
            405,
        ), f"{method.upper()} {path} is reachable: {response.status_code}"
