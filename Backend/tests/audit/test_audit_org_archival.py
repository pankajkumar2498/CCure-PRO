"""
tests/audit/test_audit_org_archival.py
─────────────────────────────────────────────────────────────────────────────
Phase 4: `DELETE /admin/organizations/{id}` archives instead of deleting.

The reason is measurable rather than stylistic. Thirty foreign keys reference
`organizations` and **every one of them is `ON DELETE CASCADE`**, so the
previous `db.delete(org)` destroyed the tenant's users, assets, scans, all
fourteen `compliance_*` tables including findings and evidence, and its entire
audit trail — irreversibly, with no undo, at exactly the moment an offboarding
is most likely to be disputed.

The `ON DELETE CASCADE` relationships are deliberately unchanged. This route
simply stops invoking them, which is what makes the change reversible and
low-risk.
"""

from native_rbac import system_role, create_user

import pytest
from auth.jwt_handler import create_access_token
from db.models import AuditLog, Organization, User

pytestmark = pytest.mark.usefixtures("db_session")


def _headers(user: User) -> dict:
    """
    Mint a token for `user` directly.

    Deliberately not "promote `test_user` and reuse `auth_headers`": the access
    token carries the role it was issued with, and the API rejects a token
    whose role no longer matches the account ("Token role scope no longer
    matches the user account"). Promoting after login invalidates the very
    header the test would then use.
    """
    return {
        "Authorization": "Bearer "
        + create_access_token(
            user.id,
            user.username,
            org_id=user.org_id,
        )
    }


@pytest.fixture
def other_org(db_session, test_org):
    """A second organisation, so the 'cannot archive your own' guard is not
    what is being measured."""
    org = Organization(name="Archival Target Ltd", slug="archival-target")
    db_session.add(org)
    db_session.commit()
    return org


@pytest.fixture
def superadmin(db_session, test_org):
    role = system_role(db_session, "platform.superadmin")
    assert role is not None, "superadmin role must be seeded"
    user = create_user(
        db_session,
        username="archival_superadmin",
        email="archival.superadmin@test.com",
        password_hash="hash",
        org_id=test_org.id,
        role=role,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def member(db_session, other_org):
    role = system_role(db_session, "platform.org_admin")
    user = create_user(
        db_session,
        username="tenant_member",
        email="tenant.member@test.com",
        password_hash="hash",
        org_id=other_org.id,
        role=role,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.commit()
    return user


def test_archiving_does_not_delete_the_organization(
    client, db_session, superadmin, other_org
):
    """The headline property: the row is still there afterwards."""
    org_id = other_org.id

    response = client.delete(
        f"/admin/organizations/{org_id}", headers=_headers(superadmin)
    )
    assert response.status_code == 200, response.text
    assert response.json()["archived"] is True

    db_session.expire_all()
    survivor = db_session.get(Organization, org_id)
    assert survivor is not None, "archiving must not delete the organisation"
    assert survivor.archived_at is not None
    assert survivor.is_active is False
    assert survivor.archived_by_user_id == str(superadmin.id)


def test_archiving_preserves_the_tenants_audit_history(
    client, db_session, superadmin, other_org, member
):
    """
    The whole point. Under the old hard delete these rows went with the
    organisation via `ON DELETE CASCADE`.
    """
    from core.audit import log_audit_event

    log_audit_event(db_session, member, "user.login", "user", str(member.id))
    db_session.commit()
    before = db_session.query(AuditLog).filter(AuditLog.org_id == other_org.id).count()
    assert before >= 1
    client.delete(f"/admin/organizations/{other_org.id}", headers=_headers(superadmin))

    db_session.expire_all()
    after = db_session.query(AuditLog).filter(AuditLog.org_id == other_org.id).count()
    assert after == before, "archiving must not touch the tenant's audit trail"


def test_archived_events_remain_attributable(
    client, db_session, superadmin, other_org, member
):
    """Members are soft-deleted, so the actor snapshot is what keeps their
    history readable."""
    from core.audit import log_audit_event

    log_audit_event(db_session, member, "user.login", "user", str(member.id))
    db_session.commit()
    client.delete(f"/admin/organizations/{other_org.id}", headers=_headers(superadmin))

    db_session.expire_all()
    row = (
        db_session.query(AuditLog)
        .filter(AuditLog.org_id == other_org.id)
        .filter(AuditLog.action == "user.login")
        .first()
    )
    assert row.actor_username == "tenant_member"


def test_members_are_soft_deleted_and_deactivated(
    client, db_session, superadmin, other_org, member
):
    """Existing `users` semantics, reused rather than reinvented."""
    client.delete(f"/admin/organizations/{other_org.id}", headers=_headers(superadmin))

    db_session.expire_all()
    refreshed = db_session.get(User, member.id)
    assert refreshed is not None, "members must be soft-deleted, not removed"
    assert refreshed.is_deleted is True
    assert refreshed.is_active is False
    assert refreshed.deleted_at is not None


def test_sessions_are_revoked(client, db_session, superadmin, other_org, member):
    """
    Without this an archived tenant keeps working for the rest of the
    access-token lifetime — 30 minutes — because `is_active` is only consulted
    when a token is validated against the database.
    """
    import datetime

    from db.base import utcnow
    from db.models import RefreshTokenSession

    db_session.add(
        RefreshTokenSession(
            user_id=member.id,
            org_id=other_org.id,
            token_jti="jti-archival-probe",
            token_hash="deadbeef",
            expires_at=utcnow() + datetime.timedelta(days=7),
        )
    )
    db_session.commit()
    response = client.delete(
        f"/admin/organizations/{other_org.id}", headers=_headers(superadmin)
    )
    assert response.json()["sessions_revoked"] >= 1

    db_session.expire_all()
    assert (
        db_session.query(RefreshTokenSession)
        .filter(RefreshTokenSession.org_id == other_org.id)
        .count()
        == 0
    )


def test_the_archival_is_audited(client, db_session, superadmin, other_org):
    client.delete(
        f"/admin/organizations/{other_org.id}?reason=contract+ended",
        headers=_headers(superadmin),
    )

    db_session.expire_all()
    event = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "organization.archived")
        .order_by(AuditLog.created_at.desc())
        .first()
    )
    assert event is not None, "archiving a tenant must be audited"
    assert event.resource_id == other_org.id
    assert event.severity == "critical"
    assert event.changes["reason"] == "contract ended"


def test_archived_organizations_are_hidden_from_the_default_listing(
    client, db_session, superadmin, other_org
):
    client.delete(f"/admin/organizations/{other_org.id}", headers=_headers(superadmin))

    listed = client.get("/admin/organizations", headers=_headers(superadmin)).json()
    ids = {o["id"] for o in listed["organizations"]}
    assert other_org.id not in ids

    with_archived = client.get(
        "/admin/organizations?include_archived=true", headers=_headers(superadmin)
    ).json()
    assert other_org.id in {o["id"] for o in with_archived["organizations"]}


def test_restore_reverses_the_archival(client, db_session, superadmin, other_org):
    client.delete(f"/admin/organizations/{other_org.id}", headers=_headers(superadmin))

    response = client.post(
        f"/admin/organizations/{other_org.id}/restore", headers=_headers(superadmin)
    )
    assert response.status_code == 200, response.text
    assert response.json()["restored"] is True

    db_session.expire_all()
    restored = db_session.get(Organization, other_org.id)
    assert restored.archived_at is None
    assert restored.is_active is True

    event = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "organization.restored")
        .first()
    )
    assert event is not None


def test_restore_does_not_bulk_reactivate_members(
    client, db_session, superadmin, other_org, member
):
    """
    Restoring an account is a decision about that person, not about the
    tenancy. A bulk reactivation would quietly re-enable accounts that had been
    disabled for their own reasons before the organisation was archived.
    """
    client.delete(f"/admin/organizations/{other_org.id}", headers=_headers(superadmin))
    client.post(
        f"/admin/organizations/{other_org.id}/restore", headers=_headers(superadmin)
    )

    db_session.expire_all()
    refreshed = db_session.get(User, member.id)
    assert refreshed.is_active is False
    assert refreshed.is_deleted is True


def test_archiving_is_idempotent(client, db_session, superadmin, other_org):
    first = client.delete(
        f"/admin/organizations/{other_org.id}", headers=_headers(superadmin)
    )
    second = client.delete(
        f"/admin/organizations/{other_org.id}", headers=_headers(superadmin)
    )
    assert first.json()["archived"] is True
    assert second.json()["archived"] is False


def test_a_non_superadmin_cannot_archive(
    client, db_session, test_user, auth_headers, other_org
):
    """
    `test_user` is an org admin. The check is on the **role**, not on a
    permission, because org_admin holds `organizations:update` for its own
    tenant — so a permission check could not express "superadmin only" here.
    """
    response = client.delete(
        f"/admin/organizations/{other_org.id}", headers=auth_headers
    )
    assert response.status_code == 403

    db_session.expire_all()
    assert db_session.get(Organization, other_org.id).archived_at is None


def test_cannot_archive_your_own_organization(client, db_session, superadmin):
    response = client.delete(
        f"/admin/organizations/{superadmin.org_id}", headers=_headers(superadmin)
    )
    assert response.status_code == 400
    assert "own organization" in response.json()["detail"]
