"""
tests/test_admin_reset_password.py
─────────────────────────────────────────────────────────────────────────────
Integration tests for admin-driven password reset.
"""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from auth.jwt_handler import create_access_token, verify_password
from db.models import (
    Organization,
    Permission,
    Role,
    RolePermission,
    User,
    RefreshTokenSession,
)


def _grant_permission(
    db_session: Session, role: Role, resource: str, action: str
) -> None:
    permission = (
        db_session.query(Permission)
        .filter(Permission.resource == resource, Permission.action == action)
        .first()
    )
    if permission is None:
        permission = Permission(
            resource=resource, action=action, description=f"{resource}:{action}"
        )
        db_session.add(permission)
        db_session.flush()

    exists = (
        db_session.query(RolePermission)
        .filter(
            RolePermission.role_id == role.id,
            RolePermission.permission_id == permission.id,
        )
        .first()
    )
    if exists is None:
        db_session.add(RolePermission(role_id=role.id, permission_id=permission.id))
        db_session.flush()


def _auth_headers(user: User) -> dict:
    token = create_access_token(
        user.id,
        user.username,
        role=getattr(user.role, "name", None),
        org_id=user.org_id,
    )
    return {"Authorization": f"Bearer {token}"}


def test_superadmin_reset_password_success(client: TestClient, db_session: Session):
    """Test that a superadmin can successfully reset another user's password."""
    org = Organization(
        name="SA Reset Org",
        slug="sa-reset-org",
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    db_session.add(org)

    superadmin_role = db_session.query(Role).filter_by(name="superadmin").first()
    analyst_role = db_session.query(Role).filter_by(name="analyst").first()

    _grant_permission(db_session, superadmin_role, "users", "update")

    superadmin = User(
        id="usr_sa_admin_1234",
        username="sa-admin",
        email="sa-admin@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=superadmin_role.id,
        is_active=True,
        is_verified=True,
    )
    target_user = User(
        id="usr_sa_target_1234",
        username="sa-target",
        email="sa-target@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=analyst_role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add_all([superadmin, target_user])
    db_session.commit()

    # Call reset-password endpoint
    response = client.post(
        f"/admin/users/{target_user.id}/reset-password/",
        headers=_auth_headers(superadmin),
        json={"password": "NewCompliantPass123!"},
    )

    assert response.status_code == 200
    db_session.refresh(target_user)
    assert verify_password("NewCompliantPass123!", target_user.password_hash)


def test_org_admin_reset_password_tenant_isolation(
    client: TestClient, db_session: Session
):
    """Test that an org admin can reset password in their own org, but NOT in another org."""
    org_a = Organization(
        name="Org A", slug="org-a", max_assets=100, max_users=10, is_active=True
    )
    org_b = Organization(
        name="Org B", slug="org-b", max_assets=100, max_users=10, is_active=True
    )
    db_session.add_all([org_a, org_b])

    org_admin_role = db_session.query(Role).filter_by(name="org_admin").first()
    analyst_role = db_session.query(Role).filter_by(name="analyst").first()

    _grant_permission(db_session, org_admin_role, "users", "update")

    admin_a = User(
        id="usr_orga_admin_1111",
        username="admin-a",
        email="admin-a@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    user_a = User(
        id="usr_orga_user_1111",
        username="user-a",
        email="user-a@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role_id=analyst_role.id,
        is_active=True,
        is_verified=True,
    )
    user_b = User(
        id="usr_orgb_user_2222",
        username="user-b",
        email="user-b@test.com",
        password_hash="hash",
        org_id=org_b.id,
        role_id=analyst_role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add_all([admin_a, user_a, user_b])
    db_session.commit()

    # 1. Reset password for user in same organization should succeed
    response_success = client.post(
        f"/admin/users/{user_a.id}/reset-password/",
        headers=_auth_headers(admin_a),
        json={"password": "OrgAPasswordReset123!"},
    )
    assert response_success.status_code == 200
    db_session.refresh(user_a)
    assert verify_password("OrgAPasswordReset123!", user_a.password_hash)

    # 2. Reset password for user in different organization should return 404 (not found in scoped query)
    response_fail = client.post(
        f"/admin/users/{user_b.id}/reset-password/",
        headers=_auth_headers(admin_a),
        json={"password": "CrossOrgPasswordReset123!"},
    )
    assert response_fail.status_code == 404


def test_reset_password_revokes_sessions(client: TestClient, db_session: Session):
    """Test that resetting a password deletes all active RefreshTokenSession entries for the user."""
    org = Organization(
        name="Revocation Org",
        slug="revoc-org",
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    db_session.add(org)

    superadmin_role = db_session.query(Role).filter_by(name="superadmin").first()
    analyst_role = db_session.query(Role).filter_by(name="analyst").first()

    _grant_permission(db_session, superadmin_role, "users", "update")

    superadmin = User(
        id="usr_sa_admin_5555",
        username="sa-admin-rev",
        email="sa-admin-rev@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=superadmin_role.id,
        is_active=True,
        is_verified=True,
    )
    target_user = User(
        id="usr_target_rev_5555",
        username="target-rev",
        email="target-rev@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=analyst_role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add_all([superadmin, target_user])
    db_session.flush()

    # Create active sessions
    session_1 = RefreshTokenSession(
        user_id=target_user.id,
        org_id=org.id,
        token_jti="jti_1",
        token_hash="hash_1",
        expires_at=db_session.query(RefreshTokenSession.expires_at).scalar()
        or target_user.created_at,  # any valid date
    )
    # Give expires_at dummy value in database
    from datetime import datetime, timezone, timedelta

    session_1.expires_at = datetime.now(timezone.utc) + timedelta(days=1)

    db_session.add(session_1)
    db_session.commit()

    # Verify session exists
    assert (
        db_session.query(RefreshTokenSession)
        .filter(RefreshTokenSession.user_id == target_user.id)
        .count()
        == 1
    )

    # Call reset password
    response = client.post(
        f"/admin/users/{target_user.id}/reset-password/",
        headers=_auth_headers(superadmin),
        json={"password": "NewRevocationPass123!"},
    )
    assert response.status_code == 200

    # Verify sessions are deleted
    assert (
        db_session.query(RefreshTokenSession)
        .filter(RefreshTokenSession.user_id == target_user.id)
        .count()
        == 0
    )


def test_reset_password_weak_password_validation(
    client: TestClient, db_session: Session
):
    """Test that resetting a password with weak credentials triggers a validation error (422)."""
    org = Organization(
        name="Weak Pass Org",
        slug="weak-org",
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    db_session.add(org)

    superadmin_role = db_session.query(Role).filter_by(name="superadmin").first()

    _grant_permission(db_session, superadmin_role, "users", "update")

    superadmin = User(
        id="usr_sa_admin_9999",
        username="sa-admin-weak",
        email="sa-admin-weak@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=superadmin_role.id,
        is_active=True,
        is_verified=True,
    )
    target_user = User(
        id="usr_target_weak_9999",
        username="target-weak",
        email="target-weak@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=superadmin_role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add_all([superadmin, target_user])
    db_session.commit()

    # 1. Too short
    response = client.post(
        f"/admin/users/{target_user.id}/reset-password/",
        headers=_auth_headers(superadmin),
        json={"password": "Short1!"},
    )
    assert response.status_code == 422

    # 2. No uppercase
    response = client.post(
        f"/admin/users/{target_user.id}/reset-password/",
        headers=_auth_headers(superadmin),
        json={"password": "lowercaseonly123!"},
    )
    assert response.status_code == 422

    # 3. No digit
    response = client.post(
        f"/admin/users/{target_user.id}/reset-password/",
        headers=_auth_headers(superadmin),
        json={"password": "NoDigitsAllowed!"},
    )
    assert response.status_code == 422

    # 4. No special character
    response = client.post(
        f"/admin/users/{target_user.id}/reset-password/",
        headers=_auth_headers(superadmin),
        json={"password": "NoSpecialCharacter123"},
    )
    assert response.status_code == 422
