"""
tests/test_auth_self_reset.py
─────────────────────────────────────────────────────────────────────────────
Integration tests for self-service password reset.
"""

import hashlib
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from auth.jwt_handler import verify_password
from db.models import Organization, Role, User, PasswordResetToken, RefreshTokenSession


def test_forgot_password_unregistered_email_success(client: TestClient, db_session: Session):
    """Test that requesting reset for an unregistered email returns 200 (prevents enumeration)."""
    with patch("core.tasks.send_password_reset_email_task.delay") as mock_delay:
        response = client.post("/auth/forgot-password", json={"email": "nonexistent@test.com"})
        assert response.status_code == 200
        assert "If this email is registered" in response.json()["detail"]
        mock_delay.assert_not_called()


def test_forgot_password_registered_email_success(client: TestClient, db_session: Session):
    """Test that requesting reset for a registered email generates a token and runs Celery task."""
    org = Organization(name="Test Org", slug="test-org", max_assets=100, max_users=10, is_active=True)
    db_session.add(org)
    db_session.flush()

    role = Role(name="analyst", description="Analyst", is_system_role=True)
    db_session.add(role)
    db_session.flush()

    user = User(
        id="usr_test_user_123",
        username="testuser",
        email="testuser@test.com",
        password_hash="oldhash",
        org_id=org.id,
        role_id=role.id,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    with patch("core.tasks.send_password_reset_email_task.delay") as mock_delay:
        response = client.post("/auth/forgot-password", json={"email": "testuser@test.com"})
        assert response.status_code == 200
        assert "If this email is registered" in response.json()["detail"]

        # Verify token created in database
        tokens = db_session.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id).all()
        assert len(tokens) == 1
        assert tokens[0].expires_at > datetime.now(timezone.utc)

        # Verify Celery task dispatched with correct link
        mock_delay.assert_called_once()
        args, _ = mock_delay.call_args
        assert args[0] == "testuser@test.com"
        assert args[1] == "testuser"
        assert "reset-password?token=" in args[2]


def test_reset_password_weak_passwords(client: TestClient, db_session: Session):
    """Test that reset endpoint validates password complexity rules."""
    response = client.post("/auth/reset-password", json={"token": "sometoken", "password": "weak"})
    assert response.status_code == 422


def test_reset_password_success_and_revokes_sessions(client: TestClient, db_session: Session):
    """Test successful password reset updates hash, invalidates sessions, and purges token."""
    org = Organization(name="Test Org", slug="test-org", max_assets=100, max_users=10, is_active=True)
    db_session.add(org)
    db_session.flush()

    role = Role(name="analyst", description="Analyst", is_system_role=True)
    db_session.add(role)
    db_session.flush()

    user = User(
        id="usr_test_user_456",
        username="resetuser",
        email="resetuser@test.com",
        password_hash="oldhash",
        org_id=org.id,
        role_id=role.id,
        is_active=True,
    )
    db_session.add(user)
    db_session.flush()

    # Create active sessions
    session = RefreshTokenSession(
        user_id=user.id,
        org_id=org.id,
        token_jti="jti_123",
        token_hash="hash_123",
        expires_at=datetime.now(timezone.utc) + timedelta(days=1)
    )
    db_session.add(session)

    # Create reset token
    raw_token = "secure_token_123"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    reset_token = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15)
    )
    db_session.add(reset_token)
    db_session.commit()

    # Call reset password
    response = client.post(
        "/auth/reset-password",
        json={"token": raw_token, "password": "NewCompliantPassword123!"}
    )
    assert response.status_code == 200
    assert "reset successfully" in response.json()["detail"]

    # Verify password updated
    db_session.refresh(user)
    assert verify_password("NewCompliantPassword123!", user.password_hash)

    # Verify active refresh sessions are deleted
    assert db_session.query(RefreshTokenSession).filter(RefreshTokenSession.user_id == user.id).count() == 0

    # Verify token is deleted (single-use constraint)
    assert db_session.query(PasswordResetToken).filter(PasswordResetToken.token_hash == token_hash).count() == 0


def test_reset_password_token_invalidation_on_first_use(client: TestClient, db_session: Session):
    """Test that a token cannot be reused (token invalidation on first use)."""
    org = Organization(name="Test Org", slug="test-org", max_assets=100, max_users=10, is_active=True)
    db_session.add(org)
    db_session.flush()

    role = Role(name="analyst", description="Analyst", is_system_role=True)
    db_session.add(role)
    db_session.flush()

    user = User(
        id="usr_test_user_789",
        username="reuseuser",
        email="reuseuser@test.com",
        password_hash="oldhash",
        org_id=org.id,
        role_id=role.id,
        is_active=True,
    )
    db_session.add(user)
    db_session.flush()

    # Create reset token
    raw_token = "secure_token_456"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    reset_token = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15)
    )
    db_session.add(reset_token)
    db_session.commit()

    # First reset should succeed
    response1 = client.post(
        "/auth/reset-password",
        json={"token": raw_token, "password": "NewCompliantPassword123!"}
    )
    assert response1.status_code == 200

    # Second reset with the same token should fail
    response2 = client.post(
        "/auth/reset-password",
        json={"token": raw_token, "password": "AnotherCompliantPassword123!"}
    )
    assert response2.status_code == 400
    assert "Invalid or expired reset token." in response2.json()["detail"]
