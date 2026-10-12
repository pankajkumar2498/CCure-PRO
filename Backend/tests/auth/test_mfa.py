"""
tests/test_mfa.py
─────────────────────────────────────────────────────────────────────────────
Unit tests for the Dual-Channel MFA system (TOTP setup, verification, email
OTP fallback, backup codes, and session revocation).
"""

from native_rbac import system_role, create_user

import pyotp
from auth.jwt_handler import hash_password
from auth.router import decrypt_secret
from db.models.users import RefreshTokenSession, User
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


def test_mfa_flow_e2e(client: TestClient, db_session: Session, test_user: User):
    """
    Complete E2E test verifying the MFA setup, activation,
    two-step login, email OTP fallback, and backup codes.
    """
    # ── 1. Setup access headers for test_user ────────────────────────────────
    login_res = client.post(
        "/auth/login", json={"email": test_user.email, "password": "securepassword123"}
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Ensure MFA is disabled by default
    assert not test_user.mfa_enabled
    assert test_user.totp_secret is None

    # ── 2. Enable MFA (Retrieve QR and Secret) ──────────────────────────────
    enable_res = client.post("/auth/mfa/enable", headers=headers)
    assert enable_res.status_code == 200
    enable_data = enable_res.json()
    assert "secret" in enable_data
    assert "qr_code" in enable_data
    assert enable_data["qr_code"].startswith("data:image/png;base64,")

    totp_secret = enable_data["secret"]

    # Verify secret was encrypted in DB
    db_session.refresh(test_user)
    assert test_user.totp_secret is not None
    assert decrypt_secret(test_user.totp_secret) == totp_secret

    # ── 3. Confirm MFA with invalid code ─────────────────────────────────────
    confirm_res = client.post(
        "/auth/mfa/confirm", headers=headers, json={"code": "000000"}
    )
    assert confirm_res.status_code == 400
    assert "Invalid verification code" in confirm_res.json()["detail"]

    # ── 4. Confirm MFA with valid code ───────────────────────────────────────
    totp = pyotp.TOTP(totp_secret)
    valid_code = totp.now()

    # Pre-add another session to test session revocation
    dummy_session = RefreshTokenSession(
        user_id=test_user.id,
        org_id=test_user.org_id,
        token_jti="dummy_jti",
        token_hash="dummy_hash",
        expires_at=test_user.created_at,  # just a dummy time
    )
    db_session.add(dummy_session)
    db_session.commit()

    confirm_res = client.post(
        "/auth/mfa/confirm", headers=headers, json={"code": valid_code}
    )
    assert confirm_res.status_code == 200
    confirm_data = confirm_res.json()
    assert "backup_codes" in confirm_data
    assert len(confirm_data["backup_codes"]) == 8

    # Refresh user & assert state
    db_session.refresh(test_user)
    assert test_user.mfa_enabled
    assert len(test_user.mfa_backup_codes) == 8

    # Assert session isolation (dummy session revoked/deleted)
    sessions = (
        db_session.query(RefreshTokenSession)
        .filter(RefreshTokenSession.user_id == test_user.id)
        .all()
    )
    assert len(sessions) == 0

    # ── 5. Login Credentials Verification (MFA Required) ────────────────────
    login_res = client.post(
        "/auth/login", json={"email": test_user.email, "password": "securepassword123"}
    )
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert login_data["status"] == "mfa_required"
    assert "mfa_token" in login_data

    mfa_token = login_data["mfa_token"]

    # ── 6. Verify MFA using TOTP Code ────────────────────────────────────────
    verify_code = totp.now()
    verify_res = client.post(
        "/auth/login/verify-mfa", json={"mfa_token": mfa_token, "code": verify_code}
    )
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert "access_token" in verify_data
    assert "refresh_token" in verify_data
    assert verify_data["user"]["mfa_enabled"] is True

    # ── 7. Email Fallback OTP flow ──────────────────────────────────────────
    # Trigger login again to get a new challenge token
    login_res = client.post(
        "/auth/login", json={"email": test_user.email, "password": "securepassword123"}
    )
    mfa_token = login_res.json()["mfa_token"]

    # Trigger email OTP
    email_res = client.post("/auth/login/send-email-otp", json={"mfa_token": mfa_token})
    assert email_res.status_code == 200
    assert email_res.json()["success"] is True

    # Retrieve OTP hash from DB directly (since Celery is mocked/async)
    db_session.refresh(test_user)
    assert test_user.email_otp_hash is not None
    assert test_user.email_otp_expires_at is not None

    # Verify code extraction from DB and attempt verifying via MFA endpoint
    # Note: We need a clean way to match the hash because bcrypt/argon2 hashing is one-way.
    # In order to verify, we can temporarily swap the hash with a known hash of a code.
    known_code = "123456"
    test_user.email_otp_hash = hash_password(known_code)
    db_session.commit()

    # Verify using email OTP code
    verify_res = client.post(
        "/auth/login/verify-mfa", json={"mfa_token": mfa_token, "code": known_code}
    )
    assert verify_res.status_code == 200
    assert "access_token" in verify_res.json()

    # Ensure temporary OTP fields were immediately cleared to prevent replays
    db_session.refresh(test_user)
    assert test_user.email_otp_hash is None
    assert test_user.email_otp_expires_at is None

    # ── 8. Login using Backup Recovery Code ──────────────────────────────────
    # Trigger login again
    login_res = client.post(
        "/auth/login", json={"email": test_user.email, "password": "securepassword123"}
    )
    mfa_token = login_res.json()["mfa_token"]

    # Use first backup recovery code from confirmation step
    backup_code = confirm_data["backup_codes"][0]
    verify_res = client.post(
        "/auth/login/verify-mfa", json={"mfa_token": mfa_token, "code": backup_code}
    )
    assert verify_res.status_code == 200
    assert "access_token" in verify_res.json()

    # Check recovery code was deleted (single-use constraint)
    db_session.refresh(test_user)
    assert len(test_user.mfa_backup_codes) == 7

    # ── 9. Disable MFA ───────────────────────────────────────────────────────
    # Establish new authenticated headers
    new_token = verify_res.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {new_token}"}

    # Disable using correct password
    disable_res = client.post(
        "/auth/mfa/disable",
        headers=auth_headers,
        json={"password": "securepassword123"},
    )
    assert disable_res.status_code == 200
    assert disable_res.json()["success"] is True

    # Assert DB columns are wiped
    db_session.refresh(test_user)
    assert not test_user.mfa_enabled
    assert test_user.totp_secret is None
    assert len(test_user.mfa_backup_codes) == 0


def test_admin_reset_mfa_success(client: TestClient, db_session: Session):
    """Test that a superadmin can successfully reset another user's MFA."""
    from datetime import datetime, timedelta, timezone

    from auth.jwt_handler import create_access_token
    from db.models import Organization, RefreshTokenSession

    org = Organization(
        name="MFA Reset Org",
        slug="mfa-reset-org",
        is_active=True,
    )
    db_session.add(org)

    superadmin_role = system_role(db_session, "platform.superadmin")
    analyst_role = system_role(db_session, "platform.analyst")

    superadmin = create_user(
        db_session,
        id="usr_sa_mfa_admin",
        username="sa-mfa-admin",
        email="sa-mfa-admin@test.com",
        password_hash="hash",
        org_id=org.id,
        role=superadmin_role,
        is_active=True,
        is_verified=True,
    )
    target_user = create_user(
        db_session,
        id="usr_sa_mfa_target",
        username="sa-mfa-target",
        email="sa-mfa-target@test.com",
        password_hash="hash",
        org_id=org.id,
        role=analyst_role,
        is_active=True,
        is_verified=True,
        mfa_enabled=True,
        totp_secret="encryptedsecretkey",
        mfa_backup_codes=["code1", "code2"],
    )
    db_session.add_all([superadmin, target_user])
    db_session.flush()

    # Create active session for target user
    session = RefreshTokenSession(
        user_id=target_user.id,
        org_id=org.id,
        token_jti="jti_mfa_1",
        token_hash="hash_mfa_1",
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
    )
    db_session.add(session)
    db_session.commit()

    # Verify pre-conditions
    assert (
        db_session.query(RefreshTokenSession)
        .filter(RefreshTokenSession.user_id == target_user.id)
        .count()
        == 1
    )

    token = create_access_token(
        superadmin.id,
        superadmin.username,
        org_id=superadmin.org_id,
    )
    headers = {"Authorization": f"Bearer {token}"}

    # Act
    res = client.post(f"/admin/users/{target_user.id}/reset-mfa/", headers=headers)

    # Assert
    assert res.status_code == 200
    db_session.refresh(target_user)
    assert not target_user.mfa_enabled
    assert target_user.totp_secret is None
    assert (
        target_user.mfa_backup_codes is None or len(target_user.mfa_backup_codes) == 0
    )

    # Check sessions are revoked
    assert (
        db_session.query(RefreshTokenSession)
        .filter(RefreshTokenSession.user_id == target_user.id)
        .count()
        == 0
    )
