"""
tests/test_auth.py
─────────────────────────────────────────────────────────────────────────────
Integration tests for authentication flows (login, refresh, logout) and RBAC.
"""

from auth.jwt_handler import hash_password
from db.models.users import User
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


def test_login_success(client: TestClient, test_user: User):
    """Test successful login returns access and refresh tokens."""
    response = client.post(
        "/auth/login", json={"email": "admin@test.com", "password": "securepassword123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == "admin@test.com"


def test_login_email_is_case_insensitive(
    client: TestClient, db_session: Session, test_user: User
):
    """Login should match stored email regardless of submitted casing."""
    test_user.email = "Admin@Test.COM"
    db_session.commit()

    response = client.post(
        "/auth/login", json={"email": "ADMIN@test.com", "password": "securepassword123"}
    )

    assert response.status_code == 200
    assert response.json()["user"]["email"] == "Admin@Test.COM"


def test_login_invalid_credentials(client: TestClient, test_user: User):
    """Test login with wrong password fails."""
    response = client.post(
        "/auth/login", json={"email": "admin@test.com", "password": "wrongpassword"}
    )
    assert response.status_code == 401
    assert "Invalid email or password" in response.json()["detail"]


def test_register_is_disabled_by_default(client: TestClient):
    """
    Self-service registration ships off. The route must not merely refuse —
    it must not acknowledge that it exists, so a scan of a deployment cannot
    tell "disabled here" from "not a feature".
    """
    response = client.post(
        "/auth/register",
        json={
            "full_name": "New User",
            "username": "newuser",
            "email": "newuser@test.com",
            "password": "StrongP@ssw0rd!",
        },
    )
    assert response.status_code == 404


def test_register_creates_pending_account_without_tokens(
    client: TestClient, db_session: Session, self_registration_enabled
):
    """
    Registration must not hand back a session.

    This is the regression guard for the original defect: the endpoint used to
    return access + refresh tokens for an `analyst` account, which carries
    scans:execute.
    """
    response = client.post(
        "/auth/register",
        json={
            "full_name": "New User",
            "username": "newuser",
            "email": "newuser@test.com",
            "password": "StrongP@ssw0rd!",
        },
    )
    assert response.status_code == 202
    body = response.json()
    assert "access_token" not in body
    assert "refresh_token" not in body
    assert body["status"] == "pending_verification"
    assert "ccure_refresh_token" not in response.cookies

    user = db_session.query(User).filter(User.email == "newuser@test.com").first()
    assert user is not None
    assert user.is_verified is False
    assert user.is_active is False
    assert user.approved_at is None
    # Read-only role, not analyst: approval must not be a rubber stamp on
    # scan execution that was granted at signup.
    assert user.role.name == "viewer"


def test_register_pending_account_cannot_log_in(
    client: TestClient, self_registration_enabled
):
    """A registered-but-unverified account is refused even with the right password."""
    client.post(
        "/auth/register",
        json={
            "full_name": "Pending User",
            "username": "pendinguser",
            "email": "pending@test.com",
            "password": "StrongP@ssw0rd!",
        },
    )
    res = client.post(
        "/auth/login",
        json={"email": "pending@test.com", "password": "StrongP@ssw0rd!"},
    )
    assert res.status_code == 403
    assert "Verify your email" in res.json()["detail"]


def test_register_normalizes_email_to_lowercase(
    client: TestClient, db_session: Session, self_registration_enabled
):
    """Registration stores normalized lowercase emails."""
    response = client.post(
        "/auth/register",
        json={
            "full_name": "Mixed Case",
            "username": "mixedcaseuser",
            "email": "MixedCase@Example.COM",
            "password": "StrongP@ssw0rd!",
        },
    )

    assert response.status_code == 202
    # The response no longer echoes the account, so assert against the row.
    user = db_session.query(User).filter(User.username == "mixedcaseuser").first()
    assert user is not None
    assert user.email == "mixedcase@example.com"


def test_register_weak_passwords_return_422(
    client: TestClient, self_registration_enabled
):
    """Registration fails with HTTP 422 when password complexity is not met."""
    weak_passwords = [
        "short1!",  # Too short (< 12 chars)
        "nopassworduppercase123!",  # Missing uppercase letter
        "NOUPPERCASESPECIAL!",  # Missing digit
        "NoSpecialChar123",  # Missing special character
    ]

    for pw in weak_passwords:
        res = client.post(
            "/auth/register",
            json={
                "full_name": "Test User",
                "username": "testuser422",
                "email": "testuser422@example.com",
                "password": pw,
            },
        )
        assert res.status_code == 422, f"Expected 422 for password: {pw}"


def test_register_does_not_disclose_collisions(
    client: TestClient, db_session: Session, self_registration_enabled
):
    """
    A taken username or email must be indistinguishable from a fresh signup.

    Previously these returned 409 with "Username already taken" / "Email
    already registered", which let anyone confirm whether a given address or
    username held an account. The collision is still enforced — no second row
    is created — it is just not reported to the caller.
    """
    first = client.post(
        "/auth/register",
        json={
            "full_name": "Abhilash User",
            "username": "abhilash",
            "email": "abhilash1@test.com",
            "password": "StrongP@ssw0rd!",
        },
    )
    assert first.status_code == 202

    # Same username, different case, different email.
    second = client.post(
        "/auth/register",
        json={
            "full_name": "Abhilash User",
            "username": "Abhilash",
            "email": "abhilash2@test.com",
            "password": "StrongP@ssw0rd!",
        },
    )
    assert second.status_code == 202
    assert second.json() == first.json()

    # ...and no account was actually created for the second attempt.
    assert (
        db_session.query(User).filter(User.email == "abhilash2@test.com").first()
        is None
    )


def test_check_email_is_not_an_existence_oracle(
    client: TestClient, test_user: User, self_registration_enabled
):
    """A registered address must not be reported as unavailable."""
    res = client.get("/auth/check-email?q=admin@test.com")
    assert res.status_code == 200
    assert res.json()["available"] is True


def test_check_username_is_gated_when_registration_disabled(client: TestClient):
    """With self-registration off, the availability oracles are unreachable."""
    assert client.get("/auth/check-username?q=someone").status_code == 404
    assert client.get("/auth/check-email?q=someone@test.com").status_code == 404


def test_get_current_user(client: TestClient, auth_headers: dict):
    """Test accessing protected route with valid token."""
    response = client.get("/auth/me", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["email"] == "admin@test.com"


def test_rbac_denies_unauthorized_role(
    client: TestClient, db_session: Session, test_org, test_role_viewer
):
    """Test that a viewer role cannot access an admin-only scan endpoint."""
    # Create a viewer user. Verified and approved: this test is about RBAC
    # refusing the scan endpoint, not about the account gates refusing login.
    from db.base import utcnow

    viewer = User(
        username="viewer",
        email="viewer@test.com",
        password_hash=hash_password("password123"),
        org_id=test_org.id,
        role_id=test_role_viewer.id,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
    )
    db_session.add(viewer)
    db_session.commit()

    # Login as viewer
    res = client.post(
        "/auth/login", json={"email": "viewer@test.com", "password": "password123"}
    )
    token = res.json()["access_token"]

    # Attempt to hit an endpoint requiring "admin" or "analyst" (e.g., traditional scan)
    scan_res = client.post(
        "/scan/host",
        headers={"Authorization": f"Bearer {token}"},
        json={"target": "127.0.0.1", "scan_type": "ping"},
    )

    # Should be forbidden by RBAC
    assert scan_res.status_code == 403
    assert "Insufficient privileges" in scan_res.json()["detail"]


def test_register_with_full_name(
    client: TestClient, db_session: Session, self_registration_enabled
):
    """Test registration saves full_name."""
    res = client.post(
        "/auth/register",
        json={
            "username": "fullnameuser",
            "email": "fullnameuser@test.com",
            "password": "StrongP@ssw0rd!",
            "full_name": "John Doe",
            "agree_to_terms": True,
        },
    )
    assert res.status_code == 202
    user = db_session.query(User).filter(User.username == "fullnameuser").first()
    assert user is not None
    assert user.full_name == "John Doe"


def test_register_must_agree_to_terms(client: TestClient, self_registration_enabled):
    """Test registration fails when agree_to_terms is False."""
    res = client.post(
        "/auth/register",
        json={
            "username": "termsuser",
            "email": "termsuser@test.com",
            "password": "StrongP@ssw0rd!",
            "agree_to_terms": False,
        },
    )
    assert res.status_code == 422


def test_login_with_username(client: TestClient, test_user: User):
    """Test logging in with username instead of email."""
    res = client.post(
        "/auth/login",
        json={"email_or_username": test_user.username, "password": "securepassword123"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user"]["username"] == test_user.username


def test_identity_collision_prevention(
    client: TestClient, db_session: Session, test_user: User, self_registration_enabled
):
    """A username containing '@' is rejected before it can shadow an email."""
    res = client.post(
        "/auth/register",
        json={
            "username": "admin@test.com",
            "email": "anotheradmin@test.com",
            "password": "StrongP@ssw0rd!",
            "full_name": "Collision Attempt",
        },
    )
    # 422 from the username validator — '@' is not allowed in a username, so
    # this never reaches the uniqueness check. It must not create a row.
    assert res.status_code == 422
    assert (
        db_session.query(User).filter(User.email == "anotheradmin@test.com").first()
        is None
    )


def test_forgot_password_with_username(client: TestClient, test_user: User):
    """Test requesting password reset using username."""
    res = client.post(
        "/auth/forgot-password",
        json={"email_or_username": test_user.username},
    )
    assert res.status_code == 200
    assert "detail" in res.json()
