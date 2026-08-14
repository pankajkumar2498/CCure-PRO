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


def test_register_user(client: TestClient):
    """Test user registration endpoint."""
    response = client.post(
        "/auth/register",
        json={
            "full_name": "New User",
            "username": "newuser",
            "email": "newuser@test.com",
            "password": "StrongP@ssw0rd!",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["user"]["email"] == "newuser@test.com"
    assert data["user"]["username"] == "newuser"
    assert data["user"]["full_name"] == "New User"


def test_register_normalizes_email_to_lowercase(client: TestClient):
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

    assert response.status_code == 201
    assert response.json()["user"]["email"] == "mixedcase@example.com"


def test_register_weak_passwords_return_422(client: TestClient):
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


def test_register_username_case_insensitive_collision(client: TestClient):
    """Registration prevents registering duplicate usernames with different casing (e.g., abhilash vs Abhilash)."""
    # First registration
    res1 = client.post(
        "/auth/register",
        json={
            "full_name": "Abhilash User",
            "username": "abhilash",
            "email": "abhilash1@test.com",
            "password": "StrongP@ssw0rd!",
        },
    )
    assert res1.status_code == 201

    # Check username endpoint should indicate Abhilash is not available
    res_check = client.get("/auth/check-username?q=Abhilash")
    assert res_check.status_code == 200
    assert res_check.json()["available"] is False

    # Attempt second registration with different casing (Abhilash)
    res2 = client.post(
        "/auth/register",
        json={
            "full_name": "Abhilash User",
            "username": "Abhilash",
            "email": "abhilash2@test.com",
            "password": "StrongP@ssw0rd!",
        },
    )
    assert res2.status_code == 409
    assert "Username already taken" in res2.json()["detail"]


def test_get_current_user(client: TestClient, auth_headers: dict):
    """Test accessing protected route with valid token."""
    response = client.get("/auth/me", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["email"] == "admin@test.com"


def test_rbac_denies_unauthorized_role(
    client: TestClient, db_session: Session, test_org, test_role_viewer
):
    """Test that a viewer role cannot access an admin-only scan endpoint."""
    # Create a viewer user
    viewer = User(
        username="viewer",
        email="viewer@test.com",
        password_hash=hash_password("password123"),
        org_id=test_org.id,
        role_id=test_role_viewer.id,
        is_active=True,
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


def test_register_with_full_name(client: TestClient):
    """Test registration saves and returns full_name."""
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
    assert res.status_code == 201
    data = res.json()
    assert data["user"]["full_name"] == "John Doe"


def test_register_must_agree_to_terms(client: TestClient):
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


def test_identity_collision_prevention(client: TestClient, test_user: User):
    """Test that a username matching an existing email cannot be registered."""
    res = client.post(
        "/auth/register",
        json={
            "username": "admin@test.com",
            "email": "anotheradmin@test.com",
            "password": "StrongP@ssw0rd!",
        },
    )
    # Should fail due to @ in username or matching existing email
    assert res.status_code in (409, 422)


def test_forgot_password_with_username(client: TestClient, test_user: User):
    """Test requesting password reset using username."""
    res = client.post(
        "/auth/forgot-password",
        json={"email_or_username": test_user.username},
    )
    assert res.status_code == 200
    assert "detail" in res.json()
