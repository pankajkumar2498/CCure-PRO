"""
tests/test_auth.py
─────────────────────────────────────────────────────────────────────────────
Integration tests for authentication flows (login, refresh, logout) and RBAC.
"""

from fastapi.testclient import TestClient
from db.models.users import User
from db.models.rbac import Role
from sqlalchemy.orm import Session
from auth.jwt_handler import hash_password

def test_login_success(client: TestClient, test_user: User):
    """Test successful login returns access and refresh tokens."""
    response = client.post(
        "/auth/login",
        json={"email": "admin@test.com", "password": "securepassword123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == "admin@test.com"


def test_login_invalid_credentials(client: TestClient, test_user: User):
    """Test login with wrong password fails."""
    response = client.post(
        "/auth/login",
        json={"email": "admin@test.com", "password": "wrongpassword"}
    )
    assert response.status_code == 401
    assert "Invalid email or password" in response.json()["detail"]


def test_register_user(client: TestClient):
    """Test user registration endpoint."""
    response = client.post(
        "/auth/register",
        json={
            "username": "newuser",
            "email": "newuser@test.com",
            "password": "StrongP@ssw0rd!"
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["user"]["email"] == "newuser@test.com"
    assert data["user"]["username"] == "newuser"


def test_get_current_user(client: TestClient, auth_headers: dict):
    """Test accessing protected route with valid token."""
    response = client.get("/auth/me", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["email"] == "admin@test.com"


def test_rbac_denies_unauthorized_role(
    client: TestClient, 
    db_session: Session, 
    test_org, 
    test_role_viewer
):
    """Test that a viewer role cannot access an admin-only scan endpoint."""
    # Create a viewer user
    viewer = User(
        username="viewer",
        email="viewer@test.com",
        password_hash=hash_password("password123"),
        org_id=test_org.id,
        role_id=test_role_viewer.id,
        is_active=True
    )
    db_session.add(viewer)
    db_session.commit()

    # Login as viewer
    res = client.post("/auth/login", json={"email": "viewer@test.com", "password": "password123"})
    token = res.json()["access_token"]
    
    # Attempt to hit an endpoint requiring "admin" or "analyst" (e.g., traditional scan)
    scan_res = client.post(
        "/scan/host",
        headers={"Authorization": f"Bearer {token}"},
        json={"target": "127.0.0.1", "scan_type": "ping"}
    )
    
    # Should be forbidden by RBAC
    assert scan_res.status_code == 403
    assert "Insufficient privileges" in scan_res.json()["detail"]
