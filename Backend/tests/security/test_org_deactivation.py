"""
tests/test_org_deactivation.py
─────────────────────────────────────────────────────────────────────────────────
Production-grade integration tests for organization deactivation flow.

Tests verify that:
  1. Users cannot log in when their organization is deactivated
  2. Existing sessions/tokens become invalid when org is deactivated
  3. Token refresh fails for deactivated organizations
  4. User statuses remain unchanged (only org status matters)
  5. Reactivating the org restores full access
  6. Proper error responses with clear messaging
"""

from native_rbac import system_role, create_user, fixture_role


import pytest
from db.models import Organization
from fastapi.testclient import TestClient


@pytest.fixture
def setup_org_and_users(db_session):
    """
    Create:
      - One active org with 2 users
      - Test role
    """
    # Ensure test role exists
    test_role = system_role(db_session, "platform.analyst")
    if not test_role:
        test_role = fixture_role(db_session, "analyst")
        db_session.add(test_role)
        db_session.flush()

    # Create test organization
    org = Organization(
        name="Test Organization",
        slug="test-org",
        plan="community",
        max_assets=100,
        max_users=10,
        is_active=True,
        settings={},
    )
    db_session.add(org)
    db_session.flush()

    # Create test users. Approved as well as verified: these stand in for
    # admin-provisioned accounts, and login refuses approved_at IS NULL.
    from auth.jwt_handler import hash_password
    from db.base import utcnow

    user1 = create_user(
        db_session,
        username="testuser1",
        email="user1@testorg.com",
        password_hash=hash_password("TestPassword123!"),
        org_id=org.id,
        role=test_role,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
    )
    user2 = create_user(
        db_session,
        username="testuser2",
        email="user2@testorg.com",
        password_hash=hash_password("TestPassword456!"),
        org_id=org.id,
        role=test_role,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
    )
    db_session.add(user1)
    db_session.add(user2)
    db_session.commit()

    return {
        "org": org,
        "user1": user1,
        "user2": user2,
        "role": test_role,
        "password1": "TestPassword123!",
        "password2": "TestPassword456!",
    }


class TestOrgDeactivationLoginFlow:
    """Test login behavior with org deactivation."""

    def test_login_succeeds_with_active_org(
        self, client: TestClient, setup_org_and_users
    ):
        """User can log in when org is active."""
        user = setup_org_and_users["user1"]
        password = setup_org_and_users["password1"]

        response = client.post(
            "/auth/login",
            json={"email": user.email, "password": password},
        )

        assert response.status_code == 200
        assert "access_token" in response.json()
        assert "refresh_token" in response.json()

    def test_login_fails_with_deactivated_org(
        self, client: TestClient, db_session, setup_org_and_users
    ):
        """User cannot log in when org is deactivated."""
        org = setup_org_and_users["org"]
        user = setup_org_and_users["user1"]
        password = setup_org_and_users["password1"]

        # Deactivate org
        org.is_active = False
        db_session.commit()

        response = client.post(
            "/auth/login",
            json={"email": user.email, "password": password},
        )

        assert response.status_code == 403
        assert "organization has been deactivated" in response.json()["detail"].lower()

    def test_login_fails_even_with_active_user_but_deactivated_org(
        self, client: TestClient, db_session, setup_org_and_users
    ):
        """User status is irrelevant if org is deactivated."""
        org = setup_org_and_users["org"]
        user = setup_org_and_users["user1"]
        password = setup_org_and_users["password1"]

        # Deactivate org but leave user active
        org.is_active = False
        user.is_active = True  # Explicitly active
        db_session.commit()

        response = client.post(
            "/auth/login",
            json={"email": user.email, "password": password},
        )

        assert response.status_code == 403
        assert "organization" in response.json()["detail"].lower()

    def test_login_succeeds_after_org_reactivation(
        self, client: TestClient, db_session, setup_org_and_users
    ):
        """User can log in again after org is reactivated."""
        org = setup_org_and_users["org"]
        user = setup_org_and_users["user1"]
        password = setup_org_and_users["password1"]

        # Deactivate then reactivate org
        org.is_active = False
        db_session.commit()

        # Verify login fails
        response1 = client.post(
            "/auth/login",
            json={"email": user.email, "password": password},
        )
        assert response1.status_code == 403

        # Reactivate org
        org.is_active = True
        db_session.commit()

        # Verify login succeeds
        response2 = client.post(
            "/auth/login",
            json={"email": user.email, "password": password},
        )
        assert response2.status_code == 200
        assert "access_token" in response2.json()


class TestOrgDeactivationTokenRefresh:
    """Test token refresh behavior with org deactivation."""

    def test_refresh_token_fails_with_deactivated_org(
        self, client: TestClient, db_session, setup_org_and_users
    ):
        """Token refresh fails when org is deactivated."""
        org = setup_org_and_users["org"]
        user = setup_org_and_users["user1"]
        password = setup_org_and_users["password1"]

        # Get initial tokens
        login_response = client.post(
            "/auth/login",
            json={"email": user.email, "password": password},
        )
        assert login_response.status_code == 200
        refresh_token = login_response.json()["refresh_token"]

        # Deactivate org
        org.is_active = False
        db_session.commit()

        # Try to refresh token
        refresh_response = client.post(
            "/auth/refresh",
            json={"refresh_token": refresh_token},
        )

        assert refresh_response.status_code == 401
        assert "Invalid or expired refresh token" in refresh_response.json()["detail"]

    def test_refresh_token_succeeds_after_org_reactivation(
        self, client: TestClient, db_session, setup_org_and_users
    ):
        """Token refresh works again after org is reactivated."""
        org = setup_org_and_users["org"]
        user = setup_org_and_users["user1"]
        password = setup_org_and_users["password1"]

        # Get initial tokens
        login_response = client.post(
            "/auth/login",
            json={"email": user.email, "password": password},
        )
        refresh_token = login_response.json()["refresh_token"]

        # Deactivate org
        org.is_active = False
        db_session.commit()

        # Refresh fails
        refresh1 = client.post(
            "/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert refresh1.status_code == 401

        # Reactivate org
        org.is_active = True
        db_session.commit()

        # Refresh succeeds
        refresh2 = client.post(
            "/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert refresh2.status_code == 200
        assert "access_token" in refresh2.json()


class TestOrgDeactivationMiddleware:
    """Test that existing sessions are blocked when org is deactivated."""

    def test_existing_session_blocked_when_org_deactivated(
        self, client: TestClient, db_session, setup_org_and_users
    ):
        """User with valid token loses access when org is deactivated."""
        org = setup_org_and_users["org"]
        user = setup_org_and_users["user1"]
        password = setup_org_and_users["password1"]

        # Get tokens
        login_response = client.post(
            "/auth/login",
            json={"email": user.email, "password": password},
        )
        access_token = login_response.json()["access_token"]

        # Verify /me works with active org
        me_response1 = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert me_response1.status_code == 200

        # Deactivate org
        org.is_active = False
        db_session.commit()

        # Verify /me fails with same token
        me_response2 = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert me_response2.status_code == 403
        assert "organization" in me_response2.json()["detail"].lower()

    def test_session_restored_when_org_reactivated(
        self, client: TestClient, db_session, setup_org_and_users
    ):
        """User regains access when org is reactivated."""
        org = setup_org_and_users["org"]
        user = setup_org_and_users["user1"]
        password = setup_org_and_users["password1"]

        # Get tokens
        login_response = client.post(
            "/auth/login",
            json={"email": user.email, "password": password},
        )
        access_token = login_response.json()["access_token"]

        # Deactivate then reactivate org
        org.is_active = False
        db_session.commit()

        me_response1 = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert me_response1.status_code == 403

        org.is_active = True
        db_session.commit()

        me_response2 = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert me_response2.status_code == 200


class TestOrgDeactivationUserStatusIndependence:
    """Test that user statuses remain unchanged during org deactivation."""

    def test_user_status_not_modified_by_org_deactivation(
        self, client: TestClient, db_session, setup_org_and_users
    ):
        """Org deactivation does not modify user.is_active status."""
        org = setup_org_and_users["org"]
        user = setup_org_and_users["user1"]

        # Record initial state
        initial_is_active = user.is_active
        initial_is_deleted = getattr(user, "is_deleted", False)

        # Deactivate org
        org.is_active = False
        db_session.commit()
        db_session.refresh(user)

        # Verify user state unchanged
        assert user.is_active == initial_is_active
        assert getattr(user, "is_deleted", False) == initial_is_deleted

    def test_reactivated_org_without_user_modification(
        self, client: TestClient, db_session, setup_org_and_users
    ):
        """Org reactivation works without modifying user statuses."""
        org = setup_org_and_users["org"]
        user = setup_org_and_users["user1"]
        password = setup_org_and_users["password1"]

        # Deactivate, then reactivate org
        org.is_active = False
        db_session.commit()

        org.is_active = True
        db_session.commit()

        # Verify user can log in without any user state changes needed
        response = client.post(
            "/auth/login",
            json={"email": user.email, "password": password},
        )
        assert response.status_code == 200


class TestOrgDeactivationMultipleUsers:
    """Test deactivation affects all users in org."""

    def test_all_users_blocked_when_org_deactivated(
        self, client: TestClient, db_session, setup_org_and_users
    ):
        """All users in deactivated org lose access."""
        org = setup_org_and_users["org"]
        user1 = setup_org_and_users["user1"]
        user2 = setup_org_and_users["user2"]
        password1 = setup_org_and_users["password1"]
        password2 = setup_org_and_users["password2"]

        # Get tokens for both users
        login1 = client.post(
            "/auth/login",
            json={"email": user1.email, "password": password1},
        )
        login2 = client.post(
            "/auth/login",
            json={"email": user2.email, "password": password2},
        )
        token1 = login1.json()["access_token"]
        token2 = login2.json()["access_token"]

        # Both should work initially
        assert (
            client.get(
                "/auth/me",
                headers={"Authorization": f"Bearer {token1}"},
            ).status_code
            == 200
        )
        assert (
            client.get(
                "/auth/me",
                headers={"Authorization": f"Bearer {token2}"},
            ).status_code
            == 200
        )

        # Deactivate org
        org.is_active = False
        db_session.commit()

        # Both users blocked
        assert (
            client.get(
                "/auth/me",
                headers={"Authorization": f"Bearer {token1}"},
            ).status_code
            == 403
        )
        assert (
            client.get(
                "/auth/me",
                headers={"Authorization": f"Bearer {token2}"},
            ).status_code
            == 403
        )

    def test_all_users_restored_when_org_reactivated(
        self, client: TestClient, db_session, setup_org_and_users
    ):
        """All users in org regain access when org is reactivated."""
        org = setup_org_and_users["org"]
        user1 = setup_org_and_users["user1"]
        user2 = setup_org_and_users["user2"]
        password1 = setup_org_and_users["password1"]
        password2 = setup_org_and_users["password2"]

        # Get tokens for both users
        login1 = client.post(
            "/auth/login",
            json={"email": user1.email, "password": password1},
        )
        login2 = client.post(
            "/auth/login",
            json={"email": user2.email, "password": password2},
        )
        token1 = login1.json()["access_token"]
        token2 = login2.json()["access_token"]

        # Deactivate org
        org.is_active = False
        db_session.commit()

        # Both blocked
        assert (
            client.get(
                "/auth/me",
                headers={"Authorization": f"Bearer {token1}"},
            ).status_code
            == 403
        )
        assert (
            client.get(
                "/auth/me",
                headers={"Authorization": f"Bearer {token2}"},
            ).status_code
            == 403
        )

        # Reactivate org
        org.is_active = True
        db_session.commit()

        # Both restored
        assert (
            client.get(
                "/auth/me",
                headers={"Authorization": f"Bearer {token1}"},
            ).status_code
            == 200
        )
        assert (
            client.get(
                "/auth/me",
                headers={"Authorization": f"Bearer {token2}"},
            ).status_code
            == 200
        )
