"""
tests/test_email_verification.py
─────────────────────────────────────────────────────────────────────────────
The email-verification and administrator-approval gates on self-registration.

What these tests are guarding against is one specific defect: POST
/auth/register used to create an account in the `analyst` role — which carries
scans:execute — and return working access and refresh tokens in the same
response. Anyone able to reach the endpoint could issue themselves a credential
that drives Nmap, Scapy and Nuclei from a worker holding raw-socket privileges.

So the assertions to keep are the negative ones. A test that only checks the
happy path would still pass if the tokens came back.
"""

import hashlib
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from db.base import utcnow
from db.models import EmailVerificationToken, Organization, Role, User
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


@pytest.fixture
def registered(client: TestClient, db_session: Session, self_registration_enabled):
    """Register one account and hand back (user, plaintext_token)."""
    with patch("core.tasks.send_verification_email_task.delay") as delay:
        res = client.post(
            "/auth/register",
            json={
                "full_name": "Vera Fyer",
                "username": "verafyer",
                "email": "vera@test.com",
                "password": "StrongP@ssw0rd!",
            },
        )
    assert res.status_code == 202
    assert delay.called, "registration must dispatch a verification email"

    # The link is built as {FRONTEND_URL}/verify-email?token={token}
    link = delay.call_args[0][2]
    token = link.split("token=")[1]

    user = db_session.query(User).filter(User.email == "vera@test.com").first()
    return user, token


# ── Token handling ────────────────────────────────────────────────────────────


def test_only_the_token_hash_is_stored(registered, db_session: Session):
    """A database read must not yield a redeemable link."""
    user, token = registered
    row = (
        db_session.query(EmailVerificationToken)
        .filter(EmailVerificationToken.user_id == user.id)
        .first()
    )
    assert row is not None
    assert row.token_hash != token
    assert row.token_hash == hashlib.sha256(token.encode()).hexdigest()
    # The plaintext must not appear in any column.
    assert token not in (row.email or "")


def test_verification_marks_verified_but_grants_no_session(
    client: TestClient, db_session: Session, registered
):
    user, token = registered

    res = client.post("/auth/verify-email", json={"token": token})
    assert res.status_code == 200
    assert res.json()["status"] == "pending_approval"
    # Verification is not a login.
    assert "access_token" not in res.json()

    db_session.refresh(user)
    assert user.is_verified is True
    assert user.approved_at is None
    assert user.is_active is False


def test_token_is_single_use(client: TestClient, registered):
    _, token = registered
    assert client.post("/auth/verify-email", json={"token": token}).status_code == 200
    second = client.post("/auth/verify-email", json={"token": token})
    assert second.status_code == 400
    assert "invalid or has expired" in second.json()["detail"]


def test_expired_token_is_rejected(client: TestClient, db_session: Session, registered):
    user, token = registered
    row = (
        db_session.query(EmailVerificationToken)
        .filter(EmailVerificationToken.user_id == user.id)
        .first()
    )
    row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db_session.commit()

    res = client.post("/auth/verify-email", json={"token": token})
    assert res.status_code == 400
    db_session.refresh(user)
    assert user.is_verified is False


def test_unknown_token_is_rejected_identically(client: TestClient, registered):
    """
    A guessed token must produce the same response as an expired or used one,
    so the endpoint cannot be used to probe which tokens exist.
    """
    _, real = registered
    guessed = client.post("/auth/verify-email", json={"token": "not-a-real-token"})
    assert guessed.status_code == 400

    client.post("/auth/verify-email", json={"token": real})  # consume
    used = client.post("/auth/verify-email", json={"token": real})
    assert used.status_code == 400
    assert used.json()["detail"] == guessed.json()["detail"]


def test_resend_does_not_kill_the_earlier_link(
    client: TestClient, db_session: Session, registered
):
    """
    Regression test for a real broken registration.

    Re-issuing used to delete every outstanding token, so each resend killed the
    link in the email the user was about to click:

        register  -> token A emailed
        resend    -> token A deleted, token B emailed
        click A   -> 400 "This link is no longer valid"
        resend    -> token B deleted, token C emailed
        click B   -> 400 again

    The user could not escape the loop, because the failure prompted another
    resend. Both links must work.
    """
    user, first_token = registered

    with patch("core.tasks.send_verification_email_task.delay") as delay:
        client.post("/auth/resend-verification", json={"email": "vera@test.com"})
    second_token = delay.call_args[0][2].split("token=")[1]
    assert second_token != first_token

    # The older link — the one that arrived first and is most likely clicked.
    res = client.post("/auth/verify-email", json={"token": first_token})
    assert res.status_code == 200, (
        "the earlier verification link must still work after a resend; "
        f"got {res.status_code}: {res.text}"
    )

    db_session.refresh(user)
    assert user.is_verified is True


def test_a_newer_link_also_works_after_an_older_one_was_used(
    client: TestClient, db_session: Session, registered
):
    """
    Both links point at the same mailbox, so redeeming one must not turn the
    other into an error page. Verification is idempotent.
    """
    user, first_token = registered
    with patch("core.tasks.send_verification_email_task.delay") as delay:
        client.post("/auth/resend-verification", json={"email": "vera@test.com"})
    second_token = delay.call_args[0][2].split("token=")[1]

    assert (
        client.post("/auth/verify-email", json={"token": first_token}).status_code
        == 200
    )
    assert (
        client.post("/auth/verify-email", json={"token": second_token}).status_code
        == 200
    )


def test_live_token_count_is_bounded(
    client: TestClient, db_session: Session, registered, monkeypatch
):
    """
    Several live tokens are fine; unbounded growth is not. A resend loop must not
    accumulate rows for one account.
    """
    from db.models import EmailVerificationToken

    user, _ = registered
    for _ in range(6):
        with patch("core.tasks.send_verification_email_task.delay"):
            client.post("/auth/resend-verification", json={"email": "vera@test.com"})

    live = (
        db_session.query(EmailVerificationToken)
        .filter(EmailVerificationToken.user_id == user.id)
        .count()
    )
    from auth.router import MAX_LIVE_VERIFICATION_TOKENS

    assert live <= MAX_LIVE_VERIFICATION_TOKENS, (
        f"{live} live tokens for one account; expected at most "
        f"{MAX_LIVE_VERIFICATION_TOKENS}"
    )


def test_expired_tokens_are_pruned_on_reissue(
    client: TestClient, db_session: Session, registered
):
    """An expired token is unusable and is a retained email address with no purpose."""
    from datetime import datetime, timedelta, timezone

    from db.models import EmailVerificationToken

    user, _ = registered
    row = (
        db_session.query(EmailVerificationToken)
        .filter(EmailVerificationToken.user_id == user.id)
        .first()
    )
    row.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db_session.commit()
    stale_id = row.id

    with patch("core.tasks.send_verification_email_task.delay"):
        client.post("/auth/resend-verification", json={"email": "vera@test.com"})

    assert (
        db_session.query(EmailVerificationToken)
        .filter(EmailVerificationToken.id == stale_id)
        .first()
        is None
    )


def test_superseded_token_beyond_the_cap_is_rejected(
    client: TestClient, db_session: Session, registered
):
    """
    The cap must actually evict, not just stop counting.

    Several links stay live so a resend does not break the email already in the
    user's inbox, but that window is bounded: once MAX_LIVE_VERIFICATION_TOKENS
    newer links exist, the oldest is gone and must be refused.
    """
    from auth.router import MAX_LIVE_VERIFICATION_TOKENS

    user, oldest_token = registered

    # Push the original token out of the window.
    for _ in range(MAX_LIVE_VERIFICATION_TOKENS):
        with patch("core.tasks.send_verification_email_task.delay") as delay:
            res = client.post(
                "/auth/resend-verification", json={"email": "vera@test.com"}
            )
            assert res.status_code == 200
        newest_token = delay.call_args[0][2].split("token=")[1]

    assert (
        db_session.query(EmailVerificationToken)
        .filter(EmailVerificationToken.user_id == user.id)
        .count()
        <= MAX_LIVE_VERIFICATION_TOKENS
    )
    assert (
        client.post("/auth/verify-email", json={"token": oldest_token}).status_code
        == 400
    ), "a token evicted by the cap must no longer be redeemable"
    assert (
        client.post("/auth/verify-email", json={"token": newest_token}).status_code
        == 200
    )


def test_token_does_not_verify_a_changed_address(
    client: TestClient, db_session: Session, registered
):
    """
    A link issued for one address must not confirm a different one. Otherwise
    changing the email after requesting a link would let the old mailbox verify
    an address it never received mail at.
    """
    user, token = registered
    user.email = "someone-else@test.com"
    db_session.commit()

    assert client.post("/auth/verify-email", json={"token": token}).status_code == 400
    db_session.refresh(user)
    assert user.is_verified is False


# ── Anti-enumeration ──────────────────────────────────────────────────────────


def test_resend_does_not_reveal_whether_an_account_exists(
    client: TestClient, registered, self_registration_enabled
):
    known = client.post("/auth/resend-verification", json={"email": "vera@test.com"})
    unknown = client.post(
        "/auth/resend-verification", json={"email": "nobody@nowhere.test"}
    )
    assert known.status_code == unknown.status_code == 200
    assert known.json() == unknown.json()


def test_resend_sends_nothing_for_an_unknown_address(
    client: TestClient, self_registration_enabled
):
    with patch("core.tasks.send_verification_email_task.delay") as delay:
        client.post("/auth/resend-verification", json={"email": "nobody@nowhere.test"})
    delay.assert_not_called()


# ── The approval gate ─────────────────────────────────────────────────────────


def test_verified_but_unapproved_account_cannot_log_in(client: TestClient, registered):
    _, token = registered
    client.post("/auth/verify-email", json={"token": token})

    res = client.post(
        "/auth/login", json={"email": "vera@test.com", "password": "StrongP@ssw0rd!"}
    )
    assert res.status_code == 403
    assert "awaiting administrator approval" in res.json()["detail"]


def test_approved_account_can_log_in_and_holds_no_scan_permission(
    client: TestClient, db_session: Session, registered
):
    """
    The end-to-end path. The second assertion is the important one: approval
    enables sign-in, it does not confer scans:execute.
    """
    user, token = registered
    client.post("/auth/verify-email", json={"token": token})

    user.approved_at = utcnow()
    user.is_active = True
    db_session.commit()

    res = client.post(
        "/auth/login", json={"email": "vera@test.com", "password": "StrongP@ssw0rd!"}
    )
    assert res.status_code == 200
    token_hdr = {"Authorization": f"Bearer {res.json()['access_token']}"}

    scan = client.post(
        "/scan/host-discovery",
        headers=token_hdr,
        json={"targets": ["127.0.0.1"], "scan_type": "ping"},
    )
    assert scan.status_code == 403


def test_approval_emails_the_account_holder(
    client: TestClient,
    db_session: Session,
    auth_headers: dict,
    test_user: User,
    registered,
):
    """
    Approval must notify the user by email.

    The in-app notification the endpoint raises is only visible after a
    successful login — which is exactly what a pending user cannot do. Without
    the email their only way to discover approval is to retry the login page,
    so this is the difference between a working flow and one that appears to
    hang forever.
    """
    user, token = registered
    client.post("/auth/verify-email", json={"token": token})

    user.org_id = test_user.org_id
    db_session.commit()

    with patch("core.tasks.send_account_approved_email_task.delay") as delay:
        res = client.post(f"/admin/users/{user.id}/approve", headers=auth_headers)
    assert res.status_code == 200, res.text
    assert delay.called, "approval must dispatch an email to the account holder"

    to_addr, username, login_url = delay.call_args[0][:3]
    assert to_addr == "vera@test.com"
    assert username == "verafyer"
    assert login_url.endswith("/login")
    assert login_url.startswith("https://"), (
        "the login link must be https — FRONTEND_URL drives it and a plain-http "
        "link cannot be HSTS-protected"
    )


def test_approval_failure_to_email_does_not_undo_the_approval(
    client: TestClient,
    db_session: Session,
    auth_headers: dict,
    test_user: User,
    registered,
):
    """A broken SMTP server must not roll back an administrator's decision."""
    user, token = registered
    client.post("/auth/verify-email", json={"token": token})
    user.org_id = test_user.org_id
    db_session.commit()

    with patch(
        "core.tasks.send_account_approved_email_task.delay",
        side_effect=RuntimeError("broker down"),
    ):
        res = client.post(f"/admin/users/{user.id}/approve", headers=auth_headers)

    assert res.status_code == 200
    db_session.refresh(user)
    assert user.approved_at is not None
    assert user.is_active is True


def test_admin_cannot_approve_an_unverified_account(
    client: TestClient,
    db_session: Session,
    auth_headers: dict,
    test_user: User,
    registered,
):
    """
    Approval must not be usable as a verification override — that would enable
    a login for an address nobody has demonstrated control of.
    """
    user, _ = registered
    # Self-registration lands in the self-service org; move the pending account
    # into the approving admin's org so this test exercises the verification
    # check rather than the cross-org 404 (which test_pending_approval_is_org
    # _scoped covers).
    user.org_id = test_user.org_id
    db_session.commit()

    res = client.post(f"/admin/users/{user.id}/approve", headers=auth_headers)
    assert res.status_code == 400
    assert "has not been verified" in res.json()["detail"]

    db_session.refresh(user)
    assert user.approved_at is None


def test_pending_approval_is_org_scoped(
    client: TestClient, auth_headers: dict, registered
):
    """
    An org_admin must not be able to approve an account in another tenant.
    The self-registered user lands in the self-service org, so the admin of a
    different org cannot see it at all.
    """
    user, _ = registered
    res = client.post(f"/admin/users/{user.id}/approve", headers=auth_headers)
    assert res.status_code == 404


def test_org_creation_admin_can_actually_log_in(
    client: TestClient, db_session: Session
):
    """
    Creating an organisation with an initial admin must produce an account that
    can sign in.

    This is a regression test for a real miss: the login gates were added to
    auth/router.py and admin_users.py, but POST /admin/organizations builds its
    own User row, and that one was left without is_verified/approved_at. The
    organisation was created, the admin appeared in the list, and then could not
    log in — leaving a tenant whose only administrator was locked out, which
    means the tenant cannot be administered at all.
    """
    from auth.jwt_handler import create_access_token
    from db.base import utcnow
    from db.models import Organization, Role

    superadmin_role = db_session.query(Role).filter(Role.name == "superadmin").first()
    host_org = db_session.query(Organization).first()
    sa = User(
        username="orgmaker",
        email="orgmaker@test.com",
        password_hash="x",
        org_id=host_org.id,
        role_id=superadmin_role.id,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
    )
    db_session.add(sa)
    db_session.commit()
    db_session.refresh(sa)

    token = create_access_token(sa.id, sa.username, role="superadmin", org_id=sa.org_id)
    res = client.post(
        "/admin/organizations",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "Tenant With Admin",
            "slug": "tenant-with-admin",
            "admin_username": "tenantadmin",
            "admin_email": "tenantadmin@test.com",
            "admin_password": "StrongP@ssw0rd!",
            "admin_full_name": "Tenant Admin",
        },
    )
    assert res.status_code in (200, 201), res.text

    created = db_session.query(User).filter(User.username == "tenantadmin").first()
    assert created is not None
    assert created.is_verified is True, "org admin must not need to verify an email"
    assert created.approved_at is not None, "org admin must not await approval"

    login = client.post(
        "/auth/login",
        json={"email": "tenantadmin@test.com", "password": "StrongP@ssw0rd!"},
    )
    assert login.status_code == 200, (
        "the initial org admin cannot sign in — the account gates were applied "
        f"without exempting the provisioning path: {login.text}"
    )


def test_admin_created_users_are_verified_and_approved(
    client: TestClient, db_session: Session, auth_headers: dict, test_org: Organization
):
    """
    Admin provisioning is itself the approval. Without this the new gates would
    have locked every admin-created account out of its own login.
    """
    role = db_session.query(Role).filter(Role.name == "viewer").first()
    res = client.post(
        "/admin/users",
        headers=auth_headers,
        json={
            "username": "provisioned",
            "email": "provisioned@test.com",
            "password": "StrongP@ssw0rd!",
            "full_name": "Provisioned User",
            "role_id": role.id,
            "organization_id": test_org.id,
        },
    )
    assert res.status_code == 200, res.text

    created = (
        db_session.query(User).filter(User.email == "provisioned@test.com").first()
    )
    assert created.is_verified is True
    assert created.approved_at is not None

    login = client.post(
        "/auth/login",
        json={"email": "provisioned@test.com", "password": "StrongP@ssw0rd!"},
    )
    assert login.status_code == 200
