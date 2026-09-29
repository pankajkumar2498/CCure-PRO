"""
tests/auth/test_session_management.py
─────────────────────────────────────
Concurrent sessions and what the account owner can do about them.

The premise, asserted rather than assumed: **an account may be signed in on any
number of devices at once, and that is deliberate.** Capping it would push
people into sharing a browser or logging each other out, and neither makes
anything safer. What the choice requires instead is that the owner can *see*
where the account is signed in and end any of it — so these tests treat the
session list and its revocation paths as the security control, and a regression
that silently caps concurrent logins fails the first test here.
"""

from unittest.mock import patch

import pytest
from db.base import gen_user_id, utcnow
from db.models import Organization, RefreshTokenSession, Role, User
from db.models.users import PasswordResetToken  # noqa: F401  (schema import)
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from auth.jwt_handler import hash_password

LOGIN = {"email": "sessions@test.com", "password": "securepassword123"}


@pytest.fixture
def session_user(db_session: Session) -> User:
    org = Organization(
        name="Session Org",
        slug="session-org",
        max_assets=10,
        max_users=10,
        is_active=True,
    )
    db_session.add(org)
    db_session.flush()

    role = db_session.query(Role).filter_by(name="analyst").first()
    user = User(
        id=gen_user_id(org.slug, "sessionuser"),
        username="sessionuser",
        email="sessions@test.com",
        full_name="Session User",
        password_hash=hash_password("securepassword123"),
        org_id=org.id,
        role_id=role.id,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _login(client: TestClient, user_agent: str | None = None) -> str:
    """Sign in and return the access token, leaving the refresh cookie set."""
    headers = {"User-Agent": user_agent} if user_agent else {}
    response = client.post("/auth/login", json=LOGIN, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _active_sessions(db_session: Session, user: User) -> list[RefreshTokenSession]:
    return (
        db_session.query(RefreshTokenSession)
        .filter(
            RefreshTokenSession.user_id == user.id,
            RefreshTokenSession.revoked_at.is_(None),
        )
        .all()
    )


# ── The deliberate behaviour ─────────────────────────────────────────────────


def test_an_account_may_be_signed_in_on_several_devices_at_once(
    client: TestClient, db_session: Session, session_user: User
):
    """
    Three sign-ins, three live sessions. None of them displaces another.

    This is asserted so that "unlimited concurrent sessions" stays a decision
    somebody made rather than something nobody checked — a later change that
    caps or replaces sessions has to come here and change the premise on
    purpose.
    """
    for agent in ("Mozilla/5.0 (Windows NT 10.0) Chrome/120", "curl/8.4.0", None):
        _login(client, agent)

    assert len(_active_sessions(db_session, session_user)) == 3


def test_logging_out_one_device_leaves_the_others_signed_in(
    client: TestClient, db_session: Session, session_user: User
):
    """Sign-out is per session; it is not an account-wide event."""
    _login(client)
    _login(client)
    assert len(_active_sessions(db_session, session_user)) == 2

    assert client.post("/auth/logout").status_code == 200
    assert len(_active_sessions(db_session, session_user)) == 1


# ── Telling the sessions apart ───────────────────────────────────────────────


def test_sessions_carry_a_device_description(
    client: TestClient, db_session: Session, session_user: User
):
    """
    `device_info` existed on this table from the start and was never written,
    so the screen showed rows a person could not tell apart. A list of
    indistinguishable sessions is worse than no list: it invites revoking the
    wrong one, or concluding nothing is wrong because nothing looks different.
    """
    token = _login(client, "Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/120.0 Safari")

    response = client.get(
        "/user/sessions", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200

    rows = response.json()
    assert len(rows) == 1
    assert rows[0]["device_info"]["browser"] == "Chrome"
    assert rows[0]["device_info"]["platform"] == "Windows"
    assert rows[0]["device_info"]["raw"].startswith("Mozilla/5.0")


def test_the_session_making_the_request_is_marked_current(
    client: TestClient, db_session: Session, session_user: User
):
    """
    `is_current` was hardcoded False behind a TODO, so every row looked like
    somebody else's and the one row a user must not revoke was unmarked.

    It cannot be answered from the access token — that carries the user, not
    the session — so it is read from the refresh cookie, which identifies this
    session specifically.
    """
    _login(client)  # an older session, on the same cookie jar
    token = _login(client)  # the cookie now belongs to this one

    rows = client.get(
        "/user/sessions", headers={"Authorization": f"Bearer {token}"}
    ).json()

    assert len(rows) == 2
    current = [r for r in rows if r["is_current"]]
    assert len(current) == 1, "exactly one session must be marked current"

    # And it is the newest one, which is what the cookie holds.
    assert current[0]["session_id"] == max(r["session_id"] for r in rows)


def test_is_current_is_false_rather_than_an_error_without_a_cookie(
    client: TestClient, db_session: Session, session_user: User
):
    """
    An API client holding only a bearer token has no browser session to point
    at. That is honest, and it must not stop the list being returned.
    """
    token = _login(client)
    client.cookies.clear()

    rows = client.get(
        "/user/sessions", headers={"Authorization": f"Bearer {token}"}
    ).json()
    assert rows and all(r["is_current"] is False for r in rows)


def test_expired_sessions_are_not_listed(
    client: TestClient, db_session: Session, session_user: User
):
    """
    A row past its expires_at cannot be refreshed, so listing it shows a
    session that does not exist and invites revoking something already gone.
    """
    from datetime import timedelta

    token = _login(client)
    _login(client)

    stale = _active_sessions(db_session, session_user)[0]
    stale.expires_at = utcnow() - timedelta(days=1)
    db_session.commit()

    rows = client.get(
        "/user/sessions", headers={"Authorization": f"Bearer {token}"}
    ).json()
    assert stale.id not in [r["session_id"] for r in rows]


# ── Ending sessions ──────────────────────────────────────────────────────────


def test_sign_out_everywhere_else_keeps_only_the_current_session(
    client: TestClient, db_session: Session, session_user: User
):
    """
    The control that matters when somebody suspects their account is being used
    elsewhere. Revoking one at a time requires knowing which row is the
    intruder, and the reason for being on this screen is not knowing.
    """
    _login(client)
    _login(client)
    token = _login(client)
    assert len(_active_sessions(db_session, session_user)) == 3

    response = client.delete(
        "/user/sessions", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["revoked"] == 2
    assert response.json()["kept_current_session"] is True

    remaining = _active_sessions(db_session, session_user)
    assert len(remaining) == 1


def test_sign_out_everywhere_else_revokes_all_when_the_caller_is_unidentifiable(
    client: TestClient, db_session: Session, session_user: User
):
    """
    "I could not tell which session is yours" must not become "so I left them
    all running". Without a refresh cookie the safe direction is to revoke
    everything, including whatever the caller is using.
    """
    _login(client)
    token = _login(client)
    client.cookies.clear()

    response = client.delete(
        "/user/sessions", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["revoked"] == 2
    assert response.json()["kept_current_session"] is False
    assert _active_sessions(db_session, session_user) == []


def test_revocation_marks_rows_rather_than_deleting_them(
    client: TestClient, db_session: Session, session_user: User
):
    """
    The audit trail has to keep showing that these sessions existed and when
    they ended. Deleting the rows would erase the evidence of the very event
    being responded to.
    """
    _login(client)
    token = _login(client)

    client.delete("/user/sessions", headers={"Authorization": f"Bearer {token}"})

    rows = (
        db_session.query(RefreshTokenSession)
        .filter(RefreshTokenSession.user_id == session_user.id)
        .all()
    )
    assert len(rows) == 2
    assert sum(1 for r in rows if r.revoked_at is not None) == 1


def test_a_revoked_session_can_no_longer_refresh(
    client: TestClient, db_session: Session, session_user: User
):
    """Revocation has to end the session, not merely hide it from the list."""
    _login(client)
    victim_cookie = dict(client.cookies)

    token = _login(client)
    client.delete("/user/sessions", headers={"Authorization": f"Bearer {token}"})

    client.cookies.clear()
    for name, value in victim_cookie.items():
        client.cookies.set(name, value)

    assert client.post("/auth/refresh").status_code == 401


def test_one_user_cannot_revoke_another_users_session(
    client: TestClient, db_session: Session, session_user: User, test_user: User
):
    """
    Session ids are sequential integers, so the ownership filter on the
    single-session endpoint is the only thing standing between a guessed id and
    signing another tenant's user out.
    """
    _login(client)
    victim_session = _active_sessions(db_session, session_user)[0]

    other = client.post(
        "/auth/login",
        json={"email": "admin@test.com", "password": "securepassword123"},
    )
    assert other.status_code == 200
    other_token = other.json()["access_token"]

    response = client.delete(
        f"/user/sessions/{victim_session.id}",
        headers={"Authorization": f"Bearer {other_token}"},
    )
    assert response.status_code == 404

    db_session.refresh(victim_session)
    assert victim_session.revoked_at is None


# ── Security events end every session ────────────────────────────────────────


def test_password_reset_ends_every_session(
    client: TestClient, db_session: Session, session_user: User
):
    """
    A reset is the response to "somebody else may have my password". Leaving
    their sessions running would defeat the point — the new password is not
    what they are using.
    """
    import hashlib
    import secrets
    from datetime import datetime, timedelta, timezone

    _login(client)
    _login(client)
    assert len(_active_sessions(db_session, session_user)) == 2

    token = secrets.token_urlsafe(32)
    db_session.add(
        PasswordResetToken(
            user_id=session_user.id,
            token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
        )
    )
    db_session.commit()

    with patch("core.tasks.send_password_reset_email_task.delay"):
        response = client.post(
            "/auth/reset-password",
            json={"token": token, "password": "CompletelyNew1!"},
        )
    assert response.status_code == 200
    assert _active_sessions(db_session, session_user) == []


# ── The user-agent parse ─────────────────────────────────────────────────────


def test_user_agent_parse_prefers_the_specific_name():
    """
    Every Chromium browser says "Chrome" and Edge says both "Chrome" and "Edg",
    so ordering in the table is what makes the answer right rather than merely
    plausible.
    """
    from core.user_agent import describe

    edge = describe(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    )
    assert edge["browser"] == "Edge"
    assert edge["platform"] == "Windows"

    android = describe("Mozilla/5.0 (Linux; Android 14) Chrome/120 Mobile Safari")
    assert android["browser"] == "Chrome"
    assert android["platform"] == "Android"

    assert describe("curl/8.4.0")["browser"] == "curl"


def test_user_agent_parse_is_bounded_and_never_raises():
    """
    The header is attacker-controlled and lands in a JSONB column that is read
    back into an API response, so its size has to be bounded here.
    """
    from core.user_agent import describe

    described = describe("A" * 10_000)
    assert len(described["raw"]) <= 400

    for junk in (None, "", "\x00\x01", "…"):
        result = describe(junk)
        assert set(result) == {"browser", "platform", "raw"}


# ── Retention ────────────────────────────────────────────────────────────────


def test_expired_sessions_are_swept_but_recent_history_is_kept(
    client: TestClient, db_session: Session, session_user: User
):
    """
    `refresh_token_sessions` gains a row per login *and* one per rotation, which
    with 30-minute access tokens is roughly 48 a day per signed-in session, and
    nothing ever deleted any of them.

    Two properties the sweep must have. It only removes rows that are **both**
    past expires_at and older than the retention window — so it can never end a
    session that still works. And a revoked-but-recent row survives: the
    revocation is the audit record of somebody signing a device out, which is
    exactly what an investigation needs, and deleting it the moment it stopped
    being usable would erase the evidence of the event being investigated.
    """
    import datetime

    from config import AppConfig
    from ccure_platform.identity.account_maintenance import (
        purge_expired_refresh_sessions,
    )
    from db.models import RefreshTokenSession

    now = datetime.datetime.now(datetime.timezone.utc)
    days = AppConfig.REFRESH_SESSION_RETENTION_DAYS

    def make(jti, issued_ago_days, expires_ago_days, revoked=False):
        row = RefreshTokenSession(
            user_id=session_user.id,
            org_id=session_user.org_id,
            token_jti=jti,
            token_hash=f"hash-{jti}",
            issued_at=now - datetime.timedelta(days=issued_ago_days),
            expires_at=now - datetime.timedelta(days=expires_ago_days),
            revoked_at=(now if revoked else None),
        )
        db_session.add(row)
        return row

    make("ancient", days + 30, days + 23)
    make("recent-revoked", 1, -6, revoked=True)
    make("live", 1, -6)
    db_session.commit()

    result = purge_expired_refresh_sessions()
    assert result["success"] is True
    assert result["purged"] >= 1

    # Re-read rather than touching the objects created above: the task deletes
    # through its own session, so those instances are stale and merely reading
    # an attribute raises ObjectDeletedError.
    db_session.expire_all()
    surviving = {
        r.token_jti
        for r in db_session.query(RefreshTokenSession).filter(
            RefreshTokenSession.user_id == session_user.id
        )
    }
    assert "ancient" not in surviving, "expired and past retention: should go"
    assert "recent-revoked" in surviving, "revocation is the audit record"
    assert "live" in surviving, "a live session must never be swept"


def test_session_purge_is_scheduled():
    """
    The task existing is not the same as the task running. This repository has
    already had periodic tasks defined in `beat_schedule` that nothing executed
    for months — compliance scheduling and the stale-account purge both sat
    dead because no beat process was started.
    """
    from core.celery_app import celery_app

    entry = celery_app.conf.beat_schedule.get("purge-expired-refresh-sessions-daily")
    assert entry, "no beat entry for the refresh-session sweep"
    assert entry["task"] == "ccure.tasks.purge_expired_refresh_sessions"

    import ccure_platform.identity.account_maintenance  # noqa: F401

    assert "ccure.tasks.purge_expired_refresh_sessions" in celery_app.tasks
