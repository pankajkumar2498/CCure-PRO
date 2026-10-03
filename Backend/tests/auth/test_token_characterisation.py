"""
Token characterisation — Phase 9.1.

These tests pin what the four token kinds *are* and how every verification path
treats them **today** (HS256, python-jose), so that consolidating token handling
into ``ccure_platform.identity.tokens`` can be shown to change nothing. They
were written and passed against the code before the consolidation, and pass
unchanged after it.

For each kind — ``access``, ``refresh``, ``ticket``, ``mfa_challenge`` — they
cover:

* the header and the exact claim set, and the lifetime;
* acceptance by the path that consumes that kind;
* refusal, by that path, of: a tampered signature, a token signed with another
  key, ``alg: none``, an expired token, each *other* kind, a token with no
  ``type``, and malformed input — with the path's own, uniform error;
* the legacy ``decode_token``, which the two WebSocket logins and the rate-limit
  audit still call, returning the payload for every valid kind and ``None`` for
  every invalid token.

Tokens are minted directly rather than through ``/auth/login``, so no test
commits a login (CLAUDE.md: "Do not test this through TestClient with
auth_headers").

**Since Phase 9.4** new tokens are ES256 by default
(``tests/auth/test_token_issuance.py`` characterises those). Every test here
runs with ``CCURE_TOKEN_SIGNING_ALG=HS256``, the rollback, so this file now pins
two things at once: the rollback still issues byte-for-byte the pre-9.4 token,
and the HS256 tokens still in circulation are treated exactly as before.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt as jose_jwt

from ccure_platform.identity import jwt_handler
from ccure_platform.identity.dependencies import get_current_user_flexible
from config import JWTConfig

KINDS = ("access", "refresh", "ticket", "mfa_challenge")

EXPECTED_CLAIMS = {
    "access": {"sub", "username", "type", "org_id", "iat", "exp"},
    "refresh": {"sub", "type", "jti", "iat", "exp"},
    "ticket": {"sub", "username", "type", "iat", "exp"},
    "mfa_challenge": {"sub", "username", "type", "org_id", "iat", "exp"},
}
EXPECTED_LIFETIME = {
    "access": timedelta(minutes=JWTConfig.ACCESS_TOKEN_EXPIRES_MINUTES),
    "refresh": timedelta(days=JWTConfig.REFRESH_TOKEN_EXPIRES_DAYS),
    "ticket": timedelta(seconds=60),
    "mfa_challenge": timedelta(minutes=5),
}


@pytest.fixture(autouse=True)
def _hs256_issuance(monkeypatch):
    """The legacy issuance mode (see the module docstring)."""
    monkeypatch.setattr(JWTConfig, "TOKEN_SIGNING_ALG", "HS256")


# ── helpers ───────────────────────────────────────────────────────────────────


def _b64(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _payload(token: str) -> dict:
    return jose_jwt.get_unverified_claims(token)


def _mint(user, kind: str, db) -> str:
    role = getattr(user.role, "name", None)
    if kind == "access":
        return jwt_handler.create_access_token(
            user.id, user.username, role=role, org_id=user.org_id
        )
    if kind == "refresh":
        return jwt_handler.create_refresh_token(user.id, db)
    if kind == "ticket":
        return jwt_handler.create_download_ticket(user.id, user.username)
    return jwt_handler.create_mfa_challenge_token(
        user.id, user.username, role=role, org_id=user.org_id
    )


def _variants(valid: str) -> dict[str, str]:
    """Every way a token of the same claims can be wrong."""
    claims = _payload(valid)
    now = datetime.now(timezone.utc)
    header, body, signature = valid.split(".")
    flipped = signature[:-2] + ("AA" if signature[-2:] != "AA" else "BB")
    expired = dict(
        claims,
        iat=int((now - timedelta(hours=2)).timestamp()),
        exp=int((now - timedelta(hours=1)).timestamp()),
    )
    no_type = {k: v for k, v in claims.items() if k != "type"}
    return {
        "tampered signature": f"{header}.{body}.{flipped}",
        "tampered payload": f"{header}.{_b64(dict(claims, sub='usr_someone_else'))}.{signature}",
        "wrong signing key": jose_jwt.encode(
            claims, "a-different-key-entirely", algorithm="HS256"
        ),
        "alg none": f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(claims)}.",
        "alg none, no dot": f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(claims)}",
        "HS512 with the right key": jose_jwt.encode(
            claims, jwt_handler.SECRET_KEY, algorithm="HS512"
        ),
        "expired": jose_jwt.encode(expired, jwt_handler.SECRET_KEY, algorithm="HS256"),
        "no type": jose_jwt.encode(no_type, jwt_handler.SECRET_KEY, algorithm="HS256"),
        "empty": "",
        "garbage": "not-a-jwt",
        "two segments": f"{header}.{body}",
        "three junk segments": "abc.def.ghi",
        "non-json payload": f"{header}.{base64.urlsafe_b64encode(b'{nope').rstrip(b'=').decode()}.{signature}",
    }


def _other_kinds(user, kind: str, db) -> dict[str, str]:
    return {other: _mint(user, other, db) for other in KINDS if other != kind}


# ── the tokens themselves ─────────────────────────────────────────────────────


@pytest.mark.parametrize("kind", KINDS)
def test_header_claims_and_lifetime(db_session, test_user, kind):
    token = _mint(test_user, kind, db_session)
    assert jose_jwt.get_unverified_header(token) == {"alg": "HS256", "typ": "JWT"}
    claims = _payload(token)
    assert set(claims) == EXPECTED_CLAIMS[kind]
    assert claims["type"] == kind
    assert claims["sub"] == str(test_user.id)
    assert isinstance(claims["iat"], int) and isinstance(claims["exp"], int)
    assert timedelta(seconds=claims["exp"] - claims["iat"]) == EXPECTED_LIFETIME[kind]
    if "org_id" in claims:
        assert claims["org_id"] == str(test_user.org_id)
    # RBAC-8: no role claim is issued; none is an authorization input
    assert "role" not in claims


def test_the_signing_configuration_is_hs256_from_jwt_secret_key():
    assert jwt_handler.ALGORITHM == "HS256"
    assert jwt_handler.SECRET_KEY == JWTConfig.SECRET_KEY
    assert jwt_handler.ACCESS_TOKEN_EXPIRE == EXPECTED_LIFETIME["access"]
    assert jwt_handler.REFRESH_TOKEN_EXPIRE == EXPECTED_LIFETIME["refresh"]


# ── legacy decode_token (WebSocket logins, rate-limit audit) ──────────────────


@pytest.mark.parametrize("kind", KINDS)
def test_decode_token_returns_the_payload_of_any_valid_kind(
    db_session, test_user, kind
):
    token = _mint(test_user, kind, db_session)
    assert jwt_handler.decode_token(token) == _payload(token)


@pytest.mark.parametrize("kind", KINDS)
def test_decode_token_refuses_every_invalid_variant(db_session, test_user, kind):
    for name, bad in _variants(_mint(test_user, kind, db_session)).items():
        if name == "no type":
            continue  # decode_token never checked the kind; its callers do
        assert jwt_handler.decode_token(bad) is None, name


def test_decode_token_does_not_check_the_kind(db_session, test_user):
    """Recorded as finding F9-3; its callers each check `type` themselves."""
    token = _mint(test_user, "access", db_session)
    no_type = jose_jwt.encode(
        {k: v for k, v in _payload(token).items() if k != "type"},
        jwt_handler.SECRET_KEY,
        algorithm="HS256",
    )
    assert jwt_handler.decode_token(no_type) is not None


# ── access: the Bearer dependency behind every protected route ────────────────


def test_an_access_token_is_accepted_by_a_protected_route(
    client, db_session, test_user
):
    token = _mint(test_user, "access", db_session)
    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["id"] == str(test_user.id)


def test_a_protected_route_refuses_every_bad_access_token_uniformly(
    client, db_session, test_user
):
    bad = _variants(_mint(test_user, "access", db_session))
    bad.update(
        {
            f"a {k} token": v
            for k, v in _other_kinds(test_user, "access", db_session).items()
        }
    )
    for name, token in bad.items():
        if name in ("empty",):
            continue  # an empty bearer is refused by HTTPBearer itself, before us
        response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401, name
        assert response.json()["detail"] == "Invalid or expired token", name
        # The dependency raises with WWW-Authenticate: Bearer, but the
        # application's error handler does not forward exception headers, so
        # the client receives none (observed 29 Sep 2026; finding F9-11).
        # Pinned as it is: a change here is a change in behaviour.
        assert response.headers.get("www-authenticate") is None, name


# ── ticket: ?ticket= on downloads (current_user_flexible) ─────────────────────


def test_a_ticket_is_accepted_by_the_download_dependency(db_session, test_user):
    ticket = _mint(test_user, "ticket", db_session)
    user = get_current_user_flexible(ticket=ticket, credentials=None, db=db_session)
    assert str(user.id) == str(test_user.id)


def test_the_download_dependency_refuses_every_bad_ticket(db_session, test_user):
    bad = _variants(_mint(test_user, "ticket", db_session))
    bad.update(
        {
            f"a {k} token": v
            for k, v in _other_kinds(test_user, "ticket", db_session).items()
        }
    )
    for name, token in bad.items():
        if name == "empty":
            continue  # an empty ticket means "no ticket"; the Bearer path is used
        with pytest.raises(HTTPException) as exc:
            get_current_user_flexible(ticket=token, credentials=None, db=db_session)
        assert exc.value.status_code == 401, name
        assert exc.value.detail == "Invalid or expired download ticket.", name


def test_the_download_dependency_still_takes_a_bearer_access_token(
    db_session, test_user
):
    access = _mint(test_user, "access", db_session)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=access)
    user = get_current_user_flexible(ticket=None, credentials=creds, db=db_session)
    assert str(user.id) == str(test_user.id)
    ticket = _mint(test_user, "ticket", db_session)
    with pytest.raises(HTTPException) as exc:
        get_current_user_flexible(
            ticket=None,
            credentials=HTTPAuthorizationCredentials(
                scheme="Bearer", credentials=ticket
            ),
            db=db_session,
        )
    assert exc.value.status_code == 401


# ── refresh: rotation, revocation, logout ─────────────────────────────────────


def test_a_refresh_token_rotates_once_and_only_once(db_session, test_user):
    token = _mint(test_user, "refresh", db_session)
    bundle = jwt_handler.refresh_access_token(token, db_session)
    assert set(bundle) == {"access_token", "refresh_token", "token_type"}
    assert bundle["token_type"] == "bearer"
    assert _payload(bundle["access_token"])["type"] == "access"
    assert _payload(bundle["refresh_token"])["type"] == "refresh"
    # the presented token was rotated away and cannot be used again
    assert jwt_handler.refresh_access_token(token, db_session) is None
    assert (
        jwt_handler.refresh_access_token(bundle["refresh_token"], db_session)
        is not None
    )


def test_refresh_refuses_every_bad_token(db_session, test_user):
    valid = _mint(test_user, "refresh", db_session)
    bad = _variants(valid)
    bad.update(
        {
            f"a {k} token": v
            for k, v in _other_kinds(test_user, "refresh", db_session).items()
        }
    )
    for name, token in bad.items():
        assert jwt_handler.refresh_access_token(token, db_session) is None, name
        assert jwt_handler.revoke_refresh_token(token, db_session) is False, name
    # none of that disturbed the valid session
    assert jwt_handler.refresh_access_token(valid, db_session) is not None


def test_a_correctly_signed_refresh_token_without_its_session_is_refused(
    db_session, test_user
):
    forged = jose_jwt.encode(
        {
            "sub": str(test_user.id),
            "type": "refresh",
            "jti": "no-such-session",
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(days=1)).timestamp()),
        },
        jwt_handler.SECRET_KEY,
        algorithm="HS256",
    )
    assert jwt_handler.refresh_access_token(forged, db_session) is None


def test_logout_revokes_a_refresh_token_and_refuses_anything_else(
    client, db_session, test_user
):
    other = _other_kinds(test_user, "refresh", db_session)
    for name, token in other.items():
        response = client.post("/auth/logout", json={"refresh_token": token})
        assert response.status_code == 401, name
        assert response.json()["detail"] == "Invalid or expired refresh token", name
    token = _mint(test_user, "refresh", db_session)
    assert client.post("/auth/logout", json={"refresh_token": token}).status_code == 200
    assert jwt_handler.refresh_access_token(token, db_session) is None


# ── mfa_challenge: /auth/login/verify-mfa ─────────────────────────────────────


def test_a_challenge_token_is_accepted_and_only_the_code_is_then_judged(
    client, db_session, test_user
):
    token = _mint(test_user, "mfa_challenge", db_session)
    response = client.post(
        "/auth/login/verify-mfa", json={"mfa_token": token, "code": "000000"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid verification code"


def test_verify_mfa_refuses_every_bad_challenge_token(client, db_session, test_user):
    bad = _variants(_mint(test_user, "mfa_challenge", db_session))
    bad.update(
        {
            f"a {k} token": v
            for k, v in _other_kinds(test_user, "mfa_challenge", db_session).items()
        }
    )
    for name, token in bad.items():
        response = client.post(
            "/auth/login/verify-mfa", json={"mfa_token": token, "code": "000000"}
        )
        assert response.status_code == 401, name
        assert response.json()["detail"] == "Invalid or expired challenge token.", name
