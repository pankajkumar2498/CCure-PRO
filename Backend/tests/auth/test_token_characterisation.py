"""
Token characterisation — Phase 9.1, rewritten for ES256 only (Phase 9.6c).

These tests pin what the four token kinds *are* and how every verification path
treats them. They were written against the HS256 mechanism to show the 9.1
consolidation changed nothing; with HS256 removed they pin the same matrix for the
only token the platform issues, so the guarantees survive the mechanism.

For each kind — ``access``, ``refresh``, ``ticket``, ``mfa_challenge`` — they
cover:

* the header and the exact claim set, and the lifetime;
* acceptance by the path that consumes that kind;
* refusal, by that path, of: a tampered signature or payload, a token signed with
  another key, ``alg: none``, a forged HS256 token, an expired token, each *other*
  kind, a token with no ``type``, and malformed input — with the path's own, uniform
  error;
* the any-kind ``decode_token``, which the two WebSocket logins and the rate-limit
  audit still call, returning the payload for every valid kind and ``None`` for
  every invalid token.

Tokens are minted directly rather than through ``/auth/login``, so no test
commits a login (CLAUDE.md: "Do not test this through TestClient with
auth_headers").
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt as jose_jwt

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ccure_platform.identity import jwt_handler, tokens
from ccure_platform.identity.dependencies import get_current_user_flexible
from config import JWTConfig

KINDS = ("access", "refresh", "ticket", "mfa_challenge")

#: What sign() adds to every user token itself.
_PLATFORM = {"iss", "aud", "ptype", "nbf", "jti", "iat", "exp"}
EXPECTED_CLAIMS = {
    "access": {"sub", "username", "type", "org_id"} | _PLATFORM,
    "refresh": {"sub", "type"} | _PLATFORM,
    "ticket": {"sub", "username", "type"} | _PLATFORM,
    "mfa_challenge": {"sub", "username", "type", "org_id"} | _PLATFORM,
}
EXPECTED_LIFETIME = {
    "access": timedelta(minutes=JWTConfig.ACCESS_TOKEN_EXPIRES_MINUTES),
    "refresh": timedelta(days=JWTConfig.REFRESH_TOKEN_EXPIRES_DAYS),
    "ticket": timedelta(seconds=60),
    "mfa_challenge": timedelta(minutes=5),
}


# ── helpers ───────────────────────────────────────────────────────────────────


def _b64(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _payload(token: str) -> dict:
    return jose_jwt.get_unverified_claims(token)


def _es256(claims: dict, *, header: dict | None = None, key=None) -> str:
    """A correctly formed ES256 token over ``claims`` — signed by the platform's
    active key unless ``key`` (a private key object) says otherwise."""
    active = tokens.signing_key()
    pem = (
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        if key is not None
        else tokens._private_pem(active)
    )
    return jose_jwt.encode(
        claims, pem, algorithm="ES256", headers=header or {"kid": active.kid}
    )


def _mint(user, kind: str, db) -> str:
    if kind == "access":
        return jwt_handler.create_access_token(
            user.id, user.username, org_id=user.org_id
        )
    if kind == "refresh":
        return jwt_handler.create_refresh_token(user.id, db)
    if kind == "ticket":
        return jwt_handler.create_download_ticket(user.id, user.username)
    return jwt_handler.create_mfa_challenge_token(
        user.id, user.username, org_id=user.org_id
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
    other_key = ec.generate_private_key(ec.SECP256R1())
    return {
        "tampered signature": f"{header}.{body}.{flipped}",
        "tampered payload": f"{header}.{_b64(dict(claims, sub='usr_someone_else'))}.{signature}",
        "wrong signing key, right kid": _es256(claims, key=other_key),
        "alg none": f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(claims)}.",
        "alg none, no dot": f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(claims)}",
        "forged HS256, no kid": jose_jwt.encode(
            claims, "a-different-key-entirely", algorithm="HS256"
        ),
        "forged HS256 naming the real kid": jose_jwt.encode(
            claims,
            "a-different-key-entirely",
            algorithm="HS256",
            headers={"kid": tokens.signing_key().kid},
        ),
        "expired": _es256(expired),
        "no type": _es256(no_type),
        "wrong issuer": _es256(dict(claims, iss="https://elsewhere.example")),
        "wrong audience": _es256(dict(claims, aud="urn:ccure:ir")),
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
    header = jose_jwt.get_unverified_header(token)
    assert header["alg"] == "ES256" and header["kid"] == tokens.signing_key().kid
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


def test_the_platform_holds_no_symmetric_signing_configuration():
    assert not hasattr(jwt_handler, "SECRET_KEY")
    assert not hasattr(jwt_handler, "ALGORITHM")
    assert not hasattr(JWTConfig, "SECRET_KEY")
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


def test_decode_token_requires_a_type_claim_but_not_a_particular_kind(
    db_session, test_user
):
    """Finding F9-3 recorded that the HS256-era decode never checked ``type``. An
    ES256 token must carry it (REQUIRED_ASYMMETRIC_CLAIMS), so a token with none is
    refused; which kind it names is still left to each caller."""
    token = _mint(test_user, "access", db_session)
    no_type = _es256({k: v for k, v in _payload(token).items() if k != "type"})
    assert jwt_handler.decode_token(no_type) is None
    for kind in KINDS:
        assert jwt_handler.decode_token(_mint(test_user, kind, db_session)) is not None


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
    now = datetime.now(timezone.utc)
    forged = _es256(
        {
            "sub": str(test_user.id),
            "type": "refresh",
            "jti": "no-such-session",
            "iss": tokens.ISSUER,
            "aud": tokens.USER_AUDIENCE,
            "ptype": "user",
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(days=1)).timestamp()),
        }
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
