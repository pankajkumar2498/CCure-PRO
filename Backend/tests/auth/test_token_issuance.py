"""
ES256 token issuance — Phase 9.4.

New tokens of all four kinds are signed ES256 with the keyset's active key,
through ``tokens.sign`` alone, and carry the full claim set (design §3.3).
ES256 is the only algorithm (Phase 9.6c removed HS256 issuance and verification);
the per-kind refusal matrix is ``test_token_characterisation.py``.

The session's keyset is the throwaway one ``conftest.py`` generates; tests that
need another swap ``tokens._keyset`` with monkeypatch. Tokens are minted
directly, not through ``/auth/login`` (CLAUDE.md: "Do not test this through
TestClient with auth_headers").
"""

from __future__ import annotations

import logging
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from jose import jwt as jose_jwt

from ccure_platform.identity import jwt_handler, keys, tokens
from ccure_platform.identity.dependencies import get_current_user_flexible
from config import JWTConfig
from db.models import RefreshTokenSession
from scripts.security import manage_token_keys as tool

KINDS = ("access", "refresh", "ticket", "mfa_challenge")

#: The claims each kind carried before 9.4, unchanged.
LEGACY_CLAIMS = {
    "access": {"sub", "username", "type", "org_id", "iat", "exp"},
    "refresh": {"sub", "type", "jti", "iat", "exp"},
    "ticket": {"sub", "username", "type", "iat", "exp"},
    "mfa_challenge": {"sub", "username", "type", "org_id", "iat", "exp"},
}
#: What 9.4 adds to every kind (design §3.3).
ADDED_CLAIMS = {"iss", "aud", "ptype", "jti", "nbf"}
LIFETIME = {
    "access": timedelta(minutes=JWTConfig.ACCESS_TOKEN_EXPIRES_MINUTES),
    "refresh": timedelta(days=JWTConfig.REFRESH_TOKEN_EXPIRES_DAYS),
    "ticket": timedelta(seconds=60),
    "mfa_challenge": timedelta(minutes=5),
}


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


def _verify(token, kind):
    return tokens.verify(
        token, expected_kind=kind, issuer=tokens.ISSUER, audience=tokens.USER_AUDIENCE
    )


def _bearer(client, token):
    return client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})


# ── the tokens themselves ─────────────────────────────────────────────────────


def test_the_session_issues_es256():
    assert tokens.SIGNING_ALGORITHM == "ES256"


@pytest.mark.parametrize("kind", KINDS)
def test_new_tokens_are_es256_from_the_active_key(db_session, test_user, kind):
    token = _mint(test_user, kind, db_session)
    active = tokens.signing_key()
    assert active.state == "active"
    assert jose_jwt.get_unverified_header(token) == {
        "alg": "ES256",
        "kid": active.kid,
        "typ": "JWT",
    }


@pytest.mark.parametrize("kind", KINDS)
def test_new_tokens_carry_the_full_claim_set(db_session, test_user, kind):
    claims = jose_jwt.get_unverified_claims(_mint(test_user, kind, db_session))
    assert set(claims) == LEGACY_CLAIMS[kind] | ADDED_CLAIMS
    assert claims["iss"] == "https://ccurepro.cdac.in"
    assert claims["aud"] == "urn:ccure:api"
    assert claims["ptype"] == "user"
    assert claims["type"] == kind
    assert claims["sub"] == str(test_user.id)
    assert claims["nbf"] == claims["iat"]
    assert timedelta(seconds=claims["exp"] - claims["iat"]) == LIFETIME[kind]
    assert isinstance(claims["jti"], str) and len(claims["jti"]) >= 16
    if "org_id" in claims:
        assert claims["org_id"] == str(test_user.org_id)
    # RBAC-8: no role claim is issued; none is an authorization input
    assert "role" not in claims


def test_every_token_gets_its_own_jti(db_session, test_user):
    jtis = {
        jose_jwt.get_unverified_claims(_mint(test_user, "access", db_session))["jti"]
        for _ in range(5)
    }
    assert len(jtis) == 5


def test_the_refresh_jti_is_the_session_rows(db_session, test_user):
    """The caller's jti is kept, because the session row is keyed on it."""
    token = _mint(test_user, "refresh", db_session)
    jti = jose_jwt.get_unverified_claims(token)["jti"]
    row = db_session.query(RefreshTokenSession).filter_by(token_jti=jti).one()
    assert str(row.user_id) == str(test_user.id)


def test_a_new_token_verifies_with_the_published_key_alone(db_session, test_user):
    token = _mint(test_user, "access", db_session)
    kid = jose_jwt.get_unverified_header(token)["kid"]
    (jwk,) = [k for k in tokens.public_jwks()["keys"] if k["kid"] == kid]
    claims = jose_jwt.decode(
        token,
        jwk,
        algorithms=["ES256"],
        audience="urn:ccure:api",
        issuer="https://ccurepro.cdac.in",
    )
    assert claims["sub"] == str(test_user.id)


# ── each kind is accepted where it is consumed ────────────────────────────────


def test_an_es256_access_token_reaches_a_protected_route(client, db_session, test_user):
    response = _bearer(client, _mint(test_user, "access", db_session))
    assert response.status_code == 200
    assert response.json()["id"] == str(test_user.id)


def test_an_es256_ticket_is_accepted_by_the_download_dependency(db_session, test_user):
    ticket = _mint(test_user, "ticket", db_session)
    user = get_current_user_flexible(ticket=ticket, credentials=None, db=db_session)
    assert str(user.id) == str(test_user.id)


@pytest.mark.parametrize("kind", KINDS)
def test_the_legacy_decode_accepts_every_es256_kind(db_session, test_user, kind):
    """The WebSocket ticket logins and the rate-limit audit, unchanged."""
    token = _mint(test_user, kind, db_session)
    assert jwt_handler.decode_token(token) == jose_jwt.get_unverified_claims(token)


def test_an_es256_mfa_challenge_verifies_as_one(db_session, test_user):
    token = _mint(test_user, "mfa_challenge", db_session)
    assert _verify(token, "mfa_challenge")["sub"] == str(test_user.id)
    assert _verify(token, "access") is None


def test_an_es256_refresh_token_rotates_into_es256_tokens(db_session, test_user):
    refresh = _mint(test_user, "refresh", db_session)
    rotated = jwt_handler.refresh_access_token(refresh, db_session)
    for name in ("access_token", "refresh_token"):
        assert jose_jwt.get_unverified_header(rotated[name])["alg"] == "ES256", name
    assert jwt_handler.refresh_access_token(refresh, db_session) is None  # rotated


def test_claim_consistency_still_applies_to_es256_tokens(client, db_session, test_user):
    # the organisation claim must still match the account...
    token = jwt_handler.create_access_token(
        test_user.id, test_user.username, org_id="org_someone_else"
    )
    response = _bearer(client, token)
    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Token organization scope no longer matches the user account"
    )
    # ...and a role claim is ignored: it can neither grant nor refuse anything (RBAC-8)
    forged = jwt_handler.create_access_token(
        test_user.id, test_user.username, role="superadmin", org_id=test_user.org_id
    )
    assert _bearer(client, forged).status_code == 200


# ── legacy sessions ───────────────────────────────────────────────────────────


# ── what sign() refuses ───────────────────────────────────────────────────────


@pytest.mark.parametrize("claim", ["iss", "aud", "ptype", "iat", "nbf", "exp"])
def test_sign_sets_the_platform_claims_itself(claim):
    with pytest.raises(ValueError):
        tokens.sign({"sub": "usr_x", "type": "access", claim: "x"}, timedelta(1))


@pytest.mark.parametrize("kind", [None, "service_access", "accesss"])
def test_sign_refuses_a_kind_it_does_not_issue(kind):
    claims = {"sub": "usr_x"} if kind is None else {"sub": "usr_x", "type": kind}
    with pytest.raises(ValueError):
        tokens.sign(claims, timedelta(minutes=1))


def _keyset_in(tmp_path, *states):
    for state in states:
        tool.generate(str(tmp_path), state, owner=None)
    return keys.load_keyset(str(tmp_path))


def test_no_active_key_means_no_es256_token(tmp_path, monkeypatch):
    monkeypatch.setattr(tokens, "_keyset", _keyset_in(tmp_path, "next", "retired"))
    with pytest.raises(tokens.SigningUnavailable, match="no active key"):
        tokens.sign({"sub": "usr_x", "type": "access"}, timedelta(minutes=1))
    with pytest.raises(tokens.SigningUnavailable):
        tokens.assert_signing_ready()


def test_no_keyset_means_no_es256_token(monkeypatch):
    monkeypatch.setattr(tokens, "_keyset", None)
    with pytest.raises(tokens.SigningUnavailable, match="no usable token keyset"):
        tokens.sign({"sub": "usr_x", "type": "access"}, timedelta(minutes=1))


def test_assert_signing_ready_names_the_active_key():
    assert tokens.assert_signing_ready() == f"ES256 with key {tokens.signing_key().kid}"


def test_the_api_refuses_to_start_without_an_active_key(tmp_path, monkeypatch):
    """Design §3.7: a core that cannot sign must not come up half-working."""
    from main import app

    monkeypatch.setattr(tokens, "_keyset", _keyset_in(tmp_path, "next"))
    with pytest.raises(tokens.SigningUnavailable):
        with TestClient(app):
            pass


# ── refusals are logged, never the token ──────────────────────────────────────


def _es256_with(key, **claims):
    return jose_jwt.encode(
        claims,
        tokens._private_pem(key),
        algorithm="ES256",
        headers={"kid": key.kid},
    )


def _refusal_lines(caplog):
    return [r for r in caplog.records if r.name == "ccure.tokens"]


@pytest.mark.parametrize(
    "case, reason, level",
    [
        ("expired", "expired", logging.INFO),
        ("wrong audience", "wrong_audience", logging.WARNING),
        ("wrong issuer", "wrong_issuer", logging.WARNING),
        ("unknown kid", "unknown_kid", logging.WARNING),
        ("wrong kind", "wrong_kind", logging.INFO),
        ("missing jti", "missing_claim", logging.WARNING),
    ],
)
def test_a_refusal_names_its_reason_and_never_the_token(caplog, case, reason, level):
    from datetime import datetime, timezone

    key = tokens.signing_key()
    now = int(datetime.now(timezone.utc).timestamp())
    base = dict(
        iss=tokens.ISSUER,
        aud=tokens.USER_AUDIENCE,
        sub="usr_probe",
        type="access",
        ptype="user",
        jti="jti-probe-0001",
        iat=now,
        nbf=now,
        exp=now + 60,
    )
    token = {
        "expired": lambda: _es256_with(key, **dict(base, exp=now - 1)),
        "wrong audience": lambda: _es256_with(key, **dict(base, aud="urn:ccure:ir")),
        "wrong issuer": lambda: _es256_with(key, **dict(base, iss="https://evil")),
        "unknown kid": lambda: jose_jwt.encode(
            base,
            tokens._private_pem(key),
            algorithm="ES256",
            headers={"kid": "not-a-kid"},
        ),
        "wrong kind": lambda: _es256_with(key, **dict(base, type="refresh")),
        "missing jti": lambda: _es256_with(
            key, **{k: v for k, v in base.items() if k != "jti"}
        ),
    }[case]()
    caplog.set_level(logging.INFO, logger="ccure.tokens")
    assert _verify(token, "access") is None
    (line,) = _refusal_lines(caplog)
    assert f"reason={reason}" in line.getMessage()
    assert line.levelno == level
    text = caplog.text
    assert token not in text
    assert token.split(".")[2] not in text  # not even the signature
    if case != "missing jti":
        assert "jti-probe-0001" in line.getMessage()


def test_an_accepted_token_logs_nothing(caplog, db_session, test_user):
    caplog.set_level(logging.DEBUG, logger="ccure.tokens")
    assert _verify(_mint(test_user, "access", db_session), "access")
    assert _refusal_lines(caplog) == []


def test_an_oversized_claim_is_truncated_in_the_log(caplog):
    from datetime import datetime, timezone

    key = tokens.signing_key()
    now = int(datetime.now(timezone.utc).timestamp())
    token = _es256_with(
        key,
        iss=tokens.ISSUER,
        aud="urn:ccure:elsewhere",
        sub="usr_probe",
        type="access",
        ptype="user",
        jti="J" * 5000,
        iat=now,
        nbf=now,
        exp=now + 60,
    )
    caplog.set_level(logging.INFO, logger="ccure.tokens")
    assert _verify(token, "access") is None
    (line,) = _refusal_lines(caplog)
    assert "J" * 64 in line.getMessage()
    assert "J" * 65 not in line.getMessage()


def test_logout_revokes_a_session(db_session, test_user):
    refresh = jwt_handler.create_refresh_token(test_user.id, db_session)
    assert jwt_handler.revoke_refresh_token(refresh, db_session) is True
    assert jwt_handler.refresh_access_token(refresh, db_session) is None


def test_there_is_no_way_to_ask_for_another_algorithm():
    """Issuance has one algorithm; no setting, no name, no function selects another."""
    assert tokens.SIGNING_ALGORITHM == "ES256"
    assert not hasattr(tokens, "signing_algorithm")
    assert not hasattr(JWTConfig, "TOKEN_SIGNING_ALG")
    assert not hasattr(JWTConfig, "ACCEPT_LEGACY_HS256")


def test_an_hs256_token_is_refused_and_logged_with_its_reason(
    caplog, db_session, test_user
):
    hs256 = jose_jwt.encode(
        {"sub": test_user.id, "type": "access"}, "any-secret", algorithm="HS256"
    )
    caplog.set_level(logging.INFO, logger="ccure.tokens")
    assert _verify(hs256, "access") is None
    (line,) = _refusal_lines(caplog)
    assert "reason=missing_kid" in line.getMessage()
    assert hs256 not in caplog.text
