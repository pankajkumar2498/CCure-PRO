"""
ES256 token issuance — Phase 9.4.

New tokens of all four kinds are signed ES256 with the keyset's active key,
through ``tokens.sign`` alone, and carry the full claim set (design §3.3).
Legacy HS256 tokens still in circulation keep working, and a legacy session
moves onto ES256 at its next refresh. The HS256 rollback
(``CCURE_TOKEN_SIGNING_ALG=HS256``) is characterised by
``test_token_characterisation.py``, which runs in that mode.

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
    "access": {"sub", "username", "type", "role", "org_id", "iat", "exp"},
    "refresh": {"sub", "type", "jti", "iat", "exp"},
    "ticket": {"sub", "username", "type", "iat", "exp"},
    "mfa_challenge": {"sub", "username", "type", "role", "org_id", "iat", "exp"},
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


@pytest.fixture
def legacy_issuance(monkeypatch):
    """Issue as 9.3 did, to make the legacy tokens still in circulation."""
    monkeypatch.setattr(JWTConfig, "TOKEN_SIGNING_ALG", "HS256")


def _as_legacy(monkeypatch, mint):
    monkeypatch.setattr(JWTConfig, "TOKEN_SIGNING_ALG", "HS256")
    try:
        return mint()
    finally:
        monkeypatch.setattr(JWTConfig, "TOKEN_SIGNING_ALG", "ES256")


def _verify(token, kind):
    return tokens.verify(
        token, expected_kind=kind, issuer=tokens.ISSUER, audience=tokens.USER_AUDIENCE
    )


def _bearer(client, token):
    return client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})


# ── the tokens themselves ─────────────────────────────────────────────────────


def test_the_session_issues_es256():
    assert tokens.signing_algorithm() == "ES256"
    assert JWTConfig.TOKEN_SIGNING_ALG == "ES256"


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
    if "role" in claims:
        assert claims["role"] == test_user.role.name


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
    token = jwt_handler.create_access_token(
        test_user.id, test_user.username, role="superadmin", org_id=test_user.org_id
    )
    response = _bearer(client, token)
    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Token role scope no longer matches the user account"
    )


# ── legacy sessions ───────────────────────────────────────────────────────────


def test_a_legacy_refresh_token_is_replaced_by_es256_tokens(
    db_session, test_user, monkeypatch
):
    legacy = _as_legacy(
        monkeypatch, lambda: jwt_handler.create_refresh_token(test_user.id, db_session)
    )
    assert jose_jwt.get_unverified_header(legacy) == {"alg": "HS256", "typ": "JWT"}
    rotated = jwt_handler.refresh_access_token(legacy, db_session)
    assert rotated is not None
    for name in ("access_token", "refresh_token"):
        assert jose_jwt.get_unverified_header(rotated[name])["alg"] == "ES256", name
    assert jwt_handler.refresh_access_token(legacy, db_session) is None
    assert jwt_handler.refresh_access_token(rotated["refresh_token"], db_session)


def test_a_mixed_age_session_keeps_working(client, db_session, test_user, monkeypatch):
    """A legacy access token still in its 30 minutes, beside new ES256 ones."""
    legacy_access = _as_legacy(
        monkeypatch, lambda: _mint(test_user, "access", db_session)
    )
    new_access = _mint(test_user, "access", db_session)
    assert jose_jwt.get_unverified_header(legacy_access)["alg"] == "HS256"
    assert _bearer(client, legacy_access).status_code == 200
    assert _bearer(client, new_access).status_code == 200


@pytest.mark.parametrize("era", ["legacy", "es256"])
def test_logout_revokes_a_session_of_either_era(
    db_session, test_user, monkeypatch, era
):
    def mint():
        return jwt_handler.create_refresh_token(test_user.id, db_session)

    refresh = _as_legacy(monkeypatch, mint) if era == "legacy" else mint()
    assert jwt_handler.revoke_refresh_token(refresh, db_session) is True
    assert jwt_handler.refresh_access_token(refresh, db_session) is None


def test_es256_tokens_survive_a_rollback_to_hs256(
    client, db_session, test_user, legacy_issuance
):
    """Rollback flips issuance only; what was issued ES256 stays valid."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(JWTConfig, "TOKEN_SIGNING_ALG", "ES256")
        es256_access = _mint(test_user, "access", db_session)
    assert tokens.signing_algorithm() == "HS256"
    assert jose_jwt.get_unverified_header(es256_access)["alg"] == "ES256"
    assert _bearer(client, es256_access).status_code == 200


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


def test_hs256_mode_needs_no_keyset(monkeypatch, legacy_issuance):
    monkeypatch.setattr(tokens, "_keyset", None)
    assert tokens.assert_signing_ready().startswith("HS256")
    token = tokens.sign({"sub": "usr_x", "type": "access"}, timedelta(minutes=1))
    assert jose_jwt.get_unverified_header(token) == {"alg": "HS256", "typ": "JWT"}


@pytest.mark.parametrize("value", ["RS256", "none", "", "es384"])
def test_an_unknown_signing_algorithm_is_refused(monkeypatch, value):
    monkeypatch.setattr(JWTConfig, "TOKEN_SIGNING_ALG", value)
    with pytest.raises(tokens.SigningUnavailable):
        tokens.assert_signing_ready()
    with pytest.raises(tokens.SigningUnavailable):
        tokens.sign({"sub": "usr_x", "type": "access"}, timedelta(minutes=1))


def test_the_setting_is_case_insensitive(monkeypatch):
    monkeypatch.setattr(JWTConfig, "TOKEN_SIGNING_ALG", " es256 ")
    assert tokens.signing_algorithm() == "ES256"


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


def test_a_disabled_legacy_token_is_logged_as_such(
    caplog, db_session, test_user, monkeypatch
):
    legacy = _as_legacy(monkeypatch, lambda: _mint(test_user, "access", db_session))
    monkeypatch.setattr(JWTConfig, "ACCEPT_LEGACY_HS256", False)
    caplog.set_level(logging.INFO, logger="ccure.tokens")
    assert _verify(legacy, "access") is None
    (line,) = _refusal_lines(caplog)
    assert "reason=legacy_disabled legacy=True" in line.getMessage()
    assert legacy not in caplog.text


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
