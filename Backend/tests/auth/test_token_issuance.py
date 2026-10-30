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

import base64
import hashlib
import hmac
import json
import logging
import time
import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from jose import JWTError
from jose import jwt as jose_jwt

from ccure_platform.identity import jwt_handler, keys, tokens, verification
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


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _public_bytes(public_key, encoding: str) -> bytes:
    return public_key.public_bytes(
        getattr(serialization.Encoding, encoding),
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _forge_hs256(signed_token: str, kid: str, secret: bytes) -> str:
    """``signed_token``'s claims under ``kid``, re-signed HS256 with ``secret``,
    by hand, so python-jose's own HMAC key guard is not what refuses it."""
    claims = signed_token.split(".")[1]
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid}).encode())
    signing_input = f"{header}.{claims}".encode("ascii")
    signature = _b64url(hmac.new(secret, signing_input, hashlib.sha256).digest())
    return f"{header}.{claims}.{signature}"


def _jwks_key_source():
    """The key source the gateway builds (``gateway/token_check/jwks.py``):
    public members only, from the published JWK Set, ``alg`` fixed to ES256."""

    def coordinate(value: str) -> int:
        return int.from_bytes(
            base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big"
        )

    found = {}
    for jwk in tokens.public_jwks()["keys"]:
        assert (jwk["kty"], jwk["crv"], jwk["alg"]) == ("EC", "P-256", "ES256")
        public = ec.EllipticCurvePublicNumbers(
            coordinate(jwk["x"]), coordinate(jwk["y"]), ec.SECP256R1()
        ).public_key()
        found[jwk["kid"]] = SimpleNamespace(
            kid=jwk["kid"],
            alg="ES256",
            public_pem=_public_bytes(public, "PEM").decode("ascii"),
        )
    return SimpleNamespace(verification_key=found.get)


@pytest.mark.parametrize("encoding", ["DER", "PEM"])
def test_an_hs256_token_keyed_with_the_public_key_is_refused(
    caplog, db_session, test_user, encoding
):
    """PYSEC-2026-4298 (CVE-2026-85394): python-jose through 3.5.0 accepts a
    DER-encoded public key as an HMAC secret, so a verifier that lets the
    token's ``alg`` choose can be handed an HS256 token signed with the public
    key. The accepted-advisory entry rests on this being refused on every
    verification entry point: a real access token's claims under the active
    key's ``kid``, re-signed HS256 with that key's public bytes, is refused by

    * ``tokens.verify`` (every bearer, ticket and refresh check),
    * ``tokens.decode_any_kind`` (``decode_token``: the WebSocket ticket logins),
    * ``verification.verify`` over the gateway's JWKS-only key source, and
    * python-jose itself with ``algorithms=[ES256]``, as ``decode`` calls it.

    Each path first accepts the genuine token, so the refusal can only be the
    algorithm's.
    """
    key = tokens.signing_key()
    real = _mint(test_user, "access", db_session)
    forged = _forge_hs256(
        real, key.kid, _public_bytes(key.private_key.public_key(), encoding)
    )
    gateway = _jwks_key_source()

    def through_gateway(token):
        return verification.verify(
            token,
            expected_kind="access",
            issuer=tokens.ISSUER,
            audience=tokens.USER_AUDIENCE,
            keyset=lambda: gateway,
        )

    assert _verify(real, "access") is not None
    assert tokens.decode_any_kind(real) is not None
    assert isinstance(through_gateway(real), dict)

    caplog.set_level(logging.INFO, logger="ccure.tokens")
    assert _verify(forged, "access") is None
    assert tokens.decode_any_kind(forged) is None
    reasons = [r.getMessage() for r in _refusal_lines(caplog)]
    assert len(reasons) == 2 and all("reason=alg_mismatch" in m for m in reasons)

    refusal = through_gateway(forged)
    assert isinstance(refusal, verification.Refusal)
    assert refusal.reason == "alg_mismatch"

    with pytest.raises(JWTError, match="alg value is not allowed"):
        jose_jwt.decode(
            forged,
            key.public_pem,
            algorithms=[key.alg],
            audience=tokens.USER_AUDIENCE,
            issuer=tokens.ISSUER,
        )


@pytest.mark.parametrize("encoding", ["DER", "PEM"])
def test_an_hs256_service_assertion_keyed_with_the_public_key_is_refused(
    caplog, encoding
):
    """The same attack on ``/auth/service-token``'s client assertion: a
    service's registered public key used as the HMAC secret, under its own
    ``kid``. Refused before decoding, and the genuine ES256 assertion with the
    same claims is accepted."""
    service_id, kid = "svc-pysec-2026-4298", "svc-kid-1"
    private = ec.generate_private_key(ec.SECP256R1())
    registered = SimpleNamespace(
        kid=kid,
        alg="ES256",
        public_pem=_public_bytes(private.public_key(), "PEM").decode("ascii"),
    )

    def key_for(sid, k):
        return registered if (sid, k) == (service_id, kid) else None

    now = int(time.time())
    claims = {
        "iss": service_id,
        "sub": service_id,
        "aud": tokens.SERVICE_ASSERTION_AUDIENCE,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + 30,
    }
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    real = jose_jwt.encode(claims, private_pem, algorithm="ES256", headers={"kid": kid})
    forged = _forge_hs256(real, kid, _public_bytes(private.public_key(), encoding))

    assert tokens.verify_service_assertion(real, key_for=key_for) == claims

    caplog.set_level(logging.INFO, logger="ccure.tokens")
    assert tokens.verify_service_assertion(forged, key_for=key_for) is None
    (line,) = _refusal_lines(caplog)
    assert "reason=alg_mismatch" in line.getMessage()
