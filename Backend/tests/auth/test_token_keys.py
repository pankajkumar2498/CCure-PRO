"""
Signing-key infrastructure, JWKS and dual verification — Phase 9.3.

These tests mint ES256 tokens themselves, with keysets built by the real
management tool, and pin how the platform *verifies* them. (Issuance switched to
ES256 in step 9.4; ``test_token_issuance.py`` covers that. Legacy HS256 tokens
are minted here through the HS256 issuance mode, which issues exactly what 9.3
did.)

* old HS256 tokens still verify (and the 9.1 characterisation suite is unchanged);
* keys are chosen by ``kid`` alone: unknown, missing, removed or wrong-key ``kid``s
  are refused; ``next``, ``active`` and ``retired`` keys verify;
* ``alg: none``, other algorithms, HS256 carrying a ``kid``, HS256 signed with the
  public key, and embedded-key headers are refused;
* issuer, audience, principal type and the required claims are enforced;
* the JWKS publishes exactly the public members of the verifying keys;
* a keyset that fails validation is refused as a whole, and HS256 carries on.
"""

from __future__ import annotations

import inspect
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jose import jwt as jose_jwt

from ccure_platform.identity import jwt_handler, keys, tokens
from scripts.security import manage_token_keys as tool


# ── fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def keyset_dir(tmp_path):
    """A keyset with one key in each verifying state."""
    for state in ("next", "active", "retired"):
        tool.generate(str(tmp_path), state, owner=None)
    return tmp_path


@pytest.fixture
def keyset(keyset_dir, monkeypatch):
    loaded = keys.load_keyset(str(keyset_dir))
    monkeypatch.setattr(tokens, "_keyset", loaded)
    return loaded


def _key(keyset, state):
    return keyset.in_state(state)[0]


def _pem(private_key) -> str:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _claims(user=None, kind="access", **overrides):
    now = datetime.now(timezone.utc)
    claims = {
        "iss": tokens.ISSUER,
        "aud": tokens.USER_AUDIENCE,
        "sub": str(user.id) if user else "usr_probe",
        "type": kind,
        "ptype": "user",
        "jti": uuid.uuid4().hex,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }
    if user is not None and kind in ("access", "mfa_challenge"):
        claims.update(
            role=user.role.name, org_id=str(user.org_id), username=user.username
        )
    for name, value in overrides.items():
        if value is None:
            claims.pop(name, None)
        else:
            claims[name] = value
    return claims


def _es256(key, claims, *, kid=None, headers=None, private_key=None):
    header = {"kid": key.kid if kid is None else kid}
    header.update(headers or {})
    return jose_jwt.encode(
        claims, _pem(private_key or key.private_key), algorithm="ES256", headers=header
    )


def _verify(token, kind="access"):
    return tokens.verify(
        token, expected_kind=kind, issuer=tokens.ISSUER, audience=tokens.USER_AUDIENCE
    )


# ── the contract ──────────────────────────────────────────────────────────────


def test_verify_requires_kind_issuer_and_audience():
    params = inspect.signature(tokens.verify).parameters
    for name in ("expected_kind", "issuer", "audience"):
        assert params[name].kind is inspect.Parameter.KEYWORD_ONLY, name
        assert params[name].default is inspect.Parameter.empty, name


def test_issuer_and_audience_are_the_owners_decisions():
    assert tokens.ISSUER == "https://ccurepro.cdac.in"
    assert tokens.USER_AUDIENCE == "urn:ccure:api"


# ── HS256 is unaffected ───────────────────────────────────────────────────────


@pytest.fixture
def legacy_issuance(monkeypatch):
    """Mint tokens as 9.3 did: CCURE_TOKEN_SIGNING_ALG=HS256, the rollback."""
    from config import JWTConfig

    monkeypatch.setattr(JWTConfig, "TOKEN_SIGNING_ALG", "HS256")


@pytest.mark.parametrize("kind", ["access", "refresh", "ticket", "mfa_challenge"])
def test_legacy_hs256_tokens_still_verify_with_a_keyset_loaded(
    keyset, legacy_issuance, db_session, test_user, kind
):
    role = test_user.role.name
    token = {
        "access": lambda: jwt_handler.create_access_token(
            test_user.id, test_user.username, role=role, org_id=test_user.org_id
        ),
        "refresh": lambda: jwt_handler.create_refresh_token(test_user.id, db_session),
        "ticket": lambda: jwt_handler.create_download_ticket(
            test_user.id, test_user.username
        ),
        "mfa_challenge": lambda: jwt_handler.create_mfa_challenge_token(
            test_user.id, test_user.username, role=role, org_id=test_user.org_id
        ),
    }[kind]()
    assert jose_jwt.get_unverified_header(token)["alg"] == "HS256"
    assert _verify(token, kind)["sub"] == str(test_user.id)
    assert jwt_handler.decode_token(token)["type"] == kind


def test_issuance_signs_with_the_active_key_of_a_rotating_keyset(keyset, test_user):
    """With next, active and retired keys loaded, only the active one signs."""
    access = jwt_handler.create_access_token(test_user.id, test_user.username)
    assert jose_jwt.get_unverified_header(access) == {
        "alg": "ES256",
        "kid": _key(keyset, "active").kid,
        "typ": "JWT",
    }


def test_turning_legacy_off_refuses_hs256(
    keyset, legacy_issuance, test_user, monkeypatch
):
    from config import JWTConfig

    token = jwt_handler.create_access_token(test_user.id, test_user.username)
    assert jose_jwt.get_unverified_header(token)["alg"] == "HS256"
    monkeypatch.setattr(JWTConfig, "ACCEPT_LEGACY_HS256", False)
    assert _verify(token) is None
    assert jwt_handler.decode_token(token) is None


# ── ES256 acceptance, by kid ──────────────────────────────────────────────────


@pytest.mark.parametrize("state", ["next", "active", "retired"])
def test_a_token_from_any_verifying_state_verifies(keyset, state):
    payload = _verify(_es256(_key(keyset, state), _claims()))
    assert payload and payload["sub"] == "usr_probe"


def test_an_es256_access_token_reaches_a_protected_route(client, keyset, test_user):
    token = _es256(_key(keyset, "active"), _claims(test_user))
    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["id"] == str(test_user.id)


def test_the_legacy_decode_accepts_es256_for_its_unchanged_callers(keyset):
    token = _es256(_key(keyset, "active"), _claims(kind="ticket"))
    assert jwt_handler.decode_token(token)["type"] == "ticket"


def test_verification_needs_only_the_published_public_key(keyset):
    """A verifier holding nothing but the JWKS can check a token."""
    jwk = next(
        k
        for k in tokens.public_jwks()["keys"]
        if k["kid"] == _key(keyset, "active").kid
    )
    token = _es256(_key(keyset, "active"), _claims())
    payload = jose_jwt.decode(
        token,
        jwk,
        algorithms=["ES256"],
        audience=tokens.USER_AUDIENCE,
        issuer=tokens.ISSUER,
    )
    assert payload["sub"] == "usr_probe"


# ── refusals ──────────────────────────────────────────────────────────────────


def _refusals(keyset):
    active = _key(keyset, "active")
    stranger = ec.generate_private_key(ec.SECP256R1())
    claims = _claims()
    public_pem = active.public_pem
    return {
        "unknown kid": _es256(active, claims, kid="not-a-known-kid"),
        "missing kid": jose_jwt.encode(
            claims, _pem(active.private_key), algorithm="ES256"
        ),
        "known kid, other key": _es256(active, claims, private_key=stranger),
        # Legacy-shaped (no iss/aud), so only the kid fence can refuse it.
        "HS256 with a kid": jose_jwt.encode(
            _claims(iss=None, aud=None),
            jwt_handler.SECRET_KEY,
            algorithm="HS256",
            headers={"kid": active.kid},
        ),
        "HS256 signed with the public key": _hmac_forged(claims, public_pem),
        "HS256 with the public key and its kid": _hmac_forged(
            claims, public_pem, kid=active.kid
        ),
        "ES384 header": _alg_swapped(_es256(active, claims), "ES384"),
        "RS256 header": _alg_swapped(_es256(active, claims), "RS256"),
        "alg none": _none_token(claims, active.kid),
        "jwk header": _es256(active, claims, headers={"jwk": active.public_jwk()}),
        "jku header": _es256(
            active, claims, headers={"jku": "https://evil.example/jwks.json"}
        ),
        "x5u header": _es256(
            active, claims, headers={"x5u": "https://evil.example/cert.pem"}
        ),
        "crit header": _es256(active, claims, headers={"crit": ["exp"]}),
        "wrong issuer": _es256(active, _claims(iss="https://evil.example")),
        "no issuer": _es256(active, _claims(iss=None)),
        "wrong audience": _es256(active, _claims(aud="urn:ccure:ir")),
        "no audience": _es256(active, _claims(aud=None)),
        "service principal": _es256(active, _claims(ptype="service")),
        "no principal type": _es256(active, _claims(ptype=None)),
        "no jti": _es256(active, _claims(jti=None)),
        "no nbf": _es256(active, _claims(nbf=None)),
        "no iat": _es256(active, _claims(iat=None)),
        "not yet valid": _es256(
            active,
            _claims(
                nbf=int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
            ),
        ),
        "expired": _es256(
            active,
            _claims(
                exp=int((datetime.now(timezone.utc) - timedelta(seconds=1)).timestamp())
            ),
        ),
        "wrong kind": _es256(active, _claims(kind="refresh")),
    }


def _hmac_forged(claims, secret: str, *, kid=None) -> str:
    """
    The key-confusion attack: HS256 keyed with the published public key.
    Forged by hand because python-jose refuses to build it.
    """
    import hashlib
    import hmac

    header = {"alg": "HS256", "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    signing_input = f"{_b64(header)}.{_b64(claims)}"
    digest = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    import base64

    return f"{signing_input}.{base64.urlsafe_b64encode(digest).rstrip(b'=').decode()}"


def _b64(obj) -> str:
    import base64

    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _none_token(claims, kid) -> str:
    return f"{_b64({'alg': 'none', 'typ': 'JWT', 'kid': kid})}.{_b64(claims)}."


def _alg_swapped(token: str, alg: str) -> str:
    header, body, signature = token.split(".")
    import base64

    decoded = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
    decoded["alg"] = alg
    return f"{_b64(decoded)}.{body}.{signature}"


def test_every_refusal_is_refused(keyset):
    for name, token in _refusals(keyset).items():
        assert _verify(token) is None, name


def test_the_legacy_decode_refuses_them_too(keyset):
    for name, token in _refusals(keyset).items():
        if name == "wrong kind":
            continue  # decode_token never checked the kind; its callers do
        assert jwt_handler.decode_token(token) is None, name


def test_a_protected_route_refuses_them_uniformly(client, keyset):
    for name, token in _refusals(keyset).items():
        response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401, name
        assert response.json()["detail"] == "Invalid or expired token", name


def test_without_a_keyset_es256_is_refused_and_hs256_is_not(
    test_user, monkeypatch, keyset_dir, legacy_issuance
):
    loaded = keys.load_keyset(str(keyset_dir))
    token = _es256(loaded.in_state("active")[0], _claims())
    monkeypatch.setattr(tokens, "_keyset", None)
    assert _verify(token) is None
    hs = jwt_handler.create_access_token(test_user.id, test_user.username)
    assert _verify(hs) is not None


# ── rotation states ───────────────────────────────────────────────────────────


def test_rotation_moves_keys_through_their_states(tmp_path, monkeypatch):
    old = tool.generate(str(tmp_path), "active", owner=None)
    new = tool.generate(str(tmp_path), "next", owner=None)

    def load():
        ks = keys.load_keyset(str(tmp_path))
        monkeypatch.setattr(tokens, "_keyset", ks)
        return ks

    ks = load()
    old_token = _es256(ks.verification_key(old), _claims())
    new_token = _es256(ks.verification_key(new), _claims())
    assert _verify(old_token) and _verify(new_token)  # next is pre-distributed

    tool.set_state(str(tmp_path), old, "retired")
    tool.set_state(str(tmp_path), new, "active")
    ks = load()
    assert [k.kid for k in ks.in_state("active")] == [new]
    assert _verify(old_token), "a retired key still verifies"

    tool.remove(str(tmp_path), old)
    load()
    assert _verify(old_token) is None, "a removed key no longer verifies"
    assert _verify(new_token)
    assert old not in {k["kid"] for k in tokens.public_jwks()["keys"]}


def test_the_tool_refuses_two_active_keys(tmp_path):
    tool.generate(str(tmp_path), "active", owner=None)
    with pytest.raises(keys.KeySetError):
        tool.generate(str(tmp_path), "active", owner=None)
    assert len(keys.load_keyset(str(tmp_path)).keys) == 1  # nothing half-written


def test_the_tool_refuses_to_remove_the_active_key(tmp_path):
    kid = tool.generate(str(tmp_path), "active", owner=None)
    with pytest.raises(keys.KeySetError):
        tool.remove(str(tmp_path), kid)


def test_private_key_files_are_owner_only(keyset_dir):
    import os
    import stat

    for pem in keyset_dir.glob("*.pem"):
        assert stat.S_IMODE(os.stat(pem).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(keyset_dir / keys.MANIFEST).st_mode) == 0o644


# ── keyset validation ─────────────────────────────────────────────────────────


def _rewrite(directory, mutate):
    path = directory / keys.MANIFEST
    manifest = json.loads(path.read_text())
    mutate(manifest)
    path.write_text(json.dumps(manifest))


@pytest.mark.parametrize(
    "name, mutate",
    [
        ("kid does not match the key", lambda m: m["keys"][0].update(kid="forged-kid")),
        ("unknown state", lambda m: m["keys"][0].update(state="primary")),
        ("wrong algorithm", lambda m: m["keys"][0].update(alg="RS256")),
        ("path traversal", lambda m: m["keys"][0].update(file="../../etc/passwd")),
        ("hidden file", lambda m: m["keys"][0].update(file=".secret.pem")),
        ("missing file", lambda m: m["keys"][0].update(file="absent.pem")),
        ("duplicate kid", lambda m: m["keys"].append(dict(m["keys"][0]))),
        ("two next keys", lambda m: [e.update(state="next") for e in m["keys"]]),
        ("wrong version", lambda m: m.update(version=2)),
        ("no keys", lambda m: m.update(keys=[])),
    ],
)
def test_an_invalid_keyset_is_refused_whole(keyset_dir, name, mutate):
    _rewrite(keyset_dir, mutate)
    with pytest.raises(keys.KeySetError):
        keys.load_keyset(str(keyset_dir))


@pytest.mark.parametrize("wrong", ["rsa", "p384"])
def test_only_p256_keys_are_accepted(tmp_path, wrong):
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if wrong == "rsa"
        else ec.generate_private_key(ec.SECP384R1())
    )
    (tmp_path / "k.pem").write_text(_pem(key))
    (tmp_path / keys.MANIFEST).write_text(
        json.dumps(
            {
                "version": 1,
                "keys": [
                    {"kid": "x", "alg": "ES256", "state": "active", "file": "k.pem"}
                ],
            }
        )
    )
    with pytest.raises(keys.KeySetError):
        keys.load_keyset(str(tmp_path))


def test_a_refused_keyset_leaves_asymmetric_verification_off(keyset_dir, monkeypatch):
    from config import JWTConfig

    _rewrite(keyset_dir, lambda m: m["keys"][0].update(kid="forged-kid"))
    monkeypatch.setattr(JWTConfig, "TOKEN_KEYS_DIR", str(keyset_dir))
    monkeypatch.setattr(tokens, "_keyset", tokens._KEYSET_UNLOADED)
    assert tokens.public_jwks() is None
    assert tokens.keyset_status().startswith("refused:")


# ── JWKS ──────────────────────────────────────────────────────────────────────


def test_jwks_publishes_exactly_the_public_members(client, keyset):
    response = client.get("/auth/jwks.json")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "public, max-age=300"
    published = response.json()
    assert set(published) == {"keys"}
    assert {k["kid"] for k in published["keys"]} == {k.kid for k in keyset.keys}
    for jwk in published["keys"]:
        assert set(jwk) == {"kty", "crv", "x", "y", "kid", "alg", "use"}
        assert (jwk["kty"], jwk["crv"], jwk["alg"], jwk["use"]) == (
            "EC",
            "P-256",
            "ES256",
            "sig",
        )
        assert not keys.PRIVATE_JWK_MEMBERS & set(jwk)
    text = response.text
    for key in keyset.keys:
        private_value = key.private_key.private_numbers().private_value
        assert str(private_value) not in text


def test_jwks_answers_503_when_no_keyset_is_configured(client, monkeypatch):
    monkeypatch.setattr(tokens, "_keyset", None)
    response = client.get("/auth/jwks.json")
    assert response.status_code == 503
    assert response.json()["detail"] == "Token signing keys are not configured."


def test_jwks_is_public_and_rate_limited():
    from core.rate_limiter import limiter

    assert limiter._route_limits.get(
        "auth.router.jwks"
    ), "no per-route limit on /auth/jwks.json"


def test_a_signing_key_never_reaches_a_repr(keyset):
    for key in keyset.keys:
        assert "PRIVATE" not in repr(key)
        assert "private_key" not in repr(key)
