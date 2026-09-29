"""
Fixtures for the gateway-auth tests.

Run in a disposable container built from the core's image (it has pytest,
FastAPI and Starlette, which the parity tests use as the oracle), with the
repository mounted read-only and no network:

    docker run --rm --network none \
      -v "$PWD/gateway":/gateway:ro -v "$PWD/Backend":/backend:ro -v "$PWD/docs":/docs:ro \
      -e PYTHONPATH=/gateway:/backend -e PYTHONDONTWRITEBYTECODE=1 \
      -e CCURE_ACCEPT_LEGACY_HS256=false -w /gateway \
      ccure-audit-pro-backend:latest python -m pytest -q -p no:cacheprovider token_check/tests

Every key and token here is generated at run time and thrown away.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jose import jwt

ISSUER = "https://issuer.gateway-auth.test"
AUDIENCE = "urn:ccure:api"


def _pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwk_of(kid: str, private_key) -> dict:
    n = private_key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid,
            "x": _b64(n.x.to_bytes(32, "big")), "y": _b64(n.y.to_bytes(32, "big"))}


class Mint:
    """Throwaway keys and a token factory for one issuer/audience."""

    def __init__(self, issuer=ISSUER, audience=AUDIENCE):
        self.issuer, self.audience = issuer, audience
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.kid = "kid-" + secrets.token_hex(4)
        self.other = ec.generate_private_key(ec.SECP256R1())
        self.legacy_secret = secrets.token_hex(32)

    def jwks(self) -> dict:
        return {"keys": [jwk_of(self.kid, self.key)]}

    def token(self, kind="access", *, kid=None, key=None, **over) -> str:
        now = datetime.now(timezone.utc)
        svc = kind == "service_access"
        claims = {"iss": self.issuer, "aud": "urn:ccure:core" if svc else self.audience,
                  "sub": "svc:alpha" if svc else "usr_gw", "type": kind,
                  "ptype": "service" if svc else "user", "jti": secrets.token_urlsafe(8),
                  "iat": now - timedelta(seconds=5), "nbf": now - timedelta(seconds=5),
                  "exp": now + timedelta(minutes=5)}
        for k, v in over.items():
            if v is None:
                claims.pop(k, None)
            else:
                claims[k] = v
        return jwt.encode(claims, _pem(key or self.key), algorithm="ES256",
                          headers={"kid": kid or self.kid})

    def expired(self, kind="access") -> str:
        past = datetime.now(timezone.utc) - timedelta(hours=2)
        return self.token(kind, iat=past, nbf=past, exp=past + timedelta(minutes=5))

    def legacy(self, kind="access") -> str:
        return jwt.encode({"sub": "usr_gw", "type": kind,
                           "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
                          self.legacy_secret, algorithm="HS256")


@pytest.fixture
def mint():
    return Mint()


@pytest.fixture
def keys(mint):
    from token_check.jwks import JwksKeySource

    source = JwksKeySource("http://jwks.test/keys", max_age=300, min_refetch=30,
                           fetch=lambda url: mint.jwks())
    assert source.refresh()
    return source


@pytest.fixture
def settings():
    from token_check.config import Settings

    return Settings(issuer=ISSUER, user_audience=AUDIENCE, jwks_url="http://jwks.test/keys")


@pytest.fixture
def verify(settings, keys):
    from ccure_platform.identity import verification

    def _verify(token, kind):
        return verification.verify(token, expected_kind=kind, issuer=settings.issuer,
                                   audience=settings.user_audience, keyset=lambda: keys, legacy=None)

    return _verify


def matrix_path():
    for candidate in ("/docs/architecture/phase10/route_auth_matrix.json",
                      os.path.join(os.path.dirname(__file__), "..", "..", "..", "docs",
                                   "architecture", "phase10", "route_auth_matrix.json")):
        if os.path.exists(candidate):
            return candidate
    return None


def load_matrix():
    path = matrix_path()
    if path is None:
        pytest.skip("route_auth_matrix.json is not mounted")
    with open(path) as fh:
        return json.load(fh)
