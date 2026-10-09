"""
Native authentication end to end: ES256 tokens, native RBAC, and no JWT secret.

Phase 9, before the legacy HS256 mechanism is removed and after the workers lost the
secret. One flow through the real app (login, a protected call, refresh, logout) with
the legacy secret made unusable, plus what must be refused: a forged HS256 token, a
tampered one, an expired one, the wrong kind of token, no token.

The platform holds no JWT secret at all (conftest removes it from the environment), so
the flow below could not pass if anything still needed one.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from jose import jwt as jose_jwt

from ccure_platform.identity import tokens


def _login(client):
    r = client.post(
        "/auth/login", json={"email": "admin@test.com", "password": "securepassword123"}
    )
    assert r.status_code == 200, r.text
    return r


def test_login_issues_es256_with_a_kid_and_the_platform_claims(client, test_user):
    token = _login(client).json()["access_token"]
    header = jose_jwt.get_unverified_header(token)
    claims = jose_jwt.get_unverified_claims(token)
    assert header["alg"] == "ES256" and header.get("kid")
    assert claims["iss"] == tokens.ISSUER and claims["aud"] == tokens.USER_AUDIENCE
    assert claims["ptype"] == "user" and claims["type"] == "access" and claims["jti"]


def test_a_protected_call_answers_from_native_rbac_with_no_legacy_identity(
    client, test_user
):
    token = _login(client).json()["access_token"]
    me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    body = me.json()
    assert body["authorization"]["permissions"], "native permission keys expected"
    flat = str(body)
    assert "role_id" not in flat


def test_refresh_and_logout_work_and_a_revoked_session_stops_refreshing(
    client, test_user
):
    _login(client)
    refreshed = client.post("/auth/refresh")
    assert refreshed.status_code == 200
    assert (
        jose_jwt.get_unverified_header(refreshed.json()["access_token"])["alg"]
        == "ES256"
    )
    assert client.post("/auth/logout").status_code in (200, 204)
    assert client.post("/auth/refresh").status_code == 401


@pytest.mark.parametrize(
    "secret", ["x-not-the-real-secret-x", "dev-secret-key-change-in-production"]
)
def test_a_forged_hs256_token_is_refused_whatever_secret_signed_it(
    client, test_user, secret
):
    forged = jose_jwt.encode(
        {"sub": test_user.id, "type": "access", "username": test_user.username},
        secret,
        algorithm="HS256",
    )
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401


def test_a_tampered_token_is_refused(client, test_user):
    token = _login(client).json()["access_token"]
    head, body, sig = token.split(".")
    tampered = ".".join([head, body[:-2] + ("AA" if body[-2:] != "AA" else "BB"), sig])
    assert (
        client.get(
            "/auth/me", headers={"Authorization": f"Bearer {tampered}"}
        ).status_code
        == 401
    )


def test_an_expired_token_is_refused(client, test_user):
    expired = tokens.sign(
        {"sub": test_user.id, "type": "access", "username": test_user.username},
        timedelta(seconds=-30),
    )
    assert (
        client.get(
            "/auth/me", headers={"Authorization": f"Bearer {expired}"}
        ).status_code
        == 401
    )


def test_a_refresh_token_is_not_an_access_token(client, test_user):
    _login(client)
    refresh_cookie = client.cookies.get("refresh_token")
    if not refresh_cookie:
        pytest.skip("refresh cookie is not readable by the test client here")
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {refresh_cookie}"})
    assert r.status_code == 401


def test_no_token_and_a_garbage_token_are_refused(client):
    assert client.get("/auth/me").status_code in (401, 403)
    assert (
        client.get(
            "/auth/me", headers={"Authorization": "Bearer not-a-token"}
        ).status_code
        == 401
    )
