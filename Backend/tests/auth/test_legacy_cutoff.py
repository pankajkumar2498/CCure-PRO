"""
The legacy HS256 cut-off switch — Phase 9.6a.

``CCURE_ACCEPT_LEGACY_HS256`` decides whether HS256 tokens still verify. The
cut-off itself (9.6b) is flipping it to false once no HS256 session remains;
these tests prove, before that day, what the flip does and that it can be
undone:

* **off**: an HS256 token is refused on every path that reads a token —
  a protected route, a download ticket, both WebSocket logins, the rate-limit
  audit's caller identification, refresh and logout — and the api refuses to
  start with HS256 issuance selected, because it would issue tokens that are
  then refused;
* **ES256 is unaffected** on every one of those paths;
* **on again** (the rollback): the same HS256 tokens verify again, and HS256
  issuance — the 9.4 rollback — works.

HS256 tokens are minted through the HS256 issuance mode while the switch is on,
exactly as the tokens still in circulation were, and the switch is then turned
off. Tokens are minted directly, not through ``/auth/login``.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from jose import jwt as jose_jwt

from ccure_platform.identity import jwt_handler, tokens
from ccure_platform.identity.dependencies import get_current_user_flexible
from config import JWTConfig

KINDS = ("access", "refresh", "ticket", "mfa_challenge")


def _mint(user, kind, db):
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


@pytest.fixture
def minted(db_session, test_user, monkeypatch):
    """One token of each kind in each algorithm, all minted with the switch on."""
    assert JWTConfig.ACCEPT_LEGACY_HS256 is True
    made = {}
    monkeypatch.setattr(JWTConfig, "TOKEN_SIGNING_ALG", "HS256")
    for kind in KINDS:
        made[("HS256", kind)] = _mint(test_user, kind, db_session)
    monkeypatch.setattr(JWTConfig, "TOKEN_SIGNING_ALG", "ES256")
    for kind in KINDS:
        made[("ES256", kind)] = _mint(test_user, kind, db_session)
    for (alg, _), token in made.items():
        assert jose_jwt.get_unverified_header(token)["alg"] == alg
    return made


def _switch(monkeypatch, on: bool):
    monkeypatch.setattr(JWTConfig, "ACCEPT_LEGACY_HS256", on)


def _verify(token, kind):
    return tokens.verify(
        token, expected_kind=kind, issuer=tokens.ISSUER, audience=tokens.USER_AUDIENCE
    )


def _websocket(ticket):
    return SimpleNamespace(query_params={"ticket": ticket})


def _request_with_bearer(token):
    return SimpleNamespace(headers={"authorization": f"Bearer {token}"})


# ── each path, with the switch off and on ─────────────────────────────────────


def _route(client, token):
    return client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})


def _download(client, ticket):
    return client.get(f"/reports/download/scan_nonexistent?fmt=JSON&ticket={ticket}")


def _ws_scan_history(ticket):
    from routers.scan_history import _get_websocket_user

    return _get_websocket_user(_websocket(ticket))


def _ws_web_scans(ticket):
    from routers.web_scans import _get_websocket_user

    return _get_websocket_user(_websocket(ticket))


def _rate_limit_audit(token):
    from core.rate_limit_audit import _caller_identity

    return _caller_identity(_request_with_bearer(token))


@pytest.mark.parametrize("on", [False, True])
def test_a_protected_route(client, minted, monkeypatch, test_user, on):
    _switch(monkeypatch, on)
    hs = _route(client, minted[("HS256", "access")])
    assert hs.status_code == (200 if on else 401)
    if not on:
        assert hs.json()["detail"] == "Invalid or expired token"
    assert _route(client, minted[("ES256", "access")]).status_code == 200


@pytest.mark.parametrize("on", [False, True])
def test_a_download_ticket(client, db_session, minted, monkeypatch, test_user, on):
    _switch(monkeypatch, on)
    # Over HTTP: a refused ticket names the ticket; an accepted one gets past
    # authentication to the scan lookup.
    refused = "Invalid or expired download ticket."
    hs = _download(client, minted[("HS256", "ticket")])
    es = _download(client, minted[("ES256", "ticket")])
    assert (hs.json().get("detail") == refused) is (not on)
    assert es.json().get("detail") != refused
    # And through the dependency itself.
    if on:
        user = get_current_user_flexible(
            ticket=minted[("HS256", "ticket")], credentials=None, db=db_session
        )
        assert str(user.id) == str(test_user.id)
    else:
        with pytest.raises(HTTPException) as refusal:
            get_current_user_flexible(
                ticket=minted[("HS256", "ticket")], credentials=None, db=db_session
            )
        assert refusal.value.status_code == 401
    user = get_current_user_flexible(
        ticket=minted[("ES256", "ticket")], credentials=None, db=db_session
    )
    assert str(user.id) == str(test_user.id)


@pytest.mark.parametrize("login", [_ws_scan_history, _ws_web_scans])
@pytest.mark.parametrize("on", [False, True])
def test_both_websocket_logins(minted, monkeypatch, test_user, login, on):
    _switch(monkeypatch, on)
    if on:
        assert str(login(minted[("HS256", "ticket")]).id) == str(test_user.id)
    else:
        with pytest.raises(HTTPException) as refusal:
            login(minted[("HS256", "ticket")])
        assert refusal.value.status_code == 401
    assert str(login(minted[("ES256", "ticket")]).id) == str(test_user.id)


@pytest.mark.parametrize("on", [False, True])
def test_the_rate_limit_audit_decode(minted, monkeypatch, test_user, on):
    _switch(monkeypatch, on)
    expected = (str(test_user.id), str(test_user.org_id))
    hs = _rate_limit_audit(minted[("HS256", "access")])
    assert hs == (expected if on else (None, None))
    assert _rate_limit_audit(minted[("ES256", "access")]) == expected


@pytest.mark.parametrize("on", [False, True])
def test_refresh(db_session, minted, monkeypatch, on):
    _switch(monkeypatch, on)
    hs = jwt_handler.refresh_access_token(minted[("HS256", "refresh")], db_session)
    assert (hs is not None) is on
    es = jwt_handler.refresh_access_token(minted[("ES256", "refresh")], db_session)
    assert es is not None
    # Rotation always issues ES256, whichever era the refresh token was from.
    for rotated in filter(None, (hs, es)):
        assert jose_jwt.get_unverified_header(rotated["access_token"])["alg"] == "ES256"


def test_refresh_over_http_with_the_switch_off(client, minted, monkeypatch):
    _switch(monkeypatch, False)
    response = client.post(
        "/auth/refresh", json={"refresh_token": minted[("HS256", "refresh")]}
    )
    assert response.status_code == 401


@pytest.mark.parametrize("on", [False, True])
def test_logout(db_session, minted, monkeypatch, on):
    _switch(monkeypatch, on)
    # Off, an HS256 session cannot even be named, so logout revokes nothing —
    # and the token stays unusable, which is what matters.
    assert (
        jwt_handler.revoke_refresh_token(minted[("HS256", "refresh")], db_session) is on
    )
    assert (
        jwt_handler.refresh_access_token(minted[("HS256", "refresh")], db_session)
        is None
    )
    assert (
        jwt_handler.revoke_refresh_token(minted[("ES256", "refresh")], db_session)
        is True
    )


@pytest.mark.parametrize("on", [False, True])
def test_every_kind_through_verify_and_the_legacy_decode(minted, monkeypatch, on):
    _switch(monkeypatch, on)
    for kind in KINDS:
        assert (_verify(minted[("HS256", kind)], kind) is not None) is on, kind
        assert (
            jwt_handler.decode_token(minted[("HS256", kind)]) is not None
        ) is on, kind
        assert _verify(minted[("ES256", kind)], kind) is not None, kind
        assert jwt_handler.decode_token(minted[("ES256", kind)]) is not None, kind


def test_a_refusal_is_logged_as_legacy_disabled(caplog, minted, monkeypatch):
    _switch(monkeypatch, False)
    caplog.set_level(logging.INFO, logger="ccure.tokens")
    assert _verify(minted[("HS256", "access")], "access") is None
    assert "reason=legacy_disabled legacy=True" in caplog.text
    assert minted[("HS256", "access")] not in caplog.text


# ── issuance and start-up ─────────────────────────────────────────────────────


def test_hs256_issuance_is_refused_with_the_switch_off(monkeypatch):
    monkeypatch.setattr(JWTConfig, "TOKEN_SIGNING_ALG", "HS256")
    _switch(monkeypatch, False)
    with pytest.raises(tokens.SigningUnavailable, match="ACCEPT_LEGACY_HS256=false"):
        tokens.assert_signing_ready()
    with pytest.raises(tokens.SigningUnavailable):
        tokens.sign({"sub": "usr_x", "type": "access"}, jwt_handler.ACCESS_TOKEN_EXPIRE)


def test_es256_issuance_is_unaffected_by_the_switch(monkeypatch, test_user):
    _switch(monkeypatch, False)
    assert tokens.assert_signing_ready().startswith("ES256 with key ")
    token = jwt_handler.create_access_token(test_user.id, test_user.username)
    assert jose_jwt.get_unverified_header(token)["alg"] == "ES256"
    assert _verify(token, "access") is not None


def test_the_rollback_restores_hs256_issuance_and_verification(monkeypatch, test_user):
    """Switch on + CCURE_TOKEN_SIGNING_ALG=HS256: the 9.4 rollback works again."""
    _switch(monkeypatch, False)
    monkeypatch.setattr(JWTConfig, "TOKEN_SIGNING_ALG", "HS256")
    with pytest.raises(tokens.SigningUnavailable):
        tokens.assert_signing_ready()
    _switch(monkeypatch, True)
    assert tokens.assert_signing_ready().startswith("HS256")
    token = jwt_handler.create_access_token(test_user.id, test_user.username)
    assert jose_jwt.get_unverified_header(token) == {"alg": "HS256", "typ": "JWT"}
    assert _verify(token, "access") is not None


def test_the_api_refuses_to_start_with_hs256_issuance_and_the_switch_off(
    caplog, monkeypatch
):
    from main import app

    monkeypatch.setattr(JWTConfig, "TOKEN_SIGNING_ALG", "HS256")
    _switch(monkeypatch, False)
    caplog.set_level(logging.INFO, logger="ccure.security")
    with pytest.raises(tokens.SigningUnavailable):
        with TestClient(app):
            pass
    assert "Legacy HS256 verification: disabled (CCURE_ACCEPT_LEGACY_HS256=false)" in (
        caplog.text
    )
    assert "Refusing to start" in caplog.text


@pytest.mark.parametrize(
    "on, expected",
    [
        (True, "enabled (CCURE_ACCEPT_LEGACY_HS256=true)"),
        (False, "disabled (CCURE_ACCEPT_LEGACY_HS256=false)"),
    ],
)
def test_the_start_up_status_line(monkeypatch, on, expected):
    _switch(monkeypatch, on)
    assert tokens.legacy_verification_status() == expected


def _switch_as_configured(value: str | None) -> bool:
    """ACCEPT_LEGACY_HS256 as a fresh process configured this way sees it."""
    import os
    import subprocess
    import sys

    from testpaths import BACKEND_ROOT

    env = {k: v for k, v in os.environ.items() if k != "CCURE_ACCEPT_LEGACY_HS256"}
    env["SKIP_DOTENV_LOAD"] = "1"
    if value is not None:
        env["CCURE_ACCEPT_LEGACY_HS256"] = value
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from config import JWTConfig; print(JWTConfig.ACCEPT_LEGACY_HS256)",
        ],
        cwd=BACKEND_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    return result.stdout.strip().splitlines()[-1] == "True"


@pytest.mark.parametrize(
    "value, on",
    [
        (None, True),
        ("true", True),
        ("false", False),
        ("FALSE", False),
        (" false ", False),
    ],
)
def test_the_switch_defaults_to_on(value, on):
    """
    Unset, and anything but "false", keeps HS256 verifying — the safe side.
    Checked in a fresh process: reloading config here would split JWTConfig
    into two classes for every later test.
    """
    assert _switch_as_configured(value) is on


def test_service_tokens_are_unaffected_by_the_switch(monkeypatch):
    """9.5's service tokens are ES256 only; the switch concerns user tokens."""
    _switch(monkeypatch, False)
    token = tokens.sign_service_token(
        service_id="ir",
        audience=tokens.CORE_SERVICE_AUDIENCE,
        scopes=frozenset({"audit:findings:read"}),
        tenant="org_x",
    )
    assert jose_jwt.get_unverified_header(token)["alg"] == "ES256"
