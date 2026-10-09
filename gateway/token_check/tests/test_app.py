"""The ASGI service nginx calls: responses, readiness, failure modes, logging."""

from __future__ import annotations

import logging
import re

import pytest
from starlette.testclient import TestClient

from token_check import app as app_module
from token_check.app import GatewayAuth
from token_check.jwks import JwksKeySource


def _check(client, policy, auth=None, query="", method="GET"):
    headers = {"X-Ccure-Policy": policy, "X-Ccure-Method": method, "X-Ccure-Args": query}
    if auth is not None:
        headers["Authorization"] = auth
    return client.get("/check", headers=headers)


@pytest.fixture
def client(settings, keys):
    return TestClient(GatewayAuth(settings, keys))


def test_allowed_is_204_with_the_principal_and_no_body(client, mint):
    r = _check(client, "bearer", f"Bearer {mint.token()}")
    assert r.status_code == 204 and r.content == b""
    assert r.headers["x-ccure-auth-sub"] == "usr_gw"
    assert r.headers["x-ccure-auth-kind"] == "access"
    assert r.headers["x-ccure-auth-ptype"] == "user"
    assert r.headers["x-ccure-auth-jti"]
    assert "x-ccure-refusal" not in r.headers
    assert r.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("policy,auth,query,status,code", [
    ("bearer", None, "", 403, "missing_bearer"),
    ("bearer", "Basic x", "", 403, "non_bearer_scheme"),
    ("bearer", "Bearer garbage", "", 401, "invalid_bearer"),
    ("ticket_or_bearer", None, "", 401, "missing_flexible"),
    ("ticket_or_bearer", None, "ticket=garbage", 401, "invalid_ticket"),
    ("ticket", None, "", 403, "ws_refused"),
])
def test_refusals_carry_status_and_code_only(client, policy, auth, query, status, code):
    r = _check(client, policy, auth, query)
    assert r.status_code == status and r.content == b""
    assert r.headers["x-ccure-refusal"] == code
    assert not any(h.startswith("x-ccure-auth-") for h in r.headers)
    assert "www-authenticate" not in r.headers  # X2-a


def test_options_and_none_pass_without_reading_a_credential(client):
    for r in (_check(client, "bearer", "Bearer garbage", method="OPTIONS"),
              _check(client, "none", "Bearer garbage")):
        assert r.status_code == 204
        assert not any(h.startswith("x-ccure-") for h in r.headers)  # no principal named


def test_unknown_policy_is_a_500_so_nginx_fails_closed(client):
    for policy in ("", "unrouted", "BEARER"):
        assert _check(client, policy, "Bearer x").status_code == 500


def test_no_key_set_refuses_everything_that_needs_one(settings, mint):
    empty = JwksKeySource("http://x", max_age=300, min_refetch=30, fetch=lambda u: {"keys": []})
    client = TestClient(GatewayAuth(settings, empty))
    assert client.get("/healthz").status_code == 503
    assert _check(client, "bearer", f"Bearer {mint.token()}").status_code == 503
    assert _check(client, "ticket", query=f"ticket={mint.token('ticket')}").status_code == 503
    assert _check(client, "none").status_code == 204  # public routes do not need keys


def test_an_internal_error_is_a_500_never_a_pass(client, monkeypatch, mint):
    def boom(**_):
        raise RuntimeError("bug")

    monkeypatch.setattr(app_module.checker, "decide", boom)
    assert _check(client, "bearer", f"Bearer {mint.token()}").status_code == 500


def test_readiness(client):
    assert client.get("/healthz").status_code == 200


@pytest.mark.parametrize("method,path", [("GET", "/"), ("POST", "/check"), ("GET", "/check/x"),
                                         ("DELETE", "/healthz"), ("GET", "/docs")])
def test_nothing_else_is_served(client, method, path):
    assert client.request(method, path).status_code == 404


def test_lifespan_loads_the_key_set(settings, mint):
    source = JwksKeySource("http://x", max_age=300, min_refetch=30, fetch=lambda u: mint.jwks())
    with TestClient(GatewayAuth(settings, source)) as client:
        for _ in range(100):
            if client.get("/healthz").status_code == 200:
                break
        assert client.get("/healthz").status_code == 200


def test_first_authorization_header_wins_as_in_starlette(client, mint):
    r = client.get("/check", headers=[("X-Ccure-Policy", "bearer"), ("X-Ccure-Method", "GET"),
                                      ("Authorization", f"Bearer {mint.token()}"),
                                      ("Authorization", "Bearer garbage")])
    assert r.status_code == 204


def test_logs_never_carry_a_credential_or_the_query(client, mint, caplog):
    caplog.set_level(logging.DEBUG)
    secrets_sent = [mint.token(), mint.token("ticket"), mint.expired(), mint.legacy()]
    for token in secrets_sent:
        _check(client, "bearer", f"Bearer {token}")
        _check(client, "ticket_or_bearer", None, f"ticket={token}&x=SECRETQUERY")
        _check(client, "ticket", "Bearer " + token, f"ticket={token}")
    _check(client, "bearer", "Bearer not-a-token-SECRETGARBAGE")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "check refused" in text  # refusals are logged…
    for token in secrets_sent:  # …without the token, its signature or its payload
        for part in token.split("."):
            if len(part) > 8:
                assert part not in text
    assert "SECRETQUERY" not in text and "SECRETGARBAGE" not in text
    assert not re.search(r"eyJ[\w-]{10,}", text)
    assert "Bearer" not in text
