"""
Parity with the application's own dependencies — the real ones, not copies.

A FastAPI app is built around the core's ``get_current_auth_context`` (strict
bearer) and ``get_current_user_flexible`` (ticket-or-bearer), with only the
database load replaced. Every combination of Authorization header and query
string is sent to it and given to the checker; status and message must match.
The query string handed to the checker is the one the application actually
received, captured from the ASGI scope, so the comparison includes the
client's encoding exactly as nginx's ``$args`` would pass it.

The WebSocket logins need a database and a permission lookup, so their parity
is pinned at the two points the checker reproduces: Starlette's query parsing,
and ``decode_any_kind`` + ``type == "ticket"`` + ``sub``.
"""

from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import quote

import pytest

from token_check.checker import REFUSALS, decide, last_ticket


@pytest.fixture
def app_and_checker(monkeypatch):
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    from ccure_platform.identity import dependencies, keys as keymod, tokens, verification
    from conftest import Mint

    mint = Mint(issuer=tokens.ISSUER, audience=tokens.USER_AUDIENCE)
    keyset = keymod.KeySet(keys=(keymod.SigningKey(kid=mint.kid, state="active", alg="ES256",
                                                   private_key=mint.key),))
    monkeypatch.setattr(tokens, "_keyset", keyset)
    user = SimpleNamespace(id="usr_gw")
    monkeypatch.setattr(dependencies, "_load_auth_context_from_payload",
                        lambda payload, db: SimpleNamespace(user=user, user_id="usr_gw"))

    app = FastAPI()
    seen = {}

    @app.middleware("http")
    async def capture(request, call_next):
        seen["query"] = request.scope.get("query_string", b"")
        return await call_next(request)

    app.dependency_overrides[dependencies.get_db] = lambda: None

    @app.get("/strict")
    def strict(ctx=Depends(dependencies.get_current_auth_context)):
        return {"ok": True}

    @app.get("/flexible")
    def flexible(user=Depends(dependencies.get_current_user_flexible)):
        return {"ok": True}

    from token_check.jwks import JwksKeySource

    source = JwksKeySource("http://jwks.test", max_age=300, min_refetch=30,
                           fetch=lambda url: {"keys": [k.public_jwk() for k in keyset.keys]})
    assert source.refresh()

    def gw_verify(token, kind):
        return verification.verify(token, expected_kind=kind, issuer=tokens.ISSUER,
                                   audience=tokens.USER_AUDIENCE, keyset=lambda: source)

    return TestClient(app, raise_server_exceptions=True), seen, gw_verify, mint


def _app_result(response):
    if response.status_code == 200:
        return "allowed"
    body = response.json()
    return (response.status_code, body.get("detail"))


def _gw_result(decision):
    if decision.allowed:
        return "allowed"
    return REFUSALS[decision.code]


def _auth_variants(m):
    return {
        "absent": None,
        "empty": "",
        "scheme only": "Bearer",
        "scheme and space": "Bearer ",
        "leading space": " Bearer x",
        "basic": "Basic dXNlcjpwYXNz",
        "lower bearer valid": f"bearer {m.token()}",
        "upper bearer valid": f"BEARER {m.token()}",
        "valid": f"Bearer {m.token()}",
        "double space valid": f"Bearer  {m.token()}",
        "garbage": "Bearer not-a-token",
        "ticket as bearer": f"Bearer {m.token('ticket')}",
        "refresh as bearer": f"Bearer {m.token('refresh')}",
        "service token": f"Bearer {m.token('service_access')}",
        "expired": f"Bearer {m.expired()}",
        "legacy": f"Bearer {m.legacy()}",
        "unknown kid": f"Bearer {m.token(kid='kid-x')}",
    }


def _query_variants(m):
    good = m.token("ticket")
    return {
        "none": "",
        "empty ticket": "ticket=",
        "bare ticket": "ticket",
        "valid ticket": f"ticket={good}",
        "garbage ticket": "ticket=not-a-token",
        "access as ticket": f"ticket={m.token()}",
        "expired ticket": f"ticket={m.expired('ticket')}",
        "last wins good": f"ticket=garbage&ticket={good}",
        "last wins bad": f"ticket={good}&ticket=garbage",
        "percent encoded": "ticket=" + quote(good, safe=""),
        "among others": f"a=1&ticket={good}&b=%20",
        "plus in value": "ticket=a+b",
    }


@pytest.mark.parametrize("route,policy", [("/strict", "bearer"), ("/flexible", "ticket_or_bearer")])
def test_every_header_and_query_combination_matches_the_application(app_and_checker, route, policy):
    client, seen, gw_verify, m = app_and_checker
    mismatches, compared = [], 0
    for a_name, auth in _auth_variants(m).items():
        for q_name, query in _query_variants(m).items():
            headers = {} if auth is None else {"Authorization": auth}
            response = client.get(route + ("?" + query if query else ""), headers=headers)
            app = _app_result(response)
            gw = _gw_result(decide(policy=policy, method="GET", authorization=auth,
                                   raw_query=seen["query"], verify=gw_verify))
            compared += 1
            if app != gw:
                mismatches.append(f"{route} auth={a_name!r} query={q_name!r}: app {app}, gateway {gw}")
    assert compared == len(_auth_variants(m)) * len(_query_variants(m))
    assert not mismatches, "\n".join(mismatches)


@pytest.mark.parametrize("raw", [
    b"", b"ticket", b"ticket=", b"ticket=a", b"ticket=a&ticket=b", b"ticket=%41%42",
    b"ticket=a+b", b"x=1;ticket=2", b"ticket=%zz", b"TICKET=a", b"ticket=\xe9", b"&&ticket=z&&",
])
def test_ticket_extraction_is_starlettes(raw):
    from starlette.datastructures import QueryParams

    assert last_ticket(raw) == (QueryParams(raw).get("ticket") or "")


def test_ws_acceptance_equals_decode_any_kind_plus_type_and_sub(app_and_checker):
    """What routers.scan_history / web_scans accept, before their DB checks."""
    from ccure_platform.identity import tokens

    _, _, gw_verify, m = app_and_checker
    candidates = [m.token("ticket"), m.token(), m.token("refresh"), m.token("mfa_challenge"),
                  m.token("service_access"), m.expired("ticket"), m.legacy("ticket"),
                  m.token("ticket", sub=""), m.token("ticket", kid="kid-x"), "garbage", ""]
    for token in candidates:
        payload = tokens.decode_any_kind(token) if token else None
        app_accepts = bool(payload) and payload.get("type") == "ticket" and bool(payload.get("sub"))
        d = decide(policy="ticket", method="GET", authorization=None,
                   raw_query=("ticket=" + token).encode(), verify=gw_verify)
        assert d.allowed == app_accepts, token[:40]
