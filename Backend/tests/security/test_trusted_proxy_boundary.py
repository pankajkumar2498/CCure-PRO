"""
Phase 10.3 — the proxy trust boundary (finding F10-1).

The API used to run uvicorn with ``--forwarded-allow-ips='*'``: every caller of
``:8000`` could set its own client address (the rate-limit key and the audit
address) and its own scheme. Phase 10.1 proved it live. Now uvicorn runs with
``--no-proxy-headers`` and ``core.trusted_proxy.TrustedProxyHeadersMiddleware``
resolves both, for peers in ``AppConfig.TRUSTED_PROXIES`` only.

Pinned here:
* a trusted proxy (host nginx arrives as 172.18.0.1; the gateway by its fixed
  address) still forwards the client address and scheme;
* an untrusted caller — a LAN client, a container on the compose network,
  anything else — cannot forge the client address or HTTPS, by any header;
* the rate-limit key, ``request.client``, HSTS and absolute URLs all follow the
  one resolved answer;
* the configuration cannot drift back: start.sh, middleware order, the default
  trust set.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re

import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse

from core import ip_resolver
from core.trusted_proxy import TrustedProxyHeadersMiddleware
from testpaths import BACKEND_ROOT

TRUSTED = "172.18.0.1"  # host nginx through docker-proxy on the live compose network
UNTRUSTED = [
    "10.180.6.50",
    "203.0.113.7",
    "172.18.0.8",
    "172.18.0.5",
    "::ffff:10.0.0.1",
]
FORGED = {
    "x-forwarded-for": "8.8.8.8",
    "x-real-ip": "9.9.9.9",
    "x-forwarded-proto": "https",
}


def _scope(peer, headers=None, kind="http"):
    return {
        "type": kind,
        "scheme": "ws" if kind == "websocket" else "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "root_path": "",
        "method": "GET",
        "server": ("testserver", 8000),
        "client": (peer, 45678) if peer else None,
        "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()]
        + [(b"host", b"api.test")],
    }


def _through(scope):
    seen = {}

    async def inner(s, receive, send):
        seen.update(s)

    asyncio.run(TrustedProxyHeadersMiddleware(inner)(scope, None, None))
    return seen


# ── the middleware ───────────────────────────────────────────────────────────


def test_a_trusted_proxy_forwards_the_client_and_the_scheme():
    seen = _through(
        _scope(
            TRUSTED, {"x-forwarded-for": "10.180.6.30", "x-forwarded-proto": "https"}
        )
    )
    assert seen["client"] == ("10.180.6.30", 0) and seen["scheme"] == "https"


def test_a_trusted_proxy_x_real_ip_alone_is_honoured():
    seen = _through(_scope(TRUSTED, {"x-real-ip": "10.180.6.30"}))
    assert seen["client"][0] == "10.180.6.30"


@pytest.mark.parametrize("peer", UNTRUSTED)
def test_an_untrusted_peer_cannot_forge_the_client_address_or_https(peer):
    seen = _through(_scope(peer, FORGED))
    assert seen["client"] == (peer, 45678)
    assert seen["scheme"] == "http"


@pytest.mark.parametrize("peer", UNTRUSTED)
def test_an_untrusted_peer_cannot_forge_wss(peer):
    seen = _through(_scope(peer, FORGED, kind="websocket"))
    assert seen["client"] == (peer, 45678) and seen["scheme"] == "ws"


def test_a_trusted_proxy_upgrades_a_websocket_to_wss():
    seen = _through(
        _scope(
            TRUSTED,
            {"x-forwarded-for": "10.180.6.30", "x-forwarded-proto": "https"},
            "websocket",
        )
    )
    assert seen["scheme"] == "wss" and seen["client"][0] == "10.180.6.30"


def test_an_appended_chain_resolves_to_the_rightmost_untrusted_hop():
    seen = _through(_scope(TRUSTED, {"x-forwarded-for": "8.8.8.8, 198.51.100.10"}))
    assert seen["client"][0] == "198.51.100.10"


@pytest.mark.parametrize(
    "proto,scheme",
    [
        ("https, http", "https"),
        ("HTTPS", "https"),
        ("http", "http"),
        ("ftp", "http"),
        ("https;evil", "http"),
        ("", "http"),
    ],
)
def test_only_http_and_https_are_accepted_as_a_scheme(proto, scheme):
    seen = _through(_scope(TRUSTED, {"x-forwarded-proto": proto} if proto else {}))
    assert seen["scheme"] == scheme


def test_a_trusted_proxy_without_forwarding_headers_changes_nothing():
    scope = _scope(TRUSTED)
    assert _through(scope) == scope


def test_a_garbage_forwarded_address_falls_back_to_the_peer():
    seen = _through(_scope(TRUSTED, {"x-forwarded-for": "not-an-ip"}))
    assert seen["client"][0] == TRUSTED


def test_lifespan_and_unknown_scopes_pass_untouched():
    scope = {"type": "lifespan"}
    assert _through(scope) == scope


# ── the real application: rate-limit key, HSTS, absolute URLs ───────────────


def _with_peer(asgi_app, peer):
    async def shim(scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            scope = {**scope, "client": (peer, 45678)}
        await asgi_app(scope, receive, send)

    return shim


def _probe_app():
    """A minimal app behind the middleware, reporting what the application sees."""
    from core.rate_limiter import _rate_limit_key

    async def app(scope, receive, send):
        request = Request(scope, receive)
        body = {
            "client": request.client.host,
            "resolved": ip_resolver.get_client_ip(request),
            "rate_key": _rate_limit_key(request),
            "scheme": request.url.scheme,
            "url": str(request.url),
        }
        await JSONResponse(body)(scope, receive, send)

    return TrustedProxyHeadersMiddleware(app)


def _client(peer):
    from starlette.testclient import TestClient

    return TestClient(_with_peer(_probe_app(), peer))


def test_rate_limit_key_audit_address_and_client_agree_for_a_trusted_proxy():
    seen = (
        _client(TRUSTED)
        .get(
            "/",
            headers={
                "X-Forwarded-For": "10.180.6.30",
                "X-Real-IP": "10.180.6.30",
                "X-Forwarded-Proto": "https",
            },
        )
        .json()
    )
    assert seen["client"] == seen["resolved"] == seen["rate_key"] == "10.180.6.30"
    assert seen["scheme"] == "https" and seen["url"].startswith("https://")


@pytest.mark.parametrize("peer", UNTRUSTED)
def test_rate_limit_key_cannot_be_forged_by_an_untrusted_caller(peer):
    seen = (
        _client(peer)
        .get(
            "/",
            headers={
                "X-Forwarded-For": "8.8.8.8",
                "X-Real-IP": "9.9.9.9",
                "X-Forwarded-Proto": "https",
            },
        )
        .json()
    )
    assert seen["client"] == seen["resolved"] == seen["rate_key"] == peer
    assert seen["scheme"] == "http" and seen["url"].startswith("http://")


def test_two_clients_behind_the_proxy_get_two_buckets():
    a = (
        _client(TRUSTED)
        .get("/", headers={"X-Forwarded-For": "10.180.6.30"})
        .json()["rate_key"]
    )
    b = (
        _client(TRUSTED)
        .get("/", headers={"X-Forwarded-For": "10.180.6.31"})
        .json()["rate_key"]
    )
    assert a != b


def test_the_application_sends_hsts_only_for_a_trusted_https_scheme():
    from starlette.testclient import TestClient

    from main import app

    trusted = TestClient(_with_peer(app, TRUSTED)).get(
        "/", headers={"X-Forwarded-Proto": "https"}
    )
    forged = TestClient(_with_peer(app, "10.180.6.50")).get(
        "/", headers={"X-Forwarded-Proto": "https"}
    )
    assert trusted.headers.get("strict-transport-security") == "max-age=300"
    assert "strict-transport-security" not in forged.headers


def test_application_generated_absolute_urls_follow_the_resolved_scheme():
    """The trailing-slash redirect is built from the request's scheme and host."""
    from starlette.testclient import TestClient

    from main import app

    headers = {"X-Forwarded-Proto": "https", "Host": "ccurepro.cdac.in"}
    trusted = TestClient(_with_peer(app, TRUSTED), follow_redirects=False).get(
        "/scans/", headers=headers
    )
    forged = TestClient(_with_peer(app, "10.180.6.50"), follow_redirects=False).get(
        "/scans/", headers=headers
    )
    assert trusted.status_code == forged.status_code == 307
    assert trusted.headers["location"] == "https://ccurepro.cdac.in/scans"
    assert forged.headers["location"] == "http://ccurepro.cdac.in/scans"


# ── the configuration cannot drift back ──────────────────────────────────────


def test_uvicorn_trusts_no_forwarding_header_itself():
    start = (BACKEND_ROOT / "start.sh").read_text()
    commands = [line for line in start.splitlines() if "exec uvicorn" in line]
    assert len(commands) == 2
    for command in commands:
        assert "--no-proxy-headers" in command
        assert "--proxy-headers" not in command.replace("--no-proxy-headers", "")
        assert "forwarded-allow-ips" not in command


def test_the_trust_middleware_is_outermost():
    from main import app

    assert app.user_middleware[0].cls is TrustedProxyHeadersMiddleware
    assert sum(m.cls is TrustedProxyHeadersMiddleware for m in app.user_middleware) == 1


def test_the_default_trust_set_names_exact_peers_only():
    source = (BACKEND_ROOT / "config.py").read_text()
    default = re.search(r'os\.getenv\("TRUSTED_PROXIES", "([^"]+)"\)', source).group(1)
    entries = [e.strip() for e in default.split(",")]
    assert entries == ["127.0.0.1", "::1", "172.18.0.1"]
    for entry in entries:
        assert ipaddress.ip_network(entry).num_addresses == 1, entry


def test_the_start_up_trust_log_raises_no_width_warning():
    assert ip_resolver.log_trust_boundary() == []
