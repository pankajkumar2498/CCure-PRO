"""
Phase 10.7 — the frontend container's own /api/ path goes through the gateway.

Before 10.7, 127.0.0.1:3200/api/ reached the api directly (frontend nginx →
api:8000), skipping gateway-auth, and appended the caller's X-Forwarded-For.
Now it runs the committed Frontend/nginx.conf, which proxies /api/ to the
gateway over TCP. The gateway trusts no TCP peer (10.6), so:

* the request reaches the application through the gateway, /api prefix and all;
* the client the application sees is the frontend container, whatever the
  caller forged, and the scheme is http;
* the API's own resolution rule keys the rate limit on the frontend container.
"""

from __future__ import annotations

import http.client
import json

import pytest

from test_trust_boundary import FORGED, GATEWAY_IP, ROUTE, _key, resolver  # noqa: F401  (fixture)

FRONTEND = ("frontend", 80)
FRONTEND_IP = "10.254.40.30"


def via_frontend(headers, path=ROUTE):
    c = http.client.HTTPConnection(*FRONTEND, timeout=10)
    c.request("GET", path, headers={"Host": "127.0.0.1:3200", **headers})
    r = c.getresponse()
    body = r.read()
    c.close()
    assert r.status == 200, (r.status, body[:200])
    got = json.loads(body)
    assert got.get("stub") is True
    return got["headers"], got["peer"], got["path"]


def test_frontend_api_reaches_the_application_through_the_gateway():
    h, peer, path = via_frontend({})
    assert peer == GATEWAY_IP  # the gateway forwarded it, not the frontend
    assert path == "/api/pipeline-modes"  # /api kept by the frontend, stripped by the gateway
    assert h["x-real-ip"] == [FRONTEND_IP]
    assert h["x-forwarded-for"] == [FRONTEND_IP]
    assert h["x-forwarded-proto"] == ["http"]


@pytest.mark.parametrize("forged", [
    FORGED,
    {"X-Real-IP": "127.0.0.1", "X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "172.31.254.1"},
])
def test_frontend_api_cannot_forge_identity_or_scheme(resolver, forged):  # noqa: F811
    h, peer, _ = via_frontend(forged)
    assert h["x-real-ip"] == [FRONTEND_IP]
    assert h["x-forwarded-proto"] == ["http"]
    assert not any("203.0.113" in v or "198.51.100" in v for vs in h.values() for v in vs)
    assert _key(resolver, h, peer) == FRONTEND_IP


def test_frontend_api_strips_identity_headers():
    h, _, _ = via_frontend({"X-User-ID": "usr_spoof", "X-Tenant-ID": "org_spoof", "X-Ccure-Auth-Sub": "usr_spoof"})
    assert not {"x-user-id", "x-tenant-id"} & set(h)
    assert h.get("x-ccure-auth-sub", [""]) == [""]
