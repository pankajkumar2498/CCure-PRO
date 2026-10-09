"""
F10-1 regressions against the real application (Phase 10.3).

* api      trusts only the gateway (the target once the gateway fronts it).
* api-edge trusts only the docker-proxy peer (10.254.20.1 here, 172.18.0.1 on
           the live network) — host nginx's position, i.e. production's
           committed configuration for today's path.

The rate-limit key is observed through its effect: /auth/check-username allows
10 a minute per key, so a caller whose forged address were believed would get
a fresh bucket for every address it names.
"""

from __future__ import annotations

from conftest import API, EDGE_API, GATEWAY, edge_headers, relay, request

FORGED = {"X-Forwarded-For": "203.0.113.200", "X-Real-IP": "203.0.113.201", "X-Forwarded-Proto": "https"}


def _exhaust(send, tag):
    """Send until 429 (at most 12); return how many were allowed."""
    for n in range(12):
        if send(n).status == 429:
            return n
    return None


def test_a_direct_caller_cannot_forge_its_client_address():
    """Forged addresses do not open fresh buckets: they all share the caller's own."""
    allowed = _exhaust(lambda n: request(API, "GET", f"/auth/check-username?q=direct{n}",
                                         {"X-Forwarded-For": f"203.0.113.{n + 1}", "X-Real-IP": f"203.0.113.{n + 1}"}),
                       "direct")
    assert allowed is not None and allowed <= 10
    again = request(API, "GET", "/auth/check-username?q=direct-new", {"X-Forwarded-For": "198.18.0.99"})
    assert again.status == 429


def test_a_direct_caller_cannot_forge_https():
    resp = request(API, "GET", "/scans/", FORGED)
    assert resp.header("location") == "http://ccurepro.cdac.in/scans"
    assert resp.header("strict-transport-security") is None


def test_a_container_caller_cannot_forge_address_or_https():
    allowed = _exhaust(lambda n: relay(["api", 8000], "GET", f"/auth/check-username?q=insider{n}",
                                       {"X-Forwarded-For": f"203.0.113.{n + 50}"}), "insider")
    assert allowed is not None and allowed <= 10
    assert relay(["api", 8000], "GET", "/auth/check-username?q=insider-new", {"X-Forwarded-For": "198.18.0.98"}).status == 429
    redirect = relay(["api", 8000], "GET", "/scans/", FORGED)
    assert redirect.header("location") == "http://ccurepro.cdac.in/scans"


def test_the_gateway_is_the_proxy_the_application_trusts():
    resp = request(GATEWAY, "GET", "/scans/", edge_headers("198.51.100.70"))
    assert resp.header("location") == "https://ccurepro.cdac.in/scans"
    assert resp.header("strict-transport-security") == "max-age=300"


def test_the_gateway_ignores_an_untrusted_peer_s_forwarding_headers():
    """insider → gateway: its X-Real-IP is not believed, so every forged address shares one bucket."""
    allowed = _exhaust(lambda n: relay(["gateway", 8080], "GET", f"/api/auth/check-username?q=gw-insider{n}",
                                       {"X-Real-IP": f"203.0.113.{n + 100}", "X-Forwarded-For": f"203.0.113.{n + 100}"}),
                       "gw-insider")
    assert allowed is not None and allowed <= 10
    assert relay(["gateway", 8080], "GET", "/api/scans/", FORGED).header("location") == "http://ccurepro.cdac.in/scans"


# ── production's committed configuration (api-edge) ──────────────────────────


def test_production_config_honours_the_host_nginx_peer():
    """The docker-proxy peer (host nginx's position) forwards client and scheme."""
    allowed = _exhaust(lambda n: request(EDGE_API, "GET", f"/auth/check-username?q=edge{n}",
                                         {"X-Forwarded-For": "198.51.100.80", "X-Real-IP": "198.51.100.80"}), "edge")
    assert allowed == 10
    other = request(EDGE_API, "GET", "/auth/check-username?q=edge-b", {"X-Forwarded-For": "198.51.100.81"})
    assert other.status == 200  # a second client behind host nginx: its own bucket
    resp = request(EDGE_API, "GET", "/scans/", {"X-Forwarded-Proto": "https"})
    assert resp.header("location") == "https://ccurepro.cdac.in/scans"


def test_production_config_refuses_a_container_s_forged_headers():
    allowed = _exhaust(lambda n: relay(["api-edge", 8000], "GET", f"/auth/check-username?q=edge-insider{n}",
                                       {"X-Forwarded-For": f"203.0.113.{n + 150}"}), "edge-insider")
    assert allowed is not None and allowed <= 10
    redirect = relay(["api-edge", 8000], "GET", "/scans/", FORGED)
    assert redirect.header("location") == "http://ccurepro.cdac.in/scans"
    assert redirect.header("strict-transport-security") is None
