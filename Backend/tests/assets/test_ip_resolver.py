"""
tests/assets/test_ip_resolver.py
────────────────────────────────
Unit tests for core/ip_resolver.py.

The resolved address is the rate-limiting bucket key and the audit-trail
address, so these are security tests, not formatting tests. The cases that
matter are the ones where somebody is *lying* about the client address.

Note on the fixtures: `AppConfig.TRUSTED_PROXIES` names reverse proxies only —
loopback and 172.18.0.1, the compose network's gateway, which is the peer host
nginx arrives as through docker-proxy. It deliberately no longer contains
10.0.0.0/8 or 192.168.0.0/16, because this deployment's own clients live at
10.180.6.0/24 and trusting that range made every real client indistinguishable
from a proxy entitled to declare somebody else's address. Since Phase 10.3
(finding F10-1) it no longer contains the Docker pool 172.16.0.0/12 either:
that trusted every *container* on the network, including the frontend's
``/api/`` proxy, which appends X-Forwarded-For.
"""

from core.ip_resolver import _is_trusted_proxy, get_client_ip
from fastapi import Request


def create_mock_request(client_ip=None, headers=None) -> Request:
    header_list = []
    if headers:
        for k, v in headers.items():
            header_list.append((k.lower().encode("utf-8"), v.encode("utf-8")))

    scope = {
        "type": "http",
        "headers": header_list,
    }
    if client_ip:
        scope["client"] = (client_ip, 12345)
    else:
        scope["client"] = None

    return Request(scope)


# ── The trust list itself ────────────────────────────────────────────────────


def test_is_trusted_proxy_accepts_the_real_proxy_hops():
    """Loopback and the bridge gateway host nginx arrives as."""
    assert _is_trusted_proxy("127.0.0.1") is True
    assert _is_trusted_proxy("172.18.0.1") is True


def test_containers_on_the_compose_network_are_not_trusted_proxies():
    """
    F10-1. A container is a caller, not a proxy: the frontend container
    (172.18.0.8) proxies /api/ and appends X-Forwarded-For, and any other
    container could send one. None of them may declare a client address.
    """
    for container in (
        "172.18.0.2",
        "172.18.0.5",
        "172.18.0.8",
        "172.17.0.2",
        "172.31.255.254",
    ):
        assert _is_trusted_proxy(container) is False, container
    request = create_mock_request(
        client_ip="172.18.0.8", headers={"x-forwarded-for": "8.8.8.8"}
    )
    assert get_client_ip(request) == "172.18.0.8"


def test_client_networks_are_not_trusted_proxies():
    """
    The regression this whole change exists for.

    10.180.6.14 is a client workstation on the deployment LAN. While
    10.0.0.0/8 was in TRUSTED_PROXIES it was treated as a hop entitled to
    declare the client address, and the correct answer only came back through
    the "all hops trusted, take the leftmost" fallback — which reads the one
    field a client controls.
    """
    assert _is_trusted_proxy("10.180.6.14") is False
    assert _is_trusted_proxy("10.0.0.1") is False
    assert _is_trusted_proxy("192.168.1.1") is False
    assert _is_trusted_proxy("8.8.8.8") is False
    assert _is_trusted_proxy("invalid-ip") is False


# ── Basic resolution ─────────────────────────────────────────────────────────


def test_get_client_ip_no_headers():
    request = create_mock_request(client_ip="203.0.113.1")
    assert get_client_ip(request) == "203.0.113.1"


def test_get_client_ip_none():
    assert get_client_ip(None) is None


def test_get_client_ip_real_ip_header_from_a_trusted_proxy():
    request = create_mock_request(
        client_ip="172.18.0.1", headers={"x-real-ip": "198.51.100.10"}
    )
    assert get_client_ip(request) == "198.51.100.10"


def test_get_client_ip_x_forwarded_for_from_a_trusted_proxy():
    """The deployed shape: host nginx sets XFF to the client, bridge-gateway peer."""
    request = create_mock_request(
        client_ip="172.18.0.1", headers={"x-forwarded-for": "10.180.6.14"}
    )
    assert get_client_ip(request) == "10.180.6.14"


# ── Spoofing ─────────────────────────────────────────────────────────────────


def test_appended_hop_cannot_move_the_bucket():
    """
    A client that prefixes its own value to X-Forwarded-For must not be
    believed. The walk runs right-to-left and stops at the first hop that is
    not a trusted proxy, so everything further left is discarded.
    """
    request = create_mock_request(
        client_ip="172.18.0.1",
        headers={"x-forwarded-for": "8.8.8.8, 198.51.100.10"},
    )
    assert get_client_ip(request) == "198.51.100.10"


def test_direct_client_cannot_forge_x_forwarded_for():
    """A peer that is not a trusted proxy has no say in the answer at all."""
    request = create_mock_request(
        client_ip="203.0.113.7",
        headers={"x-forwarded-for": "8.8.8.8"},
    )
    assert get_client_ip(request) == "203.0.113.7"


def test_direct_client_cannot_forge_x_real_ip():
    """
    The hole this guard closes.

    X-Real-IP used to be honoured unconditionally whenever no X-Forwarded-For
    was present, with no check on who sent it. Any caller able to reach the
    application directly could name its own rate-limiting bucket — and its own
    address in the audit log — with a single header.
    """
    request = create_mock_request(
        client_ip="203.0.113.7",
        headers={"x-real-ip": "8.8.8.8"},
    )
    assert get_client_ip(request) == "203.0.113.7"


def test_client_on_the_lan_cannot_forge_headers_either():
    """
    10.180.6.x is a user network, not a proxy. Before the trust list was
    narrowed this request resolved to the attacker-supplied 8.8.8.8.
    """
    request = create_mock_request(
        client_ip="10.180.6.50",
        headers={"x-forwarded-for": "8.8.8.8", "x-real-ip": "8.8.8.8"},
    )
    assert get_client_ip(request) == "10.180.6.50"


# ── Degenerate inputs ────────────────────────────────────────────────────────


def test_all_hops_trusted_returns_the_leftmost():
    """
    Only reachable when the client genuinely sits inside a proxy range — an
    internal call, in practice. The leftmost entry is the conventional answer.
    """
    request = create_mock_request(
        client_ip="127.0.0.1", headers={"x-forwarded-for": "::1, 172.18.0.1"}
    )
    assert get_client_ip(request) == "::1"


def test_garbage_header_falls_back_rather_than_keying_on_it():
    """
    A non-address must never become a rate-limit key: every caller sending the
    same junk would share one bucket.
    """
    request = create_mock_request(
        client_ip="172.18.0.1", headers={"x-forwarded-for": "not-an-ip"}
    )
    assert get_client_ip(request) == "172.18.0.1"
