"""
tests/test_ip_resolver.py
─────────────────────────
Unit tests for core/ip_resolver.py to verify secure client IP resolution.
"""

from fastapi import Request
from core.ip_resolver import get_client_ip, _is_trusted_proxy


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


def test_is_trusted_proxy():
    # AppConfig.TRUSTED_PROXIES defaults to common private networks
    assert _is_trusted_proxy("127.0.0.1") is True
    assert _is_trusted_proxy("172.18.0.5") is True
    assert _is_trusted_proxy("10.0.0.1") is True
    assert _is_trusted_proxy("10.180.6.14") is True
    assert _is_trusted_proxy("8.8.8.8") is False
    assert _is_trusted_proxy("invalid-ip") is False


def test_get_client_ip_no_headers():
    request = create_mock_request(client_ip="203.0.113.1")
    assert get_client_ip(request) == "203.0.113.1"


def test_get_client_ip_none():
    assert get_client_ip(None) is None


def test_get_client_ip_real_ip_header():
    request = create_mock_request(
        client_ip="172.18.0.5", headers={"x-real-ip": "198.51.100.10"}
    )
    assert get_client_ip(request) == "198.51.100.10"


def test_get_client_ip_x_forwarded_for_trusted():
    # Hops: [198.51.100.10 (untrusted), 10.0.0.1 (trusted), 172.18.0.5 (trusted socket)]
    # Traversal from right to left should stop at the first untrusted IP (198.51.100.10)
    request = create_mock_request(
        client_ip="172.18.0.5", headers={"x-forwarded-for": "198.51.100.10, 10.0.0.1"}
    )
    assert get_client_ip(request) == "198.51.100.10"


def test_get_client_ip_x_forwarded_for_spoofed():
    # Attacker tries to spoof 8.8.8.8 by appending it to the headers.
    # Hops: [8.8.8.8, 198.51.100.10, 10.0.0.1, 172.18.0.5]
    # Traversal from right to left must stop at the true client IP (198.51.100.10)
    request = create_mock_request(
        client_ip="172.18.0.5",
        headers={"x-forwarded-for": "8.8.8.8, 198.51.100.10, 10.0.0.1"},
    )
    assert get_client_ip(request) == "198.51.100.10"


def test_get_client_ip_all_trusted():
    # If all hops are trusted, return the leftmost client IP
    request = create_mock_request(
        client_ip="127.0.0.1", headers={"x-forwarded-for": "10.0.0.2, 10.0.0.1"}
    )
    assert get_client_ip(request) == "10.0.0.2"
