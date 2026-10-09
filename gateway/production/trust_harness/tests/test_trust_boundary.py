"""
Phase 10.6 — the gateway believes a client address and scheme only from the
edge's unix socket.

The finding this closes (10.5): the gateway trusted the bridge address
172.31.254.1, which is how host nginx reached it — and how every other host
process reaches it too. Any local process could dial the gateway, assert
X-Real-IP / X-Forwarded-Proto, and choose its own rate-limit key, audit
address and scheme.

Here, against the production files (see docker-compose.yml):

* the legitimate path — TLS to the edge, which runs the committed host nginx
  file, then the unix socket — delivers the real client and https, whatever
  the client forged;
* a TCP caller of the gateway ("a host process") is an ordinary client: its
  own address and http, whatever it forged;
* the socket itself refuses every uid but www-data (the edge) and root;
* the API's own resolution rule (core/ip_resolver.py, loaded unchanged, with
  the production trust list) turns what the gateway forwards into the right
  rate-limit key in every case, and never a forged one.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import ssl
import sys
import types

import pytest

EDGE = ("edge-tls", 8443)
GATEWAY = ("gateway", 8080)
GATEWAY_IP = "10.254.40.10"
RUNNER_IP = "10.254.40.60"
SOCK = "/edge/gateway.sock"
FORGED = {
    "X-Real-IP": "203.0.113.9",
    "X-Forwarded-For": "203.0.113.9, 198.51.100.7",
    "X-Forwarded-Proto": "https",
}
# a public route: no auth_request, so the stub's echo is the whole answer. The
# gateway strips one /api; the application's own route is /api/pipeline-modes.
ROUTE = "/api/api/pipeline-modes"

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def _echo(conn, headers, path=ROUTE):
    conn.request("GET", path, headers={"Host": "ccurepro.cdac.in", **headers})
    r = conn.getresponse()
    body = r.read()
    conn.close()
    assert r.status == 200, (r.status, body[:200])
    got = json.loads(body)
    assert got.get("stub") is True
    return {k: v for k, v in got["headers"].items()}, got["peer"]


def via_edge(headers):
    return _echo(http.client.HTTPSConnection(*EDGE, context=_CTX, timeout=10), headers)


def via_tcp(headers):
    return _echo(http.client.HTTPConnection(*GATEWAY, timeout=10), headers)


def _socket_as(uid, gid, request: bytes) -> str:
    """Connect to the edge socket with the given ids (in a child process, so the
    runner keeps root) and return the response, or the error's name."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            s = socket.socket(socket.AF_UNIX)
            s.settimeout(5)
            s.connect(SOCK)
            s.sendall(request)
            data = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
            out = data.decode("latin-1")
        except Exception as exc:  # noqa: BLE001
            out = f"ERR {type(exc).__name__}"
        os.write(w, out.encode("latin-1"))
        os._exit(0)
    os.close(w)
    chunks = []
    while True:
        chunk = os.read(r, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    os.waitpid(pid, 0)
    return b"".join(chunks).decode("latin-1")


@pytest.fixture(scope="module")
def resolver():
    """core/ip_resolver.py unchanged, configured as production configures it:
    the api trusts the gateway's address (and loopback / the docker-proxy peer,
    which do not occur here)."""
    cfg = types.ModuleType("config")
    cfg.AppConfig = types.SimpleNamespace(TRUSTED_PROXIES=["127.0.0.1", "::1", "172.18.0.1", GATEWAY_IP])
    sys.modules["config"] = cfg
    sys.path.insert(0, "/resolver")
    from core import ip_resolver

    return ip_resolver


def _key(resolver, headers, peer):
    return resolver.resolve_client(peer, headers.get("x-forwarded-for", [None])[0],
                                   headers.get("x-real-ip", [None])[0])


# ── the legitimate path ──────────────────────────────────────────────────────
def test_legitimate_edge_path_delivers_the_real_client_and_https():
    h, peer = via_edge({})
    assert peer == GATEWAY_IP
    assert h["x-real-ip"] == [RUNNER_IP]
    assert h["x-forwarded-for"] == [RUNNER_IP]
    assert h["x-forwarded-proto"] == ["https"]


def test_legitimate_edge_path_ignores_everything_the_client_forged():
    h, _ = via_edge({**FORGED, "X-Forwarded-Proto": "http"})
    assert h["x-real-ip"] == [RUNNER_IP]
    assert h["x-forwarded-for"] == [RUNNER_IP]
    assert h["x-forwarded-proto"] == ["https"]


def test_legitimate_edge_path_rate_limit_key_is_the_client(resolver):
    h, peer = via_edge(FORGED)
    assert _key(resolver, h, peer) == RUNNER_IP


# ── a host process dialling the gateway over TCP ─────────────────────────────
def test_tcp_caller_cannot_forge_client_address():
    h, _ = via_tcp(FORGED)
    assert h["x-real-ip"] == [RUNNER_IP]
    assert h["x-forwarded-for"] == [RUNNER_IP]
    assert not any("203.0.113" in v or "198.51.100" in v for vs in h.values() for v in vs)


def test_tcp_caller_cannot_forge_https():
    h, _ = via_tcp(FORGED)
    assert h["x-forwarded-proto"] == ["http"]


@pytest.mark.parametrize("forged", [
    {"X-Real-IP": "203.0.113.9"},
    {"X-Forwarded-For": "203.0.113.9"},
    {"X-Forwarded-For": "198.51.100.7, 203.0.113.9"},
    {"X-Real-IP": "127.0.0.1", "X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "172.31.254.1"},
    {"X-Real-IP": "unix:"},
])
def test_tcp_caller_rate_limit_key_is_its_own_address(resolver, forged):
    h, peer = via_tcp(forged)
    assert _key(resolver, h, peer) == RUNNER_IP


def test_identity_headers_are_stripped_on_the_tcp_path_too():
    h, _ = via_tcp({"X-User-ID": "usr_spoof", "X-Tenant-ID": "org_spoof", "X-Ccure-Auth-Sub": "usr_spoof"})
    assert not {"x-user-id", "x-tenant-id"} & set(h)
    assert h.get("x-ccure-auth-sub", [""]) == [""]


# ── the socket: the filesystem is the authenticator ──────────────────────────
REQ = (b"GET " + ROUTE.encode() + b" HTTP/1.1\r\nHost: ccurepro.cdac.in\r\n"
       b"X-Real-IP: 203.0.113.9\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n")


@pytest.mark.parametrize("uid,gid,who", [
    (1001, 1001, "an ordinary host account (the operator's uid)"),
    (101, 101, "the gateway's own uid, without the www-data group"),
    (1000, 1000, "uid 1000"),
    (65534, 65534, "nobody"),
])
def test_socket_refuses_everyone_but_the_edge(uid, gid, who):
    assert _socket_as(uid, gid, REQ) == "ERR PermissionError", who


def test_socket_admits_the_edge_group_and_that_peer_is_trusted():
    # www-data IS the edge: what it asserts is believed. That is the boundary —
    # host nginx always overwrites both headers (ccure.gateway.conf), so a
    # client can never put a value there itself (the edge tests above).
    out = _socket_as(33, 33, REQ)
    assert out.startswith("HTTP/1.1 200"), out[:200]
    assert "transfer-encoding: chunked" not in out.lower()
    body = json.loads(out.split("\r\n\r\n", 1)[1])
    assert body["headers"]["x-real-ip"] == ["203.0.113.9"]
    assert body["headers"]["x-forwarded-proto"] == ["https"]


def test_socket_directory_is_root_www_data_0770():
    st = os.stat("/edge")
    assert (st.st_uid, st.st_gid, st.st_mode & 0o777) == (0, 33, 0o770)
    s = os.stat(SOCK)
    assert s.st_mode & 0o777 == 0o666  # nginx's own chmod: the directory is the gate
