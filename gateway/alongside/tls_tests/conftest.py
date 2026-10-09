"""
Phase 10.4 fixtures: the HTTPS path

    client ──TLS──▶ edge-tls (host nginx's /api/ behaviour) ──▶ gateway ──▶ gateway-auth
                                                                   └──────▶ api (the real application)

Two places run these tests (EDGE_TLS_ADDR says which):

* ``runner-tls`` INSIDE the network (edge-tls:8443) — the edge sees the runner's
  real address, 10.254.20.60, so per-client behaviour is observable;
* the host runner through the published 127.0.0.1:8443 — the listener checks.

The edge is verified against the run's throwaway CA (/tls/ca.pem). Tokens are
recorded for run.sh's log scan and never printed.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import socket
import ssl

import pytest

EDGE_HOST, EDGE_PORT = os.environ.get("EDGE_TLS_ADDR", "edge-tls:8443").rsplit(":", 1)
EDGE = (EDGE_HOST, int(EDGE_PORT))
IN_NETWORK = EDGE_HOST != "127.0.0.1"
API = ("api", 8000) if IN_NETWORK else ("127.0.0.1", 18000)
CA = "/tls/ca.pem"
HOST = "ccurepro.cdac.in"
OUT = os.environ.get("ALONGSIDE_OUT", "/out")
USER = "alongside_probe"
RUNNER_IP = "10.254.20.60"


def tls_context(minimum=None, maximum=None):
    context = ssl.create_default_context(cafile=CA)
    if minimum:
        context.minimum_version = minimum
    if maximum:
        context.maximum_version = maximum
    return context


class Response:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def header(self, name):
        return next((v for k, v in self.headers if k == name.lower()), None)

    def count(self, name):
        return sum(1 for k, _ in self.headers if k == name.lower())

    def names(self):
        return {k for k, _ in self.headers}

    def json(self):
        return json.loads(self.body)


def _send(conn, method, path, headers, body):
    try:
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for k, v in {"Host": HOST, **(headers or {})}.items():
            conn.putheader(k, v)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        resp = conn.getresponse()
        data = resp.read()
        return Response(resp.status, [(k.lower(), v) for k, v in resp.getheaders()], data)
    finally:
        conn.close()


def https(method, path, headers=None, body=None, timeout=120):
    """Through the TLS edge. `path` is the application path; /api is added."""
    conn = http.client.HTTPSConnection(*EDGE, timeout=timeout, context=tls_context())
    return _send(conn, method, "/api" + path, headers, body)


def direct(method, path, headers=None, body=None, timeout=120):
    """The same application, directly (an untrusted peer: it sees http)."""
    return _send(http.client.HTTPConnection(*API, timeout=timeout), method, path, headers, body)


def relay_https(method, path, headers=None):
    """A second HTTPS client: the insider (10.254.20.50) through the TLS edge."""
    spec = json.dumps({"target": ["edge-tls", 8443], "tls": True, "method": method, "path": "/api" + path,
                       "headers": {"Host": HOST, **(headers or {})}}).encode()
    out = _send(http.client.HTTPConnection("insider", 9000, timeout=30), "POST", "/relay",
                {"Content-Type": "application/json"}, spec).json()
    return Response(out["status"], [(k.lower(), v) for k, v in out["headers"]], out["body"].encode())


def wss(path, headers=None):
    """A WebSocket handshake over TLS: (status, headers, first frame, leftover)."""
    return _ws(tls_context().wrap_socket(socket.create_connection(EDGE, timeout=10), server_hostname=EDGE_HOST),
               "/api" + path, headers)


def ws_direct(path, headers=None):
    return _ws(socket.create_connection(API, timeout=10), path, headers)


def _ws(sock, path, headers):
    lines = [f"GET {path} HTTP/1.1", f"Host: {HOST}", "Upgrade: websocket", "Connection: Upgrade",
             f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}", "Sec-WebSocket-Version: 13"]
    lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
    try:
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        head, _, data = buf.partition(b"\r\n\r\n")
        first, *rest = head.decode("latin-1").split("\r\n")
        status = int(first.split()[1])
        hdrs = [(h.split(":", 1)[0].strip().lower(), h.split(":", 1)[1].strip()) for h in rest if ":" in h]
        frame = None
        if status == 101:
            try:
                while len(data) < 2:
                    data += sock.recv(65536)
                opcode, length, off = data[0] & 0x0F, data[1] & 0x7F, 2
                if length == 126:
                    while len(data) < 4:
                        data += sock.recv(65536)
                    length, off = int.from_bytes(data[2:4], "big"), 4
                while len(data) < off + length:
                    data += sock.recv(65536)
                payload = data[off:off + length]
                frame = ("text", payload.decode()) if opcode == 1 else ("close", int.from_bytes(payload[:2], "big") if length >= 2 else None)
            except (socket.timeout, TimeoutError):
                frame = ("timeout", None)
        return status, hdrs, frame, data if status != 101 else b""
    finally:
        sock.close()


def keep(token):
    with open(os.path.join(OUT, "tokens.txt"), "a") as fh:
        fh.write(token + "\n")
    return token


class _Session(dict):
    """Credentials; its repr names nothing, so a traceback can never show a token."""

    def __repr__(self):
        return "<https session: credentials withheld>"


@pytest.fixture(scope="session")
def session():
    body = json.dumps({"email_or_username": USER, "password": os.environ["ALONGSIDE_USER_PASSWORD"]}).encode()
    resp = https("POST", "/auth/login", {"Content-Type": "application/json"}, body)
    assert resp.status == 200, f"sign-in over HTTPS failed: {resp.status}"
    access = keep(resp.json()["access_token"])
    cookie = next((v for k, v in resp.headers if k == "set-cookie"), "")
    keep(cookie.split(";", 1)[0].split("=", 1)[-1])

    def ticket():
        r = https("POST", "/auth/ticket", {"Authorization": f"Bearer {access}"})
        assert r.status == 200
        return keep(r.json()["ticket"])

    return _Session(access=access, cookie_attributes=cookie.split(";", 1)[-1], ticket=ticket)


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


in_network_only = pytest.mark.skipif(not IN_NETWORK, reason="needs a distinct client address (runner-tls)")
