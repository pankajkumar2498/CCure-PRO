"""
Alongside validation fixtures (Phase 10.3). The runner uses the HOST network,
so it reaches the loopback-published ports the way host nginx does:

* GATEWAY  127.0.0.1:8082  → gateway → gateway-auth → api (trusts the gateway only)
* API      127.0.0.1:18000 → api, directly (the peer is the docker-proxy address,
                             which api does NOT trust)
* EDGE_API 127.0.0.1:18001 → api-edge, directly (production's committed trust:
                             the docker-proxy peer is host nginx and IS trusted)
* INSIDER  127.0.0.1:18050 → a relay inside the network (10.254.20.50), an
                             untrusted container peer

Every token obtained is appended to $ALONGSIDE_OUT/tokens.txt for run.sh's log
scan, and never printed.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import socket

import pytest

GATEWAY = ("127.0.0.1", 8082)
API = ("127.0.0.1", 18000)
EDGE_API = ("127.0.0.1", 18001)
INSIDER = ("127.0.0.1", 18050)
HOST = "ccurepro.cdac.in"
OUT = os.environ.get("ALONGSIDE_OUT", "/out")
USER = "alongside_probe"


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


def edge_headers(client="198.51.100.40"):
    """What host nginx sets on every request it forwards."""
    return {"X-Real-IP": client, "X-Forwarded-For": client, "X-Forwarded-Proto": "https"}


def request(target, method, path, headers=None, body=None, timeout=60):
    """One request. Paths are application paths; /api is added for the gateway."""
    full = ("/api" + path) if target == GATEWAY else path
    hdrs = {"Host": HOST, **(edge_headers() if target == GATEWAY else {}), **(headers or {})}
    conn = http.client.HTTPConnection(*target, timeout=timeout)
    try:
        conn.putrequest(method, full, skip_host=True, skip_accept_encoding=True)
        for k, v in hdrs.items():
            conn.putheader(k, v)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        resp = conn.getresponse()
        data = resp.read()
        return Response(resp.status, [(k.lower(), v) for k, v in resp.getheaders()], data)
    finally:
        conn.close()


def relay(target, method, path, headers=None):
    """A request made by the untrusted container peer (10.254.20.50)."""
    spec = json.dumps({"target": target, "method": method, "path": path,
                       "headers": {"Host": HOST, **(headers or {})}}).encode()
    out = request(INSIDER, "POST", "/relay", {"Content-Type": "application/json"}, spec).json()
    return Response(out["status"], [(k.lower(), v) for k, v in out["headers"]], out["body"].encode())


def websocket(target, path, headers=None):
    """Raw handshake: (status, headers, first text frame or close code, leftover)."""
    full = ("/api" + path) if target == GATEWAY else path
    lines = [f"GET {full} HTTP/1.1", f"Host: {HOST}", "Upgrade: websocket", "Connection: Upgrade",
             f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}", "Sec-WebSocket-Version: 13"]
    extra = {**(edge_headers() if target == GATEWAY else {}), **(headers or {})}
    lines += [f"{k}: {v}" for k, v in extra.items()]
    sock = socket.create_connection(target, timeout=10)
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


@pytest.fixture(scope="session")
def session():
    """Sign in once through the gateway: access token, refresh cookie, tickets."""
    body = json.dumps({"email_or_username": USER, "password": os.environ["ALONGSIDE_USER_PASSWORD"]}).encode()
    resp = request(GATEWAY, "POST", "/auth/login", {"Content-Type": "application/json"}, body)
    assert resp.status == 200, f"sign-in through the gateway failed: {resp.status}"
    access = keep(resp.json()["access_token"])
    cookie = next((v.split(";", 1)[0] for k, v in resp.headers if k == "set-cookie"), "")
    keep(cookie.split("=", 1)[1] if "=" in cookie else cookie)

    def ticket():
        r = request(GATEWAY, "POST", "/auth/ticket", {"Authorization": f"Bearer {access}"})
        assert r.status == 200
        return keep(r.json()["ticket"])

    return _Session(access=access, cookie=cookie, ticket=ticket)


class _Session(dict):
    """The session's credentials. Its repr names nothing, so a failing test's
    traceback — pytest prints fixture values — can never show a token."""

    def __repr__(self):
        return "<alongside session: credentials withheld>"


def bearer(token):
    return {"Authorization": f"Bearer {token}"}
