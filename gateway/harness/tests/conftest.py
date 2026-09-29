"""
Harness fixtures (Phase 10.2d). These run INSIDE the harness network, in the
``runner`` container (10.254.10.10, the trusted edge); gateway/harness/run.sh
drives them. Nothing here reaches the live stack.

The runner generates a throwaway ES256 key, publishes only its JWKS (through
the stub, where gateway-auth fetches it) and mints tokens with it. Every token
it mints is appended to /harness-out/tokens.txt so run.sh can prove none of
them appears in any gateway or gateway-auth log.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import socket
import time

import pytest

GATEWAY = ("gateway", 8080)
STUB = ("stub-api", 8000)
CHECKER = ("gateway-auth", 8080)
OUTSIDER = ("outsider", 9000)
KEYS_DIR = "/harness-keys"
OUT_DIR = "/harness-out"
EDGE_CLIENT = "198.51.100.23"  # the client address the edge (host nginx) asserts
HOST = "ccurepro.cdac.in"
DOCS = "/docs/architecture/phase10"


def pytest_configure(config):
    config.addinivalue_line("markers", "checker_down: run while gateway-auth is stopped")


class Response:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers  # list of (lower-name, value), in order
        self.body = body

    def header(self, name):
        name = name.lower()
        return next((v for k, v in self.headers if k == name), None)

    def names(self):
        return [k for k, _ in self.headers]

    def count(self, name):
        return sum(1 for k, _ in self.headers if k == name.lower())

    def json(self):
        return json.loads(self.body)


def request(method, path, headers=None, body=None, target=GATEWAY, edge=True, timeout=30):
    """One HTTP/1.1 request. As the edge, sets what host nginx sets."""
    hdrs = {"Host": HOST}
    if edge and target == GATEWAY:
        hdrs.update({"X-Real-IP": EDGE_CLIENT, "X-Forwarded-For": EDGE_CLIENT, "X-Forwarded-Proto": "https"})
    hdrs.update(headers or {})
    conn = http.client.HTTPConnection(*target, timeout=timeout)
    try:
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for name, value in (hdrs.items() if isinstance(hdrs, dict) else hdrs):
            conn.putheader(name, value)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        resp = conn.getresponse()
        data = resp.read()
        return Response(resp.status, [(k.lower(), v) for k, v in resp.getheaders()], data)
    finally:
        conn.close()


def websocket(path, headers=None, target=GATEWAY, frames=1):
    """A raw RFC 6455 handshake: (status, headers, [text frames])."""
    key = base64.b64encode(os.urandom(16)).decode()
    lines = [f"GET {path} HTTP/1.1", f"Host: {HOST}", "Upgrade: websocket", "Connection: Upgrade",
             f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13"]
    if target == GATEWAY:
        lines += [f"X-Real-IP: {EDGE_CLIENT}", f"X-Forwarded-For: {EDGE_CLIENT}", "X-Forwarded-Proto: https"]
    lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
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
        status_line, *header_lines = head.decode("latin-1").split("\r\n")
        status = int(status_line.split()[1])
        hdrs = [(h.split(":", 1)[0].strip().lower(), h.split(":", 1)[1].strip()) for h in header_lines if ":" in h]
        texts = []
        if status == 101:
            while len(texts) < frames:
                while len(data) < 2:
                    data += sock.recv(65536)
                opcode, length, off = data[0] & 0x0F, data[1] & 0x7F, 2
                if length == 126:
                    while len(data) < 4:
                        data += sock.recv(65536)
                    length, off = int.from_bytes(data[2:4], "big"), 4
                while len(data) < off + length:
                    data += sock.recv(65536)
                payload, data = data[off:off + length], data[off + length:]
                if opcode == 1:
                    texts.append(payload.decode())
                if opcode == 8:
                    break
        return status, hdrs, texts, data if status != 101 else b""
    finally:
        sock.close()


def relay(method, path, headers=None):
    """A request sent to the gateway by the UNTRUSTED outsider (10.254.10.20)."""
    spec = json.dumps({"method": method, "path": path, "headers": {"Host": HOST, **(headers or {})}})
    resp = request("POST", "/relay", {"Content-Type": "application/json"}, spec.encode(), target=OUTSIDER)
    out = resp.json()
    return Response(out["status"], [(k.lower(), v) for k, v in out["headers"]], out["body"].encode())


class HarnessMint:
    """The token_check test Mint, with the harness issuer, recording every token."""

    def __init__(self):
        import importlib.util

        # gateway/token_check/tests/conftest.py, loaded by path: both test
        # directories have a conftest.py, so a plain import would find this one.
        spec = importlib.util.spec_from_file_location(
            "token_check_test_conftest", "/gateway/token_check/tests/conftest.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        Mint = module.Mint

        self._mint = Mint(issuer=os.environ["CCURE_HARNESS_ISSUER"], audience=os.environ["CCURE_HARNESS_AUDIENCE"])
        self.kid = self._mint.kid

    def _keep(self, token):
        with open(os.path.join(OUT_DIR, "tokens.txt"), "a") as fh:
            fh.write(token + "\n")
        return token

    def jwks(self):
        return self._mint.jwks()

    def token(self, kind="access", **kw):
        return self._keep(self._mint.token(kind, **kw))

    def expired(self, kind="access"):
        return self._keep(self._mint.expired(kind))

    def legacy(self, kind="access"):
        return self._keep(self._mint.legacy(kind))


@pytest.fixture(scope="session")
def mint():
    m = HarnessMint()
    tmp = os.path.join(KEYS_DIR, "jwks.json.tmp")
    with open(tmp, "w") as fh:
        json.dump(m.jwks(), fh)
    os.replace(tmp, os.path.join(KEYS_DIR, "jwks.json"))
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:  # gateway-auth fetches it (min refetch 1 s)
        probe = request("GET", "/api/scans", {"Authorization": f"Bearer {m.token()}"})
        if probe.status == 200:
            return m
        time.sleep(1)
    pytest.fail("gateway-auth never accepted the harness key")


def load_doc(name):
    with open(os.path.join(DOCS, name)) as fh:
        return json.load(fh)


def stub_received(resp):
    """What the stub reported receiving, from a forwarded response."""
    body = resp.json()
    assert body.get("stub") is True, "the request did not reach the stub"
    return body
