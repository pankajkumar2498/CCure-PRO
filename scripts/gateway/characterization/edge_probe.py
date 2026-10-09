#!/usr/bin/env python3
"""
Phase 10.1 — characterisation of the CURRENT edge (host nginx) and the direct
API port, for anonymous and invalid-credential requests. Standard library only.

Read-only by construction: no valid credential is used, every POST carries an
empty body the API refuses at validation, the only DELETE carries an invalid
ticket against a scan id that does not exist, and requests to /api/auth/ are
paced under host nginx's ccure_auth zone (30 r/m, burst 10).

Output: JSON on stdout. Token-shaped strings and cookie values are redacted.

    python3 scripts/gateway/characterization/edge_probe.py > out.json
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import ssl
import sys
import time

EDGE_HOST = os.environ.get("CCURE_EDGE_HOST", "127.0.0.1")
EDGE_SNI = os.environ.get("CCURE_EDGE_NAME", "ccurepro.cdac.in")
DIRECT_PORT = int(os.environ.get("CCURE_DIRECT_PORT", "8000"))
SCAN_ID = os.environ.get("CCURE_PROBE_SCAN", "scn_defa_c522b539_29sep26_fh9j")
WEB_SCAN_ID = os.environ.get("CCURE_PROBE_WEB_SCAN", "wsc_test_f88fc2f1_29sep26_o19q")
ALLOWED_ORIGIN = "https://ccurepro.cdac.in"
EVIL_ORIGIN = "https://evil.example"

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

_JWT = re.compile(r"eyJ[\w.-]*")  # any JWT prefix, complete or not
_TICKET_Q = re.compile(r"(ticket|token)=[^&\s\"]+")


def redact(text: str) -> str:
    text = _JWT.sub("<JWT>", text)
    return _TICKET_Q.sub(r"\1=<X>", text)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def fake_hs256() -> str:
    """Legacy-shaped (no kid) HS256 token signed with a random secret."""
    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64(json.dumps({"sub": "usr_probe", "type": "ticket", "exp": 4102444800}).encode())
    sig = hmac.new(os.urandom(32), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64(sig)}"


def fake_es256() -> str:
    """ES256-shaped token with an unknown kid and a random signature."""
    head = _b64(json.dumps({"alg": "ES256", "typ": "JWT", "kid": "probe-unknown-kid"}).encode())
    body = _b64(json.dumps({"sub": "usr_probe", "type": "access", "exp": 4102444800}).encode())
    return f"{head}.{body}.{_b64(os.urandom(64))}"


def alg_none() -> str:
    head = _b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = _b64(json.dumps({"sub": "usr_probe", "type": "access", "exp": 4102444800}).encode())
    return f"{head}.{body}."


GARBAGE = "not-a-token"
HS = fake_hs256()
ES = fake_es256()
NONE = alg_none()


def _conn(target: str):
    if target == "edge":
        return http.client.HTTPSConnection(EDGE_HOST, 443, context=_CTX, timeout=15)
    return http.client.HTTPConnection("127.0.0.1", DIRECT_PORT, timeout=15)


def _path(target: str, api_path: str) -> str:
    """api_path is the application path (/scans); the edge adds /api."""
    if api_path.startswith("SPA:"):
        return api_path[4:]
    return ("/api" + api_path) if target == "edge" else api_path


def _headers_view(resp_headers):
    pairs = [(k.lower(), redact(v)) for k, v in resp_headers]
    counts: dict[str, int] = {}
    for k, _ in pairs:
        counts[k] = counts.get(k, 0) + 1
    cookies = []
    for k, v in pairs:
        if k == "set-cookie":
            name, _, rest = v.partition("=")
            _, _, attrs = rest.partition(";")
            cookies.append({"name": name, "attributes": attrs.strip()})
    return pairs, counts, cookies


def http_case(case_id, target, method, api_path, headers=None, body=None, read=400):
    headers = dict(headers or {})
    if target == "edge":
        headers.setdefault("Host", EDGE_SNI)
    path = _path(target, api_path)
    conn = _conn(target)
    started = time.monotonic()
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read(read)
        pairs, counts, cookies = _headers_view(resp.getheaders())
        ctype = resp.getheader("content-type") or ""
        sample = raw.decode("utf-8", "replace")
        if "text/html" in ctype:
            sample = "<html…>" if "<html" in sample.lower() or "<!doctype" in sample.lower() else sample[:120]
        return {
            "id": case_id, "target": target, "method": method,
            "path": redact(path), "request_headers": sorted(k for k in headers if k.lower() != "host"),
            "status": resp.status,
            "headers": pairs, "header_counts": counts, "set_cookie": cookies,
            "body_sample": redact(sample)[:300],  # redact, then truncate
            "ms": round((time.monotonic() - started) * 1000, 2),
        }
    except Exception as exc:  # recorded, never raised
        return {"id": case_id, "target": target, "method": method, "path": redact(path), "error": repr(exc)}
    finally:
        conn.close()


def ws_case(case_id, target, api_path, headers=None):
    """Raw RFC 6455 handshake; records the HTTP answer to the upgrade."""
    path = _path(target, api_path)
    key = base64.b64encode(os.urandom(16)).decode()
    host = EDGE_SNI if target == "edge" else f"127.0.0.1:{DIRECT_PORT}"
    lines = [
        f"GET {path} HTTP/1.1", f"Host: {host}", "Upgrade: websocket", "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13", f"Origin: {ALLOWED_ORIGIN}",
    ] + [f"{k}: {v}" for k, v in (headers or {}).items()]
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode()
    try:
        sock = socket.create_connection(("127.0.0.1" if target == "direct" else EDGE_HOST,
                                         DIRECT_PORT if target == "direct" else 443), timeout=10)
        if target == "edge":
            sock = _CTX.wrap_socket(sock, server_hostname=EDGE_SNI)
        sock.sendall(raw)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        sock.close()
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin1").split("\r\n")
        status = int(head[0].split()[1]) if head and len(head[0].split()) > 1 else None
        pairs = [(h.split(":", 1)[0].strip().lower(), redact(h.split(":", 1)[1].strip()))
                 for h in head[1:] if ":" in h]
        counts: dict[str, int] = {}
        for k, _ in pairs:
            counts[k] = counts.get(k, 0) + 1
        return {"id": case_id, "target": target, "method": "WS", "path": redact(path),
                "status": status, "status_line": head[0] if head else None,
                "headers": pairs, "header_counts": counts}
    except Exception as exc:
        return {"id": case_id, "target": target, "method": "WS", "path": redact(path), "error": repr(exc)}


PUBLIC = [
    ("GET", "/auth/check-username"), ("GET", "/auth/check-email"),
    ("POST", "/auth/register"), ("POST", "/auth/verify-email"),
    ("POST", "/auth/resend-verification"), ("POST", "/auth/login"),
    ("POST", "/auth/logout"), ("GET", "/auth/jwks.json"), ("POST", "/auth/refresh"),
    ("POST", "/auth/forgot-password"), ("POST", "/auth/reset-password"),
    ("POST", "/auth/login/send-email-otp"), ("POST", "/auth/login/verify-mfa"),
    ("POST", "/auth/service-token"), ("GET", "/"), ("GET", "/api/pipeline-modes"),
    ("GET", "/api/workflow-example"),
]


def main() -> None:
    out: list[dict] = []

    def add(rec):
        out.append(rec)
        # /api/auth/ at the edge is 30 r/m burst 10 in host nginx; stay under it.
        if rec.get("target") == "edge" and str(rec.get("path", "")).startswith("/api/auth/"):
            time.sleep(2.2)

    J = {"Content-Type": "application/json"}

    for target in ("edge", "direct"):
        # 1. public allowlist — reachable without a credential (empty bodies → 422)
        for method, p in PUBLIC:
            add(http_case(f"public {method} {p}", target, method, p,
                          headers=J if method == "POST" else None,
                          body=b"{}" if method == "POST" else None))

        # 2. bearer route, missing / invalid credentials
        for label, hdr in [
            ("missing", {}), ("empty-bearer", {"Authorization": "Bearer "}),
            ("garbage", {"Authorization": f"Bearer {GARBAGE}"}),
            ("basic-scheme", {"Authorization": "Basic dXNlcjpwYXNz"}),
            ("alg-none", {"Authorization": f"Bearer {NONE}"}),
            ("legacy-hs256-random-secret", {"Authorization": f"Bearer {HS}"}),
            ("es256-unknown-kid", {"Authorization": f"Bearer {ES}"}),
        ]:
            add(http_case(f"bearer-route {label}", target, "GET", "/scans", headers=hdr))
        add(http_case("bearer-route 404 unknown path, missing", target, "GET", "/no-such-route"))
        add(http_case("bearer-route POST missing", target, "POST", "/scan/host-discovery", headers=J, body=b"{}"))

        # 3. ticket-or-bearer routes
        dl = f"/reports/download/{SCAN_ID}"
        for label, suffix, hdr in [
            ("missing", "", {}),
            ("ticket-garbage", f"?ticket={GARBAGE}", {}),
            ("ticket-legacy-hs256", f"?ticket={HS}", {}),
            ("ticket-es256-unknown-kid", f"?ticket={ES}", {}),
            ("bearer-garbage", "", {"Authorization": f"Bearer {GARBAGE}"}),
            ("ticket-garbage+bearer-garbage", f"?ticket={GARBAGE}", {"Authorization": f"Bearer {GARBAGE}"}),
        ]:
            add(http_case(f"download {label}", target, "GET", dl + suffix, headers=hdr))
        add(http_case("export missing", target, "GET", f"/reports/export/{SCAN_ID}"))
        add(http_case("export ticket-garbage", target, "GET", f"/reports/export/{SCAN_ID}?ticket={GARBAGE}"))
        add(http_case("delete-report missing (nonexistent id)", target, "DELETE", "/reports/scn_probe_does_not_exist"))
        add(http_case("delete-report ticket-garbage (nonexistent id)", target, "DELETE",
                      f"/reports/scn_probe_does_not_exist?ticket={GARBAGE}"))

        # 4. WebSockets
        for route, sid in (("/scans/{}/progress", SCAN_ID), ("/web-scans/{}/progress", WEB_SCAN_ID)):
            p = route.format(sid)
            for label, suffix in [("missing", ""), ("ticket-garbage", f"?ticket={GARBAGE}"),
                                  ("ticket-legacy-hs256", f"?ticket={HS}"),
                                  ("ticket-es256-unknown-kid", f"?ticket={ES}")]:
                add(ws_case(f"ws {route} {label}", target, p + suffix))
            add(ws_case(f"ws {route} bearer-header-only garbage", target, p,
                        headers={"Authorization": f"Bearer {GARBAGE}"}))

        # 5. SSE
        for p in ("/notifications/stream", "/scans/events"):
            add(http_case(f"sse {p} missing", target, "GET", p, headers={"Accept": "text/event-stream"}))
            add(http_case(f"sse {p} garbage", target, "GET", p,
                          headers={"Accept": "text/event-stream", "Authorization": f"Bearer {GARBAGE}"}))

        # 6. /api/ir/*
        for p in ("/ir/", "/ir/health", "/ir/incidents"):
            add(http_case(f"ir {p} missing", target, "GET", p))
            add(http_case(f"ir {p} garbage", target, "GET", p, headers={"Authorization": f"Bearer {GARBAGE}"}))

        # 7. X-Request-ID
        add(http_case("xrid none, 200", target, "GET", "/"))
        add(http_case("xrid client value, 200", target, "GET", "/", headers={"X-Request-ID": "probe-rid-0001"}))
        add(http_case("xrid client value, 403", target, "GET", "/scans", headers={"X-Request-ID": "probe-rid-0002"}))
        add(http_case("xrid client 300-char value", target, "GET", "/", headers={"X-Request-ID": "r" * 300}))

        # 8. CORS
        pre = {"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,content-type"}
        add(http_case("cors preflight allowed origin /auth/login", target, "OPTIONS", "/auth/login",
                      headers={"Origin": ALLOWED_ORIGIN, **pre}))
        add(http_case("cors preflight disallowed origin /auth/login", target, "OPTIONS", "/auth/login",
                      headers={"Origin": EVIL_ORIGIN, **pre}))
        add(http_case("cors preflight allowed origin protected /scans", target, "OPTIONS", "/scans",
                      headers={"Origin": ALLOWED_ORIGIN, "Access-Control-Request-Method": "GET",
                               "Access-Control-Request-Headers": "authorization"}))
        add(http_case("cors PNA preflight allowed", target, "OPTIONS", "/scans",
                      headers={"Origin": ALLOWED_ORIGIN, "Access-Control-Request-Method": "GET",
                               "Access-Control-Request-Private-Network": "true"}))
        add(http_case("cors PNA preflight disallowed", target, "OPTIONS", "/scans",
                      headers={"Origin": EVIL_ORIGIN, "Access-Control-Request-Method": "GET",
                               "Access-Control-Request-Private-Network": "true"}))
        add(http_case("cors simple GET allowed origin", target, "GET", "/", headers={"Origin": ALLOWED_ORIGIN}))
        add(http_case("cors simple GET disallowed origin", target, "GET", "/", headers={"Origin": EVIL_ORIGIN}))
        add(http_case("cors 403 allowed origin", target, "GET", "/scans", headers={"Origin": ALLOWED_ORIGIN}))

        # 9. refresh cookie (failure paths only; the valid path is live_valid_probe.py)
        add(http_case("refresh no cookie", target, "POST", "/auth/refresh", headers=J, body=b"{}"))
        add(http_case("refresh garbage cookie", target, "POST", "/auth/refresh",
                      headers={**J, "Cookie": f"ccure_refresh_token={GARBAGE}"}, body=b"{}"))
        add(http_case("refresh legacy-hs256 cookie", target, "POST", "/auth/refresh",
                      headers={**J, "Cookie": f"ccure_refresh_token={HS}"}, body=b"{}"))
        add(http_case("logout no cookie", target, "POST", "/auth/logout", headers=J, body=b"{}"))
        add(http_case("ticket issuance without bearer", target, "POST", "/auth/ticket"))

    # 10. SPA routes carrying a query token (edge only — the SPA is not on :8000)
    for p in ("SPA:/", "SPA:/index.html", "SPA:/reset-password?token=probe-not-a-token",
              "SPA:/verify-email?token=probe-not-a-token", "SPA:/assets/index-CkVhwOG4.js",
              "SPA:/api", "SPA:/API/scans"):
        add(http_case(f"spa {p[4:]}", "edge", "GET", p))

    # 11. The frontend container's own /api/ proxy on loopback :3200 (M6 bypass)
    for label, path, hdr in [("3200 /api/ root", "/api/", {}), ("3200 /api/scans missing", "/api/scans", {})]:
        conn = http.client.HTTPConnection("127.0.0.1", 3200, timeout=10)
        try:
            conn.request("GET", path, headers=hdr)
            r = conn.getresponse()
            r.read(200)
            pairs, counts, _ = _headers_view(r.getheaders())
            out.append({"id": label, "target": "frontend-3200", "method": "GET", "path": path,
                        "status": r.status, "headers": pairs, "header_counts": counts})
        finally:
            conn.close()

    json.dump({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "cases": out}, sys.stdout, indent=1)


if __name__ == "__main__":
    main()
