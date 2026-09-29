#!/usr/bin/env python3
"""
Phase 10.1 — characterisation of the VALID-credential paths through the current
edge (host nginx), for the owner to run interactively. Standard library only.

It signs in once as the person running it (password read with getpass, never
echoed, never written), exercises the carriers below, and signs out — which
revokes only the session it created. What it writes on the server is what an
ordinary sign-in writes: a refresh-session row and its rotation, and audit
entries for login, ticket issuance, downloads and logout. The report it
downloads is already stored, so nothing is regenerated.

Nothing secret reaches the output: token values become <JWT>, query secrets
become <X>, cookie values are recorded as a SHA-256 prefix (so rotation is
visible without the value), and downloaded bodies as size + SHA-256.

    python3 scripts/gateway/characterization/live_valid_probe.py
        [--out docs/architecture/phase10/valid_probe_results.json]
        [--skip-expiry-wait]
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import sys
import time

EDGE_HOST = os.environ.get("CCURE_EDGE_HOST", "127.0.0.1")
EDGE_NAME = os.environ.get("CCURE_EDGE_NAME", "ccurepro.cdac.in")
DIRECT_PORT = 8000
SCAN_ID = os.environ.get("CCURE_PROBE_SCAN", "scn_defa_c522b539_29sep26_fh9j")
WEB_SCAN_ID = os.environ.get("CCURE_PROBE_WEB_SCAN", "wsc_defa_c522b539_29sep26_sy97")
ORIGIN = "https://ccurepro.cdac.in"
COOKIE = "ccure_refresh_token"
J = {"Content-Type": "application/json"}

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE
_JWT = re.compile(r"eyJ[\w.-]*")  # any JWT prefix, complete or not
_Q = re.compile(r"(ticket|token)=[^&\s\"]+")


def red(s: str) -> str:
    return _Q.sub(r"\1=<X>", _JWT.sub("<JWT>", s))


def h8(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:8]


def _conn(target, timeout=60):
    if target == "edge":
        return http.client.HTTPSConnection(EDGE_HOST, 443, context=_CTX, timeout=timeout)
    return http.client.HTTPConnection("127.0.0.1", DIRECT_PORT, timeout=timeout)


def _path(target, p):
    return "/api" + p if target == "edge" else p


def _cookies(pairs):
    """(recorded view, raw refresh-cookie value or None)."""
    view, raw = [], None
    for k, v in pairs:
        if k != "set-cookie":
            continue
        name, _, rest = v.partition("=")
        value, _, attrs = rest.partition(";")
        view.append({"name": name, "value_sha8": h8(value) if value else "",
                     "empty_value": value in ("", '""'), "attributes": attrs.strip()})
        if name == COOKIE and value not in ("", '""'):
            raw = value
    return view, raw


def call(case, target, method, p, headers=None, body=None, sse_seconds=None):
    """Returns (record, parsed JSON body or None, raw refresh cookie or None)."""
    headers = dict(headers or {})
    if target == "edge":
        headers.setdefault("Host", EDGE_NAME)
    rec = {"id": case, "target": target, "method": method, "path": red(_path(target, p)),
           "request_headers": sorted(k for k in headers if k.lower() != "host")}
    parsed, raw_cookie = None, None
    # An SSE read blocks until the next event; the socket timeout bounds it.
    c = _conn(target, timeout=(sse_seconds + 3) if sse_seconds else 60)
    t0 = time.monotonic()
    try:
        c.request(method, _path(target, p), body=body, headers=headers)
        r = c.getresponse()
        pairs = [(k.lower(), v) for k, v in r.getheaders()]
        rec["status"] = r.status
        counts: dict[str, int] = {}
        for k, _ in pairs:
            counts[k] = counts.get(k, 0) + 1
        rec["header_counts"] = counts
        rec["headers"] = [(k, red(v)) for k, v in pairs if k != "set-cookie"]
        rec["set_cookie"], raw_cookie = _cookies(pairs)
        ctype = r.getheader("content-type") or ""
        if sse_seconds and r.status == 200:
            events, buf, end = [], b"", time.monotonic() + sse_seconds
            rec["sse_stopped"] = "duration"
            while time.monotonic() < end:
                try:
                    chunk = r.fp.read1(4096)  # raw: chunk-size lines are harmless to event parsing
                except (socket.timeout, TimeoutError):
                    rec["sse_stopped"] = "idle timeout"
                    break
                if not chunk:
                    rec["sse_stopped"] = "server closed"
                    break
                buf += chunk
                while b"\n\n" in buf:
                    msg, buf = buf.split(b"\n\n", 1)
                    name = next((ln[6:].strip().decode() for ln in msg.split(b"\n")
                                 if ln.startswith(b"event:")), "message")
                    events.append({"event": name, "at_ms": round((time.monotonic() - t0) * 1000),
                                   "bytes": len(msg)})
            rec["sse_events"] = events
        else:
            digest, size, head = hashlib.sha256(), 0, b""
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
                if len(head) < 8192:
                    head += chunk
            rec["bytes"], rec["sha256"] = size, digest.hexdigest()
            if "json" in ctype and size < 1_000_000:
                try:
                    parsed = json.loads(head if size <= len(head) else b"null")
                except ValueError:
                    parsed = None
                if r.status >= 400:  # refusal bodies only; a success body is live data
                    rec["body_sample"] = red(head.decode("utf-8", "replace"))[:300]  # redact, then truncate
                if isinstance(parsed, dict):
                    rec["response_keys"] = sorted(parsed)
    except Exception as exc:
        rec["error"] = repr(exc)
    finally:
        rec["ms"] = round((time.monotonic() - t0) * 1000, 1)
        c.close()
    return rec, parsed, raw_cookie


def ws(case, target, p, frames_wanted=1):
    key = base64.b64encode(os.urandom(16)).decode()
    host = EDGE_NAME if target == "edge" else f"127.0.0.1:{DIRECT_PORT}"
    req = (f"GET {_path(target, p)} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
           f"Origin: {ORIGIN}\r\n\r\n").encode()
    rec = {"id": case, "target": target, "method": "WS", "path": red(_path(target, p))}
    s = None
    try:
        s = socket.create_connection((EDGE_HOST if target == "edge" else "127.0.0.1",
                                      443 if target == "edge" else DIRECT_PORT), timeout=10)
        if target == "edge":
            s = _CTX.wrap_socket(s, server_hostname=EDGE_NAME)
        s.sendall(req)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        head, _, data = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin1").split("\r\n")
        rec["status"] = int(lines[0].split()[1])
        rec["headers"] = [(ln.split(":", 1)[0].strip().lower(), red(ln.split(":", 1)[1].strip()))
                          for ln in lines[1:] if ":" in ln]
        frames = []

        def need(n):
            nonlocal data
            while len(data) < n:
                chunk = s.recv(65536)
                if not chunk:
                    raise ConnectionError("closed mid-frame")
                data += chunk

        if rec["status"] == 101:
            t0 = time.monotonic()
            while len(frames) < frames_wanted and time.monotonic() - t0 < 10:
                try:
                    need(2)
                except (socket.timeout, TimeoutError):
                    rec["frames_note"] = f"no further frame within the socket timeout after {len(frames)}"
                    break
                opcode, ln, off = data[0] & 0x0F, data[1] & 0x7F, 2
                if ln == 126:
                    need(4)
                    ln, off = int.from_bytes(data[2:4], "big"), 4
                elif ln == 127:
                    need(10)
                    ln, off = int.from_bytes(data[2:10], "big"), 10
                need(off + ln)
                payload, data = data[off:off + ln], data[off + ln:]
                entry = {"opcode": opcode, "bytes": ln, "at_ms": round((time.monotonic() - t0) * 1000)}
                if opcode == 1:
                    try:
                        obj = json.loads(payload)
                        if isinstance(obj, dict):
                            entry["json_keys"] = sorted(obj)
                            entry["type"] = obj.get("type") or obj.get("event")
                            entry["status"] = obj.get("status")
                    except ValueError:
                        entry["text_len"] = len(payload)
                elif opcode == 8:
                    entry["close_code"] = int.from_bytes(payload[:2], "big") if ln >= 2 else None
                frames.append(entry)
                if opcode == 8:
                    break
            # client close frame (masked, zero mask), status 1000
            s.sendall(bytes([0x88, 0x82, 0, 0, 0, 0, 0x03, 0xE8]))
        rec["frames"] = frames
    except Exception as exc:
        rec["error"] = repr(exc)
    finally:
        if s:
            s.close()
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="docs/architecture/phase10/valid_probe_results.json")
    ap.add_argument("--skip-expiry-wait", action="store_true")
    args = ap.parse_args()

    # Non-interactive use: CCURE_PROBE_IDENT / CCURE_PROBE_PASSWORD (environment
    # only — never argv, which any local user can read from the process list).
    ident = os.environ.pop("CCURE_PROBE_IDENT", "") or input("Email or username: ").strip()
    pw = os.environ.pop("CCURE_PROBE_PASSWORD", "") or getpass.getpass("Password (not echoed): ")
    out: list[dict] = []

    rec, body, cookie = call("login", "edge", "POST", "/auth/login", J,
                             json.dumps({"email_or_username": ident, "password": pw}).encode())
    pw = None
    out.append(rec)
    if isinstance(body, dict) and body.get("status") == "mfa_required":
        mfa_token = body["mfa_token"]
        code = input("MFA required. TOTP code, or 'email' to have one sent: ").strip()
        if code.lower() == "email":
            r2, _, _ = call("mfa send-email-otp", "edge", "POST", "/auth/login/send-email-otp", J,
                            json.dumps({"mfa_token": mfa_token}).encode())
            out.append(r2)
            code = input("Code from the email: ").strip()
        rec, body, cookie = call("login verify-mfa", "edge", "POST", "/auth/login/verify-mfa", J,
                                 json.dumps({"mfa_token": mfa_token, "code": code}).encode())
        out.append(rec)
    access = body.get("access_token") if isinstance(body, dict) else None
    if not access or not cookie:
        print("Sign-in did not produce an access token and a refresh cookie; stopping.", file=sys.stderr)
        json.dump({"cases": out}, open(args.out, "w"), indent=1)
        return
    B = {"Authorization": f"Bearer {access}"}

    def add(item):
        out.append(item[0] if isinstance(item, tuple) else item)
        return item

    # bearer baseline, CORS on an authenticated response, X-Request-ID echo
    add(call("bearer GET /scans?limit=1", "edge", "GET", "/scans?limit=1", B))
    add(call("bearer GET /scans?limit=1 allowed Origin", "edge", "GET", "/scans?limit=1", {**B, "Origin": ORIGIN}))
    add(call("bearer GET /scans?limit=1 client X-Request-ID", "edge", "GET", "/scans?limit=1",
             {**B, "X-Request-ID": "probe-rid-valid"}))

    # 1. GET /api/reports/download/<scan_id>
    dl = f"/reports/download/{SCAN_ID}"
    add(call("download bearer", "edge", "GET", dl, B))
    add(call("download bearer (direct :8000)", "direct", "GET", dl, B))
    trec, tbody, _ = add(call("ticket issue", "edge", "POST", "/auth/ticket", B))
    ticket = tbody.get("ticket") if isinstance(tbody, dict) else None
    if ticket:
        add(call("download ticket", "edge", "GET", f"{dl}?ticket={ticket}"))
        add(call("download same ticket again (replay within 60 s)", "edge", "GET", f"{dl}?ticket={ticket}"))
        add(call("download ticket (direct :8000, same ticket)", "direct", "GET", f"{dl}?ticket={ticket}"))
        add(call("ticket used as bearer on /scans", "edge", "GET", "/scans?limit=1",
                 {"Authorization": f"Bearer {ticket}"}))
        add(call("ticket + valid bearer on download", "edge", "GET", f"{dl}?ticket={ticket}", B))
    add(call("access token passed as ?ticket=", "edge", "GET", f"{dl}?ticket={access}"))
    add(call("valid bearer + garbage ticket on download", "edge", "GET", f"{dl}?ticket=not-a-token", B))

    # 2. WebSocket ticket routes
    _, wbody, _ = add(call("ticket issue (ws)", "edge", "POST", "/auth/ticket", B))
    wt = wbody.get("ticket") if isinstance(wbody, dict) else None
    if wt:
        add(ws("ws scans progress valid ticket", "edge", f"/scans/{SCAN_ID}/progress?ticket={wt}", 2))
        add(ws("ws scans progress same ticket again", "edge", f"/scans/{SCAN_ID}/progress?ticket={wt}"))
        add(ws("ws web-scans progress same ticket", "edge", f"/web-scans/{WEB_SCAN_ID}/progress?ticket={wt}", 2))
        add(ws("ws scans progress same ticket (direct :8000)", "direct", f"/scans/{SCAN_ID}/progress?ticket={wt}"))
    add(ws("ws scans progress access token as ticket", "edge", f"/scans/{SCAN_ID}/progress?ticket={access}"))

    # 3. SSE and a StreamingResponse download
    add(call("sse notifications 8 s", "edge", "GET", "/notifications/stream",
             {**B, "Accept": "text/event-stream"}, sse_seconds=8))
    add(call("sse scans/events 8 s", "edge", "GET", "/scans/events?scope=active",
             {**B, "Accept": "text/event-stream"}, sse_seconds=8))
    add(call("streaming: ISO SoA pdf", "edge", "GET",
             "/compliance/reports/soa?framework_id=cfw_iso27001_2022&fmt=pdf", B))

    # 4. refresh cookie: rotate, reuse the old one, log out, reuse after logout
    r1, b1, rotated = call("refresh valid cookie", "edge", "POST", "/auth/refresh",
                           {**J, "Cookie": f"{COOKIE}={cookie}", "Origin": ORIGIN}, b"{}")
    out.append(r1)
    r1["rotated"] = bool(rotated) and rotated != cookie
    add(call("refresh with the pre-rotation cookie (reuse)", "edge", "POST", "/auth/refresh",
             {**J, "Cookie": f"{COOKIE}={cookie}"}, b"{}"))
    current = rotated or cookie
    add(call("logout with current cookie", "edge", "POST", "/auth/logout",
             {**J, "Cookie": f"{COOKIE}={current}"}, b"{}"))
    add(call("refresh after logout", "edge", "POST", "/auth/refresh",
             {**J, "Cookie": f"{COOKIE}={current}"}, b"{}"))
    add(call("access token still accepted after logout", "edge", "GET", "/scans?limit=1", B))

    if ticket and not args.skip_expiry_wait:
        print("Waiting 61 s to characterise an expired ticket (--skip-expiry-wait skips this)…")
        time.sleep(61)
        add(call("download expired ticket (>60 s)", "edge", "GET", f"{dl}?ticket={ticket}"))

    json.dump({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "cases": out}, open(args.out, "w"), indent=1)
    leaked = [m for m in ("eyJ",) if m in open(args.out).read()]
    print(f"Wrote {args.out}" + ("" if not leaked else "  WARNING: token-shaped text present"))


if __name__ == "__main__":
    main()
