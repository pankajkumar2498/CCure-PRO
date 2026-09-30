#!/usr/bin/env python3
"""
Phase 10.5 — live validation of the production edge, before and after the
cut-over to the gateway. Standard library only; run on the VM.

    live_checks.py capture   --out edge_before.json   # no credential needed
    live_checks.py compare   edge_before.json edge_after.json
    live_checks.py latency   --out lat.json [--n 200]
    live_checks.py ratelimit --out rl.json
    live_checks.py valid     --out valid.json         # the OWNER runs this:
                                                      # password via getpass

``capture`` sends the same request set to :443 (host nginx) and to :8000
(direct) and records, per case, status, header multiset and body. Run once
before the cut-over and once after, ``compare`` proves that what a client of
:443 sees is unchanged — with exactly one expected class of difference, a
refusal the gateway answered itself, which carries no X-Request-ID and
``"request_id": null`` (frozen decision, Phase 10.1).

Read-only by construction, like the 10.1 edge probe: no credential in
``capture``, every POST carries an empty body the API refuses, the one DELETE
names a report that does not exist, and requests to /api/auth/ are paced under
host nginx's ccure_auth zone (30 r/m, burst 10).

``valid`` signs in once as the person running it and signs out at the end,
which revokes only the session it created. The upload case sends 20 MiB the
application refuses by content (declared text/plain, last byte not UTF-8), so
the whole body must arrive for the refusal to happen and nothing is stored.

Nothing secret reaches any output file: token values become <JWT>, query
secrets <X>, cookie values a SHA-256 prefix, success bodies a size + digest.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import ssl
import statistics
import sys
import time
import uuid

EDGE_HOST = os.environ.get("CCURE_EDGE_HOST", "127.0.0.1")
EDGE_NAME = os.environ.get("CCURE_EDGE_NAME", "ccurepro.cdac.in")
EDGE_PORT = int(os.environ.get("CCURE_EDGE_PORT", "443"))
DIRECT_PORT = int(os.environ.get("CCURE_DIRECT_PORT", "8000"))
SCAN_ID = os.environ.get("CCURE_PROBE_SCAN", "scn_defa_c522b539_29sep26_fh9j")
WEB_SCAN_ID = os.environ.get("CCURE_PROBE_WEB_SCAN", "wsc_defa_c522b539_29sep26_sy97")
CONTROL_ID = os.environ.get("CCURE_PROBE_CONTROL", "cct_iso27001_2022_5_1")
ALLOWED_ORIGIN = "https://ccurepro.cdac.in"
EVIL_ORIGIN = "https://evil.example"
COOKIE = "ccure_refresh_token"
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
POLICY = os.path.join(REPO, "gateway", "policy", "route_policy.json")

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE
_JWT = re.compile(r"eyJ[\w.-]*")
_Q = re.compile(r"(ticket|token)=[^&\s\"]+")
# Values that legitimately differ run to run.
VOLATILE = {"date", "x-request-id", "x-ratelimit-reset", "x-ratelimit-remaining", "content-length"}
_RAW_COOKIE: list = [None]  # the refresh cookie from the last response that set one
SPOOF = {
    "X-Tenant-ID": "org_spoof", "X-User-ID": "usr_spoof", "X-Ccure-Auth-Sub": "usr_spoof",
    "X-Forwarded-User": "spoof", "X-Remote-User": "spoof", "X-Ccure-Policy": "none",
}


def red(s: str) -> str:
    return _Q.sub(r"\1=<X>", _JWT.sub("<JWT>", s))


def h8(s) -> str:
    return hashlib.sha256(s if isinstance(s, bytes) else s.encode()).hexdigest()[:12]


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def fake_jwt(alg="HS256", kid=None, kind="access") -> str:
    head = {"alg": alg, "typ": "JWT"} | ({"kid": kid} if kid else {})
    body = {"sub": "usr_probe", "type": kind, "exp": 4102444800}
    h, b = _b64(json.dumps(head).encode()), _b64(json.dumps(body).encode())
    sig = hmac.new(os.urandom(32), f"{h}.{b}".encode(), hashlib.sha256).digest()
    return f"{h}.{b}.{_b64(sig)}"


# ── transport ─────────────────────────────────────────────────────────────────
def _conn(target, timeout=30, source=None):
    if target == "edge":
        host = source or EDGE_HOST
        return http.client.HTTPSConnection(host, EDGE_PORT, context=_CTX, timeout=timeout)
    return http.client.HTTPConnection("127.0.0.1", DIRECT_PORT, timeout=timeout)


def _path(target, p):
    return "/api" + p if target == "edge" else p


def request(case, target, method, p, headers=None, body=None, *, sse_seconds=None,
            keep_success_body=False, edge_addr=None):
    headers = dict(headers or {})
    if target == "edge":
        headers.setdefault("Host", EDGE_NAME)
    rec = {"id": case, "target": target, "method": method, "path": red(_path(target, p))}
    parsed = None
    c = _conn(target, timeout=(sse_seconds + 5) if sse_seconds else 60, source=edge_addr)
    t0 = time.monotonic()
    try:
        c.request(method, _path(target, p), body=body, headers=headers)
        r = c.getresponse()
        pairs = [(k.lower(), v) for k, v in r.getheaders()]
        rec["status"] = r.status
        rec["headers"] = sorted([k, red(v) if k != "set-cookie" else "<cookie>"] for k, v in pairs)
        for k, v in pairs:
            name, _, rest = v.partition("=")
            if k == "set-cookie" and name == COOKIE and rest.split(";", 1)[0] not in ("", '""'):
                _RAW_COOKIE[0] = rest.split(";", 1)[0]
        ctype = r.getheader("content-type") or ""
        if sse_seconds and r.status == 200:
            events, buf, end = [], b"", time.monotonic() + sse_seconds
            while time.monotonic() < end:
                try:
                    chunk = r.fp.read1(4096)
                except (socket.timeout, TimeoutError):
                    break
                if not chunk:
                    break
                buf += chunk
                while b"\n\n" in buf:
                    msg, buf = buf.split(b"\n\n", 1)
                    name = next((ln[6:].strip().decode() for ln in msg.split(b"\n")
                                 if ln.startswith(b"event:")), "message")
                    events.append({"event": name, "at_ms": round((time.monotonic() - t0) * 1000)})
            rec["sse_events"] = events
        else:
            digest, size, head = hashlib.sha256(), 0, b""
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
                if len(head) < 65536:
                    head += chunk
            rec["bytes"], rec["sha256"] = size, digest.hexdigest()
            if "json" in ctype and size <= len(head):
                try:
                    parsed = json.loads(head)
                except ValueError:
                    parsed = None
            # Refusal and error bodies are recorded (redacted); a success body
            # is live data and is kept only as its digest unless asked.
            if r.status >= 300 or keep_success_body:
                rec["body"] = red(head.decode("utf-8", "replace"))[:2000]
    except Exception as exc:  # noqa: BLE001 — recorded, never raised
        rec["error"] = repr(exc)
    finally:
        rec["ms"] = round((time.monotonic() - t0) * 1000, 2)
        c.close()
    return rec, parsed


def ws(case, target, p, frames_wanted=1, edge_addr=None, hold=10):
    key = base64.b64encode(os.urandom(16)).decode()
    host = EDGE_NAME if target == "edge" else f"127.0.0.1:{DIRECT_PORT}"
    req = (f"GET {_path(target, p)} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
           f"Origin: {ALLOWED_ORIGIN}\r\n\r\n").encode()
    rec = {"id": case, "target": target, "method": "WS", "path": red(_path(target, p))}
    s = None
    try:
        s = socket.create_connection(((edge_addr or EDGE_HOST) if target == "edge" else "127.0.0.1",
                                      EDGE_PORT if target == "edge" else DIRECT_PORT), timeout=10)
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
        rec["headers"] = sorted([ln.split(":", 1)[0].strip().lower(), red(ln.split(":", 1)[1].strip())]
                                for ln in lines[1:] if ":" in ln)
        frames = []
        if rec["status"] == 101:
            t0 = time.monotonic()
            def need(n):
                nonlocal data
                while len(data) < n:
                    chunk = s.recv(65536)
                    if not chunk:
                        raise ConnectionError("closed mid-frame")
                    data += chunk

            s.settimeout(hold + 5)
            while len(frames) < frames_wanted and time.monotonic() - t0 < hold:
                try:
                    need(2)
                except (socket.timeout, TimeoutError):
                    rec["ended"] = f"open and silent until the {hold} s hold ended"
                    break
                except ConnectionError:
                    rec["ended"] = f"server closed the TCP connection at {round(time.monotonic() - t0, 1)} s"
                    break
                opcode, ln, off = data[0] & 0x0F, data[1] & 0x7F, 2
                if ln == 126:
                    need(4)
                    ln, off = int.from_bytes(data[2:4], "big"), 4
                need(off + ln)
                payload, data = data[off:off + ln], data[off + ln:]
                entry = {"opcode": opcode, "bytes": ln, "at_s": round(time.monotonic() - t0, 1)}
                if opcode == 1:
                    try:
                        obj = json.loads(payload)
                        entry["json_keys"] = sorted(obj) if isinstance(obj, dict) else None
                        entry["type"] = obj.get("type") if isinstance(obj, dict) else None
                    except ValueError:
                        pass
                frames.append(entry)
                if opcode == 8:
                    rec["ended"] = f"server close frame at {entry['at_s']} s"
                    break
            else:
                rec.setdefault("ended", f"held {hold} s")
            try:
                s.sendall(bytes([0x88, 0x82, 0, 0, 0, 0, 0x03, 0xE8]))
            except OSError:
                pass
        else:
            rest = data
            s.settimeout(2)
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    rest += chunk
            except (socket.timeout, TimeoutError, ssl.SSLError):
                pass
            rec["body_bytes"] = len(rest)
        rec["frames"] = frames
    except Exception as exc:  # noqa: BLE001
        rec["error"] = repr(exc)
    finally:
        if s:
            s.close()
    return rec


# ── pacing under host nginx's own zones ───────────────────────────────────────
class Pacer:
    """/api/auth/: 30 r/m burst 10 → one per 2.1 s. /api/: 20 r/s → 12 r/s."""

    def __init__(self):
        self.last = {"auth": 0.0, "api": 0.0}

    def wait(self, app_path):
        zone, gap = ("auth", 2.1) if app_path.startswith("/auth/") else ("api", 1 / 12)
        delta = time.monotonic() - self.last[zone]
        if delta < gap:
            time.sleep(gap - delta)
        self.last[zone] = time.monotonic()


def _fill(path):
    return re.sub(r"\{[^}]+\}", "p105x", path)


# ── capture: the credential-less matrix ───────────────────────────────────────
def capture(args):
    rules = json.load(open(POLICY))["routes"]
    pacer = Pacer()
    out = []

    def both(case, method, p, headers=None, body=None):
        pacer.wait(p)
        out.append(request(case, "edge", method, p, headers, body)[0])
        out.append(request(case, "direct", method, p, headers, body)[0])

    def both_ws(case, p):
        pacer.wait(p)
        out.append(ws(case, "edge", p))
        out.append(ws(case, "direct", p))

    garbage = "Bearer " + fake_jwt("ES256", kid="p105-unknown-kid")
    legacy = "Bearer " + fake_jwt("HS256")
    # 1. every authenticated HTTP route: missing credential, and a forged one
    for r in rules:
        if r["scope"] != "http" or r["class"] not in ("bearer", "ticket_or_bearer"):
            continue
        p = _fill(r["path"])
        body = b"" if r["method"] in ("POST", "PUT", "PATCH") else None
        both(f"{r['class']} missing {r['method']} {r['path']}", r["method"], p, None, body)
        both(f"{r['class']} forged-es256 {r['method']} {r['path']}", r["method"], p,
             {"Authorization": garbage}, body)
    # 2. every bearer refusal variant, on one route per zone
    for p in ("/scans?limit=1", "/auth/me"):
        for name, hdr in [("empty bearer", "Bearer "), ("basic", "Basic dXNlcjpwYXNz"),
                          ("garbage", "Bearer not-a-token"), ("legacy hs256", legacy),
                          ("lowercase scheme", "bearer " + fake_jwt("ES256", kid="x"))]:
            both(f"variant {name} GET {p}", "GET", p, {"Authorization": hdr})
        both(f"identity spoof, no credential GET {p}", "GET", p, SPOOF)
        both(f"allowed Origin refusal GET {p}", "GET", p, {"Origin": ALLOWED_ORIGIN})
        both(f"evil Origin refusal GET {p}", "GET", p, {"Origin": EVIL_ORIGIN})
        both(f"client X-Request-ID refusal GET {p}", "GET", p, {"X-Request-ID": "p105-rid-refusal"})
    # 3. tickets without a valid credential
    dl = f"/reports/download/{SCAN_ID}"
    ex = f"/reports/export/{SCAN_ID}"
    for name, q, hdr in [("invalid ticket", "?ticket=not-a-token", None),
                         ("empty ticket", "?ticket=", None),
                         ("legacy ticket", "?ticket=" + fake_jwt("HS256", kind="ticket"), None),
                         ("invalid ticket + garbage bearer", "?ticket=not-a-token", {"Authorization": garbage}),
                         ("no ticket, basic", "", {"Authorization": "Basic dXNlcjpwYXNz"})]:
        both(f"download {name}", "GET", dl + q, hdr)
        both(f"export {name}", "GET", ex + q, hdr)
    both("delete report invalid ticket (nonexistent id)", "DELETE", "/reports/scn_p105_does_not_exist?ticket=not-a-token")
    # 4. WebSockets
    for wp in (f"/scans/{SCAN_ID}/progress", f"/web-scans/{WEB_SCAN_ID}/progress"):
        both_ws(f"ws no ticket {wp}", wp)
        both_ws(f"ws invalid ticket {wp}", wp + "?ticket=not-a-token")
        both_ws(f"ws legacy ticket {wp}", wp + "?ticket=" + fake_jwt("HS256", kind="ticket"))
    # 5. public routes (read-only ones), health, OPTIONS, 404/405/307, /api/ir
    for p in ("/", "/auth/jwks.json", "/api/pipeline-modes", "/api/workflow-example"):
        both(f"public GET {p}", "GET", p)
        both(f"public GET {p} allowed Origin", "GET", p, {"Origin": ALLOWED_ORIGIN})
    both("public GET / client X-Request-ID", "GET", "/", {"X-Request-ID": "p105-rid-public"})
    both("public GET / identity spoof", "GET", "/", SPOOF)
    both("public POST /auth/login empty body", "POST", "/auth/login", {"Content-Type": "application/json"}, b"")
    for p, m in (("/scans", "GET"), ("/auth/login", "POST"), ("/reports/download/" + SCAN_ID, "GET")):
        for origin in (ALLOWED_ORIGIN, EVIL_ORIGIN):
            both(f"OPTIONS {p} {origin}", "OPTIONS", p,
                 {"Origin": origin, "Access-Control-Request-Method": m,
                  "Access-Control-Request-Headers": "authorization,content-type"})
    both("404 unknown path", "GET", "/p105-no-such-route")
    both("404 unknown path with bearer", "GET", "/p105-no-such-route", {"Authorization": garbage})
    both("405 wrong method", "PUT", "/auth/jwks.json", None, b"")
    both("307 trailing slash", "GET", "/scans/")
    both("307 trailing slash, forged proto+xff", "GET", "/scans/",
         {"X-Forwarded-Proto": "http", "X-Forwarded-For": "203.0.113.9", "X-Real-IP": "203.0.113.9"})
    for p, m in (("/ir/", "GET"), ("/ir/incidents", "GET"), ("/ir/incidents", "POST"), ("/ir/x/y", "DELETE")):
        both(f"ir {m} {p}", m, p, {"Authorization": garbage}, b"" if m == "POST" else None)
    # 6. the SPA and the plaintext redirect are host nginx's own, and unchanged
    for name, fn in (("spa /", lambda: _raw_https("/")),
                     ("http :80 redirect", lambda: _raw_http80("/api/scans"))):
        out.append({"id": name, "target": "edge", **fn()})
    json.dump({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "cases": out},
              open(args.out, "w"), indent=1)
    print(f"wrote {args.out}: {len(out)} records")


def _raw_https(p):
    c = http.client.HTTPSConnection(EDGE_HOST, 443, context=_CTX, timeout=15)
    c.request("GET", p, headers={"Host": EDGE_NAME})
    r = c.getresponse()
    body = r.read()
    rec = {"method": "GET", "path": p, "status": r.status, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
           "headers": sorted([k.lower(), v] for k, v in r.getheaders())}
    c.close()
    return rec


def _raw_http80(p):
    c = http.client.HTTPConnection(EDGE_HOST, 80, timeout=15)
    c.request("GET", p, headers={"Host": EDGE_NAME})
    r = c.getresponse()
    r.read()
    rec = {"method": "GET", "path": p, "status": r.status,
           "headers": sorted([k.lower(), v] for k, v in r.getheaders())}
    c.close()
    return rec


# ── compare ───────────────────────────────────────────────────────────────────
def _norm_body(body):
    if body is None:
        return None
    try:
        obj = json.loads(body)
    except ValueError:
        return body
    if isinstance(obj, dict) and "request_id" in obj:
        obj = dict(obj, request_id="<rid>" if obj["request_id"] else None)
    return obj


def _hdrs(rec):
    return sorted([k, "<v>" if k in VOLATILE else v] for k, v in rec.get("headers", []))


def compare(args):
    before = json.load(open(args.before))["cases"]
    after = json.load(open(args.after))["cases"]
    key = lambda r: (r["id"], r["target"])  # noqa: E731
    b, a = {key(r): r for r in before}, {key(r): r for r in after}
    report = {"identical": [], "gateway_refusal": [], "different": [], "missing": []}
    for k in sorted(b):
        if k not in a:
            report["missing"].append(k)
            continue
        x, y = b[k], a[k]
        same_status = x.get("status") == y.get("status")
        bx, by = _norm_body(x.get("body")), _norm_body(y.get("body"))
        hx, hy = _hdrs(x), _hdrs(y)
        same_body = bx == by if x.get("body") is not None else x.get("sha256") == y.get("sha256")
        if same_status and hx == hy and same_body:
            report["identical"].append("|".join(k))
            continue
        # The one expected class: the gateway answered a refusal itself.
        names_x = {n for n, _ in x.get("headers", [])}
        names_y = {n for n, _ in y.get("headers", [])}
        gw = (k[1] == "edge" and same_status and isinstance(bx, dict) and isinstance(by, dict)
              and bx.get("request_id") == "<rid>" and by.get("request_id") is None
              and {kk: vv for kk, vv in bx.items() if kk != "request_id"}
              == {kk: vv for kk, vv in by.items() if kk != "request_id"}
              and "x-request-id" in names_x and "x-request-id" not in names_y)
        # a WebSocket refusal: bare 403 both times, and the app's X-Request-ID gone
        gw = gw or (k[1] == "edge" and x.get("method") == "WS" and same_status
                    and x.get("body_bytes") == y.get("body_bytes") == 0)
        entry = {"case": "|".join(k), "status": [x.get("status"), y.get("status")],
                 "header_names_only_before": sorted(names_x - names_y),
                 "header_names_only_after": sorted(names_y - names_x)}
        hv = {n: v for n, v in hx} , {n: v for n, v in hy}
        entry["header_values_changed"] = sorted(n for n in names_x & names_y
                                                if hv[0].get(n) != hv[1].get(n) and n not in VOLATILE)
        if not gw:
            entry["body_before"], entry["body_after"] = x.get("body"), y.get("body")
        report["gateway_refusal" if gw else "different"].append(entry)
    summary = {k: len(v) for k, v in report.items()}
    print(json.dumps(summary))
    for e in report["different"]:
        print("DIFF", json.dumps(e)[:600])
    if args.out:
        json.dump({"summary": summary, **report}, open(args.out, "w"), indent=1)
    return 1 if report["different"] or report["missing"] else 0


# ── latency / error rate ──────────────────────────────────────────────────────
def latency(args):
    res = {}
    for name, p in (("public GET /api/", "/"), ("bearer refusal GET /api/scans", "/scans?limit=1")):
        for target in ("edge", "direct"):
            ms, errors, statuses = [], 0, {}
            for _ in range(args.n):
                t0 = time.monotonic()
                rec, _ = request(name, target, "GET", p)
                ms.append((time.monotonic() - t0) * 1000)
                statuses[rec.get("status")] = statuses.get(rec.get("status"), 0) + 1
                errors += 1 if ("error" in rec or (rec.get("status") or 0) >= 500) else 0
                time.sleep(0.08)
            ms.sort()
            res[f"{name} [{target}]"] = {
                "n": args.n, "p50": round(statistics.median(ms), 2),
                "p95": round(ms[int(0.95 * len(ms)) - 1], 2), "p99": round(ms[int(0.99 * len(ms)) - 1], 2),
                "max": round(ms[-1], 2), "errors": errors, "statuses": {str(k): v for k, v in statuses.items()}}
            print(name, target, res[f"{name} [{target}]"])
    json.dump(res, open(args.out, "w"), indent=1)


# ── rate limiting: per-client buckets that a forged header cannot move ───────
def ratelimit(args):
    """GET /api/auth/check-email is public and limited 10/min per client. From
    two client addresses (loopback and the LAN address, both real $remote_addr
    values at host nginx), each request forging a fresh X-Forwarded-For and
    X-Real-IP: the 11th request is refused by the APPLICATION (X-Request-ID,
    RATE_LIMIT_EXCEEDED) for the first client, and the second client is
    unaffected. host nginx's ccure_auth zone (30 r/m, burst 10) admits 11."""
    lan = args.lan
    out = {"client_a": "127.0.0.1", "client_b": lan, "a": [], "b": []}
    p = "/auth/check-email?q=p105-" + uuid.uuid4().hex[:8] + "@example.com"
    for i in range(11):
        fake = f"203.0.113.{i + 1}"
        rec, _ = request(f"a{i}", "edge", "GET", p, {"X-Forwarded-For": fake, "X-Real-IP": fake,
                                                     "X-Forwarded-Proto": "http"}, edge_addr="127.0.0.1")
        names = {n for n, _ in rec.get("headers", [])}
        try:
            code = json.loads(rec.get("body") or "null")
            code = code.get("error_code") if isinstance(code, dict) else None
        except ValueError:
            code = "<non-json: host nginx>"
        out["a"].append({"i": i + 1, "status": rec.get("status"), "x_request_id": "x-request-id" in names,
                         "error_code": code})
    rec, _ = request("b0", "edge", "GET", p, {"X-Forwarded-For": "127.0.0.1"}, edge_addr=lan)
    out["b"].append({"status": rec.get("status")})
    a = out["a"]
    out["verdict"] = {
        "first_10_allowed": all(x["status"] == 200 for x in a[:10]),
        "11th_refused_by_application": a[10]["status"] == 429 and a[10]["x_request_id"]
        and a[10]["error_code"] == "RATE_LIMIT_EXCEEDED",
        "second_client_unaffected": out["b"][0]["status"] == 200,
    }
    print(json.dumps(out["verdict"]))
    json.dump(out, open(args.out, "w"), indent=1)


# ── valid credential (the owner runs this) ────────────────────────────────────
def valid(args):
    ident = os.environ.pop("CCURE_PROBE_IDENT", "") or input("Email or username: ").strip()
    pw = os.environ.pop("CCURE_PROBE_PASSWORD", "") or getpass.getpass("Password (not echoed): ")
    J = {"Content-Type": "application/json"}
    out, checks = [], {}

    def add(rec):
        out.append(rec[0] if isinstance(rec, tuple) else rec)
        return rec

    rec, body = request("login", "edge", "POST", "/auth/login", J,
                        json.dumps({"email_or_username": ident, "password": pw}).encode())
    pw = None
    out.append(rec)
    if isinstance(body, dict) and body.get("status") == "mfa_required":
        mfa = body["mfa_token"]
        code = input("MFA required. TOTP code, or 'email' to have one sent: ").strip()
        if code.lower() == "email":
            add(request("mfa send-email-otp", "edge", "POST", "/auth/login/send-email-otp", J,
                        json.dumps({"mfa_token": mfa}).encode()))
            code = input("Code from the email: ").strip()
        rec, body = request("login verify-mfa", "edge", "POST", "/auth/login/verify-mfa", J,
                            json.dumps({"mfa_token": mfa, "code": code}).encode())
        out.append(rec)
    access = body.get("access_token") if isinstance(body, dict) else None
    cookie_set = any(k == "set-cookie" for k, _ in rec.get("headers", []))
    checks["login through the gateway"] = bool(access) and cookie_set
    if not access:
        json.dump({"checks": checks, "cases": out}, open(args.out, "w"), indent=1)
        sys.exit("sign-in failed; nothing else was run")
    B = {"Authorization": f"Bearer {access}"}

    def same(name, e, d, *, body_equal=True):
        ok = e.get("status") == d.get("status") and (not body_equal or e.get("sha256") == d.get("sha256"))
        checks[name] = ok
        return ok

    # bearer, identity spoofing, X-Request-ID, CORS on a success
    e, _ = add(request("bearer /auth/me", "edge", "GET", "/auth/me", B))
    d, _ = add(request("bearer /auth/me", "direct", "GET", "/auth/me", B))
    same("bearer /auth/me edge == direct", e, d)
    s, _ = add(request("bearer /auth/me + spoofed identity headers", "edge", "GET", "/auth/me", {**B, **SPOOF}))
    checks["identity headers change nothing"] = s.get("status") == 200 and s.get("sha256") == e.get("sha256")
    r, _ = add(request("bearer /scans client X-Request-ID", "edge", "GET", "/scans?limit=1",
                       {**B, "X-Request-ID": "p105-rid-valid"}))
    rid = [v for k, v in r.get("headers", []) if k == "x-request-id"]
    checks["client X-Request-ID preserved once"] = rid == ["p105-rid-valid"]
    r, _ = add(request("bearer /scans allowed Origin", "edge", "GET", "/scans?limit=1", {**B, "Origin": ALLOWED_ORIGIN}))
    acao = [v for k, v in r.get("headers", []) if k == "access-control-allow-origin"]
    checks["CORS on an authenticated success"] = acao == [ALLOWED_ORIGIN]
    hsts = [v for k, v in r.get("headers", []) if k == "strict-transport-security"]
    checks["HSTS exactly once on a success"] = hsts == ["max-age=300"]

    # tickets and downloads
    dl = f"/reports/download/{SCAN_ID}"
    e, _ = add(request("download bearer", "edge", "GET", dl, B))
    d, _ = add(request("download bearer", "direct", "GET", dl, B))
    same("download (bearer) byte-identical edge == direct", e, d)
    _, t = add(request("ticket issue", "edge", "POST", "/auth/ticket", B))
    ticket = t.get("ticket") if isinstance(t, dict) else None
    if ticket:
        e, _ = add(request("download ticket", "edge", "GET", f"{dl}?ticket={ticket}"))
        checks["download (ticket) byte-identical to bearer"] = e.get("status") == 200 and e.get("sha256") == d.get("sha256")
        e2, _ = add(request("download ticket replay <60s", "edge", "GET", f"{dl}?ticket={ticket}"))
        checks["ticket reusable within 60 s (as characterised)"] = e2.get("status") == 200
        g, _ = add(request("valid ticket + garbage bearer", "edge", "GET", f"{dl}?ticket={ticket}",
                           {"Authorization": "Bearer not-a-token"}))
        checks["ticket evaluated first (valid ticket + garbage bearer = 200)"] = g.get("status") == 200
        tb, _ = add(request("ticket used as bearer on /scans", "edge", "GET", "/scans?limit=1",
                            {"Authorization": f"Bearer {ticket}"}))
        tbd, _ = add(request("ticket used as bearer on /scans", "direct", "GET", "/scans?limit=1",
                             {"Authorization": f"Bearer {ticket}"}))
        checks["ticket refused as a bearer, same status as direct"] = tb.get("status") == tbd.get("status") == 401
    g, _ = add(request("garbage ticket + valid bearer", "edge", "GET", f"{dl}?ticket=not-a-token", B))
    checks["garbage ticket + valid bearer = 401 (ticket first)"] = g.get("status") == 401
    x, _ = add(request("access token as ?ticket=", "edge", "GET", f"{dl}?ticket={access}"))
    xd, _ = add(request("access token as ?ticket=", "direct", "GET", f"{dl}?ticket={access}"))
    checks["access token refused as a ticket, same as direct"] = x.get("status") == xd.get("status") == 401
    de, _ = add(request("DELETE nonexistent report, bearer", "edge", "DELETE", "/reports/scn_p105_does_not_exist", B))
    dd, _ = add(request("DELETE nonexistent report, bearer", "direct", "DELETE", "/reports/scn_p105_does_not_exist", B))
    checks["DELETE /reports (ticket-or-bearer) same as direct"] = de.get("status") == dd.get("status")

    # WebSocket
    _, w = add(request("ticket issue (ws)", "edge", "POST", "/auth/ticket", B))
    wt = w.get("ticket") if isinstance(w, dict) else None
    if wt:
        we = add(ws("ws valid ticket", "edge", f"/scans/{SCAN_ID}/progress?ticket={wt}", 1))
        wd = add(ws("ws valid ticket", "direct", f"/scans/{SCAN_ID}/progress?ticket={wt}", 1))
        checks["WebSocket 101 + first frame, edge == direct"] = (
            we.get("status") == wd.get("status") == 101 and bool(we.get("frames"))
            and [f.get("json_keys") for f in we["frames"]] == [f.get("json_keys") for f in wd["frames"]])
        ww = add(ws("ws web-scan valid ticket", "edge", f"/web-scans/{WEB_SCAN_ID}/progress?ticket={wt}", 1))
        checks["web-scan WebSocket 101"] = ww.get("status") == 101

    # SSE and a streamed PDF
    se, _ = add(request("sse notifications", "edge", "GET", "/notifications/stream",
                        {**B, "Accept": "text/event-stream"}, sse_seconds=6))
    checks["SSE first event 'connected' < 2 s"] = bool(se.get("sse_events")) and \
        se["sse_events"][0]["event"] == "connected" and se["sse_events"][0]["at_ms"] < 2000
    pe, _ = add(request("SoA pdf", "edge", "GET", "/compliance/reports/soa?framework_id=cfw_iso27001_2022&fmt=pdf", B))
    checks["streamed PDF 200, complete"] = pe.get("status") == 200 and (pe.get("bytes") or 0) > 1000

    # 20 MiB upload, refused by content: the refusal needs the LAST byte
    boundary = "p105" + uuid.uuid4().hex
    payload = b"A" * (20 * 1024 * 1024 - 1) + b"\xff"
    mp = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"p105.txt\"\r\n"
          f"Content-Type: text/plain\r\n\r\n").encode() + payload + f"\r\n--{boundary}--\r\n".encode()
    H = {**B, "Content-Type": f"multipart/form-data; boundary={boundary}"}
    ue, _ = add(request("upload 20 MiB refused by content", "edge", "POST", f"/compliance/controls/{CONTROL_ID}/evidence", H, mp))
    ud, _ = add(request("upload 20 MiB refused by content", "direct", "POST", f"/compliance/controls/{CONTROL_ID}/evidence", H, mp))
    checks["20 MiB upload reaches the application whole (same 400 as direct)"] = (
        ue.get("status") == ud.get("status") == 400 and _norm_body(ue.get("body")) == _norm_body(ud.get("body"))
        and "binary data" in (ue.get("body") or ""))

    # authenticated latency, edge vs direct
    lat = {}
    for target in ("edge", "direct"):
        ms = []
        for _ in range(args.n):
            t0 = time.monotonic()
            request("lat", target, "GET", "/auth/me", B)
            ms.append((time.monotonic() - t0) * 1000)
            time.sleep(2.2 if target == "edge" else 0.05)  # /api/auth/ zone: 30 r/m
        ms.sort()
        lat[target] = {"n": args.n, "p50": round(statistics.median(ms), 2),
                       "p95": round(ms[int(0.95 * len(ms)) - 1], 2)}
    # refresh-cookie rotation through the gateway, then sign out with the
    # current cookie, which revokes this session and nothing else
    first = _RAW_COOKIE[0]
    rr, rb = add(request("refresh", "edge", "POST", "/auth/refresh",
                         {**J, "Cookie": f"{COOKIE}={first}", "Origin": ALLOWED_ORIGIN}, b"{}"))
    checks["refresh through the gateway rotates the cookie"] = (
        rr.get("status") == 200 and _RAW_COOKIE[0] not in (None, first)
        and isinstance(rb, dict) and bool(rb.get("access_token")))
    lo, _ = add(request("logout", "edge", "POST", "/auth/logout", {**J, "Cookie": f"{COOKIE}={_RAW_COOKIE[0]}"}, b"{}"))
    ra, _ = add(request("refresh after logout", "edge", "POST", "/auth/refresh",
                        {**J, "Cookie": f"{COOKIE}={_RAW_COOKIE[0]}"}, b"{}"))
    checks["logout revokes the session (refresh after logout = 401)"] = lo.get("status") == 200 and ra.get("status") == 401
    _RAW_COOKIE[0] = first = None
    out = json.loads(red(json.dumps(out)))
    json.dump({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "checks": checks,
               "latency_bearer_auth_me": lat, "cases": out}, open(args.out, "w"), indent=1)
    for k, v in checks.items():
        print(("PASS " if v else "FAIL ") + k)
    print("latency /auth/me:", lat)
    leaked = "eyJ" in open(args.out).read()
    print(f"wrote {args.out}" + ("  WARNING: token-shaped text present" if leaked else ""))


# ── 10.6: the gateway's trust boundary, live ─────────────────────────────────
GATEWAY_TCP = os.environ.get("CCURE_GATEWAY_TCP", "172.31.254.10:8080")
EDGE_SOCK = os.environ.get("CCURE_EDGE_SOCK", "/var/lib/ccure-edge/gateway.sock")


def trust(args):
    """A host process — this one — trying to borrow host nginx's authority.

    Over TCP to the gateway it forges X-Real-IP / X-Forwarded-For /
    X-Forwarded-Proto; the gateway must forward its own address and http, so
    the API's 429 names the bridge address and its redirect is http. On the
    edge socket it must be refused by the filesystem."""
    host, port = GATEWAY_TCP.split(":")
    out = {}

    def tcp(p, headers):
        c = http.client.HTTPConnection(host, int(port), timeout=15)
        c.request("GET", "/api" + p, headers={"Host": EDGE_NAME, **headers})
        r = c.getresponse()
        body = r.read()
        c.close()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, body

    forged = {"X-Real-IP": "203.0.113.77", "X-Forwarded-For": "203.0.113.77", "X-Forwarded-Proto": "https"}
    q = "/auth/check-email?q=p106-" + uuid.uuid4().hex[:8] + "@example.com"
    statuses = [tcp(q, forged)[0] for _ in range(11)]
    st, h, _ = tcp("/scans/", forged)
    out["tcp_forged"] = {
        "statuses": statuses,
        "redirect_status": st,
        "redirect_location": h.get("location"),
        "hsts_from_app": "strict-transport-security" in h,
    }
    time.sleep(1)
    try:
        import subprocess
        log = subprocess.run(["docker", "logs", "--since", "2m", "ccure-api"], capture_output=True, text=True).stderr
        ips = sorted({m.group(1) for m in re.finditer(r"RATE_LIMIT_REJECTED .*? ip=(\S+)", log)
                      if "/auth/check-email" in m.group(0)})
        out["tcp_forged"]["rate_limit_rejected_ips"] = ips
    except Exception as exc:  # noqa: BLE001
        out["tcp_forged"]["rate_limit_rejected_ips"] = f"unavailable: {exc!r}"
    try:
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(3)
        s.connect(EDGE_SOCK)
        s.close()
        out["socket_as_this_user"] = "CONNECTED"
    except Exception as exc:  # noqa: BLE001
        out["socket_as_this_user"] = type(exc).__name__
    t = out["tcp_forged"]
    out["verdict"] = {
        "tcp caller rate-limited on its own address": statuses[:10] == [200] * 10 and statuses[10] == 429
        and t.get("rate_limit_rejected_ips") == ["172.31.254.1"],
        "tcp caller cannot forge https": st == 307 and (t["redirect_location"] or "").startswith("http://")
        and not t["hsts_from_app"],
        "socket refuses a non-www-data host process": os.getuid() != 0 and out["socket_as_this_user"] == "PermissionError",
    }
    print(json.dumps(out["verdict"], indent=1))
    json.dump(out, open(args.out, "w"), indent=1)
    return 0 if all(out["verdict"].values()) else 1


def _jwt_exp(token: str) -> float:
    part = token.split(".")[1]
    return float(json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))["exp"])


def observe(args):
    """The owner's long run: the full `valid` battery, then one session held
    past its access token's expiry — a notification stream open throughout
    (heartbeats), a WebSocket held open, the expired token refused through the
    gateway, a silent refresh, the new token accepted, and logout. About 32
    minutes. Nothing secret is printed or written."""
    import threading

    ident = os.environ.pop("CCURE_PROBE_IDENT", "") or input("Email or username: ").strip()
    pw = os.environ.pop("CCURE_PROBE_PASSWORD", "") or getpass.getpass("Password (not echoed): ")
    mfa_hint = ""
    # 1. the one-minute battery, with its own sign-in and sign-out
    os.environ["CCURE_PROBE_IDENT"], os.environ["CCURE_PROBE_PASSWORD"] = ident, pw
    battery = argparse.Namespace(out=args.out.replace(".json", "_battery.json"), n=args.n)
    print("== 1. the valid-credential battery")
    valid(battery)
    # 2. the long session
    print("== 2. one session held past its access token's lifetime")
    J = {"Content-Type": "application/json"}
    checks, notes = {}, {}
    rec, body = request("login", "edge", "POST", "/auth/login", J,
                        json.dumps({"email_or_username": ident, "password": pw}).encode())
    pw = None
    if isinstance(body, dict) and body.get("status") == "mfa_required":
        code = input("MFA required for the long session. TOTP code: ").strip()
        rec, body = request("login verify-mfa", "edge", "POST", "/auth/login/verify-mfa", J,
                            json.dumps({"mfa_token": body["mfa_token"], "code": code}).encode())
    access = body.get("access_token") if isinstance(body, dict) else None
    cookie = _RAW_COOKIE[0]
    if not access or not cookie:
        sys.exit("sign-in for the long session failed")
    B = {"Authorization": f"Bearer {access}"}
    exp = _jwt_exp(access)
    wait = max(0.0, exp - time.time()) + 20
    # Dry runs only (a throwaway stack): cap the wait so the code path can be
    # exercised in minutes; the expiry check then fails, as it should.
    if os.environ.get("CCURE_OBSERVE_MAX_WAIT"):
        wait = min(wait, float(os.environ["CCURE_OBSERVE_MAX_WAIT"]))
    notes["access_token_lifetime_remaining_s"] = round(exp - time.time())
    print(f"   access token expires in {notes['access_token_lifetime_remaining_s']} s; holding the session until then + 20 s")

    events, stream_end = [], {}

    def sse():
        c = _conn("edge", timeout=90)
        t0 = time.monotonic()
        try:
            c.request("GET", "/api/notifications/stream",
                      headers={"Host": EDGE_NAME, "Accept": "text/event-stream", **B})
            r = c.getresponse()
            stream_end["status"] = r.status
            buf = b""
            while time.monotonic() - t0 < wait + 30:
                chunk = r.fp.read1(4096)
                if not chunk:
                    stream_end["why"] = "server closed"
                    break
                buf += chunk
                while b"\n\n" in buf:
                    msg, buf = buf.split(b"\n\n", 1)
                    name = next((ln[6:].strip().decode() for ln in msg.split(b"\n") if ln.startswith(b"event:")),
                                 "comment" if msg.startswith(b":") else "message")
                    events.append((round(time.monotonic() - t0, 1), name))
            else:
                stream_end["why"] = "observation ended"
        except Exception as exc:  # noqa: BLE001
            stream_end["why"] = repr(exc)
        finally:
            c.close()

    th = threading.Thread(target=sse, daemon=True)
    th.start()
    _, tb = request("ticket (ws)", "edge", "POST", "/auth/ticket", B)
    wt = tb.get("ticket") if isinstance(tb, dict) else None
    wrec = ws("ws held 120 s", "edge", f"/scans/{SCAN_ID}/progress?ticket={wt}", 1000, hold=120) if wt else {}
    checks["WebSocket upgraded through the gateway and delivered its first frame"] = (
        wrec.get("status") == 101 and bool(wrec.get("frames")) and "error" not in wrec)
    notes["websocket"] = {"status": wrec.get("status"), "frames": len(wrec.get("frames", [])),
                          "ended": wrec.get("ended"), "error": wrec.get("error")}
    # An absolute deadline: the WebSocket above may close well before its
    # hold, so time is measured from the token's own expiry, never from here.
    end = time.time() + wait if os.environ.get("CCURE_OBSERVE_MAX_WAIT") else exp + 20
    while time.time() < end:
        time.sleep(min(300, max(0, end - time.time())))
        print(f"   {time.strftime('%H:%M:%S')}  stream events so far: {len(events)}")
    # 3. the expired token, the refresh, the new token
    notes["checked_after_expiry_s"] = round(time.time() - exp, 1)
    e, _ = request("expired access token", "edge", "GET", "/auth/me", B)
    d, _ = request("expired access token", "direct", "GET", "/auth/me", B)
    notes["expired_token_status"] = {"edge": e.get("status"), "direct": d.get("status"),
                                     "edge_body": e.get("body")}
    checks["expired access token refused through the gateway (401, same as direct)"] = \
        e.get("status") == d.get("status") == 401
    rr, rb = request("refresh after expiry", "edge", "POST", "/auth/refresh",
                     {**J, "Cookie": f"{COOKIE}={cookie}", "Origin": ALLOWED_ORIGIN}, b"{}")
    new = rb.get("access_token") if isinstance(rb, dict) else None
    checks["refresh after the access token expired: 200 and a new token"] = rr.get("status") == 200 and bool(new)
    if new:
        m, _ = request("new token /auth/me", "edge", "GET", "/auth/me", {"Authorization": f"Bearer {new}"})
        checks["the refreshed token is accepted through the gateway"] = m.get("status") == 200
    th.join(timeout=60)
    gaps = [b - a for (a, _), (b, _) in zip(events, events[1:])]
    beats = [t for t, n in events if n != "connected"]
    notes["sse"] = {"status": stream_end.get("status"), "events": len(events), "first": events[:1],
                    "held_s": events[-1][0] if events else 0, "max_gap_s": max(gaps) if gaps else None,
                    "ended": stream_end.get("why")}
    checks["SSE held > 10 min with heartbeats, no gap > 60 s"] = (
        stream_end.get("status") == 200 and bool(beats) and events[-1][0] > 600 and (max(gaps) if gaps else 999) <= 60)
    lo, _ = request("logout", "edge", "POST", "/auth/logout", {**J, "Cookie": f"{COOKIE}={_RAW_COOKIE[0]}"}, b"{}")
    ra, _ = request("refresh after logout", "edge", "POST", "/auth/refresh",
                    {**J, "Cookie": f"{COOKIE}={_RAW_COOKIE[0]}"}, b"{}")
    checks["logout, then refresh refused"] = lo.get("status") == 200 and ra.get("status") == 401
    _RAW_COOKIE[0] = cookie = access = new = B = None
    json.dump({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "checks": checks, "notes": notes},
              open(args.out, "w"), indent=1)
    for k, v in checks.items():
        print(("PASS " if v else "FAIL ") + k)
    print("notes:", json.dumps(notes))
    leaked = "eyJ" in open(args.out).read()
    print(f"wrote {args.out}" + ("  WARNING: token-shaped text present" if leaked else "") + mfa_hint)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("capture"); c.add_argument("--out", required=True)
    m = sub.add_parser("compare"); m.add_argument("before"); m.add_argument("after"); m.add_argument("--out")
    lt = sub.add_parser("latency"); lt.add_argument("--out", required=True); lt.add_argument("--n", type=int, default=200)
    rl = sub.add_parser("ratelimit"); rl.add_argument("--out", required=True); rl.add_argument("--lan", default="10.180.22.127")
    v = sub.add_parser("valid"); v.add_argument("--out", required=True); v.add_argument("--n", type=int, default=20)
    tr = sub.add_parser("trust"); tr.add_argument("--out", required=True)
    ob = sub.add_parser("observe"); ob.add_argument("--out", required=True); ob.add_argument("--n", type=int, default=20)
    args = ap.parse_args()
    rc = {"capture": capture, "compare": compare, "latency": latency, "ratelimit": ratelimit, "valid": valid,
          "trust": trust, "observe": observe}[args.cmd](args)
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
