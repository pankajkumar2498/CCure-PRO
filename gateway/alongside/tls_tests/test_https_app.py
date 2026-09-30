"""
The real application over HTTPS, through the TLS test edge and the gateway
(Phase 10.4), compared with the same request sent to the application directly.

Expected, asserted differences: a gateway refusal has no X-Request-ID; over
HTTPS the application resolves https (the edge's X-Forwarded-Proto, believed
because the edge → gateway → api chain is trusted hop by hop), so it builds
https:// URLs and HSTS is present exactly once (the edge's value).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid

import pytest

from conftest import (RUNNER_IP, bearer, direct, https, in_network_only, relay_https, ws_direct,
                      wss)

pytestmark = in_network_only

VOLATILE_BODY = ("request_id", "emitted_at")
UNSTABLE = {"date", "server", "content-length", "connection", "x-request-id", "strict-transport-security",
            "transfer-encoding", "x-ratelimit-reset", "set-cookie", "x-frame-options", "referrer-policy"}
PUBLIC = [(e["method"], e["path"]) for e in json.load(open("/docs/architecture/phase10/route_table.json"))
          if e["auth"] == "public"]


def _body(resp):
    try:
        data = resp.json()
    except ValueError:
        return resp.body
    if isinstance(data, dict):
        for key in VOLATILE_BODY:
            data.pop(key, None)
    return data


def same(a, b, compare_body=True):
    assert a.status == b.status, (a.status, b.status)
    assert a.names() - UNSTABLE == b.names() - UNSTABLE, sorted((a.names() ^ b.names()) - UNSTABLE)
    if compare_body:
        assert _body(a) == _body(b)


def hsts_once(resp):
    assert resp.count("strict-transport-security") == 1, resp.headers
    assert resp.header("strict-transport-security") == "max-age=300"


# ── public routes, bearer, identity ──────────────────────────────────────────


def test_public_routes_over_https():
    skip = {"/auth/register", "/auth/forgot-password", "/auth/resend-verification",  # 3/min, shared bucket
            "/auth/check-username"}  # the rate-limit test's route
    checked = 0
    for method, path in PUBLIC:
        if path in skip:
            continue
        body = b"{}" if method == "POST" else None
        headers = {"Content-Type": "application/json"} if body else {}
        via, plain = https(method, path, headers, body), direct(method, path, headers, body)
        same(via, plain, compare_body=path != "/")
        hsts_once(via)
        checked += 1
    assert checked == 13


def test_bearer_over_https(session):
    via, plain = https("GET", "/scans?limit=1", bearer(session["access"])), direct("GET", "/scans?limit=1", bearer(session["access"]))
    same(via, plain)
    assert via.status == 200
    hsts_once(via)


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer "}, {"Authorization": "Basic dXNlcjpwYXNz"},
                                     {"Authorization": "Bearer not-a-token"}])
def test_bearer_refusals_over_https(headers):
    via, plain = https("GET", "/scans", headers), direct("GET", "/scans", headers)
    same(via, plain)
    assert via.header("x-request-id") is None and via.json()["request_id"] is None
    hsts_once(via)


def test_identity_headers_cannot_be_spoofed_over_https(session):
    spoof = {"X-Tenant-ID": "org_evil", "X-User-ID": "usr_evil", "X-Ccure-Auth-Sub": "usr_evil",
             "X-Forwarded-User": "usr_evil", "X-Real-IP": "203.0.113.9"}
    via = https("GET", "/auth/me", {**bearer(session["access"]), **spoof})
    assert via.status == 200 and "evil" not in via.body.decode()
    assert _body(via) == _body(https("GET", "/auth/me", bearer(session["access"])))


# ── tickets ──────────────────────────────────────────────────────────────────


def test_tickets_over_https(session):
    path = "/reports/download/scn_tls_none"
    valid = session["ticket"]()
    for headers, query in (({}, f"?ticket={valid}"), (bearer("garbage"), f"?ticket={valid}"),
                           (bearer(session["access"]), "?ticket=garbage"), (bearer(session["access"]), "?ticket="),
                           ({}, "?ticket=garbage"), ({}, "")):
        same(https("GET", path + query, headers), direct("GET", path + query, headers))
    assert https("GET", path + f"?ticket={valid}").status not in (401, 403)  # reused within 60 s
    for headers, query in (({}, f"?ticket={session['ticket']()}"), ({}, "")):
        same(https("DELETE", "/reports/scn_tls_none" + query, headers), direct("DELETE", "/reports/scn_tls_none" + query, headers))


# ── WebSocket, SSE ───────────────────────────────────────────────────────────


def test_wss_upgrade_with_a_valid_ticket(session):
    via = wss(f"/scans/scn_tls_none/progress?ticket={session['ticket']()}")
    plain = ws_direct(f"/scans/scn_tls_none/progress?ticket={session['ticket']()}")
    assert via[0] == plain[0]
    assert via[2] == plain[2] or (via[2][0] == plain[2][0] == "text")


def test_wss_refusal_is_a_bare_403():
    for query in ("", "?ticket=garbage"):
        status, headers, frame, rest = wss(f"/scans/x/progress{query}")
        assert status == 403 and rest == b"" and frame is None
        assert "x-request-id" not in dict(headers)


def test_sse_starts_promptly_over_https(session):
    import http.client

    from conftest import EDGE, HOST, tls_context

    conn = http.client.HTTPSConnection(*EDGE, timeout=15, context=tls_context())
    started = time.monotonic()
    conn.putrequest("GET", "/api/notifications/stream", skip_host=True)
    for k, v in {"Host": HOST, "Accept": "text/event-stream", **bearer(session["access"])}.items():
        conn.putheader(k, v)
    conn.endheaders()
    resp = conn.getresponse()
    assert resp.status == 200 and resp.getheader("content-type").startswith("text/event-stream")
    first = b""
    while b"\n\n" not in first:
        first += resp.fp.read1(1024)
    elapsed = time.monotonic() - started
    conn.close()
    assert b"event: connected" in first
    assert elapsed < 1.0, elapsed


# ── large bodies through the real application ────────────────────────────────


def _multipart(name, content, content_type):
    boundary = uuid.uuid4().hex
    head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
            f"Content-Type: {content_type}\r\n\r\n").encode()
    return boundary, head + content + f"\r\n--{boundary}--\r\n".encode()


def test_large_upload_and_download_are_byte_identical_over_https(session):
    controls = https("GET", "/compliance/frameworks/cfw_iso27001_2022/controls", bearer(session["access"]))
    assert controls.status == 200, controls.status
    data = controls.json()
    items = data if isinstance(data, list) else data.get("controls") or data.get("items") or data.get("data") or []
    control_id = items[0]["control_id"]
    content = b"%PDF-1.4\n" + os.urandom(20 * 1024 * 1024) + b"\n%%EOF\n"
    boundary, body = _multipart("tls-large.pdf", content, "application/pdf")
    up = https("POST", f"/compliance/controls/{control_id}/evidence",
               {**bearer(session["access"]), "Content-Type": f"multipart/form-data; boundary={boundary}"}, body)
    assert up.status == 201, (up.status, up.body[:200])
    file_id = up.json()["id"]
    assert up.json()["sha256"] == hashlib.sha256(content).hexdigest()  # the application received it intact
    down = https("GET", f"/compliance/evidence/{file_id}/download", bearer(session["access"]))
    assert down.status == 200 and hashlib.sha256(down.body).digest() == hashlib.sha256(content).digest()
    plain = direct("GET", f"/compliance/evidence/{file_id}/download", bearer(session["access"]))
    assert plain.body == down.body


# ── OPTIONS, unrouted, scheme, X-Request-ID, CORS ────────────────────────────


def test_options_over_https():
    pre = {"Origin": "https://ccurepro.cdac.in", "Access-Control-Request-Method": "GET",
           "Access-Control-Request-Headers": "authorization"}
    via, plain = https("OPTIONS", "/scans", pre), direct("OPTIONS", "/scans", pre)
    same(via, plain, compare_body=False)
    assert via.status == 200


@pytest.mark.parametrize("method,path", [("GET", "/no-such-route"), ("GET", "/scan/host-discovery"),
                                         ("DELETE", "/scans"), ("GET", "/ir/health"), ("POST", "/ir/incidents")])
def test_unrouted_over_https(method, path):
    via, plain = https(method, path), direct(method, path)
    same(via, plain)
    assert via.header("allow") == plain.header("allow")
    hsts_once(via)


@pytest.mark.parametrize("spoof", [{}, {"X-Forwarded-Proto": "http"}, {"X-Forwarded-Proto": "http", "X-Forwarded-For": "203.0.113.5"}])
def test_https_resolves_to_https_whatever_the_client_claims(spoof):
    resp = https("GET", "/scans/", spoof)
    assert resp.status == 307
    assert resp.header("location") == "https://ccurepro.cdac.in/scans"
    hsts_once(resp)


def test_client_request_id_is_preserved_over_https(session):
    resp = https("GET", "/scans?limit=1", {**bearer(session["access"]), "X-Request-ID": "tls-rid-1"})
    assert resp.header("x-request-id") == "tls-rid-1" and resp.count("x-request-id") == 1


def test_cors_over_https(session):
    origin = {"Origin": "https://ccurepro.cdac.in"}
    for headers in ({**origin, **bearer(session["access"])}, origin):
        via, plain = https("GET", "/scans?limit=1", headers), direct("GET", "/scans?limit=1", headers)
        for name in ("access-control-allow-origin", "access-control-allow-credentials", "vary"):
            assert via.header(name) == plain.header(name), name


def test_security_headers_once_over_https(session):
    via = https("GET", "/scans?limit=1", bearer(session["access"]))
    for name in ("x-content-type-options", "x-frame-options", "referrer-policy", "content-security-policy",
                 "cross-origin-resource-policy", "strict-transport-security"):
        assert via.count(name) == 1, name
    assert via.header("referrer-policy") == "no-referrer"  # the application's, as on the live /api/ path


# ── per-client identity through the whole chain ─────────────────────────────


def _insider_bucket_is_clear():
    # The 10.3 suite drained the insider's bucket through other paths minutes ago;
    # /auth/check-username is 10/minute in a fixed window, so wait for it to roll.
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        if relay_https("GET", "/auth/check-username?q=tls-insider-wait").status == 200:
            return True
        time.sleep(5)
    return False


def test_each_https_client_has_its_own_bucket_and_cannot_forge_another():
    """runner (10.254.20.60) forges a new X-Forwarded-For each time: one bucket regardless."""
    assert _insider_bucket_is_clear()
    first = None
    for n in range(12):
        resp = https("GET", f"/auth/check-username?q=tls{n}", {"X-Forwarded-For": f"203.0.113.{n + 1}",
                                                               "X-Real-IP": f"203.0.113.{n + 1}"})
        if resp.status == 429:
            first = n
            break
    assert first is not None and first <= 10, first
    assert resp.json()["error_code"] == "RATE_LIMIT_EXCEEDED"
    other = relay_https("GET", "/auth/check-username?q=tls-insider")  # 10.254.20.50: its own bucket
    assert other.status == 200
    with open(os.path.join(os.environ.get("ALONGSIDE_OUT", "/out"), "expected_rate_limit_ip.txt"), "w") as fh:
        fh.write(RUNNER_IP + "\n")
