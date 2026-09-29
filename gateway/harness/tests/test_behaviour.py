"""
Gateway behaviour through the real nginx configuration and the real
gateway-auth image (Phase 10.2d): tickets, OPTIONS, public routes, X6-a,
X-Request-ID, identity stripping, the trust boundary, streaming, WebSockets and
header duplication.
"""

from __future__ import annotations

import hashlib
import json
import time

import pytest

from conftest import (EDGE_CLIENT, GATEWAY, STUB, load_doc, relay, request, stub_received,
                      websocket)

SCAN = "scn_harness"
PUBLIC = [(e["method"], e["path"]) for e in load_doc("route_table.json") if e["auth"] == "public"]


def _bearer(t):
    return {"Authorization": f"Bearer {t}"}


# ── tickets ──────────────────────────────────────────────────────────────────


def test_ticket_takes_precedence_over_authorization(mint):
    ticket, access = mint.token("ticket"), mint.token()
    dl = f"/api/reports/download/{SCAN}"
    ok = request("GET", f"{dl}?ticket={ticket}&size=64", _bearer("garbage"))
    assert ok.status == 200 and ok.body == next_pattern(64)
    refused = request("GET", f"{dl}?ticket=garbage", _bearer(access))
    assert refused.status == 401 and refused.json()["message"] == "Invalid or expired download ticket."


def test_empty_ticket_is_absent(mint):
    dl = f"/api/reports/download/{SCAN}"
    assert request("GET", f"{dl}?ticket=&size=64", _bearer(mint.token())).status == 200
    missing = request("GET", f"{dl}?ticket=")
    assert missing.status == 401 and missing.json()["message"] == "Authentication token is missing."


def test_last_ticket_wins_as_in_starlette(mint):
    good, dl = mint.token("ticket"), f"/api/reports/download/{SCAN}"
    assert request("GET", f"{dl}?ticket=garbage&ticket={good}&size=64").status == 200
    assert request("GET", f"{dl}?ticket={good}&ticket=garbage&size=64").status == 401


def test_a_ticket_is_reusable_within_its_lifetime(mint):
    ticket, dl = mint.token("ticket"), f"/api/reports/download/{SCAN}?size=64"
    for _ in range(3):
        assert request("GET", f"{dl}&ticket={ticket}").status == 200
    assert websocket(f"/api/scans/{SCAN}/progress?ticket={ticket}")[0] == 101


def test_delete_report_is_ticket_or_bearer(mint):
    ticket = mint.token("ticket")
    forwarded = request("DELETE", f"/api/reports/{SCAN}?ticket={ticket}")
    assert forwarded.status == 200 and stub_received(forwarded)["method"] == "DELETE"
    assert request("DELETE", f"/api/reports/{SCAN}", _bearer(mint.token())).status == 200
    refused = request("DELETE", f"/api/reports/{SCAN}")
    assert refused.status == 401 and refused.json()["message"] == "Authentication token is missing."


# ── WebSockets ───────────────────────────────────────────────────────────────


def test_websocket_upgrade_with_a_valid_ticket(mint):
    status, headers, frames, _ = websocket(f"/api/scans/{SCAN}/progress?ticket={mint.token('ticket')}")
    assert status == 101
    received = json.loads(frames[0])
    assert received["stub"] and received["headers"]["x-ccure-auth-kind"] == ["ticket"]
    assert "x-request-id" not in dict(headers)


def test_websocket_refusal_is_a_bare_403(mint):
    for query in ("", "?ticket=garbage", f"?ticket={mint.token()}", f"?ticket={mint.expired('ticket')}"):
        status, headers, frames, rest = websocket(f"/api/web-scans/wsc_x/progress{query}")
        names = {k for k, _ in headers}
        assert status == 403 and rest == b"" and not frames, query
        assert dict(headers).get("content-type") == "text/plain" and dict(headers).get("content-length") == "0"
        assert not names & {"x-request-id", "x-frame-options", "content-security-policy", "www-authenticate"}


def test_a_plain_get_to_a_websocket_path_is_unrouted():
    via_gateway = request("GET", f"/api/scans/{SCAN}/progress")
    direct = request("GET", f"/scans/{SCAN}/progress", target=STUB)
    assert via_gateway.status == direct.status == 404


# ── OPTIONS and public routes ────────────────────────────────────────────────


def test_options_passes_without_authentication():
    pre = {"Origin": "https://ccurepro.cdac.in", "Access-Control-Request-Method": "GET",
           "Access-Control-Request-Headers": "authorization"}
    resp = request("OPTIONS", "/api/scans", pre)
    assert resp.status == 200 and resp.header("access-control-allow-origin") == "https://ccurepro.cdac.in"
    evil = request("OPTIONS", "/api/scans", {**pre, "Origin": "https://evil.example"})
    assert evil.status == 400 and evil.header("access-control-allow-origin") is None
    # forwarded unauthenticated: the application's own answer, whatever it is
    for path in ("/no/such/route", "/scans/x"):
        assert request("OPTIONS", "/api" + path).status == request("OPTIONS", path, target=STUB).status


def test_the_public_allowlist_is_reachable_without_credentials():
    assert len(PUBLIC) == 17
    for method, path in PUBLIC:
        resp = request(method, "/api" + path, {"Content-Type": "application/json"},
                       b"{}" if method == "POST" else None)
        assert resp.status == 200, (method, path, resp.status)
        if path != "/auth/jwks.json":
            assert stub_received(resp)["path"] == path


# ── X6-a: unrouted requests reach the application unauthenticated ────────────


@pytest.mark.parametrize("method,path", [
    ("GET", "/no-such-route"),
    ("GET", "/scans/"),              # trailing-slash redirect
    ("GET", "/scan/host-discovery"),  # wrong method
    ("DELETE", "/scans"),
    ("PUT", "/auth/login"),
    ("HEAD", "/scans"),
    ("GET", "/ir/health"),
    ("POST", "/ir/incidents"),
    ("GET", "/ir/"),
    ("GET", "/scans%2F"),
])
def test_unrouted_requests_get_the_applications_answer(method, path):
    via_gateway = request(method, "/api" + path)
    direct = request(method, path.replace("%2F", "/"), target=STUB)
    assert via_gateway.status == direct.status, (via_gateway.status, direct.status)
    assert via_gateway.body == direct.body
    for header in ("allow", "location", "content-type"):
        assert via_gateway.header(header) == direct.header(header), header
    assert via_gateway.status in (404, 405, 307)


def test_api_ir_stays_404():
    for method in ("GET", "POST", "DELETE"):
        resp = request(method, "/api/ir/incidents/x", {"Authorization": "Bearer garbage"})
        assert resp.status == 404 and resp.json() == {"detail": "Not Found"}


# ── X-Request-ID ─────────────────────────────────────────────────────────────


def test_client_request_id_passes_through_unchanged(mint):
    for path, headers in (("/api/", {}), ("/api/scans", _bearer(mint.token()))):
        resp = request("GET", path, {**headers, "X-Request-ID": "harness-rid-" + "r" * 200})
        assert stub_received(resp)["headers"]["x-request-id"] == ["harness-rid-" + "r" * 200]
        assert resp.header("x-request-id") == "harness-rid-" + "r" * 200 and resp.count("x-request-id") == 1


def test_a_gateway_refusal_has_no_request_id():
    for headers in ({}, {"X-Request-ID": "harness-rid-refused"}):
        resp = request("GET", "/api/scans", headers)
        assert resp.status == 403 and resp.header("x-request-id") is None
        assert resp.json()["request_id"] is None


# ── identity headers ─────────────────────────────────────────────────────────

SPOOF = {
    "X-Tenant-ID": "org_evil", "X-Tenant": "org_evil", "X-Org": "org_evil", "X-Org-ID": "org_evil",
    "X-Organization-ID": "org_evil", "X-User": "usr_evil", "X-User-ID": "usr_evil",
    "X-User-Email": "evil@example", "X-User-Role": "superadmin", "X-Auth-User": "usr_evil",
    "X-Auth-Request-User": "usr_evil", "X-Auth-Request-Email": "evil@example",
    "X-Forwarded-User": "usr_evil", "X-Forwarded-Email": "evil@example", "X-Remote-User": "usr_evil",
    "Remote-User": "usr_evil", "X-Ccure-Auth-Sub": "usr_evil", "X-Ccure-Auth-Jti": "jti_evil",
    "X-Ccure-Auth-Ptype": "service", "X-Ccure-Auth-Kind": "service_access",
    "X-Ccure-Policy": "none", "X-Ccure-Method": "OPTIONS", "X-Ccure-Args": "ticket=x",
    "X-Ccure-Refusal": "none",
}


def test_identity_headers_are_stripped_on_public_routes():
    received = stub_received(request("GET", "/api/", SPOOF))["headers"]
    leaked = {k for k in SPOOF if k.lower() in received}
    assert not leaked, leaked


def test_verified_identity_cannot_be_spoofed(mint):
    received = stub_received(request("GET", "/api/scans", {**SPOOF, **_bearer(mint.token())}))["headers"]
    assert received["x-ccure-auth-sub"] == ["usr_gw"]
    assert received["x-ccure-auth-kind"] == ["access"] and received["x-ccure-auth-ptype"] == ["user"]
    assert received["x-ccure-auth-jti"] != ["jti_evil"]
    leaked = {k for k in SPOOF if k.lower() in received and not k.lower().startswith("x-ccure-auth-")}
    assert not leaked, leaked


def test_a_client_cannot_choose_its_own_policy():
    resp = request("GET", "/api/scans", {"X-Ccure-Policy": "none", "X-Ccure-Method": "OPTIONS"})
    assert resp.status == 403 and resp.json()["message"] == "Not authenticated"


# ── trust boundary ───────────────────────────────────────────────────────────


def test_the_trusted_edge_asserts_the_client_address():
    received = stub_received(request("GET", "/api/", {"X-Forwarded-For": "203.0.113.66, 203.0.113.67"}))
    headers = received["headers"]
    assert headers["x-real-ip"] == [EDGE_CLIENT]
    assert headers["x-forwarded-for"] == [EDGE_CLIENT]  # set, never appended
    assert headers["x-forwarded-proto"] == ["https"]


def test_an_untrusted_peer_cannot_assert_an_address_or_scheme():
    resp = relay("GET", "/api/", {"X-Real-IP": "203.0.113.9", "X-Forwarded-For": "203.0.113.9",
                                  "X-Forwarded-Proto": "https"})
    headers = stub_received(resp)["headers"]
    assert headers["x-real-ip"] == ["10.254.10.20"]
    assert headers["x-forwarded-for"] == ["10.254.10.20"]
    assert headers["x-forwarded-proto"] == ["http"]


# ── streaming ────────────────────────────────────────────────────────────────


def next_pattern(size):
    block = hashlib.sha256(b"ccure-harness").digest() * (64 * 1024 // 32)
    out = b""
    while len(out) < size:
        out += block[: min(64 * 1024, size - len(out))]
    return out


def test_a_large_download_streams_without_touching_disk(mint):
    """The gateway's temp directories are mounted read-only: buffering would fail the request."""
    size = 30 * 1024 * 1024
    resp = request("GET", f"/api/reports/download/{SCAN}?size={size}", _bearer(mint.token()), timeout=120)
    assert resp.status == 200 and len(resp.body) == size
    assert hashlib.sha256(resp.body).hexdigest() == hashlib.sha256(next_pattern(size)).hexdigest()
    assert resp.header("content-disposition") == 'attachment; filename="harness.pdf"'


def test_a_large_upload_streams_without_touching_disk(mint):
    body = b"x" * (25 * 1024 * 1024)
    resp = request("POST", "/api/compliance/controls/ctl_harness/evidence",
                   {**_bearer(mint.token()), "Content-Type": "application/octet-stream"}, body, timeout=120)
    assert resp.status == 200
    received = resp.json()
    assert received["bytes"] == len(body) and received["sha256"] == hashlib.sha256(body).hexdigest()


def test_sse_is_delivered_as_it_is_produced(mint):
    import http.client

    conn = http.client.HTTPConnection(*GATEWAY, timeout=15)
    conn.putrequest("GET", "/api/notifications/stream?beats=4&interval=1", skip_host=True)
    for k, v in {"Host": "ccurepro.cdac.in", "Accept": "text/event-stream",
                 "Authorization": f"Bearer {mint.token()}", "X-Real-IP": EDGE_CLIENT,
                 "X-Forwarded-Proto": "https"}.items():
        conn.putheader(k, v)
    conn.endheaders()
    resp = conn.getresponse()
    assert resp.status == 200 and resp.getheader("content-type").startswith("text/event-stream")
    started, arrivals, buf = time.monotonic(), [], b""
    while len(arrivals) < 5:
        chunk = resp.fp.read1(4096)
        if not chunk:
            break
        buf += chunk
        while b"\n\n" in buf:
            _, buf = buf.split(b"\n\n", 1)
            arrivals.append(time.monotonic() - started)
    conn.close()
    assert len(arrivals) == 5
    gaps = [b - a for a, b in zip(arrivals, arrivals[1:])]
    assert arrivals[0] < 0.5, arrivals  # the first event is not held back
    assert all(0.7 < g < 1.5 for g in gaps), gaps  # one a second: nothing batched


# ── headers ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("path,needs_token", [("/", False), ("/scans", True), ("/no-such", False)])
def test_proxied_responses_carry_each_application_header_once(mint, path, needs_token):
    headers = _bearer(mint.token()) if needs_token else {}
    via = request("GET", "/api" + path, {**headers, "X-Request-ID": "rid-dup"})
    direct = request("GET", path, {**headers, "X-Request-ID": "rid-dup"}, target=STUB)
    skip = {"date", "server", "connection", "content-length"}
    counts_via = {k: via.count(k) for k in set(via.names()) - skip}
    counts_direct = {k: direct.count(k) for k in set(direct.names()) - skip}
    assert counts_via == counts_direct
    assert all(n == 1 for n in counts_via.values()), counts_via


def test_gateway_refusals_carry_each_header_once():
    resp = request("GET", "/api/scans", {"Origin": "https://ccurepro.cdac.in"})
    assert resp.status == 403
    assert all(resp.count(k) == 1 for k in set(resp.names())), resp.headers
    assert resp.header("access-control-allow-origin") == "https://ccurepro.cdac.in"
    assert resp.header("vary") == "Origin" and resp.header("access-control-allow-credentials") == "true"
    no_origin = request("GET", "/api/scans")
    assert not {"access-control-allow-origin", "access-control-allow-credentials", "vary"} & set(no_origin.names())
    evil = request("GET", "/api/scans", {"Origin": "https://evil.example"})
    assert evil.header("access-control-allow-origin") is None
    assert evil.header("access-control-allow-credentials") == "true"  # as CORSMiddleware answers
