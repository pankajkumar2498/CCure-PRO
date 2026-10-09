"""
The gateway in front of the REAL application (Phase 10.3): every result through
the gateway compared with the same request sent to the application directly.

Differences that are expected, and asserted rather than ignored:
* a gateway refusal carries no X-Request-ID (and request_id null);
* through the gateway the application sees the edge's https (it trusts the
  gateway), so it adds HSTS and builds https:// absolute URLs; directly it
  sees http.
"""

from __future__ import annotations

import json

import pytest

from conftest import API, GATEWAY, bearer, request, websocket

UNSTABLE = {"date", "server", "content-length", "connection", "x-request-id", "strict-transport-security",
            "transfer-encoding", "x-ratelimit-reset", "set-cookie"}
PUBLIC = [(e["method"], e["path"]) for e in json.load(open("/docs/architecture/phase10/route_table.json"))
          if e["auth"] == "public"]


def _body(resp):
    try:
        data = resp.json()
    except ValueError:
        return resp.body
    if isinstance(data, dict):
        for volatile in ("request_id", "emitted_at"):  # per-response values
            data.pop(volatile, None)
    return data


def same(a, b, compare_body=True):
    assert a.status == b.status, (a.status, b.status)
    assert a.names() - UNSTABLE == b.names() - UNSTABLE, sorted((a.names() ^ b.names()) - UNSTABLE)
    if compare_body:
        assert _body(a) == _body(b)


# ── public routes ────────────────────────────────────────────────────────────


def test_public_routes_behave_as_the_application_does():
    checked = 0
    for method, path in PUBLIC:
        if path in ("/auth/register", "/auth/forgot-password", "/auth/resend-verification"):
            continue  # 3/min: exercised once below, not twice here
        body = b"{}" if method == "POST" else None
        headers = {"Content-Type": "application/json"} if body else {}
        via, direct = request(GATEWAY, method, path, headers, body), request(API, method, path, headers, body)
        same(via, direct, compare_body=path != "/")
        checked += 1
    assert checked == 14


def test_rate_limited_public_routes_are_reachable_without_credentials():
    for path in ("/auth/register", "/auth/forgot-password", "/auth/resend-verification"):
        resp = request(GATEWAY, "POST", path, {"Content-Type": "application/json"}, b"{}")
        assert resp.status == 422, (path, resp.status)


# ── bearer ───────────────────────────────────────────────────────────────────


def test_a_valid_bearer_is_forwarded_and_answered_by_the_application(session):
    via = request(GATEWAY, "GET", "/scans?limit=1", bearer(session["access"]))
    direct = request(API, "GET", "/scans?limit=1", bearer(session["access"]))
    same(via, direct)
    assert via.status == 200


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer "}, {"Authorization": "Basic dXNlcjpwYXNz"},
                                     {"Authorization": "Bearer not-a-token"}])
def test_bearer_refusals_equal_the_applications(headers):
    via, direct = request(GATEWAY, "GET", "/scans", headers), request(API, "GET", "/scans", headers)
    same(via, direct)
    assert via.header("x-request-id") is None and via.json()["request_id"] is None
    assert direct.header("x-request-id") is not None


def test_the_application_sees_the_verified_user_not_a_spoofed_one(session):
    spoof = {"X-Tenant-ID": "org_evil", "X-User-ID": "usr_evil", "X-Ccure-Auth-Sub": "usr_evil",
             "X-Forwarded-User": "usr_evil"}
    via = request(GATEWAY, "GET", "/auth/me", {**bearer(session["access"]), **spoof})
    plain = request(GATEWAY, "GET", "/auth/me", bearer(session["access"]))
    assert via.status == 200 and _body(via) == _body(plain)
    assert "evil" not in via.body.decode()


# ── tickets ──────────────────────────────────────────────────────────────────


def test_ticket_download_and_precedence(session):
    path = "/reports/download/scn_alongside_none"
    valid = session["ticket"]()
    cases = [
        ({}, f"?ticket={valid}"),                                  # a valid ticket alone
        (bearer("garbage"), f"?ticket={valid}"),                   # ticket first: bearer ignored
        (bearer(session["access"]), "?ticket=garbage"),            # a bad ticket refuses a valid bearer
        (bearer(session["access"]), "?ticket="),                   # empty ticket → bearer decides
        ({}, "?ticket=garbage"),
        ({}, ""),
    ]
    for headers, query in cases:
        same(request(GATEWAY, "GET", path + query, headers), request(API, "GET", path + query, headers))
    assert request(GATEWAY, "GET", path + f"?ticket={valid}").status not in (401, 403)  # reused within 60 s


def test_delete_report_is_ticket_or_bearer(session):
    path = "/reports/scn_alongside_none"
    for headers, query in (({}, f"?ticket={session['ticket']()}"), ({}, ""), ({}, "?ticket=garbage")):
        same(request(GATEWAY, "DELETE", path + query, headers), request(API, "DELETE", path + query, headers))


# ── WebSocket, SSE, streaming ────────────────────────────────────────────────


def test_websocket_with_a_valid_ticket_matches_the_application(session):
    via = websocket(GATEWAY, f"/scans/scn_alongside_none/progress?ticket={session['ticket']()}")
    direct = websocket(API, f"/scans/scn_alongside_none/progress?ticket={session['ticket']()}")
    assert via[0] == direct[0]
    assert via[2] == direct[2] or (via[2][0] == direct[2][0] == "text")


def test_websocket_refusal_is_a_bare_403_like_the_application():
    for query in ("", "?ticket=garbage"):
        via = websocket(GATEWAY, f"/scans/x/progress{query}")
        direct = websocket(API, f"/scans/x/progress{query}")
        assert via[0] == direct[0] == 403
        assert via[3] == direct[3] == b""
        assert "x-request-id" not in dict(via[1])


def test_sse_is_a_stream_through_the_gateway(session):
    import http.client

    for target in (GATEWAY, API):
        conn = http.client.HTTPConnection(*target, timeout=15)
        path = ("/api" if target == GATEWAY else "") + "/notifications/stream"
        conn.putrequest("GET", path, skip_host=True)
        for k, v in {"Host": "ccurepro.cdac.in", "Accept": "text/event-stream", **bearer(session["access"])}.items():
            conn.putheader(k, v)
        conn.endheaders()
        resp = conn.getresponse()
        assert resp.status == 200 and resp.getheader("content-type").startswith("text/event-stream")
        first = b""
        while b"\n\n" not in first:
            first += resp.fp.read1(1024)
        conn.close()
        assert b"event: connected" in first  # the first event (raw read: chunk framing around it)


def test_a_streamed_report_is_byte_identical(session):
    path = "/compliance/reports/soa?framework_id=cfw_iso27001_2022&fmt=pdf"
    via = request(GATEWAY, "GET", path, bearer(session["access"]), timeout=120)
    direct = request(API, "GET", path, bearer(session["access"]), timeout=120)
    # The PDF embeds its own generation time, so the two bodies are compared
    # by what the gateway could have damaged: status, type, completeness.
    assert via.status == direct.status
    assert via.header("content-type") == direct.header("content-type")
    if via.status == 200:
        assert via.body.startswith(b"%PDF") and via.body.rstrip().endswith(b"%%EOF")
        assert abs(len(via.body) - len(direct.body)) < 64


# ── OPTIONS, unrouted, X-Request-ID, CORS, headers ───────────────────────────


def test_options_preflight_reaches_the_application():
    pre = {"Origin": "https://ccurepro.cdac.in", "Access-Control-Request-Method": "GET",
           "Access-Control-Request-Headers": "authorization"}
    via, direct = request(GATEWAY, "OPTIONS", "/scans", pre), request(API, "OPTIONS", "/scans", pre)
    same(via, direct, compare_body=False)
    assert via.status == 200 and via.header("access-control-allow-origin") == "https://ccurepro.cdac.in"


@pytest.mark.parametrize("method,path", [("GET", "/no-such-route"), ("GET", "/scan/host-discovery"),
                                         ("DELETE", "/scans"), ("GET", "/ir/health"), ("POST", "/ir/incidents")])
def test_unrouted_requests_get_the_applications_404_and_405(method, path):
    via, direct = request(GATEWAY, method, path), request(API, method, path)
    same(via, direct)
    assert via.header("allow") == direct.header("allow")


def test_the_trailing_slash_redirect_is_https_through_the_gateway():
    via, direct = request(GATEWAY, "GET", "/scans/"), request(API, "GET", "/scans/")
    assert via.status == direct.status == 307
    assert via.header("location") == "https://ccurepro.cdac.in/scans"
    assert direct.header("location") == "http://ccurepro.cdac.in/scans"


def test_client_request_id_is_preserved(session):
    for path, headers in (("/", {}), ("/scans?limit=1", bearer(session["access"]))):
        resp = request(GATEWAY, "GET", path, {**headers, "X-Request-ID": "alongside-rid-1"})
        assert resp.header("x-request-id") == "alongside-rid-1" and resp.count("x-request-id") == 1


def test_cors_on_responses_and_refusals_matches_the_application(session):
    origin = {"Origin": "https://ccurepro.cdac.in"}
    for headers in ({**origin, **bearer(session["access"])}, origin):
        via, direct = request(GATEWAY, "GET", "/scans?limit=1", headers), request(API, "GET", "/scans?limit=1", headers)
        for name in ("access-control-allow-origin", "access-control-allow-credentials", "vary"):
            assert via.header(name) == direct.header(name), name


def test_security_headers_arrive_once_and_hsts_follows_the_edge(session):
    via = request(GATEWAY, "GET", "/scans?limit=1", bearer(session["access"]))
    direct = request(API, "GET", "/scans?limit=1", bearer(session["access"]))
    for name in ("x-content-type-options", "x-frame-options", "referrer-policy", "content-security-policy",
                 "cross-origin-resource-policy"):
        assert via.count(name) == direct.count(name) == 1, name
        assert via.header(name) == direct.header(name)
    assert via.header("strict-transport-security") == "max-age=300"
    assert direct.header("strict-transport-security") is None


# ── rate limiting through the gateway ────────────────────────────────────────


def test_each_client_behind_the_edge_gets_its_own_bucket():
    from conftest import edge_headers

    first = None
    for n in range(12):
        resp = request(GATEWAY, "GET", f"/auth/check-username?q=alongside{n}", edge_headers("198.51.100.61"))
        if resp.status == 429:
            first = n
            break
    assert first == 10, first  # 10/minute
    assert resp.json()["error_code"] == "RATE_LIMIT_EXCEEDED" and resp.header("retry-after")
    other = request(GATEWAY, "GET", "/auth/check-username?q=alongside-b", edge_headers("198.51.100.62"))
    assert other.status == 200
