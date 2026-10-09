"""
Fail-closed (Phase 10.2d): run by gateway/harness/run.sh while gateway-auth is
STOPPED. Protected requests are refused with 503 and never forwarded; public,
OPTIONS and unrouted requests do not depend on gateway-auth at all.
"""

from __future__ import annotations

import pytest

from conftest import load_doc, request, stub_received, websocket

pytestmark = pytest.mark.checker_down

PUBLIC = [(e["method"], e["path"]) for e in load_doc("route_table.json") if e["auth"] == "public"]
UNAVAILABLE = {"success": False, "error_code": "AUTH_UNAVAILABLE",
               "message": "Authentication is temporarily unavailable.",
               "detail": "Authentication is temporarily unavailable.", "request_id": None}


@pytest.mark.parametrize("method,path,headers", [
    ("GET", "/api/scans", {"Authorization": "Bearer anything"}),
    ("GET", "/api/scans", {}),
    ("POST", "/api/scan/host-discovery", {"Authorization": "Bearer anything"}),
    ("GET", "/api/reports/download/x?ticket=anything", {}),
    ("DELETE", "/api/reports/x", {"Authorization": "Bearer anything"}),
    ("GET", "/api/notifications/stream", {"Authorization": "Bearer anything"}),
])
def test_protected_requests_fail_closed(method, path, headers):
    resp = request(method, path, headers)
    assert resp.status == 503
    assert resp.json() == UNAVAILABLE
    assert resp.header("retry-after") == "5" and resp.header("x-request-id") is None


def test_websocket_fails_closed():
    status, headers, frames, _ = websocket("/api/scans/x/progress?ticket=anything")
    assert status == 503 and not frames


def test_public_routes_do_not_depend_on_the_checker():
    for method, path in PUBLIC:
        resp = request(method, "/api" + path, {"Content-Type": "application/json"},
                       b"{}" if method == "POST" else None)
        assert resp.status == 200, (method, path, resp.status)


def test_options_and_unrouted_do_not_depend_on_the_checker():
    pre = {"Origin": "https://ccurepro.cdac.in", "Access-Control-Request-Method": "GET"}
    assert request("OPTIONS", "/api/scans", pre).status == 200
    assert request("GET", "/api/no-such").status == 404
    assert request("GET", "/api/scan/host-discovery").status == 405
    assert request("GET", "/api/ir/health").status == 404
    assert stub_received(request("GET", "/api/"))["path"] == "/"
