"""
Phase 5 — structured API security testing.

A controlled API app serves an OpenAPI 3 spec at /openapi.json, a GraphQL
endpoint (introspection toggleable), a spec-declared-secure endpoint that is not
actually protected (missing auth), and a command-injectable operation — so the
importer, the GraphQL probe, the API-specific checks, and the "imported surface
feeds the existing engines" reuse are all exercised.
"""

import asyncio
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from core.web.api_scan import ApiScanEngine

_SLEEP = re.compile(r"sleep\s+(\d+)")

_SPEC = {
    "openapi": "3.0.0",
    "servers": [{"url": "SERVER"}],
    "paths": {
        "/items/{id}": {
            "get": {
                "security": [{"bearer": []}],
                "parameters": [{"name": "id", "in": "path"}],
            }
        },
        "/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
        "/exec": {"get": {"parameters": [{"name": "host", "in": "query"}]}},
        "/login": {
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"properties": {"username": {}, "password": {}}}
                        }
                    }
                }
            }
        },
    },
    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
}

_INTROSPECTION_ON = {"introspection": True}


def _make_handler(base_holder):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, obj, code=200):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def _html(self, body, code=200):
            b = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            u = urlparse(self.path)
            qs = parse_qs(u.query, keep_blank_values=True)
            p = u.path
            if p == "/openapi.json":
                spec = json.loads(json.dumps(_SPEC).replace("SERVER", base_holder[0]))
                return self._json(spec)
            if p == "/items/1":
                # Spec says bearer required, but it serves anyone (missing auth).
                return self._html(
                    "<html>Item 1 owner-data confidential record "
                    "field-a field-b field-c field-d extra padding "
                    "to exceed the body length threshold here.</html>"
                )
            if p == "/exec":
                host = (qs.get("host") or [""])[0]
                m = _SLEEP.search(host)
                if m and re.search(r"[;&|`$]", host):
                    time.sleep(min(int(m.group(1)), 10))
                return self._html(f"<html>ping {host}</html>")
            if p == "/search":
                return self._html(
                    "<html>results for query padded to exceed the "
                    "minimum substantive body length threshold now.</html>"
                )
            return self._html("<html>home</html>")

        def do_POST(self):
            u = urlparse(self.path)
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n).decode("utf-8", "replace")
            if u.path == "/graphql":
                if base_holder[1]:  # introspection enabled
                    return self._json(
                        {
                            "data": {
                                "__schema": {
                                    "queryType": {"name": "Query"},
                                    "types": [
                                        {"name": "Query", "kind": "OBJECT"},
                                        {"name": "User", "kind": "OBJECT"},
                                        {"name": "Secret", "kind": "OBJECT"},
                                    ],
                                }
                            }
                        }
                    )
                return self._json(
                    {"errors": [{"message": "introspection disabled"}]}, 400
                )
            return self._html("<html>ok</html>")

    return H


@pytest.fixture
def api_app():
    # base_holder[0]=base url (filled after bind), [1]=introspection enabled
    holder = ["", True]
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(holder))
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    holder[0] = base
    try:
        yield base, holder
    finally:
        srv.shutdown()
        srv.server_close()


def _run(c):
    return asyncio.run(c)


# ── OpenAPI import ─────────────────────────────────────────────────────────────
def test_openapi_discovered_and_imported(api_app):
    base, _ = api_app
    res = _run(ApiScanEngine().run(base + "/", options={}))
    assert res["stats"]["spec_source"].endswith("/openapi.json")
    urls = {e["url"].split("?")[0] for e in res["endpoints"]}
    assert any(u.endswith("/items/1") for u in urls)  # path param filled
    assert any(u.endswith("/search") for u in urls)
    items = next(
        e for e in res["endpoints"] if e["url"].split("?")[0].endswith("/items/1")
    )
    search = next(
        e for e in res["endpoints"] if e["url"].split("?")[0].endswith("/search")
    )
    login_ep = next(
        e for e in res["endpoints"] if e["url"].split("?")[0].endswith("/login")
    )
    assert items["parameters"] == {"path": ["id"]}
    assert search["parameters"] == {"query": ["q"]}
    assert login_ep["parameters"] == {"json": ["username", "password"]}
    assert json.loads(login_ep["request_body"]) == {"username": "1", "password": "1"}
    forms = {
        f["url"].split("?")[0]: [i["name"] for i in f["inputs"]] for f in res["forms"]
    }
    assert any(u.endswith("/login") for u in forms)  # body → form
    login = [v for u, v in forms.items() if u.endswith("/login")][0]
    assert "username" in login and "password" in login


def test_openapi_import_from_explicit_url(api_app):
    base, _ = api_app
    res = _run(
        ApiScanEngine(discover=False).run(
            base + "/", options={"api_spec_url": base + "/openapi.json"}
        )
    )
    assert res["stats"]["operations"] == 4


# ── GraphQL ─────────────────────────────────────────────────────────────────
def test_graphql_introspection_enabled_is_a_finding(api_app):
    base, holder = api_app
    holder[1] = True
    res = _run(
        ApiScanEngine().run(base + "/", options={"graphql_url": base + "/graphql"})
    )
    gi = [f for f in res["findings"] if f["finding_type"] == "graphql_introspection"]
    assert gi, "introspection finding missing"
    assert gi[0]["cwe_id"] == "CWE-200"


def test_graphql_introspection_disabled_no_finding(api_app):
    base, holder = api_app
    holder[1] = False
    res = _run(
        ApiScanEngine().run(base + "/", options={"graphql_url": base + "/graphql"})
    )
    assert [
        f for f in res["findings"] if f["finding_type"] == "graphql_introspection"
    ] == []


# ── missing auth ──────────────────────────────────────────────────────────────
def test_missing_authentication_detected(api_app):
    base, _ = api_app
    res = _run(ApiScanEngine().run(base + "/", options={"api_discover": True}))
    # /items/{id} is spec-secured but serves anonymously.
    ma = [
        f
        for f in res["findings"]
        if f["finding_type"] == "api_missing_auth" and "/items/1" in f["request_url"]
    ]
    assert (
        ma
    ), f"missing-auth not detected: {[f['finding_type'] for f in res['findings']]}"
    assert ma[0]["cwe_id"] == "CWE-306"


# ── non-API target ────────────────────────────────────────────────────────────
def test_non_api_target_is_clean(api_app):
    base, holder = api_app
    holder[1] = False
    # Point at a path with no spec and disable discovery + graphql.
    res = _run(ApiScanEngine(discover=False).run(base + "/", options={}))
    assert res["stats"]["spec_source"] is None
    assert res["endpoints"] == [] and res["findings"] == []


# ── reuse: imported endpoint feeds the Phase 2 injection engine ───────────────
def test_imported_endpoint_feeds_injection_engine(api_app):
    from core.web.injection import InjectionEngine

    base, _ = api_app
    imported = _run(ApiScanEngine().run(base + "/", options={}))
    # Find the imported /exec endpoint (has query param 'host').
    exec_eps = [
        e for e in imported["endpoints"] if e["url"].split("?")[0].endswith("/exec")
    ]
    assert exec_eps, "exec endpoint not imported"
    inj = InjectionEngine(
        classes=("command_injection",),
        cmdi_delay_1=1,
        cmdi_delay_2=2,
        timeout_s=8,
        rate_limit=50,
    )
    res = _run(inj.scan(base + "/", exec_eps, []))
    ci = [f for f in res["findings"] if f["finding_type"] == "command_injection"]
    assert ci, "command injection on the imported API endpoint not detected"
