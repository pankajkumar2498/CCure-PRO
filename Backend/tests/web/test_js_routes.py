"""
Phase 22 — static route/endpoint extraction from JS bundles (Codex item 5).

The crawler previously discovered API calls only when the browser executed them;
an endpoint hardcoded in a bundle but never triggered stayed invisible. These
tests pin the source-level extractor: fetch/axios/XHR calls, router route
definitions, verb+path, and bare API-path literals become same-origin endpoints,
while cross-origin URLs, assets and template placeholders are dropped.
"""

from core.web.js_routes import extract_js_routes, route_endpoints

BASE = "http://app.test/"


def test_extracts_fetch_axios_xhr_calls():
    js = """
      fetch("/api/users");
      axios.get('/api/orders');
      xhr.open("POST", "/api/admin/reset");
    """
    routes = extract_js_routes(js, BASE)
    assert "http://app.test/api/users" in routes
    assert "http://app.test/api/orders" in routes
    assert "http://app.test/api/admin/reset" in routes


def test_extracts_unexecuted_hardcoded_route():
    # The key case: a hardcoded API path that is never called at runtime.
    js = 'const HIDDEN = "/api/internal/secrets"; // never invoked'
    assert "http://app.test/api/internal/secrets" in extract_js_routes(js, BASE)


def test_extracts_spa_router_definitions():
    js = """
      const routes = [{ path: "/dashboard" }, { path: '/admin/panel' }];
      router.push("/profile/settings");
    """
    routes = extract_js_routes(js, BASE)
    assert "http://app.test/dashboard" in routes
    assert "http://app.test/admin/panel" in routes
    assert "http://app.test/profile/settings" in routes


def test_drops_cross_origin_and_assets_and_placeholders():
    js = """
      fetch("https://evil.example/api/steal");
      var s = "/static/app.js";
      var img = "/logo.png";
      var t = "/api/user/${id}/data";
    """
    routes = extract_js_routes(js, BASE)
    assert not any("evil.example" in r for r in routes)
    assert not any(r.endswith("app.js") for r in routes)
    assert not any(r.endswith("logo.png") for r in routes)
    assert not any("${" in r for r in routes)


def test_route_endpoints_shape_and_source():
    eps = route_endpoints('fetch("/api/x")', BASE)
    assert eps and eps[0]["source"] == "js_static"
    assert eps[0]["url"] == "http://app.test/api/x"
    assert eps[0]["method"] == "GET"


def test_empty_and_garbage_are_safe():
    assert extract_js_routes("", BASE) == []
    assert extract_js_routes("var x = 1; function f(){return 2;}", BASE) == []


# ── Phase 23c: source-map support (Codex item 9) ──────────────────────────────
def test_sourcemap_ref_reads_last_reference():
    from core.web.js_routes import sourcemap_ref

    js = "console.log(1)\n//# sourceMappingURL=app.js.map\n"
    assert sourcemap_ref(js) == "app.js.map"
    assert sourcemap_ref("no map here") is None


def test_resolve_and_inline_sourcemap():
    import base64

    from core.web.js_routes import (
        inline_sourcemap,
        resolve_sourcemap_url,
        sourcemap_ref,
    )

    assert (
        resolve_sourcemap_url("app.js.map", "https://a.test/static/app.js")
        == "https://a.test/static/app.js.map"
    )
    assert (
        resolve_sourcemap_url("data:application/json;base64,xxx", "https://a") is None
    )
    payload = base64.b64encode(b'{"sources":[]}').decode()
    ref = f"data:application/json;base64,{payload}"
    assert inline_sourcemap(ref) == '{"sources":[]}'


def test_routes_from_sourcemap_mines_original_source():
    from core.web.js_routes import routes_from_sourcemap

    smap = {
        "version": 3,
        "sources": ["src/api.js"],
        "sourcesContent": [
            "export const load = () => fetch('/api/admin/secret-report');"
        ],
    }
    import json

    routes = routes_from_sourcemap(json.dumps(smap), "https://a.test/app")
    assert "https://a.test/api/admin/secret-report" in routes


def test_parse_sourcemap_is_robust_to_garbage():
    from core.web.js_routes import parse_sourcemap

    assert parse_sourcemap("not json") == {"sources": [], "sourcesContent": []}
    assert parse_sourcemap('{"sources": "x"}')["sources"] == []
