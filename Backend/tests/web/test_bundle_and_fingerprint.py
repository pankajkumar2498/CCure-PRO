"""
Phase 16 — bundled-JS dependency detection (Part A) and multi-source technology
fingerprinting (Part B).

Part A proves version-bearing library signatures are found deep inside a
webpack/minified bundle (past the banner window), that presence-only signals
(source maps) never become a version claim, and that a library seen many ways
collapses to one finding. Part B proves technologies are detected from headers,
cookies and DOM/asset markers — not just headers — and that a plain page yields
no speculative fingerprint.
"""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from core.web.fingerprint import TechFingerprinter
from core.web.js_deps import JsDependencyEngine
from core.web.js_deps.engine import (
    detect_all_from_bundle,
    detect_from_content,
    sourcemap_libraries,
)


def _run(c):
    return asyncio.run(c)


# ── Part A: bundle signature detection (pure) ────────────────────────────────
def test_bundle_finds_versions_past_the_banner_window():
    body = (
        "x" * 9000
        + 'a.fn.jquery="3.4.1";'
        + "y" * 5000
        + 'lodash.VERSION="4.17.15";'
        + 'e.version={full:"1.7.8",major:1};'
    )
    # banner-only scan (first 4000 chars) misses all of it
    assert detect_from_content(body) is None
    got = {(n, v) for n, _npm, v in detect_all_from_bundle(body)}
    assert ("jquery", "3.4.1") in got
    assert ("lodash", "4.17.15") in got
    assert ("angularjs", "1.7.8") in got


def test_bundle_does_not_claim_a_version_from_a_generic_string():
    # a bare version="x" not tied to a known library must not be claimed
    assert detect_all_from_bundle('var config={version:"9.9.9"};') == []
    assert detect_all_from_bundle("no libraries here at all") == []


def test_sourcemap_is_presence_only_never_a_version():
    import base64
    import json

    sm = base64.b64encode(
        json.dumps(
            {
                "version": 3,
                "sources": [
                    "webpack://./node_modules/jquery/dist/jquery.js",
                    "webpack://./node_modules/lodash/lodash.js",
                ],
            }
        ).encode()
    ).decode()
    content = "console.log(1);\n//# sourceMappingURL=data:application/json;base64," + sm
    names = sourcemap_libraries(content)
    assert "jquery" in names and "lodash" in names
    # presence names carry no version — they must never be fed to CVE matching
    assert all(isinstance(n, str) for n in names)


# ── Part A: bundle -> finding, with dedup (injected OSV for determinism) ─────
def _fake_osv(npm, ver):
    if npm == "jquery":
        return [{"osv_id": "GHSA-x", "cve": "CVE-2019-11358", "fixed": "3.4.0"}]
    return []


def _fake_enrich(cve):
    return {"cvss": 6.1, "severity": "medium", "cwe": "CWE-1321"}


def _bundle_app(bundle_bytes, also_html_ref=False):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/":
                refs = "<script src='/static/app.bundle.js'></script>"
                if also_html_ref:
                    refs += "<script src='/js/jquery-1.12.4.min.js'></script>"
                b = f"<html><head>{refs}</head><body>x</body></html>".encode()
            elif self.path.endswith("app.bundle.js"):
                b = bundle_bytes
            elif "jquery" in self.path:
                b = b"/*! jQuery v1.12.4 */"
            else:
                b = b"x"
            self.send_response(200)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_bundled_jquery_becomes_a_finding():
    bundle = (
        "!function(e){var p='" + "A" * 9000 + '\';e.fn.jquery="1.12.4";}(window);'
    ).encode()
    srv, base = _bundle_app(bundle)
    try:
        eng = JsDependencyEngine(osv_query=_fake_osv, cve_enrich=_fake_enrich)
        res = _run(eng.scan(base + "/"))
        vj = [f for f in res["findings"] if f["cve_id"] == "CVE-2019-11358"]
        assert vj, "bundled jQuery not detected/matched"
        assert vj[0]["cwe_id"] == "CWE-1321"
    finally:
        srv.shutdown()
        srv.server_close()


def test_same_library_via_url_and_bundle_is_one_finding():
    # jQuery 1.12.4 referenced both by a CDN-style URL and inside the bundle.
    bundle = (
        "!function(e){var p='" + "A" * 9000 + '\';e.fn.jquery="1.12.4";}(window);'
    ).encode()
    srv, base = _bundle_app(bundle, also_html_ref=True)
    try:
        eng = JsDependencyEngine(osv_query=_fake_osv, cve_enrich=_fake_enrich)
        res = _run(eng.scan(base + "/"))
        vj = [f for f in res["findings"] if f["cve_id"] == "CVE-2019-11358"]
        assert len(vj) == 1, f"duplicate findings for one lib+version: {len(vj)}"
    finally:
        srv.shutdown()
        srv.server_close()


# ── Part B: fingerprinter (pure) ─────────────────────────────────────────────
def test_fingerprint_from_headers_cookies_dom():
    fp = TechFingerprinter()
    # DOM-only Angular (the Juice Shop case header-only detection missed)
    ng = fp.fingerprint("http://t/", 200, {}, {}, '<app ng-version="15.1.2"></app>')
    assert any(t["name"] == "Angular" and t["version"] == "15.1.2" for t in ng)
    # cookie + header + body reinforce
    wp = fp.fingerprint(
        "http://t/",
        200,
        {"x-powered-by": "PHP/8.1"},
        {"wordpress_logged_in_abc": ""},
        '<link href="/wp-content/x.css">',
    )
    names = {t["name"] for t in wp}
    assert {"PHP", "WordPress"} <= names
    # Next.js via marker
    nx = fp.fingerprint(
        "http://t/", 200, {}, {}, '<script id="__NEXT_DATA__">{}</script>'
    )
    assert any(t["name"] == "Next.js" for t in nx)
    # meta generator carries a version
    gen = fp.fingerprint(
        "http://t/",
        200,
        {},
        {},
        '<meta name="generator" content="Drupal 10.1 (https://drupal.org)">',
    )
    assert any(
        t["name"].startswith("Drupal") and t.get("version") == "10.1" for t in gen
    )


def test_fingerprint_is_not_speculative_on_a_plain_page():
    fp = TechFingerprinter()
    assert (
        fp.fingerprint("http://t/", 200, {}, {}, "<html><body>hello</body></html>")
        == []
    )


def test_fingerprint_dedupes_and_keeps_version():
    fp = TechFingerprinter()
    techs = fp.fingerprint(
        "http://t/", 200, {"server": "nginx/1.27.5"}, {}, "<html>x</html>"
    )
    nginx = [t for t in techs if t["name"] == "nginx"]
    assert len(nginx) == 1 and nginx[0]["version"] == "1.27.5"


# ── Part B: crawler technology dedup ─────────────────────────────────────────
def test_crawler_dedupes_header_and_fingerprint_entries():
    from core.web.crawling.browser import PlaywrightCrawler

    techs = [
        {"name": "nginx/1.27.5", "category": "server", "source": "header"},
        {
            "name": "nginx",
            "category": "server",
            "version": "1.27.5",
            "confidence": "high",
            "source": "fingerprint",
        },
        {
            "name": "Angular",
            "category": "framework",
            "version": "15.1.2",
            "confidence": "high",
            "source": "fingerprint",
        },
    ]
    out = PlaywrightCrawler._dedupe_technologies(techs)
    names = {t["name"] for t in out}
    # nginx collapses to one entry (the richer, versioned one wins)
    assert sum(1 for t in out if t["name"].lower().startswith("nginx")) == 1
    assert "Angular" in names
    nginx = next(t for t in out if t["name"].lower().startswith("nginx"))
    assert nginx.get("version") == "1.27.5"
