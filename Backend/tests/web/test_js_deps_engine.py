"""
Phase 7 — vulnerable JavaScript dependency detection.

Detection (URL + banner) and version-range logic are unit-tested pure. Matching
is tested against an injected OSV query for determinism, and once against the
live OSV feed (skipped if unavailable). A controlled app serves a deliberately
old jQuery so end-to-end detection can be exercised, and a patched version to
prove non-vulnerable behaviour.
"""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pytest

from core.web.js_deps import JsDependencyEngine
from core.web.js_deps.engine import detect_from_url, detect_from_content, _ver_tuple


# ── pure detection ─────────────────────────────────────────────────────────────
def test_detect_from_url_variants():
    assert detect_from_url("http://x/js/jquery-1.12.4.min.js") == (
        "jquery",
        "jquery",
        "1.12.4",
    )
    assert detect_from_url(
        "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js"
    ) == ("jquery", "jquery", "3.4.1")
    assert detect_from_url("https://unpkg.com/vue@2.6.10/dist/vue.js") == (
        "vue",
        "vue",
        "2.6.10",
    )
    assert detect_from_url("http://x/app.bundle.js") is None


def test_detect_from_banner():
    assert detect_from_content("/*! jQuery v1.12.4 | (c) jQuery Foundation */") == (
        "jquery",
        "jquery",
        "1.12.4",
    )
    assert detect_from_content("/**\n * @license AngularJS v1.7.8\n */") == (
        "angularjs",
        "angular",
        "1.7.8",
    )


def test_version_range_logic():
    aff = JsDependencyEngine._affected
    assert aff("1.12.4", [("0", "3.4.0")]) is True
    assert aff("3.5.0", [("0", "3.4.0")]) is False
    assert aff("3.4.0", [("0", "3.4.0")]) is False  # fixed version is not affected
    assert aff("2.0.0", [("1.9.0", "2.1.0")]) is True
    assert _ver_tuple("3.4.1-beta") == (3, 4, 1)


# ── controlled app ──────────────────────────────────────────────────────────────
def _make_handler(holder):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body, ctype="text/html"):
            b = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            ver = holder["version"]  # read dynamically per request
            p = urlparse(self.path).path
            if p == "/":
                self._send(
                    f"<html><head>"
                    f'<script src="/js/jquery-{ver}.min.js"></script>'
                    f'<script src="/js/app.bundle.js"></script>'
                    f"</head><body>home</body></html>"
                )
            elif p == "/page2":
                # Same library referenced again (dedup check).
                self._send(
                    f'<html><script src="/js/jquery-{ver}.min.js"></script></html>'
                )
            elif p.startswith("/js/jquery-"):
                self._send(
                    f"/*! jQuery v{ver} | (c) jQuery Foundation */\n!function(){{}}();",
                    "application/javascript",
                )
            else:
                self._send(
                    "// unknown bundle, no banner\nvar x=1;", "application/javascript"
                )

    return H


@pytest.fixture
def app():
    holder = {"version": "1.12.4"}
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(holder))
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        yield base, holder
    finally:
        srv.shutdown()
        srv.server_close()


def _run(c):
    return asyncio.run(c)


# Injected feeds for determinism.
def _fake_osv(npm, ver):
    if npm == "jquery" and JsDependencyEngine._affected(ver, [("0", "3.4.0")]):
        return [{"osv_id": "GHSA-test-jq", "cve": "CVE-2019-11358", "fixed": "3.4.0"}]
    return []


def _fake_enrich(cve):
    return {
        "cvss": 6.1,
        "severity": "medium",
        "cwe": "CWE-1321",
        "cvss_vector": "CVSS:3.1/AV:N",
    }


def _eng(**kw):
    kw.setdefault("osv_query", _fake_osv)
    kw.setdefault("cve_enrich", _fake_enrich)
    return JsDependencyEngine(**kw)


def test_vulnerable_library_detected_and_enriched(app):
    base, _ = app
    res = _run(_eng().scan(base + "/"))
    vj = [f for f in res["findings"] if f["finding_type"] == "vulnerable_js_library"]
    assert vj, "vulnerable jQuery not detected"
    f = vj[0]
    assert f["cve_id"] == "CVE-2019-11358"
    assert f["cwe_id"] == "CWE-1321"
    assert f["cvss_score"] == 6.1
    assert f["severity"] == "medium"
    assert "3.4.0" in f["remediation"]
    assert f["source"] == "OSV"


def test_non_vulnerable_version_no_finding(app):
    base, holder = app
    holder["version"] = "3.7.1"  # patched; fake OSV fixes at 3.4.0
    res = _run(_eng().scan(base + "/"))
    assert [
        f for f in res["findings"] if f["finding_type"] == "vulnerable_js_library"
    ] == []


def test_duplicate_prevention(app):
    base, _ = app
    # jQuery referenced on / and /page2 → still one finding per (lib,version,cve).
    res = _run(
        _eng().scan(
            base + "/",
            endpoints=[{"url": base + "/page2", "content_type": "text/html"}],
        )
    )
    vj = [f for f in res["findings"] if f["cve_id"] == "CVE-2019-11358"]
    assert len(vj) == 1, f"duplicate findings: {len(vj)}"


def test_unknown_library_no_finding(app):
    base, holder = app
    holder["version"] = "1.12.4"
    # app.bundle.js is unknown → no detection, no finding beyond jquery.
    res = _run(_eng(osv_query=lambda n, v: []).scan(base + "/"))
    assert res["findings"] == []
    # jQuery was still identified as a library (detection works, just not vulnerable here).
    assert res["stats"]["libraries"] >= 1


def test_minified_banner_detection():
    # A minified body with only a license banner still yields the version.
    det = detect_from_content("/*! jQuery v1.12.4 */!function(e,t){}(window);")
    assert det == ("jquery", "jquery", "1.12.4")


# ── live OSV integration (skipped if the feed is unavailable) ──────────────────
def _osv_ready():
    try:
        return bool(JsDependencyEngine._osv_npm_advisories("jquery", "1.12.4"))
    except Exception:
        return False


@pytest.mark.skipif(not _osv_ready(), reason="live OSV npm feed unavailable")
def test_live_osv_matches_old_jquery(app):
    base, _ = app  # serves 1.12.4
    # Real OSV query, real (best-effort) enrichment.
    res = _run(JsDependencyEngine().scan(base + "/"))
    vj = [f for f in res["findings"] if f["finding_type"] == "vulnerable_js_library"]
    assert vj, "live OSV did not flag jQuery 1.12.4"
    assert any(f.get("cve_id", "").startswith("CVE-") for f in vj)
