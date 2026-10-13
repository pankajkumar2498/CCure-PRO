"""
Active XSS engine — reflected, DOM and stored — against a controlled target.

The engine proves execution in a real browser, so these tests need a browser
and a deterministic vulnerable app. The app is an in-process http.server started
per test (state isolation), serving intentionally vulnerable and intentionally
safe endpoints so both detection and the absence of false positives are pinned.

If no Chromium is available the whole module skips rather than fails, so a
browserless CI environment does not turn a capability gap into a red build; the
real validation runs where the scanner's browser is installed.
"""

import asyncio
import html
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

import pytest

from core.web.xss import XssEngine


def _browser_ok() -> bool:
    try:

        async def _t():
            from playwright.async_api import async_playwright
            from core.web.browser_runtime import launch_options

            async with async_playwright() as p:
                b = await p.chromium.launch(
                    **launch_options(),
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage"],
                )
                await b.close()
            return True

        return asyncio.run(_t())
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _browser_ok(), reason="Chromium not available for the active XSS engine"
)


def _make_handler(store):
    class VulnHandler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def _send(self, body, code=200, headers=None):
            b = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if body:
                self.wfile.write(b)

        def do_GET(self):
            u = urlparse(self.path)
            qs = parse_qs(u.query, keep_blank_values=True)
            q = (qs.get("q") or [""])[0]
            p = u.path
            if p == "/reflect":  # HTML body context, raw
                self._send(f"<html><body><div>Results for: {q}</div></body></html>")
            elif p == "/reflect_attr":  # attribute context, raw
                self._send(
                    f'<html><body><input type="text" name="q" value="{q}"></body></html>'
                )
            elif p == "/reflect_js":  # JS string context, raw
                self._send(
                    f'<html><body><script>var term = "{q}";'
                    f"document.title = term;</script></body></html>"
                )
            elif p == "/safe":  # correctly encoded — must NOT fire
                self._send(
                    f"<html><body><div>Results for: {html.escape(q)}</div></body></html>"
                )
            elif p == "/dom":  # hash -> innerHTML (DOM sink)
                self._send(
                    '<html><body><div id="out"></div><script>'
                    'document.getElementById("out").innerHTML = '
                    "decodeURIComponent(location.hash.slice(1));"
                    "</script></body></html>"
                )
            elif p == "/stored":  # renders every stored comment raw
                items = "".join(f"<li>{c}</li>" for c in store)
                self._send(
                    '<html><body><form method="POST" action="/stored">'
                    '<input name="comment"><input type="submit"></form>'
                    f"<ul>{items}</ul></body></html>"
                )
            elif p == "/auth_reflect":  # only reflects with the session cookie
                if "session=letmein" in (self.headers.get("Cookie") or ""):
                    self._send(f"<html><body>Secret: {q}</body></html>")
                else:
                    self._send("<html><body>login required</body></html>")
            elif p.startswith("/path_reflect/"):
                value = unquote(p.rsplit("/", 1)[-1])
                self._send(f"<html><body>Path: {value}</body></html>")
            elif p == "/header_reflect":
                value = self.headers.get("X-Name", "")
                self._send(f"<html><body>Header: {value}</body></html>")
            elif p == "/cookie_reflect":
                value = ""
                for part in (self.headers.get("Cookie") or "").split(";"):
                    if "=" not in part:
                        continue
                    name, raw = part.split("=", 1)
                    if name.strip() == "theme":
                        value = unquote(raw.strip().strip('"'))
                self._send(f"<html><body>Cookie: {value}</body></html>")
            elif p == "/slow":
                time.sleep(3)
                self._send("<html><body>slow</body></html>")
            else:
                self._send("<html><body>home</body></html>")

        def do_POST(self):
            u = urlparse(self.path)
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n).decode()
            if "json" in (self.headers.get("Content-Type") or "").lower():
                try:
                    obj = json.loads(raw or "{}")
                except Exception:
                    obj = {}
                term = str(obj.get("term", ""))
                if u.path == "/json_reflect":
                    self._send(f"<html><body><div>{term}</div></body></html>")
                    return
                if u.path == "/json_safe":
                    self._send(
                        f"<html><body><div>{html.escape(term)}</div></body></html>"
                    )
                    return
            form = parse_qs(raw, keep_blank_values=True)
            if u.path == "/stored":
                store.append((form.get("comment") or [""])[0])  # stored raw
                self._send("", code=303, headers={"Location": "/stored"})
            else:
                self._send("<html><body>ok</body></html>")

    return VulnHandler


@pytest.fixture
def target():
    store = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(store))
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        yield base, store
    finally:
        srv.shutdown()
        srv.server_close()


def _engine(**kw):
    kw.setdefault("rate_limit", 50)  # tests hit localhost; keep them quick
    kw.setdefault("timeout_ms", 6000)
    return XssEngine(**kw)


def _run(coro):
    return asyncio.run(coro)


def _types(findings):
    return {f["title"].split()[0] for f in findings}


# ── reflected ────────────────────────────────────────────────────────────────
def test_reflected_html_context(target):
    base, _ = target
    eng = _engine(test_dom=False, test_stored=False)
    res = _run(
        eng.scan(f"{base}/reflect?q=hello", [{"url": f"{base}/reflect?q=hello"}], [])
    )
    fs = [f for f in res["findings"] if f["xss_variant"] == "reflected"]
    assert fs, "reflected HTML-context XSS not detected"
    f = fs[0]
    assert f["severity"] == "high"
    assert f["cwe_id"] == "CWE-79"
    assert f["is_verified"] is True
    assert f["detected_by"] == "ccure-xss"
    assert "q" in f["title"]


def test_reflected_attribute_context(target):
    base, _ = target
    eng = _engine(test_dom=False, test_stored=False)
    res = _run(
        eng.scan(f"{base}/reflect_attr?q=x", [{"url": f"{base}/reflect_attr?q=x"}], [])
    )
    assert any(
        f["xss_variant"] == "reflected" for f in res["findings"]
    ), "attr XSS missed"


def test_reflected_js_context(target):
    base, _ = target
    eng = _engine(test_dom=False, test_stored=False)
    res = _run(
        eng.scan(f"{base}/reflect_js?q=x", [{"url": f"{base}/reflect_js?q=x"}], [])
    )
    assert any(
        f["xss_variant"] == "reflected" for f in res["findings"]
    ), "JS-context XSS missed"


def test_safe_endpoint_is_not_flagged(target):
    # Correctly HTML-encoded reflection must produce no finding — this is the
    # false-positive guard the "reflection != execution" design exists for.
    base, _ = target
    eng = _engine(test_dom=False, test_stored=False)
    res = _run(eng.scan(f"{base}/safe?q=x", [{"url": f"{base}/safe?q=x"}], []))
    assert res["findings"] == [], f"false positive on encoded output: {res['findings']}"


def test_encoded_payload_still_detects(target):
    # The engine URL-encodes payloads into the query string; a vulnerable
    # endpoint that decodes and reflects must still be caught.
    base, _ = target
    eng = _engine(test_dom=False, test_stored=False)
    res = _run(eng.scan(f"{base}/reflect?q=a", [{"url": f"{base}/reflect?q=a"}], []))
    assert any(f["xss_variant"] == "reflected" for f in res["findings"])


def test_non_vulnerable_param_no_finding(target):
    base, _ = target
    eng = _engine(test_dom=False, test_stored=False)
    # /home echoes nothing back, so no parameter is reflected.
    res = _run(eng.scan(f"{base}/home?q=x", [{"url": f"{base}/home?q=x"}], []))
    assert res["findings"] == []


def test_reflected_json_body_context(target):
    base, _ = target
    ep = {
        "url": f"{base}/json_reflect",
        "method": "POST",
        "request_content_type": "application/json",
        "request_body": '{"term": "hello"}',
        "parameters": {"json": ["term"]},
    }
    eng = _engine(test_dom=False, test_stored=False)
    res = _run(eng.scan(base, [ep], []))
    fs = [f for f in res["findings"] if f["xss_variant"] == "reflected"]
    assert fs, "JSON-body reflected XSS not detected"
    assert any(
        p["location"] == "json" and p["param"] == "term"
        for p in res["stats"]["tested_params"]
    )
    assert "location=json" in fs[0]["request_evidence"]


def test_safe_json_body_is_not_flagged(target):
    base, _ = target
    ep = {
        "url": f"{base}/json_safe",
        "method": "POST",
        "request_content_type": "application/json",
        "request_body": '{"term": "hello"}',
        "parameters": {"json": ["term"]},
    }
    eng = _engine(test_dom=False, test_stored=False)
    res = _run(eng.scan(base, [ep], []))
    assert res["findings"] == []


def test_reflected_path_parameter_context(target):
    base, _ = target
    ep = {
        "url": f"{base}/path_reflect/123",
        "method": "GET",
        "parameters": {"path": ["itemId"]},
    }
    eng = _engine(test_dom=False, test_stored=False)
    res = _run(eng.scan(base, [ep], []))
    fs = [f for f in res["findings"] if f["xss_variant"] == "reflected"]
    assert fs, "path-parameter reflected XSS not detected"
    assert any(
        p["location"] == "path" and p["param"] == "itemId"
        for p in res["stats"]["tested_params"]
    )
    assert "location=path" in fs[0]["request_evidence"]


def test_reflected_header_context_when_policy_allows(target):
    base, _ = target
    ep = {
        "url": f"{base}/header_reflect",
        "method": "GET",
        "parameters": {"header": ["X-Name"]},
        "request_headers": {"X-Name": "alice"},
    }
    eng = _engine(test_dom=False, test_stored=False)
    res = _run(
        eng.scan(
            base,
            [ep],
            [],
            options={"allowed_locations": ["query", "form", "json", "path", "header"]},
        )
    )
    fs = [f for f in res["findings"] if f["xss_variant"] == "reflected"]
    assert fs, "header reflected XSS not detected when headers are enabled"
    assert "location=header" in fs[0]["request_evidence"]


def test_reflected_cookie_context_when_policy_allows(target):
    base, _ = target
    ep = {
        "url": f"{base}/cookie_reflect",
        "method": "GET",
        "parameters": {"cookie": ["theme"]},
        "request_cookies": {"theme": "light"},
    }
    eng = _engine(test_dom=False, test_stored=False)
    res = _run(
        eng.scan(
            base,
            [ep],
            [],
            options={"allowed_locations": ["query", "form", "json", "path", "cookie"]},
        )
    )
    fs = [f for f in res["findings"] if f["xss_variant"] == "reflected"]
    assert fs, "cookie reflected XSS not detected when cookies are enabled"
    assert "location=cookie" in fs[0]["request_evidence"]


def test_header_cookie_xss_are_policy_gated(target):
    base, _ = target
    eps = [
        {
            "url": f"{base}/header_reflect",
            "method": "GET",
            "parameters": {"header": ["X-Name"]},
        },
        {
            "url": f"{base}/cookie_reflect",
            "method": "GET",
            "parameters": {"cookie": ["theme"]},
        },
    ]
    eng = _engine(test_dom=False, test_stored=False)
    res = _run(
        eng.scan(
            base,
            eps,
            [],
            options={"allowed_locations": ["query", "form", "json", "path"]},
        )
    )
    assert res["stats"]["parameters_tested"] == 0
    assert res["findings"] == []


# ── DOM ──────────────────────────────────────────────────────────────────────
def test_dom_xss_via_hash(target):
    base, _ = target
    eng = _engine(test_reflected=False, test_stored=False)
    res = _run(eng.scan(f"{base}/dom", [{"url": f"{base}/dom"}], []))
    fs = [f for f in res["findings"] if f["xss_variant"] == "dom"]
    assert fs, "DOM XSS via location.hash not detected"
    assert fs[0]["cwe_id"] == "CWE-79"


# ── stored ───────────────────────────────────────────────────────────────────
def test_stored_xss(target):
    base, store = target
    form = {
        "url": f"{base}/stored",
        "method": "POST",
        "inputs": [{"name": "comment", "type": "text"}],
        "page_url": f"{base}/stored",
    }
    eng = _engine(test_reflected=False, test_dom=False)
    res = _run(eng.scan(f"{base}/stored", [], [form]))
    fs = [f for f in res["findings"] if f["xss_variant"] == "stored"]
    assert fs, "stored XSS not detected"
    assert fs[0]["severity"] == "critical"
    assert any("payload" in c or c for c in store), "payload was not stored"


# ── auth reuse ───────────────────────────────────────────────────────────────
def test_auth_protected_xss_requires_session(target):
    base, _ = target
    ep = [{"url": f"{base}/auth_reflect?q=x"}]
    # Without the cookie the endpoint never reflects -> no finding.
    without = _run(
        _engine(test_dom=False, test_stored=False).scan(
            f"{base}/auth_reflect?q=x", ep, []
        )
    )
    assert without["findings"] == []
    # With the session cookie reused, the protected reflection is reachable.
    host = urlparse(base)
    cookie = [
        {"name": "session", "value": "letmein", "domain": host.hostname, "path": "/"}
    ]
    withc = _run(
        _engine(test_dom=False, test_stored=False).scan(
            f"{base}/auth_reflect?q=x", ep, [], auth_cookies=cookie
        )
    )
    assert any(
        f["xss_variant"] == "reflected" for f in withc["findings"]
    ), "auth-protected XSS not found even with the session cookie"


# ── behaviour ────────────────────────────────────────────────────────────────
def test_duplicate_finding_is_one_per_parameter(target):
    base, _ = target
    eng = _engine(test_dom=False, test_stored=False)
    res = _run(eng.scan(f"{base}/reflect?q=x", [{"url": f"{base}/reflect?q=x"}], []))
    reflected = [f for f in res["findings"] if f["xss_variant"] == "reflected"]
    # One parameter, one finding — the engine stops at the first firing payload.
    assert len(reflected) == 1


def test_cancellation_stops_testing(target):
    base, _ = target
    eng = _engine()
    eps = [{"url": f"{base}/reflect?q={i}"} for i in range(10)]
    res = _run(eng.scan(f"{base}/reflect?q=x", eps, [], cancel_cb=lambda: True))
    # Cancelled before any work -> nothing tested, no crash.
    assert res["stats"]["parameters_tested"] == 0
    assert res["findings"] == []


def test_timeout_is_handled(target):
    base, _ = target
    eng = _engine(test_dom=False, test_stored=False, timeout_ms=800)
    # /slow sleeps 3s server-side; an 800ms navigation timeout must not crash.
    res = _run(eng.scan(f"{base}/slow?q=x", [{"url": f"{base}/slow?q=x"}], []))
    assert res["available"] is True
    assert res["findings"] == []


def test_same_origin_scope_is_enforced(target):
    base, _ = target
    eng = _engine(test_dom=False, test_stored=False, same_origin_only=True)
    # An out-of-scope endpoint must be skipped even if handed in.
    res = _run(eng.scan(base, [{"url": "http://evil.example.com/reflect?q=x"}], []))
    assert res["findings"] == []
    assert res["stats"]["parameters_tested"] == 0
