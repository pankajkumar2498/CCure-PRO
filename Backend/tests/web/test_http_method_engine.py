"""
Phase 6 — HTTP method / verb security testing.

A controlled app implements TRACE (toggleable), an endpoint whose GET is gated
by a session cookie but whose HEAD is not (the classic method-based auth
bypass), a correctly-protected endpoint (both verbs gated), and an open one.
The engine is driven read-only; nothing mutates.
"""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from urllib.parse import urlparse

import pytest

from core.web.http_methods import HttpMethodEngine


def _make_handler(holder):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _authed(self):
            c = SimpleCookie(self.headers.get("Cookie", ""))
            return "SESS" in c and c["SESS"].value == "valid"

        def _send(self, body, code=200, head_only=False):
            b = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b)))
            if self.path == "/open":
                self.send_header("Allow", "GET, POST, HEAD, OPTIONS")
            self.end_headers()
            if b and not head_only:
                self.wfile.write(b)

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Allow", "GET, HEAD, OPTIONS, POST")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_TRACE(self):
            if not holder.get("trace"):
                self._send("Method Not Allowed", 405)
                return
            # Echo the request line + headers (Cross-Site Tracing behaviour).
            echo = f"TRACE {self.path}\r\n" + "".join(
                f"{k}: {v}\r\n" for k, v in self.headers.items()
            )
            b = echo.encode()
            self.send_response(200)
            self.send_header("Content-Type", "message/http")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            p = urlparse(self.path).path
            if p == "/protected":
                if self._authed():
                    self._send(
                        "<html>protected content for the authenticated user</html>"
                    )
                else:
                    self._send("<html>Unauthorized</html>", 401)
            elif p == "/secure":
                if self._authed():
                    self._send("<html>secure content</html>")
                else:
                    self._send("<html>Unauthorized</html>", 401)
            else:
                self._send("<html>open page</html>")

        def do_HEAD(self):
            p = urlparse(self.path).path
            if p == "/protected":
                # BUG: HEAD is not gated — auth bypass via alternate verb.
                self._send("", 200, head_only=True)
            elif p == "/secure":
                # Correct: HEAD honours the same auth as GET.
                self._send("", 200 if self._authed() else 401, head_only=True)
            else:
                self._send("", 200, head_only=True)

    return H


@pytest.fixture
def app():
    holder = {"trace": True}
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


def _owner():
    return {"headers": {}, "cookies": {"SESS": "valid"}}


def _eng(**kw):
    kw.setdefault("rate_limit", 50)
    return HttpMethodEngine(**kw)


def test_trace_enabled_detected(app):
    base, holder = app
    holder["trace"] = True
    res = _run(_eng().scan(base + "/", [], owner=_owner()))
    tr = [
        f
        for f in res["findings"]
        if f["finding_type"] == "insecure_http_method"
        and f["request_method"] == "TRACE"
    ]
    assert tr, "TRACE not detected"
    assert tr[0]["cwe_id"] == "CWE-693"


def test_trace_disabled_no_finding(app):
    base, holder = app
    holder["trace"] = False
    res = _run(_eng().scan(base + "/", [], owner=_owner()))
    assert [f for f in res["findings"] if f["request_method"] == "TRACE"] == []


def test_method_auth_bypass_detected(app):
    base, _ = app
    eps = [{"url": base + "/protected"}]
    res = _run(_eng().scan(base + "/", eps, owner=_owner()))
    b = [f for f in res["findings"] if f["finding_type"] == "http_method_auth_bypass"]
    assert (
        b
    ), f"method auth-bypass not detected: {[f['finding_type'] for f in res['findings']]}"
    assert b[0]["cwe_id"] == "CWE-288"
    assert b[0]["severity"] == "high"


def test_properly_protected_no_bypass(app):
    base, _ = app
    eps = [{"url": base + "/secure"}]
    res = _run(_eng().scan(base + "/", eps, owner=_owner()))
    assert [
        f
        for f in res["findings"]
        if f["finding_type"] == "http_method_auth_bypass"
        and "/secure" in f["request_url"]
    ] == []


def test_no_owner_session_skips_bypass_check(app):
    # Without an authenticated baseline the engine cannot prove a bypass and
    # must not guess.
    base, holder = app
    holder["trace"] = False
    eps = [{"url": base + "/protected"}]
    res = _run(_eng().scan(base + "/", eps, owner=None))
    assert [
        f for f in res["findings"] if f["finding_type"] == "http_method_auth_bypass"
    ] == []


def test_cancellation_stops(app):
    base, _ = app
    eps = [{"url": base + f"/protected?{i}"} for i in range(10)]
    res = _run(_eng().scan(base + "/", eps, owner=_owner(), cancel_cb=lambda: True))
    assert res["findings"] == [] or all(
        f["request_method"] == "TRACE" for f in res["findings"]
    )
