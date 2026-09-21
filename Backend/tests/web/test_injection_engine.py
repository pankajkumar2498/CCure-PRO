"""
Active server-side injection engine (command/SSTI/XXE/LDAP/XPath).

Tested against an in-process app that emulates each vulnerability class through
exactly the side-channel the engine keys on — a real command-injection endpoint
sleeps for the injected delay, a template endpoint evaluates arithmetic, an XML
endpoint expands an internal entity, and the LDAP/XPath endpoints emit a parser
error on a broken filter. The safe endpoints reflect input inertly, and the
always-slow endpoint proves the differential-timing guard does not fire on a
merely slow server.

Pure-Python and dependency-free, so it runs anywhere the suite runs (no browser,
no external services). Small delays keep it fast.
"""

import asyncio
import html
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

import pytest

from core.web.injection import InjectionEngine

_SLEEP = re.compile(r"sleep\s+(\d+)")
_TPL = re.compile(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}")
_ENTITY = re.compile(r'<!ENTITY\s+(\w+)\s+"([^"]*)"\s*>')


def _make_handler():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body, code=200):
            b = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            if b:
                self.wfile.write(b)

        def do_GET(self):
            u = urlparse(self.path)
            qs = parse_qs(u.query, keep_blank_values=True)
            p = u.path

            def val(k):
                return (qs.get(k) or [""])[0]

            if p == "/cmd":  # command injection: really sleeps the injected delay
                x = val("host")
                m = _SLEEP.search(x)
                if m and re.search(r"[;&|`$]", x):
                    time.sleep(min(int(m.group(1)), 10))
                self._send(f"<html>PING {html.escape(x)}</html>")
            elif p == "/tpl":  # SSTI: evaluates {{a*b}}
                x = val("name")
                out = _TPL.sub(lambda m: str(int(m.group(1)) * int(m.group(2))), x)
                self._send(f"<html>Hello {out}</html>")
            elif p.startswith("/tplpath/"):
                x = unquote(p.rsplit("/", 1)[-1])
                out = _TPL.sub(lambda m: str(int(m.group(1)) * int(m.group(2))), x)
                self._send(f"<html>Path {out}</html>")
            elif p == "/header_tpl":
                x = self.headers.get("X-Name", "")
                out = _TPL.sub(lambda m: str(int(m.group(1)) * int(m.group(2))), x)
                self._send(f"<html>Header {out}</html>")
            elif p == "/cookie_tpl":
                cookies = {}
                for part in (self.headers.get("Cookie") or "").split(";"):
                    if "=" in part:
                        k, v = part.strip().split("=", 1)
                        cookies[k] = v
                x = cookies.get("theme", "")
                out = _TPL.sub(lambda m: str(int(m.group(1)) * int(m.group(2))), x)
                self._send(f"<html>Cookie {out}</html>")
            elif p == "/ldap":  # LDAP: parser error on a broken filter
                x = val("u")
                if x.count("(") != x.count(")") or "*)(" in x:
                    self._send(
                        "<html>Error: javax.naming.directory."
                        "InvalidSearchFilterException: bad search filter</html>",
                        code=500,
                    )
                else:
                    self._send(f"<html>user {html.escape(x)}</html>")
            elif p == "/xpath":  # XPath: parser error on unbalanced quote, plus boolean
                x = val("q")
                if x == "' or '1'='1":
                    self._send("<html>MATCH: admin, alice, bob, carol, dave</html>")
                elif x == "' or '1'='2":
                    self._send("<html>NONE</html>")
                elif x.count("'") % 2 == 1:
                    self._send(
                        "<html>Error: javax.xml.xpath.XPathExpressionException: "
                        "unterminated string literal</html>",
                        code=500,
                    )
                else:
                    self._send(f"<html>node {html.escape(x)}</html>")
            elif p == "/safe":  # inert reflection — true negative for every class
                self._send(f"<html>{html.escape(val('q'))}</html>")
            elif p == "/slow":  # always slow, no injection — CMDI must NOT fire
                time.sleep(2)
                self._send(f"<html>{html.escape(val('q'))}</html>")
            elif p == "/error":
                self._send("<html>server error</html>", code=500)
            elif p == "/malformed":
                # abrupt close: send a header then garbage without proper body
                try:
                    self.wfile.write(b"HTTP/1.0 200 OK\r\n\r\n\x00\x01garbage")
                except Exception:
                    pass
            else:
                self._send("<html>home</html>")

        def do_POST(self):
            u = urlparse(self.path)
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n).decode("utf-8", "replace")
            if u.path == "/xml":  # XXE: expands internal entities
                entities = dict(_ENTITY.findall(raw))
                out = raw
                for name, v in entities.items():
                    out = out.replace(f"&{name};", v)
                # strip the doctype/markup, echo the parsed probe text
                self._send(f"<result>{html.escape(out)}</result>")
            elif u.path == "/cmd":
                self._send("<html>posted</html>")
            else:
                self._send("<html>ok</html>")

    return H


@pytest.fixture
def target():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler())
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        yield base
    finally:
        srv.shutdown()
        srv.server_close()


def _engine(**kw):
    kw.setdefault("rate_limit", 50)
    kw.setdefault("cmdi_delay_1", 1)
    kw.setdefault("cmdi_delay_2", 2)
    kw.setdefault("timeout_s", 8)
    return InjectionEngine(**kw)


def _run(coro):
    return asyncio.run(coro)


def _classes(findings):
    return {f["finding_type"] for f in findings}


# ── one class each ────────────────────────────────────────────────────────────
def test_command_injection_detected(target):
    eng = _engine(classes=("command_injection",))
    res = _run(
        eng.scan(
            f"{target}/cmd?host=127.0.0.1",
            [{"url": f"{target}/cmd?host=127.0.0.1"}],
            [],
        )
    )
    fs = [f for f in res["findings"] if f["finding_type"] == "command_injection"]
    assert fs, "command injection not detected via timing"
    assert fs[0]["cwe_id"] == "CWE-78"
    assert fs[0]["severity"] == "critical"
    assert fs[0]["is_verified"] is True
    assert fs[0]["detected_by"] == "ccure-injection"


def test_ssti_detected(target):
    eng = _engine(classes=("ssti",))
    res = _run(eng.scan(f"{target}/tpl?name=x", [{"url": f"{target}/tpl?name=x"}], []))
    fs = [f for f in res["findings"] if f["finding_type"] == "ssti"]
    assert fs, "SSTI not detected via arithmetic evaluation"
    assert fs[0]["cwe_id"] == "CWE-1336"
    assert (
        "computed" in fs[0]["description"].lower()
        or "evaluat" in fs[0]["description"].lower()
    )


def test_path_parameter_ssti_detected(target):
    eng = _engine(classes=("ssti",))
    ep = {
        "url": f"{target}/tplpath/123",
        "method": "GET",
        "parameters": {"path": ["name"]},
    }
    res = _run(eng.scan(target, [ep], []))
    fs = [f for f in res["findings"] if f["finding_type"] == "ssti"]
    assert fs, "SSTI in path parameter not detected"
    assert any(
        p["location"] == "path" and p["param"] == "name"
        for p in res["stats"]["tested_params"]
    )


def test_header_parameter_ssti_detected_when_policy_allows(target):
    eng = _engine(classes=("ssti",))
    ep = {
        "url": f"{target}/header_tpl",
        "method": "GET",
        "parameters": {"header": ["X-Name"]},
    }
    res = _run(eng.scan(target, [ep], [], options={"allowed_locations": ["header"]}))
    fs = [f for f in res["findings"] if f["finding_type"] == "ssti"]
    assert fs, "SSTI in header parameter not detected when headers are enabled"
    assert any(
        p["location"] == "header" and p["param"] == "X-Name"
        for p in res["stats"]["tested_params"]
    )


def test_cookie_parameter_ssti_detected_when_policy_allows(target):
    eng = _engine(classes=("ssti",))
    ep = {
        "url": f"{target}/cookie_tpl",
        "method": "GET",
        "parameters": {"cookie": ["theme"]},
    }
    res = _run(eng.scan(target, [ep], [], options={"allowed_locations": ["cookie"]}))
    fs = [f for f in res["findings"] if f["finding_type"] == "ssti"]
    assert fs, "SSTI in cookie parameter not detected when cookies are enabled"
    assert any(
        p["location"] == "cookie" and p["param"] == "theme"
        for p in res["stats"]["tested_params"]
    )


def test_header_cookie_parameters_are_policy_gated(target):
    eng = _engine(classes=("ssti",))
    eps = [
        {
            "url": f"{target}/header_tpl",
            "method": "GET",
            "parameters": {"header": ["X-Name"]},
        },
        {
            "url": f"{target}/cookie_tpl",
            "method": "GET",
            "parameters": {"cookie": ["theme"]},
        },
    ]
    res = _run(
        eng.scan(
            target,
            eps,
            [],
            options={"allowed_locations": ["query", "form", "json", "path"]},
        )
    )
    assert res["stats"]["parameters_tested"] == 0
    assert res["findings"] == []


def test_xxe_detected(target):
    form = {
        "url": f"{target}/xml",
        "method": "POST",
        "inputs": [{"name": "body", "type": "text"}],
        "page_url": f"{target}/xml",
    }
    eng = _engine(classes=("xxe",))
    res = _run(eng.scan(f"{target}/xml", [], [form]))
    fs = [f for f in res["findings"] if f["finding_type"] == "xxe"]
    assert fs, "XXE (internal entity expansion) not detected"
    assert fs[0]["cwe_id"] == "CWE-611"


def test_ldap_injection_detected(target):
    eng = _engine(classes=("ldap_injection",))
    res = _run(
        eng.scan(f"{target}/ldap?u=alice", [{"url": f"{target}/ldap?u=alice"}], [])
    )
    fs = [f for f in res["findings"] if f["finding_type"] == "ldap_injection"]
    assert fs, "LDAP injection not detected via error signature"
    assert fs[0]["cwe_id"] == "CWE-90"


def test_xpath_injection_detected(target):
    eng = _engine(classes=("xpath_injection",))
    res = _run(
        eng.scan(f"{target}/xpath?q=alice", [{"url": f"{target}/xpath?q=alice"}], [])
    )
    fs = [f for f in res["findings"] if f["finding_type"] == "xpath_injection"]
    assert fs, "XPath injection not detected"
    assert fs[0]["cwe_id"] == "CWE-643"


# ── false-positive guards ─────────────────────────────────────────────────────
def test_safe_endpoint_no_findings(target):
    eng = _engine()
    res = _run(eng.scan(f"{target}/safe?q=x", [{"url": f"{target}/safe?q=x"}], []))
    assert res["findings"] == [], f"false positive on inert endpoint: {res['findings']}"


def test_slow_endpoint_is_not_command_injection(target):
    # Always-slow endpoint: the differential timing (fast zero-delay control +
    # tracking two delays) must not fire on a merely slow server.
    eng = _engine(classes=("command_injection",))
    res = _run(eng.scan(f"{target}/slow?q=x", [{"url": f"{target}/slow?q=x"}], []))
    assert [
        f for f in res["findings"] if f["finding_type"] == "command_injection"
    ] == []


# ── behaviour / robustness ────────────────────────────────────────────────────
def test_all_classes_together(target):
    eps = [
        {"url": f"{target}/cmd?host=127.0.0.1"},
        {"url": f"{target}/tpl?name=x"},
        {"url": f"{target}/ldap?u=alice"},
        {"url": f"{target}/xpath?q=alice"},
        {"url": f"{target}/safe?q=x"},
    ]
    form = {
        "url": f"{target}/xml",
        "method": "POST",
        "inputs": [{"name": "body", "type": "text"}],
        "page_url": f"{target}/xml",
    }
    res = _run(_engine().scan(f"{target}/", eps, [form]))
    got = _classes(res["findings"])
    for c in ("command_injection", "ssti", "xxe", "ldap_injection", "xpath_injection"):
        assert c in got, f"{c} missing from combined scan: {got}"


def test_duplicate_finding_one_per_param_class(target):
    eng = _engine(classes=("ldap_injection",))
    res = _run(
        eng.scan(f"{target}/ldap?u=alice", [{"url": f"{target}/ldap?u=alice"}], [])
    )
    ldap = [f for f in res["findings"] if f["finding_type"] == "ldap_injection"]
    assert len(ldap) == 1


def test_cancellation_stops(target):
    eng = _engine()
    eps = [{"url": f"{target}/ldap?u={i}"} for i in range(10)]
    res = _run(eng.scan(f"{target}/", eps, [], cancel_cb=lambda: True))
    assert res["stats"]["parameters_tested"] == 0
    assert res["findings"] == []


def test_timeout_handled(target):
    # Tight timeout against the slow endpoint must not crash; command-injection
    # delays exceed the timeout so nothing is confirmed.
    eng = _engine(
        classes=("command_injection",), timeout_s=1, cmdi_delay_1=3, cmdi_delay_2=5
    )
    res = _run(eng.scan(f"{target}/slow?q=x", [{"url": f"{target}/slow?q=x"}], []))
    assert res["available"] is True
    assert res["findings"] == []


def test_server_error_handled(target):
    eng = _engine()
    res = _run(eng.scan(f"{target}/error?q=x", [{"url": f"{target}/error?q=x"}], []))
    # A 500 that carries no parser signature is not a finding.
    assert [
        f
        for f in res["findings"]
        if f["finding_type"] in ("ldap_injection", "xpath_injection")
    ] == []


def test_malformed_response_handled(target):
    eng = _engine()
    res = _run(
        eng.scan(f"{target}/malformed?q=x", [{"url": f"{target}/malformed?q=x"}], [])
    )
    assert res["available"] is True  # did not crash


def test_authentication_cookie_is_reused(target):
    # The engine must send the provided session cookie; we assert it does not
    # error and honours the auth path (functional smoke — the app is open, so a
    # missing cookie would not change results, but the code path must run).
    cookie = [
        {"name": "session", "value": "letmein", "domain": "127.0.0.1", "path": "/"}
    ]
    res = _run(
        _engine(classes=("ldap_injection",)).scan(
            f"{target}/ldap?u=alice",
            [{"url": f"{target}/ldap?u=alice"}],
            [],
            auth_cookies=cookie,
        )
    )
    assert any(f["finding_type"] == "ldap_injection" for f in res["findings"])


def test_same_origin_scope_enforced(target):
    eng = _engine()
    res = _run(eng.scan(target, [{"url": "http://evil.example.com/ldap?u=x"}], []))
    assert res["findings"] == []
    assert res["stats"]["parameters_tested"] == 0


def test_rate_limiting_is_applied(target):
    # A low rate limit must space requests out measurably.
    eng = _engine(classes=("ldap_injection",), rate_limit=5)
    t0 = time.monotonic()
    res = _run(eng.scan(f"{target}/safe?q=x", [{"url": f"{target}/safe?q=x"}], []))
    # baseline(2) + up to 4 error templates + possibly boolean pair; several
    # requests at 5/s should take a fraction of a second at minimum.
    assert res["stats"]["requests"] >= 3
    assert (time.monotonic() - t0) >= (res["stats"]["requests"] - 1) / 5.0 * 0.5
