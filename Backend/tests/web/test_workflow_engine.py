"""
Phase 13 — authenticated multi-step workflow engine.

Pure validation and secret protection run everywhere. The end-to-end test
drives the real workflow engine against a controlled application that requires
login -> dashboard -> resource -> action (with a CSRF-protected login and
cookie session), and is skipped cleanly where no browser is available. It
proves the workflow reaches the authenticated surface, that the surface is
returned for the DETECT engines, that passwords/tokens are never exposed, and
that off-scope navigation is refused.
"""

import asyncio
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from core.web.workflow import WorkflowEngine, validate_workflow
from core.web.workflow.actions import action_type, normalize_workflow


# ── validation (pure) ────────────────────────────────────────────────────────
def test_valid_workflow_passes():
    wf = {
        "actions": [
            {"action": "open", "url": "/login"},
            {"action": "type", "selector": "#u", "value": "admin"},
            {"action": "type", "selector": "#p", "value": "pw", "secret": True},
            {"action": "submit", "selector": "#go"},
            {"action": "verify", "contains": "Dashboard"},
        ]
    }
    assert validate_workflow(wf) == []


def test_validation_rejects_bad_workflows():
    assert validate_workflow({"actions": []})  # empty
    assert validate_workflow([{"action": "frobnicate"}])  # unknown action
    assert validate_workflow([{"action": "open"}])  # missing url
    assert validate_workflow([{"action": "click"}])  # missing selector
    assert validate_workflow([{"action": "type", "selector": "#u"}])  # missing value
    assert validate_workflow([{"action": "wait"}])  # needs ms or selector
    assert validate_workflow([{"action": "verify"}])  # needs a condition


def test_normalize_and_alias():
    assert normalize_workflow([{"action": "open", "url": "/"}])["actions"]
    assert action_type({"action": "navigate"}) == "open"
    assert action_type({"action": "enter_text"}) == "type"


# ── secret protection in storage/redaction ───────────────────────────────────
def test_workflow_secrets_encrypted_and_redacted():
    from core.web.auth.secrets import (
        decrypt_auth_config,
        encrypt_auth_config,
        redact_auth_config,
    )

    cfg = {
        "auth_type": "form_login",
        "workflow": {
            "actions": [
                {"action": "open", "url": "/login"},
                {"action": "type", "selector": "#p", "value": "s3cret", "secret": True},
            ]
        },
    }
    enc = encrypt_auth_config(cfg)
    enc_val = enc["workflow"]["actions"][1]["value"]
    assert enc_val.startswith("enc:v1:")  # stored encrypted
    assert "s3cret" not in enc_val
    # round-trips
    dec = decrypt_auth_config(enc)
    assert dec["workflow"]["actions"][1]["value"] == "s3cret"
    # redacted view never shows the value
    red = redact_auth_config(cfg)
    assert red["workflow"]["actions"][1]["value"] == "********"
    # the URL of the open action stays readable
    assert red["workflow"]["actions"][0]["url"] == "/login"


# ── controlled login -> dashboard -> resource -> action app ──────────────────
def _make_app():
    valid_sids = set()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _authed(self):
            cookie = self.headers.get("Cookie", "")
            return any(
                c.strip().startswith("sid=") and c.strip()[4:] in valid_sids
                for c in cookie.split(";")
            )

        def _html(self, body, status=200, headers=None):
            b = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/login":
                self._html(
                    "<html><body><h1>Sign in</h1>"
                    "<form method='POST' action='/login'>"
                    "<input type='hidden' name='csrf' value='csrf-tok-123'>"
                    "<input id='username' name='username'>"
                    "<input id='password' name='password' type='password'>"
                    "<button id='login-btn' type='submit'>Login</button>"
                    "</form></body></html>"
                )
            elif path == "/dashboard":
                if not self._authed():
                    self._html("<html><body>Login required</body></html>")
                    return
                self._html(
                    "<html><body><h1>Dashboard</h1>"
                    "<a href='/resource/1'>resource 1</a></body></html>"
                )
            elif path == "/resource/1":
                if not self._authed():
                    self._html("<html><body>Login required</body></html>")
                    return
                self._html(
                    "<html><body><h1>Resource 1</h1>"
                    "<form method='POST' action='/resource/1/action'>"
                    "<input type='hidden' name='csrf' value='csrf-tok-123'>"
                    "<button id='do-action' type='submit'>Do action</button>"
                    "</form></body></html>"
                )
            elif path == "/resource/1/done":
                if not self._authed():
                    self._html("<html><body>Login required</body></html>")
                    return
                self._html("<html><body><h1>Action complete</h1></body></html>")
            else:
                self._html("<html><body>not found</body></html>", status=404)

        def _redirect(self, location, extra=None):
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()

        def do_POST(self):
            path = urlparse(self.path).path
            length = int(self.headers.get("Content-Length", 0))
            data = parse_qs(self.rfile.read(length).decode())
            if path == "/login":
                if (
                    data.get("csrf", [""])[0]
                    and data.get("username", [""])[0] == "admin"
                    and data.get("password", [""])[0] == "s3cret-pass"
                ):
                    valid_sids.add("SESSION1")
                    # Realistic auth: set the session cookie and redirect, so the
                    # browser's URL becomes /dashboard.
                    self._redirect(
                        "/dashboard", extra={"Set-Cookie": "sid=SESSION1; Path=/"}
                    )
                else:
                    self._html("<html><body>Invalid login</body></html>")
            elif path == "/resource/1/action":
                if not self._authed():
                    self._html("<html><body>Login required</body></html>")
                    return
                self._redirect("/resource/1/done")
            else:
                self._html("<html><body>not found</body></html>", status=404)

    return H


@pytest.fixture
def app():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_app())
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        yield base
    finally:
        srv.shutdown()
        srv.server_close()


def _browser_ok():
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            b = p.chromium.launch(headless=True, args=["--no-sandbox"])
            b.close()
        return True
    except Exception:
        return False


browser_required = pytest.mark.skipif(not _browser_ok(), reason="no launchable browser")


def _run(coro):
    return asyncio.run(coro)


def _login_workflow(base):
    return {
        "actions": [
            {"action": "open", "url": base + "/login"},
            {"action": "type", "selector": "#username", "value": "admin"},
            {
                "action": "type",
                "selector": "#password",
                "value": "s3cret-pass",
                "secret": True,
            },
            {"action": "submit", "selector": "#login-btn"},
            {"action": "verify", "contains": "Dashboard"},
            {"action": "open", "url": base + "/resource/1"},
            {"action": "verify", "contains": "Resource 1"},
            {"action": "click", "selector": "#do-action"},
            {"action": "verify", "contains": "Action complete"},
        ]
    }


@browser_required
def test_end_to_end_login_dashboard_resource_action(app):
    base = app
    eng = WorkflowEngine(allowed_domains={urlparse(base).netloc})
    res = _run(eng.run(_login_workflow(base), base_url=base))
    assert res["ok"] is True, res["errors"]
    assert res["steps_run"] == 9
    urls = {e["url"].replace(base, "") for e in res["endpoints"]}
    # the authenticated surface reached is available for the DETECT engines
    assert any(u.startswith("/dashboard") for u in urls)
    assert any(u.startswith("/resource/1") for u in urls)
    # the post-action page (reached only after performing the authenticated
    # action) is discovered too
    assert any(u.startswith("/resource/1/done") for u in urls)


@browser_required
def test_password_is_never_exposed(app):
    base = app
    eng = WorkflowEngine(allowed_domains={urlparse(base).netloc})
    res = _run(eng.run(_login_workflow(base), base_url=base))
    blob = repr(
        {
            "captured": res["captured"],
            "errors": res["errors"],
            "endpoints": res["endpoints"],
            "forms": res["forms"],
        }
    )
    assert "s3cret-pass" not in blob  # never in any API-visible field


@browser_required
def test_offscope_navigation_is_refused(app):
    base = app
    eng = WorkflowEngine(allowed_domains={urlparse(base).netloc})
    wf = {
        "actions": [
            {"action": "open", "url": base + "/login"},
            {"action": "open", "url": "http://evil.example.test/steal"},
        ]
    }
    res = _run(eng.run(wf, base_url=base))
    assert res["ok"] is False
    assert any("scope" in e.lower() for e in res["errors"])
    for e in res["endpoints"]:
        assert "evil.example.test" not in e["url"]


@browser_required
def test_failed_verify_stops_workflow(app):
    base = app
    eng = WorkflowEngine(allowed_domains={urlparse(base).netloc})
    wf = {
        "actions": [
            {"action": "open", "url": base + "/login"},
            {"action": "verify", "contains": "This text is not on the page"},
            {"action": "open", "url": base + "/dashboard"},
        ]
    }
    res = _run(eng.run(wf, base_url=base))
    assert res["ok"] is False
    assert res["steps_run"] == 1  # stopped at the failed verify


@browser_required
def test_cancellation_stops_workflow(app):
    base = app
    eng = WorkflowEngine(allowed_domains={urlparse(base).netloc})
    res = _run(eng.run(_login_workflow(base), base_url=base, cancel_cb=lambda: True))
    assert res["ok"] is False
    assert res["steps_run"] == 0


def test_auth_schema_validates_workflow():
    """A workflow reaches the engine through the scan-config schema, which
    rejects a malformed one at request time."""
    from routers.web_scans import WebScanAuthSchema

    good = WebScanAuthSchema(
        auth_type="form_login",
        workflow={"actions": [{"action": "open", "url": "/login"}]},
    )
    assert good.workflow is not None
    with pytest.raises(Exception):
        WebScanAuthSchema(
            auth_type="form_login", workflow={"actions": [{"action": "x"}]}
        )


def test_engine_unavailable_returns_cleanly(monkeypatch):
    eng = WorkflowEngine(allowed_domains={"t"})
    monkeypatch.setattr(eng, "is_available", lambda: False)
    res = _run(
        eng.run({"actions": [{"action": "open", "url": "http://t/"}]}, "http://t/")
    )
    assert res["ok"] is False
    assert res["endpoints"] == []
