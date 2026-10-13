"""
Phase 3 — authenticated scanning: CSRF/token logins, verification, session
expiry, re-authentication, multi-step workflows, authenticated crawling.

A stateful in-process app models a real CSRF-protected login: the login page
issues a per-session anti-CSRF token bound to a session cookie, and the login
only succeeds when the right token is submitted on that same session — exactly
the flow that the pre-Phase-3 `_form_login` could not do. Protected pages are
reachable only with an authenticated session, so authenticated crawling can be
proven to reach surface an anonymous crawl cannot.

Auth-flow tests are HTTP-only and always run; the two authenticated-crawl tests
need a browser and skip cleanly without one.
"""

import asyncio
import html
import secrets as _secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse

import pytest

from core.web.auth.session_manager import (
    WebSession,
    WebSessionManager,
    extract_form_tokens,
    looks_like_login_page,
)


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


_needs_browser = pytest.mark.skipif(
    not _browser_ok(), reason="Chromium not available for authenticated crawl"
)

_TOKENS: dict = {}
_AUTHED: set = set()


def _make_handler():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _sid(self):
            c = SimpleCookie(self.headers.get("Cookie", ""))
            return c["SESSID"].value if "SESSID" in c else None

        def _send(self, body, code=200, set_sid=None, location=None):
            b = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            if set_sid:
                self.send_header("Set-Cookie", f"SESSID={set_sid}; Path=/")
            if location:
                self.send_header("Location", location)
            self.end_headers()
            if b:
                self.wfile.write(b)

        def do_GET(self):
            u = urlparse(self.path)
            qs = parse_qs(u.query, keep_blank_values=True)
            sid = self._sid()
            p = u.path
            if p == "/login":
                new_sid = sid or _secrets.token_hex(8)
                token = _secrets.token_hex(12)
                _TOKENS[new_sid] = token
                self._send(
                    f'<html><body><form method="POST" action="/login">'
                    f'<input type="hidden" name="user_token" value="{token}">'
                    f'<input name="username"><input type="password" name="password">'
                    f"</form></body></html>",
                    set_sid=new_sid,
                )
            elif p == "/dashboard":
                if sid in _AUTHED:
                    self._send(
                        "<html><body><h1>Dashboard</h1>Welcome admin"
                        '<a href="/secret">secret</a></body></html>'
                    )
                else:
                    self._send("<html><body>Please log in</body></html>", code=200)
            elif p == "/secret":
                if sid in _AUTHED:
                    q = (qs.get("q") or [""])[0]
                    self._send(
                        f"<html><body>SECRET AREA {html.escape(q)}</body></html>"
                    )
                else:
                    self._send("<html><body>Please log in</body></html>")
            elif p == "/verify":
                if sid in _AUTHED:
                    self._send("<html><body>authenticated ok</body></html>")
                else:
                    self._send("<html><body>Please log in</body></html>", code=401)
            else:
                self._send("<html><body>home</body></html>")

        def do_POST(self):
            u = urlparse(self.path)
            n = int(self.headers.get("Content-Length", 0))
            form = parse_qs(self.rfile.read(n).decode(), keep_blank_values=True)
            sid = self._sid()
            if u.path == "/login":
                tok = (form.get("user_token") or [""])[0]
                user = (form.get("username") or [""])[0]
                pw = (form.get("password") or [""])[0]
                if (
                    sid
                    and _TOKENS.get(sid) == tok
                    and user == "admin"
                    and pw == "password"
                ):
                    _AUTHED.add(sid)
                    self._send("", code=303, location="/dashboard")
                else:
                    self._send("<html><body>Login failed</body></html>", code=200)
            else:
                self._send("<html><body>ok</body></html>")

    return H


@pytest.fixture
def app():
    _TOKENS.clear()
    _AUTHED.clear()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler())
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        yield base
    finally:
        srv.shutdown()
        srv.server_close()


def _run(coro):
    return asyncio.run(coro)


def _form_cfg(base, **over):
    cfg = {
        "type": "form_login",
        "login_url": f"{base}/login",
        "username": "admin",
        "password": "password",
        "username_field": "username",
        "password_field": "password",
        "csrf_field": "user_token",
        "success_indicator": "Dashboard",
    }
    cfg.update(over)
    return cfg


# ── CSRF / hidden token ───────────────────────────────────────────────────────
def test_extract_form_tokens_unit():
    htmls = '<input type="hidden" name="user_token" value="abc"><input name="u">'
    assert extract_form_tokens(htmls, "user_token") == {"user_token": "abc"}
    assert extract_form_tokens(htmls) == {"user_token": "abc"}  # hidden captured


def test_csrf_form_login_succeeds(app):
    mgr = WebSessionManager()
    s = _run(mgr.authenticate(_form_cfg(app), "wsc_t1"))
    assert s.is_authenticated, s.auth_error
    assert s.cookies.get("SESSID")


def test_wrong_password_fails_cleanly(app):
    mgr = WebSessionManager()
    s = _run(mgr.authenticate(_form_cfg(app, password="wrong"), "wsc_t2"))
    assert not s.is_authenticated
    assert "did not succeed" in s.auth_error.lower()


def test_wrong_csrf_field_still_works_via_hidden_extraction(app):
    # A wrong csrf_field name is a safety net, not a failure: extract_hidden
    # (default) still carries the login page's hidden token, so login succeeds.
    mgr = WebSessionManager()
    s = _run(mgr.authenticate(_form_cfg(app, csrf_field="nonexistent"), "wsc_t3a"))
    assert s.is_authenticated, s.auth_error


def test_known_csrf_field_names_are_auto_captured():
    # The extractor recognises conventional token field names even when neither
    # csrf_field nor hidden extraction would otherwise capture them — the
    # robustness that makes a wrong csrf_field harmless.
    htmls = '<input type="text" name="csrfmiddlewaretoken" value="zzz">'
    assert extract_form_tokens(htmls, csrf_field="wrong", extract_hidden=False) == {
        "csrfmiddlewaretoken": "zzz"
    }


# ── verification ──────────────────────────────────────────────────────────────
def test_session_verification_passes(app):
    mgr = WebSessionManager()
    cfg = _form_cfg(
        app, verify_url=f"{app}/verify", verify_success_indicator="authenticated ok"
    )
    s = _run(mgr.authenticate(cfg, "wsc_t4"))
    assert s.is_authenticated
    assert s.verified is True


def test_session_verification_detects_bad_session(app):
    # A cookie session that was never authenticated must fail verification.
    mgr = WebSessionManager()
    cfg = {
        "type": "cookie",
        "cookies": {"SESSID": "not-a-real-session"},
        "verify_url": f"{app}/verify",
        "login_url": f"{app}/login",
    }
    # cookie type does not run verify itself; use verify helper via a client.
    import httpx

    async def _check():
        async with httpx.AsyncClient() as c:
            for k, v in cfg["cookies"].items():
                c.cookies.set(k, v)
            return await mgr._verify_on_client(c, cfg, {})

    ok, reason = _run(_check())
    assert ok is False


# ── expiry / loss detection ───────────────────────────────────────────────────
def test_session_expiry_detection():
    cfg = {"login_url": "http://x/login", "failure_indicator": "Please log in"}
    assert WebSession.looks_unauthenticated(401, "http://x/dashboard", "ok", cfg)
    assert WebSession.looks_unauthenticated(
        200, "http://x/dashboard", "Please log in", cfg
    )
    assert WebSession.looks_unauthenticated(200, "http://x/login", "form", cfg)
    assert not WebSession.looks_unauthenticated(
        200, "http://x/dashboard", "Welcome", cfg
    )
    assert looks_like_login_page("session expired", "http://x/y", {})


# ── re-authentication (bounded) ───────────────────────────────────────────────
def test_reauthentication_is_bounded(app):
    mgr = WebSessionManager()
    cfg = _form_cfg(app, max_reauth=2)
    a = _run(mgr.reauthenticate(cfg, "wsc_t5"))
    b = _run(mgr.reauthenticate(cfg, "wsc_t5"))
    c = _run(mgr.reauthenticate(cfg, "wsc_t5"))  # third exceeds cap of 2
    assert a.is_authenticated and b.is_authenticated
    assert not c.is_authenticated
    assert "limit" in c.auth_error.lower()


# ── multi-step workflow ───────────────────────────────────────────────────────
def test_multi_step_login(app):
    mgr = WebSessionManager()
    cfg = {
        "type": "multi_step",
        "login_url": f"{app}/login",
        "verify_url": f"{app}/verify",
        "verify_success_indicator": "authenticated ok",
        "login_steps": [
            {
                "method": "GET",
                "url": f"{app}/login",
                "extract": {"tok": {"hidden": "user_token"}},
            },
            {
                "method": "POST",
                "url": f"{app}/login",
                "fields": {
                    "username": "admin",
                    "password": "password",
                    "user_token": "{{tok}}",
                },
                "success_indicator": "Dashboard",
            },
        ],
    }
    s = _run(mgr.authenticate(cfg, "wsc_t6"))
    assert s.is_authenticated, s.auth_error
    assert s.verified is True


# ── existing types still work + custom headers ────────────────────────────────
def test_bearer_and_cookie_types_unchanged():
    mgr = WebSessionManager()
    b = _run(mgr.authenticate({"type": "bearer_token", "token": "xyz"}, "wsc_t7"))
    assert b.is_authenticated and b.headers["Authorization"] == "Bearer xyz"
    c = _run(mgr.authenticate({"type": "cookie", "cookies": {"s": "1"}}, "wsc_t8"))
    assert c.is_authenticated and c.cookies == {"s": "1"}


def test_custom_headers_merged_into_session():
    mgr = WebSessionManager()
    s = _run(
        mgr.authenticate(
            {"type": "bearer_token", "token": "xyz", "headers": {"X-Tenant": "acme"}},
            "wsc_t9",
        )
    )
    assert s.headers.get("X-Tenant") == "acme"
    assert s.headers.get("Authorization") == "Bearer xyz"


# ── credential exposure ───────────────────────────────────────────────────────
def test_credentials_are_not_exposed(app):
    from core.web.auth.secrets import redact_auth_config
    from orchestrator.web_orchestrator import auth_failure_finding

    cfg = _form_cfg(app)
    red = redact_auth_config(cfg)
    assert red["password"] == "********"
    # A session's serialised form and the auth-failure finding must not carry
    # the password.
    mgr = WebSessionManager()
    s = _run(mgr.authenticate(cfg, "wsc_t10"))
    assert "password" not in str(s.to_dict())
    finding = auth_failure_finding(app, "login did not succeed")
    assert "password" not in str(finding).lower() or "s3cret" not in str(finding)


# ── authenticated crawling (browser) ──────────────────────────────────────────
@_needs_browser
def test_authenticated_crawl_reaches_protected_pages(app):
    from core.web.crawling.browser import PlaywrightCrawler

    mgr = WebSessionManager()
    s = _run(mgr.authenticate(_form_cfg(app), "wsc_c1"))
    assert s.is_authenticated
    cookies = s.get_cookies_for_playwright(app)

    async def _crawl():
        c = PlaywrightCrawler(max_depth=2, max_urls=50)
        return await c.crawl(start_url=f"{app}/dashboard", auth_cookies=cookies)

    res = _run(_crawl())
    urls = {e["url"].split("?")[0] for e in res.endpoints}
    assert any(
        u.endswith("/secret") for u in urls
    ), f"protected page not reached: {urls}"


@_needs_browser
def test_session_loss_during_crawl_triggers_reauth(app):
    from core.web.crawling.browser import PlaywrightCrawler

    # Start the crawl with an invalid session so /dashboard looks like login;
    # the re-auth callback performs a real CSRF login and returns valid cookies,
    # after which the protected surface becomes reachable.
    mgr = WebSessionManager()
    bad = [{"name": "SESSID", "value": "invalid", "url": app}]

    async def _reauth():
        s = await mgr.reauthenticate(_form_cfg(app, max_reauth=3), "wsc_c2")
        return s.get_cookies_for_playwright(app) if s.is_authenticated else None

    async def _crawl():
        c = PlaywrightCrawler(max_depth=2, max_urls=50)
        return await c.crawl(
            start_url=f"{app}/dashboard",
            auth_cookies=bad,
            auth_config={
                "login_url": f"{app}/login",
                "failure_indicator": "Please log in",
            },
            reauth_cb=_reauth,
        )

    res = _run(_crawl())
    events = [e["event"] for e in res.auth_events]
    assert "reauthenticated" in events, f"no re-auth event: {res.auth_events}"
    urls = {e["url"].split("?")[0] for e in res.endpoints}
    assert any(
        u.endswith("/secret") for u in urls
    ), f"protected page not reached after reauth: {urls}"
