"""
Phase 4 — controlled authorization / access-control testing.

A stateful multi-user app models the real thing: alice (account 1001) and bob
(account 1002) are separate users, admin is privileged, and each identity gets
its own isolated session cookie. The app exposes deliberately vulnerable
endpoints (no ownership/role check) alongside correctly protected ones, a
generic endpoint that ignores the id, and a public endpoint — so both the
finding path and every false-positive guard are exercised.

The engine is driven directly with per-identity sessions (headers/cookies),
which is exactly what the orchestrator builds from the authenticated users.
"""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse

import pytest

from core.web.access_control import AccessControlEngine

# username -> (account_id, role)
_USERS = {"alice": (1001, "user"), "bob": (1002, "user"), "admin": (9000, "admin")}
_SESSIONS: dict = {}  # cookie -> username
_ACCOUNTS = {
    1001: "Account 1001 owner=alice balance=4210 email=alice@example.test notes=personal-alice",
    1002: "Account 1002 owner=bob balance=8890 email=bob@example.test notes=personal-bob",
    9000: "Account 9000 owner=admin balance=0 email=admin@example.test notes=root",
}

# A realistic-length HTML wrapper so responses clear the engine's substantive
# body-length guard, while the resource-specific detail (account/admin) differs.
_WRAP_HEAD = (
    "<!DOCTYPE html><html><head><title>App</title></head><body>"
    "<nav>Home | Profile | Settings | Help | Logout</nav>"
    "<div class='container'><h1>Resource</h1><section class='detail'>"
)
_WRAP_TAIL = (
    "</section><footer>&copy; 2026 Example Corp — all rights reserved. "
    "Support: support@example.test. Terms and privacy policy apply.</footer>"
    "</div></body></html>"
)


def _page(detail):
    return _WRAP_HEAD + detail + _WRAP_TAIL


def _make_handler():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _user(self):
            c = SimpleCookie(self.headers.get("Cookie", ""))
            return _SESSIONS.get(c["SESS"].value) if "SESS" in c else None

        def _send(self, body, code=200, set_cookie=None):
            b = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            if set_cookie:
                self.send_header("Set-Cookie", f"SESS={set_cookie}; Path=/")
            self.end_headers()
            if b:
                self.wfile.write(b)

        def do_POST(self):
            u = urlparse(self.path)
            n = int(self.headers.get("Content-Length", 0))
            form = parse_qs(self.rfile.read(n).decode(), keep_blank_values=True)
            if u.path == "/login":
                user = (form.get("username") or [""])[0]
                pw = (form.get("password") or [""])[0]
                if user in _USERS and pw == "pw":
                    tok = f"sess-{user}"
                    _SESSIONS[tok] = user
                    self._send(
                        "<html>welcome " + user + " Logout</html>", set_cookie=tok
                    )
                else:
                    self._send("<html>Login failed</html>")
            else:
                self._send("<html>ok</html>")

        def do_GET(self):
            u = urlparse(self.path)
            qs = parse_qs(u.query, keep_blank_values=True)
            user = self._user()
            rid = (qs.get("id") or [""])[0]
            p = u.path

            if p == "/account":  # VULNERABLE IDOR: any logged-in user, any id
                if not user:
                    self._send("<html>Unauthorized - please log in</html>", 401)
                    return
                try:
                    acc = _ACCOUNTS.get(int(rid))
                except ValueError:
                    acc = None
                self._send(
                    _page(acc) if acc else _page("No such account " + rid),
                    200 if acc else 404,
                )
            elif p == "/safe_account":  # SECURE: ownership enforced
                if not user:
                    self._send("<html>Unauthorized</html>", 401)
                    return
                try:
                    want = int(rid)
                except ValueError:
                    want = -1
                if _USERS.get(user, (None,))[0] == want:
                    self._send(_page(_ACCOUNTS.get(want)))
                else:
                    self._send("<html>Forbidden - not your account</html>", 403)
            elif p == "/admin":  # VULNERABLE vertical: any logged-in user
                if not user:
                    self._send("<html>Unauthorized</html>", 401)
                    return
                self._send(
                    _page(
                        "ADMIN PANEL user-list: alice, bob, admin; controls=delete,reset,impersonate,audit"
                    )
                )
            elif p == "/safe_admin":  # SECURE: role enforced
                if not user:
                    self._send("<html>Unauthorized</html>", 401)
                    return
                if _USERS.get(user, (None, None))[1] == "admin":
                    self._send(
                        _page(
                            "ADMIN PANEL user-list: alice, bob, admin; controls=delete,reset,impersonate,audit"
                        )
                    )
                else:
                    self._send("<html>Forbidden - admins only</html>", 403)
            elif p == "/generic":  # ignores id — same content always (FP guard)
                if not user:
                    self._send("<html>Unauthorized</html>", 401)
                    return
                self._send(
                    _page(
                        "Generic dashboard - same for everyone regardless of id value here"
                    )
                )
            elif p == "/public":  # public — anyone incl anon (FP guard)
                self._send(
                    _page(
                        f"Public brochure page for id {rid} - marketing content, no auth needed"
                    )
                )
            else:
                self._send("<html>home</html>")

    return H


@pytest.fixture
def app():
    _SESSIONS.clear()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler())
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        yield base
    finally:
        srv.shutdown()
        srv.server_close()


def _login(base, user):
    """Return a session dict {label,headers,cookies} for the engine."""
    import httpx

    r = httpx.post(f"{base}/login", data={"username": user, "password": "pw"})
    tok = r.cookies.get("SESS")
    return {"label": user, "headers": {}, "cookies": {"SESS": tok}}


def _run(coro):
    return asyncio.run(coro)


def _eng(**kw):
    kw.setdefault("rate_limit", 50)
    return AccessControlEngine(**kw)


# ── horizontal IDOR ───────────────────────────────────────────────────────────
def test_horizontal_idor_detected(app):
    alice = _login(app, "alice")  # owner of 1001
    bob = _login(app, "bob")  # attacker (owns 1002)
    endpoints = [{"url": f"{app}/account?id=1001"}]
    res = _run(_eng().scan(f"{app}/", endpoints, owner=alice, peers=[bob]))
    idor = [f for f in res["findings"] if f["finding_type"] == "idor"]
    assert idor, f"IDOR not detected: {res['stats']}"
    f = idor[0]
    assert f["cwe_id"] == "CWE-639"
    assert f["severity"] == "high"
    assert f["detected_by"] == "ccure-access-control"
    assert "bob" in f["request_evidence"]  # attacker identity recorded


def test_secure_resource_no_finding(app):
    alice = _login(app, "alice")
    bob = _login(app, "bob")
    endpoints = [{"url": f"{app}/safe_account?id=1001"}]
    res = _run(_eng().scan(f"{app}/", endpoints, owner=alice, peers=[bob]))
    assert (
        res["findings"] == []
    ), f"false positive on protected resource: {res['findings']}"


# ── false-positive guards ─────────────────────────────────────────────────────
def test_generic_endpoint_not_flagged(app):
    # Same content regardless of id → resource-specific gate must reject it.
    alice = _login(app, "alice")
    bob = _login(app, "bob")
    endpoints = [{"url": f"{app}/generic?id=1001"}]
    res = _run(_eng().scan(f"{app}/", endpoints, owner=alice, peers=[bob]))
    assert res["findings"] == []


def test_public_resource_not_flagged(app):
    # Anon can read it → public gate must reject it.
    alice = _login(app, "alice")
    bob = _login(app, "bob")
    endpoints = [{"url": f"{app}/public?id=1001"}]
    res = _run(_eng().scan(f"{app}/", endpoints, owner=alice, peers=[bob]))
    assert res["findings"] == []


def test_changed_id_alone_is_not_a_finding(app):
    # bob accessing his OWN account (1002) is not IDOR even though the id
    # differs from alice's — the engine only flags cross-identity access to the
    # OWNER's resource. Owner=alice on 1001; bob is the peer. bob sees 1001
    # (vulnerable) → that IS idor; but on safe_account bob sees only 1002.
    alice = _login(app, "alice")
    bob = _login(app, "bob")
    endpoints = [{"url": f"{app}/safe_account?id=1002"}]  # bob's own via safe ep
    res = _run(_eng().scan(f"{app}/", endpoints, owner=alice, peers=[bob]))
    # alice cannot see 1002 on safe_account (403) → not an owned baseline → no finding
    assert res["findings"] == []


# ── vertical privilege escalation ─────────────────────────────────────────────
def test_vertical_privilege_escalation_detected(app):
    alice = _login(app, "alice")  # low-priv
    admin = _login(app, "admin")
    admin["privileged"] = True
    res = _run(
        _eng().scan(f"{app}/", [], owner=alice, peers=[admin], admin_paths=["/admin"])
    )
    esc = [f for f in res["findings"] if f["finding_type"] == "privilege_escalation"]
    assert esc, f"vertical escalation not detected: {res['stats']}"
    assert esc[0]["cwe_id"] == "CWE-269"
    assert esc[0]["severity"] == "critical"


def test_secure_admin_no_finding(app):
    alice = _login(app, "alice")
    admin = _login(app, "admin")
    admin["privileged"] = True
    res = _run(
        _eng().scan(
            f"{app}/", [], owner=alice, peers=[admin], admin_paths=["/safe_admin"]
        )
    )
    assert [
        f for f in res["findings"] if f["finding_type"] == "privilege_escalation"
    ] == []


# ── isolation / behaviour ──────────────────────────────────────────────────────
def test_sessions_are_isolated(app):
    # The engine must use each identity's own cookie; if sessions leaked, bob
    # and alice would be indistinguishable and safe_account could misbehave.
    alice = _login(app, "alice")
    bob = _login(app, "bob")
    assert alice["cookies"]["SESS"] != bob["cookies"]["SESS"]
    # On the secure endpoint, alice sees 1001 and bob is forbidden 1001.
    endpoints = [{"url": f"{app}/safe_account?id=1001"}]
    res = _run(_eng().scan(f"{app}/", endpoints, owner=alice, peers=[bob]))
    assert res["findings"] == []


def test_cancellation_stops(app):
    alice = _login(app, "alice")
    bob = _login(app, "bob")
    eps = [{"url": f"{app}/account?id={i}"} for i in (1001, 1002, 9000)]
    res = _run(
        _eng().scan(f"{app}/", eps, owner=alice, peers=[bob], cancel_cb=lambda: True)
    )
    assert res["findings"] == []


def test_credentials_not_in_findings(app):
    alice = _login(app, "alice")
    bob = _login(app, "bob")
    res = _run(
        _eng().scan(
            f"{app}/", [{"url": f"{app}/account?id=1001"}], owner=alice, peers=[bob]
        )
    )
    blob = str(res["findings"])
    assert "sess-alice" not in blob and "sess-bob" not in blob  # no session tokens
    assert "password" not in blob.lower()
