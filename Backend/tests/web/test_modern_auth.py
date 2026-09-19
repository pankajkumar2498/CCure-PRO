"""
Phase 23 — modern authenticated scanning: JWT, API key, OAuth2 (Codex item 6).

The session manager already did form/CSRF/cookie/bearer/multi-step auth. This
adds first-class token auth used by modern APIs: a static JWT (shape + expiry
validated, no silent 401 scan), an API-key header, and an OAuth2 token-endpoint
grant. OAuth redirect flows (auth_code/OIDC/SAML) are a documented follow-on.
"""

import base64
import json
import time

from core.web.auth.session_manager import WebSessionManager, _inspect_jwt


def _jwt(exp_offset=3600):
    """A syntactically valid (unsigned-content) JWT with an exp claim."""
    hdr = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    payload = {"sub": "alice", "exp": int(time.time()) + exp_offset}
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{hdr}.{body}.sig"


# ── JWT inspection ───────────────────────────────────────────────────────────
def test_inspect_jwt_valid_expired_malformed():
    ok, exp = _inspect_jwt(_jwt(3600))
    assert ok and exp > time.time()
    ok2, exp2 = _inspect_jwt(_jwt(-3600))
    assert ok2 and exp2 < time.time()
    assert _inspect_jwt("not-a-jwt") == (False, None)
    assert _inspect_jwt("only.two") == (False, None)


def test_jwt_session_valid():
    mgr = WebSessionManager()
    sess = mgr._create_jwt_session({"type": "jwt", "token": _jwt(3600)}, "s1")
    assert sess.auth_type == "jwt"
    assert sess.headers["Authorization"].startswith("Bearer ")
    assert not sess.auth_error
    assert sess.is_authenticated


def test_jwt_session_expired_is_flagged():
    mgr = WebSessionManager()
    sess = mgr._create_jwt_session({"type": "jwt", "token": _jwt(-3600)}, "s2")
    assert "expired" in sess.auth_error.lower()


def test_jwt_session_malformed_is_flagged():
    mgr = WebSessionManager()
    sess = mgr._create_jwt_session({"type": "jwt", "token": "garbage"}, "s3")
    assert "well-formed" in sess.auth_error.lower()


# ── API key ──────────────────────────────────────────────────────────────────
def test_api_key_default_header():
    mgr = WebSessionManager()
    sess = mgr._create_api_key_session({"type": "api_key", "key": "SECRET"}, "s4")
    assert sess.auth_type == "api_key"
    assert sess.headers["X-API-Key"] == "SECRET"
    assert sess.is_authenticated


def test_api_key_custom_header_and_prefix():
    mgr = WebSessionManager()
    sess = mgr._create_api_key_session(
        {
            "type": "api_key",
            "value": "K",
            "header": "Authorization",
            "prefix": "ApiKey ",
        },
        "s5",
    )
    assert sess.headers["Authorization"] == "ApiKey K"


def test_api_key_missing_value_flagged():
    mgr = WebSessionManager()
    sess = mgr._create_api_key_session({"type": "api_key"}, "s6")
    assert sess.auth_error and not sess.is_authenticated


# ── browser redirect login (OAuth2 auth-code / OIDC / SAML) ──────────────────
def test_redirect_login_requires_start_url():
    import asyncio

    mgr = WebSessionManager()
    sess = asyncio.run(mgr._oauth2_authcode_browser({"type": "oidc"}, "s7"))
    assert not sess.is_authenticated
    assert "start_url" in sess.auth_error


def test_redirect_login_type_dispatches_to_browser_flow():
    import asyncio

    # No start_url → the browser flow's own error, proving oidc/saml route here
    # rather than to the unknown-type fallback (which gives no auth_error text).
    mgr = WebSessionManager()
    for t in ("oauth2_authcode", "oidc", "saml"):
        sess = asyncio.run(mgr.authenticate({"type": t}, "s-" + t))
        assert sess.auth_type == t
        assert "start_url" in sess.auth_error
