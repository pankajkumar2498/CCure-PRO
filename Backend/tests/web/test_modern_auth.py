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


# ── Phase 23b: redirect-login edge cases (TOTP / MFA-code / consent wiring) ───
def test_totp_matches_pyotp_style_reference():
    """TOTP is RFC 6238 SHA-1; check a known vector for a fixed time."""
    import core.web.auth.session_manager as sm

    # RFC 6238 test secret "12345678901234567890" -> base32 GEZDGNBVGY3TQOJQ...
    secret = base64.b32encode(b"12345678901234567890").decode()
    orig = sm.time.time
    try:
        sm.time.time = lambda: 59.0  # RFC 6238 T=59s, counter 1
        code = sm._totp_now(secret, digits=8)
    finally:
        sm.time.time = orig
    assert code == "94287082"  # RFC 6238 Appendix B, SHA-1, T=59


def test_resolve_mfa_code_prefers_static_then_totp():
    mgr = WebSessionManager()
    assert mgr._resolve_mfa_code({"mfa_code": "123456"}) == "123456"
    secret = base64.b32encode(b"12345678901234567890").decode()
    got = mgr._resolve_mfa_code({"totp_secret": secret})
    assert got.isdigit() and len(got) == 6
    assert mgr._resolve_mfa_code({}) == ""


def test_redirect_edge_case_fields_encrypt_and_survive_roundtrip():
    """The new secret (totp_secret) is encrypted at rest; selectors are not."""
    from core.web.auth.secrets import (
        decrypt_auth_config,
        encrypt_auth_config,
        redact_auth_config,
    )

    cfg = {
        "type": "oidc",
        "start_url": "https://app.test/login",
        "idp_next_submit": "#next",
        "idp_mfa_field": "#otp",
        "idp_consent_submit": "#allow",
        "totp_secret": "JBSWY3DPEHPK3PXP",
        "password": "s3cr3t",
    }
    enc = encrypt_auth_config(cfg)
    assert enc["totp_secret"].startswith("enc:v1:")
    assert enc["password"].startswith("enc:v1:")
    assert enc["idp_next_submit"] == "#next"  # selectors are not secrets
    dec = decrypt_auth_config(enc)
    assert dec["totp_secret"] == "JBSWY3DPEHPK3PXP"
    assert dec["idp_mfa_field"] == "#otp"
    red = redact_auth_config(enc)
    assert red["totp_secret"] == "********"


def test_modern_token_secrets_now_encrypted():
    """jwt / key / value / client_secret gained encryption in Phase 23b."""
    from core.web.auth.secrets import decrypt_auth_config, encrypt_auth_config

    cfg = {
        "type": "oauth2",
        "jwt": "a.b.c",
        "key": "api-key-123",
        "value": "val-456",
        "client_secret": "cs-789",
    }
    enc = encrypt_auth_config(cfg)
    for k in ("jwt", "key", "value", "client_secret"):
        assert enc[k].startswith("enc:v1:"), k
    assert decrypt_auth_config(enc) == cfg


# ── Phase 23c: recorded login sequence (Codex item 6) ─────────────────────────
def test_recorded_steps_values_encrypted_at_rest():
    from core.web.auth.secrets import (
        decrypt_auth_config,
        encrypt_auth_config,
        redact_auth_config,
    )

    cfg = {
        "type": "recorded",
        "recorded_steps": [
            {"action": "goto", "url": "https://app.test/login"},
            {"action": "fill", "selector": "#user", "value": "alice"},
            {"action": "fill", "selector": "#pass", "value": "s3cr3t"},
            {"action": "click", "selector": "#submit"},
        ],
    }
    enc = encrypt_auth_config(cfg)
    # every step value is protected (a password typed into a field)
    vals = [s.get("value") for s in enc["recorded_steps"] if "value" in s]
    assert all(v.startswith("enc:v1:") for v in vals)
    dec = decrypt_auth_config(enc)
    assert [s.get("value") for s in dec["recorded_steps"] if "value" in s] == [
        "alice",
        "s3cr3t",
    ]
    # non-value fields untouched
    assert dec["recorded_steps"][0]["url"] == "https://app.test/login"
    red = redact_auth_config(enc)
    assert all(
        s.get("value") == "********" for s in red["recorded_steps"] if "value" in s
    )


def test_recorded_login_empty_steps_errors():
    import asyncio

    mgr = WebSessionManager()
    sess = asyncio.run(
        mgr._recorded_login({"type": "recorded", "recorded_steps": []}, "s1")
    )
    assert sess.auth_type == "recorded"
    assert sess.auth_error and "recorded_steps" in sess.auth_error


def test_play_step_dispatches_actions():
    """The step player calls the right Playwright method per action."""
    import asyncio

    calls = []

    class _Page:
        async def goto(self, url, **k):
            calls.append(("goto", url))

        async def fill(self, sel, val, **k):
            calls.append(("fill", sel, val))

        async def click(self, sel, **k):
            calls.append(("click", sel))

        async def wait_for_load_state(self, *a, **k):
            pass

        async def select_option(self, sel, val, **k):
            calls.append(("select", sel, val))

        async def press(self, sel, val, **k):
            calls.append(("press", sel, val))

        async def wait_for_timeout(self, ms):
            calls.append(("wait", ms))

        async def wait_for_selector(self, sel, **k):
            calls.append(("wait_for", sel))

    page = _Page()
    steps = [
        {"action": "goto", "url": "https://a/login"},
        {"action": "fill", "selector": "#u", "value": "x"},
        {"action": "click", "selector": "#go"},
        {"action": "press", "selector": "#u", "value": "Enter"},
        {"action": "wait", "timeout": 100},
    ]
    for s in steps:
        asyncio.run(WebSessionManager._play_step(page, s))
    kinds = [c[0] for c in calls]
    assert kinds == ["goto", "fill", "click", "press", "wait"]
