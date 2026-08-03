"""
Regression tests for web-scan authentication and credential-at-rest handling.

These cover defects found running the module against a live JSON-API target
(OWASP Juice Shop): a login that returns a bearer token and no cookie, a 200
that is actually a rejected login, cookies with no domain, and credentials
persisted in plain text.
"""

import pytest

from core.web.auth.secrets import (
    decrypt_auth_config,
    encrypt_auth_config,
    redact_auth_config,
)
from core.web.auth.session_manager import WebSession


# ── Credential encryption at rest ────────────────────────────────────────────


def test_password_and_token_are_encrypted():
    cfg = {"type": "form_login", "username": "u", "password": "p", "token": "t"}
    enc = encrypt_auth_config(cfg)
    assert enc["password"].startswith("enc:v1:")
    assert enc["token"].startswith("enc:v1:")
    # Non-secret fields are untouched.
    assert enc["username"] == "u"
    assert enc["type"] == "form_login"


def test_encryption_round_trips():
    cfg = {"password": "s3cret!", "cookies": {"sid": "abc"}, "headers": {"X": "y"}}
    assert decrypt_auth_config(encrypt_auth_config(cfg)) == cfg


def test_double_encryption_is_a_noop():
    cfg = {"password": "p"}
    once = encrypt_auth_config(cfg)
    twice = encrypt_auth_config(once)
    assert once == twice
    assert decrypt_auth_config(twice) == cfg


def test_legacy_plaintext_config_still_decrypts():
    """Rows written before encryption existed have no prefix and must survive."""
    plain = {"password": "old-plaintext", "token": "legacy"}
    assert decrypt_auth_config(plain) == plain


def test_redaction_hides_every_secret():
    cfg = {"password": "p", "token": "t", "cookies": {"sid": "s"}, "username": "u"}
    red = redact_auth_config(cfg)
    assert red["password"] == "********"
    assert red["token"] == "********"
    assert red["cookies"]["sid"] == "********"
    assert red["username"] == "u"


# ── Token extraction from a login response ───────────────────────────────────


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def test_token_extracted_by_explicit_path():
    resp = _FakeResponse({"authentication": {"token": "abc.def.ghi"}})
    assert WebSession is not None  # import guard
    from core.web.auth.session_manager import WebSessionManager

    assert (
        WebSessionManager._extract_token(resp, "authentication.token") == "abc.def.ghi"
    )


def test_token_auto_detected_without_path():
    from core.web.auth.session_manager import WebSessionManager

    resp = _FakeResponse({"data": {"access_token": "xyztokenvalue"}})
    assert WebSessionManager._extract_token(resp) == "xyztokenvalue"


def test_no_token_returns_none():
    from core.web.auth.session_manager import WebSessionManager

    resp = _FakeResponse({"message": "ok"})
    assert WebSessionManager._extract_token(resp) is None


# ── Session authentication state ─────────────────────────────────────────────


def test_token_only_session_is_authenticated():
    """
    A JSON-API login yields a bearer token and no cookie. Requiring a cookie
    reported this session as anonymous and every protected page went untested.
    """
    s = WebSession(scan_id="x", headers={"Authorization": "Bearer t"})
    assert s.is_authenticated
    assert s.get_auth_headers()["Authorization"] == "Bearer t"


def test_error_session_is_not_authenticated():
    s = WebSession(scan_id="x", headers={"Authorization": "Bearer t"}, auth_error="bad")
    assert not s.is_authenticated


def test_empty_session_is_not_authenticated():
    assert not WebSession(scan_id="x").is_authenticated


# ── Playwright cookie formatting ─────────────────────────────────────────────


def test_cookies_scoped_by_url_not_bare_domain():
    """
    Playwright rejects a whole add_cookies batch if any cookie lacks a domain.
    Non-form_login sessions had no login_url, so this aborted the auth crawl.
    """
    s = WebSession(scan_id="x", cookies={"sid": "abc"})
    pw = s.get_cookies_for_playwright("http://app:3000/")
    assert pw == [{"name": "sid", "value": "abc", "url": "http://app:3000"}]


def test_cookies_prefer_login_url_origin():
    s = WebSession(scan_id="x", cookies={"sid": "abc"}, login_url="https://site/login")
    pw = s.get_cookies_for_playwright("http://other/")
    assert pw[0]["url"] == "https://site"


def test_cookies_without_any_origin_are_dropped_not_crashed():
    s = WebSession(scan_id="x", cookies={"sid": "abc"})
    assert s.get_cookies_for_playwright("") == []
