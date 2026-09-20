"""
Phase 23c — auth-aware Nuclei (Codex P2 item 13).

Nuclei already used an auth-header target file, template coverage records,
partial-timeout tracking, an exclusion policy and dedup. The remaining gap: a
cookie-session scan ran Nuclei anonymously because the session cookies were not
folded into a Cookie header. These pin that fold.
"""

from core.web.nuclei.wrapper import auth_headers_with_cookies


def test_cookies_folded_into_cookie_header():
    merged = auth_headers_with_cookies(
        {"Authorization": "Bearer t"}, {"session": "abc", "csrf": "x"}
    )
    assert merged["Authorization"] == "Bearer t"
    assert merged["Cookie"] == "session=abc; csrf=x"


def test_existing_cookie_header_not_overwritten():
    merged = auth_headers_with_cookies({"Cookie": "explicit=1"}, {"session": "abc"})
    assert merged["Cookie"] == "explicit=1"


def test_no_cookies_leaves_headers_unchanged():
    assert auth_headers_with_cookies({"X-A": "1"}, None) == {"X-A": "1"}
    assert auth_headers_with_cookies(None, {}) == {}
