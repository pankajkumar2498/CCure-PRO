"""
tests/test_cors_and_headers.py
─────────────────────────────────────────────────────────────────────────────
CORS origin policy and response security headers.

The defect these guard against: `allow_origin_regex="https?://.*"` was passed to
CORSMiddleware alongside the explicit allow-list. It matches every origin on the
web, so an OPTIONS preflight carrying `Origin: https://evil.example.com` came
back with that origin echoed in `Access-Control-Allow-Origin` and
`Access-Control-Allow-Credentials: true` — the browser was being told any site
the victim visits may send their cookies here and read the reply. The
CORS_ALLOW_ORIGINS list was decoration.

A separate bypass sat in the Private Network Access preflight branch, which
answers before CORSMiddleware runs and reflected `Origin` verbatim.
"""

import pytest
from fastapi.testclient import TestClient

HOSTILE = "https://evil.example.com"


def _allowed_origin() -> str:
    from main import allow_origins

    assert allow_origins, "the deployment must configure at least one origin"
    return allow_origins[0]


# ── Origin policy ─────────────────────────────────────────────────────────────


def test_preflight_from_hostile_origin_is_not_approved(client: TestClient):
    res = client.options(
        "/auth/login",
        headers={
            "Origin": HOSTILE,
            "Access-Control-Request-Method": "POST",
        },
    )
    # Starlette answers a disallowed preflight with 400 and no ACAO header.
    # Either way, what must never happen is the origin being echoed back.
    assert res.headers.get("access-control-allow-origin") != HOSTILE


def test_preflight_from_configured_origin_is_approved(client: TestClient):
    origin = _allowed_origin()
    res = client.options(
        "/auth/login",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
        },
    )
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == origin
    assert res.headers.get("access-control-allow-credentials") == "true"


def test_actual_request_from_hostile_origin_gets_no_cors_grant(client: TestClient):
    """
    Without ACAO on the real response the browser refuses to hand the body to
    the calling page, even though the request itself was served.
    """
    res = client.post(
        "/auth/login",
        headers={"Origin": HOSTILE},
        json={"email": "nobody@nowhere.test", "password": "x"},
    )
    assert res.headers.get("access-control-allow-origin") != HOSTILE


def test_no_wildcard_origin_regex_is_configured():
    """
    The regex is the defect itself, so assert on the configuration rather than
    only on behaviour: a future edit could reintroduce it in a form the
    behavioural tests above happen to miss.
    """
    from starlette.middleware.cors import CORSMiddleware

    import main

    cors = [m for m in main.app.user_middleware if m.cls is CORSMiddleware]
    assert cors, "CORSMiddleware must be installed"
    for m in cors:
        regex = m.kwargs.get("allow_origin_regex")
        assert regex is None, f"allow_origin_regex must not be set (got {regex!r})"
        assert "*" not in m.kwargs.get("allow_origins", []), (
            "a wildcard origin with allow_credentials=True is rejected by "
            "browsers and signals the policy was never intended"
        )


# ── Private Network Access preflight ──────────────────────────────────────────


def test_pna_preflight_from_hostile_origin_is_refused(client: TestClient):
    res = client.options(
        "/auth/login",
        headers={
            "Origin": HOSTILE,
            "Access-Control-Request-Private-Network": "true",
        },
    )
    assert res.status_code == 403
    assert res.headers.get("access-control-allow-origin") != HOSTILE


def test_pna_preflight_from_configured_origin_is_allowed(client: TestClient):
    origin = _allowed_origin()
    res = client.options(
        "/auth/login",
        headers={
            "Origin": origin,
            "Access-Control-Request-Private-Network": "true",
        },
    )
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-private-network") == "true"
    assert res.headers.get("access-control-allow-origin") == origin


# ── Response security headers ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "header,expected",
    [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("cross-origin-resource-policy", "same-site"),
    ],
)
def test_security_headers_present_on_api_responses(
    client: TestClient, header, expected
):
    res = client.get("/auth/me")
    assert res.headers.get(header) == expected


def test_api_csp_forbids_loading_anything(client: TestClient):
    """
    An API returns JSON and files; it never needs to load a resource. 'none'
    means a response that does end up rendered as a document cannot fetch,
    frame, or execute anything.
    """
    res = client.get("/auth/me")
    csp = res.headers.get("content-security-policy", "")
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp


def test_security_headers_present_on_error_responses(client: TestClient):
    """A 401 is still a response the browser may render; it needs the headers too."""
    res = client.get("/auth/me")
    assert res.status_code in (401, 403)
    assert res.headers.get("x-content-type-options") == "nosniff"


def test_hsts_is_not_claimed_over_plain_http(client: TestClient):
    """
    HSTS must not appear on a plain-HTTP response.

    A browser ignores it there, so an unconditional header would be decoration
    that makes a header dump look protected when it is not. The API is also
    still directly reachable on 127.0.0.1:8000 without TLS for local tooling,
    and that listener has no certificate to back the claim up.

    The proto is forced with a header rather than by using an http base_url: the
    session client is https so that Secure cookies work (see conftest), and
    X-Forwarded-Proto is in any case the signal that decides this in production,
    where the app itself always speaks plain HTTP to Nginx.
    """
    res = client.get("/auth/me", headers={"X-Forwarded-Proto": "http"})
    assert "strict-transport-security" not in {k.lower() for k in res.headers.keys()}


def test_hsts_is_sent_when_the_request_arrived_over_tls(client: TestClient):
    """
    Host Nginx terminates TLS and forwards X-Forwarded-Proto: https, which is
    the only signal the app has that the client's hop was encrypted.
    """
    res = client.get("/auth/me", headers={"X-Forwarded-Proto": "https"})
    assert res.headers.get("strict-transport-security") == "max-age=300"


def test_hsts_reads_only_the_first_forwarded_proto(client: TestClient):
    """
    X-Forwarded-Proto accumulates left-to-right through proxies. Taking the
    whole string would fail to match "https" and silently drop the header; the
    nearest-client hop is the first entry.
    """
    res = client.get("/auth/me", headers={"X-Forwarded-Proto": "https, http"})
    assert res.headers.get("strict-transport-security") == "max-age=300"


def test_hsts_max_age_is_short_during_rollout(client: TestClient):
    """
    HSTS is a one-way door: a client that cached HTTPS-only for a year cannot
    reach a broken deployment to be told why. This asserts the deliberate
    low value so raising it becomes a conscious edit, in both Nginx and here.
    """
    res = client.get("/auth/me", headers={"X-Forwarded-Proto": "https"})
    max_age = int(res.headers["strict-transport-security"].split("=")[1])
    assert max_age <= 3600, (
        "raise Nginx's add_header Strict-Transport-Security and _HSTS_VALUE "
        "together, and only after every client is confirmed working"
    )
