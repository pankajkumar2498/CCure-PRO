"""
Regression tests for the web crawler and DETECT target selection.

Each test here corresponds to a defect found by running the module against a
live deliberately-vulnerable application (OWASP Juice Shop). They are written
against the pure helpers so they run without a browser or a target.
"""

import asyncio

import pytest

from core.web.crawling.browser import PlaywrightCrawler
from orchestrator.web_orchestrator import (
    build_injection_targets,
    open_redirect_findings,
)


# ── URL normalisation: SPA routes ────────────────────────────────────────────


def test_route_fragment_is_preserved():
    """
    Hash routes identify distinct screens.

    Dropping the fragment collapsed every route of an Angular/React/Vue
    application onto the root URL, so the crawler visited the landing page and
    reported a single-page site.
    """
    assert (
        PlaywrightCrawler._normalize_url("http://app/#/login") == "http://app/#/login"
    )
    assert (
        PlaywrightCrawler._normalize_url("http://app/#/search?q=1")
        == "http://app/#/search?q=1"
    )


def test_anchor_fragment_is_dropped():
    """A plain anchor scrolls within a page that has already been crawled."""
    assert PlaywrightCrawler._normalize_url("http://app/docs#section-2") == (
        "http://app/docs"
    )


def test_query_string_is_preserved():
    assert (
        PlaywrightCrawler._normalize_url("http://app/search?q=a&p=2")
        == "http://app/search?q=a&p=2"
    )


def test_non_http_scheme_rejected():
    assert PlaywrightCrawler._normalize_url("javascript:alert(1)") is None
    assert PlaywrightCrawler._normalize_url("") is None


# ── Scope enforcement ────────────────────────────────────────────────────────


def test_other_host_is_out_of_scope():
    """
    An open redirect must not walk the crawler onto a third party — the scan
    is authorised for the target, not for wherever the target points.
    """
    assert not PlaywrightCrawler._is_in_scope("https://github.com/x", {"app:3000"}, [])
    assert PlaywrightCrawler._is_in_scope("http://app:3000/x", {"app:3000"}, [])


def test_exclude_pattern_removes_url():
    import re

    assert not PlaywrightCrawler._is_in_scope(
        "http://app/logout", {"app"}, [re.compile(r"/logout")]
    )


# ── JS endpoint extraction: false-positive suppression ───────────────────────


@pytest.mark.parametrize(
    "candidate",
    [
        "text/html",  # MIME type, not a path
        "application/json",
        "/path with spaces",
        "${base}/api",  # unresolved template placeholder
        "{{route}}",
        "data:image/png;base64,AAA",
        "#/login",  # client-side route, not a request path
        "",
    ],
)
def test_implausible_endpoints_rejected(candidate):
    """
    Each of these was previously stored as discovered attack surface and handed
    to nuclei and sqlmap to scan.
    """
    assert not PlaywrightCrawler._is_plausible_endpoint(candidate)


@pytest.mark.parametrize(
    "candidate",
    ["/api/users", "/rest/products/search?q=", "https://app/v1/orders"],
)
def test_real_endpoints_accepted(candidate):
    assert PlaywrightCrawler._is_plausible_endpoint(candidate)


def test_js_endpoints_stay_on_target_host():
    html = """<script>fetch("/rest/user/whoami");
              fetch("https://cdn.other.com/lib.js");
              var mime = "text/html";</script>"""
    found = PlaywrightCrawler._extract_js_endpoints(html, "http://app:3000/")
    urls = {e["url"] for e in found}
    assert "http://app:3000/rest/user/whoami" in urls
    assert not any("other.com" in u for u in urls)
    assert not any("text/html" in u for u in urls)


# ── Content fingerprinting (soft-404 detection) ──────────────────────────────


def test_fingerprint_ignores_whitespace_only_differences():
    a = PlaywrightCrawler._content_fingerprint("<html>  <body>x</body>\n</html>")
    b = PlaywrightCrawler._content_fingerprint("<html> <body>x</body> </html>")
    assert a == b


def test_fingerprint_differs_for_different_content():
    a = PlaywrightCrawler._content_fingerprint("<html>page one</html>")
    b = PlaywrightCrawler._content_fingerprint("<html>page two</html>")
    assert a != b


# ── Passive embedded surface discovery ───────────────────────────────────────


class _LinkEl:
    def __init__(self, **attrs):
        self.attrs = attrs

    async def get_attribute(self, name):
        return self.attrs.get(name)


class _LinkPage:
    def __init__(self):
        self.by_selector = {}

    async def query_selector_all(self, selector):
        return self.by_selector.get(selector, [])


def _run(coro):
    return asyncio.run(coro)


def test_extract_links_includes_iframe_sources():
    page = _LinkPage()
    page.by_selector = {
        "a[href]": [_LinkEl(href="/linked")],
        "iframe[src], frame[src]": [
            _LinkEl(src="/embedded"),
            _LinkEl(src="about:blank"),
            _LinkEl(src="javascript:alert(1)"),
        ],
    }
    links = set(_run(PlaywrightCrawler._extract_links(page, "http://app/root")))
    assert "http://app/linked" in links
    assert "http://app/embedded" in links
    assert not any(x.startswith("about:") or x.startswith("javascript:") for x in links)


# ── Injection target selection ───────────────────────────────────────────────


def test_query_string_endpoint_is_injectable():
    targets = build_injection_targets([{"url": "http://app/search?q=1"}], [])
    # A target also carries coverage_params: the exact discovered parameter
    # context that downstream engines should mark when they actually run.
    assert targets == [
        {
            "url": "http://app/search?q=1",
            "method": "GET",
            "data": None,
            "content_type": None,
            "coverage_params": [
                {"url": "http://app/search?q=1", "location": "query", "param": "q"}
            ],
        }
    ]


def test_endpoint_without_parameters_is_skipped():
    assert build_injection_targets([{"url": "http://app/about"}], []) == []


def test_client_side_route_is_not_an_injection_target():
    """A fragment never reaches the server, so there is nothing to inject."""
    assert build_injection_targets([{"url": "http://app/#/login?q=1"}], []) == []


def test_post_form_becomes_a_body_bearing_target():
    """
    Forms were collected by the crawl and never tested. A POST target with no
    body probes no parameter at all and always reports clean.
    """
    forms = [
        {
            "url": "http://app/rest/user/login",
            "method": "POST",
            "inputs": [
                {"name": "email", "type": "text"},
                {"name": "password", "type": "password"},
                {"name": "go", "type": "submit"},
                {"name": "csrf", "type": "hidden"},
            ],
        }
    ]
    targets = build_injection_targets([], forms)
    assert len(targets) == 1
    assert targets[0]["method"] == "POST"
    # Submit buttons and hidden CSRF tokens are not injectable parameters.
    assert targets[0]["data"] == "email=1&password=1"


def test_get_form_becomes_a_query_string():
    forms = [
        {
            "url": "http://app/search",
            "method": "GET",
            "inputs": [{"name": "q", "type": "text"}],
        }
    ]
    targets = build_injection_targets([], forms)
    assert targets[0]["url"] == "http://app/search?q=1"
    assert targets[0]["method"] == "GET"


def test_form_without_named_fields_is_skipped():
    forms = [{"url": "http://app/x", "method": "POST", "inputs": [{"name": ""}]}]
    assert build_injection_targets([], forms) == []


def test_duplicate_targets_collapse():
    eps = [{"url": "http://app/s?q=1"}, {"url": "http://app/s?q=1"}]
    assert len(build_injection_targets(eps, [])) == 1


# ── Open redirect reporting ──────────────────────────────────────────────────


def test_scope_departure_becomes_a_finding():
    findings = open_redirect_findings(
        [{"from": "http://app/redirect?to=x", "to": "https://evil.example/"}],
        "http://app",
    )
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "open_redirect"
    assert findings[0]["matched_at"] == "http://app/redirect?to=x"
    assert "evil.example" in findings[0]["payload_used"]


def test_repeat_departures_to_one_host_report_once():
    findings = open_redirect_findings(
        [
            {"from": "http://app/a?to=x", "to": "https://evil.example/1"},
            {"from": "http://app/b?to=y", "to": "https://evil.example/2"},
        ],
        "http://app",
    )
    assert len(findings) == 1


def test_no_departures_no_findings():
    assert open_redirect_findings([], "http://app") == []
