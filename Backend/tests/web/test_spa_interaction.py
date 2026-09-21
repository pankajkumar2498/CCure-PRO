"""
Phase 23 — autonomous SPA interaction safety + discovery (Codex Crawler 2.0).

_interact_page clicks safe, non-destructive controls to reach client-side routes
a link crawl never sees. These tests exercise the selection/safety logic with a
duck-typed fake page (no browser needed): a benign control that changes the
route is discovered; destructive-labelled and submit controls are never clicked.
Live browser + WebSocket behaviour is validated at runtime separately.
"""

import asyncio

from core.web.crawling.browser import PlaywrightCrawler


class _FakeEl:
    def __init__(
        self, page, text="", etype=None, new_url=None, *, in_form=False, form_attr=None
    ):
        self._page = page
        self._text = text
        self._etype = etype
        self._new_url = new_url
        self._in_form = in_form
        self._form_attr = form_attr
        self.clicked = False

    async def inner_text(self):
        return self._text

    async def get_attribute(self, name):
        if name == "type":
            return self._etype
        if name == "form":
            return self._form_attr
        return None

    async def evaluate(self, script):
        if "closest('form')" in script or 'closest("form")' in script:
            return self._in_form
        return None

    async def click(self, **kwargs):
        self.clicked = True
        if self._new_url:
            self._page._url = self._new_url


class _FakePage:
    def __init__(self):
        self._url = "http://t/"
        self.elements = []

    @property
    def url(self):
        return self._url

    async def query_selector_all(self, selector):
        return self.elements

    async def wait_for_timeout(self, ms):
        pass

    async def goto(self, url, **kwargs):
        self._url = url


def _run(coro):
    return asyncio.run(coro)


def test_safe_control_that_changes_route_is_discovered():
    page = _FakePage()
    safe = _FakeEl(page, text="Open dashboard", new_url="http://t/#/dashboard")
    page.elements = [safe]
    crawler = PlaywrightCrawler()
    found = _run(crawler._interact_page(page, "http://t/"))
    assert safe.clicked
    assert "http://t/#/dashboard" in found


def test_destructive_controls_are_never_clicked():
    page = _FakePage()
    for label in ("Delete account", "Log out", "Pay now", "Reset database"):
        page.elements.append(_FakeEl(page, text=label, new_url="http://t/#/boom"))
    crawler = PlaywrightCrawler()
    found = _run(crawler._interact_page(page, "http://t/"))
    assert found == []
    assert all(not e.clicked for e in page.elements)


def test_submit_controls_are_skipped():
    page = _FakePage()
    submit = _FakeEl(page, text="Search", etype="submit", new_url="http://t/#/x")
    page.elements = [submit]
    crawler = PlaywrightCrawler()
    found = _run(crawler._interact_page(page, "http://t/"))
    assert not submit.clicked and found == []


def test_default_buttons_inside_forms_are_skipped():
    page = _FakePage()
    default_submit = _FakeEl(
        page, text="Comment", new_url="http://t/#/posted", in_form=True
    )
    page.elements = [default_submit]
    crawler = PlaywrightCrawler()
    found = _run(crawler._interact_page(page, "http://t/"))
    assert not default_submit.clicked and found == []


def test_remote_form_controls_are_skipped():
    page = _FakePage()
    remote = _FakeEl(
        page, text="Save", new_url="http://t/#/saved", form_attr="profile-form"
    )
    page.elements = [remote]
    crawler = PlaywrightCrawler()
    found = _run(crawler._interact_page(page, "http://t/"))
    assert not remote.clicked and found == []


def test_clicks_are_bounded():
    from core.web.crawling.browser import _INTERACT_MAX

    page = _FakePage()
    # more benign controls than the cap; each would change the route
    page.elements = [
        _FakeEl(page, text=f"view {i}", new_url=f"http://t/#/r{i}")
        for i in range(_INTERACT_MAX + 5)
    ]
    crawler = PlaywrightCrawler()
    _run(crawler._interact_page(page, "http://t/"))
    assert sum(1 for e in page.elements if e.clicked) <= _INTERACT_MAX
