"""
Phase 11 — crawler performance (bounded concurrency) and adaptive ffuf.

Pure logic (frontier ordering, ffuf tier selection, the curated wordlist, the
word-cap) runs everywhere. The concurrency correctness tests drive the real
Playwright crawler against a controlled multi-page app and are skipped cleanly
where a browser is not available. They assert the properties that matter:
concurrency must not change *what* is found (deterministic, no duplicates,
scope preserved), must honour cancellation, and must actually be faster.
"""

import asyncio
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from core.web.crawling.browser import PlaywrightCrawler
from core.web.ffuf.wrapper import FfufWrapper


# ── frontier ordering (pure) ─────────────────────────────────────────────────
def test_order_frontier_dedups_and_sorts():
    items = [
        ("http://t/b", 2),
        ("http://t/a", 1),
        ("http://t/b", 1),  # shallower depth for b wins
        ("http://t/a", 1),  # duplicate
    ]
    ordered = PlaywrightCrawler._order_frontier(items)
    assert ordered == [("http://t/a", 1), ("http://t/b", 1)]


def test_order_frontier_is_deterministic():
    import random

    items = [(f"http://t/p{i}", i % 3) for i in range(50)]
    shuffled = items[:]
    random.shuffle(shuffled)
    assert PlaywrightCrawler._order_frontier(
        items
    ) == PlaywrightCrawler._order_frontier(shuffled)


# ── ffuf adaptive tiers (pure) ───────────────────────────────────────────────
def test_ffuf_tier_thresholds():
    from config import WebScanConfig

    small = WebScanConfig.FFUF_SMALL_MAX_ENDPOINTS
    med = WebScanConfig.FFUF_MEDIUM_MAX_ENDPOINTS
    assert FfufWrapper.resolve_tier(0) == "small"
    assert FfufWrapper.resolve_tier(small) == "small"
    assert FfufWrapper.resolve_tier(small + 1) == "standard"
    assert FfufWrapper.resolve_tier(med) == "standard"
    assert FfufWrapper.resolve_tier(med + 1) == "deep"
    assert FfufWrapper.resolve_tier(10_000) == "deep"


def test_ffuf_wordlist_for_tier():
    from config import WebScanConfig

    wl_s, _ = FfufWrapper.wordlist_for_tier("small")
    assert wl_s == WebScanConfig.FFUF_WORDLIST_SMALL
    wl_std, _ = FfufWrapper.wordlist_for_tier("standard")
    assert wl_std == WebScanConfig.FFUF_WORDLIST
    wl_deep, _ = FfufWrapper.wordlist_for_tier("deep")
    assert wl_deep in (WebScanConfig.FFUF_WORDLIST_DEEP or WebScanConfig.FFUF_WORDLIST,)


def test_small_wordlist_exists_and_covers_sensitive_paths():
    import os

    from config import WebScanConfig
    from core.web.ffuf.wrapper import _SENSITIVE_PATHS

    path = WebScanConfig.FFUF_WORDLIST_SMALL
    assert os.path.isfile(path), f"curated small wordlist missing: {path}"
    with open(path) as fh:
        entries = {ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")}
    # The reduction must not drop the high-value checks: every sensitive path
    # the wrapper flags must be reachable by the small tier.
    missing = {p for p in _SENSITIVE_PATHS if p not in entries}
    assert not missing, f"small wordlist misses sensitive paths: {sorted(missing)}"


# ── ffuf word-cap truncation (fake subprocess) ───────────────────────────────
class _FakeCompleted:
    def __init__(self):
        self.returncode = 0
        self.stdout = ""
        self.stderr = ""


def test_ffuf_max_words_truncates(monkeypatch, tmp_path):
    wl = tmp_path / "big.txt"
    wl.write_text("\n".join(f"p{i}" for i in range(1000)) + "\n")

    captured = {}

    monkeypatch.setattr(FfufWrapper, "require_available", lambda self: None)
    monkeypatch.setattr(FfufWrapper, "is_available", lambda self: True)

    def fake_run(self, args, timeout=None, **kw):
        # find -w and -o
        wlpath = args[args.index("-w") + 1]
        with open(wlpath) as fh:
            captured["wordcount"] = sum(1 for _ in fh)
        out = args[args.index("-o") + 1]
        with open(out, "w") as fh:
            fh.write('{"results": []}')
        return _FakeCompleted()

    monkeypatch.setattr(FfufWrapper, "_run_subprocess", fake_run)
    ff = FfufWrapper()
    res = ff.run(target="http://t/", wordlist=str(wl), max_words=50, tier="small")
    assert captured["wordcount"] == 50  # truncated
    assert res["stats"]["tier"] == "small"
    assert res["stats"]["words"] == 50


# ── real-crawler concurrency correctness (browser-gated) ─────────────────────
def _browser_ok():
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            b = p.chromium.launch(headless=True, args=["--no-sandbox"])
            b.close()
        return True
    except Exception:
        return False


_BROWSER = _browser_ok()
browser_required = pytest.mark.skipif(not _BROWSER, reason="no launchable browser")


def _make_app(n_pages, counter, delay=0.0, external=False):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            counter["n"] += 1
            if delay:
                time.sleep(delay)
            path = self.path.split("?")[0]
            if path == "/":
                links = "".join(f'<a href="/page/{i}">p{i}</a>' for i in range(n_pages))
                if external:
                    links += '<a href="http://evil.example.test/x">ext</a>'
                body = f"<html><body>home{links}</body></html>"
            elif path.startswith("/page/"):
                body = f"<html><body>c {path}<a href='/'>h</a></body></html>"
            else:
                body = "<html><body>x</body></html>"
            b = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    return H


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _run(coro):
    return asyncio.run(coro)


@browser_required
def test_concurrency_finds_same_endpoints_as_sequential():
    counter = {"n": 0}
    srv, base = _serve(_make_app(12, counter))
    try:
        seq = PlaywrightCrawler(
            max_depth=3, max_urls=100, concurrency=1, rate_limit=200
        )
        con = PlaywrightCrawler(
            max_depth=3, max_urls=100, concurrency=6, rate_limit=200
        )
        r1 = _run(seq.crawl(start_url=base + "/"))
        r5 = _run(con.crawl(start_url=base + "/"))
        set1 = {e["url"] for e in r1.endpoints}
        set5 = {e["url"] for e in r5.endpoints}
        assert set1 == set5  # concurrency does not change what is found
        assert len(set5) == 13  # home + 12 pages
        # No duplicate crawling: one visit per unique page.
        assert r5.pages_visited == 13
    finally:
        srv.shutdown()
        srv.server_close()


@browser_required
def test_concurrency_is_faster_on_a_slow_target():
    c1 = {"n": 0}
    c5 = {"n": 0}
    srv1, base1 = _serve(_make_app(16, c1, delay=0.12))
    srv2, base2 = _serve(_make_app(16, c5, delay=0.12))
    try:
        seq = PlaywrightCrawler(
            max_depth=2, max_urls=100, concurrency=1, rate_limit=200
        )
        con = PlaywrightCrawler(
            max_depth=2, max_urls=100, concurrency=8, rate_limit=200
        )
        t0 = time.monotonic()
        _run(seq.crawl(start_url=base1 + "/"))
        d1 = time.monotonic() - t0
        t0 = time.monotonic()
        _run(con.crawl(start_url=base2 + "/"))
        d5 = time.monotonic() - t0
        assert d5 < d1, f"concurrent ({d5:.2f}s) not faster than sequential ({d1:.2f}s)"
    finally:
        srv1.shutdown()
        srv1.server_close()
        srv2.shutdown()
        srv2.server_close()


@browser_required
def test_cancellation_stops_the_crawl_early():
    counter = {"n": 0}
    srv, base = _serve(_make_app(60, counter, delay=0.05))
    try:
        crawler = PlaywrightCrawler(
            max_depth=3, max_urls=200, concurrency=3, rate_limit=200
        )
        # Cancel after the first wave.
        state = {"calls": 0}

        def _cancel():
            state["calls"] += 1
            return state["calls"] > 1  # allow the home wave, then cancel

        res = _run(crawler.crawl(start_url=base + "/", cancel_cb=_cancel))
        # It must stop well short of the full 61 pages.
        assert res.pages_visited < 61
    finally:
        srv.shutdown()
        srv.server_close()


@browser_required
def test_scope_preserved_under_concurrency():
    counter = {"n": 0}
    srv, base = _serve(_make_app(8, counter, external=True))
    try:
        crawler = PlaywrightCrawler(
            max_depth=3, max_urls=100, concurrency=5, rate_limit=200
        )
        res = _run(crawler.crawl(start_url=base + "/"))
        for e in res.endpoints:
            assert "evil.example.test" not in e["url"]  # never left scope
    finally:
        srv.shutdown()
        srv.server_close()
