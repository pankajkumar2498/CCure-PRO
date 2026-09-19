"""
core/web/crawling/browser.py
────────────────────────────────────────────────────────────────────────────
Playwright-based headless browser crawler for web application scanning.

This crawler handles:
  - SPA navigation (React, Angular, Vue) via JavaScript rendering
  - Form discovery (login forms, search forms, file upload forms)
  - API endpoint extraction from inline JavaScript
  - Link extraction from anchors, JS navigation, and network requests
  - Cookie/session management for authenticated crawling
  - DOM XSS detection via safe payload injection
  - Scope enforcement (stay within target domain/path)
"""

import asyncio
import hashlib
import logging
import re
import time
import uuid
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from config import WebScanConfig

log = logging.getLogger("ccure.web.crawler")

# Regex patterns for extracting API endpoints from JavaScript
_JS_ENDPOINT_PATTERNS = [
    re.compile(r"""(?:fetch|axios|XMLHttpRequest)\s*\(\s*['"`]([^'"`]+)['"`]"""),
    re.compile(
        r"""(?:url|endpoint|api|path)\s*[:=]\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE
    ),
    re.compile(r"""(?:GET|POST|PUT|DELETE|PATCH)\s*['"`]\s*([/][^'"`\s]+)"""),
]

# Autonomous SPA interaction (Phase 23): controls whose label suggests a
# destructive or state-changing action are never clicked — this product scans
# production, so an autonomous crawl must not delete, pay, or log itself out.
_DESTRUCTIVE_WORDS = (
    "delete",
    "remove",
    "destroy",
    "drop",
    "logout",
    "log out",
    "sign out",
    "signout",
    "pay",
    "buy",
    "purchase",
    "checkout",
    "confirm",
    "submit order",
    "unsubscribe",
    "deactivate",
    "close account",
    "reset",
    "wipe",
)
#: Max controls clicked per page during autonomous interaction.
_INTERACT_MAX = 8

# File extensions to skip during crawling
_SKIP_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".bmp",
    ".mp3",
    ".mp4",
    ".wav",
    ".avi",
    ".mov",
    ".webm",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".zip",
    ".tar",
    ".gz",
    ".rar",
    ".7z",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".css",
    ".map",
}


class CrawlResult:
    """Result of a crawling session."""

    def __init__(self):
        self.endpoints: list[dict] = []
        self.forms: list[dict] = []
        self.js_endpoints: list[dict] = []
        #: Static DOM source→sink findings from JS bundle analysis (Phase 22).
        self.js_findings: list[dict] = []
        self.technologies: list[dict] = []
        self.cookies: list[dict] = []
        self.errors: list[str] = []
        self.pages_visited: int = 0
        self.api_specs: list[dict] = []
        #: Navigations that left the authorised scope and were abandoned.
        #: Recorded rather than merely dropped: an open redirect that sends the
        #: crawler to a third party is itself a finding about the target.
        self.out_of_scope: list[dict] = []
        #: URLs the application answered with its not-found page.
        self.soft_404s: list[str] = []
        #: Session-loss / re-authentication events observed during the crawl,
        #: so the report can say the authenticated session dropped and whether
        #: it was recovered — otherwise a mid-crawl logout silently turns the
        #: rest of the crawl anonymous.
        self.auth_events: list[dict] = []
        #: Directed graph of DOM states and the interactions connecting them,
        #: built from the autonomous interaction pass (Phase 23b). Empty unless
        #: interaction is enabled. Serialised into scans.options for the report.
        self.dom_graph: dict = {}

    def to_dict(self) -> dict:
        return {
            "endpoints": self.endpoints,
            "forms": self.forms,
            "js_endpoints": self.js_endpoints,
            "technologies": self.technologies,
            "cookies": self.cookies,
            "errors": self.errors,
            "pages_visited": self.pages_visited,
            "api_specs": self.api_specs,
            "out_of_scope": self.out_of_scope,
            "soft_404s": self.soft_404s,
            "dom_graph": self.dom_graph,
        }


class PlaywrightCrawler:
    """
    Headless browser crawler using Playwright.

    Handles JavaScript-rendered content, SPAs, and authenticated sessions.

    Usage:
        crawler = PlaywrightCrawler(
            max_depth=5,
            max_urls=500,
            timeout=30000,
        )
        result = await crawler.crawl(
            start_url="https://example.com",
            auth_cookies=[{"name": "session", "value": "abc", "domain": "example.com"}],
        )
    """

    def __init__(
        self,
        max_depth: int | None = None,
        max_urls: int | None = None,
        timeout: int | None = None,
        concurrency: int | None = None,
        settle_timeout: int | None = None,
        rate_limit: int | None = None,
    ):
        self.max_depth = max_depth or WebScanConfig.MAX_CRAWL_DEPTH
        self.max_urls = max_urls or WebScanConfig.MAX_CRAWL_URLS
        self.timeout = timeout or WebScanConfig.PLAYWRIGHT_TIMEOUT
        self.concurrency = concurrency or WebScanConfig.CRAWL_CONCURRENCY
        #: Shared navigation-start rate ceiling across all concurrent workers.
        self.rate_limit = rate_limit or WebScanConfig.CRAWL_RATE_LIMIT
        #: How long to wait for a page to go quiet after the document loads,
        #: bounded so a page that never goes quiet cannot stall the crawl.
        self.settle_timeout = settle_timeout or WebScanConfig.CRAWL_SETTLE_TIMEOUT

    async def crawl(
        self,
        start_url: str,
        auth_cookies: list[dict] | None = None,
        auth_headers: dict[str, str] | None = None,
        scope_patterns: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
        progress_cb=None,
        auth_config: dict | None = None,
        reauth_cb=None,
        cancel_cb=None,
        interact: bool = False,
    ) -> CrawlResult:
        """
        Crawl a web application starting from start_url.

        Args:
            start_url: Starting URL for crawling
            auth_cookies: Cookies for authenticated crawling
            auth_headers: Headers for authenticated crawling
            scope_patterns: URL patterns to stay within
            exclude_patterns: URL patterns to skip
            progress_cb: optional callable(pages_visited, endpoints_found) invoked
                periodically so a caller can surface live crawl progress. Best
                effort — any exception it raises is swallowed.

        Returns:
            CrawlResult with discovered endpoints, forms, and JS endpoints
        """
        result = CrawlResult()
        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc

        # DOM state graph (Phase 23b): records the interaction transitions the
        # autonomous pass discovers. One graph per crawl, attached to the result.
        from core.web.dom_graph import DomStateGraph

        dom_graph = DomStateGraph()

        # Scope enforcement
        allowed_domains = {base_domain}
        if scope_patterns:
            for pattern in scope_patterns:
                parsed = urlparse(pattern)
                if parsed.netloc:
                    allowed_domains.add(parsed.netloc)

        exclude_compiled = []
        if exclude_patterns:
            for pattern in exclude_patterns:
                try:
                    exclude_compiled.append(re.compile(pattern))
                except re.error:
                    log.warning("Invalid exclude pattern: %s", pattern)

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            log.error(
                "Playwright not installed. Install via: pip install playwright && playwright install chromium"
            )
            result.errors.append("Playwright not installed")
            return result

        visited: set[str] = set()

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-gpu",
                        "--disable-dev-shm-usage",
                    ],
                )
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 CCure-Audit-PRO/1.0"
                    ),
                )

                # Apply auth cookies
                if auth_cookies:
                    await context.add_cookies(auth_cookies)

                # Apply auth headers
                if auth_headers:
                    await context.set_extra_http_headers(auth_headers)

                # Authenticated crawling: only watch for session loss when the
                # crawl started authenticated and a re-auth callback exists.
                # The callback is itself bounded (WebSessionManager.max_reauth),
                # and once it can no longer recover the session we stop checking
                # so the crawl does not stall re-detecting the same logout.
                _auth_watch = bool((auth_cookies or auth_headers) and reauth_cb)

                # Refuse to *navigate* off-scope in the first place.
                #
                # The check after page.goto() below catches a redirect that has
                # already happened; by then the request to the third party has
                # been sent. A scan is authorised for a target, not for whatever
                # an open redirect on that target points at, so the navigation
                # is aborted before it leaves.
                #
                # Only document requests are blocked. Sub-resources — a script or
                # stylesheet on a CDN — are left alone, because blocking those
                # stops the page rendering and a crawler that cannot render sees
                # nothing to crawl.
                blocked_navigations: list[dict] = []

                async def _scope_guard(route, request):
                    try:
                        if (
                            request.resource_type == "document"
                            and not self._is_in_scope(
                                request.url, allowed_domains, exclude_compiled
                            )
                        ):
                            blocked_navigations.append({"url": request.url})
                            await route.abort()
                            return
                        await route.continue_()
                    except Exception:
                        try:
                            await route.continue_()
                        except Exception:
                            pass

                await context.route("**/*", _scope_guard)

                # Intercept network requests for API discovery (attached
                # per-page below, so every concurrent worker's page contributes).
                network_apis: list[dict] = []
                # Bundle routes discovered by scanning JS *source* (Phase 22,
                # Crawler 2.0): an endpoint hardcoded in a bundle but never
                # executed is still part of the attack surface.
                bundle_routes: list[dict] = []
                dom_flows: list[dict] = []
                websockets: list[dict] = []
                _js_scanned = {"n": 0}

                def _on_ws(ws) -> None:
                    # WebSocket endpoints are real attack surface (Phase 23,
                    # Crawler 2.0) — record the ws:// URL if it is in scope.
                    try:
                        wurl = getattr(ws, "url", "") or ""
                        if wurl and self._is_in_scope(
                            wurl.replace("ws://", "http://").replace(
                                "wss://", "https://"
                            ),
                            allowed_domains,
                            exclude_compiled,
                        ):
                            websockets.append(
                                {
                                    "url": wurl,
                                    "method": "GET",
                                    "is_api": True,
                                    "source": "websocket",
                                }
                            )
                    except Exception:
                        pass

                _JS_SCAN_MAX = 40
                _JS_BODY_MAX = 2_000_000

                async def _on_response(response):
                    try:
                        url = response.url
                        # Scan JavaScript source for hardcoded routes/APIs.
                        try:
                            ctype = (
                                response.headers.get("content-type", "") or ""
                            ).lower()
                            is_js = "javascript" in ctype or url.split("?")[0].endswith(
                                ".js"
                            )
                            if (
                                is_js
                                and _js_scanned["n"] < _JS_SCAN_MAX
                                and self._is_in_scope(
                                    url, allowed_domains, exclude_compiled
                                )
                            ):
                                _js_scanned["n"] += 1
                                body = await response.text()
                                if body and len(body) <= _JS_BODY_MAX:
                                    from core.web.js_dom import analyze_dom_flows
                                    from core.web.js_routes import route_endpoints

                                    bundle_routes.extend(
                                        route_endpoints(body, start_url)
                                    )
                                    # Static DOM source→sink analysis (Item 9).
                                    dom_flows.extend(analyze_dom_flows(body, url))
                        except Exception:
                            pass
                        if self._is_api_call(url):
                            req = response.request
                            # Capture the REQUEST body + its content-type (Phase
                            # 22): a JSON API body is where modern parameters
                            # live, and without it sqlmap / the injection engine
                            # never see those parameters. post_data is a string
                            # property (None for GET); bounded so a large upload
                            # cannot bloat the crawl result.
                            req_body = None
                            try:
                                pd = req.post_data
                                if pd and len(pd) <= 20000:
                                    req_body = pd
                            except Exception:
                                req_body = None
                            req_ctype = ""
                            try:
                                req_ctype = req.headers.get("content-type", "")
                            except Exception:
                                req_ctype = ""
                            entry = {
                                "url": url,
                                "method": req.method,
                                "status": response.status,
                                "content_type": response.headers.get(
                                    "content-type", ""
                                ),
                                "request_body": req_body,
                                "request_content_type": req_ctype,
                                "is_api": True,
                                "source": "network_intercept",
                            }
                            # Value-free parameter model for the inventory.
                            try:
                                from core.web.surface import describe_parameters

                                params = describe_parameters(entry)
                                if params:
                                    entry["parameters"] = params
                            except Exception:
                                pass
                            network_apis.append(entry)
                    except Exception:
                        pass

                # Learn what a missing page looks like before trusting any 200.
                fp_page = await context.new_page()
                fp_page.on("response", _on_response)
                soft_404 = await self._soft_404_fingerprint(fp_page, start_url)
                try:
                    await fp_page.close()
                except Exception:
                    pass
                if soft_404:
                    log.info(
                        "Target answers unknown paths with 200 — soft-404 baseline "
                        "recorded; pages matching it will not be reported as endpoints"
                    )

                # ── Bounded-concurrency crawl (Phase 11) ──────────────────────
                # A level-synchronous BFS: each wave processes up to
                # ``concurrency`` URLs at once, each in its own page (so at most
                # ``concurrency`` pages exist at any moment — the browser cannot
                # be exhausted), and every navigation passes a shared rate
                # limiter. A URL is added to ``visited`` before it is awaited, so
                # two workers never crawl the same URL. The frontier is ordered
                # deterministically each wave, so the set of pages visited — and
                # therefore the findings — does not depend on task scheduling.
                sem = asyncio.Semaphore(max(1, int(self.concurrency)))
                min_interval = 1.0 / max(1, int(self.rate_limit))
                rl = {"last": 0.0}
                rl_lock = asyncio.Lock()
                reauth_lock = asyncio.Lock()
                state = {"auth_watch": _auth_watch, "reauth_gen": 0}

                async def _throttle():
                    async with rl_lock:
                        now = time.monotonic()
                        wait = min_interval - (now - rl["last"])
                        if wait > 0:
                            await asyncio.sleep(wait)
                        rl["last"] = time.monotonic()

                def _cancelled() -> bool:
                    try:
                        return bool(cancel_cb and cancel_cb())
                    except Exception:
                        return False

                async def _process(url: str, depth: int) -> dict:
                    out: dict = {"links": [], "requeue": None}
                    async with sem:
                        if _cancelled():
                            return out
                        result.pages_visited += 1
                        if progress_cb is not None and result.pages_visited % 3 == 0:
                            try:
                                progress_cb(
                                    result.pages_visited,
                                    len(result.endpoints) + len(result.js_endpoints),
                                )
                            except Exception:
                                pass

                        gen = state["reauth_gen"]
                        page = await context.new_page()
                        page.on("response", _on_response)
                        page.on("websocket", _on_ws)
                        blocked_before = len(blocked_navigations)
                        try:
                            await _throttle()
                            response = await page.goto(
                                url,
                                wait_until="domcontentloaded",
                                timeout=self.timeout,
                            )
                            try:
                                await page.wait_for_load_state(
                                    "networkidle", timeout=self.settle_timeout
                                )
                            except Exception:
                                pass  # Busy page — crawl what has rendered so far.

                            final_url = self._normalize_url(page.url) or url
                            visited.add(final_url)

                            if not self._is_in_scope(
                                final_url, allowed_domains, exclude_compiled
                            ):
                                log.warning(
                                    "Redirect left scope: %s -> %s — not crawled",
                                    url[:100],
                                    final_url[:100],
                                )
                                result.out_of_scope.append(
                                    {
                                        "from": url,
                                        "to": final_url,
                                        "status": (
                                            response.status if response else None
                                        ),
                                    }
                                )
                                return out

                            content = await page.content()

                            # Authenticated-crawl session-loss detection,
                            # serialized so one logout triggers at most one
                            # re-authentication across all concurrent workers.
                            if state["auth_watch"]:
                                from core.web.auth.session_manager import WebSession

                                status_code = response.status if response else 0
                                if WebSession.looks_unauthenticated(
                                    status_code, final_url, content, auth_config or {}
                                ):
                                    async with reauth_lock:
                                        if not state["auth_watch"]:
                                            pass
                                        elif state["reauth_gen"] != gen:
                                            # Another worker re-authenticated
                                            # after this page loaded — our view
                                            # is stale; re-crawl rather than
                                            # re-authenticate a second time.
                                            visited.discard(final_url)
                                            visited.discard(url)
                                            out["requeue"] = (url, depth)
                                            return out
                                        else:
                                            fresh = None
                                            try:
                                                fresh = await reauth_cb()
                                            except Exception as exc:
                                                log.debug(
                                                    "re-auth callback error: %s", exc
                                                )
                                            if fresh:
                                                try:
                                                    await context.clear_cookies()
                                                    await context.add_cookies(fresh)
                                                except Exception as exc:
                                                    log.debug(
                                                        "re-auth cookie apply "
                                                        "failed: %s",
                                                        exc,
                                                    )
                                                state["reauth_gen"] += 1
                                                result.auth_events.append(
                                                    {
                                                        "url": final_url,
                                                        "event": "reauthenticated",
                                                    }
                                                )
                                                log.info(
                                                    "Session lost at %s — "
                                                    "re-authenticated, re-crawling",
                                                    final_url[:100],
                                                )
                                                visited.discard(final_url)
                                                visited.discard(url)
                                                out["requeue"] = (url, depth)
                                                return out
                                            state["auth_watch"] = False
                                            result.auth_events.append(
                                                {
                                                    "url": final_url,
                                                    "event": (
                                                        "session_lost_unrecovered"
                                                    ),
                                                }
                                            )
                                            log.warning(
                                                "Session lost at %s and could not "
                                                "be re-established — remaining "
                                                "pages are crawled unauthenticated",
                                                final_url[:100],
                                            )

                            if (
                                soft_404
                                and final_url != start_url
                                and not self._has_route_fragment(final_url)
                                and self._content_fingerprint(content) == soft_404
                            ):
                                result.soft_404s.append(final_url)
                                return out

                            resp_headers = dict(response.headers) if response else {}
                            endpoint = {
                                "url": final_url,
                                "method": "GET",
                                "content_type": resp_headers.get("content-type", ""),
                                "response_code": response.status if response else None,
                                "response_size": len(content),
                                "source": (
                                    "crawler" if response else "crawler_spa_route"
                                ),
                                "parameters": {},
                                "response_headers": resp_headers,
                            }
                            if resp_headers:
                                self._detect_tech_from_headers(resp_headers, result)
                            self._fingerprint_page(
                                final_url, resp_headers, content, result
                            )
                            result.endpoints.append(endpoint)

                            links = await self._extract_links(page, final_url)
                            for link in links:
                                if link not in visited:
                                    out["links"].append((link, depth + 1))

                            forms = await self._extract_forms(page, final_url)
                            result.forms.extend(forms)

                            js_eps = self._extract_js_endpoints(content, final_url)
                            result.js_endpoints.extend(js_eps)

                            # Autonomous SPA interaction (Phase 23, Crawler 2.0):
                            # click safe, non-destructive controls to reach
                            # client-side routes/state a link crawl never sees.
                            # Opt-in — clicking is an active behaviour, and this
                            # product scans production; destructive controls are
                            # never clicked (see _interact_page).
                            if interact and depth < self.max_depth:
                                try:
                                    new_links = await self._interact_page(
                                        page, final_url, dom_graph
                                    )
                                    for link in new_links:
                                        if link not in visited and self._is_in_scope(
                                            link, allowed_domains, exclude_compiled
                                        ):
                                            out["links"].append((link, depth + 1))
                                except Exception as exc:
                                    log.debug("SPA interaction error: %s", exc)

                        except Exception as exc:
                            if len(blocked_navigations) > blocked_before:
                                for blocked in blocked_navigations[blocked_before:]:
                                    log.warning(
                                        "Blocked off-scope navigation: %s -> %s",
                                        url[:100],
                                        blocked["url"][:100],
                                    )
                                    result.out_of_scope.append(
                                        {
                                            "from": url,
                                            "to": blocked["url"],
                                            "blocked": True,
                                        }
                                    )
                            else:
                                log.debug("Crawl error for %s: %s", url[:100], exc)
                                result.errors.append(f"{url[:100]}: {str(exc)[:200]}")
                        finally:
                            try:
                                await page.close()
                            except Exception:
                                pass
                        return out

                frontier: list = [(start_url, 0)]
                while frontier and len(visited) < self.max_urls and not _cancelled():
                    batch: list = []
                    for u, d in frontier:
                        if len(visited) >= self.max_urls:
                            break
                        nu = self._normalize_url(u)
                        if not nu or nu in visited:
                            continue
                        if d > self.max_depth:
                            continue
                        if not self._is_in_scope(nu, allowed_domains, exclude_compiled):
                            continue
                        if self._should_skip_url(nu):
                            continue
                        visited.add(nu)
                        batch.append((nu, d))
                    if not batch:
                        break
                    outs = await asyncio.gather(
                        *[_process(u, d) for u, d in batch],
                        return_exceptions=True,
                    )
                    nxt: list = []
                    for o in outs:
                        if isinstance(o, dict):
                            nxt.extend(o.get("links") or [])
                            if o.get("requeue"):
                                nxt.append(o["requeue"])
                    frontier = self._order_frontier(nxt)

                # Add network-intercepted API calls
                result.js_endpoints.extend(network_apis)
                # Add routes mined from JS bundle source (unexecuted included).
                if bundle_routes:
                    result.js_endpoints.extend(bundle_routes)
                    log.info(
                        "Crawl: %d route(s) mined from %d JS bundle(s)",
                        len(bundle_routes),
                        _js_scanned["n"],
                    )
                # WebSocket endpoints observed during the crawl (Item 5/2.0).
                if websockets:
                    result.js_endpoints.extend(websockets)
                    log.info(
                        "Crawl: %d WebSocket endpoint(s) observed", len(websockets)
                    )
                # DOM source→sink findings from JS bundle analysis (Item 9).
                if dom_flows:
                    # Dedupe by (title) across bundles/pages.
                    _seen_dom: set = set()
                    for d in dom_flows:
                        if d["title"] not in _seen_dom:
                            _seen_dom.add(d["title"])
                            result.js_findings.append(d)
                    log.info(
                        "Crawl: %d DOM source→sink flow(s) found in JS",
                        len(result.js_findings),
                    )

                await browser.close()

        except Exception as exc:
            log.error("Playwright crawler failed: %s", exc)
            result.errors.append(str(exc))

        # Deduplicate endpoints
        result.endpoints = self._deduplicate_endpoints(result.endpoints)
        result.js_endpoints = self._deduplicate_endpoints(result.js_endpoints)
        # Deterministic output order — concurrency must not change which
        # findings a report shows or the order downstream engines see them.
        result.endpoints.sort(key=lambda e: (e.get("url") or ""))
        result.js_endpoints.sort(key=lambda e: (e.get("url") or ""))
        result.forms.sort(
            key=lambda f: (
                f.get("action") or f.get("url") or "",
                str(f.get("method") or ""),
            )
        )
        result.technologies = self._dedupe_technologies(result.technologies)
        if dom_graph.node_count:
            result.dom_graph = dom_graph.to_dict()
            _g = result.dom_graph["summary"]
            log.info(
                "Crawl: DOM state graph — %d states, %d transitions, "
                "%d SPA-hidden states",
                _g["states"],
                _g["transitions"],
                _g["spa_hidden_states"],
            )

        log.info(
            "Crawl complete: %d pages visited, %d endpoints, %d forms, "
            "%d JS endpoints, %d soft-404s discarded, %d off-scope navigations blocked",
            result.pages_visited,
            len(result.endpoints),
            len(result.forms),
            len(result.js_endpoints),
            len(result.soft_404s),
            len(result.out_of_scope),
        )

        return result

    # ── Extraction Helpers ────────────────────────────────────────────────────

    async def _dom_fingerprint(self, page) -> tuple[str, str]:
        """Return (fingerprint, title) for the page's current DOM state, using
        the structural probe. Best-effort — an empty fingerprint on failure so a
        state still gets a URL-keyed node."""
        from core.web.dom_graph import DOM_FINGERPRINT_JS, fingerprint_from_probe

        try:
            probe = await page.evaluate(DOM_FINGERPRINT_JS)
            return fingerprint_from_probe(probe), (probe or {}).get("title", "")
        except Exception:
            return "", ""

    async def _interact_page(self, page, base_url: str, dom_graph=None) -> list[str]:
        """
        Autonomously click safe, non-destructive controls to reach client-side
        routes/state a link crawl never sees (Phase 23, Crawler 2.0). Returns
        new same-page URLs (SPA routes reached via pushState/hash or client
        navigation). Opt-in; destructive-labelled and submit controls are never
        clicked, and the number of clicks per page is bounded.

        When ``dom_graph`` is supplied it records each interaction as a state
        transition (Phase 23b): the base state, the control clicked, and the
        state it led to — including a state reached on the *same* URL, which is
        the SPA coverage a URL list cannot show.
        """
        discovered: set = set()
        try:
            elements = await page.query_selector_all(
                "button, [role=button], [onclick], a[href^='#'], a[href^='javascript']"
            )
        except Exception:
            return []
        # Fingerprint the base state once so every transition shares one origin.
        base_sig = None
        if dom_graph is not None:
            fp, title = await self._dom_fingerprint(page)
            base_sig = dom_graph.add_state(base_url, fp, title)
        clicks = 0
        for el in elements:
            if clicks >= _INTERACT_MAX:
                break
            try:
                text = ((await el.inner_text()) or "").strip().lower()[:80]
            except Exception:
                text = ""
            if any(bad in text for bad in _DESTRUCTIVE_WORDS):
                continue
            try:
                etype = ((await el.get_attribute("type")) or "").lower()
            except Exception:
                etype = ""
            if etype == "submit":
                continue  # a submit may POST a form — not a safe autonomous click
            before = page.url
            try:
                await el.click(timeout=2000, no_wait_after=True)
                await page.wait_for_timeout(300)
            except Exception:
                continue
            clicks += 1
            after = page.url
            # Record the transition: the state after the click may differ from
            # the base even when the URL did not (an opened panel, a client
            # route), which is exactly the hidden state worth recording.
            state_changed = False
            if dom_graph is not None and base_sig:
                fp2, title2 = await self._dom_fingerprint(page)
                to_sig = dom_graph.add_state(after, fp2, title2)
                if to_sig != base_sig:
                    dom_graph.add_transition(base_sig, to_sig, text, control=etype)
                    state_changed = True
            if after != before and after not in discovered:
                discovered.add(after)
            if after != before or state_changed:
                # Reset to the base page so the next click starts from a known
                # state rather than compounding SPA transitions.
                try:
                    await page.goto(
                        base_url, wait_until="domcontentloaded", timeout=self.timeout
                    )
                except Exception:
                    break
        return list(discovered)

    @staticmethod
    async def _extract_links(page, current_url: str) -> list[str]:
        """
        Extract navigable destinations from the current page.

        ``a[href]`` alone under-reports a component-framework application.
        Angular's ``routerLink``, and the equivalent data attributes in other
        frameworks, are frequently placed on buttons and list items that never
        receive an href — on a typical Angular app that is where the
        authenticated areas live, so a crawl limited to anchors sees the
        marketing pages and stops.
        """
        links = set()
        try:
            for el in await page.query_selector_all("a[href]"):
                href = await el.get_attribute("href")
                if href:
                    links.add(urljoin(current_url, href.strip()))
        except Exception:
            pass

        # Router directives hold an application path, not a URL. Where the app
        # routes on the fragment, that is where its paths have to be put back.
        parsed_current = urlparse(current_url)
        hash_routed = parsed_current.fragment.startswith("/")
        origin = f"{parsed_current.scheme}://{parsed_current.netloc}"
        try:
            selector = "[routerLink], [ng-reflect-router-link], [data-href], [data-url]"
            for el in await page.query_selector_all(selector):
                for attr in (
                    "routerLink",
                    "ng-reflect-router-link",
                    "data-href",
                    "data-url",
                ):
                    raw = await el.get_attribute(attr)
                    if not raw:
                        continue
                    route = raw.strip().strip("[]").strip("'\" ")
                    if not route or route.startswith(
                        ("javascript:", "mailto:", "tel:")
                    ):
                        continue
                    if route.startswith("http"):
                        links.add(route)
                    elif hash_routed and route.startswith("/"):
                        links.add(f"{origin}/#{route}")
                    else:
                        links.add(urljoin(current_url, route))
        except Exception:
            pass

        return list(links)

    @staticmethod
    async def _extract_forms(page, current_url: str) -> list[dict]:
        """Extract form information from the page."""
        forms = []
        try:
            form_elements = await page.query_selector_all("form")
            for form in form_elements:
                action = await form.get_attribute("action") or current_url
                method = (await form.get_attribute("method") or "GET").upper()
                action_url = urljoin(current_url, action)

                # Extract input fields
                inputs = []
                input_elements = await form.query_selector_all(
                    "input, textarea, select"
                )
                has_file_upload = False
                has_password = False

                for inp in input_elements:
                    input_type = (await inp.get_attribute("type") or "text").lower()
                    input_id = await inp.get_attribute("id") or ""

                    # Reactive-form frameworks bind fields by directive rather
                    # than by the name attribute, so a large share of modern
                    # inputs have no name at all. Falling back leaves the field
                    # identifiable; without this every such input is recorded as
                    # "" and no injection test can address it.
                    input_name = ""
                    for attr in (
                        "name",
                        "formcontrolname",
                        "ng-reflect-name",
                        "data-name",
                        "id",
                    ):
                        value = await inp.get_attribute(attr)
                        if value and value.strip():
                            input_name = value.strip()
                            break

                    if input_type == "file":
                        has_file_upload = True
                    if input_type == "password":
                        has_password = True

                    inputs.append(
                        {
                            "name": input_name,
                            "type": input_type,
                            "id": input_id,
                        }
                    )

                forms.append(
                    {
                        "url": action_url,
                        "method": method,
                        "inputs": inputs,
                        "has_file_upload": has_file_upload,
                        "has_password": has_password,
                        "source": "crawler",
                        "page_url": current_url,
                    }
                )
        except Exception:
            pass
        return forms

    @staticmethod
    def _is_plausible_endpoint(path: str) -> bool:
        """
        Whether a string matched in JavaScript is worth treating as a URL.

        The extraction patterns match any ``url:``/``path:`` assignment, which in
        minified bundles also catches MIME types, CSS values, i18n keys and
        template literals. Each one that gets through becomes a fabricated
        endpoint: it is stored as discovered attack surface and handed to nuclei
        and sqlmap to scan, so the cost of a loose filter is paid in scan time
        and in a report describing an application that does not exist.
        """
        if not path or len(path) > 512:
            return False
        if any(ch in path for ch in (" ", "\t", "\n", "<", ">", "{", "}", "`")):
            return False
        # Unresolved template placeholders are not addresses.
        if "${" in path or "%s" in path or "{{" in path:
            return False
        if path.startswith(("data:", "blob:", "javascript:", "mailto:", "tel:", "#")):
            return False
        # MIME types and bare content types read as paths but are not.
        if re.match(r"^(text|image|application|audio|video|font)/", path):
            return False
        return path.startswith("/") or path.startswith("http")

    @staticmethod
    def _extract_js_endpoints(html_content: str, base_url: str) -> list[dict]:
        """Extract API endpoints from inline and referenced JavaScript."""
        endpoints = []
        seen = set()
        parsed_base = urlparse(base_url)
        for pattern in _JS_ENDPOINT_PATTERNS:
            for match in pattern.finditer(html_content):
                path = match.group(1).strip()
                if not path or path in seen:
                    continue
                seen.add(path)

                if not PlaywrightCrawler._is_plausible_endpoint(path):
                    continue

                # Resolve relative paths
                if path.startswith("/"):
                    full_url = f"{parsed_base.scheme}://{parsed_base.netloc}{path}"
                elif path.startswith("http"):
                    # A URL on someone else's host is not this target's surface.
                    if urlparse(path).netloc != parsed_base.netloc:
                        continue
                    full_url = path
                else:
                    continue

                endpoints.append(
                    {
                        "url": full_url,
                        "method": "GET",
                        "source": "js_parse",
                        "content_type": "",
                        "response_code": None,
                    }
                )
        return endpoints

    @staticmethod
    def _detect_tech_from_headers(headers: dict, result: CrawlResult) -> None:
        """Detect technologies from HTTP response headers."""
        server = headers.get("server", "")
        if server:
            result.technologies.append(
                {"name": server, "category": "server", "source": "header"}
            )

        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            result.technologies.append(
                {"name": powered_by, "category": "framework", "source": "header"}
            )

        # HSTS check
        if not headers.get("strict-transport-security"):
            pass  # Will be flagged by audit phase

    @staticmethod
    def _fingerprint_page(url, headers: dict, content: str, result: "CrawlResult"):
        """
        Multi-source technology fingerprint for a page (Phase 16, Part B).

        Runs the fetch-free fingerprinter over the response the crawl already
        has (headers, Set-Cookie names, HTML/asset markers) and merges the
        result — so a stack that only advertises itself in the DOM (Angular's
        ng-version, __NEXT_DATA__, wp-content, …) is detected, not just what a
        Server header happens to say. Best-effort; never raises.
        """
        try:
            from core.web.fingerprint import TechFingerprinter

            cookie_names = {}
            raw_cookies = headers.get("set-cookie", "") or ""
            for chunk in re.split(r"[\n,]", raw_cookies):
                name = chunk.split("=", 1)[0].strip()
                if name and " " not in name:
                    cookie_names[name] = ""
            techs = TechFingerprinter().fingerprint(
                url, 200, headers=headers, cookies=cookie_names, html=content or ""
            )
            for t in techs:
                result.technologies.append(
                    {
                        "name": t["name"],
                        "category": t["category"],
                        "version": t.get("version"),
                        "confidence": t["confidence"],
                        "evidence": t["evidence"],
                        "source": "fingerprint",
                    }
                )
        except Exception as exc:  # noqa: BLE001
            log.debug("fingerprint failed for %s: %s", str(url)[:80], exc)

    # ── Scope & Filtering ─────────────────────────────────────────────────────

    @staticmethod
    def _is_in_scope(
        url: str, allowed_domains: set[str], exclude_patterns: list
    ) -> bool:
        parsed = urlparse(url)
        if parsed.netloc not in allowed_domains:
            return False
        for pattern in exclude_patterns:
            if pattern.search(url):
                return False
        return True

    @staticmethod
    def _should_skip_url(url: str) -> bool:
        """Skip non-HTML resources."""
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        return any(path_lower.endswith(ext) for ext in _SKIP_EXTENSIONS)

    @staticmethod
    def _normalize_url(url: str) -> str | None:
        """
        Normalize a URL, keeping the parts that identify a distinct page.

        Fragments are *not* uniformly discarded. Angular, React and Vue
        applications routinely put the whole route in the fragment —
        ``/#/login``, ``/#/search`` — so stripping it collapses every screen in
        the application onto the root URL. A crawler that does that visits the
        landing page once and reports the SPA as a single-page site, which is
        exactly the class of target this crawler exists to handle.

        The distinction is what the fragment looks like. A route fragment
        (``#/...``) selects content and is kept; a plain anchor (``#section-2``)
        scrolls within a page already crawled and is dropped, so the same page
        is not re-visited once per heading.
        """
        if not url or not url.startswith("http"):
            return None
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        if parsed.fragment.startswith("/"):
            normalized += f"#{parsed.fragment}"
        return normalized

    @staticmethod
    def _content_fingerprint(body: str) -> str:
        """
        A stable hash of page content, used to recognise the same page served
        under many URLs.
        """
        collapsed = re.sub(r"\s+", " ", body or "").strip()
        return hashlib.sha1(collapsed.encode("utf-8", "replace")).hexdigest()

    @staticmethod
    def _has_route_fragment(url: str) -> bool:
        return urlparse(url).fragment.startswith("/")

    async def _soft_404_fingerprint(self, page, start_url: str) -> str | None:
        """
        What this application returns for a path that does not exist.

        Single-page applications answer *every* unmatched path with the same
        200 and the same shell HTML, so a crawler cannot use the status code to
        tell a real page from a missing one. Without this baseline, any stray
        link — including one resolved from another site's markup — looks like a
        live endpoint, and a crawl reports hundreds of URLs that are one page.

        Returns the fingerprint of the not-found response, or None when no
        usable baseline exists — either because the application answers
        unmatched paths honestly (404/410), in which case the status code is
        already sufficient, or because its not-found page is indistinguishable
        from its real landing page.

        That second case is the one to be careful about. An application routed
        on the path rather than the fragment — React Router, Next.js, Angular
        without hash routing — serves the identical shell for ``/`` and for a
        path that does not exist. Filtering on that fingerprint would discard
        the landing page, and with it every link the crawl would have followed,
        leaving an empty result for a perfectly ordinary application. When the
        baseline cannot distinguish, it is not used.
        """
        parsed = urlparse(start_url)
        probe = (
            f"{parsed.scheme}://{parsed.netloc}/"
            f"ccure-probe-{uuid.uuid4().hex[:16]}/does-not-exist"
        )

        async def _render(url: str):
            response = await page.goto(
                url, wait_until="domcontentloaded", timeout=self.timeout
            )
            try:
                await page.wait_for_load_state(
                    "networkidle", timeout=self.settle_timeout
                )
            except Exception:
                pass
            return response, await page.content()

        try:
            response, probe_body = await _render(probe)
            if not response or response.status >= 400:
                return None
            probe_fingerprint = self._content_fingerprint(probe_body)
        except Exception as exc:
            log.debug("Soft-404 baseline probe failed: %s", exc)
            return None

        try:
            _, start_body = await _render(start_url)
        except Exception as exc:
            log.debug("Soft-404 comparison against the start page failed: %s", exc)
            return probe_fingerprint

        if self._content_fingerprint(start_body) == probe_fingerprint:
            log.info(
                "The target serves identical content for its landing page and for "
                "a path that does not exist, so a missing page cannot be told "
                "from a real one by content — soft-404 filtering is disabled for "
                "this scan and discovered paths are reported as found"
            )
            return None

        return probe_fingerprint

    @staticmethod
    def _is_api_call(url: str) -> bool:
        """Heuristic: is this URL an API endpoint?"""
        api_indicators = ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/ws/"]
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in api_indicators)

    @staticmethod
    def _dedupe_technologies(techs: list) -> list:
        """
        One entry per technology across the whole crawl. A richer fingerprint
        (carries a version / confidence / evidence) supersedes a bare
        header-derived entry for the same technology, so the inventory reads
        cleanly rather than listing "nginx/1.27.5" and "nginx" separately.
        """
        rank = {"high": 2, "medium": 1}
        best: dict = {}
        order: list = []
        for t in techs or []:
            raw = str(t.get("name") or "").strip()
            if not raw:
                continue
            # Normalise a bare "nginx/1.27.5" header value to "nginx" so it
            # merges with the fingerprint entry.
            key = re.split(r"[/ ]", raw, 1)[0].lower()
            if key not in best:
                best[key] = dict(t)
                order.append(key)
                continue
            cur = best[key]
            cand_rich = 1 if (t.get("version") or t.get("confidence")) else 0
            cur_rich = 1 if (cur.get("version") or cur.get("confidence")) else 0
            if cand_rich > cur_rich or (
                cand_rich == cur_rich
                and rank.get(t.get("confidence"), 0)
                > rank.get(cur.get("confidence"), 0)
            ):
                best[key] = dict(t)
        return [best[k] for k in order]

    @staticmethod
    def _order_frontier(items: list) -> list:
        """
        Deduplicate and deterministically order the next BFS wave.

        Each ``(url, depth)`` is kept at its shallowest depth, then sorted by
        (depth, url). Ordering the frontier is what makes the crawl
        deterministic under concurrency: which URLs fall inside ``max_urls``,
        and the order downstream engines receive them, no longer depend on the
        order tasks happened to finish.
        """
        best: dict = {}
        for url, depth in items:
            if url not in best or depth < best[url]:
                best[url] = depth
        return sorted(best.items(), key=lambda kv: (kv[1], kv[0]))

    @staticmethod
    def _deduplicate_endpoints(endpoints: list[dict]) -> list[dict]:
        """Deduplicate endpoints by URL+method."""
        seen: set[str] = set()
        unique: list[dict] = []
        for ep in endpoints:
            key = f"{ep.get('method', 'GET')}:{ep.get('url', '')}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        return unique
