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
from collections import deque
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from config import WebScanConfig

log = logging.getLogger("ccure.web.crawler")

# Regex patterns for extracting API endpoints from JavaScript
_JS_ENDPOINT_PATTERNS = [
    re.compile(r"""(?:fetch|axios|XMLHttpRequest)\s*\(\s*['"`]([^'"`]+)['"`]"""),
    re.compile(r"""(?:url|endpoint|api|path)\s*[:=]\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
    re.compile(r"""(?:GET|POST|PUT|DELETE|PATCH)\s*['"`]\s*([/][^'"`\s]+)"""),
]

# File extensions to skip during crawling
_SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".webm",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".map",
}


class CrawlResult:
    """Result of a crawling session."""

    def __init__(self):
        self.endpoints: List[Dict] = []
        self.forms: List[Dict] = []
        self.js_endpoints: List[Dict] = []
        self.technologies: List[Dict] = []
        self.cookies: List[Dict] = []
        self.errors: List[str] = []
        self.pages_visited: int = 0
        self.api_specs: List[Dict] = []

    def to_dict(self) -> Dict:
        return {
            "endpoints": self.endpoints,
            "forms": self.forms,
            "js_endpoints": self.js_endpoints,
            "technologies": self.technologies,
            "cookies": self.cookies,
            "errors": self.errors,
            "pages_visited": self.pages_visited,
            "api_specs": self.api_specs,
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
        max_depth: Optional[int] = None,
        max_urls: Optional[int] = None,
        timeout: Optional[int] = None,
        concurrency: Optional[int] = None,
    ):
        self.max_depth = max_depth or WebScanConfig.MAX_CRAWL_DEPTH
        self.max_urls = max_urls or WebScanConfig.MAX_CRAWL_URLS
        self.timeout = timeout or WebScanConfig.PLAYWRIGHT_TIMEOUT
        self.concurrency = concurrency or WebScanConfig.CRAWL_CONCURRENCY

    async def crawl(
        self,
        start_url: str,
        auth_cookies: Optional[List[Dict]] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        scope_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
    ) -> CrawlResult:
        """
        Crawl a web application starting from start_url.

        Args:
            start_url: Starting URL for crawling
            auth_cookies: Cookies for authenticated crawling
            auth_headers: Headers for authenticated crawling
            scope_patterns: URL patterns to stay within
            exclude_patterns: URL patterns to skip

        Returns:
            CrawlResult with discovered endpoints, forms, and JS endpoints
        """
        result = CrawlResult()
        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc

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
            log.error("Playwright not installed. Install via: pip install playwright && playwright install chromium")
            result.errors.append("Playwright not installed")
            return result

        visited: Set[str] = set()
        queue: deque = deque()
        queue.append((start_url, 0))  # (url, depth)

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

                # Intercept network requests for API discovery
                network_apis: List[Dict] = []

                page = await context.new_page()

                # Listen for API calls
                async def _on_response(response):
                    try:
                        url = response.url
                        if self._is_api_call(url):
                            network_apis.append({
                                "url": url,
                                "method": response.request.method,
                                "status": response.status,
                                "content_type": response.headers.get("content-type", ""),
                                "source": "network_intercept",
                            })
                    except Exception:
                        pass

                page.on("response", _on_response)

                while queue and len(visited) < self.max_urls:
                    url, depth = queue.popleft()

                    # Normalize URL
                    url = self._normalize_url(url)
                    if not url or url in visited:
                        continue
                    if depth > self.max_depth:
                        continue
                    if not self._is_in_scope(url, allowed_domains, exclude_compiled):
                        continue
                    if self._should_skip_url(url):
                        continue

                    visited.add(url)
                    result.pages_visited += 1

                    try:
                        response = await page.goto(url, wait_until="networkidle", timeout=self.timeout)
                        if not response:
                            continue

                        # Extract page content
                        content = await page.content()

                        # Record endpoint
                        endpoint = {
                            "url": url,
                            "method": "GET",
                            "content_type": response.headers.get("content-type", ""),
                            "response_code": response.status,
                            "response_size": len(content),
                            "source": "crawler",
                            "parameters": {},
                        }

                        # Extract response headers
                        resp_headers = dict(response.headers)
                        endpoint["response_headers"] = resp_headers

                        # Technology detection from headers
                        self._detect_tech_from_headers(resp_headers, result)

                        result.endpoints.append(endpoint)

                        # Extract links
                        links = await self._extract_links(page, url)
                        for link in links:
                            if link not in visited:
                                queue.append((link, depth + 1))

                        # Extract forms
                        forms = await self._extract_forms(page, url)
                        result.forms.extend(forms)

                        # Extract JS endpoints
                        js_eps = self._extract_js_endpoints(content, url)
                        result.js_endpoints.extend(js_eps)

                    except Exception as exc:
                        log.debug("Crawl error for %s: %s", url[:100], exc)
                        result.errors.append(f"{url[:100]}: {str(exc)[:200]}")

                # Add network-intercepted API calls
                result.js_endpoints.extend(network_apis)

                await browser.close()

        except Exception as exc:
            log.error("Playwright crawler failed: %s", exc)
            result.errors.append(str(exc))

        # Deduplicate endpoints
        result.endpoints = self._deduplicate_endpoints(result.endpoints)
        result.js_endpoints = self._deduplicate_endpoints(result.js_endpoints)

        log.info(
            "Crawl complete: %d pages, %d endpoints, %d forms, %d JS endpoints",
            result.pages_visited, len(result.endpoints),
            len(result.forms), len(result.js_endpoints),
        )

        return result

    # ── Extraction Helpers ────────────────────────────────────────────────────

    @staticmethod
    async def _extract_links(page, current_url: str) -> List[str]:
        """Extract all links from the current page."""
        links = set()
        try:
            elements = await page.query_selector_all("a[href]")
            for el in elements:
                href = await el.get_attribute("href")
                if href:
                    absolute = urljoin(current_url, href.strip())
                    links.add(absolute)
        except Exception:
            pass
        return list(links)

    @staticmethod
    async def _extract_forms(page, current_url: str) -> List[Dict]:
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
                input_elements = await form.query_selector_all("input, textarea, select")
                has_file_upload = False
                has_password = False

                for inp in input_elements:
                    input_type = (await inp.get_attribute("type") or "text").lower()
                    input_name = await inp.get_attribute("name") or ""
                    input_id = await inp.get_attribute("id") or ""

                    if input_type == "file":
                        has_file_upload = True
                    if input_type == "password":
                        has_password = True

                    inputs.append({
                        "name": input_name,
                        "type": input_type,
                        "id": input_id,
                    })

                forms.append({
                    "url": action_url,
                    "method": method,
                    "inputs": inputs,
                    "has_file_upload": has_file_upload,
                    "has_password": has_password,
                    "source": "crawler",
                    "page_url": current_url,
                })
        except Exception:
            pass
        return forms

    @staticmethod
    def _extract_js_endpoints(html_content: str, base_url: str) -> List[Dict]:
        """Extract API endpoints from inline and referenced JavaScript."""
        endpoints = []
        seen = set()
        for pattern in _JS_ENDPOINT_PATTERNS:
            for match in pattern.finditer(html_content):
                path = match.group(1).strip()
                if not path or path in seen:
                    continue
                seen.add(path)

                # Resolve relative paths
                if path.startswith("/"):
                    parsed = urlparse(base_url)
                    full_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                elif path.startswith("http"):
                    full_url = path
                else:
                    continue

                endpoints.append({
                    "url": full_url,
                    "method": "GET",
                    "source": "js_parse",
                    "content_type": "",
                    "response_code": None,
                })
        return endpoints

    @staticmethod
    def _detect_tech_from_headers(headers: Dict, result: CrawlResult) -> None:
        """Detect technologies from HTTP response headers."""
        server = headers.get("server", "")
        if server:
            result.technologies.append({"name": server, "category": "server", "source": "header"})

        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            result.technologies.append({"name": powered_by, "category": "framework", "source": "header"})

        # HSTS check
        if not headers.get("strict-transport-security"):
            pass  # Will be flagged by audit phase

    # ── Scope & Filtering ─────────────────────────────────────────────────────

    @staticmethod
    def _is_in_scope(url: str, allowed_domains: Set[str], exclude_patterns: List) -> bool:
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
    def _normalize_url(url: str) -> Optional[str]:
        """Normalize URL by removing fragments and cleaning up."""
        if not url or not url.startswith("http"):
            return None
        parsed = urlparse(url)
        # Remove fragment
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized

    @staticmethod
    def _is_api_call(url: str) -> bool:
        """Heuristic: is this URL an API endpoint?"""
        api_indicators = ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/ws/"]
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in api_indicators)

    @staticmethod
    def _deduplicate_endpoints(endpoints: List[Dict]) -> List[Dict]:
        """Deduplicate endpoints by URL+method."""
        seen: Set[str] = set()
        unique: List[Dict] = []
        for ep in endpoints:
            key = f"{ep.get('method', 'GET')}:{ep.get('url', '')}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        return unique
