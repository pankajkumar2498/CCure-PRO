"""
core/web/workflow/engine.py
────────────────────────────────────────────────────────────────────────────
Authenticated multi-step workflow engine (Phase 13).

Replays a validated workflow (see ``actions.py``) in one real browser session,
so an operator can reach security-sensitive functionality that lives behind
several authenticated steps — log in → dashboard → resource → action — for
*their* application, expressed as configuration rather than code baked into the
product. The endpoints, forms and API calls the workflow reaches are returned
so the existing DETECT engines test them like any other discovered surface.

Guarantees this is built around:

  • **Session persistence** — one browser context for the whole workflow, so
    cookies and captured values carry from step to step.
  • **CSRF handling** — steps submit real forms and click real controls, so the
    browser sends the anti-CSRF hidden fields the page rendered; a token can
    also be extracted and reused via ``{{name}}``.
  • **Dynamic values** — ``{{name}}`` in a url/value/body is filled from values
    earlier steps captured.
  • **Conditional checks, timeouts, retries, cancellation** — a ``verify`` step
    can gate the workflow; every action has a bounded timeout and optional
    retries; a cancel callback (also the global-timeout signal) stops it.
  • **Secrets never leak** — a password typed in, a captured token or cookie is
    tracked as a secret and masked in every log line, error and returned
    field; the raw session material is handed back to the orchestrator on a
    separate channel for internal use, never in the API-visible result.
  • **Scope** — every navigation and API request is checked against the scan's
    authorised scope; an off-scope target is refused, not visited.
"""

from __future__ import annotations

from core.web.browser_runtime import launch_options

import asyncio
import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from core.web.workflow.actions import (
    NAVIGATING_ACTIONS,
    action_type,
    normalize_workflow,
    validate_workflow,
)

log = logging.getLogger("ccure.web.workflow")

_DEFAULT_ACTION_TIMEOUT_MS = 15000
_DEFAULT_WORKFLOW_TIMEOUT_MS = 180000


class WorkflowEngine:
    def __init__(
        self,
        *,
        allowed_domains: Optional[set] = None,
        action_timeout_ms: int = _DEFAULT_ACTION_TIMEOUT_MS,
        verify_tls: bool = False,
    ) -> None:
        self.allowed_domains = set(allowed_domains or set())
        self.action_timeout_ms = action_timeout_ms
        self.verify_tls = verify_tls

    def is_available(self) -> bool:
        try:
            import playwright.async_api  # noqa: F401

            return True
        except Exception:
            return False

    # ── scope + secret helpers ────────────────────────────────────────────────
    def _in_scope(self, url: str) -> bool:
        if not self.allowed_domains:
            return True
        netloc = urlparse(url).netloc
        return netloc in self.allowed_domains

    @staticmethod
    def _mask(text: str, secrets: set) -> str:
        if not text:
            return text
        out = str(text)
        for s in secrets:
            if s:
                out = out.replace(s, "***")
        return out

    # ── entrypoint ────────────────────────────────────────────────────────────
    async def run(
        self,
        workflow: Any,
        base_url: str,
        auth_cookies: Optional[list] = None,
        auth_headers: Optional[dict] = None,
        cancel_cb: Optional[Callable[[], bool]] = None,
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        wf = normalize_workflow(workflow)
        errors = validate_workflow(wf)
        result: Dict[str, Any] = {
            "ok": False,
            "endpoints": [],
            "forms": [],
            "captured": {},  # masked, safe to surface
            "errors": list(errors),
            "steps_run": 0,
            "session_cookies": [],  # raw — internal use only, never API-returned
            "session_headers": {},  # raw — internal use only
        }
        if errors:
            return result
        if not self.is_available():
            result["errors"].append("Playwright not available")
            return result

        base_netloc = urlparse(base_url).netloc
        if base_netloc:
            self.allowed_domains.add(base_netloc)

        actions = wf.get("actions") or []
        overall_timeout = int(wf.get("timeout_ms") or _DEFAULT_WORKFLOW_TIMEOUT_MS)
        deadline = time.monotonic() + overall_timeout / 1000.0

        captured: Dict[str, str] = {}
        secrets: set = set()
        endpoints: List[dict] = []
        forms: List[dict] = []
        network_apis: List[dict] = []
        # Per-run, never shared between workflows (a captured bearer for reuse).
        self._pending_headers = {}

        def _cancelled() -> bool:
            try:
                return bool(cancel_cb and cancel_cb())
            except Exception:
                return False

        def _fill(value):
            if isinstance(value, str):
                for k, v in captured.items():
                    value = value.replace("{{" + k + "}}", v)
            return value

        def _record_endpoint(url: str, method: str = "GET", source: str = "workflow"):
            if url and self._in_scope(url):
                endpoints.append(
                    {"url": url, "method": method, "source": source, "parameters": {}}
                )

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            result["errors"].append("Playwright not installed")
            return result

        from core.web.crawling.browser import PlaywrightCrawler

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    **launch_options(),
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-gpu",
                        "--disable-dev-shm-usage",
                    ],
                )
                context = await browser.new_context(ignore_https_errors=True)
                if auth_cookies:
                    try:
                        await context.add_cookies(auth_cookies)
                    except Exception as exc:
                        log.debug("workflow: could not apply auth cookies: %s", exc)
                if auth_headers:
                    try:
                        await context.set_extra_http_headers(auth_headers)
                    except Exception:
                        pass

                # Refuse to navigate a document off-scope (open-redirect / scope
                # containment), exactly as the crawler does.
                async def _scope_guard(route, request):
                    try:
                        if request.resource_type == "document" and not self._in_scope(
                            request.url
                        ):
                            await route.abort()
                            return
                        await route.continue_()
                    except Exception:
                        try:
                            await route.continue_()
                        except Exception:
                            pass

                await context.route("**/*", _scope_guard)

                page = await context.new_page()

                def _on_response(response):
                    try:
                        if PlaywrightCrawler._is_api_call(response.url):
                            network_apis.append(
                                {
                                    "url": response.url,
                                    "method": response.request.method,
                                    "status": response.status,
                                    "source": "workflow_network",
                                }
                            )
                    except Exception:
                        pass

                page.on("response", _on_response)

                for i, step in enumerate(actions, 1):
                    if _cancelled():
                        result["errors"].append(f"cancelled before action {i}")
                        break
                    if time.monotonic() > deadline:
                        result["errors"].append(f"workflow timed out before action {i}")
                        break

                    atype = action_type(step)
                    a_timeout = int(step.get("timeout_ms") or self.action_timeout_ms)
                    retries = int(step.get("retries") or 0)

                    # Scope pre-check for navigating actions, before anything runs.
                    if atype in NAVIGATING_ACTIONS:
                        target = urljoin(base_url, _fill(step.get("url") or ""))
                        if not self._in_scope(target):
                            result["errors"].append(
                                f"action {i} ({atype}): target is outside the scan "
                                f"scope and was refused"
                            )
                            break

                    last_exc = None
                    for attempt in range(retries + 1):
                        try:
                            await self._dispatch(
                                atype,
                                step,
                                page,
                                context,
                                base_url,
                                a_timeout,
                                captured,
                                secrets,
                                _fill,
                                _record_endpoint,
                                forms,
                                result,
                            )
                            last_exc = None
                            break
                        except _WorkflowStop as stop:
                            # A verify condition failed (non-optional) — stop the
                            # workflow deliberately, message already sanitised.
                            result["errors"].append(str(stop))
                            last_exc = stop
                            break
                        except Exception as exc:  # noqa: BLE001
                            last_exc = exc
                            if attempt < retries:
                                await asyncio.sleep(0.5)
                                continue
                    if isinstance(last_exc, _WorkflowStop):
                        break
                    if last_exc is not None:
                        msg = self._mask(str(last_exc), secrets)[:200]
                        result["errors"].append(f"action {i} ({atype}) failed: {msg}")
                        break

                    result["steps_run"] += 1
                    if progress_cb:
                        try:
                            progress_cb(f"workflow step {i}/{len(actions)} ({atype})")
                        except Exception:
                            pass

                # Collect the resulting session for internal reuse.
                try:
                    ck = await context.cookies()
                    result["session_cookies"] = [
                        c for c in ck if isinstance(c, dict) and c.get("name")
                    ]
                except Exception:
                    pass

                await browser.close()

            # Endpoints: navigated pages + network API calls, deduped.
            endpoints.extend(network_apis)
            result["endpoints"] = PlaywrightCrawler._deduplicate_endpoints(endpoints)
            result["forms"] = forms
            # captured is masked for the API-visible result; secret values never
            # appear here.
            result["captured"] = {
                k: (self._mask(v, secrets) if v in secrets else v)
                for k, v in captured.items()
            }
            # Session headers (e.g. a captured bearer) for internal reuse only.
            result["session_headers"] = self._pending_headers
            result["ok"] = not any(e for e in result["errors"]) and result[
                "steps_run"
            ] == len(actions)
        except Exception as exc:  # noqa: BLE001
            result["errors"].append(self._mask(str(exc), secrets)[:200])
        return result

    # ── action dispatch ───────────────────────────────────────────────────────
    async def _dispatch(
        self,
        atype,
        step,
        page,
        context,
        base_url,
        a_timeout,
        captured,
        secrets,
        _fill,
        _record_endpoint,
        forms,
        result,
    ):
        from core.web.crawling.browser import PlaywrightCrawler

        if atype == "open":
            url = urljoin(base_url, _fill(step.get("url")))
            await page.goto(url, wait_until="domcontentloaded", timeout=a_timeout)
            _record_endpoint(page.url)
            forms.extend(await PlaywrightCrawler._extract_forms(page, page.url))

        elif atype == "click":
            await page.click(step["selector"], timeout=a_timeout)
            await page.wait_for_load_state("domcontentloaded", timeout=a_timeout)
            _record_endpoint(page.url)
            forms.extend(await PlaywrightCrawler._extract_forms(page, page.url))

        elif atype == "type":
            value = _fill(step.get("value", ""))
            if step.get("secret") or step.get("field") == "password":
                secrets.add(value)
            await page.fill(step["selector"], value, timeout=a_timeout)

        elif atype == "select":
            await page.select_option(
                step["selector"], _fill(step.get("value")), timeout=a_timeout
            )

        elif atype == "submit":
            selector = step.get("selector")
            if selector:
                await page.click(selector, timeout=a_timeout)
            else:
                await page.evaluate(
                    "() => { const f = document.querySelector('form'); if (f) f.submit(); }"
                )
            await page.wait_for_load_state("domcontentloaded", timeout=a_timeout)
            _record_endpoint(page.url)
            forms.extend(await PlaywrightCrawler._extract_forms(page, page.url))

        elif atype == "wait":
            if step.get("selector"):
                await page.wait_for_selector(step["selector"], timeout=a_timeout)
            else:
                await asyncio.sleep(min(int(step.get("ms", 0)), a_timeout) / 1000.0)

        elif atype == "extract":
            await self._do_extract(step, page, captured, secrets, _fill)

        elif atype == "verify":
            await self._do_verify(step, page, secrets)

        elif atype == "capture_token":
            await self._do_capture_token(step, page, context, captured, secrets)

        elif atype == "capture_cookie":
            await self._do_capture_cookie(step, context, captured, secrets)

        elif atype == "api_request":
            await self._do_api_request(
                step,
                context,
                base_url,
                a_timeout,
                captured,
                secrets,
                _fill,
                _record_endpoint,
            )

    async def _do_extract(self, step, page, captured, secrets, _fill):
        name = step["name"]
        value = None
        if step.get("selector"):
            attr = step.get("attr", "text")
            loc = page.locator(step["selector"]).first
            if attr == "text":
                value = await loc.text_content()
            else:
                value = await loc.get_attribute(attr)
        elif step.get("regex"):
            content = await page.content()
            m = re.search(step["regex"], content)
            if m:
                value = m.group(m.lastindex or 0)
        elif step.get("from") == "url":
            value = page.url
        if value is not None:
            captured[name] = value
            if step.get("secret"):
                secrets.add(value)

    async def _do_verify(self, step, page, secrets):
        content = await page.content()
        ok = True
        detail = ""
        if "contains" in step:
            ok = str(step["contains"]) in content
            detail = f"expected text {step['contains']!r} present"
        elif "not_contains" in step:
            ok = str(step["not_contains"]) not in content
            detail = f"expected text {step['not_contains']!r} absent"
        elif "selector" in step:
            try:
                ok = await page.locator(step["selector"]).first.count() > 0
            except Exception:
                ok = False
            detail = f"expected selector {step['selector']!r}"
        if not ok and not step.get("optional"):
            raise _WorkflowStop(self._mask(f"verify failed: {detail}", secrets))

    async def _do_capture_token(self, step, page, context, captured, secrets):
        name = step["name"]
        src = step.get("from", "localStorage")
        value = None
        if src == "localStorage":
            key = step.get("key", name)
            value = await page.evaluate(f"() => window.localStorage.getItem('{key}')")
        elif src == "cookie":
            for c in await context.cookies():
                if c.get("name") == step.get("key", name):
                    value = c.get("value")
                    break
        elif src == "selector":
            loc = page.locator(step["selector"]).first
            value = await loc.get_attribute(step.get("attr", "value"))
        if value:
            captured[name] = value
            secrets.add(value)  # tokens are always secret
            if step.get("as_header"):
                self._pending_headers[step.get("header", "Authorization")] = (
                    f"{step.get('prefix', 'Bearer ')}{value}"
                )

    async def _do_capture_cookie(self, step, context, captured, secrets):
        name = step["name"]
        for c in await context.cookies():
            if c.get("name") == step.get("cookie", name):
                captured[name] = c.get("value", "")
                secrets.add(c.get("value", ""))  # session cookies are secret
                break

    async def _do_api_request(
        self,
        step,
        context,
        base_url,
        a_timeout,
        captured,
        secrets,
        _fill,
        _record_endpoint,
    ):
        method = str(step.get("method", "GET")).upper()
        url = urljoin(base_url, _fill(step.get("url")))
        if not self._in_scope(url):
            raise _WorkflowStop("api_request target is outside the scan scope")
        req = context.request
        kwargs = {"timeout": a_timeout}
        if step.get("body") is not None:
            kwargs["data"] = _fill(step["body"])
        resp = await req.fetch(url, method=method, **kwargs)
        _record_endpoint(url, method=method)
        if step.get("name"):
            try:
                captured[step["name"]] = await resp.text()
            except Exception:
                pass


class _WorkflowStop(Exception):
    """A deliberate, sanitized stop (a failed non-optional verify)."""
