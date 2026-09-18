"""
core/web/xss/engine.py
────────────────────────────────────────────────────────────────────────────
Active Cross-Site Scripting engine (reflected, DOM, stored).

The existing pipeline relies on nuclei templates for XSS, which — validated
against OWASP Juice Shop — misses reflected and DOM XSS that a browser-driven
active test catches. This engine adds that capability *inside the existing
architecture*: it consumes the endpoints and forms the CRAWL phase already
produced, reuses the authenticated session RECON/CRAWL established, emits
findings in the same dict shape ``_persist_web_findings`` reads, and is invoked
as one more tool inside ``run_detect`` beside nuclei and sqlmap.

Detection is by **proof of execution**, never by reflection:

* a fresh, unique sentinel token is injected per (endpoint, parameter, payload);
* the payload's only effect is to call ``window.__ccure_xss_probe(token)``;
* a finding is raised only when that call actually reaches the browser.

So a value that is reflected but correctly encoded — the safe case — is inert
and never reported, and a value that executes is reported with the browser
event as evidence. The three variants differ only by delivery vector, which is
what lets the engine label them without guessing:

* **reflected** — payload sent to the server in a query/form parameter and
  executed in the response;
* **dom** — payload placed in the URL fragment, which never leaves the browser,
  so execution proves a client-side sink;
* **stored** — payload submitted through a form, then found executing on a
  *later* page load.

Everything is bounded and safe by default: same-origin only, capped targets /
parameters / payloads, rate limited, per-navigation timeouts, cancellation
honoured, and payloads that neither exfiltrate nor write to the target.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse

from core.web.xss.payloads import (
    CWE_ID,
    DOM_PAYLOAD_TEMPLATES,
    FINDING_TYPE,
    PAYLOAD_TEMPLATES,
    REMEDIATION,
    SENTINEL,
    SEVERITY,
    SINK_INSTRUMENTATION_JS,
)

log = logging.getLogger("ccure.web.xss")

#: input types that never carry a reflectable value.
_NON_INJECTABLE_INPUT_TYPES = {"submit", "button", "reset", "image", "file", "hidden"}

#: fields never worth spraying: submitting a payload as a password/CSRF token
#: tests nothing and can trip account lockout.
_SKIP_FIELD_NAMES = {"csrf", "csrf_token", "_token", "authenticity_token", "password"}


class XssEngine:
    """
    Browser-driven active XSS tester.

    Bounds (all overridable, safe defaults):
      max_targets            — endpoints/forms considered, most-parameterised first
      max_params_per_target  — parameters tested on one target
      max_payloads_per_param — payloads tried before moving on
      rate_limit             — requests/second ceiling (shared with the scan)
      timeout_ms             — per-navigation timeout
      same_origin_only       — never leave the target's origin
    """

    def __init__(
        self,
        *,
        rate_limit: int = 5,
        max_targets: int = 25,
        max_params_per_target: int = 10,
        max_payloads_per_param: int = 8,
        timeout_ms: int = 8000,
        same_origin_only: bool = True,
        test_reflected: bool = True,
        test_dom: bool = True,
        test_stored: bool = True,
    ) -> None:
        self.rate_limit = max(1, int(rate_limit or 1))
        self.max_targets = max_targets
        self.max_params_per_target = max_params_per_target
        self.max_payloads_per_param = max_payloads_per_param
        self.timeout_ms = timeout_ms
        self.same_origin_only = same_origin_only
        self.test_reflected = test_reflected
        self.test_dom = test_dom
        self.test_stored = test_stored

        # Per-test execution oracle state, reset before each navigation.
        self._fired: set[str] = set()
        self._sinks: List[str] = []
        self._min_interval = 1.0 / self.rate_limit
        self._last_request = 0.0
        self.stats: Dict[str, Any] = {
            "targets_tested": 0,
            "parameters_tested": 0,
            "payloads_sent": 0,
            "requests": 0,
            "reflected": 0,
            "dom": 0,
            "stored": 0,
            "duration_s": 0.0,
        }

    # ── availability ────────────────────────────────────────────────────────
    def is_available(self) -> bool:
        try:
            import playwright.async_api  # noqa: F401

            return True
        except Exception:
            return False

    # ── oracle ──────────────────────────────────────────────────────────────
    def _sentinel(self, value: str = "") -> None:
        """Called from the page whenever a payload (or a hooked sink) fires."""
        v = str(value)
        if v.startswith("SINK:"):
            self._sinks.append(v[5:])
        else:
            self._fired.add(v)

    def _reset(self) -> None:
        self._fired = set()
        self._sinks = []

    async def _throttle(self) -> None:
        now = time.monotonic()
        wait = self._min_interval - (now - self._last_request)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request = time.monotonic()

    # ── public entrypoint ───────────────────────────────────────────────────
    async def scan(
        self,
        target_url: str,
        endpoints: List[dict],
        forms: List[dict],
        auth_headers: Optional[dict] = None,
        auth_cookies: Optional[list] = None,
        options: Optional[dict] = None,
        waf_detected: Optional[str] = None,
        progress_cb: Optional[Callable[[str], None]] = None,
        cancel_cb: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        """Run the enabled XSS variants and return findings + stats."""
        t0 = time.monotonic()
        findings: List[dict] = []
        if not self.is_available():
            return {"findings": findings, "stats": self.stats, "available": False}

        from playwright.async_api import async_playwright

        origin = urlparse(target_url)
        self._origin_netloc = origin.netloc

        def _cancelled() -> bool:
            try:
                return bool(cancel_cb and cancel_cb())
            except Exception:
                return False

        def _progress(msg: str) -> None:
            try:
                if progress_cb:
                    progress_cb(msg)
            except Exception:
                pass

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage"],
                )
                context = await browser.new_context(ignore_https_errors=True)
                # Reuse the session RECON/CRAWL established, exactly as the
                # crawler does — otherwise every protected page is untested.
                if auth_cookies:
                    try:
                        await context.add_cookies(auth_cookies)
                    except Exception as exc:
                        log.debug("xss: could not set auth cookies: %s", exc)
                if auth_headers:
                    try:
                        await context.set_extra_http_headers(auth_headers)
                    except Exception as exc:
                        log.debug("xss: could not set auth headers: %s", exc)

                # One binding for the whole context: every page and navigation
                # can reach window.__ccure_xss_probe.
                await context.expose_function(SENTINEL, self._sentinel)
                await context.add_init_script(SINK_INSTRUMENTATION_JS)
                # A real alert() from a payload is also proof — dismiss it so it
                # cannot block, and record a token-bearing message.
                page = await context.new_page()
                page.on("dialog", self._on_dialog)

                if self.test_reflected and not _cancelled():
                    _progress("XSS: testing reflected parameters…")
                    findings += await self._scan_reflected(
                        page, target_url, endpoints, forms, _cancelled
                    )
                if self.test_dom and not _cancelled():
                    _progress("XSS: testing DOM sinks…")
                    findings += await self._scan_dom(
                        page, target_url, endpoints, _cancelled
                    )
                if self.test_stored and not _cancelled():
                    _progress("XSS: testing stored inputs…")
                    findings += await self._scan_stored(
                        page, target_url, forms, _cancelled
                    )

                await context.close()
                await browser.close()
        except Exception as exc:
            log.warning("xss engine error: %s", exc)

        self.stats["duration_s"] = round(time.monotonic() - t0, 2)
        return {"findings": findings, "stats": self.stats, "available": True}

    def _on_dialog(self, dialog) -> None:
        try:
            msg = dialog.message or ""
            if msg:
                self._fired.add(msg)
        finally:
            try:
                asyncio.ensure_future(dialog.dismiss())
            except Exception:
                pass

    # ── scope ───────────────────────────────────────────────────────────────
    def _in_scope(self, url: str) -> bool:
        if not self.same_origin_only:
            return True
        try:
            return urlparse(url).netloc == self._origin_netloc
        except Exception:
            return False

    # ── reflected ───────────────────────────────────────────────────────────
    def _reflected_candidates(self, target_url, endpoints, forms) -> List[dict]:
        """
        (url, method, param, base_params) tuples worth testing, richest first.

        Query parameters come from endpoints (and the target itself); form
        fields come from discovered forms. Mirrors build_injection_targets so
        the XSS engine tests the same surface sqlmap does.
        """
        cands: List[dict] = []
        seen: set = set()

        def _add_query(url: str, method: str):
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            if not params:
                return
            base = parsed._replace(query="").geturl()
            names = [n for n, _ in params]
            for name in names[: self.max_params_per_target]:
                key = (method, base, name, "query")
                if key in seen or not self._in_scope(url):
                    continue
                seen.add(key)
                cands.append(
                    {
                        "url": base,
                        "method": method,
                        "param": name,
                        "params": params,
                        "kind": "query",
                    }
                )

        _add_query(target_url, "GET")
        for ep in endpoints or []:
            if isinstance(ep, dict) and ep.get("url"):
                _add_query(ep["url"], "GET")

        for form in forms or []:
            if not isinstance(form, dict):
                continue
            url = form.get("url", "")
            if not url or not self._in_scope(url):
                continue
            method = str(form.get("method") or "GET").upper()
            fields = [
                inp.get("name")
                for inp in form.get("inputs") or []
                if isinstance(inp, dict)
                and inp.get("name")
                and str(inp.get("type", "")).lower() not in _NON_INJECTABLE_INPUT_TYPES
                and str(inp.get("name", "")).lower() not in _SKIP_FIELD_NAMES
            ]
            fields = fields[: self.max_params_per_target]
            for name in fields:
                key = (method, url, name, "form")
                if key in seen:
                    continue
                seen.add(key)
                cands.append(
                    {
                        "url": url,
                        "method": method,
                        "param": name,
                        "fields": fields,
                        "kind": "form",
                    }
                )
        # Most-parameterised targets first, then cap.
        return cands[: self.max_targets * self.max_params_per_target]

    async def _scan_reflected(self, page, target_url, endpoints, forms, cancelled):
        findings: List[dict] = []
        candidates = self._reflected_candidates(target_url, endpoints, forms)
        tested_targets: set = set()
        for cand in candidates:
            if cancelled():
                break
            self.stats["parameters_tested"] += 1
            tested_targets.add(cand["url"])
            hit = await self._probe_param(page, cand)
            if hit:
                findings.append(hit)
        self.stats["targets_tested"] = len(tested_targets)
        self.stats["reflected"] = sum(1 for f in findings if f)
        return [f for f in findings if f]

    async def _probe_param(self, page, cand) -> Optional[dict]:
        for ctx_label, template in PAYLOAD_TEMPLATES[: self.max_payloads_per_param]:
            token = "cx" + secrets.token_hex(8)
            payload = template.format(sentinel=SENTINEL, token=token)
            self.stats["payloads_sent"] += 1
            try:
                if cand["kind"] == "query":
                    await self._deliver_query(page, cand, payload)
                else:
                    if cand["method"] == "POST":
                        await self._deliver_form_post(page, cand, payload)
                    else:
                        await self._deliver_form_get(page, cand, payload)
            except Exception as exc:
                log.debug("xss reflected delivery failed: %s", exc)
                continue
            if token in self._fired:
                return self._make_finding("reflected", cand, ctx_label, payload, token)
        return None

    async def _deliver_query(self, page, cand, payload):
        params = [(n, payload if n == cand["param"] else v) for n, v in cand["params"]]
        url = urlparse(cand["url"])._replace(query=urlencode(params)).geturl()
        await self._navigate(page, url)

    async def _deliver_form_get(self, page, cand, payload):
        params = [(n, payload if n == cand["param"] else "1") for n in cand["fields"]]
        url = urlparse(cand["url"])._replace(query=urlencode(params)).geturl()
        await self._navigate(page, url)

    async def _deliver_form_post(self, page, cand, payload):
        # An auto-submitting form renders the POST *response* in the browser, so
        # the execution oracle sees reflected output a raw HTTP client cannot.
        inputs = "".join(
            f'<input name="{_html_attr(n)}" value="{_html_attr(payload if n == cand["param"] else "1")}">'
            for n in cand["fields"]
        )
        html = (
            f'<form id="f" method="POST" action="{_html_attr(cand["url"])}">'
            f"{inputs}</form>"
        )
        self._reset()
        await self._throttle()
        await page.set_content(html, wait_until="domcontentloaded")
        try:
            async with page.expect_navigation(timeout=self.timeout_ms):
                await page.evaluate("document.getElementById('f').submit()")
        except Exception:
            pass
        await self._settle(page)
        self.stats["requests"] += 1

    # ── DOM ─────────────────────────────────────────────────────────────────
    async def _scan_dom(self, page, target_url, endpoints, cancelled):
        findings: List[dict] = []
        urls = [target_url]
        for ep in endpoints or []:
            if isinstance(ep, dict) and ep.get("url") and self._in_scope(ep["url"]):
                urls.append(ep["url"])
        # De-dup by path; the fragment is what we vary.
        seen: set = set()
        pruned = []
        for u in urls:
            key = urlparse(u)._replace(query="", fragment="").geturl()
            if key not in seen:
                seen.add(key)
                pruned.append(key)
        for base in pruned[: self.max_targets]:
            if cancelled():
                break
            hit = await self._probe_dom(page, base)
            if hit:
                findings.append(hit)
        self.stats["dom"] = len(findings)
        return findings

    async def _probe_dom(self, page, base) -> Optional[dict]:
        for ctx_label, template in DOM_PAYLOAD_TEMPLATES[: self.max_payloads_per_param]:
            token = "cd" + secrets.token_hex(8)
            payload = template.format(sentinel=SENTINEL, token=token)
            self.stats["payloads_sent"] += 1
            # The fragment never reaches the server, so execution here is a
            # DOM sink by construction. Two delivery vectors, because apps read
            # the fragment either on initial load or on a hashchange:
            #   A) navigate with the fragment already present;
            #   B) set location.hash after load and dispatch hashchange.
            try:
                self._reset()
                await self._throttle()
                await page.goto(
                    f"{base}#{payload}",
                    wait_until="domcontentloaded",
                    timeout=self.timeout_ms,
                )
                await self._settle(page)
                self.stats["requests"] += 1
                if token in self._fired:
                    cand = {"url": base, "method": "GET", "param": "#fragment"}
                    return self._make_finding("dom", cand, ctx_label, payload, token)
            except Exception as exc:
                log.debug("xss dom delivery (load) failed: %s", exc)

            try:
                self._reset()
                await self._throttle()
                await page.goto(
                    base, wait_until="domcontentloaded", timeout=self.timeout_ms
                )
                await page.evaluate(
                    "(p) => { location.hash = p; "
                    "window.dispatchEvent(new HashChangeEvent('hashchange')); }",
                    payload,
                )
                await self._settle(page)
                self.stats["requests"] += 1
                if token in self._fired:
                    cand = {"url": base, "method": "GET", "param": "#fragment"}
                    return self._make_finding("dom", cand, ctx_label, payload, token)
            except Exception as exc:
                log.debug("xss dom delivery (hashchange) failed: %s", exc)
        return None

    # ── stored ──────────────────────────────────────────────────────────────
    async def _scan_stored(self, page, target_url, forms, cancelled):
        findings: List[dict] = []
        count = 0
        for form in forms or []:
            if cancelled() or count >= self.max_targets:
                break
            if not isinstance(form, dict):
                continue
            url = form.get("url", "")
            page_url = form.get("page_url") or url
            if not url or not self._in_scope(url):
                continue
            fields = [
                inp.get("name")
                for inp in form.get("inputs") or []
                if isinstance(inp, dict)
                and inp.get("name")
                and str(inp.get("type", "")).lower() not in _NON_INJECTABLE_INPUT_TYPES
                and str(inp.get("name", "")).lower() not in _SKIP_FIELD_NAMES
            ]
            if not fields:
                continue
            count += 1
            hit = await self._probe_stored(page, form, url, page_url, fields)
            if hit:
                findings.append(hit)
        self.stats["stored"] = len(findings)
        return findings

    async def _probe_stored(self, page, form, url, page_url, fields):
        method = str(form.get("method") or "POST").upper()
        # One auto-firing payload is enough to prove persistence; more submits
        # just add rows to the target.
        ctx_label, template = PAYLOAD_TEMPLATES[1]  # img onerror — robust
        token = "cs" + secrets.token_hex(8)
        payload = template.format(sentinel=SENTINEL, token=token)
        self.stats["payloads_sent"] += 1
        # Submit.
        try:
            inputs = "".join(
                f'<input name="{_html_attr(n)}" value="{_html_attr(payload if i == 0 else "1")}">'
                for i, n in enumerate(fields)
            )
            html = f'<form id="f" method="{method}" action="{_html_attr(url)}">{inputs}</form>'
            self._reset()
            await self._throttle()
            await page.set_content(html, wait_until="domcontentloaded")
            try:
                async with page.expect_navigation(timeout=self.timeout_ms):
                    await page.evaluate("document.getElementById('f').submit()")
            except Exception:
                pass
            await self._settle(page)
            self.stats["requests"] += 1
        except Exception as exc:
            log.debug("xss stored submit failed: %s", exc)
            return None
        fired_on_submit = token in self._fired
        # Revisit a fresh page load; execution here (not merely on submit) is
        # persistence.
        try:
            self._reset()
            await self._throttle()
            await page.goto(
                page_url, wait_until="domcontentloaded", timeout=self.timeout_ms
            )
            await self._settle(page)
            self.stats["requests"] += 1
        except Exception as exc:
            log.debug("xss stored revisit failed: %s", exc)
            return None
        if token in self._fired:
            cand = {"url": page_url, "method": method, "param": fields[0]}
            finding = self._make_finding("stored", cand, ctx_label, payload, token)
            finding["description"] += (
                " The payload executed on a fresh load of the page after being "
                "submitted through the form, which demonstrates it was persisted "
                "server-side (stored XSS)."
            )
            return finding
        if fired_on_submit:
            # Executed on submit but not on revisit — that is reflected, not
            # stored; the reflected pass will have reported it if in scope.
            return None
        return None

    # ── navigation helpers ──────────────────────────────────────────────────
    async def _navigate(self, page, url):
        self._reset()
        await self._throttle()
        await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
        await self._settle(page)
        self.stats["requests"] += 1

    async def _settle(self, page):
        # Give onload/onerror/hashchange handlers a bounded moment to run.
        try:
            await page.wait_for_timeout(250)
        except Exception:
            pass

    # ── finding ─────────────────────────────────────────────────────────────
    def _make_finding(self, variant, cand, ctx_label, payload, token) -> dict:
        url = cand.get("url", "")
        param = cand.get("param", "")
        method = cand.get("method", "GET")
        sinks = ", ".join(sorted(set(self._sinks))) if self._sinks else ""
        title = (
            f"{variant.upper()} Cross-Site Scripting (XSS) in " f"'{param}' at {url}"
        )
        desc = (
            f"An active test proved script execution: a unique payload injected "
            f"into the '{param}' parameter ({method}) caused the browser to run "
            f"attacker-controlled JavaScript (confirmed by the execution sentinel "
            f"firing with token {token}). Output context: {ctx_label}."
        )
        if sinks:
            desc += f" Client-side sink(s) reached: {sinks}."
        return {
            "finding_type": FINDING_TYPE,
            "title": title[:255],
            "description": desc,
            "severity": SEVERITY.get(variant, "high"),
            "detected_by": "ccure-xss",
            "cwe_id": CWE_ID,
            "matched_at": url,
            "request_url": url,
            "request_method": method,
            "payload_used": payload,
            "request_evidence": f"parameter={param}; context={ctx_label}; variant={variant}",
            "response_evidence": (
                f"Browser executed the injected script (sentinel token {token})."
                + (f" DOM sink(s): {sinks}." if sinks else "")
            ),
            "remediation": REMEDIATION.get(variant, REMEDIATION["reflected"]),
            "is_verified": True,
            "confidence": "confirmed",
            "xss_variant": variant,
        }


def _html_attr(value: str) -> str:
    """Minimal escaping for values placed inside a double-quoted HTML attribute
    of the *harness* form (not the payload's target). Keeps the auto-submit form
    well-formed; the payload itself is delivered as the field value verbatim."""
    return (
        str(value)
        .replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
