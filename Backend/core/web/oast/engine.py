"""
core/web/oast/engine.py
────────────────────────────────────────────────────────────────────────────
Active out-of-band (OAST) probe engine (Phase 9).

Injects payloads that, if the target is vulnerable, cause it to call back to a
collaborator the scanner controls, then polls the collaborator and correlates
each callback to the payload that caused it. Used only for the classes where a
callback is the *only* available evidence:

  • **Blind SSRF** — a parameter value pointing at the collaborator; a
    server-side fetch is the callback.
  • **Out-of-band OS command injection** — a shelled-out ``nslookup``/``curl``
    to the collaborator. Non-destructive: a name lookup / GET, never a
    file-modifying or system-altering command.
  • **Blind XXE** — an external general entity resolving to the collaborator's
    HTTP URL, sent only where the endpoint accepts XML. Points at the
    collaborator, never at ``file://`` or an internal address.

Integrated like every other Phase 1–7 engine: consumes the CRAWL phase's
endpoints/forms, reuses the authenticated session, is same-origin by default,
rate-limited, cancellation- and timeout-aware, and emits findings in the shape
``_persist_web_findings`` reads. It runs only when a self-hosted collaborator is
configured, so it never depends on outbound internet or a third-party service.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse

log = logging.getLogger("ccure.web.oast.engine")

_NON_INJECTABLE_INPUT_TYPES = {"submit", "button", "reset", "image", "file", "hidden"}
_SKIP_FIELD_NAMES = {"csrf", "csrf_token", "_token", "authenticity_token", "password"}
_ALL_CLASSES = ("ssrf", "command_injection", "xxe")


class OastEngine:
    def __init__(
        self,
        session,
        client,
        *,
        rate_limit: int = 5,
        max_targets: int = 25,
        max_params_per_target: int = 10,
        timeout_s: float = 15.0,
        poll_timeout_s: float = 30.0,
        poll_interval_s: float = 2.0,
        classes: Optional[tuple] = None,
        same_origin_only: bool = True,
        verify_tls: bool = False,
    ) -> None:
        self.session = session
        self.client = client
        self.rate_limit = max(1, int(rate_limit or 1))
        self.max_targets = max_targets
        self.max_params_per_target = max_params_per_target
        self.timeout_s = timeout_s
        self.poll_timeout_s = poll_timeout_s
        self.poll_interval_s = max(0.2, float(poll_interval_s))
        self.classes = tuple(classes or _ALL_CLASSES)
        self.same_origin_only = same_origin_only
        self.verify_tls = verify_tls

        self._min_interval = 1.0 / self.rate_limit
        self._last_request = 0.0
        self.stats: Dict[str, Any] = {
            "parameters_probed": 0,
            "payloads_sent": 0,
            "interactions": 0,
            "duration_s": 0.0,
            **{c: 0 for c in _ALL_CLASSES},
        }

    def is_available(self) -> bool:
        try:
            import httpx  # noqa: F401
        except Exception:
            return False
        return self.session is not None and self.client is not None

    async def _throttle(self) -> None:
        now = time.monotonic()
        wait = self._min_interval - (now - self._last_request)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request = time.monotonic()

    # ── payload construction ──────────────────────────────────────────────────
    def _cmdi_payloads(self, token: str) -> List[str]:
        domain = self.session.domain_for(token)
        url = self.session.http_url_for(token)
        # Non-destructive callbacks only: DNS lookup + HTTP GET, several shell
        # syntaxes so one of them lands in a vulnerable context.
        return [
            f";nslookup {domain};",
            f"|nslookup {domain}",
            f"$(nslookup {domain})",
            f"`nslookup {domain}`",
            f";curl -s {url};",
            f"&& curl -s {url}",
        ]

    def _ssrf_payloads(self, token: str) -> List[str]:
        return [self.session.http_url_for(token)]

    def _xxe_body(self, token: str) -> str:
        url = self.session.http_url_for(token)
        return (
            f'<?xml version="1.0"?>'
            f'<!DOCTYPE r [<!ENTITY x SYSTEM "{url}">]>'
            f"<r>&x;</r>"
        )

    # ── target enumeration ────────────────────────────────────────────────────
    def _same_origin(self, url: str) -> bool:
        if not self.same_origin_only:
            return True
        return urlparse(url).netloc == self._origin_netloc

    def _query_targets(self, endpoints: List[dict]) -> List[dict]:
        targets = []
        for ep in endpoints or []:
            url = ep.get("url") or ep.get("request_url") or ""
            if not url or not self._same_origin(url):
                continue
            params = [k for k, _ in parse_qsl(urlparse(url).query)]
            if not params:
                continue
            targets.append(
                {
                    "url": url,
                    "method": (ep.get("method") or "GET").upper(),
                    "params": params[: self.max_params_per_target],
                    "kind": "query",
                }
            )
        return targets

    def _form_targets(self, forms: List[dict]) -> List[dict]:
        targets = []
        for form in forms or []:
            action = form.get("action") or form.get("url") or ""
            if not action or not self._same_origin(action):
                continue
            fields = []
            for inp in form.get("inputs", []) or form.get("fields", []) or []:
                name = inp.get("name")
                itype = (inp.get("type") or "text").lower()
                if not name or itype in _NON_INJECTABLE_INPUT_TYPES:
                    continue
                if name.lower() in _SKIP_FIELD_NAMES:
                    continue
                fields.append(name)
            if not fields:
                continue
            targets.append(
                {
                    "url": action,
                    "method": (form.get("method") or "POST").upper(),
                    "params": fields[: self.max_params_per_target],
                    "kind": "form",
                    "content_type": (form.get("content_type") or "").lower(),
                }
            )
        return targets

    # ── sending ───────────────────────────────────────────────────────────────
    async def _send_query(self, client, url, method, param, value):
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query)
        new_pairs = [(k, (value if k == param else v)) for k, v in pairs]
        new_url = parsed._replace(query=urlencode(new_pairs)).geturl()
        await self._throttle()
        try:
            await client.request(method, new_url, timeout=self.timeout_s)
            self.stats["payloads_sent"] += 1
        except Exception:
            pass

    async def _send_form(self, client, url, method, data):
        await self._throttle()
        try:
            if method == "GET":
                await client.get(url, params=data, timeout=self.timeout_s)
            else:
                await client.post(url, data=data, timeout=self.timeout_s)
            self.stats["payloads_sent"] += 1
        except Exception:
            pass

    async def _send_xml(self, client, url, method, body):
        await self._throttle()
        try:
            await client.request(
                method if method != "GET" else "POST",
                url,
                content=body.encode(),
                headers={"Content-Type": "application/xml"},
                timeout=self.timeout_s,
            )
            self.stats["payloads_sent"] += 1
        except Exception:
            pass

    # ── entrypoint ────────────────────────────────────────────────────────────
    async def scan(
        self,
        target_url: str,
        endpoints: List[dict],
        forms: List[dict],
        auth_headers: Optional[dict] = None,
        auth_cookies: Optional[list] = None,
        options: Optional[dict] = None,
        progress_cb: Optional[Callable[[str], None]] = None,
        cancel_cb: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        t0 = time.monotonic()
        findings: List[dict] = []
        if not self.is_available():
            return {"findings": findings, "stats": self.stats, "available": False}

        import httpx

        self._origin_netloc = urlparse(target_url).netloc

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

        targets = (self._query_targets(endpoints) + self._form_targets(forms))[
            : self.max_targets
        ]
        if not targets:
            self.stats["duration_s"] = round(time.monotonic() - t0, 2)
            return {"findings": findings, "stats": self.stats, "available": True}

        poll_start = time.monotonic()
        headers = dict(auth_headers or {})
        cookies = {}
        for c in auth_cookies or []:
            if isinstance(c, dict) and c.get("name"):
                cookies[c["name"]] = c.get("value", "")

        async with httpx.AsyncClient(
            verify=self.verify_tls,
            headers=headers,
            cookies=cookies,
            follow_redirects=False,
        ) as client:
            for tgt in targets:
                if _cancelled():
                    break
                for param in tgt["params"]:
                    if _cancelled():
                        break
                    self.stats["parameters_probed"] += 1
                    # SSRF + command injection go into any parameter.
                    if "ssrf" in self.classes:
                        tok = self.session.mint(
                            "ssrf",
                            url=tgt["url"],
                            param=param,
                            method=tgt["method"],
                            payload_kind="oob-url",
                        )
                        self.stats["ssrf"] += 1
                        val = self._ssrf_payloads(tok)[0]
                        if tgt["kind"] == "query":
                            await self._send_query(
                                client, tgt["url"], tgt["method"], param, val
                            )
                        else:
                            await self._send_form(
                                client, tgt["url"], tgt["method"], {param: val}
                            )
                    if "command_injection" in self.classes:
                        for pl in self._cmdi_payloads(
                            self.session.mint(
                                "command_injection",
                                url=tgt["url"],
                                param=param,
                                method=tgt["method"],
                                payload_kind="oob-cmd",
                            )
                        ):
                            if _cancelled():
                                break
                            if tgt["kind"] == "query":
                                await self._send_query(
                                    client, tgt["url"], tgt["method"], param, pl
                                )
                            else:
                                await self._send_form(
                                    client, tgt["url"], tgt["method"], {param: pl}
                                )
                        self.stats["command_injection"] += 1
                # XXE at the endpoint level (whole-body), where XML is accepted.
                if "xxe" in self.classes and (
                    tgt["kind"] == "form"
                    and "xml" in (tgt.get("content_type") or "")
                    or tgt["kind"] == "query"
                ):
                    if _cancelled():
                        break
                    tok = self.session.mint(
                        "xxe",
                        url=tgt["url"],
                        param="(xml body)",
                        method=tgt["method"],
                        payload_kind="oob-xxe",
                    )
                    self.stats["xxe"] += 1
                    await self._send_xml(
                        client, tgt["url"], tgt["method"], self._xxe_body(tok)
                    )

            _progress("OAST payloads sent; awaiting out-of-band interactions")

            # ── poll + correlate ──────────────────────────────────────────────
            deadline = poll_start + self.poll_timeout_s
            wanted = self.session.tokens()
            seen_tokens: set = set()
            interactions: List[dict] = []
            while time.monotonic() < deadline and not _cancelled():
                batch = self.client.poll(since=0.0)
                for it in batch:
                    tok = str(it.get("token") or "").lower()
                    if self.session.owns(tok):
                        interactions.append(it)
                        seen_tokens.add(tok)
                # Every payload we sent has already called back — nothing more to wait for.
                if wanted and seen_tokens >= wanted:
                    break
                await asyncio.sleep(self.poll_interval_s)

            self.stats["interactions"] = len(
                {(i.get("token"), i.get("protocol")) for i in interactions}
            )
            findings = self.session.correlate(interactions)

        self.stats["duration_s"] = round(time.monotonic() - t0, 2)
        return {"findings": findings, "stats": self.stats, "available": True}
