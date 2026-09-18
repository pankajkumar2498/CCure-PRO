"""
core/web/http_methods/engine.py
────────────────────────────────────────────────────────────────────────────
Systematic HTTP method / verb security testing (Phase 6).

Read-only and safe by default. It sends only non-mutating verbs — OPTIONS,
HEAD, GET and TRACE — unless the operator explicitly enables write testing.
Nothing is created, modified or deleted.

It looks for two confirmed conditions, plus an advisory:

* **Cross-Site Tracing / TRACE enabled** (CWE-693): a TRACE request is answered
  200 and echoes a marker header the scanner sent — proof the method is on.
* **Method-based authentication bypass** (CWE-288): an endpoint that denies an
  anonymous GET (it requires auth, confirmed because the authenticated session
  *can* GET it) nonetheless answers an anonymous HEAD with success — the auth
  check is tied to the verb, so an alternate verb reaches the functionality.
  HEAD is used precisely because it is safe (no body, no side effect).
* **Dangerous verbs advertised** (advisory): OPTIONS Allow lists write verbs;
  reported low and only confirmed by actually sending them when write testing
  is explicitly enabled.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

log = logging.getLogger("ccure.web.httpmethods")

_SAFE_METHODS = ("OPTIONS", "HEAD", "GET", "TRACE")
_WRITE_METHODS = ("PUT", "PATCH", "DELETE", "POST")
_DENY_STATUS = {401, 403, 407}


class HttpMethodEngine:
    def __init__(
        self,
        *,
        rate_limit: int = 5,
        max_endpoints: int = 30,
        timeout_s: float = 15.0,
        same_origin_only: bool = True,
        allow_write_testing: bool = False,
        verify_tls: bool = False,
    ) -> None:
        self.rate_limit = max(1, int(rate_limit or 1))
        self.max_endpoints = max_endpoints
        self.timeout_s = timeout_s
        self.same_origin_only = same_origin_only
        self.allow_write_testing = allow_write_testing
        self.verify_tls = verify_tls
        self._min_interval = 1.0 / self.rate_limit
        self._last = 0.0
        self.stats: Dict[str, Any] = {
            "endpoints_tested": 0,
            "requests": 0,
            "duration_s": 0.0,
            "insecure_http_method": 0,
            "http_method_auth_bypass": 0,
        }

    def is_available(self) -> bool:
        try:
            import httpx  # noqa: F401

            return True
        except Exception:
            return False

    async def _throttle(self):
        wait = self._min_interval - (time.monotonic() - self._last)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last = time.monotonic()

    async def scan(
        self,
        target_url: str,
        endpoints: List[dict],
        owner: Optional[dict] = None,
        progress_cb: Optional[Callable[[str], None]] = None,
        cancel_cb: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        t0 = time.monotonic()
        findings: List[dict] = []
        if not self.is_available():
            return {"findings": findings, "stats": self.stats, "available": False}

        import httpx

        self._origin = urlparse(target_url).netloc

        def _cancelled():
            try:
                return bool(cancel_cb and cancel_cb())
            except Exception:
                return False

        owner_headers = (
            {
                k: v
                for k, v in (owner or {}).get("headers", {}).items()
                if k.lower() != "cookie"
            }
            if owner
            else {}
        )
        owner_cookies = (owner or {}).get("cookies", {}) if owner else {}

        try:
            async with httpx.AsyncClient(
                verify=self.verify_tls, timeout=self.timeout_s, follow_redirects=False
            ) as anon, httpx.AsyncClient(
                verify=self.verify_tls,
                timeout=self.timeout_s,
                follow_redirects=False,
                headers=owner_headers or None,
                cookies=owner_cookies or None,
            ) as owner_c:
                # 1. TRACE / Cross-Site Tracing (origin-level, one probe).
                if not _cancelled():
                    f = await self._trace(anon, target_url)
                    if f:
                        findings.append(f)

                # 2. Per-endpoint method analysis.
                urls = self._targets(target_url, endpoints)
                for i, url in enumerate(urls):
                    if _cancelled():
                        break
                    self.stats["endpoints_tested"] += 1
                    if progress_cb and i % 5 == 0:
                        try:
                            progress_cb(f"HTTP methods: endpoint {i + 1}/{len(urls)}…")
                        except Exception:
                            pass
                    findings += await self._analyze(anon, owner_c, url, bool(owner))
        except Exception as exc:
            log.warning("http-method engine error: %s", exc)

        self.stats["duration_s"] = round(time.monotonic() - t0, 2)
        return {"findings": findings, "stats": self.stats, "available": True}

    def _targets(self, target_url, endpoints) -> List[str]:
        urls, seen = [], set()
        for e in [{"url": target_url}] + list(endpoints or []):
            u = e.get("url") if isinstance(e, dict) else None
            if not u:
                continue
            base = u.split("#")[0]
            key = base
            if key in seen:
                continue
            if self.same_origin_only and urlparse(base).netloc != self._origin:
                continue
            seen.add(key)
            urls.append(base)
            if len(urls) >= self.max_endpoints:
                break
        return urls

    async def _req(self, client, method, url, **kw):
        await self._throttle()
        try:
            r = await client.request(method, url, **kw)
            self.stats["requests"] += 1
            return r
        except Exception:
            self.stats["requests"] += 1
            return None

    async def _trace(self, anon, target_url) -> Optional[dict]:
        marker = "CCureTrace" + secrets.token_hex(6)
        r = await self._req(
            anon, "TRACE", target_url, headers={"X-CCure-Probe": marker}
        )
        if r is not None and r.status_code == 200 and marker in (r.text or ""):
            self.stats["insecure_http_method"] += 1
            return self._finding(
                "insecure_http_method",
                target_url,
                "TRACE",
                "The HTTP TRACE method is enabled: a TRACE request was answered "
                "200 and echoed the request, enabling Cross-Site Tracing (XST), "
                "which can expose headers such as cookies to script in older or "
                "misconfigured stacks.",
                "CWE-693",
                "medium",
                evidence=f"TRACE {target_url} → 200, echoed marker header.",
            )
        return None

    async def _analyze(self, anon, owner_c, url, have_owner) -> List[dict]:
        out: List[dict] = []
        # OPTIONS: enumerate advertised methods (advisory only).
        opt = await self._req(anon, "OPTIONS", url)
        allow = (opt.headers.get("Allow", "") if opt is not None else "").upper()
        dangerous = [
            m for m in ("PUT", "PATCH", "DELETE", "TRACE", "CONNECT") if m in allow
        ]

        # Method-based auth bypass needs an authenticated baseline.
        if have_owner:
            o_get = await self._req(owner_c, "GET", url)
            a_get = await self._req(anon, "GET", url)
            if (
                o_get is not None
                and o_get.status_code == 200
                and a_get is not None
                and (
                    a_get.status_code in _DENY_STATUS
                    or a_get.status_code in (301, 302, 303, 307, 308)
                )
            ):
                # Auth is required for GET (owner in, anon out). Does an
                # alternate *safe* verb bypass it?
                a_head = await self._req(anon, "HEAD", url)
                if a_head is not None and a_head.status_code == 200:
                    self.stats["http_method_auth_bypass"] += 1
                    out.append(
                        self._finding(
                            "http_method_auth_bypass",
                            url,
                            "HEAD",
                            "Authentication is enforced for GET (the authenticated "
                            "session receives 200 while an anonymous GET is denied), "
                            "but an anonymous HEAD request to the same URL returns "
                            "200 — the authorization check is tied to the verb, so an "
                            "alternate method reaches protected functionality.",
                            "CWE-288",
                            "high",
                            evidence=(
                                f"owner GET → {o_get.status_code}; anon GET → "
                                f"{a_get.status_code} (denied); anon HEAD → 200 "
                                f"(bypass)."
                            ),
                        )
                    )
        # Write-verb acceptance — only when explicitly enabled (safe default off).
        if self.allow_write_testing and dangerous:
            for m in ("PUT", "DELETE", "PATCH"):
                if m not in allow:
                    continue
                r = await self._req(anon, m, url)
                if r is not None and r.status_code in (200, 201, 204):
                    out.append(
                        self._finding(
                            "insecure_http_method",
                            url,
                            m,
                            f"The state-changing method {m} was accepted "
                            f"(HTTP {r.status_code}) without authentication.",
                            "CWE-650",
                            "high",
                            evidence=f"{m} {url} → {r.status_code} (write testing enabled).",
                        )
                    )
        return out

    def _finding(self, ftype, url, method, desc, cwe, severity, *, evidence):
        titles = {
            "insecure_http_method": f"Insecure HTTP method ({method})",
            "http_method_auth_bypass": f"HTTP method-based authentication bypass ({method})",
        }
        return {
            "finding_type": ftype,
            "title": f"{titles.get(ftype, ftype)} at {url}"[:255],
            "description": desc,
            "severity": severity,
            "detected_by": "ccure-http-methods",
            "cwe_id": cwe,
            "matched_at": url,
            "request_url": url,
            "request_method": method,
            "response_evidence": evidence,
            "remediation": (
                "Disable the TRACE method and any unused HTTP verbs at the web "
                "server / framework. Enforce authentication and authorization "
                "per-resource for *all* methods (including HEAD and OPTIONS), not "
                "per-verb, and deny by default."
            ),
            "is_verified": True,
            "confidence": "confirmed",
        }
