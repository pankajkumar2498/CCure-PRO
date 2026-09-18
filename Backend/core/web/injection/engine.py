"""
core/web/injection/engine.py
────────────────────────────────────────────────────────────────────────────
Active server-side injection engine (Phase 2): OS command injection, SSTI,
XXE, LDAP injection, XPath injection.

Sibling of the Phase 1 XSS engine and, like it, integrated into the existing
pipeline rather than bolted on: it consumes the endpoints/forms the CRAWL phase
produced, reuses the authenticated session, is driven from
``WebScanOrchestrator.run_detect`` via the ``ToolCoverage`` pattern, emits
findings in the shape ``_persist_web_findings`` reads, honours cancellation and
timeouts, and is rate-limited and same-origin by default.

These classes are server-side, so — unlike XSS — they are tested over HTTP with
``httpx`` (already the orchestrator's client), not a browser. Detection is
evidence-based and never "a suspicious string was reflected":

* **Command injection** — a controlled timing side-channel that must track two
  *different* requested delays while a zero-delay control stays fast, which
  rules out a merely slow endpoint. Payloads are ``sleep``/``ping`` only.
* **SSTI** — the arithmetic *product* of a unique expression appears while the
  literal expression does not (evaluation, not reflection).
* **XXE** — an *internal* canary entity is expanded (no external/file entity is
  ever sent).
* **LDAP / XPath** — a specific parser *error signature* that is absent from the
  baseline (a boolean differential is recorded as supporting evidence).

Nothing here modifies or deletes target data, runs a destructive command, reads
a local file, or calls an external host.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse

from core.web.injection import payloads as P

log = logging.getLogger("ccure.web.injection")

_NON_INJECTABLE_INPUT_TYPES = {"submit", "button", "reset", "image", "file", "hidden"}
_SKIP_FIELD_NAMES = {"csrf", "csrf_token", "_token", "authenticity_token", "password"}

_ALL_CLASSES = ("command_injection", "ssti", "xxe", "ldap_injection", "xpath_injection")


class InjectionEngine:
    """
    HTTP-driven active injection tester.

    Bounds (safe defaults, all overridable):
      max_targets / max_params_per_target — surface considered
      rate_limit                          — requests/second ceiling
      timeout_s                           — per-request timeout (> max CI delay)
      cmdi_delay_1 / cmdi_delay_2         — the two timing probes that must track
      same_origin_only                    — never leave the target's origin
    """

    def __init__(
        self,
        *,
        rate_limit: int = 5,
        max_targets: int = 25,
        max_params_per_target: int = 10,
        timeout_s: float = 20.0,
        cmdi_delay_1: int = 5,
        cmdi_delay_2: int = 8,
        same_origin_only: bool = True,
        classes: Optional[tuple] = None,
        verify_tls: bool = False,
    ) -> None:
        self.rate_limit = max(1, int(rate_limit or 1))
        self.max_targets = max_targets
        self.max_params_per_target = max_params_per_target
        self.timeout_s = timeout_s
        self.cmdi_delay_1 = cmdi_delay_1
        self.cmdi_delay_2 = cmdi_delay_2
        self.same_origin_only = same_origin_only
        self.classes = tuple(classes or _ALL_CLASSES)
        self.verify_tls = verify_tls

        self._min_interval = 1.0 / self.rate_limit
        self._last_request = 0.0
        self.stats: Dict[str, Any] = {
            "parameters_tested": 0,
            "requests": 0,
            "duration_s": 0.0,
            **{c: 0 for c in _ALL_CLASSES},
        }

    # ── availability ────────────────────────────────────────────────────────
    def is_available(self) -> bool:
        try:
            import httpx  # noqa: F401

            return True
        except Exception:
            return False

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

        cookies = {}
        for c in auth_cookies or []:
            if isinstance(c, dict) and c.get("name"):
                cookies[c["name"]] = c.get("value", "")

        try:
            async with httpx.AsyncClient(
                verify=self.verify_tls,
                timeout=self.timeout_s,
                follow_redirects=True,
                headers=auth_headers or None,
                cookies=cookies or None,
            ) as client:
                self._client = client
                param_cands = self._param_candidates(target_url, endpoints, forms)
                post_targets = self._post_targets(target_url, forms)

                for i, cand in enumerate(param_cands):
                    if _cancelled():
                        break
                    self.stats["parameters_tested"] += 1
                    if i % 5 == 0:
                        _progress(f"Injection: parameter {i + 1}/{len(param_cands)}…")
                    findings += await self._probe_param(cand, _cancelled)

                if "xxe" in self.classes:
                    for turl in post_targets:
                        if _cancelled():
                            break
                        hit = await self._probe_xxe(turl)
                        if hit:
                            findings.append(hit)
        except Exception as exc:
            log.warning("injection engine error: %s", exc)

        self.stats["duration_s"] = round(time.monotonic() - t0, 2)
        return {"findings": findings, "stats": self.stats, "available": True}

    # ── candidate model (mirrors the XSS engine / build_injection_targets) ────
    def _in_scope(self, url: str) -> bool:
        if not self.same_origin_only:
            return True
        try:
            return urlparse(url).netloc == self._origin_netloc
        except Exception:
            return False

    def _param_candidates(self, target_url, endpoints, forms) -> List[dict]:
        cands: List[dict] = []
        seen: set = set()

        def _add_query(url: str):
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            if not params:
                return
            base = parsed._replace(query="").geturl()
            for name in [n for n, _ in params][: self.max_params_per_target]:
                key = ("GET", base, name)
                if key in seen or not self._in_scope(url):
                    continue
                seen.add(key)
                cands.append(
                    {
                        "url": base,
                        "method": "GET",
                        "param": name,
                        "params": params,
                        "kind": "query",
                    }
                )

        _add_query(target_url)
        for ep in endpoints or []:
            if isinstance(ep, dict) and ep.get("url"):
                _add_query(ep["url"])

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
            ][: self.max_params_per_target]
            for name in fields:
                key = (method, url, name)
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
        return cands[: self.max_targets * self.max_params_per_target]

    def _post_targets(self, target_url, forms) -> List[str]:
        urls: List[str] = []
        seen: set = set()
        for form in forms or []:
            if not isinstance(form, dict):
                continue
            if str(form.get("method") or "GET").upper() != "POST":
                continue
            url = form.get("url", "")
            if url and self._in_scope(url) and url not in seen:
                seen.add(url)
                urls.append(url)
        return urls[: self.max_targets]

    # ── request helper ────────────────────────────────────────────────────────
    async def _send(self, cand, value) -> tuple[int, float, str]:
        """Send one request injecting ``value`` into the candidate's parameter."""
        await self._throttle()
        method = cand["method"]
        t = time.monotonic()
        try:
            if cand["kind"] == "query":
                params = [
                    (n, value if n == cand["param"] else v) for n, v in cand["params"]
                ]
                url = urlparse(cand["url"])._replace(query=urlencode(params)).geturl()
                resp = await self._client.get(url)
            elif method == "POST":
                data = {
                    n: (value if n == cand["param"] else "1") for n in cand["fields"]
                }
                resp = await self._client.post(cand["url"], data=data)
            else:  # form GET
                params = [
                    (n, value if n == cand["param"] else "1") for n in cand["fields"]
                ]
                url = urlparse(cand["url"])._replace(query=urlencode(params)).geturl()
                resp = await self._client.get(url)
            elapsed = time.monotonic() - t
            self.stats["requests"] += 1
            return resp.status_code, elapsed, resp.text
        except Exception:
            elapsed = time.monotonic() - t
            self.stats["requests"] += 1
            return 0, elapsed, ""

    async def _baseline(self, cand) -> tuple[float, str]:
        marker = "ccbase" + secrets.token_hex(4)
        times = []
        body = ""
        for _ in range(2):
            _, el, txt = await self._send(cand, marker)
            times.append(el)
            body = txt
        times.sort()
        return times[len(times) // 2], body

    # ── per-parameter probes ──────────────────────────────────────────────────
    async def _probe_param(self, cand, cancelled) -> List[dict]:
        found: List[dict] = []
        baseline_t, baseline_body = await self._baseline(cand)

        if "ssti" in self.classes and not cancelled():
            hit = await self._probe_ssti(cand, baseline_body)
            if hit:
                found.append(hit)
        if "command_injection" in self.classes and not cancelled():
            hit = await self._probe_cmdi(cand, baseline_t)
            if hit:
                found.append(hit)
        if "ldap_injection" in self.classes and not cancelled():
            hit = await self._probe_error_based(
                cand,
                baseline_body,
                "ldap_injection",
                P.LDAP_ERROR_TEMPLATES,
                P.LDAP_ERROR_SIGNATURES,
                P.LDAP_TRUE,
                P.LDAP_FALSE,
            )
            if hit:
                found.append(hit)
        if "xpath_injection" in self.classes and not cancelled():
            hit = await self._probe_error_based(
                cand,
                baseline_body,
                "xpath_injection",
                P.XPATH_ERROR_TEMPLATES,
                P.XPATH_ERROR_SIGNATURES,
                P.XPATH_TRUE,
                P.XPATH_FALSE,
            )
            if hit:
                found.append(hit)
        return found

    # ── command injection: differential timing ────────────────────────────────
    async def _probe_cmdi(self, cand, baseline_t) -> Optional[dict]:
        d1, d2 = self.cmdi_delay_1, self.cmdi_delay_2
        for tmpl in P.CMDI_TEMPLATES:
            payload = tmpl.format(d=d1, dn=d1 + 1)
            _, t1, _ = await self._send(cand, payload)
            if (t1 - baseline_t) < d1 * 0.6:
                continue  # not delayed — next separator
            # Candidate delay. Confirm with a zero-delay control and a second,
            # larger delay that the response time must track.
            control = tmpl.format(d=0, dn=1)
            _, tc, _ = await self._send(cand, control)
            payload2 = tmpl.format(d=d2, dn=d2 + 1)
            _, t2, _ = await self._send(cand, payload2)
            control_fast = (tc - baseline_t) < d1 * 0.5
            tracks = (t2 - baseline_t) >= d2 * 0.6 and (t2 - t1) >= (d2 - d1) * 0.5
            if control_fast and tracks:
                self.stats["command_injection"] += 1
                return self._make_finding(
                    cand,
                    "command_injection",
                    payload2,
                    technique="differential timing",
                    evidence=(
                        f"Response time tracked the injected delay: baseline "
                        f"{baseline_t:.2f}s; sleep {d1}s → {t1:.2f}s; sleep 0 "
                        f"(control) → {tc:.2f}s; sleep {d2}s → {t2:.2f}s. The "
                        f"delay only appears with a non-zero sleep and scales "
                        f"with it, which a merely slow endpoint cannot produce."
                    ),
                )
        return None

    # ── SSTI: arithmetic evaluation ───────────────────────────────────────────
    async def _probe_ssti(self, cand, baseline_body) -> Optional[dict]:
        a = secrets.randbelow(400) + 600  # 600..999
        b = secrets.randbelow(400) + 600
        product = str(a * b)
        literal = f"{a}*{b}"
        if product in (baseline_body or ""):
            return None  # product already on the page — cannot attribute
        for engine_hint, tmpl in P.SSTI_TEMPLATES:
            payload = tmpl.format(a=a, b=b)
            _, _, body = await self._send(cand, payload)
            if product in body and literal not in body:
                self.stats["ssti"] += 1
                return self._make_finding(
                    cand,
                    "ssti",
                    payload,
                    technique=f"expression evaluation ({engine_hint})",
                    evidence=(
                        f"The template expression evaluated: injecting "
                        f"'{payload}' returned the computed product {product} "
                        f"(={a}×{b}) while the literal expression '{literal}' "
                        f"was not present, so the value was executed by a "
                        f"server-side template engine ({engine_hint}), not "
                        f"merely reflected."
                    ),
                )
        return None

    # ── LDAP / XPath: parser-error signature (+ boolean differential) ─────────
    async def _probe_error_based(
        self, cand, baseline_body, cls, templates, signatures, true_val, false_val
    ) -> Optional[dict]:
        base_low = (baseline_body or "").lower()
        for payload in templates:
            _, _, body = await self._send(cand, payload)
            low = body.lower()
            for sig in signatures:
                if sig.lower() in low and sig.lower() not in base_low:
                    # Supporting boolean differential (best-effort).
                    _, _, t_body = await self._send(cand, true_val)
                    _, _, f_body = await self._send(cand, false_val)
                    boolean = (
                        "; a boolean differential was also observed"
                        if len(t_body) != len(f_body)
                        else ""
                    )
                    self.stats[cls] += 1
                    return self._make_finding(
                        cand,
                        cls,
                        payload,
                        technique="parser error signature",
                        evidence=(
                            f"Injecting '{payload}' provoked a "
                            f"{cls.replace('_', ' ')} parser error in the "
                            f"response (signature: '{sig}') that the baseline "
                            f"did not contain{boolean}."
                        ),
                    )
        return None

    # ── XXE: internal-entity canary on POST endpoints ─────────────────────────
    async def _probe_xxe(self, url) -> Optional[dict]:
        canary = "ccxxe" + secrets.token_hex(6)
        ename = "e" + secrets.token_hex(3)
        body = P.XXE_TEMPLATE.format(name=ename, c=canary)
        for ctype in P.XXE_CONTENT_TYPES:
            await self._throttle()
            try:
                resp = await self._client.post(
                    url, content=body.encode(), headers={"Content-Type": ctype}
                )
                self.stats["requests"] += 1
                text = resp.text
            except Exception:
                self.stats["requests"] += 1
                continue
            raw_ref = f"&{ename};"
            if canary in text and raw_ref not in text:
                self.stats["xxe"] += 1
                cand = {"url": url, "method": "POST", "param": "(XML body)"}
                return self._make_finding(
                    cand,
                    "xxe",
                    body,
                    technique="internal-entity canary expansion",
                    evidence=(
                        f"The XML parser resolved a document-internal entity: a "
                        f"unique canary defined via <!ENTITY> was returned "
                        f"expanded ('{canary}') rather than as the literal "
                        f"reference '{raw_ref}', proving DTD/entity processing "
                        f"is enabled (Content-Type {ctype}). No external or "
                        f"file entity was sent."
                    ),
                )
        return None

    # ── finding ───────────────────────────────────────────────────────────────
    def _make_finding(self, cand, cls, payload, *, technique, evidence) -> dict:
        url = cand.get("url", "")
        param = cand.get("param", "")
        method = cand.get("method", "GET")
        title = f"{P.TITLE[cls]} in '{param}' at {url}"
        return {
            "finding_type": cls,
            "title": title[:255],
            "description": (
                f"An active test detected {P.TITLE[cls]} in the '{param}' "
                f"parameter ({method}) via {technique}. {evidence}"
            ),
            "severity": P.SEVERITY[cls],
            "detected_by": "ccure-injection",
            "cwe_id": P.CWE[cls],
            "matched_at": url,
            "request_url": url,
            "request_method": method,
            "payload_used": payload[:2000],
            "request_evidence": f"parameter={param}; class={cls}; technique={technique}",
            "response_evidence": evidence[:4000],
            "remediation": P.REMEDIATION[cls],
            "is_verified": True,
            "confidence": "confirmed",
            "injection_class": cls,
        }
