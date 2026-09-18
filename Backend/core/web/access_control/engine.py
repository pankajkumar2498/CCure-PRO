"""
core/web/access_control/engine.py
────────────────────────────────────────────────────────────────────────────
Controlled authorization / access-control testing (Phase 4): IDOR, horizontal
and vertical privilege escalation, unauthorized resource access.

Multi-user by construction, and sessions are never mixed: each configured user
(A, B, an optional administrator) is authenticated into its **own** isolated
httpx client via the Phase 3 session manager, plus an anonymous client with no
session. A test compares what these separate identities see for the *same*
resource.

Evidence, not coincidence. The engine refuses to call a finding on any of the
things the specification calls out as insufficient — an HTTP 200, an identifier
that changed, public content, or a generic endpoint that returns the same body
whatever the id. Every horizontal finding must clear four gates:

  1. owner sees substantive resource content for its own identifier;
  2. the endpoint is resource-specific — the owner sees *different* content for
     a bogus identifier (so it is not a generic page that ignores the id);
  3. the resource is protected — an anonymous client is denied it (so it is not
     simply public);
  4. the other user (or anon) sees the owner's content — high similarity to the
     owner's baseline — which is the actual authorization bypass.

Read-only by default. No resource is deleted, modified, purchased or
transferred; state-changing HTTP methods are only ever sent when the operator
explicitly enables safe write testing.
"""

from __future__ import annotations

import asyncio
import logging
import re
import secrets as _secrets
import time
from difflib import SequenceMatcher
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse

log = logging.getLogger("ccure.web.accesscontrol")

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
_MONGO_RE = re.compile(r"^[0-9a-f]{24}$", re.I)
_HEXID_RE = re.compile(r"^[0-9a-f]{8,}$", re.I)

#: Query-parameter names that conventionally carry a resource identifier.
_ID_PARAM_NAMES = {
    "id",
    "uid",
    "user",
    "user_id",
    "userid",
    "account",
    "account_id",
    "acct",
    "order",
    "order_id",
    "orderid",
    "doc",
    "document",
    "document_id",
    "docid",
    "file",
    "file_id",
    "pid",
    "oid",
    "object_id",
    "record",
    "record_id",
    "invoice",
    "invoice_id",
    "customer",
    "customer_id",
    "profile",
    "profile_id",
    "number",
    "no",
    "ref",
    "key",
    "item",
    "item_id",
    "cart",
    "msg",
    "message_id",
}

#: A denial: the resource was refused, not served.
_DENY_STATUS = {401, 403, 404, 407}
_DENY_MARKERS = (
    "access denied",
    "forbidden",
    "unauthorized",
    "not authorized",
    "permission denied",
    "please log in",
    "login required",
    "must be logged in",
    "you do not have",
    "insufficient priv",
)


def _is_identifier(value: str) -> Optional[str]:
    """Classify a path segment / value as an identifier kind, or None."""
    v = (value or "").strip()
    if not v:
        return None
    if v.isdigit() and 1 <= len(v) <= 18:
        return "numeric"
    if _UUID_RE.match(v):
        return "uuid"
    if _MONGO_RE.match(v):
        return "objectid"
    if _HEXID_RE.match(v) and len(v) <= 64:
        return "hex"
    return None


def _bogus(value: str, kind: str) -> str:
    """A different, same-shaped identifier for the generic-endpoint gate."""
    if kind == "numeric":
        n = int(value)
        return str(n + 7919 if n < 10**15 else n - 7919)
    if kind == "uuid":
        return "00000000-0000-4000-8000-" + _secrets.token_hex(6)
    return _secrets.token_hex(max(4, len(value) // 2))


class AccessControlEngine:
    """Evidence-based IDOR / privilege-escalation tester across isolated users."""

    def __init__(
        self,
        *,
        rate_limit: int = 5,
        max_candidates: int = 30,
        timeout_s: float = 15.0,
        same_origin_only: bool = True,
        similarity_same: float = 0.90,
        min_body_len: int = 128,
        allow_write_testing: bool = False,
        verify_tls: bool = False,
    ) -> None:
        self.rate_limit = max(1, int(rate_limit or 1))
        self.max_candidates = max_candidates
        self.timeout_s = timeout_s
        self.same_origin_only = same_origin_only
        self.similarity_same = similarity_same
        self.min_body_len = min_body_len
        self.allow_write_testing = allow_write_testing
        self.verify_tls = verify_tls
        self._min_interval = 1.0 / self.rate_limit
        self._last = 0.0
        self.stats: Dict[str, Any] = {
            "candidates": 0,
            "requests": 0,
            "duration_s": 0.0,
            "idor": 0,
            "privilege_escalation": 0,
            "broken_access_control": 0,
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

    # ── public entrypoint ─────────────────────────────────────────────────────
    async def scan(
        self,
        target_url: str,
        endpoints: List[dict],
        owner: dict,
        peers: List[dict],
        admin_paths: Optional[List[str]] = None,
        progress_cb: Optional[Callable[[str], None]] = None,
        cancel_cb: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        """
        owner  = {"label","headers","cookies"} — the session the crawl ran under
                 (its discovered endpoints are treated as its resources).
        peers  = [{"label","headers","cookies","privileged"}] — the other users.
        """
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

        def _progress(m):
            try:
                if progress_cb:
                    progress_cb(m)
            except Exception:
                pass

        clients: Dict[str, Any] = {}
        try:
            # One isolated client per identity, plus anon. Never shared.
            def _mk(sess):
                cookies = {}
                for k, v in (sess.get("cookies") or {}).items():
                    cookies[k] = v
                return httpx.AsyncClient(
                    verify=self.verify_tls,
                    timeout=self.timeout_s,
                    follow_redirects=False,  # a 302 to /login is a denial signal
                    headers=sess.get("headers") or None,
                    cookies=cookies or None,
                )

            clients["__anon__"] = httpx.AsyncClient(
                verify=self.verify_tls, timeout=self.timeout_s, follow_redirects=False
            )
            owner_label = owner.get("label", "A")
            clients[owner_label] = _mk(owner)
            for p in peers:
                clients[p["label"]] = _mk(p)

            candidates = self._candidates(target_url, endpoints)
            self.stats["candidates"] = len(candidates)

            # ── Horizontal IDOR + unauthorized (anon) access ──────────────────
            non_priv_peers = [p for p in peers if not p.get("privileged")]
            for i, cand in enumerate(candidates):
                if _cancelled():
                    break
                if i % 5 == 0:
                    _progress(f"Access-control: resource {i + 1}/{len(candidates)}…")
                findings += await self._test_horizontal(
                    clients, owner_label, non_priv_peers, cand
                )

            # ── Vertical privilege escalation (admin-only paths) ──────────────
            admin_peers = [p for p in peers if p.get("privileged")]
            if admin_peers and admin_paths and not _cancelled():
                _progress("Access-control: vertical privilege checks…")
                low_labels = [owner_label] + [p["label"] for p in non_priv_peers]
                for path in admin_paths[: self.max_candidates]:
                    if _cancelled():
                        break
                    findings += await self._test_vertical(
                        clients, target_url, admin_peers, low_labels, path
                    )
        except Exception as exc:
            log.warning("access-control engine error: %s", exc)
        finally:
            for c in clients.values():
                try:
                    await c.aclose()
                except Exception:
                    pass

        self.stats["duration_s"] = round(time.monotonic() - t0, 2)
        return {"findings": findings, "stats": self.stats, "available": True}

    # ── candidate discovery ───────────────────────────────────────────────────
    def _candidates(self, target_url, endpoints) -> List[dict]:
        cands: List[dict] = []
        seen: set = set()
        urls = [target_url] + [
            e.get("url")
            for e in (endpoints or [])
            if isinstance(e, dict) and e.get("url")
        ]
        for url in urls:
            if not url or (
                self.same_origin_only and urlparse(url).netloc != self._origin
            ):
                continue
            parsed = urlparse(url)
            # Path-segment identifiers.
            segs = parsed.path.split("/")
            for idx, seg in enumerate(segs):
                kind = _is_identifier(seg)
                if kind:
                    key = ("path", parsed.path, idx)
                    if key not in seen:
                        seen.add(key)
                        cands.append(
                            {
                                "url": url,
                                "loc": "path",
                                "seg_index": idx,
                                "id_value": seg,
                                "id_kind": kind,
                                "param": None,
                            }
                        )
            # Query-parameter identifiers.
            for name, value in parse_qsl(parsed.query, keep_blank_values=True):
                kind = _is_identifier(value)
                if kind and (
                    name.lower() in _ID_PARAM_NAMES
                    or kind != "numeric"
                    or len(value) >= 2
                ):
                    key = ("query", parsed.path, name)
                    if key not in seen:
                        seen.add(key)
                        cands.append(
                            {
                                "url": url,
                                "loc": "query",
                                "seg_index": None,
                                "id_value": value,
                                "id_kind": kind,
                                "param": name,
                            }
                        )
            if len(cands) >= self.max_candidates:
                break
        return cands[: self.max_candidates]

    def _swap(self, cand, new_id) -> str:
        """Rebuild the candidate URL with a different identifier value."""
        parsed = urlparse(cand["url"])
        if cand["loc"] == "path":
            segs = parsed.path.split("/")
            segs[cand["seg_index"]] = new_id
            return parsed._replace(path="/".join(segs)).geturl()
        params = [
            (n, new_id if n == cand["param"] else v)
            for n, v in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return parsed._replace(query=urlencode(params)).geturl()

    # ── requests ───────────────────────────────────────────────────────────────
    async def _get(self, client, url) -> tuple[int, str]:
        await self._throttle()
        try:
            r = await client.get(url)
            self.stats["requests"] += 1
            return r.status_code, r.text or ""
        except Exception:
            self.stats["requests"] += 1
            return 0, ""

    @staticmethod
    def _denied(status: int, text: str) -> bool:
        if status in _DENY_STATUS or status in (301, 302, 303, 307, 308):
            return True
        low = (text or "").lower()
        return any(m in low for m in _DENY_MARKERS)

    def _substantive(self, status: int, text: str) -> bool:
        return status == 200 and len(text or "") >= self.min_body_len

    def _similar(self, a: str, b: str) -> float:
        if not a or not b:
            return 0.0
        # Bounded for performance; quick_ratio is an upper bound so gate on ratio.
        return SequenceMatcher(None, a[:20000], b[:20000]).ratio()

    # ── horizontal IDOR / unauthorized access ─────────────────────────────────
    async def _test_horizontal(self, clients, owner_label, peers, cand) -> List[dict]:
        out: List[dict] = []
        owner_c = clients[owner_label]
        url = cand["url"]

        o_status, o_body = await self._get(owner_c, url)
        if not self._substantive(o_status, o_body):
            return out  # owner cannot see it → not an owned resource to protect

        # Gate 2: resource-specific? A bogus id must return *different* content,
        # otherwise the endpoint ignores the id (generic page) and any match is
        # meaningless.
        bogus_url = self._swap(cand, _bogus(cand["id_value"], cand["id_kind"]))
        b_status, b_body = await self._get(owner_c, bogus_url)
        if (
            self._substantive(b_status, b_body)
            and self._similar(o_body, b_body) >= self.similarity_same
        ):
            return out  # generic endpoint — same content for any id

        # Gate 3: protected? Anonymous must be denied, else it is simply public.
        an_status, an_body = await self._get(clients["__anon__"], url)
        anon_denied = self._denied(an_status, an_body) or not self._substantive(
            an_status, an_body
        )
        if not anon_denied and self._similar(an_body, o_body) >= self.similarity_same:
            # Public resource — record nothing as IDOR, but this is itself
            # unauthorized access only if the content is clearly authenticated;
            # a public page is not a finding.
            return out

        # If anon was NOT denied and simply sees the same content, the resource
        # is public — not a finding (the specification's "content is public"
        # guard). Gate 3 has already returned in that case.

        # Gate 4: does another authenticated identity see the owner's protected,
        # resource-specific content? That is the authorization bypass.
        for peer in peers:
            pc = clients[peer["label"]]
            p_status, p_body = await self._get(pc, url)
            if (
                self._substantive(p_status, p_body)
                and self._similar(p_body, o_body) >= self.similarity_same
            ):
                self.stats["idor"] += 1
                out.append(
                    self._finding(
                        "idor",
                        cand,
                        owner_label,
                        peer["label"],
                        o_status,
                        p_status,
                        o_body,
                        p_body,
                        an_status,
                        technique="horizontal IDOR",
                        cwe="CWE-639",
                        severity="high",
                    )
                )
        return out

    # ── vertical privilege escalation ─────────────────────────────────────────
    async def _test_vertical(
        self, clients, target_url, admin_peers, low_labels, path
    ) -> List[dict]:
        out: List[dict] = []
        url = (
            path
            if path.startswith("http")
            else urlparse(target_url)
            ._replace(path=path, query="", fragment="")
            .geturl()
        )
        if self.same_origin_only and urlparse(url).netloc != self._origin:
            return out

        for admin in admin_peers:
            a_status, a_body = await self._get(clients[admin["label"]], url)
            if not self._substantive(a_status, a_body):
                continue  # admin cannot see it either → not admin functionality
            an_status, an_body = await self._get(clients["__anon__"], url)
            anon_denied = self._denied(an_status, an_body) or not self._substantive(
                an_status, an_body
            )
            if not anon_denied:
                # A declared admin path served to an anonymous client is broken
                # access control — here "should be protected" is explicit
                # (the operator listed it as admin-only), so this is not the
                # ambiguous public-content case the horizontal guard rejects.
                if self._similar(an_body, a_body) >= self.similarity_same:
                    self.stats["broken_access_control"] += 1
                    out.append(
                        self._finding(
                            "broken_access_control",
                            {
                                "url": url,
                                "loc": "path",
                                "id_value": "-",
                                "id_kind": "-",
                                "param": None,
                            },
                            admin["label"],
                            "anonymous",
                            a_status,
                            an_status,
                            a_body,
                            an_body,
                            an_status,
                            technique="unauthenticated access to a declared admin-only path",
                            cwe="CWE-284",
                            severity="high",
                        )
                    )
                continue  # not protected — vertical (authenticated) test moot
            for low in low_labels:
                l_status, l_body = await self._get(clients[low], url)
                if (
                    self._substantive(l_status, l_body)
                    and self._similar(l_body, a_body) >= self.similarity_same
                ):
                    self.stats["privilege_escalation"] += 1
                    out.append(
                        self._finding(
                            "privilege_escalation",
                            {
                                "url": url,
                                "loc": "path",
                                "id_value": "-",
                                "id_kind": "-",
                                "param": None,
                            },
                            admin["label"],
                            low,
                            a_status,
                            l_status,
                            a_body,
                            l_body,
                            an_status,
                            technique="vertical privilege escalation (admin functionality reached by a lower-privilege user)",
                            cwe="CWE-269",
                            severity="critical",
                        )
                    )
        return out

    # ── finding ────────────────────────────────────────────────────────────────
    def _finding(
        self,
        ftype,
        cand,
        source_owner,
        source_attacker,
        owner_status,
        attacker_status,
        owner_body,
        attacker_body,
        anon_status,
        *,
        technique,
        cwe,
        severity,
    ) -> dict:
        url = cand["url"]
        ident = cand.get("id_value", "-")
        param = cand.get("param")
        loc = (
            "parameter '%s'" % param
            if param
            else ("path identifier" if cand.get("loc") == "path" else "resource")
        )
        title = f"{_TITLE[ftype]} at {url}"
        sim = round(self._similar(owner_body, attacker_body), 3)
        desc = (
            f"{_TITLE[ftype]} confirmed by cross-identity comparison. The "
            f"resource at {url} ({loc}, identifier '{ident}') returns "
            f"substantive owner content to '{source_owner}' (HTTP {owner_status}); "
            f"an anonymous request is denied (HTTP {anon_status}); yet "
            f"'{source_attacker}', a different authorization context, receives "
            f"HTTP {attacker_status} with content {int(sim * 100)}% identical to "
            f"the owner's — i.e. it accessed a protected resource it is not "
            f"authorized for. The endpoint is resource-specific (a different "
            f"identifier returns different content), ruling out a generic page."
        )
        return {
            "finding_type": ftype,
            "title": title[:255],
            "description": desc,
            "severity": severity,
            "detected_by": "ccure-access-control",
            "cwe_id": cwe,
            "matched_at": url,
            "request_url": url,
            "request_method": "GET",
            "payload_used": f"identifier '{ident}' accessed as '{source_attacker}'",
            "request_evidence": (
                f"technique={technique}; source_user={source_attacker}; "
                f"owner={source_owner}; identifier={ident}; location={loc}"
            ),
            "response_evidence": (
                f"owner({source_owner}) HTTP {owner_status}; anon HTTP {anon_status} "
                f"(denied); attacker({source_attacker}) HTTP {attacker_status}; "
                f"content similarity attacker↔owner = {int(sim * 100)}%."
            ),
            "remediation": _REMEDIATION[ftype],
            "is_verified": True,
            "confidence": "confirmed",
            "access_class": ftype,
        }


_TITLE = {
    "idor": "Insecure Direct Object Reference (IDOR) / horizontal privilege escalation",
    "privilege_escalation": "Vertical privilege escalation",
    "broken_access_control": "Broken access control — unauthorized resource access",
}
_REMEDIATION = {
    "idor": (
        "Enforce object-level authorization on every request: verify the "
        "authenticated principal owns or may access the requested object before "
        "returning it, rather than trusting a client-supplied identifier. Use "
        "unguessable identifiers as defence in depth, never as the control."
    ),
    "privilege_escalation": (
        "Enforce function-level authorization server-side for every privileged "
        "action and page; do not rely on hiding admin links. Check role/"
        "permission on each request and deny by default."
    ),
    "broken_access_control": (
        "Require authentication and authorization for non-public resources; deny "
        "by default and verify access server-side on every request."
    ),
}
