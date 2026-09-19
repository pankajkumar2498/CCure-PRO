"""
core/web/oast/session.py
────────────────────────────────────────────────────────────────────────────
OAST interaction identity and correlation (Phase 9).

Blind SSRF, out-of-band command injection and blind XXE leave no trace in the
HTTP response — the only evidence is a callback the payload causes the *target*
to make to a collaborator server the scan controls. This module owns the two
halves of making that evidence attributable:

  • minting a unique interaction token per (finding class, endpoint, parameter)
    and remembering, in memory only, what each token was for; and
  • correlating a callback the collaborator observed back to the payload that
    caused it, producing a finding with the callback as evidence.

Three properties this is built to guarantee, each pinned by a test:

  • **Tokens cannot collide between scans.** Every session draws a random
    namespace prefix, so two scans running concurrently mint from disjoint
    spaces and a callback is only ever attributed to the session that owns the
    token (``owns()`` checks the prefix before the registry).

  • **The callback carries no sensitive scan information.** The token is an
    opaque hex label; the target URL, parameter, payload, scan id, credentials
    and session all live only in this process's registry, keyed by the token.
    A collaborator (or anyone watching DNS) sees ``c1a2b3<seq>.<domain>`` and
    learns nothing about what is being scanned or where.

  • **A token is a valid DNS label.** All-hex, lowercase, well under 63 bytes,
    so it works identically as an HTTP Host subdomain and a DNS query name.
"""

from __future__ import annotations

import logging
import re
import secrets
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

log = logging.getLogger("ccure.web.oast")

#: Correlated OAST evidence uses these finding types (all already CWE-mapped in
#: standards_mapping: ssrf→CWE-918, command_injection→CWE-78, xxe→CWE-611).
OAST_FINDING_TYPES = ("ssrf", "command_injection", "xxe")

_TOKEN_RE = re.compile(r"^[0-9a-f]{6,40}$")


class OastSession:
    """
    Per-scan token namespace and correlation registry.

    Args:
        base_domain: the collaborator's DNS zone, e.g. ``oast.ccure.internal``.
            Callbacks arrive as ``<token>.<base_domain>`` over DNS and (with
            wildcard DNS) HTTP.
        http_base_url: optional base URL for path-style HTTP callbacks, e.g.
            ``http://10.0.0.9:8888``. Used where wildcard DNS is not available
            (a receiver bound to a bare IP). When set, HTTP callbacks are
            ``<http_base_url>/<token>``.
        scan_id / correlation_id: recorded for logs only — never placed in a
            token or a callback URL.
    """

    def __init__(
        self,
        base_domain: str = "",
        http_base_url: str = "",
        *,
        scan_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> None:
        self.base_domain = (base_domain or "").strip().strip(".").lower()
        self.http_base_url = (http_base_url or "").strip().rstrip("/")
        self.scan_id = scan_id
        self.correlation_id = correlation_id
        # A random per-session namespace. Two sessions (two scans) draw
        # different prefixes, so their token spaces are disjoint and a callback
        # can never be attributed to the wrong scan.
        self.prefix = secrets.token_hex(3)  # 6 hex chars
        self._seq = 0
        self._registry: Dict[str, dict] = {}

    # ── minting ───────────────────────────────────────────────────────────────
    def mint(
        self,
        finding_type: str,
        *,
        url: str = "",
        param: str = "",
        method: str = "GET",
        payload_kind: str = "",
    ) -> str:
        """
        Reserve a unique token and remember what it is for (in memory only).

        The returned token is safe to embed in a payload; nothing about the
        target or the scan is derivable from it.
        """
        self._seq += 1
        token = f"{self.prefix}{self._seq:04x}"
        # Uniqueness within the session is structural (monotonic seq), but assert
        # it: a collision here would silently merge two findings' evidence.
        if token in self._registry:  # pragma: no cover - defensive
            raise RuntimeError(f"OAST token collision: {token}")
        self._registry[token] = {
            "finding_type": finding_type,
            "url": url,
            "param": param,
            "method": method,
            "payload_kind": payload_kind,
            "minted_at": time.time(),
        }
        return token

    # ── callback addresses for payloads ───────────────────────────────────────
    def domain_for(self, token: str) -> str:
        """DNS name for a token: ``<token>.<base_domain>``."""
        return f"{token}.{self.base_domain}" if self.base_domain else token

    def http_url_for(self, token: str, path: str = "") -> str:
        """
        HTTP callback URL for a token.

        Path-style (``<http_base_url>/<token>``) when a base URL is configured
        — the shape a receiver bound to a bare IP needs — otherwise host-style
        (``http://<token>.<base_domain>/``) for a collaborator with wildcard
        DNS.
        """
        tail = f"/{path.lstrip('/')}" if path else ""
        if self.http_base_url:
            return f"{self.http_base_url}/{token}{tail}"
        return f"http://{self.domain_for(token)}{tail or '/'}"

    # ── ownership / lookup ────────────────────────────────────────────────────
    def owns(self, token: str) -> bool:
        """
        Whether a token belongs to this session.

        Checks the namespace prefix first, so a callback from a *different*
        scan's token is rejected before the registry is even consulted — the
        structural guarantee against cross-scan attribution.
        """
        if not token or not token.startswith(self.prefix):
            return False
        return token in self._registry

    def tokens(self) -> set:
        return set(self._registry)

    # ── correlation ───────────────────────────────────────────────────────────
    def correlate(self, interactions: List[dict]) -> List[dict]:
        """
        Turn observed callbacks into findings.

        Each interaction is a dict from the collaborator:
        ``{token, protocol, remote_addr, timestamp, ...}``. Only interactions
        whose token this session owns become findings; anything else (another
        scan's token, a stray scanner, a malformed name) is ignored. One
        finding per (token, protocol) — a payload that fires twice is one
        proof, not two.
        """
        findings: List[dict] = []
        seen: set = set()
        for it in interactions or []:
            token = str(it.get("token") or "").strip().lower()
            if not self.owns(token):
                continue
            protocol = str(it.get("protocol") or "http").lower()
            key = (token, protocol)
            if key in seen:
                continue
            seen.add(key)
            findings.append(self._finding(token, protocol, it))
        return findings

    def _finding(self, token: str, protocol: str, it: dict) -> dict:
        ctx = self._registry[token]
        ftype = ctx["finding_type"]
        remote = str(it.get("remote_addr") or "unknown")
        when = it.get("timestamp")
        param = ctx.get("param") or "(body)"
        url = ctx.get("url") or ""
        host = urlparse(url).netloc or url

        titles = {
            "ssrf": "Blind Server-Side Request Forgery (out-of-band)",
            "command_injection": "Out-of-Band OS Command Injection",
            "xxe": "Out-of-Band XML External Entity (XXE)",
        }
        title = titles.get(ftype, f"Out-of-band interaction ({ftype})")

        # Evidence is the callback itself — proof the target reached the
        # collaborator. It deliberately names no secret: the token, the
        # protocol, the observed source address and the payload class only.
        evidence_lines = [
            f"Out-of-band {protocol.upper()} interaction received by the OAST collaborator.",
            f"Interaction token: {token}",
            f"Observed source address: {remote}",
        ]
        if when:
            evidence_lines.append(f"Received at: {when}")
        if it.get("qname"):
            evidence_lines.append(f"DNS query: {it['qname']}")
        if it.get("path"):
            evidence_lines.append(f"HTTP path: {it['path']}")
        evidence_lines.append(
            f"Injected into parameter '{param}' of {ctx.get('method', 'GET')} {url}"
        )

        return {
            "finding_type": ftype,
            "title": title,
            "description": (
                f"A payload injected into parameter '{param}' caused the target "
                f"to make an out-of-band {protocol.upper()} request to a server "
                f"the scanner controls. This is proof-of-interaction: the "
                f"weakness is present and reachable, not inferred from the "
                f"response. Host: {host or 'n/a'}."
            ),
            "severity": "high" if ftype != "ssrf" else "high",
            "detected_by": "ccure-oast",
            "matched_at": url,
            "request_url": url,
            "request_method": ctx.get("method", "GET"),
            "payload_used": ctx.get("payload_kind", ""),
            "response_evidence": "\n".join(evidence_lines),
            "is_verified": True,
            # Interaction protocol is carried so a report can say DNS vs HTTP.
            "oast_protocol": protocol,
        }

    # ── lifecycle ─────────────────────────────────────────────────────────────
    def close(self) -> None:
        """Forget every token this session minted (cleanup)."""
        self._registry.clear()


def token_from_host(host: str, base_domain: str = "") -> str:
    """
    Extract an interaction token from an HTTP Host header or a DNS-style name.

    ``c1a2b30001.oast.ccure.internal`` → ``c1a2b30001``. The leading label is
    the token; the base domain (if given and matched) is stripped, otherwise
    the first label is used.
    """
    host = (host or "").strip().strip(".").lower()
    if not host:
        return ""
    # Drop a :port on a Host header.
    host = host.split(":")[0]
    base = (base_domain or "").strip().strip(".").lower()
    if base and host.endswith("." + base):
        label = host[: -(len(base) + 1)].split(".")[-1]
    else:
        label = host.split(".")[0]
    return label if _TOKEN_RE.match(label) else ""


def token_from_path(path: str) -> str:
    """Extract a token from the first path segment of an HTTP request."""
    seg = (path or "").lstrip("/").split("/")[0].split("?")[0].strip().lower()
    return seg if _TOKEN_RE.match(seg) else ""
