"""
core/trusted_proxy.py
─────────────────────
The application's proxy trust boundary (Phase 10.3, finding F10-1).

Only a peer named in ``AppConfig.TRUSTED_PROXIES`` may tell this application
who the client is or which scheme it used. This middleware applies that rule
to the ASGI scope itself, outermost in the stack, so everything after it —
the rate limiters, the audit trail, ``request.url`` (absolute URLs, redirects)
and the HSTS decision in main.py — sees one resolved answer.

**Why it replaced uvicorn's own proxy handling.** The server ran with
``--proxy-headers --forwarded-allow-ips='*'``. In uvicorn 0.29, ``'*'`` means
*every* peer is a proxy: the client address was rewritten from the leftmost
``X-Forwarded-For`` entry — the one field a client controls — and the scheme
from ``X-Forwarded-Proto``, for any caller that could reach port 8000. Phase
10.1 proved it live: a forged ``X-Forwarded-For`` sent straight to ``:8000``
(and through the frontend container's ``/api/`` proxy on ``:3200``) became the
rate-limit key. ``core.ip_resolver``'s own "is the peer a trusted proxy?" check
never helped, because by the time it ran uvicorn had already replaced the peer
with the forged value. uvicorn 0.29 also accepts exact addresses only (no
ranges) and hands the application a ``None`` client when every hop is trusted,
so start.sh now runs it with ``--no-proxy-headers`` and this middleware, which
uses ``core.ip_resolver.resolve_client`` — the same rule ``get_client_ip``
applies — makes the decision instead.

Behaviour:

* **Untrusted peer** — the scope is left exactly as the socket reported it.
  Any ``X-Forwarded-For`` / ``X-Real-IP`` / ``X-Forwarded-Proto`` it sent is
  ignored for the client address and the scheme.
* **Trusted peer** — the client becomes the resolved address (the right-most
  untrusted hop), only when a forwarding header is present; the scheme becomes
  the first ``X-Forwarded-Proto`` value, only if it is exactly ``http`` or
  ``https`` (``ws``/``wss`` on a WebSocket).

The headers themselves are passed on untouched.
"""

from __future__ import annotations

from core.ip_resolver import is_trusted_peer, resolve_client

_SCHEMES = {
    "http": {"http": "http", "https": "https"},
    "websocket": {"http": "ws", "https": "wss"},
}


def _first(headers, name: bytes) -> str | None:
    for key, value in headers:
        if key.lower() == name:
            return value.decode("latin-1")
    return None


class TrustedProxyHeadersMiddleware:
    """Resolve client address and scheme from forwarding headers — trusted peers only."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") in _SCHEMES:
            client = scope.get("client")
            peer = client[0] if client else None
            if is_trusted_peer(peer):
                headers = scope.get("headers") or []
                forwarded_for = _first(headers, b"x-forwarded-for")
                real_ip = _first(headers, b"x-real-ip")
                proto = _first(headers, b"x-forwarded-proto")
                changes = {}
                if forwarded_for or real_ip:
                    changes["client"] = (
                        resolve_client(peer, forwarded_for, real_ip),
                        0,
                    )
                if proto:
                    scheme = _SCHEMES[scope["type"]].get(
                        proto.split(",")[0].strip().lower()
                    )
                    if scheme:
                        changes["scheme"] = scheme
                if changes:
                    scope = {**scope, **changes}
        await self.app(scope, receive, send)
