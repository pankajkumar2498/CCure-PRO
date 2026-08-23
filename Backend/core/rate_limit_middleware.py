"""
core/rate_limit_middleware.py
─────────────────────────────
A baseline per-IP request ceiling for every API route that carries no explicit
limit of its own.

Why this exists
───────────────
Rate limiting here is declared per route with `@limiter.limit`, which means the
set of protected endpoints is exactly the set somebody remembered to decorate.
That is the right model for the endpoints that need a *specific* number — login,
registration, password recovery, OTP, scan dispatch — because the right number
for those follows from what the endpoint costs and what abusing it buys. It is a
poor model for the long tail: a route added next month is unprotected by
default, and nothing fails to remind anyone.

This middleware is the backstop. It is deliberately generous — it is not trying
to be the control that stops credential stuffing, it is trying to ensure no
route is *entirely* unbounded. The endpoints that need a real limit still carry
one, and theirs is stricter, so theirs is what refuses first.

Why not slowapi's own middleware
────────────────────────────────
slowapi ships `SlowAPIMiddleware` (BaseHTTPMiddleware) and
`SlowAPIASGIMiddleware`. The ASGI one wraps `send` and re-emits the buffered
`http.response.start` message on *every* `http.response.body` message, so any
response delivered in more than one chunk sends its headers repeatedly. This API
streams: report downloads are `FileResponse`, notifications are SSE, and scan
progress is long-lived. The BaseHTTPMiddleware variant avoids that but buffers
responses through a memory stream, which is a poor fit for the same endpoints.

So this middleware never touches `send` at all. Under the limit it hands the
request to the application untouched — byte-for-byte the behaviour with no
middleware present. Over the limit it answers 429 itself and the application is
never called.

Placement
─────────
Registered *before* CORSMiddleware in `main.py`, which in Starlette's stack
means it runs inside it. That ordering matters twice: the browser can read a 429
only if CORS headers are on it, and the request-ID middleware sitting further
out stamps `X-Request-ID` and the security headers onto the response. It also
means CORS preflights are answered before reaching here and never consume
budget.
"""

from __future__ import annotations

import logging
import time

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

# How long to stay on the local counter after a storage failure before probing
# the shared store again. Long enough not to hammer a backend already unwell.
_BACKEND_RECHECK_SECONDS = 30.0


class BaselineRateLimitMiddleware:
    """
    Per-IP ceiling applied to every HTTP request that is not exempt.

    Falls back to a process-local counter when the shared store is unreachable.
    The fallback is weaker — its window is per worker process, so the effective
    ceiling is multiplied by the worker count — but it is never *absent*, which
    is the property that matters: a rate limit that disappears when its backing
    store does is a rate limit an attacker can remove.
    """

    def __init__(
        self,
        app: ASGIApp,
        limit: str,
        storage_uri: str,
        exempt_paths: list[str] | None = None,
    ) -> None:
        self.app = app
        # Exemptions are matched *exactly* unless the entry ends in "*", in
        # which case the text before it is a prefix. The distinction is not
        # cosmetic: the health endpoint on this API is "/", and a prefix match
        # on "/" exempts the entire application — a rate limit that silently
        # covers nothing. Exact by default makes that impossible to write by
        # accident.
        self._exempt_exact = frozenset(
            p for p in (exempt_paths or ()) if not p.endswith("*")
        )
        self._exempt_prefix = tuple(
            p[:-1] for p in (exempt_paths or ()) if p.endswith("*") and len(p) > 1
        )
        self._item = None
        self._strategy = None
        self._fallback_strategy = None
        self._storage_dead_until = 0.0

        if not limit:
            logger.info("Baseline API rate limit disabled by configuration")
            return

        try:
            from limits import parse
            from limits.storage import MemoryStorage, storage_from_string
            from limits.strategies import FixedWindowRateLimiter

            self._item = parse(limit)
            self._strategy = FixedWindowRateLimiter(storage_from_string(storage_uri))
            self._fallback_strategy = FixedWindowRateLimiter(MemoryStorage())
            logger.info("Baseline API rate limit active: %s per client IP", limit)
        except Exception:
            # A malformed limit string must not stop the application booting.
            # Logged at error level precisely because the outcome is a silently
            # unprotected long tail rather than a visible failure.
            logger.error(
                "Baseline API rate limit could not be configured from %r; "
                "per-route limits still apply but there is no backstop",
                limit,
                exc_info=True,
            )
            self._item = None

    # ── Counting ─────────────────────────────────────────────────────────────

    def _within_limit(self, key: str) -> bool:
        """
        True when this request is allowed through.

        Never raises: a failure to *count* must not become a failure to serve.
        It degrades to the local counter instead, which is the difference
        between a degraded control and no control at all.
        """
        from core.rate_limit_audit import report_degradation

        now = time.monotonic()

        if now >= self._storage_dead_until:
            try:
                verdict = bool(self._strategy.hit(self._item, key))
                # Only announced on transition, so a recovered store logs once
                # rather than on every request.
                report_degradation("baseline", False)
                return verdict
            except Exception:
                self._storage_dead_until = now + _BACKEND_RECHECK_SECONDS
                report_degradation("baseline", True)
                logger.warning(
                    "Baseline rate-limit store unreachable; counting in process "
                    "memory for the next %ss",
                    int(_BACKEND_RECHECK_SECONDS),
                    exc_info=True,
                )

        try:
            return bool(self._fallback_strategy.hit(self._item, key))
        except Exception:  # pragma: no cover - MemoryStorage does not fail
            logger.exception("Baseline rate-limit fallback failed; allowing request")
            return True

    # ── ASGI ─────────────────────────────────────────────────────────────────

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self._item is None or scope["type"] != "http":
            # Non-HTTP scopes are websockets. They are one connection rather
            # than a stream of requests, so a per-request ceiling says nothing
            # useful about them; they are bounded by authentication instead.
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        if path in self._exempt_exact or (
            self._exempt_prefix and path.startswith(self._exempt_prefix)
        ):
            return await self.app(scope, receive, send)

        app_state = getattr(scope.get("app"), "state", None)
        limiter = getattr(app_state, "limiter", None)

        if limiter is not None:
            # slowapi tracks its own storage health on the shared limiter and
            # says nothing about it beyond one log line at the moment it
            # switches. Surfacing it from here means the per-route limiter's
            # degradation raises the same alert as this one, rather than being
            # visible only to whoever greps for slowapi's wording.
            self._report_shared_limiter_health(limiter)

        if limiter is not None and not limiter.enabled:
            # One switch turns off all rate limiting, including this. The test
            # suite uses it; without this check the baseline would keep counting
            # and the suite's own request volume would start failing tests that
            # have nothing to do with rate limiting.
            return await self.app(scope, receive, send)

        request = Request(scope)
        try:
            from core.ip_resolver import get_client_ip

            key = get_client_ip(request) or "unknown"
        except Exception:
            logger.debug("Baseline limit could not resolve client IP", exc_info=True)
            key = "unknown"

        if self._within_limit("baseline:" + key):
            return await self.app(scope, receive, send)

        from core.rate_limit_audit import record_rejection

        request_id = getattr(request.state, "request_id", None)
        retry_after = self._retry_after_seconds()
        record_rejection(
            request,
            layer="baseline",
            limit=str(self._item),
            retry_after=retry_after,
        )
        response = JSONResponse(
            status_code=429,
            content={
                "success": False,
                "error_code": "RATE_LIMIT_EXCEEDED",
                "message": "Too many requests. Please slow down and try again.",
                "retry_after_seconds": retry_after,
                "request_id": request_id,
            },
            headers={
                "Retry-After": str(retry_after),
                "X-Request-ID": request_id or "",
            },
        )
        await response(scope, receive, send)

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _retry_after_seconds(self) -> int:
        """The configured window, so the value matches the limit that refused."""
        try:
            return int(self._item.get_expiry())
        except Exception:
            return 60

    @staticmethod
    def _report_shared_limiter_health(limiter) -> None:
        from core.rate_limit_audit import report_degradation

        try:
            report_degradation("endpoint", bool(getattr(limiter, "_storage_dead")))
        except Exception:  # never let bookkeeping break a request
            pass
