"""
core/web/rate_limits.py
─────────────────────────────────────────────────────────────────────────────
The web DAST routes' rate limits, enforced by the limiter the host registers
(Group 4, D2 in docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

``routers/web_scans.py`` used to decorate two routes with
``core.rate_limiter.limiter`` itself. It declares the limit with :func:`limit`
now, and the host registers its limiter with :func:`configure`: Audit's
composition root registers ``core.rate_limiter.limiter``
(``ccure_audit/web_routes.py``), the one ``main`` puts on ``app.state``.

Nothing about the limit changes. The registered limiter decorates the route's
own function, exactly as the decorator did, so slowapi records the limit under
the same key (``routers.web_scans.start_web_scan``) and its wrapper checks and
counts the request and writes the rate-limit headers. A route declared before
the limiter is registered is decorated when it is; one declared after, at once.

A limited route called with no limiter registered raises ``RateLimiterMissing``
rather than serving the request unlimited.
"""

from __future__ import annotations

import asyncio
import functools
import threading
from typing import Any, Callable, Optional

__all__ = ["RateLimiterMissing", "configure", "current", "limit"]


class RateLimiterMissing(RuntimeError):
    """A limited web DAST route was called and no host registered a limiter."""


_limiter: Optional[Any] = None
_lock = threading.Lock()


class _LimitedRoute:
    """One declared limit, and its route decorated by each limiter that applied it."""

    def __init__(self, spec: str, func: Callable[..., Any]):
        self.spec = spec
        self.func = func
        # id(limiter) -> (limiter, the function it decorated). Decorated once
        # per limiter: a second decoration would count every request twice.
        self._decorated: dict[int, tuple[Any, Callable[..., Any]]] = {}

    def by(self, limiter: Any) -> Callable[..., Any]:
        with _lock:
            held = self._decorated.get(id(limiter))
            if held is None or held[0] is not limiter:
                held = (limiter, limiter.limit(self.spec)(self.func))
                self._decorated[id(limiter)] = held
            return held[1]


_routes: list[_LimitedRoute] = []


def configure(limiter: Any) -> None:
    """
    Register the limiter the routes' limits are enforced by, and apply it to
    every route already declared. The same limiter again does nothing; a
    second, different one is refused.
    """
    global _limiter
    if _limiter is limiter:
        return
    if _limiter is not None:
        raise ValueError("a web DAST rate limiter is already registered")
    _limiter = limiter
    for route in _routes:
        route.by(limiter)


def current() -> Any:
    """The registered limiter."""
    if _limiter is None:
        raise RateLimiterMissing(
            "No rate limiter is registered for the web DAST routes. Audit's "
            "composition root, ccure_audit/web_routes.py, registers "
            "core.rate_limiter.limiter: main loads it."
        )
    return _limiter


def limit(spec: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Declare a route's rate limit, as ``@limiter.limit(spec)`` did."""

    def decorate(func: Callable[..., Any]) -> Callable[..., Any]:
        route = _LimitedRoute(spec, func)
        _routes.append(route)
        if _limiter is not None:
            route.by(_limiter)

        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def limited(*args: Any, **kwargs: Any) -> Any:
                return await route.by(current())(*args, **kwargs)

        else:

            @functools.wraps(func)
            def limited(*args: Any, **kwargs: Any) -> Any:
                return route.by(current())(*args, **kwargs)

        return limited

    return decorate
