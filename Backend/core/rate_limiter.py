"""
The API's rate limiter — one shared slowapi instance for every router.

Moved here from ``scan_helpers.py`` (Phase 3 of the modular-platform programme).
``auth/router.py`` limits the login and password routes, and had to import the
scan helpers module to reach the limiter — identity depending on scanning code.
The limiter is infrastructure both use; ``scan_helpers`` re-exports this very
object, so ``from scan_helpers import limiter`` still returns the same instance
``main.py`` registers and the test suite disables.

Behaviour is unchanged, including the logger (``ccure.api``).
"""

import logging

from config import AppConfig
from core.ip_resolver import get_client_ip
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.responses import Response

log = logging.getLogger("ccure.api")


def _rate_limit_key(request) -> str:
    """
    Identify the client a rate limit should apply to.

    slowapi's get_remote_address returns the socket peer. Behind the nginx
    gateway that is always the proxy container, so every user shared a single
    bucket and one analyst's burst locked scanning for the whole organisation.
    get_client_ip walks the X-Forwarded-For chain from the nearest hop outward
    and stops at the first address that is not a trusted proxy, so a client
    cannot spoof its way into someone else's bucket either.
    """
    try:
        resolved = get_client_ip(request)
        if resolved:
            return resolved
    except Exception:  # never let limiter bookkeeping break a request
        log.debug("Falling back to socket address for rate limiting", exc_info=True)
    return get_remote_address(request)


# ─── Rate limiter (shared across routers) ────────────────────────────────────
#
# Counters live in the same Redis instance as Celery, which is what makes the
# limit a real limit: an in-process counter would be multiplied by the number of
# API worker processes, so "3/minute" would mean 3 per minute *per worker*.
#
# `in_memory_fallback` decides what happens when that Redis is unreachable, and
# the previous answer was bad in a way that is easy to miss. slowapi is built
# with swallow_errors=False, so a storage failure propagated straight out of the
# decorator: login, registration and every scan endpoint answered 500. That is
# not a fail-closed rate limit, it is an outage of the authentication system,
# and it hands anyone who can disrupt Redis a way to take the product down.
#
# With a fallback configured, slowapi switches to process-local counters for the
# duration and re-probes the backend periodically. Two honest caveats: the
# counters are per worker process, and slowapi applies the *fallback* limit in
# place of each route's own while the backend is down. The control is degraded,
# not absent — which is the right trade for an outage nobody chose.
_fallback_limits = (
    [AppConfig.RATE_LIMIT_MEMORY_FALLBACK]
    if AppConfig.RATE_LIMIT_MEMORY_FALLBACK
    else []
)


class _HeaderSafeLimiter(Limiter):
    """A Limiter whose header injection cannot take an endpoint down.

    With ``headers_enabled=True`` slowapi writes X-RateLimit-* onto the
    response after the handler returns. It finds that response one of two
    ways: the handler returned a ``Response`` object, or the handler declared
    a ``response: Response`` parameter that FastAPI filled in. A handler that
    does neither — the overwhelming majority, since returning a dict and
    letting FastAPI serialise it is the normal style — hands slowapi ``None``,
    and upstream `_inject_headers` answers that with a bare
    ``raise Exception(...)`` from inside the endpoint call.

    That is a 500 on every single request to the route, caused by a missing
    parameter, and it is invisible until the route is exercised on a live
    server: the test suite sets ``limiter.enabled = False``, which skips
    injection entirely. Twenty-one routes shipped in exactly that state,
    including `/scan/host-discovery` and `/auth/reset-password`, because
    adding a limit to a route requires a change to its signature that nothing
    checked for.

    Missing rate-limit headers are a cosmetic loss; a 500 on scan dispatch is
    an outage. So the same trade this module already makes for a Redis outage
    applies here — degrade, log, and keep answering. `_route_limits` is
    untouched, so the limit itself is still enforced; only the advisory
    headers go missing.

    `tests/security/test_rate_limit_headers.py` is what keeps this from
    becoming a silent excuse for never declaring the parameter.
    """

    # Endpoints already warned about. The condition is a property of the route,
    # not of the request, so it is logged once per endpoint — the same reason
    # RATE_LIMIT_DEGRADED is logged on transition rather than per request. A
    # line every request would bury the log of a busy route in a message about
    # a missing header.
    _warned_endpoints: set[str] = set()

    def _inject_headers(self, response, current_limit):  # type: ignore[override]
        if not isinstance(response, Response):
            if self.enabled and self._headers_enabled and current_limit is not None:
                # current_limit[1] is [key, scope]; the scope is the endpoint
                # slowapi registered the limit against, which is the one piece
                # of information that makes this actionable.
                scope = current_limit[1][-1] if len(current_limit[1]) > 1 else "?"
                if scope not in self._warned_endpoints:
                    self._warned_endpoints.add(scope)
                    log.warning(
                        "Rate limit headers skipped for %s: the endpoint "
                        "neither returned a Response nor declared a "
                        "`response: Response` parameter. The limit is still "
                        "enforced. See tests/security/test_rate_limit_headers.py",
                        scope,
                    )
            return response
        return super()._inject_headers(response, current_limit)


limiter = _HeaderSafeLimiter(
    key_func=_rate_limit_key,
    storage_uri=AppConfig.CELERY_BROKER_URL,
    in_memory_fallback=_fallback_limits,
    # X-RateLimit-* on every limited response. Clients can back off before they
    # are refused, and an auditor can confirm a limit is live from the wire
    # rather than from the source.
    headers_enabled=True,
)
