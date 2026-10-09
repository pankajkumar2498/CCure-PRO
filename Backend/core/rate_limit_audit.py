"""
core/rate_limit_audit.py
────────────────────────
Observability for rate limiting: what got refused, and whether the limiter is
still working properly.

Why this is its own module
──────────────────────────
A rate limit that refuses silently is a technical control. A rate limit that
records *what* it refused is a security signal — the difference between "some
requests were dropped" and "one address made 1,000 login attempts against one
account in four minutes". The second is detectable credential stuffing; the
first is noise. Both layers (the per-route limiter and the baseline middleware)
have to record it the same way or the signal is split across two shapes.

What is deliberately **not** recorded
─────────────────────────────────────
No password, OTP, refresh token, reset token or Authorization header value ever
reaches this module — it is handed a request and an exception, and reads only
the fields named below.

**The account named in a failed login is also not recorded**, and that is a
decision rather than an omission. `/auth/forgot-password` already refuses to
log whether an identifier matched, on the grounds that writing "not registered"
beside an address moves the account-existence oracle somewhere with a wider
audience and a longer retention period. A 429 log line naming the address
somebody was trying would recreate exactly that, in the file most likely to be
shipped to a log aggregator. The authenticated user id *is* recorded when the
caller presented a valid token, because that is not a guess about who exists —
they proved it.

Degradation
───────────
`report_degradation` exists because the fallback path is invisible by design:
when Redis goes away the limiter keeps answering, so nothing in the response
tells an operator that the counters are now per-worker and the effective
ceiling has been multiplied by the worker count. It logs only on *transition*,
so a long outage produces two lines rather than one per request, and it uses a
fixed marker string so an alert can be keyed on it:

    RATE_LIMIT_DEGRADED   — counters are no longer shared; effective limit is
                            (configured limit x worker count)
    RATE_LIMIT_RECOVERED  — shared counters are authoritative again
"""

from __future__ import annotations

import logging

logger = logging.getLogger("ccure.security.ratelimit")

# How to read an access token, supplied by the application at start-up
# (main.py registers auth.jwt_handler.decode_token). Injected rather than
# imported since Phase 3 of the modular-platform programme: this module is
# shared infrastructure, and importing the auth package from here made it
# depend on a feature. With nothing registered, callers are simply not
# attributed — the same answer given to any caller without a valid token.
_token_decoder = None


def set_token_decoder(decoder) -> None:
    """Register the function that verifies and decodes an access token."""
    global _token_decoder
    _token_decoder = decoder


# Tracks the last reported state per component so only transitions are logged.
_degraded_state: dict[str, bool] = {}


def _client_ip(request) -> str:
    try:
        from core.ip_resolver import get_client_ip

        return get_client_ip(request) or "unknown"
    except Exception:
        return "unknown"


def _caller_identity(request) -> tuple[str | None, str | None]:
    """
    (user_id, org_id) when the caller presented a valid access token.

    Signature-verified, so this cannot be spoofed into attributing an attack to
    somebody else. Returns (None, None) for an unauthenticated caller, which is
    most of what this module sees — the endpoints with the tightest limits are
    the ones you reach before you have a token.
    """
    try:
        header = request.headers.get("authorization") or ""
        if not header.lower().startswith("bearer "):
            return None, None

        if _token_decoder is None:
            return None, None

        payload = _token_decoder(header.split(" ", 1)[1].strip())
        if not payload or payload.get("type") == "refresh":
            return None, None
        return payload.get("sub"), payload.get("org_id")
    except Exception:
        return None, None


def limit_window_seconds(exc) -> int | None:
    """
    The window of the limit that was breached, for Retry-After.

    Reads slowapi's `RateLimitExceeded.limit.limit`, which is a `limits`
    RateLimitItem. Returns None rather than guessing if the shape changes — a
    wrong Retry-After is worse than none, because a client will believe it.
    """
    try:
        return int(exc.limit.limit.get_expiry())
    except Exception:
        return None


def record_rejection(
    request,
    *,
    layer: str,
    limit: str | None = None,
    retry_after: int | None = None,
) -> None:
    """
    Log one refused request.

    `layer` names which control refused it — "endpoint" for a per-route
    @limiter.limit, "baseline" for the API-wide ceiling. Without it the two are
    indistinguishable in the log, and they mean very different things: the
    first is somebody hammering a specific sensitive operation, the second is
    volume against the application generally.
    """
    user_id, org_id = _caller_identity(request)
    client_ip = _client_ip(request)
    method = getattr(request, "method", "-")
    path = getattr(getattr(request, "url", None), "path", "-")
    request_id = getattr(getattr(request, "state", None), "request_id", None)

    logger.warning(
        "RATE_LIMIT_REJECTED layer=%s method=%s path=%s ip=%s user=%s org=%s "
        "limit=%s retry_after=%s request_id=%s",
        layer,
        method,
        path,
        client_ip,
        user_id or "-",
        org_id or "-",
        limit or "-",
        retry_after if retry_after is not None else "-",
        request_id or "-",
        extra={
            "event": "rate_limit_rejected",
            "layer": layer,
            "http_method": method,
            "path": path,
            "client_ip": client_ip,
            "user_id": user_id,
            "org_id": org_id,
            "limit": limit,
            "retry_after": retry_after,
            "request_id": request_id,
        },
    )


def report_degradation(component: str, degraded: bool) -> None:
    """
    Announce that rate limiting has fallen back to process-local counters, or
    recovered. Logs only when the state changes.
    """
    if _degraded_state.get(component) == degraded:
        return
    _degraded_state[component] = degraded

    if degraded:
        logger.error(
            "RATE_LIMIT_DEGRADED component=%s — the shared counter store is "
            "unreachable and limits are now enforced per worker process. The "
            "effective ceiling is the configured limit multiplied by the "
            "worker count until this clears.",
            component,
            extra={"event": "rate_limit_degraded", "component": component},
        )
    else:
        logger.warning(
            "RATE_LIMIT_RECOVERED component=%s — shared counters are "
            "authoritative again.",
            component,
            extra={"event": "rate_limit_recovered", "component": component},
        )


def reset_degradation_state() -> None:
    """Clear the transition tracker. For tests only."""
    _degraded_state.clear()
