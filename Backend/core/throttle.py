"""
core/throttle.py
────────────────
Counters for abuse controls that a per-minute rate limit cannot express.

`@limiter.limit("3/minute")` bounds a *burst* from one address. It says nothing
about a patient script, and nothing at all about a counter that should be keyed
on something other than the caller — the account being targeted, for instance,
which is the only key that helps when the caller rotates addresses.

This is the same shape as the counter in `auth/registration_limits.py`, which
predates it and stays where it is: that one carries registration-specific
reasoning about the approval queue and reads better beside it.

Two properties worth stating plainly:

  * **Redis, not process memory.** The API runs more than one worker. An
    in-process counter would multiply every ceiling here by the worker count,
    which is the same bug as counting rate limits locally.

  * **Fail open, by default and on purpose.** These are abuse dampeners layered
    on top of controls that actually hold — a 256-bit reset token, administrator
    approval, the per-minute limiter with its own in-memory fallback. Refusing
    every password reset in the estate because Redis is unwell is a worse
    outcome than the abuse this bounds. Callers that need the opposite trade
    pass ``fail_open=False``.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_KEY_PREFIX = "ccure:throttle"


def hit(
    bucket: str,
    identity: str,
    limit: int,
    window_seconds: int,
    fail_open: bool = True,
) -> bool:
    """
    Record one event and report whether the ceiling is now exceeded.

    Returns True when this event puts `identity` over `limit` within
    `window_seconds` — i.e. True means *refuse*.

    Counts every attempt rather than every success. A caller probing with
    inputs that get rejected is exactly the traffic worth bounding, and
    counting only successes would let them probe indefinitely.

    A limit of 0 or below disables the ceiling, and an empty identity is not
    counted: a missing key would put every anonymous caller in one bucket and
    the first of them would lock out the rest.
    """
    if limit <= 0 or not identity:
        return False

    key = f"{_KEY_PREFIX}:{bucket}:{identity}"

    try:
        from core.redis_client import get_redis_client

        client = get_redis_client()
        count = client.incr(key)
        if count == 1:
            # Set only on creation, so a sustained attack cannot keep pushing
            # the expiry forward and neither can it reset the window.
            client.expire(key, window_seconds)
        return count > limit
    except Exception as exc:
        if fail_open:
            logger.warning(
                "Throttle %r unavailable (%s); allowing",
                bucket,
                exc.__class__.__name__,
            )
            return False
        logger.error(
            "Throttle %r unavailable (%s); refusing",
            bucket,
            exc.__class__.__name__,
        )
        return True


def client_identity(request) -> str:
    """
    The client address, resolved the same way the rate limiter resolves it.

    Goes through `core.ip_resolver`, which only believes forwarding headers
    from a trusted proxy — so a caller cannot move itself into a fresh bucket
    by setting X-Forwarded-For.
    """
    try:
        from core.ip_resolver import get_client_ip

        return get_client_ip(request) or ""
    except Exception:
        client = getattr(request, "client", None)
        return getattr(client, "host", None) or ""
