"""
ccure_platform/identity/registration_limits.py (was auth/registration_limits.py until Phase 8.2)
──────────────────────────────────────────────────────────────────────────────
Volume controls for self-service registration.

Domain screening and volume control solve different problems and neither
substitutes for the other. A blocklist does nothing about a bot registering two
hundred accounts through real Gmail addresses; a rate limit does nothing about
one person signing up from a throwaway inbox.

What already existed: `@limiter.limit("3/minute")` on `/auth/register`. That
stops a burst and nothing else — three per minute sustained is 4,320 accounts a
day, each one sending an email to an address the caller chose. Two ceilings are
added here.

Both fail **open**. A Redis outage or a slow count must not make the product
unable to accept new users; these are abuse dampeners, not security boundaries,
and the security boundary — administrator approval — is somewhere else and
still holds.
"""

from __future__ import annotations

from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "auth.registration_limits")

import datetime
import logging

logger = logging.getLogger(__name__)

_DAILY_KEY_PREFIX = "ccure:reg:daily"


def _client_ip(request) -> str:
    try:
        # Same resolver the rate limiter uses: it walks X-Forwarded-For from the
        # nearest hop outward and stops at the first untrusted address, so a
        # caller behind the nginx gateway is counted individually and cannot
        # spoof its way into somebody else's bucket.
        from core.ip_resolver import get_client_ip

        return get_client_ip(request) or "unknown"
    except Exception:
        client = getattr(request, "client", None)
        return getattr(client, "host", None) or "unknown"


def daily_ip_quota_exceeded(request) -> bool:
    """
    True when this client has already registered its daily allowance.

    Counted in Redis because the API runs more than one process and an
    in-process counter would multiply the real limit by the worker count. The
    key carries the UTC date and expires after 48 hours, so no cleanup job is
    needed and a clock skew of a few hours cannot resurrect yesterday's count.

    Increments on every *attempt*, not on every success. A caller probing with
    addresses that get refused is exactly the traffic worth capping, and
    counting only successes would let them probe indefinitely.
    """
    from config import AppConfig

    limit = AppConfig.REGISTRATION_DAILY_IP_LIMIT
    if limit <= 0:
        return False

    ip = _client_ip(request)
    if ip == "unknown":
        return False

    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
    key = f"{_DAILY_KEY_PREFIX}:{today}:{ip}"

    try:
        from core.redis_client import get_redis_client

        client = get_redis_client()
        count = client.incr(key)
        if count == 1:
            client.expire(key, 60 * 60 * 48)
        return count > limit
    except Exception as exc:
        # Fail open. See module docstring: an unreachable Redis must not stop
        # legitimate signups, and the approval gate still stands behind this.
        logger.warning(
            "Registration daily quota check unavailable (%s); allowing",
            exc.__class__.__name__,
        )
        return False


def pending_queue_full(db) -> bool:
    """
    True when the approval queue has more entries than an admin can be expected
    to triage.

    The queue is a person's attention, and a flood of junk accounts is a denial
    of service against that attention just as surely as against a CPU. Past the
    ceiling, new registrations are refused until somebody drains it — which is
    the correct failure: the accounts already queued are the ones that need
    looking at, and adding more does not help anyone.
    """
    from config import AppConfig

    limit = AppConfig.PENDING_APPROVAL_QUEUE_LIMIT
    if limit <= 0:
        return False

    try:
        from ccure_platform.models import User

        pending = (
            db.query(User)
            .filter(
                User.approved_at.is_(None),
                User.is_deleted.is_(False),
            )
            .count()
        )
        return pending >= limit
    except Exception as exc:
        logger.warning(
            "Pending-queue ceiling check failed (%s); allowing",
            exc.__class__.__name__,
        )
        return False
