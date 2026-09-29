"""
Single use of a service assertion (Phase 9.5).

Each assertion's ``jti`` is recorded in Redis with ``SET NX`` for as long as
the assertion could still be valid, so a captured assertion cannot be replayed
for a second token. **Fail closed** (owner's decision): if Redis cannot answer,
the assertion is refused rather than accepted unrecorded — a replay window
opened by an outage is exactly the case this exists for.
"""

from __future__ import annotations

import hashlib
import logging

log = logging.getLogger("ccure.service_identity")

_KEY_PREFIX = "ccure:svc-assertion"


class ReplayStoreUnavailable(RuntimeError):
    """The replay store could not record the assertion."""


def claim_assertion(service_id: str, jti: str, ttl_seconds: int) -> bool:
    """
    True the first time ``(service_id, jti)`` is presented; False on a replay.
    Raises ReplayStoreUnavailable when the store cannot answer.
    """
    digest = hashlib.sha256(jti.encode("utf-8")).hexdigest()
    key = f"{_KEY_PREFIX}:{service_id}:{digest}"
    try:
        from core.redis_client import get_redis_client

        return bool(
            get_redis_client().set(key, "1", nx=True, ex=max(1, int(ttl_seconds)))
        )
    except Exception as exc:  # any store failure refuses
        log.error(
            "Service assertion replay store unavailable (%s); refusing",
            exc.__class__.__name__,
        )
        raise ReplayStoreUnavailable(str(exc)) from exc
