import datetime
import json
import logging

import redis as sync_redis
import redis.asyncio as async_redis
from config import AppConfig
from redis.exceptions import RedisError

# Async client for FastAPI WebSocket (PubSub)
redis_client = async_redis.from_url(AppConfig.CELERY_BROKER_URL)

# Sync client for Celery workers / Thread pools (Publishing)
_sync_redis_client = sync_redis.from_url(AppConfig.CELERY_BROKER_URL)


def get_redis_client():
    """Return the synchronous Redis client."""
    return _sync_redis_client


#: Progress publishing is a live-update convenience, not a system of record.
#:
#: Every figure these channels carry is already committed to PostgreSQL — phase
#: rows and their summaries by scans/db_helpers.py, per-IP counters by
#: scans/progress.py — and GET /scan/progress/{scan_id} reads it back from
#: there. A subscriber that misses a frame therefore loses nothing permanent;
#: it refreshes and sees the same state.
#:
#: So a Redis outage must not end a scan. It previously did: an unguarded
#: publish raised ConnectionError out of the engine loop and up through the
#: Celery task, discarding an audit that had already done its network work.
#: The scan died for want of a status message about itself.
#:
#: publish_notification_sync below has always been written this way. These two
#: now match it.
def _publish(channel: str, message: str, label: str) -> None:
    """Publish, or log why it could not. Never raises at the caller."""
    logger = logging.getLogger("ccure.redis")
    try:
        _sync_redis_client.publish(channel, message)
    except RedisError as exc:
        logger.warning(
            "Realtime progress publish failed on %s (%s): %s — the scan "
            "continues; state remains readable from the database.",
            channel,
            label,
            exc.__class__.__name__,
        )


async def publish_progress(scan_id: str, phase: int, progress: dict):
    """Async progress publishing for async engines (Discovery, Port)."""
    l = logging.getLogger("ccure.redis")
    message = json.dumps({"scan_id": scan_id, "phase": phase, "progress": progress})
    l.info(
        "[TRACE][REDIS][%s] Publishing progress (ASYNC) for scan %s, phase %d, status %s",
        datetime.datetime.now().isoformat(),
        scan_id,
        phase,
        progress.get("status"),
    )
    import asyncio

    await asyncio.to_thread(_publish, f"scan_progress:{scan_id}", message, "async")


def publish_progress_sync(scan_id: str, phase: int, progress: dict):
    """Synchronous progress publishing for threaded engines (Vulnerability) or Celery tasks."""
    l = logging.getLogger("ccure.redis")
    message = json.dumps({"scan_id": scan_id, "phase": phase, "progress": progress})
    l.info(
        "[TRACE][REDIS][%s] Publishing progress (SYNC) for scan %s, phase %d, status %s",
        datetime.datetime.now().isoformat(),
        scan_id,
        phase,
        progress.get("status"),
    )
    _publish(f"scan_progress:{scan_id}", message, "sync")


def publish_notification_sync(user_id: str, event: dict) -> None:
    """Publish a user-scoped notification event without failing the caller."""
    logger = logging.getLogger("ccure.redis")
    channel = f"notifications:user:{user_id}"
    try:
        _sync_redis_client.publish(channel, json.dumps(event, default=str))
        logger.debug(
            "Published notification event %s for user %s", event.get("event"), user_id
        )
    except RedisError as exc:
        logger.warning(
            "Notification realtime publish failed for user %s: %s",
            user_id,
            exc.__class__.__name__,
        )


def connect_nmap_lease_client():
    """
    A fresh connection for the Nmap wrapper's global process limiter, on the
    Celery broker. Moved from the wrapper unchanged (G3); the caller pings it.
    """
    import redis

    from config import AppConfig

    return redis.from_url(
        AppConfig.CELERY_BROKER_URL,
        socket_timeout=3,
        socket_connect_timeout=3,
        decode_responses=True,
    )
