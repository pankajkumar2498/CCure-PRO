import redis.asyncio as async_redis
import redis as sync_redis
from config import AppConfig
import json
import datetime
import logging

# Async client for FastAPI WebSocket (PubSub)
redis_client = async_redis.from_url(AppConfig.CELERY_BROKER_URL)

# Sync client for Celery workers / Thread pools (Publishing)
_sync_redis_client = sync_redis.from_url(AppConfig.CELERY_BROKER_URL)

async def publish_progress(scan_id: str, phase: int, progress: dict):
    """Async progress publishing for async engines (Discovery, Port)."""
    l = logging.getLogger("ccure.redis")
    message = json.dumps({
        "scan_id": scan_id,
        "phase": phase,
        "progress": progress
    })
    l.info("[TRACE][REDIS][%s] Publishing progress (ASYNC) for scan %s, phase %d, status %s", 
           datetime.datetime.now().isoformat(), scan_id, phase, progress.get("status"))
    import asyncio
    await asyncio.to_thread(_sync_redis_client.publish, f"scan_progress:{scan_id}", message)

def publish_progress_sync(scan_id: str, phase: int, progress: dict):
    """Synchronous progress publishing for threaded engines (Vulnerability) or Celery tasks."""
    l = logging.getLogger("ccure.redis")
    message = json.dumps({
        "scan_id": scan_id,
        "phase": phase,
        "progress": progress
    })
    l.info("[TRACE][REDIS][%s] Publishing progress (SYNC) for scan %s, phase %d, status %s", 
           datetime.datetime.now().isoformat(), scan_id, phase, progress.get("status"))
    _sync_redis_client.publish(f"scan_progress:{scan_id}", message)
