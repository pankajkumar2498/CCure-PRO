"""
routers/notifications.py
─────────────────────────────────────────────────────────────────────────────
User notification center for scan events, system messages, and alerts.

Endpoints
─────────
  GET    /notifications                      → List notifications
  GET    /notifications/summary               → Get unread count by category
  PATCH  /notifications/{id}/read             → Mark single notification as read
  PATCH  /notifications/read-all              → Mark all notifications as read
  DELETE /notifications/{id}                  → Delete a notification
  DELETE /notifications                       → Delete all notifications

Notification Types
──────────────────
  - scan_completed    → Scan finished successfully
  - scan_failed       → Scan encountered an error
  - scan_paused       → Scan was paused
  - vulnerability_found → Critical/High vulnerability discovered
  - system_message    → System maintenance, new features, etc.
  - admin_notice      → User invitation, permission changes, etc.
"""

from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "routers.notifications")


import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import List, Optional

from ccure_platform.identity.dependencies import get_current_user
from ccure_platform.notifications.service import (
    NotificationResponse,
    NotificationSummaryResponse,
    publish_summary,
    summary_payload,
)
from core.redis_client import redis_client
from db.base import SessionLocal, get_db, utcnow
from db.models import Notification, User
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

router = APIRouter(prefix="/notifications", tags=["Notifications"])
logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────────────
# SSE framing (HTTP transport — stays with the endpoints)
# ────────────────────────────────────────────────────────────────────────────


def _format_sse(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, default=str, separators=(',', ':'))}\n\n"


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────


@router.get("", response_model=list[NotificationResponse])
def list_notifications(
    category: str | None = Query(
        None, description="Filter by category (scan, security, system, admin)"
    ),
    unread_only: bool = Query(False, description="Show only unread notifications"),
    limit: int = Query(50, ge=1, le=200, description="Max notifications to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List notifications for the current user.

    Supports filtering by category and showing only unread.
    Ordered by newest first.
    """
    query = db.query(Notification).filter(Notification.user_id == current_user.id)

    if unread_only:
        query = query.filter(Notification.is_read == False)

    if category:
        query = query.filter(Notification.category == category)

    notifications = (
        query.order_by(Notification.created_at.desc()).offset(offset).limit(limit).all()
    )
    return notifications


@router.get("/summary", response_model=NotificationSummaryResponse)
def get_notification_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get a summary of unread notifications by category.

    Useful for showing badge counts in UI.
    """
    return summary_payload(db, str(current_user.id))


@router.get("/stream")
async def stream_notifications(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """
    Stream committed notification events for the current user.

    The durable inbox stays in PostgreSQL. Redis Pub/Sub distributes events
    across API workers, and this SSE stream keeps the browser updated without
    periodic "do I have anything new?" requests.
    """
    user_id = str(current_user.id)
    channel = f"notifications:user:{user_id}"

    async def event_generator():
        db = SessionLocal()
        try:
            summary = summary_payload(db, user_id)
        finally:
            db.close()

        yield _format_sse(
            "connected",
            {
                "ok": True,
                "summary": summary,
            },
        )

        connected_at = time.monotonic()
        pubsub = redis_client.pubsub()
        try:
            await pubsub.subscribe(channel)
            # A fresh connection every few tens of seconds, for one user, all
            # day, is normal SSE churn (tab backgrounding, laptop sleep, a
            # flaky hop) — logging it at INFO turns into most of the log
            # volume once more than a couple of users are online. What is
            # actually interesting is a connection that keeps *closing*
            # abnormally fast; see the duration check in `finally` below.
            logger.debug("Notification stream connected for user %s", user_id)
        except Exception as exc:
            logger.warning(
                "Notification stream heartbeat-only mode for user %s: %s",
                user_id,
                exc.__class__.__name__,
            )
            await pubsub.close()
            while True:
                yield _format_sse("heartbeat", {"emitted_at": utcnow().isoformat()})
                await asyncio.sleep(25)
            return

        try:
            while True:
                message = await pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=25
                )
                if message:
                    payload = json.loads(message["data"])
                    yield _format_sse(payload.get("event", "notification"), payload)
                else:
                    yield _format_sse("heartbeat", {"emitted_at": utcnow().isoformat()})
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Notification stream failed for user %s: %s", user_id, exc)
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.close()
            duration = time.monotonic() - connected_at
            # The heartbeat cadence is 25s, so a healthy connection that has
            # nothing else to send still lives past that mark. One closing
            # sooner than that never got as far as its first heartbeat —
            # that's the client aborting, a proxy dropping it, or an auth
            # failure, not routine churn — and is worth a WARNING precisely
            # because it's the signal that would otherwise be buried under
            # routine reconnects logged at the same level.
            if duration < 20:
                logger.warning(
                    "Notification stream for user %s closed after %.1fs, "
                    "before its first heartbeat — investigate for a "
                    "premature disconnect (client, proxy, or auth) rather "
                    "than treating this as routine reconnect churn",
                    user_id,
                    duration,
                )
            else:
                logger.debug(
                    "Notification stream disconnected for user %s after %.1fs",
                    user_id,
                    duration,
                )

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.patch("/{notification_id}/read", response_model=NotificationResponse)
def mark_as_read(
    notification_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Mark a single notification as read."""
    notification = (
        db.query(Notification)
        .filter(
            Notification.id == notification_id,
            Notification.user_id == current_user.id,
        )
        .first()
    )

    if not notification:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found",
        )

    if not notification.is_read:
        notification.is_read = True
        notification.read_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(notification)
        publish_summary(db, str(current_user.id))

    return notification


@router.patch("/read-all", status_code=200)
def mark_all_as_read(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Mark all unread notifications as read."""
    now = datetime.now(timezone.utc)
    db.query(Notification).filter(
        Notification.user_id == current_user.id,
        Notification.is_read == False,
    ).update(
        {
            Notification.is_read: True,
            Notification.read_at: now,
        }
    )
    db.commit()
    publish_summary(db, str(current_user.id))
    return {"detail": "All notifications marked as read"}


@router.delete("/{notification_id}", status_code=204)
def delete_notification(
    notification_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a single notification."""
    notification = (
        db.query(Notification)
        .filter(
            Notification.id == notification_id,
            Notification.user_id == current_user.id,
        )
        .first()
    )

    if not notification:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found",
        )

    db.delete(notification)
    db.commit()
    publish_summary(db, str(current_user.id))


@router.delete("", status_code=204)
def delete_all_notifications(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete all notifications for the current user."""
    db.query(Notification).filter(
        Notification.user_id == current_user.id,
    ).delete()
    db.commit()
    publish_summary(db, str(current_user.id))
