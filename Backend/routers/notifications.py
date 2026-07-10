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

import asyncio
import json
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from db.base import get_db, gen_notification_id, SessionLocal, utcnow
from db.models import User, Notification, Role
from auth.dependencies import get_current_user
from core.redis_client import publish_notification_sync, redis_client

router = APIRouter(prefix="/notifications", tags=["Notifications"])
logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────────────
# Enums
# ────────────────────────────────────────────────────────────────────────────

class NotificationType(str, Enum):
    """Available notification types."""
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_PAUSED = "scan_paused"
    VULNERABILITY_FOUND = "vulnerability_found"
    SYSTEM_MESSAGE = "system_message"
    ADMIN_NOTICE = "admin_notice"


class NotificationCategory(str, Enum):
    """Notification categories for filtering."""
    SCAN = "scan"
    SECURITY = "security"
    SYSTEM = "system"
    ADMIN = "admin"


# ────────────────────────────────────────────────────────────────────────────
# Request/Response Models
# ────────────────────────────────────────────────────────────────────────────

class NotificationResponse(BaseModel):
    """Notification response model."""
    id: str
    type: str
    category: str
    title: str
    message: str
    is_read: bool
    related_scan_id: Optional[str]
    related_data: dict
    action_url: Optional[str]
    created_at: datetime
    read_at: Optional[datetime]

    class Config:
        from_attributes = True


class NotificationSummaryResponse(BaseModel):
    """Summary of unread notifications by category."""
    total_unread: int
    by_category: dict  # {"scan": 2, "security": 1, "system": 0, "admin": 0}
    last_notification_at: Optional[datetime]


# ────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ────────────────────────────────────────────────────────────────────────────

def _format_sse(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, default=str, separators=(',', ':'))}\n\n"


def _notification_payload(notification: Notification) -> dict:
    return NotificationResponse.model_validate(notification).model_dump(mode="json")


def _summary_payload(db: Session, user_id: str) -> dict:
    unread_by_category = db.query(
        Notification.category,
        func.count(Notification.id).label("count")
    ).filter(
        Notification.user_id == user_id,
        Notification.is_read == False,
    ).group_by(Notification.category).all()

    category_counts = {cat: 0 for cat in ["scan", "security", "system", "admin"]}
    for cat, count in unread_by_category:
        category_counts[cat] = count

    last_notif = db.query(Notification).filter(
        Notification.user_id == user_id
    ).order_by(Notification.created_at.desc()).first()

    return NotificationSummaryResponse(
        total_unread=sum(category_counts.values()),
        by_category=category_counts,
        last_notification_at=last_notif.created_at if last_notif else None,
    ).model_dump(mode="json")


def _publish_new_notification(notification: Notification) -> None:
    publish_notification_sync(str(notification.user_id), {
        "event": "notification.created",
        "notification": _notification_payload(notification),
    })


def _publish_summary(db: Session, user_id: str) -> None:
    publish_notification_sync(str(user_id), {
        "event": "notifications.summary",
        "summary": _summary_payload(db, str(user_id)),
    })


def create_notification(
    db: Session,
    user_id: str,
    notification_type: NotificationType,
    category: NotificationCategory,
    title: str,
    message: str,
    related_scan_id: Optional[str] = None,
    related_data: Optional[dict] = None,
    action_url: Optional[str] = None,
) -> Notification:
    """
    Create and store a new notification.
    
    Called internally when scan completes, vulnerability is found, etc.
    """
    user = db.query(User).filter(User.id == user_id).first()
    username = user.username if user else user_id

    notification = Notification(
        id=gen_notification_id(user_id, notification_type.value),
        user_id=user_id,
        type=notification_type.value,
        category=category.value,
        title=title,
        message=message,
        related_scan_id=related_scan_id,
        related_data=related_data or {},
        action_url=action_url,
    )
    db.add(notification)
    db.commit()
    db.refresh(notification)
    logger.info("Created notification for user %s: %s", user_id, title)
    _publish_new_notification(notification)
    _publish_summary(db, user_id)
    return notification

def fan_out_notification(
    db: Session,
    org_id: str,
    target_roles: List[str],
    notification_type: NotificationType,
    category: NotificationCategory,
    title: str,
    message: str,
    related_scan_id: Optional[str] = None,
    related_data: Optional[dict] = None,
    action_url: Optional[str] = None,
    exclude_user_id: Optional[str] = None,
) -> int:
    """
    Fan-out a notification to all active users in an organization matching specific roles,
    respecting their in-app alert preferences.
    """
    # Find roles
    roles = db.query(Role).filter(Role.name.in_(target_roles)).all()
    role_ids = [r.id for r in roles]
    
    if not role_ids:
        return 0

    # Find users
    users = db.query(User).filter(
        User.org_id == org_id,
        User.role_id.in_(role_ids),
        User.is_active == True,
        User.is_deleted == False
    ).all()

    inserted = 0
    notifications = []
    for user in users:
        # Exclude the triggerer if requested (e.g. they already got a direct personal notification)
        if exclude_user_id and str(user.id) == exclude_user_id:
            continue
            
        # Respect User Preferences
        prefs = user.preferences or {}
        if prefs.get("in_app_alerts", True) is False:
            continue

        notification = Notification(
            id=gen_notification_id(user.id, notification_type.value),
            user_id=user.id,
            type=notification_type.value,
            category=category.value,
            title=title,
            message=message,
            related_scan_id=related_scan_id,
            related_data=related_data or {},
            action_url=action_url,
        )
        db.add(notification)
        notifications.append(notification)
        inserted += 1

    if inserted > 0:
        db.commit()
        for notification in notifications:
            _publish_new_notification(notification)
            _publish_summary(db, str(notification.user_id))
        logger.info("Fanned out notification %r to %d users in org %s", title, inserted, org_id)
        
    return inserted


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────

@router.get("", response_model=List[NotificationResponse])
def list_notifications(
    category: Optional[str] = Query(None, description="Filter by category (scan, security, system, admin)"),
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

    notifications = query.order_by(Notification.created_at.desc()).offset(offset).limit(limit).all()
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
    return _summary_payload(db, str(current_user.id))


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
            yield _format_sse("connected", {
                "ok": True,
                "summary": _summary_payload(db, user_id),
            })
        finally:
            db.close()

        pubsub = redis_client.pubsub()
        try:
            await pubsub.subscribe(channel)
            logger.info("Notification stream connected for user %s", user_id)
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
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=25)
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
            logger.info("Notification stream disconnected for user %s", user_id)

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
    notification = db.query(Notification).filter(
        Notification.id == notification_id,
        Notification.user_id == current_user.id,
    ).first()

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
        _publish_summary(db, str(current_user.id))

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
    ).update({
        Notification.is_read: True,
        Notification.read_at: now,
    })
    db.commit()
    _publish_summary(db, str(current_user.id))
    return {"detail": "All notifications marked as read"}


@router.delete("/{notification_id}", status_code=204)
def delete_notification(
    notification_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a single notification."""
    notification = db.query(Notification).filter(
        Notification.id == notification_id,
        Notification.user_id == current_user.id,
    ).first()

    if not notification:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found",
        )

    db.delete(notification)
    db.commit()
    _publish_summary(db, str(current_user.id))
    return None


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
    _publish_summary(db, str(current_user.id))
    return None
