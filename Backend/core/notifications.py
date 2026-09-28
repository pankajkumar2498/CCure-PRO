"""
Notification service — creating, storing and publishing in-app notifications.

Moved here from ``routers/notifications.py`` (Phase 3 of the modular-platform
programme). Scan persistence (``scans/db_helpers.py``) had to import an HTTP
router to raise a notification — four lazy imports that broke the http-edge
rule. The router now holds only the endpoints; this module is what everything
else calls.

Behaviour is unchanged: the same rows, the same Redis publications and the
same payload shapes. Records still log under ``routers.notifications``, the
logger name they were written with before the move, so existing log filters
keep matching.
"""

from __future__ import annotations

import logging
from datetime import datetime
from enum import Enum

from ccure_platform import api as platform_api
from core.redis_client import publish_notification_sync
from db.base import gen_notification_id
from db.models import Notification
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

logger = logging.getLogger("routers.notifications")


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
    related_scan_id: str | None
    related_data: dict
    action_url: str | None
    created_at: datetime
    read_at: datetime | None

    class Config:
        from_attributes = True


class NotificationSummaryResponse(BaseModel):
    """Summary of unread notifications by category."""

    total_unread: int
    by_category: dict  # {"scan": 2, "security": 1, "system": 0, "admin": 0}
    last_notification_at: datetime | None


# ────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ────────────────────────────────────────────────────────────────────────────


def notification_payload(notification: Notification) -> dict:
    return NotificationResponse.model_validate(notification).model_dump(mode="json")


def summary_payload(db: Session, user_id: str) -> dict:
    unread_by_category = (
        db.query(Notification.category, func.count(Notification.id).label("count"))
        .filter(
            Notification.user_id == user_id,
            Notification.is_read == False,
        )
        .group_by(Notification.category)
        .all()
    )

    category_counts = {cat: 0 for cat in ["scan", "security", "system", "admin"]}
    for cat, count in unread_by_category:
        category_counts[cat] = count

    last_notif = (
        db.query(Notification)
        .filter(Notification.user_id == user_id)
        .order_by(Notification.created_at.desc())
        .first()
    )

    return NotificationSummaryResponse(
        total_unread=sum(category_counts.values()),
        by_category=category_counts,
        last_notification_at=last_notif.created_at if last_notif else None,
    ).model_dump(mode="json")


def publish_new_notification(notification: Notification) -> None:
    publish_notification_sync(
        str(notification.user_id),
        {
            "event": "notification.created",
            "notification": notification_payload(notification),
        },
    )


def publish_summary(db: Session, user_id: str) -> None:
    publish_notification_sync(
        str(user_id),
        {
            "event": "notifications.summary",
            "summary": summary_payload(db, str(user_id)),
        },
    )


def create_notification(
    db: Session,
    user_id: str,
    notification_type: NotificationType,
    category: NotificationCategory,
    title: str,
    message: str,
    related_scan_id: str | None = None,
    related_data: dict | None = None,
    action_url: str | None = None,
) -> Notification:
    """
    Create and store a new notification.

    Called internally when scan completes, vulnerability is found, etc.
    """
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
    publish_new_notification(notification)
    publish_summary(db, user_id)
    return notification


def fan_out_notification(
    db: Session,
    org_id: str,
    target_roles: list[str],
    notification_type: NotificationType,
    category: NotificationCategory,
    title: str,
    message: str,
    related_scan_id: str | None = None,
    related_data: dict | None = None,
    action_url: str | None = None,
    exclude_user_id: str | None = None,
) -> int:
    """
    Fan-out a notification to all active users in an organization matching specific roles,
    respecting their in-app alert preferences.
    """
    users = platform_api.active_members_with_roles(db, org_id, target_roles)
    if not users:
        return 0

    inserted = 0
    notifications = []
    for user in users:
        # Exclude the triggerer if requested (e.g. they already got a direct personal notification)
        if exclude_user_id and str(user.id) == exclude_user_id:
            continue

        # Respect User Preferences
        if not user.in_app_alerts:
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
            publish_new_notification(notification)
            publish_summary(db, str(notification.user_id))
        logger.info(
            "Fanned out notification %r to %d users in org %s", title, inserted, org_id
        )

    return inserted
