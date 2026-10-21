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

from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "core.notifications")


import logging
from datetime import datetime
from enum import Enum

from ccure_platform.accounts import users_holding_permission
from core.redis_client import publish_notification_sync
from db.base import gen_notification_id
from ccure_platform.models import Notification
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

logger = logging.getLogger("routers.notifications")


# ────────────────────────────────────────────────────────────────────────────
# Enums
# ────────────────────────────────────────────────────────────────────────────


class NotificationType(str, Enum):
    """
    The notification types the platform itself raises.

    ``type`` is stored and returned as a plain string, so a product raises its
    own types as strings or as its own enum (``create_notification`` takes any):
    Audit's (``scan_completed`` …) are ``scans/notification_vocabulary.py``'s.
    """

    SYSTEM_MESSAGE = "system_message"
    ADMIN_NOTICE = "admin_notice"


class NotificationCategory(str, Enum):
    """The categories the platform itself uses, for filtering."""

    SECURITY = "security"
    SYSTEM = "system"
    ADMIN = "admin"


#: Categories products have registered, in registration order. The platform
#: does not know them; it needs them for one thing — the summary lists every
#: category, zero when nothing is unread, as it always has.
_product_categories: list[str] = []


def register_notification_categories(*categories: "str | Enum") -> None:
    """A product declares the categories it raises. Registering one twice is a no-op."""
    for category in categories:
        value = _text(category)
        if value not in _product_categories and value not in {
            c.value for c in NotificationCategory
        }:
            _product_categories.append(value)


def known_categories() -> list[str]:
    """Every category the summary lists: products' first, then the platform's."""
    return [*_product_categories, *(c.value for c in NotificationCategory)]


def _text(value: "str | Enum") -> str:
    return value.value if isinstance(value, Enum) else str(value)


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

    category_counts = {cat: 0 for cat in known_categories()}
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
    notification_type: "NotificationType | str",
    category: "NotificationCategory | str",
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
        id=gen_notification_id(user_id, _text(notification_type)),
        user_id=user_id,
        type=_text(notification_type),
        category=_text(category),
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
    permission_key: str,
    notification_type: "NotificationType | str",
    category: "NotificationCategory | str",
    title: str,
    message: str,
    related_scan_id: str | None = None,
    related_data: dict | None = None,
    action_url: str | None = None,
    exclude_user_id: str | None = None,
) -> int:
    """
    Fan-out a notification to all active users in an organization who hold
    ``permission_key`` there, respecting their in-app alert preferences.
    """
    users = users_holding_permission(db, org_id, permission_key)
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
            id=gen_notification_id(user.id, _text(notification_type)),
            user_id=user.id,
            type=_text(notification_type),
            category=_text(category),
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
