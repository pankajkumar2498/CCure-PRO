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

import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List

from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db.base import get_db
from db.models import User, Notification, Role
from auth.dependencies import get_current_user

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
    id: UUID
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
    notification = Notification(
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
    logger.info(f"Created notification for user {user_id}: {title}")
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
    for user in users:
        # Exclude the triggerer if requested (e.g. they already got a direct personal notification)
        if exclude_user_id and str(user.id) == exclude_user_id:
            continue
            
        # Respect User Preferences
        prefs = user.preferences or {}
        if prefs.get("in_app_alerts", True) is False:
            continue

        notification = Notification(
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
        inserted += 1

    if inserted > 0:
        db.commit()
        logger.info(f"Fanned out notification '{title}' to {inserted} users in org {org_id}")
        
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
    # Count unread by category
    from sqlalchemy import func

    unread_by_category = db.query(
        Notification.category,
        func.count(Notification.id).label("count")
    ).filter(
        Notification.user_id == current_user.id,
        Notification.is_read == False,
    ).group_by(Notification.category).all()

    category_counts = {cat: 0 for cat in ["scan", "security", "system", "admin"]}
    for cat, count in unread_by_category:
        category_counts[cat] = count

    total_unread = sum(category_counts.values())

    # Get last notification timestamp
    last_notif = db.query(Notification).filter(
        Notification.user_id == current_user.id
    ).order_by(Notification.created_at.desc()).first()

    return NotificationSummaryResponse(
        total_unread=total_unread,
        by_category=category_counts,
        last_notification_at=last_notif.created_at if last_notif else None,
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
    return None
