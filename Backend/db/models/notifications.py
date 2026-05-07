"""
db/models/notifications.py
──────────────────────────────────────────────────────────────────────────────
User notification system for scan events, vulnerabilities, and system messages.

Table
──────
  notifications — User notifications with read status and metadata

Indexes optimize for:
  - user_id, is_read, created_at (list unread notifications)
  - user_id, category (filter by category)
"""

from sqlalchemy import Column, String, Boolean, ForeignKey, Text, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from db.base import Base, TIMESTAMPTZ, gen_uuid, utcnow


class Notification(Base):
    """
    User notifications for various events (scans, vulnerabilities, system updates, etc).

    Fields
    ──────
    user_id         — Owner of this notification
    type            — Type of notification (scan_completed, vulnerability_found, etc)
    category        — Category for filtering (scan, security, system, admin)
    title           — Short title shown in list
    message         — Full message/description
    is_read         — Whether user has seen this notification
    related_scan_id — Optional: link to a scan
    related_data    — JSONB for flexible metadata (severity, count, etc)
    action_url      — Optional: URL to navigate to when clicked
    created_at      — When notification was generated
    read_at         — When user marked it as read (null if not read)

    Composite indexes optimize queries for:
      - user_id, is_read, created_at (list unread notifications)
      - user_id, category (filter by category)
    """
    __tablename__ = "notifications"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    user_id         = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    type            = Column(String(50), nullable=False)
    category        = Column(String(50), nullable=False)
    title           = Column(String(255), nullable=False)
    message         = Column(Text, nullable=False)
    is_read         = Column(Boolean, nullable=False, default=False, index=True)
    related_scan_id = Column(String(100), nullable=True)
    related_data    = Column(JSONB, nullable=True, default=dict)
    action_url      = Column(String(512), nullable=True)
    created_at      = Column(TIMESTAMPTZ, nullable=False, default=utcnow, index=True)
    read_at         = Column(TIMESTAMPTZ, nullable=True)

    user            = relationship("User")

    # Composite indexes for efficient queries
    __table_args__ = (
        Index("idx_user_read_created", "user_id", "is_read", "created_at"),
        Index("idx_user_category", "user_id", "category"),
        Index("idx_notifications_data_gin", "related_data", postgresql_using="gin"),
    )

    def __repr__(self):
        return f"<Notification {self.id} type={self.type} read={self.is_read}>"
