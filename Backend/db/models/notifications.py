"""
db/models/notifications.py
──────────────────────────────────────────────────────────────────────────────
User notification system for scan events, vulnerabilities, and system messages.

ID Convention (Stripe-Style)
─────────────────────────────
  Notification  →  ntf_{username_10chars}_{type_15chars}_{4rand}
                   e.g.  ntf_pankaj_scan_complete_x9v1
"""

from sqlalchemy import Column, String, Boolean, ForeignKey, Text, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from db.base import Base, TIMESTAMPTZ, utcnow


class Notification(Base):
    """
    User notifications for various events (scans, vulnerabilities, system updates).

    ID: ntf_{username}_{type}_{4rand}
        e.g. ntf_pankaj_scan_complete_x9v1
    """

    __tablename__ = "notifications"
    __table_args__ = (
        Index("idx_user_read_created", "user_id", "is_read", "created_at"),
        Index("idx_user_category", "user_id", "category"),
        Index("idx_notifications_data_gin", "related_data", postgresql_using="gin"),
    )

    # Stripe-style readable ID: "ntf_pankaj_scan_complete_x9v1"
    id = Column(String(200), primary_key=True)
    user_id = Column(
        String(150),
        ForeignKey("users.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
        index=True,
    )

    type = Column(String(50), nullable=False)
    category = Column(String(50), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    is_read = Column(Boolean, nullable=False, default=False, index=True)
    related_scan_id = Column(String(100), nullable=True)  # e.g. scn_def_07may25_x9v1
    related_data = Column(JSONB, nullable=True, default=dict)
    action_url = Column(String(512), nullable=True)
    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow, index=True)
    read_at = Column(TIMESTAMPTZ, nullable=True)

    user = relationship("User")

    def __repr__(self):
        return f"<Notification {self.id!r} type={self.type!r} read={self.is_read}>"
