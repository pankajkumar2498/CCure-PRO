"""
core/web/offboarding.py — the web scans' part of a user purge.

When the platform purges an account, Audit's purge hook
(``ccure_audit/offboarding.py``) detaches Audit's references to it. A web scan
names the account that started it in ``created_by``; the scan stays, and only
that pointer is cleared. The table is this capability's, so the statement is.

Until B8 the ORM cleared it, through a ``User.web_scans`` back-reference that
the web-scan models attached to the platform's ``User``. The database does not:
``web_scans`` was migrated without the foreign keys its model declares. This
statement has the effect the flush had (``created_by`` cleared, ``updated_at``
stamped).
"""

from __future__ import annotations

from db.models import WebScan
from sqlalchemy.orm import Session


def detach_user_from_web_scans(db: Session, user_id: str) -> None:
    db.query(WebScan).filter(WebScan.created_by == user_id).update(
        {WebScan.created_by: None}, synchronize_session=False
    )
