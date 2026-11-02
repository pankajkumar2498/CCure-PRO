"""
scans/offboarding.py — the scan records' part of a user purge.

When the platform purges an account, Audit's purge hook
(``ccure_audit/offboarding.py``) detaches Audit's references to it. A scan
names the account that started it in ``created_by``; the scan stays — a scan
outlives the person who ran it — and only that pointer is cleared. The table is
this capability's, so the statement is.

Moved unchanged from ``ccure_audit.offboarding.detach_user_from_audit_data``,
which calls it where the statement was: on the same session, in the same
transaction, before the user row is deleted.
"""

from __future__ import annotations

from db.models import Scan
from sqlalchemy.orm import Session


def detach_user_from_scans(db: Session, user_id: str) -> None:
    db.query(Scan).filter(Scan.created_by == user_id).update(
        {Scan.created_by: None}, synchronize_session=False
    )
