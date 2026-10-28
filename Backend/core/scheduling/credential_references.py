"""
core/scheduling/credential_references.py — scheduling's answer when the
credential vault asks who refers to a credential.

A deletion reports how many schedules it leaves without a credential
(``scan_schedules.credential_id`` is ON DELETE SET NULL, and the dispatcher
then fails such a schedule loudly). The vault used to count them by querying
this capability's table itself. Since G2 (C5) it asks, and scheduling answers
for its own rows: the query is the one the vault ran, unchanged.

Registered at import; ``main.py`` imports this module.
"""

from __future__ import annotations

from core.credential_vault import SCAN_SCHEDULE_REFERENCES, register_reference_counter
from db.models.scan_schedules import ScanSchedule
from sqlalchemy.orm import Session


def schedules_using_credential(db: Session, org_id: str, credential_id: str) -> int:
    return (
        db.query(ScanSchedule.id)
        .filter(
            ScanSchedule.credential_id == credential_id, ScanSchedule.org_id == org_id
        )
        .count()
    )


register_reference_counter(SCAN_SCHEDULE_REFERENCES, schedules_using_credential)
