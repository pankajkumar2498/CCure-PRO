"""
core/scheduling/policy_references.py — scheduling's answer when the policy
API asks which schedules refer to a policy.

The scan-policy router used to query this capability's table itself. It now
asks its port, ``core.scan_policy.schedule_references``, and scheduling
answers for its own rows: the queries are the ones the router ran, unchanged,
and each row goes back as ``(id, name, is_enabled)``. Registered by Audit's
composition root, ``ccure_audit/policy_references.py``, so nothing here
imports scan-policy code.
"""

from __future__ import annotations

from typing import List, Tuple

from db.models.scan_schedules import ScanSchedule
from sqlalchemy.orm import Session


class _PolicyReferences:
    def count(self, db: Session, policy_id: str) -> int:
        return (
            db.query(ScanSchedule.id)
            .filter(ScanSchedule.policy_id == policy_id)
            .count()
        )

    def schedules(
        self, db: Session, org_id: str, policy_id: str, *, enabled_only: bool
    ) -> List[Tuple[str, str, bool]]:
        criteria = [ScanSchedule.policy_id == policy_id, ScanSchedule.org_id == org_id]
        if enabled_only:
            criteria.append(ScanSchedule.is_enabled.is_(True))
        return [
            (s.id, s.name, s.is_enabled)
            for s in db.query(ScanSchedule).filter(*criteria).all()
        ]


REFERENCES = _PolicyReferences()
