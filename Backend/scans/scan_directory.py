"""
scans/scan_directory.py — the scans capability's answer to the findings side's
scan directory (``core/findings/scan_directory.py``).

A comparison chooses a scan's baseline from the earlier scans of the same shape
and reports the configuration each scan ran under. Both are questions about the
scan records and the scan-policy snapshot written into them, which the findings
capability may not import; this module answers them, and Audit's composition
root (``ccure_audit/scan_directory.py``) registers it.

Moved unchanged from ``core.findings.comparison``: the query that was
``previous_scan_for``'s, and the body of ``policy_context``; and from
``scans.asset_syncer``, the lookup of the scan whose assessment scope it
records. The comparison
keeps its own judgement — which candidate overlaps the scan's targets.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from db.models.scans import Scan
from core.scan_policy import read_policy_snapshot


class _ScanDirectory:
    def earlier_completed_scans(self, db: Session, scan: Any, limit: int) -> List[Any]:
        return (
            db.query(Scan)
            .filter(
                Scan.org_id == scan.org_id,
                Scan.id != scan.id,
                Scan.pipeline_mode == scan.pipeline_mode,
                Scan.created_at < scan.created_at,
                Scan.status.in_(("complete", "completed")),
            )
            .order_by(Scan.created_at.desc())
            .limit(limit)
        )

    def policy_context(self, scan: Any) -> Dict[str, Any]:

        policy = read_policy_snapshot(scan)
        if policy is None:
            return {"recorded": False}
        return {
            "recorded": True,
            "policy_id": policy.policy_id,
            "policy_name": policy.policy_name or None,
            "policy_family_code": policy.policy_family_code or None,
            "version_number": policy.version_number or None,
            "fingerprint": policy.fingerprint(),
            "source": policy.source,
            "summary": policy.describe(),
        }

    def scan_record(self, db: Session, scan_id: str) -> Optional[Any]:
        return db.query(Scan).filter(Scan.id == scan_id).first()


DIRECTORY = _ScanDirectory()
