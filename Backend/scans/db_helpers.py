"""
scans/db_helpers.py
-------------------
Pure functions called from main.py phase endpoints to
create / update Scan rows without duplicating DB logic.
"""

import json
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session

from scans.models import Scan


def create_scan(
    db:        Session,
    user_id:   int,
    target:    str,
    scan_type: str,
    phase1_data: dict,
) -> Scan:
    """
    Called right after /scan/phase1 succeeds.
    Creates a new Scan row and returns it (with .id populated).
    """
    results = {"phase1": phase1_data}
    summary = phase1_data.get("summary", {})
    duration = summary.get("scan_duration", 0.0)

    scan = Scan(
        user_id      = user_id,
        target       = target,
        scan_type    = scan_type,
        phase        = 1,
        status       = "running",
        results      = json.dumps(results),
        summary      = json.dumps(summary),
        scan_duration= duration,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def create_completed_scan(
    db:            Session,
    user_id:       int,
    target:        str,
    scan_type:     str,
    phase:         int,
    results:       dict,
    summary:       dict,
    scan_duration: Optional[float] = None,
) -> Scan:
    """
    Create a scan row that is already complete.

    Used for scan types that do not progress through the normal
    phase1 -> phase2 -> phase3 workflow but should still appear in
    history as finished with their full report persisted.
    """
    duration = summary.get("scan_duration", 0.0) if scan_duration is None else scan_duration

    scan = Scan(
        user_id       = user_id,
        target        = target,
        scan_type     = scan_type,
        phase         = phase,
        status        = "complete",
        results       = json.dumps(results),
        summary       = json.dumps(summary),
        scan_duration = duration,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def update_scan_phase(
    db:         Session,
    scan_id:    int,
    user_id:    int,
    phase:      int,
    phase_data: dict,
    is_final:   bool = False,
) -> Optional[Scan]:
    """
    Called after /scan/phase2 or /scan/phase3.
    Merges new phase results into the existing Scan row.
    Returns None if scan_id not found or doesn't belong to user.
    """
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.user_id == user_id)
        .first()
    )
    if not scan:
        return None

    # Merge new phase into existing results blob
    existing = json.loads(scan.results or "{}")
    key = f"phase{phase}"
    existing[key] = phase_data

    new_summary  = phase_data.get("summary", {})
    add_duration = new_summary.get("scan_duration", 0.0)

    scan.results      = json.dumps(existing)
    scan.summary      = json.dumps(new_summary)
    scan.phase        = phase
    scan.scan_duration= (scan.scan_duration or 0.0) + add_duration
    scan.status       = "complete" if is_final else "running"
    scan.updated_at   = datetime.utcnow()

    db.commit()
    db.refresh(scan)
    return scan
