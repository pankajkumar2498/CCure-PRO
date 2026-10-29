"""
scans/reads.py
─────────────────────────────────────────────────────────────────────────────
What the read side asks of the scan records (G2, the remainder of C7 in
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

The dashboard counts and charts an organisation's scans, the export reads a
scan's stored phases, and the report download records where it wrote a scan's
regenerated PDFs. Each used to query or write ``scans`` and ``scan_phases``
itself through the scan models; they ask here now. The queries are moved
unchanged, so a response is byte for byte what it was.

What a scan's report says about the scan is ``scans/report_context.py``, and
which scan a caller may read is ``scans/scan_access.py``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, List, Tuple

from db.models.scans import Scan, ScanPhase
from sqlalchemy import func
from sqlalchemy.orm import Session

__all__ = [
    "completed_scan_counts",
    "forget_report_paths",
    "latest_completed_scans",
    "phases_newest_first",
    "recent_scans",
    "record_report_paths",
    "scan_counts",
]

_COMPLETED = ["complete", "completed"]


def latest_completed_scans(db: Session, org: str, limit: int = 2) -> List[Scan]:
    """The organisation's most recently completed scans, newest first."""
    return (
        db.query(Scan)
        .filter(
            Scan.org_id == org,
            Scan.status.in_(_COMPLETED),
            Scan.is_deleted == False,
        )
        .order_by(Scan.completed_at.desc())
        .limit(limit)
        .all()
    )


def scan_counts(db: Session, org: str, since: datetime) -> Tuple[int, int, int]:
    """Scans queued since *since*, scans running, scans queued — in that order."""
    queued_since = (
        db.query(func.count(Scan.id))
        .filter(Scan.org_id == org, Scan.queued_at >= since, Scan.is_deleted == False)
        .scalar()
        or 0
    )
    running = (
        db.query(func.count(Scan.id))
        .filter(Scan.org_id == org, Scan.status == "running", Scan.is_deleted == False)
        .scalar()
        or 0
    )
    queued = (
        db.query(func.count(Scan.id))
        .filter(Scan.org_id == org, Scan.status == "queued", Scan.is_deleted == False)
        .scalar()
        or 0
    )
    return queued_since, running, queued


def completed_scan_counts(db: Session, org: str, since: datetime) -> List[Any]:
    """Each scan completed since *since*, oldest first: its completion time
    and its critical, high, medium and low counts."""
    return (
        db.query(
            Scan.completed_at,
            Scan.critical_count,
            Scan.high_count,
            Scan.medium_count,
            Scan.low_count,
        )
        .filter(
            Scan.org_id == org,
            Scan.completed_at >= since,
            Scan.status.in_(_COMPLETED),
            Scan.is_deleted == False,
        )
        .order_by(Scan.completed_at.asc())
        .all()
    )


def recent_scans(db: Session, org: str, limit: int) -> List[Scan]:
    """The organisation's most recently queued scans, newest first."""
    return (
        db.query(Scan)
        .filter(Scan.org_id == org, Scan.is_deleted == False)
        .order_by(Scan.queued_at.desc())
        .limit(limit)
        .all()
    )


def phases_newest_first(db: Session, scan_id: str) -> List[ScanPhase]:
    """A scan's stored phases, the latest in the pipeline first."""
    return (
        db.query(ScanPhase)
        .filter(ScanPhase.scan_id == scan_id)
        .order_by(ScanPhase.phase_order.desc())
        .all()
    )


def record_report_paths(
    db: Session, scan: Scan, *, executive: str | None, technical: str | None
) -> None:
    """Record where a scan's regenerated reports were written, and commit."""
    if executive:
        scan.report_executive_path = executive
    if technical:
        scan.report_technical_path = technical
    db.commit()
    db.refresh(scan)


#: The scan columns that name a report file.
REPORT_PATH_COLUMNS = (
    "report_executive_path",
    "report_technical_path",
    "report_pdf_path",
)


def forget_report_paths(db: Session, scan: Scan) -> None:
    """Clear every report path a scan records, and commit."""
    for column in REPORT_PATH_COLUMNS:
        if getattr(scan, column, None):
            setattr(scan, column, None)
    db.add(scan)
    db.commit()
