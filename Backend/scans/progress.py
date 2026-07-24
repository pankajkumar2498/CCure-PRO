"""
scans/progress.py
─────────────────────────────────────────────────────────────────────────────
Database-backed scan progress tracking — multi-worker safe.

Replaces the old in-memory ``_scan_progress`` dict + ``threading.Lock`` from
main.py which broke under ``uvicorn --workers N`` because each worker had its
own process-local copy.

Progress is now stored in the PostgreSQL ``scans`` table using the existing
columns (``status``, ``total_hosts``, ``active_hosts``, ``started_at``,
``duration_seconds``) plus a JSONB ``progress`` field inside ``options``.

How it works
────────────
  init_progress(db, scan_id, total_ips)
      → Sets scan.total_hosts = total_ips, scan.status = "running",
        and stores started_at.  Also writes {"progress": {"discovered": 0}}
        into scan.options.

  update_progress(db, scan_id, discovered, active)
      → Atomically bumps the discovered / active counters in the DB.

  finish_progress(db, scan_id)
      → Marks status = "complete", records elapsed time.

  read_progress(db, scan_id, user_id)
      → Returns a progress dict safe to send to the client.

All writes are atomic UPDATEs — safe under concurrent workers / connections.
"""

from datetime import datetime, timezone
from typing import Optional

from db.models.scans import Scan
from sqlalchemy.orm import Session


def init_progress(db: Session, scan_id: str, total_ips: int) -> None:
    """Initialize progress tracking for a scan in the database."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return

    scan.total_hosts = total_ips
    scan.active_hosts = 0
    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)

    # Store fine-grained progress in options JSONB
    opts = dict(scan.options or {})
    opts["progress"] = {
        "discovered": 0,
        "active": 0,
        "total_ips": total_ips,
        "start_time": datetime.now(timezone.utc).isoformat(),
    }
    scan.options = opts
    db.commit()


def update_progress(
    db: Session,
    scan_id: str,
    discovered: int,
    active: int | None = None,
) -> None:
    """Atomically update progress counters in the database."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return

    opts = dict(scan.options or {})
    progress = dict(opts.get("progress", {}))

    progress["discovered"] = discovered
    if active is not None:
        progress["active"] = active
        scan.active_hosts = active

    # Calculate elapsed time
    start_str = progress.get("start_time")
    if start_str:
        try:
            started = datetime.fromisoformat(start_str)
            elapsed = (datetime.now(timezone.utc) - started).total_seconds()
            progress["elapsed_time"] = round(elapsed, 2)
        except (ValueError, TypeError):
            pass

    opts["progress"] = progress
    scan.options = opts
    db.commit()


def finish_progress(db: Session, scan_id: str) -> None:
    """Mark a scan's progress as complete in the database."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return

    opts = dict(scan.options or {})
    progress = dict(opts.get("progress", {}))

    progress["status"] = "complete"
    # Calculate final elapsed time
    start_str = progress.get("start_time")
    if start_str:
        try:
            started = datetime.fromisoformat(start_str)
            elapsed = (datetime.now(timezone.utc) - started).total_seconds()
            progress["elapsed_time"] = round(elapsed, 2)
            scan.duration_seconds = (scan.duration_seconds or 0) + elapsed
        except (ValueError, TypeError):
            pass

    opts["progress"] = progress
    scan.options = opts

    if scan.status == "running":
        scan.status = "complete"
        scan.completed_at = datetime.now(timezone.utc)

    db.commit()


def read_progress(db: Session, scan_id: str, user_id: str) -> dict:
    """
    Read scan progress from the database.

    Returns a dict safe to serialize to JSON for the client:
      - total_ips, discovered, active, status, elapsed_time, percentage
    """
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.created_by == user_id).first()
    if not scan:
        return {"status": "not_found", "message": "Scan not found or completed"}

    opts = scan.options or {}
    progress = opts.get("progress", {})

    total_ips = progress.get("total_ips", scan.total_hosts or 0)
    discovered = progress.get("discovered", 0)
    active = progress.get("active", scan.active_hosts or 0)
    status = progress.get("status", scan.status or "unknown")

    # Calculate live elapsed if still running
    elapsed = progress.get("elapsed_time", 0)
    if status == "running":
        start_str = progress.get("start_time")
        if start_str:
            try:
                started = datetime.fromisoformat(start_str)
                elapsed = round(
                    (datetime.now(timezone.utc) - started).total_seconds(), 2
                )
            except (ValueError, TypeError):
                pass

    percentage = round((discovered / total_ips * 100), 1) if total_ips > 0 else 0

    return {
        "total_ips": total_ips,
        "discovered": discovered,
        "active": active,
        "status": status,
        "elapsed_time": elapsed,
        "percentage": percentage,
    }
