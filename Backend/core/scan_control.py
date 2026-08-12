"""
core/scan_control.py
─────────────────────────────────────────────────────────────────────────────
Cooperative scan cancellation and DB-backed progress, readable from anywhere.

Why this module exists
──────────────────────
Cancellation used to be checked with the same SQLAlchemy session the scan task
had already used to load the ``Scan`` row. Once an object is in a session's
identity map, a later ``query(...).first()`` returns that same instance and does
*not* overwrite attributes that are already loaded — so the task kept reading the
status it saw at start-up and never noticed the API committing ``cancelled``.
The Stop button reported success while the scan ran to completion.

Every helper here therefore opens its own short-lived session, reads, and closes.
That is the whole point: these functions must never share a session with a
long-running caller, or they inherit its stale snapshot again.

The engine polls ``is_cancelled()`` between probe batches. Cancellation is
cooperative by necessity — the host scanner worker runs a ``--pool=threads``
Celery pool, where ``revoke(terminate=True)`` cannot kill a running thread.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from db.base import SessionLocal
from db.models.scans import Scan

log = logging.getLogger("ccure.scan_control")

# Statuses that mean "this scan is over"; a scan in any of these must not be
# restarted, re-cancelled, or have its recorded outcome overwritten.
TERMINAL_STATUSES: frozenset[str] = frozenset(
    {"complete", "completed", "failed", "cancelled", "canceled", "unreachable"}
)

# Statuses that mean the user asked for this scan to stop.
CANCELLED_STATUSES: frozenset[str] = frozenset({"cancelled", "canceled", "cancelling"})


class ScanCancelled(Exception):
    """Raised inside a scan phase when the user has cancelled the scan."""

    def __init__(self, scan_id: str):
        super().__init__(f"Scan {scan_id} was cancelled by the user")
        self.scan_id = scan_id


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def read_status(scan_id: str) -> str | None:
    """Return the scan's current status, read through a fresh session."""
    if not scan_id:
        return None
    db = SessionLocal()
    try:
        return db.query(Scan.status).filter(Scan.id == scan_id).scalar()
    except Exception:
        log.exception("Could not read status for scan %s", scan_id)
        return None
    finally:
        db.close()


def is_cancelled(scan_id: str) -> bool:
    """
    True when the user has asked for this scan to stop.

    Safe to call from inside a long-running task: it never reuses the caller's
    session, so it always sees the committed status rather than a snapshot.
    """
    status = read_status(scan_id)
    return status in CANCELLED_STATUSES if status else False


def raise_if_cancelled(scan_id: str) -> None:
    """Abort the current phase if the scan has been cancelled."""
    if scan_id and is_cancelled(scan_id):
        raise ScanCancelled(scan_id)


def make_cancel_check(scan_id: str | None):
    """
    Build a zero-argument predicate the engines can poll without importing the DB.

    Returns a callable that is always cheap to call and never raises; when
    ``scan_id`` is None (ad-hoc scans with no DB row) it is a constant False.
    """
    if not scan_id:
        return lambda: False

    def _check() -> bool:
        try:
            return is_cancelled(scan_id)
        except Exception:  # a monitoring failure must never abort a good scan
            log.debug("Cancellation check failed for scan %s", scan_id, exc_info=True)
            return False

    return _check


# ── Progress ─────────────────────────────────────────────────────────────────
# init/update/finish write into scans.options["progress"], which
# GET /scan/progress/{scan_id} reads back. These were previously defined in
# scans/progress.py but never called outside the test-suite, so that endpoint
# reported 0% for every scan ever run.


def start_progress(scan_id: str, total_ips: int) -> None:
    """Record the target count and start time so progress can be computed."""
    if not scan_id:
        return
    db = SessionLocal()
    try:
        from scans.progress import init_progress

        init_progress(db, scan_id, total_ips)
    except Exception:
        log.debug("Could not initialise progress for %s", scan_id, exc_info=True)
        db.rollback()
    finally:
        db.close()


def record_progress(scan_id: str, discovered: int, active: int | None = None) -> None:
    """Persist how many targets have been probed so far."""
    if not scan_id:
        return
    db = SessionLocal()
    try:
        from scans.progress import update_progress

        update_progress(db, scan_id, discovered=discovered, active=active)
    except Exception:
        log.debug("Could not record progress for %s", scan_id, exc_info=True)
        db.rollback()
    finally:
        db.close()
