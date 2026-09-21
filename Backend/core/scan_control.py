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


# ── Last-resort finalisation ─────────────────────────────────────────────────
# Everything above this line goes through the ORM. That is fine while the ORM
# works — and useless in the one situation a scan most needs settling, which is
# a task that died *because* the ORM could not be used.
#
# On 4 Sep 2026 a stale worker held a pre-GAP-14 `Scan` mapper, so
# `Scan.vulnerabilities` could not resolve its join condition. Every scan task
# raised `InvalidRequestError` on its first DB touch, and then the `except`
# handler's `mark_scan_failed` raised the identical error on its own first
# query. Nothing recorded an outcome, and scans 60 and 61 sat in 'running'
# indefinitely with the UI reporting a live scan against a host that was up the
# whole time. A failure path that shares a dependency with the thing it is
# recovering from is not a failure path.
#
# `force_terminal_status` therefore issues plain SQL against `scans`. It touches
# no mapper, no relationship and no model attribute, so it survives any ORM
# configuration error, and it is deliberately the *only* helper here written
# that way — normal paths should keep using the ORM.


def force_terminal_status(
    scan_id: str,
    status: str = "failed",
    reason: str | None = None,
) -> bool:
    """
    Stamp a terminal status on a scan without touching the ORM mappers.

    Returns True when a row was updated. Never raises: this is the handler of
    last resort, and an exception escaping it would replace a recorded failure
    with an unrecorded one.

    A scan already in a terminal state is left alone. The first outcome
    recorded is the true one -- a watchdog must never overwrite the reason a
    task took the trouble to write.
    """
    if not scan_id:
        return False

    from sqlalchemy import text

    # Interpolated rather than bound because the values are this module's own
    # frozenset, never caller input, and an expanding bindparam here would be
    # the only thing in the statement that needed the ORM's dialect machinery.
    terminal_sql = ", ".join(f"'{s}'" for s in sorted(TERMINAL_STATUSES))

    now = _utcnow()
    db = SessionLocal()
    try:
        # Read first so the duration can be computed in Python. Doing it in SQL
        # needs EXTRACT(EPOCH ...), which is PostgreSQL-only, and this function
        # has to work wherever it is called from.
        row = db.execute(
            text("SELECT status, started_at FROM scans WHERE id = :scan_id"),
            {"scan_id": scan_id},
        ).first()
        if row is None:
            log.debug("force_terminal_status: no scan %s", scan_id)
            return False
        if (row[0] or "") in TERMINAL_STATUSES:
            return False

        started_at = row[1]
        duration = None
        if started_at is not None:
            if started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=timezone.utc)
            duration = (now - started_at).total_seconds()

        result = db.execute(
            text(
                f"""
                UPDATE scans
                   SET status = :status,
                       failure_reason = COALESCE(failure_reason, :reason),
                       completed_at = COALESCE(completed_at, :now),
                       updated_at = :now,
                       duration_seconds = COALESCE(duration_seconds, :duration)
                 WHERE id = :scan_id
                   AND status NOT IN ({terminal_sql})
                """
            ),
            {
                "status": status,
                "reason": reason,
                "now": now,
                "duration": duration,
                "scan_id": scan_id,
            },
        )
        # Any phase still claiming to be running belongs to a task that is gone.
        db.execute(
            text(
                """
                UPDATE scan_phases
                   SET status = :status,
                       completed_at = COALESCE(completed_at, :now)
                 WHERE scan_id = :scan_id
                   AND status NOT IN ('complete', 'failed', 'skipped', 'cancelled')
                """
            ),
            {"status": status, "now": now, "scan_id": scan_id},
        )
        db.commit()
        updated = (result.rowcount or 0) > 0
        if updated:
            log.warning(
                "Scan %s force-settled as '%s': %s", scan_id, status, reason or "-"
            )
        return updated
    except Exception:
        log.exception("Could not force-settle scan %s", scan_id)
        try:
            db.rollback()
        except Exception:
            pass
        return False
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────────
# Web-application scans live in their own table (`web_scans`) with a different
# lifecycle from network `scans`, so they need their own terminal-status
# settler. Same contract as force_terminal_status above: plain SQL, no ORM
# mapper, never raises, and only ever moves a scan *out of* a non-terminal
# state — the first recorded outcome is the true one.
# ─────────────────────────────────────────────────────────────────────────────

WEB_TERMINAL_STATUSES: frozenset[str] = frozenset(
    {"complete", "completed", "failed", "cancelled"}
)


def force_terminal_web_scan_status(
    web_scan_id: str,
    status: str = "failed",
    reason: str | None = None,
) -> bool:
    """
    Stamp a terminal status on a web scan without touching the ORM mappers.

    Returns True when a row was updated. Never raises. A scan already in a
    terminal state is left alone, so a watchdog can never overwrite the reason a
    task took the trouble to write.

    Any phase sub-status still claiming to be ``running`` is settled to the same
    terminal state, because a phase that still reads running belongs to a task
    that is gone — the same reasoning force_terminal_status applies to
    ``scan_phases``.
    """
    if not web_scan_id:
        return False

    from sqlalchemy import text

    terminal_sql = ", ".join(f"'{s}'" for s in sorted(WEB_TERMINAL_STATUSES))

    now = _utcnow()
    db = SessionLocal()
    try:
        row = db.execute(
            text("SELECT status, started_at FROM web_scans WHERE id = :id"),
            {"id": web_scan_id},
        ).first()
        if row is None:
            log.debug("force_terminal_web_scan_status: no web scan %s", web_scan_id)
            return False
        if (row[0] or "") in WEB_TERMINAL_STATUSES:
            return False

        started_at = row[1]
        duration = None
        if started_at is not None:
            if started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=timezone.utc)
            duration = (now - started_at).total_seconds()

        result = db.execute(
            text(
                f"""
                UPDATE web_scans
                   SET status = :status,
                       failure_reason = COALESCE(failure_reason, :reason),
                       completed_at = COALESCE(completed_at, :now),
                       updated_at = :now,
                       duration_seconds = COALESCE(duration_seconds, :duration),
                       recon_status  = CASE WHEN recon_status  = 'running'
                                            THEN :status ELSE recon_status  END,
                       crawl_status  = CASE WHEN crawl_status  = 'running'
                                            THEN :status ELSE crawl_status  END,
                       detect_status = CASE WHEN detect_status = 'running'
                                            THEN :status ELSE detect_status END,
                       audit_status  = CASE WHEN audit_status  = 'running'
                                            THEN :status ELSE audit_status END
                 WHERE id = :id
                   AND status NOT IN ({terminal_sql})
                """
            ),
            {
                "status": status,
                "reason": reason,
                "now": now,
                "duration": duration,
                "id": web_scan_id,
            },
        )
        db.commit()
        updated = (result.rowcount or 0) > 0
        if updated:
            log.warning(
                "Web scan %s force-settled as '%s': %s",
                web_scan_id,
                status,
                reason or "-",
            )
        return updated
    except Exception:
        log.exception("Could not force-settle web scan %s", web_scan_id)
        try:
            db.rollback()
        except Exception:
            pass
        return False
    finally:
        db.close()
