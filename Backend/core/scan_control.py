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

The engine polls between probe batches. Cancellation is cooperative by
necessity — the host scanner worker runs a ``--pool=threads`` Celery pool, where
``revoke(terminate=True)`` cannot kill a running thread.

Engines do not import this module (B2). They are handed a ``CancelToken`` and a
``ProgressSink`` (``core.engine_ports``), and ``engine_ports(scan_id)`` below
builds both for a scan from the functions in this module, so the status read,
the progress counters and the Redis channel stay with the orchestration layer.
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


class ScanCancelToken:
    """
    The ``CancelToken`` for one scan: is its row marked cancelled?

    ``is_cancelled`` never raises — a monitoring failure must never abort a good
    scan — and ``raise_if_cancelled`` raises :class:`ScanCancelled`, which every
    scan task catches. Each call reads the status through a fresh session, for
    the reason at the top of this module.
    """

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self._check = make_cancel_check(scan_id)

    def is_cancelled(self) -> bool:
        return self._check()

    def raise_if_cancelled(self) -> None:
        raise_if_cancelled(self.scan_id)

    def __repr__(self) -> str:
        return f"scan {self.scan_id}"


class ScanProgress:
    """
    The ``ProgressSink`` for one scan: frames on Redis channel
    ``scan_progress:<scan_id>`` for the live view, and the counters in
    ``scans.options["progress"]`` that ``GET /scan/progress/{scan_id}`` reads.

    The Redis functions are looked up when called, as the engines used to look
    them up, so a test that replaces ``core.redis_client.publish_progress``
    still sees every frame.
    """

    def __init__(self, scan_id: str):
        self.scan_id = scan_id

    def start(self, total: int) -> None:
        start_progress(self.scan_id, total)

    async def publish(self, phase: int, progress: dict) -> None:
        from core.redis_client import publish_progress

        await publish_progress(self.scan_id, phase, progress)

    def publish_sync(self, phase: int, progress: dict) -> None:
        from core.redis_client import publish_progress_sync

        publish_progress_sync(self.scan_id, phase, progress)

    def record(self, done: int, active: int | None = None) -> None:
        record_progress(self.scan_id, done, active)

    def __repr__(self) -> str:
        return f"progress of scan {self.scan_id}"


def engine_ports(scan_id: str | None):
    """
    The progress sink and cancellation token to hand an engine for *scan_id*.

    ``(None, None)`` when there is no scan record (an ad-hoc scan): the engine
    then reports nothing and cannot be cancelled, exactly as it behaved when it
    was given no scan id.
    """
    if not scan_id:
        return None, None
    return ScanProgress(scan_id), ScanCancelToken(scan_id)


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


def record_findings_sync_failure(scan_id: str, reason: str) -> bool:
    """
    Demote a scan whose findings could not be stored from complete to failed.

    "Complete" has to mean the results are queryable. When both the inline
    finding sync and its asynchronous retry fail, the scan's findings exist
    only in the phase payload: the findings list, the dashboard, the asset's
    risk and every export read nothing, while the scan row still carries the
    severity counts it tallied first. Left as "complete", that is a scan
    reporting success over results nobody can see.

    This is the one sanctioned move out of a terminal state, and it is narrow:
    only ``complete``/``completed`` scans are touched, so a cancellation or an
    earlier failure is never overwritten. The phase payload is kept, so the
    findings can be re-synced once the cause is fixed. Plain SQL, never raises,
    for the same reason as :func:`force_terminal_status`.
    """
    if not scan_id:
        return False

    from sqlalchemy import text

    db = SessionLocal()
    try:
        result = db.execute(
            text(
                """
                UPDATE scans
                   SET status = 'failed',
                       failure_reason = :reason,
                       updated_at = :now
                 WHERE id = :scan_id
                   AND status IN ('complete', 'completed')
                """
            ),
            {"reason": reason, "now": _utcnow(), "scan_id": scan_id},
        )
        db.commit()
        updated = (result.rowcount or 0) > 0
        if updated:
            log.error("Scan %s marked failed: %s", scan_id, reason)
        return updated
    except Exception:
        log.exception("Could not record the finding-sync failure for scan %s", scan_id)
        try:
            db.rollback()
        except Exception:
            pass
        return False
    finally:
        db.close()


# Web-application scans' terminal-status settler, force_terminal_web_scan_status,
# and WEB_TERMINAL_STATUSES moved to core/web/scan_status.py in B2: web_scans
# belongs to the web capability, which no longer imports this module.
