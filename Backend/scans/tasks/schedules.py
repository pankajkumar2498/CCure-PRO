"""
Dispatching the recurring scans that are due (core/scheduling), once per beat
tick however many beat processes run.

Split from core/tasks.py in G1 (C2, docs/architecture/MODULAR_REFACTORING_LOG.md
§6), unchanged. Logs under ``ccure.tasks``, as the hub did.
"""

import logging
from core.celery_app import celery_app
from db.base import SessionLocal
from sqlalchemy import text

log = logging.getLogger("ccure.tasks")


# ─────────────────────────────────────────────────────────────────────────────
# Scan scheduling (Phase 1 — Nessus capability gap closure)
# ─────────────────────────────────────────────────────────────────────────────

#: Advisory-lock key for the scheduler. Any 64-bit constant works; this one is
#: recorded here so a future lock does not collide with it by accident.
_SCAN_SCHEDULER_LOCK_KEY = 0x5CA45CED


@celery_app.task(name="ccure.tasks.run_due_scan_schedules", queue="scanner")
def run_due_scan_schedules() -> dict:
    """
    Dispatch every scan schedule whose next run has arrived.

    Runs on beat every minute. One minute is the resolution of the feature —
    a schedule set for 09:00 fires between 09:00 and 09:01 — and is cheap
    because the due query is one indexed lookup that returns nothing on almost
    every tick.

    **Duplicate execution is prevented by a transaction-scoped advisory lock,
    not by hope.** Exactly one beat process is supposed to run, but two is the
    classic operational mistake (CLAUDE.md records that this deployment had
    *zero* for a long time, which is the same class of error pointed the other
    way), and a Celery task can also be redelivered after a worker dies
    mid-execution. ``pg_try_advisory_xact_lock`` returns false rather than
    waiting, so a second concurrent tick exits immediately instead of queueing
    up behind the first and dispatching everything twice a minute later.

    Transaction-scoped, never session-scoped: ``pg_advisory_lock`` releases
    when the *connection* closes, and SQLAlchemy pools connections, so a
    session-scoped lock leaks onto the next unrelated request that draws the
    same connection. Same reasoning as ``core/audit_retention.py``.

    Each schedule is committed independently. One tenant's broken schedule must
    not roll back another tenant's successful dispatch.
    """
    from core.scheduling.dispatcher import due_schedules, dispatch_schedule
    from db.models.scan_schedules import RUN_STATUS_DISPATCHED

    db = SessionLocal()
    dispatched = 0
    failed = 0
    skipped = 0
    try:
        got_lock = db.execute(
            text("SELECT pg_try_advisory_xact_lock(:k)"),
            {"k": _SCAN_SCHEDULER_LOCK_KEY},
        ).scalar()
        if not got_lock:
            log.info(
                "run_due_scan_schedules: another scheduler tick holds the lock; "
                "skipping this one."
            )
            db.rollback()
            return {"success": True, "skipped_locked": True, "dispatched": 0}

        due = due_schedules(db)
        if not due:
            db.rollback()
            return {"success": True, "dispatched": 0, "due": 0}

        # The lock is transaction-scoped, so it is released by the first commit
        # below. That is acceptable and deliberate: its job is to stop two
        # ticks *starting* the same sweep, and by the time the first schedule
        # commits, `next_run_at` has already moved past due for it.
        for schedule in due:
            run = dispatch_schedule(db, schedule)
            db.commit()
            if run.status == RUN_STATUS_DISPATCHED:
                dispatched += 1
            elif run.status == "failed":
                failed += 1
            else:
                skipped += 1

        log.info(
            "Scan schedules: %d due, %d dispatched, %d failed, %d skipped.",
            len(due),
            dispatched,
            failed,
            skipped,
        )
        return {
            "success": True,
            "due": len(due),
            "dispatched": dispatched,
            "failed": failed,
            "skipped": skipped,
        }
    except Exception as exc:
        # Recorded with its traceback, not reduced to success:False with the
        # reason discarded — the failure mode that hid a TypeError on every
        # compliance beat tick for months.
        db.rollback()
        log.exception("run_due_scan_schedules failed")
        return {"success": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        db.close()
