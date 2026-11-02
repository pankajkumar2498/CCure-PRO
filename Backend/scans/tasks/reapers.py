"""
The deployment's real scan timeouts: settling network and web scans that a
worker stopped reporting on, or that no worker collected.

Split from core/tasks.py in G1 (C2, docs/architecture/MODULAR_REFACTORING_LOG.md
§6), unchanged. Logs under ``ccure.tasks``, as the hub did.
"""

import logging
from core.celery_app import celery_app
from db.base import SessionLocal, utcnow
from sqlalchemy import text
from config import AppConfig
from core.web import timeout as web_timeout
from core.web.scan_status import (
    force_terminal_web_scan_status,
    non_terminal_web_scans,
)

log = logging.getLogger("ccure.tasks")


@celery_app.task(name="ccure.tasks.reap_stalled_scans", queue="default")
def reap_stalled_scans() -> dict:
    """
    Settle scans that are still 'running' or 'queued' with nothing working on
    them, and tell whoever is watching why.

    This is the deployment's actual scan timeout. `task_time_limit` in
    `core/celery_app.py` reads like one and is not:

    * Celery's hard time limit is delivered by signalling a **billiard worker
      process**, so it does nothing under the `--pool=threads` worker this
      deployment runs on Windows.
    * Even where it does fire, it acts on a *running task*. It cannot settle a
      scan whose worker died, was restarted mid-scan, or — the case that
      produced this task — failed inside its own `except` handler and so never
      recorded an outcome at all.

    On 4 Sep 2026 a worker holding a stale `Scan` mapper raised
    `InvalidRequestError` on every scan task's first query, and again inside
    `mark_scan_failed`. Two scans against a host that was up the whole time sat
    in 'running' indefinitely, and the UI showed a live scan for both. Nothing
    in the system would ever have settled them.

    Deliberately conservative in three ways:

    * It only ever moves a scan **out of** a non-terminal state, through
      `force_terminal_status`, which no-ops on anything already settled. A
      real outcome written by a task always wins.
    * It writes plain SQL, so it still works when the fault that stranded the
      scan is the ORM itself.
    * A queued scan and a running scan get different deadlines and different
      messages, because "no scanner is running" and "the scan hung" send the
      operator to different places.
    """
    from datetime import timedelta, timezone

    from core.redis_client import publish_progress_sync
    from core.scan_control import force_terminal_status

    running_minutes = int(getattr(AppConfig, "SCAN_STALL_TIMEOUT_MINUTES", 90) or 0)
    queued_minutes = int(getattr(AppConfig, "SCAN_QUEUE_TIMEOUT_MINUTES", 15) or 0)
    if running_minutes <= 0 and queued_minutes <= 0:
        return {"success": True, "disabled": True, "reaped": 0}

    now = utcnow()
    reaped: list[dict] = []

    db = SessionLocal()
    try:
        # Read with plain SQL for the same reason the writer uses it: a mapper
        # failure is one of the conditions this task exists to clean up after,
        # and a reaper that cannot run during that failure is no reaper.
        rows = db.execute(
            text(
                """
                SELECT id, scan_no, status, started_at, queued_at, created_at
                  FROM scans
                 WHERE status IN ('running', 'queued', 'pending', 'cancelling')
                """
            )
        ).fetchall()
    except Exception as exc:
        log.exception("reap_stalled_scans could not list scans")
        return {"success": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        db.close()

    for scan_id, scan_no, status, started_at, queued_at, created_at in rows:
        is_running = (status or "").lower() in ("running", "cancelling")
        limit_minutes = running_minutes if is_running else queued_minutes
        if limit_minutes <= 0:
            continue

        # Fall back down the chain: a scan with no started_at never got that
        # far, and one with no timestamps at all is old enough to reap on any
        # reading.
        anchor = started_at if is_running else (queued_at or created_at)
        anchor = anchor or created_at or started_at
        if anchor is None:
            continue
        if anchor.tzinfo is None:
            anchor = anchor.replace(tzinfo=timezone.utc)

        age = now - anchor
        if age < timedelta(minutes=limit_minutes):
            continue

        minutes = int(age.total_seconds() // 60)
        if is_running:
            reason = (
                f"Scan timed out: no progress recorded for {minutes} minutes "
                f"(limit {limit_minutes}). The scanner task stopped responding "
                f"or the scanner worker is no longer running."
            )
        else:
            reason = (
                f"Scan was never picked up by a scanner worker after "
                f"{minutes} minutes (limit {limit_minutes}). Check that the "
                f"host scanner worker is running."
            )

        if not force_terminal_status(scan_id, status="failed", reason=reason):
            continue

        reaped.append({"scan_id": scan_id, "scan_no": scan_no, "reason": reason})

        # Push a terminal frame so a browser sitting on the live scan screen
        # stops showing a scan that is over. Without this the only thing that
        # ends that view is its own client-side timeout, which is the symptom
        # this task was written to remove.
        try:
            publish_progress_sync(
                scan_id, 1, {"status": "failed", "error": reason, "reason": reason}
            )
        except Exception:
            log.debug("Could not publish timeout for scan %s", scan_id, exc_info=True)

    if reaped:
        log.warning(
            "reap_stalled_scans settled %d stalled scan(s): %s",
            len(reaped),
            ", ".join(str(r["scan_no"]) for r in reaped),
        )
    return {"success": True, "reaped": len(reaped), "scans": reaped}


@celery_app.task(name="ccure.tasks.reap_stalled_web_scans", queue="default")
def reap_stalled_web_scans() -> dict:
    """
    Settle web-application scans stranded in a non-terminal state.

    The network reaper (`reap_stalled_scans`) only knows about the `scans`
    table; web scans live in `web_scans` with a four-phase lifecycle of their
    own, and until this task existed nothing settled one whose worker died, was
    restarted mid-phase, or failed inside its own `except` handler. Twelve web
    scans sat 'running'/'queued' for weeks because of that gap, each showing a
    live scan in the UI that would never end.

    Deliberately conservative, exactly like the network reaper:

    * It only ever moves a scan **out of** a non-terminal state, through
      `force_terminal_web_scan_status`, which no-ops on anything already
      settled — a real outcome written by a task always wins.
    * It reads and writes plain SQL, so it still works when the fault that
      stranded the scan is the ORM itself.
    * A queued scan and a running scan get different deadlines and different
      messages, because "no web-worker is running" and "a phase hung" send the
      operator to different places.

    The running-scan deadline is **per phase**, set just above each phase task's
    own Celery hard `time_limit`. So a scan is reaped only once the phase's task
    is genuinely gone (the hard limit SIGKILLs the worker process, which skips
    the task's `except` handler and orphans the row) — never while a phase is
    doing legitimate work inside its budget. A long DETECT running at 100
    minutes is within its 140-minute limit and is left alone.
    """
    # The table and the deadlines are web DAST's (2 Nov 2026): it lists the
    # live web scans and says which have stalled; this task, on beat, settles
    # them and tells the UI.
    now = utcnow()

    try:
        rows = non_terminal_web_scans()
    except Exception as exc:
        log.exception("reap_stalled_web_scans could not list web scans")
        return {"success": False, "error": f"{type(exc).__name__}: {exc}"}

    reaped: list[dict] = []
    for stalled in web_timeout.stalled_web_scans(rows, now):
        scan_id, reason = stalled["web_scan_id"], stalled["reason"]
        if not force_terminal_web_scan_status(scan_id, status="failed", reason=reason):
            continue

        reaped.append(stalled)

        # Push a terminal frame on the same Redis channel the web progress
        # WebSocket subscribes to, so a browser sitting on the live scan screen
        # stops showing a scan that is over.
        web_timeout.publish_terminal_frame(scan_id, reason)

    if reaped:
        log.warning(
            "reap_stalled_web_scans settled %d stalled web scan(s): %s",
            len(reaped),
            ", ".join(r["web_scan_id"] for r in reaped),
        )
    return {"success": True, "reaped": len(reaped), "web_scans": reaped}
