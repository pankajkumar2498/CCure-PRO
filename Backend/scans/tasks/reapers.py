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

    from config import AppConfig
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
    from datetime import timedelta, timezone

    from config import WebScanConfig
    from core.web.scan_status import force_terminal_web_scan_status

    # Just above each phase task's hard `time_limit` (recon/audit 2400s,
    # crawl 4200s, detect 8400s), plus grace so the tick and the phase-start
    # stamp need not be perfectly aligned.
    grace = 10
    phase_limits = {
        "recon": 40 + grace,
        "crawl": 70 + grace,
        "detect": 140 + grace,
        "audit": 40 + grace,
    }
    queued_minutes = int(
        getattr(WebScanConfig, "WEB_SCAN_QUEUE_TIMEOUT_MINUTES", 15) or 0
    )
    # Global wall-clock cap (Phase 12). The in-task enforcement
    # (core/web/timeout.enforce_global_timeout) fires at exactly
    # WEB_SCAN_TIMEOUT from execution start; this reaper is the backstop for a
    # worker that has died and cannot self-enforce, so it waits a grace beyond
    # the cap before stepping in. 0 disables the global cap — the per-phase
    # deadlines above still apply.
    _web_timeout = int(getattr(WebScanConfig, "WEB_SCAN_TIMEOUT", 14400) or 0)
    overall_seconds = (_web_timeout + grace * 60) if _web_timeout > 0 else 0

    non_terminal = (
        "queued",
        "running",
        "pending",
        "recon",
        "crawl",
        "detect",
        "audit",
        "cancelling",
    )

    now = utcnow()
    reaped: list[dict] = []

    db = SessionLocal()
    try:
        rows = db.execute(
            text(
                """
                SELECT id, status, pipeline_phase, queued_at, created_at,
                       started_at, recon_started_at, crawl_started_at,
                       detect_started_at, audit_started_at, updated_at
                  FROM web_scans
                 WHERE status = ANY(:statuses)
                   AND is_deleted IS NOT TRUE
                """
            ),
            {"statuses": list(non_terminal)},
        ).fetchall()
    except Exception as exc:
        log.exception("reap_stalled_web_scans could not list web scans")
        return {"success": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        db.close()

    def _aware(dt):
        if dt is None:
            return None
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt

    for r in rows:
        (
            scan_id,
            status,
            phase,
            queued_at,
            created_at,
            started_at,
            recon_at,
            crawl_at,
            detect_at,
            audit_at,
            updated_at,
        ) = r
        status_l = (status or "").lower()
        phase = (phase or "queued").lower()

        # A scan that never left the queue: recon never stamped a start, so no
        # phase deadline applies — only the queue deadline does.
        never_started = phase in ("queued", "") or recon_at is None
        if never_started:
            if queued_minutes <= 0:
                continue
            anchor = _aware(queued_at) or _aware(created_at)
            limit_minutes = queued_minutes
            kind = "queued"
        else:
            phase_start = {
                "recon": recon_at,
                "crawl": crawl_at,
                "detect": detect_at,
                "audit": audit_at,
            }.get(phase)
            anchor = _aware(phase_start) or _aware(updated_at) or _aware(started_at)
            limit_minutes = phase_limits.get(phase, 140 + grace)
            kind = "running"

        if anchor is None:
            # No timestamp to reason from: fall back to the absolute backstop
            # against created_at, which every row has.
            anchor = _aware(created_at)
            if anchor is None:
                continue

        age = now - anchor
        over_phase = age >= timedelta(minutes=limit_minutes)

        # Independent global wall-clock backstop off the scan's own start.
        start_anchor = _aware(started_at) or _aware(created_at)
        over_overall = (
            overall_seconds > 0
            and start_anchor is not None
            and (now - start_anchor) >= timedelta(seconds=overall_seconds)
        )

        if not (over_phase or over_overall):
            continue

        minutes = int(age.total_seconds() // 60)
        if kind == "queued":
            reason = (
                f"Web scan was never picked up by a web-scanner worker after "
                f"{minutes} minutes (limit {limit_minutes}). Check that the "
                f"web-worker (queues web_recon,web_crawl,web_dast,web_audit) "
                f"is running."
            )
        elif over_overall and not over_phase:
            total_min = int((now - start_anchor).total_seconds() // 60)
            reason = (
                f"Web scan exceeded the global time limit "
                f"({overall_seconds // 60} min): running for {total_min} minutes "
                f"since it started. Settled by the watchdog because the worker "
                f"did not self-enforce the timeout (it may have died)."
            )
        else:
            reason = (
                f"Web scan timed out in the {phase.upper()} phase: no progress "
                f"for {minutes} minutes (limit {limit_minutes}). The phase task "
                f"stopped responding or the web-worker is no longer running."
            )

        if not force_terminal_web_scan_status(scan_id, status="failed", reason=reason):
            continue

        reaped.append({"web_scan_id": scan_id, "phase": phase, "reason": reason})

        # Push a terminal frame on the same Redis channel the web progress
        # WebSocket subscribes to, so a browser sitting on the live scan screen
        # stops showing a scan that is over.
        try:
            import json as _json

            from core.redis_client import get_redis_client

            get_redis_client().publish(
                f"scan_progress:{scan_id}",
                _json.dumps(
                    {
                        "scan_id": scan_id,
                        "scan_type": "web",
                        "phase": "failed",
                        "progress": {
                            "status": "failed",
                            "message": reason,
                            "error": reason,
                            "reason": reason,
                        },
                    }
                ),
            )
        except Exception:
            log.debug(
                "Could not publish timeout for web scan %s", scan_id, exc_info=True
            )

    if reaped:
        log.warning(
            "reap_stalled_web_scans settled %d stalled web scan(s): %s",
            len(reaped),
            ", ".join(r["web_scan_id"] for r in reaped),
        )
    return {"success": True, "reaped": len(reaped), "web_scans": reaped}
