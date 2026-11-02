"""
core/web/timeout.py
────────────────────────────────────────────────────────────────────────────
Global wall-clock timeout for web application scans (Phase 12).

The phase-aware watchdog (``reap_stalled_web_scans``) and the per-phase Celery
hard limits remain the answer to "a phase hung" and "no worker is running".
This adds the one thing they did not enforce: a single ceiling on the *total*
wall-clock time a scan may run, beginning when the scan actually starts
executing (its ``started_at``, stamped when RECON begins — not when it was
queued).

It is enforced two ways that reinforce each other:

  • **Actively**, so running work stops rather than being cleaned up hours
    later. ``is_timed_out`` makes the scan's cancellation check
    (``_scan_is_cancelled``) return True once the deadline passes, so every
    engine that already honours cancellation (crawler, XSS, injection, access
    control, HTTP-method, JS-deps, OAST) aborts mid-phase; and each phase task
    calls ``enforce_global_timeout`` at entry, so the phase chain stops at the
    next boundary. On expiry the scan is settled terminal, the reason recorded,
    the UI notified and session state released — findings already collected are
    preserved.

  • **As a backstop**, by ``reap_stalled_web_scans`` on beat, for the case
    where the worker itself has died and cannot self-enforce.

Nothing here ever overwrites a scan that already reached a terminal state — the
settle goes through ``force_terminal_web_scan_status``, which no-ops on a scan a
task already finished (the completion race), and the deadline is only consulted
while the scan is non-terminal.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

log = logging.getLogger("ccure.web.timeout")


def configured_timeout() -> int:
    """The global timeout in seconds, or 0 when disabled."""
    from core.web import settings as web_settings

    try:
        return int(getattr(web_settings.current(), "WEB_SCAN_TIMEOUT", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def deadline_from(
    started_at: Optional[datetime], timeout: Optional[int] = None
) -> Optional[datetime]:
    """
    The instant the scan must be finished by, or None when there is no deadline
    (timeout disabled, or the scan has not started executing yet).
    """
    if started_at is None:
        return None
    t = configured_timeout() if timeout is None else int(timeout)
    if t <= 0:
        return None
    return _aware(started_at) + timedelta(seconds=t)


def is_timed_out(
    started_at: Optional[datetime],
    now: Optional[datetime] = None,
    timeout: Optional[int] = None,
) -> bool:
    """
    Whether the global deadline has passed.

    A scan that has not started executing (``started_at is None``) is never
    timed out — the global clock begins at execution start, and the queue
    timeout covers the waiting period.
    """
    dl = deadline_from(started_at, timeout=timeout)
    if dl is None:
        return False
    return (now or datetime.now(timezone.utc)) >= dl


def remaining_seconds(
    started_at: Optional[datetime],
    now: Optional[datetime] = None,
    timeout: Optional[int] = None,
) -> Optional[float]:
    """
    Seconds left before the deadline, or None when there is no deadline. A
    negative value means the deadline has already passed; callers bounding a
    subprocess should clamp at 0.
    """
    dl = deadline_from(started_at, timeout=timeout)
    if dl is None:
        return None
    return (dl - (now or datetime.now(timezone.utc))).total_seconds()


def _read_scan_row(web_scan_id: str):
    """Return (status, started_at) via plain SQL, or None. Never raises."""
    from sqlalchemy import text

    from db.base import SessionLocal

    db = SessionLocal()
    try:
        row = db.execute(
            text("SELECT status, started_at FROM web_scans WHERE id = :id"),
            {"id": web_scan_id},
        ).fetchone()
        return (row[0], row[1]) if row else None
    except Exception:
        log.debug("timeout: could not read web scan %s", web_scan_id, exc_info=True)
        return None
    finally:
        db.close()


def publish_terminal_frame(
    web_scan_id: str, reason: str, *, timed_out: bool = False
) -> None:
    """
    Tell a browser on the live scan screen that the scan is over, on the same
    Redis channel the web progress WebSocket subscribes to. Best effort: never
    raises. ``timed_out`` marks the global-timeout frame, which carries it.
    """
    try:
        import json

        from core.redis_client import get_redis_client

        progress = {
            "status": "failed",
            "message": reason,
            "error": reason,
            "reason": reason,
        }
        if timed_out:
            progress["timed_out"] = True
        get_redis_client().publish(
            f"scan_progress:{web_scan_id}",
            json.dumps(
                {
                    "scan_id": web_scan_id,
                    "scan_type": "web",
                    "phase": "failed",
                    "progress": progress,
                }
            ),
        )
    except Exception:
        log.debug("timeout: could not publish frame for %s", web_scan_id, exc_info=True)


def _publish_timeout_frame(web_scan_id: str, reason: str) -> None:
    """Notify the UI over the same Redis channel the progress WebSocket uses."""
    publish_terminal_frame(web_scan_id, reason, timed_out=True)


def release_scan_state(web_scan_id: str) -> None:
    """
    Release Redis/session state held for a scan (best effort).

    The authenticated-session record lives at ``webscan:session:{scan_id}`` with
    a TTL, so it would expire on its own; deleting it on a timeout frees it now
    rather than leaving a dead scan's credentials-bearing session in Redis.
    """
    try:
        from core.redis_client import get_redis_client

        get_redis_client().delete(f"webscan:session:{web_scan_id}")
    except Exception:
        log.debug("timeout: could not release state for %s", web_scan_id, exc_info=True)


def enforce_global_timeout(
    web_scan_id: str, phase: Optional[str] = None
) -> Optional[dict]:
    """
    If the scan has exceeded the global timeout, settle it and return the
    timeout info; otherwise return None.

    Safe to call from any phase task at entry and from the reaper. It:
      * no-ops when the timeout is disabled, the scan is missing, has not
        started, is within budget, or is already terminal (so a completed or
        failed result is never overwritten — the completion race);
      * settles the scan terminal via ``force_terminal_web_scan_status``
        (plain SQL, no ORM), which preserves every finding already written;
      * records the reason, notifies the UI, and releases session state.
    """
    if not web_scan_id:
        return None
    timeout = configured_timeout()
    if timeout <= 0:
        return None

    from core.web.scan_status import (
        WEB_TERMINAL_STATUSES,
        force_terminal_web_scan_status,
    )

    row = _read_scan_row(web_scan_id)
    if not row:
        return None
    status, started_at = row
    if (status or "").lower() in WEB_TERMINAL_STATUSES:
        return None
    if not is_timed_out(started_at, timeout=timeout):
        return None

    elapsed = None
    sa = _aware(started_at)
    if sa is not None:
        elapsed = int((datetime.now(timezone.utc) - sa).total_seconds())
    where = f" during the {phase.upper()} phase" if phase else ""
    reason = (
        f"Web scan exceeded the global time limit of {timeout}s "
        f"({timeout // 60} min){where}"
        + (f" after {elapsed // 60} min" if elapsed is not None else "")
        + ". Active work was stopped; findings collected so far are preserved."
    )

    if not force_terminal_web_scan_status(web_scan_id, status="failed", reason=reason):
        # Already terminal by the time we tried — a real result won the race.
        return None

    _publish_timeout_frame(web_scan_id, reason)
    release_scan_state(web_scan_id)
    log.warning("Web scan %s hit the global timeout: %s", web_scan_id, reason)
    return {
        "web_scan_id": web_scan_id,
        "reason": reason,
        "elapsed_s": elapsed,
        "phase": phase,
        "timed_out": True,
    }


# ── The stall reaper's deadlines (moved from scans.tasks.reapers, 2 Nov 2026) ──
#
# The beat task ``reap_stalled_web_scans`` lists the live web scans
# (``core.web.scan_status.non_terminal_web_scans``), asks this which have
# stalled, settles each through ``force_terminal_web_scan_status`` and
# publishes its terminal frame. What follows is only the decision: plain values
# in, plain values out.

#: Grace, in minutes, beyond each deadline, so the tick and the phase-start
#: stamp need not be perfectly aligned.
STALL_GRACE_MINUTES = 10

#: Just above each phase task's hard ``time_limit`` (recon/audit 2400s,
#: crawl 4200s, detect 8400s), plus grace.
PHASE_STALL_MINUTES = {
    "recon": 40 + STALL_GRACE_MINUTES,
    "crawl": 70 + STALL_GRACE_MINUTES,
    "detect": 140 + STALL_GRACE_MINUTES,
    "audit": 40 + STALL_GRACE_MINUTES,
}


def stalled_web_scans(rows, now: datetime, settings=None) -> list[dict]:
    """
    The scans among ``rows`` (``non_terminal_web_scans``' tuples) that have
    stalled at ``now``, each ``{"web_scan_id", "phase", "reason"}``, in row
    order.

    A queued scan and a running scan get different deadlines and different
    messages, because "no web-worker is running" and "a phase hung" send the
    operator to different places. The running deadline is per phase, just above
    the phase task's own hard limit, so a phase doing legitimate work inside its
    budget is left alone. Independently, a scan running past the global
    wall-clock cap (``WEB_SCAN_TIMEOUT``) plus grace is settled: this is the
    backstop for a worker that died and could not enforce it itself.
    """
    if settings is None:
        from core.web import settings as web_settings

        settings = web_settings.current()

    grace = STALL_GRACE_MINUTES
    queued_minutes = int(getattr(settings, "WEB_SCAN_QUEUE_TIMEOUT_MINUTES", 15) or 0)
    # 0 disables the global cap — the per-phase deadlines still apply.
    _web_timeout = int(getattr(settings, "WEB_SCAN_TIMEOUT", 14400) or 0)
    overall_seconds = (_web_timeout + grace * 60) if _web_timeout > 0 else 0

    stalled: list[dict] = []
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
            limit_minutes = PHASE_STALL_MINUTES.get(phase, 140 + grace)
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
        stalled.append({"web_scan_id": scan_id, "phase": phase, "reason": reason})
    return stalled
