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
    from config import WebScanConfig

    try:
        return int(getattr(WebScanConfig, "WEB_SCAN_TIMEOUT", 0) or 0)
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


def _publish_timeout_frame(web_scan_id: str, reason: str) -> None:
    """Notify the UI over the same Redis channel the progress WebSocket uses."""
    try:
        import json

        from core.redis_client import get_redis_client

        get_redis_client().publish(
            f"scan_progress:{web_scan_id}",
            json.dumps(
                {
                    "scan_id": web_scan_id,
                    "scan_type": "web",
                    "phase": "failed",
                    "progress": {
                        "status": "failed",
                        "message": reason,
                        "error": reason,
                        "reason": reason,
                        "timed_out": True,
                    },
                }
            ),
        )
    except Exception:
        log.debug("timeout: could not publish frame for %s", web_scan_id, exc_info=True)


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
