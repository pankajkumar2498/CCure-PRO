"""
core/web/scan_status.py
─────────────────────────────────────────────────────────────────────────────
Terminal status for web-application scans, settled without the ORM.

Web scans live in their own table (``web_scans``) with a different lifecycle
from network ``scans``, so they have their own terminal-status settler. It used
to sit in ``core/scan_control.py`` beside the network scan's, which made the
web scanner import the network scan's control module and put the one writer of
``web_scans``' terminal state outside the web capability that owns the table.
It moved here unchanged in B2 (docs/architecture/MODULAR_REFACTORING_LOG.md);
the logger keeps its old name so the log lines it writes do not change.

Same contract as ``core.scan_control.force_terminal_status``: plain SQL, no ORM
mapper, never raises, and only ever moves a scan *out of* a non-terminal state —
the first recorded outcome is the true one.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from db.base import SessionLocal

log = logging.getLogger("ccure.scan_control")

WEB_TERMINAL_STATUSES: frozenset[str] = frozenset(
    {"complete", "completed", "failed", "cancelled"}
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


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
