"""
ccure_platform/identity/account_maintenance.py
──────────────────────────────────────────────────────────────────────────────
Scheduled housekeeping of accounts and sessions.

Moved here from ``core/tasks.py`` in Phase 8.4 (project owner's approval of the
Phase 8.3 recommendation). Purging accounts that never verified and sessions
long past use is identity's work; it sat in the scan task hub only because that
was where the scheduled tasks were. Its sibling, the purge of accounts that
verified but were never approved, already lives in ``email_security_tasks``.

Nothing observable changed:

* the task names, and so the beat schedule in ``core/celery_app.py``, are
  exactly as they were;
* the queue is ``default``;
* the log lines keep the ``ccure.tasks`` logger they were written under;
* the code of both tasks is unchanged.

The worker loads this module through ``celery_app.conf.include``.
"""

from __future__ import annotations

import logging

from core.celery_app import celery_app
from db.base import SessionLocal

log = logging.getLogger("ccure.tasks")


@celery_app.task(name="ccure.tasks.purge_stale_unverified_accounts", queue="default")
def purge_stale_unverified_accounts() -> dict:
    """
    Delete accounts that were never verified within the configured window.

    An unverified account is personal data being retained for no purpose, and
    it also holds a username and email address hostage against the person who
    legitimately wants them. Only rows that are unverified *and* unapproved are
    touched, so an admin-provisioned account whose owner has not clicked the
    link yet is never removed by this.
    """
    import datetime

    from config import AppConfig
    from ccure_platform.models import User

    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        days=AppConfig.UNVERIFIED_ACCOUNT_TTL_DAYS
    )
    db = SessionLocal()
    try:
        stale = (
            db.query(User)
            .filter(
                User.is_verified.is_(False),
                User.approved_at.is_(None),
                User.created_at < cutoff,
            )
            .all()
        )
        removed = len(stale)
        for user in stale:
            log.info(
                "Purging unverified account %s (created %s)", user.id, user.created_at
            )
            db.delete(user)
        db.commit()
        return {"success": True, "purged": removed}
    except Exception as exc:
        db.rollback()
        log.error("Failed to purge unverified accounts: %s", exc, exc_info=True)
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.purge_expired_refresh_sessions", queue="default")
def purge_expired_refresh_sessions() -> dict:
    """
    Delete refresh-token sessions that are long past being useful.

    `refresh_token_sessions` is append-only in practice: every login inserts a
    row, every refresh inserts another and revokes the old one, and nothing
    ever removed any of them. With 30-minute access tokens the SPA refreshes
    roughly 48 times a day per signed-in session, so a single daily user
    generates on the order of 17,000 rows a year — none of which any query
    needs after the row expires.

    Two properties worth keeping:

    * **Revoked rows are kept for the full retention window, not deleted
      immediately.** The revocation *is* the audit record — "this session was
      signed out at 14:02 from this address" is exactly what someone
      investigating a compromise needs, and deleting it the moment it stops
      being usable would erase the evidence of the event being investigated.

    * **Only rows that are both past `expires_at` and older than the window are
      removed.** A row cannot be revived: `_get_refresh_session` rejects
      anything expired, so nothing here can end a session that still works.

    Bounded by `REFRESH_SESSION_RETENTION_DAYS`.
    """
    import datetime

    from config import AppConfig
    from ccure_platform.models import RefreshTokenSession

    days = AppConfig.REFRESH_SESSION_RETENTION_DAYS
    if days <= 0:
        return {"success": True, "purged": 0, "skipped": "retention disabled"}

    now = datetime.datetime.now(datetime.timezone.utc)
    cutoff = now - datetime.timedelta(days=days)

    db = SessionLocal()
    try:
        removed = (
            db.query(RefreshTokenSession)
            .filter(
                RefreshTokenSession.expires_at < now,
                RefreshTokenSession.issued_at < cutoff,
            )
            .delete(synchronize_session=False)
        )
        db.commit()
        if removed:
            log.info(
                "Purged %s refresh-token session(s) issued before %s", removed, cutoff
            )
        return {"success": True, "purged": removed}
    except Exception as exc:
        db.rollback()
        log.error("Failed to purge refresh sessions: %s", exc, exc_info=True)
        return {"success": False, "error": str(exc)}
    finally:
        db.close()
