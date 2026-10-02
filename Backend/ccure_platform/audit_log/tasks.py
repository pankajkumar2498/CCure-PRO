"""
ccure_platform/audit_log/tasks.py
──────────────────────────────────────────────────────────────────────────────
Scheduled audit-log retention.

Moved here from ``core/tasks.py`` (backend alignment, step 1: split the task
hub by owner). Retention of the platform's ``audit_logs`` table is the
platform's work; it sat in the scan task hub only because that was where the
scheduled tasks were. Like ``identity/account_maintenance.py`` before it, this
changed nothing observable:

* the task name, and so the beat entry in ``core/celery_app.py``
  (``purge-expired-audit-logs-daily``), is exactly as it was;
* the queue is ``default``, and retries, arguments and the return shape are
  unchanged;
* the log lines keep the ``ccure.tasks`` logger they were written under;
* the code of the task is unchanged.

The worker loads this module through ``celery_app.conf.include``. The retention
logic itself (``core/audit_retention.py``) has not moved; it is named in
``exempt_targets`` of the ``platform-is-shared-foundation`` rule, beside
``core.audit``, until it moves here.
"""

from __future__ import annotations

import logging

from core.celery_app import celery_app
from db.base import SessionLocal

log = logging.getLogger("ccure.tasks")


@celery_app.task(name="ccure.tasks.purge_expired_audit_logs", queue="default")
def purge_expired_audit_logs() -> dict:
    """
    Phase 6a. Remove audit rows that predate the tamper-evidence chain and are
    older than the configured retention period.

    **Legacy rows only** — those with no ``record_hash``. Nothing can ever have
    linked to one, because ``prev_hash`` references a ``record_hash`` value and
    a legacy row has none, so removing them cannot break a chain for any
    dataset. Chained rows are phase 6b and the database refuses them here
    regardless of what this function asks for.

    **Dry run unless ``AUDIT_RETENTION_DRY_RUN`` is explicitly false**, and a
    no-op entirely while ``AUDIT_LOG_RETENTION_DAYS`` is 0, which is the
    shipped default and stays that way until a period is agreed with the
    business or compliance owner. A refusal is returned as a report rather than
    raised: this runs on beat, and an exception in a nightly job is a line in a
    log nobody reads, whereas ``{"skipped": ...}`` is visible in the result.
    """
    from config import AppConfig
    from core.audit_retention import RetentionRefused, run_retention

    db = SessionLocal()
    try:
        return {
            "success": True,
            **run_retention(
                db,
                dry_run=AppConfig.AUDIT_RETENTION_DRY_RUN,
                operator="beat:purge_expired_audit_logs",
            ),
        }
    except RetentionRefused as refusal:
        log.info("audit retention did not run: %s", refusal)
        return {"success": True, "skipped": str(refusal), "deleted_total": 0}
    except Exception as exc:
        log.exception("audit retention task failed")
        return {"success": False, "error": str(exc), "deleted_total": 0}
    finally:
        db.close()
