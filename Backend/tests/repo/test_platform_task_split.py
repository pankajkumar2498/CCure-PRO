"""
Backend alignment, step 1: the task hub split by owner.

The audit-log retention task moved from ``core/tasks.py`` to
``ccure_platform/audit_log/tasks.py``. A Celery task name is an API — it is in
the beat schedule and in any message already queued — so what must not change
is the registered name, the queue and the schedule, whichever module defines it.
"""

from __future__ import annotations

from celery.schedules import crontab

NAME = "ccure.tasks.purge_expired_audit_logs"


def _task():
    from core.celery_app import celery_app

    celery_app.loader.import_default_modules()
    return celery_app.tasks[NAME]


def test_the_retention_task_keeps_its_registered_name_and_queue():
    task = _task()
    assert task.name == NAME
    assert task.queue == "default"


def test_the_retention_task_is_now_the_platforms():
    assert _task().__module__ == "ccure_platform.audit_log.tasks"


def test_the_scan_hub_no_longer_defines_it():
    import core.tasks as hub

    assert not hasattr(hub, "purge_expired_audit_logs")


def test_the_beat_entry_is_unchanged():
    from core.celery_app import celery_app

    entry = celery_app.conf.beat_schedule["purge-expired-audit-logs-daily"]
    assert entry["task"] == NAME
    assert entry["schedule"] == crontab(hour=4, minute=30)


def test_the_task_keeps_its_logger_name():
    import ccure_platform.audit_log.tasks as mod

    assert mod.log.name == "ccure.tasks"
