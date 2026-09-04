import os

from celery import Celery
from config import AppConfig
from kombu import Queue

# Initialize the Celery Application
# We name it "ccure_tasks" and point it to our Redis container
celery_app = Celery(
    "ccure_tasks",
    broker=AppConfig.CELERY_BROKER_URL,
    backend=AppConfig.CELERY_RESULT_BACKEND,
    include=[
        "core.tasks",  # Network scan background jobs
        "core.web.tasks",  # Web application scan background jobs
        "core.compliance_tasks",  # Compliance scan background jobs
        "core.email_security_tasks",  # Email domain screening and account hygiene
    ],
)

# Optional but recommended configuration for security and stability
celery_app.conf.update(
    task_always_eager=os.getenv("CELERY_TASK_ALWAYS_EAGER", "False").lower() == "true",
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_default_queue="default",
    task_queues=(
        Queue("default"),
        Queue("scanner"),  # Network scan tasks (existing)
        Queue("web_recon"),  # Web scan: subdomain enum, tech detect, WAF detect
        Queue("web_crawl"),  # Web scan: Playwright spidering, ffuf directory brute
        Queue("web_dast"),  # Web scan: Nuclei templates, SQLMap injection
        Queue("web_audit"),  # Web scan: TLS audit, compliance mapping
        Queue("compliance"),  # Compliance scan baseline queue (new)
    ),
    task_track_started=True,
    worker_concurrency=AppConfig.SCANNER_WORKER_CONCURRENCY,  # Limits parallel heavy scans
    worker_prefetch_multiplier=AppConfig.SCANNER_WORKER_PREFETCH_MULTIPLIER,
    task_time_limit=AppConfig.NMAP_TIMEOUT + 60,  # Kill tasks if they hang
)

from celery.schedules import crontab

celery_app.conf.beat_schedule = {
    "prune-compliance-remediation-logs-weekly": {
        "task": "compliance.prune_remediation_logs",
        "schedule": crontab(hour=0, minute=0, day_of_week="sun"),
    },
    "run-scheduled-compliance-scans-every-5-min": {
        "task": "compliance.run_scheduled_scans",
        "schedule": crontab(minute="*/5"),
    },
    # An account that was registered and never verified is personal data held
    # for no purpose, and it also keeps a username and email address reserved
    # against whoever legitimately wants them.
    "purge-stale-unverified-accounts-daily": {
        "task": "ccure.tasks.purge_stale_unverified_accounts",
        "schedule": crontab(hour=3, minute=30),
    },
    # A *verified* account nobody ever approved is not covered by the task
    # above — that one filters on is_verified=False, and a throwaway-inbox
    # registrant does click the verification link. Without this second sweep the
    # approval queue only ever grows.
    "purge-stale-unapproved-accounts-daily": {
        "task": "ccure.tasks.purge_stale_unapproved_accounts",
        "schedule": crontab(hour=3, minute=45),
    },
    # New disposable-mail providers appear constantly, so a corpus frozen at
    # deploy time decays into uselessness. Weekly, off-hours; the sync merges
    # and never replaces, so a failed run leaves the previous data intact.
    # refresh_token_sessions gains a row per login *and* one per token
    # rotation, which with 30-minute access tokens is ~48 a day per signed-in
    # session. Nothing ever deleted them. Revoked rows are deliberately kept
    # for the full retention window — the revocation is the audit record.
    "purge-expired-refresh-sessions-daily": {
        "task": "ccure.tasks.purge_expired_refresh_sessions",
        "schedule": crontab(hour=4, minute=0),
    },
    # Phase 18 (GAP-14). An accepted risk with an expiry date is a decision
    # with a shelf life; when it runs out the finding is simply outstanding
    # again and belongs back in the remediation queue. Hourly rather than
    # daily because an expiry is a compliance boundary — an acceptance that
    # lapsed at 09:00 should not still be suppressing a critical finding at
    # 23:59 — and the query is one indexed predicate matching a handful of
    # rows.
    "expire-risk-acceptances-hourly": {
        "task": "ccure.tasks.expire_risk_acceptances",
        "schedule": crontab(minute=5),
    },
    "sync-disposable-email-domains-weekly": {
        "task": "ccure.tasks.sync_disposable_domains",
        "schedule": crontab(hour=4, minute=15, day_of_week="mon"),
    },
    # Phase 6a audit retention. Scheduled, but a **no-op until
    # AUDIT_LOG_RETENTION_DAYS is set to a non-zero value**, and a dry run
    # unless AUDIT_RETENTION_DRY_RUN is explicitly false — so registering it
    # here changes nothing about what the deployment does today.
    #
    # It is registered anyway rather than added later, because the interaction
    # worth exercising is the schedule itself: a retention job that has never
    # once run its preconditions on this beat is a job nobody has tested.
    # 04:30 puts it after the refresh-session sweep and well clear of the
    # 6-hourly backup window it depends on.
    "purge-expired-audit-logs-daily": {
        "task": "ccure.tasks.purge_expired_audit_logs",
        "schedule": crontab(hour=4, minute=30),
    },
    # Scan scheduling (Phase 1). Every minute, because one minute is the
    # resolution the feature promises: a schedule set for 09:00 fires between
    # 09:00 and 09:01. The cost of a tick that finds nothing is one indexed
    # lookup against ix_scan_schedules_due, and the task takes a
    # try-advisory-xact-lock so a second beat process cannot double-dispatch.
    "run-due-scan-schedules-every-minute": {
        "task": "ccure.tasks.run_due_scan_schedules",
        "schedule": crontab(minute="*"),
    },
}
