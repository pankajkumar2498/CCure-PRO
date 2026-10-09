import os

from celery import Celery
from config import AppConfig
from kombu import Queue

# The platform module registry (Phase 11) is a leaf — standard library only —
# which is why shared infrastructure may read it (layer_rules:
# infrastructure-is-foundation, exempt_targets).
from ccure_platform.modules import registry as module_registry

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
        "auth.mail_tasks",  # Outgoing application email
        "ccure_platform.identity.account_maintenance",  # Account and session purges
        "ccure_platform.audit_log.tasks",  # Audit-log retention
        # Each enabled module's task modules (Phase 11). Empty until a module
        # declares one: Audit's are the list above until Phase 16, and Policy Pro
        # and Rank are disabled.
        *module_registry.task_modules(),
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
        # Queues the enabled modules declare (Phase 11); none today.
        *(Queue(name) for name in module_registry.queues()),
    ),
    task_track_started=True,
    worker_concurrency=AppConfig.SCANNER_WORKER_CONCURRENCY,  # Limits parallel heavy scans
    worker_prefetch_multiplier=AppConfig.SCANNER_WORKER_PREFETCH_MULTIPLIER,
    # No global task_time_limit.
    #
    # This was `AppConfig.NMAP_TIMEOUT + 60` (360s) and applied to *every* task
    # in the application. NMAP_TIMEOUT is the lease on a single nmap invocation,
    # not a budget for a task that spawns many of them -- and a scan can wait up
    # to NMAP_PROCESS_WAIT_TIMEOUT (900s) just to acquire one nmap slot, so the
    # whole-task budget sat below the queue wait for one of its own subprocesses.
    #
    # It was invisible on the Windows host worker, which ran `--pool=threads`,
    # where Celery's hard limit cannot fire -- which is what the comments here
    # and in config.py used to mean by calling it "inert". The Linux VM worker
    # runs prefork, where it fires: measured 22 Sep 2026, a task was killed at
    # exactly 360s with TimeLimitExceeded(360). Against this deployment's own
    # history that would have killed 11 of 48 completed scans; the average
    # completed scan was already 426s.
    #
    # A global default is deliberately not set in its place. A limit that covers
    # every task has to be sized for the longest one, at which point it bounds
    # nothing that matters -- and the failure it produces is silent, because the
    # hard limit delivers SystemExit, which the tasks' `except Exception`
    # handlers do not catch. Each scan task declares its own soft and hard limit
    # from the SCAN_TIME_LIMIT_* budgets in config.py; the mail, purge and
    # bookkeeping tasks are bounded by what they do.
    #
    # `reap_stalled_scans` on beat remains the deployment's real scan timeout,
    # for the reason given beside it below: it is the only mechanism that can
    # settle a scan whose worker died or was restarted.
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
    # The deployment's real scan timeout. Celery's own per-task limits (set on
    # each scan task from the SCAN_TIME_LIMIT_* budgets) can only act on a task
    # that is still running. They cannot settle a scan whose worker died, was
    # restarted, or failed inside its own error handling, which is how scans
    # 60-62 came to sit in 'running' indefinitely on 4 Sep 2026 against a host
    # that was up. Note the limits were additionally inert on the old Windows
    # `--pool=threads` host worker; on the Linux prefork worker they do fire,
    # but this sweep is still the only backstop for a dead worker.
    #
    # Every two minutes: the deadlines are measured in tens of minutes, so the
    # tick only decides how promptly a stuck scan is reported, and the cost of
    # a tick that finds nothing is one indexed status lookup.
    "reap-stalled-scans-every-2-min": {
        "task": "ccure.tasks.reap_stalled_scans",
        "schedule": crontab(minute="*/2"),
    },
    # Web-application scans live in their own table with a four-phase lifecycle
    # and were not covered by the network reaper above — a hung crawl, a dead
    # web-worker, or a phase failing inside its own except handler left a web
    # scan 'running' forever, and the UI showed it live forever. Same cadence
    # and same conservative contract as the network reaper.
    "reap-stalled-web-scans-every-2-min": {
        "task": "ccure.tasks.reap_stalled_web_scans",
        "schedule": crontab(minute="*/2"),
    },
}


# The web-scanner worker's start-up self-check is registered by the web module
# itself, in core/web/tasks.py (Phase 3) — shared infrastructure does not
# import a feature.


def registered_task(name: str):
    """
    The task registered under ``name`` — the same object ``.delay()`` is called
    on when the defining module is imported directly.

    Code below the task hub dispatches through this rather than importing
    ``core.tasks``: importing the hub to reach one task put the scheduler, the
    scan persistence helpers and the hub in one import cycle. The object is the
    registered task itself, so its queue, time limits, eager execution and any
    test patch of ``.delay`` all behave exactly as before.

    A process that has not imported the task modules yet (a script, a shell)
    loads the modules this app is configured with — the same list a worker
    loads at start-up — and looks again. A name that is still missing raises
    ``celery.exceptions.NotRegistered``, as it would from a worker.
    """
    try:
        return celery_app.tasks[name]
    except KeyError:
        celery_app.loader.import_default_modules()
        return celery_app.tasks[name]
