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
    "run-scheduled-compliance-scans-every-minute": {
        "task": "compliance.run_scheduled_scans",
        "schedule": 60.0,
    },
}
