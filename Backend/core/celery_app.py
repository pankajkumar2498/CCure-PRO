import os
from pathlib import Path
from celery import Celery
from kombu import Queue
from config import AppConfig

# Initialize the Celery Application
# We name it "ccure_tasks" and point it to our Redis container
celery_app = Celery(
    "ccure_tasks",
    broker=AppConfig.CELERY_BROKER_URL,
    backend=AppConfig.CELERY_RESULT_BACKEND,
    include=[
        "core.tasks",       # Network scan background jobs
        "core.web.tasks",   # Web application scan background jobs
    ]
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
        Queue("scanner"),       # Network scan tasks (existing)
        Queue("web_recon"),     # Web scan: subdomain enum, tech detect, WAF detect
        Queue("web_crawl"),     # Web scan: Playwright spidering, ffuf directory brute
        Queue("web_dast"),      # Web scan: Nuclei templates, SQLMap injection
        Queue("web_audit"),     # Web scan: TLS audit, compliance mapping
    ),
    task_track_started=True,
    worker_concurrency=AppConfig.SCANNER_WORKER_CONCURRENCY, # Limits parallel heavy scans
    worker_prefetch_multiplier=AppConfig.SCANNER_WORKER_PREFETCH_MULTIPLIER,
    task_time_limit=AppConfig.NMAP_TIMEOUT + 60, # Kill tasks if they hang
)

