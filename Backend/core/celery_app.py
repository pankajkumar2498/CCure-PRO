import os
from celery import Celery
from kombu import Queue
from config import AppConfig

# Initialize the Celery Application
# We name it "ccure_tasks" and point it to our Redis container
celery_app = Celery(
    "ccure_tasks",
    broker=AppConfig.CELERY_BROKER_URL,
    backend=AppConfig.CELERY_RESULT_BACKEND,
    include=["core.tasks"] # We will put our background jobs in core/tasks.py
)

# Optional but recommended configuration for security and stability
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_default_queue="default",
    task_queues=(
        Queue("default"),
        Queue("scanner"),
    ),
    task_track_started=True,
    worker_concurrency=AppConfig.SCANNER_WORKER_CONCURRENCY, # Limits parallel heavy scans
    worker_prefetch_multiplier=AppConfig.SCANNER_WORKER_PREFETCH_MULTIPLIER,
    task_time_limit=AppConfig.NMAP_TIMEOUT + 60, # Kill tasks if they hang
)
