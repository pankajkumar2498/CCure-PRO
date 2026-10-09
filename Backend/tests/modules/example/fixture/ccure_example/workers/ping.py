"""A Celery task, named under the module's task prefix (ccure.example).

shared_task binds to whichever Celery app loads the module, so the module never
imports the platform's task runtime.
"""

from celery import shared_task


@shared_task(name="ccure.example.ping")
def ping() -> str:
    return "pong"
