"""
The web-scanning engine's settings, registered (Group 4,
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

The engine reads its settings only through ``core.web.settings``. In Audit
they are the deployment's ``config.WebScanConfig``, registered here — the
composition root — so the engine names no global configuration and a host
reusing it registers its own. The worker self-check reaches the database and
Redis only through the probes registered here too (2 Nov 2026). Loaded by name in every process that scans or
serves web DAST: ``core/celery_app.py`` names it in Celery's ``imports``, which
the worker loads at start-up, and ``main.py`` loads through the same call.
"""

from __future__ import annotations

from config import WebScanConfig
from core.redis_client import get_redis_client
from core.web.self_check import register_infrastructure_probes
from core.web.settings import configure
from db.base import SessionLocal
from sqlalchemy import text

configure(WebScanConfig)


# The worker self-check's database and Redis probes (2 Nov 2026): the same
# reads it made itself, on this deployment's database and Redis.
def _postgres() -> None:
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
    finally:
        db.close()


def _redis() -> None:
    get_redis_client().ping()


register_infrastructure_probes({"postgres": _postgres, "redis": _redis})
