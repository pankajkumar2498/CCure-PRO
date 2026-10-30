"""
The web-scanning engine's settings, registered (Group 4,
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

The engine reads its settings only through ``core.web.settings``. In Audit
they are the deployment's ``config.WebScanConfig``, registered here — the
composition root — so the engine names no global configuration and a host
reusing it registers its own. Loaded by name in every process that scans or
serves web DAST: ``core/celery_app.py`` names it in Celery's ``imports``, which
the worker loads at start-up, and ``main.py`` loads through the same call.
"""

from __future__ import annotations

from config import WebScanConfig
from core.web.settings import configure

configure(WebScanConfig)
