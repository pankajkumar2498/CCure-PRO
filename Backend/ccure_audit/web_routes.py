"""
The web DAST routes' rate limiter, registered (Group 4, D2,
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

``routers/web_scans.py`` declares its limits through ``core.web.rate_limits``
and names no limiter. In Audit they are enforced by the API's one limiter,
``core.rate_limiter.limiter`` (the object ``main`` puts on ``app.state`` and
the suite disables), registered here, the composition root, so every limit key
and its enforcement are what they were. ``main.py`` loads this module.
"""

from __future__ import annotations

from core.rate_limiter import limiter
from core.web.rate_limits import configure

configure(limiter)
