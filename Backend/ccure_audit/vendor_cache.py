"""
The asset registry's MAC-vendor cache, registered as the scan kernel's shared
OUI cache (G3, docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

``core.oui_lookup`` is part of the scan kernel and names no table; the asset
registry answers its cache (``core/mac_vendor_cache.py``). Registered here, as
the host directory and compliance's evidence providers are, so that what Audit
plugs into what is said in its composition root.

Loaded by name in every process that looks vendors up: ``core/celery_app.py``
names it in Celery's ``imports``, which the worker loads at start-up, and
``main.py`` loads through the same call. A process without it skips the shared
cache, as one without a database always did.
"""

from __future__ import annotations

from core import mac_vendor_cache
from core.oui_lookup import register_vendor_cache

register_vendor_cache(mac_vendor_cache.STORE)
