"""
Moved to ``ccure_platform/identity/email_security_tasks.py`` (Phase 8.3 of the
modular-platform programme): email-risk enrichment, the retro-scan, the
unapproved-account purge and the disposable-domain sync are account screening
and lifecycle, which is identity's.

This path is an alias of the **same module object** — see
``ccure_platform/_legacy.py``. The Celery ``include`` list still names this
path, and the four task names are unchanged.
"""

import ccure_platform.identity.email_security_tasks as _module  # noqa: F401  (registers the alias on import)
import sys

sys.modules[__name__] = _module
