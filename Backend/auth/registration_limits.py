"""
Moved to ``ccure_platform/identity/registration_limits.py`` (Phase 8.2 of the modular-platform programme).

This path is an alias of the **same module object**, not a copy and not a star
re-export — see ``ccure_platform/_legacy.py``. Existing imports, private names,
``isinstance`` checks and ``patch`` targets behave exactly as before.
"""

import ccure_platform.identity.registration_limits as _module  # noqa: F401  (registers the alias on import)
import sys

sys.modules[__name__] = _module
