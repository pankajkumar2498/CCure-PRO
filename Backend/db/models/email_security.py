"""
Moved to ``ccure_platform/models/email_security.py`` (B8 of the module-independence plan: the platform registers its models alone).

This path is an alias of the **same module object**, not a copy and not a star
re-export — see ``ccure_platform/_legacy.py``. Existing imports, private names,
``isinstance`` checks and ``patch`` targets behave exactly as before.
"""

import ccure_platform.models.email_security as _module  # noqa: F401  (registers the alias on import)
import sys

sys.modules[__name__] = _module
