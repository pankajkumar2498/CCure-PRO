"""
Moved to ``ccure_platform/administration/organizations.py`` (organisation administration, step 2 of the backend alignment).

This path is an alias of the **same module object**, not a copy and not a star
re-export — see ``ccure_platform/_legacy.py``. Existing imports, private names,
``isinstance`` checks and ``patch`` targets behave exactly as before.
"""

import ccure_platform.administration.organizations as _module  # noqa: F401  (registers the alias on import)
import sys

sys.modules[__name__] = _module
