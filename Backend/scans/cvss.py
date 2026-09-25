"""
Moved to ``core/checks/cvss.py`` (Phase 3 of the modular-platform programme).

It is a pure library — standard library only — and the engines, the check
contract and the configuration audit all need it, but under ``scans`` it sat in
the orchestration layer those are not allowed to import.

This path is an alias of the **same module object**, not a copy and not a star
re-export: every existing import, private name, ``isinstance`` check and
``patch.object`` target behaves exactly as before. New code imports from
``core.checks.cvss``.
"""

import sys

from core.checks import cvss as _module

sys.modules[__name__] = _module
