"""
Legacy import paths for code that moved into ``ccure_platform`` (Phase 8.2).

Identity's code and models moved here from ``auth/`` and ``db/models/``. Every
old path must keep resolving, and to **the same module object** — not a copy,
not a star re-export — so that ``db.models.users.User is
ccure_platform.models.users.User``, a patch applied through either name is seen
through both, and SQLAlchemy never meets a model class twice. A second import of
a model file under another name would define its tables twice, which SQLAlchemy
refuses at start-up.

``adopt_legacy_name`` is called at the top of each moved module, before any
other statement that reads ``__name__``. It does three things:

* registers the module under its legacy name in ``sys.modules``, from inside
  its own import, so the alias exists whichever name is imported first;
* sets it as an attribute of the legacy parent package when that package is
  already loaded. For the other order, the legacy packages (``auth``,
  ``db.models``) answer a missing submodule attribute from ``sys.modules`` in
  their own ``__getattr__``;
* sets the module's ``__name__`` back to the legacy name.

The last one is the deliberate part. Everything derived from ``__name__`` is
externally observable, and Phase 8.2 changes none of it:

* the limiter's route table is keyed ``f"{func.__module__}.{func.__name__}"``
  (``auth.router.login``), and the security tests and the endpoint inventory
  read those keys;
* logger names (``auth.router``, ``auth.jwt_handler``, …), which log filters
  match on;
* the ``__module__`` of Pydantic models and SQLAlchemy classes, which FastAPI
  uses to name OpenAPI components when two classes share a name, and Pydantic
  uses to resolve postponed annotations.

The module's real location is still ``__spec__.name`` and ``__file__``.
Renaming the loggers and limiter keys to their new paths is a later, deliberate
change, not a side effect of moving a file.

Each legacy path also keeps a small stub file (``auth/router.py``,
``db/models/users.py``, …) — the ``scans.cvss`` pattern from Phase 3 — so a
fresh interpreter importing the old name finds the new module.
"""

from __future__ import annotations

import sys

#: legacy name -> the module it is an alias of. The one record of what moved in
#: Phase 8.2; ``tests/repo/test_platform_identity_move.py`` checks every entry in
#: both directions (each legacy file is a stub of exactly this module, and each
#: moved module adopts exactly this name).
MOVED_MODULES: dict[str, str] = {
    "auth.router": "ccure_platform.identity.router",
    "auth.jwt_handler": "ccure_platform.identity.jwt_handler",
    "auth.dependencies": "ccure_platform.identity.dependencies",
    "auth.email_utils": "ccure_platform.identity.email_utils",
    "auth.email_domain_guard": "ccure_platform.identity.email_domain_guard",
    "auth.email_risk_signals": "ccure_platform.identity.email_risk_signals",
    "auth.mail_dispatch": "ccure_platform.identity.mail_dispatch",
    "auth.mail_service": "ccure_platform.identity.mail_service",
    "auth.mail_tasks": "ccure_platform.identity.mail_tasks",
    "auth.registration_limits": "ccure_platform.identity.registration_limits",
    "auth.rbac": "ccure_platform.rbac.dependencies",
    "db.models.users": "ccure_platform.models.users",
    "db.models.rbac": "ccure_platform.models.rbac",
}


def adopt_legacy_name(module_name: str, legacy_name: str) -> None:
    """Make ``legacy_name`` the same module object as ``module_name``."""
    module = sys.modules[module_name]
    sys.modules[legacy_name] = module
    parent_name, _, child = legacy_name.rpartition(".")
    parent = sys.modules.get(parent_name)
    if parent is not None:
        setattr(parent, child, module)
    module.__name__ = legacy_name
