"""
ccure_platform/administration — the shared administration surface.

User, organisation, role and email-domain administration (``/admin/users``,
``/admin/organizations``, ``/admin/roles``, ``/admin/email-domains``), which the
platform shell's Administration screens call. Each module is the router moved
from ``routers/admin_*.py`` with its paths, permissions and behaviour unchanged;
the legacy module names are kept (``ccure_platform/_legacy.py``).

Nothing here touches a module's tables. What a user purge does to a module's
records is that module's, through ``ccure_platform/offboarding.py``.
"""
