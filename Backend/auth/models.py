"""
auth/models.py
--------------
DEPRECATED — Legacy proxy kept only for backward compatibility.

All new code should import directly from:
  - db.base       → engine, SessionLocal, Base, get_db
  - db.models     → User, RefreshTokenSession, etc.

This module will be removed in a future version.
"""

import warnings as _warnings

_warnings.warn(
    "auth.models is a deprecated proxy. Import from db.base and db.models directly.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export for any remaining legacy callers
from db.base import engine, SessionLocal, Base, get_db  # noqa: F401
from db.models.users import User, RefreshTokenSession  # noqa: F401


def ensure_auth_schema():
    """No-op — schema is managed by db/migrate_production_schema.py."""
    pass


def create_tables():
    """No-op — schema is managed by db/migrate_production_schema.py."""
    pass
