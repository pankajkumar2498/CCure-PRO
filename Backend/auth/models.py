"""
auth/models.py
--------------
Legacy proxy for auth database models.
This proxies to the new production-grade database schema in the `db/` package.
"""

from db.base import engine, SessionLocal, Base, get_db
from db.models.users import User, RefreshTokenSession

# Proxy ensure_auth_schema for backward compatibility
# The production db/migrate_production_schema.py script now handles migrations,
# so this is a no-op just to satisfy imports.
def ensure_auth_schema():
    pass

def create_tables():
    pass