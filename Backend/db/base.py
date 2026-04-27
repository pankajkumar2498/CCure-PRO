"""
db/base.py
──────────────────────────────────────────────────────────────────────────────
Production-grade SQLAlchemy base, engine, and session setup.

Key design decisions:
  - Uses PostgreSQL-native types: UUID, JSONB, INET, MACADDR, TIMESTAMPTZ, CIDR
  - Connection pool tuned for production workloads
  - All timestamps are timezone-aware (TIMESTAMPTZ)
  - UUIDs are used as primary keys for all core entities
    (prevents enumeration attacks and allows distributed generation)
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import create_engine, event, text, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import declarative_base, sessionmaker

# TIMESTAMPTZ alias — maps to TIMESTAMP WITH TIME ZONE in PostgreSQL
# Used throughout all model files for timezone-aware timestamp columns.
TIMESTAMPTZ = DateTime(timezone=True)

from config import AppConfig

# ─── Engine ───────────────────────────────────────────────────────────────────

engine = create_engine(
    AppConfig.DATABASE_URL,
    # Pool settings tuned for production
    pool_pre_ping=True,        # Drop stale connections before use
    pool_size=10,              # Persistent connections kept open
    max_overflow=20,           # Burst connections allowed above pool_size
    pool_recycle=3600,         # Recycle connections every hour
    pool_timeout=30,           # Wait max 30s for a connection
    echo=False,                # Set True to log SQL (dev only)
)

# ─── Enable pg_trgm extension for fast text search ───────────────────────────

@event.listens_for(engine, "connect")
def _set_extensions(dbapi_connection, connection_record):
    """Enable useful PostgreSQL extensions on first connection."""
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
        cursor.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        cursor.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    except Exception:
        pass  # Extensions may already exist
    finally:
        cursor.close()

# ─── Session & Base ──────────────────────────────────────────────────────────

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# ─── Helpers ─────────────────────────────────────────────────────────────────

def gen_uuid() -> str:
    """Generate a new UUID v4 string — used as default for PK columns."""
    return str(uuid.uuid4())


def utcnow() -> datetime:
    """Return the current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


# ─── FastAPI dependency ───────────────────────────────────────────────────────

def get_db():
    """FastAPI dependency: yields a scoped DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
