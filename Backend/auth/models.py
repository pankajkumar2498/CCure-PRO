"""
auth/models.py
--------------
SQLAlchemy User model + database setup.
Supports both SQLite (dev) and PostgreSQL (prod) via DATABASE_URL env var.
"""

import os
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# ── Database Configuration ────────────────────────────────────────────────────
# Default to SQLite for local testing
# Set DATABASE_URL env var to switch to PostgreSQL (or any other database)
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./ccure_users.db"
)

# For PostgreSQL, you would set:
# DATABASE_URL=postgresql://user:password@localhost:5432/ccure_db

# Special handling for SQLite connection
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    # For PostgreSQL and other databases
    engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, index=True)
    username      = Column(String, unique=True, index=True, nullable=False)
    email         = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at    = Column(DateTime, default=datetime.utcnow)
    updated_at    = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


def create_tables():
    """Create all tables (called on app startup)."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """FastAPI dependency: yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
