"""
auth/models.py
--------------
SQLAlchemy auth models + database setup.
Supports both SQLite (dev) and PostgreSQL (prod) via DATABASE_URL env var.
"""

import os
import secrets
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, create_engine, inspect, text
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

# ── Database Configuration ────────────────────────────────────────────────────
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./ccure_users.db"
)

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
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

    refresh_tokens = relationship("RefreshTokenSession", back_populates="user", cascade="all, delete-orphan")


class RefreshTokenSession(Base):
    __tablename__ = "refresh_token_sessions"

    id          = Column(Integer, primary_key=True, index=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token_jti   = Column(String, unique=True, index=True, nullable=False, default=lambda: secrets.token_urlsafe(32))
    token_hash  = Column(String, unique=True, index=True, nullable=False)
    issued_at   = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at  = Column(DateTime, nullable=False)
    revoked_at  = Column(DateTime, nullable=True)
    replaced_by = Column(String, nullable=True)

    user = relationship("User", back_populates="refresh_tokens")


def ensure_auth_schema():
    """Backfill auth schema for existing databases."""
    inspector = inspect(engine)

    tables = inspector.get_table_names()
    if "refresh_token_sessions" not in tables:
        Base.metadata.create_all(bind=engine)
        return

    existing_columns = {column["name"] for column in inspector.get_columns("refresh_token_sessions")}
    statements = []

    if "issued_at" not in existing_columns:
        statements.append("ALTER TABLE refresh_token_sessions ADD COLUMN issued_at DATETIME")
    if "expires_at" not in existing_columns:
        statements.append("ALTER TABLE refresh_token_sessions ADD COLUMN expires_at DATETIME")
    if "revoked_at" not in existing_columns:
        statements.append("ALTER TABLE refresh_token_sessions ADD COLUMN revoked_at DATETIME")
    if "replaced_by" not in existing_columns:
        statements.append("ALTER TABLE refresh_token_sessions ADD COLUMN replaced_by VARCHAR")

    if not statements:
        return

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def create_tables():
    """Create all tables (called on app startup)."""
    Base.metadata.create_all(bind=engine)
    ensure_auth_schema()


def get_db():
    """FastAPI dependency: yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()