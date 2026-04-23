"""
config.py
─────────────────────────────────────────────────────────────────────────
Centralized configuration for CCure Audit PRO.
Loads settings from environment variables with sensible defaults.
"""

import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent
DEFAULT_SQLITE_DB = BACKEND_DIR / "ccure_users.db"
ENV_FILE = BACKEND_DIR / ".env"

# Always load the Backend/.env file so database switching is controlled
# from one place even when the app is launched outside the Backend folder.
load_dotenv(dotenv_path=ENV_FILE)


def _normalize_database_url(database_url: str) -> str:
    """Resolve relative SQLite paths against the Backend directory."""
    if not database_url.startswith("sqlite:///"):
        return database_url

    raw_path = database_url.replace("sqlite:///", "", 1)
    sqlite_path = Path(raw_path)

    if not sqlite_path.is_absolute():
        sqlite_path = (BACKEND_DIR / sqlite_path).resolve()

    return f"sqlite:///{sqlite_path.as_posix()}"


class DatabaseConfig:
    """Database configuration with SQLite/PostgreSQL support."""

    DATABASE_URL: str = _normalize_database_url(
        os.getenv(
            "DATABASE_URL",
            f"sqlite:///{DEFAULT_SQLITE_DB.as_posix()}"
        )
    )

    @staticmethod
    def get_engine_kwargs():
        """Return engine kwargs based on database type."""
        if DatabaseConfig.DATABASE_URL.startswith("sqlite"):
            return {"connect_args": {"check_same_thread": False}}
        elif DatabaseConfig.DATABASE_URL.startswith("postgresql"):
            # PostgreSQL-specific optimizations
            return {
                "pool_pre_ping": True,              # Test connections before using
                "pool_size": 10,                    # Connection pool size
                "max_overflow": 20,                 # Additional connections allowed
                "pool_recycle": 3600,               # Recycle connections every hour
            }
        return {}


class JWTConfig:
    """JWT authentication configuration."""

    SECRET_KEY: str = os.getenv(
        "JWT_SECRET_KEY",
        "dev-secret-key-change-in-production"  # ⚠️ Never use in production
    )
    ACCESS_TOKEN_EXPIRES_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRES_MINUTES", "30"))
    REFRESH_TOKEN_EXPIRES_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRES_DAYS", "7"))


class ScanConfig:
    """Scan engine configuration."""

    NMAP_TIMEOUT: int = int(os.getenv("NMAP_TIMEOUT", "300"))
    NMAP_THREADS: int = int(os.getenv("NMAP_THREADS", "4"))


class AppConfig:
    """Application-wide configuration."""

    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # Database
    DATABASE_URL = DatabaseConfig.DATABASE_URL
    DATABASE_ENGINE_KWARGS = DatabaseConfig.get_engine_kwargs()

    # JWT
    JWT_SECRET_KEY = JWTConfig.SECRET_KEY
    ACCESS_TOKEN_EXPIRES_MINUTES = JWTConfig.ACCESS_TOKEN_EXPIRES_MINUTES
    REFRESH_TOKEN_EXPIRES_DAYS = JWTConfig.REFRESH_TOKEN_EXPIRES_DAYS

    # Scans
    NMAP_TIMEOUT = ScanConfig.NMAP_TIMEOUT
    NMAP_THREADS = ScanConfig.NMAP_THREADS

    @staticmethod
    def is_sqlite() -> bool:
        """Check if using SQLite database."""
        return AppConfig.DATABASE_URL.startswith("sqlite")

    @staticmethod
    def is_postgresql() -> bool:
        """Check if using PostgreSQL database."""
        return AppConfig.DATABASE_URL.startswith("postgresql")
