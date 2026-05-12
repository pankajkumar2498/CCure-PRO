from logging.config import fileConfig
import os
import sys
import re
from pathlib import Path

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# Load environment variables
from dotenv import load_dotenv

# Prefer explicit DATABASE_URL from environment. Otherwise load Backend/.env.
env_path = Path(__file__).resolve().parents[1] / ".env"
if "DATABASE_URL" not in os.environ and env_path.exists():
    load_dotenv(dotenv_path=env_path)

# Add project root to Python path so imports work.
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# Import models for autogenerate
from db.base import Base
from db.models.rbac          import Organization, Role, Permission, RolePermission
from db.models.users         import User, RefreshTokenSession, AuditLog
from db.models.assets        import Asset, AssetTag, AssetNote, AssetChangeLog
from db.models.scans         import Scan, ScanPhase
from db.models.findings      import (
    Service, TLSDetail, HttpSecurityDetail,
    VulnerabilityDefinition, AssetVulnerability,
)
from db.models.notifications import Notification

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Ensure env var database url overrides the ini setting.
database_url = os.getenv("DATABASE_URL")
if database_url:
    config.set_main_option("sqlalchemy.url", database_url)

# Set target metadata for autogenerate
target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = os.getenv("DATABASE_URL") or config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_object=include_object,
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_object=include_object,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


def include_object(object, name, type_, reflected, compare_to):
    """Ignore partition child tables and their indexes during autogenerate."""
    if type_ == "table" and re.match(r".*_p[0-9]+$", name):
        return False

    if type_ == "index":
        if compare_to is not None and hasattr(compare_to, 'table'):
            tbl = getattr(compare_to, 'table')
            if tbl is not None and re.match(r".*_p[0-9]+$", tbl.name):
                return False
    return True

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
