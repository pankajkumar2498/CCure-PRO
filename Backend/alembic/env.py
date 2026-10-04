import os
import re
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context

# Load environment variables
from dotenv import load_dotenv
from sqlalchemy import engine_from_config, pool

# Prefer explicit DATABASE_URL from environment. Otherwise load the same
# Backend env file as the app: .env.test for development, .env for production.
backend_dir = Path(__file__).resolve().parents[1]
app_env = os.getenv(
    "APP_ENV", os.getenv("ENVIRONMENT", os.getenv("ENV", "development"))
).lower()
env_path = backend_dir / (".env" if app_env in {"production", "prod"} else ".env.test")
if "DATABASE_URL" not in os.environ and env_path.exists():
    load_dotenv(dotenv_path=env_path)

# Add project root to Python path so imports work.
_PROJECT_ROOT = backend_dir
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# Import models for autogenerate
from db.base import Base

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
#
# `disable_existing_loggers=False` is required, not cosmetic. The default is
# True, and it sets `.disabled = True` on every logger that already exists in
# the process and is not named in alembic.ini — the whole application's
# loggers, in other words.
#
# That is irreversible from the outside: `Logger.isEnabledFor()` checks
# `.disabled` before it consults levels or handlers, so once it is set neither
# `setLevel()` nor attaching a handler directly to the logger brings the
# records back. Nothing is emitted at all.
#
# It only bites when alembic runs *in-process* rather than as the CLI, which
# `tests/conftest.py` does when it upgrades the scratch schema. The symptom is
# a test asserting on log output that captures zero records, several hundred
# tests later, with nothing to connect it back to here.
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# Ensure env var database url overrides the ini setting.
database_url = os.getenv("DATABASE_URL")
if database_url:
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))

# Set target metadata for autogenerate.
#
# Phase 11.3: each core module keeps its tables on a MetaData of its own, in its
# own schema, declared in its manifest.toml. Autogenerate compares all of them,
# and sees exactly `public` plus the modules' schemas — never `audit_chain` or
# `audit_retention`, which the DBA bootstraps own and no migration touches.
from ccure_platform.modules import registry as module_registry

target_metadata = [
    Base.metadata,
    *(
        md
        for m in module_registry.modules()
        for md in module_registry.module_metadatas(m)
    ),
]
_SCHEMAS = {m.db_schema for m in module_registry.modules()} | {"public"}


def include_name(name, type_, parent_names):
    """Autogenerate reflects only public and the core modules' schemas."""
    if type_ == "schema":
        return name is None or name in _SCHEMAS
    return True


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
        include_schemas=True,
        include_name=include_name,
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
            include_schemas=True,
            include_name=include_name,
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
        if compare_to is not None and hasattr(compare_to, "table"):
            tbl = compare_to.table
            if tbl is not None and re.match(r".*_p[0-9]+$", tbl.name):
                return False
    return True


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
