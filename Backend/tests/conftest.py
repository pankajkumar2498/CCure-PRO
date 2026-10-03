"""
tests/conftest.py
─────────────────────────────────────────────────────────────────────────────
Pytest configuration and global fixtures for the CCure Audit PRO backend.
Tests are expected to run against PostgreSQL and require DATABASE_URL to be set accordingly.
"""

import logging
import os
import sys
from collections.abc import Generator
from pathlib import Path

import pytest

# Several helpers below log on their failure paths. The module referenced a
# `logger` that was never defined, so those paths raised NameError instead of
# reporting the condition they were written to report.
logger = logging.getLogger(__name__)
import sqlalchemy.dialects.sqlite.base as sqlite_base
from dotenv import load_dotenv
from fastapi.testclient import TestClient

# ── Legacy SQLite Compatibility Helpers ───────────────────────────────────────
# These helpers remain available for older test code, but tests must run on PostgreSQL.
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB, MACADDR, UUID
from sqlalchemy.types import JSON, BigInteger, Integer, SmallInteger, String

# ── Isolate the test run from production infrastructure ───────────────────────
#
# Two things were leaking out of the test suite into the live deployment.
#
# 1. Celery. Nothing pointed the broker anywhere else, so `.delay()` in a test
#    published to the *production* Redis, and the host scanner worker consumed
#    and executed it. Real verification and MFA emails were sent through the
#    real Gmail account to fixture addresses (`vera@test.com`,
#    `admin@test.com`), which burns sending quota and repeatedly delivers to
#    domains that do not exist — a good way to get an account rate-limited. It
#    also meant test-dispatched *scan* tasks ran on the production worker; a
#    stale `run_host_discovery_task` for a deleted test user was still failing
#    in that worker's log.
#
# 2. SMTP. Any code path that sent mail synchronously reached smtp.gmail.com
#    directly.
#
# Both are closed here, before anything imports celery_app or mail_service.
#
# The broker is moved to a dedicated Redis *database* on the same server rather
# than to an in-memory transport: `core/redis_client.py` builds a redis client
# straight from CELERY_BROKER_URL and rejects any scheme that is not redis://,
# so `memory://` breaks the import chain at
# core.nmap.wrapper -> core.redis_client. Database 15 is not consumed by any
# worker, so a task published from a test goes nowhere and is executed by
# nothing — while every consumer of the URL still gets a URL it can parse.
#
# The host and port are inherited rather than hardcoded, so this follows the
# deployment instead of assuming localhost.
#
# MAIL_INLINE_FALLBACK is turned off so dispatch_email keeps taking the
# `.delay()` path: tests assert on dispatch by patching `.delay`, and the
# fallback would otherwise bypass those patches and try to send for real.
_TEST_REDIS_DB = "15"


def _redis_url_on_test_db(url: str) -> str:
    """Point a redis:// URL at the throwaway test database, keeping host/auth."""
    if not url or "://" not in url:
        return f"redis://localhost:6379/{_TEST_REDIS_DB}"
    scheme, _, remainder = url.partition("://")
    if scheme not in ("redis", "rediss"):
        return f"redis://localhost:6379/{_TEST_REDIS_DB}"
    authority = remainder.split("/", 1)[0]
    return f"{scheme}://{authority}/{_TEST_REDIS_DB}"


_broker = _redis_url_on_test_db(os.getenv("CELERY_BROKER_URL", ""))
os.environ["CELERY_BROKER_URL"] = _broker
os.environ["CELERY_RESULT_BACKEND"] = _broker
os.environ["MAIL_INLINE_FALLBACK"] = "False"

sqlite_base.SQLiteDialect.colspecs.update(
    {
        UUID: String,
        JSONB: JSON,
        INET: String,
        MACADDR: String,
        CIDR: String,
        SmallInteger: Integer,
        BigInteger: Integer,
    }
)

# Add Backend to PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Add tests/ itself, so every module under it can `from testpaths import ...`
# whichever grouping subdirectory it lives in.
#
# Those subdirectories deliberately carry no __init__.py. As packages their
# names would be importable, and `tests/auth` and `tests/scans` would collide
# head-on with Backend's own `auth` and `scans` packages: pytest names the
# module `auth.test_auth`, Python resolves `auth` to the application package,
# and every test in the group fails to import with ModuleNotFoundError. Without
# the markers pytest imports each file under its bare basename, which the suite
# keeps unique.
#
# pytest also happens to put this directory on sys.path while loading this very
# file. Doing it explicitly means the shared path anchors do not depend on that
# implementation detail.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load environment from Backend/.env.test if available BEFORE importing app
dotenv_path = Path(__file__).absolute().parents[1] / ".env.test"
if dotenv_path.exists():
    load_dotenv(dotenv_path=dotenv_path)

# Prevent config.py from loading .env and overriding our test settings
os.environ["SKIP_DOTENV_LOAD"] = "1"

# Run Celery tasks synchronously under pytest so Redis is not required locally
os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "true")
os.environ.setdefault("CELERY_TASK_EAGER_PROPAGATES", "true")

# ── Test database selection ───────────────────────────────────────────────────
# The suite drops and rebuilds its schema, so pointing it at the wrong database
# destroys that database. Selection therefore fails *closed*: a target must be
# recognisable as a pytest database by name, and anything else is refused.
#
# This replaced a deny-list of ('ccure_db', 'prod', 'production', 'ccure_test').
# A deny-list cannot protect a database nobody remembered to add to it —
# 'ccure_staging', 'ccure_dev', 'main' and 'postgres' all passed it.
import re
from urllib.parse import urlparse

from datetime import datetime, timezone

from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, OperationalError

#: A database may be used by pytest only if its name matches. Keep this narrow.
#
# '_test$' used to be in here and it cost us a production database: the live
# application DB is named 'ccure_test', so the guard meant to protect it was the
# thing that authorised wiping it. "test" in a name says nothing about whether
# real data lives there. Only '_pytest'-style names — which nobody gives a
# database they care about — are accepted now.
TEST_DB_NAME_PATTERN = re.compile(r"(^pytest_|_pytest$|_pytest_db$)")

#: Databases that must never be used by the suite even if renamed into the
#: pattern above. A belt to the pattern's braces.
FORBIDDEN_DB_NAMES = frozenset(
    {
        "ccure_test",
        "ccure_db",
        "ccure_prod",
        "ccure_app",
        "ccure_staging",
        "ccure_dev",
        "vuln_intel",
        "postgres",
        "template0",
        "template1",
    }
)

#: A table the suite creates in any scratch database it owns. Its presence is
#: the positive proof that a database is disposable. A real database will never
#: have one, so even a correctly-named database that happens to hold live data
#: is refused until someone deliberately marks it.
SENTINEL_TABLE = "_pytest_scratch_marker"

#: Name of the disposable database the suite owns.
SCRATCH_DB_NAME = "ccure_pytest_db"

DEFAULT_TEST_DATABASE_URL = (
    f"postgresql://ccure_user:ccure_admin_2026@127.0.0.1:5432/{SCRATCH_DB_NAME}"
)


def _db_name(url: str) -> str:
    return urlparse(url).path.lstrip("/")


def _scratch_url_beside(url: str) -> str:
    """
    Point at the scratch database on the *same* server as ``url``.

    Refusing an unsafe target only helps if the safe target is reachable. The
    hardcoded default assumes 127.0.0.1, which is wrong inside a container — and
    a safe default that cannot connect just tempts the next person to override
    it with something dangerous. Reuse the host and credentials we were given
    and swap only the database name.
    """
    parsed = urlparse(url)
    if not parsed.netloc:
        return DEFAULT_TEST_DATABASE_URL
    return parsed._replace(path=f"/{SCRATCH_DB_NAME}").geturl()


def _is_test_database(url: str) -> bool:
    name = _db_name(url)
    if not name or name.lower() in FORBIDDEN_DB_NAMES:
        return False
    return bool(TEST_DB_NAME_PATTERN.search(name))


#: Tables whose contents prove a database is in real use. Reference data
#: (CVE feed, compliance catalogue) is excluded — a scratch database legitimately
#: carries those, and they are never what someone mourns.
_LIVE_DATA_TABLES = ("users", "scans", "assets", "services")


def _assert_database_is_disposable(url: str) -> None:
    """
    Refuse to run unless the target database is provably a scratch database.

    Name matching alone is not enough: it is one typo, one rename, or one
    inherited DATABASE_URL away from truncating something irreplaceable. A
    database qualifies when it carries the sentinel table, or when it is empty
    enough that there is nothing to lose — in which case it is marked so the
    check is cheap next time.
    """
    name = _db_name(url)
    engine = create_engine(url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            marked = conn.execute(
                text("SELECT to_regclass(:t)"), {"t": f"public.{SENTINEL_TABLE}"}
            ).scalar()
            if marked:
                return

            populated = {}
            for table in _LIVE_DATA_TABLES:
                if not conn.execute(
                    text("SELECT to_regclass(:t)"), {"t": f"public.{table}"}
                ).scalar():
                    continue
                count = conn.execute(
                    text(f"SELECT count(*) FROM {table}")  # noqa: S608 - fixed list
                ).scalar()
                if count:
                    populated[table] = count

            if populated:
                detail = ", ".join(f"{t}={n}" for t, n in sorted(populated.items()))
                raise RuntimeError(
                    f"Refusing to run: database '{name}' holds live data ({detail}) "
                    f"and is not marked as a pytest scratch database.\n"
                    f"The suite TRUNCATEs organizations and users CASCADE, which "
                    f"would destroy all of it.\n"
                    f"If this database really is disposable, mark it explicitly:\n"
                    f'  psql -d {name} -c "CREATE TABLE {SENTINEL_TABLE} '
                    f'(marked_at timestamptz DEFAULT now());"'
                )

            conn.execute(
                text(
                    f"CREATE TABLE IF NOT EXISTS {SENTINEL_TABLE} "
                    f"(marked_at timestamptz DEFAULT now())"
                )
            )
    except (OperationalError, DBAPIError):
        # The database may not exist yet; creation happens further down and the
        # sentinel is written on the next pass. Connectivity errors surface there
        # with a better message than this check could give.
        pass
    finally:
        engine.dispose()


# TEST_DATABASE_URL is an explicit choice and is honoured as given; DATABASE_URL
# is inherited from the developer's .env and points at a real database, so it is
# only accepted when it independently looks like a test database.
_explicit = os.getenv("TEST_DATABASE_URL")
_inherited = os.getenv("DATABASE_URL")

if _explicit:
    database_url = _explicit
    if not _is_test_database(database_url):
        raise RuntimeError(
            f"TEST_DATABASE_URL points at '{_db_name(database_url)}', which is not "
            f"a recognised pytest database. The suite TRUNCATEs organizations and "
            f"users CASCADE, so it refuses to run anywhere that is not named to "
            f"match {TEST_DB_NAME_PATTERN.pattern} "
            f"(and is not one of: {', '.join(sorted(FORBIDDEN_DB_NAMES))})."
        )
elif _inherited and _is_test_database(_inherited):
    database_url = _inherited
else:
    # DATABASE_URL is inherited from whatever environment pytest happens to run
    # in — a developer's .env, or the API container, where it points straight at
    # the live application database. Falling back to the dedicated scratch
    # database is the safe default; inheriting is the exception, not the rule.
    # Keep the rejected URL's host and credentials so the fallback is reachable
    # from wherever the suite is running.
    database_url = (
        _scratch_url_beside(_inherited) if _inherited else DEFAULT_TEST_DATABASE_URL
    )
    if _inherited:
        print(
            f"[conftest] DATABASE_URL points at '{_db_name(_inherited)}', which is "
            f"not a pytest scratch database. Using '{SCRATCH_DB_NAME}' instead.",
            file=sys.stderr,
        )

# Last line of defence, applied to whichever URL won above: a correctly-named
# database still has to prove it is disposable before anything truncates it.
_assert_database_is_disposable(database_url)

if not database_url.startswith("postgresql"):
    raise RuntimeError(
        "Tests must run against PostgreSQL. Set TEST_DATABASE_URL to a "
        "postgresql:// URL instead of sqlite:///."
    )

# Final assertion, after every branch above. Nothing past this point may run
# against a database whose name does not opt in.
if not _is_test_database(database_url):
    raise RuntimeError(
        f"Refusing to run tests against '{_db_name(database_url)}'. Expected a "
        f"database matching {TEST_DB_NAME_PATTERN.pattern}."
    )

os.environ["DATABASE_URL"] = database_url


def _ensure_test_db_exists(url: str):
    """Create the target database when missing. Only ever called post-guard."""
    try:
        target_db = _db_name(url)
        if not target_db or not url.startswith("postgresql"):
            return
        postgres_url = url.rsplit("/", 1)[0] + "/postgres"
        admin_engine = create_engine(postgres_url, isolation_level="AUTOCOMMIT")
        with admin_engine.connect() as conn:
            res = conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :dbname"),
                {"dbname": target_db},
            )
            if not res.scalar():
                conn.execute(text(f'CREATE DATABASE "{target_db}"'))
        admin_engine.dispose()
    except (OperationalError, DBAPIError) as err:
        logger.debug("Test DB creation skipped: %s", err)


# Creation happens *after* the guard. Previously it ran first, so a typo in
# DATABASE_URL created a stray database before the check rejected the name.
_ensure_test_db_exists(database_url)

os.environ["JWT_SECRET_KEY"] = "test-secret-key-do-not-use-in-prod"
# Pinned to the same value the MFA key fell back to before Phase 9.2, so the
# test process derives exactly the key it always did — and never the real one
# a developer's Backend/.env may now carry.
os.environ["MFA_ENCRYPTION_KEY"] = os.environ["JWT_SECRET_KEY"]

# Token issuance (Phase 9.4). The suite runs the target state — ES256 from a
# throwaway keyset generated for this session — whatever the container's own
# CCURE_TOKEN_* settings are, and never with the deployment's real keys. The
# directory is created here, before config is imported, and removed at exit.
import atexit
import shutil
import tempfile

_TEST_TOKEN_KEYS_DIR = tempfile.mkdtemp(prefix="ccure-pytest-keys-")
atexit.register(shutil.rmtree, _TEST_TOKEN_KEYS_DIR, ignore_errors=True)
os.environ["CCURE_TOKEN_KEYS_DIR"] = _TEST_TOKEN_KEYS_DIR
os.environ["CCURE_TOKEN_SIGNING_ALG"] = "ES256"
os.environ["CCURE_ACCEPT_LEGACY_HS256"] = "true"

from scripts.security.manage_token_keys import generate as _generate_token_key

_generate_token_key(_TEST_TOKEN_KEYS_DIR, "active", owner=None)

from main import app

# ── Disable rate limiting during tests ───────────────────────────────────────
# slowapi enforces limits based on request count. In CI, rapid parallel calls
# to auth/login trigger 429 Too Many Requests. Disable globally for the test run.
try:
    app.state.limiter.enabled = False
except (AttributeError, KeyError):
    logger.debug("app.state.limiter not present; continuing without disabling limiter")

from auth.jwt_handler import hash_password
from db.base import Base, SessionLocal, engine, get_db
from db.models.rbac import Organization, Role, RolePermission
from db.models.users import User

# ── RBAC provisioning for fixture-created accounts ───────────────────────────────────
#
# After the RBAC-8 cutover an account holds only what its ``rbac_user_roles`` rows grant.
# Production gets those rows from the cutover's reconciliation (``scripts/rbac/cutover.py``,
# the golden legacy-role → system-role mapping); the application itself assigns them when
# it creates an account. The suite's fixtures create ``User`` rows directly with a
# ``role_id``, so this listener does for them what the reconciliation does for a
# production account — the same mapping, nothing else — and keeps the assignment in step
# when a test changes ``role_id``. It is test-only and is the *only* place the suite maps a
# legacy role to RBAC.
from sqlalchemy import event as _sa_event
from sqlalchemy import inspect as _sa_inspect


def _golden_role_scopes() -> dict:
    from ccure_platform.rbac import legacy_map

    return {
        r["legacy_role"]: (r["role_key"], r["assignable_scope"])
        for r in legacy_map.load_golden()["roles"]
    }


_GOLDEN_ROLES = _golden_role_scopes()


_GOLDEN_ATOM_KEYS = None


def _atom_keys() -> dict:
    global _GOLDEN_ATOM_KEYS
    if _GOLDEN_ATOM_KEYS is None:
        from ccure_platform.rbac import legacy_map

        _GOLDEN_ATOM_KEYS = {
            a["atom"]: tuple(a["new_keys"]) for a in legacy_map.load_golden()["atoms"]
        }
    return _GOLDEN_ATOM_KEYS


def _legacy_role_keys(connection, role_id) -> frozenset:
    """The RBAC keys the golden mapping gives the atoms a legacy role holds."""
    atoms = connection.execute(
        text(
            "SELECT p.resource || ':' || p.action FROM role_permissions rp "
            "JOIN permissions p ON p.id = rp.permission_id WHERE rp.role_id = :r"
        ),
        {"r": role_id},
    ).scalars()
    table = _atom_keys()
    return frozenset(k for a in atoms for k in table.get(a, ()))


def _keyset_role_id(connection, keys: frozenset):
    """A platform custom role holding exactly ``keys`` (created once, by key)."""
    import hashlib

    from sqlalchemy.orm import Session

    key = (
        "custom.platform.legacytest_"
        + hashlib.sha1(",".join(sorted(keys)).encode()).hexdigest()[:16]
    )
    found = connection.execute(
        text("SELECT id FROM rbac_roles WHERE key = :k"), {"k": key}
    ).scalar()
    if found is not None:
        return found
    from ccure_platform.rbac.model import RbacRole, append_revision
    from rbac_testing import grant

    session = Session(bind=connection, expire_on_commit=False)
    row = RbacRole(
        key=key,
        display_name="Legacy test " + key[-8:],
        kind="custom",
        assignable_scope="platform",
        managed_by="admin",
    )
    session.add(row)
    session.flush()
    append_revision(session, row, "created")
    grant(session, row, *sorted(keys))
    return row.id


def _insert_assignment(connection, user, role_id, scope, org):
    connection.execute(
        text(
            "INSERT INTO rbac_user_roles "
            "(id, user_id, role_id, scope_type, scope_org_id, granted_by) "
            "SELECT gen_random_uuid(), :u, r.id, :s, :o, 'test:legacy-reconciliation' "
            "FROM rbac_roles r WHERE r.id = :r AND r.state = 'active' "
            "AND NOT EXISTS (SELECT 1 FROM rbac_user_roles x WHERE x.user_id = :u "
            "AND x.role_id = r.id AND x.revoked_at IS NULL)"
        ),
        {"u": user.id, "s": scope, "o": org, "r": role_id},
    )


def _assign_from_legacy_role(connection, user) -> None:
    if user.role_id is None or connection.info.get("rbac_no_provision"):
        return
    name = connection.execute(
        text("SELECT name FROM roles WHERE id = :i"), {"i": user.role_id}
    ).scalar()
    mapped = _GOLDEN_ROLES.get(name)
    held: set = set()
    if mapped is not None:
        key, scope = mapped
        connection.execute(
            text(
                "INSERT INTO rbac_user_roles "
                "(id, user_id, role_id, scope_type, scope_org_id, granted_by) "
                "SELECT gen_random_uuid(), :u, r.id, :s, :o, 'test:legacy-reconciliation' "
                "FROM rbac_roles r WHERE r.key = :k AND r.state = 'active' "
                "AND NOT EXISTS (SELECT 1 FROM rbac_user_roles x WHERE x.user_id = :u "
                "AND x.role_id = r.id AND x.revoked_at IS NULL)"
            ),
            {
                "u": user.id,
                "s": scope,
                "o": user.org_id if scope == "organization" else None,
                "k": key,
            },
        )
        held = set(
            connection.execute(
                text(
                    "SELECT rp.permission_key FROM rbac_role_permissions rp "
                    "JOIN rbac_roles r ON r.id = rp.role_id WHERE r.key = :k"
                ),
                {"k": key},
            ).scalars()
        )
    # atoms a test granted the legacy role beyond what its system role holds
    extra = _legacy_role_keys(connection, user.role_id) - held
    if extra:
        _insert_assignment(
            connection,
            user,
            _keyset_role_id(connection, frozenset(extra)),
            "platform",
            None,
        )


def _revoke_test_assignments(connection, user_id) -> None:
    connection.execute(
        text(
            "UPDATE rbac_user_roles SET revoked_at = now(), revoke_reason = 'migrated' "
            "WHERE user_id = :u AND revoked_at IS NULL "
            "AND granted_by = 'test:legacy-reconciliation'"
        ),
        {"u": user_id},
    )


@_sa_event.listens_for(RolePermission, "after_insert")
def _reprovision_on_legacy_grant(mapper, connection, target):
    if connection.info.get("rbac_no_provision"):
        return
    users = connection.execute(
        text("SELECT id, org_id, role_id FROM users WHERE role_id = :r"),
        {"r": target.role_id},
    ).all()
    for uid, org_id, role_id in users:
        _revoke_test_assignments(connection, uid)
        _assign_from_legacy_role(
            connection,
            type("U", (), {"id": uid, "org_id": org_id, "role_id": role_id})(),
        )


@_sa_event.listens_for(User, "after_insert")
def _provision_rbac_on_insert(mapper, connection, target):
    _assign_from_legacy_role(connection, target)


@_sa_event.listens_for(User, "after_update")
def _provision_rbac_on_role_change(mapper, connection, target):
    if connection.info.get("rbac_no_provision"):
        return
    if not _sa_inspect(target).attrs.role_id.history.has_changes():
        return
    connection.execute(
        text(
            "UPDATE rbac_user_roles SET revoked_at = now(), revoke_reason = 'migrated' "
            "WHERE user_id = :u AND revoked_at IS NULL "
            "AND granted_by = 'test:legacy-reconciliation'"
        ),
        {"u": target.id},
    )
    _assign_from_legacy_role(connection, target)


from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session

# ── Additional SQLite Hack: @compiles ───────────────────────────────────────


@compiles(UUID, "sqlite")
def compile_uuid(element, compiler, **kw):
    return "VARCHAR(36)"


@compiles(JSONB, "sqlite")
def compile_jsonb(element, compiler, **kw):
    return "JSON"


@compiles(INET, "sqlite")
def compile_inet(element, compiler, **kw):
    return "VARCHAR(45)"


@compiles(MACADDR, "sqlite")
def compile_macaddr(element, compiler, **kw):
    return "VARCHAR(17)"


@compiles(CIDR, "sqlite")
def compile_cidr(element, compiler, **kw):
    return "VARCHAR(45)"


from sqlalchemy.types import BigInteger, SmallInteger


@compiles(SmallInteger, "sqlite")
def compile_smallint(element, compiler, **kw):
    return "INTEGER"


@compiles(BigInteger, "sqlite")
def compile_bigint(element, compiler, **kw):
    return "INTEGER"


# Patch UUID bind_processor to handle string UUIDs gracefully in SQLite
original_bind_processor = UUID.bind_processor


def custom_bind_processor(self, dialect):
    if dialect.name == "sqlite":

        def process(value):
            if value is not None:
                return str(value)
            return value

        return process
    return original_bind_processor(self, dialect)


UUID.bind_processor = custom_bind_processor

# ── Database Setup ────────────────────────────────────────────────────────────


#: True when this session built the schema straight from the models. A drift
#: check is meaningless in that case — the database was *defined* by the models
#: moments earlier, so any comparison is guaranteed to agree. Only the
#: incremental path (migrations applied to a pre-existing database) can reveal a
#: model change that no migration accounts for.
SCHEMA_WAS_BOOTSTRAPPED = False


def _build_test_schema():
    """
    Bring the test database's schema into agreement with the models.

    The problem this solves: ``Base.metadata.create_all()`` silently skips
    tables that already exist. Because the pytest database persists between
    runs, any column change left it stale, producing ``UndefinedColumn`` errors
    that read like application bugs. A renamed column cost a debugging session
    exactly that way.

    Why this does not simply run ``alembic upgrade heads`` on an empty database:
    revision ``7f96fc2fa41a_initial_schema`` is an intentional no-op baseline
    adopted over an already-existing schema, and no migration creates the core
    tables. From empty, ``upgrade heads`` therefore creates nothing and the first
    incremental revision fails on ``ALTER TABLE organizations``. The models are
    the only complete description of the schema, so a bootstrap builds from
    them and stamps Alembic to match.

    Once bootstrapped, a database stamped *behind* the heads is upgraded normally —
    which does exercise newly added migrations, against a populated schema,
    which is the same path a real deployment takes.
    """
    global SCHEMA_WAS_BOOTSTRAPPED

    from alembic import command
    from alembic.config import Config
    from alembic.runtime.migration import MigrationContext
    from alembic.script import ScriptDirectory
    from sqlalchemy import inspect

    from ccure_platform.modules import registry as module_registry

    backend_dir = Path(__file__).absolute().parents[1]
    cfg = Config(str(backend_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend_dir / "alembic"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    # Phase 11.3: a history with a branch per core module has several heads.
    # get_current_head() and get_current_revision() raise once there is more
    # than one, so both sides are compared as sets.
    heads = set(ScriptDirectory.from_config(cfg).get_heads())
    module_schemas = [
        m.db_schema for m in module_registry.modules() if m.db_schema != "public"
    ]

    with engine.connect() as conn:
        inspector = inspect(conn)
        table_count = len(inspector.get_table_names())
        current = set(MigrationContext.configure(conn).get_current_heads())

    forced = os.getenv("PYTEST_REBUILD_SCHEMA") == "1"
    bootstrap = forced or not current

    if bootstrap:
        logger.info(
            "Bootstrapping test schema from models (%d existing tables dropped)",
            table_count,
        )
        with engine.begin() as conn:
            conn.execute(text("DROP SCHEMA public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
            # The core modules' schemas (Phase 11.3) are rebuilt with public:
            # `stamp heads` below records their branches as applied, so the
            # schemas those branches create must exist, and must be empty.
            for schema in module_schemas:
                conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
                conn.execute(text(f'CREATE SCHEMA "{schema}"'))

        # Dropping the schema also drops pg_trgm, pgcrypto and uuid-ossp, which
        # live in it — without them create_all fails on the trigram index over
        # vulnerability_definitions.title. db/base.py recreates all three from a
        # "connect" event listener, so disposing the pool forces a fresh
        # connection and lets that listener stay the single source of truth
        # rather than duplicating the list here.
        engine.dispose()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))

        with engine.begin() as conn:
            Base.metadata.create_all(bind=conn)
            for md in (
                md
                for m in module_registry.modules()
                for md in module_registry.module_metadatas(m)
            ):
                md.create_all(bind=conn)
        command.stamp(cfg, "heads")
        SCHEMA_WAS_BOOTSTRAPPED = True
        return

    if current != heads:
        logger.info(
            "Applying migrations %s -> %s to test schema",
            sorted(current),
            sorted(heads),
        )
        command.upgrade(cfg, "heads")

    # Gap-fill: models added without a migration still need their tables. Any
    # table created here is a missing migration and is reported as such.
    with engine.connect() as conn:
        before = set(inspect(conn).get_table_names())
    with engine.begin() as conn:
        Base.metadata.create_all(bind=conn)
    with engine.connect() as conn:
        added = sorted(set(inspect(conn).get_table_names()) - before)
    if added:
        logger.warning(
            "Tables created from models with no migration backing them: %s",
            ", ".join(added),
        )


@pytest.fixture(scope="session", autouse=True)
def seed_system_roles():
    """Seed system roles once per test session to guarantee they exist."""
    from db.migrate_production_schema import create_partitions, seed_rbac

    # The guards above vet DATABASE_URL when this file loads, but test modules
    # are imported *afterwards*, during collection, and a module-level
    # `os.environ["DATABASE_URL"] = ...` silently replaces the vetted value.
    # alembic/env.py reads the environment, not the Config handed to it, so
    # `_build_test_schema`'s stamp then writes to whatever that module named.
    # tests/topology/test_topology_client.py named `ccure_test` — the live
    # database's name on the Windows deployment — and CI only escaped because
    # its own throwaway server happened to answer at that address. Checked
    # here, before anything touches a database, so it fails every test loudly
    # rather than migrating the wrong one.
    if os.environ.get("DATABASE_URL") != database_url:
        raise RuntimeError(
            f"DATABASE_URL was changed after conftest vetted it: it now names "
            f"'{_db_name(os.environ.get('DATABASE_URL') or '')}' instead of "
            f"'{_db_name(database_url)}'. A test module assigns it at import "
            f"time; find it with: grep -rn 'DATABASE_URL' tests/"
        )

    _build_test_schema()

    with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            # The theme list lives in exactly one place —
            # `db.models.compliance.CONTROL_THEMES` — and is imported here
            # rather than copied.
            #
            # It used to be a fourth hardcoded copy (model, the table's own
            # migration, every framework migration, and this file), and this
            # copy silently won: it rewrites the constraint on every session,
            # so a theme added to the model and its migration was still
            # rejected by the test database and nothing said why.
            from db.models.compliance import CONTROL_THEME_SQL

            conn.execute(
                text(
                    "ALTER TABLE compliance_controls DROP CONSTRAINT IF EXISTS ck_control_theme;"
                )
            )
            conn.execute(
                text(
                    f"ALTER TABLE compliance_controls ADD CONSTRAINT ck_control_theme CHECK ({CONTROL_THEME_SQL});"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE compliance_scores DROP CONSTRAINT IF EXISTS ck_score_theme;"
                )
            )
            conn.execute(
                text(
                    f"ALTER TABLE compliance_scores ADD CONSTRAINT ck_score_theme CHECK ({CONTROL_THEME_SQL});"
                )
            )
        create_partitions(conn)
        seed_rbac(conn)

        # audit_logs' append-only enforcement is triggers and grants, which
        # SQLAlchemy metadata cannot express — so the create_all bootstrap
        # above does not produce it, and `alembic stamp heads` means the
        # migration that would never runs. Applying it here is what lets
        # tests/audit/test_audit_immutability.py actually exercise the
        # controls instead of skipping. It must come *after* create_partitions:
        # the TRUNCATE triggers are installed per partition, so partitions
        # have to exist first.
        from db.audit_hardening import apply_audit_immutability

        apply_audit_immutability(conn)

    # RBAC-8: the Platform RBAC catalogue and the five system roles are the only
    # authorization model, so they are reference data like the legacy roles were. Applied
    # once per session; the per-test purge leaves them (and removes the assignments).
    from sqlalchemy.orm import Session as _RbacSeedSession

    with _RbacSeedSession(engine) as _rbac_seed:
        from ccure_platform import composition as _composition
        from ccure_platform.rbac.catalogue import ensure_system_roles, sync

        sync(_rbac_seed, _composition.load_permission_sources(), audit=False)
        ensure_system_roles(_rbac_seed)
        _rbac_seed.commit()

    # Clear anything a previously crashed run left behind, *before* the app
    # starts. The baseline is whatever exists once the app has seeded itself, so
    # a stale organisation surviving into that snapshot would be recorded as
    # reference data and never cleaned up again.
    with engine.begin() as conn:
        # See _purge_test_data: DELETE, not TRUNCATE — audit_logs refuses
        # TRUNCATE and cascading into it would destroy the trail.
        conn.execute(text("DELETE FROM rbac_user_roles"))
        conn.execute(text("DELETE FROM organizations"))
        conn.execute(text("DELETE FROM users"))


#: Domains the test suite registers with. `test.com` alone accounts for 106
#: registrations across the auth, admin, RBAC and tenant-isolation suites.
_TEST_ALLOW_DOMAINS = (
    "test.com",
    "example.com",
    "testorg.com",
    "ccurepro.com",
    "b.test",
    "nowhere.test",
    "acme.com",
)

#: A deliberately tiny corpus. The production snapshot has 75,170 entries and
#: loading it here would make every session slower for no extra coverage — the
#: guard's behaviour depends on whether a domain is in the set, not how large
#: the set is.
_TEST_DISPOSABLE_DOMAINS = (
    "mailinator.com",
    "hutdot.com",
    "temp-mail.org",
    "guerrillamail.com",
    "10minutemail.com",
    # Present in BOTH lists on purpose. `test.com` really is on a published
    # disposable blocklist, so the whole suite depends on ALLOW beating the
    # corpus — this keeps that precedence continuously proven rather than
    # assumed, and reproduces production, where a false-positive listing is
    # exactly what the allow rule exists to override.
    "test.com",
)


@pytest.fixture(scope="session", autouse=True)
def seed_email_domain_rules(seed_system_roles):
    """
    Give the email domain guard a deterministic rule set for the whole session.

    Without this the suite fails wholesale the moment enforcement is on:
    `test.com` is on a real maintained blocklist, and 106 registrations across
    four suites use it. That is not a reason to weaken the guard — it is why the
    ALLOW override exists, and seeding it here is what a real deployment does
    for its own domains.
    """
    from db.models.email_security import (
        VERDICT_ALLOW,
        DisposableDomain,
        EmailDomainRule,
        seed_domain_rules,
    )

    with engine.begin() as conn:
        # The shipped floor (gmail, outlook, …) plus this suite's own domains.
        seed_domain_rules(conn)

        existing = {
            row[0]
            for row in conn.execute(text("SELECT domain FROM email_domain_rules"))
        }
        rows = [
            {
                "domain": domain,
                "verdict": VERDICT_ALLOW,
                "source": "seed",
                "reason": "pytest fixture domain",
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            }
            for domain in _TEST_ALLOW_DOMAINS
            if domain not in existing
        ]
        if rows:
            conn.execute(EmailDomainRule.__table__.insert(), rows)

        present = {
            row[0]
            for row in conn.execute(text("SELECT domain FROM disposable_domains"))
        }
        corpus = [
            {
                "domain": domain,
                "sources": ["pytest"],
                "first_seen_at": datetime.now(timezone.utc),
                "last_seen_at": datetime.now(timezone.utc),
                "miss_count": 0,
            }
            for domain in _TEST_DISPOSABLE_DOMAINS
            if domain not in present
        ]
        if corpus:
            conn.execute(DisposableDomain.__table__.insert(), corpus)

    # The guard caches the rule set per process on a TTL; the fixture has just
    # changed it underneath a cache that may already be warm.
    from auth.email_domain_guard import invalidate_cache

    invalidate_cache()
    yield


@pytest.fixture(scope="session", autouse=True)
def relax_registration_volume_limits():
    """
    Switch off the per-IP volume ceilings for the suite.

    Every request the suite makes arrives from one TestClient address, and
    these counters live in Redis with expiries measured in hours — so a ceiling
    is shared by every test that touches the endpoint *and* survives between
    runs. Left on, a later `pytest` of the same day starts returning 429 for
    tests that have nothing to do with rate limiting, which reads as a broken
    endpoint.

    Three of them now, and they fail the same way:

      * REGISTRATION_DAILY_IP_LIMIT — ~110 registrations across the auth,
        admin, RBAC and tenant-isolation suites, against a cap of 10.
      * PASSWORD_RESET_IP_HOURLY_LIMIT — counts *failed* reset submissions, and
        the reset suites deliberately submit bad tokens.
      * PASSWORD_RESET_ACCOUNT_HOURLY_LIMIT — keyed on the user id, which is
        derived from the org slug and username, so the fixtures rebuild the
        same id every run and inherit the previous run's count.

    Set directly rather than through monkeypatch because they have to hold for
    the whole session. A test that wants to exercise a ceiling patches
    `core.throttle.hit` for its own duration rather than putting a real number
    back — the counters are shared state and a real number leaks into whatever
    runs next.
    """
    from config import AppConfig

    previous = {
        name: getattr(AppConfig, name)
        for name in (
            "REGISTRATION_DAILY_IP_LIMIT",
            "PASSWORD_RESET_IP_HOURLY_LIMIT",
            "PASSWORD_RESET_ACCOUNT_HOURLY_LIMIT",
        )
    }
    for name in previous:
        setattr(AppConfig, name, 0)
    yield
    for name, value in previous.items():
        setattr(AppConfig, name, value)


@pytest.fixture(scope="session", autouse=True)
def pin_trusted_proxies_to_the_code_default():
    """
    Resolve client addresses against config.py's own TRUSTED_PROXIES default,
    whatever the process environment says.

    core/ip_resolver.py builds its trust list from the environment once, at
    import, and the suite runs inside the live api container, which inherits
    the deployment's value. Since Phase 10.7 that value is
    `127.0.0.1,::1,172.31.254.10` — the gateway only — and every test written
    against the code default (host nginx as 172.18.0.1) failed: sixteen of
    them, all correct. A test must not depend on how the machine it runs on is
    configured (the eager-mode test in CLAUDE.md is the same lesson).

    The default is read from config.py's source rather than restated here, so
    there is one list; tests that need a different trust list patch
    `core.ip_resolver._TRUSTED_NETWORKS` for their own duration.
    """
    import ipaddress
    import re

    from config import AppConfig
    from core import ip_resolver
    from testpaths import BACKEND_ROOT

    source = (BACKEND_ROOT / "config.py").read_text()
    default = re.search(r'os\.getenv\("TRUSTED_PROXIES", "([^"]+)"\)', source).group(1)
    entries = [e.strip() for e in default.split(",") if e.strip()]

    previous = (AppConfig.TRUSTED_PROXIES, ip_resolver._TRUSTED_NETWORKS)
    AppConfig.TRUSTED_PROXIES = entries
    ip_resolver._TRUSTED_NETWORKS = [ipaddress.ip_network(e) for e in entries]
    yield
    AppConfig.TRUSTED_PROXIES, ip_resolver._TRUSTED_NETWORKS = previous


@pytest.fixture(scope="session", autouse=True)
def session_client(seed_email_domain_rules) -> Generator[TestClient, None, None]:
    """
    One TestClient — and therefore one application startup — per session.

    Entering a TestClient runs the app's lifespan, which performs four additive
    schema checks (ensure_user_schema, ensure_scan_schema, ensure_topology_schema,
    ensure_mac_vendor_schema) and seeds the compliance catalog. That cost about
    ten seconds. The `client` fixture was function-scoped, so every test paid it
    — for tests whose own assertions ran in under a tenth of a second.

    Nothing in the suite depends on a per-test application instance: no test
    reads app.state and none manipulates dependency_overrides, which the
    function-scoped `client` fixture continues to set per test.

    base_url is https, not the default http://testserver
    ───────────────────────────────────────────────────
    The refresh cookie is issued with the Secure attribute (host Nginx
    terminates TLS and redirects 80 to 443). httpx correctly refuses to store a
    Secure cookie received over http, so with the default base_url every
    cookie-based flow silently lost its session — the refresh-after-org-
    reactivation test failed because `_resolve_refresh_token` found neither a
    body token nor a cookie.

    Overriding the scheme is the fix rather than relaxing the cookie flag: the
    suite should exercise the same cookie the deployment actually issues. It
    also means a future regression that drops the Secure attribute will not be
    masked here.
    """
    with TestClient(app, base_url="https://testserver") as test_client:
        # Lifespan has now seeded the default organisation and the compliance
        # catalog. Capture the organisations that exist at this point: they are
        # reference data and must survive the per-test reset.
        with engine.begin() as conn:
            _BASELINE_ORG_IDS.update(
                row[0] for row in conn.execute(text("SELECT id FROM organizations"))
            )
            # Frameworks are captured too. They hang off the baseline organisation,
            # so deleting test-created organisations does not reach the ones a
            # test creates directly — without this they accumulate across the
            # session and leak between tests.
            _BASELINE_FRAMEWORK_IDS.update(
                row[0]
                for row in conn.execute(text("SELECT id FROM compliance_frameworks"))
            )
            _BASELINE_CONTROL_IDS.update(
                row[0]
                for row in conn.execute(text("SELECT id FROM compliance_controls"))
            )
        logger.info(
            "Reference data seeded; preserving %d organisation(s), %d framework(s) "
            "and %d control(s) across resets",
            len(_BASELINE_ORG_IDS),
            len(_BASELINE_FRAMEWORK_IDS),
            len(_BASELINE_CONTROL_IDS),
        )
        yield test_client


#: Organisations that exist after session seeding. These are reference data, not
#: test data, and must survive the per-test reset — the compliance catalog hangs
#: off one of them.
_BASELINE_ORG_IDS: set[str] = set()

#: Compliance frameworks present after seeding. Same rationale as the orgs
#: above: these carry the ~800 seeded controls and must outlive a test, but a
#: framework a *test* creates must not.
_BASELINE_FRAMEWORK_IDS: set[str] = set()

#: Controls present after seeding. A test that adds a control to an *existing*
#: seeded framework (test_nerc_cip_framework_integration and
#: test_nis2_framework_integration both do) is reached by neither the
#: organisation delete nor the framework delete, so those rows accumulated
#: across the session. Harmless until something asserts a control count, at
#: which point it becomes an order-dependent failure.
_BASELINE_CONTROL_IDS: set[str] = set()

#: Roles seeded by seed_rbac(); anything else is test-created.
_SYSTEM_ROLES = ("superadmin", "org_admin", "analyst", "viewer", "scanner")


def _purge_test_data():
    """
    Remove test-created rows, leaving reference data in place.

    This used to be ``TRUNCATE TABLE organizations, users CASCADE``. That looks
    narrow but is not: ``compliance_frameworks.tenant_id`` references
    ``organizations`` with ON DELETE CASCADE, and ``compliance_controls``
    cascades from there in turn, so the statement reached 63 tables and wiped
    the ~800 seeded compliance controls on every single test. The application's
    startup then re-seeded all twelve frameworks the next time a test built a
    TestClient.

    Deleting only the organisations that tests created keeps the cascade doing
    the useful half of its job (removing that tenant's scans, assets, users and
    findings) while leaving the catalog intact.
    """
    with engine.begin() as conn:
        # RBAC assignments reference users and organisations with ON DELETE RESTRICT (the
        # protection that stops an account losing its role history by accident), so a
        # test's assignments go first. Roles, the catalogue and the role history stay.
        conn.execute(text("DELETE FROM rbac_user_roles"))
        if _BASELINE_ORG_IDS:
            # Cheap guard: the cascading DELETE touches 63 tables, so it is
            # worth one indexed count to skip it when a test created nothing.
            pending = conn.execute(
                text("SELECT 1 FROM organizations WHERE id <> ALL(:keep) LIMIT 1"),
                {"keep": list(_BASELINE_ORG_IDS)},
            ).scalar()
            if pending:
                conn.execute(
                    text("DELETE FROM organizations WHERE id <> ALL(:keep)"),
                    {"keep": list(_BASELINE_ORG_IDS)},
                )
        else:
            # No baseline captured (session fixtures did not run, e.g. a single
            # test invoked with --noconftest-style isolation) — fall back to the
            # old behaviour rather than silently leaving tenant data behind.
            # DELETE, not TRUNCATE. `audit_logs` carries an append-only
            # trigger (db/audit_hardening.py) and TRUNCATE is refused outright;
            # the organisation DELETE reaches audit rows through the org_id
            # ON DELETE CASCADE, which the trigger permits.
            conn.execute(text("DELETE FROM organizations"))

        # users has no seeded rows and cascades only to notifications,
        # password_reset_tokens and refresh_token_sessions.
        #
        # DELETE rather than TRUNCATE CASCADE, for two independent reasons.
        # `audit_logs.user_id` references `users`, so TRUNCATE CASCADE reached
        # audit_logs and emptied it — destroying, every single test, the rows
        # the audit suite had just written. And audit_logs now carries an
        # append-only trigger that refuses TRUNCATE outright, so the statement
        # would fail rather than merely do the wrong thing. A DELETE fires the
        # user_id foreign key's ON DELETE SET NULL instead, which is the one
        # UPDATE the trigger permits, and leaves the audit trail standing.
        if conn.execute(text("SELECT 1 FROM users LIMIT 1")).scalar():
            conn.execute(text("DELETE FROM users"))

        # Frameworks created by a test against the baseline organisation are not
        # reached by the organisation delete above, so they are removed here.
        # Their controls follow via ON DELETE CASCADE.
        if _BASELINE_FRAMEWORK_IDS:
            stray = conn.execute(
                text(
                    "SELECT 1 FROM compliance_frameworks "
                    "WHERE id <> ALL(:keep) LIMIT 1"
                ),
                {"keep": list(_BASELINE_FRAMEWORK_IDS)},
            ).scalar()
            if stray:
                conn.execute(
                    text("DELETE FROM compliance_frameworks WHERE id <> ALL(:keep)"),
                    {"keep": list(_BASELINE_FRAMEWORK_IDS)},
                )

        # Controls added to a framework that is itself baseline. Guarded by a
        # count rather than a scan over ~800 ids, so the common case (nothing
        # added) costs one aggregate. Their rule links follow via cascade.
        if _BASELINE_CONTROL_IDS:
            total = conn.execute(
                text("SELECT count(*) FROM compliance_controls")
            ).scalar()
            if total != len(_BASELINE_CONTROL_IDS):
                conn.execute(
                    text("DELETE FROM compliance_controls WHERE id <> ALL(:keep)"),
                    {"keep": list(_BASELINE_CONTROL_IDS)},
                )

        conn.execute(
            text("DELETE FROM roles WHERE name <> ALL(:system_roles)"),
            {"system_roles": list(_SYSTEM_ROLES)},
        )

        _purge_synthetic_catalogue_rows(conn)


#: The identifier prefix every test-created vulnerability-catalogue row must
#: use. Year 9999 cannot belong to a published CVE, so the pattern can never
#: match a real advisory and the cleanup below can never delete feed data.
#:
#: Tests mint ids under this prefix rather than a plausible one **and the rows
#: are removed after every test**, because until now neither was true and the
#: catalogue was the one table the purge did not reach. Findings are cascaded
#: away with their organisation; the ``vulnerability_definitions`` rows those
#: findings pointed at simply stayed, run after run, forever.
#:
#: On the live application database that produced 24 permanent rows titled
#: "Test vulnerability" and "Package CVE", dated between 2026-06-19 and
#: 2026-08-10 — the last of them on the day of the incident recorded in
#: CLAUDE.md, when a full-suite run inherited the API container's
#: ``DATABASE_URL``. The three database-name guards above stop that recurring;
#: this stops a run leaving catalogue residue behind *at all*, on whatever
#: database it reaches.
SYNTHETIC_CVE_PREFIX = "CVE-9999-"
_SYNTHETIC_CVE_LIKE = SYNTHETIC_CVE_PREFIX + "%"


def _purge_synthetic_catalogue_rows(conn) -> None:
    """
    Remove catalogue rows a test created, and any findings still pointing at
    them.

    Findings go first and this is not optional: ``asset_vulnerabilities.vuln_id``
    references ``vulnerability_definitions.id`` **ON DELETE RESTRICT**, so a
    finding created under a *baseline* organisation — which the organisation
    purge above deliberately does not delete — would make the catalogue delete
    raise instead of clean up.

    Both statements are keyed on an indexed prefix of a primary key, so the
    common case (a test created nothing) costs two index probes.
    """
    conn.execute(
        text("DELETE FROM asset_vulnerabilities WHERE vuln_id LIKE :p"),
        {"p": _SYNTHETIC_CVE_LIKE},
    )
    conn.execute(
        text("DELETE FROM vulnerability_definitions WHERE id LIKE :p"),
        {"p": _SYNTHETIC_CVE_LIKE},
    )


@pytest.fixture(scope="function", autouse=True)
def reset_database(session_client):
    """
    Purge test-created data after each test.

    This used to purge before *and* after every test, paying for the same
    cleanup twice. Teardown runs even when a test fails, so the post-test purge
    is what provides isolation; the pre-test purge only covered a previous
    process dying mid-test, which is a once-per-session concern and is handled
    when the session's baseline is established.
    """
    yield
    _purge_test_data()


@pytest.fixture(scope="function")
def db_session() -> Generator[Session, None, None]:
    """Provide a real database session for each test."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="function")
def activate_frameworks(monkeypatch):
    """Temporarily offer a parked framework, for one test.

    Eleven of the thirteen seeded catalogues are parked while ISO 27001 and
    NIST CSF are finished (`core.compliance_frameworks`), and the compliance
    routes answer 403 for them. Their integration suites still have to run —
    a parked framework should not be allowed to rot — so each one activates
    itself explicitly here rather than the whole session being switched to
    "everything on", which would mean nothing ever exercised the parked path.

    The active list is read per call from the environment, so `monkeypatch`
    reaches it and unwinds automatically at the end of the test.
    """
    from core.compliance_frameworks import DEFAULT_ACTIVE_FRAMEWORK_IDS

    def _activate(*framework_ids: str) -> tuple:
        ids = list(DEFAULT_ACTIVE_FRAMEWORK_IDS)
        ids += [f for f in framework_ids if f not in ids]
        monkeypatch.setenv("COMPLIANCE_ACTIVE_FRAMEWORKS", ",".join(ids))
        return tuple(ids)

    return _activate


@pytest.fixture(scope="function")
def client(
    session_client: TestClient, db_session: Session
) -> Generator[TestClient, None, None]:
    """
    The session's TestClient, with get_db pointed at this test's session.

    The client is shared; the dependency override is not. Overrides are applied
    and cleared per test exactly as before, so each test still talks to its own
    database session — only the application startup is now shared.
    """

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    yield session_client
    app.dependency_overrides.clear()


# ── Data Fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture(scope="function")
def test_org(db_session: Session) -> Organization:
    import uuid

    uid = uuid.uuid4().hex[:8]
    org = Organization(
        id=f"org_{uid}",
        name=f"Test Org {uid}",
        slug=f"test-org-{uid}",
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)
    return org


@pytest.fixture(scope="session", autouse=True)
def block_outbound_smtp():
    """
    Make it impossible for the test suite to send real email.

    The broker is already redirected to a scratch Redis database, so queued mail
    goes nowhere. This is the second layer, for anything that sends
    synchronously — and under CI that is the *normal* path, not an accident:
    conftest setdefault()s CELERY_TASK_ALWAYS_EAGER to "true", so `.delay()`
    executes the task in-process and any test that does not patch the sender
    reaches smtplib for real.

    A no-op, not a raiser
    ─────────────────────
    This first raised AssertionError to make an accidental send loud. That was
    wrong once the mail tasks gained `autoretry_for=(Exception,)`: in eager mode
    the exception propagated into Celery's retry machinery, which retried five
    times and then logged

        MAIL PERMANENTLY UNDELIVERED after 5 retries: ... error=The test suite
        attempted a real SMTP connection

    on a run where nothing was actually wrong. That is alarming noise in a CI
    log, it exercises the retry path pointlessly on every affected test, and it
    turns a legitimate code path into a failure.

    Substituting a no-op keeps the property that actually matters — no message
    leaves this machine — while letting eager tasks complete as they would in
    production. Sends are recorded on the class so a test can assert on them if
    one ever needs to.
    """
    import smtplib

    class _NullSMTP:
        """Accepts the smtplib API and does nothing with it."""

        sent = []

        def __init__(self, *args, **kwargs):
            self._host = args[0] if args else kwargs.get("host", "")

        def ehlo(self, *a, **k):
            return (250, b"OK")

        def has_extn(self, *a, **k):
            return False

        def starttls(self, *a, **k):
            return (220, b"OK")

        def login(self, *a, **k):
            return (235, b"OK")

        def sendmail(self, from_addr, to_addrs, msg, *a, **k):
            _NullSMTP.sent.append((from_addr, to_addrs))
            return {}

        def send_message(self, msg, *a, **k):
            _NullSMTP.sent.append((msg.get("From"), msg.get("To")))
            return {}

        def quit(self, *a, **k):
            return (221, b"OK")

        def close(self, *a, **k):
            return None

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    original_smtp, original_ssl = smtplib.SMTP, smtplib.SMTP_SSL
    smtplib.SMTP, smtplib.SMTP_SSL = _NullSMTP, _NullSMTP
    try:
        yield _NullSMTP
    finally:
        smtplib.SMTP, smtplib.SMTP_SSL = original_smtp, original_ssl


@pytest.fixture(scope="function")
def self_registration_enabled(monkeypatch):
    """
    Turn on POST /auth/register for one test.

    The feature ships off, so any test exercising self-service signup has to
    opt in. Keeping the default off in tests too means a test cannot silently
    depend on production having it enabled.
    """
    from config import AppConfig

    monkeypatch.setattr(AppConfig, "ALLOW_SELF_REGISTRATION", True)
    yield


@pytest.fixture(scope="function")
def test_role_admin(db_session: Session) -> Role:
    return db_session.query(Role).filter(Role.name == "org_admin").first()


@pytest.fixture(scope="function")
def test_role_viewer(db_session: Session) -> Role:
    return db_session.query(Role).filter(Role.name == "viewer").first()


@pytest.fixture(scope="function")
def test_user(
    db_session: Session, test_org: Organization, test_role_admin: Role
) -> User:
    """
    A standard authenticated user with admin rights.

    Verified *and* approved, because that is what an admin-provisioned account
    looks like and this fixture stands in for one. Login refuses accounts with
    approved_at IS NULL; a fixture that omitted it would test the pending-user
    path in every suite that just wants a logged-in user.
    """
    from db.base import gen_user_id, utcnow

    user = User(
        id=gen_user_id(test_org.slug, "testadmin"),
        username="testadmin",
        email="admin@test.com",
        full_name="Test Admin",
        password_hash=hash_password("securepassword123"),
        org_id=test_org.id,
        role_id=test_role_admin.id,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
        approved_by="fixture",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="function")
def auth_headers(client: TestClient, test_user: User) -> dict:
    """Returns headers containing a valid JWT for the test_user."""
    response = client.post(
        "/auth/login", json={"email": "admin@test.com", "password": "securepassword123"}
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="function", autouse=True)
def isolate_compliance_evidence_dir(tmp_path, monkeypatch):
    """
    Point evidence storage at a per-test temporary directory.

    ``routers.compliance._evidence_root()`` defaults to
    ``/app/data/compliance_evidence``, and ``/app`` is the API container's bind
    mount of ``./Backend``. Two consequences, both wrong for a test run: an
    upload test drops real evidence files into the working tree, and on a host
    where ``/app`` does not exist the endpoint tries to create it **at the
    filesystem root**.

    That second one is why this is autouse rather than a fixture each upload
    test opts into. Creating ``/app`` succeeds for root and raises
    ``PermissionError`` for anyone else, so the same test passes in a container
    running as root and fails on a CI runner running as an ordinary user —
    ``tests/audit/test_audit_compliance_status.py`` failed on GitHub for
    exactly this reason while passing locally. A per-file opt-in leaves the
    next upload test one forgotten fixture away from the same split.

    The root is re-read from the environment on every call, so setting the
    variable is sufficient; nothing needs patching at import time.
    """
    monkeypatch.setenv("COMPLIANCE_EVIDENCE_DIR", str(tmp_path / "compliance_evidence"))


@pytest.fixture(scope="function", autouse=True)
def detect_process_leaks():
    """Autouse fixture that checks for orphaned child processes (e.g. nmap, nuclei) after each test."""
    try:
        import psutil
    except ImportError:
        # Fallback if psutil is not installed locally
        yield
        return

    current_proc = psutil.Process()
    # Collect existing child processes before test run
    before_children = set(current_proc.children(recursive=True))

    yield

    # Collect children after test run
    after_children = set(current_proc.children(recursive=True))
    new_orphans = after_children - before_children

    if new_orphans:
        leak_details = []
        for proc in new_orphans:
            try:
                name = proc.name()
                pid = proc.pid
                leak_details.append(f"{name} (PID {pid})")
                proc.terminate()
            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.Error,
            ) as proc_err:
                logger.debug("Could not terminate process %s: %s", proc, proc_err)
        # Fail the test if orphaned processes are detected
        assert (
            False
        ), f"Resource Leak: Active subprocesses left running: {', '.join(leak_details)}"


#: The genuine ``SSHScanner.connect``, kept aside whenever the session-wide
#: mock below replaces it. A test whose subject *is* what connect() does with
#: key material needs the real function, and CI sets MOCK_SCANNERS=true — so
#: without a way back to it those tests pass on a developer's machine and fail
#: only in CI, which is the one place nobody can step through them.
#: ``real_ssh_connect`` is how a test asks for it.
_REAL_SSH_CONNECT = None


@pytest.fixture(scope="session", autouse=True)
def global_scanner_mocking():
    """Globally mocks scanners if MOCK_SCANNERS=true is set in the environment."""
    if os.getenv("MOCK_SCANNERS") == "true":
        from unittest.mock import MagicMock, patch

        from engines.credentialed.ssh_scanner import SSHScanner

        global _REAL_SSH_CONNECT
        _REAL_SSH_CONNECT = SSHScanner.connect

        # Mock SSH connections
        ssh_patcher = patch(
            "engines.credentialed.ssh_scanner.SSHScanner.connect", return_value=True
        )
        ssh_patcher.start()

        # Mock Nmap executable dependency check/command runner
        nmap_mock = MagicMock()
        nmap_mock.scan.return_value = {"nmap": {"scanstats": {"uphosts": "1"}}}
        nmap_patcher = patch("nmap.PortScanner", return_value=nmap_mock)
        nmap_patcher.start()

        yield

        ssh_patcher.stop()
        nmap_patcher.stop()
    else:
        yield


@pytest.fixture
def real_ssh_connect():
    """
    Give one test back the real ``SSHScanner.connect``.

    ``global_scanner_mocking`` replaces it with a stub returning True for the
    whole session, which is right for the tests that merely need a session to
    exist and wrong for the handful whose assertion is that connect() *raises*
    — on a key it cannot parse, or a passphrase that does not fit. Against the
    stub those never raise, so they fail with DID NOT RAISE under exactly the
    MOCK_SCANNERS=true that CI passes and nowhere else.

    A no-op when the mock is not installed, so a test using it behaves the same
    whether or not MOCK_SCANNERS is set. That is the point: a test must not
    depend on how the machine running it is configured.
    """
    if _REAL_SSH_CONNECT is None:
        yield
        return

    from engines.credentialed.ssh_scanner import SSHScanner

    stub = SSHScanner.connect
    SSHScanner.connect = _REAL_SSH_CONNECT
    try:
        yield
    finally:
        SSHScanner.connect = stub
