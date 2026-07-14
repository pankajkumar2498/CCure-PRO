"""
tests/conftest.py
─────────────────────────────────────────────────────────────────────────────
Pytest configuration and global fixtures for the CCure Audit PRO backend.
Tests are expected to run against PostgreSQL and require DATABASE_URL to be set accordingly.
"""

import os
import pytest
from typing import Generator
from fastapi.testclient import TestClient
import sys
from pathlib import Path
from dotenv import load_dotenv

# ── Legacy SQLite Compatibility Helpers ───────────────────────────────────────
# These helpers remain available for older test code, but tests must run on PostgreSQL.
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET, MACADDR, CIDR
from sqlalchemy.types import String, JSON, SmallInteger, BigInteger, Integer
import sqlalchemy.dialects.sqlite.base as sqlite_base

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

# Load environment from Backend/.env.test if available BEFORE importing app
dotenv_path = Path(__file__).absolute().parents[1] / ".env.test"
if dotenv_path.exists():
    load_dotenv(dotenv_path=dotenv_path)

# Prevent config.py from loading .env and overriding our test settings
os.environ["SKIP_DOTENV_LOAD"] = "1"

# Run Celery tasks synchronously under pytest so Redis is not required locally
os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "true")
os.environ.setdefault("CELERY_TASK_EAGER_PROPAGATES", "true")

# Require PostgreSQL for pytest
database_url = os.getenv("DATABASE_URL")
if not database_url:
    # Set default local test database URL fallback for convenience
    database_url = "postgresql://ccure_user:ccure_admin_2026@127.0.0.1:5432/ccure_test"
    os.environ["DATABASE_URL"] = database_url

if not database_url.startswith("postgresql"):
    raise RuntimeError(
        "Tests must run against PostgreSQL. Set DATABASE_URL to a postgresql:// URL instead of sqlite:///."
    )

# Safety guard: refuse to run against production databases
from urllib.parse import urlparse

parsed = urlparse(database_url)
db_name = parsed.path.lstrip("/")
if db_name in ("ccure_db", "prod", "production"):
    raise RuntimeError(
        f"Refusing to run tests against production database '{db_name}'. "
        "Use a dedicated test database like 'ccure_test'."
    )
if "prod" in db_name.lower():
    raise RuntimeError(
        f"Refusing to run tests against database '{db_name}' containing 'prod'. "
        "Use a dedicated test database."
    )

os.environ["JWT_SECRET_KEY"] = "test-secret-key-do-not-use-in-prod"

from sqlalchemy.orm import Session
from main import app
from db.base import get_db, engine, Base, SessionLocal
from db.models.users import User
from db.models.rbac import Organization, Role
from auth.jwt_handler import hash_password
from sqlalchemy.ext.compiler import compiles

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


from sqlalchemy.types import SmallInteger, BigInteger


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


@pytest.fixture(scope="function", autouse=True)
def reset_database():
    """Clean up the database before and after each test to ensure isolation in PostgreSQL."""
    from sqlalchemy import text

    def _cleanup():
        with engine.begin() as conn:
            # Delete all organizations except the default one seeded in migrate_production_schema
            conn.execute(text("DELETE FROM organizations WHERE id != 'org_default'"))
            # Delete any extra users created during the test
            conn.execute(text("DELETE FROM users WHERE username != 'testadmin'"))
            # Delete any non-system roles created during the test
            conn.execute(
                text(
                    "DELETE FROM roles WHERE name NOT IN ('superadmin', 'org_admin', 'analyst', 'viewer', 'scanner')"
                )
            )

    # Clean up before the test (in case a previous run crashed and left dirty state)
    _cleanup()
    yield
    # Clean up after the test
    _cleanup()


@pytest.fixture(scope="function")
def db_session() -> Generator[Session, None, None]:
    """Provide a real database session for each test."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="function")
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """FastAPI TestClient that overrides the get_db dependency."""

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
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


@pytest.fixture(scope="function")
def test_role_admin(db_session: Session) -> Role:
    from sqlalchemy import text
    from db.base import utcnow

    existing = db_session.query(Role).filter(Role.id == 1).first()
    if existing:
        return existing

    db_session.execute(
        text(
            "INSERT INTO roles (id, name, description, is_system_role, created_at) VALUES (1, 'org_admin', 'Admin role', false, :now)"
        ),
        {"now": utcnow()},
    )
    db_session.commit()
    return db_session.query(Role).filter(Role.id == 1).first()


@pytest.fixture(scope="function")
def test_role_viewer(db_session: Session) -> Role:
    from sqlalchemy import text
    from db.base import utcnow

    existing = db_session.query(Role).filter(Role.id == 2).first()
    if existing:
        return existing

    db_session.execute(
        text(
            "INSERT INTO roles (id, name, description, is_system_role, created_at) VALUES (2, 'viewer', 'Viewer role', false, :now)"
        ),
        {"now": utcnow()},
    )
    db_session.commit()
    return db_session.query(Role).filter(Role.id == 2).first()


@pytest.fixture(scope="function")
def test_user(
    db_session: Session, test_org: Organization, test_role_admin: Role
) -> User:
    """A standard authenticated user with admin rights."""
    from db.base import gen_user_id

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
            except Exception:
                pass
        # Fail the test if orphaned processes are detected
        assert (
            False
        ), f"Resource Leak: Active subprocesses left running: {', '.join(leak_details)}"


@pytest.fixture(scope="session", autouse=True)
def global_scanner_mocking():
    """Globally mocks scanners if MOCK_SCANNERS=true is set in the environment."""
    if os.getenv("MOCK_SCANNERS") == "true":
        from unittest.mock import patch, MagicMock

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
