"""
tests/conftest.py
─────────────────────────────────────────────────────────────────────────────
Pytest configuration and global fixtures for the CCure Audit PRO backend.
Sets up an in-memory SQLite database, FastAPI TestClient, and mock users.
"""

import os
import pytest
from typing import Generator
from fastapi.testclient import TestClient
import sys
import os

# ── SQLite Compatibility Hacks ────────────────────────────────────────────────
# Make SQLite accept PostgreSQL-specific types without compile/bind errors.
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET, MACADDR, CIDR
from sqlalchemy.types import String, JSON, SmallInteger, BigInteger, Integer
import sqlalchemy.dialects.sqlite.base as sqlite_base

sqlite_base.SQLiteDialect.colspecs.update({
    UUID: String,
    JSONB: JSON,
    INET: String,
    MACADDR: String,
    CIDR: String,
    SmallInteger: Integer,
    BigInteger: Integer,
})

# Add Backend to PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Set test environment before importing the app
os.environ["DATABASE_URL"] = "sqlite:///test_db.sqlite"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-do-not-use-in-prod"

from sqlalchemy.orm import Session
from main import app
from db.base import get_db, engine, Base, SessionLocal
from db.models.users import User
from db.models.rbac import Organization, Role
from auth.jwt_handler import hash_password
from sqlalchemy.ext.compiler import compiles
# ── Additional SQLite Hack: @compiles ───────────────────────────────────────

@compiles(UUID, 'sqlite')
def compile_uuid(element, compiler, **kw):
    return "VARCHAR(36)"

@compiles(JSONB, 'sqlite')
def compile_jsonb(element, compiler, **kw):
    return "JSON"

@compiles(INET, 'sqlite')
def compile_inet(element, compiler, **kw):
    return "VARCHAR(45)"

@compiles(MACADDR, 'sqlite')
def compile_macaddr(element, compiler, **kw):
    return "VARCHAR(17)"

@compiles(CIDR, 'sqlite')
def compile_cidr(element, compiler, **kw):
    return "VARCHAR(45)"

from sqlalchemy.types import SmallInteger, BigInteger

@compiles(SmallInteger, 'sqlite')
def compile_smallint(element, compiler, **kw):
    return "INTEGER"

@compiles(BigInteger, 'sqlite')
def compile_bigint(element, compiler, **kw):
    return "INTEGER"

# Patch UUID bind_processor to handle string UUIDs gracefully in SQLite
original_bind_processor = UUID.bind_processor
def custom_bind_processor(self, dialect):
    if dialect.name == 'sqlite':
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
    """Drop and recreate all tables for each test to ensure isolation."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    
    # Seed required defaults for /auth/register
    from sqlalchemy.orm import Session
    from sqlalchemy import text
    from db.base import utcnow
    with Session(engine) as session:
        session.execute(text(
            "INSERT INTO organizations (id, name, slug, plan, max_assets, max_users, is_active, settings, created_at, updated_at) "
            "VALUES ('00000000-0000-0000-0000-000000000000', 'Default', 'default', 'community', 100, 10, 1, '{}', :now, :now)"
        ), {"now": utcnow()})
        session.execute(text(
            "INSERT INTO roles (id, name, description, is_system_role, created_at) "
            "VALUES (3, 'analyst', 'Analyst role', 0, :now)"
        ), {"now": utcnow()})
        session.commit()
    
    yield
    Base.metadata.drop_all(bind=engine)

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

from db.models.assets import Asset
from db.models.findings import Service, AssetVulnerability, VulnerabilityDefinition
from db.models.scans import Scan, ScanPhase

@pytest.fixture(scope="function")
def test_org(db_session: Session) -> Organization:
    org = Organization(name="Test Org", slug="test-org", max_assets=100, max_users=10, is_active=True)
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)
    return org


@pytest.fixture(scope="function")
def test_role_admin(db_session: Session) -> Role:
    from sqlalchemy import text
    from db.base import utcnow
    db_session.execute(text("INSERT INTO roles (id, name, description, is_system_role, created_at) VALUES (1, 'org_admin', 'Admin role', 0, :now)"), {"now": utcnow()})
    db_session.commit()
    return db_session.query(Role).filter(Role.id == 1).first()


@pytest.fixture(scope="function")
def test_role_viewer(db_session: Session) -> Role:
    from sqlalchemy import text
    from db.base import utcnow
    db_session.execute(text("INSERT INTO roles (id, name, description, is_system_role, created_at) VALUES (2, 'viewer', 'Viewer role', 0, :now)"), {"now": utcnow()})
    db_session.commit()
    return db_session.query(Role).filter(Role.id == 2).first()


@pytest.fixture(scope="function")
def test_user(db_session: Session, test_org: Organization, test_role_admin: Role) -> User:
    """A standard authenticated user with admin rights."""
    user = User(
        username="testadmin",
        email="admin@test.com",
        full_name="Test Admin",
        password_hash=hash_password("securepassword123"),
        org_id=test_org.id,
        role_id=test_role_admin.id,
        is_active=True,
        is_verified=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="function")
def auth_headers(client: TestClient, test_user: User) -> dict:
    """Returns headers containing a valid JWT for the test_user."""
    response = client.post(
        "/auth/login",
        json={"email": "admin@test.com", "password": "securepassword123"}
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
