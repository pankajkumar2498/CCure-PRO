"""
Helpers for the RBAC suites (``tests/rbac/``).

**Why this is a module and not a conftest.** ``test_schema_drift`` does
``import conftest`` and expects the suite's own; a second ``conftest.py`` would
replace it in ``sys.modules``. A test module imports the fixture it wants:

    from rbac_testing import rbac_db_fixture  # noqa: F401  (registers ``rbac_db``)

The fixture is *named* ``rbac_db`` (``@pytest.fixture(name=...)``) but exported
as ``rbac_db_fixture``, so importing it does not collide with the test
parameters of the same name (ruff F811).

**Why ``rbac_db`` never commits.** The rbac tables reference ``organizations`` and
``users`` with ``ON DELETE RESTRICT``, and two of them refuse deletes outright
(role history is append-only; roles are never deleted). The suite's per-test purge
deletes test organisations and users — which would fail, loudly and in unrelated
tests, if one of these tests left a row behind. So every RBAC test runs in a
transaction that is rolled back, and nothing it creates is ever committed.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from ccure_platform.rbac import contract as c
from ccure_platform.rbac.catalogue import ensure_system_roles, sync
from ccure_platform.rbac.model import (
    RbacPermission,
    RbacRole,
    RbacRolePermission,
    RbacUserRole,
    append_revision,
)


@pytest.fixture(name="rbac_db")
def rbac_db_fixture():
    """A session whose every write is rolled back at the end of the test."""
    from db.base import engine

    connection = engine.connect()
    outer = connection.begin()
    # The suite seeds the catalogue and system roles once per session (committed).
    # These tests exercise the seeding, sync and reconciliation themselves, so each
    # starts from an empty RBAC schema; TRUNCATE is transactional, so the rollback
    # below restores the seeded rows. The legacy-role provisioning listener in
    # conftest is switched off for this connection: a test grants what it needs.
    connection.info["rbac_no_provision"] = True
    names = [
        r[0]
        for r in connection.execute(
            text(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public' "
                "AND tablename LIKE 'rbac\\_%'"
            )
        )
    ]
    connection.execute(text("TRUNCATE " + ", ".join(names)))
    session = Session(
        bind=connection,
        join_transaction_mode="create_savepoint",
        expire_on_commit=False,
    )
    try:
        yield session
    finally:
        session.close()
        outer.rollback()
        # the flag lives on the pooled DBAPI connection: leave it clean for the next test
        connection.info.pop("rbac_no_provision", None)
        connection.close()


def uid() -> str:
    return uuid.uuid4().hex[:8]


def make_org(db: Session, tag: str | None = None):
    from db.models import Organization

    tag = tag or uid()
    org = Organization(
        id=f"org_{tag}",
        name=f"RBAC Test Org {tag}",
        slug=f"rbac-test-{tag}",
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    db.add(org)
    db.flush()
    return org


def make_user(
    db: Session,
    org,
    *,
    name: str | None = None,
    active: bool = True,
    verified: bool = True,
    approved: bool = True,
    deleted: bool = False,
):
    """A user in ``org`` holding no role at all: ``users.role_id`` is deprecated and
    non-authoritative (RBAC-8), and a test grants what it needs with ``assign``."""
    from db.base import gen_user_id, utcnow
    from db.models import User

    name = name or f"u{uid()}"
    user = User(
        id=gen_user_id(org.slug, name),
        username=name,
        email=f"{name}@rbac-test.example",
        full_name=name,
        password_hash="not-a-real-hash",
        org_id=org.id,
        is_active=active,
        is_deleted=deleted,
        is_verified=verified,
        approved_at=utcnow() if approved else None,
        approved_by="fixture" if approved else None,
    )
    db.add(user)
    db.flush()
    return user


def decl(key: str, scope_kind: str = "organization", **kw) -> c.PermissionDecl:
    kw.setdefault("description", f"Test permission {key}")
    if scope_kind == "platform":
        kw.setdefault("delegable_to_org_roles", False)
    return c.PermissionDecl(key=key, scope_kind=scope_kind, **kw)


def source(namespace: str, *decls: c.PermissionDecl, module_key: str | None = None):
    return c.ModuleDeclarations(
        module_key=module_key or namespace, namespace=namespace, permissions=decls
    )


def role(db: Session, key: str) -> RbacRole:
    ensure_system_roles(db)
    return db.query(RbacRole).filter(RbacRole.key == key).one()


def declare(db: Session, *sources: c.ModuleDeclarations):
    return sync(db, sources)


def grant(db: Session, role_row: RbacRole, *keys: str) -> None:
    for key in keys:
        db.add(RbacRolePermission(role_id=role_row.id, permission_key=key))
    db.flush()


def assign(
    db: Session,
    user,
    role_row: RbacRole,
    scope_type: str | None = None,
    org_id: str | None = None,
) -> RbacUserRole:
    scope_type = scope_type or role_row.assignable_scope
    if scope_type == "organization" and org_id is None:
        org_id = user.org_id
    row = RbacUserRole(
        user_id=user.id, role_id=role_row.id, scope_type=scope_type, scope_org_id=org_id
    )
    db.add(row)
    db.flush()
    return row


def custom_org_role(
    db: Session, org, slug: str, display_name: str, *keys: str
) -> RbacRole:
    row = RbacRole(
        key=f"custom.{org.id}.{slug}",
        display_name=display_name,
        kind="custom",
        assignable_scope="organization",
        org_id=org.id,
        managed_by="admin",
    )
    db.add(row)
    db.flush()
    append_revision(db, row, "created")
    grant(db, row, *keys)
    return row


def platform_custom_role(
    db: Session, slug: str, display_name: str, *keys: str
) -> RbacRole:
    row = RbacRole(
        key=f"custom.platform.{slug}",
        display_name=display_name,
        kind="custom",
        assignable_scope="platform",
        managed_by="admin",
    )
    db.add(row)
    db.flush()
    append_revision(db, row, "created")
    grant(db, row, *keys)
    return row


def force_state(db: Session, row: RbacRole, state: str) -> RbacRole:
    """Move a role to ``state`` directly, the way the database requires: the
    revision advances in the same statement, and ``retired_at`` follows the state.
    Tests that need a role in a state use this; ``governance.transition_role`` is
    the gated primitive and has its own tests."""
    from datetime import datetime, timezone

    row.state = state
    row.revision = int(row.revision) + 1
    row.retired_at = datetime.now(timezone.utc) if state == "retired" else None
    db.flush()
    return row


def permission_rows(db: Session) -> dict[str, RbacPermission]:
    return {p.key: p for p in db.query(RbacPermission).all()}


def system_role_id(db: Session, legacy_name: str) -> str:
    """The id of the RBAC system role the golden mapping names for a legacy role name —
    for tests that create accounts through the API (``rbac_role_id``)."""
    from ccure_platform.rbac import legacy_map

    key = legacy_map.system_role_key_for_legacy(legacy_name)
    return str(db.query(RbacRole).filter(RbacRole.key == key).one().id)
