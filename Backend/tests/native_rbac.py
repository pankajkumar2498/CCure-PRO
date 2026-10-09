"""Explicit native RBAC fixtures for application integration tests.

No account receives a role implicitly. Callers choose a seeded role by its
native key, or create a custom platform fixture role with specific grants.
"""

from uuid import uuid4

from ccure_platform.models.rbac_tables import RbacRole, RbacRolePermission, RbacUserRole
from db.models.users import User


def system_role(db, key):
    return db.query(RbacRole).filter_by(key=key, kind="system").one()


def fixture_role(db, label, *, keys=()):
    role = RbacRole(
        key=f"custom.platform.test_{uuid4().hex}",
        display_name=f"{label} {uuid4().hex[:8]}",
        kind="custom",
        assignable_scope="platform",
        managed_by="admin",
    )
    db.add(role)
    db.flush()
    grant_permissions(db, role, *keys)
    return role


def grant_permissions(db, role, *keys):
    for key in keys:
        if (
            db.query(RbacRolePermission)
            .filter_by(role_id=role.id, permission_key=key)
            .first()
            is None
        ):
            db.add(RbacRolePermission(role_id=role.id, permission_key=key))
    db.flush()


def assign_role(db, user, role):
    db.flush()
    scope = role.assignable_scope
    assignment = RbacUserRole(
        user_id=user.id,
        role_id=role.id,
        scope_type=scope,
        scope_org_id=user.org_id if scope == "organization" else None,
        granted_by="test:explicit-native-assignment",
    )
    db.add(assignment)
    db.flush()
    return assignment


def create_user(db, *, role=None, **fields):
    user = User(**fields)
    db.add(user)
    db.flush()
    if role is not None:
        assign_role(db, user, role)
    return user
