"""
ccure_platform/rbac/model.py — RBAC's persistence seat.

The tables are *defined* in ``ccure_platform/models/rbac_tables.py``, where every
platform model lives and where the ``models-are-leaves`` rule keeps them free of
application imports; they are registered with the rest of the platform's models
through ``ccure_platform.models``. This module re-exports them for RBAC's own code and adds the few
helpers every part of RBAC needs: turning a row into a plain-value view, hashing
a permission set, and appending a role revision.

**Nothing outside ``ccure_platform`` imports this module** (layer rule
``rbac-tables-are-private``). A module that wants to know what a user may do asks
``ccure_platform.api``; it never reads these tables.
"""

from __future__ import annotations

import hashlib
from typing import Iterable

from ccure_platform.models.rbac_tables import (  # noqa: F401  (re-exported)
    TRIGGER_FUNCTIONS,
    TRIGGER_SQL,
    RbacDefaultRole,
    RbacPermission,
    RbacRole,
    RbacRolePermission,
    RbacRoleRevision,
    RbacUserRole,
)
from ccure_platform.rbac import contract as c
from sqlalchemy import select
from sqlalchemy.orm import Session


def permission_set_hash(keys: Iterable[str]) -> str:
    """SHA-256 of the sorted, newline-joined permission keys. The empty set
    hashes to the digest of the empty string; a revision records which set a
    role held without storing the set again."""
    return hashlib.sha256("\n".join(sorted(set(keys))).encode("utf-8")).hexdigest()


def to_permission(row: RbacPermission) -> c.Permission:
    return c.Permission(
        key=row.key,
        module=row.module,
        resource=row.resource,
        action=row.action,
        description=row.description,
        scope_kind=row.scope_kind,
        sensitivity=row.sensitivity,
        delegable_to_org_roles=bool(row.delegable_to_org_roles),
        continuity=bool(row.continuity),
        status=row.status,
        replaced_by=row.replaced_by,
    )


def to_role(row: RbacRole) -> c.Role:
    return c.Role(
        id=str(row.id),
        key=row.key,
        display_name=row.display_name,
        kind=row.kind,
        assignable_scope=row.assignable_scope,
        org_id=row.org_id,
        managed_by=row.managed_by,
        state=row.state,
        auto_grant_new_permissions=bool(row.auto_grant_new_permissions),
        replaced_by_role_id=(
            str(row.replaced_by_role_id) if row.replaced_by_role_id else None
        ),
        revision=row.revision,
    )


def granted_keys(db: Session, role_id: str) -> frozenset[str]:
    """The permission keys a role holds, as rows — what the resolver reads."""
    return frozenset(
        db.execute(
            select(RbacRolePermission.permission_key).where(
                RbacRolePermission.role_id == role_id
            )
        ).scalars()
    )


def append_revision(
    db: Session,
    role: RbacRole,
    change_kind: str,
    *,
    changed_by: str | None = None,
    advance: bool = True,
) -> RbacRoleRevision:
    """
    Append the history row for ``role`` as it is now — display name,
    description, state and permission set. A ``created`` revision records the
    role's first revision (1); every other kind advances the role to its next.
    Call it after the change it records; it flushes so the row exists for
    whatever reads next in the same transaction.

    ``advance=False`` records the role's *current* revision without advancing it.
    A state change uses it: the database refuses a state change that does not
    advance the revision in the same statement (so a state change can never be
    silent), which means the caller advances the revision together with the
    state and only then records the row.
    """
    if change_kind not in c.REVISION_KINDS:
        raise ValueError(f"unknown revision kind {change_kind!r}")
    db.flush()  # make the grants and fields being recorded visible to the read
    if change_kind == "created" or not advance:
        revision = int(role.revision or 1)
    else:
        revision = int(role.revision) + 1
        role.revision = revision
    row = RbacRoleRevision(
        role_id=role.id,
        revision=revision,
        display_name=role.display_name,
        description=role.description,
        permission_set_hash=permission_set_hash(granted_keys(db, role.id)),
        state=role.state,
        change_kind=change_kind,
        changed_by=changed_by,
    )
    db.add(row)
    db.flush()
    return row
