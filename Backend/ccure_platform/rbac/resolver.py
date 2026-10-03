"""
ccure_platform/rbac/resolver.py — from rows to grants.

The one place a role's rows are walked. Given a principal it returns the
``Grant``s the principal holds; the engine then decides from those alone. A role
is a join path here and nothing more: the query selects *permission keys* and
where the assignment applies, and the result carries no role id, key or display
name — so what the engine is handed cannot depend on any of them.

A grant exists when **all** of these hold at the moment of the query:

* the assignment is live — not revoked and not past ``expires_at``;
* the role is ``active`` or ``retiring`` (a retiring role stays effective until
  it is retired, so a retirement never causes an outage; a retired role grants
  nothing);
* the permission is not ``retired``.

Two resolvers, one engine. A human principal resolves from assignments. A
service principal (a token with scopes for one tenant — ``service_identity``,
RBAC-0 §3) resolves from its scopes, each of which must be a catalogue key; it
never touches role tables.

Nothing is cached across requests: a revocation takes effect on the next call.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Mapping

from ccure_platform.rbac import contract as c
from ccure_platform.rbac import engine
from ccure_platform.rbac.model import (
    RbacPermission,
    RbacRole,
    RbacRolePermission,
    RbacUserRole,
    to_permission,
)
from sqlalchemy import or_, select
from sqlalchemy.orm import Session


def load_catalogue(db: Session) -> dict[str, c.Permission]:
    """Every permission the catalogue knows, by key."""
    return {
        row.key: to_permission(row)
        for row in db.execute(select(RbacPermission)).scalars()
    }


def principal_for_user(user) -> c.Principal:
    """
    A human ``Principal`` from the account a route already holds. Duck-typed on
    ``id``, ``org_id`` and the account-state flags, so RBAC imports no identity
    model. Authentication has already vetted the account; ``active`` records the
    flags that would make it unusable anyway.
    """
    active = bool(getattr(user, "is_active", True)) and not bool(
        getattr(user, "is_deleted", False)
    )
    return c.Principal(
        kind="human",
        principal_id=str(user.id),
        home_org_id=getattr(user, "org_id", None),
        active=active,
    )


def resolve_grants(
    db: Session, principal: c.Principal, *, at: datetime | None = None
) -> tuple[c.Grant, ...]:
    """The grants a human principal holds now. A service principal resolves
    through ``service_grants`` instead and holds nothing here."""
    if principal.kind != "human":
        return ()
    now = at or datetime.now(timezone.utc)
    rows = db.execute(
        select(
            RbacRolePermission.permission_key,
            RbacUserRole.scope_type,
            RbacUserRole.scope_org_id,
        )
        .select_from(RbacUserRole)
        .join(RbacRole, RbacRole.id == RbacUserRole.role_id)
        .join(RbacRolePermission, RbacRolePermission.role_id == RbacRole.id)
        .join(RbacPermission, RbacPermission.key == RbacRolePermission.permission_key)
        .where(
            RbacUserRole.user_id == principal.principal_id,
            RbacUserRole.revoked_at.is_(None),
            or_(RbacUserRole.expires_at.is_(None), RbacUserRole.expires_at > now),
            RbacRole.state.in_(("active", "retiring")),
            RbacPermission.status != "retired",
        )
        .distinct()
    ).all()
    return tuple(
        c.Grant(permission_key=k, assignment_scope=scope, scope_org_id=org)
        for k, scope, org in rows
    )


def service_grants(
    principal: c.Principal,
    scopes: Iterable[str],
    catalogue: Mapping[str, c.Permission],
) -> tuple[c.Grant, ...]:
    """
    Grants for a service principal: each token scope that is an active catalogue
    key, held in the principal's one tenant. A scope the catalogue does not know
    grants nothing (default deny) — it is never "assumed".
    """
    if principal.kind != "service" or not principal.home_org_id:
        return ()
    out = []
    for scope in sorted(set(scopes)):
        perm = catalogue.get(scope)
        if (
            perm is None
            or perm.status == "retired"
            or perm.scope_kind != "organization"
        ):
            continue
        out.append(
            c.Grant(
                permission_key=scope,
                assignment_scope="organization",
                scope_org_id=principal.home_org_id,
            )
        )
    return tuple(out)


def authorize(
    db: Session,
    principal: c.Principal,
    permission_key: str,
    scope: c.ScopeContext | None = None,
    *,
    grants: Iterable[c.Grant] | None = None,
) -> c.AuthorizationDecision:
    """Resolve and decide. ``grants`` lets a caller that already holds them (a
    service principal's, or a test's) skip the lookup."""
    catalogue = load_catalogue(db)
    held = tuple(grants) if grants is not None else resolve_grants(db, principal)
    return engine.decide(principal, held, catalogue, permission_key, scope)


def effective_permissions(
    db: Session, principal: c.Principal, org_id: str | None = None
) -> c.EffectivePermissionSet:
    """The permission keys ``principal`` holds in ``org_id`` (its own
    organisation when None) — computed with exactly the engine's rules."""
    catalogue = load_catalogue(db)
    grants = resolve_grants(db, principal)
    target = org_id or principal.home_org_id
    keys = engine.held_keys(principal, grants, catalogue, target)
    return c.EffectivePermissionSet(
        principal_id=principal.principal_id, org_id=target, permissions=keys
    )
