"""
ccure_platform/rbac/dependencies.py (was auth/rbac.py until Phase 8.2)
────────────────────────────────────────────────────────────────────────────────
FastAPI dependency factories for Role-Based Access Control (RBAC).

Usage
─────
    from ccure_platform.rbac.dependencies import require_role, require_permission

    # Allow only superadmin and org_admin to access an endpoint
    @app.post("/admin/dangerous-action",
              dependencies=[Depends(require_role(["superadmin", "org_admin"]))])
    def dangerous_action():
        ...

    # Allow any role that has the 'scans:execute' permission atom
    @app.post("/scan/host-discovery",
              dependencies=[Depends(require_permission("scans", "execute"))])
    def host_discovery():
        ...

Role hierarchy (seeded in db/migrate_production_schema.py):
  superadmin  → all permissions
  org_admin   → full org scope (scans, scan lifecycle, assets, users, settings, credentials)
  analyst     → scans (create/read/execute/cancel), assets (read), reports
  viewer      → org-wide read-only (scans, assets, findings, reports, settings)
  scanner     → API-only (scans create/read/execute, credentials read)
"""

from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "auth.rbac")

import logging
from collections.abc import Sequence
from typing import Union

from ccure_platform.identity.dependencies import get_current_user
from db.base import get_db
from db.models import Permission, RolePermission, User
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Shadow comparison hook (RBAC-3) — observation only
# ─────────────────────────────────────────────────────────────────────────────
#
# After a guard below has decided, it hands its decision to the shadow comparison
# and carries on with that decision. Both helpers return None, swallow every
# exception, and are off unless the shadow flag is set (config.RbacShadowConfig):
# nothing here can grant, deny or change what a guard returns or raises.
# docs/architecture/RBAC_SHADOW_AUTHORIZATION.md


def _observe_permission(db, user, resource, action, allowed, operation) -> None:
    try:
        from ccure_platform.rbac.shadow_runtime import observe_permission

        observe_permission(db, user, resource, action, allowed, operation=operation)
    except Exception:  # noqa: BLE001 - observation must never break a guard
        return None


def _observe_role_check(user, required, allowed, request) -> None:
    try:
        from ccure_platform.rbac.shadow_runtime import observe_role_check, operation_of

        observe_role_check(user, required, allowed, operation=operation_of(request))
    except Exception:  # noqa: BLE001 - observation must never break a guard
        return None


def _operation(request) -> str | None:
    try:
        from ccure_platform.rbac.shadow_runtime import enabled, operation_of

        return operation_of(request) if enabled() else None
    except Exception:  # noqa: BLE001
        return None


# ─────────────────────────────────────────────────────────────────────────────
# require_role — simple role-name guard
# ─────────────────────────────────────────────────────────────────────────────


def require_role(allowed_roles: str | Sequence[str]):
    """
    Returns a FastAPI dependency that rejects requests from users whose
    role name is NOT in `allowed_roles`.

    Parameters
    ----------
    allowed_roles : str or list[str]
        One or more role names (e.g. "superadmin", ["org_admin", "analyst"]).
        Comparison is case-insensitive.

    Raises
    ------
    HTTPException 403
        If the user's role is not in the allowed set.
    """
    if isinstance(allowed_roles, str):
        allowed_roles = [allowed_roles]
    allowed_set = {r.lower() for r in allowed_roles}

    def _guard(user: User = Depends(get_current_user), request: Request = None) -> User:
        role = getattr(user, "role", None)
        role_name = (getattr(role, "name", "") or "").lower() if role else ""

        if not role_name:
            _observe_role_check(user, allowed_set, False, request)
            logger.warning(
                "RBAC denied: user %s has no role assigned.",
                user.id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your account does not have a role assigned. Contact an administrator.",
            )

        if role_name not in allowed_set:
            _observe_role_check(user, allowed_set, False, request)
            logger.warning(
                "RBAC denied: user %s (role=%s) attempted action requiring %s.",
                user.id,
                role_name,
                allowed_set,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Insufficient privileges. "
                    f"Your role '{role_name}' does not have access to this resource. "
                    f"Required: {', '.join(sorted(allowed_set))}."
                ),
            )
        _observe_role_check(user, allowed_set, True, request)
        return user

    return _guard


# ─────────────────────────────────────────────────────────────────────────────
# require_permission — granular resource×action guard
# ─────────────────────────────────────────────────────────────────────────────


def _legacy_decision(db: Session, user: User, resource: str, action: str) -> bool:
    """The legacy rule, unchanged: a user with no role holds nothing, the superadmin
    role holds everything, and any other role holds what ``role_permissions`` says."""
    role = getattr(user, "role", None)
    if not role:
        return False
    if (getattr(role, "name", "") or "").lower() == "superadmin":
        return True
    return (
        db.query(RolePermission)
        .join(Permission, Permission.id == RolePermission.permission_id)
        .filter(
            RolePermission.role_id == role.id,
            Permission.resource == resource,
            Permission.action == action,
        )
        .first()
    ) is not None


def user_has_permission(
    db: Session,
    user: User,
    resource: str,
    action: str,
    *,
    operation: str | None = None,
    authoritative: bool = False,
) -> bool:
    """
    Whether ``user``'s role holds the (resource, action) permission atom.

    The single implementation behind :func:`require_permission`, exposed for
    the case a route dependency cannot express: a permission that depends on
    the request body. Setting a web finding to ``accepted_risk`` needs
    ``findings:accept_risk`` on top of the ``findings:update`` the route itself
    requires, and only the handler knows which status was asked for.

    A user with no role holds nothing. Superadmin holds everything.

    ``operation`` is the route, for the shadow comparison's diagnostics only.

    ``authoritative`` (RBAC-4) marks a call site the migration inventory lists as
    migrated: when that path is switched on (``rbac.authority``) the new engine's
    answer is returned instead of the legacy one. Off, or for a path not switched on,
    the legacy answer is returned exactly as before.
    """
    allowed = _legacy_decision(db, user, resource, action)
    _observe_permission(db, user, resource, action, allowed, operation)
    if authoritative:
        from ccure_platform.rbac import authority

        return authority.decide_atom(
            db, user, resource, action, allowed, operation=operation
        ).allowed
    return allowed


def require_permission(resource: str, action: str):
    """
    Returns a FastAPI dependency that rejects requests from users whose
    role does NOT hold the specified (resource, action) permission atom.

    Parameters
    ----------
    resource : str   e.g. "scans", "credentials"
    action   : str   e.g. "create", "execute"

    Raises
    ------
    HTTPException 403
        If the permission is not assigned to the user's role.
    """

    def _guard(
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
        request: Request = None,
    ) -> User:
        role = getattr(user, "role", None)
        if not role:
            _observe_permission(db, user, resource, action, False, _operation(request))
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your account does not have a role assigned.",
            )

        if not user_has_permission(
            db,
            user,
            resource,
            action,
            operation=_operation(request),
            authoritative=True,
        ):
            role_name = getattr(role, "name", "unknown")
            logger.warning(
                "RBAC denied: user %s (role=%s) lacks %s:%s.",
                user.id,
                role_name,
                resource,
                action,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Insufficient privileges. "
                    f"Your role '{role_name}' does not have '{resource}:{action}' permission."
                ),
            )
        return user

    return _guard


# ─────────────────────────────────────────────────────────────────────────────
# Permission-key guards (RBAC-4) — replacing role-name checks
# ─────────────────────────────────────────────────────────────────────────────


def _legacy_key_decision(user: User, key: str) -> bool:
    """The legacy rule the key replaced: the role-name set recorded for it in
    ``authority.LEGACY_KEY_ROLES``. This is the rollback path; module code never
    names a role."""
    from ccure_platform.rbac.authority import legacy_roles_for_key

    allowed = {r.lower() for r in legacy_roles_for_key(key)}
    role = getattr(user, "role", None)
    return bool(role) and (getattr(role, "name", "") or "").lower() in allowed


def has_permission(db: Session, user: User, key: str, *, operation=None) -> bool:
    """Whether ``user`` holds the permission ``key``: the new engine when the key's
    path is switched on, otherwise the legacy rule the key replaced."""
    from ccure_platform.rbac import authority

    legacy = _legacy_key_decision(user, key)
    return authority.decide_key(db, user, key, legacy, operation=operation).allowed


def require_authorized(key: str):
    """
    A route dependency that requires the permission ``key``. With authority off (the
    default) it is exactly the legacy role guard it replaced, including its messages
    and the RBAC-3 role-name observation.
    """

    def _guard(
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
        request: Request = None,
    ) -> User:
        from ccure_platform.rbac import authority
        from ccure_platform.rbac.authority import legacy_roles_for_key

        role = getattr(user, "role", None)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your account does not have a role assigned. Contact an administrator.",
            )
        legacy = _legacy_key_decision(user, key)
        _observe_role_check(user, set(legacy_roles_for_key(key)), legacy, request)
        out = authority.decide_key(db, user, key, legacy, operation=_operation(request))
        if not out.allowed:
            logger.warning("RBAC denied: user %s lacks %s.", user.id, key)
            if out.source == authority.SOURCE_LEGACY:
                role_name = (getattr(role, "name", "") or "").lower()
                req = ", ".join(sorted(legacy_roles_for_key(key)))
                detail = (
                    "Insufficient privileges. "
                    f"Your role '{role_name}' does not have access to this resource. "
                    f"Required: {req}."
                )
            else:
                detail = f"Insufficient privileges. Missing permission: {key}."
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)
        return user

    return _guard
