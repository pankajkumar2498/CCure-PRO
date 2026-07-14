"""
auth/rbac.py
────────────────────────────────────────────────────────────────────────────────
FastAPI dependency factories for Role-Based Access Control (RBAC).

Usage
─────
    from auth.rbac import require_role, require_permission

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

import logging
from typing import Sequence, Union

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user
from db.base import get_db
from db.models import User, RolePermission, Permission

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# require_role — simple role-name guard
# ─────────────────────────────────────────────────────────────────────────────


def require_role(allowed_roles: Union[str, Sequence[str]]):
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

    def _guard(user: User = Depends(get_current_user)) -> User:
        role = getattr(user, "role", None)
        role_name = (getattr(role, "name", "") or "").lower() if role else ""

        if not role_name:
            logger.warning(
                "RBAC denied: user %s has no role assigned.",
                user.id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your account does not have a role assigned. Contact an administrator.",
            )

        if role_name not in allowed_set:
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
        return user

    return _guard


# ─────────────────────────────────────────────────────────────────────────────
# require_permission — granular resource×action guard
# ─────────────────────────────────────────────────────────────────────────────


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
    ) -> User:
        role = getattr(user, "role", None)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your account does not have a role assigned.",
            )

        role_name = getattr(role, "name", "unknown")

        # Superadmin bypass: superadmins have all permissions
        if role_name.lower() == "superadmin":
            return user

        # Check if the user's role has this specific permission
        has_perm = (
            db.query(RolePermission)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .filter(
                RolePermission.role_id == role.id,
                Permission.resource == resource,
                Permission.action == action,
            )
            .first()
        ) is not None

        if not has_perm:
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
