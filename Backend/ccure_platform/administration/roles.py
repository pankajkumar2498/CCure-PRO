from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "routers.admin_rbac")

from ccure_platform.rbac.dependencies import require_authorized
from ccure_platform.rbac.scope import check_role_assignment
from db.base import get_db
from db.models import Role, RolePermission, User
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, joinedload

router = APIRouter(prefix="/admin/roles", tags=["RBAC Administration"])


@router.get("")
@router.get("/")
def list_roles(
    # the organisation an account would be placed in; the backend, not the form,
    # decides which roles may be handed out there (RBAC-7)
    organization_id: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authorized("platform.role.read")),
):
    roles = db.query(Role).all()
    org = str(organization_id or current_user.org_id)
    return {
        "roles": [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "is_system_role": r.is_system_role,
                # backend-authoritative: the assignment rules (organisation boundary,
                # permission and scope ceilings, hierarchy) applied to this actor
                "assignable": check_role_assignment(
                    current_user, r, target_user_id=None, target_org_id=org
                ).allowed,
            }
            for r in roles
        ]
    }


@router.get("/{role_id}/permissions")
@router.get("/{role_id}/permissions/")
def list_role_permissions(
    role_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authorized("platform.permission.read")),
):
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    role_perms = (
        db.query(RolePermission)
        .options(joinedload(RolePermission.permission))
        .filter(RolePermission.role_id == role_id)
        .all()
    )

    return {
        "role_id": role.id,
        "role_name": role.name,
        "permissions": [
            {
                "id": rp.permission.id,
                "resource": rp.permission.resource,
                "action": rp.permission.action,
                "description": rp.permission.description,
            }
            for rp in role_perms
        ],
    }
