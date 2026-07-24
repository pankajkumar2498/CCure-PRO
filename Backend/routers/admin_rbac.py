from auth.rbac import require_permission
from db.base import get_db
from db.models import Role, RolePermission, User
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload

router = APIRouter(prefix="/admin/roles", tags=["RBAC Administration"])


@router.get("")
@router.get("/")
def list_roles(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("roles", "read")),
):
    roles = db.query(Role).all()
    return {
        "roles": [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "is_system_role": r.is_system_role,
            }
            for r in roles
        ]
    }


@router.get("/{role_id}/permissions")
@router.get("/{role_id}/permissions/")
def list_role_permissions(
    role_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("roles", "read")),
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
