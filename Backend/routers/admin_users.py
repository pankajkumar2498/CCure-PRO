from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, EmailStr
from sqlalchemy.orm import Session
from datetime import datetime

from auth.rbac import require_permission
from auth.jwt_handler import hash_password
from db.base import get_db, utcnow
from db.models import (
    AssetNote,
    AssetTag,
    AssetVulnerability,
    AuditLog,
    Organization,
    RefreshTokenSession,
    Role,
    Scan,
    User,
)
from core.audit import log_audit_event

router = APIRouter(prefix="/admin/users", tags=["User Management"])


def _is_superadmin(user: User) -> bool:
    return (getattr(getattr(user, "role", None), "name", "") or "").lower() == "superadmin"


def _serialize_user(user: User) -> dict:
    return {
        "id": str(user.id),
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "organization_id": str(user.org_id),
        "role_id": user.role_id,
        "is_active": user.is_active,
        "is_deleted": bool(getattr(user, "is_deleted", False)),
        "locked_until": user.locked_until,
        "last_login_at": user.last_login_at,
        "deleted_at": getattr(user, "deleted_at", None),
        "created_at": user.created_at,
    }


def _scoped_users_query(db: Session, current_user: User, scope: str = "active"):
    query = db.query(User)
    if not _is_superadmin(current_user):
        query = query.filter(User.org_id == current_user.org_id)
    if scope == "active":
        query = query.filter(User.is_deleted.is_(False))
    elif scope == "deleted":
        query = query.filter(User.is_deleted.is_(True))
    elif scope != "all":
        raise HTTPException(status_code=400, detail="Invalid scope. Use active, deleted, or all.")
    return query


def _resolve_target_org_id(db: Session, current_user: User, requested_org_id: Optional[str]) -> str:
    if not _is_superadmin(current_user):
        return str(current_user.org_id)

    if not requested_org_id:
        raise HTTPException(status_code=400, detail="organization_id is required when superadmin creates a user")

    org = db.query(Organization).filter(Organization.id == requested_org_id).first()
    if not org:
        raise HTTPException(status_code=400, detail="Invalid organization_id")

    return str(org.id)

class UserCreateSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    email: EmailStr
    full_name: Optional[str] = None
    role_id: int
    password: str
    organization_id: Optional[str] = None

class UserUpdateSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: Optional[str] = None
    email: Optional[EmailStr] = None

class UserRoleUpdateSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role_id: int

class UserStatusUpdateSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_active: Optional[bool] = None
    locked_until: Optional[datetime] = None

@router.get("")
@router.get("/")
def list_users(
    role_id: Optional[int] = None,
    is_active: Optional[bool] = None,
    scope: str = "active",
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "read"))
):
    query = _scoped_users_query(db, current_user, scope=scope)
        
    if role_id is not None:
        query = query.filter(User.role_id == role_id)
    if is_active is not None:
        query = query.filter(User.is_active == is_active)
    
    total = query.count()
    order_by = [User.created_at.desc()]
    if scope == "deleted":
        order_by = [User.deleted_at.desc(), User.created_at.desc()]
    users = query.order_by(*order_by).offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "scope": scope,
        "users": [_serialize_user(u) for u in users],
    }

@router.post("")
@router.post("/")
def create_user(
    request: Request,
    user_data: UserCreateSchema, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(require_permission("users", "create"))
):
    target_org_id = _resolve_target_org_id(db, current_user, user_data.organization_id)

    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
        
    role = db.query(Role).filter(Role.id == user_data.role_id).first()
    if not role:
        raise HTTPException(status_code=400, detail="Invalid role_id")

    # Enforce hierarchy: org_admin cannot create superadmin
    if role.name == "superadmin" and current_user.role.name != "superadmin":
        raise HTTPException(status_code=403, detail="Cannot assign superadmin role")

    new_user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        role_id=user_data.role_id,
        org_id=target_org_id,
        password_hash=hash_password(user_data.password),
        is_active=True
    )
    db.add(new_user)
    db.flush()

    log_audit_event(
        db=db,
        user=current_user,
        action="user.created",
        resource_type="user",
        resource_id=str(new_user.id),
        request=request
    )
    db.commit()
    db.refresh(new_user)
    return {"id": str(new_user.id), "username": new_user.username, "organization_id": str(new_user.org_id)}

@router.put("/{user_id}")
@router.put("/{user_id}/")
def update_user(
    user_id: str,
    request: Request,
    user_data: UserUpdateSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "update"))
):
    user = _scoped_users_query(db, current_user, scope="active").filter(User.id == user_id).first()
        
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    changes = {}
    if user_data.full_name is not None and user.full_name != user_data.full_name:
        changes["full_name"] = {"old": user.full_name, "new": user_data.full_name}
        user.full_name = user_data.full_name
    if user_data.email is not None and user.email != user_data.email:
        if db.query(User).filter(User.email == user_data.email).first():
            raise HTTPException(status_code=400, detail="Email already in use")
        changes["email"] = {"old": user.email, "new": user_data.email}
        user.email = user_data.email
        
    if changes:
        log_audit_event(db, current_user, "user.updated", "user", str(user.id), changes, request)
        db.commit()
    return {"detail": "User updated successfully"}

@router.patch("/{user_id}/role")
@router.patch("/{user_id}/role/")
def change_role(
    user_id: str,
    request: Request,
    role_data: UserRoleUpdateSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "update"))
):
    user = _scoped_users_query(db, current_user, scope="active").filter(User.id == user_id).first()
        
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    role = db.query(Role).filter(Role.id == role_data.role_id).first()
    if not role:
        raise HTTPException(status_code=400, detail="Invalid role_id")
        
    if role.name == "superadmin" and current_user.role.name != "superadmin":
        raise HTTPException(status_code=403, detail="Cannot assign superadmin role")
        
    changes = {"role_id": {"old": user.role_id, "new": role.id}}
    user.role_id = role.id
    log_audit_event(db, current_user, "user.role_changed", "user", str(user.id), changes, request)
    db.commit()
    return {"detail": "User role updated successfully"}

@router.patch("/{user_id}/status")
@router.patch("/{user_id}/status/")
def change_status(
    user_id: str,
    request: Request,
    status_data: UserStatusUpdateSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "update"))
):
    user = _scoped_users_query(db, current_user, scope="active").filter(User.id == user_id).first()
        
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    changes = {}
    if status_data.is_active is not None and user.is_active != status_data.is_active:
        changes["is_active"] = {"old": user.is_active, "new": status_data.is_active}
        user.is_active = status_data.is_active
    
    # Manual unlock
    if status_data.locked_until is None and user.locked_until is not None:
        changes["locked_until"] = {"old": str(user.locked_until), "new": None}
        user.locked_until = None
        user.failed_login_count = 0
        
    if changes:
        log_audit_event(db, current_user, "user.status_changed", "user", str(user.id), changes, request)
        db.commit()
    return {"detail": "User status updated successfully"}

@router.delete("/{user_id}")
@router.delete("/{user_id}/")
def delete_user(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "delete"))
):
    user = _scoped_users_query(db, current_user, scope="all").filter(User.id == user_id).first()
        
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if str(user.id) == str(current_user.id):
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    if user.is_deleted:
        return {
            "detail": "User is already in Deleted Users",
            "moved_to_deleted_users": False,
        }

    previous_active = bool(user.is_active)
    user.is_deleted = True
    user.deleted_at = utcnow()
    user.is_active = False
    user.updated_at = utcnow()
    db.query(RefreshTokenSession).filter(RefreshTokenSession.user_id == user.id).delete(synchronize_session=False)
    log_audit_event(
        db,
        current_user,
        "user.deleted",
        "user",
        str(user.id),
        {
            "is_deleted": {"old": False, "new": True},
            "deleted_at": {"old": None, "new": user.deleted_at.isoformat()},
            "is_active": {"old": previous_active, "new": False},
        },
        request,
    )
    db.commit()
    return {
        "detail": "User moved to Deleted Users",
        "moved_to_deleted_users": True,
    }


@router.post("/{user_id}/restore")
@router.post("/{user_id}/restore/")
def restore_user(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "delete")),
):
    user = _scoped_users_query(db, current_user, scope="deleted").filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Deleted user not found")

    deleted_at_before = user.deleted_at.isoformat() if user.deleted_at else None
    user.is_deleted = False
    user.deleted_at = None
    user.is_active = False
    user.updated_at = utcnow()
    log_audit_event(
        db,
        current_user,
        "user.restored",
        "user",
        str(user.id),
        {
            "is_deleted": {"old": True, "new": False},
            "deleted_at": {"old": deleted_at_before, "new": None},
            "is_active": {"old": False, "new": False},
        },
        request,
    )
    db.commit()
    return {"detail": "User restored. The account remains inactive until explicitly reactivated."}


@router.delete("/{user_id}/purge")
@router.delete("/{user_id}/purge/")
def purge_user(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "delete")),
):
    user = _scoped_users_query(db, current_user, scope="deleted").filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Deleted user not found")

    target_user_id = user.id
    db.query(AuditLog).filter(AuditLog.user_id == target_user_id).update({AuditLog.user_id: None}, synchronize_session=False)
    db.query(AssetNote).filter(AssetNote.user_id == target_user_id).update({AssetNote.user_id: None}, synchronize_session=False)
    db.query(AssetTag).filter(AssetTag.created_by_id == target_user_id).update({AssetTag.created_by_id: None}, synchronize_session=False)
    db.query(Scan).filter(Scan.created_by == target_user_id).update({Scan.created_by: None}, synchronize_session=False)
    db.query(AssetVulnerability).filter(AssetVulnerability.accepted_by == target_user_id).update(
        {AssetVulnerability.accepted_by: None},
        synchronize_session=False,
    )
    db.query(RefreshTokenSession).filter(RefreshTokenSession.user_id == target_user_id).delete(synchronize_session=False)

    log_audit_event(db, current_user, "user.purged", "user", str(target_user_id), request=request)
    db.delete(user)
    db.commit()
    return {"detail": "User permanently deleted"}
