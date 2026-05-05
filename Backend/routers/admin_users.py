from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from datetime import datetime

from auth.rbac import require_permission
from auth.dependencies import get_current_user
from auth.jwt_handler import hash_password
from db.base import get_db, utcnow
from db.models import User, Role
from core.audit import log_audit_event

router = APIRouter(prefix="/admin/users", tags=["User Management"])

class UserCreateSchema(BaseModel):
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    role_id: int
    password: str

class UserUpdateSchema(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None

class UserRoleUpdateSchema(BaseModel):
    role_id: int

class UserStatusUpdateSchema(BaseModel):
    is_active: Optional[bool] = None
    locked_until: Optional[datetime] = None

@router.get("")
def list_users(
    role_id: Optional[int] = None,
    is_active: Optional[bool] = None,
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "read"))
):
    query = db.query(User).filter(User.org_id == current_user.org_id)
    if role_id is not None:
        query = query.filter(User.role_id == role_id)
    if is_active is not None:
        query = query.filter(User.is_active == is_active)
    
    total = query.count()
    users = query.order_by(User.created_at.desc()).offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "users": [
            {
                "id": str(u.id),
                "username": u.username,
                "email": u.email,
                "full_name": u.full_name,
                "role_id": u.role_id,
                "is_active": u.is_active,
                "locked_until": u.locked_until,
                "last_login_at": u.last_login_at,
                "created_at": u.created_at
            }
            for u in users
        ]
    }

@router.post("/")
def create_user(
    request: Request,
    user_data: UserCreateSchema, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(require_permission("users", "create"))
):
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
        org_id=current_user.org_id,
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
    return {"id": str(new_user.id), "username": new_user.username}

@router.put("/{user_id}")
def update_user(
    user_id: str,
    request: Request,
    user_data: UserUpdateSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "update"))
):
    user = db.query(User).filter(User.id == user_id, User.org_id == current_user.org_id).first()
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
def change_role(
    user_id: str,
    request: Request,
    role_data: UserRoleUpdateSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "update"))
):
    user = db.query(User).filter(User.id == user_id, User.org_id == current_user.org_id).first()
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
def change_status(
    user_id: str,
    request: Request,
    status_data: UserStatusUpdateSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "update"))
):
    user = db.query(User).filter(User.id == user_id, User.org_id == current_user.org_id).first()
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
def delete_user(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "delete"))
):
    user = db.query(User).filter(User.id == user_id, User.org_id == current_user.org_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if str(user.id) == str(current_user.id):
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
        
    user.is_active = False
    log_audit_event(db, current_user, "user.deleted", "user", str(user.id), {"is_active": {"old": True, "new": False}}, request)
    db.commit()
    return {"detail": "User soft deleted successfully"}
