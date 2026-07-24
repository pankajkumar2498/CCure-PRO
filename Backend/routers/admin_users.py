import logging
from datetime import datetime
from typing import Optional

from auth.email_utils import email_matches, normalize_email
from auth.jwt_handler import hash_password, validate_password_strength
from auth.rbac import require_permission
from core.audit import log_audit_event
from db.base import gen_user_id, get_db, utcnow
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
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, EmailStr, field_validator
from sqlalchemy.orm import Session

router = APIRouter(prefix="/admin/users", tags=["User Management"])
log = logging.getLogger(__name__)


def _is_superadmin(user: User) -> bool:
    return (
        getattr(getattr(user, "role", None), "name", "") or ""
    ).lower() == "superadmin"


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
        "mfa_enabled": bool(getattr(user, "mfa_enabled", False)),
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
        raise HTTPException(
            status_code=400, detail="Invalid scope. Use active, deleted, or all."
        )
    return query


def _resolve_target_org_id(
    db: Session, current_user: User, requested_org_id: str | None
) -> str:
    if not _is_superadmin(current_user):
        return str(current_user.org_id)

    if not requested_org_id:
        raise HTTPException(
            status_code=400,
            detail="organization_id is required when superadmin creates a user",
        )

    org = db.query(Organization).filter(Organization.id == requested_org_id).first()
    if not org:
        raise HTTPException(status_code=400, detail="Invalid organization_id")

    return str(org.id)


def _notify_user_admin_action(
    db: Session,
    current_user: User,
    target_user: User,
    action_title: str,
    action_message: str,
    fan_out_message: str,
):
    """
    Centralized helper to dispatch notifications for user administration actions.
    Dispatches:
      1. Personal receipt to the acting admin.
      2. Fan-out to admins in the target user's organization.
      3. Fan-out to admins in the acting admin's organization (if different).
    """
    try:
        from routers.notifications import (
            NotificationCategory,
            NotificationType,
            create_notification,
            fan_out_notification,
        )

        # 1. Personal receipt for the admin who performed the action
        create_notification(
            db=db,
            user_id=str(current_user.id),
            notification_type=NotificationType.ADMIN_NOTICE,
            category=NotificationCategory.ADMIN,
            title=action_title,
            message=action_message,
        )

        # 2. AUDIT TRANSPARENCY: Fan out to admins in the target organization
        fan_out_notification(
            db=db,
            org_id=str(target_user.org_id),
            target_roles=["superadmin", "org_admin"],
            notification_type=NotificationType.ADMIN_NOTICE,
            category=NotificationCategory.ADMIN,
            title=action_title,
            message=fan_out_message,
            exclude_user_id=str(current_user.id),
        )

        # 3. CROSS-ORG VISIBILITY: If acting admin is from a different org (e.g. Superadmin),
        #    notify admins in their own organization as well.
        if str(current_user.org_id) != str(target_user.org_id):
            fan_out_notification(
                db=db,
                org_id=str(current_user.org_id),
                target_roles=["superadmin", "org_admin"],
                notification_type=NotificationType.ADMIN_NOTICE,
                category=NotificationCategory.ADMIN,
                title=action_title,
                message=fan_out_message,
                exclude_user_id=str(current_user.id),
            )
    except Exception as _notif_exc:
        log.warning(
            "Notification dispatch failed for user administration action "
            "[action=%s, target_user=%s, acting_admin=%s]: %s",
            action_title,
            target_user.username,
            current_user.username,
            _notif_exc,
            exc_info=True,
        )


class UserCreateSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    email: EmailStr
    full_name: str | None = None
    role_id: int
    password: str
    organization_id: str | None = None


class UserUpdateSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str | None = None
    email: EmailStr | None = None


class UserRoleUpdateSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role_id: int


class UserStatusUpdateSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_active: bool | None = None
    locked_until: datetime | None = None


class UserResetPasswordSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return validate_password_strength(v)


@router.get("")
@router.get("/")
def list_users(
    role_id: int | None = None,
    organization_id: str | None = None,
    is_active: bool | None = None,
    q: str | None = None,
    scope: str = "active",
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "read")),
):
    query = _scoped_users_query(db, current_user, scope=scope)

    if role_id is not None:
        query = query.filter(User.role_id == role_id)
    if is_active is not None:
        query = query.filter(User.is_active == is_active)

    # Superadmins can drill down into a specific org; non-superadmins are already scoped
    if _is_superadmin(current_user) and organization_id:
        query = query.filter(User.org_id == organization_id)

    # Server-side search: username, email, full_name
    if q:
        term = f"%{q}%"
        query = query.filter(
            (User.username.ilike(term))
            | (User.email.ilike(term))
            | (User.full_name.ilike(term))
        )

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
    current_user: User = Depends(require_permission("users", "create")),
):
    target_org_id = _resolve_target_org_id(db, current_user, user_data.organization_id)
    email = normalize_email(user_data.email)

    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(email_matches(User.email, email)).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    role = db.query(Role).filter(Role.id == user_data.role_id).first()
    if not role:
        raise HTTPException(status_code=400, detail="Invalid role_id")

    # Enforce hierarchy: org_admin cannot create superadmin
    if role.name == "superadmin" and current_user.role.name != "superadmin":
        raise HTTPException(status_code=403, detail="Cannot assign superadmin role")

    # Resolve org slug for readable ID generation
    org = db.query(Organization).filter(Organization.id == target_org_id).first()
    org_slug = org.slug if org else target_org_id

    new_user = User(
        id=gen_user_id(org_slug, user_data.username),  # e.g. usr_acm_alice_x9v1
        username=user_data.username,
        email=email,
        full_name=user_data.full_name,
        role_id=user_data.role_id,
        org_id=target_org_id,
        password_hash=hash_password(user_data.password),
        is_active=True,
    )
    db.add(new_user)
    db.flush()

    log_audit_event(
        db=db,
        user=current_user,
        action="user.created",
        resource_type="user",
        resource_id=str(new_user.id),
        request=request,
    )
    db.commit()
    db.refresh(new_user)

    _notify_user_admin_action(
        db=db,
        current_user=current_user,
        target_user=new_user,
        action_title="User Created",
        action_message=f"Successfully created new user account: {new_user.username}",
        fan_out_message=f"Admin {current_user.username} created new user account: {new_user.username}",
    )

    return {
        "id": str(new_user.id),
        "username": new_user.username,
        "organization_id": str(new_user.org_id),
    }


class UserMoveOrgSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")
    organization_id: str  # Target org ID (e.g. "org_acme_corp")


@router.patch("/{user_id}/organization")
@router.patch("/{user_id}/organization/")
def move_user_to_organization(
    user_id: str,
    request: Request,
    body: UserMoveOrgSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "update")),
):
    """
    Move a user to a different organization.

    Rules:
      - Only superadmins can move users across organizations.
      - You cannot move yourself.
      - The target organization must exist and be active.
      - All active refresh token sessions are revoked immediately
        so the user's next login picks up the new org context cleanly.

    Example:
      PATCH /admin/users/usr_sel_alice_x9v1/organization
      { "organization_id": "org_acme_corp" }
    """
    if not _is_superadmin(current_user):
        raise HTTPException(
            status_code=403,
            detail="Only superadmins can move users between organizations.",
        )

    if str(user_id) == str(current_user.id):
        raise HTTPException(
            status_code=400, detail="You cannot move yourself to another organization."
        )

    # Load the target user
    user = db.query(User).filter(User.id == user_id, User.is_deleted.is_(False)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Validate target org
    target_org = (
        db.query(Organization).filter(Organization.id == body.organization_id).first()
    )
    if not target_org:
        raise HTTPException(
            status_code=404, detail=f"Organization '{body.organization_id}' not found."
        )
    if not target_org.is_active:
        raise HTTPException(
            status_code=400, detail=f"Organization '{target_org.name}' is deactivated."
        )

    # No-op if already in that org
    if str(user.org_id) == str(body.organization_id):
        return {
            "detail": f"User '{user.username}' is already in organization '{target_org.name}'.",
            "no_change": True,
        }

    old_org_id = str(user.org_id)
    old_org = db.query(Organization).filter(Organization.id == old_org_id).first()
    old_org_name = old_org.name if old_org else old_org_id

    # Move the user
    user.org_id = body.organization_id

    # Revoke all active sessions — next login will get a fresh token with new org context
    db.query(RefreshTokenSession).filter(RefreshTokenSession.user_id == user.id).delete(
        synchronize_session=False
    )

    log_audit_event(
        db=db,
        user=current_user,
        action="user.organization_changed",
        resource_type="user",
        resource_id=str(user.id),
        changes={
            "org_id": {"old": old_org_id, "new": body.organization_id},
            "old_org_name": old_org_name,
            "new_org_name": target_org.name,
        },
        request=request,
    )
    db.commit()

    return {
        "detail": f"User '{user.username}' moved successfully.",
        "user_id": str(user.id),
        "username": user.username,
        "old_organization": {"id": old_org_id, "name": old_org_name},
        "new_organization": {"id": str(target_org.id), "name": target_org.name},
        "sessions_revoked": True,
    }


@router.put("/{user_id}")
@router.put("/{user_id}/")
def update_user(
    user_id: str,
    request: Request,
    user_data: UserUpdateSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "update")),
):
    user = (
        _scoped_users_query(db, current_user, scope="active")
        .filter(User.id == user_id)
        .first()
    )

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    changes = {}
    if user_data.full_name is not None and user.full_name != user_data.full_name:
        changes["full_name"] = {"old": user.full_name, "new": user_data.full_name}
        user.full_name = user_data.full_name
    if user_data.email is not None:
        email = normalize_email(user_data.email)
        if (
            user.email != email
            and db.query(User)
            .filter(email_matches(User.email, email), User.id != user.id)
            .first()
        ):
            raise HTTPException(status_code=400, detail="Email already in use")
        if user.email != email:
            changes["email"] = {"old": user.email, "new": email}
            user.email = email

    if changes:
        log_audit_event(
            db, current_user, "user.updated", "user", str(user.id), changes, request
        )
        db.commit()
    return {"detail": "User updated successfully"}


@router.patch("/{user_id}/role")
@router.patch("/{user_id}/role/")
def change_role(
    user_id: str,
    request: Request,
    role_data: UserRoleUpdateSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "update")),
):
    user = (
        _scoped_users_query(db, current_user, scope="active")
        .filter(User.id == user_id)
        .first()
    )

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    role = db.query(Role).filter(Role.id == role_data.role_id).first()
    if not role:
        raise HTTPException(status_code=400, detail="Invalid role_id")

    if role.name == "superadmin" and current_user.role.name != "superadmin":
        raise HTTPException(status_code=403, detail="Cannot assign superadmin role")

    changes = {"role_id": {"old": user.role_id, "new": role.id}}
    user.role_id = role.id
    log_audit_event(
        db, current_user, "user.role_changed", "user", str(user.id), changes, request
    )
    db.commit()
    return {"detail": "User role updated successfully"}


@router.patch("/{user_id}/status")
@router.patch("/{user_id}/status/")
def change_status(
    user_id: str,
    request: Request,
    status_data: UserStatusUpdateSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "update")),
):
    user = (
        _scoped_users_query(db, current_user, scope="active")
        .filter(User.id == user_id)
        .first()
    )

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if str(user.id) == str(current_user.id) and status_data.is_active is False:
        raise HTTPException(
            status_code=400, detail="You cannot deactivate your own account."
        )

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
        log_audit_event(
            db,
            current_user,
            "user.status_changed",
            "user",
            str(user.id),
            changes,
            request,
        )
        db.commit()

        if "is_active" in changes:
            action = "Enabled" if user.is_active else "Disabled"
            _notify_user_admin_action(
                db=db,
                current_user=current_user,
                target_user=user,
                action_title=f"User {action}",
                action_message=f"Successfully {action.lower()} user account: {user.username}",
                fan_out_message=f"Admin {current_user.username} {action.lower()} user account: {user.username}",
            )

    return {"detail": "User status updated successfully"}


@router.delete("/{user_id}")
@router.delete("/{user_id}/")
def delete_user(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "delete")),
):
    user = (
        _scoped_users_query(db, current_user, scope="all")
        .filter(User.id == user_id)
        .first()
    )

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
    db.query(RefreshTokenSession).filter(RefreshTokenSession.user_id == user.id).delete(
        synchronize_session=False
    )
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

    _notify_user_admin_action(
        db=db,
        current_user=current_user,
        target_user=user,
        action_title="User Suspended",
        action_message=f"User {user.username} has been moved to Deleted Users.",
        fan_out_message=f"Admin {current_user.username} suspended user account: {user.username}.",
    )

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
    user = (
        _scoped_users_query(db, current_user, scope="deleted")
        .filter(User.id == user_id)
        .first()
    )
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

    _notify_user_admin_action(
        db=db,
        current_user=current_user,
        target_user=user,
        action_title="User Restored",
        action_message=f"Successfully restored user account: {user.username}",
        fan_out_message=f"Admin {current_user.username} restored user account: {user.username}",
    )

    return {
        "detail": "User restored. The account remains inactive until explicitly reactivated."
    }


@router.delete("/{user_id}/purge")
@router.delete("/{user_id}/purge/")
def purge_user(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "delete")),
):
    user = (
        _scoped_users_query(db, current_user, scope="deleted")
        .filter(User.id == user_id)
        .first()
    )
    if not user:
        raise HTTPException(status_code=404, detail="Deleted user not found")

    target_user_id = user.id
    db.query(AuditLog).filter(AuditLog.user_id == target_user_id).update(
        {AuditLog.user_id: None}, synchronize_session=False
    )
    db.query(AssetNote).filter(AssetNote.user_id == target_user_id).update(
        {AssetNote.user_id: None}, synchronize_session=False
    )
    db.query(AssetTag).filter(AssetTag.created_by_id == target_user_id).update(
        {AssetTag.created_by_id: None}, synchronize_session=False
    )
    db.query(Scan).filter(Scan.created_by == target_user_id).update(
        {Scan.created_by: None}, synchronize_session=False
    )
    db.query(AssetVulnerability).filter(
        AssetVulnerability.accepted_by == target_user_id
    ).update(
        {AssetVulnerability.accepted_by: None},
        synchronize_session=False,
    )
    db.query(RefreshTokenSession).filter(
        RefreshTokenSession.user_id == target_user_id
    ).delete(synchronize_session=False)

    log_audit_event(
        db, current_user, "user.purged", "user", str(target_user_id), request=request
    )
    db.delete(user)
    db.commit()
    return {"detail": "User permanently deleted"}


@router.post("/{user_id}/reset-password")
@router.post("/{user_id}/reset-password/")
def reset_password(
    user_id: str,
    body: UserResetPasswordSchema,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "update")),
):
    """
    Reset a user's password.
    Only users with 'users:update' permission can call this.
    Org admins can only reset users in their own organization.
    All active refresh tokens/sessions for the user are deleted immediately.
    """
    user = (
        _scoped_users_query(db, current_user, scope="active")
        .filter(User.id == user_id)
        .first()
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update password hash
    user.password_hash = hash_password(body.password)

    # Invalidate all active sessions for that user
    db.query(RefreshTokenSession).filter(RefreshTokenSession.user_id == user.id).delete(
        synchronize_session=False
    )

    log_audit_event(
        db=db,
        user=current_user,
        action="user.password_reset",
        resource_type="user",
        resource_id=str(user.id),
        changes={"password_hash": "modified"},
        request=request,
    )
    db.commit()

    return {"detail": "Password reset successfully"}


@router.post("/{user_id}/reset-mfa")
@router.post("/{user_id}/reset-mfa/")
def reset_mfa(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "update")),
):
    """
    Reset a user's Multi-Factor Authentication.
    Only users with 'users:update' permission can call this.
    Org admins can only reset users in their own organization.
    All active refresh tokens/sessions for the user are deleted immediately.
    """
    user = (
        _scoped_users_query(db, current_user, scope="active")
        .filter(User.id == user_id)
        .first()
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Clear MFA configuration
    user.totp_secret = None
    user.mfa_enabled = False
    user.mfa_backup_codes = None

    # Invalidate all active sessions for that user
    db.query(RefreshTokenSession).filter(RefreshTokenSession.user_id == user.id).delete(
        synchronize_session=False
    )

    log_audit_event(
        db=db,
        user=current_user,
        action="user.mfa_reset_by_admin",
        resource_type="user",
        resource_id=str(user.id),
        changes={
            "mfa_enabled": {"old": True, "new": False},
            "totp_secret": "cleared",
            "mfa_backup_codes": "cleared",
        },
        request=request,
    )
    db.commit()

    return {"detail": "Multi-Factor Authentication reset successfully"}
