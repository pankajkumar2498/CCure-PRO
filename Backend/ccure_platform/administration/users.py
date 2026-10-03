from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "routers.admin_users")

import logging
from datetime import datetime
from typing import Optional

from ccure_platform.identity.email_domain_guard import (
    assert_email_allowed,
    invalidate_cache,
)
from ccure_platform.identity.email_utils import (
    canonicalize_email,
    email_matches,
    normalize_email,
    username_matches,
)
from ccure_platform.identity.jwt_handler import (
    hash_password,
    validate_password_strength,
)
from ccure_platform.rbac.dependencies import require_permission
from ccure_platform.offboarding import run_user_purge_hooks

# Registers RBAC's purge hook (it removes the account's role assignments, keeping
# their history in the audit trail, before the user row is deleted).
import ccure_platform.rbac.offboarding  # noqa: F401,E402
from ccure_platform.audit_log.writer import log_audit_event
from db.base import gen_user_id, get_db, utcnow
from db.models import (
    AuditLog,
    Organization,
    RefreshTokenSession,
    Role,
    User,
)
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, EmailStr, field_validator
from sqlalchemy.orm import Session

router = APIRouter(prefix="/admin/users", tags=["User Management"])
log = logging.getLogger(__name__)


def _enforce_assignment_hierarchy(
    db, actor, role, *, target_user_id: str | None, target_org_id: str
) -> None:
    """403 unless ``actor`` may hand ``role`` to an account in ``target_org_id``."""
    from ccure_platform.rbac.scope import check_role_assignment

    verdict = check_role_assignment(
        actor, role, target_user_id=target_user_id, target_org_id=target_org_id
    )
    if verdict.allowed:
        return
    if verdict.source == "legacy":
        raise HTTPException(status_code=403, detail="Cannot assign superadmin role")
    raise HTTPException(
        status_code=403,
        detail="Role assignment refused: " + ", ".join(verdict.violations),
    )


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
        # The email-risk verdict, so the administrator deciding whether to
        # approve this account can see *why* it was flagged rather than only
        # that it was. This is the half of disposable-email defence that the
        # blocklist cannot do: `radiant-flow.org` is on no list anywhere, and
        # a human looking at "domain registered 4 months ago, no web presence"
        # makes the call the automation cannot.
        "is_email_flagged": bool(getattr(user, "is_email_flagged", False)),
        "email_risk": getattr(user, "email_risk", None) or {},
        "flagged_at": getattr(user, "flagged_at", None),
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
        from ccure_platform.notifications.service import (
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

    if (
        db.query(User)
        .filter(username_matches(User.username, user_data.username))
        .first()
    ):
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(email_matches(User.email, email)).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    # Same mailbox, different spelling. `p.kumar+ops@gmail.com` and
    # `pkumar@gmail.com` deliver to one inbox, so treating them as two accounts
    # would let the farming hole reopen through the admin path.
    canonical = canonicalize_email(email)
    if canonical and db.query(User).filter(User.email_canonical == canonical).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    # Screened like any other new address. An administrator provisioning an
    # account is trusted, but a typo or a contractor handing over a throwaway
    # address is not a trust question — and if the domain really is wanted, the
    # remedy is one ALLOW rule rather than a hole in the check.
    verdict = assert_email_allowed(db, email, request=request, actor=current_user)

    role = db.query(Role).filter(Role.id == user_data.role_id).first()
    if not role:
        raise HTTPException(status_code=400, detail="Invalid role_id")

    # Assignment hierarchy (RBAC-5): decided by rbac/scope.py — the legacy rule while
    # the new model is off, the RBAC governance rules once it is switched on.
    _enforce_assignment_hierarchy(
        db, current_user, role, target_user_id=None, target_org_id=str(target_org_id)
    )

    # Resolve org slug for readable ID generation
    org = db.query(Organization).filter(Organization.id == target_org_id).first()
    org_slug = org.slug if org else target_org_id

    # Admin provisioning is itself the approval, and the admin sets the
    # password out-of-band, so both gates that self-registration must clear are
    # already satisfied here. Without this, adding the gates would have locked
    # every admin-created account out of its own login.
    new_user = User(
        id=gen_user_id(org_slug, user_data.username),  # e.g. usr_acm_alice_x9v1
        username=user_data.username,
        email=email,
        email_canonical=canonical or None,
        full_name=user_data.full_name,
        role_id=user_data.role_id,
        org_id=target_org_id,
        password_hash=hash_password(user_data.password),
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
        approved_by=str(current_user.id),
        is_email_flagged=verdict.flagged or verdict.blocked,
        email_risk=verdict.as_risk_payload(),
        flagged_at=utcnow() if (verdict.flagged or verdict.blocked) else None,
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

    _enforce_assignment_hierarchy(
        db,
        current_user,
        role,
        target_user_id=str(user.id),
        target_org_id=str(user.org_id),
    )

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


@router.get("/pending")
@router.get("/pending/")
def list_pending_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "read")),
):
    """
    Self-registered accounts awaiting approval, scoped to what the caller
    administers. These accounts cannot sign in until approve_user runs.
    """
    pending = (
        _scoped_users_query(db, current_user, scope="active")
        .filter(User.approved_at.is_(None))
        .order_by(User.created_at.desc())
        .all()
    )
    return [
        {
            "id": str(u.id),
            "username": u.username,
            "email": u.email,
            "full_name": u.full_name,
            "organization_id": str(u.org_id),
            "is_verified": u.is_verified,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            # Everything the reviewer needs to judge the address, alongside the
            # address itself. Without this the queue shows `safan76549@hutdot.com`
            # and a real user identically.
            "is_email_flagged": bool(getattr(u, "is_email_flagged", False)),
            "email_risk": getattr(u, "email_risk", None) or {},
        }
        for u in pending
    ]


def _allowlist_email_domain(db: Session, *, user: User, actor: User, reason=None):
    """
    Add this account's email domain to the platform-wide ALLOW list.

    Returns the domain that was allowed, or None if there was nothing to do.

    An existing rule is updated rather than duplicated, because `domain` is
    unique and a second INSERT would abort the approval transaction — the
    administrator would see a 500 on an action that was otherwise valid.
    """
    from ccure_platform.identity.email_domain_guard import extract_domain
    from db.models.email_security import VERDICT_ALLOW, EmailDomainRule

    domain = extract_domain(user.email or "")
    if not domain:
        return None

    existing = (
        db.query(EmailDomainRule).filter(EmailDomainRule.domain == domain).first()
    )
    note = reason or (f"Allowed while approving {user.username} ({user.id}).")

    if existing:
        existing.verdict = VERDICT_ALLOW
        existing.source = "approval"
        existing.reason = note
        existing.created_by = str(actor.id)
        existing.updated_at = utcnow()
    else:
        db.add(
            EmailDomainRule(
                domain=domain,
                verdict=VERDICT_ALLOW,
                source="approval",
                reason=note,
                created_by=str(actor.id),
            )
        )
    return domain


class ApproveUserSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Two different decisions, kept separate on purpose.
    #
    # "This person is fine" and "this domain is fine for everyone, forever" are
    # not the same judgement, and an approval screen that conflates them invites
    # an administrator who meant the first to accidentally make the second.
    # Allowlisting a throwaway domain platform-wide is not something anyone
    # should be able to do by clicking the same button they use to admit one
    # colleague.
    allowlist_domain: bool = False
    reason: Optional[str] = None


@router.post("/{user_id}/approve")
@router.post("/{user_id}/approve/")
def approve_user(
    user_id: str,
    request: Request,
    payload: ApproveUserSchema | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("users", "update")),
):
    """
    Approve a pending account, allowing it to sign in.

    Requires the mailbox to have been verified first. Approving an unverified
    account would activate a login for an address nobody has demonstrated
    control of, which is the whole failure this gate exists to prevent — so it
    is refused rather than treated as an override.

    The approved account keeps whatever role it was created with (`viewer` for
    self-registration). Granting scan execution stays a separate, explicit act
    through the role endpoint, so approval never silently confers it.

    `allowlist_domain` is the second, wider decision and defaults to False.
    Without it, approving a flagged account clears that one account and leaves
    the domain exactly as it was — so admitting a colleague whose employer got
    caught by an over-eager blocklist does not quietly open the door to every
    address at a throwaway service.
    """
    user = (
        _scoped_users_query(db, current_user, scope="active")
        .filter(User.id == user_id)
        .first()
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.approved_at is not None:
        return {"detail": "User is already approved"}

    if not user.is_verified:
        raise HTTPException(
            status_code=400,
            detail=(
                "This account's email address has not been verified yet. "
                "It cannot be approved until the owner confirms the mailbox."
            ),
        )

    user.approved_at = utcnow()
    user.approved_by = str(current_user.id)
    user.is_active = True
    user.updated_at = utcnow()

    # Approving the account clears its flag. The administrator has looked at the
    # address and decided; leaving a red badge on an account they just admitted
    # trains everyone to ignore badges.
    allowlisted_domain = None
    if user.is_email_flagged:
        user.is_email_flagged = False
        risk = dict(user.email_risk or {})
        risk["cleared_by"] = str(current_user.id)
        risk["cleared_at"] = utcnow().isoformat()
        user.email_risk = risk

    if payload is not None and payload.allowlist_domain:
        allowlisted_domain = _allowlist_email_domain(
            db,
            user=user,
            actor=current_user,
            reason=payload.reason,
        )

    log_audit_event(
        db,
        current_user,
        "user.approved",
        "user",
        str(user.id),
        {
            "approved_by": str(current_user.id),
            "role": getattr(user.role, "name", None),
            "allowlisted_domain": allowlisted_domain,
        },
        request,
    )
    if allowlisted_domain:
        log_audit_event(
            db,
            current_user,
            "admin.email_domain_allowlisted",
            "email_domain",
            allowlisted_domain,
            {"granted_via": "user_approval", "user_id": str(user.id)},
            request,
        )
    db.commit()

    if allowlisted_domain:
        # The guard keeps the rule set in a process-local cache with a TTL. An
        # administrator who just unblocked a domain should not have to wait it
        # out, and neither should the person trying to register.
        invalidate_cache()

    _notify_user_admin_action(
        db=db,
        current_user=current_user,
        target_user=user,
        action_title="User Approved",
        action_message=f"Account approved and sign-in enabled: {user.username}",
        fan_out_message=(
            f"Admin {current_user.username} approved account: {user.username}"
        ),
    )

    # Tell the account holder by email.
    #
    # The in-app notification above is only visible after a successful login,
    # which is precisely what this user could not do until a moment ago — so on
    # its own it tells them nothing. Without an email their only option is to
    # retry the login page until it stops refusing them.
    #
    # Dispatched through Celery and never awaited: the approval is already
    # committed, and a broken SMTP server must not turn an administrator's
    # decision into a 500.
    try:
        from config import AppConfig
        from ccure_platform.identity.mail_dispatch import dispatch_email

        dispatch_email(
            "account_approved",
            user.email,
            user.username,
            f"{AppConfig.FRONTEND_URL.rstrip('/')}/login",
            getattr(user.role, "name", None),
        )
    except Exception:
        # `log`, not `logger` — this module names it `log`. Getting that wrong
        # made the handler itself raise NameError, converting a mail-dispatch
        # hiccup into a 500 on an approval that had already been committed:
        # the account was live but the admin was told the operation failed.
        log.warning(
            "Could not queue account-approved email for user id=%s",
            user.id,
            exc_info=True,
        )

    return {"detail": "User approved", "id": str(user.id)}


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
    # Each module detaches its own references (ccure_platform/offboarding.py);
    # the platform no longer updates Audit's tables from here.
    run_user_purge_hooks(db, target_user_id)
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
