"""
auth/router.py
--------------
FastAPI router that wires up all authentication endpoints:

    POST  /auth/register    → create a new account
    POST  /auth/login       → get access + refresh tokens
    POST  /auth/logout      → revoke refresh token
    GET   /auth/me          → current user profile
    POST  /auth/refresh     → rotate refresh token and issue new access token
"""

import logging
import os

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from typing import Optional, List, Union

from auth.dependencies import get_current_user
from auth.jwt_handler import (
    REFRESH_TOKEN_EXPIRE,
    create_access_token,
    create_refresh_token,
    hash_password,
    refresh_access_token,
    revoke_refresh_token,
    verify_password,
)
from db.base import get_db
from db.models import User, Organization, Role

router = APIRouter(prefix="/auth", tags=["Authentication"])
logger = logging.getLogger(__name__)
REFRESH_COOKIE_NAME = os.getenv("REFRESH_COOKIE_NAME", "ccure_refresh_token")
REFRESH_COOKIE_PATH = os.getenv("REFRESH_COOKIE_PATH", "/auth")
REFRESH_COOKIE_SAMESITE = os.getenv("REFRESH_COOKIE_SAMESITE", "lax")
REFRESH_COOKIE_SECURE = os.getenv("REFRESH_COOKIE_SECURE", "false").lower() == "true"
REFRESH_COOKIE_DOMAIN = os.getenv("REFRESH_COOKIE_DOMAIN") or None


# ── Request / Response Schemas ────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

    @field_validator("username")
    @classmethod
    def username_length(cls, v: str) -> str:
        if len(v.strip()) < 3:
            raise ValueError("Username must be at least 3 characters")
        return v.strip()

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(not c.isalnum() for c in v):
            raise ValueError("Password must contain at least one special character")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: Optional[str] = None


class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = None


class PermissionOut(BaseModel):
    resource: str
    action: str

class RoleOut(BaseModel):
    name: str
    permissions: List[PermissionOut]

class OrganizationOut(BaseModel):
    id: Union[str, int]
    name: str
    slug: str

    model_config = {"from_attributes": True}

class UserOut(BaseModel):
    id: Union[str, int]
    org_id: Optional[Union[str, int]] = None
    username: str
    email: str
    created_at: str
    role: Optional[RoleOut] = None
    organization: Optional[OrganizationOut] = None

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    user: UserOut


class RefreshResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"


# ── Endpoints ─────────────────────────────────────────────────────────────────

def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=refresh_token,
        httponly=True,
        secure=REFRESH_COOKIE_SECURE,
        samesite=REFRESH_COOKIE_SAMESITE,
        max_age=int(REFRESH_TOKEN_EXPIRE.total_seconds()),
        path=REFRESH_COOKIE_PATH,
        domain=REFRESH_COOKIE_DOMAIN,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=REFRESH_COOKIE_NAME,
        path=REFRESH_COOKIE_PATH,
        domain=REFRESH_COOKIE_DOMAIN,
        samesite=REFRESH_COOKIE_SAMESITE,
        secure=REFRESH_COOKIE_SECURE,
    )


def _resolve_refresh_token(request: Request, token_from_body: Optional[str]) -> Optional[str]:
    return token_from_body or request.cookies.get(REFRESH_COOKIE_NAME)

@router.post("/register", response_model=TokenResponse, status_code=201)
def register(req: RegisterRequest, response: Response, db: Session = Depends(get_db)):
    """
    Create a new user account.
    Returns access + refresh tokens immediately so the user is logged in.
    """
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=409, detail="Email already registered")

    if db.query(User).filter(User.username == req.username.strip()).first():
        raise HTTPException(status_code=409, detail="Username already taken")

    # For production auto-registration, place new users in the Self-Service Organization with the 'analyst' role.
    # This organization can be managed by superadmins and org_admins
    self_service_org = db.query(Organization).filter(Organization.slug == "self-service").first()
    
    # Create self-service org if it doesn't exist
    if not self_service_org:
        self_service_org = Organization(
            name="Self-Service Users",
            slug="self-service",
            plan="community",
            max_assets=100,
            max_users=50,
            is_active=True,
            settings={"description": "Organization for self-registered users"}
        )
        db.add(self_service_org)
        db.flush()
    
    default_role = db.query(Role).filter(Role.name == "analyst").first()
    
    if not default_role:
        raise HTTPException(status_code=500, detail="RBAC not seeded in production DB.")

    user = User(
        username=req.username.strip(),
        email=req.email,
        password_hash=hash_password(req.password),
        org_id=self_service_org.id,
        role_id=default_role.id
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        error_text = str(exc).lower()
        if "email" in error_text:
            raise HTTPException(status_code=409, detail="Email already registered")
        if "username" in error_text:
            raise HTTPException(status_code=409, detail="Username already taken")
        raise HTTPException(status_code=400, detail="Registration failed: duplicate entry")

    db.refresh(user)
    refresh_token = create_refresh_token(user.id, db)
    _set_refresh_cookie(response, refresh_token)

    return {
        "access_token": create_access_token(
            str(user.id),
            user.username,
            role=getattr(user.role, "name", None),
            org_id=user.org_id,
        ),
        "user": {
            "id": str(user.id),
            "org_id": str(user.org_id),
            "username": user.username,
            "email": user.email,
            "created_at": user.created_at.isoformat(),
            "role": {
                "name": user.role.name,
                "permissions": [
                    {"resource": rp.permission.resource, "action": rp.permission.action}
                    for rp in user.role.permissions
                ]
            } if user.role else None
        },
    }


@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    """
    Authenticate with email + password.
    Returns access + refresh tokens on success.
    """
    from core.audit import log_audit_event
    from db.base import utcnow
    import datetime

    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if getattr(user, "is_deleted", False):
        log_audit_event(db, user, "user.login_failed", request=request, status="denied", changes={"reason": "account deleted"})
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account deleted",
        )

    if not user.is_active:
        log_audit_event(db, user, "user.login_failed", request=request, status="denied", changes={"reason": "account disabled"})
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account disabled",
        )

    if user.locked_until and user.locked_until > utcnow():
        log_audit_event(db, user, "user.login_failed", request=request, status="denied", changes={"reason": "account locked"})
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account locked temporarily",
        )

    try:
        is_valid = verify_password(req.password, user.password_hash)
    except Exception as exc:
        logger.warning(
            "Password verification failed for login attempt on email=%s: %s",
            req.email,
            exc.__class__.__name__,
        )
        is_valid = False

    if not is_valid:
        user.failed_login_count += 1
        if user.failed_login_count >= 5:
            user.locked_until = utcnow() + datetime.timedelta(minutes=15)
            log_audit_event(db, user, "user.locked", request=request, status="failure", changes={"reason": "too many failed attempts"})
        
        log_audit_event(db, user, "user.login_failed", request=request, status="failure")
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Success
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    log_audit_event(db, user, "user.login", request=request, status="success")
    db.commit()

    refresh_token = create_refresh_token(user.id, db)
    _set_refresh_cookie(response, refresh_token)

    return {
        "access_token": create_access_token(
            str(user.id),
            user.username,
            role=getattr(user.role, "name", None),
            org_id=user.org_id,
        ),
        "user": {
            "id": str(user.id),
            "org_id": str(user.org_id),
            "username": user.username,
            "email": user.email,
            "created_at": user.created_at.isoformat(),
            "role": {
                "name": user.role.name,
                "permissions": [
                    {"resource": rp.permission.resource, "action": rp.permission.action}
                    for rp in user.role.permissions
                ]
            } if user.role else None
        },
    }


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    req: Optional[LogoutRequest] = None,
    db: Session = Depends(get_db),
):
    """
    Revoke the presented refresh token server-side.
    """
    refresh_token = _resolve_refresh_token(request, req.refresh_token if req else None)
    if not refresh_token:
        _clear_refresh_cookie(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    revoked = revoke_refresh_token(refresh_token, db)
    _clear_refresh_cookie(response)
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    return {"detail": "Logged out successfully."}


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    """
    Return the profile of the currently authenticated user.
    Requires: Authorization: Bearer <access_token>
    """
    return {
        "id": str(current_user.id),
        "org_id": str(current_user.org_id),
        "username": current_user.username,
        "email": current_user.email,
        "created_at": current_user.created_at.isoformat(),
        "role": {
            "name": current_user.role.name,
            "permissions": [
                {"resource": rp.permission.resource, "action": rp.permission.action}
                for rp in current_user.role.permissions
            ]
        } if current_user.role else None,
        "organization": {
            "id": str(current_user.organization.id),
            "name": current_user.organization.name,
            "slug": current_user.organization.slug,
        } if getattr(current_user, "organization", None) else None,
    }


@router.post("/refresh", response_model=RefreshResponse)
def refresh(
    request: Request,
    response: Response,
    req: Optional[RefreshRequest] = None,
    db: Session = Depends(get_db),
):
    """
    Rotate a valid refresh token and return a new access token + refresh token.
    """
    refresh_token = _resolve_refresh_token(request, req.refresh_token if req else None)
    if not refresh_token:
        _clear_refresh_cookie(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    token_bundle = refresh_access_token(refresh_token, db)
    if not token_bundle:
        _clear_refresh_cookie(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    if token_bundle.get("refresh_token"):
        _set_refresh_cookie(response, token_bundle["refresh_token"])
    token_bundle["refresh_token"] = None
    return token_bundle
