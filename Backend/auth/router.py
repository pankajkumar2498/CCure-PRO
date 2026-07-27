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
from typing import List, Optional, Union
from uuid import UUID

from auth.dependencies import get_current_user
from auth.email_utils import email_matches, normalize_email, username_matches
from auth.jwt_handler import (
    REFRESH_TOKEN_EXPIRE,
    create_access_token,
    create_download_ticket,
    create_refresh_token,
    decode_token,
    hash_password,
    refresh_access_token,
    revoke_refresh_token,
    validate_password_strength,
    verify_password,
)
from db.base import gen_org_id, gen_user_id, get_db
from db.models import Organization, RefreshTokenSession, Role, User
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, field_validator
from scan_helpers import limiter
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

router = APIRouter(prefix="/auth", tags=["Authentication"])
logger = logging.getLogger(__name__)
REFRESH_COOKIE_NAME = os.getenv("REFRESH_COOKIE_NAME", "ccure_refresh_token")
REFRESH_COOKIE_PATH = os.getenv("REFRESH_COOKIE_PATH", "/")
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
        return validate_password_strength(v)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return validate_password_strength(v)


class RefreshRequest(BaseModel):
    refresh_token: str | None = None


class LogoutRequest(BaseModel):
    refresh_token: str | None = None


class PermissionOut(BaseModel):
    resource: str
    action: str


class RoleOut(BaseModel):
    name: str
    permissions: list[PermissionOut]


class OrganizationOut(BaseModel):
    id: str | UUID | int
    name: str
    slug: str

    model_config = {"from_attributes": True}


class UserOut(BaseModel):
    id: str | UUID | int
    org_id: str | UUID | int | None = None
    username: str
    email: str
    created_at: str
    mfa_enabled: bool = False
    role: RoleOut | None = None
    organization: OrganizationOut | None = None

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"
    user: UserOut


class RefreshResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"


class MfaChallengeResponse(BaseModel):
    status: str = "mfa_required"
    mfa_token: str


class MfaVerifyRequest(BaseModel):
    mfa_token: str
    code: str


class MfaEmailRequest(BaseModel):
    mfa_token: str


class MfaConfirmRequest(BaseModel):
    code: str


class MfaDisableRequest(BaseModel):
    password: str


@router.post("/ticket")
def generate_ws_download_ticket(current_user: User = Depends(get_current_user)):
    """Generate a short-lived (60s) JWT ticket for WebSocket connections and PDF downloads."""
    ticket = create_download_ticket(current_user.id, current_user.username)
    return {"ticket": ticket}


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
    if REFRESH_COOKIE_PATH != "/auth":
        response.delete_cookie(
            key=REFRESH_COOKIE_NAME,
            path="/auth",
            domain=REFRESH_COOKIE_DOMAIN,
            samesite=REFRESH_COOKIE_SAMESITE,
            secure=REFRESH_COOKIE_SECURE,
        )


def _resolve_refresh_token(request: Request, token_from_body: str | None) -> str | None:
    return token_from_body or request.cookies.get(REFRESH_COOKIE_NAME)


@router.get("/check-username")
@limiter.limit("20/minute")
def check_username(request: Request, q: str, db: Session = Depends(get_db)):
    """Check if a username is available"""
    if len(q.strip()) < 3:
        return {"available": False}
    exists = db.query(User).filter(username_matches(User.username, q)).first()
    return {"available": not bool(exists)}


@router.get("/check-email")
@limiter.limit("20/minute")
def check_email(request: Request, q: str, db: Session = Depends(get_db)):
    """Check if an email is available"""
    if not q.strip() or "@" not in q:
        return {"available": False}
    exists = db.query(User).filter(email_matches(User.email, q)).first()
    return {"available": not bool(exists)}


@router.post("/register", response_model=TokenResponse, status_code=201)
@limiter.limit("5/minute")
def register(
    req: RegisterRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Create a new user account.
    Returns access + refresh tokens immediately so the user is logged in.
    """
    email = normalize_email(req.email)

    if db.query(User).filter(email_matches(User.email, email)).first():
        raise HTTPException(status_code=409, detail="Email already registered")

    if db.query(User).filter(username_matches(User.username, req.username)).first():
        raise HTTPException(status_code=409, detail="Username already taken")

    # For production auto-registration, place new users in the Self-Service Organization with the 'analyst' role.
    # This organization can be managed by superadmins and org_admins
    self_service_org = (
        db.query(Organization).filter(Organization.slug == "self-service").first()
    )

    # Create self-service org if it doesn't exist
    if not self_service_org:
        self_service_org = Organization(
            id=gen_org_id("self-service"),  # → org_self-service
            name="Self-Service Users",
            slug="self-service",
            plan="community",
            max_assets=100,
            max_users=50,
            is_active=True,
            settings={"description": "Organization for self-registered users"},
        )
        db.add(self_service_org)
        db.flush()

    default_role = db.query(Role).filter(Role.name == "analyst").first()

    if not default_role:
        raise HTTPException(status_code=500, detail="RBAC not seeded in production DB.")

    user = User(
        id=gen_user_id(
            self_service_org.slug, req.username.strip()
        ),  # → usr_sel_pankaj_x9v1
        username=req.username.strip(),
        email=email,
        password_hash=hash_password(req.password),
        org_id=self_service_org.id,
        role_id=default_role.id,
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
        raise HTTPException(
            status_code=400, detail="Registration failed: duplicate entry"
        )

    db.refresh(user)
    from core.audit import log_audit_event

    log_audit_event(
        db,
        user,
        "user.created",
        "user",
        str(user.id),
        request=request,
        status="success",
        changes={"source": "self_registration"},
    )
    db.commit()

    refresh_token = create_refresh_token(user.id, db, request=request)
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
            "mfa_enabled": user.mfa_enabled,
            "role": (
                {
                    "name": user.role.name,
                    "permissions": [
                        {
                            "resource": rp.permission.resource,
                            "action": rp.permission.action,
                        }
                        for rp in user.role.permissions
                    ],
                }
                if user.role
                else None
            ),
        },
    }


@router.post("/login", response_model=Union[TokenResponse, MfaChallengeResponse])
@limiter.limit("10/minute")
def login(
    req: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Authenticate with email + password.
    Returns access + refresh tokens on success.

    Organization Status Validation:
    - Users from deactivated organizations cannot log in.
    - This prevents new sessions from being created for inactive orgs.
    - Existing sessions are checked on every request in middleware.
    """
    import datetime

    from core.audit import log_audit_event
    from db.base import utcnow

    email = normalize_email(req.email)
    user = db.query(User).filter(email_matches(User.email, email)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if getattr(user, "is_deleted", False):
        log_audit_event(
            db,
            user,
            "user.login_failed",
            "user",
            str(user.id),
            request=request,
            status="denied",
            changes={"reason": "account deleted"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account deleted",
        )

    if not user.is_active:
        log_audit_event(
            db,
            user,
            "user.login_failed",
            "user",
            str(user.id),
            request=request,
            status="denied",
            changes={"reason": "account disabled"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account disabled",
        )

    # ─ Organization Status Check ────────────────────────────────────────────
    # Prevent login for users whose organization has been deactivated.
    # User statuses remain unchanged for reversibility.
    organization = db.query(Organization).filter(Organization.id == user.org_id).first()
    if organization and not organization.is_active:
        log_audit_event(
            db,
            user,
            "user.login_failed",
            "user",
            str(user.id),
            request=request,
            status="denied",
            changes={"reason": "organization deactivated"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your organization has been deactivated. Please contact support.",
        )

    if user.locked_until and user.locked_until > utcnow():
        log_audit_event(
            db,
            user,
            "user.login_failed",
            "user",
            str(user.id),
            request=request,
            status="denied",
            changes={"reason": "account locked"},
        )
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
            email,
            exc.__class__.__name__,
        )
        is_valid = False

    if not is_valid:
        user.failed_login_count += 1
        if user.failed_login_count >= 5:
            user.locked_until = utcnow() + datetime.timedelta(minutes=15)
            log_audit_event(
                db,
                user,
                "user.locked",
                "user",
                str(user.id),
                request=request,
                status="failure",
                changes={"reason": "too many failed attempts"},
            )

        log_audit_event(
            db,
            user,
            "user.login_failed",
            "user",
            str(user.id),
            request=request,
            status="failure",
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Success
    user.failed_login_count = 0
    user.locked_until = None

    if user.mfa_enabled:
        from auth.jwt_handler import create_mfa_challenge_token

        mfa_token = create_mfa_challenge_token(
            user_id=user.id,
            username=user.username,
            role=getattr(user.role, "name", None),
            org_id=user.org_id,
        )
        log_audit_event(
            db,
            user,
            "user.mfa_challenge_issued",
            "user",
            str(user.id),
            request=request,
            status="success",
        )
        db.commit()
        return {"status": "mfa_required", "mfa_token": mfa_token}

    user.last_login_at = utcnow()
    log_audit_event(
        db, user, "user.login", "user", str(user.id), request=request, status="success"
    )
    db.commit()

    refresh_token = create_refresh_token(user.id, db, request=request)
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
            "mfa_enabled": user.mfa_enabled,
            "role": (
                {
                    "name": user.role.name,
                    "permissions": [
                        {
                            "resource": rp.permission.resource,
                            "action": rp.permission.action,
                        }
                        for rp in user.role.permissions
                    ],
                }
                if user.role
                else None
            ),
        },
    }


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    req: LogoutRequest | None = None,
    db: Session = Depends(get_db),
):
    """
    Revoke the presented refresh token server-side.
    """
    from core.audit import log_audit_event

    refresh_token = _resolve_refresh_token(request, req.refresh_token if req else None)
    if not refresh_token:
        _clear_refresh_cookie(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    payload = decode_token(refresh_token)
    session_row = None
    user = None
    if payload and payload.get("type") == "refresh" and payload.get("jti"):
        session_row = (
            db.query(RefreshTokenSession)
            .filter(RefreshTokenSession.token_jti == payload.get("jti"))
            .first()
        )
        if session_row:
            user = db.query(User).filter(User.id == session_row.user_id).first()

    revoked = revoke_refresh_token(refresh_token, db)
    _clear_refresh_cookie(response)
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    if user:
        log_audit_event(
            db,
            user,
            "user.logout",
            "session",
            str(session_row.id) if session_row else str(user.id),
            request=request,
            status="success",
            changes={"user_id": str(user.id)},
        )
        db.commit()
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
        "mfa_enabled": current_user.mfa_enabled,
        "role": (
            {
                "name": current_user.role.name,
                "permissions": [
                    {"resource": rp.permission.resource, "action": rp.permission.action}
                    for rp in current_user.role.permissions
                ],
            }
            if current_user.role
            else None
        ),
        "organization": (
            {
                "id": str(current_user.organization.id),
                "name": current_user.organization.name,
                "slug": current_user.organization.slug,
            }
            if getattr(current_user, "organization", None)
            else None
        ),
    }


@router.post("/refresh", response_model=RefreshResponse)
def refresh(
    request: Request,
    response: Response,
    req: RefreshRequest | None = None,
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

    token_bundle = refresh_access_token(refresh_token, db, request=request)
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


@router.post("/forgot-password")
@limiter.limit("3/minute")
def forgot_password(
    req: ForgotPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Submits a password reset request.
    Generates a secure token, hashes it, saves it to the database,
    and dispatches a Celery task to send the email.

    Always returns 200 OK to prevent account enumeration.
    """
    import hashlib
    import secrets
    from datetime import datetime, timedelta, timezone

    from config import AppConfig
    from core.audit import log_audit_event
    from core.tasks import send_password_reset_email_task
    from db.models import PasswordResetToken

    email = normalize_email(req.email)
    logger.info("Forgot password requested for: %s", email)

    user = db.query(User).filter(email_matches(User.email, email)).first()

    if not user:
        logger.info("Email '%s' is not registered in the database.", email)
    else:
        logger.info("Found registered user: %s (ID: %s)", user.username, user.id)

    if user:
        # Generate token
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

        # Store in db
        reset_token = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
        )
        db.add(reset_token)

        # Log audit trail
        log_audit_event(
            db=db,
            user=user,
            action="user.forgot_password_requested",
            resource_type="user",
            resource_id=str(user.id),
            request=request,
            status="success",
        )
        db.commit()

        # Build reset link using configuration frontend URL
        reset_link = (
            f"{AppConfig.FRONTEND_URL.rstrip('/')}/reset-password?token={token}"
        )

        # Trigger background task
        send_password_reset_email_task.delay(user.email, user.username, reset_link)

    return {
        "detail": "If this email is registered, you will receive a reset link shortly."
    }


@router.post("/reset-password")
def reset_password_endpoint(
    req: ResetPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Resets the user's password using the secure token.
    Validates token presence, expiration, updates the user's password,
    invalidates all current user sessions, and revokes the token.
    """
    import hashlib
    from datetime import datetime, timezone

    from auth.jwt_handler import hash_password
    from core.audit import log_audit_event
    from db.models import PasswordResetToken, RefreshTokenSession

    token_hash = hashlib.sha256(req.token.encode("utf-8")).hexdigest()

    # Find the token in the database
    reset_token = (
        db.query(PasswordResetToken)
        .filter(PasswordResetToken.token_hash == token_hash)
        .first()
    )
    if not reset_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token.",
        )

    # Check expiration
    if reset_token.expires_at <= datetime.now(timezone.utc):
        db.delete(reset_token)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token.",
        )

    # Fetch user
    user = db.query(User).filter(User.id == reset_token.user_id).first()
    if not user:
        db.delete(reset_token)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found.",
        )

    # Update user password
    user.password_hash = hash_password(req.password)

    # Invalidate all active sessions for the user
    db.query(RefreshTokenSession).filter(RefreshTokenSession.user_id == user.id).delete(
        synchronize_session=False
    )

    # Delete the reset token (single-use constraint)
    db.delete(reset_token)

    # Log audit trail
    log_audit_event(
        db=db,
        user=user,
        action="user.password_reset_completed",
        resource_type="user",
        resource_id=str(user.id),
        changes={"password_hash": "modified"},
        request=request,
        status="success",
    )

    db.commit()

    return {"detail": "Your password has been reset successfully."}


# ── MFA Helper Cryptographic Functions ────────────────────────────────────────


def encrypt_secret(plain_secret: str) -> str:
    """Symmetrically encrypt the secret key using Fernet."""
    from config import AppConfig
    from cryptography.fernet import Fernet

    f = Fernet(AppConfig.MFA_KEY)
    return f.encrypt(plain_secret.encode()).decode()


def decrypt_secret(encrypted_secret: str) -> str:
    """Symmetrically decrypt the secret key using Fernet."""
    from config import AppConfig
    from cryptography.fernet import Fernet

    f = Fernet(AppConfig.MFA_KEY)
    return f.decrypt(encrypted_secret.encode()).decode()


# ── MFA Endpoints ────────────────────────────────────────────────────────────


@router.post("/login/send-email-otp")
@limiter.limit("5/minute")
def send_email_otp(
    req: MfaEmailRequest, request: Request, db: Session = Depends(get_db)
):
    """
    Generate and email a 6-digit verification code fallback.
    Rate limited to 5 requests/minute.
    """
    import secrets
    from datetime import timedelta

    from core.tasks import send_mfa_otp_task
    from db.base import utcnow

    payload = decode_token(req.mfa_token)
    if not payload or payload.get("type") != "mfa_challenge":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired challenge token.",
        )

    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    if not user or getattr(user, "is_deleted", False) or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired challenge token.",
        )

    # Generate 6-digit random code
    code = f"{secrets.randbelow(1000000):06d}"

    # Save hashed code to database
    user.email_otp_hash = hash_password(code)
    user.email_otp_expires_at = utcnow() + timedelta(minutes=5)
    db.commit()

    # Dispatch Celery task to send email
    send_mfa_otp_task.delay(user.email, user.username, code)

    return {"success": True}


@router.post("/login/verify-mfa", response_model=TokenResponse)
@limiter.limit("5/minute")
def verify_mfa(
    req: MfaVerifyRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Verify the MFA code (App TOTP, Email OTP, or Recovery Backup Code).
    Rate limited to 5 requests/minute.
    """
    from core.audit import log_audit_event
    from db.base import utcnow

    payload = decode_token(req.mfa_token)
    if not payload or payload.get("type") != "mfa_challenge":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired challenge token.",
        )

    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    if not user or getattr(user, "is_deleted", False) or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired challenge token.",
        )

    # Stateless security clearance: fetch temporary Email OTP hash and clear immediately
    temp_hash = user.email_otp_hash
    temp_expires = user.email_otp_expires_at
    user.email_otp_hash = None
    user.email_otp_expires_at = None
    db.commit()

    code = req.code.strip()
    verified = False
    verification_method = None

    # 1. Try Authenticator App TOTP
    if user.totp_secret:
        try:
            import pyotp

            decrypted = decrypt_secret(user.totp_secret)
            totp = pyotp.TOTP(decrypted)
            # valid_window=1 allows codes from previous or next 30-sec interval to combat clock drift
            if totp.verify(code, valid_window=1):
                verified = True
                verification_method = "totp"
        except Exception as e:
            logger.error(
                f"Error during TOTP verification for user {user.id}: {e}", exc_info=True
            )

    # 2. Try Email OTP
    if not verified and temp_hash and temp_expires:
        if temp_expires > utcnow():
            if verify_password(code, temp_hash):
                verified = True
                verification_method = "email_otp"

    # 3. Try Backup Recovery Code
    if not verified and user.mfa_backup_codes:
        # User backup codes list is stored as JSON list of hashes
        matched_hash = None
        for h in user.mfa_backup_codes:
            if verify_password(code, h):
                matched_hash = h
                break

        if matched_hash:
            # Code matched! Remove it from list (single-use constraint)
            codes = list(user.mfa_backup_codes)
            codes.remove(matched_hash)
            user.mfa_backup_codes = codes
            verified = True
            verification_method = "backup_code"
            log_audit_event(
                db=db,
                user=user,
                action="user.mfa_recovery_used",
                resource_type="user",
                resource_id=str(user.id),
                request=request,
                status="success",
            )
            db.commit()

    if not verified:
        log_audit_event(
            db=db,
            user=user,
            action="user.mfa_failed",
            resource_type="user",
            resource_id=str(user.id),
            request=request,
            status="failure",
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid verification code",
        )

    # Login succeeded! Complete session establishment
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    log_audit_event(
        db=db,
        user=user,
        action="user.login",
        resource_type="user",
        resource_id=str(user.id),
        request=request,
        status="success",
        changes={"mfa_method": verification_method},
    )
    db.commit()

    refresh_token = create_refresh_token(user.id, db, request=request)
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
            "mfa_enabled": user.mfa_enabled,
            "role": (
                {
                    "name": user.role.name,
                    "permissions": [
                        {
                            "resource": rp.permission.resource,
                            "action": rp.permission.action,
                        }
                        for rp in user.role.permissions
                    ],
                }
                if user.role
                else None
            ),
        },
    }


@router.post("/mfa/enable")
def enable_mfa(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """
    Initiates MFA setup by generating a TOTP secret and rendering it as a QR code.
    Accessible only to authenticated users. If MFA is already active, returns 400.
    """
    import base64
    import io

    import pyotp
    import qrcode

    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled",
        )

    secret = pyotp.random_base32()
    encrypted_secret = encrypt_secret(secret)
    current_user.totp_secret = encrypted_secret
    db.commit()

    provisioning_url = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.email, issuer_name="CCure Audit PRO"
    )

    # Generate QR Code as Base64 Data URI
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(provisioning_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()
    qr_data_uri = f"data:image/png;base64,{qr_base64}"

    return {"secret": secret, "qr_code": qr_data_uri}


@router.post("/mfa/confirm")
def confirm_mfa(
    req: MfaConfirmRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Confirms the setup code and enables MFA for the user.
    Generates backup codes and revokes other sessions.
    """
    import secrets

    import pyotp
    from core.audit import log_audit_event

    if not current_user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA setup has not been initiated",
        )

    try:
        decrypted = decrypt_secret(current_user.totp_secret)
        totp = pyotp.TOTP(decrypted)
        is_valid = totp.verify(req.code.strip(), valid_window=1)
    except Exception:
        is_valid = False

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code",
        )

    # Generate 8 recovery codes
    plain_backups = [secrets.token_hex(4).upper() for _ in range(8)]
    hashed_backups = [hash_password(code) for code in plain_backups]

    current_user.mfa_enabled = True
    current_user.mfa_backup_codes = hashed_backups

    # Revoke all other active sessions for user (session isolation)
    db.query(RefreshTokenSession).filter(
        RefreshTokenSession.user_id == current_user.id
    ).delete(synchronize_session=False)

    log_audit_event(
        db=db,
        user=current_user,
        action="user.mfa_enabled",
        resource_type="user",
        resource_id=str(current_user.id),
        request=request,
        status="success",
    )
    db.commit()

    return {"backup_codes": plain_backups}


@router.post("/mfa/disable")
def disable_mfa(
    req: MfaDisableRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Disable MFA. Requires password validation for safety.
    """
    from core.audit import log_audit_event

    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled",
        )

    if not verify_password(req.password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password",
        )

    current_user.mfa_enabled = False
    current_user.totp_secret = None
    current_user.mfa_backup_codes = []
    current_user.email_otp_hash = None
    current_user.email_otp_expires_at = None

    # Revoke all active sessions for user
    db.query(RefreshTokenSession).filter(
        RefreshTokenSession.user_id == current_user.id
    ).delete(synchronize_session=False)

    log_audit_event(
        db=db,
        user=current_user,
        action="user.mfa_disabled",
        resource_type="user",
        resource_id=str(current_user.id),
        request=request,
        status="success",
    )
    db.commit()

    return {"success": True}
