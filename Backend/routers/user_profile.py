"""
routers/user_profile.py
─────────────────────────────────────────────────────────────────────────────
User profile, preferences, and session management endpoints.

Endpoints
─────────
  GET    /user/profile                    → Get current user profile
  PUT    /user/profile                    → Update user profile (name, email, phone)
  POST   /user/change-password            → Change password
  GET    /user/preferences                → Get user preferences
  PUT    /user/preferences                → Update user preferences
  GET    /user/sessions                   → List active sessions (refresh token sessions)
  DELETE /user/sessions                   → Revoke every session except this one
  DELETE /user/sessions/{session_id}      → Revoke a session
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from auth.dependencies import get_current_user
from auth.email_domain_guard import assert_email_allowed
from auth.email_utils import canonicalize_email, email_matches, normalize_email
from auth.jwt_handler import hash_password, verify_password
from core.audit import log_audit_event
from db.base import get_db, utcnow
from db.models import RefreshTokenSession, User
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.orm import Session

router = APIRouter(prefix="/user", tags=["User Profile & Preferences"])
logger = logging.getLogger(__name__)


# ── Request/Response Models ───────────────────────────────────────────────────


class ProfileUpdateRequest(BaseModel):
    """Update user profile information."""

    full_name: str | None = None
    email: EmailStr | None = None

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v):
        if v is not None and len(v.strip()) == 0:
            raise ValueError("Full name cannot be empty")
        return v.strip() if v else None


class ChangePasswordRequest(BaseModel):
    """Request to change password."""

    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v):
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(not c.isalnum() for c in v):
            raise ValueError("Password must contain at least one special character")
        return v


class PreferencesRequest(BaseModel):
    """Update user preferences."""

    theme: str | None = None  # "light", "dark"
    default_scan_type: str | None = (
        None  # "host-discovery", "asset", "vulnerability_audit", "credentialed"
    )
    email_alerts: bool | None = None
    in_app_alerts: bool | None = None
    timezone: str | None = None
    sidebar_collapsed: bool | None = None
    default_rows_per_page: int | None = None

    @field_validator("theme")
    @classmethod
    def validate_theme(cls, v):
        if v is not None and v not in ["light", "dark"]:
            raise ValueError("Theme must be 'light' or 'dark'")
        return v

    @field_validator("default_scan_type")
    @classmethod
    def validate_scan_type(cls, v):
        valid_types = [
            "host-discovery",
            "asset",
            "vulnerability_audit",
            "advanced",
            "credentialed",
        ]
        if v is not None and v not in valid_types:
            raise ValueError(f"Scan type must be one of {valid_types}")
        return v


class UserProfileResponse(BaseModel):
    """User profile information."""

    id: str
    username: str
    email: str
    full_name: str | None
    organization_name: str
    role_name: str
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime
    avatar_url: str | None

    class Config:
        from_attributes = True


class UserPreferencesResponse(BaseModel):
    """User preferences."""

    theme: str = "light"
    default_scan_type: str = "asset"
    email_alerts: bool = True
    in_app_alerts: bool = True
    timezone: str = "UTC"
    sidebar_collapsed: bool = False
    default_rows_per_page: int = 10

    class Config:
        from_attributes = True


class SessionResponse(BaseModel):
    """Active session information."""

    session_id: int
    ip_address: str | None
    device_info: dict
    issued_at: datetime
    expires_at: datetime
    is_current: bool  # True if this is the session from the current request

    class Config:
        from_attributes = True


# ── Helper Functions ──────────────────────────────────────────────────────────


def _serialize_profile(user: User) -> UserProfileResponse:
    """Convert User model to ProfileResponse."""
    return UserProfileResponse(
        id=str(user.id),
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        organization_name=user.organization.name if user.organization else "N/A",
        role_name=user.role.name if user.role else "N/A",
        is_active=user.is_active,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
        avatar_url=user.avatar_url,
    )


def _get_user_preferences(user: User) -> UserPreferencesResponse:
    """Merge stored preferences with defaults."""
    stored = user.preferences or {}
    defaults = {
        "theme": "light",
        "default_scan_type": "asset",
        "email_alerts": True,
        "in_app_alerts": True,
        "timezone": "UTC",
        "sidebar_collapsed": False,
        "default_rows_per_page": 10,
    }
    merged = {**defaults, **stored}
    return UserPreferencesResponse(**merged)


def _current_session_jti(request: Request) -> str | None:
    """
    The refresh-token jti belonging to the request being served, or None.

    Needed because `is_current` cannot be answered from the access token: that
    token carries the user, not the session, and a user may hold several. The
    refresh token is the thing that identifies *this* session, and the browser
    sends it as an HttpOnly cookie on every same-site request.

    Read-only and forgiving. A caller with no cookie — an API client holding
    only a bearer token, say — simply gets `is_current: false` on every row,
    which is honest: there is no browser session to point at. It must never
    raise, because failing to identify the current session is not a reason to
    refuse to list sessions.
    """
    from auth.router import REFRESH_COOKIE_NAME
    from ccure_platform.identity.tokens import ISSUER, REFRESH, USER_AUDIENCE, verify

    token = request.cookies.get(REFRESH_COOKIE_NAME)
    if not token:
        return None
    try:
        payload = verify(
            token, expected_kind=REFRESH, issuer=ISSUER, audience=USER_AUDIENCE
        )
    except Exception:
        return None
    if not payload:
        return None
    return payload.get("jti")


def _extract_session_info(
    refresh_token_session: RefreshTokenSession, current_token_jti: str | None = None
) -> SessionResponse:
    """Convert RefreshTokenSession to SessionResponse."""
    device_info = refresh_token_session.device_info or {}
    return SessionResponse(
        session_id=refresh_token_session.id,
        ip_address=(
            str(refresh_token_session.ip_address)
            if refresh_token_session.ip_address
            else None
        ),
        device_info=device_info,
        issued_at=refresh_token_session.issued_at,
        expires_at=refresh_token_session.expires_at,
        is_current=refresh_token_session.token_jti == current_token_jti,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/profile", response_model=UserProfileResponse)
def get_profile(
    current_user: User = Depends(get_current_user),
):
    """
    Get current user's profile information.

    Returns user details including name, email, organization, role, and account status.
    """
    return _serialize_profile(current_user)


@router.put("/profile", response_model=UserProfileResponse)
def update_profile(
    req: ProfileUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Update user profile information (full name, email).

    Only non-null fields in the request are updated.
    """
    changes = {}

    if req.full_name is not None:
        if req.full_name != current_user.full_name:
            changes["full_name"] = f"{current_user.full_name} → {req.full_name}"
            current_user.full_name = req.full_name

    if req.email is not None:
        email = normalize_email(req.email)
        if email != current_user.email:
            # Check if email is already in use
            existing = (
                db.query(User)
                .filter(email_matches(User.email, email), User.id != current_user.id)
                .first()
            )
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email address is already in use by another account",
                )

            # The same mailbox spelled differently is the same mailbox.
            canonical = canonicalize_email(email)
            if canonical:
                clash = (
                    db.query(User)
                    .filter(
                        User.email_canonical == canonical,
                        User.id != current_user.id,
                    )
                    .first()
                )
                if clash:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Email address is already in use by another account",
                    )

            # Screened, because this is a new address entering the system — the
            # same event as a registration, just from an account that already
            # exists. Leaving it unscreened would make profile-edit the obvious
            # way around the check: register with a real address, then move to a
            # throwaway one.
            verdict = assert_email_allowed(
                db, email, request=request, actor=current_user
            )

            changes["email"] = f"{current_user.email} -> {email}"
            current_user.email = email
            current_user.email_canonical = canonical or None
            current_user.email_risk = verdict.as_risk_payload()
            if verdict.flagged or verdict.blocked:
                current_user.is_email_flagged = True
                current_user.flagged_at = utcnow()

    if changes:
        log_audit_event(
            db,
            current_user,
            "user.profile_updated",
            "user",
            str(current_user.id),
            request=request,
            status="success",
            changes=changes,
        )
        db.commit()
        db.refresh(current_user)
        logger.info(f"User {current_user.username} updated profile: {changes}")

    return _serialize_profile(current_user)


@router.post("/change-password", status_code=200)
def change_password(
    req: ChangePasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Change the current user's password.

    Requires verification of the current password before setting a new one.
    """
    # Verify current password
    if not verify_password(req.current_password, current_user.password_hash):
        log_audit_event(
            db,
            current_user,
            "user.password_change_failed",
            "user",
            str(current_user.id),
            request=request,
            status="denied",
            changes={"reason": "invalid current password"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )

    # Check that new password is different from current
    if verify_password(req.new_password, current_user.password_hash):
        log_audit_event(
            db,
            current_user,
            "user.password_change_failed",
            "user",
            str(current_user.id),
            request=request,
            status="denied",
            changes={"reason": "new password matches current password"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from current password",
        )

    # Update password
    current_user.password_hash = hash_password(req.new_password)
    current_user.failed_login_count = 0  # Reset failed attempts
    log_audit_event(
        db,
        current_user,
        "user.password_changed",
        "user",
        str(current_user.id),
        request=request,
        status="success",
        changes={"detail": "User changed their password"},
    )
    db.commit()
    logger.info(f"User {current_user.username} changed their password")

    return {"detail": "Password changed successfully"}


@router.get("/preferences", response_model=UserPreferencesResponse)
def get_preferences(
    current_user: User = Depends(get_current_user),
):
    """
    Get current user's preferences (theme, default scan type, notifications, etc.).

    Returns merged preferences with sensible defaults.
    """
    return _get_user_preferences(current_user)


@router.put("/preferences", response_model=UserPreferencesResponse)
def update_preferences(
    req: PreferencesRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Update user preferences.

    Only non-null fields in the request are updated. Preferences are stored in JSONB
    so you can add any custom fields without schema migration.
    """
    stored = current_user.preferences or {}
    changes = {}

    # Update only non-null fields
    if req.theme is not None and req.theme != stored.get("theme"):
        changes["theme"] = req.theme
        stored["theme"] = req.theme

    if req.default_scan_type is not None and req.default_scan_type != stored.get(
        "default_scan_type"
    ):
        changes["default_scan_type"] = req.default_scan_type
        stored["default_scan_type"] = req.default_scan_type

    if req.email_alerts is not None and req.email_alerts != stored.get("email_alerts"):
        changes["email_alerts"] = req.email_alerts
        stored["email_alerts"] = req.email_alerts

    if req.in_app_alerts is not None and req.in_app_alerts != stored.get(
        "in_app_alerts"
    ):
        changes["in_app_alerts"] = req.in_app_alerts
        stored["in_app_alerts"] = req.in_app_alerts

    if req.timezone is not None and req.timezone != stored.get("timezone"):
        changes["timezone"] = req.timezone
        stored["timezone"] = req.timezone

    if req.sidebar_collapsed is not None and req.sidebar_collapsed != stored.get(
        "sidebar_collapsed"
    ):
        changes["sidebar_collapsed"] = req.sidebar_collapsed
        stored["sidebar_collapsed"] = req.sidebar_collapsed

    if (
        req.default_rows_per_page is not None
        and req.default_rows_per_page != stored.get("default_rows_per_page")
    ):
        changes["default_rows_per_page"] = req.default_rows_per_page
        stored["default_rows_per_page"] = req.default_rows_per_page

    if changes:
        from sqlalchemy.orm.attributes import flag_modified

        current_user.preferences = stored
        flag_modified(current_user, "preferences")
        log_audit_event(
            db,
            current_user,
            "user.preferences_updated",
            "user",
            str(current_user.id),
            request=request,
            status="success",
            changes=changes,
        )
        db.commit()
        db.refresh(current_user)
        logger.info(f"User {current_user.username} updated preferences: {changes}")

    return _get_user_preferences(current_user)


@router.get("/sessions", response_model=list[SessionResponse])
def get_sessions(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List active sessions for the current user.

    This product allows an account to be signed in on any number of devices at
    once, which is a deliberate choice rather than an oversight — capping it
    would push people into sharing one browser or logging each other out, and
    neither makes anything safer. What that choice *requires* is that the owner
    of an account can see where it is signed in and end any of those sessions,
    which is what this endpoint and the two below are for.

    Expired rows are filtered as well as revoked ones: a row past its
    expires_at cannot be refreshed, so listing it would show a session that
    does not exist and invite someone to revoke something already gone.
    """
    current_token_jti = _current_session_jti(request)

    sessions = (
        db.query(RefreshTokenSession)
        .filter(
            RefreshTokenSession.user_id == current_user.id,
            RefreshTokenSession.revoked_at.is_(None),
            RefreshTokenSession.expires_at > utcnow(),
        )
        .order_by(RefreshTokenSession.issued_at.desc())
        .all()
    )

    return [_extract_session_info(s, current_token_jti) for s in sessions]


@router.delete("/sessions", status_code=200)
def revoke_other_sessions(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Sign out every session except the one making this request.

    The control that matters when somebody suspects their account is being used
    elsewhere: revoking sessions one at a time requires knowing which row is the
    intruder, and the whole reason for reaching this screen is not knowing.

    Revocation, not deletion. The rows stay with `revoked_at` set so the audit
    trail keeps showing that these sessions existed and when they were ended —
    deleting them would erase the evidence of the event being responded to.

    If the caller cannot be identified (no refresh cookie), every session is
    revoked including whatever the caller is using. That is the safe direction:
    "I could not tell which one is yours" must not mean "so I left them all
    running".
    """
    current_token_jti = _current_session_jti(request)

    query = db.query(RefreshTokenSession).filter(
        RefreshTokenSession.user_id == current_user.id,
        RefreshTokenSession.revoked_at.is_(None),
    )
    if current_token_jti:
        query = query.filter(RefreshTokenSession.token_jti != current_token_jti)

    revoked = query.update(
        {RefreshTokenSession.revoked_at: utcnow()}, synchronize_session=False
    )

    log_audit_event(
        db,
        current_user,
        "user.sessions_revoked_bulk",
        "session",
        str(current_user.id),
        request=request,
        status="success",
        changes={
            "sessions_revoked": revoked,
            "kept_current_session": bool(current_token_jti),
        },
    )
    db.commit()
    logger.info("User %s revoked %s other session(s)", current_user.username, revoked)
    return {"revoked": revoked, "kept_current_session": bool(current_token_jti)}


@router.delete("/sessions/{session_id}", status_code=204)
def revoke_session(
    session_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Revoke a specific session (refresh token).

    Prevents the session from being used for future token refreshes.
    """
    session = (
        db.query(RefreshTokenSession)
        .filter(
            RefreshTokenSession.id == session_id,
            RefreshTokenSession.user_id == current_user.id,
        )
        .first()
    )

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )

    if session.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session is already revoked",
        )

    session.revoked_at = datetime.now(timezone.utc)
    log_audit_event(
        db,
        current_user,
        "user.session_revoked",
        "session",
        str(session.id),
        request=request,
        status="success",
        changes={
            "session_id": session_id,
            "ip": str(session.ip_address) if session.ip_address else None,
        },
    )
    db.commit()
    logger.info(f"User {current_user.username} revoked session {session_id}")
