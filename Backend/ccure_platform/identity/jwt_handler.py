"""
ccure_platform/identity/jwt_handler.py (was auth/jwt_handler.py until Phase 8.2)
-------------------
JWT generation, verification, refresh rotation, and password helpers.
"""

from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "auth.jwt_handler")

import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Union

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from core.ip_resolver import get_client_ip
from core.user_agent import describe_request
from db.base import SessionLocal
from db.models import RefreshTokenSession, User
from fastapi import Request
from ccure_platform.identity import tokens
from passlib.context import CryptContext
from sqlalchemy.orm import Session

# ── Logging ───────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
# Single source of truth: read JWT settings from config.JWTConfig so that
# config.py (which loads .env) is the only place that touches env vars.
from config import JWTConfig as _JWTCfg

ENVIRONMENT = os.getenv("APP_ENV", os.getenv("ENVIRONMENT", "development")).lower()
# Signing lives in ccure_platform.identity.tokens (Phase 9.1). These names
# stay importable from here, with the same values, for existing callers.
SECRET_KEY: str = tokens.SECRET_KEY
ALGORITHM = tokens.ALGORITHM
ACCESS_TOKEN_EXPIRE = timedelta(minutes=_JWTCfg.ACCESS_TOKEN_EXPIRES_MINUTES)
REFRESH_TOKEN_EXPIRE = timedelta(days=_JWTCfg.REFRESH_TOKEN_EXPIRES_DAYS)

# Runtime guard: warn or fail if the key is insecure.
_KNOWN_WEAK_KEYS = {
    "dev-secret-key-change-in-production",
    "ccure-dev-only-secret-change-me",
    "ccure-super-secret-change-in-production",
    "your-super-secret-jwt-key-change-in-production",
}
if SECRET_KEY in _KNOWN_WEAK_KEYS:
    if ENVIRONMENT == "production":
        raise RuntimeError(
            "JWT_SECRET_KEY must be set to a strong, unique value in production. "
            "The current value is a known development default."
        )
    logger.warning(
        "JWT_SECRET_KEY is using a development default. "
        "Set JWT_SECRET_KEY in your .env before deploying to production."
    )

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
argon2_hasher = PasswordHasher()


# ── Password helpers ──────────────────────────────────────────────────────────


def validate_password_strength(password: str) -> str:
    """
    Validate that the password meets complexity requirements:
    - At least 12 characters
    - At least one uppercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit")
    if not any(not c.isalnum() for c in password):
        raise ValueError("Password must contain at least one special character")
    return password


def hash_password(plain: str) -> str:
    """Hash password using argon2 (recommended) or bcrypt fallback."""
    try:
        return argon2_hasher.hash(plain)
    except Exception:
        return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify password - supports both bcrypt and argon2 hashes."""
    if hashed.startswith("$argon2"):
        try:
            argon2_hasher.verify(hashed, plain)
            return True
        except VerifyMismatchError:
            return False
        except Exception:
            return False

    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False


# ── Token helpers ─────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _create_token(data: dict, expires_delta: timedelta) -> str:
    return tokens.sign(data, expires_delta)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_access_token(
    user_id: int,
    username: str,
    role: str | None = None,
    org_id: str | None = None,
) -> str:
    payload = {"sub": str(user_id), "username": username, "type": "access"}
    if role is not None:
        payload["role"] = role
    if org_id is not None:
        payload["org_id"] = str(org_id)
    return _create_token(
        payload,
        ACCESS_TOKEN_EXPIRE,
    )


def create_mfa_challenge_token(
    user_id: str | int,
    username: str,
    role: str | None = None,
    org_id: str | None = None,
) -> str:
    """Create a short-lived (5 minutes) challenge token for multi-factor authentication step-up."""
    payload = {"sub": str(user_id), "username": username, "type": "mfa_challenge"}
    if role is not None:
        payload["role"] = role
    if org_id is not None:
        payload["org_id"] = str(org_id)
    return _create_token(
        payload,
        timedelta(minutes=5),
    )


def create_download_ticket(user_id: str, username: str) -> str:
    """Create a short-lived (60 seconds) ticket for secure websockets/downloads."""
    payload = {"sub": str(user_id), "username": username, "type": "ticket"}
    return _create_token(
        payload,
        timedelta(seconds=60),
    )


def create_refresh_token(
    user_id, db: Session | None = None, request: Request | None = None
) -> str:
    """
    Create a new refresh token for a user.

    Organization Status Check:
    - User must belong to an active organization.
    - This prevents token creation for deactivated organizations.
    """
    owns_session = db is None
    db = db or SessionLocal()

    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError("User not found")
        if getattr(user, "is_deleted", False) or not getattr(user, "is_active", True):
            raise ValueError("User account is not eligible for refresh tokens")

        # ─ Organization Status Check ────────────────────────────────────────
        # Prevent token creation for users in deactivated organizations.
        from db.models import Organization

        organization = (
            db.query(Organization).filter(Organization.id == user.org_id).first()
        )
        if organization and not organization.is_active:
            raise ValueError(
                "User's organization is deactivated; cannot create refresh token"
            )

        jti = secrets.token_urlsafe(32)
        expires_at = _utcnow() + REFRESH_TOKEN_EXPIRE
        token = _create_token(
            {"sub": str(user_id), "type": "refresh", "jti": jti},
            REFRESH_TOKEN_EXPIRE,
        )
        session_row = RefreshTokenSession(
            user_id=user_id,
            org_id=user.org_id,
            token_jti=jti,
            token_hash=_hash_token(token),
            expires_at=expires_at,
            ip_address=get_client_ip(request) if request else None,
            # device_info existed on this table from the start and was never
            # written, so /user/sessions listed rows a person could not tell
            # apart. See core/user_agent.py for how far the parse is trusted.
            device_info=describe_request(request),
        )
        db.add(session_row)
        db.commit()
        return token
    except Exception:
        db.rollback()
        raise
    finally:
        if owns_session:
            db.close()


def decode_token(token: str) -> dict | None:
    """
    Decode and validate a JWT of **any** kind.
    Returns the payload dict, or None if invalid / expired.

    Kept, unchanged, for the callers outside Phase 9 — the two WebSocket
    ticket logins (Phase 10) and the rate-limit audit — which check the kind
    themselves. Everything else verifies through
    ``tokens.verify(token, expected_kind=…)``.
    """
    return tokens.decode_any_kind(token)


def _get_refresh_session(db: Session, refresh_token: str) -> RefreshTokenSession | None:
    payload = tokens.verify(
        refresh_token,
        expected_kind=tokens.REFRESH,
        issuer=tokens.ISSUER,
        audience=tokens.USER_AUDIENCE,
    )
    if not payload:
        return None

    token_jti = payload.get("jti")
    token_sub = payload.get("sub")
    if not token_jti or not token_sub:
        return None

    session_row = (
        db.query(RefreshTokenSession)
        .filter(RefreshTokenSession.token_jti == token_jti)
        .first()
    )
    if not session_row:
        return None

    if session_row.token_hash != _hash_token(refresh_token):
        return None

    if session_row.revoked_at is not None:
        return None

    if session_row.expires_at <= _utcnow():
        return None

    if str(session_row.user_id) != str(token_sub):
        return None

    return session_row


def revoke_refresh_token(refresh_token: str, db: Session | None = None) -> bool:
    owns_session = db is None
    db = db or SessionLocal()

    try:
        session_row = _get_refresh_session(db, refresh_token)
        if not session_row:
            return False

        session_row.revoked_at = _utcnow()
        db.commit()
        return True
    except Exception:
        db.rollback()
        logger.exception("Failed to revoke refresh token")
        return False
    finally:
        if owns_session:
            db.close()


def refresh_access_token(
    refresh_token: str, db: Session | None = None, request: Request | None = None
) -> dict | None:
    """
    Given a valid refresh token, rotate it and return fresh access/refresh tokens.
    Returns None if the refresh token is invalid, expired, revoked, unknown, or from a deactivated org.

    Organization Status Check:
    - If the user's organization has been deactivated, refresh fails immediately.
    - This prevents token rotation for users in inactive organizations.
    """
    owns_session = db is None
    db = db or SessionLocal()

    try:
        session_row = _get_refresh_session(db, refresh_token)
        if not session_row:
            return None

        user = db.query(User).filter(User.id == session_row.user_id).first()
        if not user:
            return None
        if getattr(user, "is_deleted", False) or not getattr(user, "is_active", True):
            return None

        # ─ Organization Status Check ────────────────────────────────────────
        # Prevent token refresh if organization is deactivated.
        # This ensures session termination for deactivated organizations.
        from db.models import Organization

        organization = (
            db.query(Organization).filter(Organization.id == user.org_id).first()
        )
        if organization and not organization.is_active:
            return None

        new_jti = secrets.token_urlsafe(32)
        new_refresh_token = _create_token(
            {"sub": str(user.id), "type": "refresh", "jti": new_jti},
            REFRESH_TOKEN_EXPIRE,
        )
        replacement = RefreshTokenSession(
            user_id=user.id,
            org_id=user.org_id,
            token_jti=new_jti,
            token_hash=_hash_token(new_refresh_token),
            expires_at=_utcnow() + REFRESH_TOKEN_EXPIRE,
            ip_address=get_client_ip(request) if request else None,
            # Carried across the rotation. A refresh happens every 30 minutes,
            # so leaving it off here would blank the description of every
            # session shortly after it was created.
            device_info=(
                describe_request(request)
                if request
                else (session_row.device_info or {})
            ),
        )

        session_row.revoked_at = _utcnow()
        session_row.replaced_by = new_jti

        db.add(replacement)
        db.commit()

        return {
            "access_token": create_access_token(
                user.id,
                user.username,
                role=getattr(user.role, "name", None),
                org_id=user.org_id,
            ),
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
        }
    except Exception:
        db.rollback()
        logger.exception("Failed to refresh access token")
        return None
    finally:
        if owns_session:
            db.close()
