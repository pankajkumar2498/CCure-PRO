"""
auth/jwt_handler.py
-------------------
JWT generation, verification, refresh rotation, and password helpers.
"""

import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import Request
from core.ip_resolver import get_client_ip

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from db.base import SessionLocal
from db.models.users import RefreshTokenSession, User

# ── Logging ───────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
# Single source of truth: read JWT settings from config.JWTConfig so that
# config.py (which loads .env) is the only place that touches env vars.
from config import JWTConfig as _JWTCfg

ENVIRONMENT = os.getenv("APP_ENV", os.getenv("ENVIRONMENT", "development")).lower()
SECRET_KEY: str = _JWTCfg.SECRET_KEY
ALGORITHM = "HS256"
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
    now = _utcnow()
    payload = data.copy()
    payload["iat"] = now
    payload["exp"] = now + expires_delta
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_access_token(user_id: int, username: str, role: Optional[str] = None, org_id: Optional[str] = None) -> str:
    payload = {"sub": str(user_id), "username": username, "type": "access"}
    if role is not None:
        payload["role"] = role
    if org_id is not None:
        payload["org_id"] = str(org_id)
    return _create_token(
        payload,
        ACCESS_TOKEN_EXPIRE,
    )


def create_download_ticket(user_id: str, username: str) -> str:
    """Create a short-lived (60 seconds) ticket for secure websockets/downloads."""
    payload = {"sub": str(user_id), "username": username, "type": "ticket"}
    return _create_token(
        payload,
        timedelta(seconds=60),
    )


def create_refresh_token(user_id, db: Optional[Session] = None, request: Optional[Request] = None) -> str:
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
        organization = db.query(Organization).filter(Organization.id == user.org_id).first()
        if organization and not organization.is_active:
            raise ValueError("User's organization is deactivated; cannot create refresh token")
        
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


def decode_token(token: str) -> Optional[dict]:
    """
    Decode and validate a JWT.
    Returns the payload dict, or None if invalid / expired.
    """
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


def _get_refresh_session(db: Session, refresh_token: str) -> Optional[RefreshTokenSession]:
    payload = decode_token(refresh_token)
    if not payload or payload.get("type") != "refresh":
        return None

    token_jti = payload.get("jti")
    token_sub = payload.get("sub")
    if not token_jti or not token_sub:
        return None

    session_row = db.query(RefreshTokenSession).filter(
        RefreshTokenSession.token_jti == token_jti
    ).first()
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


def revoke_refresh_token(refresh_token: str, db: Optional[Session] = None) -> bool:
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


def refresh_access_token(refresh_token: str, db: Optional[Session] = None, request: Optional[Request] = None) -> Optional[dict]:
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
        organization = db.query(Organization).filter(Organization.id == user.org_id).first()
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
