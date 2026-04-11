"""
auth/jwt_handler.py
-------------------
JWT generation, verification, refresh rotation, and password helpers.
"""

import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from auth.models import RefreshTokenSession, SessionLocal, User

# ── Logging ───────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
ENVIRONMENT = os.getenv("APP_ENV", os.getenv("ENVIRONMENT", "development")).lower()
SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE = timedelta(hours=1)
REFRESH_TOKEN_EXPIRE = timedelta(days=7)

if not SECRET_KEY:
    if ENVIRONMENT == "production":
        raise RuntimeError("JWT_SECRET must be set to a strong non-default value before starting the application.")
    SECRET_KEY = "ccure-dev-only-secret-change-me"
    logger.warning("JWT_SECRET is not set; using a development-only fallback secret.")
elif SECRET_KEY == "ccure-super-secret-change-in-production":
    if ENVIRONMENT == "production":
        raise RuntimeError("JWT_SECRET must not use the old default value in production.")
    logger.warning("JWT_SECRET is using the legacy default secret outside production. Change it before deployment.")

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
    return datetime.utcnow()


def _create_token(data: dict, expires_delta: timedelta) -> str:
    now = _utcnow()
    payload = data.copy()
    payload["iat"] = now
    payload["exp"] = now + expires_delta
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_access_token(user_id: int, username: str) -> str:
    return _create_token(
        {"sub": str(user_id), "username": username, "type": "access"},
        ACCESS_TOKEN_EXPIRE,
    )


def create_refresh_token(user_id: int, db: Optional[Session] = None) -> str:
    owns_session = db is None
    db = db or SessionLocal()

    try:
        jti = secrets.token_urlsafe(32)
        expires_at = _utcnow() + REFRESH_TOKEN_EXPIRE
        token = _create_token(
            {"sub": str(user_id), "type": "refresh", "jti": jti},
            REFRESH_TOKEN_EXPIRE,
        )
        session_row = RefreshTokenSession(
            user_id=user_id,
            token_jti=jti,
            token_hash=_hash_token(token),
            expires_at=expires_at,
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


def refresh_access_token(refresh_token: str, db: Optional[Session] = None) -> Optional[dict]:
    """
    Given a valid refresh token, rotate it and return fresh access/refresh tokens.
    Returns None if the refresh token is invalid, expired, revoked, or unknown.
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

        new_jti = secrets.token_urlsafe(32)
        new_refresh_token = _create_token(
            {"sub": str(user.id), "type": "refresh", "jti": new_jti},
            REFRESH_TOKEN_EXPIRE,
        )
        replacement = RefreshTokenSession(
            user_id=user.id,
            token_jti=new_jti,
            token_hash=_hash_token(new_refresh_token),
            expires_at=_utcnow() + REFRESH_TOKEN_EXPIRE,
        )

        session_row.revoked_at = _utcnow()
        session_row.replaced_by = new_jti

        db.add(replacement)
        db.commit()

        return {
            "access_token": create_access_token(user.id, user.username),
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
