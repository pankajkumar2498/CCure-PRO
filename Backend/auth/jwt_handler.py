"""
auth/jwt_handler.py
-------------------
JWT generation, verification, and refresh logic.
"""

import os
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# ── Config ────────────────────────────────────────────────────────────────────
SECRET_KEY            = os.getenv("JWT_SECRET", "ccure-super-secret-change-in-production")
ALGORITHM             = "HS256"
ACCESS_TOKEN_EXPIRE   = timedelta(hours=1)
REFRESH_TOKEN_EXPIRE  = timedelta(days=7)

# Support both bcrypt and argon2 for password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
argon2_hasher = PasswordHasher()


# ── Password helpers ──────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    """Hash password using argon2 (recommended) or bcrypt fallback."""
    try:
        return argon2_hasher.hash(plain)
    except Exception:
        # Fallback to bcrypt
        return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify password - supports both bcrypt and argon2 hashes."""
    # Check if it's an argon2 hash (starts with $argon2)
    if hashed.startswith("$argon2"):
        try:
            argon2_hasher.verify(hashed, plain)
            return True
        except VerifyMismatchError:
            return False
        except Exception:
            return False
    else:
        # Fall back to passlib for bcrypt
        try:
            return pwd_context.verify(plain, hashed)
        except Exception:
            return False


# ── Token helpers ─────────────────────────────────────────────────────────────

def _create_token(data: dict, expires_delta: timedelta) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + expires_delta
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_access_token(user_id: int, username: str) -> str:
    return _create_token(
        {"sub": str(user_id), "username": username, "type": "access"},
        ACCESS_TOKEN_EXPIRE,
    )


def create_refresh_token(user_id: int) -> str:
    return _create_token(
        {"sub": str(user_id), "type": "refresh"},
        REFRESH_TOKEN_EXPIRE,
    )


def decode_token(token: str) -> Optional[dict]:
    """
    Decode and validate a JWT.
    Returns the payload dict, or None if invalid / expired.
    """
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


def refresh_access_token(refresh_token: str) -> Optional[str]:
    """
    Given a valid refresh token, return a new access token.
    Returns None if the refresh token is invalid or not of type 'refresh'.
    """
    payload = decode_token(refresh_token)
    if not payload or payload.get("type") != "refresh":
        return None
    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError):
        return None

    from auth.models import SessionLocal, User

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return None
        return create_access_token(user.id, user.username)
    finally:
        db.close()
