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
from auth.models import User, get_db

router = APIRouter(prefix="/auth", tags=["Authentication"])
logger = logging.getLogger(__name__)
REFRESH_COOKIE_NAME = os.getenv("REFRESH_COOKIE_NAME", "ccure_refresh_token")
REFRESH_COOKIE_PATH = os.getenv("REFRESH_COOKIE_PATH", "/auth")
REFRESH_COOKIE_SAMESITE = os.getenv("REFRESH_COOKIE_SAMESITE", "lax")
REFRESH_COOKIE_SECURE = os.getenv("REFRESH_COOKIE_SECURE", "false").lower() == "true"
REFRESH_COOKIE_DOMAIN = os.getenv("REFRESH_COOKIE_DOMAIN") or None


# ── Request / Response Schemas ────────────────────────────────────────────────

class RegisterRequest1(BaseModel):
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
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str | None = None


class LogoutRequest(BaseModel):
    refresh_token: str | None = None


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    created_at: str

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


def _resolve_refresh_token(request: Request, token_from_body: str | None) -> str | None:
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

    user = User(
        username=req.username.strip(),
        email=req.email,
        password_hash=hash_password(req.password),
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
        "access_token": create_access_token(user.id, user.username),
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "created_at": user.created_at.isoformat(),
        },
    }


@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, response: Response, db: Session = Depends(get_db)):
    """
    Authenticate with email + password.
    Returns access + refresh tokens on success.
    """
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    try:
        is_valid = verify_password(req.password, user.password_hash)
    except Exception as exc:
        logger.warning(
            "Password verification failed for login attempt on email=%s: %s",
            req.email,
            exc.__class__.__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    refresh_token = create_refresh_token(user.id, db)
    _set_refresh_cookie(response, refresh_token)

    return {
        "access_token": create_access_token(user.id, user.username),
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "created_at": user.created_at.isoformat(),
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
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "created_at": current_user.created_at.isoformat(),
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
