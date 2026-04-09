"""
auth/router.py
--------------
FastAPI router that wires up all authentication endpoints:

    POST  /auth/register    → create a new account
    POST  /auth/login       → get access + refresh tokens
    POST  /auth/logout      → client-side hint (token is stateless)
    GET   /auth/me          → current user profile
    POST  /auth/refresh     → swap refresh token for new access token
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from auth.models import User, get_db
from auth.jwt_handler import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    refresh_access_token,
)
from auth.dependencies import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ── Request / Response Schemas ────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

    @field_validator("username")
    @classmethod
    def username_length(cls, v: str) -> str:
        if len(v) < 3:
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
    refresh_token: str


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    created_at: str

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/register", response_model=TokenResponse, status_code=201)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    """
    Create a new user account.
    Returns access + refresh tokens immediately so the user is logged in.
    """
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=409, detail="Email already registered")

    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=409, detail="Username already taken")

    user = User(
        username=req.username,
        email=req.email,
        password_hash=hash_password(req.password),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError as e:
        db.rollback()
        if "email" in str(e).lower():
            raise HTTPException(status_code=409, detail="Email already registered")
        elif "username" in str(e).lower():
            raise HTTPException(status_code=409, detail="Username already taken")
        else:
            raise HTTPException(status_code=400, detail="Registration failed: duplicate entry")
    db.refresh(user)

    return {
        "access_token":  create_access_token(user.id, user.username),
        "refresh_token": create_refresh_token(user.id),
        "user": {
            "id":         user.id,
            "username":   user.username,
            "email":      user.email,
            "created_at": user.created_at.isoformat(),
        },
    }


@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
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
    except Exception as e:
        import traceback
        print(f"Error verifying password: {e}")
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    return {
        "access_token":  create_access_token(user.id, user.username),
        "refresh_token": create_refresh_token(user.id),
        "user": {
            "id":         user.id,
            "username":   user.username,
            "email":      user.email,
            "created_at": user.created_at.isoformat(),
        },
    }


@router.post("/logout")
def logout():
    """
    Logout hint for the client.
    Since JWTs are stateless the client just deletes its stored tokens.
    For a production app, add a token-blacklist here (e.g. Redis set with TTL).
    """
    return {"detail": "Logged out. Please delete your tokens on the client."}


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    """
    Return the profile of the currently authenticated user.
    Requires:  Authorization: Bearer <access_token>
    """
    return {
        "id":         current_user.id,
        "username":   current_user.username,
        "email":      current_user.email,
        "created_at": current_user.created_at.isoformat(),
    }


@router.post("/refresh")
def refresh(req: RefreshRequest):
    """
    Swap a valid refresh token for a new access token.
    """
    new_access = refresh_access_token(req.refresh_token)
    if not new_access:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    return {"access_token": new_access, "token_type": "bearer"}
