"""
auth/dependencies.py
--------------------
FastAPI dependencies for authenticated user resolution and tenant scope.
"""

from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session, joinedload

from auth.jwt_handler import decode_token
from db.base import get_db
from db.models import User

bearer_scheme = HTTPBearer()


@dataclass(frozen=True)
class AuthContext:
    user: User
    user_id: str
    organization_id: Optional[str]
    role: str


def _decode_access_payload(token: str) -> dict:
    payload = decode_token(token)

    if not payload or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


def _load_auth_context_from_payload(payload: dict, db: Session) -> AuthContext:
    try:
        user_id = str(payload["sub"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = (
        db.query(User)
        .options(joinedload(User.role), joinedload(User.organization))
        .filter(User.id == user_id)
        .first()
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    if getattr(user, "is_deleted", False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account has been deleted",
        )
    if not getattr(user, "is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    db_role = (getattr(getattr(user, "role", None), "name", "") or "").lower()
    db_org_id = str(user.org_id) if user.org_id else None

    token_role = payload.get("role")
    token_org_id = payload.get("org_id")

    # Enforce claim consistency when present, while remaining compatible with
    # older access tokens until they naturally rotate out.
    if token_role is not None and str(token_role).lower() != db_role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token role scope no longer matches the user account",
        )
    if token_org_id is not None and str(token_org_id) != db_org_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token organization scope no longer matches the user account",
        )

    return AuthContext(
        user=user,
        user_id=str(user.id),
        organization_id=db_org_id,
        role=db_role,
    )


def get_current_auth_context(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> AuthContext:
    payload = _decode_access_payload(credentials.credentials)
    return _load_auth_context_from_payload(payload, db)


def get_current_user(
    auth_context: AuthContext = Depends(get_current_auth_context),
) -> User:
    """
    Inject as a dependency on any protected endpoint:

        @app.get("/protected")
        def protected(user: User = Depends(get_current_user)):
            ...

    The user's Role is eagerly loaded so RBAC guards can access
    ``user.role.name`` without triggering lazy-load issues.
    """
    return auth_context.user


def get_current_user_flexible(
    token: str = None,
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False)),
    db: Session = Depends(get_db),
) -> User:
    """
    More flexible version of get_current_user that checks:
      1. 'token' query parameter (for direct file downloads)
      2. 'Authorization: Bearer <token>' header (standard API calls)

    The user's Role is eagerly loaded for RBAC enforcement.
    """
    final_token = token or (credentials.credentials if credentials else None)
    
    if not final_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is missing.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = _decode_access_payload(final_token)
    return _load_auth_context_from_payload(payload, db).user
