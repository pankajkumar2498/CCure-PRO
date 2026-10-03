"""
ccure_platform/identity/dependencies.py (was auth/dependencies.py until Phase 8.2)
--------------------
FastAPI dependencies for authenticated user resolution and tenant scope.
"""

from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "auth.dependencies")

from dataclasses import dataclass
from typing import Optional

from ccure_platform.identity.tokens import (
    ACCESS,
    ISSUER,
    TICKET,
    USER_AUDIENCE,
    verify,
)
from db.base import get_db
from db.models import User
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session, joinedload

bearer_scheme = HTTPBearer()


@dataclass(frozen=True)
class AuthContext:
    user: User
    user_id: str
    organization_id: str | None


def _decode_access_payload(token: str) -> dict:
    payload = verify(token, expected_kind=ACCESS, issuer=ISSUER, audience=USER_AUDIENCE)
    if not payload:
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
        .options(joinedload(User.organization))
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

    # ─ Organization Status Check ────────────────────────────────────────────
    # When an organization is deactivated, ALL users in that org lose access
    # immediately, even if their individual user status remains active.
    #
    # This is enforced on every request/token refresh, so deactivation takes
    # effect instantly without invalidating existing JWT tokens (stateless).
    # Reactivating the org restores access without modifying user statuses.
    organization = getattr(user, "organization", None)
    if organization and not getattr(organization, "is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your organization has been deactivated. Please contact support.",
        )

    db_org_id = str(user.org_id) if user.org_id else None

    # A ``role`` claim in an older access token is ignored: no role — name, id or label —
    # is an authorization input (RBAC-8). The organisation claim, when present, must
    # still match the account.
    token_org_id = payload.get("org_id")
    if token_org_id is not None and str(token_org_id) != db_org_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token organization scope no longer matches the user account",
        )

    return AuthContext(
        user=user,
        user_id=str(user.id),
        organization_id=db_org_id,
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

    The account the request is authenticated as; its permissions are
    resolved by the RBAC engine (no role is read from it).
    """
    return auth_context.user


def get_current_user_flexible(
    ticket: str = None,
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False)),
    db: Session = Depends(get_db),
) -> User:
    """
    More flexible version of get_current_user that checks:
      1. 'ticket' query parameter (for direct file downloads via short-lived JWT ticket)
      2. 'Authorization: Bearer <token>' header (standard API calls)

    The account the request is authenticated as.
    """
    if ticket:
        payload = verify(
            ticket, expected_kind=TICKET, issuer=ISSUER, audience=USER_AUDIENCE
        )
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired download ticket.",
            )
        return _load_auth_context_from_payload(payload, db).user

    final_token = credentials.credentials if credentials else None

    if not final_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is missing.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = _decode_access_payload(final_token)
    return _load_auth_context_from_payload(payload, db).user
