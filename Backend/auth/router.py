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
from typing import List, NoReturn, Optional, Union
from uuid import UUID

from auth.dependencies import get_current_user
from auth.email_domain_guard import (
    assert_email_allowed,
    current_mode as current_guard_mode,
    evaluate_email,
)
from auth.email_utils import (
    canonicalize_email,
    email_matches,
    normalize_email,
    username_matches,
)
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
from auth.registration_limits import daily_ip_quota_exceeded, pending_queue_full
from db.base import gen_org_id, gen_user_id, get_db, utcnow
from db.models import Organization, RefreshTokenSession, Role, User
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import AliasChoices, BaseModel, EmailStr, Field, field_validator
from scan_helpers import limiter
from sqlalchemy import or_
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
    full_name: str
    agree_to_terms: bool = True

    @field_validator("username")
    @classmethod
    def username_length(cls, v: str) -> str:
        cleaned = v.strip()
        if len(cleaned) < 3:
            raise ValueError("Username must be at least 3 characters")
        if "@" in cleaned:
            raise ValueError("Username cannot contain '@' symbol")
        return cleaned

    @field_validator("full_name")
    @classmethod
    def sanitize_full_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Full name is required")
        cleaned = v.strip()
        if len(cleaned) > 255:
            raise ValueError("Full name cannot exceed 255 characters")
        return cleaned

    @field_validator("agree_to_terms")
    @classmethod
    def validate_terms(cls, v: bool) -> bool:
        if not v:
            raise ValueError(
                "You must agree to the Terms of Service and Privacy Policy"
            )
        return v

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return validate_password_strength(v)


class LoginRequest(BaseModel):
    email_or_username: str = Field(
        validation_alias=AliasChoices("email_or_username", "email")
    )
    password: str


class ForgotPasswordRequest(BaseModel):
    email_or_username: str = Field(
        validation_alias=AliasChoices("email_or_username", "email")
    )


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
    full_name: str | None = None
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


# How many verification links may be redeemable for one account at a time.
#
# Three covers the realistic case — a user who clicks resend once or twice and
# then opens whichever email they happen to see first — while bounding how many
# rows a resend loop can create. See _issue_verification_token for why more than
# one is safe.
MAX_LIVE_VERIFICATION_TOKENS = 3

_DUMMY_HASH: str | None = None


def _dummy_password_check(password: str) -> None:
    """
    Burn roughly one password verification against a throwaway hash.

    Used when no account matched, so that "unknown identifier" and "wrong
    password" take comparable time. The hash is computed once per process
    rather than per request — deriving it every call would make the no-account
    path *slower* than the real one and reintroduce the timing signal with the
    sign flipped.
    """
    global _DUMMY_HASH
    try:
        if _DUMMY_HASH is None:
            import secrets

            _DUMMY_HASH = hash_password(secrets.token_urlsafe(32))
        verify_password(password, _DUMMY_HASH)
    except Exception:  # never let the equaliser itself fail a login
        logger.debug("Dummy password check failed", exc_info=True)


def _deny_login(
    db: Session, user: User, request: Request, reason: str, detail: str
) -> None:
    """Audit a post-credential login denial and raise 403. Never returns."""
    from core.audit import log_audit_event

    log_audit_event(
        db,
        user,
        "user.login_failed",
        "user",
        str(user.id),
        request=request,
        status="denied",
        changes={"reason": reason},
    )
    db.commit()
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def _issue_verification_token(db: Session, user: User, request: Request | None = None):
    """
    Mint a single-use email-verification token and dispatch the link.

    Only the SHA-256 hash is stored, so a database read yields nothing that can
    be redeemed.

    Several links may be live at once — deliberately
    ───────────────────────────────────────────────
    This used to delete every outstanding token on re-issue, on the reasoning
    that one live link is tidier than two. In practice that made the resend
    button a trap, and it broke a real registration:

        16:58:32  register  -> token A emailed
        16:58:54  resend    -> token A DELETED, token B emailed
        17:00:16  user clicks the link in email A  -> 400 "no longer valid"
        17:01:07  resend    -> token B DELETED, token C emailed
        17:01:41  user clicks the link in email B  -> 400 again

    Every resend killed the link the user was about to click, and the failure
    prompted another resend, so the loop could not be escaped. Two emails in an
    inbox and only the newest working is not a distinction anyone can see.

    Keeping several live costs nothing that matters here. A verification token
    proves control of a mailbox and grants no session — it cannot log anyone in,
    and the account still needs administrator approval. All live tokens for a
    user point at the same mailbox, so an attacker holding that mailbox gains
    nothing from there being three rather than one. The controls that carry the
    weight are unchanged: single **use** (the row is deleted on redemption),
    a 24-hour expiry, and 3/min rate limiting on resend.

    Password-reset tokens are a different case and keep the one-live rule: they
    change a credential, so a stale one is worth strictly more to an attacker.

    Older tokens beyond MAX_LIVE_VERIFICATION_TOKENS are pruned, along with any
    that have expired, so this cannot grow without bound.

    Returns the plaintext token. Callers must not put it in a response body;
    it is returned so tests can exercise redemption without parsing an email.
    """
    import hashlib
    import secrets
    from datetime import datetime, timedelta, timezone

    from config import AppConfig
    from core.mail_dispatch import dispatch_email
    from db.models import EmailVerificationToken

    now = datetime.now(timezone.utc)

    # Drop anything already expired for this user — it is unusable and is a
    # retained record of an email address with no purpose.
    db.query(EmailVerificationToken).filter(
        EmailVerificationToken.user_id == user.id,
        EmailVerificationToken.expires_at <= now,
    ).delete(synchronize_session=False)

    # Keep only the newest few, so a user hammering resend cannot accumulate
    # rows indefinitely. One slot is freed for the token about to be added.
    keep = max(1, MAX_LIVE_VERIFICATION_TOKENS - 1)
    surplus = (
        db.query(EmailVerificationToken.id)
        .filter(EmailVerificationToken.user_id == user.id)
        .order_by(EmailVerificationToken.created_at.desc())
        .offset(keep)
        .all()
    )
    if surplus:
        db.query(EmailVerificationToken).filter(
            EmailVerificationToken.id.in_([row.id for row in surplus])
        ).delete(synchronize_session=False)

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(
        hours=AppConfig.EMAIL_VERIFICATION_TTL_HOURS
    )

    db.add(
        EmailVerificationToken(
            user_id=user.id,
            token_hash=token_hash,
            email=user.email,
            expires_at=expires_at,
        )
    )

    from core.audit import log_audit_event

    log_audit_event(
        db,
        user,
        "user.verification_token_issued",
        "user",
        str(user.id),
        request=request,
        status="success",
    )
    db.commit()

    verify_link = f"{AppConfig.FRONTEND_URL.rstrip('/')}/verify-email?token={token}"
    # dispatch_email, not .delay: with no worker consuming the queue, .delay
    # succeeded and the link was never sent — the account existed, the token
    # was committed, and the user got silence.
    dispatch_email("verification", user.email, user.username, verify_link)
    return token


def _require_self_registration_enabled() -> None:
    """
    Gate every self-service signup route behind ALLOW_SELF_REGISTRATION.

    404 rather than 403: when the feature is off, the endpoint should not
    advertise that it exists and is merely disabled here.
    """
    from config import AppConfig

    if not AppConfig.ALLOW_SELF_REGISTRATION:
        raise HTTPException(status_code=404, detail="Not Found")


@router.get("/check-username")
@limiter.limit("10/minute")
def check_username(request: Request, q: str, db: Session = Depends(get_db)):
    """
    Check whether a username is free.

    This is an existence oracle, so it is only reachable while self-service
    registration is enabled — the signup form is the sole legitimate caller.
    It answers about usernames only. It previously also matched the query
    against the *email* column, which let anyone confirm whether a given email
    address held an account by passing it here, and confirm it from the
    username endpoint too. Usernames are semi-public within a tenant; email
    addresses are not.
    """
    _require_self_registration_enabled()
    query_str = q.strip()
    if len(query_str) < 3 or "@" in query_str:
        return {"available": False}
    exists = db.query(User).filter(username_matches(User.username, query_str)).first()
    return {"available": not bool(exists)}


@router.get("/check-email")
@limiter.limit("10/minute")
def check_email(request: Request, q: str, db: Session = Depends(get_db)):
    """
    Report whether an email address can be used to register.

    Deliberately does *not* answer "does this account exist". A taken address
    and a free one both return available=true, and the collision surfaces at
    submit time as a generic failure. Live "already registered" feedback on a
    signup form is a convenience for the person typing and a bulk account
    oracle for everyone else, and only one of those two is worth having.

    The endpoint is kept so the frontend contract does not break, and it still
    rejects syntactically invalid input, which is what the field actually needs
    in order to give useful feedback.

    It *does* now answer about the domain. A verdict of "this is a disposable
    mail service" says nothing about whether an account exists — it is a fact
    about the domain, identical for every caller — so surfacing it costs no
    privacy and saves the person filling in the form from completing a signup
    that is going to be refused at submit.
    """
    _require_self_registration_enabled()
    query_str = q.strip()
    if not query_str or "@" not in query_str:
        return {"available": False, "reason": "invalid"}

    verdict = evaluate_email(db, query_str)
    if verdict.blocked and current_guard_mode() == "enforce":
        return {
            "available": False,
            "reason": verdict.reason,
            "detail": verdict.detail,
        }
    return {"available": True, "reason": verdict.reason}


# The gate is a route dependency as well as a call inside the handler.
# Dependencies are resolved before request-body validation errors are raised,
# so without this a disabled deployment answered POST /auth/register with a 422
# listing the fields it expects — confirming the route exists, which is the one
# thing the 404 is meant to avoid now that /openapi.json and /docs are closed.
@router.post(
    "/register",
    status_code=202,
    dependencies=[Depends(_require_self_registration_enabled)],
)
@limiter.limit("3/minute")
def register(
    req: RegisterRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Create a new, inert account and email a verification link.

    What changed and why
    ────────────────────
    This endpoint used to create the account and return access + refresh
    tokens in the same response, placing the user in a self-service
    organisation with the `analyst` role. In this product `analyst` carries
    scans:execute — so anyone who could reach this route could issue
    themselves a working credential and point Nmap, Scapy and Nuclei at the
    network from a worker running with raw-socket privileges on the host.

    Registration now yields nothing usable:

      * the route only exists when ALLOW_SELF_REGISTRATION is on (default off,
        because POST /admin/users is the supported onboarding path),
      * no tokens are returned — 202, not 201, because the account is pending,
      * the account is created is_verified=False, is_active=False,
        approved_at=NULL and cannot log in until *both* the mailbox is
        confirmed and an administrator approves it.

    The response body is identical whether or not the address was already
    registered, so this route cannot be used to enumerate accounts.
    """
    _require_self_registration_enabled()

    email = normalize_email(req.email)
    username = req.username.strip()

    # ── Volume ceilings ──────────────────────────────────────────────────────
    # Checked before anything is written. Both fail open; see
    # auth/registration_limits.py for why that is the right direction.
    if daily_ip_quota_exceeded(request):
        logger.warning("Registration refused: daily per-IP quota exhausted")
        raise HTTPException(
            status_code=429,
            detail="Too many registrations from this network today. Try again tomorrow.",
        )

    if pending_queue_full(db):
        logger.error(
            "Registration refused: the approval queue is at its configured "
            "ceiling. An administrator needs to triage it."
        )
        raise HTTPException(
            status_code=503,
            detail=(
                "New registrations are paused while pending accounts are "
                "reviewed. Please try again later."
            ),
        )

    # ── Email domain screening ───────────────────────────────────────────────
    # Raises 400 with a reason when the domain is a known throwaway service and
    # the guard is in enforce mode. This deliberately breaks the uniform-202
    # contract below, and it is safe to: the response says something about the
    # *domain*, which the caller already knew, and nothing about whether an
    # account exists. Telling someone their temp-mail was refused beats
    # accepting it and spending an administrator's time on it later.
    verdict = assert_email_allowed(db, email, request=request)

    # Uniform response for every outcome below. Returned on success, on an
    # already-registered email, and on a taken username, so none of the three
    # can be told apart by an unauthenticated caller.
    pending_response = {
        "detail": (
            "If that email address can be registered, a verification link is "
            "on its way. New accounts also require administrator approval "
            "before sign-in is enabled."
        ),
        "status": "pending_verification",
    }

    # The mailbox this address actually delivers to. `p.kumar+1@gmail.com` and
    # `pkumar@gmail.com` are one inbox and two distinct values of users.email,
    # so without this a single Gmail account registers unlimited users through a
    # domain nobody would ever blocklist. Falls back to the literal address when
    # no canonical form applies, so the uniqueness check never silently weakens.
    canonical = canonicalize_email(email)

    email_taken = bool(db.query(User).filter(email_matches(User.email, email)).first())
    if not email_taken and canonical:
        email_taken = bool(
            db.query(User).filter(User.email_canonical == canonical).first()
        )
    username_taken = bool(
        db.query(User).filter(username_matches(User.username, username)).first()
    )

    if email_taken or username_taken:
        # Logged server-side so the collision is visible to operators, and
        # deliberately not signalled to the caller.
        logger.info(
            "Registration collision (email_taken=%s username_taken=%s)",
            email_taken,
            username_taken,
        )
        return pending_response

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

    # A self-registered account lands on `viewer`, not `analyst`. Even once
    # verified and approved it is read-only until an administrator deliberately
    # raises it, so the approval step is a decision about access rather than a
    # rubber stamp on scan execution that has already been granted.
    default_role = db.query(Role).filter(Role.name == "viewer").first()

    if not default_role:
        raise HTTPException(status_code=500, detail="RBAC not seeded in production DB.")

    user = User(
        id=gen_user_id(self_service_org.slug, username),  # → usr_sel_pankaj_x9v1
        username=username,
        email=email,
        email_canonical=canonical or None,
        full_name=req.full_name,
        password_hash=hash_password(req.password),
        org_id=self_service_org.id,
        role_id=default_role.id,
        # Inert on all three axes until each is satisfied deliberately.
        is_verified=False,
        is_active=False,
        approved_at=None,
        # Advisory only. In flag mode a blocked verdict lands here instead of
        # refusing the request, which is what makes a staged rollout possible.
        is_email_flagged=verdict.flagged or verdict.blocked,
        email_risk=verdict.as_risk_payload(),
        flagged_at=utcnow() if (verdict.flagged or verdict.blocked) else None,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        # Lost the race against a concurrent registration for the same email or
        # username. The pre-checks above are advisory; the unique indexes are
        # what actually enforce this. Return the same body as every other
        # outcome rather than reporting which column collided.
        db.rollback()
        logger.info("Registration lost a uniqueness race; returning pending response")
        return pending_response

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
        changes={
            "source": "self_registration",
            "full_name": user.full_name,
            "state": "pending_verification",
            "email_domain": verdict.domain,
            "email_flags": verdict.flags,
        },
    )
    db.commit()

    _issue_verification_token(db, user, request=request)

    # The network half of the screening — MX presence and RDAP domain age —
    # runs here, after the response is decided and the row is committed.
    #
    # Never inline. This endpoint takes a domain chosen by an unauthenticated
    # caller, so resolving it in-request would let a stranger direct outbound
    # lookups from this host at a target of their choosing and time the result.
    # The signals it produces were only ever allowed to raise a flag, so nothing
    # is lost by learning them a few seconds later.
    _queue_email_risk_enrichment(user.id)

    return pending_response


def _queue_email_risk_enrichment(user_id: str) -> None:
    """Ask a worker to add the network-derived risk signals for one account."""
    from config import AppConfig

    if not AppConfig.EMAIL_RISK_ENRICHMENT_ENABLED:
        return
    try:
        from core.email_security_tasks import enrich_email_risk

        enrich_email_risk.delay(user_id)
    except Exception as exc:
        # An unavailable enrichment path is a coverage gap, not an error: the
        # account is already screened against the blocklist and already queued
        # for a human. Log it and move on rather than failing a registration
        # that has otherwise succeeded.
        logger.warning(
            "Could not queue email risk enrichment for %s: %s",
            user_id,
            exc.__class__.__name__,
        )


class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: str


@router.post("/verify-email")
@limiter.limit("10/minute")
def verify_email(
    req: VerifyEmailRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Redeem an email-verification token.

    Verification proves control of the mailbox at this moment. It proves
    nothing about identity and, on its own, grants no access: the account
    still needs `approved_at` before login succeeds (unless
    SELF_REGISTRATION_AUTO_APPROVE is deliberately enabled).

    Failures are uniform — expired, already-used, never-existed and
    wrong-user tokens all return the same 400 — so the endpoint cannot be used
    to probe which tokens exist.
    """
    import hashlib
    from datetime import datetime, timezone

    from config import AppConfig
    from core.audit import log_audit_event
    from db.base import utcnow
    from db.models import EmailVerificationToken

    invalid = HTTPException(
        status_code=400,
        detail="This verification link is invalid or has expired. Request a new one.",
    )

    token_hash = hashlib.sha256(req.token.encode("utf-8")).hexdigest()
    record = (
        db.query(EmailVerificationToken)
        .filter(EmailVerificationToken.token_hash == token_hash)
        .first()
    )
    if not record:
        raise invalid

    if record.expires_at <= datetime.now(timezone.utc):
        db.delete(record)
        db.commit()
        raise invalid

    user = db.query(User).filter(User.id == record.user_id).first()
    if not user or user.is_deleted:
        db.delete(record)
        db.commit()
        raise invalid

    # The token was issued for a specific address. If the account's email has
    # since changed, this link must not confirm the new one — otherwise
    # changing the address after requesting a link would let an old mailbox
    # verify an address it never received mail at.
    if normalize_email(record.email) != normalize_email(user.email):
        db.delete(record)
        db.commit()
        raise invalid

    user.is_verified = True

    auto_approved = AppConfig.SELF_REGISTRATION_AUTO_APPROVE
    if auto_approved:
        user.approved_at = utcnow()
        user.approved_by = "auto:SELF_REGISTRATION_AUTO_APPROVE"
        user.is_active = True

    # Single-use: the row is deleted in the same transaction that flips the flag.
    db.delete(record)

    log_audit_event(
        db,
        user,
        "user.email_verified",
        "user",
        str(user.id),
        request=request,
        status="success",
        changes={"auto_approved": auto_approved},
    )
    db.commit()

    if auto_approved:
        return {
            "detail": "Email verified. You can now sign in.",
            "status": "verified",
        }
    return {
        "detail": (
            "Email verified. Your account is awaiting administrator approval; "
            "you will be able to sign in once it is approved."
        ),
        "status": "pending_approval",
    }


@router.post(
    "/resend-verification",
    dependencies=[Depends(_require_self_registration_enabled)],
)
@limiter.limit("3/minute")
def resend_verification(
    req: ResendVerificationRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Re-send a verification link.

    Always returns 200 with the same body, whether the address is unknown,
    already verified, or genuinely pending — the response must not reveal
    which. Rate-limited per client because this endpoint sends mail to an
    address the caller chose, which makes it usable as a mail relay against a
    third party if left open.
    """
    _require_self_registration_enabled()

    generic = {
        "detail": (
            "If that address has an account awaiting verification, a new link "
            "is on its way."
        )
    }

    email = normalize_email(req.email.strip())
    user = db.query(User).filter(email_matches(User.email, email)).first()

    if not user or user.is_deleted or user.is_verified:
        # Nothing to do. Logged without the address so the log does not become
        # the enumeration oracle the response refuses to be.
        logger.info("Verification resend requested for a non-pending account")
        return generic

    _issue_verification_token(db, user, request=request)
    return generic


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

    identifier = req.email_or_username.strip()
    user = (
        db.query(User)
        .filter(
            or_(
                email_matches(User.email, identifier),
                username_matches(User.username, identifier),
            )
        )
        .first()
    )
    if not user:
        # Spend comparable time on an unknown identifier as on a known one.
        # Without this the endpoint answers "no such account" measurably faster
        # than "wrong password", which is the same enumeration leak the uniform
        # error message exists to prevent — just delivered by a stopwatch.
        _dummy_password_check(req.password)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # ── Lockout is checked before the password, deliberately ─────────────────
    # It is the one pre-credential check that must stay: its whole purpose is
    # to stop the brute-force attempt that is being made right now, and
    # verifying the password first would defeat it. It leaks only that *some*
    # account matched the identifier and is currently locked — which an
    # attacker who just caused the lockout already knows.
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
        # `identifier`, not `email` — there is no `email` local in this
        # function, so this handler raised NameError instead of logging, and a
        # malformed stored hash surfaced as a 500 rather than a failed login.
        logger.warning(
            "Password verification failed for login attempt on identifier=%s: %s",
            identifier,
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

    # ── Password is correct. Only now may account state be disclosed ─────────
    #
    # These four checks used to run *before* the password was verified, which
    # made each of them an account oracle: anyone could learn that an address
    # was registered — and whether it was deleted, disabled or in a suspended
    # organisation — by submitting it with any password at all and reading the
    # 403. The uniform "Invalid email or password" above was undone by the
    # branches that preceded it.
    #
    # Running them here costs one Argon2 verification against a known-bad
    # password and closes the leak: a caller who does not hold the credential
    # cannot reach any of these messages.
    user.failed_login_count = 0
    user.locked_until = None

    if getattr(user, "is_deleted", False):
        _deny_login(db, user, request, "account deleted", "Account deleted")

    if not user.is_verified:
        _deny_login(
            db,
            user,
            request,
            "email not verified",
            "Verify your email address before signing in. "
            "Use the link we sent you, or request a new one.",
        )

    if user.approved_at is None:
        _deny_login(
            db,
            user,
            request,
            "awaiting administrator approval",
            "Your account is awaiting administrator approval.",
        )

    if not user.is_active:
        _deny_login(db, user, request, "account disabled", "Account disabled")

    # ─ Organization Status Check ────────────────────────────────────────────
    # Prevent login for users whose organization has been deactivated.
    # User statuses remain unchanged for reversibility.
    organization = db.query(Organization).filter(Organization.id == user.org_id).first()
    if organization and not organization.is_active:
        _deny_login(
            db,
            user,
            request,
            "organization deactivated",
            "Your organization has been deactivated. Please contact support.",
        )

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
            "full_name": user.full_name,
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
# Unauthenticated in the FastAPI sense — the refresh token in the cookie is
# what identifies the session, so there is no dependency to refuse first. That
# makes it reachable by anyone, and it writes to the database on every call.
# Generous, because closing several tabs logs out several sessions at once.
@limiter.limit("30/minute")
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
        "full_name": current_user.full_name,
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
# The other unauthenticated write path. It mints access tokens, rotates the
# refresh token and writes two rows per call, and nothing bounded how often it
# could be driven. 30/minute clears real use by a wide margin — the SPA
# refreshes on 401 and every 20 minutes, so a busy user with several tabs open
# is still in single figures per hour.
@limiter.limit("30/minute")
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
    from core.mail_dispatch import dispatch_email
    from core.throttle import hit
    from db.models import PasswordResetToken

    identifier = req.email_or_username.strip()

    user = (
        db.query(User)
        .filter(
            or_(
                email_matches(User.email, identifier),
                username_matches(User.username, identifier),
            )
        )
        .first()
    )

    # The submitted identifier is deliberately not logged, and neither is
    # whether it matched. This endpoint refuses to disclose account existence
    # over HTTP by always returning the same 200; writing "not registered in
    # the database" beside the address to a log file simply moves the oracle
    # somewhere with a wider audience and a longer retention period. The user
    # id is safe to record once matched, and is enough to reconstruct events.
    if user:
        logger.info("Password reset requested for user id=%s", user.id)
    else:
        logger.info("Password reset requested for an unrecognised identifier")

    # Ceiling on how often one *account* can be sent a reset link.
    #
    # The per-IP limit above bounds a burst from one source and does nothing
    # about a caller who rotates addresses, which is all it takes to turn this
    # endpoint into a mail bomb aimed at somebody else's inbox — the address is
    # chosen by the caller and the mail is sent by us.
    #
    # Keyed on the user id, and when it trips the request falls through to the
    # same 200 below having sent nothing. Answering 429 here would be an
    # account-existence oracle: only a real account can exceed a per-account
    # ceiling, so the status code would disclose exactly what the uniform
    # response exists to hide.
    if user and hit(
        "pwreset:account",
        str(user.id),
        AppConfig.PASSWORD_RESET_ACCOUNT_HOURLY_LIMIT,
        window_seconds=3600,
    ):
        logger.warning(
            "Password-reset requests for user id=%s exceeded the hourly "
            "ceiling; no mail sent",
            user.id,
        )
        user = None

    if user:
        # Invalidate any reset link already outstanding for this account.
        #
        # Without this, each request added a token and every one of them stayed
        # redeemable, so asking three times produced three working links from
        # three separate emails. The newest link is the one the user is looking
        # at; the older ones are unattended copies of a credential sitting in a
        # mailbox.
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id
        ).delete(synchronize_session=False)

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
        dispatch_email("password_reset", user.email, user.username, reset_link)

    return {
        "detail": "If this email is registered, you will receive a reset link shortly."
    }


@router.post("/reset-password")
@limiter.limit("5/minute")
def reset_password_endpoint(
    req: ResetPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Resets the user's password using the secure token.
    Validates token presence, expiration, updates the user's password,
    invalidates all current user sessions, and revokes the token.

    Anti-automation
    ───────────────
    This endpoint carried no rate limit at all, which made it the one
    unauthenticated write path in the API that could be driven without bound.
    That is not primarily a token-guessing risk — the token is 32 random bytes
    and `/auth/forgot-password` next door was already limited — it is that an
    unbounded endpoint produces no signal. A script could submit for as long as
    it liked and the only trace was a stream of 400s that nothing counted.

    Two ceilings now, both per client IP: a burst limit above, and an hourly
    cap on *failed* submissions below. Failures only, so a household or office
    behind one NAT address resetting passwords legitimately is never affected
    by its neighbours — you have to be getting it wrong to accumulate.
    """
    import hashlib
    from datetime import datetime, timezone

    from auth.jwt_handler import hash_password
    from config import AppConfig
    from core.audit import log_audit_event
    from core.throttle import client_identity, hit
    from db.models import PasswordResetToken, RefreshTokenSession

    caller = client_identity(request)

    def _reject_bad_token() -> NoReturn:
        """Count a failed submission, then answer the uniform 400.

        Deliberately identical for an unknown token, an expired one and one
        whose user has since been removed: the three are indistinguishable to
        the caller, so none of them can be used to probe for a live token.
        """
        if hit(
            "pwreset:ip",
            caller,
            AppConfig.PASSWORD_RESET_IP_HOURLY_LIMIT,
            window_seconds=3600,
        ):
            logger.warning(
                "Password-reset submissions from %s exceeded the hourly ceiling",
                caller,
            )
            raise HTTPException(
                status_code=429,
                detail="Too many password reset attempts. Try again later.",
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token.",
        )

    token_hash = hashlib.sha256(req.token.encode("utf-8")).hexdigest()

    # Find the token in the database
    reset_token = (
        db.query(PasswordResetToken)
        .filter(PasswordResetToken.token_hash == token_hash)
        .first()
    )
    if not reset_token:
        _reject_bad_token()

    # Check expiration
    if reset_token.expires_at <= datetime.now(timezone.utc):
        db.delete(reset_token)
        db.commit()
        _reject_bad_token()

    # Fetch user
    user = db.query(User).filter(User.id == reset_token.user_id).first()
    if not user:
        db.delete(reset_token)
        db.commit()
        # "User not found." used to be returned here, which told a caller
        # holding a token for a deleted account something the other two
        # branches did not. One message for all three.
        _reject_bad_token()

    # Update user password
    user.password_hash = hash_password(req.password)

    # Invalidate all active sessions for the user
    db.query(RefreshTokenSession).filter(RefreshTokenSession.user_id == user.id).delete(
        synchronize_session=False
    )

    # Retire every reset token this account holds, not only the one redeemed.
    #
    # Single-use was already enforced for the token presented, but a user who
    # clicked "forgot password" three times left three live tokens and only one
    # was consumed here. The others stayed valid for the rest of their 15
    # minutes against a password that had already been changed — so a link
    # leaked from an inbox or a proxy log still worked *after* the legitimate
    # owner had completed a reset, which is precisely the moment it must not.
    db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id).delete(
        synchronize_session=False
    )

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

    # Tell the account owner out-of-band that their password changed. If the
    # reset was an attacker completing a takeover, this notice is the only
    # signal the real owner gets, and it reaches a channel the attacker had to
    # compromise to get this far. Dispatched via Celery and never awaited: a
    # broken SMTP server must not turn a completed reset into a 500 that
    # invites the user to try again with a token that no longer exists.
    try:
        from core.ip_resolver import get_client_ip
        from core.mail_dispatch import dispatch_email

        dispatch_email(
            "password_changed",
            user.email,
            user.username,
            datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC"),
            get_client_ip(request),
        )
    except Exception:
        logger.warning(
            "Could not queue password-change notification for user id=%s",
            user.id,
            exc_info=True,
        )

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

    from core.mail_dispatch import dispatch_email
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
    dispatch_email("mfa_otp", user.email, user.username, code)

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
