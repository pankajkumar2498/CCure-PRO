"""
routers/web_scans.py
────────────────────────────────────────────────────────────────────────────
FastAPI endpoints for Web Application Scanning (DAST).

Endpoints:
  POST   /web-scans                     — Start a new web scan
  GET    /web-scans                     — List web scans (org-scoped)
  GET    /web-scans/{id}                — Get scan details + progress
  GET    /web-scans/{id}/findings       — Get findings (filterable)
  GET    /web-scans/{id}/assets         — Get discovered endpoints
  POST   /web-scans/{id}/cancel         — Cancel a running scan
  PATCH  /web-scans/{id}/findings/{fid} — Triage a finding
"""

import asyncio
import json
import logging
from datetime import timedelta
from typing import Dict, List, Optional

from ccure_platform.api import CurrentUser, require_permission, user_has_permission
from auth.jwt_handler import decode_token
from ccure_platform.api import log_audit_event
from db.base import SessionLocal, gen_web_scan_id, get_db, utcnow
from ccure_platform import api as platform_api
from db.models import User
from core.web.finding_view import (  # noqa: F401  (the old private names stay)
    finding_curl as _finding_curl,
    finding_detail as _finding_detail,
)
from core.web.auth.secrets import encrypt_auth_config
from db.models.web_scans import (
    WebApiOperation,
    WebAsset,
    WebFinding,
    WebForm,
    WebParameter,
    WebScan,
)
from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from pydantic import BaseModel, Field, field_validator
from scan_helpers import limiter
from sqlalchemy.orm import Session, joinedload

log = logging.getLogger("ccure.routers.web_scans")

router = APIRouter(prefix="/web-scans", tags=["Web Scans"])


# ── Helpers ───────────────────────────────────────────────────────────────────


def _is_superadmin(user: CurrentUser) -> bool:
    return (
        getattr(getattr(user, "role", None), "name", "") or ""
    ).lower() == "superadmin"


def _resolve_org(user: CurrentUser, requested_org: str | None) -> str:
    if _is_superadmin(user) and requested_org:
        return requested_org
    return str(user.org_id)


IDEMPOTENCY_WINDOW = timedelta(minutes=10)
ACTIVE_SCAN_STATUSES = {"queued", "pending", "running"}


# ── Pydantic Schemas ──────────────────────────────────────────────────────────


class WebScanScopeSchema(BaseModel):
    include_subdomains: bool = False
    exclude_paths: list[str] = Field(default_factory=list)
    max_depth: int = Field(default=5, ge=1, le=20)


class AccessControlUserSchema(BaseModel):
    """One authorization context for Phase 4 access-control testing."""

    label: str = Field(description="A short identity label, e.g. 'A', 'B', 'admin'.")
    auth: dict = Field(
        default_factory=dict,
        description="This user's own auth config (same shape as the top-level "
        "auth block). Its secrets are encrypted at rest like the main login.",
    )
    privileged: bool = Field(
        default=False,
        description="Marks an administrator/high-privilege identity, used as the "
        "baseline for vertical privilege-escalation checks.",
    )


class AccessControlSchema(BaseModel):
    """Phase 4 multi-user access-control (IDOR / privilege-escalation) config."""

    users: list[AccessControlUserSchema] = Field(
        default_factory=list,
        description="Additional isolated identities (User B, an administrator) "
        "tested against the resources the main session can reach.",
    )
    admin_paths: list[str] = Field(
        default_factory=list,
        description="Known administrator-only paths, tested for vertical "
        "privilege escalation by lower-privilege identities.",
    )
    allow_write_testing: bool = Field(
        default=False,
        description="Permit safe state-changing method probes. Off by default: "
        "testing is read-only unless the environment explicitly allows writes.",
    )


class WebScanAuthSchema(BaseModel):
    type: str = Field(
        default="none",
        description=(
            "Auth type: none, form_login, bearer_token, cookie, custom_header, "
            "multi_step, jwt, api_key, oauth2, oauth2_authcode, oidc, saml, "
            "recorded"
        ),
    )
    # ── Phase 23c: recorded login sequence (Codex item 6) ─────────────────────
    recorded_steps: list[dict] | None = Field(
        default=None,
        description="Ordered browser actions to replay a recorded login: "
        "[{action: goto|fill|click|select|press|wait|wait_for, selector?, "
        "value?, url?, timeout?}]. The recording is produced in a browser and "
        "replayed headless to capture the authenticated session.",
    )
    capture_local_storage: list[str] | None = Field(
        default=None,
        description="localStorage keys to read after a recorded login; a "
        "token-like value is presented as a Bearer header so token-auth SPAs "
        "are scanned as logged in.",
    )
    # ── Phase 23: browser-driven redirect login (OAuth2 auth-code / OIDC / SAML)
    start_url: str | None = Field(
        default=None, description="URL that initiates the redirect login flow."
    )
    idp_username_field: str | None = Field(
        default=None, description="CSS selector for the IdP username/email field."
    )
    idp_password_field: str | None = Field(
        default=None, description="CSS selector for the IdP password field."
    )
    idp_submit: str | None = Field(
        default=None, description="CSS selector for the IdP submit button."
    )
    # ── Phase 23b: redirect-login edge cases (identifier-first / MFA / consent)
    idp_next_submit: str | None = Field(
        default=None,
        description="CSS selector for the 'Next' button in an identifier-first "
        "flow (username, Next, then password on a second screen).",
    )
    idp_mfa_field: str | None = Field(
        default=None, description="CSS selector for the MFA/OTP code field."
    )
    mfa_code: str | None = Field(
        default=None, description="Static one-time code for the MFA screen."
    )
    totp_secret: str | None = Field(
        default=None,
        description="Base32 TOTP shared secret; a current code is generated for "
        "the MFA screen when mfa_code is not supplied.",
    )
    idp_consent_submit: str | None = Field(
        default=None,
        description="CSS selector for the OAuth consent/authorize/allow button.",
    )
    success_url_contains: str | None = Field(
        default=None, description="Substring expected in the post-login URL."
    )
    login_url: str | None = None
    username: str | None = None
    password: str | None = None
    username_field: str = "username"
    password_field: str = "password"
    success_indicator: str | None = None
    token: str | None = None
    cookies: dict[str, str] | None = None
    headers: dict[str, str] | None = None
    # ── Phase 23: modern token auth (jwt / api_key / oauth2) ──────────────────
    jwt: str | None = Field(default=None, description="Static JWT for type=jwt.")
    key: str | None = Field(default=None, description="API key value for type=api_key.")
    value: str | None = Field(default=None, description="Alias for key/token value.")
    header: str | None = Field(
        default=None, description="Header name for jwt/api_key injection."
    )
    prefix: str | None = Field(
        default=None, description="Value prefix, e.g. 'Bearer ' or 'ApiKey '."
    )
    token_url: str | None = Field(
        default=None, description="OAuth2 token endpoint for type=oauth2."
    )
    grant_type: str | None = Field(
        default=None, description="OAuth2 grant: client_credentials | password."
    )
    client_id: str | None = None
    client_secret: str | None = None
    scope: str | None = None
    audience: str | None = None
    token_field: str | None = Field(
        default=None,
        description="JSON field holding the access token (default access_token).",
    )
    # ── Phase 3: CSRF / hidden-token logins, verification, re-auth ────────────
    csrf_field: str | None = Field(
        default=None,
        description="Name of the anti-CSRF token field on the login page. "
        "When omitted, all hidden fields are captured automatically.",
    )
    csrf_url: str | None = Field(
        default=None,
        description="Page to read the CSRF/hidden token from before logging in "
        "(defaults to login_url).",
    )
    extract_hidden: bool = Field(
        default=True,
        description="Carry the login page's hidden form fields into the login.",
    )
    failure_indicator: str | None = Field(
        default=None,
        description="Text whose presence in a response means the session is "
        "invalid / login failed.",
    )
    verify_url: str | None = Field(
        default=None,
        description="Authenticated-only URL fetched after login to confirm the "
        "session works.",
    )
    verify_success_indicator: str | None = Field(
        default=None,
        description="Text expected on verify_url when authenticated "
        "(defaults to success_indicator).",
    )
    max_reauth: int = Field(
        default=2,
        ge=0,
        le=10,
        description="Maximum re-authentication attempts if the session is lost "
        "mid-scan.",
    )
    login_steps: list[dict] | None = Field(
        default=None,
        description="Multi-step login/workflow: an ordered list of "
        "{method,url,fields,extract,success_indicator} steps run on one session.",
    )
    # Phase 13: a browser-driven authenticated workflow (login -> dashboard ->
    # resource -> action) as validated configuration. The endpoints it reaches
    # are handed to the DETECT engines. Either a bare list of actions or
    # {actions:[...], timeout_ms:...}.
    workflow: dict | list | None = Field(
        default=None,
        description="Authenticated multi-step workflow: an ordered list of "
        "actions (open/click/type/select/submit/wait/extract/verify/"
        "capture_token/capture_cookie/api_request) replayed in one browser "
        "session; discovered authenticated endpoints feed the security engines.",
    )

    @field_validator("workflow")
    @classmethod
    def _valid_workflow(cls, value):
        if value is None:
            return None
        from core.web.workflow.actions import validate_workflow

        errs = validate_workflow(value)
        if errs:
            raise ValueError("; ".join(errs[:5]))
        return value

    access_control: AccessControlSchema | None = Field(
        default=None,
        description="Phase 4 access-control testing: additional isolated users "
        "(B, admin) and admin paths for IDOR / privilege-escalation checks.",
    )
    # Token-based logins. The session manager supports these, but with no field
    # here Pydantic drops them from the request body, so an operator scanning a
    # JSON-API application had no way to describe its login and the scan ran
    # anonymously.
    method: str = Field(default="POST", description="Login request method")
    content_type: str = Field(
        default="auto",
        description="Login body encoding: auto, form, or json",
    )
    token_path: str | None = Field(
        default=None,
        description="Dot path to the token in a JSON login response, "
        "e.g. 'authentication.token'. Auto-detected when omitted.",
    )
    token_header: str = Field(default="Authorization")
    token_prefix: str = Field(default="Bearer ")
    extra_fields: dict[str, str] | None = Field(
        default=None, description="Additional fields to send with the login"
    )


class WebScanOptionsSchema(BaseModel):
    enable_sqli: bool = True
    enable_xss: bool = True
    # Phase 2 / 4 / 5 engines (default on; a field so a client can disable one).
    enable_injection: bool = True
    enable_access_control: bool = True
    enable_api_scan: bool = True
    # Phase 9 active OOB probing. Runs only when a self-hosted OAST collaborator
    # is configured (OAST_SERVER / OAST_DOMAIN / OAST_HTTP_URL); this flag lets a
    # client turn the pass off even when one is.
    enable_oast: bool = True
    # Phase 5 API import knobs.
    api_spec_url: str | None = Field(
        default=None, description="URL of an OpenAPI/Swagger spec to import."
    )
    graphql_url: str | None = Field(
        default=None, description="GraphQL endpoint URL to probe for introspection."
    )
    api_discover: bool = Field(
        default=True,
        description="Auto-discover an OpenAPI spec and GraphQL endpoint at "
        "well-known paths.",
    )
    # Phase 23, Item 8: traffic-based API import. Inline JSON (or a parsed dict)
    # for a HAR export or a Postman v2 collection; same-origin requests become
    # scan targets alongside the spec/GraphQL surface.
    har: dict | None = Field(
        default=None, description="A HAR document (JSON) to import requests from."
    )
    postman: dict | None = Field(
        default=None, description="A Postman v2 collection (JSON) to import."
    )
    wsdl: str | None = Field(
        default=None,
        description="A WSDL (SOAP) document (XML) to import operations from.",
    )
    # Phase 23, Crawler 2.0: opt-in autonomous SPA interaction — click safe,
    # non-destructive controls to reach client-side routes a link crawl misses.
    # Off by default: clicking is an active behaviour on a production target.
    spa_interaction: bool = Field(
        default=False,
        description="Autonomously click non-destructive controls to discover "
        "SPA routes/state (active behaviour; off by default).",
    )
    nuclei_severity: list[str] = Field(default=["medium", "high", "critical"])
    rate_limit: int = Field(default=10, ge=1, le=100)
    # ── Phase 23c: scan policy engine (Codex P2 item 11) ──────────────────────
    scan_policy: str | None = Field(
        default=None,
        description="Named policy preset: safe, standard, deep, api, "
        "authenticated. Explicit knobs below override the preset.",
    )
    max_params_per_page: int | None = Field(
        default=None, ge=1, le=200, description="Cap parameters tested per page."
    )
    attack_cookies: bool | None = Field(
        default=None, description="Test cookies as injection points (sqlmap L2)."
    )
    attack_headers: bool | None = Field(
        default=None, description="Test HTTP headers as injection points (sqlmap L3)."
    )
    attack_file_uploads: bool | None = Field(
        default=None, description="Test multipart/file-upload fields."
    )
    nuclei_timeout: int | None = Field(
        default=None, ge=30, le=14400, description="Per-scan Nuclei time budget (s)."
    )
    sqlmap_timeout: int | None = Field(
        default=None, ge=30, le=3600, description="Per-target sqlmap time budget (s)."
    )
    # The orchestrator implements quick/standard/deep depth profiles and
    # defaults to standard. Without this field the request body could not carry
    # the choice, so the profiles were unreachable through the API.
    scan_depth: str = Field(
        default="standard",
        description="Template coverage: quick, standard, or deep",
    )

    # Phase 10 nuclei profile. Optional; when set it overrides the scan_depth
    # mapping (quick→FAST, standard→STANDARD, deep→DEEP). Kept as a distinct
    # field because "profile" is the term operators use for the nuclei run.
    nuclei_profile: str | None = Field(
        default=None,
        description="Nuclei scan profile: fast, standard, or deep.",
    )

    @field_validator("scan_depth")
    @classmethod
    def _known_depth(cls, value: str) -> str:
        from orchestrator.web_orchestrator import SCAN_DEPTHS

        normalized = (value or "").strip().lower()
        if normalized not in SCAN_DEPTHS:
            raise ValueError(
                f"scan_depth must be one of: {', '.join(sorted(SCAN_DEPTHS))}"
            )
        return normalized

    @field_validator("nuclei_profile")
    @classmethod
    def _known_profile(cls, value):
        if value is None or not str(value).strip():
            return None
        from core.web.nuclei.profiles import normalize_profile

        canonical = normalize_profile(value)
        if canonical is None:
            raise ValueError("nuclei_profile must be one of: fast, standard, deep")
        return canonical


class StartWebScanRequest(BaseModel):
    target_url: str = Field(..., min_length=8, max_length=2048)
    scan_name: str | None = Field(None, max_length=255)
    scan_scope: WebScanScopeSchema = Field(default_factory=WebScanScopeSchema)
    auth: WebScanAuthSchema = Field(default_factory=WebScanAuthSchema)
    options: WebScanOptionsSchema = Field(default_factory=WebScanOptionsSchema)
    authorization_confirmed: bool = Field(
        ...,
        description="User MUST confirm they are authorized to scan this target",
    )


class TriageFindingRequest(BaseModel):
    status: str = Field(
        ..., description="open, confirmed, false_positive, accepted_risk, fixed"
    )
    reason: str | None = None


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", status_code=201)
# Same class as /scan/host-discovery and the other dispatch routes, and it was
# the only one of them with no limit. This sends ffuf and nuclei at a target
# the caller names, so an unbounded loop here is an unbounded outbound attack
# from this host's address — the abuse lands on somebody else's network and
# arrives with our name on it.
@limiter.limit("5/minute")
def start_web_scan(
    request: Request,
    response: Response,
    body: StartWebScanRequest,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("scans", "execute")),
):
    """
    Start a new web application scan.

    Requires authorization_confirmed=true (legal compliance gate).
    The scan runs as a background Celery task pipeline:
    RECON → CRAWL → DETECT → AUDIT
    """
    # ── Authorization gate ────────────────────────────────────────────────
    if not body.authorization_confirmed:
        raise HTTPException(
            status_code=422,
            detail="You must confirm authorization to scan this target (authorization_confirmed=true).",
            headers={"X-Error-Code": "AUTHORIZATION_NOT_CONFIRMED"},
        )

    # ── Validate target URL ──────────────────────────────────────────────
    # Robust cleanup: strip whitespace, hidden Unicode, and non-printable chars
    import re

    target_url = body.target_url.strip()
    # Remove control characters and non-printable Unicode (like zero-width space/joiner)
    target_url = re.sub(
        r"[\x00-\x1F\x7F-\x9F\u2000-\u200F\u2028-\u202F\u205F-\u206F]", "", target_url
    )

    if not target_url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=422, detail="target_url must start with http:// or https://"
        )

    from urllib.parse import urlparse

    parsed = urlparse(target_url)
    target_domain = parsed.netloc
    if not target_domain:
        raise HTTPException(
            status_code=422, detail="Invalid target URL — could not extract domain"
        )

    # ── Org context ──────────────────────────────────────────────────────
    idempotency_key = _normalize_idempotency_key(idempotency_key)
    target_org_id = _resolve_org(user, org_id)

    org = platform_api.organisation(db, target_org_id)
    org_slug = org.slug if org else target_org_id

    duplicate_scan = _find_duplicate_web_scan(
        db=db,
        user=user,
        org_id=target_org_id,
        target_url=target_url,
        idempotency_key=idempotency_key,
    )
    if duplicate_scan:
        log.info(
            "Web scan duplicate launch collapsed: %s -> %s (user=%s)",
            target_url,
            duplicate_scan.id,
            user.id,
        )
        return _start_scan_response(
            duplicate_scan,
            duplicate=True,
            message="Existing web scan returned for this launch request.",
        )

    # ── Create WebScan record ────────────────────────────────────────────
    scan_id = gen_web_scan_id(org_slug)

    scan = WebScan(
        id=scan_id,
        org_id=target_org_id,
        created_by=user.id,
        scan_name=body.scan_name or f"Web Scan: {target_domain}",
        target_url=target_url,
        target_domain=target_domain,
        scan_scope=body.scan_scope.model_dump(),
        auth_config=encrypt_auth_config(body.auth.model_dump(exclude_none=True)),
        options={
            **body.options.model_dump(),
            "_launch": {
                "idempotency_key": idempotency_key,
                "requested_by": str(user.id),
                "requested_at": utcnow().isoformat(),
            },
        },
        rate_limit=body.options.rate_limit,
        authorization_confirmed=True,
        status="queued",
        pipeline_phase="queued",
        started_at=utcnow(),
    )
    db.add(scan)
    # Recorded in the same commit as the row, so a web scan cannot exist
    # without the trail saying who launched it, against what, and that they
    # confirmed authorisation. That confirmation is a client-supplied boolean;
    # the audit entry is the only durable record that it was given, and by whom.
    # The auth block is summarised by type only — it carries passwords, tokens,
    # TOTP secrets and cookies, none of which belongs in an audit row.
    log_audit_event(
        db=db,
        user=user,
        action="web_scan.created",
        resource_type="web_scan",
        resource_id=scan_id,
        changes={
            "target_url": target_url,
            "scan_name": body.scan_name,
            "authorization_confirmed": True,
            "auth_type": body.auth.type,
            "include_subdomains": body.scan_scope.include_subdomains,
            "max_depth": body.scan_scope.max_depth,
            "scan_policy": body.options.scan_policy,
            "rate_limit": body.options.rate_limit,
        },
        request=request,
        org_id=target_org_id,
    )
    db.commit()
    db.refresh(scan)

    # ── Dispatch Phase 1 (RECON) ─────────────────────────────────────────
    from core.web.tasks import run_web_recon_task

    task = run_web_recon_task.delay(
        user_id=user.id,
        web_scan_id=scan_id,
        target_url=target_url,
        scan_scope=body.scan_scope.model_dump(),
        options=body.options.model_dump(),
    )

    db.query(WebScan).filter(WebScan.id == scan_id).update(
        {
            "current_task_id": task.id,
            "status": "running",
        }
    )
    db.commit()
    db.refresh(scan)

    return _start_scan_response(
        scan,
        task_id=task.id,
        message="Web scan queued successfully. Pipeline: RECON -> CRAWL -> DETECT -> AUDIT",
    )


@router.get("")
def list_web_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: str | None = Query(None),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("scans", "read")),
):
    """List web scans for the resolved organization."""
    target_org_id = _resolve_org(user, org_id)
    query = db.query(WebScan).filter(
        WebScan.org_id == target_org_id,
        WebScan.is_deleted == False,
    )

    if status:
        query = query.filter(WebScan.status == status)

    total = query.count()
    scans = (
        query.order_by(WebScan.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return {
        "success": True,
        "data": [_scan_summary(s) for s in scans],
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
        },
    }


@router.get("/{scan_id}")
def get_web_scan(
    scan_id: str,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("scans", "read")),
):
    """Get detailed web scan information including phase progress."""
    scan = _get_scan_or_404(db, scan_id, user, org_id)

    return {
        "success": True,
        "data": {
            **_scan_summary(scan),
            "scan_scope": scan.scan_scope,
            "options": scan.options,
            "waf_detected": scan.waf_detected,
            "tech_stack": scan.tech_stack,
            "subdomains": scan.subdomains,
            "phases": {
                "recon": {
                    "status": scan.recon_status,
                    "started_at": _iso(scan.recon_started_at),
                    "completed_at": _iso(scan.recon_completed_at),
                },
                "crawl": {
                    "status": scan.crawl_status,
                    "started_at": _iso(scan.crawl_started_at),
                    "completed_at": _iso(scan.crawl_completed_at),
                },
                "detect": {
                    "status": scan.detect_status,
                    "started_at": _iso(scan.detect_started_at),
                    "completed_at": _iso(scan.detect_completed_at),
                },
                "audit": {
                    "status": scan.audit_status,
                    "started_at": _iso(scan.audit_started_at),
                    "completed_at": _iso(scan.audit_completed_at),
                },
            },
        },
    }


@router.get("/{scan_id}/findings")
def get_web_scan_findings(
    scan_id: str,
    severity: str | None = Query(None),
    finding_type: str | None = Query(None),
    status: str | None = Query(None, alias="finding_status"),
    detected_by: str | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("findings", "read")),
):
    """Get findings for a web scan with filtering and pagination."""
    scan = _get_scan_or_404(db, scan_id, user, org_id)

    query = db.query(WebFinding).filter(WebFinding.web_scan_id == scan_id)

    if severity:
        query = query.filter(WebFinding.severity == severity.lower())
    if finding_type:
        query = query.filter(WebFinding.finding_type == finding_type)
    if status:
        query = query.filter(WebFinding.status == status)
    if detected_by:
        query = query.filter(WebFinding.detected_by.ilike(f"%{detected_by}%"))

    total = query.count()
    findings = (
        query.order_by(
            # Critical first, then high, medium, low, info
            WebFinding.severity.desc(),
            WebFinding.created_at.desc(),
        )
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return {
        "success": True,
        "data": [_finding_detail(f) for f in findings],
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
        },
    }


@router.get("/{scan_id}/assets")
def get_web_scan_assets(
    scan_id: str,
    source: str | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("scans", "read")),
):
    """Get discovered web assets/endpoints for a scan."""
    scan = _get_scan_or_404(db, scan_id, user, org_id)

    query = db.query(WebAsset).filter(WebAsset.web_scan_id == scan_id)
    if source:
        query = query.filter(WebAsset.source == source)

    total = query.count()
    assets = (
        query.order_by(WebAsset.created_at.asc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return {
        "success": True,
        "data": [_asset_detail(a) for a in assets],
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
        },
    }


@router.get("/{scan_id}/parameters")
def get_web_scan_parameters(
    scan_id: str,
    location: str | None = Query(None, description="query/form/json/path/…/soap"),
    tested: bool | None = Query(None, description="filter by coverage status"),
    name: str | None = Query(None, description="parameter name (exact)"),
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=500),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("scans", "read")),
):
    """
    The attack surface at parameter granularity (Phase 23b relational model):
    every (endpoint, location, name) with its coverage — tested, by which
    engines, or why it was skipped. Filterable by location, coverage status and
    name, which the JSONB parameter blob and the report's coverage summary
    cannot answer relationally. Includes an ``untested`` roll-up so a caller can
    see, in one call, how much surface remains unassessed.
    """
    scan = _get_scan_or_404(db, scan_id, user, org_id)

    query = db.query(WebParameter).filter(WebParameter.web_scan_id == scan.id)
    if location:
        query = query.filter(WebParameter.location == location)
    if tested is not None:
        query = query.filter(WebParameter.tested == tested)
    if name:
        query = query.filter(WebParameter.name == name)

    total = query.count()
    tested_total = (
        db.query(WebParameter)
        .filter(
            WebParameter.web_scan_id == scan.id,
            WebParameter.tested.is_(True),
        )
        .count()
    )
    surface_total = (
        db.query(WebParameter).filter(WebParameter.web_scan_id == scan.id).count()
    )
    rows = (
        query.order_by(
            WebParameter.tested.asc(),  # untested first — the interesting rows
            WebParameter.location.asc(),
            WebParameter.name.asc(),
        )
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return {
        "success": True,
        "data": [
            {
                "id": p.id,
                "web_asset_id": p.web_asset_id,
                "location": p.location,
                "name": p.name,
                "source": p.source,
                "tested": p.tested,
                "tested_by": p.tested_by or [],
                "skipped_reason": p.skipped_reason,
            }
            for p in rows
        ],
        "coverage": {
            "surface_parameters": surface_total,
            "tested_parameters": tested_total,
            "untested_parameters": surface_total - tested_total,
            "coverage_pct": (
                round(100.0 * tested_total / surface_total, 1) if surface_total else 0.0
            ),
        },
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
        },
    }


@router.get("/{scan_id}/forms")
def get_web_scan_forms(
    scan_id: str,
    has_file_upload: bool | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=500),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("scans", "read")),
):
    """The discovered form inventory (Codex item 1) — first-class WebForm rows
    with their inputs, file-upload and password flags."""
    scan = _get_scan_or_404(db, scan_id, user, org_id)
    query = db.query(WebForm).filter(WebForm.web_scan_id == scan.id)
    if has_file_upload is not None:
        query = query.filter(WebForm.has_file_upload == has_file_upload)
    total = query.count()
    rows = (
        query.order_by(WebForm.action_url.asc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return {
        "success": True,
        "data": [
            {
                "id": f.id,
                "action_url": f.action_url,
                "method": f.method,
                "page_url": f.page_url,
                "inputs": f.inputs or [],
                "input_count": f.input_count,
                "has_file_upload": f.has_file_upload,
                "has_password": f.has_password,
                "source": f.source,
            }
            for f in rows
        ],
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
        },
    }


@router.get("/{scan_id}/api-operations")
def get_web_scan_api_operations(
    scan_id: str,
    kind: str | None = Query(None, description="rest / graphql / soap"),
    page: int = Query(1, ge=1),
    per_page: int = Query(200, ge=1, le=500),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("scans", "read")),
):
    """The API operation inventory (Codex item 1) — REST/GraphQL/SOAP operations
    as first-class WebApiOperation rows, with a per-kind roll-up."""
    scan = _get_scan_or_404(db, scan_id, user, org_id)
    query = db.query(WebApiOperation).filter(WebApiOperation.web_scan_id == scan.id)
    if kind:
        query = query.filter(WebApiOperation.kind == kind)
    total = query.count()
    all_rows = db.query(WebApiOperation.kind).filter(
        WebApiOperation.web_scan_id == scan.id
    )
    by_kind: dict[str, int] = {}
    for (k,) in all_rows:
        by_kind[k] = by_kind.get(k, 0) + 1
    rows = (
        query.order_by(WebApiOperation.kind.asc(), WebApiOperation.identity.asc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return {
        "success": True,
        "data": [
            {
                "id": o.id,
                "kind": o.kind,
                "identity": o.identity,
                "url": o.url,
                "method": o.method,
                "operation_name": o.operation_name,
                "spec_source": o.spec_source,
                "parameters": o.parameters or {},
                "secured": o.secured,
            }
            for o in rows
        ],
        "by_kind": by_kind,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
        },
    }


@router.post("/{scan_id}/cancel")
def cancel_web_scan(
    scan_id: str,
    request: Request,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("scans", "execute")),
):
    """Cancel a running web scan."""
    scan = _get_scan_or_404(db, scan_id, user, org_id)

    if scan.status in ("complete", "cancelled", "failed"):
        raise HTTPException(
            status_code=409,
            detail=f"Scan is already {scan.status}",
        )

    # Revoke the Celery task
    if scan.current_task_id:
        try:
            from core.celery_app import celery_app

            import sys

            sig = "SIGTERM" if sys.platform == "win32" else "SIGKILL"
            celery_app.control.revoke(scan.current_task_id, terminate=True, signal=sig)
        except Exception as exc:
            log.warning("Failed to revoke task %s: %s", scan.current_task_id, exc)

    previous_status = scan.status
    db.query(WebScan).filter(WebScan.id == scan_id).update(
        {
            "status": "cancelled",
            "completed_at": utcnow(),
            "updated_at": utcnow(),
        }
    )
    log_audit_event(
        db=db,
        user=user,
        action="web_scan.cancelled",
        resource_type="web_scan",
        resource_id=scan_id,
        changes={"status": {"from": previous_status, "to": "cancelled"}},
        request=request,
        org_id=scan.org_id,
    )
    db.commit()

    log.info("Web scan %s cancelled by user %s", scan_id, user.id)
    return {"success": True, "message": "Web scan cancelled"}


#: One audit action per triage outcome, so each carries its own severity in
#: core/audit_taxonomy.py — accepting a risk is what an auditor looks for, and
#: must not share a severity with reopening a finding. Keys are exactly the
#: statuses `triage_finding` accepts; the variants are pinned in
#: tests/audit/test_audit_action_inventory.py.
_TRIAGE_AUDIT_ACTIONS = {
    "open": "web_finding.open",
    "confirmed": "web_finding.confirmed",
    "false_positive": "web_finding.false_positive",
    "accepted_risk": "web_finding.accepted_risk",
    "fixed": "web_finding.fixed",
    "reopened": "web_finding.reopened",
}


@router.patch("/{scan_id}/findings/{finding_id}")
def triage_finding(
    scan_id: str,
    finding_id: str,
    body: TriageFindingRequest,
    request: Request,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("findings", "update")),
):
    """Triage a finding — mark as false positive, accepted risk, confirmed, etc."""
    scan = _get_scan_or_404(db, scan_id, user, org_id)

    finding = (
        db.query(WebFinding)
        .filter(
            WebFinding.id == finding_id,
            WebFinding.web_scan_id == scan_id,
        )
        .first()
    )

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    valid_statuses = {
        "open",
        "confirmed",
        "false_positive",
        "accepted_risk",
        "fixed",
        "reopened",
    }
    if body.status not in valid_statuses:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}",
        )

    # Accepting a risk is its own authorisation, as it is for network findings
    # (`findings:accept_risk`, routers/remediation.py). Without the split,
    # anyone able to edit a finding could clear their own list by accepting
    # everything on it. The route's own dependency is `findings:update`; only
    # the body says which status was asked for, so this check lives here.
    if body.status == "accepted_risk" and not user_has_permission(
        db, user, "findings", "accept_risk"
    ):
        raise HTTPException(
            status_code=403,
            detail=(
                "Accepting a risk requires the 'findings:accept_risk' permission, "
                "which your role does not have."
            ),
        )

    previous_status = finding.status
    finding.status = body.status
    finding.updated_at = utcnow()

    if body.status == "false_positive":
        finding.false_positive_reason = body.reason
    elif body.status == "accepted_risk":
        finding.accepted_risk_reason = body.reason
        finding.accepted_by = user.id
    elif body.status == "fixed":
        finding.fixed_at = utcnow()
        finding.remediation_notes = body.reason

    log_audit_event(
        db=db,
        user=user,
        action=_TRIAGE_AUDIT_ACTIONS[body.status],
        resource_type="web_finding",
        resource_id=finding_id,
        changes={
            "web_scan_id": scan_id,
            "status": {"from": previous_status, "to": body.status},
            "reason": body.reason,
        },
        request=request,
        org_id=scan.org_id,
    )
    db.commit()

    log.info(
        "Finding %s triaged to '%s' by user %s (scan %s)",
        finding_id,
        body.status,
        user.id,
        scan_id,
    )

    return {"success": True, "finding_id": finding_id, "status": body.status}


@router.get("/{scan_id}/findings/{finding_id}/screenshot")
def get_finding_screenshot(
    scan_id: str,
    finding_id: str,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("findings", "read")),
):
    """
    Serve the proof screenshot captured for a finding (Codex item 10), e.g. a
    rendered XSS. The finding must belong to the scan, and the stored path must
    resolve inside the scan's own evidence directory — a screenshot_path is
    written by the scanner, but this refuses to serve anything that escapes the
    evidence root, so a crafted path cannot read an arbitrary server file.
    """
    import os

    from fastapi.responses import FileResponse

    from orchestrator.web_orchestrator import WebScanOrchestrator

    scan = _get_scan_or_404(db, scan_id, user, org_id)
    finding = (
        db.query(WebFinding)
        .filter(WebFinding.id == finding_id, WebFinding.web_scan_id == scan.id)
        .first()
    )
    if not finding or not finding.screenshot_path:
        raise HTTPException(status_code=404, detail="No screenshot for this finding")

    evidence_root = os.path.realpath(WebScanOrchestrator._evidence_dir(scan.id))
    target = os.path.realpath(finding.screenshot_path)
    # Path-traversal guard: the resolved file must live under this scan's
    # evidence directory, and must actually exist.
    if not (target == evidence_root or target.startswith(evidence_root + os.sep)):
        raise HTTPException(status_code=404, detail="Screenshot not available")
    if not os.path.isfile(target):
        raise HTTPException(status_code=404, detail="Screenshot file missing")
    return FileResponse(target, media_type="image/png")


@router.get("/{scan_id}/report")
@limiter.limit("10/minute")
def download_web_scan_report(
    request: Request,
    scan_id: str,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("scans", "read")),
):
    """
    Generate and download a PDF report for a completed web scan.

    The report includes:
      - Executive summary with severity breakdown
      - OWASP Top 10 scorecard
      - All findings with HTTP evidence
      - Endpoint inventory
    """
    import os

    from fastapi.responses import FileResponse

    scan = _get_scan_or_404(db, scan_id, user, org_id)

    if scan.status not in ("complete", "failed"):
        raise HTTPException(
            status_code=409,
            detail=f"Report not available — scan is {scan.status}. Wait for completion.",
        )

    # Fetch all findings and assets for this scan
    findings = db.query(WebFinding).filter(WebFinding.web_scan_id == scan_id).all()
    assets = db.query(WebAsset).filter(WebAsset.web_scan_id == scan_id).all()

    _detect_cov = (scan.options or {}).get("tool_coverage", {}).get("detect", {})
    _crawl_cov = (scan.options or {}).get("tool_coverage", {}).get("crawl", {})
    # Site-map inventory for the report (Codex item 15): forms + API operations
    # as counts, from the first-class tables.
    _forms_count = db.query(WebForm).filter(WebForm.web_scan_id == scan.id).count()
    _api_ops_by_kind: dict = {}
    for (k,) in db.query(WebApiOperation.kind).filter(
        WebApiOperation.web_scan_id == scan.id
    ):
        _api_ops_by_kind[k] = _api_ops_by_kind.get(k, 0) + 1
    scan_dict = {
        **_scan_summary(scan),
        "scan_scope": scan.scan_scope,
        "waf_detected": scan.waf_detected,
        "tech_stack": scan.tech_stack or [],
        "subdomains": scan.subdomains or [],
        # Phase 10: nuclei profile + execution metrics for the report.
        "nuclei_profile": _detect_cov.get("nuclei_profile"),
        "nuclei_profile_label": _detect_cov.get("nuclei_profile_label"),
        "nuclei_metrics": _detect_cov.get("nuclei_metrics") or {},
        "scan_depth": _detect_cov.get("scan_depth"),
        # Phase 22: per-parameter coverage ledger for the report.
        "coverage_ledger": _detect_cov.get("coverage_ledger") or {},
        # Phase 23c (Codex item 15): scan policy, scheduler plan, tool coverage
        # and the site-map inventory, so the report states what was assessed,
        # what was attacked, and what ran.
        "scan_policy": _detect_cov.get("scan_policy") or {},
        "schedule": _detect_cov.get("schedule") or {},
        "tool_coverage_detail": _detect_cov,
        "auth_status": _detect_cov.get("auth_status")
        or (scan.auth_config or {}).get("type"),
        "site_map": {
            "endpoints": scan.total_endpoints or 0,
            "forms": _forms_count,
            "api_operations": _api_ops_by_kind,
            # DOM state graph summary (Crawler 2.0), if the interaction pass ran.
            "dom_graph": _crawl_cov.get("dom_graph_summary") or {},
        },
    }
    findings_list = [_finding_detail(f) for f in findings]
    assets_list = [_asset_detail(a) for a in assets]

    from reporting.web_pdf_generator import WebScanReportGenerator

    gen = WebScanReportGenerator()
    pdf_path = gen.generate(scan_dict, findings_list, assets_list)

    if not os.path.exists(pdf_path):
        raise HTTPException(status_code=500, detail="Report generation failed")

    return FileResponse(
        path=pdf_path,
        filename=os.path.basename(pdf_path),
        media_type="application/pdf",
    )


# ── Helpers ───────────────────────────────────────────────────────────────────


@router.websocket("/{scan_id}/progress")
async def web_scan_progress_ws(websocket: WebSocket, scan_id: str):
    """
    Real-time web scan progress over Redis PubSub.
    Sends a DB snapshot first so clients do not miss early progress events.
    """
    try:
        current_user = _get_websocket_user(websocket)
    except HTTPException:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    db = SessionLocal()
    try:
        query = db.query(WebScan).filter(
            WebScan.id == scan_id,
            WebScan.is_deleted == False,
        )
        if (
            getattr(getattr(current_user, "role", None), "name", "").lower()
            != "superadmin"
        ):
            query = query.filter(WebScan.org_id == str(current_user.org_id))
        scan = query.first()

        if not scan:
            await websocket.send_json(
                {
                    "scan_id": scan_id,
                    "scan_type": "web",
                    "phase": "not_found",
                    "progress": {
                        "status": "not_found",
                        "message": "Web scan not found.",
                    },
                }
            )
            await websocket.close(code=1008)
            return

        await websocket.send_json(
            {
                "scan_id": scan_id,
                "scan_type": "web",
                "phase": scan.pipeline_phase,
                "progress": _web_scan_progress_snapshot(scan),
                "scan": _scan_summary(scan),
            }
        )
    finally:
        db.close()

    from core.redis_client import redis_client

    pubsub = redis_client.pubsub()
    await pubsub.subscribe(f"scan_progress:{scan_id}")

    try:
        while True:
            message = await pubsub.get_message(
                ignore_subscribe_messages=True, timeout=0.5
            )
            if message:
                payload = json.loads(message["data"])
                await websocket.send_json(payload)
            else:
                await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        log.error("Web scan progress WebSocket error for %s: %s", scan_id, exc)
        await websocket.close(code=1011)
    finally:
        await pubsub.unsubscribe(f"scan_progress:{scan_id}")
        await pubsub.close()


def _get_websocket_user(websocket: WebSocket) -> CurrentUser:
    ticket = websocket.query_params.get("ticket")
    if not ticket:
        raise HTTPException(
            status_code=401, detail="Authentication ticket is required."
        )

    payload = decode_token(ticket)
    if not payload or payload.get("type") != "ticket" or not payload.get("sub"):
        raise HTTPException(
            status_code=401, detail="Invalid or expired authentication."
        )

    db = SessionLocal()
    try:
        user = (
            db.query(User)
            .options(joinedload(User.role))
            .filter(User.id == str(payload["sub"]))
            .first()
        )
        if not user:
            raise HTTPException(status_code=401, detail="User not found.")
        if getattr(user, "is_deleted", False) or not getattr(user, "is_active", True):
            raise HTTPException(status_code=403, detail="User is not active.")
        db.expunge(user)
        return user
    finally:
        db.close()


def _web_scan_progress_snapshot(scan: WebScan) -> dict:
    status = str(scan.status or "unknown").lower()
    phase = scan.pipeline_phase or "queued"
    phase_order = {
        "queued": 0,
        "recon": 1,
        "crawl": 2,
        "detect": 3,
        "audit": 4,
        "complete": 4,
    }
    percentage = (
        100
        if status in {"complete", "completed"}
        else min(95, phase_order.get(phase, 0) * 25)
    )

    return {
        "status": scan.status,
        "phase": phase,
        "percentage": percentage,
        "message": _web_scan_status_message(scan),
        "total_endpoints": scan.total_endpoints,
        "total_findings": scan.total_findings,
        "updated_at": _iso(scan.updated_at),
    }


def _web_scan_status_message(scan: WebScan) -> str:
    phase = str(scan.pipeline_phase or "queued").lower()
    if scan.status == "queued":
        return "Scan queued and waiting for a worker."
    if scan.status == "failed":
        return scan.failure_reason or "Scan failed."
    if scan.status == "cancelled":
        return "Scan cancelled."
    if scan.status in {"complete", "completed"}:
        return "Web application scan complete."
    messages = {
        "recon": "Running reconnaissance.",
        "crawl": "Crawling web application.",
        "detect": "Scanning for vulnerabilities.",
        "audit": "Running final audit and report preparation.",
    }
    return messages.get(phase, "Initializing web scan.")


def _normalize_idempotency_key(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    return normalized[:128]


def _find_duplicate_web_scan(
    db: Session,
    user: CurrentUser,
    org_id: str,
    target_url: str,
    idempotency_key: str | None,
) -> WebScan | None:
    cutoff = utcnow() - IDEMPOTENCY_WINDOW
    recent_scans = (
        db.query(WebScan)
        .filter(
            WebScan.org_id == org_id,
            WebScan.created_by == user.id,
            WebScan.target_url == target_url,
            WebScan.is_deleted == False,
            WebScan.created_at >= cutoff,
        )
        .order_by(WebScan.created_at.desc())
        .limit(25)
        .all()
    )

    if idempotency_key:
        for scan in recent_scans:
            launch = (scan.options or {}).get("_launch", {})
            if launch.get("idempotency_key") == idempotency_key:
                return scan

    for scan in recent_scans:
        if str(scan.status or "").lower() in ACTIVE_SCAN_STATUSES:
            return scan

    return None


def _start_scan_response(
    scan: WebScan,
    task_id: str | None = None,
    duplicate: bool = False,
    message: str = "Web scan queued successfully.",
) -> dict:
    return {
        "success": True,
        "duplicate": duplicate,
        "id": scan.id,
        "web_scan_id": scan.id,
        "task_id": task_id or scan.current_task_id,
        "target_url": scan.target_url,
        "status": scan.status,
        "pipeline_phase": scan.pipeline_phase,
        "message": message,
    }


def _get_scan_or_404(
    db: Session, scan_id: str, user: CurrentUser, org_id: str | None = None
) -> WebScan:
    target_org_id = _resolve_org(user, org_id)
    scan = (
        db.query(WebScan)
        .filter(
            WebScan.id == scan_id,
            WebScan.org_id == target_org_id,
            WebScan.is_deleted == False,
        )
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Web scan not found")
    return scan


def _iso(dt) -> str | None:
    return dt.isoformat() if dt else None


def _scan_summary(scan: WebScan) -> dict:
    return {
        "id": scan.id,
        "scan_name": scan.scan_name,
        "target_url": scan.target_url,
        "target_domain": scan.target_domain,
        "status": scan.status,
        "pipeline_phase": scan.pipeline_phase,
        "total_endpoints": scan.total_endpoints,
        "total_findings": scan.total_findings,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "info_count": scan.info_count,
        "waf_detected": scan.waf_detected,
        "duration_seconds": scan.duration_seconds,
        "created_at": _iso(scan.created_at),
        "started_at": _iso(scan.started_at),
        "completed_at": _iso(scan.completed_at),
    }


def _asset_detail(a: WebAsset) -> dict:
    return {
        "id": a.id,
        "url": a.url,
        "method": a.method,
        "content_type": a.content_type,
        "response_code": a.response_code,
        "parameters": a.parameters,
        "auth_required": a.auth_required,
        "is_api": a.is_api,
        "is_form": a.is_form,
        "has_file_upload": a.has_file_upload,
        "source": a.source,
        "technology": a.technology,
        "response_size": a.response_size,
        "response_time": a.response_time,
        "created_at": _iso(a.created_at),
    }
