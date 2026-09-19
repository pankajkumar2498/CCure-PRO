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

from auth.dependencies import get_current_user
from auth.jwt_handler import decode_token
from db.base import SessionLocal, gen_web_scan_id, get_db, utcnow
from db.models import User
from core.web.auth.secrets import encrypt_auth_config
from db.models.web_scans import WebAsset, WebFinding, WebScan
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


def _is_superadmin(user: User) -> bool:
    return (
        getattr(getattr(user, "role", None), "name", "") or ""
    ).lower() == "superadmin"


def _resolve_org(user: User, requested_org: str | None) -> str:
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
            "multi_step"
        ),
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
    nuclei_severity: list[str] = Field(default=["medium", "high", "critical"])
    rate_limit: int = Field(default=10, ge=1, le=100)
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
    user: User = Depends(get_current_user),
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

    from db.models.rbac import Organization

    org = db.query(Organization).filter(Organization.id == target_org_id).first()
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
    user: User = Depends(get_current_user),
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
    user: User = Depends(get_current_user),
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
    user: User = Depends(get_current_user),
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
    user: User = Depends(get_current_user),
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


@router.post("/{scan_id}/cancel")
def cancel_web_scan(
    scan_id: str,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
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

    db.query(WebScan).filter(WebScan.id == scan_id).update(
        {
            "status": "cancelled",
            "completed_at": utcnow(),
            "updated_at": utcnow(),
        }
    )
    db.commit()

    log.info("Web scan %s cancelled by user %s", scan_id, user.id)
    return {"success": True, "message": "Web scan cancelled"}


@router.patch("/{scan_id}/findings/{finding_id}")
def triage_finding(
    scan_id: str,
    finding_id: str,
    body: TriageFindingRequest,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
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

    db.commit()

    log.info(
        "Finding %s triaged to '%s' by user %s (scan %s)",
        finding_id,
        body.status,
        user.id,
        scan_id,
    )

    return {"success": True, "finding_id": finding_id, "status": body.status}


@router.get("/{scan_id}/report")
@limiter.limit("10/minute")
def download_web_scan_report(
    request: Request,
    scan_id: str,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
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


def _get_websocket_user(websocket: WebSocket) -> User:
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
    user: User,
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
    db: Session, scan_id: str, user: User, org_id: str | None = None
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


def _finding_detail(f: WebFinding) -> dict:
    return {
        "id": f.id,
        "finding_type": f.finding_type,
        "title": f.title,
        "description": f.description,
        "severity": f.severity,
        "cvss_score": f.cvss_score,
        "cvss_vector": f.cvss_vector,
        "detected_by": f.detected_by,
        "template_id": f.template_id,
        "matched_at": f.matched_at,
        "request_method": f.request_method,
        "request_url": f.request_url,
        "payload_used": f.payload_used,
        "response_code": f.response_code,
        "owasp_category": f.owasp_category,
        "compliance_tags": f.compliance_tags,
        "cve_id": f.cve_id,
        "cwe_id": f.cwe_id,
        "status": f.status,
        "is_verified": f.is_verified,
        "created_at": _iso(f.created_at),
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
