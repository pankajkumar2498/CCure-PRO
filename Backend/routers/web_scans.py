"""
routers/web_scans.py
────────────────────────────────────────────────────────────────────────────
FastAPI endpoints for Web Application Scanning (DAST).

Endpoints:
  POST   /api/web-scans                     — Start a new web scan
  GET    /api/web-scans                     — List web scans (org-scoped)
  GET    /api/web-scans/{id}                — Get scan details + progress
  GET    /api/web-scans/{id}/findings       — Get findings (filterable)
  GET    /api/web-scans/{id}/assets         — Get discovered endpoints
  POST   /api/web-scans/{id}/cancel         — Cancel a running scan
  PATCH  /api/web-scans/{id}/findings/{fid} — Triage a finding
"""

import logging
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user
from db.base import get_db, gen_web_scan_id, utcnow
from db.models import User
from db.models.web_scans import WebScan, WebAsset, WebFinding

log = logging.getLogger("ccure.routers.web_scans")

router = APIRouter(prefix="/api/web-scans", tags=["Web Scans"])


# ── Pydantic Schemas ──────────────────────────────────────────────────────────

class WebScanScopeSchema(BaseModel):
    include_subdomains: bool = False
    exclude_paths: List[str] = Field(default_factory=list)
    max_depth: int = Field(default=5, ge=1, le=20)


class WebScanAuthSchema(BaseModel):
    type: str = Field(default="none", description="Auth type: none, form_login, bearer_token, cookie, custom_header")
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    username_field: str = "username"
    password_field: str = "password"
    success_indicator: Optional[str] = None
    token: Optional[str] = None
    cookies: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None


class WebScanOptionsSchema(BaseModel):
    enable_sqli: bool = True
    enable_xss: bool = True
    nuclei_severity: List[str] = Field(default=["medium", "high", "critical"])
    rate_limit: int = Field(default=10, ge=1, le=100)


class StartWebScanRequest(BaseModel):
    target_url: str = Field(..., min_length=8, max_length=2048)
    scan_name: Optional[str] = Field(None, max_length=255)
    scan_scope: WebScanScopeSchema = Field(default_factory=WebScanScopeSchema)
    auth: WebScanAuthSchema = Field(default_factory=WebScanAuthSchema)
    options: WebScanOptionsSchema = Field(default_factory=WebScanOptionsSchema)
    authorization_confirmed: bool = Field(
        ...,
        description="User MUST confirm they are authorized to scan this target",
    )


class TriageFindingRequest(BaseModel):
    status: str = Field(..., description="open, confirmed, false_positive, accepted_risk, fixed")
    reason: Optional[str] = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("", status_code=201)
def start_web_scan(
    body: StartWebScanRequest,
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
    target_url = body.target_url.strip()
    if not target_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=422, detail="target_url must start with http:// or https://")

    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    target_domain = parsed.netloc
    if not target_domain:
        raise HTTPException(status_code=422, detail="Invalid target URL — could not extract domain")

    # ── Org context ──────────────────────────────────────────────────────
    from db.models.rbac import Organization
    org = db.query(Organization).filter(Organization.id == str(user.org_id)).first()
    org_slug = org.slug if org else str(user.org_id)

    # ── Create WebScan record ────────────────────────────────────────────
    scan_id = gen_web_scan_id(org_slug)

    scan = WebScan(
        id=scan_id,
        org_id=str(user.org_id),
        created_by=user.id,
        scan_name=body.scan_name or f"Web Scan: {target_domain}",
        target_url=target_url,
        target_domain=target_domain,
        scan_scope=body.scan_scope.model_dump(),
        auth_config=body.auth.model_dump(exclude_none=True),
        options=body.options.model_dump(),
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

    db.query(WebScan).filter(WebScan.id == scan_id).update({
        "current_task_id": task.id,
        "status": "running",
    })
    db.commit()

    log.info("Web scan started: %s → %s (user=%s)", scan_id, target_url, user.id)

    return {
        "success": True,
        "web_scan_id": scan_id,
        "task_id": task.id,
        "target_url": target_url,
        "message": "Web scan queued successfully. Pipeline: RECON → CRAWL → DETECT → AUDIT",
    }


@router.get("")
def list_web_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List web scans for the current user's organization."""
    query = db.query(WebScan).filter(
        WebScan.org_id == str(user.org_id),
        WebScan.is_deleted == False,
    )

    if status:
        query = query.filter(WebScan.status == status)

    total = query.count()
    scans = (
        query
        .order_by(WebScan.created_at.desc())
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
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get detailed web scan information including phase progress."""
    scan = _get_scan_or_404(db, scan_id, user)

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
    severity: Optional[str] = Query(None),
    finding_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None, alias="finding_status"),
    detected_by: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get findings for a web scan with filtering and pagination."""
    scan = _get_scan_or_404(db, scan_id, user)

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
        query
        .order_by(
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
    source: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get discovered web assets/endpoints for a scan."""
    scan = _get_scan_or_404(db, scan_id, user)

    query = db.query(WebAsset).filter(WebAsset.web_scan_id == scan_id)
    if source:
        query = query.filter(WebAsset.source == source)

    total = query.count()
    assets = (
        query
        .order_by(WebAsset.created_at.asc())
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
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Cancel a running web scan."""
    scan = _get_scan_or_404(db, scan_id, user)

    if scan.status in ("complete", "cancelled", "failed"):
        raise HTTPException(
            status_code=409,
            detail=f"Scan is already {scan.status}",
        )

    # Revoke the Celery task
    if scan.current_task_id:
        try:
            from core.celery_app import celery_app
            celery_app.control.revoke(scan.current_task_id, terminate=True, signal="SIGKILL")
        except Exception as exc:
            log.warning("Failed to revoke task %s: %s", scan.current_task_id, exc)

    db.query(WebScan).filter(WebScan.id == scan_id).update({
        "status": "cancelled",
        "completed_at": utcnow(),
        "updated_at": utcnow(),
    })
    db.commit()

    log.info("Web scan %s cancelled by user %s", scan_id, user.id)
    return {"success": True, "message": "Web scan cancelled"}


@router.patch("/{scan_id}/findings/{finding_id}")
def triage_finding(
    scan_id: str,
    finding_id: str,
    body: TriageFindingRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Triage a finding — mark as false positive, accepted risk, confirmed, etc."""
    scan = _get_scan_or_404(db, scan_id, user)

    finding = db.query(WebFinding).filter(
        WebFinding.id == finding_id,
        WebFinding.web_scan_id == scan_id,
    ).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    valid_statuses = {"open", "confirmed", "false_positive", "accepted_risk", "fixed", "reopened"}
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
        finding_id, body.status, user.id, scan_id,
    )

    return {"success": True, "finding_id": finding_id, "status": body.status}


@router.get("/{scan_id}/report")
def download_web_scan_report(
    scan_id: str,
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

    scan = _get_scan_or_404(db, scan_id, user)

    if scan.status not in ("complete", "failed"):
        raise HTTPException(
            status_code=409,
            detail=f"Report not available — scan is {scan.status}. Wait for completion.",
        )

    # Fetch all findings and assets for this scan
    findings = db.query(WebFinding).filter(WebFinding.web_scan_id == scan_id).all()
    assets = db.query(WebAsset).filter(WebAsset.web_scan_id == scan_id).all()

    scan_dict = {
        **_scan_summary(scan),
        "scan_scope": scan.scan_scope,
        "waf_detected": scan.waf_detected,
        "tech_stack": scan.tech_stack or [],
        "subdomains": scan.subdomains or [],
    }
    findings_list = [_finding_detail(f) for f in findings]
    assets_list = [_asset_detail(a) for a in assets]

    from web_pdf_generator import WebScanReportGenerator
    gen = WebScanReportGenerator(output_dir="reports")
    pdf_path = gen.generate(scan_dict, findings_list, assets_list)

    if not os.path.exists(pdf_path):
        raise HTTPException(status_code=500, detail="Report generation failed")

    return FileResponse(
        path=pdf_path,
        filename=os.path.basename(pdf_path),
        media_type="application/pdf",
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_scan_or_404(db: Session, scan_id: str, user: User) -> WebScan:
    scan = db.query(WebScan).filter(
        WebScan.id == scan_id,
        WebScan.org_id == str(user.org_id),
        WebScan.is_deleted == False,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Web scan not found")
    return scan


def _iso(dt) -> Optional[str]:
    return dt.isoformat() if dt else None


def _scan_summary(scan: WebScan) -> Dict:
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


def _finding_detail(f: WebFinding) -> Dict:
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
        "status": f.status,
        "is_verified": f.is_verified,
        "created_at": _iso(f.created_at),
    }


def _asset_detail(a: WebAsset) -> Dict:
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
