"""
routers/findings.py
─────────────────────────────────────────────────────────────────────────────
Vulnerability / Findings Browser REST API.

Field notes (verified against db/models/findings.py):
  VulnerabilityDefinition has NO epss_score, in_kev, has_exploit, cvss_v3_vector.
  It has: cvss_v3_score, cvss_vector, severity, cwe_ids, references,
          description, title, published_at, source (use source='kev' as proxy).
  AssetVulnerability has: status, proof, plugin_output, remediation_notes,
          fixed_at, accepted_by, accepted_risk_reason, first_found_at, last_found_at.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, or_
from sqlalchemy.orm import Session, joinedload

from auth.rbac import require_permission
from db.base import get_db, utcnow
from db.models import User
from db.models.assets import Asset
from db.models.findings import AssetVulnerability, VulnerabilityDefinition, Service
from core.vuln_intel import compute_priority
from core.audit import log_audit_event

log = logging.getLogger("ccure.findings")
router = APIRouter(prefix="/findings", tags=["Findings"])


def _is_superadmin(user: User) -> bool:
    return (getattr(getattr(user, "role", None), "name", "") or "").lower() == "superadmin"


def _resolve_org(user: User, requested_org: Optional[str]) -> str:
    if _is_superadmin(user) and requested_org:
        return requested_org
    return str(user.org_id)


# ── List Findings ─────────────────────────────────────────────────────────────

@router.get("")
@router.get("/")
def list_findings(
    severity:  Optional[str]  = Query(None),
    status:    Optional[str]  = Query(None),
    priority:  Optional[str]  = Query(None),
    in_kev:    Optional[bool] = Query(None),
    search:    Optional[str]  = Query(None),
    asset_id:  Optional[str]  = Query(None),
    scan_id:   Optional[str]  = Query(None),
    sort_by:   str            = Query("priority"),
    skip:      int            = Query(0, ge=0),
    limit:     int            = Query(50, ge=1, le=500),
    org_id:    Optional[str]  = Query(None),
    db:        Session        = Depends(get_db),
    user:      User           = Depends(require_permission("findings", "read")),
):
    org = _resolve_org(user, org_id)

    q = (
        db.query(AssetVulnerability, VulnerabilityDefinition, Asset)
        .join(VulnerabilityDefinition, AssetVulnerability.vuln_id == VulnerabilityDefinition.id)
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(Asset.org_id == org)
    )

    if severity:
        sev_list = [s.strip().title() for s in severity.split(",")]
        q = q.filter(VulnerabilityDefinition.severity.in_(sev_list))

    if status:
        q = q.filter(AssetVulnerability.status.in_([s.strip() for s in status.split(",")]))
    else:
        q = q.filter(AssetVulnerability.status == "open")

    # in_kev: proxy through source column
    if in_kev is True:
        q = q.filter(VulnerabilityDefinition.source == "kev")
    elif in_kev is False:
        q = q.filter(VulnerabilityDefinition.source != "kev")

    if asset_id:
        q = q.filter(AssetVulnerability.asset_id == asset_id)

    if scan_id:
        q = q.filter(AssetVulnerability.scan_id == scan_id)

    if search:
        q = q.filter(
            or_(
                VulnerabilityDefinition.id.ilike(f"%{search}%"),
                VulnerabilityDefinition.title.ilike(f"%{search}%"),
            )
        )

    total = q.count()

    if sort_by == "cvss":
        q = q.order_by(VulnerabilityDefinition.cvss_v3_score.desc())
    elif sort_by == "first_found":
        q = q.order_by(AssetVulnerability.first_found_at.desc())
    else:
        q = q.order_by(
            VulnerabilityDefinition.cvss_v3_score.desc(),
        )

    rows = q.offset(skip).limit(limit).all()

    result = []
    for finding, vuln, asset in rows:
        is_kev = (vuln.source == "kev")
        ps, pl = compute_priority(
            cvss_score=float(vuln.cvss_v3_score or 0),
            epss_score=0.0,
            in_kev=is_kev,
            has_exploit=False,
        )

        # Apply priority label filter post-compute
        if priority:
            allowed = [p.strip().upper() for p in priority.split(",")]
            if pl not in allowed:
                continue

        result.append({
            "id":             finding.id,
            "vuln_id":        vuln.id,
            "title":          vuln.title,
            "severity":       vuln.severity,
            "cvss_v3_score":  float(vuln.cvss_v3_score or 0),
            "epss_score":     0.0,
            "in_kev":         is_kev,
            "has_exploit":    False,
            "priority_score": ps,
            "priority_label": pl,
            "cwe_ids":        vuln.cwe_ids or [],
            "status":         finding.status,
            "asset": {
                "id":         asset.id,
                "ip_address": str(asset.ip_address),
                "hostname":   asset.hostname,
                "risk_score": asset.risk_score,
            },
            "first_found_at": finding.first_found_at.isoformat() if finding.first_found_at else None,
            "last_found_at":  finding.last_found_at.isoformat() if finding.last_found_at else None,
            "fixed_at":       finding.fixed_at.isoformat() if finding.fixed_at else None,
        })

    return {"total": total, "skip": skip, "limit": limit, "findings": result}


# ── Finding Detail ────────────────────────────────────────────────────────────

@router.get("/{finding_id}")
def get_finding(
    finding_id: str,
    org_id:     Optional[str] = Query(None),
    db:         Session       = Depends(get_db),
    user:       User          = Depends(require_permission("findings", "read")),
):
    org = _resolve_org(user, org_id)

    row = (
        db.query(AssetVulnerability, VulnerabilityDefinition, Asset)
        .join(VulnerabilityDefinition, AssetVulnerability.vuln_id == VulnerabilityDefinition.id)
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(AssetVulnerability.id == finding_id, Asset.org_id == org)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding, vuln, asset = row
    is_kev = (vuln.source == "kev")
    ps, pl = compute_priority(
        cvss_score=float(vuln.cvss_v3_score or 0),
        epss_score=0.0,
        in_kev=is_kev,
        has_exploit=False,
    )

    return {
        "id":                    finding.id,
        "status":                finding.status,
        "proof":                 finding.proof,
        "plugin_output":         finding.plugin_output,
        "remediation_notes":     finding.remediation_notes,
        "accepted_risk_reason":  finding.accepted_risk_reason,
        "accepted_by":           finding.accepted_by,
        "first_found_at":  finding.first_found_at.isoformat() if finding.first_found_at else None,
        "last_found_at":   finding.last_found_at.isoformat() if finding.last_found_at else None,
        "fixed_at":        finding.fixed_at.isoformat() if finding.fixed_at else None,
        "vulnerability": {
            "id":            vuln.id,
            "title":         vuln.title,
            "description":   vuln.description,
            "severity":      vuln.severity,
            "cvss_v3_score": float(vuln.cvss_v3_score or 0),
            "cvss_v3_vector": vuln.cvss_vector,       # field is cvss_vector not cvss_v3_vector
            "cvss_v2_score": float(vuln.cvss_v2_score or 0) if vuln.cvss_v2_score else None,
            "epss_score":    0.0,
            "in_kev":        is_kev,
            "has_exploit":   False,
            "priority_score": ps,
            "priority_label": pl,
            "cwe_ids":       vuln.cwe_ids or [],
            "references":    vuln.references or [],
            "published_at":  str(vuln.published_at) if vuln.published_at else None,
        },
        "asset": {
            "id":         asset.id,
            "ip_address": str(asset.ip_address),
            "hostname":   asset.hostname,
            "os_name":    asset.os_name,
            "risk_score": asset.risk_score,
            "risk_level": asset.risk_level,
        },
    }


# ── Update Finding Status ─────────────────────────────────────────────────────

class StatusUpdate(BaseModel):
    status:               str
    accepted_risk_reason: Optional[str] = None
    remediation_notes:    Optional[str] = None


@router.patch("/{finding_id}/status")
def update_finding_status(
    finding_id: str,
    body:       StatusUpdate,
    org_id:     Optional[str] = Query(None),
    db:         Session       = Depends(get_db),
    user:       User          = Depends(require_permission("findings", "update")),
):
    org = _resolve_org(user, org_id)

    row = (
        db.query(AssetVulnerability, Asset)
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(AssetVulnerability.id == finding_id, Asset.org_id == org)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding, _ = row
    allowed = {"open", "accepted", "fixed"}
    if body.status not in allowed:
        raise HTTPException(status_code=400, detail=f"Status must be one of: {allowed}")

    finding.status = body.status

    if body.status == "accepted":
        finding.accepted_by          = str(user.id)
        finding.accepted_risk_reason = body.accepted_risk_reason

    if body.status == "fixed":
        finding.fixed_at = utcnow()

    if body.remediation_notes:
        finding.remediation_notes = body.remediation_notes

    db.commit()

    log_audit_event(
        db=db, user=user,
        action=f"finding_{body.status}",
        resource_type="finding",
        resource_id=finding_id,
        status="success",
    )

    return {"success": True, "id": finding_id, "status": body.status}


# ── Update Remediation Notes ──────────────────────────────────────────────────

class NotesUpdate(BaseModel):
    remediation_notes: str


@router.patch("/{finding_id}/notes")
def update_finding_notes(
    finding_id: str,
    body:       NotesUpdate,
    org_id:     Optional[str] = Query(None),
    db:         Session       = Depends(get_db),
    user:       User          = Depends(require_permission("findings", "update")),
):
    org = _resolve_org(user, org_id)
    row = (
        db.query(AssetVulnerability, Asset)
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(AssetVulnerability.id == finding_id, Asset.org_id == org)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding, _ = row
    finding.remediation_notes = body.remediation_notes.strip()
    db.commit()
    return {"success": True, "id": finding_id}
