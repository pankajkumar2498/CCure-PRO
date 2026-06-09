"""
routers/assets.py
─────────────────────────────────────────────────────────────────────────────
Asset Registry REST API — verified against actual model field names.

Imports use only what actually exists:
  log_audit_event(db, user, action, resource_type, resource_id, status)
  Asset fields verified from db/models/assets.py
  Service/TLS/HTTP fields verified from db/models/findings.py
"""

import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import or_, func, String
from sqlalchemy.orm import Session, joinedload

from auth.rbac import require_permission
from db.base import get_db
from db.models import User, AuditLog
from db.models.assets import Asset, AssetTag, AssetNote, AssetChangeLog
from db.models.findings import (
    Service, TLSDetail, HttpSecurityDetail,
    AssetVulnerability, VulnerabilityDefinition,
)
from core.vuln_intel import compute_priority
from core.audit import log_audit_event

log = logging.getLogger("ccure.assets")
router = APIRouter(prefix="/assets", tags=["Assets"])


def _display_json_value(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _is_superadmin(user: User) -> bool:
    return (getattr(getattr(user, "role", None), "name", "") or "").lower() == "superadmin"


def _resolve_org(user: User, requested_org: Optional[str]) -> str:
    if _is_superadmin(user) and requested_org:
        return requested_org
    return str(user.org_id)


def _asset_or_404(db: Session, asset_id: str, org_id: str) -> Asset:
    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.org_id == org_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


def _serialize_asset(a: Asset) -> dict:
    vc = a.vuln_counts or {}

    # Hide/nullify os_confidence if OS details are blank or unknown
    has_os = False
    for val in (a.os_name, a.os_family):
        if val is not None:
            normalized = str(val).strip().lower()
            if normalized not in ("", "unknown", "n/a", "none", "—"):
                has_os = True
                break
    os_confidence = a.os_confidence if has_os else None

    return {
        "id":              a.id,
        "ip_address":      str(a.ip_address),
        "mac_address":     str(a.mac_address) if a.mac_address else None,
        "hostname":        a.hostname,
        "fqdn":            a.fqdn,
        "netbios_name":    a.netbios_name,
        "dns_name":        a.dns_name,
        "os_name":         a.os_name,
        "os_family":       a.os_family,
        "os_version":      getattr(a, "os_version", None),
        "os_confidence":   os_confidence,
        "device_category": a.device_category,
        "vendor":          a.vendor,
        "manufacturer":    getattr(a, "manufacturer", None),
        "subnet":          a.subnet,
        "vlan_id":         a.vlan_id,
        "risk_score":      a.risk_score,
        "risk_level":      a.risk_level,
        "is_managed":      a.is_managed,
        "is_active":       a.is_active,
        "owner":           a.owner,
        "discovery_method": a.discovery_method,
        "response_time_ms": a.response_time_ms,
        "last_scan_id":    a.last_scan_id,
        "vuln_counts": {
            "critical": vc.get("critical", vc.get("Critical", 0)),
            "high":     vc.get("high",     vc.get("High", 0)),
            "medium":   vc.get("medium",   vc.get("Medium", 0)),
            "low":      vc.get("low",      vc.get("Low", 0)),
        },
        "tags":           [t.tag for t in (a.tags or [])],
        "first_seen_at":  a.first_seen_at.isoformat() if a.first_seen_at else None,
        "last_seen_at":   a.last_seen_at.isoformat() if a.last_seen_at else None,
    }


@router.get("")
@router.get("/")
def list_assets(
    search:     Optional[str]  = Query(None),
    risk_level: Optional[str]  = Query(None),
    os_family:  Optional[str]  = Query(None),
    is_managed: Optional[bool] = Query(None),
    is_active:  Optional[bool] = Query(None),
    subnet:     Optional[str]  = Query(None),
    sort_by:    str            = Query("risk_score"),
    sort_dir:   str            = Query("desc"),
    skip:       int            = Query(0, ge=0),
    limit:      int            = Query(50, ge=1, le=500),
    org_id:     Optional[str]  = Query(None),
    db:         Session        = Depends(get_db),
    user:       User           = Depends(require_permission("assets", "read")),
):
    org = _resolve_org(user, org_id)
    q = db.query(Asset).filter(Asset.org_id == org)

    if search:
        q = q.filter(
            or_(
                Asset.hostname.ilike(f"%{search}%"),
                Asset.fqdn.ilike(f"%{search}%"),
                Asset.netbios_name.ilike(f"%{search}%"),
                func.cast(Asset.ip_address, String).ilike(f"%{search}%"),
            )
        )
    if risk_level:
        levels = [r.strip().lower() for r in risk_level.split(",")]
        q = q.filter(func.lower(Asset.risk_level).in_(levels))
    if os_family:
        q = q.filter(Asset.os_family.ilike(f"%{os_family}%"))
    if is_managed is not None:
        q = q.filter(Asset.is_managed == is_managed)
    if is_active is not None:
        q = q.filter(Asset.is_active == is_active)
    if subnet:
        q = q.filter(Asset.subnet.ilike(f"%{subnet}%"))

    total = q.count()

    col_map = {
        "risk_score":    Asset.risk_score,
        "first_seen_at": Asset.first_seen_at,
        "last_seen_at":  Asset.last_seen_at,
    }
    sort_col = col_map.get(sort_by, Asset.risk_score)
    q = q.order_by(sort_col.desc() if sort_dir == "desc" else sort_col.asc())
    assets = q.options(joinedload(Asset.tags)).offset(skip).limit(limit).all()

    return {
        "total": total, "skip": skip, "limit": limit,
        "assets": [_serialize_asset(a) for a in assets],
    }


# ── Asset Detail ──────────────────────────────────────────────────────────────

@router.get("/{asset_id}")
def get_asset(
    asset_id: str,
    org_id:   Optional[str] = Query(None),
    db:       Session       = Depends(get_db),
    user:     User          = Depends(require_permission("assets", "read")),
):
    org   = _resolve_org(user, org_id)
    asset = _asset_or_404(db, asset_id, org)
    data  = _serialize_asset(asset)
    data["custom_attributes"] = asset.custom_attributes or {}
    data["notes_summary"]     = getattr(asset, "notes_summary", None)
    data["notes"] = [
        {
            "id":         n.id,
            "content":    n.content,
            "user_id":    n.user_id,
            "created_at": n.created_at.isoformat() if n.created_at else None,
        }
        for n in (asset.notes or [])
    ]
    return data


# ── Asset Services ────────────────────────────────────────────────────────────

@router.get("/{asset_id}/services")
def get_asset_services(
    asset_id: str,
    org_id:   Optional[str] = Query(None),
    db:       Session       = Depends(get_db),
    user:     User          = Depends(require_permission("assets", "read")),
):
    org = _resolve_org(user, org_id)
    _asset_or_404(db, asset_id, org)

    services = (
        db.query(Service)
        .options(joinedload(Service.tls_detail), joinedload(Service.http_detail))
        .filter(Service.asset_id == asset_id)
        .order_by(Service.port.asc())
        .all()
    )

    result = []
    for svc in services:
        d = {
            "id":              svc.id,
            "port":            svc.port,
            "protocol":        svc.protocol,
            "state":           svc.state,
            "service_name":    svc.service_name,
            "service_product": svc.service_product,
            "service_version": svc.service_version,
            "banner":          svc.banner,
            "created_at":      svc.created_at.isoformat() if svc.created_at else None,
            "tls":  None,
            "http": None,
        }
        if svc.tls_detail:
            t = svc.tls_detail
            d["tls"] = {
                "is_enabled":         t.is_enabled,
                "protocol_version":   t.protocol_version,
                "cipher_suite":       t.cipher_suite,
                "grade":              t.grade,
                "is_weak_cipher":     t.is_weak_cipher,
                "cert_is_expired":    t.cert_is_expired,
                "cert_is_self_signed":t.cert_is_self_signed,
                "cert_not_after":     t.cert_not_after.isoformat() if t.cert_not_after else None,
                "cert_subject":       t.cert_subject,
                "issues":             t.issues or [],
            }
        if svc.http_detail:
            h = svc.http_detail
            d["http"] = {
                "status_code":     h.status_code,
                "has_hsts":        h.has_hsts,
                "has_csp":         h.has_csp,
                "x_frame_options": h.x_frame_options,
                "x_content_type":  h.x_content_type,
                "security_score":  h.security_score,
                "missing_headers": h.missing_headers or [],
            }
        result.append(d)

    return {"services": result}


# ── Asset Findings ────────────────────────────────────────────────────────────

@router.get("/{asset_id}/findings")
def get_asset_findings(
    asset_id: str,
    status:   Optional[str] = Query(None),
    org_id:   Optional[str] = Query(None),
    db:       Session       = Depends(get_db),
    user:     User          = Depends(require_permission("findings", "read")),
):
    org = _resolve_org(user, org_id)
    _asset_or_404(db, asset_id, org)

    q = (
        db.query(AssetVulnerability)
        .options(joinedload(AssetVulnerability.vulnerability))
        .filter(AssetVulnerability.asset_id == asset_id)
    )
    if status:
        q = q.filter(AssetVulnerability.status.in_([s.strip() for s in status.split(",")]))

    findings = q.all()
    result = []
    for f in findings:
        v = f.vulnerability
        if not v:
            continue
        ps, pl = compute_priority(
            cvss_score=float(v.cvss_v3_score or 0),
            epss_score=0.0,
            in_kev=(v.source == "kev"),
            has_exploit=False,
        )
        result.append({
            "id":           f.id,
            "vuln_id":      v.id,
            "title":        v.title,
            "severity":     v.severity,
            "cvss_v3_score": float(v.cvss_v3_score or 0),
            "epss_score":   0.0,
            "in_kev":       v.source == "kev",
            "priority_score": ps,
            "priority_label": pl,
            "status":       f.status,
            "proof":        f.proof,
            "plugin_output": f.plugin_output,
            "remediation_notes": f.remediation_notes,
            "first_found_at": f.first_found_at.isoformat() if f.first_found_at else None,
            "last_found_at":  f.last_found_at.isoformat() if f.last_found_at else None,
            "fixed_at":       f.fixed_at.isoformat() if f.fixed_at else None,
        })

    result.sort(key=lambda x: (-x["priority_score"], -x["cvss_v3_score"]))
    return {"findings": result}


# ── Asset Changelog (Modernized Timeline) ─────────────────────────────────────

@router.get("/{asset_id}/changelog")
def get_asset_changelog(
    asset_id: str,
    limit:    int           = Query(100, ge=1, le=500),
    category: Optional[str] = Query(None, description="Filter by event category"),
    severity: Optional[str] = Query(None, description="Minimum severity filter"),
    view:     str           = Query("timeline", description="'timeline' (grouped) or 'raw'"),
    org_id:   Optional[str] = Query(None),
    db:       Session       = Depends(get_db),
    user:     User          = Depends(require_permission("assets", "read")),
):
    from db.models.scans import Scan as ScanModel
    from core.audit_event_translator import translate_and_group_changelog

    org = _resolve_org(user, org_id)
    _asset_or_404(db, asset_id, org)

    entries = (
        db.query(AssetChangeLog)
        .filter(AssetChangeLog.asset_id == asset_id)
        .order_by(AssetChangeLog.detected_at.desc())
        .limit(limit)
        .all()
    )

    # Serialize raw entries
    raw_changelog = [
        {
            "id":          e.id,
            "change_type": e.change_type,
            "field_name":  e.field_name,
            "old_value":   _display_json_value(e.old_value),
            "new_value":   _display_json_value(e.new_value),
            "scan_id":     e.scan_id,
            "detected_at": e.detected_at.isoformat() if e.detected_at else None,
        }
        for e in entries
    ]

    # Build scan_type lookup for accurate group labels
    scan_ids = list({e.scan_id for e in entries if e.scan_id})
    scan_type_map = {}
    if scan_ids:
        scan_rows = (
            db.query(ScanModel.id, ScanModel.pipeline_mode)
            .filter(ScanModel.id.in_(scan_ids))
            .all()
        )
        for s in scan_rows:
            scan_type_map[s.id] = s.pipeline_mode or "scan"

    # Translate and group
    result = translate_and_group_changelog(raw_changelog, scan_type_map)

    # Apply category filter
    if category:
        cats = [c.strip().lower() for c in category.split(",")]
        result["timeline"] = [
            {**g, "events": [e for e in g["events"] if e.get("category") in cats]}
            for g in result["timeline"]
        ]
        result["timeline"] = [g for g in result["timeline"] if g["events"]]

    # Apply severity filter
    if severity:
        from core.audit_event_translator import SEVERITY_RANK
        min_rank = SEVERITY_RANK.get(severity.upper(), 0)
        result["timeline"] = [
            {**g, "events": [e for e in g["events"] if SEVERITY_RANK.get(e.get("severity", "INFO"), 0) >= min_rank]}
            for g in result["timeline"]
        ]
        result["timeline"] = [g for g in result["timeline"] if g["events"]]

    # Include legacy format for backward compatibility
    result["changelog"] = raw_changelog

    # Fetch administrative audit logs for this asset
    admin_logs_query = (
        db.query(AuditLog)
        .options(joinedload(AuditLog.user))
        .filter(AuditLog.resource_type == "asset")
        .filter(AuditLog.resource_id == asset_id)
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
        .all()
    )
    result["admin_logs"] = [
        {
            "id": str(log.id),
            "user_email": log.user.email if log.user else "System",
            "action": log.action,
            "status": log.status,
            "changes": log.changes,
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log in admin_logs_query
    ]

    return result


# ── Patch Asset ───────────────────────────────────────────────────────────────

class AssetUpdate(BaseModel):
    is_managed:        Optional[bool] = None
    owner:             Optional[str]  = None
    custom_attributes: Optional[dict] = None


@router.patch("/{asset_id}")
def update_asset(
    asset_id: str,
    body:     AssetUpdate,
    org_id:   Optional[str] = Query(None),
    db:       Session       = Depends(get_db),
    user:     User          = Depends(require_permission("assets", "update")),
):
    org   = _resolve_org(user, org_id)
    asset = _asset_or_404(db, asset_id, org)

    if body.is_managed is not None:
        asset.is_managed = body.is_managed
    if body.owner is not None:
        asset.owner = body.owner
    if body.custom_attributes is not None:
        asset.custom_attributes = body.custom_attributes

    db.commit()

    # Use the real audit function signature
    log_audit_event(
        db=db, user=user,
        action="asset_updated",
        resource_type="asset",
        resource_id=asset_id,
        status="success",
    )

    return {"success": True, "id": asset_id}


# ── Tags ──────────────────────────────────────────────────────────────────────

class TagBody(BaseModel):
    tag: str


@router.post("/{asset_id}/tags", status_code=status.HTTP_201_CREATED)
def add_tag(
    asset_id: str,
    body:     TagBody,
    org_id:   Optional[str] = Query(None),
    db:       Session       = Depends(get_db),
    user:     User          = Depends(require_permission("assets", "update")),
):
    org = _resolve_org(user, org_id)
    _asset_or_404(db, asset_id, org)

    tag_val = body.tag.strip()[:100]
    existing = db.query(AssetTag).filter(
        AssetTag.asset_id == asset_id, AssetTag.tag == tag_val
    ).first()
    if existing:
        return {"success": True, "tag": tag_val}

    db.add(AssetTag(asset_id=asset_id, tag=tag_val, created_by_id=str(user.id)))
    db.commit()
    return {"success": True, "tag": tag_val}


@router.delete("/{asset_id}/tags/{tag}")
def remove_tag(
    asset_id: str,
    tag:      str,
    org_id:   Optional[str] = Query(None),
    db:       Session       = Depends(get_db),
    user:     User          = Depends(require_permission("assets", "update")),
):
    org = _resolve_org(user, org_id)
    _asset_or_404(db, asset_id, org)

    row = db.query(AssetTag).filter(
        AssetTag.asset_id == asset_id, AssetTag.tag == tag
    ).first()
    if row:
        db.delete(row)
        db.commit()
    return {"success": True}


# ── Notes ─────────────────────────────────────────────────────────────────────

class NoteBody(BaseModel):
    content: str


@router.post("/{asset_id}/notes", status_code=status.HTTP_201_CREATED)
def add_note(
    asset_id: str,
    body:     NoteBody,
    org_id:   Optional[str] = Query(None),
    db:       Session       = Depends(get_db),
    user:     User          = Depends(require_permission("assets", "update")),
):
    org = _resolve_org(user, org_id)
    _asset_or_404(db, asset_id, org)

    note = AssetNote(
        asset_id=asset_id,
        user_id=str(user.id),
        content=body.content.strip(),
    )
    db.add(note)
    db.commit()
    return {"success": True, "id": note.id}
