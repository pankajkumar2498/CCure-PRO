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

from auth.rbac import require_permission
from core.audit import log_audit_event
from core.vuln_intel import compute_priority
from db.base import get_db
from db.models import AMTInventoryRecord, AuditLog, User
from db.models.assets import Asset, AssetChangeLog, AssetNote, AssetTag
from db.models.findings import (
    OBSERVED_SERVICE_STATES,
    AssetVulnerability,
    Service,
    TLSDetail,
)
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import String, func, or_
from sqlalchemy.orm import Session, joinedload

log = logging.getLogger("ccure.assets")
router = APIRouter(prefix="/assets", tags=["Assets"])


def _display_json_value(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _is_superadmin(user: User) -> bool:
    return (
        getattr(getattr(user, "role", None), "name", "") or ""
    ).lower() == "superadmin"


def _resolve_org(user: User, requested_org: str | None) -> str:
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
        "id": a.id,
        "ip_address": str(a.ip_address),
        "mac_address": str(a.mac_address) if a.mac_address else None,
        "hostname": a.hostname,
        "fqdn": a.fqdn,
        "netbios_name": a.netbios_name,
        "dns_name": a.dns_name,
        "os_name": a.os_name,
        "os_family": a.os_family,
        "os_version": getattr(a, "os_version", None),
        "os_confidence": os_confidence,
        "device_category": a.device_category,
        "vendor": a.vendor,
        "manufacturer": getattr(a, "manufacturer", None),
        "subnet": a.subnet,
        "vlan_id": a.vlan_id,
        "risk_score": a.risk_score,
        "risk_level": a.risk_level,
        "is_managed": a.is_managed,
        "is_active": a.is_active,
        "owner": a.owner,
        "emp_id": (a.custom_attributes or {}).get("owner_employee_id"),
        "serial": (a.custom_attributes or {}).get("serial_number"),
        "discovery_method": a.discovery_method,
        "response_time_ms": a.response_time_ms,
        "last_scan_id": a.last_scan_id,
        "vuln_counts": {
            "critical": vc.get("critical", vc.get("Critical", 0)),
            "high": vc.get("high", vc.get("High", 0)),
            "medium": vc.get("medium", vc.get("Medium", 0)),
            "low": vc.get("low", vc.get("Low", 0)),
        },
        "tags": [t.tag for t in (a.tags or [])],
        "first_seen_at": a.first_seen_at.isoformat() if a.first_seen_at else None,
        "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
        "provenance": getattr(a, "provenance", None) or {},
    }


@router.get("")
@router.get("/")
def list_assets(
    search: str | None = Query(None),
    risk_level: str | None = Query(None),
    os_family: str | None = Query(None),
    verification_status: str | None = Query(None),
    is_managed: bool | None = Query(None),
    is_active: bool | None = Query(None),
    subnet: str | None = Query(None),
    sort_by: str = Query("risk_score"),
    sort_dir: str = Query("desc"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("assets", "read")),
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
                Asset.owner.ilike(f"%{search}%"),
                Asset.custom_attributes["serial_number"].astext.ilike(f"%{search}%"),
                Asset.custom_attributes["owner_employee_id"].astext.ilike(
                    f"%{search}%"
                ),
            )
        )
    if risk_level:
        levels = [r.strip().lower() for r in risk_level.split(",")]
        q = q.filter(func.lower(Asset.risk_level).in_(levels))
    if os_family:
        if os_family.lower() == "unknown":
            q = q.filter(
                or_(
                    Asset.os_family.is_(None),
                    Asset.os_family == "",
                    Asset.os_family.ilike("%unknown%"),
                )
            ).filter(
                or_(
                    Asset.os_name.is_(None),
                    Asset.os_name == "",
                    Asset.os_name.ilike("%unknown%"),
                )
            )
        else:
            q = q.filter(
                or_(
                    Asset.os_family.ilike(f"%{os_family}%"),
                    Asset.os_name.ilike(f"%{os_family}%"),
                )
            )
    if verification_status:
        v_status = verification_status.lower()
        if v_status == "verified":
            q = q.filter(
                or_(
                    Asset.custom_attributes["correlation"]["status"].astext == "active",
                    Asset.provenance["owner"]["source"].astext == "amt_import",
                    Asset.custom_attributes["amt_asset_tag"].astext.isnot(None),
                )
            )
        elif v_status == "unverified":
            q = (
                q.filter(Asset.mac_address.isnot(None))
                .filter(
                    or_(
                        Asset.custom_attributes["correlation"]["status"].astext
                        != "active",
                        Asset.custom_attributes["correlation"].is_(None),
                    )
                )
                .filter(
                    or_(
                        Asset.provenance["owner"]["source"].astext != "amt_import",
                        Asset.provenance["owner"].is_(None),
                    )
                )
                .filter(Asset.custom_attributes["amt_asset_tag"].is_(None))
            )
        elif v_status == "pending":
            q = q.filter(Asset.mac_address.is_(None))
    if is_managed is not None:
        q = q.filter(Asset.is_managed == is_managed)
    if is_active is not None:
        q = q.filter(Asset.is_active == is_active)
    if subnet:
        q = q.filter(Asset.subnet.ilike(f"%{subnet}%"))

    total = q.count()

    col_map = {
        "risk_score": Asset.risk_score,
        "first_seen_at": Asset.first_seen_at,
        "last_seen_at": Asset.last_seen_at,
    }
    sort_col = col_map.get(sort_by, Asset.risk_score)
    q = q.order_by(sort_col.desc() if sort_dir == "desc" else sort_col.asc())
    assets = q.options(joinedload(Asset.tags)).offset(skip).limit(limit).all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "assets": [_serialize_asset(a) for a in assets],
    }


# ── Debug AMT Reconciliation ──────────────────────────────────────────────────


@router.get("/debug-reconcile")
def debug_reconcile(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("assets", "read")),
):
    from core.amt_reconciliation import reconcile_amt_inventory
    from core.utils import normalize_mac

    # Fetch scanned assets with MACs (global / all orgs to see if there is an org mismatch)
    scanned_assets = db.query(Asset).filter(Asset.mac_address != None).all()

    scanned_details = []
    for a in scanned_assets:
        scanned_details.append(
            {
                "id": a.id,
                "org_id": a.org_id,
                "ip": str(a.ip_address),
                "mac": str(a.mac_address) if a.mac_address else None,
                "norm_mac": (
                    normalize_mac(str(a.mac_address)) if a.mac_address else None
                ),
                "owner": a.owner,
            }
        )

    # Fetch AMT records (global / all orgs)
    amt_records = db.query(AMTInventoryRecord).all()

    amt_details = []
    for r in amt_records:
        amt_details.append(
            {
                "id": r.id,
                "org_id": r.org_id,
                "mac1": str(r.mac_address_1) if r.mac_address_1 else None,
                "norm_mac1": (
                    normalize_mac(str(r.mac_address_1)) if r.mac_address_1 else None
                ),
                "mac2": str(r.mac_address_2) if r.mac_address_2 else None,
                "norm_mac2": (
                    normalize_mac(str(r.mac_address_2)) if r.mac_address_2 else None
                ),
                "asset_user": r.asset_user,
            }
        )

    # Run the current reconciliation engine to see what it outputs for the user's org
    stats = reconcile_amt_inventory(db, user.org_id)

    return {
        "user_logged_in_org_id": user.org_id,
        "scanned_count_total": len(scanned_assets),
        "amt_count_total": len(amt_records),
        "scanned_assets": scanned_details,
        "amt_records": amt_details,
        "reconciliation_stats": stats,
    }


# ── Global TLS/Certificates Inventory ──────────────────────────────────────────


@router.get("/certificates")
def list_global_certificates(
    search: str | None = Query(None),
    sort_by: str = Query("expiration"),
    sort_dir: str = Query("asc"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("assets", "read")),
):
    """
    Retrieve a centralized inventory of all TLS/SSL certificates and configurations
    across the entire organization infrastructure.
    """
    org = _resolve_org(user, org_id)

    # Base query joining TLSDetail, Service, and Asset to enforce org-level isolation
    q = db.query(TLSDetail).join(Service).join(Asset).filter(Asset.org_id == org)

    if search:
        search_filter = or_(
            TLSDetail.grade.ilike(f"%{search}%"),
            TLSDetail.protocol_version.ilike(f"%{search}%"),
            TLSDetail.cipher_suite.ilike(f"%{search}%"),
            func.cast(Service.port, String).ilike(f"%{search}%"),
            Asset.hostname.ilike(f"%{search}%"),
            func.cast(Asset.ip_address, String).ilike(f"%{search}%"),
            func.cast(TLSDetail.cert_subject, String).ilike(f"%{search}%"),
            func.cast(TLSDetail.cert_issuer, String).ilike(f"%{search}%"),
        )
        q = q.filter(search_filter)

    total = q.count()

    # Column mapping for sorting
    col_map = {
        "grade": TLSDetail.grade,
        "expiration": TLSDetail.cert_not_after,
        "port": Service.port,
        "ip_address": Asset.ip_address,
        "hostname": Asset.hostname,
    }
    sort_col = col_map.get(sort_by, TLSDetail.cert_not_after)
    q = q.order_by(sort_col.desc() if sort_dir == "desc" else sort_col.asc())

    certs = (
        q.options(joinedload(TLSDetail.service).joinedload(Service.asset))
        .offset(skip)
        .limit(limit)
        .all()
    )

    result = []
    for c in certs:
        result.append(
            {
                "id": c.id,
                "service_id": c.service_id,
                "port": c.service.port if c.service else None,
                "protocol": c.service.protocol if c.service else "tcp",
                "protocol_version": c.protocol_version,
                "cipher_suite": c.cipher_suite,
                "grade": c.grade or "N/A",
                "is_weak_cipher": c.is_weak_cipher,
                "cert_is_expired": c.cert_is_expired,
                "cert_is_self_signed": c.cert_is_self_signed,
                "cert_not_after": (
                    c.cert_not_after.isoformat() if c.cert_not_after else None
                ),
                "cert_subject": c.cert_subject,
                "cert_issuer": c.cert_issuer,
                "issues": c.issues or [],
                "asset_id": c.service.asset_id if c.service else None,
                "asset_ip": (
                    str(c.service.asset.ip_address)
                    if (c.service and c.service.asset)
                    else None
                ),
                "asset_hostname": (
                    c.service.asset.hostname
                    if (c.service and c.service.asset)
                    else None
                ),
            }
        )

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "certificates": result,
    }


# ── Global Services Inventory ──────────────────────────────────────────────────

_TARGETED_SERVICES = {
    21: {"risk_level": "Medium", "reason": "FTP (Plaintext Credentials)"},
    22: {"risk_level": "Medium", "reason": "SSH Remote Access"},
    23: {"risk_level": "Critical", "reason": "Telnet (Unencrypted Remote Shell)"},
    139: {"risk_level": "High", "reason": "NetBIOS Session Service"},
    445: {"risk_level": "Critical", "reason": "Microsoft SMB (Active Attack Target)"},
    1433: {"risk_level": "High", "reason": "Microsoft SQL Server"},
    1521: {"risk_level": "High", "reason": "Oracle TNS Listener"},
    3306: {"risk_level": "Medium", "reason": "MySQL Database Server"},
    3389: {"risk_level": "Critical", "reason": "Remote Desktop Protocol (RDP)"},
    5432: {"risk_level": "Medium", "reason": "PostgreSQL Database Server"},
    5900: {"risk_level": "High", "reason": "VNC Remote Desktop"},
}


@router.get("/services")
def list_global_services(
    search: str | None = Query(None),
    port: int | None = Query(None),
    protocol: str | None = Query(None),
    asset_type: str | None = Query(None),
    subnet: str | None = Query(None),
    sort_by: str = Query("asset_count"),
    sort_dir: str = Query("desc"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("assets", "read")),
):
    """
    Retrieve an aggregated centralized inventory of all discovered services and open ports
    across the entire organization infrastructure.
    """
    org = _resolve_org(user, org_id)

    service_name_expr = func.coalesce(func.nullif(Service.service_name, ""), "unknown")

    # Base query joining Service and Asset to enforce org-level isolation and support filters
    q = (
        db.query(
            service_name_expr.label("service_name"),
            Service.port.label("port"),
            Service.protocol.label("protocol"),
            func.count(func.distinct(Service.asset_id)).label("asset_count"),
            func.max(Service.updated_at).label("last_seen"),
        )
        .join(Asset)
        .filter(Asset.org_id == org, Service.state.in_(OBSERVED_SERVICE_STATES))
    )

    # Apply filters
    if search:
        search_filter = or_(
            Service.service_name.ilike(f"%{search}%"),
            Service.service_product.ilike(f"%{search}%"),
            func.cast(Service.port, String).ilike(f"%{search}%"),
        )
        q = q.filter(search_filter)

    if port is not None:
        q = q.filter(Service.port == port)
    if protocol:
        q = q.filter(Service.protocol.ilike(protocol))
    if asset_type:
        q = q.filter(Asset.device_category.ilike(f"%{asset_type}%"))
    if subnet:
        q = q.filter(Asset.subnet.ilike(f"%{subnet}%"))

    q = q.group_by(service_name_expr, Service.port, Service.protocol)

    # Sorting
    if sort_by == "port":
        sort_col = Service.port
    elif sort_by == "protocol":
        sort_col = Service.protocol
    elif sort_by == "service_name":
        sort_col = service_name_expr
    elif sort_by == "last_seen":
        sort_col = func.max(Service.updated_at)
    else:  # asset_count (default)
        sort_col = func.count(func.distinct(Service.asset_id))

    q = q.order_by(sort_col.desc() if sort_dir == "desc" else sort_col.asc())

    # Get total count of aggregates by evaluating subquery count
    total = db.query(func.count()).select_from(q.subquery()).scalar()

    records = q.offset(skip).limit(limit).all()

    result = []
    for rec in records:
        port_num = rec.port
        risk_info = _TARGETED_SERVICES.get(
            port_num, {"risk_level": "None", "reason": "Standard Service"}
        )
        result.append(
            {
                "service_name": rec.service_name,
                "port": rec.port,
                "protocol": rec.protocol,
                "asset_count": rec.asset_count,
                "last_seen": rec.last_seen.isoformat() if rec.last_seen else None,
                "risk_level": risk_info["risk_level"],
                "risk_reason": risk_info["reason"],
            }
        )

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "services": result,
    }


@router.get("/services/assets")
def list_service_assets(
    service_name: str = Query(...),
    port: int = Query(...),
    protocol: str = Query(...),
    search: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("assets", "read")),
):
    """
    Retrieve all assets running a specific service-port-protocol signature.
    Supports internal searching by IP/hostname.
    """
    org = _resolve_org(user, org_id)

    q = (
        db.query(Service)
        .join(Asset)
        .filter(
            Asset.org_id == org,
            Service.port == port,
            Service.protocol.ilike(protocol),
            Service.state.in_(OBSERVED_SERVICE_STATES),
        )
    )

    if service_name and service_name != "unknown":
        q = q.filter(Service.service_name.ilike(service_name))
    else:
        q = q.filter(or_(Service.service_name == None, Service.service_name == ""))

    if search:
        search_filter = or_(
            Asset.hostname.ilike(f"%{search}%"),
            func.cast(Asset.ip_address, String).ilike(f"%{search}%"),
        )
        q = q.filter(search_filter)

    total = q.count()

    services = q.options(joinedload(Service.asset)).offset(skip).limit(limit).all()

    result = []
    for svc in services:
        result.append(
            {
                "asset_id": svc.asset_id,
                "asset_hostname": svc.asset.hostname or "—",
                "asset_ip": str(svc.asset.ip_address) if svc.asset.ip_address else "—",
                "asset_type": svc.asset.device_category or "—",
                "state": svc.state,
                "service_version": svc.service_version or "—",
                "service_product": svc.service_product or "—",
                "last_scan_time": (
                    svc.updated_at.isoformat() if svc.updated_at else None
                ),
            }
        )

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "assets": result,
    }


@router.get("/coverage-stats")
def get_coverage_stats(
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("assets", "read")),
):
    """
    Retrieve coverage and gap statistics between scanned assets and corporate AMT inventory.
    """
    org = _resolve_org(user, org_id)

    # Get scanned assets counts
    total_scanned = (
        db.query(Asset).filter(Asset.org_id == org, Asset.mac_address != None).count()
    )

    # Get inventory reference counts (isolated to current tenant)
    total_inventory = (
        db.query(AMTInventoryRecord).filter(AMTInventoryRecord.org_id == org).count()
    )

    if total_inventory == 0:
        return {
            "configured": False,
            "total_scanned": total_scanned,
            "total_inventory": 0,
            "fully_audited": 0,
            "shadow_it": total_scanned,
            "coverage_gap": 0,
            "coverage_percentage": 0.0,
        }

    # Query matching active assets (Fully Audited)
    scanned_macs_query = db.query(Asset.mac_address).filter(
        Asset.org_id == org, Asset.mac_address != None
    )

    fully_audited = (
        db.query(AMTInventoryRecord)
        .filter(
            AMTInventoryRecord.org_id == org,
            or_(
                AMTInventoryRecord.mac_address_1.in_(scanned_macs_query),
                AMTInventoryRecord.mac_address_2.in_(scanned_macs_query),
            ),
        )
        .count()
    )

    # Shadow IT: Scanned assets that do NOT match any AMT inventory MAC for this org
    amt_mac1_query = db.query(AMTInventoryRecord.mac_address_1).filter(
        AMTInventoryRecord.org_id == org
    )
    amt_mac2_query = db.query(AMTInventoryRecord.mac_address_2).filter(
        AMTInventoryRecord.org_id == org, AMTInventoryRecord.mac_address_2 != None
    )

    shadow_it = (
        db.query(Asset)
        .filter(
            Asset.org_id == org,
            Asset.mac_address != None,
            ~Asset.mac_address.in_(amt_mac1_query),
            ~Asset.mac_address.in_(amt_mac2_query),
        )
        .count()
    )

    # Coverage Gap: Inventory records that are not present in scanned assets MACs
    coverage_gap = (
        db.query(AMTInventoryRecord)
        .filter(
            AMTInventoryRecord.org_id == org,
            ~AMTInventoryRecord.mac_address_1.in_(scanned_macs_query),
            or_(
                AMTInventoryRecord.mac_address_2 == None,
                ~AMTInventoryRecord.mac_address_2.in_(scanned_macs_query),
            ),
        )
        .count()
    )

    coverage_percentage = (
        round((fully_audited / total_inventory) * 100, 2)
        if total_inventory > 0
        else 0.0
    )

    return {
        "configured": True,
        "total_scanned": total_scanned,
        "total_inventory": total_inventory,
        "fully_audited": fully_audited,
        "shadow_it": shadow_it,
        "coverage_gap": coverage_gap,
        "coverage_percentage": coverage_percentage,
    }


@router.get("/reconciliation/drilldown")
def get_reconciliation_drilldown(
    category: str = Query(...),
    search: str | None = Query(None),
    owner: str | None = Query(None),
    department: str | None = Query(None),
    location: str | None = Query(None),
    sort_by: str | None = Query(None),
    sort_dir: str = Query("desc"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    org_id: str | None = Query(None),
    export: bool = Query(False),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("assets", "read")),
):
    """
    Retrieve paginated lists of assets or inventory records for reconciliation drilldown categories:
    - scanned: All scanned assets with MAC address
    - inventory: All imported inventory records
    - matched: Reconciled assets that match inventory MAC addresses
    - shadow_it: Scanned assets with MAC addresses that do not exist in inventory
    - coverage_gap: Inventory records with MAC addresses that do not exist in scanned assets
    """
    import csv
    import io

    from fastapi.responses import StreamingResponse

    org = _resolve_org(user, org_id)

    # 1. Base queries matching coverage-stats definitions
    if category in ("scanned", "matched", "shadow_it"):
        # We query the Asset model
        q = db.query(Asset).filter(Asset.org_id == org, Asset.mac_address != None)

        # Apply matched / shadow IT subqueries
        amt_mac1 = db.query(AMTInventoryRecord.mac_address_1).filter(
            AMTInventoryRecord.org_id == org
        )
        amt_mac2 = db.query(AMTInventoryRecord.mac_address_2).filter(
            AMTInventoryRecord.org_id == org, AMTInventoryRecord.mac_address_2 != None
        )

        if category == "matched":
            q = q.filter(
                or_(Asset.mac_address.in_(amt_mac1), Asset.mac_address.in_(amt_mac2))
            )
        elif category == "shadow_it":
            q = q.filter(
                ~Asset.mac_address.in_(amt_mac1), ~Asset.mac_address.in_(amt_mac2)
            )

        # Apply searching
        if search:
            q = q.filter(
                or_(
                    Asset.hostname.ilike(f"%{search}%"),
                    Asset.fqdn.ilike(f"%{search}%"),
                    Asset.netbios_name.ilike(f"%{search}%"),
                    func.cast(Asset.ip_address, String).ilike(f"%{search}%"),
                    func.cast(Asset.mac_address, String).ilike(f"%{search}%"),
                    Asset.owner.ilike(f"%{search}%"),
                    Asset.vendor.ilike(f"%{search}%"),
                )
            )

        # Apply filters
        if owner:
            q = q.filter(Asset.owner.ilike(f"%{owner}%"))
        if department:
            q = q.filter(
                or_(
                    Asset.custom_attributes["amt_company_name"].astext.ilike(
                        f"%{department}%"
                    ),
                    Asset.vendor.ilike(f"%{department}%"),
                )
            )
        if location:
            q = q.filter(
                Asset.custom_attributes["amt_location"].astext.ilike(f"%{location}%")
            )

        # Sorting mapping
        col_map = {
            "hostname": Asset.hostname,
            "ip_address": Asset.ip_address,
            "mac_address": Asset.mac_address,
            "risk_score": Asset.risk_score,
            "first_seen_at": Asset.first_seen_at,
            "last_seen_at": Asset.last_seen_at,
            "owner": Asset.owner,
        }
        sort_col = col_map.get(sort_by, Asset.last_seen_at)
        q = q.order_by(sort_col.desc() if sort_dir == "desc" else sort_col.asc())

    elif category in ("inventory", "coverage_gap"):
        # We query the AMTInventoryRecord model
        q = db.query(AMTInventoryRecord).filter(AMTInventoryRecord.org_id == org)

        # Apply coverage gap subquery
        if category == "coverage_gap":
            scanned_macs = db.query(Asset.mac_address).filter(
                Asset.org_id == org, Asset.mac_address != None
            )
            q = q.filter(
                ~AMTInventoryRecord.mac_address_1.in_(scanned_macs),
                or_(
                    AMTInventoryRecord.mac_address_2 == None,
                    ~AMTInventoryRecord.mac_address_2.in_(scanned_macs),
                ),
            )

        # Apply searching
        if search:
            q = q.filter(
                or_(
                    AMTInventoryRecord.asset_name.ilike(f"%{search}%"),
                    AMTInventoryRecord.asset_tag.ilike(f"%{search}%"),
                    AMTInventoryRecord.serial.ilike(f"%{search}%"),
                    AMTInventoryRecord.vendor.ilike(f"%{search}%"),
                    AMTInventoryRecord.asset_user.ilike(f"%{search}%"),
                    AMTInventoryRecord.emp_id.ilike(f"%{search}%"),
                    func.cast(AMTInventoryRecord.mac_address_1, String).ilike(
                        f"%{search}%"
                    ),
                    func.cast(AMTInventoryRecord.mac_address_2, String).ilike(
                        f"%{search}%"
                    ),
                )
            )

        # Apply filters
        if owner:
            q = q.filter(AMTInventoryRecord.asset_user.ilike(f"%{owner}%"))
        if department:
            q = q.filter(
                or_(
                    AMTInventoryRecord.company_name.ilike(f"%{department}%"),
                    AMTInventoryRecord.asset_type.ilike(f"%{department}%"),
                )
            )
        if location:
            q = q.filter(AMTInventoryRecord.location.ilike(f"%{location}%"))

        # Sorting mapping
        col_map = {
            "asset_tag": AMTInventoryRecord.asset_tag,
            "asset_name": AMTInventoryRecord.asset_name,
            "serial": AMTInventoryRecord.serial,
            "asset_user": AMTInventoryRecord.asset_user,
            "status": AMTInventoryRecord.status,
            "location": AMTInventoryRecord.location,
            "company_name": AMTInventoryRecord.company_name,
        }
        sort_col = col_map.get(sort_by, AMTInventoryRecord.asset_tag)
        q = q.order_by(sort_col.desc() if sort_dir == "desc" else sort_col.asc())

    else:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid category: '{category}'. Valid options are: scanned, inventory, matched, shadow_it, coverage_gap.",
        )

    # 2. Export handling
    if export:
        # Fetch all results, bypassing pagination
        results = q.all()
        output = io.StringIO()
        writer = csv.writer(output)

        if category in ("scanned", "matched", "shadow_it"):
            writer.writerow(
                [
                    "ID",
                    "Hostname",
                    "IP Address",
                    "MAC Address",
                    "Device Category",
                    "OS Family",
                    "OS Name",
                    "Vendor",
                    "Owner",
                    "Is Managed",
                    "Is Active",
                    "First Seen At",
                    "Last Seen At",
                    "Risk Level",
                    "Risk Score",
                ]
            )
            for a in results:
                writer.writerow(
                    [
                        a.id,
                        a.hostname or "",
                        str(a.ip_address) if a.ip_address else "",
                        str(a.mac_address) if a.mac_address else "",
                        a.device_category or "",
                        a.os_family or "",
                        a.os_name or "",
                        a.vendor or "",
                        a.owner or "",
                        a.is_managed,
                        a.is_active,
                        a.first_seen_at.isoformat() if a.first_seen_at else "",
                        a.last_seen_at.isoformat() if a.last_seen_at else "",
                        a.risk_level or "",
                        a.risk_score,
                    ]
                )
        else:
            writer.writerow(
                [
                    "ID",
                    "Asset Tag",
                    "Asset Name",
                    "Serial",
                    "Vendor",
                    "Asset Type",
                    "Asset User",
                    "Employee ID",
                    "Status",
                    "Location",
                    "Location ID",
                    "Company Name",
                    "MAC Address 1",
                    "MAC Address 2",
                ]
            )
            for r in results:
                writer.writerow(
                    [
                        r.id,
                        r.asset_tag or "",
                        r.asset_name or "",
                        r.serial or "",
                        r.vendor or "",
                        r.asset_type or "",
                        r.asset_user or "",
                        r.emp_id or "",
                        r.status or "",
                        r.location or "",
                        r.location_id or "",
                        r.company_name or "",
                        str(r.mac_address_1) if r.mac_address_1 else "",
                        str(r.mac_address_2) if r.mac_address_2 else "",
                    ]
                )

        output.seek(0)
        response = StreamingResponse(iter([output.getvalue()]), media_type="text/csv")
        response.headers["Content-Disposition"] = (
            f"attachment; filename=amt_{category}_export.csv"
        )
        return response

    # 3. Paginated JSON response
    total = q.count()
    records = q.offset(skip).limit(limit).all()

    if category in ("scanned", "matched", "shadow_it"):
        serialized = [_serialize_asset(r) for r in records]
    else:
        # Serializer for AMTInventoryRecord
        serialized = [
            {
                "id": r.id,
                "org_id": r.org_id,
                "mac_address_1": str(r.mac_address_1) if r.mac_address_1 else None,
                "mac_address_2": str(r.mac_address_2) if r.mac_address_2 else None,
                "asset_tag": r.asset_tag,
                "asset_name": r.asset_name,
                "serial": r.serial,
                "vendor": r.vendor,
                "asset_type": r.asset_type,
                "asset_user": r.asset_user,
                "emp_id": r.emp_id,
                "status": r.status,
                "location": r.location,
                "location_id": r.location_id,
                "company_name": r.company_name,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "updated_at": r.updated_at.isoformat() if r.updated_at else None,
            }
            for r in records
        ]

    return {"total": total, "skip": skip, "limit": limit, "data": serialized}


# ── Asset Detail ─────────────────────────────────────────────────────────────────────────────


@router.get("/{asset_id}")
def get_asset(
    asset_id: str,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("assets", "read")),
):
    org = _resolve_org(user, org_id)
    asset = _asset_or_404(db, asset_id, org)
    data = _serialize_asset(asset)
    data["custom_attributes"] = asset.custom_attributes or {}
    data["notes_summary"] = getattr(asset, "notes_summary", None)
    data["notes"] = [
        {
            "id": n.id,
            "content": n.content,
            "user_id": n.user_id,
            "created_at": n.created_at.isoformat() if n.created_at else None,
        }
        for n in (asset.notes or [])
    ]
    return data


# ── Asset Services ────────────────────────────────────────────────────────────


@router.get("/{asset_id}/services")
def get_asset_services(
    asset_id: str,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("assets", "read")),
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
            "id": svc.id,
            "port": svc.port,
            "protocol": svc.protocol,
            "state": svc.state,
            "service_name": svc.service_name,
            "service_product": svc.service_product,
            "service_version": svc.service_version,
            "banner": svc.banner,
            "created_at": svc.created_at.isoformat() if svc.created_at else None,
            "tls": None,
            "http": None,
        }
        if svc.tls_detail:
            t = svc.tls_detail
            d["tls"] = {
                "is_enabled": t.is_enabled,
                "protocol_version": t.protocol_version,
                "cipher_suite": t.cipher_suite,
                "grade": t.grade,
                "is_weak_cipher": t.is_weak_cipher,
                "cert_is_expired": t.cert_is_expired,
                "cert_is_self_signed": t.cert_is_self_signed,
                "cert_not_after": (
                    t.cert_not_after.isoformat() if t.cert_not_after else None
                ),
                "cert_subject": t.cert_subject,
                "issues": t.issues or [],
            }
        if svc.http_detail:
            h = svc.http_detail
            d["http"] = {
                "status_code": h.status_code,
                "has_hsts": h.has_hsts,
                "has_csp": h.has_csp,
                "x_frame_options": h.x_frame_options,
                "x_content_type": h.x_content_type,
                "security_score": h.security_score,
                "missing_headers": h.missing_headers or [],
            }
        result.append(d)

    return {"services": result}


# ── Asset Findings ────────────────────────────────────────────────────────────


@router.get("/{asset_id}/findings")
def get_asset_findings(
    asset_id: str,
    status: str | None = Query(None),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("findings", "read")),
):
    org = _resolve_org(user, org_id)
    _asset_or_404(db, asset_id, org)

    q = (
        db.query(AssetVulnerability)
        .options(joinedload(AssetVulnerability.vulnerability))
        .filter(AssetVulnerability.asset_id == asset_id)
    )
    if status:
        q = q.filter(
            AssetVulnerability.status.in_([s.strip() for s in status.split(",")])
        )

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
        result.append(
            {
                "id": f.id,
                "vuln_id": v.id,
                "title": v.title,
                "severity": v.severity,
                "cvss_v3_score": float(v.cvss_v3_score or 0),
                "epss_score": 0.0,
                "in_kev": v.source == "kev",
                "priority_score": ps,
                "priority_label": pl,
                "status": f.status,
                "proof": f.proof,
                "plugin_output": f.plugin_output,
                "remediation_notes": f.remediation_notes,
                "first_found_at": (
                    f.first_found_at.isoformat() if f.first_found_at else None
                ),
                "last_found_at": (
                    f.last_found_at.isoformat() if f.last_found_at else None
                ),
                "fixed_at": f.fixed_at.isoformat() if f.fixed_at else None,
            }
        )

    result.sort(key=lambda x: (-x["priority_score"], -x["cvss_v3_score"]))
    return {"findings": result}


# ── Asset Changelog (Modernized Timeline) ─────────────────────────────────────


@router.get("/{asset_id}/changelog")
def get_asset_changelog(
    asset_id: str,
    limit: int = Query(100, ge=1, le=500),
    category: str | None = Query(None, description="Filter by event category"),
    severity: str | None = Query(None, description="Minimum severity filter"),
    view: str = Query("timeline", description="'timeline' (grouped) or 'raw'"),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("assets", "read")),
):
    from core.audit_event_translator import translate_and_group_changelog
    from db.models.scans import Scan as ScanModel

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
            "id": e.id,
            "change_type": e.change_type,
            "field_name": e.field_name,
            "old_value": _display_json_value(e.old_value),
            "new_value": _display_json_value(e.new_value),
            "scan_id": e.scan_id,
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
            {
                **g,
                "events": [
                    e
                    for e in g["events"]
                    if SEVERITY_RANK.get(e.get("severity", "INFO"), 0) >= min_rank
                ],
            }
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
    is_managed: bool | None = None
    owner: str | None = None
    custom_attributes: dict | None = None


@router.patch("/{asset_id}")
def update_asset(
    asset_id: str,
    body: AssetUpdate,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("assets", "update")),
):
    org = _resolve_org(user, org_id)
    asset = _asset_or_404(db, asset_id, org)

    if body.is_managed is not None:
        asset.is_managed = body.is_managed
    if body.owner is not None:
        asset.owner = body.owner
        import datetime

        prov = dict(asset.provenance or {})
        prov["owner"] = {
            "source": "analyst",
            "user_id": str(user.id),
            "updated_at": datetime.datetime.utcnow().isoformat(),
        }
        asset.provenance = prov
    if body.custom_attributes is not None:
        asset.custom_attributes = body.custom_attributes

    db.commit()

    # Use the real audit function signature
    log_audit_event(
        db=db,
        user=user,
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
    body: TagBody,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("assets", "update")),
):
    org = _resolve_org(user, org_id)
    _asset_or_404(db, asset_id, org)

    tag_val = body.tag.strip()[:100]
    existing = (
        db.query(AssetTag)
        .filter(AssetTag.asset_id == asset_id, AssetTag.tag == tag_val)
        .first()
    )
    if existing:
        return {"success": True, "tag": tag_val}

    db.add(AssetTag(asset_id=asset_id, tag=tag_val, created_by_id=str(user.id)))
    db.commit()
    return {"success": True, "tag": tag_val}


@router.delete("/{asset_id}/tags/{tag}")
def remove_tag(
    asset_id: str,
    tag: str,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("assets", "update")),
):
    org = _resolve_org(user, org_id)
    _asset_or_404(db, asset_id, org)

    row = (
        db.query(AssetTag)
        .filter(AssetTag.asset_id == asset_id, AssetTag.tag == tag)
        .first()
    )
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
    body: NoteBody,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("assets", "update")),
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


# ── AMT Inventory Import & Coverage Stats ───────────────────────────────────


def resolve_duplicate_amt_record(old_item: dict, new_item: dict) -> dict:
    """
    Decide which of the two duplicate AMT records to keep.
    Prefers:
    1. Active status over inactive/undeployed/ready to deploy.
    2. Non-empty asset_user over empty/null.
    3. Larger/newer asset_tag sequence.
    """

    def status_score(status_str: str) -> int:
        if not status_str:
            return 0
        s = status_str.lower()
        if any(w in s for w in ("in use", "deployed", "active", "in-use")):
            return 2
        if any(w in s for w in ("ready", "deploy", "spare")):
            return 1
        return -1

    score_old = status_score(old_item.get("status"))
    score_new = status_score(new_item.get("status"))

    if score_new > score_old:
        return new_item
    if score_old > score_new:
        return old_item

    # 2. Compare user assignment (prefer having a user assigned)
    user_old = bool(
        old_item.get("asset_user") and str(old_item.get("asset_user")).strip()
    )
    user_new = bool(
        new_item.get("asset_user") and str(new_item.get("asset_user")).strip()
    )

    if user_new and not user_old:
        return new_item
    if user_old and not user_new:
        return old_item

    # 3. Compare asset tag as sequential indicator
    tag_old = str(old_item.get("asset_tag") or "")
    tag_new = str(new_item.get("asset_tag") or "")

    # Extract digits to compare sequentially
    try:
        num_old = int("".join(c for c in tag_old if c.isdigit()))
        num_new = int("".join(c for c in tag_new if c.isdigit()))
        if num_new > num_old:
            return new_item
        if num_old > num_new:
            return old_item
    except ValueError:
        if tag_new > tag_old:
            return new_item

    # Default fallback: keep the new one (last one wins)
    return new_item


@router.post("/import-amt")
def import_amt_inventory(
    file: UploadFile = File(...),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("settings", "update")),
):
    """
    Upload an assets.json file to overwrite organization's AMT inventory reference data
    and trigger an async background reconciliation.
    """
    org = _resolve_org(user, org_id)

    try:
        content = file.file.read()
        data = json.loads(content.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid file format: {exc!s}")

    # Validate JSON structure (must have data array or be a list)
    records = []
    if isinstance(data, dict) and "data" in data:
        records = data["data"]
    elif isinstance(data, list):
        records = data
    else:
        raise HTTPException(
            status_code=400,
            detail="JSON file must be a list of asset records or contain a 'data' array.",
        )

    # 1. Clear out old inventory records for this org
    db.query(AMTInventoryRecord).filter(AMTInventoryRecord.org_id == org).delete()

    from core.utils import normalize_mac

    # 2. Reconcile duplicates and filter unique records using smart heuristics
    unique_records = {}
    for item in records:
        mac1 = normalize_mac(item.get("mac_address_1"))
        if not mac1:
            continue  # primary MAC is required for correlation reference

        if mac1 in unique_records:
            existing = unique_records[mac1]
            chosen = resolve_duplicate_amt_record(existing, item)
            if chosen is item:
                log.info(
                    "Duplicate MAC %s: kept new record (Tag: %s) over old record (Tag: %s) based on heuristics.",
                    mac1,
                    item.get("asset_tag"),
                    existing.get("asset_tag"),
                )
            else:
                log.info(
                    "Duplicate MAC %s: kept old record (Tag: %s) over new record (Tag: %s) based on heuristics.",
                    mac1,
                    existing.get("asset_tag"),
                    item.get("asset_tag"),
                )
            unique_records[mac1] = chosen
        else:
            unique_records[mac1] = item

    # 3. Insert resolved unique records
    inserted_count = 0
    for mac1, item in unique_records.items():
        mac2 = normalize_mac(item.get("mac_address_2"))
        db_record = AMTInventoryRecord(
            org_id=org,
            mac_address_1=mac1,
            mac_address_2=mac2,
            asset_tag=item.get("asset_tag"),
            asset_name=item.get("asset_name"),
            serial=item.get("serial"),
            vendor=item.get("vendor"),
            asset_type=item.get("asset_type"),
            asset_user=item.get("asset_user"),
            emp_id=item.get("emp_id"),
            status=item.get("status"),
            location=item.get("location"),
            location_id=item.get("location_id"),
            company_name=item.get("company_name"),
        )
        db.add(db_record)
        inserted_count += 1

    db.commit()

    # 4. Dispatch background task for reconciliation
    from core.tasks import reconcile_amt_inventory_task

    task = reconcile_amt_inventory_task.delay(org_id=org)

    # 5. Audit Log
    log_audit_event(
        db=db,
        user=user,
        action="amt_inventory_imported",
        resource_type="asset",
        resource_id=org,
        status="success",
    )

    return {"success": True, "records_imported": inserted_count, "task_id": task.id}
