"""
core/findings/reads.py
─────────────────────────────────────────────────────────────────────────────
What the asset registry's API reads from the findings tables (G6, C7 of
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

``routers/assets.py`` shows an asset's services, its TLS and HTTP details and
its findings, counts each asset's open services, and lists the estate's
services and certificates. It used to query ``services``, ``tls_details`` and
``asset_vulnerabilities`` through the findings models; it asks here now, and
gets plain values back. The queries and the rows they make are moved
unchanged.

The estate-wide listings scope by organisation and show each row's host, so
they join hosts through the findings side's port, ``core.findings.hosts``, as
every other findings query does: the findings capability imports no asset
model.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from core.findings.hosts import hosts
from core.vuln_intel import compute_priority
from db.models.findings import (
    OBSERVED_SERVICE_STATES,
    AssetVulnerability,
    Service,
    TLSDetail,
)
from sqlalchemy import String, func, or_
from sqlalchemy.orm import Session, joinedload

__all__ = [
    "asset_findings",
    "asset_services",
    "certificate_inventory",
    "open_service_counts",
    "service_hosts",
    "service_inventory",
]


def open_service_counts(db: Session, asset_ids: Sequence[str]) -> Dict[str, int]:
    """Open services per asset, in one grouped query."""
    rows = (
        db.query(Service.asset_id, func.count(Service.id))
        .filter(Service.asset_id.in_(asset_ids), Service.state == "open")
        .group_by(Service.asset_id)
        .all()
    )
    return {aid: int(n) for aid, n in rows}


def certificate_inventory(
    db: Session,
    org: str,
    *,
    search: Optional[str],
    sort_by: str,
    sort_dir: str,
    skip: int,
    limit: int,
) -> Tuple[int, List[Dict[str, Any]]]:
    """Every TLS endpoint in the organisation, and how many there are."""
    host = hosts()

    # Base query joining TLSDetail, Service, and the host to enforce org-level isolation
    # The ON clause is named: inferred, it would be re-inferred once the host
    # columns are added below, against two candidate left sides.
    q = (
        db.query(TLSDetail)
        .join(Service, TLSDetail.service_id == Service.id)
        .join(host, Service.asset_id == host.c.id)
        .filter(host.c.org_id == org)
    )

    if search:
        search_filter = or_(
            TLSDetail.grade.ilike(f"%{search}%"),
            TLSDetail.protocol_version.ilike(f"%{search}%"),
            TLSDetail.cipher_suite.ilike(f"%{search}%"),
            func.cast(Service.port, String).ilike(f"%{search}%"),
            host.c.hostname.ilike(f"%{search}%"),
            func.cast(host.c.ip_address, String).ilike(f"%{search}%"),
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
        "ip_address": host.c.ip_address,
        "hostname": host.c.hostname,
    }
    sort_col = col_map.get(sort_by, TLSDetail.cert_not_after)
    q = q.order_by(sort_col.desc() if sort_dir == "desc" else sort_col.asc())

    certs = (
        q.add_columns(host.c.ip_address, host.c.hostname)
        .options(joinedload(TLSDetail.service))
        .offset(skip)
        .limit(limit)
        .all()
    )

    result = []
    for c, host_ip, host_name in certs:
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
                # The host is inner-joined, so a row with a service has one.
                "asset_ip": str(host_ip) if c.service else None,
                "asset_hostname": host_name if c.service else None,
            }
        )
    return total, result


def service_inventory(
    db: Session,
    org: str,
    *,
    search: Optional[str],
    port: Optional[int],
    protocol: Optional[str],
    asset_type: Optional[str],
    subnet: Optional[str],
    sort_by: str,
    sort_dir: str,
    skip: int,
    limit: int,
) -> Tuple[int, List[Dict[str, Any]]]:
    """The organisation's observed services, one row per name, port and
    protocol, and how many such rows there are."""
    host = hosts()

    service_name_expr = func.coalesce(func.nullif(Service.service_name, ""), "unknown")

    # Base query joining Service and the host to enforce org-level isolation and support filters
    q = (
        db.query(
            service_name_expr.label("service_name"),
            Service.port.label("port"),
            Service.protocol.label("protocol"),
            func.count(func.distinct(Service.asset_id)).label("asset_count"),
            func.max(Service.updated_at).label("last_seen"),
        )
        .join(host, Service.asset_id == host.c.id)
        .filter(host.c.org_id == org, Service.state.in_(OBSERVED_SERVICE_STATES))
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
        q = q.filter(host.c.device_category.ilike(f"%{asset_type}%"))
    if subnet:
        q = q.filter(host.c.subnet.ilike(f"%{subnet}%"))

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

    return total, [
        {
            "service_name": rec.service_name,
            "port": rec.port,
            "protocol": rec.protocol,
            "asset_count": rec.asset_count,
            "last_seen": rec.last_seen.isoformat() if rec.last_seen else None,
        }
        for rec in records
    ]


def service_hosts(
    db: Session,
    org: str,
    *,
    service_name: str,
    port: int,
    protocol: str,
    search: Optional[str],
    skip: int,
    limit: int,
) -> Tuple[int, List[Dict[str, Any]]]:
    """The organisation's hosts running one service-port-protocol signature,
    and how many there are."""
    host = hosts()

    q = (
        db.query(Service)
        .join(host, Service.asset_id == host.c.id)
        .filter(
            host.c.org_id == org,
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
            host.c.hostname.ilike(f"%{search}%"),
            func.cast(host.c.ip_address, String).ilike(f"%{search}%"),
        )
        q = q.filter(search_filter)

    total = q.count()

    services = (
        q.add_columns(host.c.hostname, host.c.ip_address, host.c.device_category)
        .offset(skip)
        .limit(limit)
        .all()
    )

    result = []
    for svc, host_name, host_ip, host_category in services:
        result.append(
            {
                "asset_id": svc.asset_id,
                "asset_hostname": host_name or "—",
                "asset_ip": str(host_ip) if host_ip else "—",
                "asset_type": host_category or "—",
                "state": svc.state,
                "service_version": svc.service_version or "—",
                "service_product": svc.service_product or "—",
                "last_scan_time": (
                    svc.updated_at.isoformat() if svc.updated_at else None
                ),
            }
        )
    return total, result


def asset_services(db: Session, asset_id: str) -> List[Dict[str, Any]]:
    """An asset's services, by port, with their TLS and HTTP details."""
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
    return result


def asset_findings(
    db: Session, asset_id: str, status: Optional[str]
) -> List[Dict[str, Any]]:
    """An asset's findings, highest priority first; ``status`` is a
    comma-separated filter."""
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
    return result
