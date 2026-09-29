"""
routers/dashboard.py
─────────────────────────────────────────────────────────────────────────────
Security Dashboard aggregated analytics endpoints.
All queries are org-scoped. Superadmin can pass ?org_id= to view any org.

All imports verified against actual codebase files:
  - auth/rbac.py        → require_permission(resource, action)
  - db/base.py          → get_db, utcnow
  - db/models/*.py      → exact model + field names
  - core/vuln_intel.py  → compute_priority(cvss_score, epss_score, in_kev, has_exploit)
  - core/quota.py       → displayed_scan_limits → (plan, max_day, max_concurrent)

VulnerabilityDefinition NOTE:
  This model has NO epss_score, in_kev, has_exploit, cvss_v3_vector columns.
  It has: cvss_v3_score, cvss_v2_score, cvss_vector, severity, cwe_ids, references,
          published_at, title, description, source, is_custom, affected_software.
  Priority is computed passing 0/False for missing fields (safe default).
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from auth.rbac import require_permission
from core.vuln_intel import compute_priority
from db.base import get_db, utcnow
from db.models import User
from db.models.assets import Asset, AssetChangeLog
from db.models.findings import (
    OBSERVED_SERVICE_STATES,
    AssetVulnerability,
    HttpSecurityDetail,
    Service,
    TLSDetail,
    VulnerabilityDefinition,
)
from db.models.scans import Scan
from fastapi import APIRouter, Depends, Query
from scans.cvss import canonical_severity, display_severity
from sqlalchemy import case, func
from sqlalchemy.orm import Session

log = logging.getLogger("ccure.dashboard")
router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


# ── Helpers ───────────────────────────────────────────────────────────────────


def _is_superadmin(user: User) -> bool:
    return (
        getattr(getattr(user, "role", None), "name", "") or ""
    ).lower() == "superadmin"


def _resolve_org(user: User, requested_org: str | None) -> str:
    if _is_superadmin(user) and requested_org:
        return requested_org
    return str(user.org_id)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── 1. Summary Cards ──────────────────────────────────────────────────────────


@router.get("/summary")
def get_dashboard_summary(
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("dashboard", "read")),
):
    """
    8 top metric cards. Data sources:
      severity counts  → AssetVulnerability JOIN VulnerabilityDefinition WHERE status='open'
      asset stats      → Asset table aggregates
      scan counts      → Scan table with 24h rolling window
      kev count        → VulnerabilityDefinition.source = 'kev' proxy
                         (no in_kev column exists — use source field instead)
      quota            → core/quota._limits(plan)
    """
    org = _resolve_org(user, org_id)
    now = _now()
    w24h = now - timedelta(hours=24)
    w7d = now - timedelta(days=7)

    # ── Severity counts ────────────────────────────────────────────────────────
    # Counted from the finding's own severity, grouped case-insensitively.
    #
    # This previously grouped on VulnerabilityDefinition.severity — a column
    # holding both "critical" and "Critical" — and then built
    # `{row.severity.lower(): row.count}`. The two spellings arrived as separate
    # rows and the comprehension collapsed them onto one key, so whichever the
    # driver yielded last silently replaced the other. The dashboard reported 46
    # of 146 findings and 1 of 9 criticals while every other surface in the
    # product reported the true figures.
    #
    # Grouping on the folded value makes the collapse happen in SQL, where the
    # counts are summed rather than overwritten. The CHECK constraint added in
    # z9e0f1g2h3i4 stops the mixed spellings recurring; this is the second line
    # of defence, and the one that keeps old rows correct.
    sev_expr = func.lower(AssetVulnerability.severity)
    sev_rows = (
        db.query(
            sev_expr.label("severity"), func.count(AssetVulnerability.id).label("cnt")
        )
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(Asset.org_id == org, AssetVulnerability.status == "open")
        .group_by(sev_expr)
        .all()
    )
    sev_map: dict[str, int] = {}
    for r in sev_rows:
        sev_map[canonical_severity(r.severity)] = (
            sev_map.get(canonical_severity(r.severity), 0) + r.cnt
        )
    critical = sev_map.get("critical", 0)
    high = sev_map.get("high", 0)
    medium = sev_map.get("medium", 0)
    low = sev_map.get("low", 0)
    info = sev_map.get("none", 0)
    # A CVE the feed publishes no score for is still a finding on this host.
    # Leaving it out of the total made the dashboard read one lower than
    # GET /findings for the same rows — the same "totals that disagree" defect
    # this endpoint already carried once, in miniature.
    unscored = sev_map.get("unscored", 0)

    # ── Calculate Deltas from last scan ───────────────────────────────────────
    last_scans = (
        db.query(Scan)
        .filter(
            Scan.org_id == org,
            Scan.status.in_(["complete", "completed"]),
            Scan.is_deleted == False,
        )
        .order_by(Scan.completed_at.desc())
        .limit(2)
        .all()
    )

    sev_deltas = {"critical": 0, "high": 0, "medium": 0, "low_info": 0}
    if len(last_scans) >= 2:
        s1, s2 = last_scans[0], last_scans[1]
        sev_deltas["critical"] = (s1.critical_count or 0) - (s2.critical_count or 0)
        sev_deltas["high"] = (s1.high_count or 0) - (s2.high_count or 0)
        sev_deltas["medium"] = (s1.medium_count or 0) - (s2.medium_count or 0)
        sev_deltas["low_info"] = ((s1.low_count or 0) + (s1.info_count or 0)) - (
            (s2.low_count or 0) + (s2.info_count or 0)
        )
    elif len(last_scans) == 1:
        s1 = last_scans[0]
        sev_deltas["critical"] = s1.critical_count or 0
        sev_deltas["high"] = s1.high_count or 0
        sev_deltas["medium"] = s1.medium_count or 0
        sev_deltas["low_info"] = (s1.low_count or 0) + (s1.info_count or 0)

    # ── Asset stats ────────────────────────────────────────────────────────────
    ast_row = (
        db.query(
            func.count(Asset.id).label("total"),
            func.count(case((Asset.is_managed == False, 1))).label("unmanaged"),
            func.count(case((Asset.first_seen_at >= w7d, 1))).label("new_7d"),
            func.count(case((Asset.first_seen_at >= w24h, 1))).label("new_24h"),
            func.avg(Asset.risk_score).label("avg_risk"),
        )
        .filter(Asset.org_id == org)
        .one()
    )

    # Calculate risk delta (approximate: current avg vs avg of assets older than 7d)
    old_avg_risk = (
        db.query(func.avg(Asset.risk_score))
        .filter(Asset.org_id == org, Asset.first_seen_at < w7d)
        .scalar()
        or ast_row.avg_risk
        or 0
    )
    risk_delta_7d = round(float(ast_row.avg_risk or 0) - float(old_avg_risk), 1)

    # ── Scan stats ─────────────────────────────────────────────────────────────
    scans_24h = (
        db.query(func.count(Scan.id))
        .filter(Scan.org_id == org, Scan.queued_at >= w24h, Scan.is_deleted == False)
        .scalar()
        or 0
    )
    running = (
        db.query(func.count(Scan.id))
        .filter(Scan.org_id == org, Scan.status == "running", Scan.is_deleted == False)
        .scalar()
        or 0
    )
    queued = (
        db.query(func.count(Scan.id))
        .filter(Scan.org_id == org, Scan.status == "queued", Scan.is_deleted == False)
        .scalar()
        or 0
    )

    # ── Known-exploited count ────────────────────────────────────────────────
    # Read from the finding's own in_kev flag, set during the scan from the
    # CISA catalogue. The previous proxy — VulnerabilityDefinition.source ==
    # 'kev' — matched nothing, because the catalogue is populated with
    # source 'nvd', 'scanner' or 'credentialed' and never 'kev'. The dashboard
    # therefore reported zero known-exploited vulnerabilities while the
    # executive PDF, reading the same scan, named three.
    kev_count = (
        db.query(func.count(AssetVulnerability.id))
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(
            Asset.org_id == org,
            AssetVulnerability.status == "open",
            AssetVulnerability.in_kev.is_(True),
        )
        .scalar()
        or 0
    )

    # ── Quota ─────────────────────────────────────────────────────────────────
    # The plan's own figures (core.quota, the seam of the scan-limits plan
    # feature). The docstring above is the OpenAPI description and still names
    # the helper this replaced; it is left as it was.
    from core.quota import displayed_scan_limits

    plan, max_day, max_conc = displayed_scan_limits(db, org)

    avg_risk = round(float(ast_row.avg_risk or 0), 1)
    risk_level = (
        "CRITICAL"
        if avg_risk >= 75
        else (
            "HIGH"
            if avg_risk >= 50
            else "MEDIUM" if avg_risk >= 25 else "LOW" if avg_risk > 0 else "INFO"
        )
    )

    return {
        "severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
            "unscored": unscored,
            "total": critical + high + medium + low + info + unscored,
            "deltas": sev_deltas,
        },
        "assets": {
            "total": ast_row.total or 0,
            "unmanaged": ast_row.unmanaged or 0,
            "new_7d": ast_row.new_7d or 0,
            "new_24h": ast_row.new_24h or 0,
            "avg_risk_score": avg_risk,
            "risk_level": risk_level,
            "risk_delta_7d": risk_delta_7d,
        },
        "scans": {
            "last_24h": scans_24h,
            "running": running,
            "queued": queued,
            "quota_limit_24h": max_day,
            "quota_used_pct": round(scans_24h / max_day * 100, 1) if max_day else 0,
        },
        "kev": {"open_count": kev_count},
        "plan": plan,
        "org_id": org,
    }


# ── 2. Risk Breakdown ─────────────────────────────────────────────────────────


@router.get("/risk-breakdown")
def get_risk_breakdown(
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("dashboard", "read")),
):
    org = _resolve_org(user, org_id)

    # Asset risk level distribution
    level_rows = (
        db.query(Asset.risk_level, func.count(Asset.id).label("cnt"))
        .filter(Asset.org_id == org)
        .group_by(Asset.risk_level)
        .all()
    )
    level_map = {(r.risk_level or "info").lower(): r.cnt for r in level_rows}

    avg_risk = (
        db.query(func.avg(Asset.risk_score)).filter(Asset.org_id == org).scalar() or 0.0
    )

    # Priority distribution, from the per-finding scan data.
    p0 = (
        db.query(func.count(AssetVulnerability.id))
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(
            Asset.org_id == org,
            AssetVulnerability.status == "open",
            AssetVulnerability.in_kev.is_(True),
        )
        .scalar()
        or 0
    )
    p2 = (
        db.query(func.count(AssetVulnerability.id))
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(
            Asset.org_id == org,
            AssetVulnerability.status == "open",
            AssetVulnerability.cvss_score >= 9.0,
        )
        .scalar()
        or 0
    )

    # TLS issues
    tls_row = (
        db.query(
            func.count(case((TLSDetail.cert_not_after < utcnow(), 1))).label("expired"),
            func.count(case((TLSDetail.cert_is_self_signed == True, 1))).label(
                "self_signed"
            ),
            func.count(case((TLSDetail.is_weak_cipher == True, 1))).label(
                "weak_cipher"
            ),
            func.count(case((TLSDetail.grade == "F", 1))).label("grade_f"),
        )
        .join(Service, TLSDetail.service_id == Service.id)
        .join(Asset, Service.asset_id == Asset.id)
        .filter(Asset.org_id == org, TLSDetail.is_enabled == True)
        .one()
    )

    # HTTP avg score
    http_avg = (
        db.query(func.avg(HttpSecurityDetail.security_score))
        .join(Service, HttpSecurityDetail.service_id == Service.id)
        .join(Asset, Service.asset_id == Asset.id)
        .filter(Asset.org_id == org)
        .scalar()
        or 0
    )

    # Finding status breakdown
    status_rows = (
        db.query(
            AssetVulnerability.status, func.count(AssetVulnerability.id).label("cnt")
        )
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(Asset.org_id == org)
        .group_by(AssetVulnerability.status)
        .all()
    )
    status_map = {r.status: r.cnt for r in status_rows}

    return {
        "org_risk_score": round(float(avg_risk), 1),
        "risk_level_distribution": {
            "critical": level_map.get("critical", 0),
            "high": level_map.get("high", 0),
            "medium": level_map.get("medium", 0),
            "low": level_map.get("low", 0),
            "info": level_map.get("info", 0),
        },
        "priority_distribution": {
            "p0_kev": p0,
            "p2_cvss_9": p2,
        },
        "tls_issues": {
            "expired_certs": tls_row.expired or 0,
            "self_signed": tls_row.self_signed or 0,
            "weak_ciphers": tls_row.weak_cipher or 0,
            "grade_f": tls_row.grade_f or 0,
        },
        "http_avg_security_score": round(float(http_avg), 1),
        "finding_status": {
            "open": status_map.get("open", 0),
            "accepted": status_map.get("accepted", 0),
            "fixed": status_map.get("fixed", 0),
        },
    }


# ── 3. Vuln Trends (30-day chart) ─────────────────────────────────────────────


@router.get("/vuln-trends")
def get_vuln_trends(
    days: int = Query(30, ge=7, le=90),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("dashboard", "read")),
):
    org = _resolve_org(user, org_id)
    since = _now() - timedelta(days=days)

    rows = (
        db.query(
            Scan.completed_at,
            Scan.critical_count,
            Scan.high_count,
            Scan.medium_count,
            Scan.low_count,
        )
        .filter(
            Scan.org_id == org,
            Scan.completed_at >= since,
            Scan.status.in_(["complete", "completed"]),
            Scan.is_deleted == False,
        )
        .order_by(Scan.completed_at.asc())
        .all()
    )

    daily: dict = {}
    for r in rows:
        if not r.completed_at:
            continue
        k = r.completed_at.strftime("%Y-%m-%d")
        if k not in daily:
            daily[k] = {
                "date": k,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "scans": 0,
            }
        daily[k]["critical"] += r.critical_count or 0
        daily[k]["high"] += r.high_count or 0
        daily[k]["medium"] += r.medium_count or 0
        daily[k]["low"] += r.low_count or 0
        daily[k]["scans"] += 1

    return {"days": days, "data": sorted(daily.values(), key=lambda x: x["date"])}


# ── 4. Top Assets ─────────────────────────────────────────────────────────────


@router.get("/top-assets")
def get_top_assets(
    limit: int = Query(10, ge=1, le=50),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("dashboard", "read")),
):
    org = _resolve_org(user, org_id)
    assets = (
        db.query(Asset)
        .filter(Asset.org_id == org, Asset.is_active == True)
        .order_by(Asset.risk_score.desc())
        .limit(limit)
        .all()
    )

    result = []
    for a in assets:
        vc = a.vuln_counts or {}
        result.append(
            {
                "id": a.id,
                "ip_address": str(a.ip_address),
                "hostname": a.hostname,
                "fqdn": a.fqdn,
                "os_name": a.os_name,
                "os_family": a.os_family,
                "device_category": a.device_category,
                "risk_score": a.risk_score,
                "risk_level": a.risk_level,
                "is_managed": a.is_managed,
                "vuln_counts": {
                    "critical": vc.get("critical", vc.get("Critical", 0)),
                    "high": vc.get("high", vc.get("High", 0)),
                    "medium": vc.get("medium", vc.get("Medium", 0)),
                    "low": vc.get("low", vc.get("Low", 0)),
                },
                "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
            }
        )
    return {"assets": result}


# ── 5. Top CVEs ───────────────────────────────────────────────────────────────


@router.get("/top-cves")
def get_top_cves(
    limit: int = Query(10, ge=1, le=50),
    severity: str | None = Query(None),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("dashboard", "read")),
):
    org = _resolve_org(user, org_id)

    # Aggregated from the findings, so severity, score and exploit intelligence
    # are the values measured against these hosts rather than the catalogue's
    # shared defaults.
    q = (
        db.query(
            VulnerabilityDefinition,
            func.count(AssetVulnerability.asset_id.distinct()).label("affected_assets"),
            func.max(AssetVulnerability.cvss_score).label("cvss"),
            func.max(func.lower(AssetVulnerability.severity)).label("severity"),
            func.bool_or(AssetVulnerability.in_kev).label("in_kev"),
            func.bool_or(AssetVulnerability.has_exploit).label("has_exploit"),
            func.max(AssetVulnerability.epss_score).label("epss"),
        )
        .join(
            AssetVulnerability, AssetVulnerability.vuln_id == VulnerabilityDefinition.id
        )
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(Asset.org_id == org, AssetVulnerability.status == "open")
        .group_by(VulnerabilityDefinition.id)
    )

    if severity:
        sev_list = [canonical_severity(s) for s in severity.split(",") if s.strip()]
        if sev_list:
            q = q.filter(func.lower(AssetVulnerability.severity).in_(sev_list))

    rows = (
        q.order_by(
            func.max(AssetVulnerability.cvss_score).desc().nullslast(),
            func.count(AssetVulnerability.asset_id.distinct()).desc(),
        )
        .limit(limit)
        .all()
    )

    result = []
    for vuln, affected, cvss, sev, is_kev, has_exploit, epss in rows:
        ps, pl = compute_priority(
            cvss_score=float(cvss or 0),
            epss_score=float(epss or 0),
            in_kev=bool(is_kev),
            has_exploit=bool(has_exploit),
        )
        result.append(
            {
                "id": vuln.id,
                "title": vuln.title,
                "severity": display_severity(sev),
                "cvss_v3_score": float(cvss or 0),
                "cvss_version": vuln.cvss_version,
                "epss_score": float(epss or 0),
                "in_kev": bool(is_kev),
                "has_exploit": bool(has_exploit),
                "priority_score": ps,
                "priority_label": pl,
                "affected_assets": affected,
                "cwe_ids": vuln.cwe_ids or [],
            }
        )

    return {"cves": result}


# ── 6. Service Exposure ───────────────────────────────────────────────────────


@router.get("/services-exposure")
def get_services_exposure(
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("dashboard", "read")),
):
    org = _resolve_org(user, org_id)
    HIGH_RISK_PORTS = {21, 23, 69, 110, 111, 139, 445, 512, 513, 514, 3389, 5900, 5985}

    rows = (
        db.query(
            Service.port,
            Service.protocol,
            Service.service_name,
            func.count(Service.asset_id.distinct()).label("asset_count"),
        )
        .join(Asset, Service.asset_id == Asset.id)
        .filter(Asset.org_id == org, Service.state.in_(OBSERVED_SERVICE_STATES))
        .group_by(Service.port, Service.protocol, Service.service_name)
        .order_by(func.count(Service.asset_id.distinct()).desc())
        .limit(20)
        .all()
    )

    return {
        "services": [
            {
                "port": r.port,
                "protocol": r.protocol,
                "service_name": r.service_name,
                "asset_count": r.asset_count,
                "is_high_risk": r.port in HIGH_RISK_PORTS,
            }
            for r in rows
        ]
    }


# ── 7. TLS Health ─────────────────────────────────────────────────────────────


@router.get("/tls-health")
def get_tls_health(
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("dashboard", "read")),
):
    org = _resolve_org(user, org_id)
    now = _now()
    in_30d = now + timedelta(days=30)

    grade_rows = (
        db.query(TLSDetail.grade, func.count(TLSDetail.id).label("cnt"))
        .join(Service, TLSDetail.service_id == Service.id)
        .join(Asset, Service.asset_id == Asset.id)
        .filter(Asset.org_id == org, TLSDetail.is_enabled == True)
        .group_by(TLSDetail.grade)
        .all()
    )

    expiring = (
        db.query(func.count(TLSDetail.id))
        .join(Service, TLSDetail.service_id == Service.id)
        .join(Asset, Service.asset_id == Asset.id)
        .filter(
            Asset.org_id == org,
            TLSDetail.is_enabled == True,
            TLSDetail.cert_not_after <= in_30d,
            TLSDetail.cert_not_after >= now,
        )
        .scalar()
        or 0
    )

    total = (
        db.query(func.count(TLSDetail.id))
        .join(Service, TLSDetail.service_id == Service.id)
        .join(Asset, Service.asset_id == Asset.id)
        .filter(Asset.org_id == org, TLSDetail.is_enabled == True)
        .scalar()
        or 0
    )

    grade_map = {r.grade: r.cnt for r in grade_rows}

    return {
        "total_tls_services": total,
        "expiring_in_30d": expiring,
        "grade_distribution": {
            "A": grade_map.get("A", 0),
            "B": grade_map.get("B", 0),
            "C": grade_map.get("C", 0),
            "D": grade_map.get("D", 0),
            "F": grade_map.get("F", 0),
        },
    }


# ── 8. HTTP Headers ───────────────────────────────────────────────────────────


@router.get("/http-headers")
def get_http_headers(
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("dashboard", "read")),
):
    org = _resolve_org(user, org_id)

    agg = (
        db.query(
            func.count(HttpSecurityDetail.id).label("total"),
            func.count(case((HttpSecurityDetail.has_hsts == True, 1))).label("hsts"),
            func.count(case((HttpSecurityDetail.has_csp == True, 1))).label("csp"),
            func.count(case((HttpSecurityDetail.x_content_type == True, 1))).label(
                "x_content_type"
            ),
            func.count(case((HttpSecurityDetail.x_frame_options != None, 1))).label(
                "x_frame"
            ),
            func.count(case((HttpSecurityDetail.referrer_policy != None, 1))).label(
                "referrer_policy"
            ),
            func.avg(HttpSecurityDetail.security_score).label("avg_score"),
        )
        .join(Service, HttpSecurityDetail.service_id == Service.id)
        .join(Asset, Service.asset_id == Asset.id)
        .filter(Asset.org_id == org)
        .one()
    )

    total = agg.total or 1

    def pct(n):
        return round((n or 0) / total * 100, 1)

    return {
        "total_http_services": agg.total or 0,
        "avg_security_score": round(float(agg.avg_score or 0), 1),
        "coverage": {
            "hsts": {"count": agg.hsts or 0, "pct": pct(agg.hsts)},
            "csp": {"count": agg.csp or 0, "pct": pct(agg.csp)},
            "x_content_type": {
                "count": agg.x_content_type or 0,
                "pct": pct(agg.x_content_type),
            },
            "x_frame": {"count": agg.x_frame or 0, "pct": pct(agg.x_frame)},
            "referrer_policy": {
                "count": agg.referrer_policy or 0,
                "pct": pct(agg.referrer_policy),
            },
        },
    }


# ── 9. Compliance Posture ─────────────────────────────────────────────────────


@router.get("/compliance")
def get_compliance(
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("dashboard", "read")),
):
    org = _resolve_org(user, org_id)

    total_assets = (
        db.query(func.count(Asset.id)).filter(Asset.org_id == org).scalar() or 1
    )
    scanned_assets = (
        db.query(func.count(Asset.id))
        .filter(Asset.org_id == org, Asset.last_scan_id != None)
        .scalar()
        or 0
    )
    open_critical = (
        db.query(func.count(AssetVulnerability.id))
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .join(
            VulnerabilityDefinition,
            AssetVulnerability.vuln_id == VulnerabilityDefinition.id,
        )
        .filter(
            Asset.org_id == org,
            AssetVulnerability.status == "open",
            func.lower(AssetVulnerability.severity) == "critical",
        )
        .scalar()
        or 0
    )
    cleartext_svcs = (
        db.query(func.count(Service.id.distinct()))
        .join(Asset, Service.asset_id == Asset.id)
        .filter(
            Asset.org_id == org,
            Service.port.in_([21, 23, 80, 110, 143]),
            Service.state.in_(OBSERVED_SERVICE_STATES),
        )
        .scalar()
        or 0
    )
    fixed_findings = (
        db.query(func.count(AssetVulnerability.id))
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(Asset.org_id == org, AssetVulnerability.status == "fixed")
        .scalar()
        or 0
    )
    total_findings = (
        db.query(func.count(AssetVulnerability.id))
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(Asset.org_id == org)
        .scalar()
        or 1
    )

    coverage_rate = round(scanned_assets / total_assets * 100, 1)
    remediation_rate = round(fixed_findings / total_findings * 100, 1)
    no_cleartext_pct = max(
        0.0, 100 - round(cleartext_svcs / max(total_assets, 1) * 50, 1)
    )
    no_critical_pct = max(0.0, 100 - min(open_critical * 15, 80))

    def clamp(v):
        return max(0.0, min(100.0, float(v)))

    soc2 = clamp(coverage_rate * 0.4 + remediation_rate * 0.3 + no_critical_pct * 0.3)
    iso27001 = clamp(
        coverage_rate * 0.35 + remediation_rate * 0.35 + no_cleartext_pct * 0.3
    )
    pci = clamp(no_cleartext_pct * 0.4 + no_critical_pct * 0.4 + remediation_rate * 0.2)
    hipaa = clamp(coverage_rate * 0.5 + remediation_rate * 0.3 + no_critical_pct * 0.2)
    nist = clamp(
        coverage_rate * 0.3
        + remediation_rate * 0.3
        + no_critical_pct * 0.2
        + no_cleartext_pct * 0.2
    )
    dpdp = clamp(coverage_rate * 0.35 + remediation_rate * 0.35 + no_critical_pct * 0.3)
    gdpr = clamp(coverage_rate * 0.3 + remediation_rate * 0.4 + no_critical_pct * 0.3)
    cis = clamp(coverage_rate * 0.35 + remediation_rate * 0.35 + no_cleartext_pct * 0.3)
    iec = clamp(coverage_rate * 0.3 + remediation_rate * 0.4 + no_critical_pct * 0.3)
    nist82 = clamp(
        coverage_rate * 0.35 + remediation_rate * 0.35 + no_critical_pct * 0.3
    )
    nerc_cip = clamp(
        coverage_rate * 0.3 + remediation_rate * 0.4 + no_critical_pct * 0.3
    )
    nis2 = clamp(coverage_rate * 0.3 + remediation_rate * 0.4 + no_critical_pct * 0.3)

    return {
        "frameworks": [
            {
                "id": "soc2",
                "name": "SOC 2 Type II",
                "score": round(soc2, 1),
                "color": "#22c55e",
            },
            {
                "id": "iso27001",
                "name": "ISO 27001",
                "score": round(iso27001, 1),
                "color": "#3b82f6",
            },
            {
                "id": "pci",
                "name": "PCI-DSS 4.0",
                "score": round(pci, 1),
                "color": "#f97316",
            },
            {
                "id": "dpdp_2023",
                "name": "DPDP Act 2023",
                "score": round(dpdp, 1),
                "color": "#d97706",
            },
            {
                "id": "gdpr",
                "name": "EU GDPR",
                "score": round(gdpr, 1),
                "color": "#1d4ed8",
            },
            {
                "id": "hipaa",
                "name": "HIPAA",
                "score": round(hipaa, 1),
                "color": "#a855f7",
            },
            {
                "id": "nist",
                "name": "NIST CSF",
                "score": round(nist, 1),
                "color": "#14b8a6",
            },
            {
                "id": "cis",
                "name": "CIS Benchmark",
                "score": round(cis, 1),
                "color": "#eab308",
            },
            {
                "id": "iec_62443",
                "name": "IEC 62443 (OT/ICS)",
                "score": round(iec, 1),
                "color": "#f43f5e",
            },
            {
                "id": "nist_800_82",
                "name": "NIST SP 800-82 R3 (OT)",
                "score": round(nist82, 1),
                "color": "#2563eb",
            },
            {
                "id": "nerc_cip",
                "name": "NERC CIP (Power Grid)",
                "score": round(nerc_cip, 1),
                "color": "#0284c7",
            },
            {
                "id": "nis2",
                "name": "EU NIS 2 Directive",
                "score": round(nis2, 1),
                "color": "#7c3aed",
            },
        ],
    }


# ── 10. Asset Breakdown ───────────────────────────────────────────────────────


@router.get("/asset-breakdown")
def get_asset_breakdown(
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("dashboard", "read")),
):
    org = _resolve_org(user, org_id)

    os_rows = (
        db.query(Asset.os_family, func.count(Asset.id).label("cnt"))
        .filter(Asset.org_id == org)
        .group_by(Asset.os_family)
        .all()
    )
    cat_rows = (
        db.query(Asset.device_category, func.count(Asset.id).label("cnt"))
        .filter(Asset.org_id == org)
        .group_by(Asset.device_category)
        .all()
    )
    totals = (
        db.query(
            func.count(Asset.id).label("total"),
            func.count(case((Asset.is_managed == True, 1))).label("managed"),
            func.count(case((Asset.is_managed == False, 1))).label("unmanaged"),
            func.count(case((Asset.is_active == True, 1))).label("active"),
            func.count(case((Asset.is_active == False, 1))).label("offline"),
        )
        .filter(Asset.org_id == org)
        .one()
    )

    return {
        "totals": {
            "total": totals.total or 0,
            "managed": totals.managed or 0,
            "unmanaged": totals.unmanaged or 0,
            "active": totals.active or 0,
            "offline": totals.offline or 0,
        },
        "os_distribution": [
            {"os_family": r.os_family or "Unknown", "count": r.cnt} for r in os_rows
        ],
        "category_distribution": [
            {"category": r.device_category or "Unknown", "count": r.cnt}
            for r in cat_rows
        ],
    }


# ── 11. Scan Activity ─────────────────────────────────────────────────────────


@router.get("/scan-activity")
def get_scan_activity(
    limit: int = Query(8, ge=1, le=20),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("dashboard", "read")),
):
    org = _resolve_org(user, org_id)

    scans = (
        db.query(Scan)
        .filter(Scan.org_id == org, Scan.is_deleted == False)
        .order_by(Scan.queued_at.desc())
        .limit(limit)
        .all()
    )

    result = []
    for s in scans:
        phases = sorted(
            getattr(s, "phases", []) or [], key=lambda p: p.phase_order or 0
        )
        current_phase = None
        progress_pct = 0
        for ph in phases:
            if ph.status == "running":
                current_phase = ph.phase_key
                ph_sum = ph.summary or {}
                processed = ph_sum.get("hosts_processed", ph_sum.get("active_hosts", 0))
                total = s.total_hosts or 1
                progress_pct = (
                    round(min(processed / total * 100, 99), 0) if total else 0
                )
                break

        result.append(
            {
                "id": s.id,
                "scan_name": s.scan_name,
                "target_str": s.target_str,
                "scan_type": s.scan_type,
                "pipeline_mode": s.pipeline_mode,
                "intensity": s.intensity,
                "status": s.status,
                "total_hosts": s.total_hosts,
                "active_hosts": s.active_hosts,
                "critical_count": s.critical_count,
                "high_count": s.high_count,
                "current_phase": current_phase,
                "progress_pct": progress_pct,
                "queued_at": s.queued_at.isoformat() if s.queued_at else None,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "duration_seconds": s.duration_seconds,
            }
        )

    return {"scans": result}


# ── 12. Insights ──────────────────────────────────────────────────────────────


@router.get("/insights")
def get_insights(
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("dashboard", "read")),
):
    org = _resolve_org(user, org_id)
    now = _now()
    insights = []

    # 1. Highest-risk subnet
    try:
        sub = (
            db.query(Asset.subnet, func.avg(Asset.risk_score).label("avg_r"))
            .filter(Asset.org_id == org, Asset.subnet != None)
            .group_by(Asset.subnet)
            .order_by(func.avg(Asset.risk_score).desc())
            .first()
        )
        if sub and sub.avg_r and float(sub.avg_r) >= 50:
            insights.append(
                {
                    "id": "top-subnet",
                    "icon": "🌐",
                    "severity": "high",
                    "title": f"Subnet {sub.subnet} is highest-risk",
                    "detail": f"Average risk score {round(float(sub.avg_r))}/100. Review and segment this network.",
                }
            )
    except Exception:
        pass

    # 2. Stale critical/high findings (>30 days open)
    try:
        stale = (
            db.query(func.count(AssetVulnerability.id))
            .join(Asset, AssetVulnerability.asset_id == Asset.id)
            .join(
                VulnerabilityDefinition,
                AssetVulnerability.vuln_id == VulnerabilityDefinition.id,
            )
            .filter(
                Asset.org_id == org,
                AssetVulnerability.status == "open",
                AssetVulnerability.first_found_at <= now - timedelta(days=30),
                func.lower(AssetVulnerability.severity).in_(["critical", "high"]),
            )
            .scalar()
            or 0
        )
        if stale:
            insights.append(
                {
                    "id": "stale-findings",
                    "icon": "⏰",
                    "severity": "critical",
                    "title": f"{stale} Critical/High findings open for 30+ days",
                    "detail": "Long-open findings signal remediation backlog. Assign ownership and track.",
                }
            )
    except Exception:
        pass

    # 3. New attack surface (ports opened in last 7 days)
    try:
        new_ports = (
            db.query(func.count(AssetChangeLog.id))
            .join(Asset, AssetChangeLog.asset_id == Asset.id)
            .filter(
                Asset.org_id == org,
                AssetChangeLog.change_type == "port_opened",
                AssetChangeLog.detected_at >= now - timedelta(days=7),
            )
            .scalar()
            or 0
        )
        if new_ports:
            insights.append(
                {
                    "id": "new-ports",
                    "icon": "🔓",
                    "severity": "medium",
                    "title": f"{new_ports} new open ports detected this week",
                    "detail": "New services increase attack surface. Review and validate each port.",
                }
            )
    except Exception:
        pass

    # 4. Scan coverage gap (assets not seen in 14+ days)
    try:
        stale_assets = (
            db.query(func.count(Asset.id))
            .filter(
                Asset.org_id == org,
                Asset.last_seen_at < now - timedelta(days=14),
                Asset.is_active == True,
            )
            .scalar()
            or 0
        )
        if stale_assets:
            insights.append(
                {
                    "id": "scan-gap",
                    "icon": "📡",
                    "severity": "medium",
                    "title": f"{stale_assets} assets not scanned in 14+ days",
                    "detail": "Schedule a fresh scan to maintain continuous visibility.",
                }
            )
    except Exception:
        pass

    # 5. Most-recurring high+ CVE
    try:
        top_cve = (
            db.query(
                VulnerabilityDefinition.id,
                VulnerabilityDefinition.title,
                func.count(AssetVulnerability.asset_id.distinct()).label("cnt"),
            )
            .join(
                AssetVulnerability,
                AssetVulnerability.vuln_id == VulnerabilityDefinition.id,
            )
            .join(Asset, AssetVulnerability.asset_id == Asset.id)
            .filter(
                Asset.org_id == org,
                AssetVulnerability.status == "open",
                func.lower(AssetVulnerability.severity).in_(["critical", "high"]),
            )
            .group_by(VulnerabilityDefinition.id, VulnerabilityDefinition.title)
            .order_by(func.count(AssetVulnerability.asset_id.distinct()).desc())
            .first()
        )
        if top_cve and top_cve.cnt >= 2:
            insights.append(
                {
                    "id": "top-cve",
                    "icon": "🔥",
                    "severity": "critical",
                    "title": f"{top_cve.id} affects {top_cve.cnt} assets",
                    "detail": f"{(top_cve.title or '')[:80]} — one patch resolves all instances.",
                }
            )
    except Exception:
        pass

    return {"insights": insights}


# ── 13. Web Scan Summary ──────────────────────────────────────────────────────


@router.get("/web-scan-summary")
def get_web_scan_summary(
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("dashboard", "read")),
):
    """
    Aggregate statistics for web application scans.
    Mirrors the network /summary endpoint but for DAST results.
    """
    from db.models.web_scans import WebAsset, WebFinding, WebScan

    org = _resolve_org(user, org_id)
    now = _now()
    w24h = now - timedelta(hours=24)
    w7d = now - timedelta(days=7)

    # ── Scan counts ────────────────────────────────────────────────────────
    total_scans = (
        db.query(func.count(WebScan.id))
        .filter(WebScan.org_id == org, WebScan.is_deleted == False)
        .scalar()
        or 0
    )
    running_scans = (
        db.query(func.count(WebScan.id))
        .filter(
            WebScan.org_id == org,
            WebScan.status == "running",
            WebScan.is_deleted == False,
        )
        .scalar()
        or 0
    )
    completed_scans = (
        db.query(func.count(WebScan.id))
        .filter(
            WebScan.org_id == org,
            WebScan.status == "complete",
            WebScan.is_deleted == False,
        )
        .scalar()
        or 0
    )
    scans_7d = (
        db.query(func.count(WebScan.id))
        .filter(
            WebScan.org_id == org,
            WebScan.created_at >= w7d,
            WebScan.is_deleted == False,
        )
        .scalar()
        or 0
    )
    w30d = now - timedelta(days=30)
    scans_30d = (
        db.query(func.count(WebScan.id))
        .filter(
            WebScan.org_id == org,
            WebScan.created_at >= w30d,
            WebScan.is_deleted == False,
        )
        .scalar()
        or 0
    )
    # "Active" is any scan still in flight, not only the one a worker is running.
    active_scans = (
        db.query(func.count(WebScan.id))
        .filter(
            WebScan.org_id == org,
            WebScan.status.in_(["queued", "pending", "running"]),
            WebScan.is_deleted == False,
        )
        .scalar()
        or 0
    )

    # ── Finding severity counts (open only) ────────────────────────────────
    sev_rows = (
        db.query(
            WebFinding.severity,
            func.count(WebFinding.id).label("cnt"),
        )
        .filter(WebFinding.org_id == org, WebFinding.status == "open")
        .group_by(WebFinding.severity)
        .all()
    )
    sev_map = {(r.severity or "info").lower(): r.cnt for r in sev_rows}

    # ── Total endpoints discovered ─────────────────────────────────────────
    total_endpoints = (
        db.query(func.count(WebAsset.id))
        .join(WebScan, WebAsset.web_scan_id == WebScan.id)
        .filter(WebScan.org_id == org, WebScan.is_deleted == False)
        .scalar()
        or 0
    )

    # ── Unique domains scanned ─────────────────────────────────────────────
    unique_domains = (
        db.query(func.count(WebScan.target_domain.distinct()))
        .filter(WebScan.org_id == org, WebScan.is_deleted == False)
        .scalar()
        or 0
    )

    # ── Verified findings count ────────────────────────────────────────────
    verified = (
        db.query(func.count(WebFinding.id))
        .filter(
            WebFinding.org_id == org,
            WebFinding.is_verified == True,
            WebFinding.status == "open",
        )
        .scalar()
        or 0
    )

    # ── Finding status breakdown ───────────────────────────────────────────
    status_rows = (
        db.query(WebFinding.status, func.count(WebFinding.id).label("cnt"))
        .filter(WebFinding.org_id == org)
        .group_by(WebFinding.status)
        .all()
    )
    status_map = {r.status: r.cnt for r in status_rows}

    # ── Top detected tools ─────────────────────────────────────────────────
    tool_rows = (
        db.query(
            WebFinding.detected_by,
            func.count(WebFinding.id).label("cnt"),
        )
        .filter(WebFinding.org_id == org, WebFinding.status == "open")
        .group_by(WebFinding.detected_by)
        .order_by(func.count(WebFinding.id).desc())
        .limit(5)
        .all()
    )

    return {
        "scans": {
            "total": total_scans,
            "running": running_scans,
            "active": active_scans,
            "completed": completed_scans,
            "last_7d": scans_7d,
            "last_30d": scans_30d,
        },
        "severity": {
            "critical": sev_map.get("critical", 0),
            "high": sev_map.get("high", 0),
            "medium": sev_map.get("medium", 0),
            "low": sev_map.get("low", 0),
            "info": sev_map.get("info", 0),
            "total": sum(sev_map.values()),
        },
        "endpoints": {
            "total": total_endpoints,
            "unique_domains": unique_domains,
        },
        "findings": {
            "verified": verified,
            "open": status_map.get("open", 0),
            "false_positive": status_map.get("false_positive", 0),
            "fixed": status_map.get("fixed", 0),
            "accepted_risk": status_map.get("accepted_risk", 0),
        },
        "top_tools": [{"tool": r.detected_by, "count": r.cnt} for r in tool_rows],
        "org_id": org,
    }


# ── 14. Web Scan OWASP Scorecard ──────────────────────────────────────────────


@router.get("/web-owasp-scorecard")
def get_web_owasp_scorecard(
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("dashboard", "read")),
):
    """
    OWASP Top 10 (2021) coverage from web scan findings.
    Shows how many open findings map to each OWASP category.
    """
    from db.models.web_scans import WebFinding

    org = _resolve_org(user, org_id)

    owasp_categories = {
        "A01": "Broken Access Control",
        "A02": "Cryptographic Failures",
        "A03": "Injection",
        "A04": "Insecure Design",
        "A05": "Security Misconfiguration",
        "A06": "Vulnerable and Outdated Components",
        "A07": "Identification and Authentication Failures",
        "A08": "Software and Data Integrity Failures",
        "A09": "Security Logging and Monitoring Failures",
        "A10": "Server-Side Request Forgery (SSRF)",
    }

    findings = (
        db.query(WebFinding.owasp_category, WebFinding.severity)
        .filter(WebFinding.org_id == org, WebFinding.status == "open")
        .all()
    )

    scorecard = {}
    for code, name in owasp_categories.items():
        scorecard[code] = {
            "name": name,
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

    for f in findings:
        owasp = f.owasp_category or ""
        code = owasp.split(":")[0] if ":" in owasp else ""
        if code in scorecard:
            scorecard[code]["total"] += 1
            sev = (f.severity or "info").lower()
            if sev in scorecard[code]:
                scorecard[code][sev] += 1

    return {
        "scorecard": [{"code": code, **data} for code, data in scorecard.items()],
    }


# ── 15. Web Scan Trends ──────────────────────────────────────────────────────


@router.get("/web-scan-trends")
def get_web_scan_trends(
    days: int = Query(30, ge=7, le=90),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("dashboard", "read")),
):
    """
    Web scan finding trends over time — similar to /vuln-trends but for DAST.
    Aggregates by scan completion date.
    """
    from db.models.web_scans import WebScan

    org = _resolve_org(user, org_id)
    since = _now() - timedelta(days=days)

    rows = (
        db.query(
            WebScan.completed_at,
            WebScan.critical_count,
            WebScan.high_count,
            WebScan.medium_count,
            WebScan.low_count,
            WebScan.info_count,
            WebScan.total_endpoints,
        )
        .filter(
            WebScan.org_id == org,
            WebScan.completed_at >= since,
            WebScan.status == "complete",
            WebScan.is_deleted == False,
        )
        .order_by(WebScan.completed_at.asc())
        .all()
    )

    daily: dict = {}
    for r in rows:
        if not r.completed_at:
            continue
        k = r.completed_at.strftime("%Y-%m-%d")
        if k not in daily:
            daily[k] = {
                "date": k,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "endpoints": 0,
                "scans": 0,
            }
        daily[k]["critical"] += r.critical_count or 0
        daily[k]["high"] += r.high_count or 0
        daily[k]["medium"] += r.medium_count or 0
        daily[k]["low"] += r.low_count or 0
        daily[k]["info"] += r.info_count or 0
        daily[k]["endpoints"] += r.total_endpoints or 0
        daily[k]["scans"] += 1

    return {
        "days": days,
        "data": sorted(daily.values(), key=lambda x: x["date"]),
    }


# ── 16. Web Scan drill-downs (org-wide, filterable) ───────────────────────────
# The dashboard aggregates across every scan, so its numbers cannot drill into a
# single scan-scoped page. These org-wide, filtered endpoints back the clickable
# dashboard counts: the filters mirror exactly how each number is computed, so a
# count and the records behind it stay consistent.


@router.get("/web-findings")
def get_web_findings_drilldown(
    severity: str | None = Query(None),
    owasp: str | None = Query(None, description="OWASP code prefix, e.g. A05"),
    finding_type: str | None = Query(None),
    detected_by: str | None = Query(None),
    status: str | None = Query(None, description="e.g. open; omit for any status"),
    date: str | None = Query(None, description="scan completed date YYYY-MM-DD"),
    scan_id: str | None = Query(None),
    org_id: str | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("dashboard", "read")),
):
    """Org-wide web findings with the same filters the dashboard counts use."""
    from datetime import datetime

    from routers.web_scans import _finding_detail
    from db.models.web_scans import WebFinding, WebScan

    org = _resolve_org(user, org_id)
    q = (
        db.query(WebFinding, WebScan.scan_name, WebScan.target_domain)
        .join(WebScan, WebFinding.web_scan_id == WebScan.id)
        .filter(WebFinding.org_id == org, WebScan.is_deleted == False)
    )
    if severity:
        q = q.filter(WebFinding.severity == severity.lower())
    if owasp:
        # owasp_category is stored like "A05:2021 – …"; match on the code prefix.
        q = q.filter(WebFinding.owasp_category.ilike(f"{owasp}%"))
    if finding_type:
        q = q.filter(WebFinding.finding_type == finding_type)
    if detected_by:
        q = q.filter(WebFinding.detected_by.ilike(f"%{detected_by}%"))
    if status:
        q = q.filter(WebFinding.status == status)
    if scan_id:
        q = q.filter(WebFinding.web_scan_id == scan_id)
    if date:
        try:
            d0 = datetime.strptime(date, "%Y-%m-%d")
            d1 = d0 + timedelta(days=1)
            q = q.filter(WebScan.completed_at >= d0, WebScan.completed_at < d1)
        except ValueError:
            pass

    total = q.count()
    rows = (
        q.order_by(WebFinding.severity.desc(), WebFinding.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    data = []
    for finding, scan_name, target_domain in rows:
        detail = _finding_detail(finding)
        detail["scan_id"] = finding.web_scan_id
        detail["scan_name"] = scan_name
        detail["target_domain"] = target_domain
        data.append(detail)

    return {
        "success": True,
        "data": data,
        "filters": {
            "severity": severity,
            "owasp": owasp,
            "finding_type": finding_type,
            "detected_by": detected_by,
            "status": status,
            "date": date,
            "scan_id": scan_id,
        },
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
        },
    }


@router.get("/web-endpoints")
def get_web_endpoints_drilldown(
    source: str | None = Query(None),
    is_api: bool | None = Query(None),
    scan_id: str | None = Query(None),
    org_id: str | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(200, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("dashboard", "read")),
):
    """Org-wide discovered endpoints — backs the 'Total Endpoints Discovered' card."""
    from db.models.web_scans import WebAsset, WebScan

    org = _resolve_org(user, org_id)
    q = (
        db.query(WebAsset, WebScan.scan_name)
        .join(WebScan, WebAsset.web_scan_id == WebScan.id)
        .filter(WebScan.org_id == org, WebScan.is_deleted == False)
    )
    if source:
        q = q.filter(WebAsset.source == source)
    if is_api is not None:
        q = q.filter(WebAsset.is_api == is_api)
    if scan_id:
        q = q.filter(WebAsset.web_scan_id == scan_id)

    total = q.count()
    rows = (
        q.order_by(WebAsset.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    data = []
    for asset, scan_name in rows:
        data.append(
            {
                "id": asset.id,
                "scan_id": asset.web_scan_id,
                "scan_name": scan_name,
                "url": asset.url,
                "method": asset.method,
                "response_code": asset.response_code,
                "content_type": asset.content_type,
                "is_api": asset.is_api,
                "is_form": asset.is_form,
                "auth_required": asset.auth_required,
                "has_file_upload": asset.has_file_upload,
                "source": asset.source,
            }
        )

    return {
        "success": True,
        "data": data,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
        },
    }
