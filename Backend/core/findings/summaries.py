"""
core/findings/summaries.py
─────────────────────────────────────────────────────────────────────────────
Organisation-wide figures from the findings tables, for the dashboard (G2, the
remainder of C7 in docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

The dashboard counts open findings by severity, status and exploitation,
ranks CVEs, and summarises the services, TLS and HTTP details the scans
recorded. It used to query ``asset_vulnerabilities``,
``vulnerability_definitions``, ``services``, ``tls_details`` and
``http_security_details`` itself; it asks here now. The queries are moved
unchanged but for one thing: they scope by organisation through the findings
side's host port, ``core.findings.hosts``, rather than by joining the asset
model, as every other findings query does since G6. A plain subquery is pulled
up into the join, so each is still one statement.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional, Sequence

from core.findings.hosts import hosts
from db.base import utcnow
from db.models.findings import (
    OBSERVED_SERVICE_STATES,
    AssetVulnerability,
    HttpSecurityDetail,
    Service,
    TLSDetail,
    VulnerabilityDefinition,
)
from sqlalchemy import case, func
from sqlalchemy.orm import Session

__all__ = [
    "cleartext_service_count",
    "exposed_services",
    "finding_count",
    "finding_status_counts",
    "http_average_score",
    "http_header_coverage",
    "open_count_at_or_above_cvss",
    "open_critical_count",
    "open_kev_count",
    "open_severity_counts",
    "stale_high_count",
    "tls_expiring_count",
    "tls_grade_counts",
    "tls_issue_counts",
    "tls_service_count",
    "top_cves",
    "top_recurring_cve",
]


def open_severity_counts(db: Session, org: str) -> List[Any]:
    """Open findings per severity, folded to lower case in SQL so mixed
    spellings are summed rather than overwritten (see the dashboard)."""
    h = hosts()
    sev_expr = func.lower(AssetVulnerability.severity)
    return (
        db.query(
            sev_expr.label("severity"), func.count(AssetVulnerability.id).label("cnt")
        )
        .join(h, AssetVulnerability.asset_id == h.c.id)
        .filter(h.c.org_id == org, AssetVulnerability.status == "open")
        .group_by(sev_expr)
        .all()
    )


def open_kev_count(db: Session, org: str) -> Any:
    """Open findings on CISA's known-exploited list, read from the finding's
    own ``in_kev`` flag."""
    h = hosts()
    return (
        db.query(func.count(AssetVulnerability.id))
        .join(h, AssetVulnerability.asset_id == h.c.id)
        .filter(
            h.c.org_id == org,
            AssetVulnerability.status == "open",
            AssetVulnerability.in_kev.is_(True),
        )
        .scalar()
    )


def open_count_at_or_above_cvss(db: Session, org: str, score: float) -> Any:
    h = hosts()
    return (
        db.query(func.count(AssetVulnerability.id))
        .join(h, AssetVulnerability.asset_id == h.c.id)
        .filter(
            h.c.org_id == org,
            AssetVulnerability.status == "open",
            AssetVulnerability.cvss_score >= score,
        )
        .scalar()
    )


def tls_issue_counts(db: Session, org: str) -> Any:
    """One row: expired, self-signed, weak-cipher and grade-F TLS services."""
    h = hosts()
    return (
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
        .join(h, Service.asset_id == h.c.id)
        .filter(h.c.org_id == org, TLSDetail.is_enabled == True)
        .one()
    )


def http_average_score(db: Session, org: str) -> Any:
    h = hosts()
    return (
        db.query(func.avg(HttpSecurityDetail.security_score))
        .join(Service, HttpSecurityDetail.service_id == Service.id)
        .join(h, Service.asset_id == h.c.id)
        .filter(h.c.org_id == org)
        .scalar()
    )


def finding_status_counts(db: Session, org: str) -> List[Any]:
    """Findings per status, open or not."""
    h = hosts()
    return (
        db.query(
            AssetVulnerability.status, func.count(AssetVulnerability.id).label("cnt")
        )
        .join(h, AssetVulnerability.asset_id == h.c.id)
        .filter(h.c.org_id == org)
        .group_by(AssetVulnerability.status)
        .all()
    )


def top_cves(
    db: Session, org: str, limit: int, severities: Optional[Sequence[str]]
) -> List[Any]:
    """
    The catalogue entries with open findings here, ranked by the highest score
    measured against these hosts and then by how many hosts carry them. Each
    row is the definition and the aggregates the findings give it: hosts
    affected, CVSS, severity, KEV, exploit and EPSS.
    """
    h = hosts()
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
        .join(h, AssetVulnerability.asset_id == h.c.id)
        .filter(h.c.org_id == org, AssetVulnerability.status == "open")
        .group_by(VulnerabilityDefinition.id)
    )
    if severities:
        q = q.filter(func.lower(AssetVulnerability.severity).in_(severities))
    return (
        q.order_by(
            func.max(AssetVulnerability.cvss_score).desc().nullslast(),
            func.count(AssetVulnerability.asset_id.distinct()).desc(),
        )
        .limit(limit)
        .all()
    )


def exposed_services(db: Session, org: str) -> List[Any]:
    """The 20 most widespread observed services: port, protocol, name and how
    many hosts expose it."""
    h = hosts()
    return (
        db.query(
            Service.port,
            Service.protocol,
            Service.service_name,
            func.count(Service.asset_id.distinct()).label("asset_count"),
        )
        .join(h, Service.asset_id == h.c.id)
        .filter(h.c.org_id == org, Service.state.in_(OBSERVED_SERVICE_STATES))
        .group_by(Service.port, Service.protocol, Service.service_name)
        .order_by(func.count(Service.asset_id.distinct()).desc())
        .limit(20)
        .all()
    )


def tls_grade_counts(db: Session, org: str) -> List[Any]:
    h = hosts()
    return (
        db.query(TLSDetail.grade, func.count(TLSDetail.id).label("cnt"))
        .join(Service, TLSDetail.service_id == Service.id)
        .join(h, Service.asset_id == h.c.id)
        .filter(h.c.org_id == org, TLSDetail.is_enabled == True)
        .group_by(TLSDetail.grade)
        .all()
    )


def tls_expiring_count(db: Session, org: str, now: datetime, until: datetime) -> Any:
    """Enabled TLS services whose certificate expires between *now* and
    *until*."""
    h = hosts()
    return (
        db.query(func.count(TLSDetail.id))
        .join(Service, TLSDetail.service_id == Service.id)
        .join(h, Service.asset_id == h.c.id)
        .filter(
            h.c.org_id == org,
            TLSDetail.is_enabled == True,
            TLSDetail.cert_not_after <= until,
            TLSDetail.cert_not_after >= now,
        )
        .scalar()
    )


def tls_service_count(db: Session, org: str) -> Any:
    h = hosts()
    return (
        db.query(func.count(TLSDetail.id))
        .join(Service, TLSDetail.service_id == Service.id)
        .join(h, Service.asset_id == h.c.id)
        .filter(h.c.org_id == org, TLSDetail.is_enabled == True)
        .scalar()
    )


def http_header_coverage(db: Session, org: str) -> Any:
    """One row: HTTP services, how many send each security header, and their
    average security score."""
    h = hosts()
    return (
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
        .join(h, Service.asset_id == h.c.id)
        .filter(h.c.org_id == org)
        .one()
    )


def open_critical_count(db: Session, org: str) -> Any:
    h = hosts()
    return (
        db.query(func.count(AssetVulnerability.id))
        .join(h, AssetVulnerability.asset_id == h.c.id)
        .join(
            VulnerabilityDefinition,
            AssetVulnerability.vuln_id == VulnerabilityDefinition.id,
        )
        .filter(
            h.c.org_id == org,
            AssetVulnerability.status == "open",
            func.lower(AssetVulnerability.severity) == "critical",
        )
        .scalar()
    )


def cleartext_service_count(db: Session, org: str, ports: Sequence[int]) -> Any:
    """Observed services on the given cleartext ports."""
    h = hosts()
    return (
        db.query(func.count(Service.id.distinct()))
        .join(h, Service.asset_id == h.c.id)
        .filter(
            h.c.org_id == org,
            Service.port.in_(ports),
            Service.state.in_(OBSERVED_SERVICE_STATES),
        )
        .scalar()
    )


def finding_count(db: Session, org: str, status: Optional[str] = None) -> Any:
    """Findings in any status, or in *status*."""
    h = hosts()
    q = db.query(func.count(AssetVulnerability.id)).join(
        h, AssetVulnerability.asset_id == h.c.id
    )
    if status is None:
        return q.filter(h.c.org_id == org).scalar()
    return q.filter(h.c.org_id == org, AssetVulnerability.status == status).scalar()


def stale_high_count(db: Session, org: str, found_before: datetime) -> Any:
    """Open critical and high findings first found before *found_before*."""
    h = hosts()
    return (
        db.query(func.count(AssetVulnerability.id))
        .join(h, AssetVulnerability.asset_id == h.c.id)
        .join(
            VulnerabilityDefinition,
            AssetVulnerability.vuln_id == VulnerabilityDefinition.id,
        )
        .filter(
            h.c.org_id == org,
            AssetVulnerability.status == "open",
            AssetVulnerability.first_found_at <= found_before,
            func.lower(AssetVulnerability.severity).in_(["critical", "high"]),
        )
        .scalar()
    )


def top_recurring_cve(db: Session, org: str) -> Optional[Any]:
    """The open critical or high catalogue entry on the most hosts: its id,
    title and host count."""
    h = hosts()
    return (
        db.query(
            VulnerabilityDefinition.id,
            VulnerabilityDefinition.title,
            func.count(AssetVulnerability.asset_id.distinct()).label("cnt"),
        )
        .join(
            AssetVulnerability,
            AssetVulnerability.vuln_id == VulnerabilityDefinition.id,
        )
        .join(h, AssetVulnerability.asset_id == h.c.id)
        .filter(
            h.c.org_id == org,
            AssetVulnerability.status == "open",
            func.lower(AssetVulnerability.severity).in_(["critical", "high"]),
        )
        .group_by(VulnerabilityDefinition.id, VulnerabilityDefinition.title)
        .order_by(func.count(AssetVulnerability.asset_id.distinct()).desc())
        .first()
    )
