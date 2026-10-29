"""
core/web/reads.py
─────────────────────────────────────────────────────────────────────────────
What the dashboard reads from web application scanning (G2, the remainder of
C7 in docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

The dashboard summarises an organisation's web scans and their findings, maps
the open findings onto the OWASP Top 10, charts the completed scans, and lists
the findings and discovered endpoints behind each count. It used to query
``web_scans``, ``web_findings`` and ``web_assets`` itself; it asks here now.
The queries are moved unchanged, so a response is byte for byte what it was.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, List, Optional, Tuple

from db.models.web_scans import WebAsset, WebFinding, WebScan
from sqlalchemy import func
from sqlalchemy.orm import Session

__all__ = [
    "FindingFilters",
    "WebScanFigures",
    "completed_web_scan_counts",
    "endpoint_page",
    "finding_page",
    "open_finding_categories",
    "web_scan_figures",
]


@dataclass(frozen=True)
class WebScanFigures:
    """The web-scan summary's raw figures; the dashboard shapes them."""

    total_scans: int
    running_scans: int
    completed_scans: int
    scans_7d: int
    scans_30d: int
    active_scans: int
    severity_rows: List[Any]
    total_endpoints: int
    unique_domains: int
    verified: int
    status_rows: List[Any]
    tool_rows: List[Any]


def web_scan_figures(db: Session, org: str, now: datetime) -> WebScanFigures:
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

    return WebScanFigures(
        total_scans=total_scans,
        running_scans=running_scans,
        completed_scans=completed_scans,
        scans_7d=scans_7d,
        scans_30d=scans_30d,
        active_scans=active_scans,
        severity_rows=sev_rows,
        total_endpoints=total_endpoints,
        unique_domains=unique_domains,
        verified=verified,
        status_rows=status_rows,
        tool_rows=tool_rows,
    )


def open_finding_categories(db: Session, org: str) -> List[Any]:
    """Each open finding's OWASP category and severity."""
    return (
        db.query(WebFinding.owasp_category, WebFinding.severity)
        .filter(WebFinding.org_id == org, WebFinding.status == "open")
        .all()
    )


def completed_web_scan_counts(db: Session, org: str, since: datetime) -> List[Any]:
    """Each web scan completed since *since*, oldest first: its completion
    time, its counts per severity and its endpoints."""
    return (
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


@dataclass(frozen=True)
class FindingFilters:
    severity: Optional[str] = None
    owasp: Optional[str] = None
    finding_type: Optional[str] = None
    detected_by: Optional[str] = None
    status: Optional[str] = None
    date: Optional[str] = None
    scan_id: Optional[str] = None


def finding_page(
    db: Session, org: str, filters: FindingFilters, page: int, per_page: int
) -> Tuple[int, List[Any]]:
    """
    ``(total, rows)``: the organisation's web findings under *filters*, with
    the scan each came from, highest severity first, newest first among
    equals. Each row is the finding, the scan's name and its target domain.
    """
    q = (
        db.query(WebFinding, WebScan.scan_name, WebScan.target_domain)
        .join(WebScan, WebFinding.web_scan_id == WebScan.id)
        .filter(WebFinding.org_id == org, WebScan.is_deleted == False)
    )
    if filters.severity:
        q = q.filter(WebFinding.severity == filters.severity.lower())
    if filters.owasp:
        # owasp_category is stored like "A05:2021 – …"; match on the code prefix.
        q = q.filter(WebFinding.owasp_category.ilike(f"{filters.owasp}%"))
    if filters.finding_type:
        q = q.filter(WebFinding.finding_type == filters.finding_type)
    if filters.detected_by:
        q = q.filter(WebFinding.detected_by.ilike(f"%{filters.detected_by}%"))
    if filters.status:
        q = q.filter(WebFinding.status == filters.status)
    if filters.scan_id:
        q = q.filter(WebFinding.web_scan_id == filters.scan_id)
    if filters.date:
        try:
            d0 = datetime.strptime(filters.date, "%Y-%m-%d")
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
    return total, rows


def endpoint_page(
    db: Session,
    org: str,
    *,
    source: Optional[str],
    is_api: Optional[bool],
    scan_id: Optional[str],
    page: int,
    per_page: int,
) -> Tuple[int, List[Any]]:
    """
    ``(total, rows)``: the organisation's discovered endpoints, newest first.
    Each row is the endpoint and its scan's name.
    """
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
    return total, rows
