"""
core/asset_reads.py
─────────────────────────────────────────────────────────────────────────────
What the read side asks of the asset registry (G2, the remainder of C7 in
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

The dashboard summarises an organisation's assets — how many, how risky, what
they run, which were seen when — and counts the ports its change log recorded
opening; the report export dates each exported host from the registry. Both
used to query ``assets`` and ``asset_change_log`` through the asset models.
They ask here now. The queries are moved unchanged, so a response is byte for
byte what it was.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from db.models.assets import Asset, AssetChangeLog
from sqlalchemy import case, func
from sqlalchemy.orm import Session

__all__ = [
    "active_assets_unseen_since",
    "asset_count",
    "asset_overview",
    "asset_totals",
    "average_risk",
    "average_risk_seen_before",
    "category_counts",
    "lifecycle_dates",
    "os_family_counts",
    "ports_opened_since",
    "riskiest_active_assets",
    "riskiest_subnet",
    "risk_level_counts",
    "scanned_asset_count",
]


def asset_overview(db: Session, org: str, w24h: datetime, w7d: datetime) -> Any:
    """One row: total, unmanaged, first seen in the last 7 days and 24 hours,
    and the average risk score."""
    return (
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


def average_risk_seen_before(db: Session, org: str, before: datetime) -> Any:
    """The average risk score of the assets first seen before *before*."""
    return (
        db.query(func.avg(Asset.risk_score))
        .filter(Asset.org_id == org, Asset.first_seen_at < before)
        .scalar()
    )


def risk_level_counts(db: Session, org: str) -> List[Any]:
    """Assets per risk level."""
    return (
        db.query(Asset.risk_level, func.count(Asset.id).label("cnt"))
        .filter(Asset.org_id == org)
        .group_by(Asset.risk_level)
        .all()
    )


def average_risk(db: Session, org: str) -> Any:
    return db.query(func.avg(Asset.risk_score)).filter(Asset.org_id == org).scalar()


def riskiest_active_assets(db: Session, org: str, limit: int) -> List[Asset]:
    return (
        db.query(Asset)
        .filter(Asset.org_id == org, Asset.is_active == True)
        .order_by(Asset.risk_score.desc())
        .limit(limit)
        .all()
    )


def asset_count(db: Session, org: str) -> Any:
    return db.query(func.count(Asset.id)).filter(Asset.org_id == org).scalar()


def scanned_asset_count(db: Session, org: str) -> Any:
    """Assets some scan has recorded as its last."""
    return (
        db.query(func.count(Asset.id))
        .filter(Asset.org_id == org, Asset.last_scan_id != None)
        .scalar()
    )


def os_family_counts(db: Session, org: str) -> List[Any]:
    return (
        db.query(Asset.os_family, func.count(Asset.id).label("cnt"))
        .filter(Asset.org_id == org)
        .group_by(Asset.os_family)
        .all()
    )


def category_counts(db: Session, org: str) -> List[Any]:
    return (
        db.query(Asset.device_category, func.count(Asset.id).label("cnt"))
        .filter(Asset.org_id == org)
        .group_by(Asset.device_category)
        .all()
    )


def asset_totals(db: Session, org: str) -> Any:
    """One row: total, managed, unmanaged, active and offline."""
    return (
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


def riskiest_subnet(db: Session, org: str) -> Optional[Any]:
    """The subnet with the highest average risk, and that average."""
    return (
        db.query(Asset.subnet, func.avg(Asset.risk_score).label("avg_r"))
        .filter(Asset.org_id == org, Asset.subnet != None)
        .group_by(Asset.subnet)
        .order_by(func.avg(Asset.risk_score).desc())
        .first()
    )


def ports_opened_since(db: Session, org: str, since: datetime) -> Any:
    """How many ports the change log recorded opening since *since*."""
    return (
        db.query(func.count(AssetChangeLog.id))
        .join(Asset, AssetChangeLog.asset_id == Asset.id)
        .filter(
            Asset.org_id == org,
            AssetChangeLog.change_type == "port_opened",
            AssetChangeLog.detected_at >= since,
        )
        .scalar()
    )


def active_assets_unseen_since(db: Session, org: str, since: datetime) -> Any:
    return (
        db.query(func.count(Asset.id))
        .filter(
            Asset.org_id == org,
            Asset.last_seen_at < since,
            Asset.is_active == True,
        )
        .scalar()
    )


def lifecycle_dates(
    db: Session, org: str, ips: Iterable[str]
) -> Dict[str, Tuple[Any, Any]]:
    """Each address's first and last sighting, by address."""
    rows = (
        db.query(Asset.ip_address, Asset.first_seen_at, Asset.last_seen_at)
        .filter(Asset.org_id == org, Asset.ip_address.in_(ips))
        .all()
    )
    return {str(ip): (first, last) for ip, first, last in rows}
