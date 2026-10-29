"""
core/topology_assets.py
─────────────────────────────────────────────────────────────────────────────
The asset registry's answer to the topology engine's directory (G3,
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md): the queries, the lookup
and the enrolment the engine used to make itself, moved unchanged.
"""

from __future__ import annotations

from typing import Any, List, Optional

from db.models.assets import Asset
from sqlalchemy.orm import Session


def organisation_assets(db: Session, org_id: str) -> List[Asset]:
    return db.query(Asset).filter(Asset.org_id == org_id).all()


def asset(db: Session, asset_id: str) -> Optional[Asset]:
    return db.get(Asset, asset_id)


def enrol(db: Session, **fields: Any) -> Asset:
    row = Asset(**fields)
    db.add(row)
    db.flush()  # Make the PK available for the link's FK.
    return row
