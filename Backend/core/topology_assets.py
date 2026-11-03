"""
core/topology_assets.py
─────────────────────────────────────────────────────────────────────────────
The asset registry's answer to the topology engine's directory (G3,
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md): the queries, the lookup
and the enrolment the engine used to make itself.

Since 2 Nov 2026 the engine reads plain records and writes nothing: it used to
set fields on the asset rows it was handed (a hostname, a MAC, a category, a
VLAN), which the session then wrote at commit, unseen. It hands the asset
registry the enrolments and the filled gaps in its plan instead, and
:func:`write_topology_assets` writes them, in the topology store's
transaction.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from core.topology.directory import AssetRecord, asset_record
from db.models.assets import Asset
from sqlalchemy.orm import Session

#: Postgres caps bind parameters per statement; IN-lists are chunked to fit.
_ID_CHUNK = 500


def organisation_assets(db: Session, org_id: str) -> List[AssetRecord]:
    return [
        asset_record(row)
        for row in db.query(Asset).filter(Asset.org_id == org_id).all()
    ]


def asset(db: Session, asset_id: str) -> Optional[AssetRecord]:
    return asset_record(db.get(Asset, asset_id))


def write_topology_assets(
    db: Session,
    enrolments: List[Dict[str, Any]],
    changes: Dict[str, Dict[str, Any]],
    *,
    now: datetime,
) -> None:
    """
    Enrol the assets a mapping run found, then fill the gaps it filled. Does
    not commit: the topology store commits the run as one transaction.
    """
    for fields in enrolments:
        db.add(Asset(**fields, last_seen_at=now, created_at=now, updated_at=now))
    if enrolments:
        db.flush()  # Make the PKs available for the links' FKs.

    ids = list(changes)
    for start in range(0, len(ids), _ID_CHUNK):
        chunk = ids[start : start + _ID_CHUNK]
        for row in db.query(Asset).filter(Asset.id.in_(chunk)).all():
            for name, value in changes[row.id].items():
                setattr(row, name, value)
