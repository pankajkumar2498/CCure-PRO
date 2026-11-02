"""
core/topology/links.py
─────────────────────────────────────────────────────────────────────────────
The topology store: the one module that writes and reads ``network_links``
(2 Nov 2026, docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

The topology engine computes a run's links and hands them over in its plan
(``core.topology.directory.TopologyPlan``); it imports neither the model nor
SQLAlchemy. What it used to do in ``_persist_links`` and at the top of
``get_topology_graph`` is here, unchanged: the upsert in canonical
orientation, the created/updated count, the one transaction, and the query the
graph is drawn from. Audit's composition root registers it with the asset
registry's half (``ccure_audit/topology_directory.py``), which hands in the
asset writes so that they share the transaction.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Callable, List, Optional, Tuple

from core.topology.directory import StoredLink, asset_record
from db.base import utcnow
from db.models.topology import NetworkLink
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session, selectinload

# The engine's logger: these are the messages it wrote when the write was its.
log = logging.getLogger("ccure.topology.engine")

#: Postgres caps bind parameters per statement; IN-lists are chunked to fit.
_ID_CHUNK = 500

_COLUMNS = tuple(column.key for column in NetworkLink.__table__.columns)


def record_links(
    db: Session,
    *,
    org_id: str,
    scan_id: str,
    links: List[dict],
    write_assets: Callable[[datetime], None],
) -> Tuple[int, int]:
    """
    Upsert the run's links, after ``write_assets`` has written its assets, and
    commit: (created, updated).

    Runs as one transaction: a partially written topology is worse than none,
    because the map cannot tell the difference between "not adjacent" and
    "not written yet".
    """
    now = utcnow()
    if not links:
        write_assets(now)
        db.commit()
        return 0, 0

    link_ids = [values["id"] for values in links]
    existing_ids: set[str] = set()
    for start in range(0, len(link_ids), _ID_CHUNK):
        chunk = link_ids[start : start + _ID_CHUNK]
        existing_ids.update(
            row[0]
            for row in db.query(NetworkLink.id)
            .filter(NetworkLink.org_id == org_id, NetworkLink.id.in_(chunk))
            .all()
        )

    created = 0
    updated = 0

    try:
        # The assets first: a link's endpoints reference them.
        write_assets(now)
        for planned in links:
            values = {
                **planned,
                "first_seen_at": now,
                "last_seen_at": now,
                "created_at": now,
            }

            stmt = insert(NetworkLink).values(**values)
            # Endpoints are part of the conflict target's identity, but they are
            # still refreshed: a device that gains a MAC between scans must have
            # it recorded, and first_seen_at must survive.
            stmt = stmt.on_conflict_do_update(
                index_elements=["id"],
                set_={
                    key: values[key]
                    for key in values
                    if key not in ("id", "org_id", "first_seen_at", "created_at")
                },
            )
            db.execute(stmt)

            if values["id"] in existing_ids:
                updated += 1
            else:
                created += 1

        db.commit()
    except Exception:
        db.rollback()
        log.exception("Topology persistence failed for scan %s; rolled back", scan_id)
        raise

    return created, updated


def stored_links(
    db: Session,
    *,
    org_id: str,
    scan_id: Optional[str],
    active_within_days: Optional[int],
) -> List[StoredLink]:
    """The organisation's stored links and their assets, as plain values."""
    query = db.query(NetworkLink).filter(NetworkLink.org_id == org_id)
    if scan_id:
        query = query.filter(NetworkLink.scan_id == scan_id)
    if active_within_days:
        cutoff = utcnow() - timedelta(days=active_within_days)
        query = query.filter(NetworkLink.last_seen_at >= cutoff)
    # Both asset relationships are read for every link; without eager loading
    # this is two queries per link.
    query = query.options(
        selectinload(NetworkLink.source_asset),
        selectinload(NetworkLink.target_asset),
    )
    return [
        StoredLink(
            **{name: getattr(row, name) for name in _COLUMNS},
            source_asset=asset_record(row.source_asset),
            target_asset=asset_record(row.target_asset),
        )
        for row in query.all()
    ]
