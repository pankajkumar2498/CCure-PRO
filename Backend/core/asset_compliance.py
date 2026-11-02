"""
core/asset_compliance.py — what the compliance tasks ask of the asset
registry.

``core.compliance_tasks`` used to query the asset model itself: the assets a
compliance run covers, the asset a remediation runs against, and, after a
remediation that needs a restart, a ``reboot_pending`` mark it set on the
asset's ``custom_attributes``. That last one is a write to the asset
registry's table that the capability map counts only as a reference. The
registry answers all three here instead, with the queries and the assignment
moved unchanged (1 Nov 2026), as ``core/asset_evidence.py`` answers
compliance's evidence.

Nothing here commits: the compliance task's transaction does, as before.
"""

from __future__ import annotations

from typing import Iterable, List, Optional

from db.models.assets import Asset
from sqlalchemy.orm import Session


def assets_for_run(
    db: Session, org_id: str, asset_ids: Optional[Iterable[str]] = None
) -> List[Asset]:
    """The organisation's assets, only *asset_ids* when any are named."""
    query = db.query(Asset).filter(Asset.org_id == org_id)
    if asset_ids:
        query = query.filter(Asset.id.in_(asset_ids))
    return query.all()


def asset_by_id(db: Session, asset_id: str) -> Optional[Asset]:
    """The asset record, or None."""
    return db.query(Asset).filter_by(id=asset_id).first()


def mark_reboot_pending(db: Session, asset_id: str) -> bool:
    """
    Record on the asset that an applied remediation takes effect only after
    a restart (``custom_attributes["reboot_pending"]``, which the compliance
    finding view reports). Returns whether the asset exists; the caller
    commits.
    """
    asset = asset_by_id(db, asset_id)
    if not asset:
        return False
    attrs = dict(asset.custom_attributes or {})
    attrs["reboot_pending"] = True
    asset.custom_attributes = attrs
    db.add(asset)
    return True
