"""
core/asset_offboarding.py — the asset registry's part of a user purge.

When the platform purges an account, Audit's purge hook
(``ccure_audit/offboarding.py``) detaches Audit's references to it. An asset
note names its author in ``user_id`` and an asset tag its creator in
``created_by_id``; the note and the tag stay, and only that pointer is cleared.
The tables are this capability's, so the statements are.

Moved unchanged from ``ccure_audit.offboarding.detach_user_from_audit_data``,
which calls it where the statements were: on the same session, in the same
transaction, before the user row is deleted.
"""

from __future__ import annotations

from db.models import AssetNote, AssetTag
from sqlalchemy.orm import Session


def detach_user_from_assets(db: Session, user_id: str) -> None:
    db.query(AssetNote).filter(AssetNote.user_id == user_id).update(
        {AssetNote.user_id: None}, synchronize_session=False
    )
    db.query(AssetTag).filter(AssetTag.created_by_id == user_id).update(
        {AssetTag.created_by_id: None}, synchronize_session=False
    )
