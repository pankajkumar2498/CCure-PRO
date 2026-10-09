"""
ccure_audit/offboarding.py — Audit's answer to a user purge.

When the platform permanently deletes an account it asks each module to detach
its own references first (``ccure_platform/offboarding.py``). These are Audit's:
the scans a user started, their asset notes and tags, and the findings whose
risk they accepted. The records stay — a scan outlives the person who ran it —
and only the pointer to the removed account is cleared.

Moved out of ``admin_users.purge_user``, where the platform's route was
updating Audit's tables directly. The statements are the same ones, run on the
same session and in the same transaction, before the user row is deleted.

Registered at import; ``main.py`` imports this module.
"""

from __future__ import annotations

from ccure_platform.api import register_user_purge_hook
from db.models import AssetNote, AssetTag, AssetVulnerability, Scan
from sqlalchemy.orm import Session


def detach_user_from_audit_data(db: Session, user_id: str) -> None:
    db.query(AssetNote).filter(AssetNote.user_id == user_id).update(
        {AssetNote.user_id: None}, synchronize_session=False
    )
    db.query(AssetTag).filter(AssetTag.created_by_id == user_id).update(
        {AssetTag.created_by_id: None}, synchronize_session=False
    )
    db.query(Scan).filter(Scan.created_by == user_id).update(
        {Scan.created_by: None}, synchronize_session=False
    )
    db.query(AssetVulnerability).filter(
        AssetVulnerability.accepted_by == user_id
    ).update({AssetVulnerability.accepted_by: None}, synchronize_session=False)


register_user_purge_hook("audit", detach_user_from_audit_data)
