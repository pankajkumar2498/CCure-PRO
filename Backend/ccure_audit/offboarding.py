"""
ccure_audit/offboarding.py — Audit's answer to a user purge.

When the platform permanently deletes an account it asks each module to detach
its own references first (``ccure_platform/offboarding.py``). These are Audit's:
the scans and web scans a user started, their asset notes and tags, and the
findings whose risk they accepted. The records stay — a scan outlives the person
who ran it — and only the pointer to the removed account is cleared.

The web scans are the web capability's table, so their creator is cleared by
``core/web/offboarding.py``. Until B8 the ORM did it through a back-reference
on the platform's ``User`` (that module says why it is needed).

The findings are the findings capability's table, so their acceptor is cleared
by ``core.findings.writer.detach_user_from_findings`` (G3); likewise the asset
notes and tags by ``core.asset_offboarding`` and the scans by
``scans.offboarding``. This hook only composes the owners' statements.

Moved out of ``admin_users.purge_user``, where the platform's route was
updating Audit's tables directly. The statements are the same ones, run on the
same session and in the same transaction, before the user row is deleted.

Registered at import; ``main.py`` imports this module.
"""

from __future__ import annotations

from ccure_platform.api import register_user_purge_hook
from core.asset_offboarding import detach_user_from_assets
from core.web.offboarding import detach_user_from_web_scans
from core.findings.writer import detach_user_from_findings
from scans.offboarding import detach_user_from_scans
from sqlalchemy.orm import Session


def detach_user_from_audit_data(db: Session, user_id: str) -> None:
    detach_user_from_assets(db, user_id)
    detach_user_from_scans(db, user_id)
    detach_user_from_findings(db, user_id)
    detach_user_from_web_scans(db, user_id)


register_user_purge_hook("audit", detach_user_from_audit_data)
