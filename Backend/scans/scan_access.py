"""
scans/scan_access.py — the tenant- and visibility-scoped scan lookup.

Moved out of ``routers/scan_history.py`` so ``routers/phase_scans.py`` can use
the same lookup without importing another router. The code is unchanged; the
router modules keep their old private names (``_get_scan_or_404`` …) as imports
of these, so nothing that referred to them changes.
"""

from __future__ import annotations

from ccure_platform import api as platform_api
from ccure_platform.api import CurrentUser
from db.models.scans import Scan
from fastapi import HTTPException
from sqlalchemy.orm import Session, joinedload


def is_superadmin(user: CurrentUser) -> bool:
    return (
        getattr(getattr(user, "role", None), "name", "") or ""
    ).lower() == "superadmin"


def resolve_org(user: CurrentUser, requested_org: str | None) -> str:
    if is_superadmin(user) and requested_org:
        return requested_org
    return str(user.org_id)


def user_can_read_all_scans(user: CurrentUser, db: Session) -> bool:
    return platform_api.user_has_permission(db, user, "scans", "read_all")


def get_scan_or_404(
    scan_id: str, user: CurrentUser, db: Session, org_id: str | None = None
) -> Scan:
    target_org_id = resolve_org(user, org_id)
    query = (
        db.query(Scan)
        .options(joinedload(Scan.created_by_user))
        .filter(Scan.id == scan_id, Scan.org_id == target_org_id)
    )
    if not user_can_read_all_scans(user, db):
        query = query.filter(Scan.created_by == str(user.id))

    scan = query.first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
