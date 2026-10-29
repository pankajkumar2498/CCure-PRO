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


def resolve_org(user: CurrentUser, requested_org: str | None) -> str:
    return platform_api.resolve_active_organisation(user, requested_org)


def user_can_read_all_scans(
    user: CurrentUser, db: Session, org_id: str | None = None
) -> bool:
    """``audit.scan.read_all`` is organisation-wide visibility within one organisation —
    the organisation the request acts in — never visibility across organisations."""
    return platform_api.has_permission(db, user, "audit.scan.read_all", org_id=org_id)


def get_scan_or_404(
    scan_id: str, user: CurrentUser, db: Session, org_id: str | None = None
) -> Scan:
    target_org_id = resolve_org(user, org_id)
    query = (
        db.query(Scan)
        .options(joinedload(Scan.created_by_user))
        .filter(Scan.id == scan_id, Scan.org_id == target_org_id)
    )
    if not user_can_read_all_scans(user, db, target_org_id):
        query = query.filter(Scan.created_by == str(user.id))

    scan = query.first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def report_scan_or_404(
    db: Session, user: CurrentUser, scan_id: str, org_id: str | None = None
) -> Scan:
    """
    The scan, or 404 — under this caller's own visibility rules.

    Exactly the scoping the download endpoint has always applied: a superadmin
    sees any organisation, everybody else is confined to their own, and a user
    without ``scans:read_all`` sees only the scans they started. Expressed once
    so an export route cannot drift from it, which is the shape a cross-tenant
    export takes: not a missing check, a second copy of one that fell behind.

    404 rather than 403 for a scan in another organisation, deliberately — a
    403 would confirm the id exists.

    The report and export routes' lookup (``routers.reports._scan_for_user``),
    moved here unchanged in G2 so the read side names no scan model.
    """
    reach = platform_api.acts_across_organisations(user)
    query = db.query(Scan).filter(Scan.id == scan_id)
    if reach:
        if org_id:
            query = query.filter(Scan.org_id == org_id)
    else:
        query = query.filter(Scan.org_id == user.org_id)

    scan = query.first()
    # The scan's own organisation, read from the stored row, decides the rest: the
    # account must be allowed to act there, and holds read_all for it or started
    # the scan (RBAC-5; a client-supplied organisation id proves nothing).
    if (
        not scan
        or not platform_api.resource_organisation_allowed(user, scan.org_id)
        or (
            str(scan.created_by) != str(user.id)
            and not user_can_read_all_scans(user, db, scan.org_id)
        )
    ):
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan
