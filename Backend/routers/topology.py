"""
routers/topology.py
───────────────────
API routes for network topology map data.

Endpoints:
  GET /topology/map           → Full org-wide topology graph
  GET /topology/map/{scan_id} → Scan-specific topology graph
"""

import logging

from ccure_platform.api import (
    CurrentUser,
    has_permission,
    require_authorized,
    resolve_active_organisation,
)
from db.base import get_db
from db.models import Scan
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

log = logging.getLogger("ccure.api.topology")

router = APIRouter(tags=["Network Topology"])


def _resolve_org(user: CurrentUser, requested_org: str | None) -> str:
    # Scope is decided by the platform (RBAC-5): a client-named organisation is a
    # request, honoured only with cross-organisation reach and an active target.
    return resolve_active_organisation(user, requested_org)


def _can_read_all(db: Session, user: CurrentUser, org_id: str) -> bool:
    """``audit.scan.read_all`` *in that organisation* — organisation-wide
    visibility, never cross-organisation reach."""
    return has_permission(db, user, "audit.scan.read_all", org_id=org_id)


def _authorize_scan(
    db: Session, user: CurrentUser, scan_id: str, resolved_org: str
) -> None:
    """404 for an unknown scan, 403 for another organisation's, and 403 for a
    colleague's scan unless the account holds ``audit.scan.read_all`` there."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if str(scan.org_id) != resolved_org:
        raise HTTPException(
            status_code=403, detail="Access denied to this scan's organization"
        )

    if str(scan.created_by) != str(user.id) and not _can_read_all(
        db, user, resolved_org
    ):
        raise HTTPException(status_code=403, detail="Access denied to this scan")


def _authorize_organisation_map(
    db: Session, user: CurrentUser, resolved_org: str
) -> None:
    """The organisation-wide graph merges links from every user's scans, so it is
    a read of all of them: it needs ``audit.scan.read_all`` in that organisation."""
    if not _can_read_all(db, user, resolved_org):
        raise HTTPException(
            status_code=403,
            detail="The organisation-wide map needs permission to view every "
            "scan in the organisation; request a specific scan instead.",
        )


_SUBNET_MASK_QUERY = Query(
    24,
    ge=8,
    le=30,
    description="Subnet mask size for clustering (e.g. 16, 22, 23, 24)",
)

_ACTIVE_WITHIN_QUERY = Query(
    None,
    ge=1,
    le=365,
    description=(
        "Only include links seen within this many days. Omit to include all "
        "recorded history."
    ),
)


@router.get("/topology/map")
def get_topology_map(
    org_id: str | None = Query(None),
    scan_id: str | None = Query(None, description="Filter by a specific scan ID"),
    subnet_mask: int = _SUBNET_MASK_QUERY,
    active_within_days: int | None = _ACTIVE_WITHIN_QUERY,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.scan.read")),
):
    """
    Return the network topology graph for the organization.

    Response format is vis-network compatible:
    {
        "nodes": [{"id": ..., "label": ..., "group": ..., "tier": ..., "ip": ...,
                   "mac": ..., "asset_id": ...}],
        "edges": [{"from": ..., "to": ..., "label": ..., "link_type": ...,
                   "source_port": ..., "target_port": ...}]
    }
    """
    resolved_org = _resolve_org(user, org_id)

    if scan_id:
        _authorize_scan(db, user, scan_id, resolved_org)
    else:
        _authorize_organisation_map(db, user, resolved_org)

    from core.topology.engine import get_topology_graph

    graph = get_topology_graph(
        db,
        org_id=resolved_org,
        scan_id=scan_id,
        subnet_mask=subnet_mask,
        active_within_days=active_within_days,
    )

    return {"success": True, **graph}


@router.get("/topology/map/{scan_id}")
def get_topology_map_by_scan(
    scan_id: str,
    org_id: str | None = Query(None),
    subnet_mask: int = _SUBNET_MASK_QUERY,
    active_within_days: int | None = _ACTIVE_WITHIN_QUERY,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.scan.read")),
):
    """
    Return the network topology graph for a specific scan.
    Convenience wrapper around GET /topology/map?scan_id=...
    """
    resolved_org = _resolve_org(user, org_id)
    _authorize_scan(db, user, scan_id, resolved_org)

    from core.topology.engine import get_topology_graph

    graph = get_topology_graph(
        db,
        org_id=resolved_org,
        scan_id=scan_id,
        subnet_mask=subnet_mask,
        active_within_days=active_within_days,
    )

    return {"success": True, "scan_id": scan_id, **graph}
