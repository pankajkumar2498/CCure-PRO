"""
routers/topology.py
───────────────────
API routes for network topology map data.

Endpoints:
  GET /topology/map           → Full org-wide topology graph
  GET /topology/map/{scan_id} → Scan-specific topology graph
"""

import logging

from auth.rbac import require_permission
from db.base import get_db
from db.models import Scan, User
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

log = logging.getLogger("ccure.api.topology")

router = APIRouter(tags=["Network Topology"])

#: Roles allowed to read any scan in their organization.
_ORG_WIDE_ROLES = {"superadmin", "org_admin"}


def _role_name(user: User) -> str:
    return (getattr(getattr(user, "role", None), "name", "") or "").lower()


def _resolve_org(user: User, requested_org: str | None) -> str:
    """Resolve org_id: superadmins can override, others use their own."""
    if _role_name(user) == "superadmin" and requested_org:
        return requested_org
    return str(user.org_id)


def _authorize_scan(db: Session, user: User, scan_id: str, resolved_org: str) -> None:
    """
    Confirm the caller may read this scan's topology.

    Both endpoints enforced this independently; keeping one implementation means
    a change to the rules cannot land on only one of them.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if str(scan.org_id) != resolved_org:
        raise HTTPException(
            status_code=403, detail="Access denied to this scan's organization"
        )

    if _role_name(user) not in _ORG_WIDE_ROLES and str(scan.created_by) != str(user.id):
        raise HTTPException(status_code=403, detail="Access denied to this scan")


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
    user: User = Depends(require_permission("scans", "read")),
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
    subnet_mask: int = _SUBNET_MASK_QUERY,
    active_within_days: int | None = _ACTIVE_WITHIN_QUERY,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("scans", "read")),
):
    """
    Return the network topology graph for a specific scan.
    Convenience wrapper around GET /topology/map?scan_id=...
    """
    resolved_org = _resolve_org(user, None)
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
