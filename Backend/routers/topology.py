"""
routers/topology.py
───────────────────
API routes for network topology map data.

Endpoints:
  GET /topology/map           → Full org-wide topology graph
  GET /topology/map/{scan_id} → Scan-specific topology graph
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from db.base import get_db
from db.models import User, Scan
from auth.rbac import require_permission

log = logging.getLogger("ccure.api.topology")

router = APIRouter(tags=["Network Topology"])


def _resolve_org(user: User, requested_org: Optional[str]) -> str:
    """Resolve org_id: superadmins can override, others use their own."""
    role_name = (getattr(getattr(user, "role", None), "name", "") or "").lower()
    if role_name == "superadmin" and requested_org:
        return requested_org
    return str(user.org_id)


@router.get("/topology/map")
def get_topology_map(
    org_id: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None, description="Filter by a specific scan ID"),
    subnet_mask: int = Query(24, ge=8, le=30, description="Subnet mask size for clustering (e.g. 16, 22, 23, 24)"),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("scans", "read")),
):
    """
    Return the network topology graph for the organization.

    Response format is vis-network compatible:
    {
        "nodes": [{"id": ..., "label": ..., "group": ..., "ip": ..., "mac": ..., "asset_id": ...}],
        "edges": [{"from": ..., "to": ..., "label": ..., "link_type": ..., "source_port": ..., "target_port": ...}]
    }
    """
    resolved_org = _resolve_org(user, org_id)

    # Validate scan_id belongs to the org if provided
    if scan_id:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
            
        # Ensure scan belongs to the user's organization
        if str(scan.org_id) != resolved_org:
            raise HTTPException(status_code=403, detail="Access denied to this scan's organization")

        role_name = (getattr(getattr(user, "role", None), "name", "") or "").lower()
        if role_name != "superadmin" and role_name != "org_admin":
            if str(scan.created_by) != str(user.id):
                raise HTTPException(status_code=403, detail="Access denied to this scan")

    from core.topology.engine import get_topology_graph
    graph = get_topology_graph(db, org_id=resolved_org, scan_id=scan_id, subnet_mask=subnet_mask)

    return {
        "success": True,
        **graph,
    }


@router.get("/topology/map/{scan_id}")
def get_topology_map_by_scan(
    scan_id: str,
    subnet_mask: int = Query(24, ge=8, le=30, description="Subnet mask size for clustering (e.g. 16, 22, 23, 24)"),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("scans", "read")),
):
    """
    Return the network topology graph for a specific scan.
    Convenience wrapper around GET /topology/map?scan_id=...
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    resolved_org = _resolve_org(user, None)
    if str(scan.org_id) != resolved_org:
         raise HTTPException(status_code=403, detail="Access denied to this scan's organization")

    role_name = (getattr(getattr(user, "role", None), "name", "") or "").lower()
    if role_name != "superadmin" and role_name != "org_admin":
        if str(scan.created_by) != str(user.id):
            raise HTTPException(status_code=403, detail="Access denied to this scan")

    from core.topology.engine import get_topology_graph
    graph = get_topology_graph(db, org_id=resolved_org, scan_id=scan_id, subnet_mask=subnet_mask)

    return {
        "success": True,
        "scan_id": scan_id,
        **graph,
    }
