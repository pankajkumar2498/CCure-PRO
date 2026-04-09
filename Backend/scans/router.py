"""
scans/router.py
---------------
REST endpoints for scan history.

    GET    /scans            → list current user's scans (newest first)
    GET    /scans/{id}       → full detail of one scan (includes all phase results)
    DELETE /scans/{id}       → delete a scan (must belong to current user)
"""

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from auth.models import get_db
from auth.dependencies import get_current_user
from auth.models import User
from scans.models import Scan

router = APIRouter(prefix="/scans", tags=["Scan History"])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _scan_to_dict(scan: Scan, include_results: bool = False) -> dict:
    """Serialize a Scan row to a JSON-safe dict."""
    d = {
        "id":            scan.id,
        "target":        scan.target,
        "scan_type":     scan.scan_type,
        "phase":         scan.phase,
        "status":        scan.status,
        "scan_duration": scan.scan_duration,
        "created_at":    scan.created_at.isoformat(),
        "updated_at":    scan.updated_at.isoformat(),
        "summary":       _load_json(scan.summary),
    }
    if include_results:
        d["results"] = _load_json(scan.results)
    return d


def _load_json(text: str) -> dict:
    try:
        return json.loads(text or "{}")
    except Exception:
        return {}


def _get_scan_or_404(scan_id: int, user_id: int, db: Session) -> Scan:
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
def list_scans(
    skip:  int = Query(0,  ge=0),
    limit: int = Query(50, ge=1, le=200),
    db:    Session = Depends(get_db),
    user:  User    = Depends(get_current_user),
):
    """
    Return the current user's scan history, newest first.
    Does NOT include full results blob (use GET /scans/{id} for that).
    """
    scans = (
        db.query(Scan)
        .filter(Scan.user_id == user.id)
        .order_by(Scan.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    total = db.query(Scan).filter(Scan.user_id == user.id).count()

    return {
        "total": total,
        "scans": [_scan_to_dict(s) for s in scans],
    }


@router.get("/{scan_id}")
def get_scan(
    scan_id: int,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """Return full detail of one scan including all phase results."""
    scan = _get_scan_or_404(scan_id, user.id, db)
    return _scan_to_dict(scan, include_results=True)


@router.delete("/{scan_id}")
def delete_scan(
    scan_id: int,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """Delete a scan that belongs to the current user."""
    scan = _get_scan_or_404(scan_id, user.id, db)
    db.delete(scan)
    db.commit()
    return {"detail": f"Scan {scan_id} deleted"}
