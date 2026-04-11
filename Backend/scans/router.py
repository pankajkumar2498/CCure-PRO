"""
scans/router.py
---------------
REST endpoints for scan history.

    GET    /scans            → list current user's scans (newest first)
    GET    /scans/{id}       → full detail of one scan (includes all phase results)
    DELETE /scans/{id}       → delete a scan (must belong to current user)
"""

import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from auth.models import get_db
from auth.dependencies import get_current_user
from auth.models import User
from scans.models import Scan

router = APIRouter(prefix="/scans", tags=["Scan History"])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _as_utc_iso(dt: Optional[datetime]) -> Optional[str]:
    """Return a UTC ISO-8601 timestamp with trailing Z for correct client parsing."""
    if not dt:
        return None
    return f"{dt.isoformat()}Z"


def _load_phase_results(scan: Scan) -> dict:
    if getattr(scan, "phase_results", None):
        results = {}
        for phase_row in scan.phase_results:
            payload = _load_json(phase_row.payload)
            if payload:
                results[phase_row.phase_key] = payload
        if results:
            return results
    return _load_json(scan.results)


def _scan_to_dict(scan: Scan, include_results: bool = False) -> dict:
    """Serialize a Scan row to a JSON-safe dict."""
    d = {
        "id":            scan.id,
        "target":        scan.target,
        "targets":       _load_json(scan.targets_json),
        "scan_type":     scan.scan_type,
        "phase":         scan.phase,
        "status":        scan.status,
        "scan_duration": scan.scan_duration,
        "created_at":    _as_utc_iso(scan.created_at),
        "updated_at":    _as_utc_iso(scan.updated_at),
        "is_archived":   bool(scan.is_archived),
        "archived_at":   _as_utc_iso(scan.archived_at),
        "is_deleted":    bool(scan.is_deleted),
        "deleted_at":    _as_utc_iso(scan.deleted_at),
        "summary":       _load_json(scan.summary),
    }
    if include_results:
        d["results"] = _load_phase_results(scan)
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
    scope: str = Query("active"),
    db:    Session = Depends(get_db),
    user:  User    = Depends(get_current_user),
):
    """
    Return the current user's scan history, archived scans, or recycle-bin entries.
    Does NOT include full results blob (use GET /scans/{id} for that).
    """
    query = db.query(Scan).filter(Scan.user_id == user.id)

    if scope == "active":
        query = query.filter(Scan.is_deleted.is_(False), Scan.is_archived.is_(False))
    elif scope == "archived":
        query = query.filter(Scan.is_deleted.is_(False), Scan.is_archived.is_(True))
    elif scope == "deleted":
        query = query.filter(Scan.is_deleted.is_(True))
    elif scope != "all":
        raise HTTPException(status_code=400, detail="Invalid scope. Use active, archived, deleted, or all.")

    order_by = [Scan.created_at.desc()]
    if scope == "archived":
        order_by = [Scan.archived_at.desc(), Scan.created_at.desc()]
    if scope == "deleted":
        order_by = [Scan.deleted_at.desc(), Scan.created_at.desc()]

    scans = (
        query
        .order_by(*order_by)
        .offset(skip)
        .limit(limit)
        .all()
    )
    total = query.count()

    return {
        "scope": scope,
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


@router.post("/{scan_id}/archive")
def archive_scan(
    scan_id: int,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """Archive a scan so it is hidden from My Scan Jobs."""
    scan = _get_scan_or_404(scan_id, user.id, db)
    if scan.is_deleted:
        raise HTTPException(status_code=400, detail="Cannot archive a scan from the recycle bin.")
    if scan.is_archived:
        return {
            "detail": f"Scan {scan_id} is already archived",
            "archived": False,
        }

    scan.is_archived = True
    scan.archived_at = datetime.utcnow()
    scan.updated_at = datetime.utcnow()
    db.add(scan)
    db.commit()
    return {
        "detail": f"Scan {scan_id} archived",
        "archived": True,
    }


@router.post("/{scan_id}/restore")
def restore_scan(
    scan_id: int,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """Restore an archived scan back to My Scan Jobs."""
    scan = _get_scan_or_404(scan_id, user.id, db)
    if scan.is_deleted:
        scan.is_deleted = False
        scan.deleted_at = None
        scan.updated_at = datetime.utcnow()
        db.add(scan)
        db.commit()
        destination = "Archived Scans" if scan.is_archived else "My Scan Jobs"
        return {
            "detail": f"Scan {scan_id} restored to {destination}",
            "restored": True,
            "destination": "archived" if scan.is_archived else "active",
        }

    if not scan.is_archived:
        return {
            "detail": f"Scan {scan_id} is already in My Scan Jobs",
            "restored": False,
            "destination": "active",
        }

    scan.is_archived = False
    scan.archived_at = None
    scan.updated_at = datetime.utcnow()
    db.add(scan)
    db.commit()
    return {
        "detail": f"Scan {scan_id} restored to My Scan Jobs",
        "restored": True,
        "destination": "active",
    }


@router.delete("/{scan_id}")
def delete_scan(
    scan_id: int,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """Move a scan that belongs to the current user into the recycle bin."""
    scan = _get_scan_or_404(scan_id, user.id, db)
    if scan.is_deleted:
        return {
            "detail": f"Scan {scan_id} is already in the recycle bin",
            "moved_to_recycle_bin": False,
        }

    scan.is_deleted = True
    scan.deleted_at = datetime.utcnow()
    scan.updated_at = datetime.utcnow()
    db.add(scan)
    db.commit()
    return {
        "detail": f"Scan {scan_id} moved to recycle bin",
        "moved_to_recycle_bin": True,
    }


@router.delete("/{scan_id}/purge")
def purge_scan(
    scan_id: int,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """Permanently delete a scan that is already in the recycle bin."""
    scan = _get_scan_or_404(scan_id, user.id, db)
    if not scan.is_deleted:
        raise HTTPException(
            status_code=400,
            detail="Move the scan to the recycle bin before permanently deleting it.",
        )

    db.delete(scan)
    db.commit()
    return {"detail": f"Scan {scan_id} permanently deleted"}
