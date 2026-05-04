"""
scans/router.py
---------------
REST endpoints for scan history.

    GET    /scans            → list current user's scans (newest first)
    GET    /scans/{id}       → full detail of one scan (includes all phase results)
    DELETE /scans/{id}       → delete a scan (must belong to current user)
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user, get_current_user_flexible
from db.base import get_db, SessionLocal, utcnow
from db.models import User
from db.models.scans import Scan
from scans.legacy_json_builder import build_legacy_scan_results

log = logging.getLogger("ccure.scans")
router = APIRouter(prefix="/scans", tags=["Scan History"])

TERMINAL_PHASE_BY_MODE = {
    "basic": 1,
    "asset": 2,
    "advanced": 3,
}

TERMINAL_STATUSES = {"complete", "completed", "failed", "cancelled", "canceled"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _as_utc_iso(dt: Optional[datetime]) -> Optional[str]:
    """Return a UTC ISO-8601 timestamp with trailing Z for correct client parsing."""
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _load_phase_results(db: Session, scan: Scan) -> dict:
    return build_legacy_scan_results(db, str(scan.id))


def _scan_summary(scan: Scan) -> dict:
    if not scan.phases:
        return {}
    summary: dict = {}
    for phase in sorted(scan.phases, key=lambda p: p.phase_order or 0):
        if isinstance(phase.summary, dict):
            summary.update(phase.summary)
    return summary


def _scan_to_dict(scan: Scan, db: Optional[Session] = None, include_results: bool = False) -> dict:
    """Serialize a Scan row to a JSON-safe dict."""
    pipeline_mode = getattr(scan, "pipeline_mode", "basic") or "basic"
    d = {
        "id":            str(scan.id),
        "scan_no":       scan.scan_no,
        "display_id":    scan.scan_no,
        "target":        scan.target_str,
        "targets":       scan.target_hosts or [],
        "scan_type":     scan.scan_type,
        "phase":         scan.phases[-1].phase_order if scan.phases else 1,
        "status":        scan.status,
        "scan_duration": scan.duration_seconds,
        "created_at":    _as_utc_iso(scan.created_at),
        "updated_at":    _as_utc_iso(scan.updated_at),
        "is_archived":   bool(scan.is_archived),
        "archived_at":   _as_utc_iso(scan.archived_at),
        "is_deleted":    bool(scan.is_deleted),
        "deleted_at":    _as_utc_iso(scan.deleted_at),
        "pipeline_mode": pipeline_mode,
        "has_json_report": bool(getattr(scan, "report_json_path", None)),
        "has_xml_report":  bool(getattr(scan, "report_xml_path", None)),
        "summary":       _scan_summary(scan),
    }
    d["progress_percentage"] = _scan_progress_percentage(scan, pipeline_mode)
    if include_results and db:
        d["results"] = _load_phase_results(db, scan)
    return d


def _get_scan_or_404(scan_id: str, user_id: str, db: Session) -> Scan:
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.created_by == user_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def _scan_progress_percentage(scan: Scan, pipeline_mode: str) -> int:
    """Return a stable history-list progress value derived from persisted DB state."""
    status = (scan.status or "").lower()
    if status in {"complete", "completed"}:
        return 100

    terminal_phase = TERMINAL_PHASE_BY_MODE.get(pipeline_mode, 1)
    # Using phases to calculate phase
    current_phase = scan.phases[-1].phase_order if scan.phases else 0
    phase = max(0, min(current_phase, terminal_phase))
    percentage = int(round((phase / terminal_phase) * 100)) if terminal_phase else 0

    if status == "running":
        return max(8, min(96, percentage))
    if status in TERMINAL_STATUSES:
        return max(percentage, 8)
    return percentage


def _build_scans_query(db: Session, user_id: str, scope: str):
    query = db.query(Scan).filter(Scan.created_by == user_id)

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

    return query, order_by


def _scan_history_snapshot(db: Session, user_id: str, scope: str, skip: int, limit: int) -> dict:
    query, order_by = _build_scans_query(db, user_id, scope)
    scans = (
        query
        .order_by(*order_by)
        .offset(skip)
        .limit(limit)
        .all()
    )
    total = query.count()
    rows = [_scan_to_dict(s) for s in scans]
    version_parts = [
        str(total),
        *[
            f"{row['id']}:{row.get('scan_no')}:{row.get('status')}:{row.get('phase')}:{row.get('updated_at')}:{row.get('progress_percentage')}"
            for row in rows
        ],
    ]

    return {
        "scope": scope,
        "total": total,
        "scans": rows,
        "version": "|".join(version_parts),
        "emitted_at": _as_utc_iso(utcnow()),
    }


def _format_sse(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, separators=(',', ':'))}\n\n"


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
    return _scan_history_snapshot(db, user.id, scope, skip, limit)


@router.get("/events")
async def stream_scan_history(
    request: Request,
    scope: str = Query("active"),
    skip: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=200),
    interval: float = Query(2.0, ge=0.5, le=15.0),
    user: User = Depends(get_current_user_flexible),
):
    """
    Stream scan history snapshots whenever persisted DB state changes.
    Uses adaptive polling based on active running scans.
    """
    if scope not in {"active", "archived", "deleted", "all"}:
        raise HTTPException(status_code=400, detail="Invalid scope. Use active, archived, deleted, or all.")

    user_id = user.id

    async def event_generator():
        last_version = None
        yield _format_sse("connected", {"ok": True, "scope": scope})

        while not await request.is_disconnected():
            db = SessionLocal()
            try:
                snapshot = await asyncio.to_thread(_scan_history_snapshot, db, user_id, scope, skip, limit)
            finally:
                db.close()

            has_running_scans = any(s.get("status") == "running" for s in snapshot.get("scans", []))
            current_interval = 0.5 if has_running_scans else 2.0

            if snapshot["version"] != last_version:
                last_version = snapshot["version"]
                yield _format_sse("scans", snapshot)
            else:
                yield _format_sse("heartbeat", {"emitted_at": _as_utc_iso(utcnow())})

            await asyncio.sleep(current_interval)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.websocket("/{scan_id}/progress")
async def scan_progress_ws(websocket: WebSocket, scan_id: str):
    """
    Real-time progress WebSocket endpoint using Redis PubSub.
    Sends current state immediately on connect to avoid race conditions.
    """
    await websocket.accept()

    # 1. Send current status from DB immediately
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan and scan.phases:
            # Send status of the most recent phase
            latest_phase = sorted(scan.phases, key=lambda p: p.phase_order or 0)[-1]
            await websocket.send_json({
                "scan_id": scan_id,
                "phase": latest_phase.phase_order,
                "progress": {
                    "status": latest_phase.status,
                    "summary": latest_phase.summary,
                    # Include enough data to satisfy frontend checks
                    "discovered": latest_phase.hosts_processed,
                    "total_ips": (latest_phase.summary or {}).get("total_hosts", 0)
                }
            })
    finally:
        db.close()

    from core.redis_client import redis_client
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(f"scan_progress:{scan_id}")
    
    log.info("[TRACE][WS][%s] WS Subscribed to Redis for scan %s", datetime.now().isoformat(), scan_id)
    try:
        while True:
            # Reduce timeout and sleep for higher responsiveness
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=0.1)
            if message:
                data = json.loads(message["data"])
                log.info("[TRACE][WS][%s] WS Relaying message for scan %s, phase %d, status %s", 
                         datetime.now().isoformat(), scan_id, data.get("phase"), data.get("progress", {}).get("status"))
                await websocket.send_json(data)
            else:
                await asyncio.sleep(0.01)
    except WebSocketDisconnect:
        await pubsub.unsubscribe(f"scan_progress:{scan_id}")
    except Exception as e:
        log.error("WebSocket progress error: %s", e)
        await websocket.close(code=1011)


@router.get("/{scan_id}")
def get_scan(
    scan_id: str,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """Return full detail of one scan including all phase results."""
    scan = _get_scan_or_404(scan_id, str(user.id), db)
    return _scan_to_dict(scan, db=db, include_results=True)


@router.post("/{scan_id}/archive")
def archive_scan(
    scan_id: str,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """Archive a scan so it is hidden from My Scan Jobs."""
    scan = _get_scan_or_404(scan_id, str(user.id), db)
    if scan.is_deleted:
        raise HTTPException(status_code=400, detail="Cannot archive a scan from the recycle bin.")
    if scan.is_archived:
        return {
            "detail": f"Scan {scan_id} is already archived",
            "archived": False,
        }

    scan.is_archived = True
    scan.archived_at = utcnow()
    scan.updated_at = utcnow()
    db.add(scan)
    db.commit()
    return {
        "detail": f"Scan {scan_id} archived",
        "archived": True,
    }


@router.post("/{scan_id}/restore")
def restore_scan(
    scan_id: str,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """Restore an archived scan back to My Scan Jobs."""
    scan = _get_scan_or_404(scan_id, str(user.id), db)
    if scan.is_deleted:
        scan.is_deleted = False
        scan.deleted_at = None
        scan.updated_at = utcnow()
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
    scan.updated_at = utcnow()
    db.add(scan)
    db.commit()
    return {
        "detail": f"Scan {scan_id} restored to My Scan Jobs",
        "restored": True,
        "destination": "active",
    }


@router.delete("/{scan_id}")
def delete_scan(
    scan_id: str,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """Move a scan that belongs to the current user into the recycle bin."""
    scan = _get_scan_or_404(scan_id, str(user.id), db)
    if scan.is_deleted:
        return {
            "detail": f"Scan {scan_id} is already in the recycle bin",
            "moved_to_recycle_bin": False,
        }

    scan.is_deleted = True
    scan.deleted_at = utcnow()
    scan.updated_at = utcnow()
    db.add(scan)
    db.commit()
    return {
        "detail": f"Scan {scan_id} moved to recycle bin",
        "moved_to_recycle_bin": True,
    }


@router.delete("/{scan_id}/purge")
def purge_scan(
    scan_id: str,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """Permanently delete a scan that is already in the recycle bin."""
    scan = _get_scan_or_404(scan_id, str(user.id), db)
    if not scan.is_deleted:
        raise HTTPException(
            status_code=400,
            detail="Move the scan to the recycle bin before permanently deleting it.",
        )

    db.delete(scan)
    db.commit()
    return {"detail": f"Scan {scan_id} permanently deleted"}
