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

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session, joinedload

from auth.jwt_handler import decode_token
from auth.rbac import require_permission
from db.base import get_db, SessionLocal, utcnow
from db.models import User, RolePermission, Permission
from db.models.scans import Scan
from scans.legacy_json_builder import build_legacy_scan_results

log = logging.getLogger("ccure.scans")
router = APIRouter(prefix="/scans", tags=["Scan History"])

TERMINAL_PHASE_BY_MODE = {
    "basic": 1,
    "asset": 2,
    "vulnerability_audit": 3,
}

TERMINAL_STATUSES = {"complete", "completed", "failed", "cancelled", "canceled"}


# ── Helpers ───────────────────────────────────────────────────────────────────


def _is_superadmin(user: User) -> bool:
    return (
        getattr(getattr(user, "role", None), "name", "") or ""
    ).lower() == "superadmin"


def _resolve_org(user: User, requested_org: Optional[str]) -> str:
    if _is_superadmin(user) and requested_org:
        return requested_org
    return str(user.org_id)


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


def _public_summary(summary: dict) -> dict:
    if not isinstance(summary, dict):
        return {}
    return {
        key: value for key, value in summary.items() if not str(key).startswith("_")
    }


def _scan_summary(scan: Scan) -> dict:
    if not scan.phases:
        return {}
    summary: dict = {}
    for phase in sorted(scan.phases, key=lambda p: p.phase_order or 0):
        if isinstance(phase.summary, dict):
            summary.update(_public_summary(phase.summary))
    return summary


def _scan_to_dict(
    scan: Scan, db: Optional[Session] = None, include_results: bool = False
) -> dict:
    """Serialize a Scan row to a JSON-safe dict."""
    pipeline_mode = getattr(scan, "pipeline_mode", "basic") or "basic"
    creator = getattr(scan, "created_by_user", None)
    creator_username = getattr(creator, "username", None)
    creator_full_name = getattr(creator, "full_name", None)
    creator_role = getattr(getattr(creator, "role", None), "name", None)

    d = {
        "id": str(scan.id),
        "scan_no": scan.scan_no,
        "display_id": scan.scan_no,
        "target": scan.target_str,
        "targets": scan.target_hosts or [],
        "scan_type": scan.scan_type,
        "phase": scan.phases[-1].phase_order if scan.phases else 1,
        "status": scan.status,
        "scan_duration": scan.duration_seconds,
        "created_at": _as_utc_iso(scan.created_at),
        "updated_at": _as_utc_iso(scan.updated_at),
        "is_archived": bool(scan.is_archived),
        "archived_at": _as_utc_iso(scan.archived_at),
        "is_deleted": bool(scan.is_deleted),
        "deleted_at": _as_utc_iso(scan.deleted_at),
        "pipeline_mode": pipeline_mode,
        "has_json_report": bool(getattr(scan, "report_json_path", None)),
        "has_xml_report": bool(getattr(scan, "report_xml_path", None)),
        "summary": _scan_summary(scan),
        "created_by": str(scan.created_by) if scan.created_by else None,
        "started_by": {
            "user_id": str(scan.created_by) if scan.created_by else None,
            "username": creator_username,
            "full_name": creator_full_name,
            "display_name": creator_full_name or creator_username,
            "role": creator_role,
        },
    }
    d["progress_percentage"] = _scan_progress_percentage(scan, pipeline_mode)
    if include_results and db:
        d["results"] = _load_phase_results(db, scan)
    return d


def _user_can_read_all_scans(user: User, db: Session) -> bool:
    if getattr(getattr(user, "role", None), "name", "").lower() == "superadmin":
        return True

    return (
        db.query(RolePermission)
        .join(Permission, Permission.id == RolePermission.permission_id)
        .filter(
            RolePermission.role_id == user.role_id,
            Permission.resource == "scans",
            Permission.action == "read_all",
        )
        .first()
    ) is not None


def _get_scan_or_404(
    scan_id: str, user: User, db: Session, org_id: Optional[str] = None
) -> Scan:
    target_org_id = _resolve_org(user, org_id)
    query = (
        db.query(Scan)
        .options(joinedload(Scan.created_by_user))
        .filter(Scan.id == scan_id, Scan.org_id == target_org_id)
    )
    if not _user_can_read_all_scans(user, db):
        query = query.filter(Scan.created_by == str(user.id))

    scan = query.first()
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


def _build_scans_query(
    db: Session, user: User, org_id: str, scope: str, created_by: Optional[str] = None
):
    query = (
        db.query(Scan)
        .options(joinedload(Scan.created_by_user))
        .filter(Scan.org_id == org_id)
    )

    if created_by:
        if created_by == "me":
            query = query.filter(Scan.created_by == str(user.id))
        elif _user_can_read_all_scans(user, db):
            query = query.filter(Scan.created_by == created_by)
        else:
            raise HTTPException(
                status_code=403,
                detail="Insufficient privileges to view other users' scans.",
            )
    elif not _user_can_read_all_scans(user, db):
        query = query.filter(Scan.created_by == str(user.id))

    if scope == "active":
        query = query.filter(Scan.is_deleted.is_(False), Scan.is_archived.is_(False))
    elif scope == "archived":
        query = query.filter(Scan.is_deleted.is_(False), Scan.is_archived.is_(True))
    elif scope == "deleted":
        query = query.filter(Scan.is_deleted.is_(True))
    elif scope != "all":
        raise HTTPException(
            status_code=400,
            detail="Invalid scope. Use active, archived, deleted, or all.",
        )

    order_by = [Scan.created_at.desc()]
    if scope == "archived":
        order_by = [Scan.archived_at.desc(), Scan.created_at.desc()]
    if scope == "deleted":
        order_by = [Scan.deleted_at.desc(), Scan.created_at.desc()]

    return query, order_by


def _scan_history_snapshot(
    db: Session,
    user: User,
    org_id: str,
    scope: str,
    skip: int,
    limit: int,
    created_by: Optional[str] = None,
) -> dict:
    query, order_by = _build_scans_query(db, user, org_id, scope, created_by)
    scans = query.order_by(*order_by).offset(skip).limit(limit).all()
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


def _get_websocket_user(websocket: WebSocket) -> User:
    ticket = websocket.query_params.get("ticket")

    if not ticket:
        raise HTTPException(
            status_code=401,
            detail="Authentication ticket is required for WebSocket connections.",
        )

    payload = decode_token(ticket)
    if not payload:
        raise HTTPException(
            status_code=401, detail="Invalid or expired authentication."
        )

    token_type = payload.get("type")
    if token_type != "ticket":
        raise HTTPException(
            status_code=401, detail="Unsupported token type for WebSocket."
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload.")

    db = SessionLocal()
    try:
        user = (
            db.query(User)
            .options(joinedload(User.role))
            .filter(User.id == str(user_id))
            .first()
        )
        if not user:
            raise HTTPException(status_code=401, detail="User not found.")

        if getattr(user.role, "name", "").lower() != "superadmin":
            has_perm = (
                db.query(RolePermission)
                .join(Permission, Permission.id == RolePermission.permission_id)
                .filter(
                    RolePermission.role_id == user.role_id,
                    Permission.resource == "scans",
                    Permission.action == "read",
                )
                .first()
            ) is not None
            if not has_perm:
                raise HTTPException(status_code=403, detail="Insufficient privileges.")

        return user
    finally:
        db.close()


def _format_sse(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, separators=(',', ':'))}\n\n"


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("")
def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    scope: str = Query("active"),
    created_by: Optional[str] = Query(None),
    org_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("scans", "read")),
):
    """
    Return the current user's scan history, archived scans, or recycle-bin entries.
    Does NOT include full results blob (use GET /scans/{id} for that).
    """
    org = _resolve_org(user, org_id)
    return _scan_history_snapshot(db, user, org, scope, skip, limit, created_by)


@router.get("/events")
async def stream_scan_history(
    request: Request,
    scope: str = Query("active"),
    skip: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=200),
    interval: float = Query(2.0, ge=0.5, le=15.0),
    created_by: Optional[str] = Query(None),
    org_id: Optional[str] = Query(None),
    user: User = Depends(require_permission("scans", "read")),
):
    """
    Stream scan history snapshots whenever persisted DB state changes.
    Uses adaptive polling based on active running scans.
    """
    if scope not in {"active", "archived", "deleted", "all"}:
        raise HTTPException(
            status_code=400,
            detail="Invalid scope. Use active, archived, deleted, or all.",
        )

    org = _resolve_org(user, org_id)

    async def event_generator():
        last_version = None
        yield _format_sse("connected", {"ok": True, "scope": scope})

        while True:
            db = SessionLocal()
            try:
                snapshot = await asyncio.to_thread(
                    _scan_history_snapshot,
                    db,
                    user,
                    org,
                    scope,
                    skip,
                    limit,
                    created_by,
                )
            finally:
                db.close()

            has_running_scans = any(
                s.get("status") == "running" for s in snapshot.get("scans", [])
            )
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
    try:
        current_user = _get_websocket_user(websocket)
    except HTTPException:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    # 1. Send current status from DB immediately
    db = SessionLocal()
    try:
        query = db.query(Scan).filter(Scan.id == scan_id)
        if getattr(current_user.role, "name", "").lower() != "superadmin":
            query = query.filter(Scan.org_id == current_user.org_id)
            if not _user_can_read_all_scans(current_user, db):
                query = query.filter(Scan.created_by == str(current_user.id))

        scan = query.first()
        if scan and scan.phases:
            # Send status of the most recent phase
            latest_phase = sorted(scan.phases, key=lambda p: p.phase_order or 0)[-1]
            latest_summary = _public_summary(latest_phase.summary)
            await websocket.send_json(
                {
                    "scan_id": scan_id,
                    "phase": latest_phase.phase_order,
                    "progress": {
                        "status": latest_phase.status,
                        "summary": latest_summary,
                        # Include enough data to satisfy frontend checks
                        "discovered": latest_phase.hosts_processed,
                        "total_ips": latest_summary.get("total_hosts", 0),
                    },
                }
            )
    finally:
        db.close()

    from core.redis_client import redis_client

    pubsub = redis_client.pubsub()
    await pubsub.subscribe(f"scan_progress:{scan_id}")

    log.info(
        "[TRACE][WS][%s] WS Subscribed to Redis for scan %s",
        datetime.now().isoformat(),
        scan_id,
    )
    try:
        while True:
            # Reduce timeout and sleep for higher responsiveness
            message = await pubsub.get_message(
                ignore_subscribe_messages=True, timeout=0.1
            )
            if message:
                data = json.loads(message["data"])
                log.info(
                    "[TRACE][WS][%s] WS Relaying message for scan %s, phase %d, status %s",
                    datetime.now().isoformat(),
                    scan_id,
                    data.get("phase"),
                    data.get("progress", {}).get("status"),
                )
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
    org_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("scans", "read")),
):
    """Return full detail of one scan including all phase results."""
    scan = _get_scan_or_404(scan_id, user, db, org_id)
    return _scan_to_dict(scan, db=db, include_results=True)


@router.post("/{scan_id}/archive")
def archive_scan(
    scan_id: str,
    org_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("scans", "archive")),
):
    """Archive a scan so it is hidden from My Scan Jobs."""
    scan = _get_scan_or_404(scan_id, user, db, org_id)
    if scan.is_deleted:
        raise HTTPException(
            status_code=400, detail="Cannot archive a scan from the recycle bin."
        )
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


@router.post("/{scan_id}/stop")
def stop_scan(
    scan_id: str,
    org_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("scans", "execute")),
):
    """
    Terminates an active scan session.
    Marks the scan and any active phases as 'cancelled'.
    Also revokes the active Celery task.
    """
    scan = _get_scan_or_404(scan_id, user, db, org_id)
    if scan.status in TERMINAL_STATUSES:
        return {
            "detail": f"Scan {scan_id} is already in a terminal state ({scan.status})",
            "stopped": False,
        }

    # 1. Update DB Status
    scan.status = "cancelled"
    scan.updated_at = utcnow()

    # Mark all non-terminal phases as cancelled
    for phase in scan.phases:
        if phase.status not in ("complete", "failed", "skipped", "cancelled"):
            phase.status = "cancelled"
            phase.completed_at = utcnow()

    # 2. Revoke Celery Task
    if scan.current_task_id:
        try:
            from core.celery_app import celery_app

            # On Windows, terminate=True might not work for all pool types,
            # but revoke() will at least prevent the task from starting if it's queued.
            # We omit the signal param to use the OS default (SIGTERM on Linux, N/A on Windows).
            celery_app.control.revoke(scan.current_task_id, terminate=True)
            log.info("Revoked task %s for scan %s", scan.current_task_id, scan_id)
        except Exception as e:
            log.error("Failed to revoke task %s: %s", scan.current_task_id, e)

    db.add(scan)
    db.commit()
    log.info("Scan %s stopped by user %s", scan_id, user.id)
    return {"detail": f"Scan {scan_id} stopped", "stopped": True}


@router.post("/{scan_id}/restore")
def restore_scan(
    scan_id: str,
    org_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("scans", "restore")),
):
    """Restore an archived scan back to My Scan Jobs."""
    scan = _get_scan_or_404(scan_id, user, db, org_id)
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
    org_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("scans", "recycle")),
):
    """Move a scan that belongs to the current user into the recycle bin."""
    scan = _get_scan_or_404(scan_id, user, db, org_id)
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
    org_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("scans", "purge")),
):
    """Permanently delete a scan that is already in the recycle bin."""
    scan = _get_scan_or_404(scan_id, user, db, org_id)
    if not scan.is_deleted:
        raise HTTPException(
            status_code=400,
            detail="Move the scan to the recycle bin before permanently deleting it.",
        )

    db.delete(scan)
    db.commit()
    return {"detail": f"Scan {scan_id} permanently deleted"}
