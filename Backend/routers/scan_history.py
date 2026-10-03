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

from auth.jwt_handler import decode_token
from ccure_platform.api import CurrentUser, require_authorized
from db.base import SessionLocal, get_db, utcnow
from ccure_platform import api as platform_api
from db.models import User
from db.models.scans import Scan
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import StreamingResponse

from scan_helpers import limiter
from scans.legacy_json_builder import build_legacy_scan_results
from scans.scan_access import (  # noqa: F401  (the old private names stay)
    get_scan_or_404 as _get_scan_or_404,
    resolve_org as _resolve_org,
    user_can_read_all_scans as _user_can_read_all_scans,
)
from sqlalchemy import func, or_
from sqlalchemy.orm import Session, joinedload

log = logging.getLogger("ccure.scans")
router = APIRouter(prefix="/scans", tags=["Scan History"])

TERMINAL_PHASE_BY_MODE = {
    "basic": 1,
    "asset": 2,
    "vulnerability_audit": 3,
    "credentialed": 3,
}

# 'unreachable' is a terminal outcome Phase 1 sets when every target was down.
# Leaving it out let /stop overwrite a finished scan's real result with
# 'cancelled', destroying the record of what the scan actually found.
TERMINAL_STATUSES = {
    "complete",
    "completed",
    "failed",
    "cancelled",
    "canceled",
    "unreachable",
}


# ── Helpers ───────────────────────────────────────────────────────────────────


def _as_utc_iso(dt: datetime | None) -> str | None:
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
    scan: Scan, db: Session | None = None, include_results: bool = False
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
        # Without this the UI can only say "Failed" — the operator never learns
        # that, say, the target string was unparseable.
        "failure_reason": scan.failure_reason or None,
        "scan_duration": scan.duration_seconds,
        "queued_at": _as_utc_iso(scan.queued_at),
        "started_at": _as_utc_iso(scan.started_at),
        "completed_at": _as_utc_iso(scan.completed_at),
        "created_at": _as_utc_iso(scan.created_at),
        "updated_at": _as_utc_iso(scan.updated_at),
        "is_archived": bool(scan.is_archived),
        "archived_at": _as_utc_iso(scan.archived_at),
        "is_deleted": bool(scan.is_deleted),
        "deleted_at": _as_utc_iso(scan.deleted_at),
        "pipeline_mode": pipeline_mode,
        "has_executive_report": bool(getattr(scan, "report_executive_path", None)),
        "has_technical_report": bool(getattr(scan, "report_technical_path", None)),
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


def _scan_progress_percentage(scan: Scan, pipeline_mode: str) -> int:
    """Return a stable history-list progress value derived from persisted DB state."""
    status = (scan.status or "").lower()
    if status in {"complete", "completed"}:
        return 100
    # An unreachable scan ran to completion — every target simply answered
    # nothing. That is a finished scan, not a partial one.
    if status == "unreachable":
        return 100

    terminal_phase = TERMINAL_PHASE_BY_MODE.get(pipeline_mode, 1)
    # Using phases to calculate phase
    current_phase = scan.phases[-1].phase_order if scan.phases else 0
    phase = max(0, min(current_phase, terminal_phase))
    percentage = int(round((phase / terminal_phase) * 100)) if terminal_phase else 0

    if status == "running":
        return max(8, min(96, percentage))
    # A scan that failed or was cancelled stopped where it stopped. Flooring it
    # at 8% invented progress that never happened.
    if status in TERMINAL_STATUSES:
        return percentage
    return percentage


STATUS_FILTER_ALIASES: dict[str, tuple[str, ...]] = {
    "complete": ("complete", "completed"),
    "completed": ("complete", "completed"),
    "failed": ("failed",),
    "cancelled": ("cancelled", "canceled"),
    "canceled": ("cancelled", "canceled"),
    "unreachable": ("unreachable",),
    "running": ("running", "queued", "pending"),
}

SORTABLE_COLUMNS = {
    "created_at": Scan.created_at,
    "scan_no": Scan.scan_no,
    "status": Scan.status,
    "target": Scan.target_str,
    "duration": Scan.duration_seconds,
    "active_hosts": Scan.active_hosts,
    "pipeline_mode": Scan.pipeline_mode,
}


def _build_scans_query(
    db: Session,
    user: CurrentUser,
    org_id: str,
    scope: str,
    created_by: str | None = None,
    status: str | None = None,
    search: str | None = None,
    pipeline_mode: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    sort_by: str | None = None,
    sort_dir: str = "desc",
):
    query = (
        db.query(Scan)
        .options(joinedload(Scan.created_by_user))
        .filter(Scan.org_id == org_id)
    )

    if created_by:
        if created_by == "me":
            query = query.filter(Scan.created_by == str(user.id))
        elif _user_can_read_all_scans(user, db, org_id):
            query = query.filter(Scan.created_by == created_by)
        else:
            raise HTTPException(
                status_code=403,
                detail="Insufficient privileges to view other users' scans.",
            )
    elif not _user_can_read_all_scans(user, db, org_id):
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

    # ── Filters applied in SQL, not in the browser ────────────────────────────
    # These used to be client-side over whatever the first page returned, so a
    # filter silently searched only the most recent 200 scans.
    if status and status.lower() != "all":
        key = status.strip().lower()
        values = STATUS_FILTER_ALIASES.get(key)
        if values is None:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Invalid status. Use one of: "
                    + ", ".join(sorted(STATUS_FILTER_ALIASES))
                ),
            )
        query = query.filter(func.lower(Scan.status).in_(values))

    if pipeline_mode and pipeline_mode.lower() != "all":
        query = query.filter(func.lower(Scan.pipeline_mode) == pipeline_mode.lower())

    if search:
        needle = f"%{search.strip().lower()}%"
        conditions = [func.lower(Scan.target_str).like(needle)]
        digits = search.strip().lstrip("#")
        if digits.isdigit():
            conditions.append(Scan.scan_no == int(digits))
        query = query.filter(or_(*conditions))

    if date_from:
        query = query.filter(Scan.created_at >= date_from)
    if date_to:
        query = query.filter(Scan.created_at <= date_to)

    # ── Sorting ───────────────────────────────────────────────────────────────
    descending = str(sort_dir or "desc").lower() != "asc"
    if sort_by:
        column = SORTABLE_COLUMNS.get(sort_by.strip().lower())
        if column is None:
            raise HTTPException(
                status_code=400,
                detail="Invalid sort_by. Use one of: "
                + ", ".join(sorted(SORTABLE_COLUMNS)),
            )
        # NULLS LAST in both directions. PostgreSQL sorts NULLs first on DESC,
        # so "longest scans first" led with the failed scans that never recorded
        # a duration at all.
        primary = column.desc().nullslast() if descending else column.asc().nullslast()
        # scan_no breaks ties so pagination stays stable across pages.
        order_by = [primary, Scan.scan_no.desc()]
    else:
        order_by = [Scan.created_at.desc()]
        if scope == "archived":
            order_by = [Scan.archived_at.desc(), Scan.created_at.desc()]
        if scope == "deleted":
            order_by = [Scan.deleted_at.desc(), Scan.created_at.desc()]

    return query, order_by


def _scan_history_snapshot(
    db: Session,
    user: CurrentUser,
    org_id: str,
    scope: str,
    skip: int,
    limit: int,
    created_by: str | None = None,
    status: str | None = None,
    search: str | None = None,
    pipeline_mode: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    sort_by: str | None = None,
    sort_dir: str = "desc",
) -> dict:
    query, order_by = _build_scans_query(
        db,
        user,
        org_id,
        scope,
        created_by,
        status=status,
        search=search,
        pipeline_mode=pipeline_mode,
        date_from=date_from,
        date_to=date_to,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )
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
        "skip": skip,
        "limit": limit,
        "scans": rows,
        "version": "|".join(version_parts),
        "emitted_at": _as_utc_iso(utcnow()),
    }


def _get_websocket_user(websocket: WebSocket) -> CurrentUser:
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
        user = db.query(User).filter(User.id == str(user_id)).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found.")

        if not platform_api.has_permission(db, user, "audit.scan.read"):
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
    created_by: str | None = Query(None),
    org_id: str | None = Query(None),
    status: str | None = Query(
        None,
        description="all | running | complete | failed | cancelled | unreachable",
    ),
    search: str | None = Query(None, description="Match target text or scan number"),
    pipeline_mode: str | None = Query(
        None, description="basic | asset | vulnerability_audit | credentialed"
    ),
    date_from: datetime | None = Query(None, description="Created at or after (ISO)"),
    date_to: datetime | None = Query(None, description="Created at or before (ISO)"),
    sort_by: str | None = Query(
        None,
        description="created_at | scan_no | status | target | duration | active_hosts | pipeline_mode",
    ),
    sort_dir: str = Query("desc", pattern="^(asc|desc)$"),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.scan.read")),
):
    """
    Return the current user's scan history, archived scans, or recycle-bin entries.

    Filtering, search and sorting run in SQL so they cover the whole history
    rather than whichever page the client happens to be holding.
    Does NOT include full results blob (use GET /scans/{id} for that).
    """
    org = _resolve_org(user, org_id)
    return _scan_history_snapshot(
        db,
        user,
        org,
        scope,
        skip,
        limit,
        created_by,
        status=status,
        search=search,
        pipeline_mode=pipeline_mode,
        date_from=date_from,
        date_to=date_to,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )


@router.get("/events")
async def stream_scan_history(
    request: Request,
    scope: str = Query("active"),
    skip: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=200),
    interval: float = Query(2.0, ge=0.5, le=15.0),
    created_by: str | None = Query(None),
    org_id: str | None = Query(None),
    status: str | None = Query(None),
    search: str | None = Query(None),
    pipeline_mode: str | None = Query(None),
    user: CurrentUser = Depends(require_authorized("audit.scan.read")),
):
    """
    Stream scan history snapshots whenever persisted DB state changes.
    Uses adaptive polling based on active running scans.

    The stream honours the same filters as GET /scans. Without that, a live
    update overwrote the client's filtered list with the unfiltered one, and
    searching appeared to do nothing.
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
                    status,
                    search,
                    pipeline_mode,
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
        if not platform_api.acts_across_organisations(current_user):
            query = query.filter(Scan.org_id == current_user.org_id)
            if not _user_can_read_all_scans(current_user, db, current_user.org_id):
                query = query.filter(Scan.created_by == str(current_user.id))

        scan = query.first()
        if scan:
            # The scan-level status leads, and the phase status only fills in
            # while the scan is still live.
            #
            # Previously this frame was sent *only* when phase rows existed, and
            # carried only `latest_phase.status`. Both halves stranded clients:
            # a scan that failed before creating a phase produced no frame at
            # all, and a scan already settled as failed/cancelled/unreachable
            # reported its last phase's status instead of its own -- so a
            # browser reconnecting to a finished scan was told it was running
            # and sat there until its own client-side timeout.
            scan_status = (scan.status or "").lower()
            latest_phase = (
                sorted(scan.phases, key=lambda p: p.phase_order or 0)[-1]
                if scan.phases
                else None
            )
            latest_summary = (
                _public_summary(latest_phase.summary) if latest_phase else {}
            )
            status = (
                scan_status
                if scan_status in TERMINAL_STATUSES
                else (latest_phase.status if latest_phase else scan_status)
            )
            await websocket.send_json(
                {
                    "scan_id": scan_id,
                    "phase": latest_phase.phase_order if latest_phase else 1,
                    "progress": {
                        "status": status,
                        "scan_status": scan_status,
                        "reason": scan.failure_reason or None,
                        "error": scan.failure_reason or None,
                        "summary": latest_summary,
                        # Include enough data to satisfy frontend checks
                        "discovered": (
                            latest_phase.hosts_processed if latest_phase else 0
                        ),
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
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.scan.read")),
):
    """Return full detail of one scan including all phase results."""
    scan = _get_scan_or_404(scan_id, user, db, org_id)
    return _scan_to_dict(scan, db=db, include_results=True)


@router.get("/{scan_id}/policy")
@limiter.limit("60/minute")
def scan_policy_record(
    # `request` and `response` are required, not decoration -- see the
    # comparison route below for why a handler returning a dict must declare
    # them or slowapi raises on every call.
    request: Request,
    response: Response,
    scan_id: str,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.scan.read")),
):
    """
    The assessment configuration this scan actually ran under.

    Read from the scan's own immutable snapshot, **not** from the policy row it
    names. That is the whole point: the policy may have been edited, versioned,
    archived or deleted since, and none of that changes what this scan
    assessed. A question an auditor asks about a scan has to be answerable from
    the scan.

    ``recorded: false`` is a real answer for a scan that predates GAP-12, and
    it is not turned into a default policy — inventing a configuration record
    would put a claim in front of an auditor that nothing supports.

    Tenant scoping is ``_get_scan_or_404``'s, the same lookup every other scan
    route uses, so another organisation's scan answers 404 rather than
    disclosing its configuration.
    """
    from core.findings.comparison import policy_context

    scan = _get_scan_or_404(scan_id, user, db, org_id)
    context = policy_context(scan)

    payload = {
        "scan_id": str(scan.id),
        "scan_no": scan.scan_no,
        "pipeline_mode": scan.pipeline_mode,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "policy": context,
    }

    if context.get("recorded"):
        from core.scan_policy import read_policy_snapshot

        effective = read_policy_snapshot(scan)
        # The full effective configuration, field by field, so a client can
        # diff two scans without re-deriving anything.
        payload["effective"] = effective.as_dict() if effective else {}

        # Whether the policy that produced this scan still exists and still
        # says the same thing. Reported, never used to change the record: a
        # policy edited since is exactly the case the snapshot exists for, and
        # this is how a reader learns the two have diverged.
        if effective and effective.policy_id:
            from db.models.scan_policies import ScanPolicy
            from core.scan_policy.spec import effective_from_config

            row = (
                db.query(ScanPolicy)
                .filter(
                    ScanPolicy.id == effective.policy_id,
                    ScanPolicy.org_id == scan.org_id,
                )
                .first()
            )
            if row is None:
                payload["policy_current_state"] = {
                    "exists": False,
                    "matches_snapshot": False,
                    "note": (
                        "The policy that produced this scan has since been "
                        "deleted. The configuration above is unaffected."
                    ),
                }
            else:
                live = effective_from_config(
                    row.config or {},
                    policy_id=str(row.id),
                    policy_name=str(row.name or ""),
                    policy_family_code=str(row.policy_family_code or ""),
                    version_number=int(row.version_number or 1),
                    scan_kind=str(row.scan_kind or "any"),
                )
                same = live.fingerprint() == effective.fingerprint()
                payload["policy_current_state"] = {
                    "exists": True,
                    "name": row.name,
                    "status": row.status,
                    "is_enabled": row.is_enabled,
                    "version_number": row.version_number,
                    "fingerprint": live.fingerprint(),
                    "matches_snapshot": same,
                    "note": (
                        None
                        if same
                        else (
                            "The policy has been edited since this scan ran. "
                            "The configuration above is what this scan used."
                        )
                    ),
                }

    return payload


@router.get("/{scan_id}/comparison")
@limiter.limit("30/minute")
def compare_scan(
    # `request` and `response` are required, not decoration. The limiter is
    # built headers_enabled=True and writes X-RateLimit-* after the handler
    # returns; with neither a returned Response nor a declared one it hands
    # slowapi None and every request to this route raises. CLAUDE.md records
    # twenty-one routes that shipped in exactly that state.
    request: Request,
    response: Response,
    scan_id: str,
    baseline: str | None = Query(
        None,
        description=(
            "Scan to compare against. Defaults to the most recent completed "
            "scan of the same pipeline_mode in this organisation."
        ),
    ),
    asset_id: list[str] | None = Query(None),
    severity: list[str] | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
    include_findings: bool = Query(True),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.scan.read")),
):
    """
    What changed between this scan and a baseline.

    Both scans are fetched through ``_get_scan_or_404``, so the organisation
    scoping and the per-user visibility rule that govern every other scan route
    govern this one too — a caller cannot compare against a scan they could not
    read, and cannot reach another tenant's findings by naming its id.

    ``limit`` bounds the returned rows, never the counts: an estate with
    thousands of findings on one host still gets accurate totals, and the list
    is the sample. That split is deliberate — a truncated count would be a
    wrong number rather than a short page.
    """
    from core.findings import compare_scans
    from core.findings.comparison import previous_scan_for

    current = _get_scan_or_404(scan_id, user, db, org_id)

    if baseline:
        baseline_scan = _get_scan_or_404(baseline, user, db, org_id)
    else:
        baseline_scan = previous_scan_for(db, current)
        if baseline_scan is None:
            # A first scan has nothing to be compared with. That is an answer,
            # not an error: the caller gets the shape it expects with the
            # reason filled in, so a report can render "no baseline" rather
            # than a failure.
            return {
                "current_scan_id": str(current.id),
                "baseline_scan_id": None,
                "comparable": False,
                "reason": (
                    "no earlier completed scan of the same kind exists for this "
                    "organisation, so there is nothing to compare against"
                ),
                "summary": "",
                "counts": {},
                "severity_counts": {},
                "assets": [],
                "findings": [],
            }

    comparison = compare_scans(
        db,
        current=current,
        baseline=baseline_scan,
        asset_ids=asset_id,
        severities=severity,
        limit_findings=limit,
    )
    return comparison.as_dict(include_findings=include_findings)


@router.post("/{scan_id}/archive")
def archive_scan(
    scan_id: str,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.scan.lifecycle")),
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
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.scan.run")),
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
    stopped_at = utcnow()
    scan.status = "cancelled"
    scan.updated_at = stopped_at

    # Stamp the stop time here rather than relying on the worker to settle it.
    # The task is revoked immediately below, so it may never reach its own
    # cancellation checkpoint — which left cancelled scans with a duration but
    # no completed_at, and nothing to show for "when did this stop?".
    if not scan.completed_at:
        scan.completed_at = stopped_at
    if scan.started_at and scan.duration_seconds is None:
        scan.duration_seconds = (scan.completed_at - scan.started_at).total_seconds()

    # Mark all non-terminal phases as cancelled
    for phase in scan.phases:
        if phase.status not in ("complete", "failed", "skipped", "cancelled"):
            phase.status = "cancelled"
            phase.completed_at = stopped_at
            if phase.started_at and phase.duration_seconds is None:
                phase.duration_seconds = (
                    phase.completed_at - phase.started_at
                ).total_seconds()

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

    # Tell anyone watching the live scan screen. `revoke()` cannot reach a
    # running thread on the `--pool=threads` host worker, so the task may keep
    # going until its next cooperative cancellation checkpoint -- and until
    # then nothing else would tell the browser the scan is over. Without this
    # frame the operator presses Stop, sees the scan carry on, and presses it
    # again.
    try:
        from core.redis_client import publish_progress_sync

        publish_progress_sync(
            scan_id,
            1,
            {
                "status": "cancelled",
                "reason": "Scan cancelled by user.",
            },
        )
    except Exception:
        log.debug("Could not publish cancellation for %s", scan_id, exc_info=True)

    log.info("Scan %s stopped by user %s", scan_id, user.id)
    return {"detail": f"Scan {scan_id} stopped", "stopped": True}


@router.post("/{scan_id}/restore")
def restore_scan(
    scan_id: str,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.scan.lifecycle")),
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
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.scan.lifecycle")),
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
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.scan.purge")),
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
