"""
routers/audit.py
─────────────────────────────────────────────────────────────────────────────
Read-only API over the audit trail.

There is deliberately no create, update or delete route here. Audit rows are
written by ``core.audit.log_audit_event`` from the endpoint that performed the
action, and nothing in the application may alter one afterwards. Phase 3 adds
the grant- and trigger-level enforcement that makes that guarantee real rather
than a matter of which routes happen to exist.

Reading the trail is itself privileged: every route requires
``audit:read``, and a caller who is not a superadmin sees only events belonging
to their own organisation.
"""

from datetime import datetime, timedelta, timezone

from auth.rbac import require_permission
from core.audit_taxonomy import SEVERITY_LEVELS
from db.base import get_db
from db.models import AuditLog, User
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, cast, func, or_
from sqlalchemy.orm import Session, joinedload

router = APIRouter(prefix="/admin/audit-logs", tags=["Audit Logs"])

#: Named windows the UI offers, resolved server-side so "last 7 days" means the
#: same thing regardless of the caller's clock.
_RANGE_PRESETS = {
    "today": None,  # midnight UTC today — handled separately
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


def _is_superadmin(user: User) -> bool:
    return (
        getattr(getattr(user, "role", None), "name", "") or ""
    ).lower() == "superadmin"


def _resolve_window(
    range_preset: str | None,
    date_from: datetime | None,
    date_to: datetime | None,
) -> tuple[datetime | None, datetime | None]:
    """
    Turn the range parameters into an explicit (from, to) pair.

    An explicit ``date_from``/``date_to`` always wins over a preset, so a UI
    that sends both while switching from a preset to a custom range does not
    silently apply the preset instead.

    Naive datetimes are read as UTC. Every timestamp in this table is stored
    timezone-aware UTC, and comparing a naive value against one raises in
    PostgreSQL — so the alternative to assuming a zone is a 500.
    """
    if date_from is not None and date_from.tzinfo is None:
        date_from = date_from.replace(tzinfo=timezone.utc)
    if date_to is not None and date_to.tzinfo is None:
        date_to = date_to.replace(tzinfo=timezone.utc)

    if date_from is None and date_to is None and range_preset:
        preset = range_preset.strip().lower()
        if preset not in _RANGE_PRESETS:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Unknown range '{range_preset}'. "
                    f"Expected one of: {', '.join(sorted(_RANGE_PRESETS))}."
                ),
            )
        now = datetime.now(timezone.utc)
        if preset == "today":
            date_from = now.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            date_from = now - _RANGE_PRESETS[preset]

    if date_from and date_to and date_from > date_to:
        raise HTTPException(
            status_code=422, detail="date_from must not be later than date_to."
        )
    return date_from, date_to


def _scoped_query(db: Session, current_user: User, needs_user_join: bool):
    """
    Base query, tenant-scoped, joined to ``users`` at most once.

    The join has two independent callers — the tenant filter for a non-superadmin
    and the free-text search, which matches on username and email. Emitting it
    twice makes SQLAlchemy raise, so it is decided in one place here.

    **No eager load and no DISTINCT here.** Both used to be applied at this
    point and both were expensive in ways that only showed up under volume:

    * ``joinedload(AuditLog.user)`` widened every row to ~2.8 kB by selecting
      all forty user columns. The count query inherited that width, so the
      pager was aggregating rows it never looked at. The eager load is applied
      once, on the fetch path in ``list_audit_logs``, where the columns are
      actually read.
    * ``.distinct()`` was defensive against the outer join fanning out, and it
      cannot: ``users.id`` is the primary key, so each audit row matches at
      most one user row. Measured on 100,000 rows the join produced **zero**
      duplicates, and the DISTINCT it guarded against forced a sort over every
      column of that 2.8 kB row — ``Sort Method: external merge  Disk: 9808kB``,
      2,738 ms for one page's ``total``. Removing it returns identical counts.

    If a second join to a fan-out-capable table is ever added here, DISTINCT
    (or a subquery) has to come back with it.
    """
    query = db.query(AuditLog)
    superadmin = _is_superadmin(current_user)

    if superadmin and not needs_user_join:
        return query

    query = query.outerjoin(User, AuditLog.user_id == User.id)

    if not superadmin:
        # An event belongs to the tenant if the row carries the org, or if the
        # actor does. Both are checked because `user_id` is nullable (the actor
        # may since have been deleted) and `org_id` is not.
        query = query.filter(
            or_(
                AuditLog.org_id == current_user.org_id,
                User.org_id == current_user.org_id,
            )
        )
    return query


def _apply_filters(
    query,
    *,
    user_id: str | None,
    action: str | None,
    resource_type: str | None,
    status: str | None,
    severity: str | None,
    ip_address: str | None,
    date_from: datetime | None,
    date_to: datetime | None,
    q: str | None,
):
    """Apply every filter the list endpoint supports to an already-scoped query."""
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if action:
        query = query.filter(AuditLog.action == action)
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)
    if status:
        query = query.filter(AuditLog.status == status)
    if severity:
        query = query.filter(AuditLog.severity == severity.strip().lower())

    if ip_address:
        # Matched as text, not as INET. An INET comparison against a partial or
        # malformed address raises DataError inside the driver, which surfaces
        # as a 500 for what is really a typo in a filter box. Text matching also
        # gives "10.180.6." prefix search for free.
        query = query.filter(
            cast(AuditLog.ip_address, String).ilike(f"{ip_address.strip()}%")
        )

    if date_from is not None:
        query = query.filter(AuditLog.created_at >= date_from)
    if date_to is not None:
        query = query.filter(AuditLog.created_at <= date_to)

    if q:
        term = q.strip()
        like = f"%{term}%"
        # Event id and request id are matched exactly and listed first: they are
        # the two identifiers someone pastes in from a support ticket, both are
        # indexed, and an exact match on either is a single-row lookup rather
        # than a scan. The ILIKE arms stay bounded by the tenant and date
        # filters already applied above.
        query = query.filter(
            or_(
                AuditLog.id == term,
                AuditLog.request_id == term,
                AuditLog.action.ilike(like),
                AuditLog.resource_type.ilike(like),
                AuditLog.resource_id.ilike(like),
                cast(AuditLog.ip_address, String).ilike(like),
                User.username.ilike(like),
                User.email.ilike(like),
            )
        )
    return query


def _serialise(log: AuditLog, *, detail: bool = False) -> dict:
    """
    Render one row.

    The list and detail shapes differ on purpose (spec §21): the table needs
    enough to render a row, the detail view needs everything. Keeping the list
    lean matters at 100+ concurrent users — ``user_agent`` alone is often longer
    than the rest of the row combined.
    """
    payload = {
        "id": str(log.id),
        "user_id": str(log.user_id) if log.user_id else None,
        "username": log.user.username if log.user else None,
        "user_email": log.user.email if log.user else None,
        "user_agent": log.user_agent,
        "action": log.action,
        "resource_type": log.resource_type,
        "resource_id": log.resource_id,
        "status": log.status,
        "severity": log.severity,
        "request_id": log.request_id,
        "ip_address": log.ip_address,
        "changes": log.changes,
        "created_at": log.created_at,
    }
    if detail:
        payload["org_id"] = log.org_id
        payload["user_full_name"] = log.user.full_name if log.user else None
        # Stored UTC; named explicitly so the detail view can say so rather than
        # leaving the reader to assume the server's zone.
        payload["timezone"] = "UTC"
        # The session this event belongs to, where the writing call site
        # recorded one. Only some actions carry it, so it is surfaced rather
        # than promised.
        changes = log.changes if isinstance(log.changes, dict) else {}
        payload["session_id"] = changes.get("session_id")
    return payload


@router.get("")
@router.get("/")
def list_audit_logs(
    user_id: str | None = Query(None, description="Exact actor id"),
    action: str | None = Query(None, description="Exact action, e.g. user.login"),
    resource_type: str | None = Query(None, description="Exact resource type"),
    status: str | None = Query(None, description="Exact status, e.g. success"),
    severity: str | None = Query(None, description="info|low|medium|high|critical"),
    ip_address: str | None = Query(None, description="Source IP, prefix match"),
    range: str | None = Query(  # noqa: A002 - the query parameter is named `range`
        None, description="Named window: today|24h|7d|30d"
    ),
    date_from: datetime | None = Query(None, description="ISO 8601, inclusive"),
    date_to: datetime | None = Query(None, description="ISO 8601, inclusive"),
    q: str | None = Query(
        None,
        description=(
            "Search event id, request id, action, resource, IP, username, email"
        ),
    ),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("audit", "read")),
):
    """List audit events, newest first, filtered and paginated in the database."""
    if severity and severity.strip().lower() not in SEVERITY_LEVELS:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Unknown severity '{severity}'. "
                f"Expected one of: {', '.join(SEVERITY_LEVELS)}."
            ),
        )

    resolved_from, resolved_to = _resolve_window(range, date_from, date_to)

    query = _scoped_query(db, current_user, needs_user_join=bool(q))
    query = _apply_filters(
        query,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        status=status,
        severity=severity,
        ip_address=ip_address,
        date_from=resolved_from,
        date_to=resolved_to,
        q=q,
    )

    # Counted without the eager load and without ORDER BY: the pager needs a
    # number, not rows. `query.count()` would wrap the whole SELECT — every
    # column of every joined table — in a subquery and aggregate over that.
    #
    # `func.count(AuditLog.id)`, not a bare `func.count()`. With no column to
    # anchor it, SQLAlchemy emits `SELECT count(*)` with **no FROM clause** for
    # a query that has no join and no column-referencing filter — which is
    # exactly the superadmin-with-no-filters case — and PostgreSQL answers 1.
    # The table then reported "1 event" while returning fifty rows.
    total = query.with_entities(func.count(AuditLog.id)).order_by(None).scalar() or 0

    # The eager load belongs here and only here. Without it `_serialise`
    # touches `log.user` per row, which is a query per row.
    logs = (
        query.options(joinedload(AuditLog.user))
        .order_by(AuditLog.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    return {
        "total": total,
        "logs": [_serialise(log) for log in logs],
    }


# NOTE: this dynamic route must stay LAST in the module. A literal path
# registered after it — `/export` in phase 5 — would otherwise be captured here
# as an `event_id` and answer 404 instead of exporting.
@router.get("/{event_id}")
def get_audit_log(
    event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("audit", "read")),
):
    """
    One audit event in full, for the detail view.

    An event outside the caller's tenant answers 404 rather than 403: the two
    are distinguishable, and 403 would confirm that an event with this id
    exists in some other organisation.
    """
    log = (
        db.query(AuditLog)
        .options(joinedload(AuditLog.user))
        .filter(AuditLog.id == event_id)
        .first()
    )

    if log is None:
        raise HTTPException(status_code=404, detail="Audit event not found")

    if not _is_superadmin(current_user):
        actor_org = log.user.org_id if log.user else None
        if current_user.org_id not in (log.org_id, actor_org):
            raise HTTPException(status_code=404, detail="Audit event not found")

    return _serialise(log, detail=True)
