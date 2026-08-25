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

import logging
from datetime import datetime, timedelta, timezone

from auth.rbac import require_permission, require_role
from config import AppConfig
from core.audit import log_audit_event
from core.audit_retention import (
    RetentionRefused,
    active_holds,
    newest_backup,
    preview as retention_preview,
    resolve_cutoff,
    retention_installed,
    take_export_lock,
)
from core.audit_taxonomy import SEVERITY_LEVELS
from core.upload_guard import content_disposition
from db.base import SessionLocal, get_db
from db.models import AuditLog, User
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from reporting.audit_export import (
    INTEGRITY_FAILURE,
    INTEGRITY_LEGACY,
    INTEGRITY_NOT_VERIFIED,
    INTEGRITY_VERIFIED,
    VERIFICATION_NOT_REQUESTED,
    VERIFICATION_PERFORMED,
    VERIFICATION_UNAVAILABLE,
    export_filename,
    iter_csv,
    render_pdf,
)
from scan_helpers import limiter
from sqlalchemy import (
    String,
    and_,
    case,
    cast,
    func,
    literal,
    literal_column,
    or_,
    text,
)
from sqlalchemy.orm import Session, joinedload
from starlette.responses import StreamingResponse

logger = logging.getLogger(__name__)

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


# ─── Export ──────────────────────────────────────────────────────────────────
#
# Phase 5. Everything below sits above the `/{event_id}` route on purpose; see
# the note there.

#: Columns the export selects. Narrower than the ORM entity on purpose — the
#: export reads up to the row cap and never needs a mapped instance, and
#: selecting the entity would pull the `user` relationship into scope per row.
_EXPORT_COLUMNS = (
    AuditLog.id,
    AuditLog.created_at,
    AuditLog.org_id,
    AuditLog.user_id,
    AuditLog.actor_user_id,
    AuditLog.actor_username,
    AuditLog.action,
    AuditLog.resource_type,
    AuditLog.resource_id,
    AuditLog.status,
    AuditLog.severity,
    AuditLog.ip_address,
    AuditLog.user_agent,
    AuditLog.request_id,
    AuditLog.changes,
    AuditLog.prev_hash,
    AuditLog.record_hash,
)

_EXPORT_FIELDS = tuple(column.key for column in _EXPORT_COLUMNS)


def _chain_hash_schema(db: Session) -> str | None:
    """
    Where ``audit_record_hash_v1`` lives, or None if it is not installed.

    Resolved per request rather than cached: the bootstrap that installs it is
    run by a DBA out of band, so a process that cached "absent" at import time
    would keep reporting verification as unavailable until it was restarted.
    It is a catalogue lookup on an indexed system table.

    `audit_chain` wins over `public`. The chain was originally installed in
    `public` and is moved by a privileged bootstrap the application role cannot
    run, so both locations are legitimate; preferring the isolated one means a
    database that still carries a stale shadow copy in `public` verifies
    against the real function.
    """
    return db.execute(
        text(
            "SELECT n.nspname FROM pg_proc p "
            "  JOIN pg_namespace n ON n.oid = p.pronamespace "
            " WHERE p.proname = 'audit_record_hash_v1' "
            "   AND n.nspname IN ('audit_chain', 'public') "
            " ORDER BY CASE n.nspname WHEN 'audit_chain' THEN 0 ELSE 1 END "
            " LIMIT 1"
        )
    ).scalar()


def _integrity_expression(chain_schema: str | None):
    """
    The per-row integrity verdict, as SQL.

    **A non-NULL ``record_hash`` is never on its own enough to say `verified`.**
    The stored hash is the value under suspicion; the evidence is whether it
    reproduces. So the verified branch compares it against a fresh computation
    through the database's own canonical function — the same one the insert
    trigger calls — and anything that does not reproduce falls through to
    ``INTEGRITY_FAILURE``.

    With no chain schema (verification not requested, or the machinery is not
    installed) the function is never called and a stored hash yields
    ``not_verified``: present, unchecked, and labelled as such.
    """
    legacy = (AuditLog.record_hash.is_(None), literal(INTEGRITY_LEGACY))

    if chain_schema is None:
        return case(legacy, else_=literal(INTEGRITY_NOT_VERIFIED))

    # `literal_column("audit_logs")` is the whole-row reference the function's
    # second parameter takes. `_scoped_query` never aliases the table, so this
    # is the name it renders under.
    recomputed = getattr(func, chain_schema).audit_record_hash_v1(
        AuditLog.prev_hash, literal_column("audit_logs")
    )
    return case(
        legacy,
        (AuditLog.record_hash == recomputed, literal(INTEGRITY_VERIFIED)),
        else_=literal(INTEGRITY_FAILURE),
    )


def _integrity_counts(db: Session, query, chain_schema: str | None) -> dict[str, int]:
    """
    Count each integrity state over the filtered set, in one pass.

    Run **before** streaming because ``audit.log_exported`` has to record the
    failure count, and that event must be committed before the first byte
    leaves — the two requirements together rule out discovering the count while
    writing the file.
    """
    state = _integrity_expression(chain_schema).label("state")
    subquery = query.with_entities(state).order_by(None).subquery()

    # `GROUP BY state`, **not** four `count(*) FILTER (WHERE state = …)`
    # aggregates over the same subquery. The subquery is a plain scan, so
    # PostgreSQL flattens it and substitutes the expression into every place
    # `state` appears — which with four FILTER clauses means
    # `audit_record_hash_v1` is called **four times per row**. Confirmed on
    # EXPLAIN VERBOSE, and measured: it was the single largest cost in the
    # export, roughly quadrupling verified-mode time. Grouping names the
    # expression once, so it is evaluated once.
    rows = (
        db.query(subquery.c.state, func.count())
        .select_from(subquery)
        .group_by(subquery.c.state)
        .all()
    )
    tally = {state_value: count for state_value, count in rows}

    return {
        value: tally.get(value, 0)
        for value in (
            INTEGRITY_VERIFIED,
            INTEGRITY_NOT_VERIFIED,
            INTEGRITY_LEGACY,
            INTEGRITY_FAILURE,
        )
    }


def _iter_export_rows(db: Session, query, chain_schema: str | None, page_size: int):
    """
    Walk the filtered set newest-first with a **keyset** cursor.

    Not OFFSET. Offset re-scans and discards everything before the page on
    every request, so the cost of page *n* grows with *n* — over a 50,000-row
    export that is the same rows read fifty times. The cursor is
    ``(created_at, id)``: ``created_at`` alone is not unique (two events inside
    the same millisecond are ordinary), and a cursor that is not unique either
    skips rows or repeats them.
    """
    state = _integrity_expression(chain_schema).label("integrity")
    base = query.with_entities(*_EXPORT_COLUMNS, state).order_by(None)

    cursor: tuple[datetime, str] | None = None
    while True:
        page = base
        if cursor is not None:
            last_created, last_id = cursor
            page = page.filter(
                or_(
                    AuditLog.created_at < last_created,
                    and_(
                        AuditLog.created_at == last_created,
                        AuditLog.id < last_id,
                    ),
                )
            )
        rows = (
            page.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
            .limit(page_size)
            .all()
        )
        if not rows:
            return

        for row in rows:
            record = dict(zip(_EXPORT_FIELDS, row[: len(_EXPORT_FIELDS)]))
            record["integrity"] = row[-1]
            yield record

        cursor = (rows[-1].created_at, rows[-1].id)
        if len(rows) < page_size:
            return


@router.get("/export")
@limiter.limit("5/minute")
def export_audit_logs(
    request: Request,
    # slowapi writes X-RateLimit-* after the handler returns and finds the
    # response either from the return value or from this parameter. This
    # handler returns a Response, which is what slowapi actually uses — the
    # parameter is declared because `tests/security/test_rate_limit_headers.py`
    # requires every limited route to have one of the two, and a future edit
    # that returns a dict from some branch would otherwise 500 the route.
    response: Response,
    fmt: str = Query("csv", alias="format", description="csv|pdf"),
    verify: bool = Query(
        True,
        description=(
            "Recompute every stored record_hash and report the result per row. "
            "Default, and the mode an evidence export should use. Setting it "
            "false produces a file in which nothing is verified, and says so."
        ),
    ),
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
    q: str | None = Query(None, description="Same search as the list endpoint"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("audit", "export")),
):
    """
    Export the audit trail the caller can see, as CSV or PDF.

    Taking a copy of the trail off the platform is itself an auditable event,
    and it is written and **committed before the first byte is sent**. Two
    reasons, and both are load-bearing:

    * The chain insert holds a ``FOR UPDATE`` lock on the organisation's row in
      ``audit_chain_heads`` until commit. Streaming inside that transaction
      would hold it for the whole download — seconds to minutes on a slow
      client — and block every other audit write in the tenant meanwhile.
    * ``get_db`` closes the request's session when the handler returns, which
      for a ``StreamingResponse`` is *before* the body is produced. An event
      written and not yet committed at that point is silently discarded.

    The generator therefore opens its own read-only session. That is not the
    second-session pattern ``core/audit.py`` prohibits: it writes nothing, and
    the request's transaction is already committed when it starts, so there is
    no lock for it to deadlock against.
    """
    fmt = (fmt or "csv").strip().lower()
    if fmt not in ("csv", "pdf"):
        raise HTTPException(
            status_code=422,
            detail=f"Unknown format '{fmt}'. Expected one of: csv, pdf.",
        )

    if severity and severity.strip().lower() not in SEVERITY_LEVELS:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Unknown severity '{severity}'. "
                f"Expected one of: {', '.join(SEVERITY_LEVELS)}."
            ),
        )

    resolved_from, resolved_to = _resolve_window(range, date_from, date_to)

    # Every pass — the count, the integrity tally and the stream — is bounded
    # by one instant captured here. Without it the three see different sets:
    # this request's own `audit.log_exported` event is written between the
    # count and the stream, and being the newest row it would appear *first* in
    # a newest-first export the header had already counted without it.
    snapshot = datetime.now(timezone.utc)
    if resolved_to is None or resolved_to > snapshot:
        resolved_to = snapshot

    filters = {
        "user_id": user_id,
        "action": action,
        "resource_type": resource_type,
        "status": status,
        "severity": severity,
        "ip_address": ip_address,
        "range": range,
        "date_from": date_from,
        "date_to": date_to,
        "q": q,
    }

    def build(session: Session, principal: User):
        """The one place the export's row set is defined.

        Both passes go through `_scoped_query` and `_apply_filters` — the same
        two functions the list endpoint uses — so "what this caller may see"
        and "what these filters mean" have exactly one definition. A second
        implementation here would be a tenant-isolation bug waiting to be
        written.
        """
        scoped = _scoped_query(session, principal, needs_user_join=bool(q))
        return _apply_filters(
            scoped,
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

    # Phase 6a. A shared, transaction-scoped advisory lock so a retention purge
    # cannot remove rows between this count and the stream below and leave a
    # file that contradicts its own header. The purge takes the same lock
    # exclusively and non-blocking, so it defers to its next run rather than
    # waiting on a download.
    #
    # `None` for a superadmin export that is not scoped to one tenant: it
    # cannot decompose per organisation, so it takes the global key every purge
    # also acquires.
    take_export_lock(db, None if _is_superadmin(current_user) else current_user.org_id)

    query = build(db, current_user)

    cap = (
        AppConfig.AUDIT_EXPORT_PDF_MAX_ROWS
        if fmt == "pdf"
        else AppConfig.AUDIT_EXPORT_MAX_ROWS
    )
    total = query.with_entities(func.count(AuditLog.id)).order_by(None).scalar() or 0

    if total > cap:
        # A hard refusal, never a truncation. A file that stops at the cap
        # looks complete, and "nothing happened after 14:02" is precisely the
        # wrong conclusion for a silently shortened audit extract to invite.
        raise HTTPException(
            status_code=413,
            detail=(
                f"This export would contain {total:,} events, which exceeds the "
                f"{cap:,}-event limit for {fmt.upper()}. Narrow the date range "
                f"or add filters and try again. No partial export is produced."
            ),
        )

    chain_schema = _chain_hash_schema(db)
    if not verify:
        verification_mode = VERIFICATION_NOT_REQUESTED
    elif chain_schema is None:
        verification_mode = VERIFICATION_UNAVAILABLE
    else:
        verification_mode = VERIFICATION_PERFORMED

    verifying_schema = (
        chain_schema if verification_mode == VERIFICATION_PERFORMED else None
    )
    counts = _integrity_counts(db, query, verifying_schema)
    failures = counts[INTEGRITY_FAILURE]

    if failures:
        logger.warning(
            "AUDIT_INTEGRITY_FAILURE: %s of %s exported event(s) did not "
            "reproduce their stored record_hash. org_scope=%s actor=%s "
            "request_id=%s format=%s. The audit trail has been modified "
            "outside the application.",
            failures,
            total,
            "all" if _is_superadmin(current_user) else current_user.org_id,
            current_user.id,
            getattr(request.state, "request_id", None),
            fmt,
        )

    log_audit_event(
        db,
        current_user,
        "audit.log_exported",
        resource_type="audit_log",
        resource_id=None,
        changes={
            "format": fmt,
            "row_count": total,
            "verification_requested": verify,
            "verification_mode": verification_mode,
            "chain_schema": chain_schema,
            "verified": counts[INTEGRITY_VERIFIED],
            "not_verified": counts[INTEGRITY_NOT_VERIFIED],
            "legacy_unverifiable": counts[INTEGRITY_LEGACY],
            "integrity_failures": failures,
            "row_cap": cap,
            "snapshot_upper_bound": snapshot.isoformat(),
            "filters": {
                key: (value.isoformat() if isinstance(value, datetime) else value)
                for key, value in filters.items()
                if value not in (None, "")
            },
        },
        request=request,
        # An export that surfaced a broken row is not a successful export. The
        # status is what a reviewer filters on, so it has to carry the outcome
        # rather than merely the fact that the endpoint answered 200.
        status="failure" if failures else "success",
    )
    # Committed here, deliberately: see the docstring. Nothing below this line
    # writes, and the chain-head lock is released before any byte is produced.
    db.commit()

    meta = {
        "generated_at": snapshot,
        "exported_by": current_user.username,
        "exported_by_user_id": current_user.id,
        "organization_scope": (
            "all organizations (superadmin)"
            if _is_superadmin(current_user)
            else current_user.org_id
        ),
        "row_count": total,
        "snapshot_upper_bound": snapshot,
        "filters": filters,
        "request_id": getattr(request.state, "request_id", None),
        "verification_mode": verification_mode,
        "verified_count": counts[INTEGRITY_VERIFIED],
        "not_verified_count": counts[INTEGRITY_NOT_VERIFIED],
        "legacy_unverifiable_count": counts[INTEGRITY_LEGACY],
        "integrity_failure_count": failures,
        "chain_schema": chain_schema,
    }

    headers = {
        "Content-Disposition": content_disposition(
            export_filename(fmt, failed=bool(failures), generated_at=snapshot)
        ),
        # Machine-readable counterpart to the preamble, so a client that never
        # opens the file still cannot mistake a failed export for a clean one.
        "X-Audit-Integrity": (
            "FAILED"
            if failures
            else (
                "VERIFIED"
                if verification_mode == VERIFICATION_PERFORMED
                else "NOT_VERIFIED"
            )
        ),
        "X-Audit-Export-Rows": str(total),
        "X-Audit-Verification-Mode": verification_mode,
        "Cache-Control": "no-store",
    }

    if fmt == "pdf":
        # Materialised, and safe to be: the PDF cap is a separate, much smaller
        # number precisely because reportlab has to hold the whole document.
        rows = list(
            _iter_export_rows(
                db, query, verifying_schema, AppConfig.AUDIT_EXPORT_PAGE_SIZE
            )
        )
        return Response(
            content=render_pdf(meta, rows),
            media_type="application/pdf",
            headers=headers,
        )

    principal_id = current_user.id

    def stream():
        """Produce the CSV from a session of its own. See the docstring."""
        session = SessionLocal()
        try:
            principal = session.get(User, principal_id)
            if principal is None:  # pragma: no cover - the actor vanished mid-export
                raise RuntimeError(
                    "the exporting user no longer exists; refusing to produce "
                    "an unscoped export"
                )
            # The streaming session needs its own lock: advisory locks belong to
            # the transaction that took them, and the request's transaction was
            # committed before this generator ran. Every keyset page below runs
            # inside this session's single read transaction, so one acquisition
            # covers the whole stream and is released when the session closes.
            take_export_lock(
                session, None if _is_superadmin(principal) else principal.org_id
            )
            rows = _iter_export_rows(
                session,
                build(session, principal),
                verifying_schema,
                AppConfig.AUDIT_EXPORT_PAGE_SIZE,
            )
            yield from iter_csv(meta, rows)
        finally:
            session.close()

    return StreamingResponse(
        stream(),
        media_type="text/csv; charset=utf-8",
        headers=headers,
    )


# ─── Retention preview ───────────────────────────────────────────────────────
#
# Phase 6a, and note what is *not* here: no route deletes an audit row, and
# none ever will. Execution is the beat task or
# `scripts/audit/purge_audit_retention.py --apply`, so destroying audit history
# needs shell access to this host **as well as** the permission below. A
# deletion that a session cookie can reach is a deletion an XSS can reach.


@router.get("/retention/preview")
@limiter.limit("5/minute")
def preview_audit_retention(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    # `require_role`, not a permission. The rules a purge follows are
    # platform-wide and its effect is not tenant-scoped in the way reading is:
    # it destroys a record other parties may need. The same reasoning makes
    # /admin/email-domains superadmin-only, and a permission check could not
    # express it anyway — superadmin holds every permission, so any permission
    # an org_admin also held would let them through.
    current_user: User = Depends(require_role("superadmin")),
):
    """
    What audit retention would remove, and everything standing in its way.

    Read-only in the strongest sense available: it reaches the database through
    `audit_retention.preview_legacy_v1`, a STABLE function, and the application
    role holds no privilege that could delete an audit row whatever this
    handler does.
    """
    state = retention_installed(db)
    if not state["installed"]:
        return {
            "installed": False,
            "detail": (
                "Audit retention is not installed in this database. A database "
                "administrator must run bootstrap_chain_retention.sql as a "
                "superuser. Until then no purge can run."
            ),
            "components": state,
        }

    backup_path, backup_age = newest_backup()
    payload = {
        "installed": True,
        "enabled": AppConfig.AUDIT_LOG_RETENTION_DAYS > 0,
        "retention_days": AppConfig.AUDIT_LOG_RETENTION_DAYS,
        "floor_days": AppConfig.AUDIT_RETENTION_MIN_DAYS,
        "dry_run_default": AppConfig.AUDIT_RETENTION_DRY_RUN,
        "max_rows_per_run": AppConfig.AUDIT_RETENTION_MAX_ROWS_PER_RUN,
        "batch_size": AppConfig.AUDIT_RETENTION_BATCH_SIZE,
        "backup": {
            "newest": backup_path.name if backup_path else None,
            "age_hours": round(backup_age, 1) if backup_age is not None else None,
            "required_within_hours": AppConfig.AUDIT_RETENTION_REQUIRE_BACKUP_HOURS,
        },
        "holds": active_holds(db),
        "scope": (
            "legacy rows only (record_hash IS NULL). Chained rows are phase 6b "
            "and the database refuses to delete one on this path."
        ),
    }

    try:
        cutoff = resolve_cutoff()
    except RetentionRefused as refusal:
        # Disabled is the shipped state, not an error. The preview still shows
        # the trail's composition so an operator can see what a period *would*
        # affect before choosing one.
        payload["cutoff"] = None
        payload["reason"] = str(refusal)
        payload["organizations"] = retention_preview(db, datetime.now(timezone.utc))
        payload["would_delete_total"] = 0
        return payload

    rows = retention_preview(db, cutoff)
    payload["cutoff"] = cutoff.isoformat()
    payload["organizations"] = rows
    payload["would_delete_total"] = sum(
        row["eligible_count"] for row in rows if not row["on_hold"]
    )
    return payload


# NOTE: this dynamic route must stay LAST in the module. A literal path
# registered after it — `/export` and `/retention/preview`, above — would
# otherwise be captured here as an `event_id` and answer 404.
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
