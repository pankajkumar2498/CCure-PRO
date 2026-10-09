"""
routers/scan_schedules.py
─────────────────────────────────────────────────────────────────────────────
Scheduled and recurring scans — full CRUD, Run Now, and execution history.

Endpoints
─────────
  GET    /scan-schedules                  list (tenant-scoped)
  POST   /scan-schedules                  create
  GET    /scan-schedules/timezones        the IANA zones this server accepts
  GET    /scan-schedules/{id}             one schedule
  PATCH  /scan-schedules/{id}             edit
  DELETE /scan-schedules/{id}             delete
  POST   /scan-schedules/{id}/enable      enable / disable
  POST   /scan-schedules/{id}/run-now     dispatch immediately
  GET    /scan-schedules/{id}/runs        execution history

Three properties this module is responsible for
───────────────────────────────────────────────
**Tenant isolation is applied in the query, never after it.** Every lookup
filters on ``org_id`` as part of the ``WHERE`` clause, so a schedule belonging
to another organisation returns 404 rather than 403. A 403 would confirm the id
exists, which is an enumeration oracle across tenants.

**A schedule never accepts a secret.** The create and update bodies have no
password or key field, only ``credential_id``. ``POST /scan/credentialed``
takes a password and passes it into the Celery task's arguments; storing one
here would put a plaintext credential in the database, in every backup of it,
and in the broker payload on every single run.

**Every limited route declares ``response: Response``.** The limiter is built
``headers_enabled=True``, so slowapi writes X-RateLimit-* after the handler
returns and finds the response only if the handler returned one or declared the
parameter. A handler that returns a dict and declares neither hands slowapi
``None`` and upstream raises from inside the endpoint call — a 500 on every
request to that route. CLAUDE.md records 21 routes shipping in exactly that
state.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ccure_platform.api import (
    CurrentUser,
    require_authorized,
    resolve_active_organisation,
)
from ccure_platform.api import log_audit_event
from core.scheduling.dispatcher import advance_schedule, dispatch_schedule
from core.scheduling.recurrence import (
    MAX_RUN_MINUTE,
    RecurrenceSpec,
    compute_next_run,
    describe_recurrence,
    is_valid_timezone,
    minute_to_hhmm,
    parse_hhmm,
)
from db.base import gen_scan_schedule_id, get_db
from ccure_platform import api as platform_api
from db.models import ComplianceCredential
from db.models.scan_schedules import (
    DISPATCHABLE_SCAN_KINDS,
    RECURRENCE_CUSTOM,
    RECURRENCE_MONTHLY,
    RECURRENCE_ONCE,
    RECURRENCE_WEEKLY,
    RECURRENCES,
    SCAN_KIND_CREDENTIALED,
    TRIGGER_MANUAL,
    ScanSchedule,
    ScanScheduleRun,
)
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, field_validator
from scan_helpers import limiter
from sqlalchemy.orm import Session

log = logging.getLogger("ccure.scan_schedules")

router = APIRouter(prefix="/scan-schedules", tags=["Scan Schedules"])


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _resolve_org(user: CurrentUser, requested: Optional[str]) -> str:
    """
    The organisation this request acts on.

    Only a superadmin may name one; everybody else is pinned to their own. The
    parameter is otherwise ignored rather than rejected, so a client that sends
    its own org id redundantly still works.
    """
    # Scope is decided by the platform (RBAC-5): a client-named organisation is a
    # request, honoured only with cross-organisation reach and an active target.
    return resolve_active_organisation(user, requested)


def _validate_policy(
    db: Session,
    org_id: str,
    scan_kind: str,
    policy_id: Optional[str],
    credential_id: Optional[str],
) -> None:
    """
    Refuse a schedule that names a policy it cannot run.

    Checked when the schedule is written *as well as* at every dispatch, and
    the two are not redundant: this one catches a typo while the operator is
    looking at the form, and the dispatch one catches a policy archived three
    months later. Only the second is load-bearing for correctness; the first is
    what stops a schedule being created that can never fire.

    A disabled or draft policy is refused here too. Accepting one would create
    a schedule that fails every night with an error about a policy nobody
    remembers choosing.
    """
    if not policy_id:
        return

    from core.scan_policy import ResolvedPolicyError, resolve_policy

    try:
        resolve_policy(
            db,
            policy_id=policy_id,
            org_id=org_id,
            scan_kind=scan_kind,
            has_credential=bool(credential_id),
        )
    except ResolvedPolicyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _get_schedule(db: Session, schedule_id: str, org_id: str) -> ScanSchedule:
    """
    Fetch one schedule inside its tenant.

    The org filter is part of the query. Fetching by id and then comparing
    ``org_id`` in Python answers 403 for another tenant's schedule, which
    confirms the id exists — so this returns 404 for both "no such schedule"
    and "not yours", and they are indistinguishable from outside.
    """
    schedule = (
        db.query(ScanSchedule)
        .filter(ScanSchedule.id == schedule_id, ScanSchedule.org_id == org_id)
        .first()
    )
    if schedule is None:
        raise HTTPException(status_code=404, detail="Scan schedule not found.")
    return schedule


def _serialize(schedule: ScanSchedule, db: Session) -> Dict[str, Any]:
    spec = RecurrenceSpec.from_schedule(schedule)
    credential_name = None
    if schedule.credential_id:
        credential_name = (
            db.query(ComplianceCredential.name)
            .filter(ComplianceCredential.id == schedule.credential_id)
            .scalar()
        )
    return {
        "id": schedule.id,
        "org_id": schedule.org_id,
        "name": schedule.name,
        "description": schedule.description,
        "scan_kind": schedule.scan_kind,
        "targets": list(schedule.targets or []),
        "scan_options": dict(schedule.scan_options or {}),
        "credential_id": schedule.credential_id,
        "policy_id": schedule.policy_id,
        "policy_name": (schedule.policy.name if schedule.policy else None),
        # The name, never the material. A UI needs to show which credential is
        # attached; it has no business receiving anything that could be used.
        "credential_name": credential_name,
        "recurrence": schedule.recurrence,
        "timezone": schedule.timezone,
        "run_at": minute_to_hhmm(schedule.run_at_minute or 0),
        "day_of_week": schedule.day_of_week,
        "day_of_month": schedule.day_of_month,
        "cron_expression": schedule.cron_expression,
        "starts_at": schedule.starts_at.isoformat() if schedule.starts_at else None,
        "is_enabled": schedule.is_enabled,
        "next_run_at": (
            schedule.next_run_at.isoformat() if schedule.next_run_at else None
        ),
        "last_run_at": (
            schedule.last_run_at.isoformat() if schedule.last_run_at else None
        ),
        "last_status": schedule.last_status,
        "last_scan_id": schedule.last_scan_id,
        "last_error": schedule.last_error,
        "consecutive_failures": schedule.consecutive_failures,
        "total_run_count": schedule.total_run_count,
        "summary": describe_recurrence(spec),
        "created_at": schedule.created_at.isoformat() if schedule.created_at else None,
        "updated_at": schedule.updated_at.isoformat() if schedule.updated_at else None,
    }


def _serialize_run(run: ScanScheduleRun) -> Dict[str, Any]:
    return {
        "id": run.id,
        "schedule_id": run.schedule_id,
        "scan_id": run.scan_id,
        "trigger": run.trigger,
        "status": run.status,
        "detail": run.detail,
        "celery_task_id": run.celery_task_id,
        "triggered_by": run.triggered_by,
        "triggered_at": run.triggered_at.isoformat() if run.triggered_at else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Request bodies
# ─────────────────────────────────────────────────────────────────────────────


# Every body model here is prefixed ``ScanSchedule``. FastAPI keys OpenAPI
# component schemas by *class name*, so two routers with a ``ScheduleCreate``
# produce one component and the second silently replaces the first — which is
# exactly what happened: this router's models overwrote
# ``routers/compliance.py``'s, and a client generated from the schema would
# have had the wrong shape for compliance schedules. Do not shorten these.
class ScanScheduleBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=4000)
    targets: List[str] = Field(default_factory=list)
    scan_options: Dict[str, Any] = Field(default_factory=dict)
    credential_id: Optional[str] = None
    recurrence: str = Field(...)
    timezone: str = Field("UTC", max_length=64)
    #: "HH:MM" in the schedule's own zone. Accepted as a string because that is
    #: what a time input produces and what a person reads; converted to minutes
    #: past midnight for storage.
    run_at: str = Field("00:00")
    day_of_week: Optional[int] = Field(None, ge=0, le=6)
    day_of_month: Optional[int] = Field(None, ge=1, le=31)
    cron_expression: Optional[str] = Field(None, max_length=120)
    starts_at: Optional[datetime] = None
    is_enabled: bool = True
    policy_id: Optional[str] = Field(
        None,
        description=(
            "Reusable scan policy this schedule runs under (GAP-12). By "
            "reference, so editing the policy changes every future run without "
            "touching this schedule -- and completed scans keep their own "
            "recorded configuration. Re-resolved and re-validated at every "
            "dispatch, never inherited from the moment the schedule was written."
        ),
    )

    @field_validator("recurrence")
    @classmethod
    def _check_recurrence(cls, value: str) -> str:
        text = str(value or "").strip().lower()
        if text not in RECURRENCES:
            raise ValueError(f"recurrence must be one of {', '.join(RECURRENCES)}")
        return text

    @field_validator("timezone")
    @classmethod
    def _check_timezone(cls, value: str) -> str:
        text = str(value or "UTC").strip() or "UTC"
        if not is_valid_timezone(text):
            raise ValueError(
                f"{text!r} is not an IANA time zone name (e.g. 'Asia/Kolkata'). "
                "A fixed offset is not accepted: it cannot express daylight "
                "saving, so the schedule would run an hour out for half the year."
            )
        return text

    @field_validator("run_at")
    @classmethod
    def _check_run_at(cls, value: str) -> str:
        parse_hhmm(value)  # raises with a readable message
        return str(value).strip()


class ScanScheduleCreate(ScanScheduleBase):
    scan_kind: str = Field(...)

    @field_validator("scan_kind")
    @classmethod
    def _check_kind(cls, value: str) -> str:
        text = str(value or "").strip().lower()
        if text not in DISPATCHABLE_SCAN_KINDS:
            # The column admits reserved kinds so a later phase does not need a
            # CHECK migration on a table holding customer data. Accepting one
            # here would create a schedule that can never fire.
            raise ValueError(
                f"scan_kind must be one of {', '.join(DISPATCHABLE_SCAN_KINDS)}"
            )
        return text


class ScanScheduleUpdate(BaseModel):
    """Every field optional; only what is sent is changed."""

    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=4000)
    targets: Optional[List[str]] = None
    scan_options: Optional[Dict[str, Any]] = None
    credential_id: Optional[str] = None
    policy_id: Optional[str] = None
    recurrence: Optional[str] = None
    timezone: Optional[str] = Field(None, max_length=64)
    run_at: Optional[str] = None
    day_of_week: Optional[int] = Field(None, ge=0, le=6)
    day_of_month: Optional[int] = Field(None, ge=1, le=31)
    cron_expression: Optional[str] = Field(None, max_length=120)
    starts_at: Optional[datetime] = None

    @field_validator("recurrence")
    @classmethod
    def _check_recurrence(cls, value):
        if value is None:
            return value
        text = str(value).strip().lower()
        if text not in RECURRENCES:
            raise ValueError(f"recurrence must be one of {', '.join(RECURRENCES)}")
        return text

    @field_validator("timezone")
    @classmethod
    def _check_timezone(cls, value):
        if value is None:
            return value
        text = str(value).strip() or "UTC"
        if not is_valid_timezone(text):
            raise ValueError(f"{text!r} is not an IANA time zone name")
        return text

    @field_validator("run_at")
    @classmethod
    def _check_run_at(cls, value):
        if value is None:
            return value
        parse_hhmm(value)
        return str(value).strip()


class ScanScheduleEnableBody(BaseModel):
    is_enabled: bool


def _validate_recurrence_shape(
    recurrence: str,
    day_of_week: Optional[int],
    day_of_month: Optional[int],
    cron_expression: Optional[str],
    starts_at: Optional[datetime],
) -> None:
    """
    Reject a recurrence that cannot be placed on a calendar.

    The database CHECK constraints enforce the same pairings, but a constraint
    violation surfaces as a 500 with a Postgres message. These are the same
    rules stated as 400s a person can act on.
    """
    if recurrence == RECURRENCE_WEEKLY and day_of_week is None:
        raise HTTPException(
            status_code=400,
            detail="A weekly schedule needs day_of_week (0 = Monday .. 6 = Sunday).",
        )
    if recurrence == RECURRENCE_MONTHLY and day_of_month is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "A monthly schedule needs day_of_month (1-31). A month shorter "
                "than the chosen day runs on its last day."
            ),
        )
    if recurrence == RECURRENCE_CUSTOM and not (cron_expression or "").strip():
        raise HTTPException(
            status_code=400,
            detail="A custom schedule needs cron_expression.",
        )
    if recurrence != RECURRENCE_CUSTOM and (cron_expression or "").strip():
        raise HTTPException(
            status_code=400,
            detail=(
                "cron_expression is only meaningful when recurrence is "
                "'custom'. Storing one otherwise leaves a value nothing reads."
            ),
        )
    if recurrence == RECURRENCE_ONCE and starts_at is None:
        raise HTTPException(
            status_code=400,
            detail="A one-time schedule needs starts_at — the moment to run.",
        )


def _validate_credential(
    db: Session, org_id: str, scan_kind: str, credential_id: Optional[str]
) -> None:
    if scan_kind == SCAN_KIND_CREDENTIALED and not credential_id:
        raise HTTPException(
            status_code=400,
            detail=(
                "A credentialed schedule needs credential_id. Credentials are "
                "referenced, never stored on the schedule."
            ),
        )
    if not credential_id:
        return
    exists = (
        db.query(ComplianceCredential.id)
        .filter(
            ComplianceCredential.id == credential_id,
            # Scoped to the tenant: without this, one organisation could attach
            # another's stored credential to its own schedule and have the
            # worker decrypt and use it.
            ComplianceCredential.tenant_id == org_id,
        )
        .first()
    )
    if not exists:
        raise HTTPException(
            status_code=404, detail="Credential not found for this organisation."
        )


def _validate_targets_now(db: Session, org_id: str, targets: List[str]) -> List[str]:
    """
    Apply the same target gate the manual scan routes apply, at create time.

    The dispatcher re-applies it at every run — scope can be narrowed after a
    schedule is written — but rejecting an unusable target here means the user
    finds out while the form is open rather than from a failed run tomorrow.
    """
    from scan_helpers import validate_scan_targets

    cleaned = [str(t).strip() for t in (targets or []) if str(t or "").strip()]
    if not cleaned:
        raise HTTPException(status_code=400, detail="At least one target is required.")
    from core.scan_scope import org_scan_scope

    return validate_scan_targets(cleaned, scope=org_scan_scope(db, org_id))


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/timezones")
@limiter.limit("30/minute")
def list_timezones(
    request: Request,
    response: Response,
    user: CurrentUser = Depends(require_authorized("audit.scan_schedule.read")),
):
    """
    The IANA zones this server can resolve.

    Served from the server rather than hardcoded in the UI so the list can
    never claim a zone the scheduler would then fall back to UTC on.
    """
    from zoneinfo import available_timezones

    return {"timezones": sorted(available_timezones())}


@router.get("/credentials")
@limiter.limit("60/minute")
def list_selectable_credentials(
    request: Request,
    response: Response,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_authorized("audit.scan_schedule.read")),
    db: Session = Depends(get_db),
):
    """
    The stored credentials this organisation can attach to a schedule.

    Deliberately served here rather than reusing ``GET /compliance/credentials``,
    which is gated on ``compliance:read``. Choosing a credential for a
    credentialed scan is a scanning task, and requiring a compliance permission
    to do it would either lock out an analyst who has no compliance role or
    push somebody into granting compliance access for the wrong reason.

    Returns identifying fields only — no ``encrypted_password``, no
    ``encrypted_key_content``. This is a picker, not a credential export.

    Declared above ``/{schedule_id}`` because FastAPI matches in declaration
    order and would otherwise read "credentials" as a schedule id.
    """
    resolved_org = _resolve_org(user, org_id)
    rows = (
        db.query(ComplianceCredential)
        .filter(ComplianceCredential.tenant_id == resolved_org)
        .order_by(ComplianceCredential.name.asc())
        .all()
    )
    return {
        "credentials": [
            {
                "id": c.id,
                "name": c.name,
                "username": c.username,
                "auth_method": c.auth_method,
                "port": c.port,
            }
            for c in rows
        ]
    }


@router.get("")
@limiter.limit("60/minute")
def list_schedules(
    request: Request,
    response: Response,
    org_id: Optional[str] = Query(None),
    scan_kind: Optional[str] = Query(None),
    enabled: Optional[bool] = Query(None),
    user: CurrentUser = Depends(require_authorized("audit.scan_schedule.read")),
    db: Session = Depends(get_db),
):
    resolved_org = _resolve_org(user, org_id)
    query = db.query(ScanSchedule).filter(ScanSchedule.org_id == resolved_org)
    if scan_kind:
        query = query.filter(ScanSchedule.scan_kind == scan_kind)
    if enabled is not None:
        query = query.filter(ScanSchedule.is_enabled.is_(enabled))
    rows = query.order_by(ScanSchedule.created_at.desc()).all()
    return {"schedules": [_serialize(s, db) for s in rows], "total": len(rows)}


@router.post("", status_code=201)
@limiter.limit("20/minute")
def create_schedule(
    request: Request,
    response: Response,
    body: ScanScheduleCreate,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_authorized("audit.scan_schedule.manage")),
    db: Session = Depends(get_db),
):
    resolved_org = _resolve_org(user, org_id)

    _validate_recurrence_shape(
        body.recurrence,
        body.day_of_week,
        body.day_of_month,
        body.cron_expression,
        body.starts_at,
    )
    _validate_credential(db, resolved_org, body.scan_kind, body.credential_id)
    _validate_policy(
        db, resolved_org, body.scan_kind, body.policy_id, body.credential_id
    )
    targets = _validate_targets_now(db, resolved_org, body.targets)

    duplicate = (
        db.query(ScanSchedule.id)
        .filter(ScanSchedule.org_id == resolved_org, ScanSchedule.name == body.name)
        .first()
    )
    if duplicate:
        raise HTTPException(
            status_code=409,
            detail=f"A schedule named {body.name!r} already exists.",
        )

    org = platform_api.organisation(db, resolved_org)
    schedule = ScanSchedule(
        id=gen_scan_schedule_id(org.slug if org else resolved_org),
        org_id=resolved_org,
        created_by=str(user.id),
        name=body.name,
        description=body.description,
        scan_kind=body.scan_kind,
        targets=targets,
        scan_options=body.scan_options or {},
        credential_id=body.credential_id,
        policy_id=body.policy_id,
        recurrence=body.recurrence,
        timezone=body.timezone,
        run_at_minute=parse_hhmm(body.run_at),
        day_of_week=body.day_of_week,
        day_of_month=body.day_of_month,
        cron_expression=body.cron_expression,
        starts_at=body.starts_at,
        is_enabled=body.is_enabled,
    )
    schedule.next_run_at = compute_next_run(RecurrenceSpec.from_schedule(schedule))
    db.add(schedule)

    log_audit_event(
        db,
        user,
        "scan_schedule.created",
        "scan_schedule",
        schedule.id,
        changes={
            "name": schedule.name,
            "scan_kind": schedule.scan_kind,
            "recurrence": schedule.recurrence,
            "timezone": schedule.timezone,
            "targets": len(targets),
            "next_run_at": (
                schedule.next_run_at.isoformat() if schedule.next_run_at else None
            ),
        },
        request=request,
    )
    db.commit()
    db.refresh(schedule)
    return _serialize(schedule, db)


@router.get("/{schedule_id}")
@limiter.limit("60/minute")
def get_schedule(
    request: Request,
    response: Response,
    schedule_id: str,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_authorized("audit.scan_schedule.read")),
    db: Session = Depends(get_db),
):
    schedule = _get_schedule(db, schedule_id, _resolve_org(user, org_id))
    return _serialize(schedule, db)


@router.patch("/{schedule_id}")
@limiter.limit("20/minute")
def update_schedule(
    request: Request,
    response: Response,
    schedule_id: str,
    body: ScanScheduleUpdate,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_authorized("audit.scan_schedule.manage")),
    db: Session = Depends(get_db),
):
    resolved_org = _resolve_org(user, org_id)
    schedule = _get_schedule(db, schedule_id, resolved_org)
    fields = body.model_dump(exclude_unset=True)

    recurrence = fields.get("recurrence", schedule.recurrence)
    day_of_week = fields.get("day_of_week", schedule.day_of_week)
    day_of_month = fields.get("day_of_month", schedule.day_of_month)
    cron_expression = fields.get("cron_expression", schedule.cron_expression)
    starts_at = fields.get("starts_at", schedule.starts_at)

    # Changing away from weekly/monthly must clear the field the old
    # recurrence needed, or the CHECK constraints and the recurrence engine
    # disagree about which columns are meaningful.
    if "recurrence" in fields:
        if recurrence != RECURRENCE_WEEKLY and "day_of_week" not in fields:
            day_of_week = None
        if recurrence != RECURRENCE_MONTHLY and "day_of_month" not in fields:
            day_of_month = None
        if recurrence != RECURRENCE_CUSTOM and "cron_expression" not in fields:
            cron_expression = None

    _validate_recurrence_shape(
        recurrence, day_of_week, day_of_month, cron_expression, starts_at
    )

    if "credential_id" in fields:
        _validate_credential(
            db, resolved_org, schedule.scan_kind, fields["credential_id"]
        )
    if "policy_id" in fields or "credential_id" in fields:
        # Re-validated whenever either changes: a policy with
        # require_credential becomes unusable the moment the credential is
        # cleared, and that must be refused while the operator is editing
        # rather than discovered at 02:00 by a failed run.
        _validate_policy(
            db,
            resolved_org,
            schedule.scan_kind,
            fields.get("policy_id", schedule.policy_id),
            fields.get("credential_id", schedule.credential_id),
        )
    if "targets" in fields:
        fields["targets"] = _validate_targets_now(
            db, resolved_org, fields["targets"] or []
        )
    if "name" in fields and fields["name"] != schedule.name:
        clash = (
            db.query(ScanSchedule.id)
            .filter(
                ScanSchedule.org_id == resolved_org,
                ScanSchedule.name == fields["name"],
                ScanSchedule.id != schedule.id,
            )
            .first()
        )
        if clash:
            raise HTTPException(
                status_code=409,
                detail=f"A schedule named {fields['name']!r} already exists.",
            )

    for key, value in fields.items():
        if key == "run_at":
            schedule.run_at_minute = parse_hhmm(value)
        elif key not in ("day_of_week", "day_of_month", "cron_expression"):
            setattr(schedule, key, value)
    schedule.recurrence = recurrence
    schedule.day_of_week = day_of_week
    schedule.day_of_month = day_of_month
    schedule.cron_expression = cron_expression
    schedule.starts_at = starts_at

    # Any timing change re-places the next run. Leaving the old value would
    # keep firing on the previous cadence until the next dispatch, which is a
    # schedule that visibly ignores the edit that was just made.
    schedule.next_run_at = compute_next_run(RecurrenceSpec.from_schedule(schedule))

    log_audit_event(
        db,
        user,
        "scan_schedule.updated",
        "scan_schedule",
        schedule.id,
        changes={"fields": sorted(fields.keys())},
        request=request,
    )
    db.commit()
    db.refresh(schedule)
    return _serialize(schedule, db)


@router.post("/{schedule_id}/enable")
@limiter.limit("20/minute")
def set_enabled(
    request: Request,
    response: Response,
    schedule_id: str,
    body: ScanScheduleEnableBody,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_authorized("audit.scan_schedule.manage")),
    db: Session = Depends(get_db),
):
    resolved_org = _resolve_org(user, org_id)
    schedule = _get_schedule(db, schedule_id, resolved_org)
    schedule.is_enabled = bool(body.is_enabled)

    if schedule.is_enabled:
        # Re-enabling clears the failure counter and re-places the next run.
        # Without the reset a schedule disabled automatically after five
        # failures would be one failure from switching itself off again.
        schedule.consecutive_failures = 0
        schedule.last_error = None
        schedule.next_run_at = compute_next_run(RecurrenceSpec.from_schedule(schedule))
    else:
        # Clearing next_run_at on disable means the due query cannot pick it
        # up even if the enabled flag were somehow missed.
        schedule.next_run_at = None

    log_audit_event(
        db,
        user,
        "scan_schedule.enabled" if schedule.is_enabled else "scan_schedule.disabled",
        "scan_schedule",
        schedule.id,
        changes={"is_enabled": schedule.is_enabled},
        request=request,
    )
    db.commit()
    db.refresh(schedule)
    return _serialize(schedule, db)


@router.post("/{schedule_id}/run-now")
@limiter.limit("10/minute")
def run_now(
    request: Request,
    response: Response,
    schedule_id: str,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_authorized("audit.scan_schedule.manage")),
    db: Session = Depends(get_db),
):
    """
    Dispatch this schedule immediately.

    Deliberately does **not** move ``next_run_at``. Somebody testing a schedule
    at 11:00 would otherwise cancel that night's real run, which is a
    surprising cost for pressing a button labelled "Run Now".

    Works on a disabled schedule too: "disabled" means the recurrence does not
    fire by itself, not that the definition is unusable — and running one by
    hand is how an operator confirms a fix before switching it back on.
    """
    resolved_org = _resolve_org(user, org_id)
    schedule = _get_schedule(db, schedule_id, resolved_org)

    run = dispatch_schedule(
        db,
        schedule,
        trigger=TRIGGER_MANUAL,
        triggered_by=str(user.id),
        advance=False,
    )
    log_audit_event(
        db,
        user,
        "scan_schedule.run_now",
        "scan_schedule",
        schedule.id,
        changes={"status": run.status, "scan_id": run.scan_id},
        request=request,
        status="success" if run.status == "dispatched" else "failure",
    )
    db.commit()
    db.refresh(run)
    db.refresh(schedule)
    return {"run": _serialize_run(run), "schedule": _serialize(schedule, db)}


@router.get("/{schedule_id}/runs")
@limiter.limit("60/minute")
def list_runs(
    request: Request,
    response: Response,
    schedule_id: str,
    limit: int = Query(50, ge=1, le=500),
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_authorized("audit.scan_schedule.read")),
    db: Session = Depends(get_db),
):
    resolved_org = _resolve_org(user, org_id)
    _get_schedule(db, schedule_id, resolved_org)  # 404s for another tenant
    rows = (
        db.query(ScanScheduleRun)
        .filter(
            ScanScheduleRun.schedule_id == schedule_id,
            ScanScheduleRun.org_id == resolved_org,
        )
        .order_by(ScanScheduleRun.triggered_at.desc())
        .limit(limit)
        .all()
    )
    return {"runs": [_serialize_run(r) for r in rows], "total": len(rows)}


@router.delete("/{schedule_id}")
@limiter.limit("20/minute")
def delete_schedule(
    request: Request,
    response: Response,
    schedule_id: str,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_authorized("audit.scan_schedule.delete")),
    db: Session = Depends(get_db),
):
    """
    Delete the schedule and its run history.

    The scans it produced are **not** deleted: ``scan_schedule_runs.scan_id`` is
    ON DELETE SET NULL from ``scans``, and the runs cascade from the schedule.
    A scan is evidence of what was found on a network at a moment in time, and
    removing a schedule is not a reason to destroy it.
    """
    resolved_org = _resolve_org(user, org_id)
    schedule = _get_schedule(db, schedule_id, resolved_org)
    name = schedule.name

    log_audit_event(
        db,
        user,
        "scan_schedule.deleted",
        "scan_schedule",
        schedule.id,
        changes={"name": name, "scan_kind": schedule.scan_kind},
        request=request,
    )
    db.delete(schedule)
    db.commit()
    return {"success": True, "id": schedule_id, "name": name}
