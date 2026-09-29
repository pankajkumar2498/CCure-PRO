"""
routers/remediation.py
─────────────────────────────────────────────────────────────────────────────
Remediation ownership, SLA and workflow over the findings that already exist.

Endpoints
─────────
  GET   /remediation/summary                    counts by state and SLA
  GET   /remediation/overdue                    past their due date
  GET   /remediation/pending-verification       fix claimed, awaiting a scan
  GET   /remediation/sla-policy                 this organisation's deadlines
  PUT   /remediation/sla-policy                 set them
  POST  /remediation/assign                     assign / reassign / unassign (bulk)
  GET   /remediation/findings/{id}              one finding's remediation view
  PATCH /remediation/findings/{id}/state        move through the workflow
  POST  /remediation/findings/{id}/notes        append a note
  POST  /remediation/findings/{id}/accept-risk  accept, with reason and expiry
  POST  /remediation/findings/{id}/withdraw-acceptance
  GET   /remediation/findings/{id}/history      the event trail

Four properties this module is responsible for
──────────────────────────────────────────────
**No endpoint here can mark a finding verified fixed.** That is the phase's
whole point. ``PATCH .../state`` goes through
``core.remediation.workflow.change_state``, which calls ``assert_transition``
without ``by_assessment``, and the human transition table has no edge into
``verified_fixed``. A caller asking for it gets a 400 explaining that a scan
has to establish it. Nothing in this file imports
``core.remediation.verification``.

**Tenant isolation is applied in the query, never after it.** Every lookup
joins ``Asset`` and filters ``Asset.org_id``, which is how
``routers/findings.py`` already scopes a finding — a finding belonging to
another organisation returns 404, not 403, because a 403 confirms the id
exists.

**Accepting a risk is its own permission.** ``findings:update`` covers moving
work through the queue; deciding the organisation will carry a risk
indefinitely is a different authorisation and gets ``findings:accept_risk``.
Anyone who can edit a finding could otherwise clear their own overdue list by
accepting everything on it.

**Every limited route declares ``response: Response``.** The limiter is built
``headers_enabled=True``; a handler that returns a dict and declares neither a
returned ``Response`` nor the parameter hands slowapi ``None`` and raises from
inside the endpoint call — a 500 on every request. CLAUDE.md records 21 routes
that shipped in exactly that state.

Performance
───────────
The summary is **two** aggregate queries — one GROUP BY on
``remediation_state``, one counting overdue rows — not a Python loop over
findings. At the scale this product reaches (4,633 findings on one host) a
per-finding SLA computation would be the N+1 the materialised ``sla_due_at``
column exists to avoid. ``ix_asset_vuln_org_remediation`` and
``ix_asset_vuln_org_sla_due`` are the two indexes those queries run on.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ccure_platform.api import CurrentUser, require_permission
from core.audit import log_audit_event
from core.remediation import (
    ACTIVE_STATES,
    REMEDIATION_STATES,
    SLA_STATES,
    STATE_RISK_ACCEPTED,
    STATE_VERIFIED_FIXED,
    TransitionError,
    accept_risk,
    add_note,
    apply_sla,
    assign_owner,
    change_state,
    days_remaining,
    sla_policy_for_org,
    sla_state,
    withdraw_acceptance,
)
from core.remediation.sla import (
    DEFAULT_SLA_DAYS,
    org_sla_setting,
    sla_policy_for_org_id,
    store_sla_setting,
    stored_sla_setting,
)
from db.base import get_db
from ccure_platform import api as platform_api
from db.models.assets import Asset
from db.models.findings import AssetVulnerability, FindingRemediationEvent
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, field_validator
from scan_helpers import limiter
from sqlalchemy import case, func
from sqlalchemy.orm import Session

log = logging.getLogger("ccure.remediation")

router = APIRouter(prefix="/remediation", tags=["Remediation"])


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _is_superadmin(user: CurrentUser) -> bool:
    return (getattr(getattr(user, "role", None), "name", "") or "").lower() == (
        "superadmin"
    )


def _resolve_org(user: CurrentUser, requested: Optional[str]) -> str:
    if requested and _is_superadmin(user):
        return requested
    return str(user.org_id)


def _get_finding(db: Session, finding_id: str, org_id: str) -> AssetVulnerability:
    """
    Fetch one finding inside its tenant.

    The organisation filter is part of the query, the same shape
    ``routers/findings.py`` uses. Fetching by id and comparing afterwards
    answers 403 for another tenant's finding, which confirms the id exists.
    """
    row = (
        db.query(AssetVulnerability)
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(AssetVulnerability.id == finding_id, Asset.org_id == org_id)
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return row


def _sla_setting(db: Session, org_id: str):
    """The organisation's stored SLA setting (core.remediation.sla, the seam)."""
    return org_sla_setting(db, org_id)


def _serialize(finding: AssetVulnerability, *, sla_setting=None) -> Dict[str, Any]:
    policy = sla_policy_for_org(sla_setting)
    return {
        "finding_id": finding.id,
        "asset_id": finding.asset_id,
        "vuln_id": finding.vuln_id,
        "severity": finding.severity,
        # The detection lifecycle, kept distinct from the workflow below. A
        # reader has to be able to tell "absent from the last scan" from
        # "somebody confirmed it was fixed".
        "status": finding.status,
        "remediation": {
            "state": finding.remediation_state,
            "owner": finding.remediation_owner,
            "assigned_at": _iso(finding.assigned_at),
            "assigned_by": finding.assigned_by,
            "notes": finding.remediation_notes,
            "reopened_count": finding.reopened_count,
            "reopened_at": _iso(finding.reopened_at),
        },
        "sla": {
            "due_at": _iso(finding.sla_due_at),
            "basis": finding.sla_basis,
            "state": sla_state(finding, policy=policy),
            "days_remaining": days_remaining(finding, policy=policy),
            # Said in words because the product uses calendar days and a
            # reader who assumes business days is wrong by two days a week.
            "unit": "calendar days",
        },
        "verification": {
            # The two facts that separate evidence from assertion.
            "verified_at": _iso(finding.verified_at),
            "verified_scan_id": finding.verified_scan_id,
            "first_found_at": _iso(finding.first_found_at),
            "last_found_at": _iso(finding.last_found_at),
        },
        "exception": {
            "reason": finding.accepted_risk_reason,
            "accepted_by": finding.accepted_by,
            "accepted_at": _iso(finding.accepted_at),
            "expires_at": _iso(finding.exception_expires_at),
            "indefinite": (
                finding.remediation_state == STATE_RISK_ACCEPTED
                and finding.exception_expires_at is None
            ),
        },
    }


def _iso(value) -> Optional[str]:
    return value.isoformat() if value else None


# ─────────────────────────────────────────────────────────────────────────────
# Bodies
#
# Prefixed ``Remediation`` and they must stay that way. FastAPI keys OpenAPI
# component schemas by class name, so a bare ``StateUpdate`` here would
# silently replace one elsewhere in the generated contract — the defect the CI
# contract gate caught when ``scan_schedules`` shipped a ``ScheduleCreate``.
# ─────────────────────────────────────────────────────────────────────────────


class RemediationAssign(BaseModel):
    finding_ids: List[str] = Field(..., min_length=1, max_length=500)
    #: None unassigns. Explicit rather than a separate endpoint, so
    #: "reassign to nobody" and "reassign to somebody" take one code path and
    #: record the previous owner the same way.
    owner_id: Optional[str] = None
    note: Optional[str] = Field(None, max_length=2000)


class RemediationStateUpdate(BaseModel):
    state: str
    note: Optional[str] = Field(None, max_length=2000)

    @field_validator("state")
    @classmethod
    def _state(cls, v: str) -> str:
        if v not in REMEDIATION_STATES:
            raise ValueError(f"state must be one of {', '.join(REMEDIATION_STATES)}")
        return v


class RemediationNote(BaseModel):
    note: str = Field(..., min_length=1, max_length=4000)


class RemediationAcceptRisk(BaseModel):
    reason: str = Field(..., min_length=1, max_length=4000)
    #: None means the acceptance does not expire — a legitimate decision for a
    #: permanent compensating control, and different from nobody having set a
    #: date, which ``accepted_at`` records either way.
    expires_at: Optional[datetime] = None


class RemediationWithdraw(BaseModel):
    note: Optional[str] = Field(None, max_length=2000)


class RemediationSlaPolicyUpdate(BaseModel):
    days_by_severity: Optional[Dict[str, int]] = None
    due_soon_window_days: Optional[int] = Field(None, ge=0, le=365)
    honour_kev_due_date: Optional[bool] = None

    @field_validator("days_by_severity")
    @classmethod
    def _days(cls, v):
        if v is None:
            return v
        for severity, days in v.items():
            if severity.lower() not in DEFAULT_SLA_DAYS:
                raise ValueError(
                    f"{severity!r} is not a severity this build recognises: "
                    + ", ".join(sorted(DEFAULT_SLA_DAYS))
                )
            if not isinstance(days, int) or days < 0:
                raise ValueError(
                    f"the SLA for {severity!r} must be a whole number of days"
                )
        return {k.lower(): int(d) for k, d in v.items()}


# ─────────────────────────────────────────────────────────────────────────────
# Reading
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/summary")
@limiter.limit("60/minute")
def remediation_summary(
    request: Request,
    response: Response,
    org_id: Optional[str] = Query(None),
    asset_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_permission("findings", "read")),
    db: Session = Depends(get_db),
):
    """
    Counts by remediation state and SLA position.

    **Two aggregate queries, never a loop over findings.** A per-finding SLA
    computation over the 4,633 findings one Linux host produces would be the
    N+1 the materialised ``sla_due_at`` column exists to prevent — and this is
    the endpoint a dashboard calls on every load.

    The overdue count deliberately excludes ``verified_fixed`` and
    ``risk_accepted``: nothing further is owed on either, and reporting them
    as late would bury the ones that are.
    """
    org = _resolve_org(user, org_id)
    now = datetime.now(timezone.utc)

    base = (
        db.query(AssetVulnerability)
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(Asset.org_id == org)
    )
    if asset_id:
        base = base.filter(AssetVulnerability.asset_id == asset_id)

    state_rows = (
        base.with_entities(
            AssetVulnerability.remediation_state,
            func.count(AssetVulnerability.id),
        )
        .group_by(AssetVulnerability.remediation_state)
        .all()
    )
    by_state = {state: 0 for state in REMEDIATION_STATES}
    for state, count in state_rows:
        by_state[str(state or "open")] = int(count)

    sla_rows = (
        base.with_entities(
            case(
                (AssetVulnerability.sla_due_at.is_(None), "not_applicable"),
                (AssetVulnerability.sla_due_at < now, "overdue"),
                else_="within",
            ).label("bucket"),
            func.count(AssetVulnerability.id),
        )
        .filter(AssetVulnerability.remediation_state.in_(list(ACTIVE_STATES)))
        .group_by("bucket")
        .all()
    )
    sla_buckets = {"within": 0, "overdue": 0, "not_applicable": 0}
    for bucket, count in sla_rows:
        sla_buckets[str(bucket)] = int(count)

    return {
        "org_id": org,
        "by_state": by_state,
        "overdue": sla_buckets["overdue"],
        "within_sla": sla_buckets["within"],
        "no_sla": sla_buckets["not_applicable"],
        # The executive line the brief asks for, assembled once here so the
        # report and the dashboard cannot render it two different ways.
        "summary_line": (
            f"Open: {by_state['open']} | "
            f"In remediation: {by_state['in_remediation']} | "
            f"Pending verification: {by_state['pending_verification']} | "
            f"Overdue: {sla_buckets['overdue']} | "
            f"Verified fixed: {by_state['verified_fixed']}"
        ),
        "sla_states": list(SLA_STATES),
    }


def _listing(
    db: Session,
    org: str,
    *,
    overdue_only: bool = False,
    states: Optional[List[str]] = None,
    owner_id: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    query = (
        db.query(AssetVulnerability)
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(Asset.org_id == org)
    )
    if states:
        query = query.filter(AssetVulnerability.remediation_state.in_(states))
    if owner_id:
        query = query.filter(AssetVulnerability.remediation_owner == owner_id)
    if overdue_only:
        query = query.filter(
            AssetVulnerability.sla_due_at.isnot(None),
            AssetVulnerability.sla_due_at < now,
            AssetVulnerability.remediation_state.in_(list(ACTIVE_STATES)),
        )

    total = query.count()
    rows = (
        query.order_by(AssetVulnerability.sla_due_at.asc().nullslast())
        .offset(offset)
        .limit(limit)
        .all()
    )
    sla_setting = _sla_setting(db, org)
    return {
        "total": total,
        "count": len(rows),
        "findings": [_serialize(r, sla_setting=sla_setting) for r in rows],
    }


@router.get("/overdue")
@limiter.limit("60/minute")
def overdue_findings(
    request: Request,
    response: Response,
    org_id: Optional[str] = Query(None),
    owner_id: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(require_permission("findings", "read")),
    db: Session = Depends(get_db),
):
    """
    Findings past their due date, soonest-due first.

    ``total`` counts every overdue finding and is never truncated by ``limit``
    — a bounded count is a wrong number, where a bounded list is a page.
    """
    return _listing(
        db,
        _resolve_org(user, org_id),
        overdue_only=True,
        owner_id=owner_id,
        limit=limit,
        offset=offset,
    )


@router.get("/pending-verification")
@limiter.limit("60/minute")
def pending_verification(
    request: Request,
    response: Response,
    org_id: Optional[str] = Query(None),
    owner_id: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(require_permission("findings", "read")),
    db: Session = Depends(get_db),
):
    """
    Findings whose fix has been claimed and which are waiting for a scan.

    This is the queue that makes the verification requirement operable: an
    entry here is somebody's word that the work is done, and it stays here
    until an assessment agrees.
    """
    from core.remediation import STATE_PENDING_VERIFICATION

    return _listing(
        db,
        _resolve_org(user, org_id),
        states=[STATE_PENDING_VERIFICATION],
        owner_id=owner_id,
        limit=limit,
        offset=offset,
    )


@router.get("/findings/{finding_id}")
@limiter.limit("60/minute")
def finding_remediation(
    request: Request,
    response: Response,
    finding_id: str,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_permission("findings", "read")),
    db: Session = Depends(get_db),
):
    org = _resolve_org(user, org_id)
    finding = _get_finding(db, finding_id, org)
    return _serialize(finding, sla_setting=_sla_setting(db, org))


@router.get("/findings/{finding_id}/history")
@limiter.limit("60/minute")
def finding_history(
    request: Request,
    response: Response,
    finding_id: str,
    org_id: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    user: CurrentUser = Depends(require_permission("findings", "read")),
    db: Session = Depends(get_db),
):
    """
    Every remediation event for this finding, oldest first.

    Read from ``finding_remediation_events``, which nothing updates or
    deletes. So a changed owner, a moved due date or a withdrawn acceptance is
    answerable months later even though the finding row carries only the
    current values.
    """
    org = _resolve_org(user, org_id)
    _get_finding(db, finding_id, org)  # tenant gate

    events = (
        db.query(FindingRemediationEvent)
        .filter(
            FindingRemediationEvent.finding_id == finding_id,
            FindingRemediationEvent.org_id == org,
        )
        # Ties broken on the id: two events written in one transaction can
        # share `occurred_at`, and an ORDER BY on it alone leaves their
        # order undefined — a timeline that can show 'verified' before
        # the state change that led to it.
        .order_by(
            FindingRemediationEvent.occurred_at.asc(),
            FindingRemediationEvent.id.asc(),
        )
        .limit(limit)
        .all()
    )
    return {
        "finding_id": finding_id,
        "count": len(events),
        "events": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "from_state": e.from_state,
                "to_state": e.to_state,
                # One of these is set and the other is not. A system event
                # carries a label rather than an identity, so a reader can
                # tell a verification from a person's decision at a glance.
                "actor_id": e.actor_id,
                "actor_label": e.actor_label,
                "note": e.note,
                "scan_id": e.scan_id,
                "details": dict(e.details or {}),
                "occurred_at": _iso(e.occurred_at),
            }
            for e in events
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# SLA policy
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/sla-policy")
@limiter.limit("60/minute")
def get_sla_policy(
    request: Request,
    response: Response,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_permission("findings", "read")),
    db: Session = Depends(get_db),
):
    org = _resolve_org(user, org_id)
    policy = sla_policy_for_org_id(db, org)
    payload = policy.as_dict()
    payload["org_id"] = org
    payload["unit"] = "calendar days"
    payload["defaults"] = dict(DEFAULT_SLA_DAYS)
    return payload


@router.put("/sla-policy")
@limiter.limit("20/minute")
def set_sla_policy(
    request: Request,
    response: Response,
    body: RemediationSlaPolicyUpdate,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_permission("settings", "update")),
    db: Session = Depends(get_db),
):
    """
    Set this organisation's remediation deadlines.

    Stored in ``Organization.settings`` — JSONB, already carrying per-tenant
    configuration, so this needs no table. A partial update **merges** over
    the current values: an organisation changing only ``critical`` keeps its
    other five deadlines, where a replace would silently remove them and
    report thousands of findings as carrying no obligation.

    Changing the policy does **not** retroactively move existing due dates.
    They are recomputed on the next scan's sync, and the change is in the
    audit trail — rewriting thousands of historical deadlines from a settings
    edit would alter what a past report said was overdue.
    """
    org = _resolve_org(user, org_id)
    # The deadlines are the organisation's plan setting, platform-owned since
    # Phase 8.4, read and stored through core.remediation.sla (the seam). The
    # docstring above is the OpenAPI description and is left as it was.
    current = stored_sla_setting(db, org)
    if current is None:
        raise HTTPException(status_code=404, detail="Organisation not found.")

    if body.days_by_severity is not None:
        merged_days = dict(current.get("days_by_severity") or {})
        merged_days.update(body.days_by_severity)
        current["days_by_severity"] = merged_days
    if body.due_soon_window_days is not None:
        current["due_soon_window_days"] = body.due_soon_window_days
    if body.honour_kev_due_date is not None:
        current["honour_kev_due_date"] = body.honour_kev_due_date

    store_sla_setting(db, org, current)

    log_audit_event(
        db=db,
        user=user,
        action="remediation.sla_policy_updated",
        resource_type="organization",
        resource_id=org,
        changes=current,
        request=request,
    )
    db.commit()

    policy = sla_policy_for_org_id(db, org)
    payload = policy.as_dict()
    payload["org_id"] = org
    payload["unit"] = "calendar days"
    payload["note"] = (
        "Existing findings keep their recorded due dates; the new policy "
        "applies from the next scan that syncs them."
    )
    return payload


# ─────────────────────────────────────────────────────────────────────────────
# Writing
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/assign")
@limiter.limit("30/minute")
def assign(
    request: Request,
    response: Response,
    body: RemediationAssign,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_permission("findings", "update")),
    db: Session = Depends(get_db),
):
    """
    Assign, reassign or unassign remediation ownership, in bulk.

    The owner must be a user **in the same organisation**. Without that check
    a caller could name any user id in the installation and hand another
    tenant's employee a finding they can neither see nor act on.

    Findings the caller cannot see are silently absent from the result rather
    than erroring: a bulk call across a stale selection should not fail
    wholesale, and the response reports how many were actually changed.
    """
    org = _resolve_org(user, org_id)

    if body.owner_id:
        owner = platform_api.user(db, body.owner_id)
        if owner is None or owner.org_id != org:
            raise HTTPException(
                status_code=400,
                detail="The owner must be a user in this organisation.",
            )

    rows = (
        db.query(AssetVulnerability)
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(
            AssetVulnerability.id.in_(body.finding_ids),
            Asset.org_id == org,
        )
        .all()
    )
    if not rows:
        raise HTTPException(status_code=404, detail="No matching findings.")

    changed: List[str] = []
    for finding in rows:
        before = finding.remediation_owner
        assign_owner(
            db,
            finding,
            owner_id=body.owner_id,
            actor_id=str(user.id),
            note=body.note,
        )
        if finding.remediation_owner != before:
            changed.append(finding.id)

    log_audit_event(
        db=db,
        user=user,
        action="remediation.assigned" if body.owner_id else "remediation.unassigned",
        resource_type="finding",
        resource_id=",".join(changed[:20]) or "none",
        changes={"owner": body.owner_id, "count": len(changed)},
        request=request,
    )
    db.commit()
    return {
        "success": True,
        "requested": len(body.finding_ids),
        "matched": len(rows),
        "changed": len(changed),
        "owner_id": body.owner_id,
    }


@router.patch("/findings/{finding_id}/state")
@limiter.limit("60/minute")
def set_state(
    request: Request,
    response: Response,
    finding_id: str,
    body: RemediationStateUpdate,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_permission("findings", "update")),
    db: Session = Depends(get_db),
):
    """
    Move a finding through the remediation workflow.

    **``verified_fixed`` is refused here and that is the point of the phase.**
    The human transition table has no edge into it; a caller asking for it
    gets a 400 saying a subsequent scan has to establish it, and pointing at
    ``pending_verification`` — which is the claim a person is actually in a
    position to make.

    ``risk_accepted`` is refused too, but for a different reason: it needs a
    reason and an approver, so it has its own endpoint and its own permission.
    """
    org = _resolve_org(user, org_id)
    finding = _get_finding(db, finding_id, org)

    if body.state == STATE_RISK_ACCEPTED:
        raise HTTPException(
            status_code=400,
            detail=(
                "Accepting a risk needs a reason and an approver. Use "
                "POST /remediation/findings/{id}/accept-risk."
            ),
        )

    before = finding.remediation_state
    try:
        change_state(
            db, finding, target=body.state, actor_id=str(user.id), note=body.note
        )
    except TransitionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_audit_event(
        db=db,
        user=user,
        action="remediation.state_changed",
        resource_type="finding",
        resource_id=finding_id,
        changes={"from": before, "to": body.state},
        request=request,
    )
    db.commit()
    db.refresh(finding)
    return _serialize(finding, sla_setting=_sla_setting(db, org))


@router.post("/findings/{finding_id}/notes")
@limiter.limit("60/minute")
def append_note(
    request: Request,
    response: Response,
    finding_id: str,
    body: RemediationNote,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_permission("findings", "update")),
    db: Session = Depends(get_db),
):
    """
    Append a remediation note.

    The finding keeps the latest note in ``remediation_notes``, which the
    existing findings API and the reports already read. The event trail keeps
    every one, so replacing the note does not destroy what it said before.
    """
    org = _resolve_org(user, org_id)
    finding = _get_finding(db, finding_id, org)
    add_note(db, finding, note=body.note, actor_id=str(user.id))
    log_audit_event(
        db=db,
        user=user,
        action="remediation.note_added",
        resource_type="finding",
        resource_id=finding_id,
        request=request,
    )
    db.commit()
    db.refresh(finding)
    return _serialize(finding, sla_setting=_sla_setting(db, org))


@router.post("/findings/{finding_id}/accept-risk")
@limiter.limit("20/minute")
def accept_finding_risk(
    request: Request,
    response: Response,
    finding_id: str,
    body: RemediationAcceptRisk,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_permission("findings", "accept_risk")),
    db: Session = Depends(get_db),
):
    """
    Record a decision to carry the risk rather than fix it.

    Its own permission, deliberately. ``findings:update`` moves work through
    the queue; deciding the organisation will live with a critical finding is
    a different authorisation, and without the split anyone who can edit a
    finding could clear their overdue list by accepting everything on it.

    A reason is required and an expiry is optional. An acceptance that expires
    returns the finding to the remediation queue on beat; one that does not is
    a legitimate decision for a permanent compensating control, and
    ``accepted_at`` records when it was taken either way so it can still be
    found and reviewed.
    """
    org = _resolve_org(user, org_id)
    finding = _get_finding(db, finding_id, org)

    try:
        accept_risk(
            db,
            finding,
            reason=body.reason,
            actor_id=str(user.id),
            expires_at=body.expires_at,
        )
    except (TransitionError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_audit_event(
        db=db,
        user=user,
        action="remediation.risk_accepted",
        resource_type="finding",
        resource_id=finding_id,
        changes={
            "reason": body.reason,
            "expires_at": _iso(body.expires_at),
            "severity": finding.severity,
        },
        request=request,
        severity=(
            "high"
            if str(finding.severity or "").lower() in ("critical", "high")
            else None
        ),
    )
    db.commit()
    db.refresh(finding)
    return _serialize(finding, sla_setting=_sla_setting(db, org))


@router.post("/findings/{finding_id}/withdraw-acceptance")
@limiter.limit("20/minute")
def withdraw_finding_acceptance(
    request: Request,
    response: Response,
    finding_id: str,
    body: RemediationWithdraw,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_permission("findings", "accept_risk")),
    db: Session = Depends(get_db),
):
    """Return an accepted finding to the remediation queue by hand."""
    org = _resolve_org(user, org_id)
    finding = _get_finding(db, finding_id, org)
    try:
        withdraw_acceptance(db, finding, actor_id=str(user.id), note=body.note)
    except TransitionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_audit_event(
        db=db,
        user=user,
        action="remediation.acceptance_withdrawn",
        resource_type="finding",
        resource_id=finding_id,
        request=request,
    )
    db.commit()
    db.refresh(finding)
    return _serialize(finding, sla_setting=_sla_setting(db, org))


#: Coverage areas each route answers, read by
#: ``scripts/measure_remediation_coverage.py``. Declared here so an area
#: cannot claim coverage from a route that was removed.
ROUTE_AREAS = {
    ("/remediation/assign", "POST"): "rem.own.bulk",
    ("/remediation/summary", "GET"): "rem.rec.summary_api",
    ("/remediation/overdue", "GET"): "rem.sla.overdue",
    ("/remediation/pending-verification", "GET"): "rem.state.pending_verification",
    ("/remediation/findings/{finding_id}/history", "GET"): "rem.rec.history",
    ("/remediation/findings/{finding_id}/notes", "POST"): "rem.rec.notes",
    ("/remediation/findings/{finding_id}/accept-risk", "POST"): "rem.exc.grant",
    ("/remediation/sla-policy", "PUT"): "rem.sla.per_tenant",
}
