"""
routers/compliance_schedules.py
─────────────────────────────────────────────────────────────────────────────
Recurring compliance scans.

Part of the compliance router, split out of ``routers/compliance.py`` (G6,
C8 of docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md) and moved
unchanged; that module mounts the parts' sections in the order the API has
always listed them.
"""

import uuid
from ccure_platform.api import CurrentUser, log_audit_event, require_authorized
from core import compliance_frameworks
from datetime import datetime, timezone
from db.base import get_db
from db.models.compliance import (
    CompliancePolicy,
    ComplianceScanSchedule,
    ComplianceTenantFramework,
)
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

# Served as ``routers.compliance``: its routes' limiter keys, logger, gateway
# policy entries and model names are that module's, as they were before the
# split (see routers/compliance.py).
__name__ = "routers.compliance"  # noqa: A001


schedules = router = APIRouter()


class ScheduleCreate(BaseModel):
    framework_id: str
    policy_id: str
    frequency: str = Field(..., pattern="^(daily|weekly|monthly|quarterly|continuous)$")
    asset_ids: list[str] | None = None
    asset_tags: list[str] | None = None
    notify_on: str = Field("always", pattern="^(always|on_failure_only|on_score_drop)$")
    notify_channels: list[str] | None = None
    first_run_at: datetime | None = None


class ScheduleUpdate(BaseModel):
    is_active: bool | None = None
    frequency: str | None = Field(
        None, pattern="^(daily|weekly|monthly|quarterly|continuous)$"
    )
    notify_on: str | None = Field(
        None, pattern="^(always|on_failure_only|on_score_drop)$"
    )
    notify_channels: list[str] | None = None


# ─────────────────────────────────────────────────────────────────────────────
# 4.6. Scan Schedules
#
# `compliance_scan_schedules` has existed since the first compliance migration,
# Celery beat has polled it every sixty seconds, and `manage_schedules` has been
# a granted permission — with no endpoint that could create a row. Continuous
# assessment was unreachable end to end.
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/schedules", status_code=status.HTTP_201_CREATED)
def create_scan_schedule(
    payload: ScheduleCreate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(
        require_authorized("audit.compliance.manage_schedules")
    ),
):
    """Create a recurring compliance scan."""
    tf = (
        db.query(ComplianceTenantFramework)
        .filter_by(
            tenant_id=user.org_id, framework_id=payload.framework_id, is_enabled=True
        )
        .first()
    )
    if not tf:
        raise HTTPException(
            status_code=400, detail="Associated framework must be installed and active."
        )

    policy = (
        db.query(CompliancePolicy)
        .filter(
            CompliancePolicy.id == payload.policy_id,
            or_(
                CompliancePolicy.tenant_id == None,
                CompliancePolicy.tenant_id == user.org_id,
            ),
        )
        .first()
    )
    if not policy:
        raise HTTPException(status_code=404, detail="Policy baseline not found")

    schedule_id = f"csh_{uuid.uuid4().hex[:24]}"
    schedule = ComplianceScanSchedule(
        id=schedule_id,
        tenant_id=user.org_id,
        framework_id=payload.framework_id,
        policy_id=payload.policy_id,
        scope={
            "asset_ids": payload.asset_ids or [],
            "asset_tags": payload.asset_tags or [],
        },
        frequency=payload.frequency,
        notify_on=payload.notify_on,
        notify_channels=payload.notify_channels or [],
        is_active=True,
        # Due immediately on the next beat tick unless the caller says
        # otherwise, so a new schedule visibly does something.
        next_run_at=payload.first_run_at or datetime.now(timezone.utc),
    )
    db.add(schedule)
    log_audit_event(
        db, user, "create_schedule", "schedule", schedule_id, status="success"
    )
    db.commit()
    return {"message": "Schedule created", "schedule_id": schedule_id}


@router.get("/schedules")
def list_scan_schedules(
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.read")),
):
    """List this organization's compliance scan schedules."""
    # A schedule survives its framework being parked. `run_scheduled_scans`
    # now skips it, so listing it would offer an edit button on something that
    # will never fire.
    rows = (
        db.query(ComplianceScanSchedule)
        .filter(
            ComplianceScanSchedule.tenant_id == user.org_id,
            # See the scan-run listing above: parked-exclusion rather than
            # active-inclusion, so a loaded benchmark's schedules are visible.
            ~ComplianceScanSchedule.framework_id.in_(
                compliance_frameworks.parked_framework_ids()
            ),
        )
        .all()
    )
    return {
        "data": [
            {
                "id": s.id,
                "framework_id": s.framework_id,
                "policy_id": s.policy_id,
                "scope": s.scope,
                "frequency": s.frequency,
                "notify_on": s.notify_on,
                "notify_channels": s.notify_channels,
                "is_active": s.is_active,
                "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
                "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
            }
            for s in rows
        ]
    }


@router.patch("/schedules/{schedule_id}")
def update_scan_schedule(
    schedule_id: str,
    payload: ScheduleUpdate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(
        require_authorized("audit.compliance.manage_schedules")
    ),
):
    """Pause, resume or re-time a compliance scan schedule."""
    schedule = (
        db.query(ComplianceScanSchedule)
        .filter(
            ComplianceScanSchedule.id == schedule_id,
            ComplianceScanSchedule.tenant_id == user.org_id,
        )
        .first()
    )
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    if payload.is_active is not None:
        schedule.is_active = payload.is_active
    if payload.frequency is not None:
        schedule.frequency = payload.frequency
    if payload.notify_on is not None:
        schedule.notify_on = payload.notify_on
    if payload.notify_channels is not None:
        schedule.notify_channels = payload.notify_channels

    log_audit_event(
        db, user, "update_schedule", "schedule", schedule_id, status="success"
    )
    db.commit()
    return {"message": "Schedule updated"}


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_200_OK)
def delete_scan_schedule(
    schedule_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(
        require_authorized("audit.compliance.manage_schedules")
    ),
):
    """Remove a compliance scan schedule."""
    schedule = (
        db.query(ComplianceScanSchedule)
        .filter(
            ComplianceScanSchedule.id == schedule_id,
            ComplianceScanSchedule.tenant_id == user.org_id,
        )
        .first()
    )
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    db.delete(schedule)
    log_audit_event(
        db, user, "delete_schedule", "schedule", schedule_id, status="success"
    )
    db.commit()
    return {"message": "Schedule removed"}
