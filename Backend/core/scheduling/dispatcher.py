"""
core/scheduling/dispatcher.py
──────────────────────────────────────────────────────────────────────────────
Turning a due schedule into a running scan.

**There is no second scan engine here.** A scheduled network scan calls
``run_host_discovery_task.delay(...)`` and a scheduled credentialed scan calls
``run_credentialed_scan_task.delay(...)`` — the same tasks, with the same
arguments, that ``routers/phase_scans.py`` and ``routers/credentialed.py``
dispatch when a person presses the button. This module's whole job is deciding
*whether* and *with what*, then recording what happened.

The gates are re-run, not inherited
───────────────────────────────────
A schedule created in March and firing in November is a stored intent, not a
standing authorisation. Scan scope, quota and credential existence are all
re-checked at dispatch:

* **Scope.** ``enforce_org_scan_scope`` runs against the organisation row as it
  is *now*. An operator who narrows the authorised range must have that take
  effect on the next run, not on the next time somebody edits the schedule.
* **Quota.** The same ``check_scan_quota`` the manual routes call. A schedule
  is not a way around the plan limit.
* **Credentials.** Resolved by reference. ``compliance_credentials.id`` is
  ``ON DELETE SET NULL`` from the schedule, so a deleted credential leaves
  ``credential_id`` NULL — which must fail the run loudly rather than silently
  attempting an unauthenticated scan that reports a host as clean.

Every one of those produces a recorded ``ScanScheduleRun`` with a reason. That
is the difference between "the schedule stopped working" and "the schedule
stopped working because the credential was deleted on the 4th".

Failure handling
────────────────
A failed dispatch increments ``consecutive_failures`` and, past a threshold,
disables the schedule. A schedule aimed at a decommissioned subnet would
otherwise produce a failed scan every day forever, and the noise buries the
schedules that matter. Any successful dispatch resets the counter to zero.

Nothing here catches ``Exception`` broadly and reports success. The compliance
scheduler does, and that is exactly how a ``TypeError`` on every single tick
went unnoticed long enough for it to emerge that scheduled compliance scanning
had never once run.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.scheduling.recurrence import RecurrenceSpec, compute_next_run
from db.base import gen_scan_schedule_run_id
from db.models import Organization, ScanSchedule, ScanScheduleRun
from db.models.scan_schedules import (
    RUN_STATUS_DISPATCHED,
    RUN_STATUS_FAILED,
    RUN_STATUS_SKIPPED,
    SCAN_KIND_CREDENTIALED,
    SCAN_KIND_NETWORK,
    TRIGGER_MANUAL,
    TRIGGER_SCHEDULE,
)
from sqlalchemy.orm import Session

log = logging.getLogger("ccure.scheduling")

__all__ = [
    "MAX_CONSECUTIVE_FAILURES",
    "DispatchOutcome",
    "advance_schedule",
    "dispatch_schedule",
    "due_schedules",
]

#: Consecutive failed dispatches before a schedule is disabled. Five is a
#: working week of a daily schedule — long enough that a transient outage does
#: not switch anything off, short enough that a permanently broken schedule
#: stops generating noise within a week.
MAX_CONSECUTIVE_FAILURES = 5


class ScheduleDispatchError(RuntimeError):
    """A dispatch that could not proceed, with an operator-readable reason."""


@dataclass
class DispatchOutcome:
    status: str
    detail: Optional[str] = None
    scan_id: Optional[str] = None
    celery_task_id: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status == RUN_STATUS_DISPATCHED


def due_schedules(db: Session, now: Optional[datetime] = None) -> List[ScanSchedule]:
    """
    Enabled schedules whose next run has arrived.

    ``next_run_at IS NULL`` is deliberately **not** treated as due. The
    compliance scheduler does treat it as due (``or_(next_run_at.is_(None),
    next_run_at <= now)``), which means any row written without a computed next
    run fires on the very next tick regardless of the time the user chose. Here
    a NULL next run means "not scheduled" — a one-time schedule that has already
    fired, or a custom recurrence nothing can place — and it stays dormant.
    """
    now = now or datetime.now(timezone.utc)
    return (
        db.query(ScanSchedule)
        .filter(
            ScanSchedule.is_enabled.is_(True),
            ScanSchedule.next_run_at.isnot(None),
            ScanSchedule.next_run_at <= now,
        )
        .order_by(ScanSchedule.next_run_at.asc())
        .all()
    )


def advance_schedule(schedule: ScanSchedule, now: Optional[datetime] = None) -> None:
    """
    Move ``next_run_at`` past the run that has just been taken.

    Computed from *now* rather than from the previous ``next_run_at`` so a beat
    tick that was late, or a worker that was down for a day, does not leave a
    schedule trying to catch up by firing repeatedly for every window it
    missed. A daily scan that missed Tuesday runs on Wednesday, once.

    ``compute_next_run`` returns ``None`` for a one-time schedule that has
    fired, which correctly leaves ``next_run_at`` NULL and makes it dormant.
    """
    now = now or datetime.now(timezone.utc)
    schedule.next_run_at = compute_next_run(RecurrenceSpec.from_schedule(schedule), now)


def _record_run(
    db: Session,
    schedule: ScanSchedule,
    outcome: DispatchOutcome,
    trigger: str,
    triggered_by: Optional[str],
    now: datetime,
) -> ScanScheduleRun:
    run = ScanScheduleRun(
        id=gen_scan_schedule_run_id(schedule.id)[:100],
        schedule_id=schedule.id,
        org_id=schedule.org_id,
        scan_id=outcome.scan_id,
        triggered_by=triggered_by,
        trigger=trigger,
        status=outcome.status,
        detail=outcome.detail,
        celery_task_id=outcome.celery_task_id,
        triggered_at=now,
    )
    db.add(run)

    schedule.last_run_at = now
    schedule.last_status = outcome.status
    schedule.last_error = None if outcome.ok else outcome.detail
    if outcome.scan_id:
        schedule.last_scan_id = outcome.scan_id
    schedule.total_run_count = (schedule.total_run_count or 0) + 1

    if outcome.ok:
        schedule.consecutive_failures = 0
    elif outcome.status == RUN_STATUS_FAILED:
        schedule.consecutive_failures = (schedule.consecutive_failures or 0) + 1
        if schedule.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
            schedule.is_enabled = False
            schedule.last_error = (
                f"{outcome.detail} — disabled automatically after "
                f"{schedule.consecutive_failures} consecutive failures."
            )
            log.warning(
                "Scan schedule %s disabled after %d consecutive failures: %s",
                schedule.id,
                schedule.consecutive_failures,
                outcome.detail,
            )
    return run


def _resolve_targets(db: Session, schedule: ScanSchedule) -> List[str]:
    """
    Expand and re-authorise the schedule's targets against current scope.

    Imported here rather than at module scope because ``scan_helpers`` pulls in
    the FastAPI limiter, and this module is imported by a Celery worker that
    has no application instance.
    """
    from scan_helpers import validate_scan_targets

    raw = [str(t).strip() for t in (schedule.targets or []) if str(t or "").strip()]
    if not raw:
        raise ScheduleDispatchError("the schedule has no targets")

    org = db.query(Organization).filter(Organization.id == schedule.org_id).first()
    if org is None:
        raise ScheduleDispatchError(f"organisation {schedule.org_id} no longer exists")

    try:
        return validate_scan_targets(raw, org=org)
    except Exception as exc:  # noqa: BLE001 — the message is what the user reads
        # validate_scan_targets raises HTTPException; its `detail` is written
        # for a person, so it is exactly what belongs in the run record.
        detail = getattr(exc, "detail", None) or str(exc)
        raise ScheduleDispatchError(str(detail)) from exc


def _dispatch_network(
    db: Session, schedule: ScanSchedule, targets: List[str]
) -> DispatchOutcome:
    from core.tasks import run_host_discovery_task
    from scans.db_helpers import create_scan

    options: Dict[str, Any] = dict(schedule.scan_options or {})
    scan_type = str(options.get("scan_type") or "adaptive")
    pipeline_mode = str(options.get("pipeline_mode") or "basic")

    scan = create_scan(
        db=db,
        user_id=schedule.created_by,
        target=", ".join(targets),
        targets=targets,
        scan_type=scan_type,
        pipeline_mode=pipeline_mode,
        org_id=schedule.org_id,
    )
    # Marking the origin on the scan itself is what lets Scan History show
    # "scheduled" beside a run without joining back through the run table.
    scan.options = {
        **(scan.options or {}),
        **{k: v for k, v in options.items() if k not in ("scan_type", "pipeline_mode")},
        "origin": "schedule",
        "schedule_id": schedule.id,
    }
    db.flush()

    task = run_host_discovery_task.delay(
        user_id=schedule.created_by,
        targets=targets,
        scan_type=scan_type,
        pipeline_mode=pipeline_mode,
        discovery_intensity=str(options.get("discovery_intensity") or "normal"),
        scan_id=str(scan.id),
        rate_limit=options.get("rate_limit"),
        max_concurrency=options.get("max_concurrency"),
        os_detection=options.get("os_detection"),
        port_scan_intensity=str(options.get("port_scan_intensity") or "normal"),
        custom_ports=options.get("custom_ports"),
        exclude_ports=options.get("exclude_ports"),
        passive_first=options.get("passive_first"),
        exclude_ot_from_nmap=options.get("exclude_ot_from_nmap"),
        exclude_ips=options.get("exclude_ips"),
    )
    scan.current_task_id = task.id
    return DispatchOutcome(
        status=RUN_STATUS_DISPATCHED, scan_id=str(scan.id), celery_task_id=task.id
    )


def _dispatch_credentialed(
    db: Session, schedule: ScanSchedule, targets: List[str]
) -> DispatchOutcome:
    from core.tasks import run_credentialed_scan_task
    from db.models import ComplianceCredential
    from scans.db_helpers import create_scan

    if not schedule.credential_id:
        # The foreign key is ON DELETE SET NULL, so this is what a deleted
        # credential looks like. Running anyway would perform an
        # unauthenticated scan and report a host as clean because nothing could
        # be collected from it — a false negative dressed as a result.
        raise ScheduleDispatchError(
            "no credential is attached to this schedule (it may have been "
            "deleted); a credentialed scan cannot run unauthenticated"
        )

    credential = (
        db.query(ComplianceCredential)
        .filter(
            ComplianceCredential.id == schedule.credential_id,
            ComplianceCredential.tenant_id == schedule.org_id,
        )
        .first()
    )
    if credential is None:
        raise ScheduleDispatchError(
            f"credential {schedule.credential_id} does not exist for this "
            "organisation"
        )

    options: Dict[str, Any] = dict(schedule.scan_options or {})
    scan = create_scan(
        db=db,
        user_id=schedule.created_by,
        target=", ".join(targets),
        targets=targets,
        scan_type="credentialed",
        pipeline_mode="credentialed",
        org_id=schedule.org_id,
    )
    scan.options = {
        **(scan.options or {}),
        "origin": "schedule",
        "schedule_id": schedule.id,
    }
    db.flush()

    # Only the credential *reference* travels to the worker. The task resolves
    # and decrypts it there. A schedule must never put a password in the broker
    # payload, which is what the manual route does with its request body.
    task = run_credentialed_scan_task.delay(
        user_id=schedule.created_by,
        targets=targets,
        username=None,
        password=None,
        key_path=None,
        port=credential.port or 22,
        auth_method=credential.auth_method or "password",
        sections=options.get("sections"),
        os_type_req=str(options.get("os_type") or "auto"),
        scan_id=str(scan.id),
        credential_id=credential.id,
    )
    scan.current_task_id = task.id
    return DispatchOutcome(
        status=RUN_STATUS_DISPATCHED, scan_id=str(scan.id), celery_task_id=task.id
    )


_DISPATCHERS = {
    SCAN_KIND_NETWORK: _dispatch_network,
    SCAN_KIND_CREDENTIALED: _dispatch_credentialed,
}


def dispatch_schedule(
    db: Session,
    schedule: ScanSchedule,
    *,
    trigger: str = TRIGGER_SCHEDULE,
    triggered_by: Optional[str] = None,
    now: Optional[datetime] = None,
    advance: bool = True,
) -> ScanScheduleRun:
    """
    Run one schedule now, record the attempt, and move its next run on.

    Always returns a :class:`ScanScheduleRun`; a failure is a recorded run with
    ``status='failed'``, never an exception escaping to the caller. The caller
    is a beat tick iterating many tenants' schedules, and one broken schedule
    must not stop the others from being evaluated.

    ``advance`` is False for a manual Run Now: pressing the button should not
    move the recurrence. Someone testing a schedule at 11:00 would otherwise
    skip that night's real run.
    """
    now = now or datetime.now(timezone.utc)

    try:
        dispatcher = _DISPATCHERS.get(schedule.scan_kind)
        if dispatcher is None:
            outcome = DispatchOutcome(
                status=RUN_STATUS_SKIPPED,
                detail=(
                    f"scan kind {schedule.scan_kind!r} is defined but not yet "
                    "dispatchable in this release"
                ),
            )
        else:
            targets = _resolve_targets(db, schedule)

            from core.quota import check_scan_quota

            try:
                check_scan_quota(db, org_id=schedule.org_id, targets=targets)
            except (
                Exception
            ) as exc:  # noqa: BLE001 — HTTPException detail is the message
                detail = getattr(exc, "detail", None) or str(exc)
                # Over quota is not a broken schedule: it is a working schedule
                # meeting a limit, and it must not count toward the failure
                # threshold that disables it.
                outcome = DispatchOutcome(
                    status=RUN_STATUS_SKIPPED, detail=f"scan quota: {detail}"
                )
            else:
                outcome = dispatcher(db, schedule, targets)

    except ScheduleDispatchError as exc:
        outcome = DispatchOutcome(status=RUN_STATUS_FAILED, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        # Deliberately broad, and deliberately *recorded* rather than
        # swallowed: the run row carries the exception type and message, and
        # the log carries the traceback. The compliance scheduler's equivalent
        # returned {"success": False} with the reason discarded.
        log.exception("Scan schedule %s failed to dispatch", schedule.id)
        outcome = DispatchOutcome(
            status=RUN_STATUS_FAILED, detail=f"{type(exc).__name__}: {exc}"
        )

    run = _record_run(db, schedule, outcome, trigger, triggered_by, now)

    if advance and trigger == TRIGGER_SCHEDULE:
        advance_schedule(schedule, now)

    return run
