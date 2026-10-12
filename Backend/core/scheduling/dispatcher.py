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
standing authorisation. Scan scope and credential existence are
re-checked at dispatch:

* **Scope.** ``enforce_org_scan_scope`` runs against the organisation row as it
  is *now*. An operator who narrows the authorised range must have that take
  effect on the next run, not on the next time somebody edits the schedule.
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
from db.models import ScanSchedule, ScanScheduleRun
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

    from core.scan_scope import org_scan_scope

    # None when the organisation is gone — the same refusal as before.
    scope = org_scan_scope(db, schedule.org_id)
    if scope is None:
        raise ScheduleDispatchError(f"organisation {schedule.org_id} no longer exists")

    try:
        return validate_scan_targets(raw, scope=scope)
    except Exception as exc:  # noqa: BLE001 — the message is what the user reads
        # validate_scan_targets raises HTTPException; its `detail` is written
        # for a person, so it is exactly what belongs in the run record.
        detail = getattr(exc, "detail", None) or str(exc)
        raise ScheduleDispatchError(str(detail)) from exc


def _schedule_policy_options(db: Session, schedule: ScanSchedule, *, scan_kind: str):
    """
    Resolve the schedule's policy into the configuration this run will use.

    Called **before the scan row is created**, deliberately. ``create_scan``
    commits, so resolving afterwards and raising would leave a committed scan
    stuck in ``running`` that nothing ever dispatched — a ghost in Scan History
    for every night a schedule's policy was archived. The route helper avoids
    the same trap by deleting the row; here there is no need for one to exist.

    Re-resolved and re-validated at **every** dispatch, never inherited from
    the moment the schedule was written. A policy archived, disabled or
    narrowed in June must take effect on the next run, exactly as scan scope
    does — a schedule is a stored intent, not a standing
    authorisation.

    A policy that cannot be used raises :class:`ScheduleDispatchError`, so the
    run is recorded as failed **with the reason** rather than quietly falling
    back to the schedule's own ``scan_options``. Falling back is the failure
    this whole phase exists to remove: a nightly scan that silently stopped
    assessing what it was authorised to assess and went on reporting success.
    """
    from core.scan_policy import ResolvedPolicyError, resolve_policy

    options: Dict[str, Any] = dict(schedule.scan_options or {})
    try:
        resolution = resolve_policy(
            db,
            policy_id=schedule.policy_id,
            org_id=schedule.org_id,
            scan_kind=scan_kind,
            request_options=options,
            has_credential=bool(schedule.credential_id),
        )
        if resolution.policy.custom_ports:
            from core.utils import InputValidator

            InputValidator.parse_custom_ports(resolution.policy.custom_ports)
    except (ResolvedPolicyError, ValueError) as exc:
        raise ScheduleDispatchError(
            f"scan policy cannot be used for this run: {exc}"
        ) from exc

    effective = resolution.policy

    # The policy is authoritative for every setting it names; the schedule's
    # own scan_options fill in the rest. Written back into `options` so the
    # dispatch below reads one merged view rather than consulting two.
    for key, value in (
        ("custom_ports", effective.custom_ports),
        ("exclude_ports", effective.exclude_ports),
        ("discovery_intensity", effective.discovery_intensity),
        ("port_scan_intensity", effective.port_scan_intensity),
    ):
        if value:
            options[key] = value
    if effective.os_detection is not None:
        options["os_detection"] = effective.os_detection
    if effective.excluded_targets:
        options["exclude_ips"] = ",".join(effective.excluded_targets)
    if effective.sections:
        options["sections"] = list(effective.sections)

    return effective, options


def _count_policy_use(db: Session, schedule: ScanSchedule, effective) -> None:
    """
    Count a dispatched run against the policy that drove it.

    Best-effort: the counter warns an operator that a policy is in use, and
    failing a scheduled run over a statistics column would be a poor trade.
    ``GET /scan-policies/{id}/usage`` counts snapshots and is authoritative.
    """
    if not effective.policy_id:
        return
    from db.models.scan_policies import ScanPolicy

    row = (
        db.query(ScanPolicy)
        .filter(
            ScanPolicy.id == effective.policy_id,
            ScanPolicy.org_id == schedule.org_id,
        )
        .first()
    )
    if row is not None:
        row.use_count = int(row.use_count or 0) + 1


def _dispatch_network(
    db: Session, schedule: ScanSchedule, targets: List[str]
) -> DispatchOutcome:
    from core.celery_app import registered_task
    from core.task_names import RUN_HOST_DISCOVERY
    from scans.db_helpers import create_scan

    # Resolved before the scan row exists: `create_scan` commits, so a refusal
    # afterwards would leave a committed scan stuck in `running` that nothing
    # dispatched.
    effective, options = _schedule_policy_options(
        db, schedule, scan_kind=SCAN_KIND_NETWORK
    )
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
    _count_policy_use(db, schedule, effective)
    # Marking the origin on the scan itself is what lets Scan History show
    # "scheduled" beside a run without joining back through the run table.
    scan.options = {
        **(scan.options or {}),
        **{k: v for k, v in options.items() if k not in ("scan_type", "pipeline_mode")},
        "origin": "schedule",
        "schedule_id": schedule.id,
    }
    # Re-applied because the literal above rebuilds `options` wholesale and
    # would otherwise drop the snapshot written a moment ago.
    from core.scan_policy import record_policy_snapshot

    record_policy_snapshot(scan, effective, overwrite=True)
    db.flush()

    task = registered_task(RUN_HOST_DISCOVERY).delay(
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
    from core.celery_app import registered_task
    from core.task_names import RUN_CREDENTIALED_SCAN
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

    effective, options = _schedule_policy_options(
        db, schedule, scan_kind=SCAN_KIND_CREDENTIALED
    )
    scan = create_scan(
        db=db,
        user_id=schedule.created_by,
        target=", ".join(targets),
        targets=targets,
        scan_type="credentialed",
        pipeline_mode="credentialed",
        org_id=schedule.org_id,
    )
    _count_policy_use(db, schedule, effective)
    scan.options = {
        **(scan.options or {}),
        "origin": "schedule",
        "schedule_id": schedule.id,
    }
    from core.scan_policy import record_policy_snapshot

    record_policy_snapshot(scan, effective, overwrite=True)
    db.flush()

    # Only the credential *reference* travels to the worker. The task resolves
    # and decrypts it there. A schedule must never put a password in the broker
    # payload, which is what the manual route does with its request body.
    task = registered_task(RUN_CREDENTIALED_SCAN).delay(
        user_id=schedule.created_by,
        targets=targets,
        username=None,
        password=None,
        key_path=None,
        # Not ``or 22``: the task resolves the endpoint from the credential
        # it fetches, and an SSH port defaulted here for a Windows credential
        # would be a wrong answer standing in for a missing one.
        port=credential.port or None,
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
