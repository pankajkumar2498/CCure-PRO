"""
tests/scans/test_scan_schedule_dispatcher.py
─────────────────────────────────────────────────────────────────────────────
The beat side: which schedules are due, what happens when one fails, and the
guarantee that a scheduled run reaches the existing scan pipeline.

The Celery ``.delay`` is patched throughout. What is under test is the
scheduler's decisions, not Nmap.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from core.scheduling.dispatcher import (
    MAX_CONSECUTIVE_FAILURES,
    advance_schedule,
    dispatch_schedule,
    due_schedules,
)
from db.base import gen_scan_schedule_id
from db.models import Organization
from db.models.scan_schedules import (
    RUN_STATUS_DISPATCHED,
    RUN_STATUS_FAILED,
    RUN_STATUS_SKIPPED,
    TRIGGER_MANUAL,
    ScanSchedule,
    ScanScheduleRun,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def make_schedule(db_session, test_org, test_user):
    created = []

    def _make(**overrides):
        payload = {
            "id": gen_scan_schedule_id(test_org.slug) + uuid.uuid4().hex[:4],
            "org_id": test_org.id,
            "created_by": str(test_user.id),
            "name": f"sched-{uuid.uuid4().hex[:8]}",
            "scan_kind": "network",
            "targets": ["192.0.2.8"],
            "scan_options": {},
            "recurrence": "daily",
            "timezone": "UTC",
            "run_at_minute": 120,
            "is_enabled": True,
            "next_run_at": _now() - timedelta(minutes=1),
        }
        payload.update(overrides)
        schedule = ScanSchedule(**payload)
        db_session.add(schedule)
        db_session.commit()
        created.append(schedule)
        return schedule

    yield _make


@pytest.fixture
def fake_network_task(monkeypatch):
    """Capture the arguments the existing network scan task is called with."""
    from scans.tasks import phases as tasks

    captured = {}

    class _Result:
        id = "task-" + uuid.uuid4().hex[:8]

    def _delay(**kwargs):
        captured.update(kwargs)
        return _Result()

    monkeypatch.setattr(tasks.run_host_discovery_task, "delay", _delay)
    return captured


# ─────────────────────────────────────────────────────────────────────────────
# Due selection
# ─────────────────────────────────────────────────────────────────────────────


def test_only_enabled_and_due_schedules_are_selected(db_session, make_schedule):
    due_now = make_schedule(next_run_at=_now() - timedelta(minutes=5))
    future = make_schedule(next_run_at=_now() + timedelta(hours=5))
    disabled = make_schedule(
        is_enabled=False, next_run_at=_now() - timedelta(minutes=5)
    )

    selected = {s.id for s in due_schedules(db_session)}
    assert due_now.id in selected
    assert future.id not in selected
    assert disabled.id not in selected


def test_a_null_next_run_is_dormant_not_due(db_session, make_schedule):
    """
    ``compliance.run_scheduled_scans`` treats NULL as due
    (``or_(next_run_at.is_(None), next_run_at <= now)``), so any row written
    without a computed next run fires on the very next tick regardless of the
    time the user chose. Here NULL means "not scheduled" — a one-time schedule
    that has fired, or a custom recurrence nothing can place.
    """
    dormant = make_schedule(next_run_at=None)
    assert dormant.id not in {s.id for s in due_schedules(db_session)}


# ─────────────────────────────────────────────────────────────────────────────
# Dispatch reaches the existing pipeline
# ─────────────────────────────────────────────────────────────────────────────


def test_a_scheduled_network_scan_calls_the_existing_task(
    db_session, make_schedule, fake_network_task
):
    schedule = make_schedule(scan_options={"pipeline_mode": "asset"})
    run = dispatch_schedule(db_session, schedule)
    db_session.commit()

    assert run.status == RUN_STATUS_DISPATCHED
    assert run.trigger == "schedule"
    assert fake_network_task["pipeline_mode"] == "asset"
    assert fake_network_task["scan_id"] == run.scan_id


def test_a_scheduled_scan_is_marked_with_its_origin(
    db_session, make_schedule, fake_network_task
):
    """
    Scan History shows scheduled and manual runs side by side; without the
    marker they are indistinguishable and "why did this scan happen?" has no
    answer.
    """
    from db.models import Scan

    schedule = make_schedule()
    run = dispatch_schedule(db_session, schedule)
    db_session.commit()

    scan = db_session.query(Scan).filter(Scan.id == run.scan_id).one()
    assert scan.options.get("origin") == "schedule"
    assert scan.options.get("schedule_id") == schedule.id


def test_dispatch_advances_the_recurrence(db_session, make_schedule, fake_network_task):
    schedule = make_schedule(next_run_at=_now() - timedelta(minutes=1))
    dispatch_schedule(db_session, schedule)
    db_session.commit()
    assert schedule.next_run_at > _now(), "the schedule must not stay due"


def test_a_late_tick_does_not_replay_every_missed_window(
    db_session, make_schedule, fake_network_task
):
    """
    Next run is computed from *now*, not from the previous ``next_run_at``. A
    worker down for a week must not come back and fire seven times.
    """
    schedule = make_schedule(next_run_at=_now() - timedelta(days=7))
    dispatch_schedule(db_session, schedule)
    db_session.commit()
    assert schedule.next_run_at > _now()
    assert schedule.next_run_at < _now() + timedelta(days=2)


def test_a_one_time_schedule_goes_dormant_after_firing(
    db_session, make_schedule, fake_network_task
):
    schedule = make_schedule(
        recurrence="once",
        starts_at=_now() - timedelta(minutes=1),
        next_run_at=_now() - timedelta(minutes=1),
    )
    dispatch_schedule(db_session, schedule)
    db_session.commit()

    assert schedule.next_run_at is None
    assert schedule.id not in {s.id for s in due_schedules(db_session)}


# ─────────────────────────────────────────────────────────────────────────────
# Failure handling
# ─────────────────────────────────────────────────────────────────────────────


def test_a_failed_dispatch_records_a_run_with_no_scan(db_session, make_schedule):
    """
    The failure happens before a Scan exists, which is exactly why the run
    table has to exist separately from the scan table.
    """
    schedule = make_schedule(scan_kind="credentialed", credential_id=None)
    run = dispatch_schedule(db_session, schedule)
    db_session.commit()

    assert run.status == RUN_STATUS_FAILED
    assert run.scan_id is None
    assert "credential" in run.detail.lower()
    assert schedule.consecutive_failures == 1
    assert schedule.last_error


def test_repeated_failures_disable_the_schedule(db_session, make_schedule):
    """
    A schedule aimed at a decommissioned subnet would otherwise produce a
    failed scan every day forever, and the noise buries the schedules that
    matter.
    """
    schedule = make_schedule(scan_kind="credentialed", credential_id=None)
    for _ in range(MAX_CONSECUTIVE_FAILURES):
        dispatch_schedule(db_session, schedule)
        db_session.commit()

    assert schedule.consecutive_failures >= MAX_CONSECUTIVE_FAILURES
    assert schedule.is_enabled is False
    assert "disabled automatically" in schedule.last_error


def test_a_success_resets_the_failure_counter(
    db_session, make_schedule, fake_network_task
):
    schedule = make_schedule()
    schedule.consecutive_failures = 3
    db_session.commit()

    dispatch_schedule(db_session, schedule)
    db_session.commit()
    assert schedule.consecutive_failures == 0
    assert schedule.last_error is None


def test_a_broken_schedule_never_raises_out_of_dispatch(db_session, make_schedule):
    """
    The caller is a beat tick iterating many tenants' schedules. One broken
    schedule must not stop the others being evaluated.
    """
    schedule = make_schedule(targets=[])
    run = dispatch_schedule(db_session, schedule)
    db_session.commit()
    assert run.status == RUN_STATUS_FAILED
    assert run.detail


def test_a_reserved_scan_kind_is_skipped_not_failed(db_session, make_schedule):
    """
    Skipped, because nothing is wrong with the schedule — the capability is
    simply not built yet, and it must not count toward the failure threshold
    that would disable it.
    """
    schedule = make_schedule(scan_kind="cloud")
    run = dispatch_schedule(db_session, schedule)
    db_session.commit()

    assert run.status == RUN_STATUS_SKIPPED
    assert schedule.consecutive_failures == 0
    assert schedule.is_enabled is True


def test_targets_are_re_authorised_against_current_scope(
    db_session, make_schedule, test_org, fake_network_task
):
    """
    A schedule created in March and firing in November is a stored intent, not
    a standing authorisation. Narrowing the organisation's scan scope must take
    effect on the next run.
    """
    schedule = make_schedule(targets=["203.0.113.5"])
    # The column is scan_scope_cidrs; an earlier draft of this test set a
    # non-existent `scan_scope` attribute, which silently left the scope NULL
    # (meaning "unrestricted") and made the test pass a dispatch it should
    # have refused.
    test_org.scan_scope_cidrs = ["192.0.2.0/24"]
    db_session.commit()

    run = dispatch_schedule(db_session, schedule)
    db_session.commit()

    assert run.status == RUN_STATUS_FAILED, (
        "a target outside the organisation's current scan scope must not be "
        "scanned just because it was in scope when the schedule was written"
    )
    assert run.scan_id is None


# ─────────────────────────────────────────────────────────────────────────────
# Manual trigger
# ─────────────────────────────────────────────────────────────────────────────


def test_a_manual_run_does_not_advance_the_schedule(
    db_session, make_schedule, fake_network_task, test_user
):
    schedule = make_schedule(next_run_at=_now() + timedelta(hours=6))
    before = schedule.next_run_at

    run = dispatch_schedule(
        db_session,
        schedule,
        trigger=TRIGGER_MANUAL,
        triggered_by=str(test_user.id),
        advance=False,
    )
    db_session.commit()

    assert run.trigger == TRIGGER_MANUAL
    assert run.triggered_by == str(test_user.id)
    assert schedule.next_run_at == before


# ─────────────────────────────────────────────────────────────────────────────
# The beat task itself
# ─────────────────────────────────────────────────────────────────────────────


def test_the_beat_task_dispatches_due_schedules(
    db_session, make_schedule, fake_network_task
):
    from scans.tasks.schedules import run_due_scan_schedules

    schedule = make_schedule(next_run_at=_now() - timedelta(minutes=1))
    db_session.commit()

    result = run_due_scan_schedules()
    assert result["success"] is True
    assert result["dispatched"] >= 1

    db_session.expire_all()
    refreshed = db_session.query(ScanSchedule).filter_by(id=schedule.id).one()
    assert refreshed.next_run_at > _now()
    assert (
        db_session.query(ScanScheduleRun).filter_by(schedule_id=schedule.id).count()
        >= 1
    )


def test_a_second_concurrent_tick_backs_off_instead_of_double_dispatching(
    db_session, make_schedule, fake_network_task, monkeypatch
):
    """
    Exactly one beat process is supposed to run, but two is the classic
    operational mistake and a Celery task can be redelivered after a worker
    dies. ``pg_try_advisory_xact_lock`` returns false rather than waiting, so
    the second tick exits instead of queueing behind the first and dispatching
    everything twice.
    """
    import scans.tasks.schedules as tasks  # the module whose code reads SessionLocal

    make_schedule(next_run_at=_now() - timedelta(minutes=1))
    db_session.commit()

    real_execute = tasks.SessionLocal

    class _Session:
        """A session whose advisory-lock attempt always reports contention."""

        def __init__(self):
            self._inner = real_execute()

        def execute(self, statement, params=None):
            text = str(statement)
            if "pg_try_advisory_xact_lock" in text:

                class _R:
                    @staticmethod
                    def scalar():
                        return False

                return _R()
            return self._inner.execute(statement, params or {})

        def __getattr__(self, name):
            return getattr(self._inner, name)

    monkeypatch.setattr(tasks, "SessionLocal", _Session)
    result = tasks.run_due_scan_schedules()

    assert result["success"] is True
    assert result["skipped_locked"] is True
    assert result["dispatched"] == 0
