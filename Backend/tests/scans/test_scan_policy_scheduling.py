"""
tests/scans/test_scan_policy_scheduling.py
─────────────────────────────────────────────────────────────────────────────
GAP-12 — a scheduled scan runs under its policy, re-checked at every dispatch.

Following ``test_scan_schedule_dispatcher.py``: the Celery dispatch is patched
at ``.delay`` because the point under test is that scheduling reaches the
*existing* scan tasks with the right configuration, not that Nmap works.

The rule these pin: **a schedule is a stored intent, not a standing
authorisation.** A policy archived, disabled or narrowed after the schedule was
written must take effect on the next run, and a policy that cannot be used must
fail the run loudly rather than falling back to the schedule's own options —
which would be a nightly scan that silently stopped assessing what it was
authorised to assess while still reporting success.

Coverage areas exercised: pol.bind.schedule, pol.record.snapshot,
pol.depth.ports, pol.depth.discovery, pol.select.sections.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from core.scan_policy import read_policy_snapshot
from db.base import gen_scan_schedule_id
from db.models import ComplianceCredential, Organization, ScanPolicy, User
from db.models.scan_schedules import ScanSchedule
from sqlalchemy.orm import Session


def _utc(**kwargs) -> datetime:
    return datetime.now(timezone.utc) + timedelta(**kwargs)


@pytest.fixture
def network_policy(db_session: Session, test_org: Organization) -> ScanPolicy:
    policy = ScanPolicy(
        id=f"spol_{uuid.uuid4().hex[:8]}",
        org_id=test_org.id,
        name="Nightly deep ports",
        policy_family_code="nightly-deep",
        version_number=1,
        scan_kind="network",
        config={
            "custom_ports": "1-1024",
            "discovery_intensity": "deep",
            "excluded_targets": ["192.0.2.9"],
        },
        status="active",
        is_enabled=True,
    )
    db_session.add(policy)
    db_session.commit()
    db_session.refresh(policy)
    return policy


@pytest.fixture
def credential(db_session: Session, test_org: Organization) -> ComplianceCredential:
    from core.security_crypto import encrypt_credential
    from db.base import gen_compliance_credential_id

    cred = ComplianceCredential(
        id=gen_compliance_credential_id(test_org.slug),
        tenant_id=test_org.id,
        name=f"ssh-{uuid.uuid4().hex[:6]}",
        username="root",
        encrypted_password=encrypt_credential("ccure-test-only"),
        port=22,
        auth_method="password",
    )
    db_session.add(cred)
    db_session.commit()
    db_session.refresh(cred)
    return cred


def _schedule(
    db_session: Session,
    org: Organization,
    user: User,
    *,
    scan_kind="network",
    policy_id=None,
    credential_id=None,
    scan_options=None,
) -> ScanSchedule:
    schedule = ScanSchedule(
        id=gen_scan_schedule_id(org.slug),
        org_id=org.id,
        created_by=str(user.id),
        name=f"nightly-{uuid.uuid4().hex[:6]}",
        scan_kind=scan_kind,
        targets=["192.0.2.1"],
        scan_options=dict(scan_options or {}),
        policy_id=policy_id,
        credential_id=credential_id,
        recurrence="daily",
        timezone="UTC",
        run_at_minute=120,
        is_enabled=True,
        next_run_at=_utc(minutes=-1),
    )
    db_session.add(schedule)
    db_session.commit()
    db_session.refresh(schedule)
    return schedule


class _Task:
    id = "task-abc"


@pytest.fixture
def captured_dispatch(monkeypatch):
    """Capture the arguments the schedule hands to the existing scan task."""
    captured = {}

    def _fake_delay(**kwargs):
        captured.update(kwargs)
        return _Task()

    import core.tasks as tasks

    monkeypatch.setattr(tasks.run_host_discovery_task, "delay", _fake_delay)
    monkeypatch.setattr(tasks.run_credentialed_scan_task, "delay", _fake_delay)
    return captured


# ─────────────────────────────────────────────────────────────────────────────
# pol.bind.schedule
# ─────────────────────────────────────────────────────────────────────────────


def test_a_scheduled_scan_runs_under_its_policy(
    db_session: Session,
    test_org: Organization,
    test_user: User,
    network_policy: ScanPolicy,
    captured_dispatch,
):
    """
    The policy's settings must reach the *existing* task, not a parallel one.
    """
    from core.scheduling.dispatcher import dispatch_schedule
    from db.models.scans import Scan

    schedule = _schedule(db_session, test_org, test_user, policy_id=network_policy.id)
    run = dispatch_schedule(db_session, schedule)
    assert run.status == "dispatched", run.detail

    assert captured_dispatch["custom_ports"] == "1-1024"
    assert captured_dispatch["discovery_intensity"] == "deep"
    assert captured_dispatch["exclude_ips"] == "192.0.2.9"

    # And the scan carries the record of what produced it.
    scan = db_session.query(Scan).filter(Scan.id == run.scan_id).first()
    recorded = read_policy_snapshot(scan)
    assert recorded is not None
    assert recorded.policy_id == network_policy.id
    assert recorded.custom_ports == "1-1024"


def test_invalid_policy_ports_fail_without_creating_or_dispatching_a_scan(
    db_session, test_org, test_user, network_policy, captured_dispatch
):
    from core.scheduling.dispatcher import dispatch_schedule
    from db.models.scans import Scan

    network_policy.config = {"custom_ports": "22,22"}
    db_session.commit()
    schedule = _schedule(db_session, test_org, test_user, policy_id=network_policy.id)
    before = db_session.query(Scan).count()

    run = dispatch_schedule(db_session, schedule)

    assert run.status == "failed"
    assert run.scan_id is None
    assert "duplicate" in run.detail.lower()
    assert db_session.query(Scan).count() == before
    assert not captured_dispatch


def test_the_policy_wins_over_the_schedules_own_options(
    db_session: Session,
    test_org: Organization,
    test_user: User,
    network_policy: ScanPolicy,
    captured_dispatch,
):
    from core.scheduling.dispatcher import dispatch_schedule

    schedule = _schedule(
        db_session,
        test_org,
        test_user,
        policy_id=network_policy.id,
        scan_options={"custom_ports": "22", "discovery_intensity": "light"},
    )
    dispatch_schedule(db_session, schedule)
    assert captured_dispatch["custom_ports"] == "1-1024"
    assert captured_dispatch["discovery_intensity"] == "deep"


def test_the_schedules_options_fill_in_what_the_policy_does_not_name(
    db_session: Session,
    test_org: Organization,
    test_user: User,
    network_policy: ScanPolicy,
    captured_dispatch,
):
    from core.scheduling.dispatcher import dispatch_schedule

    schedule = _schedule(
        db_session,
        test_org,
        test_user,
        policy_id=network_policy.id,
        scan_options={"exclude_ports": "9100", "port_scan_intensity": "light"},
    )
    dispatch_schedule(db_session, schedule)
    assert captured_dispatch["exclude_ports"] == "9100"
    assert captured_dispatch["port_scan_intensity"] == "light"


def test_a_schedule_with_no_policy_behaves_exactly_as_before(
    db_session: Session, test_org: Organization, test_user: User, captured_dispatch
):
    """
    The backward-compatibility rule. A schedule written before this phase must
    dispatch what it always did.
    """
    from core.scheduling.dispatcher import dispatch_schedule
    from db.models.scans import Scan

    schedule = _schedule(
        db_session,
        test_org,
        test_user,
        scan_options={"custom_ports": "80,443", "discovery_intensity": "light"},
    )
    run = dispatch_schedule(db_session, schedule)
    assert run.status == "dispatched"
    assert captured_dispatch["custom_ports"] == "80,443"
    assert captured_dispatch["discovery_intensity"] == "light"

    # It still records what it ran, so a later comparison can tell two such
    # scans apart — with no policy name, because none was chosen.
    scan = db_session.query(Scan).filter(Scan.id == run.scan_id).first()
    recorded = read_policy_snapshot(scan)
    assert recorded is not None
    assert recorded.source == "request"
    assert recorded.policy_id is None
    assert recorded.custom_ports == "80,443"


# ─────────────────────────────────────────────────────────────────────────────
# Re-checked at every dispatch, never inherited
# ─────────────────────────────────────────────────────────────────────────────


def test_a_disabled_policy_fails_the_run_rather_than_falling_back(
    db_session: Session,
    test_org: Organization,
    test_user: User,
    network_policy: ScanPolicy,
    captured_dispatch,
):
    """
    Falling back is the failure this phase exists to remove: a nightly scan
    that silently stopped assessing what it was authorised to assess.
    """
    from core.scheduling.dispatcher import dispatch_schedule

    schedule = _schedule(
        db_session,
        test_org,
        test_user,
        policy_id=network_policy.id,
        scan_options={"custom_ports": "22"},
    )
    network_policy.is_enabled = False
    db_session.commit()

    run = dispatch_schedule(db_session, schedule)
    assert run.status == "failed"
    assert "policy" in (run.detail or "").lower()
    assert not captured_dispatch, "nothing may be dispatched under a refused policy"


def test_an_archived_policy_fails_the_run(
    db_session: Session,
    test_org: Organization,
    test_user: User,
    network_policy: ScanPolicy,
    captured_dispatch,
):
    from core.scheduling.dispatcher import dispatch_schedule

    schedule = _schedule(db_session, test_org, test_user, policy_id=network_policy.id)
    network_policy.status = "archived"
    db_session.commit()

    run = dispatch_schedule(db_session, schedule)
    assert run.status == "failed"
    assert not captured_dispatch


def test_a_narrowed_policy_takes_effect_on_the_next_run(
    db_session: Session,
    test_org: Organization,
    test_user: User,
    network_policy: ScanPolicy,
    captured_dispatch,
):
    """
    A policy written in March and firing in November is a stored intent, not a
    standing authorisation.
    """
    from core.scheduling.dispatcher import dispatch_schedule

    schedule = _schedule(db_session, test_org, test_user, policy_id=network_policy.id)
    first = dispatch_schedule(db_session, schedule)
    assert captured_dispatch["custom_ports"] == "1-1024"

    # Complete the first run before checking the next policy snapshot.
    from db.models.scans import Scan

    db_session.query(Scan).filter(Scan.id == first.scan_id).update(
        {"status": "complete"}
    )
    db_session.commit()

    network_policy.config = {"custom_ports": "22,443"}
    captured_dispatch.clear()
    schedule.next_run_at = _utc(minutes=-1)
    db_session.commit()

    second = dispatch_schedule(db_session, schedule)
    assert second.status == "dispatched", second.detail
    assert captured_dispatch["custom_ports"] == "22,443"


def test_a_failed_policy_resolution_is_recorded_with_its_reason(
    db_session: Session,
    test_org: Organization,
    test_user: User,
    network_policy: ScanPolicy,
):
    """
    "The schedule stopped working" and "the schedule stopped working because
    the policy was archived on the 4th" are different things to an operator.
    """
    from core.scheduling.dispatcher import dispatch_schedule
    from db.models.scan_schedules import ScanScheduleRun

    schedule = _schedule(db_session, test_org, test_user, policy_id=network_policy.id)
    network_policy.status = "archived"
    db_session.commit()

    dispatch_schedule(db_session, schedule)
    # `dispatch_schedule` adds the run row and leaves the commit to its caller
    # — the beat task — so the row is flushed rather than committed here.
    db_session.flush()
    run = (
        db_session.query(ScanScheduleRun)
        .filter(ScanScheduleRun.schedule_id == schedule.id)
        .first()
    )
    assert run is not None, "a refused policy must still record the attempt"
    assert run.status == "failed"
    assert "archived" in (run.detail or "")
    assert run.scan_id is None, "a refused policy must not leave a scan behind"


# ─────────────────────────────────────────────────────────────────────────────
# Credentialed schedules
# ─────────────────────────────────────────────────────────────────────────────


def test_a_credentialed_schedule_carries_the_policys_sections(
    db_session: Session,
    test_org: Organization,
    test_user: User,
    credential: ComplianceCredential,
    captured_dispatch,
):
    from core.scheduling.dispatcher import dispatch_schedule
    from db.models.scans import Scan

    policy = ScanPolicy(
        id=f"spol_{uuid.uuid4().hex[:8]}",
        org_id=test_org.id,
        name="Packages only",
        policy_family_code="packages-only",
        version_number=1,
        scan_kind="credentialed",
        config={"sections": ["packages", "services"], "min_severity": "high"},
        status="active",
        is_enabled=True,
    )
    db_session.add(policy)
    db_session.commit()

    schedule = _schedule(
        db_session,
        test_org,
        test_user,
        scan_kind="credentialed",
        policy_id=policy.id,
        credential_id=credential.id,
    )
    run = dispatch_schedule(db_session, schedule)
    assert run.status == "dispatched", run.detail
    assert captured_dispatch["sections"] == ["packages", "services"]
    # The credential still travels by reference only.
    assert captured_dispatch["password"] is None
    assert captured_dispatch["credential_id"] == credential.id

    scan = db_session.query(Scan).filter(Scan.id == run.scan_id).first()
    assert read_policy_snapshot(scan).min_severity == "high"


def test_a_policy_requiring_a_credential_fails_a_schedule_without_one(
    db_session: Session,
    test_org: Organization,
    test_user: User,
    captured_dispatch,
):
    """
    A credentialed schedule whose credential was deleted must not run
    unauthenticated under a policy that said it may not.
    """
    from core.scheduling.dispatcher import dispatch_schedule

    policy = ScanPolicy(
        id=f"spol_{uuid.uuid4().hex[:8]}",
        org_id=test_org.id,
        name="Must authenticate",
        policy_family_code="must-auth",
        version_number=1,
        scan_kind="network",
        config={"require_credential": True},
        status="active",
        is_enabled=True,
    )
    db_session.add(policy)
    db_session.commit()

    schedule = _schedule(db_session, test_org, test_user, policy_id=policy.id)
    run = dispatch_schedule(db_session, schedule)
    assert run.status == "failed"
    assert "credential" in (run.detail or "").lower()
    assert not captured_dispatch


def test_the_scan_records_both_its_origin_and_its_policy(
    db_session: Session,
    test_org: Organization,
    test_user: User,
    network_policy: ScanPolicy,
    captured_dispatch,
):
    """
    ``origin`` and ``schedule_id`` predate this phase and must survive the
    options literal that also carries the snapshot.
    """
    from core.scheduling.dispatcher import dispatch_schedule
    from db.models.scans import Scan

    schedule = _schedule(db_session, test_org, test_user, policy_id=network_policy.id)
    run = dispatch_schedule(db_session, schedule)
    scan = db_session.query(Scan).filter(Scan.id == run.scan_id).first()

    assert scan.options["origin"] == "schedule"
    assert scan.options["schedule_id"] == schedule.id
    assert scan.options["scan_policy"]["policy_id"] == network_policy.id


def test_the_policy_use_count_advances_on_dispatch(
    db_session: Session,
    test_org: Organization,
    test_user: User,
    network_policy: ScanPolicy,
    captured_dispatch,
):
    from core.scheduling.dispatcher import dispatch_schedule

    before = network_policy.use_count
    schedule = _schedule(db_session, test_org, test_user, policy_id=network_policy.id)
    dispatch_schedule(db_session, schedule)
    db_session.refresh(network_policy)
    assert network_policy.use_count == before + 1
