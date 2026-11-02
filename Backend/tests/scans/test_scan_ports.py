"""
The scan ports below the scans capability (31 Oct 2026).

Three capabilities beneath scans read or created scan records by importing
them, and scan policy read scheduling's table, which held assets, compliance,
scan policy, scans and scheduling in one cycle:

* the asset timeline's scan labels — ``core.asset_scans``;
* a scan policy's scan usage — ``core.scan_policy.scan_usage``;
* the scan row a scheduled run creates — ``core.scheduling.scan_records``;
* the schedules naming a policy — ``core.scan_policy.schedule_references``.

These pin that the three consumers import neither owner, that the application
registers each owner's answer, that an unregistered port refuses rather than
answering empty, and that the moved queries answer what the routers asked.
The dispatcher's scan creation through its port is exercised end to end by
``test_scan_schedule_dispatcher.py`` and ``test_scan_policy_scheduling.py``.
"""

import itertools
import uuid

import pytest
from db.base import gen_scan_schedule_id
from db.models import Organization, Scan, ScanPolicy, User
from db.models.scan_schedules import ScanSchedule
from scripts.architecture import capability_map
from scripts.architecture.import_graph import collect_edges
from sqlalchemy.orm import Session

import core.asset_scans as asset_scans
import core.scan_policy.scan_usage as scan_usage
import core.scan_policy.schedule_references as schedule_references
import core.scheduling.scan_records as scan_records

#: Each consumer, and the capabilities it reaches only through a port.
CONSUMERS = {
    "routers.assets": {"scans"},
    "routers.scan_policies": {"scans", "scheduling"},
    "core.scheduling.dispatcher": {"scans"},
}


def test_the_consumers_import_neither_owner():
    """Lazy imports count; they are how the codebase hid its couplings."""
    _, edges = capability_map.capability_edges(graph=collect_edges())
    reached = sorted(
        (e.src, e.dst)
        for e in edges
        if e.src in CONSUMERS
        and capability_map.capability_of(e.dst) in CONSUMERS[e.src]
    )
    assert reached == []


def test_the_application_registers_each_owners_answer():
    import ccure_audit.policy_references  # noqa: F401  (main.py imports it)
    import ccure_audit.scan_directory  # noqa: F401  (Celery's imports name it)
    from core.scheduling import policy_references
    from scans import reads

    assert asset_scans._pipeline_modes is reads.pipeline_modes
    assert scan_usage._counter is reads.scans_recorded_under
    assert scan_records._creator is not None
    assert schedule_references._references is policy_references.REFERENCES


def test_a_second_different_answer_is_refused():
    with pytest.raises(ValueError):
        asset_scans.register_pipeline_modes(lambda db, ids: {})
    with pytest.raises(ValueError):
        scan_usage.register_scan_usage(lambda db, org, pid: 0)
    with pytest.raises(ValueError):
        scan_records.register_scan_creator(lambda **kw: None)
    with pytest.raises(ValueError):
        schedule_references.register_schedule_references(object())


@pytest.mark.parametrize(
    "module, attr, call, missing",
    [
        (
            asset_scans,
            "_pipeline_modes",
            lambda: asset_scans.pipeline_modes(None, ["scn_1"]),
            asset_scans.AssetScanLabelsMissing,
        ),
        (
            scan_usage,
            "_counter",
            lambda: scan_usage.scans_recorded_under(None, "org_1", "spol_1"),
            scan_usage.ScanUsageMissing,
        ),
        (
            scan_records,
            "_creator",
            lambda: scan_records.create_scan(
                None,
                user_id="usr_1",
                target="192.0.2.1",
                targets=["192.0.2.1"],
                scan_type="adaptive",
                pipeline_mode="basic",
                org_id="org_1",
            ),
            scan_records.ScanCreatorMissing,
        ),
        (
            schedule_references,
            "_references",
            lambda: schedule_references.schedules_using(None, "org_1", "spol_1"),
            schedule_references.ScheduleReferencesMissing,
        ),
    ],
)
def test_an_unregistered_port_refuses_rather_than_answering_empty(
    monkeypatch, module, attr, call, missing
):
    """No answer is not zero scans, no schedules or no labels."""
    monkeypatch.setattr(module, attr, None)
    with pytest.raises(missing):
        call()


_scan_numbers = itertools.count(1)


def _scan(db: Session, org: Organization, *, mode: str, policy_id=None) -> Scan:
    options = {"scan_policy": {"policy_id": policy_id}} if policy_id else {}
    scan = Scan(
        id=f"scn_ports_{uuid.uuid4().hex[:8]}",
        org_id=org.id,
        scan_no=next(_scan_numbers),  # unique within an organisation
        target_str="192.0.2.1",
        scan_type="adaptive",
        pipeline_mode=mode,
        status="complete",
        options=options,
    )
    db.add(scan)
    db.flush()
    return scan


def _policy(db: Session, org: Organization) -> ScanPolicy:
    policy = ScanPolicy(
        id=f"spol_{uuid.uuid4().hex[:8]}",
        org_id=org.id,
        name=f"ports-{uuid.uuid4().hex[:6]}",
        policy_family_code=f"ports-{uuid.uuid4().hex[:6]}",
        version_number=1,
        scan_kind="network",
        config={},
        status="active",
        is_enabled=True,
    )
    db.add(policy)
    db.flush()
    return policy


def _schedule(
    db: Session, org: Organization, user: User, policy: ScanPolicy, *, enabled: bool
) -> ScanSchedule:
    schedule = ScanSchedule(
        id=gen_scan_schedule_id(org.slug),
        org_id=org.id,
        created_by=str(user.id),
        name=f"nightly-{uuid.uuid4().hex[:6]}",
        scan_kind="network",
        targets=["192.0.2.1"],
        scan_options={},
        policy_id=policy.id,
        recurrence="daily",
        timezone="UTC",
        run_at_minute=120,
        is_enabled=enabled,
    )
    db.add(schedule)
    db.flush()
    return schedule


def test_the_timeline_reads_the_modes_of_the_scans_that_exist(
    db_session: Session, test_org: Organization
):
    audit = _scan(db_session, test_org, mode="vulnerability_audit")
    basic = _scan(db_session, test_org, mode="basic")

    modes = asset_scans.pipeline_modes(db_session, [audit.id, basic.id, "scn_gone"])

    assert modes == {audit.id: "vulnerability_audit", basic.id: "basic"}
    assert asset_scans.pipeline_modes(db_session, []) == {}


def test_a_policys_usage_counts_its_own_organisations_snapshots(
    db_session: Session, test_org: Organization
):
    policy = _policy(db_session, test_org)
    _scan(db_session, test_org, mode="basic", policy_id=policy.id)
    _scan(db_session, test_org, mode="basic", policy_id=policy.id)
    _scan(db_session, test_org, mode="basic", policy_id="spol_other")
    _scan(db_session, test_org, mode="basic")

    assert scan_usage.scans_recorded_under(db_session, test_org.id, policy.id) == 2
    assert scan_usage.scans_recorded_under(db_session, "org_elsewhere", policy.id) == 0


def test_the_schedules_naming_a_policy_are_scheduling_s_answer(
    db_session: Session, test_org: Organization, test_user: User
):
    policy = _policy(db_session, test_org)
    on = _schedule(db_session, test_org, test_user, policy, enabled=True)
    off = _schedule(db_session, test_org, test_user, policy, enabled=False)

    every = schedule_references.schedules_using(db_session, test_org.id, policy.id)
    enabled = schedule_references.schedules_using(
        db_session, test_org.id, policy.id, enabled_only=True
    )

    assert {(s.id, s.name, s.is_enabled) for s in every} == {
        (on.id, on.name, True),
        (off.id, off.name, False),
    }
    assert [s.id for s in enabled] == [on.id]
    assert schedule_references.schedule_count(db_session, policy.id) == 2
    assert (
        schedule_references.schedules_using(db_session, "org_elsewhere", policy.id)
        == []
    )
