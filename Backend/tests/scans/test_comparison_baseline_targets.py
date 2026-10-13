"""
A scan's default comparison baseline is an earlier scan of the same hosts.

On 13 Oct 2026 an organisation scanning two hosts, 10.180.6.30 (Windows) and
10.180.6.45 (Linux), got baselines from the other machine: the Windows audit
was compared with the Linux one and reported "1406 new", and each credentialed
audit was refused against the other host's scan. ``previous_scan_for`` picked
the latest scan of the same mode in the organisation with no regard for what it
had scanned — and remediation verification reads the same baseline.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from core.findings.comparison import previous_scan_for, targets_overlap
from db.models.rbac import Organization
from db.models.scans import Scan


@pytest.fixture()
def org_id(db_session):
    oid = f"org_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Organization(
            id=oid,
            name="Baselines",
            slug=f"baselines-{uuid.uuid4().hex[:8]}",
            is_active=True,
            settings={},
        )
    )
    db_session.commit()
    return oid


_T0 = datetime(2026, 10, 13, 5, 0, tzinfo=timezone.utc)


def _scan(
    db_session, org_id, targets, minutes, mode="vulnerability_audit", status="complete"
):
    row = Scan(
        id=f"scn_{uuid.uuid4().hex[:12]}",
        org_id=org_id,
        target_str=", ".join(targets),
        target_hosts=list(targets),
        scan_type="adaptive",
        pipeline_mode=mode,
        status=status,
        created_at=_T0 + timedelta(minutes=minutes),
        started_at=_T0 + timedelta(minutes=minutes),
        completed_at=_T0 + timedelta(minutes=minutes + 3),
    )
    db_session.add(row)
    db_session.commit()
    return row


def test_another_hosts_scan_is_never_the_baseline(db_session, org_id):
    win_old = _scan(db_session, org_id, ["10.180.6.30"], 0)
    _scan(db_session, org_id, ["10.180.6.45"], 10)  # newer, other host
    win_now = _scan(db_session, org_id, ["10.180.6.30"], 20)

    assert previous_scan_for(db_session, win_now).id == win_old.id


def test_no_earlier_scan_of_these_hosts_means_no_baseline(db_session, org_id):
    _scan(db_session, org_id, ["10.180.6.45"], 0)
    first_win = _scan(db_session, org_id, ["10.180.6.30"], 10)

    assert previous_scan_for(db_session, first_win) is None


def test_a_sweep_covering_the_host_is_a_valid_baseline(db_session, org_id):
    sweep = _scan(db_session, org_id, ["10.180.6.0/24"], 0)
    one_host = _scan(db_session, org_id, ["10.180.6.30"], 10)

    assert previous_scan_for(db_session, one_host).id == sweep.id


def test_mode_and_status_still_apply(db_session, org_id):
    _scan(db_session, org_id, ["10.180.6.30"], 0, mode="asset")
    _scan(db_session, org_id, ["10.180.6.30"], 5, status="failed")
    current = _scan(db_session, org_id, ["10.180.6.30"], 10)

    assert previous_scan_for(db_session, current) is None


@pytest.mark.parametrize(
    "a,b,expected",
    [
        (["10.180.6.30"], ["10.180.6.30"], True),
        (["10.180.6.30"], ["10.180.6.45"], False),
        (["10.180.6.30", "10.180.6.45"], ["10.180.6.45"], True),
        (["10.180.6.0/24"], ["10.180.7.0/24"], False),
        (["10.180.4.0/22"], ["10.180.6.45"], True),
        (["host-a.example"], ["HOST-A.example"], True),
        (["host-a.example"], ["10.180.6.30"], False),
        (["::1"], ["127.0.0.1"], False),
    ],
)
def test_target_overlap(a, b, expected):
    sa = Scan(target_hosts=a, target_str=", ".join(a))
    sb = Scan(target_hosts=b, target_str=", ".join(b))
    assert targets_overlap(sa, sb) is expected
