"""
Moving a scan to the recycle bin, restoring it and purging it are audited.

Until 14 Oct 2026 none of the three wrote an audit event, unlike deleting a
credential: 25 validation scans were recycled and purged that day and the
audit trail holds no record of either. Purging also took the two kept assets'
whole service inventory with it (``services.scan_id`` is ON DELETE CASCADE),
which nothing recorded either.

The routes are called directly with a real session, as
``test_finding_comparison`` does, and ``commit`` is replaced by ``flush`` so
every row stays inside the test's transaction. Visibility is
``get_scan_or_404``'s job and is tested with it; it is stubbed here so these
tests are about what gets recorded.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException
from native_rbac import create_user
from starlette.requests import Request

from db.models import AuditLog, Organization, Service
from db.models.assets import Asset
from db.models.scans import Scan
from routers import scan_history


def _org(db, label: str) -> Organization:
    org = Organization(
        id=f"org_{label}_{uuid.uuid4().hex[:8]}",
        name=label,
        slug=f"{label}-{uuid.uuid4().hex[:8]}",
        is_active=True,
        settings={},
    )
    db.add(org)
    db.flush()
    return org


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "DELETE",
            "path": "/scans/x",
            "headers": [(b"user-agent", b"pytest-scan-lifecycle")],
            "client": ("192.0.2.9", 50000),
            "query_string": b"",
        }
    )


@pytest.fixture()
def world(db_session, monkeypatch):
    home = _org(db_session, "home")
    other = _org(db_session, "other")
    actor = create_user(
        db_session,
        username=f"lifecycle-{uuid.uuid4().hex[:6]}",
        email=f"lifecycle-{uuid.uuid4().hex[:6]}@test.com",
        password_hash="hash",
        org_id=home.id,
        is_active=True,
        is_verified=True,
    )

    def make_scan(org: Organization, **kw) -> Scan:
        scan = Scan(
            id=f"scn_{uuid.uuid4().hex[:10]}",
            org_id=org.id,
            created_by=actor.id,
            scan_no=7,
            target_str="192.0.2.45",
            scan_type="adaptive",
            pipeline_mode="asset",
            status="complete",
            **kw,
        )
        db_session.add(scan)
        db_session.flush()
        return scan

    monkeypatch.setattr(db_session, "commit", db_session.flush)
    monkeypatch.setattr(
        scan_history,
        "_get_scan_or_404",
        lambda scan_id, user, db, org_id=None: db.get(Scan, scan_id)
        or (_ for _ in ()).throw(HTTPException(status_code=404)),
    )
    return {
        "db": db_session,
        "home": home,
        "other": other,
        "actor": actor,
        "scan": make_scan,
    }


def _events(db, scan_id: str) -> list[AuditLog]:
    return (
        db.query(AuditLog)
        .filter(AuditLog.resource_type == "scan", AuditLog.resource_id == scan_id)
        .order_by(AuditLog.created_at, AuditLog.id)
        .all()
    )


def test_recycling_restoring_and_purging_each_leave_one_event(world):
    db, actor = world["db"], world["actor"]
    scan = world["scan"](world["home"])
    sid = scan.id

    scan_history.delete_scan(sid, _request(), db=db, user=actor)
    scan_history.restore_scan(sid, _request(), db=db, user=actor)
    scan_history.delete_scan(sid, _request(), db=db, user=actor)

    asset = Asset(
        id=f"ast_{uuid.uuid4().hex[:8]}", org_id=scan.org_id, ip_address="192.0.2.45"
    )
    db.add(asset)
    db.flush()
    db.add(
        Service(
            id=f"svc_{uuid.uuid4().hex[:8]}",
            scan_id=sid,
            asset_id=asset.id,
            port=22,
            protocol="tcp",
            state="open",
            discovery_source="network_scan",
            credentialed_confirmed=False,
        )
    )
    db.flush()
    scan_history.purge_scan(sid, _request(), db=db, user=actor)

    events = _events(db, sid)
    assert [e.action for e in events] == [
        "scan.recycled",
        "scan.restored",
        "scan.recycled",
        "scan.purged",
    ]
    assert [e.severity for e in events] == ["medium", "low", "medium", "high"]
    assert db.get(Scan, sid) is None

    restored = events[1].changes
    assert restored["restored_from"] == "recycle_bin"
    assert restored["destination"] == "active"

    purged = events[-1].changes
    assert purged["scan_no"] == 7 and purged["target"] == "192.0.2.45"
    # What the cascade took with it is on the record, counted before it went.
    assert purged["removed"] == {"findings": 0, "phases": 0}
    # The asset's service inventory is detached, not deleted (d5e7f9a1b3c6).
    assert purged["services_detached"] == 1
    (kept,) = db.query(Service).filter(Service.asset_id == asset.id).all()
    assert kept.scan_id is None
    assert purged["recycled_at"]

    for event in events:
        assert event.actor_user_id == actor.id
        assert event.user_agent == "pytest-scan-lifecycle"


def test_a_request_that_changes_nothing_records_nothing(world):
    db, actor = world["db"], world["actor"]
    scan = world["scan"](world["home"])

    scan_history.restore_scan(scan.id, _request(), db=db, user=actor)  # already active
    scan_history.delete_scan(scan.id, _request(), db=db, user=actor)
    scan_history.delete_scan(scan.id, _request(), db=db, user=actor)  # already recycled

    assert [e.action for e in _events(db, scan.id)] == ["scan.recycled"]


def test_purging_a_scan_outside_the_recycle_bin_is_refused_and_unrecorded(world):
    db, actor = world["db"], world["actor"]
    scan = world["scan"](world["home"])

    with pytest.raises(HTTPException) as refused:
        scan_history.purge_scan(scan.id, _request(), db=db, user=actor)
    assert refused.value.status_code == 400
    assert _events(db, scan.id) == []
    assert db.get(Scan, scan.id) is not None


def test_restoring_from_the_archive_says_so(world):
    db, actor = world["db"], world["actor"]
    scan = world["scan"](world["home"], is_archived=True)

    scan_history.restore_scan(scan.id, _request(), db=db, user=actor)

    (event,) = _events(db, scan.id)
    assert event.action == "scan.restored"
    assert event.changes["restored_from"] == "archive"


def test_events_are_filed_under_the_scans_organisation_not_the_actors(world):
    # A superadmin acting across organisations deletes *another* organisation's
    # evidence; that organisation's trail is where it has to appear.
    db, actor = world["db"], world["actor"]
    foreign = world["scan"](world["other"])

    scan_history.delete_scan(foreign.id, _request(), db=db, user=actor)

    (event,) = _events(db, foreign.id)
    assert event.org_id == world["other"].id != actor.org_id


def test_a_purge_detaches_services_in_the_model_the_orm_and_the_database(db_session):
    # Each half alone still deletes the inventory: the ORM's delete cascade
    # removes loaded rows before the database is asked, and a CASCADE foreign
    # key removes them however the ORM is configured. Alembic's drift check
    # does not compare ON DELETE rules, so this pins all three.
    from sqlalchemy import text

    column = Service.__table__.c.scan_id
    (foreign_key,) = column.foreign_keys
    assert (foreign_key.ondelete, column.nullable) == ("SET NULL", True)
    assert not Scan.services.property.cascade.delete
    definition = db_session.execute(
        text(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conname = 'services_scan_id_fkey'"
        )
    ).scalar()
    assert "ON DELETE SET NULL" in definition
