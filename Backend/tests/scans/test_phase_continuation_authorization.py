"""
Phase 2 / Phase 3 continuation authorisation — Phase 1, finding F1.

`POST /scan/asset-discovery` and `POST /scan/vulnerability-audit` continue a
scan that Host Discovery admitted. Both loaded it with a bare
`Scan.id == scan_id` and dispatched whatever host records the client sent:

  * a caller in organisation A could name organisation B's scan, overwrite its
    options and task id, and have results written into it;
  * any address could be port-scanned and vulnerability-scanned by attaching it
    to a scan admitted for something else — outside the organisation's
    authorised scope.

The routes are called directly with a real session rather than through
TestClient with a login, which commits pending fixture rows (CLAUDE.md, "Scan
comparison and finding lifecycle").
"""

from native_rbac import grant_permissions, system_role, create_user, fixture_role


import asyncio
import uuid

import pytest
from fastapi import HTTPException, Response
from starlette.requests import Request

from ccure_platform.rbac.dependencies import has_permission
from db.base import gen_user_id, utcnow
from db.models import Organization, Scan, User
from routers import phase_scans
from routers.phase_scans import (
    AssetDiscoveryRequest,
    VulnerabilityAuditRequest,
    scan_asset_discovery,
    scan_vulnerability_audit,
)


class _Dispatched:
    """Stands in for `task.delay` and records what would have been sent."""

    def __init__(self):
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)

        class _Task:
            id = f"task-{uuid.uuid4().hex[:8]}"

        return _Task()


@pytest.fixture
def dispatched(monkeypatch):
    phase2, phase3 = _Dispatched(), _Dispatched()
    monkeypatch.setattr(phase_scans.run_asset_discovery_task, "delay", phase2)
    monkeypatch.setattr(phase_scans.run_vulnerability_audit_task, "delay", phase3)
    return phase2, phase3


@pytest.fixture
def created_scans(db_session):
    ids: list[str] = []
    yield ids
    db_session.rollback()
    if ids:
        db_session.query(Scan).filter(Scan.id.in_(ids)).delete(
            synchronize_session=False
        )
        db_session.commit()


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/scan/asset-discovery",
            "headers": [],
            "client": ("127.0.0.1", 50001),
            "query_string": b"",
        }
    )


def _scan(db, org_id, created_by, targets, created_scans, status="complete") -> Scan:
    scan = Scan(
        org_id=org_id,
        created_by=str(created_by),
        scan_no=900000 + len(created_scans),
        target_str=", ".join(targets),
        target_hosts=list(targets),
        scan_type="adaptive",
        pipeline_mode="vulnerability_audit",
        status=status,
        options={"marker": "untouched"},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    created_scans.append(str(scan.id))
    return scan


def _other_org_with_user(db) -> tuple[Organization, User]:
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        id=f"org_{uid}",
        name=f"Other Org {uid}",
        slug=f"other-org-{uid}",
        is_active=True,
    )
    db.add(org)
    db.commit()
    role = system_role(db, "platform.analyst")
    user = create_user(
        db,
        id=gen_user_id(org.slug, f"other{uid}"),
        username=f"other{uid}",
        email=f"other{uid}@test.com",
        full_name="Other",
        password_hash="x",
        org_id=org.id,
        role=role,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
        approved_by="fixture",
    )
    db.add(user)
    db.commit()
    return org, user


def _phase2(db, user, scan_id, hosts):
    return asyncio.run(
        scan_asset_discovery(
            request=_request(),
            response=Response(),
            req=AssetDiscoveryRequest(
                hosts=hosts, scan_id=scan_id, pipeline_mode="vulnerability_audit"
            ),
            org_id=None,
            user=user,
            db=db,
        )
    )


def _phase3(db, user, scan_id, hosts):
    return asyncio.run(
        scan_vulnerability_audit(
            request=_request(),
            response=Response(),
            req=VulnerabilityAuditRequest(
                hosts=hosts, scan_id=scan_id, pipeline_mode="vulnerability_audit"
            ),
            org_id=None,
            user=user,
            db=db,
        )
    )


# ── tenant isolation ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("phase", [_phase2, _phase3], ids=["phase2", "phase3"])
def test_another_organisations_scan_is_not_found_and_not_touched(
    phase, db_session, test_user, dispatched, created_scans
):
    other_org, other_user = _other_org_with_user(db_session)
    foreign = _scan(
        db_session, other_org.id, other_user.id, ["10.20.0.5"], created_scans
    )

    with pytest.raises(HTTPException) as exc:
        phase(db_session, test_user, str(foreign.id), [{"ip_address": "10.20.0.5"}])
    assert exc.value.status_code == 404

    db_session.expire_all()
    untouched = db_session.get(Scan, foreign.id)
    assert untouched.options == {"marker": "untouched"}
    assert untouched.current_task_id is None
    assert untouched.status == "complete"
    assert dispatched[0].calls == [] and dispatched[1].calls == []


@pytest.mark.parametrize("phase", [_phase2, _phase3], ids=["phase2", "phase3"])
def test_a_scan_id_is_required(phase, db_session, test_user, dispatched):
    with pytest.raises(HTTPException) as exc:
        phase(db_session, test_user, None, [{"ip_address": "10.20.0.5"}])
    assert exc.value.status_code == 422


def test_a_colleagues_scan_is_hidden_without_read_all(
    db_session, test_org, dispatched, created_scans
):
    # A role that may run and read scans but not everyone's scans. The seeded
    # analyst role holds audit.scan.read_all, so it cannot exercise this path.
    role = fixture_role(db_session, f"own_scans_{uuid.uuid4().hex[:10]}")
    db_session.add(role)
    db_session.flush()
    grant_permissions(db_session, role, "audit.scan.run", "audit.scan.read")
    db_session.commit()

    def _member(label):
        uid = uuid.uuid4().hex[:8]
        user = create_user(
            db_session,
            id=gen_user_id(test_org.slug, f"{label}{uid}"),
            username=f"{label}{uid}",
            email=f"{label}{uid}@test.com",
            full_name=label,
            password_hash="x",
            org_id=test_org.id,
            role=role,
            is_active=True,
            is_verified=True,
            approved_at=utcnow(),
            approved_by="fixture",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        return user

    owner, colleague = _member("owner"), _member("colleague")
    assert not has_permission(db_session, colleague, "audit.scan.read_all")
    scan = _scan(db_session, test_org.id, owner.id, ["10.30.0.5"], created_scans)

    with pytest.raises(HTTPException) as exc:
        _phase2(db_session, colleague, str(scan.id), [{"ip_address": "10.30.0.5"}])
    assert exc.value.status_code == 404
    assert dispatched[0].calls == []


# ── admitted targets and scope ───────────────────────────────────────────────


@pytest.mark.parametrize("phase", [_phase2, _phase3], ids=["phase2", "phase3"])
def test_hosts_outside_the_admitted_targets_are_refused(
    phase, db_session, test_user, dispatched, created_scans
):
    scan = _scan(
        db_session, test_user.org_id, test_user.id, ["10.40.0.0/30"], created_scans
    )

    with pytest.raises(HTTPException) as exc:
        phase(
            db_session,
            test_user,
            str(scan.id),
            [{"ip_address": "10.40.0.1"}, {"ip_address": "192.0.2.77"}],
        )
    assert exc.value.status_code == 403
    assert "192.0.2.77" in exc.value.detail
    assert dispatched[0].calls == [] and dispatched[1].calls == []


def test_hosts_outside_the_current_scope_are_refused(
    db_session, test_user, test_org, dispatched, created_scans
):
    # Admitted when the scope was wider; the organisation has since narrowed it.
    scan = _scan(
        db_session,
        test_user.org_id,
        test_user.id,
        ["10.60.0.10", "10.61.0.10"],
        created_scans,
    )
    test_org.scan_scope_cidrs = ["10.60.0.0/24"]
    db_session.commit()
    try:
        with pytest.raises(HTTPException) as exc:
            _phase2(db_session, test_user, str(scan.id), [{"ip_address": "10.61.0.10"}])
        assert exc.value.status_code == 403
        assert dispatched[0].calls == []
    finally:
        test_org.scan_scope_cidrs = None
        db_session.commit()


def test_a_host_record_without_an_address_is_refused(
    db_session, test_user, dispatched, created_scans
):
    scan = _scan(
        db_session, test_user.org_id, test_user.id, ["10.70.0.5"], created_scans
    )
    with pytest.raises(HTTPException) as exc:
        _phase2(db_session, test_user, str(scan.id), [{"hostname": "nameless"}])
    assert exc.value.status_code == 422


@pytest.mark.parametrize(
    "phase, index", [(_phase2, 0), (_phase3, 1)], ids=["phase2", "phase3"]
)
def test_admitted_hosts_of_ones_own_scan_are_dispatched(
    phase, index, db_session, test_user, dispatched, created_scans
):
    scan = _scan(
        db_session, test_user.org_id, test_user.id, ["10.80.0.0/29"], created_scans
    )
    hosts = [
        {"ip_address": "10.80.0.2", "is_active": True},
        {"ip": "10.80.0.3", "is_active": True},
    ]

    result = phase(db_session, test_user, str(scan.id), hosts)

    assert result["success"] is True
    calls = dispatched[index].calls
    assert len(calls) == 1
    assert calls[0]["scan_id"] == str(scan.id)
    assert calls[0]["hosts"] == hosts


# ── F4: an unimplemented profile is refused, not silently ignored ────────────


@pytest.mark.parametrize("profile", ["conservative", "deep", "Deep"])
def test_unimplemented_vulnerability_profiles_are_refused(profile):
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc:
        VulnerabilityAuditRequest(
            hosts=[{"ip_address": "10.80.0.2"}],
            scan_id="s",
            vulnerability_profile=profile,
        )
    assert "not implemented" in str(exc.value)


@pytest.mark.parametrize("profile", [None, "recommended", "Recommended"])
def test_the_implemented_profile_is_accepted(profile):
    req = VulnerabilityAuditRequest(
        hosts=[{"ip_address": "10.80.0.2"}], scan_id="s", vulnerability_profile=profile
    )
    assert req.vulnerability_profile == profile
