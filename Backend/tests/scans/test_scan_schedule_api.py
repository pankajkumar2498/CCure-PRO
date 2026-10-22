"""
tests/scans/test_scan_schedule_api.py
─────────────────────────────────────────────────────────────────────────────
Scan scheduling: API, RBAC, tenant isolation, dispatch and audit trail.

These exercise the real router against the real database. The Celery dispatch
itself is patched at ``.delay`` — the point under test is that scheduling
reaches the *existing* scan tasks with the right arguments, not that Nmap
works, which the scan suites already cover.
"""

from native_rbac import system_role, create_user

import uuid

import pytest
from db.base import gen_scan_schedule_id
from db.models import ComplianceCredential, Organization
from db.models.scan_schedules import ScanSchedule
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

BASE = "/scan-schedules"


def _daily(**overrides):
    body = {
        "name": f"nightly-{uuid.uuid4().hex[:8]}",
        "scan_kind": "network",
        "targets": ["192.0.2.0/30"],
        "recurrence": "daily",
        "timezone": "Asia/Kolkata",
        "run_at": "02:00",
    }
    body.update(overrides)
    return body


@pytest.fixture
def credential(db_session: Session, test_org: Organization) -> ComplianceCredential:
    """A stored credential to reference. The material never leaves the row."""
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


# ─────────────────────────────────────────────────────────────────────────────
# CRUD
# ─────────────────────────────────────────────────────────────────────────────


def test_create_read_update_delete(client: TestClient, auth_headers, db_session):
    created = client.post(BASE, json=_daily(), headers=auth_headers)
    assert created.status_code == 201, created.text
    schedule = created.json()
    assert schedule["recurrence"] == "daily"
    assert schedule["timezone"] == "Asia/Kolkata"
    assert schedule["run_at"] == "02:00"
    assert schedule["is_enabled"] is True
    assert schedule["next_run_at"], "creating a schedule must place its next run"

    listed = client.get(BASE, headers=auth_headers)
    assert listed.status_code == 200
    assert any(s["id"] == schedule["id"] for s in listed.json()["schedules"])

    fetched = client.get(f"{BASE}/{schedule['id']}", headers=auth_headers)
    assert fetched.status_code == 200
    assert fetched.json()["id"] == schedule["id"]

    edited = client.patch(
        f"{BASE}/{schedule['id']}", json={"run_at": "05:30"}, headers=auth_headers
    )
    assert edited.status_code == 200
    assert edited.json()["run_at"] == "05:30"

    removed = client.delete(f"{BASE}/{schedule['id']}", headers=auth_headers)
    assert removed.status_code == 200
    assert client.get(f"{BASE}/{schedule['id']}", headers=auth_headers).status_code == (
        404
    )


def test_editing_the_time_replaces_the_next_run(client, auth_headers):
    """
    Leaving the old ``next_run_at`` would keep firing on the previous cadence
    until the next dispatch — a schedule that visibly ignores the edit just
    made.
    """
    created = client.post(BASE, json=_daily(run_at="02:00"), headers=auth_headers)
    before = created.json()["next_run_at"]

    edited = client.patch(
        f"{BASE}/{created.json()['id']}",
        json={"run_at": "23:45"},
        headers=auth_headers,
    )
    assert edited.json()["next_run_at"] != before


def test_duplicate_names_within_one_org_are_refused(client, auth_headers):
    body = _daily()
    assert client.post(BASE, json=body, headers=auth_headers).status_code == 201
    clash = client.post(BASE, json=body, headers=auth_headers)
    assert clash.status_code == 409


# ─────────────────────────────────────────────────────────────────────────────
# Recurrence validation — 400s a person can act on, not constraint violations
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "body,fragment",
    [
        ({"recurrence": "weekly"}, "day_of_week"),
        ({"recurrence": "monthly"}, "day_of_month"),
        ({"recurrence": "once"}, "starts_at"),
        ({"recurrence": "custom"}, "cron_expression"),
    ],
)
def test_incomplete_recurrences_are_refused_with_a_readable_reason(
    client, auth_headers, body, fragment
):
    response = client.post(BASE, json=_daily(**body), headers=auth_headers)
    assert response.status_code == 400
    assert fragment in response.json()["detail"]


def test_a_cron_expression_outside_custom_is_refused(client, auth_headers):
    """Otherwise the column holds a value nothing reads — the dead-column trap
    that ``compliance_scan_schedules`` fell into."""
    response = client.post(
        BASE, json=_daily(cron_expression="0 2 * * *"), headers=auth_headers
    )
    assert response.status_code == 400
    assert "custom" in response.json()["detail"]


def test_a_fixed_offset_is_not_accepted_as_a_time_zone(client, auth_headers):
    """It cannot express daylight saving, so the schedule would be an hour out
    for half the year."""
    response = client.post(BASE, json=_daily(timezone="+05:30"), headers=auth_headers)
    assert response.status_code == 422


def test_a_reserved_scan_kind_cannot_be_scheduled(client, auth_headers):
    """
    The column admits `configuration`, `database`, `network_device` and `cloud`
    so a later phase needs no CHECK migration on a table holding customer data.
    Accepting one now would create a schedule that can never fire.
    """
    response = client.post(BASE, json=_daily(scan_kind="cloud"), headers=auth_headers)
    assert response.status_code == 422


def test_unusable_targets_are_refused_at_creation(client, auth_headers):
    response = client.post(BASE, json=_daily(targets=[]), headers=auth_headers)
    assert response.status_code == 400


# ─────────────────────────────────────────────────────────────────────────────
# Credentials — by reference only
# ─────────────────────────────────────────────────────────────────────────────


def test_a_credentialed_schedule_requires_a_credential_reference(client, auth_headers):
    response = client.post(
        BASE, json=_daily(scan_kind="credentialed"), headers=auth_headers
    )
    assert response.status_code == 400
    assert "credential_id" in response.json()["detail"]


def test_a_schedule_never_returns_credential_material(client, auth_headers, credential):
    """
    The response carries the credential's *name* so a UI can show which one is
    attached, and nothing that could be used. A password on a schedule would
    otherwise sit in the database, in every backup, and in the broker payload
    on every run.
    """
    created = client.post(
        BASE,
        json=_daily(scan_kind="credentialed", credential_id=credential.id),
        headers=auth_headers,
    )
    assert created.status_code == 201
    payload = created.json()
    assert payload["credential_id"] == credential.id
    assert payload["credential_name"] == credential.name
    body = created.text.lower()
    for forbidden in ("password", "encrypted_password", "key_content", "secret"):
        assert forbidden not in body, f"{forbidden!r} leaked into the response"


def test_a_credential_from_another_tenant_cannot_be_attached(
    client, auth_headers, db_session, credential
):
    """
    Without the tenant filter on the credential lookup, one organisation could
    attach another's stored credential and have the worker decrypt and use it.
    """
    from db.base import gen_compliance_credential_id, gen_org_id
    from core.security_crypto import encrypt_credential

    other = Organization(id=gen_org_id("otherco"), name="Other Co", slug="otherco")
    db_session.add(other)
    db_session.commit()
    foreign = ComplianceCredential(
        id=gen_compliance_credential_id(other.slug),
        tenant_id=other.id,
        name="foreign-cred",
        username="root",
        encrypted_password=encrypt_credential("nope"),
        port=22,
        auth_method="password",
    )
    db_session.add(foreign)
    db_session.commit()

    response = client.post(
        BASE,
        json=_daily(scan_kind="credentialed", credential_id=foreign.id),
        headers=auth_headers,
    )
    assert response.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# Tenant isolation
# ─────────────────────────────────────────────────────────────────────────────


def test_another_tenants_schedule_is_404_not_403(
    client, auth_headers, db_session, test_org
):
    """
    A 403 would confirm the id exists, which is an enumeration oracle across
    tenants. Both cases must be indistinguishable from outside.
    """
    from db.base import gen_org_id

    other = Organization(id=gen_org_id("rivalco"), name="Rival Co", slug="rivalco")
    db_session.add(other)
    db_session.commit()

    foreign = ScanSchedule(
        id=gen_scan_schedule_id(other.slug),
        org_id=other.id,
        name="theirs",
        scan_kind="network",
        targets=["10.0.0.1"],
        scan_options={},
        recurrence="daily",
        timezone="UTC",
        run_at_minute=120,
    )
    db_session.add(foreign)
    db_session.commit()

    for method, url in [
        ("get", f"{BASE}/{foreign.id}"),
        ("patch", f"{BASE}/{foreign.id}"),
        ("delete", f"{BASE}/{foreign.id}"),
        ("get", f"{BASE}/{foreign.id}/runs"),
    ]:
        call = getattr(client, method)
        response = (
            call(url, json={}, headers=auth_headers)
            if method == "patch"
            else call(url, headers=auth_headers)
        )
        assert response.status_code == 404, f"{method} {url} -> {response.status_code}"

    listed = client.get(BASE, headers=auth_headers).json()["schedules"]
    assert all(s["id"] != foreign.id for s in listed)


# ─────────────────────────────────────────────────────────────────────────────
# RBAC
# ─────────────────────────────────────────────────────────────────────────────


def test_every_schedule_route_requires_authentication(client):
    for method, url in [
        ("get", BASE),
        ("post", BASE),
        ("get", f"{BASE}/anything"),
        ("patch", f"{BASE}/anything"),
        ("delete", f"{BASE}/anything"),
        ("post", f"{BASE}/anything/enable"),
        ("post", f"{BASE}/anything/run-now"),
        ("get", f"{BASE}/anything/runs"),
        ("get", f"{BASE}/timezones"),
    ]:
        response = getattr(client, method)(url)
        assert response.status_code in (401, 403), f"{method} {url} was reachable"


def test_a_viewer_may_read_but_not_create_or_delete(
    client, db_session, test_org, auth_headers
):
    """
    ``viewer`` holds ``scan_schedules:read`` only. Read access matters — a
    viewer who can see scans should see what produces them — but creating one
    points this platform at a network unattended and is a different question.
    """
    from auth.jwt_handler import hash_password
    from db.base import gen_user_id, utcnow

    viewer_role = system_role(db_session, "platform.viewer")
    assert viewer_role is not None, "viewer role must be seeded"

    viewer = create_user(
        db_session,
        id=gen_user_id(test_org.slug, "viewer1"),
        username="viewer1",
        email="viewer1@test.com",
        full_name="Read Only",
        password_hash=hash_password("securepassword123"),
        org_id=test_org.id,
        role=viewer_role,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
        approved_by="fixture",
    )
    db_session.add(viewer)
    db_session.commit()

    login = client.post(
        "/auth/login",
        json={"email": "viewer1@test.com", "password": "securepassword123"},
    )
    assert login.status_code == 200
    viewer_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    assert client.get(BASE, headers=viewer_headers).status_code == 200

    owned = client.post(BASE, json=_daily(), headers=auth_headers).json()
    assert client.post(BASE, json=_daily(), headers=viewer_headers).status_code == 403
    assert (
        client.delete(f"{BASE}/{owned['id']}", headers=viewer_headers).status_code
        == 403
    )
    assert (
        client.post(f"{BASE}/{owned['id']}/run-now", headers=viewer_headers).status_code
        == 403
    )


# ─────────────────────────────────────────────────────────────────────────────
# Enable / disable
# ─────────────────────────────────────────────────────────────────────────────


def test_disabling_clears_the_next_run_and_enabling_restores_it(client, auth_headers):
    created = client.post(BASE, json=_daily(), headers=auth_headers).json()

    off = client.post(
        f"{BASE}/{created['id']}/enable",
        json={"is_enabled": False},
        headers=auth_headers,
    ).json()
    assert off["is_enabled"] is False
    assert off["next_run_at"] is None, (
        "a disabled schedule must not remain due; clearing next_run_at means "
        "the due query cannot pick it up even if the flag were missed"
    )

    on = client.post(
        f"{BASE}/{created['id']}/enable",
        json={"is_enabled": True},
        headers=auth_headers,
    ).json()
    assert on["is_enabled"] is True
    assert on["next_run_at"] is not None


def test_re_enabling_clears_the_failure_counter(client, auth_headers, db_session):
    """
    Without the reset, a schedule disabled automatically after five failures
    would be one failure away from switching itself off again.
    """
    created = client.post(BASE, json=_daily(), headers=auth_headers).json()
    row = db_session.query(ScanSchedule).filter_by(id=created["id"]).one()
    row.consecutive_failures = 4
    row.is_enabled = False
    db_session.commit()

    on = client.post(
        f"{BASE}/{created['id']}/enable",
        json={"is_enabled": True},
        headers=auth_headers,
    ).json()
    assert on["consecutive_failures"] == 0
    assert on["last_error"] is None


# ─────────────────────────────────────────────────────────────────────────────
# Run now — dispatch reaches the existing pipeline
# ─────────────────────────────────────────────────────────────────────────────


def test_run_now_dispatches_the_existing_network_scan_task(
    client, auth_headers, db_session, monkeypatch
):
    """
    The central claim of Phase 1: scheduling does not add a scan engine. A
    scheduled network scan must reach ``run_host_discovery_task`` — the same
    task ``POST /scan/host-discovery`` dispatches.
    """
    from scans.tasks import phases as tasks

    captured = {}

    class _Result:
        id = "task-network-1"

    def _fake_delay(**kwargs):
        captured.update(kwargs)
        return _Result()

    monkeypatch.setattr(tasks.run_host_discovery_task, "delay", _fake_delay)

    created = client.post(BASE, json=_daily(), headers=auth_headers).json()
    response = client.post(f"{BASE}/{created['id']}/run-now", headers=auth_headers)
    assert response.status_code == 200, response.text

    run = response.json()["run"]
    assert run["status"] == "dispatched"
    assert run["trigger"] == "manual"
    assert run["scan_id"], "a dispatched run must reference the scan it created"
    assert captured["targets"], "the existing task was called with targets"
    assert captured["scan_id"] == run["scan_id"]


def test_run_now_dispatches_the_existing_credentialed_task_by_reference(
    client, auth_headers, credential, monkeypatch
):
    """
    Only the credential *reference* may travel to the worker. The manual route
    puts a plaintext password in the task arguments; a schedule that did the
    same would put one in the broker payload on every run.
    """
    from scans.tasks import credentialed as tasks

    captured = {}

    class _Result:
        id = "task-cred-1"

    def _fake_delay(**kwargs):
        captured.update(kwargs)
        return _Result()

    monkeypatch.setattr(tasks.run_credentialed_scan_task, "delay", _fake_delay)

    created = client.post(
        BASE,
        json=_daily(scan_kind="credentialed", credential_id=credential.id),
        headers=auth_headers,
    ).json()
    response = client.post(f"{BASE}/{created['id']}/run-now", headers=auth_headers)
    assert response.status_code == 200, response.text
    assert response.json()["run"]["status"] == "dispatched"

    assert captured["credential_id"] == credential.id
    assert captured["password"] is None, "no secret may reach the task arguments"
    assert captured["key_path"] is None
    assert captured["username"] is None


def test_run_now_does_not_advance_the_recurrence(client, auth_headers, monkeypatch):
    """
    Testing a schedule at 11:00 must not cancel that night's real run.
    """
    from scans.tasks import phases as tasks

    class _Result:
        id = "task-network-2"

    monkeypatch.setattr(tasks.run_host_discovery_task, "delay", lambda **kw: _Result())

    created = client.post(BASE, json=_daily(), headers=auth_headers).json()
    before = created["next_run_at"]
    after = client.post(f"{BASE}/{created['id']}/run-now", headers=auth_headers).json()
    assert after["schedule"]["next_run_at"] == before


def test_run_now_works_on_a_disabled_schedule(client, auth_headers, monkeypatch):
    """
    "Disabled" means the recurrence does not fire by itself, not that the
    definition is unusable. Running one by hand is how an operator confirms a
    fix before switching it back on.
    """
    from scans.tasks import phases as tasks

    class _Result:
        id = "task-network-3"

    monkeypatch.setattr(tasks.run_host_discovery_task, "delay", lambda **kw: _Result())

    created = client.post(
        BASE, json=_daily(is_enabled=False), headers=auth_headers
    ).json()
    response = client.post(f"{BASE}/{created['id']}/run-now", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["run"]["status"] == "dispatched"


def test_a_failed_dispatch_is_recorded_with_its_reason(
    client, auth_headers, db_session, credential, monkeypatch
):
    """
    A dispatch can fail *before* a scan exists — a deleted credential, a target
    outside scope. Without a run row the user sees a schedule that silently
    never runs and no reason anywhere.
    """
    created = client.post(
        BASE,
        json=_daily(scan_kind="credentialed", credential_id=credential.id),
        headers=auth_headers,
    ).json()

    # Simulate the credential being deleted: the FK is ON DELETE SET NULL.
    row = db_session.query(ScanSchedule).filter_by(id=created["id"]).one()
    row.credential_id = None
    db_session.commit()

    response = client.post(f"{BASE}/{created['id']}/run-now", headers=auth_headers)
    assert response.status_code == 200
    run = response.json()["run"]
    assert run["status"] == "failed"
    assert run["scan_id"] is None
    assert "credential" in (run["detail"] or "").lower()

    history = client.get(f"{BASE}/{created['id']}/runs", headers=auth_headers).json()
    assert history["runs"][0]["status"] == "failed"
    assert history["runs"][0]["detail"]


# ─────────────────────────────────────────────────────────────────────────────
# Audit trail
# ─────────────────────────────────────────────────────────────────────────────


def test_schedule_changes_are_audited(client, auth_headers, db_session):
    from db.models import AuditLog

    created = client.post(BASE, json=_daily(), headers=auth_headers).json()
    client.patch(
        f"{BASE}/{created['id']}", json={"run_at": "04:00"}, headers=auth_headers
    )
    client.post(
        f"{BASE}/{created['id']}/enable",
        json={"is_enabled": False},
        headers=auth_headers,
    )
    client.delete(f"{BASE}/{created['id']}", headers=auth_headers)

    actions = {
        row.action
        for row in db_session.query(AuditLog)
        .filter(AuditLog.resource_id == created["id"])
        .all()
    }
    assert {
        "scan_schedule.created",
        "scan_schedule.updated",
        "scan_schedule.disabled",
        "scan_schedule.deleted",
    } <= actions, f"missing audit actions, got {actions}"
