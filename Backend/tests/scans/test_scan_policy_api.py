"""
tests/scans/test_scan_policy_api.py
─────────────────────────────────────────────────────────────────────────────
GAP-12 — the policy API: CRUD, RBAC, tenant isolation, lifecycle, audit trail.

These exercise the real router against the real database, following
``test_scan_schedule_api.py``. Every fixture commits, which is what makes the
``TestClient`` + ``auth_headers`` pattern safe here — CLAUDE.md records what
happens when it is used while uncommitted fixture rows are outstanding.

Coverage areas exercised: pol.crud.create, pol.crud.read, pol.crud.update,
pol.crud.archive, pol.crud.enable, pol.authz.rbac, pol.authz.tenant,
pol.authz.audit, pol.lifecycle.version, pol.bind.validation,
pol.bind.schedule.
"""

import uuid

import pytest
from auth.jwt_handler import hash_password
from db.base import gen_user_id, utcnow
from db.models import AuditLog, Organization, Role, ScanPolicy, User
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

BASE = "/scan-policies"


def _policy(**overrides):
    body = {
        "name": f"baseline-{uuid.uuid4().hex[:8]}",
        "scan_kind": "credentialed",
        "config": {"min_severity": "high"},
        "status": "active",
    }
    body.update(overrides)
    return body


@pytest.fixture
def other_org(db_session: Session) -> Organization:
    """A second tenant, so isolation can be exercised rather than asserted."""
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        id=f"org_{uid}",
        name=f"Other Org {uid}",
        slug=f"other-org-{uid}",
        max_assets=10,
        max_users=5,
        is_active=True,
    )
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)
    return org


@pytest.fixture
def other_org_policy(db_session: Session, other_org: Organization) -> ScanPolicy:
    policy = ScanPolicy(
        id=f"spol_other_{uuid.uuid4().hex[:6]}",
        org_id=other_org.id,
        name="Their baseline",
        policy_family_code="their-baseline",
        version_number=1,
        scan_kind="any",
        config={"min_severity": "low"},
        status="active",
        is_enabled=True,
    )
    db_session.add(policy)
    db_session.commit()
    db_session.refresh(policy)
    return policy


@pytest.fixture
def viewer_headers(client: TestClient, db_session: Session, test_org: Organization):
    """A viewer: scan_policies:read only, no create/update/delete."""
    role = db_session.query(Role).filter(Role.name == "viewer").first()
    password = "viewerpassword123"
    user = User(
        id=gen_user_id(test_org.slug, "policyviewer"),
        username="policyviewer",
        email=f"viewer-{uuid.uuid4().hex[:6]}@test.com",
        full_name="Policy Viewer",
        password_hash=hash_password(password),
        org_id=test_org.id,
        role_id=role.id,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
        approved_by="fixture",
    )
    db_session.add(user)
    db_session.commit()
    resp = client.post("/auth/login", json={"email": user.email, "password": password})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


# ─────────────────────────────────────────────────────────────────────────────
# pol.crud.create / pol.crud.read / pol.crud.update / pol.crud.archive
# ─────────────────────────────────────────────────────────────────────────────


def test_create_read_update_delete(client: TestClient, auth_headers):
    created = client.post(BASE, json=_policy(), headers=auth_headers)
    assert created.status_code == 201, created.text
    policy = created.json()
    assert policy["status"] == "active"
    assert policy["is_usable"] is True
    assert policy["version_number"] == 1
    assert policy["fingerprint"], "a policy must carry a configuration identifier"

    listed = client.get(BASE, headers=auth_headers)
    assert listed.status_code == 200
    assert any(p["id"] == policy["id"] for p in listed.json()["policies"])

    fetched = client.get(f"{BASE}/{policy['id']}", headers=auth_headers)
    assert fetched.status_code == 200
    assert fetched.json()["id"] == policy["id"]

    edited = client.patch(
        f"{BASE}/{policy['id']}",
        json={"config": {"min_severity": "low"}},
        headers=auth_headers,
    )
    assert edited.status_code == 200, edited.text
    assert edited.json()["config"]["min_severity"] == "low"
    # Editing what is assessed must move the fingerprint.
    assert edited.json()["fingerprint"] != policy["fingerprint"]

    removed = client.delete(f"{BASE}/{policy['id']}", headers=auth_headers)
    assert removed.status_code == 200
    assert client.get(f"{BASE}/{policy['id']}", headers=auth_headers).status_code == 404


def test_renaming_a_policy_does_not_change_its_fingerprint(
    client: TestClient, auth_headers
):
    """A rename is not a scope change; GAP-13 must not report it as one."""
    created = client.post(BASE, json=_policy(), headers=auth_headers).json()
    renamed = client.patch(
        f"{BASE}/{created['id']}",
        json={"name": f"renamed-{uuid.uuid4().hex[:6]}"},
        headers=auth_headers,
    )
    assert renamed.status_code == 200
    assert renamed.json()["fingerprint"] == created["fingerprint"]


def test_duplicate_names_are_refused(client: TestClient, auth_headers):
    body = _policy()
    assert client.post(BASE, json=body, headers=auth_headers).status_code == 201
    clash = client.post(BASE, json=body, headers=auth_headers)
    assert clash.status_code == 409


def test_an_invalid_configuration_is_refused_with_every_reason(
    client: TestClient, auth_headers
):
    created = client.post(
        BASE,
        json=_policy(config={"min_severity": "catastrophic", "platforms": ["aix"]}),
        headers=auth_headers,
    )
    assert created.status_code == 400
    errors = created.json()["detail"]["errors"]
    assert len(errors) == 2


def test_a_policy_cannot_be_created_already_archived(client: TestClient, auth_headers):
    created = client.post(BASE, json=_policy(status="archived"), headers=auth_headers)
    assert created.status_code == 422


def test_warnings_reach_the_response(client: TestClient, auth_headers):
    created = client.post(
        BASE,
        json=_policy(scan_kind="any", config={"allow_intrusive": True}),
        headers=auth_headers,
    )
    assert created.status_code == 201
    assert any("intrusive" in w.lower() for w in created.json()["warnings"])


# ─────────────────────────────────────────────────────────────────────────────
# pol.crud.enable
# ─────────────────────────────────────────────────────────────────────────────


def test_disabling_a_policy_makes_it_unusable_without_deleting_it(
    client: TestClient, auth_headers
):
    created = client.post(BASE, json=_policy(), headers=auth_headers).json()
    disabled = client.post(
        f"{BASE}/{created['id']}/enable",
        json={"is_enabled": False},
        headers=auth_headers,
    )
    assert disabled.status_code == 200
    assert disabled.json()["is_enabled"] is False
    assert disabled.json()["is_usable"] is False
    # Still there, still readable — that is the difference from a delete.
    assert (
        client.get(f"{BASE}/{created['id']}", headers=auth_headers).status_code == 200
    )


def test_disabling_names_the_schedules_it_breaks(
    client: TestClient, auth_headers, db_session: Session, test_org: Organization
):
    """
    A schedule running unnoticed under the request defaults because its policy
    was disabled would assess something other than what was authorised.
    """
    created = client.post(
        BASE, json=_policy(scan_kind="network"), headers=auth_headers
    ).json()
    schedule = client.post(
        "/scan-schedules",
        json={
            "name": f"nightly-{uuid.uuid4().hex[:6]}",
            "scan_kind": "network",
            "targets": ["192.0.2.0/30"],
            "recurrence": "daily",
            "timezone": "UTC",
            "run_at": "02:00",
            "policy_id": created["id"],
        },
        headers=auth_headers,
    )
    assert schedule.status_code == 201, schedule.text

    disabled = client.post(
        f"{BASE}/{created['id']}/enable",
        json={"is_enabled": False},
        headers=auth_headers,
    )
    assert disabled.status_code == 200
    assert any("schedule" in w for w in disabled.json().get("warnings", []))


# ─────────────────────────────────────────────────────────────────────────────
# pol.lifecycle.version
# ─────────────────────────────────────────────────────────────────────────────


def test_a_new_version_supersedes_and_archives_the_previous(
    client: TestClient, auth_headers
):
    first = client.post(BASE, json=_policy(), headers=auth_headers).json()
    second = client.post(
        f"{BASE}/{first['id']}/version",
        json={"config": {"min_severity": "critical"}, "activate": True},
        headers=auth_headers,
    )
    assert second.status_code == 201, second.text
    payload = second.json()
    assert payload["version_number"] == 2
    assert payload["policy_family_code"] == first["policy_family_code"]
    assert payload["supersedes"] == first["id"]

    # The old one is archived but still readable — a scan that ran under it
    # must still resolve to a policy a reader can look up.
    old = client.get(f"{BASE}/{first['id']}", headers=auth_headers).json()
    assert old["status"] == "archived"
    assert old["superseded_by_policy_id"] == payload["id"]


def test_an_archived_policy_is_not_edited(client: TestClient, auth_headers):
    first = client.post(BASE, json=_policy(), headers=auth_headers).json()
    client.post(
        f"{BASE}/{first['id']}/version",
        json={"config": {"min_severity": "critical"}},
        headers=auth_headers,
    )
    edited = client.patch(
        f"{BASE}/{first['id']}",
        json={"description": "after the fact"},
        headers=auth_headers,
    )
    assert edited.status_code == 409


def test_a_policy_cannot_return_to_draft(client: TestClient, auth_headers):
    created = client.post(BASE, json=_policy(), headers=auth_headers).json()
    back = client.post(
        f"{BASE}/{created['id']}/status", json={"status": "draft"}, headers=auth_headers
    )
    assert back.status_code == 409


def test_archiving_is_refused_while_an_enabled_schedule_uses_it(
    client: TestClient, auth_headers
):
    created = client.post(
        BASE, json=_policy(scan_kind="network"), headers=auth_headers
    ).json()
    client.post(
        "/scan-schedules",
        json={
            "name": f"nightly-{uuid.uuid4().hex[:6]}",
            "scan_kind": "network",
            "targets": ["192.0.2.0/30"],
            "recurrence": "daily",
            "timezone": "UTC",
            "run_at": "03:00",
            "policy_id": created["id"],
        },
        headers=auth_headers,
    )
    archived = client.post(
        f"{BASE}/{created['id']}/status",
        json={"status": "archived"},
        headers=auth_headers,
    )
    assert archived.status_code == 409
    assert "schedule" in archived.json()["detail"]


def test_deleting_is_refused_while_a_schedule_uses_it_unless_forced(
    client: TestClient, auth_headers
):
    created = client.post(
        BASE, json=_policy(scan_kind="network"), headers=auth_headers
    ).json()
    client.post(
        "/scan-schedules",
        json={
            "name": f"nightly-{uuid.uuid4().hex[:6]}",
            "scan_kind": "network",
            "targets": ["192.0.2.0/30"],
            "recurrence": "daily",
            "timezone": "UTC",
            "run_at": "04:00",
            "policy_id": created["id"],
        },
        headers=auth_headers,
    )
    refused = client.delete(f"{BASE}/{created['id']}", headers=auth_headers)
    assert refused.status_code == 409

    forced = client.delete(f"{BASE}/{created['id']}?force=true", headers=auth_headers)
    assert forced.status_code == 200
    assert forced.json()["orphaned_schedules"]


# ─────────────────────────────────────────────────────────────────────────────
# pol.authz.tenant
# ─────────────────────────────────────────────────────────────────────────────


def test_another_tenants_policy_is_404_not_403(
    client: TestClient, auth_headers, other_org_policy: ScanPolicy
):
    """
    A 403 would confirm the id exists, which is a cross-tenant enumeration
    oracle. Every verb must answer the same way.
    """
    pid = other_org_policy.id
    assert client.get(f"{BASE}/{pid}", headers=auth_headers).status_code == 404
    assert (
        client.patch(f"{BASE}/{pid}", json={"description": "x"}, headers=auth_headers)
    ).status_code == 404
    assert (
        client.post(
            f"{BASE}/{pid}/enable", json={"is_enabled": False}, headers=auth_headers
        )
    ).status_code == 404
    assert (
        client.post(
            f"{BASE}/{pid}/status", json={"status": "archived"}, headers=auth_headers
        )
    ).status_code == 404
    assert client.delete(f"{BASE}/{pid}", headers=auth_headers).status_code == 404
    assert client.get(f"{BASE}/{pid}/usage", headers=auth_headers).status_code == 404


def test_listing_never_shows_another_tenants_policy(
    client: TestClient, auth_headers, other_org_policy: ScanPolicy
):
    listed = client.get(BASE, headers=auth_headers)
    assert listed.status_code == 200
    assert all(p["id"] != other_org_policy.id for p in listed.json()["policies"])


def test_a_scan_cannot_name_another_tenants_policy(
    client: TestClient, auth_headers, other_org_policy: ScanPolicy
):
    """
    The dangerous direction: naming a policy across a tenant boundary would let
    one workspace's configuration govern another's scan.
    """
    started = client.post(
        "/scan/host-discovery",
        json={
            "targets": ["192.0.2.1"],
            "pipeline_mode": "basic",
            "policy_id": other_org_policy.id,
        },
        headers=auth_headers,
    )
    assert started.status_code == 400
    assert "not found" in str(started.json()["detail"]).lower()


# ─────────────────────────────────────────────────────────────────────────────
# pol.authz.rbac
# ─────────────────────────────────────────────────────────────────────────────


def test_a_viewer_may_read_but_not_write(
    client: TestClient, auth_headers, viewer_headers
):
    created = client.post(BASE, json=_policy(), headers=auth_headers).json()

    assert client.get(BASE, headers=viewer_headers).status_code == 200
    assert (
        client.get(f"{BASE}/{created['id']}", headers=viewer_headers).status_code == 200
    )

    assert client.post(BASE, json=_policy(), headers=viewer_headers).status_code == 403
    assert (
        client.patch(
            f"{BASE}/{created['id']}", json={"description": "x"}, headers=viewer_headers
        ).status_code
        == 403
    )
    assert (
        client.delete(f"{BASE}/{created['id']}", headers=viewer_headers).status_code
        == 403
    )


def test_the_policy_endpoints_require_authentication(client: TestClient):
    assert client.get(BASE).status_code in (401, 403)
    assert client.post(BASE, json=_policy()).status_code in (401, 403)


# ─────────────────────────────────────────────────────────────────────────────
# pol.authz.audit
# ─────────────────────────────────────────────────────────────────────────────


def test_policy_changes_reach_the_audit_trail(
    client: TestClient, auth_headers, db_session: Session
):
    """
    "Who quietly stopped us checking the STIG" is a question an audit trail has
    to be able to answer, so the configuration is recorded, not just the event.
    """
    created = client.post(BASE, json=_policy(), headers=auth_headers).json()
    client.patch(
        f"{BASE}/{created['id']}",
        json={"config": {"min_severity": "info"}},
        headers=auth_headers,
    )

    events = (
        db_session.query(AuditLog)
        .filter(AuditLog.resource_id == created["id"])
        .order_by(AuditLog.created_at)
        .all()
    )
    actions = [e.action for e in events]
    assert "scan_policy.created" in actions
    assert "scan_policy.updated" in actions

    updated = [e for e in events if e.action == "scan_policy.updated"][-1]
    assert (updated.changes or {}).get("config", {}).get("min_severity") == "info"


# ─────────────────────────────────────────────────────────────────────────────
# pol.bind.validation — the endpoint
# ─────────────────────────────────────────────────────────────────────────────


def test_the_validate_endpoint_writes_nothing(
    client: TestClient, auth_headers, db_session: Session
):
    before = db_session.query(ScanPolicy).count()
    result = client.post(
        f"{BASE}/validate",
        json={"config": {"min_severity": "nonsense"}, "scan_kind": "any"},
        headers=auth_headers,
    )
    assert result.status_code == 200
    assert result.json()["valid"] is False
    assert db_session.query(ScanPolicy).count() == before


def test_the_settings_endpoint_reports_the_real_vocabularies(
    client: TestClient, auth_headers
):
    """
    Derived from the code that honours them, so a family added by a later phase
    is selectable without anybody editing a UI.
    """
    from core.scan_policy.spec import CHECK_FAMILIES

    result = client.get(f"{BASE}/settings", headers=auth_headers)
    assert result.status_code == 200
    payload = result.json()
    assert set(payload["check_families"]) == set(CHECK_FAMILIES)
    assert "min_severity" in payload["config_keys"]


# ─────────────────────────────────────────────────────────────────────────────
# Secrets
# ─────────────────────────────────────────────────────────────────────────────


def test_a_policy_has_no_credential_field_at_all(client: TestClient, auth_headers):
    """
    ``config`` is copied into ``scans.options``, which is client-visible, and
    printed in the report. A secret must be structurally impossible here, not
    merely absent by convention.
    """
    import dataclasses

    from core.scan_policy.spec import CONFIG_KEYS, EffectivePolicy

    # A secret has to be *carried*, so the test is about fields that can hold a
    # string. `require_credential` names a credential and holds a bool — it
    # says an authenticated session is required, it cannot contain one.
    types = {f.name: f.type for f in dataclasses.fields(EffectivePolicy)}
    forbidden = ("password", "secret", "token", "passphrase", "credential")
    for key in CONFIG_KEYS:
        if types.get(key) == "bool":
            continue
        assert not any(
            f in key.lower() for f in forbidden
        ), f"policy config key {key!r} could carry a secret"

    rejected = client.post(
        BASE, json=_policy(config={"password": "hunter2"}), headers=auth_headers
    )
    assert rejected.status_code == 400
