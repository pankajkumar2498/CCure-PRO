"""
tests/scans/test_remediation_api.py
─────────────────────────────────────────────────────────────────────────────
GAP-14 — the remediation API, RBAC, tenant isolation and the reports.

These exercise the real router against the real database, following
``test_scan_schedule_api.py``. Every fixture commits, which is what makes the
``TestClient`` + ``auth_headers`` pattern safe here.

Coverage areas exercised: rem.own.bulk, rem.rec.summary_api, rem.sla.overdue,
rem.sla.per_tenant, rem.state.pending_verification, rem.exc.grant,
rem.exc.audit, rem.rec.history, rem.rec.notes, rem.rec.report_exec,
rem.rec.report_tech, rem.verify.no_self_attest.
"""

from ccure_platform.models.rbac_tables import RbacPermission, RbacRolePermission
from native_rbac import system_role, create_user

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from auth.jwt_handler import hash_password
from db.base import gen_user_id, utcnow
from db.models import AuditLog, Organization, User
from db.models.assets import Asset
from db.models.findings import AssetVulnerability, VulnerabilityDefinition
from db.models.scans import Scan
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

BASE = "/remediation"
UTC = timezone.utc


def _now(**kw):
    return datetime.now(UTC) + timedelta(**kw)


@pytest.fixture
def finding(db_session: Session, test_org: Organization, test_user: User):
    """One real finding, with the asset, scan and catalogue rows it needs."""
    asset = Asset(
        id=f"ast_{uuid.uuid4().hex[:12]}",
        org_id=test_org.id,
        ip_address="192.0.2.77",
        hostname="rem.test",
        last_seen_at=_now(),
    )
    scan = Scan(
        id=f"scn_{uuid.uuid4().hex[:12]}",
        org_id=test_org.id,
        created_by=str(test_user.id),
        target_str="192.0.2.77",
        target_hosts=["192.0.2.77"],
        scan_type="credentialed",
        pipeline_mode="credentialed",
        status="complete",
        started_at=_now(minutes=-10),
        completed_at=_now(minutes=-5),
        options={},
    )
    vuln_id = f"CCURE-CFG-API-{uuid.uuid4().hex[:8].upper()}"
    db_session.add_all(
        [
            asset,
            scan,
            VulnerabilityDefinition(
                id=vuln_id,
                cve_id=None,
                definition_type="config_check",
                title="Fixture",
                description="fixture",
                severity="high",
            ),
        ]
    )
    db_session.flush()
    row = AssetVulnerability(
        id=f"fnd_{asset.id}_{vuln_id}"[:340],
        org_id=test_org.id,
        scan_id=scan.id,
        asset_id=asset.id,
        vuln_id=vuln_id,
        severity="high",
        status="open",
        source_family="credentialed_config",
        first_found_at=_now(days=-60),
        last_found_at=_now(),
        sla_due_at=_now(days=-30),  # deliberately overdue
    )
    db_session.add(row)
    db_session.commit()
    return row


@pytest.fixture
def viewer_headers(client: TestClient, db_session: Session, test_org: Organization):
    """A viewer: findings:read only — no update, no accept_risk."""
    role = system_role(db_session, "platform.viewer")
    password = "viewerpassword123"
    email = f"remviewer-{uuid.uuid4().hex[:6]}@test.com"
    db_session.add(
        create_user(
            db_session,
            id=gen_user_id(test_org.slug, "remviewer"),
            username=f"remviewer-{uuid.uuid4().hex[:6]}",
            email=email,
            full_name="Remediation Viewer",
            password_hash=hash_password(password),
            org_id=test_org.id,
            role=role,
            is_active=True,
            is_verified=True,
            approved_at=utcnow(),
            approved_by="fixture",
        )
    )
    db_session.commit()
    resp = client.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


# ─────────────────────────────────────────────────────────────────────────────
# rem.rec.summary_api / rem.sla.overdue
# ─────────────────────────────────────────────────────────────────────────────


def test_the_summary_reports_counts_and_the_executive_line(
    client: TestClient, auth_headers, finding
):
    """rem.rec.summary_api."""
    result = client.get(f"{BASE}/summary", headers=auth_headers)
    assert result.status_code == 200, result.text
    payload = result.json()

    assert payload["by_state"]["open"] >= 1
    assert payload["overdue"] >= 1
    # The exact shape the brief asks the executive report to show.
    for label in (
        "Open:",
        "In remediation:",
        "Pending verification:",
        "Overdue:",
        "Verified fixed:",
    ):
        assert label in payload["summary_line"]


def test_overdue_lists_the_finding_and_never_truncates_the_count(
    client: TestClient, auth_headers, finding
):
    """rem.sla.overdue."""
    result = client.get(f"{BASE}/overdue?limit=1", headers=auth_headers)
    assert result.status_code == 200
    payload = result.json()
    assert payload["total"] >= 1
    assert payload["count"] <= 1
    assert payload["findings"][0]["sla"]["state"] == "overdue"
    # Calendar days, said in words, so nobody assumes business days.
    assert payload["findings"][0]["sla"]["unit"] == "calendar days"


def test_a_verified_finding_is_not_reported_overdue(
    client: TestClient, auth_headers, finding, db_session
):
    finding.remediation_state = "verified_fixed"
    db_session.commit()
    result = client.get(f"{BASE}/overdue", headers=auth_headers)
    assert all(f["finding_id"] != finding.id for f in result.json()["findings"])


def test_pending_verification_lists_only_claimed_fixes(
    client: TestClient, auth_headers, finding, db_session
):
    """rem.state.pending_verification."""
    empty = client.get(f"{BASE}/pending-verification", headers=auth_headers)
    assert all(f["finding_id"] != finding.id for f in empty.json()["findings"])

    finding.remediation_state = "pending_verification"
    db_session.commit()

    listed = client.get(f"{BASE}/pending-verification", headers=auth_headers)
    assert any(f["finding_id"] == finding.id for f in listed.json()["findings"])


# ─────────────────────────────────────────────────────────────────────────────
# rem.own.bulk
# ─────────────────────────────────────────────────────────────────────────────


def test_assigning_in_bulk(client: TestClient, auth_headers, finding, test_user):
    """rem.own.bulk."""
    result = client.post(
        f"{BASE}/assign",
        json={"finding_ids": [finding.id], "owner_id": str(test_user.id)},
        headers=auth_headers,
    )
    assert result.status_code == 200, result.text
    assert result.json()["changed"] == 1

    view = client.get(f"{BASE}/findings/{finding.id}", headers=auth_headers)
    assert view.json()["remediation"]["owner"] == str(test_user.id)
    assert view.json()["remediation"]["state"] == "assigned"


def test_an_owner_from_another_organisation_is_refused(
    client: TestClient, auth_headers, finding, db_session
):
    """
    Without this a caller could hand another tenant's employee a finding they
    can neither see nor act on.
    """
    other_org = Organization(
        id=f"org_{uuid.uuid4().hex[:8]}",
        name=f"Other {uuid.uuid4().hex[:6]}",
        slug=f"other-{uuid.uuid4().hex[:6]}",
        max_assets=5,
        max_users=5,
        is_active=True,
    )
    db_session.add(other_org)
    db_session.flush()
    role = system_role(db_session, "platform.viewer")
    stranger = create_user(
        db_session,
        id=gen_user_id(other_org.slug, "stranger"),
        username=f"stranger-{uuid.uuid4().hex[:6]}",
        email=f"stranger-{uuid.uuid4().hex[:6]}@example.com",
        full_name="Stranger",
        password_hash=hash_password("strangerpassword123"),
        org_id=other_org.id,
        role=role,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
        approved_by="fixture",
    )
    db_session.add(stranger)
    db_session.commit()

    result = client.post(
        f"{BASE}/assign",
        json={"finding_ids": [finding.id], "owner_id": str(stranger.id)},
        headers=auth_headers,
    )
    assert result.status_code == 400
    assert "this organisation" in result.json()["detail"]


# ─────────────────────────────────────────────────────────────────────────────
# rem.verify.no_self_attest — through the API
# ─────────────────────────────────────────────────────────────────────────────


def test_the_api_refuses_to_mark_a_finding_verified_fixed(
    client: TestClient, auth_headers, finding
):
    """
    rem.verify.no_self_attest. The control the phase exists for, asserted at
    the boundary a user actually reaches.
    """
    result = client.patch(
        f"{BASE}/findings/{finding.id}/state",
        json={"state": "verified_fixed"},
        headers=auth_headers,
    )
    assert result.status_code == 400
    detail = result.json()["detail"]
    assert "verified fixed by hand" in detail
    assert "pending_verification" in detail


def test_claiming_a_fix_moves_it_to_pending_verification(
    client: TestClient, auth_headers, finding
):
    result = client.patch(
        f"{BASE}/findings/{finding.id}/state",
        json={"state": "pending_verification", "note": "patched"},
        headers=auth_headers,
    )
    assert result.status_code == 200, result.text
    payload = result.json()
    assert payload["remediation"]["state"] == "pending_verification"
    assert payload["verification"]["verified_at"] is None


def test_the_legacy_status_endpoint_no_longer_writes_the_evidence_timeline(
    client: TestClient, auth_headers, finding, db_session
):
    """
    The integration defect this phase fixes. ``PATCH /findings/{id}/status``
    with ``status="fixed"`` used to stamp ``fixed_at`` — the column GAP-13
    reconstructs a baseline from — putting a user's opinion into the evidence
    timeline every later comparison and report is built on.
    """
    result = client.patch(
        f"/findings/{finding.id}/status",
        json={"status": "fixed"},
        headers=auth_headers,
    )
    assert result.status_code == 200, result.text
    payload = result.json()

    db_session.refresh(finding)
    assert finding.fixed_at is None, "a user click must not write the evidence timeline"
    assert finding.remediation_state == "pending_verification"
    # And the caller is told, rather than left believing it is settled.
    assert payload["verified"] is False
    assert "pending verification" in payload["note"]


# ─────────────────────────────────────────────────────────────────────────────
# rem.exc.grant / rem.exc.audit
# ─────────────────────────────────────────────────────────────────────────────


def test_accepting_a_risk_through_the_api(client: TestClient, auth_headers, finding):
    """rem.exc.grant."""
    expires = (_now(days=30)).isoformat()
    result = client.post(
        f"{BASE}/findings/{finding.id}/accept-risk",
        json={"reason": "Compensating control in place", "expires_at": expires},
        headers=auth_headers,
    )
    assert result.status_code == 200, result.text
    payload = result.json()
    assert payload["remediation"]["state"] == "risk_accepted"
    assert payload["exception"]["reason"] == "Compensating control in place"
    assert payload["exception"]["accepted_by"]
    assert payload["exception"]["expires_at"]
    assert payload["exception"]["indefinite"] is False
    # Resolved for SLA purposes — nothing further is owed.
    assert payload["sla"]["state"] == "resolved"


def test_an_acceptance_without_a_reason_is_refused_by_the_api(
    client: TestClient, auth_headers, finding
):
    result = client.post(
        f"{BASE}/findings/{finding.id}/accept-risk",
        json={"reason": ""},
        headers=auth_headers,
    )
    assert result.status_code == 422


def test_accept_risk_is_not_reachable_through_the_state_endpoint(
    client: TestClient, auth_headers, finding
):
    """
    An acceptance needs a reason and an approver, so it cannot be a bare state
    change — otherwise the permission split and the justification both vanish.
    """
    result = client.patch(
        f"{BASE}/findings/{finding.id}/state",
        json={"state": "risk_accepted"},
        headers=auth_headers,
    )
    assert result.status_code == 400
    assert "reason and an approver" in result.json()["detail"]


def test_an_acceptance_reaches_the_audit_trail(
    client: TestClient, auth_headers, finding, db_session
):
    """rem.exc.audit."""
    client.post(
        f"{BASE}/findings/{finding.id}/accept-risk",
        json={"reason": "documented waiver"},
        headers=auth_headers,
    )
    events = db_session.query(AuditLog).filter(AuditLog.resource_id == finding.id).all()
    actions = [e.action for e in events]
    assert "remediation.risk_accepted" in actions
    accepted = [e for e in events if e.action == "remediation.risk_accepted"][0]
    assert (accepted.changes or {}).get("reason") == "documented waiver"


def test_withdrawing_an_acceptance(client: TestClient, auth_headers, finding):
    client.post(
        f"{BASE}/findings/{finding.id}/accept-risk",
        json={"reason": "waiver"},
        headers=auth_headers,
    )
    result = client.post(
        f"{BASE}/findings/{finding.id}/withdraw-acceptance",
        json={},
        headers=auth_headers,
    )
    assert result.status_code == 200, result.text
    assert result.json()["remediation"]["state"] == "open"


# ─────────────────────────────────────────────────────────────────────────────
# rem.rec.notes / rem.rec.history
# ─────────────────────────────────────────────────────────────────────────────


def test_notes_and_history(client: TestClient, auth_headers, finding, test_user):
    """rem.rec.notes, rem.rec.history."""
    client.post(
        f"{BASE}/assign",
        json={"finding_ids": [finding.id], "owner_id": str(test_user.id)},
        headers=auth_headers,
    )
    client.post(
        f"{BASE}/findings/{finding.id}/notes",
        json={"note": "raised change request"},
        headers=auth_headers,
    )

    history = client.get(f"{BASE}/findings/{finding.id}/history", headers=auth_headers)
    assert history.status_code == 200
    kinds = [e["event_type"] for e in history.json()["events"]]
    assert "assigned" in kinds
    assert "note_added" in kinds


# ─────────────────────────────────────────────────────────────────────────────
# rem.sla.per_tenant
# ─────────────────────────────────────────────────────────────────────────────


def test_the_sla_policy_can_be_read_and_set(client: TestClient, auth_headers):
    """rem.sla.per_tenant."""
    current = client.get(f"{BASE}/sla-policy", headers=auth_headers)
    assert current.status_code == 200
    assert current.json()["days_by_severity"]["critical"] == 15

    updated = client.put(
        f"{BASE}/sla-policy",
        json={"days_by_severity": {"critical": 3}},
        headers=auth_headers,
    )
    assert updated.status_code == 200, updated.text
    payload = updated.json()
    assert payload["days_by_severity"]["critical"] == 3
    # Merged, not replaced — the other five deadlines survive.
    assert payload["days_by_severity"]["high"] == 30
    # And the response says existing findings keep their recorded dates.
    assert "next scan" in payload["note"]


def test_an_unknown_severity_is_refused(client: TestClient, auth_headers):
    result = client.put(
        f"{BASE}/sla-policy",
        json={"days_by_severity": {"catastrophic": 1}},
        headers=auth_headers,
    )
    assert result.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# RBAC and tenant isolation
# ─────────────────────────────────────────────────────────────────────────────


def test_a_viewer_may_read_but_not_change_anything(
    client: TestClient, viewer_headers, finding, test_user
):
    assert client.get(f"{BASE}/summary", headers=viewer_headers).status_code == 200
    assert (
        client.get(f"{BASE}/findings/{finding.id}", headers=viewer_headers).status_code
        == 200
    )

    assert (
        client.post(
            f"{BASE}/assign",
            json={"finding_ids": [finding.id], "owner_id": str(test_user.id)},
            headers=viewer_headers,
        ).status_code
        == 403
    )
    assert (
        client.patch(
            f"{BASE}/findings/{finding.id}/state",
            json={"state": "in_remediation"},
            headers=viewer_headers,
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"{BASE}/findings/{finding.id}/accept-risk",
            json={"reason": "x"},
            headers=viewer_headers,
        ).status_code
        == 403
    )


def test_accepting_risk_needs_its_own_permission(
    client: TestClient, db_session, test_org, finding
):
    """
    ``findings:update`` moves work through the queue; deciding the
    organisation will carry a critical risk is a different authorisation.
    Without the split anyone who can edit a finding could clear their own
    overdue list by accepting everything on it.
    """

    atom = (
        db_session.query(RbacPermission)
        .filter(RbacPermission.key == "audit.finding.accept_risk")
        .first()
    )
    assert atom is not None, "findings:accept_risk must exist as its own atom"

    viewer = system_role(db_session, "platform.viewer")
    held = (
        db_session.query(RbacRolePermission)
        .filter(
            RbacRolePermission.role_id == viewer.id,
            RbacRolePermission.permission_key == atom.key,
        )
        .first()
    )
    assert held is None, "a viewer must not be able to accept a risk"


def _foreign_finding(db_session, tag: str, ip: str):
    """A finding belonging to a different organisation, with its own scan."""
    other_org = Organization(
        id=f"org_{uuid.uuid4().hex[:8]}",
        name=f"Other {uuid.uuid4().hex[:6]}",
        slug=f"other-{uuid.uuid4().hex[:6]}",
        max_assets=5,
        max_users=5,
        is_active=True,
    )
    db_session.add(other_org)
    db_session.flush()

    asset = Asset(
        id=f"ast_{uuid.uuid4().hex[:12]}",
        org_id=other_org.id,
        ip_address=ip,
        last_seen_at=_now(),
    )
    scan = Scan(
        id=f"scn_{uuid.uuid4().hex[:12]}",
        org_id=other_org.id,
        target_str=ip,
        target_hosts=[ip],
        scan_type="credentialed",
        pipeline_mode="credentialed",
        status="complete",
        options={},
    )
    vuln_id = f"CCURE-CFG-{tag}-{uuid.uuid4().hex[:8].upper()}"
    db_session.add_all(
        [
            asset,
            scan,
            VulnerabilityDefinition(
                id=vuln_id,
                cve_id=None,
                definition_type="config_check",
                title="Other",
                description="other",
                severity="high",
            ),
        ]
    )
    db_session.flush()
    row = AssetVulnerability(
        id=f"fnd_{asset.id}_{vuln_id}"[:340],
        org_id=other_org.id,
        scan_id=scan.id,
        asset_id=asset.id,
        vuln_id=vuln_id,
        severity="high",
        status="open",
        source_family="credentialed_config",
    )
    db_session.add(row)
    db_session.commit()
    return other_org, row


def test_another_tenants_finding_is_404_not_403(
    client: TestClient, auth_headers, db_session, test_user
):
    """A 403 would confirm the id exists across a tenant boundary."""
    _org, theirs = _foreign_finding(db_session, "OTHER", "198.51.100.9")

    for call in (
        lambda: client.get(f"{BASE}/findings/{theirs.id}", headers=auth_headers),
        lambda: client.get(
            f"{BASE}/findings/{theirs.id}/history", headers=auth_headers
        ),
        lambda: client.patch(
            f"{BASE}/findings/{theirs.id}/state",
            json={"state": "in_remediation"},
            headers=auth_headers,
        ),
        lambda: client.post(
            f"{BASE}/findings/{theirs.id}/accept-risk",
            json={"reason": "x"},
            headers=auth_headers,
        ),
        lambda: client.post(
            f"{BASE}/findings/{theirs.id}/notes",
            json={"note": "x"},
            headers=auth_headers,
        ),
    ):
        assert call().status_code == 404


def test_a_bulk_assign_cannot_reach_across_tenants(
    client: TestClient, auth_headers, db_session, test_user
):
    _org, theirs = _foreign_finding(db_session, "BULK", "198.51.100.10")

    result = client.post(
        f"{BASE}/assign",
        json={"finding_ids": [theirs.id], "owner_id": str(test_user.id)},
        headers=auth_headers,
    )
    assert result.status_code == 404
    db_session.refresh(theirs)
    assert theirs.remediation_owner is None


def test_the_endpoints_require_authentication(client: TestClient):
    assert client.get(f"{BASE}/summary").status_code in (401, 403)
    assert client.get(f"{BASE}/overdue").status_code in (401, 403)


# ─────────────────────────────────────────────────────────────────────────────
# rem.rec.report_exec / rem.rec.report_tech
# ─────────────────────────────────────────────────────────────────────────────


def _rendered(story) -> str:
    """Every word the section puts on the page, table cells included."""
    out = []

    def walk(item):
        text = getattr(item, "text", None)
        if isinstance(text, str):
            out.append(text)
        rows = getattr(item, "_cellvalues", None)
        if rows:
            for row in rows:
                for cell in row:
                    for sub in cell if isinstance(cell, (list, tuple)) else [cell]:
                        walk(sub)

    for item in story:
        walk(item)
    return " ".join(out)


def test_the_report_section_is_empty_without_remediation_data():
    """
    A report for a scan that predates this phase must be byte-for-byte what it
    was — the property `_comparison_section` and `_policy_section` preserve.
    """
    from reporting.pdf_generator import _build_styles, _remediation_section

    styles = _build_styles()
    assert _remediation_section(None, styles) == []
    assert _remediation_section({}, styles) == []


def test_the_technical_report_names_owner_sla_and_verification_state():
    """rem.rec.report_tech."""
    from reporting.pdf_generator import _build_styles, _remediation_section

    story = _remediation_section(
        {
            "by_state": {
                "open": 120,
                "in_remediation": 35,
                "pending_verification": 8,
                "verified_fixed": 42,
                "reopened": 3,
                "risk_accepted": 5,
                "assigned": 10,
            },
            "overdue": 17,
            "within_sla": 100,
            "no_sla": 4,
            "by_owner": [{"owner": "usr_alice", "open": 30, "overdue": 4}],
            "findings": [
                {
                    "vuln_id": "CVE-2026-1234",
                    "severity": "critical",
                    "remediation": {"state": "in_remediation", "owner": "usr_alice"},
                    "sla": {"due_at": "2026-09-30T00:00:00+00:00", "state": "overdue"},
                }
            ],
            "verification": {
                "comparison_usable": True,
                "verified_count": 42,
                "reopened_count": 3,
                "withheld_count": 40,
            },
        },
        _build_styles(),
    )
    assert story
    rendered = _rendered(story)

    for expected in (
        "Open: 120",
        "Overdue: 17",
        "Verified fixed: 42",
        "usr_alice",
        "CVE-2026-1234",
        "OVERDUE",
        "In remediation",
        # The sentence that makes the verification requirement legible.
        "verified fixed",
        "subsequent assessment",
        # And the honest qualification when the scan could not check everything.
        "could <b>not</b> be verified",
    ):
        assert expected in rendered, f"the report must say {expected!r}"


def test_the_report_says_when_nothing_could_be_verified():
    from reporting.pdf_generator import _build_styles, _remediation_section

    story = _remediation_section(
        {
            "by_state": {"open": 5},
            "overdue": 0,
            "within_sla": 5,
            "no_sla": 0,
            "verification": {
                "comparison_usable": False,
                "reason": "this is the first scan; there is nothing to compare against",
            },
        },
        _build_styles(),
    )
    rendered = _rendered(story)
    assert "No remediation was verified by this scan" in rendered
    assert "first scan" in rendered


def test_the_executive_line_is_the_shape_the_brief_asks_for():
    """rem.rec.report_exec."""
    from reporting.pdf_generator import _remediation_summary_line

    line = _remediation_summary_line(
        {
            "by_state": {
                "open": 120,
                "in_remediation": 35,
                "pending_verification": 8,
                "verified_fixed": 42,
            },
            "overdue": 17,
        }
    )
    assert line == (
        "Open: 120 | In remediation: 35 | Pending verification: 8 | "
        "Overdue: 17 | Verified fixed: 42"
    )
    assert _remediation_summary_line({}) == ""
    assert _remediation_summary_line(None) == ""
