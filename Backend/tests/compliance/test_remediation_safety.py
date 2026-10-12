"""
Module: Backend/tests/test_remediation_safety
Purpose: Tests the Maker-Checker self-approval validation rules for compliance remediation.
Author:  pair/Senior Full-Stack Engineer
"""

from native_rbac import create_user, fixture_role, grant_permissions


import uuid
from datetime import datetime, timezone
from unittest.mock import patch

from auth.jwt_handler import create_access_token
from db.base import gen_org_id, gen_user_id
from db.models import Organization, User
from db.models.compliance import (
    ComplianceControl,
    ComplianceFinding,
    ComplianceFramework,
    ComplianceRemediation,
    ComplianceRemediationRequest,
    ComplianceRule,
    ComplianceRuleControl,
    ComplianceTenantFramework,
)
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


def _auth_headers(user: User) -> dict:
    """Helper to generate JWT bearer auth headers directly for a test user."""
    token = create_access_token(
        user.id,
        user.username,
        org_id=user.org_id,
    )
    return {"Authorization": f"Bearer {token}"}


def test_maker_checker_self_approval_block(client: TestClient, db_session: Session):
    """
    Verifies that the Maker who requests a remediation cannot self-approve it,
    but a different user with appropriate credentials can approve it.
    """
    # 1. Create a tenant organization and roles
    suffix = uuid.uuid4().hex[:6]
    org_slug = f"comp-safe-org-{suffix}"
    org = Organization(
        id=gen_org_id(org_slug),
        name=f"Compliance Safety Org {suffix}",
        slug=org_slug,
        is_active=True,
    )
    db_session.add(org)
    db_session.flush()

    role = fixture_role(db_session, f"compliance_officer_{suffix}")
    db_session.add(role)
    db_session.flush()

    # Grant necessary permissions to the compliance officer
    grant_permissions(db_session, role, "audit.compliance.read")
    grant_permissions(db_session, role, "audit.compliance.remediate")
    grant_permissions(db_session, role, "audit.compliance.approve_exception")

    # 2. Create the Maker and Checker users
    maker = create_user(
        db_session,
        id=gen_user_id(org.slug, f"maker-user-{suffix}"),
        username=f"maker-user-{suffix}",
        email=f"maker-{suffix}@test.com",
        password_hash="hash",
        org_id=org.id,
        role=role,
        is_active=True,
        is_verified=True,
    )
    checker = create_user(
        db_session,
        id=gen_user_id(org.slug, f"checker-user-{suffix}"),
        username=f"checker-user-{suffix}",
        email=f"checker-{suffix}@test.com",
        password_hash="hash",
        org_id=org.id,
        role=role,
        is_active=True,
        is_verified=True,
    )
    db_session.add_all([maker, checker])
    db_session.flush()

    # 3. Setup Framework, Control, Rule and Remediation details
    fw = ComplianceFramework(
        id=f"fw_safe_{suffix}",
        code="SAFE",
        name=f"Safety Framework {suffix}",
        version="1.0",
    )
    db_session.add(fw)
    db_session.flush()

    ctf = ComplianceTenantFramework(
        id=f"ctf_safe_{suffix}", tenant_id=org.id, framework_id=fw.id, is_enabled=True
    )
    db_session.add(ctf)

    ctrl = ComplianceControl(
        id=f"ctrl_safe_{suffix}",
        framework_id=fw.id,
        control_number=f"SAFE-01-{suffix}",
        theme="TECH",
        title=f"Remediation Queue Guard {suffix}",
        description="Maker-Checker check",
        scannability="auto",
    )
    db_session.add(ctrl)
    db_session.flush()

    rule = ComplianceRule(
        id=f"crl_safe_{suffix}",
        rule_family_code=f"RULE-SAFE-{suffix}",
        version_number=1,
        check_type="command_output",
        evidence_source="script",
        target_platform="linux",
        check_definition={},
        severity="medium",
        status="active",
    )
    db_session.add(rule)
    db_session.flush()

    link = ComplianceRuleControl(rule_id=rule.id, control_id=ctrl.id)
    db_session.add(link)

    remediation = ComplianceRemediation(
        id=f"crm_safe_{suffix}",
        rule_id=rule.id,
        recommendation_text="Run echo fixed",
        fix_type="script",
        fix_command="echo 'fixed'",
    )
    db_session.add(remediation)
    db_session.flush()

    # 4. Create a failed finding
    finding = ComplianceFinding(
        id=f"cfnd_safe_{suffix}",
        tenant_id=org.id,
        control_id=ctrl.id,
        rule_id=rule.id,
        source="auto_scan",
        status="fail",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    db_session.add(finding)
    db_session.commit()

    # 5. Create a remediation ticket submitted by the Maker
    req = ComplianceRemediationRequest(
        id=f"crrq_safe_ticket_{suffix}",
        tenant_id=org.id,
        finding_id=finding.id,
        remediation_id=remediation.id,
        requested_by=maker.id,
        status="pending_approval",
        emergency_bypass=False,
        username="admin",
        auth_method="password",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(req)
    db_session.commit()

    # 6. Attempt self-approval by Maker (Should fail with 400 Bad Request)
    response = client.post(
        f"/compliance/remediations/requests/{req.id}/approve",
        headers=_auth_headers(maker),
        json={"status": "approved"},
    )
    assert response.status_code == 400
    assert "Zero-trust security violation" in response.json()["detail"]

    # 7. Attempt approval by Checker (Should pass successfully)
    with patch("core.compliance_tasks.run_reremediation_task.delay") as mock_task_delay:
        response = client.post(
            f"/compliance/remediations/requests/{req.id}/approve",
            headers=_auth_headers(checker),
            json={"status": "approved"},
        )
        assert response.status_code == 200
        mock_task_delay.assert_called_once()

    # Reload from database and verify Checker approval recorded
    db_session.expire_all()
    updated_req = (
        db_session.query(ComplianceRemediationRequest).filter_by(id=req.id).first()
    )
    assert updated_req.status == "approved"
    assert updated_req.approved_by == checker.id
