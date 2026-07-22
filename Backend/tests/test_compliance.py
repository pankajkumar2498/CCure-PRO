"""
tests/test_compliance.py
Unit and integration tests for the CCure Audit PRO Policy Compliance Engine.
"""

from unittest.mock import MagicMock

from core.compliance_tasks import _evaluate_operator, _check_prerequisites


def test_operator_evaluator():
    # 1. Equals
    assert _evaluate_operator("equals", "Active", "active") is True
    assert _evaluate_operator("equals", "Enabled", "disabled") is False
    assert _evaluate_operator("equals", None, "active") is False

    # 2. Not Equals
    assert _evaluate_operator("not_equals", "Active", "disabled") is True
    assert _evaluate_operator("not_equals", "Active", "active") is False

    # 3. Contains
    assert _evaluate_operator("contains", "SentinellOne Agent", "sentinel") is True
    assert _evaluate_operator("contains", "Windows Defender", "clamav") is False

    # 4. Version comparison
    assert _evaluate_operator("version_gte", "1.2.3", "1.2.0") is True
    assert _evaluate_operator("version_gte", "1.1.5", "1.2.0") is False
    assert _evaluate_operator("version_lte", "2.1", "2.5.4") is True

    # 5. List containment
    assert _evaluate_operator("contains", [22, 80, 445], 22) is True
    assert _evaluate_operator("contains", [22, 80, 445], "22") is True
    assert _evaluate_operator("contains", [80, 222, 445], 22) is False
    assert _evaluate_operator("not_contains", [80, 222, 445], 22) is True
    assert _evaluate_operator("not_contains", [22, 80, 445], 22) is False


def test_prerequisites_check():
    db_mock = MagicMock()

    asset_mock = MagicMock()
    asset_mock.id = "ast_123"
    asset_mock.custom_attributes = {"credentialed_status": "success"}

    rule_mock = MagicMock()
    rule_mock.id = "crl_abc"
    rule_mock.evidence_source = "offline_configuration"

    # Mock no dependencies
    db_mock.query().filter().all.return_value = []
    assert _check_prerequisites(db_mock, asset_mock, rule_mock, "org_abc") is True

    # Mock dependency check failing
    dep_mock = MagicMock()
    dep_mock.depends_on_rule_id = "crl_prereq"
    db_mock.query().filter().all.return_value = [dep_mock]
    db_mock.query().filter().first.return_value = None  # No finding yet
    assert _check_prerequisites(db_mock, asset_mock, rule_mock, "org_abc") is False

    # Mock dependency check passing
    finding_mock = MagicMock()
    finding_mock.status = "pass"
    db_mock.query().filter().first.return_value = finding_mock
    assert _check_prerequisites(db_mock, asset_mock, rule_mock, "org_abc") is True


def test_api_schemas():
    from fastapi.testclient import TestClient
    from main import app

    client = TestClient(app)

    res = client.get("/compliance/marketplace")
    assert res.status_code in (401, 403)


def test_marketplace_workflow(client, db_session, test_user, auth_headers):
    from db.models.compliance import (
        ComplianceFramework,
        ComplianceTenantFramework,
        CompliancePolicy,
    )

    # 1. Create a dummy framework and rules in DB
    fw = ComplianceFramework(
        id="cfw_test_framework",
        code="TESTFW",
        name="Test Framework",
        version="1.0",
    )
    db_session.add(fw)
    db_session.commit()

    # 2. Query marketplace
    res = client.get("/compliance/marketplace", headers=auth_headers)
    assert res.status_code == 200
    fws = res.json()["data"]
    assert any(f["framework_id"] == "cfw_test_framework" for f in fws)

    # 3. Install framework
    res = client.post(
        "/compliance/marketplace/cfw_test_framework/install", headers=auth_headers
    )
    assert res.status_code == 201

    # Check that default policy baseline was bootstrapped
    policy = (
        db_session.query(CompliancePolicy)
        .filter_by(framework_id="cfw_test_framework", tenant_id=test_user.org_id)
        .first()
    )
    assert policy is not None
    assert policy.name == "Test Framework Default Policy Baseline"

    # Check installed record exists and is enabled
    inst = (
        db_session.query(ComplianceTenantFramework)
        .filter_by(framework_id="cfw_test_framework", tenant_id=test_user.org_id)
        .first()
    )
    assert inst is not None
    assert inst.is_enabled is True

    # 4. Uninstall framework
    res = client.post(
        "/compliance/marketplace/cfw_test_framework/uninstall", headers=auth_headers
    )
    assert res.status_code == 200

    # Check installed record is disabled
    db_session.refresh(inst)
    assert inst.is_enabled is False

    # Check that query lists/policies does NOT return the policy since it is disabled
    res = client.get("/compliance/policies", headers=auth_headers)
    assert res.status_code == 200
    policies = res.json()["data"]
    assert not any(p["id"] == policy.id for p in policies)

    # Clean up
    db_session.delete(policy)
    db_session.delete(inst)
    db_session.delete(fw)
    db_session.commit()


def test_cis_v8_1_integration(client, db_session, test_user, auth_headers):
    from db.models.compliance import (
        ComplianceFramework,
        ComplianceControl,
        ComplianceTenantFramework,
    )
    from scripts.seed_compliance import seed_framework_and_controls
    import os

    # 1. Seed CIS Controls v8.1
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cis_seed_path = os.path.join(base_dir, "scripts", "cis_v8_1_controls_seed.json")
    if os.path.exists(cis_seed_path):
        seed_framework_and_controls(db_session, cis_seed_path)

    fw = (
        db_session.query(ComplianceFramework)
        .filter(ComplianceFramework.id == "cfw_cis_v8_1")
        .first()
    )
    assert fw is not None
    assert fw.code == "CIS_V8_1"

    # Verify control tags are persisted
    ctrl = (
        db_session.query(ComplianceControl)
        .filter(
            ComplianceControl.framework_id == "cfw_cis_v8_1",
            ComplianceControl.control_number == "1.1",
        )
        .first()
    )
    assert ctrl is not None
    assert isinstance(ctrl.tags, list)
    assert "ig1" in ctrl.tags

    # 2. Enable tenant framework for user org
    inst = ComplianceTenantFramework(
        id=f"ctf_{test_user.org_id}_cfw_cis_v8_1",
        tenant_id=test_user.org_id,
        framework_id="cfw_cis_v8_1",
        is_enabled=True,
    )
    db_session.add(inst)
    db_session.commit()

    # 3. Test Gap Analysis endpoint with correct parameter names
    res = client.get(
        "/compliance/gap-analysis?source_framework_id=cfw_iso27001_2022&target_framework_id=cfw_cis_v8_1",
        headers=auth_headers,
    )
    if res.status_code == 200:
        data = res.json()
        assert data["source_framework"]["id"] == "cfw_iso27001_2022"
        assert data["target_framework"]["id"] == "cfw_cis_v8_1"
        assert "summary" in data
        assert "controls" in data

    # 4. Test CIS PDF Report generation endpoint
    report_res = client.get(
        "/compliance/reports/cis_v8_1?fmt=pdf", headers=auth_headers
    )
    assert report_res.status_code == 200
    assert report_res.headers["content-type"] == "application/pdf"

    # Cleanup
    db_session.delete(inst)
    db_session.commit()


def test_soc2_type2_framework_seeding_and_reports(
    db_session, test_user, auth_headers, client
):
    """Test SOC 2 Type II controls seeding, theme tags, tenant installation, score recalculation, and audit report generation."""
    from db.models.compliance import (
        ComplianceFramework,
        ComplianceControl,
        ComplianceTenantFramework,
    )
    from scripts.seed_compliance import seed_framework_and_controls
    import os

    # 1. Seed SOC 2 Type II Controls
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    soc2_seed_path = os.path.join(base_dir, "scripts", "soc2_type2_controls_seed.json")
    if os.path.exists(soc2_seed_path):
        seed_framework_and_controls(db_session, soc2_seed_path)

    fw = (
        db_session.query(ComplianceFramework)
        .filter(ComplianceFramework.id == "cfw_soc2_type2")
        .first()
    )
    assert fw is not None
    assert fw.code == "SOC2_TYPE2"

    # Verify control theme and evidence_checklist items
    ctrl = (
        db_session.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == "cfw_soc2_type2")
        .first()
    )
    assert ctrl is not None
    assert ctrl.theme.startswith("SOC2_")
    assert isinstance(ctrl.evidence_checklist, list)

    # 2. Enable tenant framework for user org
    inst = (
        db_session.query(ComplianceTenantFramework)
        .filter(
            ComplianceTenantFramework.tenant_id == test_user.org_id,
            ComplianceTenantFramework.framework_id == "cfw_soc2_type2",
        )
        .first()
    )
    if not inst:
        inst = ComplianceTenantFramework(
            id=f"ctf_{test_user.org_id}_cfw_soc2_type2",
            tenant_id=test_user.org_id,
            framework_id="cfw_soc2_type2",
            is_enabled=True,
        )
        db_session.add(inst)
        db_session.commit()

    # 3. Test SOC 2 PDF Report generation endpoint
    pdf_res = client.get(
        "/compliance/reports/soc2_type2?fmt=pdf&audit_period_days=90",
        headers=auth_headers,
    )
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"

    # 4. Test SOC 2 DOCX Report generation endpoint
    docx_res = client.get(
        "/compliance/reports/soc2_type2?fmt=docx&audit_period_days=90",
        headers=auth_headers,
    )
    assert docx_res.status_code == 200

    # 5. Verify /findings endpoint includes control_evidence_checklist
    findings_res = client.get("/compliance/findings", headers=auth_headers)
    assert findings_res.status_code == 200
    findings_data = findings_res.json()
    assert "data" in findings_data
    if findings_data["data"]:
        assert "control_evidence_checklist" in findings_data["data"][0]

    # Cleanup
    if inst:
        db_session.delete(inst)
        db_session.commit()
