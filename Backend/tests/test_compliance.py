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
        controls_count=0,
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
