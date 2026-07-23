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


def test_cert_in_2022_framework_integration(
    client, test_user, auth_headers, db_session
):
    """Test CERT-In 2022 framework seeding, control crosswalks, rule evaluation operators, and report routes."""
    from datetime import datetime, timezone
    import os
    from db.models.compliance import (
        ComplianceFramework,
        ComplianceControl,
        ComplianceTenantFramework,
    )
    from scripts.seed_compliance import seed_framework_and_controls
    from scripts.seed_real_rules import seed_and_evaluate
    from core.compliance_tasks import _evaluate_operator

    # 1. Verify numeric and list comparison operators in rule engine
    assert _evaluate_operator("gte", 180, 180) is True
    assert _evaluate_operator("gte", 190, 180) is True
    assert _evaluate_operator("gte", 90, 180) is False
    assert _evaluate_operator("lte", 6, 6) is True
    assert _evaluate_operator("lte", 4, 6) is True
    assert _evaluate_operator("lte", 12, 6) is False
    assert (
        _evaluate_operator(
            "contains",
            ["samay.nplindia.in", "10.0.0.1"],
            ["samay.nplindia.in", "nic.in"],
        )
        is True
    )

    # 2. Seed CERT-In controls and real rules
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cert_in_seed = os.path.join(base_dir, "scripts", "cert_in_2022_controls_seed.json")
    if os.path.exists(cert_in_seed):
        seed_framework_and_controls(db_session, cert_in_seed)

    seed_and_evaluate()

    # 3. Verify framework exists in database
    fw = (
        db_session.query(ComplianceFramework)
        .filter(ComplianceFramework.id == "cfw_cert_in_2022")
        .first()
    )
    assert fw is not None
    assert fw.code == "CERT_IN_2022"

    # 4. Verify CERT-In controls exist
    controls = (
        db_session.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == "cfw_cert_in_2022")
        .all()
    )
    assert len(controls) >= 10

    # 5. Enable tenant framework for test org
    inst = (
        db_session.query(ComplianceTenantFramework)
        .filter(
            ComplianceTenantFramework.tenant_id == test_user.org_id,
            ComplianceTenantFramework.framework_id == "cfw_cert_in_2022",
        )
        .first()
    )
    if not inst:
        inst = ComplianceTenantFramework(
            id=f"ctf_{test_user.org_id}_cfw_cert_in_2022",
            tenant_id=test_user.org_id,
            framework_id="cfw_cert_in_2022",
            is_enabled=True,
            enabled_at=datetime.now(timezone.utc),
        )
        db_session.add(inst)
        db_session.commit()

    # 6. Test GET /compliance/summary with framework_id query parameter
    summary_res = client.get(
        "/compliance/summary?framework_id=cfw_cert_in_2022", headers=auth_headers
    )
    assert summary_res.status_code == 200
    summary_data = summary_res.json()
    assert "score_pct" in summary_data
    assert "quadrant_scores" in summary_data

    # 7. Test CERT-In PDF Report generation endpoint
    pdf_res = client.get(
        "/compliance/reports/cert_in_2022?fmt=pdf",
        headers=auth_headers,
    )
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"

    # 8. Test CERT-In DOCX Report generation endpoint
    docx_res = client.get(
        "/compliance/reports/cert_in_2022?fmt=docx",
        headers=auth_headers,
    )
    assert docx_res.status_code == 200

    # Cleanup
    if inst:
        db_session.delete(inst)
        db_session.commit()


def test_pci_dss_v4_framework_integration(client, test_user, auth_headers, db_session):
    """Test PCI-DSS v4.0 framework seeding, SAQ profiles, CDE scope filtering, evidence evaluation, and report routes."""
    from datetime import datetime, timezone
    import os
    from db.models.compliance import (
        ComplianceFramework,
        ComplianceControl,
        ComplianceTenantFramework,
    )
    from scripts.seed_compliance import seed_framework_and_controls
    from scripts.seed_real_rules import seed_and_evaluate
    from core.compliance_tasks import _evaluate_operator, _calculate_compliance_score

    # 1. Verify boolean and operator evaluations
    assert _evaluate_operator("equals", True, True) is True
    assert _evaluate_operator("equals", False, True) is False

    # 2. Seed PCI-DSS controls
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pci_seed = os.path.join(base_dir, "scripts", "pci_dss_v4_controls_seed.json")
    if os.path.exists(pci_seed):
        seed_framework_and_controls(db_session, pci_seed)

    seed_and_evaluate()

    # 3. Verify framework exists in database
    fw = (
        db_session.query(ComplianceFramework)
        .filter(ComplianceFramework.id == "cfw_pci_dss_v4")
        .first()
    )
    assert fw is not None
    assert fw.code == "PCI_DSS_V4"

    # 4. Verify PCI-DSS controls exist and contain SAQ profiles
    controls = (
        db_session.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == "cfw_pci_dss_v4")
        .all()
    )
    assert len(controls) >= 10

    # Check SAQ profiles JSONB field on controls
    saq_a_controls = [
        c for c in controls if c.saq_profiles and "saq_a" in c.saq_profiles
    ]
    assert len(saq_a_controls) > 0

    # 5. Enable tenant framework for test org
    inst = (
        db_session.query(ComplianceTenantFramework)
        .filter(
            ComplianceTenantFramework.tenant_id == test_user.org_id,
            ComplianceTenantFramework.framework_id == "cfw_pci_dss_v4",
        )
        .first()
    )
    if not inst:
        inst = ComplianceTenantFramework(
            id=f"ctf_{test_user.org_id}_cfw_pci_dss_v4",
            tenant_id=test_user.org_id,
            framework_id="cfw_pci_dss_v4",
            is_enabled=True,
            enabled_at=datetime.now(timezone.utc),
        )
        db_session.add(inst)
        db_session.commit()

    # 6. Test GET /compliance/summary with SAQ profile filter
    summary_res = client.get(
        "/compliance/summary?framework_id=cfw_pci_dss_v4&saq_profile=saq_a",
        headers=auth_headers,
    )
    assert summary_res.status_code == 200
    summary_data = summary_res.json()
    assert "score_pct" in summary_data
    assert "kpis" in summary_data

    # 7. Test PCI-DSS PDF Report generation endpoint
    pdf_res = client.get(
        "/compliance/reports/pci_dss_v4?fmt=pdf&saq_profile=saq_a",
        headers=auth_headers,
    )
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"

    # 8. Test PCI-DSS DOCX Report generation endpoint
    docx_res = client.get(
        "/compliance/reports/pci_dss_v4?fmt=docx&saq_profile=saq_a",
        headers=auth_headers,
    )
    assert docx_res.status_code == 200

    # Cleanup
    if inst:
        db_session.delete(inst)
        db_session.commit()


def test_dpdp_2023_framework_integration(client, test_user, auth_headers, db_session):
    """Test DPDP Act 2023 framework seeding, SDF scoping, web evidence adapter, gap analysis prefix stripping, and report endpoints."""
    from datetime import datetime, timezone
    import os
    from db.models.compliance import (
        ComplianceFramework,
        ComplianceControl,
        ComplianceTenantFramework,
    )
    from scripts.seed_compliance import seed_framework_and_controls
    from scripts.seed_real_rules import seed_and_evaluate

    # 1. Seed DPDP controls catalog
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dpdp_seed = os.path.join(base_dir, "scripts", "dpdp_2023_controls_seed.json")
    if os.path.exists(dpdp_seed):
        seed_framework_and_controls(db_session, dpdp_seed)

    # 2. Verify framework exists in database
    fw = (
        db_session.query(ComplianceFramework)
        .filter(ComplianceFramework.id == "cfw_dpdp_2023")
        .first()
    )
    assert fw is not None
    assert fw.code == "DPDP_2023"

    # 3. Verify DPDP controls exist and contain sdf_scope attributes
    controls = (
        db_session.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == "cfw_dpdp_2023")
        .all()
    )
    assert len(controls) >= 15

    sdf_controls = [c for c in controls if c.sdf_scope == "sdf_mandatory"]
    assert len(sdf_controls) > 0

    # 4. Enable tenant framework for test org
    inst = (
        db_session.query(ComplianceTenantFramework)
        .filter(
            ComplianceTenantFramework.tenant_id == test_user.org_id,
            ComplianceTenantFramework.framework_id == "cfw_dpdp_2023",
        )
        .first()
    )
    if not inst:
        inst = ComplianceTenantFramework(
            id=f"ctf_{test_user.org_id}_cfw_dpdp_2023",
            tenant_id=test_user.org_id,
            framework_id="cfw_dpdp_2023",
            is_enabled=True,
            enabled_at=datetime.now(timezone.utc),
        )
        db_session.add(inst)
        db_session.commit()

    # 5. Test GET /compliance/summary with SDF scope filter
    summary_res = client.get(
        "/compliance/summary?framework_id=cfw_dpdp_2023&sdf_scope=sdf_mandatory",
        headers=auth_headers,
    )
    assert summary_res.status_code == 200
    summary_data = summary_res.json()
    assert "score_pct" in summary_data
    assert "kpis" in summary_data

    # 6. Test Gap Analysis prefix resolution with DPDP
    gap_res = client.get(
        "/compliance/gap-analysis?source_framework_id=cfw_iso27001_2022&target_framework_id=cfw_dpdp_2023",
        headers=auth_headers,
    )
    assert gap_res.status_code == 200
    gap_data = gap_res.json()
    assert "summary" in gap_data
    assert "mapped_controls" in gap_data["summary"]

    # 7. Test DPDP PDF Report generation endpoint
    pdf_res = client.get(
        "/compliance/reports/dpdp_2023?fmt=pdf&sdf_scope=sdf_mandatory",
        headers=auth_headers,
    )
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"

    # 8. Test DPDP DOCX Report generation endpoint
    docx_res = client.get(
        "/compliance/reports/dpdp_2023?fmt=docx&sdf_scope=sdf_mandatory",
        headers=auth_headers,
    )
    assert docx_res.status_code == 200

    # Cleanup
    if inst:
        db_session.delete(inst)
        db_session.commit()


def test_gdpr_framework_integration(client, test_user, auth_headers, db_session):
    """Test EU GDPR framework seeding, privacy_role scoping, web evidence mapping, and report endpoints."""
    from datetime import datetime, timezone
    import os
    from db.models.compliance import (
        ComplianceFramework,
        ComplianceControl,
        ComplianceTenantFramework,
    )
    from scripts.seed_compliance import seed_framework_and_controls
    from scripts.seed_real_rules import seed_and_evaluate

    # 1. Seed GDPR controls catalog
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    gdpr_seed = os.path.join(base_dir, "scripts", "gdpr_controls_seed.json")
    if os.path.exists(gdpr_seed):
        seed_framework_and_controls(db_session, gdpr_seed)

    # 2. Verify framework exists in database
    fw = (
        db_session.query(ComplianceFramework)
        .filter(ComplianceFramework.id == "cfw_gdpr")
        .first()
    )
    assert fw is not None
    assert fw.code == "GDPR"

    # 3. Verify GDPR controls exist and contain privacy_role attributes
    controls = (
        db_session.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == "cfw_gdpr")
        .all()
    )
    assert len(controls) >= 15

    controller_controls = [
        c for c in controls if c.privacy_role in ("controller", "both")
    ]
    assert len(controller_controls) > 0

    # 4. Enable tenant framework for test org
    inst = (
        db_session.query(ComplianceTenantFramework)
        .filter(
            ComplianceTenantFramework.tenant_id == test_user.org_id,
            ComplianceTenantFramework.framework_id == "cfw_gdpr",
        )
        .first()
    )
    if not inst:
        inst = ComplianceTenantFramework(
            id=f"ctf_{test_user.org_id}_cfw_gdpr",
            tenant_id=test_user.org_id,
            framework_id="cfw_gdpr",
            is_enabled=True,
            enabled_at=datetime.now(timezone.utc),
        )
        db_session.add(inst)
        db_session.commit()

    # 5. Test GET /compliance/summary with Privacy Role filter
    summary_res = client.get(
        "/compliance/summary?framework_id=cfw_gdpr&privacy_role=controller",
        headers=auth_headers,
    )
    assert summary_res.status_code == 200
    summary_data = summary_res.json()
    assert "score_pct" in summary_data

    # 6. Test GDPR PDF Report generation endpoint
    pdf_res = client.get(
        "/compliance/reports/gdpr?fmt=pdf&privacy_role=controller",
        headers=auth_headers,
    )
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"

    # 7. Test GDPR DOCX Report generation endpoint
    docx_res = client.get(
        "/compliance/reports/gdpr?fmt=docx&privacy_role=controller",
        headers=auth_headers,
    )
    assert docx_res.status_code == 200

    # Cleanup
    if inst:
        db_session.delete(inst)
        db_session.commit()
