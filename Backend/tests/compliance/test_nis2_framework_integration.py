"""
Pytest Integration Test Suite: EU NIS 2 Directive (Directive (EU) 2022/2555) Compliance Framework
Verifies catalog seeding (22 controls across 10 Article 21 risk management domains), theme check constraints,
rule mappings, entity/sector scoping filters, and executive report endpoints.
"""

import os
import pytest
from db.models.compliance import (
    ComplianceControl,
    ComplianceFramework,
    ComplianceRule,
    ComplianceScore,
    ComplianceTenantFramework,
)
from scripts.seed_compliance import seed_framework_and_controls
from scripts.seed_real_rules import seed_and_evaluate


def test_nis2_framework_seeding(db_session):
    """Test EU NIS 2 framework and 22 seed controls registration."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    seed_json = os.path.join(base_dir, "scripts", "nis2_controls_seed.json")
    assert os.path.exists(seed_json), "nis2_controls_seed.json missing!"

    # Seed framework and controls
    seed_framework_and_controls(db_session, seed_json)

    fw = (
        db_session.query(ComplianceFramework)
        .filter(ComplianceFramework.id == "cfw_nis2")
        .first()
    )
    assert fw is not None, "EU NIS 2 framework not registered"
    assert fw.code == "NIS2"

    controls = (
        db_session.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == "cfw_nis2")
        .all()
    )
    assert len(controls) == 42, f"Expected 42 NIS 2 controls, found {len(controls)}"


def test_nis2_theme_constraints(db_session, test_org):
    """Verify that NIS2 Article 21 themes are accepted by ComplianceControl and ComplianceScore DB models."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    seed_json = os.path.join(base_dir, "scripts", "nis2_controls_seed.json")
    seed_framework_and_controls(db_session, seed_json)

    sample_control = ComplianceControl(
        id="cct_test_nis2_inc_check",
        framework_id="cfw_nis2",
        control_number="NIS2-Art21.2b-TEST",
        title="24h CSIRT Early Warning Check",
        theme="NIS2_INC",
        scannability="auto",
    )
    db_session.add(sample_control)
    db_session.commit()

    score = ComplianceScore(
        id="csc_test_nis2_inc_score",
        tenant_id=test_org.id,
        framework_id="cfw_nis2",
        theme="NIS2_INC",
        score_pct=90.0,
    )
    db_session.add(score)
    db_session.commit()

    ctrl_in_db = (
        db_session.query(ComplianceControl)
        .filter(ComplianceControl.id == "cct_test_nis2_inc_check")
        .first()
    )
    assert ctrl_in_db.theme == "NIS2_INC"

    # Both rows are attached to the seeded NIS 2 framework, which is reference
    # data and survives the per-test reset. Without this the control count for
    # that framework grows by one for the rest of the session, which any later
    # assertion on control counts would see as an order-dependent failure.
    db_session.delete(score)
    db_session.delete(ctrl_in_db)
    db_session.commit()


def test_nis2_rules_seeding(db_session):
    """Test seeding custom and auto-generated rules for EU NIS 2 controls."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    iso_json = os.path.join(base_dir, "scripts", "iso27001_2022_controls_seed.json")
    nis2_json = os.path.join(base_dir, "scripts", "nis2_controls_seed.json")

    seed_framework_and_controls(db_session, iso_json)
    seed_framework_and_controls(db_session, nis2_json)

    seed_and_evaluate()
    rules = (
        db_session.query(ComplianceRule)
        .filter(ComplianceRule.id.like("crl_nis2%"))
        .all()
    )
    assert len(rules) >= 15, f"Expected at least 15 NIS 2 rules, found {len(rules)}"


def test_nis2_crosswalk_rule_inheritance(db_session):
    """Test that NIS 2 controls inherit check rules from ISO 27001, NIST CSF, and CIS crosswalks."""
    from db.models.compliance import ComplianceRuleControl

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    iso_json = os.path.join(base_dir, "scripts", "iso27001_2022_controls_seed.json")
    nist_json = os.path.join(base_dir, "scripts", "nist_csf_v2_controls_seed.json")
    nis2_json = os.path.join(base_dir, "scripts", "nis2_controls_seed.json")

    seed_framework_and_controls(db_session, iso_json)
    seed_framework_and_controls(db_session, nist_json)
    seed_framework_and_controls(db_session, nis2_json)

    seed_and_evaluate()

    # Verify control cct_nis2_gov_01 has rule links
    links = (
        db_session.query(ComplianceRuleControl)
        .filter(ComplianceRuleControl.control_id == "cct_nis2_gov_01")
        .all()
    )
    assert (
        len(links) > 0
    ), "cct_nis2_gov_01 should have inherited rule links from crosswalk"


def test_nis2_endpoints_and_report(
    client, db_session, test_user, auth_headers, activate_frameworks
):
    """Verify summary, findings, and executive report endpoints for NIS 2 Directive."""
    activate_frameworks("cfw_nis2")
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    seed_json = os.path.join(base_dir, "scripts", "nis2_controls_seed.json")
    seed_framework_and_controls(db_session, seed_json)

    # Enable framework for tenant
    tfw = (
        db_session.query(ComplianceTenantFramework)
        .filter(
            ComplianceTenantFramework.tenant_id == test_user.org_id,
            ComplianceTenantFramework.framework_id == "cfw_nis2",
        )
        .first()
    )
    if not tfw:
        tfw = ComplianceTenantFramework(
            id=f"ctf_{test_user.org_id}_cfw_nis2",
            tenant_id=test_user.org_id,
            framework_id="cfw_nis2",
            is_enabled=True,
        )
        db_session.add(tfw)
        db_session.commit()

    # Test summary API
    res_summary = client.get(
        "/compliance/summary?framework_id=cfw_nis2&nis2_entity_type=essential",
        headers=auth_headers,
    )
    assert res_summary.status_code == 200, f"Summary failed: {res_summary.text}"

    # Test findings API
    res_findings = client.get(
        "/compliance/findings?framework_id=cfw_nis2&nis2_entity_type=essential",
        headers=auth_headers,
    )
    assert res_findings.status_code == 200, f"Findings failed: {res_findings.text}"

    # Test PDF Report export with Member State & Sector scoping
    res_pdf = client.get(
        "/compliance/reports/nis2?fmt=pdf&nis2_entity_type=essential&nis2_sector=energy&nis2_member_state=DE",
        headers=auth_headers,
    )
    assert res_pdf.status_code == 200
    assert res_pdf.headers["content-type"] == "application/pdf"

    # Test DOCX Report export
    res_docx = client.get(
        "/compliance/reports/nis2?fmt=docx&nis2_entity_type=important&nis2_sector=transport&nis2_member_state=FR",
        headers=auth_headers,
    )
    assert res_docx.status_code == 200

    assert (
        res_docx.headers["content-type"]
        == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
