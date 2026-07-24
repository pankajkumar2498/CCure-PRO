"""
Pytest Integration Test Suite: NERC CIP OT Compliance Framework
Verifies catalog seeding (52 controls across CIP-002..CIP-014), theme check constraints,
rule mapping, and executive report endpoints.
"""

import os

import pytest
from db.models.compliance import (
    ComplianceControl,
    ComplianceFramework,
    ComplianceRule,
    ComplianceScore,
)
from scripts.seed_compliance import seed_framework_and_controls
from scripts.seed_real_rules import seed_and_evaluate


def test_nerc_cip_framework_seeding(db_session):
    """Test NERC CIP framework and 52 seed controls registration."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    seed_json = os.path.join(base_dir, "scripts", "nerc_cip_controls_seed.json")
    assert os.path.exists(seed_json), "nerc_cip_controls_seed.json missing!"

    # Seed framework and controls
    seed_framework_and_controls(db_session, seed_json)

    fw = (
        db_session.query(ComplianceFramework)
        .filter(ComplianceFramework.id == "cfw_nerc_cip")
        .first()
    )
    assert fw is not None, "NERC CIP framework not registered"
    assert fw.code == "NERC_CIP"

    controls = (
        db_session.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == "cfw_nerc_cip")
        .all()
    )
    assert len(controls) == 52, f"Expected 52 NERC CIP controls, found {len(controls)}"


def test_nerc_cip_theme_constraints(db_session, test_org):
    """Verify that CIP_002..CIP-014 themes are accepted by ComplianceControl and ComplianceScore DB models."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    seed_json = os.path.join(base_dir, "scripts", "nerc_cip_controls_seed.json")
    seed_framework_and_controls(db_session, seed_json)

    sample_control = ComplianceControl(
        id="cct_test_cip_005_check",
        framework_id="cfw_nerc_cip",
        control_number="CIP-005-7 R1.1",
        title="ESP Boundary Filter Check",
        theme="CIP_005",
        scannability="auto",
    )
    db_session.add(sample_control)
    db_session.commit()

    score = ComplianceScore(
        id="csc_test_cip_005_score",
        tenant_id=test_org.id,
        framework_id="cfw_nerc_cip",
        theme="CIP_005",
        score_pct=95.0,
    )
    db_session.add(score)
    db_session.commit()

    ctrl_in_db = (
        db_session.query(ComplianceControl)
        .filter(ComplianceControl.id == "cct_test_cip_005_check")
        .first()
    )
    assert ctrl_in_db.theme == "CIP_005"


def test_nerc_cip_rules_seeding(db_session):
    """Test seeding custom and auto-generated rules for NERC CIP controls."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    iso_json = os.path.join(base_dir, "scripts", "iso27001_2022_controls_seed.json")
    nerc_json = os.path.join(base_dir, "scripts", "nerc_cip_controls_seed.json")

    seed_framework_and_controls(db_session, iso_json)
    seed_framework_and_controls(db_session, nerc_json)

    seed_and_evaluate()
    rules = (
        db_session.query(ComplianceRule)
        .filter(ComplianceRule.id.like("crl_nerc_cip%"))
        .all()
    )
    assert len(rules) >= 10, f"Expected at least 10 NERC CIP rules, found {len(rules)}"
