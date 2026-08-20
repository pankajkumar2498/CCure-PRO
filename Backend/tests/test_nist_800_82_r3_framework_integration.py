"""
tests/test_nist_800_82_r3_framework_integration.py
Integration tests for the NIST SP 800-82 Rev. 3 Guide to Operational Technology (OT) Security framework.
"""

import os
from datetime import datetime, timezone

import pytest
from db.models.compliance import (
    ComplianceControl,
    ComplianceFinding,
    ComplianceFramework,
    ComplianceTenantFramework,
)
from scripts.seed_compliance import seed_framework_and_controls


def test_nist_800_82_r3_framework_end_to_end(
    client, db_session, test_user, auth_headers, activate_frameworks
):
    """
    Verifies full lifecycle for NIST SP 800-82 Rev. 3 (OT Security):
    1. Seeding framework & controls (35 controls across 9 OT security families)
    2. Database presence & theme check (SP82_AC .. SP82_SA)
    3. OT metadata scoping (Purdue Levels L0-L5, Component Types PLC/RTU/SCADA/DCS/SIS/HMI/HISTORIAN/IED)
    4. Tenant framework enablement
    5. GET /compliance/summary with purdue_level and component_type filters
    6. GET /compliance/findings scoped query filters
    7. PDF & DOCX report generation endpoints (/compliance/reports/nist_800_82)
    8. Gap analysis calculation endpoint (ISO 27001 -> NIST SP 800-82 Rev. 3)
    9. Executive Dashboard compliance posture check (/dashboard/compliance)
    """
    activate_frameworks("cfw_nist_800_82_r3")
    # 1. Seed NIST SP 800-82 Rev. 3 controls
    scripts_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
    )
    seed_file = os.path.join(scripts_dir, "nist_800_82_r3_controls_seed.json")
    assert os.path.exists(seed_file)
    seed_framework_and_controls(db_session, seed_file)

    # 2. Verify framework in DB
    fw = (
        db_session.query(ComplianceFramework)
        .filter(ComplianceFramework.id == "cfw_nist_800_82_r3")
        .first()
    )
    assert fw is not None
    assert fw.code == "NIST_800_82_R3"
    assert "Operational Technology" in fw.name or "NIST SP 800-82" in fw.name

    # 3. Verify controls & OT metadata tags
    controls = (
        db_session.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == "cfw_nist_800_82_r3")
        .all()
    )
    assert len(controls) == 35

    purdue_levels_set = {"L0", "L1", "L2", "L3", "L3.5", "L4", "L5"}
    purdue_controls = [
        c for c in controls if any(t in purdue_levels_set for t in (c.tags or []))
    ]
    assert len(purdue_controls) >= 30

    ot_comp_types = {"PLC", "RTU", "SCADA", "DCS", "SIS", "HMI", "HISTORIAN", "IED"}
    component_controls = [
        c for c in controls if any(t in ot_comp_types for t in (c.tags or []))
    ]
    assert len(component_controls) >= 30

    # 4. Enable tenant framework for test org
    inst = (
        db_session.query(ComplianceTenantFramework)
        .filter(
            ComplianceTenantFramework.tenant_id == test_user.org_id,
            ComplianceTenantFramework.framework_id == "cfw_nist_800_82_r3",
        )
        .first()
    )
    if not inst:
        inst = ComplianceTenantFramework(
            id=f"ctf_{test_user.org_id}_cfw_nist_800_82_r3",
            tenant_id=test_user.org_id,
            framework_id="cfw_nist_800_82_r3",
            is_enabled=True,
            enabled_at=datetime.now(timezone.utc),
        )
        db_session.add(inst)
        db_session.commit()

    # 5. Test GET /compliance/summary with purdue_level filter
    res_summary = client.get(
        "/compliance/summary?framework_id=cfw_nist_800_82_r3&purdue_level=L2",
        headers=auth_headers,
    )
    assert res_summary.status_code == 200
    summary_data = res_summary.json()
    assert "score_pct" in summary_data

    # 6. Test GET /compliance/findings with component_type filter
    res_findings = client.get(
        "/compliance/findings?framework_id=cfw_nist_800_82_r3&component_type=PLC",
        headers=auth_headers,
    )
    assert res_findings.status_code == 200

    # 7. Test PDF & DOCX report generation endpoints
    res_pdf = client.get(
        "/compliance/reports/nist_800_82?fmt=pdf&purdue_level=L2&component_type=PLC",
        headers=auth_headers,
    )
    assert res_pdf.status_code == 200
    assert res_pdf.headers["content-type"] == "application/pdf"

    res_docx = client.get(
        "/compliance/reports/nist_800_82?fmt=docx&purdue_level=L2&component_type=PLC",
        headers=auth_headers,
    )
    assert res_docx.status_code == 200
    assert "openxmlformats" in res_docx.headers["content-type"]

    # 8. Test Gap Analysis endpoint (ISO 27001 -> NIST SP 800-82 Rev. 3)
    res_gap = client.get(
        "/compliance/gap-analysis?source_framework_id=cfw_iso27001_2022&target_framework_id=cfw_nist_800_82_r3",
        headers=auth_headers,
    )
    assert res_gap.status_code == 200
    gap_data = res_gap.json()
    assert "summary" in gap_data
    assert gap_data["target_framework"]["code"] == "NIST_800_82_R3"

    # 9. Test Dashboard compliance posture endpoint
    res_dash = client.get("/dashboard/compliance", headers=auth_headers)
    assert res_dash.status_code == 200
    dash_data = res_dash.json()
    assert "frameworks" in dash_data
    nist82_card = next(
        (f for f in dash_data["frameworks"] if f["id"] == "nist_800_82"), None
    )
    assert nist82_card is not None
    assert "NIST SP 800-82" in nist82_card["name"]
