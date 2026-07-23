"""
tests/test_iec_62443_framework_integration.py
Integration tests for the IEC 62443 Industrial Communication Networks & OT/ICS framework.
"""

import os
from datetime import datetime, timezone
import pytest
from db.models.compliance import (
    ComplianceFramework,
    ComplianceControl,
    ComplianceTenantFramework,
    ComplianceFinding,
)
from scripts.seed_compliance import seed_framework_and_controls


def test_iec_62443_framework_end_to_end(client, db_session, test_user, auth_headers):
    """
    Verifies full lifecycle for IEC 62443 (OT/ICS):
    1. Seeding framework & controls (~60+ controls)
    2. Database presence & theme check
    3. OT metadata scoping (Purdue Level L0-L3.5, Component Type NDD/EDR/HDR/SW, Target SL1-SL4)
    4. Tenant framework enablement
    5. GET /compliance/summary with purdue_level, component_type, and sl_level filters
    6. GET /compliance/findings scoped query filters
    7. PDF & DOCX report generation endpoints (/compliance/reports/iec_62443)
    8. Gap analysis calculation endpoint (ISO 27001 -> IEC 62443)
    9. Executive Dashboard compliance posture check (/dashboard/compliance)
    """
    # 1. Seed IEC 62443 controls
    scripts_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
    )
    seed_file = os.path.join(scripts_dir, "iec_62443_controls_seed.json")
    assert os.path.exists(seed_file)
    seed_framework_and_controls(db_session, seed_file)

    # 2. Verify framework in DB
    fw = (
        db_session.query(ComplianceFramework)
        .filter(ComplianceFramework.id == "cfw_iec_62443")
        .first()
    )
    assert fw is not None
    assert fw.code == "IEC_62443"
    assert "Industrial" in fw.name or "IEC 62443" in fw.name

    # 3. Verify controls & OT metadata tags
    controls = (
        db_session.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == "cfw_iec_62443")
        .all()
    )
    assert len(controls) >= 50

    purdue_controls = [
        c for c in controls if any(t.startswith("L") for t in (c.tags or []))
    ]
    assert len(purdue_controls) > 0

    component_controls = [
        c
        for c in controls
        if any(t in ["NDD", "EDR", "HDR", "SW"] for t in (c.tags or []))
    ]
    assert len(component_controls) > 0

    sl_controls = [
        c for c in controls if any(t.startswith("SL") for t in (c.tags or []))
    ]
    assert len(sl_controls) > 0

    # 4. Enable tenant framework for test org
    inst = (
        db_session.query(ComplianceTenantFramework)
        .filter(
            ComplianceTenantFramework.tenant_id == test_user.org_id,
            ComplianceTenantFramework.framework_id == "cfw_iec_62443",
        )
        .first()
    )
    if not inst:
        inst = ComplianceTenantFramework(
            id=f"ctf_{test_user.org_id}_cfw_iec_62443",
            tenant_id=test_user.org_id,
            framework_id="cfw_iec_62443",
            is_enabled=True,
            enabled_at=datetime.now(timezone.utc),
        )
        db_session.add(inst)
        db_session.commit()

    # 5. Test GET /compliance/summary with purdue_level filter
    res_summary = client.get(
        "/compliance/summary?framework_id=cfw_iec_62443&purdue_level=L2",
        headers=auth_headers,
    )
    assert res_summary.status_code == 200
    summary_data = res_summary.json()
    assert "score_pct" in summary_data

    # 6. Test GET /compliance/summary with component_type and sl_level filters
    res_comp = client.get(
        "/compliance/summary?framework_id=cfw_iec_62443&component_type=EDR&sl_level=SL2",
        headers=auth_headers,
    )
    assert res_comp.status_code == 200

    # 7. Test GET /compliance/findings with OT query filters
    res_findings = client.get(
        "/compliance/findings?framework_id=cfw_iec_62443&purdue_level=L2&sl_level=SL2",
        headers=auth_headers,
    )
    assert res_findings.status_code == 200

    # 8. Test PDF Report Generation
    res_pdf = client.get(
        "/compliance/reports/iec_62443?fmt=pdf&purdue_level=L2",
        headers=auth_headers,
    )
    assert res_pdf.status_code == 200
    assert res_pdf.headers["content-type"] == "application/pdf"

    # 9. Test DOCX Report Generation
    res_docx = client.get(
        "/compliance/reports/iec_62443?fmt=docx&purdue_level=L2",
        headers=auth_headers,
    )
    assert res_docx.status_code == 200

    # 10. Test Gap Analysis: ISO 27001 -> IEC 62443
    res_gap = client.get(
        "/compliance/gap-analysis?source_framework_id=cfw_iso27001_2022&target_framework_id=cfw_iec_62443",
        headers=auth_headers,
    )
    assert res_gap.status_code == 200
    gap_data = res_gap.json()
    assert "summary" in gap_data
    assert gap_data["target_framework"]["code"] == "IEC_62443"

    # 11. Test Executive Dashboard Compliance Posture endpoint
    res_dash = client.get(
        "/dashboard/compliance",
        headers=auth_headers,
    )
    assert res_dash.status_code == 200
    dash_data = res_dash.json()
    assert "frameworks" in dash_data
    iec_card = next(
        (f for f in dash_data["frameworks"] if f["id"] == "iec_62443"), None
    )
    assert iec_card is not None
    assert iec_card["name"] == "IEC 62443 (OT/ICS)"

    # Clean up tenant framework
    if inst:
        db_session.delete(inst)
        db_session.commit()
