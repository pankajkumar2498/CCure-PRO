"""
tests/test_nist_800_53_r5_framework_integration.py
Integration tests for the NIST SP 800-53 Rev. 5 framework.
"""

from core.compliance_seeds import seed_path


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


def test_nist_800_53_r5_framework_end_to_end(
    client, db_session, test_user, auth_headers, activate_frameworks
):
    """
    Verifies full lifecycle for NIST SP 800-53 Rev. 5:
    1. Seeding framework & controls (~250+ controls)
    2. Database presence & theme check
    3. Scoping baselines (LOW / MODERATE / HIGH) & Zero Trust tags
    4. Tenant framework enablement
    5. GET /compliance/summary with impact_level and zero_trust_only filters
    6. GET /compliance/findings scoped query filters
    7. PDF & DOCX report generation endpoints
    8. Gap analysis calculation endpoint
    """
    activate_frameworks("cfw_nist_800_53_r5")
    # 1. Seed NIST SP 800-53 Rev. 5 controls
    seed_file = seed_path("nist_800_53_r5_controls_seed.json")
    assert os.path.exists(seed_file)
    seed_framework_and_controls(db_session, seed_file)

    # 2. Verify framework in DB
    fw = (
        db_session.query(ComplianceFramework)
        .filter(ComplianceFramework.id == "cfw_nist_800_53_r5")
        .first()
    )
    assert fw is not None
    assert fw.code == "NIST_800_53_R5"
    assert "Rev. 5" in fw.name or "Rev.5" in fw.version

    # 3. Verify controls & themes
    controls = (
        db_session.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == "cfw_nist_800_53_r5")
        .all()
    )
    assert len(controls) >= 200

    mod_controls = [c for c in controls if "MODERATE" in (c.saq_profiles or [])]
    assert len(mod_controls) > 0

    zta_controls = [c for c in controls if "zero_trust" in (c.tags or [])]
    assert len(zta_controls) > 0

    # 4. Enable tenant framework for test org
    inst = (
        db_session.query(ComplianceTenantFramework)
        .filter(
            ComplianceTenantFramework.tenant_id == test_user.org_id,
            ComplianceTenantFramework.framework_id == "cfw_nist_800_53_r5",
        )
        .first()
    )
    if not inst:
        inst = ComplianceTenantFramework(
            id=f"ctf_{test_user.org_id}_cfw_nist_800_53_r5",
            tenant_id=test_user.org_id,
            framework_id="cfw_nist_800_53_r5",
            is_enabled=True,
            enabled_at=datetime.now(timezone.utc),
        )
        db_session.add(inst)
        db_session.commit()

    # 5. Test GET /compliance/summary with impact_level filter
    res_summary = client.get(
        "/compliance/summary?framework_id=cfw_nist_800_53_r5&impact_level=MODERATE",
        headers=auth_headers,
    )
    assert res_summary.status_code == 200
    summary_data = res_summary.json()
    assert "score_pct" in summary_data

    # 6. Test GET /compliance/summary with zero_trust_only filter
    res_zta = client.get(
        "/compliance/summary?framework_id=cfw_nist_800_53_r5&zero_trust_only=true",
        headers=auth_headers,
    )
    assert res_zta.status_code == 200

    # 7. Test GET /compliance/findings with impact_level filter
    res_findings = client.get(
        "/compliance/findings?framework_id=cfw_nist_800_53_r5&impact_level=MODERATE",
        headers=auth_headers,
    )
    assert res_findings.status_code == 200

    # 8. Test PDF Report Generation
    res_pdf = client.get(
        "/compliance/reports/nist_800_53_r5?fmt=pdf&impact_level=MODERATE",
        headers=auth_headers,
    )
    assert res_pdf.status_code == 200
    assert res_pdf.headers["content-type"] == "application/pdf"

    # 9. Test DOCX Report Generation
    res_docx = client.get(
        "/compliance/reports/nist_800_53_r5?fmt=docx&impact_level=MODERATE",
        headers=auth_headers,
    )
    assert res_docx.status_code == 200

    # 10. Test Gap Analysis: ISO 27001 -> NIST SP 800-53 R5
    res_gap = client.get(
        "/compliance/gap-analysis?source_framework_id=cfw_iso27001_2022&target_framework_id=cfw_nist_800_53_r5",
        headers=auth_headers,
    )
    assert res_gap.status_code == 200
    gap_data = res_gap.json()
    assert "summary" in gap_data
    assert gap_data["target_framework"]["code"] == "NIST_800_53_R5"

    # Clean up tenant framework
    if inst:
        db_session.delete(inst)
        db_session.commit()
