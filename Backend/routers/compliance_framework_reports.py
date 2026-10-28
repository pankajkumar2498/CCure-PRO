"""
routers/compliance_framework_reports.py
─────────────────────────────────────────────────────────────────────────────
The per-framework compliance reports' routes: CIS, SOC 2, CERT-In, PCI DSS,
DPDP, GDPR, NIST SP 800-53, IEC 62443, NIST SP 800-82, NERC CIP and NIS 2.
The documents are rendered by ``reporting/compliance/``.

Part of the compliance router, split out of ``routers/compliance.py`` (G6,
C8 of docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md) and moved
unchanged; that module mounts the parts' sections in the order the API has
always listed them.
"""

from ccure_platform.api import CurrentUser, log_audit_event, require_authorized
from core.rate_limiter import limiter
from datetime import datetime, timedelta, timezone
from db.base import get_db
from db.models.compliance import (
    ComplianceControl,
    ComplianceFinding,
    ComplianceFindingHistory,
)
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from reporting.compliance.iec_62443 import (
    _generate_iec_62443_docx,
    _generate_iec_62443_pdf,
)
from reporting.compliance.nerc_cip import (
    _generate_nerc_cip_docx,
    _generate_nerc_cip_pdf,
)
from reporting.compliance.nis2 import _generate_nis2_docx, _generate_nis2_pdf
from reporting.compliance.nist_800_53 import (
    _generate_nist_800_53_docx,
    _generate_nist_800_53_pdf,
)
from reporting.compliance.nist_800_82 import (
    _generate_nist_800_82_docx,
    _generate_nist_800_82_pdf,
)
from reporting.compliance.pci_dss import _generate_pci_dss_docx, _generate_pci_dss_pdf
from reporting.compliance.privacy import _generate_privacy_docx, _generate_privacy_pdf
from reporting.compliance.soa import _generate_soa_docx, _generate_soa_pdf
from routers.compliance_common import (
    control_sort_key,
    require_active_framework,
    rolled_up_control_findings,
)
from sqlalchemy.orm import Session

try:
    import docx
    from docx import Document
except ImportError:
    docx = None
    Document = None

# Served as ``routers.compliance``: its routes' limiter keys, logger, gateway
# policy entries and model names are that module's, as they were before the
# split (see routers/compliance.py).
__name__ = "routers.compliance"  # noqa: A001


framework_reports = router = APIRouter()


@router.get("/reports/cis_v8_1")
@limiter.limit("10/minute")
def download_cis_v8_1_report(
    request: Request,
    fmt: str = "pdf",
    ig: str | None = Query(
        None, description="Implementation Group filter: ig1, ig2, ig3"
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.export_report")),
):
    """Generates and downloads the CIS Controls v8.1 Compliance Assessment Report."""
    fw_id = "cfw_cis_v8_1"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if ig:
        ig_val = ig.strip().lower()
        query = query.filter(ComplianceControl.tags.contains([ig_val]))

    controls = query.order_by(
        ComplianceControl.theme, ComplianceControl.control_number
    ).all()
    control_ids = [c.id for c in controls]

    findings = (
        db.query(ComplianceFinding)
        .filter(
            ComplianceFinding.tenant_id == user.org_id,
            ComplianceFinding.control_id.in_(control_ids),
        )
        .all()
    )
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    report_title = "CIS Critical Security Controls v8.1 Executive Report"
    report_sub = f"CIS Controls v8.1 Assessment Ledger (Tenant: {user.org_id[:8]})"

    if fmt.lower() == "docx" and Document is not None:
        buffer = _generate_soa_docx(
            controls, findings_map, title=report_title, subtitle=report_sub
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"cis_v8_1_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_soa_pdf(
            controls, findings_map, title=report_title, subtitle=report_sub
        )
        media = "application/pdf"
        filename = f"cis_v8_1_report_{user.org_id[:4]}.pdf"

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/soc2_type2")
@limiter.limit("10/minute")
def download_soc2_type2_report(
    request: Request,
    fmt: str = "pdf",
    tsc: str | None = Query(
        None, description="Trust Services Criteria filter: cc, a, pi, c, p"
    ),
    audit_period_days: int = Query(
        90, ge=30, le=365, description="SOC 2 Type II Observation Period in Days"
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.export_report")),
):
    """Generates and downloads the SOC 2 Type II (AICPA Trust Services Criteria) Compliance Audit Report."""
    fw_id = "cfw_soc2_type2"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if tsc:
        tsc_code = f"SOC2_{tsc.strip().upper()}"
        query = query.filter(ComplianceControl.theme == tsc_code)

    controls = query.order_by(
        ComplianceControl.theme, ComplianceControl.control_number
    ).all()
    control_ids = [c.id for c in controls]

    findings = (
        db.query(ComplianceFinding)
        .filter(
            ComplianceFinding.tenant_id == user.org_id,
            ComplianceFinding.control_id.in_(control_ids),
        )
        .all()
    )
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    # Time-Series Historical Deviation check for SOC 2 Type II observation window
    window_start = datetime.now(timezone.utc) - timedelta(days=audit_period_days)
    history_deviations = (
        db.query(ComplianceFindingHistory.finding_id)
        .join(
            ComplianceFinding,
            ComplianceFinding.id == ComplianceFindingHistory.finding_id,
        )
        .filter(
            ComplianceFinding.tenant_id == user.org_id,
            ComplianceFinding.control_id.in_(control_ids),
            ComplianceFindingHistory.changed_at >= window_start,
            ComplianceFindingHistory.status == "fail",
        )
        .distinct()
        .all()
    )
    deviation_finding_ids = {h[0] for h in history_deviations}

    # Annotate findings map with historical deviations if any occurred during the window
    for f in findings:
        if f.id in deviation_finding_ids and f.status == "pass":
            ev = dict(f.evidence or {})
            ev["historical_deviation"] = (
                f"Failed at least once within the past {audit_period_days}-day observation period."
            )
            f.evidence = ev

    report_title = "SOC 2 Type II Audit Readiness & Trust Services Ledger"
    report_sub = f"AICPA Trust Services Criteria Assessment (Tenant: {user.org_id[:8]} | Observation Window: {audit_period_days} Days)"

    if fmt.lower() == "docx" and Document is not None:
        buffer = _generate_soa_docx(
            controls, findings_map, title=report_title, subtitle=report_sub
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"soc2_type2_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_soa_pdf(
            controls, findings_map, title=report_title, subtitle=report_sub
        )
        media = "application/pdf"
        filename = f"soc2_type2_report_{user.org_id[:4]}.pdf"

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/cert_in_2022")
@limiter.limit("10/minute")
def download_cert_in_2022_report(
    request: Request,
    fmt: str = "pdf",
    theme: str | None = Query(
        None,
        description="CERT-In theme filter: CERT_IR, CERT_LOG, CERT_AM, CERT_VM, CERT_AC, CERT_DP",
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.export_report")),
):
    """Generates and downloads the CERT-In Cyber Security Directions 2022 & CCMP Compliance Report."""
    fw_id = "cfw_cert_in_2022"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if theme:
        query = query.filter(ComplianceControl.theme == theme.strip().upper())

    controls = query.order_by(
        ComplianceControl.theme, ComplianceControl.control_number
    ).all()
    control_ids = [c.id for c in controls]

    findings = (
        db.query(ComplianceFinding)
        .filter(
            ComplianceFinding.tenant_id == user.org_id,
            ComplianceFinding.control_id.in_(control_ids),
        )
        .all()
    )
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    report_title = "CERT-In Directions 2022 & CCMP Security Compliance Audit Report"
    report_sub = f"Indian Cyber Security Directions & Cyber Crisis Management Plan Ledger (Tenant: {user.org_id[:8]})"

    if fmt.lower() == "docx" and Document is not None:
        buffer = _generate_soa_docx(
            controls, findings_map, title=report_title, subtitle=report_sub
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"cert_in_2022_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_soa_pdf(
            controls, findings_map, title=report_title, subtitle=report_sub
        )
        media = "application/pdf"
        filename = f"cert_in_2022_report_{user.org_id[:4]}.pdf"

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/pci_dss_v4")
@limiter.limit("10/minute")
def download_pci_dss_v4_report(
    request: Request,
    fmt: str = "pdf",
    saq_profile: str | None = Query(
        None,
        description="Filter by SAQ profile: saq_a, saq_a_ep, saq_b_ip, saq_c, saq_d_merchant, saq_d_service_provider",
    ),
    cde_scope_only: bool = Query(
        False, description="Filter only by CDE scope tagged controls/findings"
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.export_report")),
):
    """Generates and downloads the PCI-DSS v4.0 Compliance Assessment Report."""
    fw_id = "cfw_pci_dss_v4"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if saq_profile:
        query = query.filter(ComplianceControl.saq_profiles.contains([saq_profile]))

    if cde_scope_only:
        query = query.filter(ComplianceControl.tags.contains(["cde"]))

    controls = query.order_by(
        ComplianceControl.theme, ComplianceControl.control_number
    ).all()
    control_ids = [c.id for c in controls]

    finding_query = db.query(ComplianceFinding).filter(
        ComplianceFinding.tenant_id == user.org_id,
        ComplianceFinding.control_id.in_(control_ids),
    )

    if cde_scope_only:
        finding_query = finding_query.filter(ComplianceFinding.cde_scope.isnot(None))

    findings = finding_query.all()
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    report_title = "PCI-DSS v4.0 Compliance Audit Assessment Report"
    report_sub = f"PCI-DSS v4.0 Assessment Ledger (Tenant: {user.org_id[:8]}"
    if saq_profile:
        report_sub += f" | SAQ Profile: {saq_profile.upper()}"
    if cde_scope_only:
        report_sub += " | CDE Scope Only"
    report_sub += ")"

    if fmt.lower() == "docx" and Document is not None:
        buffer = _generate_pci_dss_docx(
            controls, findings_map, title=report_title, subtitle=report_sub
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"pci_dss_v4_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_pci_dss_pdf(
            controls, findings_map, title=report_title, subtitle=report_sub
        )
        media = "application/pdf"
        filename = f"pci_dss_v4_report_{user.org_id[:4]}.pdf"

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/dpdp_2023")
@limiter.limit("10/minute")
def download_dpdp_2023_report(
    request: Request,
    fmt: str = "pdf",
    sdf_scope: str | None = Query(
        None, description="Filter by SDF scope: sdf_mandatory, general_fiduciary"
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.export_report")),
):
    """Generates and downloads the DPDP Act 2023 Compliance Assessment Report."""
    fw_id = "cfw_dpdp_2023"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if sdf_scope and sdf_scope != "all":
        query = query.filter(ComplianceControl.sdf_scope == sdf_scope)

    controls = query.order_by(
        ComplianceControl.theme, ComplianceControl.control_number
    ).all()
    control_ids = [c.id for c in controls]

    findings = (
        db.query(ComplianceFinding)
        .filter(
            ComplianceFinding.tenant_id == user.org_id,
            ComplianceFinding.control_id.in_(control_ids),
        )
        .all()
    )
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    report_title = "DPDP Act 2023 Digital Personal Data Protection Audit Report"
    report_sub = (
        f"Data Protection Board of India Compliance Ledger (Tenant: {user.org_id[:8]})"
    )
    scope_label = f"SDF Scope: {sdf_scope.upper()}" if sdf_scope else "All Controls"

    if fmt.lower() == "docx" and Document is not None:
        buffer = _generate_privacy_docx(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"dpdp_2023_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_privacy_pdf(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            primary_color="#d97706",
            scope_label=scope_label,
        )
        media = "application/pdf"
        filename = f"dpdp_2023_report_{user.org_id[:4]}.pdf"

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/gdpr")
@limiter.limit("10/minute")
def download_gdpr_report(
    request: Request,
    fmt: str = "pdf",
    privacy_role: str | None = Query(
        None, description="Filter by Privacy Role: controller, processor, both"
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.export_report")),
):
    """Generates and downloads the EU GDPR Compliance Assessment Report."""
    fw_id = "cfw_gdpr"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if privacy_role and privacy_role != "all":
        query = query.filter(ComplianceControl.privacy_role.in_([privacy_role, "both"]))

    controls = query.order_by(
        ComplianceControl.theme, ComplianceControl.control_number
    ).all()
    control_ids = [c.id for c in controls]

    findings = (
        db.query(ComplianceFinding)
        .filter(
            ComplianceFinding.tenant_id == user.org_id,
            ComplianceFinding.control_id.in_(control_ids),
        )
        .all()
    )
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    report_title = "EU GDPR 2016/679 Compliance Assessment Audit Report"
    report_sub = (
        f"European Data Protection Board Assessment Ledger (Tenant: {user.org_id[:8]})"
    )
    scope_label = (
        f"Privacy Role: {privacy_role.upper()}" if privacy_role else "All Roles"
    )

    if fmt.lower() == "docx" and Document is not None:
        buffer = _generate_privacy_docx(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"gdpr_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_privacy_pdf(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            primary_color="#1d4ed8",
            scope_label=scope_label,
        )
        media = "application/pdf"
        filename = f"gdpr_report_{user.org_id[:4]}.pdf"

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/nist_800_53_r5")
@limiter.limit("10/minute")
def download_nist_800_53_r5_report(
    request: Request,
    fmt: str = "pdf",
    impact_level: str | None = Query(None, description="LOW | MODERATE | HIGH"),
    control_family: str | None = Query(None, description="SP53_AC | SP53_AU | etc"),
    zero_trust_only: bool = Query(False),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.export_report")),
):
    """Generates and downloads the NIST SP 800-53 Rev. 5 Federal Information Security Assessment Report."""
    fw_id = "cfw_nist_800_53_r5"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if impact_level and impact_level != "all":
        query = query.filter(
            ComplianceControl.saq_profiles.contains([impact_level.upper()])
        )

    if control_family and control_family != "all":
        query = query.filter(ComplianceControl.theme == control_family.upper())

    if zero_trust_only:
        query = query.filter(ComplianceControl.tags.contains(["zero_trust"]))

    controls = query.order_by(
        ComplianceControl.theme, ComplianceControl.control_number
    ).all()
    control_ids = [c.id for c in controls]

    findings = (
        db.query(ComplianceFinding)
        .filter(
            ComplianceFinding.tenant_id == user.org_id,
            ComplianceFinding.control_id.in_(control_ids),
        )
        .all()
    )
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    report_title = "NIST SP 800-53 Rev. 5 Federal Security Assessment Report"
    report_sub = (
        f"U.S. Federal & Defense Accreditation Ledger (Tenant: {user.org_id[:8]})"
    )
    scope_label = (
        f"FedRAMP Impact Level: {impact_level.upper()}"
        if impact_level and impact_level != "all"
        else "All Impact Baselines"
    )
    if zero_trust_only:
        scope_label += " (Zero Trust Architecture Only)"

    if fmt.lower() == "docx" and Document is not None:
        buffer = _generate_nist_800_53_docx(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"nist_800_53_r5_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_nist_800_53_pdf(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
        )
        media = "application/pdf"
        filename = f"nist_800_53_r5_report_{user.org_id[:4]}.pdf"

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/iec_62443")
@limiter.limit("10/minute")
def download_iec_62443_report(
    request: Request,
    fmt: str = Query("pdf", description="pdf | docx"),
    purdue_level: str | None = Query(None, description="L0 | L1 | L2 | L3 | L3.5"),
    component_type: str | None = Query(None, description="NDD | EDR | HDR | SW"),
    sl_level: str | None = Query(None, description="SL1 | SL2 | SL3 | SL4"),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.export_report")),
):
    """Generates and downloads the IEC 62443 Industrial Cybersecurity Assessment Report."""
    fw_id = "cfw_iec_62443"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if purdue_level and purdue_level != "all":
        query = query.filter(ComplianceControl.tags.contains([purdue_level.upper()]))

    if component_type and component_type != "all":
        query = query.filter(ComplianceControl.tags.contains([component_type.upper()]))

    if sl_level and sl_level != "all":
        query = query.filter(ComplianceControl.tags.contains([sl_level.upper()]))

    controls = query.order_by(
        ComplianceControl.theme, ComplianceControl.control_number
    ).all()
    control_ids = [c.id for c in controls]

    findings = (
        db.query(ComplianceFinding)
        .filter(
            ComplianceFinding.tenant_id == user.org_id,
            ComplianceFinding.control_id.in_(control_ids),
        )
        .all()
    )
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    report_title = "IEC 62443 Industrial Cybersecurity Audit Report"
    report_sub = f"OT/ICS System Security Ledger (Tenant: {user.org_id[:8]})"
    scope_parts = []
    if purdue_level and purdue_level != "all":
        scope_parts.append(f"Purdue Level: {purdue_level.upper()}")
    if component_type and component_type != "all":
        scope_parts.append(f"Component: {component_type.upper()}")
    if sl_level and sl_level != "all":
        scope_parts.append(f"Target SL: {sl_level.upper()}")
    scope_label = (
        ", ".join(scope_parts) if scope_parts else "All OT Assets & Security Levels"
    )

    if fmt.lower() == "docx":
        buffer = _generate_iec_62443_docx(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"iec_62443_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_iec_62443_pdf(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
        )
        media = "application/pdf"
        filename = f"iec_62443_report_{user.org_id[:4]}.pdf"

    from fastapi.responses import StreamingResponse

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/nist_800_82")
@limiter.limit("10/minute")
def download_nist_800_82_report(
    request: Request,
    fmt: str = Query("pdf", description="pdf | docx"),
    purdue_level: str | None = Query(
        None, description="L0 | L1 | L2 | L3 | L3.5 | L4 | L5"
    ),
    component_type: str | None = Query(
        None, description="PLC | RTU | SCADA | DCS | SIS | HMI | HISTORIAN | IED"
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.export_report")),
):
    """Generates and downloads the NIST SP 800-82 Rev. 3 OT Security Assessment Report."""
    fw_id = "cfw_nist_800_82_r3"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if purdue_level and purdue_level != "all":
        query = query.filter(ComplianceControl.tags.contains([purdue_level.upper()]))

    if component_type and component_type != "all":
        query = query.filter(ComplianceControl.tags.contains([component_type.upper()]))

    controls = query.order_by(
        ComplianceControl.theme, ComplianceControl.control_number
    ).all()
    control_ids = [c.id for c in controls]

    findings = (
        db.query(ComplianceFinding)
        .filter(
            ComplianceFinding.tenant_id == user.org_id,
            ComplianceFinding.control_id.in_(control_ids),
        )
        .all()
    )
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    report_title = "NIST SP 800-82 Rev. 3 OT Security Assessment Report"
    report_sub = (
        f"Operational Technology Security Control Ledger (Tenant: {user.org_id[:8]})"
    )
    scope_parts = []
    if purdue_level and purdue_level != "all":
        scope_parts.append(f"Purdue Level: {purdue_level.upper()}")
    if component_type and component_type != "all":
        scope_parts.append(f"Component: {component_type.upper()}")
    scope_label = (
        ", ".join(scope_parts) if scope_parts else "All OT Assets & Purdue Levels"
    )

    if fmt.lower() == "docx":
        buffer = _generate_nist_800_82_docx(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"nist_800_82_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_nist_800_82_pdf(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
        )
        media = "application/pdf"
        filename = f"nist_800_82_report_{user.org_id[:4]}.pdf"

    from fastapi.responses import StreamingResponse

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/nerc_cip")
@limiter.limit("10/minute")
def download_nerc_cip_report(
    request: Request,
    fmt: str = Query("pdf", description="pdf | docx"),
    bes_impact_level: str | None = Query(None, description="High | Medium | Low"),
    standard_number: str | None = Query(None, description="CIP-002 … CIP-014"),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.export_report")),
):
    """NERC CIP Critical Infrastructure Protection audit report.

    Both generators below have existed since the framework was added and no
    route ever reached them, while the workspace's report menu offered "NERC
    CIP Critical Infrastructure" as an option — so selecting it returned 404.
    """
    fw_id = "cfw_nerc_cip"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if bes_impact_level and bes_impact_level != "all":
        query = query.filter(
            ComplianceControl.tags.contains([bes_impact_level.capitalize()])
        )
    if standard_number and standard_number != "all":
        query = query.filter(ComplianceControl.tags.contains([standard_number.upper()]))

    controls = query.all()
    controls.sort(key=lambda c: control_sort_key(c.control_number))
    control_ids = [c.id for c in controls]
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    scope_parts = []
    if bes_impact_level and bes_impact_level != "all":
        scope_parts.append(f"BES Impact: {bes_impact_level.capitalize()}")
    if standard_number and standard_number != "all":
        scope_parts.append(f"Standard: {standard_number.upper()}")
    scope_label = (
        ", ".join(scope_parts)
        if scope_parts
        else "All BES Cyber Systems & Impact Baselines"
    )

    if fmt.lower() == "docx":
        buffer = _generate_nerc_cip_docx(
            controls, findings_map, scope_label=scope_label
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"nerc_cip_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_nerc_cip_pdf(controls, findings_map, scope_label=scope_label)
        media = "application/pdf"
        filename = f"nerc_cip_report_{user.org_id[:4]}.pdf"

    log_audit_event(db, user, "export_report", "framework", fw_id, status="success")
    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/nis2")
@limiter.limit("10/minute")
def download_nis2_report(
    request: Request,
    fmt: str = Query("pdf", description="pdf | docx"),
    nis2_entity_type: str | None = Query(
        "essential", description="essential | important"
    ),
    nis2_sector: str | None = Query(None, description="all | 18 sectors"),
    nis2_member_state: str | None = Query(
        None, description="all | DE | FR | IT | NL | BE | ES | SE | PL | IE"
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.export_report")),
):
    """Generates and downloads the EU NIS 2 Directive Regulatory Audit Report."""
    fw_id = "cfw_nis2"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if nis2_entity_type and nis2_entity_type != "all":
        query = query.filter(
            ComplianceControl.tags.contains([nis2_entity_type.capitalize()])
        )

    if nis2_sector and nis2_sector != "all":
        query = query.filter(
            ComplianceControl.tags.contains([nis2_sector.capitalize()])
        )

    controls = query.order_by(
        ComplianceControl.theme, ComplianceControl.control_number
    ).all()
    control_ids = [c.id for c in controls]

    findings = (
        db.query(ComplianceFinding)
        .filter(
            ComplianceFinding.tenant_id == user.org_id,
            ComplianceFinding.control_id.in_(control_ids),
        )
        .all()
    )
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    report_title = "EU NIS 2 Directive Regulatory Compliance Audit Report"
    report_sub = f"European Union Directive (EU) 2022/2555 Security Assessment Ledger (Tenant: {user.org_id[:8]})"

    entity_label = (
        "Essential Entity (Art. 3.1)"
        if nis2_entity_type and nis2_entity_type.lower() == "essential"
        else "Important Entity (Art. 3.2)"
    )

    scope_label = (
        nis2_sector.upper()
        if nis2_sector and nis2_sector != "all"
        else "All 18 Critical Sectors"
    )

    member_state_labels = {
        "DE": "Germany — BSI (Bundesamt für Sicherheit in der Informationstechnik)",
        "FR": "France — ANSSI (Agence nationale de la sécurité des SI)",
        "IT": "Italy — ACN (Agenzia per la Cybersicurezza Nazionale)",
        "NL": "Netherlands — NCSC-NL",
        "BE": "Belgium — CCB (Centre for Cybersecurity Belgium)",
        "ES": "Spain — INCIBE / CCN-CERT",
        "SE": "Sweden — MSB",
        "PL": "Poland — NASK / CERT Polska",
        "IE": "Ireland — NCSC-IE",
    }
    member_label = (
        member_state_labels.get(nis2_member_state.upper(), "All EU (ENISA Coordinated)")
        if nis2_member_state
        else "All EU (ENISA Coordinated)"
    )

    if fmt.lower() == "docx":
        buffer = _generate_nis2_docx(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
            entity_type_label=entity_label,
            member_state_label=member_label,
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"nis2_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_nis2_pdf(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
            entity_type_label=entity_label,
            member_state_label=member_label,
        )
        media = "application/pdf"
        filename = f"nis2_report_{user.org_id[:4]}.pdf"

    from fastapi.responses import StreamingResponse

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
