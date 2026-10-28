"""
routers/compliance_reports.py
─────────────────────────────────────────────────────────────────────────────
The compliance reports' routes: the Statement of Applicability, the
executive report, gap analysis and the NIST CSF profile. The documents
are rendered by ``reporting/compliance/``.

Part of the compliance router, split out of ``routers/compliance.py`` (G6,
C8 of docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md) and moved
unchanged; that module mounts the parts' sections in the order the API has
always listed them.
"""

import io
from ccure_platform.api import CurrentUser, log_audit_event, require_authorized
from core import nist_csf
from core.rate_limiter import limiter
from datetime import datetime, timezone
from db.base import get_db
from db.models.compliance import (
    ComplianceControl,
    ComplianceEvidenceFile,
    ComplianceException,
    ComplianceFramework,
    ComplianceScore,
    ComplianceTenantFramework,
)
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from reporting.compliance.nist_csf import (
    _csf_verdict,
    _generate_nist_csf_docx,
    _generate_nist_csf_pdf,
)
from reporting.compliance.soa import (
    _generate_soa_detailed_docx,
    _generate_soa_detailed_pdf,
)
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from routers.compliance_common import (
    SOA_EXCLUDED_THEME,
    _latest_run_id,
    control_sort_key,
    require_active_framework,
    rolled_up_control_findings,
    rolled_up_control_status,
)
from sqlalchemy import and_, func
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


reports = router = APIRouter()


@router.get("/reports/soa")
@limiter.limit("10/minute")
def download_statement_of_applicability(
    request: Request,
    fmt: str = "pdf",
    framework_id: str = Query("cfw_iso27001_2022"),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.export_report")),
):
    """Statement of Applicability for one framework.

    A Statement of Applicability is an ISO/IEC 27001 artefact covering one
    standard's control set. This used to emit the controls of *every* installed
    framework, so an organisation with all twelve installed received an
    800-row multi-standard dump labelled "ISO 27001 SoA". It is now scoped to a
    single framework, defaulting to ISO 27001:2022.
    """
    require_active_framework(framework_id)

    fw = (
        db.query(ComplianceFramework)
        .filter(ComplianceFramework.id == framework_id)
        .first()
    )
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")

    tf = (
        db.query(ComplianceTenantFramework)
        .filter_by(tenant_id=user.org_id, framework_id=framework_id, is_enabled=True)
        .first()
    )
    if not tf:
        raise HTTPException(
            status_code=400,
            detail="Framework is not installed for this organization.",
        )

    # ISO/IEC 27001's management-system clauses (4–10) are in the catalogue as
    # attestation controls but not in the SoA: clause 6.1.3(d) makes the SoA a
    # statement about Annex A controls, and clauses 4–10 are mandatory — there
    # is no applicability to state.
    controls = (
        db.query(ComplianceControl)
        .filter(
            ComplianceControl.framework_id == framework_id,
            ComplianceControl.theme != SOA_EXCLUDED_THEME,
        )
        .all()
    )
    # Numeric ordering. `ORDER BY control_number` is a string sort, so the SoA
    # came out A.5.1, A.5.10, A.5.11 … A.5.2 — the first thing an auditor
    # notices.
    controls.sort(key=lambda c: control_sort_key(c.control_number))
    control_ids = [c.id for c in controls]

    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    org = getattr(user, "organization", None)
    org_name = getattr(org, "name", None) or user.org_id

    evidence_counts = dict(
        db.query(
            ComplianceEvidenceFile.control_id, func.count(ComplianceEvidenceFile.id)
        )
        .filter(
            ComplianceEvidenceFile.tenant_id == user.org_id,
            ComplianceEvidenceFile.control_id.in_(control_ids),
        )
        .group_by(ComplianceEvidenceFile.control_id)
        .all()
    )

    meta = {
        "framework_name": fw.name,
        "framework_version": fw.version,
        "organization": org_name,
        "generated_at": datetime.now(timezone.utc),
        "generated_by": getattr(user, "email", None) or user.id,
        "last_run_id": _latest_run_id(db, user.org_id, framework_id),
        "evidence_counts": evidence_counts,
    }

    slug = fw.code.lower()
    if fmt.lower() == "docx":
        # Say so rather than quietly handing back a PDF. python-docx was not a
        # declared dependency, so every DOCX request in this module fell
        # through to the PDF branch — the caller asked for one format and
        # received another with no indication why.
        if Document is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    "DOCX export is unavailable because python-docx is not "
                    "installed on this deployment. Request fmt=pdf instead."
                ),
            )
        buffer = _generate_soa_detailed_docx(controls, findings_map, meta)
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"soa_{slug}_{user.org_id}.docx"
    else:
        buffer = _generate_soa_detailed_pdf(controls, findings_map, meta)
        media = "application/pdf"
        filename = f"soa_{slug}_{user.org_id}.pdf"

    log_audit_event(db, user, "export_soa", "framework", framework_id, status="success")
    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/executive")
# Report generation renders a PDF or DOCX synchronously inside the request,
# so each call holds a threadpool worker for as long as the render takes.
# Thirteen of these endpoints existed and none carried a limit, which made
# a loop over any one of them a CPU and memory exhaustion path that needs no
# special privilege beyond compliance:export_report.
@limiter.limit("10/minute")
def download_executive_compliance_report(
    request: Request,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.export_report")),
):
    """Generates the executive management compliance posture report PDF."""
    # Filter scores by enabled frameworks
    enabled_fw_subquery = (
        db.query(ComplianceTenantFramework.framework_id)
        .filter(
            ComplianceTenantFramework.tenant_id == user.org_id,
            ComplianceTenantFramework.is_enabled == True,
        )
        .subquery()
    )

    scores = (
        db.query(ComplianceScore)
        .filter(
            ComplianceScore.tenant_id == user.org_id,
            ComplianceScore.asset_id == None,
            ComplianceScore.theme == None,
            ComplianceScore.framework_id.in_(enabled_fw_subquery),
        )
        .all()
    )

    avg_score = (
        round(sum(float(s.score_pct) for s in scores) / len(scores), 2)
        if scores
        else 0.0
    )
    avg_weighted = (
        round(sum(float(s.weighted_score_pct) for s in scores) / len(scores), 2)
        if scores
        else 0.0
    )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ExecutiveTitle",
        parent=styles["Title"],
        fontSize=22,
        textColor=colors.HexColor("#003366"),
        spaceAfter=15,
    )
    metric_style = ParagraphStyle(
        "MetricLabel",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#4A5568"),
    )
    value_style = ParagraphStyle(
        "MetricValue",
        parent=styles["Normal"],
        fontSize=28,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#22C55E"),
    )

    story = [
        Paragraph("Executive Compliance Assessment Report", title_style),
        Paragraph(
            f"Organization ID: {user.org_id} | Date: {datetime.now().strftime('%d %b %Y')}",
            styles["Normal"],
        ),
        Spacer(1, 10 * mm),
        Paragraph("<b>1. Compliance Posture Headline Scores</b>", styles["Heading2"]),
        Spacer(1, 4 * mm),
    ]

    metrics_table = Table(
        [
            [
                Paragraph("Standard Assessment Score", metric_style),
                Paragraph("Risk-Weighted Score", metric_style),
            ],
            [
                Paragraph(f"{avg_score}%", value_style),
                Paragraph(f"{avg_weighted}%", value_style),
            ],
        ],
        colWidths=[90 * mm, 90 * mm],
    )
    metrics_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    story.append(metrics_table)
    story.append(Spacer(1, 10 * mm))

    # Add exceptions overview filtered to enabled frameworks
    exceptions_count = (
        db.query(ComplianceException)
        .join(ComplianceControl, ComplianceControl.id == ComplianceException.control_id)
        .join(
            ComplianceTenantFramework,
            and_(
                ComplianceTenantFramework.framework_id
                == ComplianceControl.framework_id,
                ComplianceTenantFramework.tenant_id == user.org_id,
                ComplianceTenantFramework.is_enabled == True,
            ),
        )
        .filter(
            ComplianceException.tenant_id == user.org_id,
            ComplianceException.status == "approved",
        )
        .count()
    )

    story.append(Paragraph("<b>2. Active Exception Waivers</b>", styles["Heading2"]))
    story.append(
        Paragraph(
            f"Currently, there are {exceptions_count} active exception waivers approved by the compliance officer.",
            styles["Normal"],
        )
    )

    doc.build(story)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=compliance_executive_{user.org_id[:4]}.pdf"
        },
    )


@router.get("/gap-analysis")
def get_compliance_gap_analysis(
    source_framework_id: str = "cfw_iso27001_2022",
    target_framework_id: str = "cfw_nist_csf_v2",
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.read")),
):
    """Calculates estimated compliance posture for target framework based on source framework crosswalk mappings."""
    require_active_framework(source_framework_id)
    require_active_framework(target_framework_id)

    target_fw = (
        db.query(ComplianceFramework)
        .filter(ComplianceFramework.id == target_framework_id)
        .first()
    )
    source_fw = (
        db.query(ComplianceFramework)
        .filter(ComplianceFramework.id == source_framework_id)
        .first()
    )

    if not target_fw or not source_fw:
        raise HTTPException(status_code=404, detail="Framework not found")

    target_controls = (
        db.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == target_framework_id)
        .all()
    )
    source_controls = (
        db.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == source_framework_id)
        .all()
    )

    def normalize(val: str) -> str:
        return (
            val.lower()
            .replace("a.", "")
            .replace(".", "")
            .replace("-", "")
            .replace(" ", "")
            .replace("_", "")
        )

    source_num_to_id = {normalize(c.control_number): c.id for c in source_controls}

    # Rolled up through the shared precedence table and scoped to the source
    # framework. This used to read every finding the tenant had, across all
    # frameworks, into a last-wins dict.
    source_findings_map = rolled_up_control_status(
        db, user.org_id, [c.id for c in source_controls]
    )

    total_target = len(target_controls)
    estimated_pass = 0
    estimated_fail = 0
    pending_manual = 0
    mapped_count = 0

    control_breakdown = []
    for ctrl in target_controls:
        status_eval = "pending_manual"
        mapped_ref = ctrl.crosswalk or []

        if mapped_ref:
            mapped_count += 1
            has_pass = False
            has_fail = False
            for cross_num in mapped_ref:
                clean_cross_num = (
                    cross_num.split(":", 1)[1] if ":" in cross_num else cross_num
                )
                norm_num = normalize(clean_cross_num)
                source_ctrl_id = source_num_to_id.get(norm_num)
                if not source_ctrl_id:
                    clean_raw = (
                        clean_cross_num.lower()
                        .replace("a.", "")
                        .replace(".", "_")
                        .replace("-", "_")
                    )
                    source_ctrl_id = f"cct_{source_fw.code.lower()}_{clean_raw}"

                found_status = source_findings_map.get(source_ctrl_id)
                if found_status in ("pass", "exception"):
                    has_pass = True
                elif found_status in ("fail", "pending_reverify"):
                    has_fail = True

            # Fail wins. A target control that crosswalks to three source
            # controls, one passing and two failing, is not "covered" — the
            # previous order checked has_pass first and rounded the gap
            # analysis up, which is the one direction a gap analysis must never
            # round.
            if has_fail:
                status_eval = "fail"
                estimated_fail += 1
            elif has_pass:
                status_eval = "pass"
                estimated_pass += 1
            else:
                pending_manual += 1
        else:
            pending_manual += 1

        control_breakdown.append(
            {
                "control_id": ctrl.id,
                "control_number": ctrl.control_number,
                "theme": ctrl.theme,
                "title": ctrl.title,
                "crosswalk": mapped_ref,
                "estimated_status": status_eval,
            }
        )

    estimated_pct = (
        round((estimated_pass / total_target) * 100, 2) if total_target > 0 else 0.0
    )

    return {
        "source_framework": {
            "id": source_fw.id,
            "name": source_fw.name,
            "code": source_fw.code,
        },
        "target_framework": {
            "id": target_fw.id,
            "name": target_fw.name,
            "code": target_fw.code,
        },
        "summary": {
            "total_target_controls": total_target,
            "mapped_controls": mapped_count,
            "estimated_pass": estimated_pass,
            "estimated_fail": estimated_fail,
            "pending_manual": pending_manual,
            "estimated_score_pct": estimated_pct,
        },
        "controls": control_breakdown,
    }


def _csf_group(controls: list, findings_map: dict) -> list:
    """`[(function_code, function_name, score, [(category, name, [rows])])]`.

    Ordered by `core.nist_csf`, which is NIST's published order rather than the
    alphabetical one.
    """
    by_function: dict = {}
    for c in controls:
        number = c.control_number or ""
        category = (
            number.partition("-")[0] if nist_csf.is_csf_subcategory(number) else "—"
        )
        function = c.theme or (category.split(".")[0] if "." in category else "—")
        by_function.setdefault(function, {}).setdefault(category, []).append(c)

    def _score(subset: list) -> tuple:
        verdicts = [_csf_verdict(findings_map, c.id) for c in subset]
        applicable = [v for v in verdicts if v != "not_applicable"]
        passed = sum(1 for v in applicable if v in ("pass", "exception"))
        assessed = sum(
            1 for v in applicable if v not in ("not_assessed", "manual_review")
        )
        pct = round(passed / len(applicable) * 100, 1) if applicable else 0.0
        return pct, passed, len(applicable), assessed

    out: list = []
    for function in nist_csf.FUNCTION_ORDER:
        if function not in by_function:
            continue
        categories = by_function[function]
        ordered_categories = [
            (code, nist_csf.CATEGORY_ORDER[code][1], categories[code])
            for code in nist_csf.CATEGORY_ORDER
            if code in categories
        ]
        # Anything that is not a recognised Category still has to appear;
        # dropping rows out of an audit artefact is worse than an odd heading.
        ordered_categories += [
            (code, code, rows)
            for code, rows in categories.items()
            if code not in nist_csf.CATEGORY_ORDER
        ]
        flat = [c for _, _, rows in ordered_categories for c in rows]
        for _, _, rows in ordered_categories:
            rows.sort(key=lambda c: control_sort_key(c.control_number))
        out.append(
            (
                function,
                nist_csf.FUNCTION_NAMES.get(function, function),
                _score(flat),
                ordered_categories,
            )
        )

    for function, categories in by_function.items():
        if function in nist_csf.FUNCTION_ORDER:
            continue
        ordered_categories = [(code, code, rows) for code, rows in categories.items()]
        flat = [c for _, _, rows in ordered_categories for c in rows]
        out.append((function, function, _score(flat), ordered_categories))

    return out


@router.get("/reports/nist_csf")
@limiter.limit("10/minute")
def download_nist_csf_report(
    request: Request,
    fmt: str = "pdf",
    functions: str | None = Query(
        None, description="Comma-separated list of functions: GV,ID,PR,DE,RS,RC"
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.export_report")),
):
    """Generates and downloads the NIST CSF v2.0 Current Profile report."""
    fw_id = nist_csf.FRAMEWORK_ID
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    scope_label = None
    if functions:
        fn_list = [f.strip().upper() for f in functions.split(",") if f.strip()]
        unknown = [f for f in fn_list if f not in nist_csf.FUNCTION_ORDER]
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Unknown CSF Function(s): {', '.join(unknown)}. "
                    f"Valid values are {', '.join(nist_csf.FUNCTION_ORDER)}."
                ),
            )
        if fn_list:
            query = query.filter(ComplianceControl.theme.in_(fn_list))
            # Report the Functions in NIST's order regardless of how the caller
            # listed them, so "RC,GV" is not printed back as a scope of
            # "Recover, Govern".
            scope_label = ", ".join(
                f"{f} {nist_csf.FUNCTION_NAMES[f]}"
                for f in nist_csf.FUNCTION_ORDER
                if f in fn_list
            )

    # Ordered in Python, not SQL: `ORDER BY theme, control_number` is a string
    # sort and CSF's order is not alphabetical in either column.
    controls = sorted(query.all(), key=lambda c: control_sort_key(c.control_number))
    control_ids = [c.id for c in controls]

    # One rolled-up verdict per Subcategory (see RolledFinding). A separate,
    # unused `ComplianceFinding` query used to run here as well and its result
    # was discarded.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    org = getattr(user, "organization", None)
    meta = {
        "organization": getattr(org, "name", None) or user.org_id,
        "generated_at": datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC"),
        "scope": scope_label,
    }

    # Grouped here, in compliance's terms (CSF's published order);
    # the renderer lays out what it is given.
    grouped = _csf_group(controls, findings_map)

    if fmt.lower() == "docx" and Document is not None:
        buffer = _generate_nist_csf_docx(controls, findings_map, meta, grouped)
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"nist_csf_current_profile_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_nist_csf_pdf(controls, findings_map, meta, grouped)
        media = "application/pdf"
        filename = f"nist_csf_current_profile_{user.org_id[:4]}.pdf"

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
