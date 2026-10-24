"""
reporting/compliance/soa.py
─────────────────────────────────────────────────────────────────────────────
The Statement of Applicability, detailed and summary, as PDF and DOCX.

Moved unchanged from ``routers/compliance.py`` (G6, C8 of
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md): a renderer takes the
controls and their rolled-up verdicts the router read, and returns the
document; it reads no table and imports no compliance code.
"""

import io
from reporting.compliance.common import _verdict_of
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

try:
    import docx
    from docx import Document
except ImportError:
    docx = None
    Document = None


# ─────────────────────────────────────────────────────────────────────────────
# Statement of Applicability
#
# ISO/IEC 27001:2022 clause 6.1.3(d) requires the SoA to state, for every
# control: whether it is applicable, the justification for including it, whether
# it is implemented, and the justification for excluding it if it is not. The
# previous export carried none of the four — it was a five-column control status
# table (id, name, category, scan mode, verdict) labelled "SoA", which is not an
# artefact a certification body can accept. It also had no organisation name, no
# generation date and no approver.
# ─────────────────────────────────────────────────────────────────────────────

# How a rolled-up verdict maps onto the two columns an SoA actually asks for.
# `not_applicable` is the only status that makes a control excluded; everything
# else means the organisation has decided the control applies, and the question
# is then whether it is implemented yet.
_SOA_APPLICABILITY = {
    "not_applicable": ("No", "Excluded"),
    "pass": ("Yes", "Implemented"),
    "exception": ("Yes", "Implemented (compensating control)"),
    "fail": ("Yes", "Not implemented"),
    "pending_reverify": ("Yes", "Remediation in progress"),
    "remediation_applied": ("Yes", "Remediation applied, awaiting verification"),
    "manual_review": ("Yes", "Awaiting review"),
}


def _soa_row(control, rolled) -> dict:
    """Builds the SoA columns for one control."""
    verdict = getattr(rolled, "status", None) or "not_assessed"
    applicable, implementation = _SOA_APPLICABILITY.get(
        verdict, ("Yes", "Not assessed")
    )

    justification = getattr(rolled, "justification", None)
    if not justification:
        if verdict == "not_applicable":
            # An exclusion with no recorded reason is a finding in its own
            # right, and saying so in the document is more useful than leaving
            # the cell blank for the auditor to discover.
            justification = (
                "NOT RECORDED — an exclusion requires a documented justification."
            )
        else:
            # For an included control the standard's own requirement is a
            # reason for inclusion; the control's objective is that reason
            # unless the organisation has written a more specific one.
            justification = control.description or control.title

    return {
        "number": control.control_number or control.id,
        "title": control.title or "",
        "theme": control.theme or "",
        "applicable": applicable,
        "justification": justification,
        "implementation": implementation,
        "verdict": verdict.replace("_", " ").upper(),
        "owner": getattr(rolled, "owner", None) or "",
        "reviewed_at": (
            getattr(rolled, "reviewed_at", None).strftime("%d %b %Y")
            if getattr(rolled, "reviewed_at", None)
            else ""
        ),
    }


def _generate_soa_detailed_pdf(
    controls: list, findings_map: dict, meta: dict
) -> io.BytesIO:
    """Renders a certification-grade Statement of Applicability as PDF."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=14 * mm,
        title=f"Statement of Applicability — {meta['framework_name']}",
        author="CCure Audit PRO",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "SoATitle",
        parent=styles["Title"],
        fontSize=17,
        textColor=colors.HexColor("#003366"),
        spaceAfter=4,
    )
    meta_style = ParagraphStyle("SoAMeta", parent=styles["Normal"], fontSize=9)
    cell = ParagraphStyle("SoACell", parent=styles["Normal"], fontSize=7, leading=9)
    head = ParagraphStyle(
        "SoAHead",
        parent=styles["Normal"],
        fontSize=7,
        leading=9,
        textColor=colors.white,
    )

    rows = [_soa_row(c, findings_map.get(c.id)) for c in controls]
    counts: dict = {}
    for r in rows:
        counts[r["applicable"]] = counts.get(r["applicable"], 0) + 1
    implemented = sum(1 for r in rows if r["implementation"].startswith("Implemented"))

    story = [
        Paragraph("Statement of Applicability", title_style),
        Paragraph(
            f"{meta['framework_name']} ({meta['framework_version']})",
            styles["Heading3"],
        ),
        Spacer(1, 3 * mm),
        Paragraph(f"<b>Organization:</b> {meta['organization']}", meta_style),
        Paragraph(
            f"<b>Generated:</b> {meta['generated_at'].strftime('%d %b %Y %H:%M UTC')}"
            f" &nbsp;&nbsp; <b>By:</b> {meta['generated_by']}",
            meta_style,
        ),
        Paragraph(
            f"<b>Controls:</b> {len(rows)} total &nbsp;|&nbsp; "
            f"{counts.get('Yes', 0)} applicable &nbsp;|&nbsp; "
            f"{counts.get('No', 0)} excluded &nbsp;|&nbsp; "
            f"{implemented} implemented",
            meta_style,
        ),
        Paragraph(
            f"<b>Source scan run:</b> {meta.get('last_run_id') or 'None — no completed scan'}",
            meta_style,
        ),
        Spacer(1, 5 * mm),
    ]

    table_data = [
        [
            Paragraph("<b>Ref</b>", head),
            Paragraph("<b>Control</b>", head),
            Paragraph("<b>Applicable</b>", head),
            Paragraph("<b>Justification</b>", head),
            Paragraph("<b>Implementation status</b>", head),
            Paragraph("<b>Owner</b>", head),
            Paragraph("<b>Reviewed</b>", head),
        ]
    ]
    evidence_counts = meta.get("evidence_counts") or {}
    for control, r in zip(controls, rows):
        n_files = evidence_counts.get(control.id, 0)
        impl = r["implementation"]
        if n_files:
            impl = f"{impl}<br/><font size='6' color='#4A5568'>{n_files} evidence file(s)</font>"
        table_data.append(
            [
                Paragraph(r["number"], cell),
                Paragraph(r["title"], cell),
                Paragraph(r["applicable"], cell),
                Paragraph(r["justification"], cell),
                Paragraph(impl, cell),
                Paragraph(r["owner"], cell),
                Paragraph(r["reviewed_at"], cell),
            ]
        )

    tbl = Table(
        table_data,
        colWidths=[18 * mm, 62 * mm, 20 * mm, 92 * mm, 44 * mm, 190 / 5 * mm, 20 * mm],
        repeatRows=1,
    )
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#003366")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E0")),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#F7FAFC")],
                ),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story.append(tbl)

    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("<b>Approval</b>", styles["Heading3"]))
    story.append(
        Paragraph(
            "This Statement of Applicability was reviewed and approved by:",
            meta_style,
        )
    )
    story.append(Spacer(1, 4 * mm))
    approval = Table(
        [
            [
                Paragraph("Name", cell),
                Paragraph("Role", cell),
                Paragraph("Signature", cell),
                Paragraph("Date", cell),
            ],
            [
                Paragraph("", cell),
                Paragraph("", cell),
                Paragraph("", cell),
                Paragraph("", cell),
            ],
        ],
        colWidths=[65 * mm, 65 * mm, 75 * mm, 40 * mm],
        rowHeights=[7 * mm, 16 * mm],
    )
    approval.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E0")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(approval)

    doc.build(story)
    buffer.seek(0)
    return buffer


def _generate_soa_detailed_docx(
    controls: list, findings_map: dict, meta: dict
) -> io.BytesIO:
    """Renders a certification-grade Statement of Applicability as a Word document."""
    try:
        from docx import Document as _Document
        from docx.enum.section import WD_ORIENT
        from docx.oxml import parse_xml
        from docx.oxml.ns import nsdecls
        from docx.shared import Pt, RGBColor
    except ImportError:
        return io.BytesIO(b"python-docx is not installed.")

    doc = _Document()
    section = doc.sections[0]
    section.orientation = WD_ORIENT.LANDSCAPE
    section.page_width, section.page_height = section.page_height, section.page_width

    heading = doc.add_paragraph()
    run = heading.add_run("Statement of Applicability")
    run.font.size = Pt(18)
    run.font.bold = True
    run.font.color.rgb = RGBColor(0, 51, 102)

    sub = doc.add_paragraph()
    sub_run = sub.add_run(f"{meta['framework_name']} ({meta['framework_version']})")
    sub_run.font.size = Pt(11)
    sub_run.font.italic = True

    rows = [_soa_row(c, findings_map.get(c.id)) for c in controls]
    applicable = sum(1 for r in rows if r["applicable"] == "Yes")
    excluded = len(rows) - applicable
    implemented = sum(1 for r in rows if r["implementation"].startswith("Implemented"))

    for line in (
        f"Organization: {meta['organization']}",
        f"Generated: {meta['generated_at'].strftime('%d %b %Y %H:%M UTC')} by {meta['generated_by']}",
        f"Controls: {len(rows)} total | {applicable} applicable | {excluded} excluded | {implemented} implemented",
        f"Source scan run: {meta.get('last_run_id') or 'None — no completed scan'}",
    ):
        p = doc.add_paragraph()
        p.add_run(line).font.size = Pt(9)

    table = doc.add_table(rows=1, cols=7)
    table.style = "Table Grid"
    headers = [
        "Ref",
        "Control",
        "Applicable",
        "Justification",
        "Implementation status",
        "Owner",
        "Reviewed",
    ]
    for idx, name in enumerate(headers):
        cell = table.rows[0].cells[idx]
        cell.text = name
        cell._tc.get_or_add_tcPr().append(
            parse_xml(f'<w:shd {nsdecls("w")} w:fill="003366"/>')
        )
        for para in cell.paragraphs:
            for r in para.runs:
                r.font.bold = True
                r.font.size = Pt(8)
                r.font.color.rgb = RGBColor(255, 255, 255)

    for r in rows:
        cells = table.add_row().cells
        for idx, key in enumerate(
            (
                "number",
                "title",
                "applicable",
                "justification",
                "implementation",
                "owner",
                "reviewed_at",
            )
        ):
            cells[idx].text = str(r[key])
            for para in cells[idx].paragraphs:
                for run_ in para.runs:
                    run_.font.size = Pt(7)

    doc.add_paragraph()
    approval_heading = doc.add_paragraph()
    approval_heading.add_run("Approval").font.bold = True
    doc.add_paragraph("This Statement of Applicability was reviewed and approved by:")
    approval = doc.add_table(rows=2, cols=4)
    approval.style = "Table Grid"
    for idx, label in enumerate(("Name", "Role", "Signature", "Date")):
        approval.rows[0].cells[idx].text = label

    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer


def _generate_soa_docx(
    controls: list,
    findings_map: dict,
    title: str = "CCure Audit PRO — Statement of Applicability (SoA)",
    subtitle: str = "Controls Compliance Ledger Catalog",
) -> io.BytesIO:
    """Generates the Word Statement of Applicability document using python-docx."""
    try:
        from docx import Document
        from docx.oxml import parse_xml
        from docx.oxml.ns import nsdecls
        from docx.shared import Inches, Pt, RGBColor
    except ImportError:
        return io.BytesIO(b"python-docx is not installed.")

    doc = Document()
    p_title = doc.add_paragraph()
    run_t = p_title.add_run(title)
    run_t.font.size = Pt(18)
    run_t.font.bold = True
    run_t.font.color.rgb = RGBColor(15, 23, 42)

    p_sub = doc.add_paragraph()
    run_sub = p_sub.add_run(subtitle)
    run_sub.font.italic = True

    table = doc.add_table(rows=1, cols=5)
    table.style = "Table Grid"
    hdr_cells = table.rows[0].cells
    hdr_names = ["Control ID", "Name", "Category", "Scan Mode", "Verdict Status"]
    for i, name in enumerate(hdr_names):
        shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="0F172A"/>')
        hdr_cells[i]._tc.get_or_add_tcPr().append(shd)
        hdr_cells[i].text = name
        for p in hdr_cells[i].paragraphs:
            for run in p.runs:
                run.font.bold = True
                run.font.color.rgb = RGBColor(255, 255, 255)

    for c in controls:
        row_cells = table.add_row().cells
        row_cells[0].text = str(c.control_number or c.id)
        row_cells[1].text = str(c.title or "")
        row_cells[2].text = str(c.theme or "N/A")
        row_cells[3].text = str(c.scannability or "manual").upper()

        row_cells[4].text = _verdict_of(findings_map, c.id)

    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer


def _generate_soa_pdf(
    controls: list,
    findings_map: dict,
    title: str = "Statement of Applicability (SoA) Report",
    subtitle: str = "Security Controls Ledger",
) -> io.BytesIO:
    """Generates the Statement of Applicability document using ReportLab."""
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
        "TitleStyle",
        parent=styles["Title"],
        fontSize=18,
        textColor=colors.HexColor("#003366"),
    )
    cell_style = ParagraphStyle("CellStyle", parent=styles["Normal"], fontSize=8)

    story = [
        Paragraph(title, title_style),
        Paragraph(subtitle, styles["Normal"]),
        Spacer(1, 10 * mm),
    ]

    table_data = [
        [
            Paragraph("<b>Control ID</b>", cell_style),
            Paragraph("<b>Name</b>", cell_style),
            Paragraph("<b>Category</b>", cell_style),
            Paragraph("<b>Scan Mode</b>", cell_style),
            Paragraph("<b>Verdict</b>", cell_style),
        ]
    ]

    for c in controls:
        status_text = _verdict_of(findings_map, c.id)
        table_data.append(
            [
                Paragraph(c.control_number or c.id, cell_style),
                Paragraph(
                    c.title[:45] + "..." if len(c.title) > 45 else c.title, cell_style
                ),
                Paragraph(c.theme, cell_style),
                Paragraph(c.scannability, cell_style),
                Paragraph(
                    (
                        f"<font color='green'>{status_text}</font>"
                        if status_text == "PASS"
                        else f"<font color='red'>{status_text}</font>"
                    ),
                    cell_style,
                ),
            ]
        )

    tbl = Table(table_data, colWidths=[20 * mm, 75 * mm, 25 * mm, 30 * mm, 30 * mm])
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#003366")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(tbl)

    doc.build(story)
    buffer.seek(0)
    return buffer
