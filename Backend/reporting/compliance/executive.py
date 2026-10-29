"""
reporting/compliance/executive.py
─────────────────────────────────────────────────────────────────────────────
The executive compliance posture report, as PDF.

Moved unchanged from ``routers/compliance_reports.py`` (G2, which finished C8's
move of the compliance documents into renderers; see
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md): the route reads the
organisation's scores and approved exceptions and hands the figures here; this
reads no table and imports no compliance code.
"""

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _generate_executive_pdf(
    org_id, avg_score, avg_weighted, exceptions_count, generated_at
):
    """The PDF, as a buffer at its start: the headline scores and the count of
    approved exception waivers, dated *generated_at*."""
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
            f"Organization ID: {org_id} | Date: {generated_at.strftime('%d %b %Y')}",
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

    story.append(Paragraph("<b>2. Active Exception Waivers</b>", styles["Heading2"]))
    story.append(
        Paragraph(
            f"Currently, there are {exceptions_count} active exception waivers approved by the compliance officer.",
            styles["Normal"],
        )
    )

    doc.build(story)
    buffer.seek(0)
    return buffer
