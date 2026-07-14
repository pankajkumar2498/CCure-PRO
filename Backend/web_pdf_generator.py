"""
web_pdf_generator.py
════════════════════════════════════════════════════════════════════════════
Generates a professional Web Application Security PDF report for DAST scans.

Reuses the ReportLab design system from pdf_generator.py (same brand palette,
headers, footers, table styles) but structures content for web scan results:
  - Executive Summary with severity gauge
  - OWASP Top 10 compliance scorecard
  - Endpoint inventory table
  - Findings grouped by severity with HTTP evidence
  - TLS/SSL audit section
  - WAF detection and tech stack notes

Usage:
    from web_pdf_generator import WebScanReportGenerator

    gen   = WebScanReportGenerator(output_dir="reports")
    path  = gen.generate(web_scan_dict)
    # path = "reports/web_scan_example_com_2026-05-24_14-30-05.pdf"
"""

import os
from datetime import datetime
from typing import List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    PageBreak,
    KeepTogether,
)
from scan_helpers import make_pdf_cve_paragraph

# ── Reuse brand palette from pdf_generator ────────────────────────────────────

CDAC_BLUE = colors.HexColor("#003366")
CDAC_LIGHT_BLUE = colors.HexColor("#0066CC")
CDAC_ACCENT = colors.HexColor("#E8F0F7")
HEADER_BG = colors.HexColor("#003366")
TABLE_HEADER_BG = colors.HexColor("#0066CC")
BORDER_COLOUR = colors.HexColor("#CBD5E0")
WHITE = colors.white
LIGHT_GREY = colors.HexColor("#F7F9FC")

# Severity colors
SEV_COLORS = {
    "critical": colors.HexColor("#DC2626"),
    "high": colors.HexColor("#EA580C"),
    "medium": colors.HexColor("#CA8A04"),
    "low": colors.HexColor("#2563EB"),
    "info": colors.HexColor("#6B7280"),
}

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
W = PAGE_W - 2 * MARGIN


# ── Styles ────────────────────────────────────────────────────────────────────


def _build_styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "WebTitle",
            parent=base["Title"],
            fontSize=20,
            textColor=CDAC_BLUE,
            spaceAfter=4,
            spaceBefore=0,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        ),
        "subtitle": ParagraphStyle(
            "WebSubtitle",
            parent=base["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#555555"),
            spaceAfter=2,
            alignment=TA_CENTER,
            fontName="Helvetica",
        ),
        "section": ParagraphStyle(
            "WebSection",
            parent=base["Heading2"],
            fontSize=12,
            textColor=WHITE,
            backColor=CDAC_BLUE,
            spaceBefore=10,
            spaceAfter=6,
            leftIndent=6,
            fontName="Helvetica-Bold",
        ),
        "subsection": ParagraphStyle(
            "WebSubSection",
            parent=base["Heading3"],
            fontSize=10,
            textColor=CDAC_BLUE,
            spaceBefore=6,
            spaceAfter=4,
            fontName="Helvetica-Bold",
        ),
        "label": ParagraphStyle(
            "WebLabel",
            parent=base["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#333333"),
            fontName="Helvetica-Bold",
        ),
        "value": ParagraphStyle(
            "WebValue",
            parent=base["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#222222"),
            fontName="Helvetica",
        ),
        "mono": ParagraphStyle(
            "WebMono",
            parent=base["Normal"],
            fontSize=7,
            fontName="Courier",
            textColor=colors.HexColor("#1A1A2E"),
            spaceAfter=1,
            leading=10,
        ),
        "small": ParagraphStyle(
            "WebSmall",
            parent=base["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#777777"),
            fontName="Helvetica",
        ),
        "normal": base["Normal"],
    }


# ── Header / Footer ──────────────────────────────────────────────────────────


def _draw_web_header_footer(canvas, doc):
    """Page decorator for web scan reports."""
    canvas.saveState()

    report_ts = getattr(
        doc, "scan_timestamp", datetime.now().strftime("%d %b %Y  %H:%M:%S")
    )
    target = getattr(doc, "target_domain", "")

    # Header
    canvas.setFillColor(HEADER_BG)
    canvas.rect(0, PAGE_H - 22 * mm, PAGE_W, 22 * mm, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 14)
    canvas.drawString(MARGIN, PAGE_H - 13 * mm, "CCure-Audit PRO — Web Security Report")
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#AACCEE"))
    canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 10 * mm, f"Target: {target}")
    canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 16 * mm, f"Generated: {report_ts}")

    canvas.setStrokeColor(CDAC_LIGHT_BLUE)
    canvas.setLineWidth(1.5)
    canvas.line(0, PAGE_H - 22 * mm, PAGE_W, PAGE_H - 22 * mm)

    # Footer
    canvas.setFillColor(HEADER_BG)
    canvas.rect(0, 0, PAGE_W, 12 * mm, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(MARGIN, 4.5 * mm, "CONFIDENTIAL — Authorized Personnel Only")
    canvas.drawRightString(PAGE_W - MARGIN, 4.5 * mm, f"Page {doc.page}")

    canvas.restoreState()


# ── Table Helpers ─────────────────────────────────────────────────────────────


def _kv_table(rows, styles, col_widths=None):
    """Key-value pair table."""
    if col_widths is None:
        col_widths = [65 * mm, W - 65 * mm]

    table_data = []
    for label, value in rows:
        val_p = (
            value
            if isinstance(value, Paragraph)
            else Paragraph(str(value or "N/A"), styles["value"])
        )
        table_data.append([Paragraph(label, styles["label"]), val_p])

    tbl = Table(table_data, colWidths=col_widths, repeatRows=0)
    tbl.setStyle(
        TableStyle(
            [
                *[
                    (
                        "BACKGROUND",
                        (0, i),
                        (-1, i),
                        CDAC_ACCENT if i % 2 == 0 else WHITE,
                    )
                    for i in range(len(table_data))
                ],
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER_COLOUR),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    return tbl


def _data_table(headers, rows, styles, widths=None):
    """Generic data table with header row."""
    header_row = [
        Paragraph(
            h,
            ParagraphStyle(
                "TH",
                fontName="Helvetica-Bold",
                fontSize=8,
                textColor=WHITE,
                alignment=TA_CENTER,
            ),
        )
        for h in headers
    ]
    data = [header_row]
    for r in rows:
        data.append(
            [
                (
                    Paragraph(str(c), styles["value"])
                    if not isinstance(c, Paragraph)
                    else c
                )
                for c in r
            ]
        )

    if not widths:
        widths = [W / len(headers)] * len(headers)

    tbl = Table(data, colWidths=widths, repeatRows=1)
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), TABLE_HEADER_BG),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER_COLOUR),
                *[
                    (
                        "BACKGROUND",
                        (0, i),
                        (-1, i),
                        CDAC_ACCENT if i % 2 == 0 else WHITE,
                    )
                    for i in range(1, len(data))
                ],
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return tbl


def _severity_paragraph(severity, styles):
    """Color-coded severity label."""
    sev = (severity or "info").lower()
    color = SEV_COLORS.get(sev, SEV_COLORS["info"])
    return Paragraph(
        f'<font color="{color.hexval()}">{sev.upper()}</font>',
        ParagraphStyle("Sev", parent=styles["value"], fontName="Helvetica-Bold"),
    )


def _section(title, styles):
    return Paragraph(f"&nbsp; {title}", styles["section"])


# ── Story Builder ─────────────────────────────────────────────────────────────


def _build_web_scan_story(
    scan: dict, findings: list, assets: list, styles: dict
) -> list:
    """Build the full PDF story for a web scan report."""
    story = []

    target_url = scan.get("target_url", "N/A")
    target_domain = scan.get("target_domain", "N/A")

    # ── Title Page ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("Web Application Security Report", styles["title"]))
    story.append(Paragraph(f"DAST Assessment — {target_domain}", styles["subtitle"]))
    story.append(Spacer(1, 3 * mm))
    story.append(
        HRFlowable(width=W, thickness=1.5, color=CDAC_LIGHT_BLUE, spaceAfter=6)
    )

    # ── 1. Scan Information ───────────────────────────────────────────────────
    story.append(_section("Scan Information", styles))

    duration = scan.get("duration_seconds")
    duration_str = f"{duration:.1f} seconds" if duration else "N/A"

    scan_info = [
        ("Scan ID", scan.get("id", "N/A")),
        ("Scan Name", scan.get("scan_name", "N/A")),
        ("Target URL", target_url),
        ("Target Domain", target_domain),
        ("Status", (scan.get("status", "N/A")).upper()),
        ("WAF Detected", scan.get("waf_detected") or "None"),
        ("Tech Stack", ", ".join(scan.get("tech_stack", [])) or "N/A"),
        ("Duration", duration_str),
        ("Started At", scan.get("started_at", "N/A")),
        ("Completed At", scan.get("completed_at", "N/A")),
        ("Report Generated", datetime.now().strftime("%d %b %Y  %H:%M:%S")),
    ]
    story.append(_kv_table(scan_info, styles))
    story.append(Spacer(1, 4 * mm))

    # ── 2. Executive Summary ──────────────────────────────────────────────────
    story.append(_section("Executive Summary", styles))

    total_findings = len(findings)
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity", "info") or "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    verified = sum(1 for f in findings if f.get("is_verified"))

    summary_rows = [
        ("Total Findings", str(total_findings)),
        ("Critical", str(sev_counts["critical"])),
        ("High", str(sev_counts["high"])),
        ("Medium", str(sev_counts["medium"])),
        ("Low", str(sev_counts["low"])),
        ("Informational", str(sev_counts["info"])),
        ("Verified (Multi-Tool)", str(verified)),
        ("Endpoints Discovered", str(len(assets))),
    ]
    story.append(_kv_table(summary_rows, styles))
    story.append(Spacer(1, 4 * mm))

    # Risk assessment
    if sev_counts["critical"] > 0:
        risk_level = "CRITICAL"
        risk_color = "#DC2626"
    elif sev_counts["high"] > 0:
        risk_level = "HIGH"
        risk_color = "#EA580C"
    elif sev_counts["medium"] > 0:
        risk_level = "MEDIUM"
        risk_color = "#CA8A04"
    else:
        risk_level = "LOW"
        risk_color = "#22C55E"

    story.append(
        Paragraph(
            f'Overall Risk: <font color="{risk_color}"><b>{risk_level}</b></font>',
            ParagraphStyle(
                "RiskLabel", parent=styles["value"], fontSize=11, alignment=TA_CENTER
            ),
        )
    )
    story.append(Spacer(1, 6 * mm))

    # ── 3. OWASP Top 10 Scorecard ─────────────────────────────────────────────
    owasp_findings = {}
    for f in findings:
        owasp = f.get("owasp_category", "")
        if owasp:
            code = owasp.split(":")[0] if ":" in owasp else ""
            if code:
                owasp_findings.setdefault(code, []).append(f)

    if owasp_findings:
        story.append(_section("OWASP Top 10 Coverage", styles))
        owasp_categories = {
            "A01": "Broken Access Control",
            "A02": "Cryptographic Failures",
            "A03": "Injection",
            "A04": "Insecure Design",
            "A05": "Security Misconfiguration",
            "A06": "Vulnerable Components",
            "A07": "Auth Failures",
            "A08": "Data Integrity Failures",
            "A09": "Logging Failures",
            "A10": "SSRF",
        }
        owasp_rows = []
        for code, name in owasp_categories.items():
            matched = owasp_findings.get(code, [])
            count = len(matched)
            max_sev = "info"
            for m in matched:
                s = (m.get("severity") or "info").lower()
                if _sev_rank(s) > _sev_rank(max_sev):
                    max_sev = s
            status = f"{count} finding(s)" if count else "No findings"
            owasp_rows.append([code, name, status, max_sev.upper() if count else "—"])

        story.append(
            _data_table(
                ["Code", "Category", "Findings", "Max Severity"],
                owasp_rows,
                styles,
                widths=[18 * mm, 55 * mm, 40 * mm, W - 113 * mm],
            )
        )
        story.append(Spacer(1, 4 * mm))

    # ── 4. Findings Detail ────────────────────────────────────────────────────
    if findings:
        story.append(PageBreak())
        story.append(_section(f"Vulnerability Findings ({total_findings})", styles))

        # Sort: critical → high → medium → low → info
        sorted_findings = sorted(
            findings, key=lambda f: -_sev_rank(f.get("severity", "info"))
        )

        for idx, f in enumerate(sorted_findings, 1):
            sev = (f.get("severity", "info") or "info").lower()

            finding_block = []
            finding_block.append(
                Paragraph(
                    f"<b>{idx}. {f.get('title', 'Unknown Finding')}</b>",
                    styles["subsection"],
                )
            )

            detail_rows = [
                ("Severity", sev.upper()),
                ("Type", f.get("finding_type", "N/A")),
                ("Detected By", f.get("detected_by", "N/A")),
                ("Matched At", f.get("matched_at", "N/A")),
                ("CVSS Score", str(f.get("cvss_score") or "N/A")),
            ]

            if f.get("owasp_category"):
                detail_rows.append(("OWASP", f["owasp_category"]))
            if f.get("cve_id"):
                detail_rows.append(
                    ("CVE", make_pdf_cve_paragraph(f["cve_id"], styles["value"]))
                )
            if f.get("compliance_tags"):
                tags = f["compliance_tags"]
                if isinstance(tags, list):
                    detail_rows.append(("Compliance", ", ".join(tags[:5])))
            if f.get("is_verified"):
                detail_rows.append(("Verified", "✓ Confirmed by multiple tools"))

            finding_block.append(
                _kv_table(detail_rows, styles, col_widths=[40 * mm, W - 40 * mm])
            )

            # Description
            desc = f.get("description", "")
            if desc:
                finding_block.append(Spacer(1, 2 * mm))
                finding_block.append(
                    Paragraph(
                        f"<i>{desc[:500]}</i>",
                        styles["small"],
                    )
                )

            # HTTP Evidence (condensed)
            if f.get("payload_used"):
                finding_block.append(Spacer(1, 2 * mm))
                finding_block.append(
                    Paragraph(
                        f"<b>Payload:</b> <font face='Courier' size='7'>{_escape(f['payload_used'][:200])}</font>",
                        styles["small"],
                    )
                )

            finding_block.append(Spacer(1, 4 * mm))
            story.append(KeepTogether(finding_block))

    # ── 5. Endpoint Inventory ─────────────────────────────────────────────────
    if assets:
        story.append(PageBreak())
        story.append(_section(f"Discovered Endpoints ({len(assets)})", styles))

        ep_rows = []
        for a in assets[:100]:
            method = a.get("method", "GET")
            url = a.get("url", "N/A")
            code = str(a.get("response_code") or "—")
            source = a.get("source", "crawler")
            flags = []
            if a.get("auth_required"):
                flags.append("🔒")
            if a.get("is_api"):
                flags.append("API")
            if a.get("is_form"):
                flags.append("Form")
            if a.get("has_file_upload"):
                flags.append("Upload")

            ep_rows.append(
                [
                    method,
                    url[:60],
                    code,
                    source,
                    " ".join(flags) if flags else "—",
                ]
            )

        story.append(
            _data_table(
                ["Method", "URL", "Status", "Source", "Flags"],
                ep_rows,
                styles,
                widths=[15 * mm, 75 * mm, 15 * mm, 25 * mm, W - 130 * mm],
            )
        )

        if len(assets) > 100:
            story.append(
                Paragraph(
                    f"... and {len(assets) - 100} more endpoints (see full data in API)",
                    styles["small"],
                )
            )

    # ── 6. Subdomains ─────────────────────────────────────────────────────────
    subdomains = scan.get("subdomains", [])
    if subdomains:
        story.append(Spacer(1, 6 * mm))
        story.append(_section(f"Subdomains ({len(subdomains)})", styles))
        sub_rows = [[s] for s in subdomains[:50]]
        story.append(_data_table(["Subdomain"], sub_rows, styles, widths=[W]))

    return story


def _sev_rank(sev: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(
        (sev or "info").lower(), 0
    )


def _escape(text: str) -> str:
    """Escape HTML entities for ReportLab paragraphs."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ── Generator Class ───────────────────────────────────────────────────────────


class WebScanReportGenerator:
    """
    Generates a branded PDF report for web application scans.

    Usage:
        gen  = WebScanReportGenerator(output_dir="reports")
        path = gen.generate(scan_dict, findings_list, assets_list)
    """

    def __init__(self, output_dir: Optional[str] = None):
        if output_dir is None or output_dir == "reports":
            backend_dir = os.path.dirname(os.path.abspath(__file__))
            output_dir = os.path.join(backend_dir, "reports")
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.styles = _build_styles()

    def generate(
        self,
        scan: dict,
        findings: List[dict],
        assets: List[dict],
    ) -> str:
        """
        Generate a Web Security PDF report.

        Args:
            scan:     WebScan record as dict (from API or DB query).
            findings: List of WebFinding dicts.
            assets:   List of WebAsset dicts.

        Returns:
            Absolute path to the generated PDF file.
        """
        domain = scan.get("target_domain", "unknown")
        safe_domain = domain.replace(".", "_").replace(":", "_")[:40]
        now = datetime.now()
        filename = f"web_scan_{safe_domain}_{now.strftime('%d-%m-%Y_%H-%M-%S')}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            leftMargin=MARGIN,
            rightMargin=MARGIN,
            topMargin=28 * mm,
            bottomMargin=18 * mm,
            title=f"Web Security Report — {domain}",
            author="CCure-Audit PRO",
            subject=f"DAST Assessment: {domain}",
        )

        doc.target_domain = domain
        started = scan.get("started_at", "")
        try:
            dt = datetime.fromisoformat(str(started))
            doc.scan_timestamp = dt.strftime("%d %b %Y  %H:%M:%S")
        except Exception:
            doc.scan_timestamp = now.strftime("%d %b %Y  %H:%M:%S")

        story = _build_web_scan_story(scan, findings, assets, self.styles)
        doc.build(
            story,
            onFirstPage=_draw_web_header_footer,
            onLaterPages=_draw_web_header_footer,
        )

        return filepath
