"""
pdf_generator.py
================
Generates two professional PDF reports after every Host Discovery scan:

  1. JSON PDF  - scan data rendered as formatted tables  (key-value + host rows)
  2. XML PDF   - scan data as syntax-highlighted, indented XML

Header : CDAC Automation Tool
Footer : Copyright@CDAC RTSG Bangalore

File naming convention:
    {scan_type}_{YYYY-MM-DD}_{HH-MM-SS}_JSON.pdf
    {scan_type}_{YYYY-MM-DD}_{HH-MM-SS}_XML.pdf

Usage:
    from pdf_generator import ScanReportGenerator

    gen    = ScanReportGenerator(output_dir="reports")
    paths  = gen.generate(scan_result_dict, scan_type="scan_host")
    # paths = {"json_pdf": "...", "xml_pdf": "..."}
"""

import os
import json
import xml.dom.minidom
from datetime import datetime
from typing import Dict, List, Optional, Any

from reportlab.lib                       import colors
from reportlab.lib.pagesizes             import A4
from reportlab.lib.units                 import mm
from reportlab.lib.styles                import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums                 import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus                  import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.platypus.flowables        import Flowable


# -----------------------------------------------------------------------------
# Brand colours
# -----------------------------------------------------------------------------

CDAC_BLUE        = colors.HexColor("#003366")   # deep navy
CDAC_LIGHT_BLUE  = colors.HexColor("#0066CC")   # accent
CDAC_ACCENT      = colors.HexColor("#E8F0F7")   # table row alt background
ACTIVE_GREEN     = colors.HexColor("#1A7A3F")
INACTIVE_RED     = colors.HexColor("#C0392B")
HEADER_BG        = colors.HexColor("#003366")
TABLE_HEADER_BG  = colors.HexColor("#0066CC")
BORDER_COLOUR    = colors.HexColor("#CBD5E0")
WHITE            = colors.white
LIGHT_GREY       = colors.HexColor("#F7F9FC")


# -----------------------------------------------------------------------------
# Styles
# -----------------------------------------------------------------------------

def _build_styles():
    base = getSampleStyleSheet()

    styles = {
        "title": ParagraphStyle(
            "ReportTitle",
            parent        = base["Title"],
            fontSize      = 20,
            textColor     = CDAC_BLUE,
            spaceAfter    = 4,
            spaceBefore   = 0,
            alignment     = TA_CENTER,
            fontName      = "Helvetica-Bold",
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle",
            parent        = base["Normal"],
            fontSize      = 10,
            textColor     = colors.HexColor("#555555"),
            spaceAfter    = 2,
            alignment     = TA_CENTER,
            fontName      = "Helvetica",
        ),
        "section": ParagraphStyle(
            "SectionHeader",
            parent        = base["Heading2"],
            fontSize      = 12,
            textColor     = WHITE,
            backColor     = CDAC_BLUE,
            spaceBefore   = 10,
            spaceAfter    = 6,
            leftIndent    = 6,
            fontName      = "Helvetica-Bold",
        ),
        "label": ParagraphStyle(
            "CellLabel",
            parent        = base["Normal"],
            fontSize      = 9,
            textColor     = colors.HexColor("#333333"),
            fontName      = "Helvetica-Bold",
        ),
        "value": ParagraphStyle(
            "CellValue",
            parent        = base["Normal"],
            fontSize      = 9,
            textColor     = colors.HexColor("#222222"),
            fontName      = "Helvetica",
        ),
        "active": ParagraphStyle(
            "ActiveStatus",
            parent        = base["Normal"],
            fontSize      = 9,
            textColor     = ACTIVE_GREEN,
            fontName      = "Helvetica-Bold",
        ),
        "inactive": ParagraphStyle(
            "InactiveStatus",
            parent        = base["Normal"],
            fontSize      = 9,
            textColor     = INACTIVE_RED,
            fontName      = "Helvetica-Bold",
        ),
        "mono": ParagraphStyle(
            "MonoText",
            parent        = base["Normal"],
            fontSize      = 8,
            fontName      = "Courier",
            textColor     = colors.HexColor("#1A1A2E"),
            spaceAfter    = 2,
            leading       = 12,
        ),
        "xml_tag": ParagraphStyle(
            "XmlTag",
            parent        = base["Normal"],
            fontSize      = 8,
            fontName      = "Courier-Bold",
            textColor     = CDAC_BLUE,
            leading       = 12,
        ),
        "normal": base["Normal"],
        "small": ParagraphStyle(
            "SmallNote",
            parent        = base["Normal"],
            fontSize      = 8,
            textColor     = colors.HexColor("#777777"),
            fontName      = "Helvetica",
        ),
    }
    return styles


# -----------------------------------------------------------------------------
# Header / Footer canvas callback
# -----------------------------------------------------------------------------

PAGE_W, PAGE_H = A4
MARGIN         = 18 * mm


def _draw_header_footer(canvas, doc):
    """Called by ReportLab on every page to paint header and footer."""
    canvas.saveState()

    # -- Header bar ----------------------------------------------------------
    canvas.setFillColor(HEADER_BG)
    canvas.rect(0, PAGE_H - 22 * mm, PAGE_W, 22 * mm, fill=1, stroke=0)

    # Logo / title text inside header
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 14)
    canvas.drawString(MARGIN, PAGE_H - 13 * mm, "CDAC Automation Tool")

    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#AACCEE"))
    canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 10 * mm, "Host Discovery Report")
    canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 16 * mm,
                           f"Generated: {datetime.now().strftime('%d %b %Y  %H:%M:%S')}")

    # Thin accent line below header
    canvas.setStrokeColor(CDAC_LIGHT_BLUE)
    canvas.setLineWidth(1.5)
    canvas.line(0, PAGE_H - 22 * mm, PAGE_W, PAGE_H - 22 * mm)

    # -- Footer bar ----------------------------------------------------------
    canvas.setFillColor(HEADER_BG)
    canvas.rect(0, 0, PAGE_W, 12 * mm, fill=1, stroke=0)

    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(MARGIN, 4.5 * mm, "Copyright@CDAC Bangalore RTSG")

    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(PAGE_W - MARGIN, 4.5 * mm,
                           f"Page {doc.page}")

    canvas.restoreState()


# -----------------------------------------------------------------------------
# JSON -> PDF helpers
# -----------------------------------------------------------------------------

def _kv_table(rows: List[tuple], styles: dict, col_widths=None) -> Table:
    """
    Build a neat two-column key / value table.
    rows : list of (label_str, value_str)
    """
    if col_widths is None:
        col_widths = [65 * mm, 105 * mm]

    table_data = []
    for label, value in rows:
        val_comp = value if isinstance(value, Paragraph) else Paragraph(str(value), styles["value"])
        table_data.append([Paragraph(label, styles["label"]), val_comp])

    tbl = Table(table_data, colWidths=col_widths, repeatRows=0)
    tbl.setStyle(TableStyle([
        # Alternating row backgrounds
        *[("BACKGROUND", (0, i), (-1, i), CDAC_ACCENT if i % 2 == 0 else WHITE)
          for i in range(len(table_data))],
        ("GRID",        (0, 0), (-1, -1), 0.4, BORDER_COLOUR),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return tbl


def _host_table(hosts: List[dict], styles: dict) -> Table:
    """
    Build the hosts summary table with one row per host.
    Columns: #, IP Address, Hostname, MAC Address, Status
    """
    headers = ["#", "IP Address", "Hostname", "MAC Address", "Status"]
    col_w   = [10*mm, 32*mm, 48*mm, 38*mm, 18*mm]

    header_row = [Paragraph(h, ParagraphStyle(
        "TH", fontName="Helvetica-Bold", fontSize=9,
        textColor=WHITE, alignment=TA_CENTER)) for h in headers]

    rows = [header_row]
    for idx, host in enumerate(hosts, start=1):
        is_active = host.get("is_active", False)
        status_p  = Paragraph(
            host.get("status", "Unknown"),
            styles["active"] if is_active else styles["inactive"]
        )
        rows.append([
            Paragraph(str(idx),                          styles["value"]),
            Paragraph(host.get("ip_address", "N/A"),     styles["value"]),
            Paragraph(host.get("hostname",   "Unknown"), styles["value"]),
            Paragraph(host.get("mac_address","N/A"),     styles["value"]),
            status_p,
        ])

    tbl = Table(rows, colWidths=col_w, repeatRows=1)
    tbl.setStyle(TableStyle([
        # Header row
        ("BACKGROUND",   (0, 0), (-1, 0),  TABLE_HEADER_BG),
        ("ALIGN",        (0, 0), (-1, 0),  "CENTER"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        # Alternating body rows
        *[("BACKGROUND", (0, i), (-1, i), CDAC_ACCENT if i % 2 == 0 else WHITE)
          for i in range(1, len(rows))],
        ("GRID",         (0, 0), (-1, -1), 0.4, BORDER_COLOUR),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [CDAC_ACCENT, WHITE]),
    ]))
    return tbl


def _section_header(title: str, styles: dict) -> Paragraph:
    return Paragraph(f"&nbsp; {title}", styles["section"])


def _build_json_story(result: dict, scan_type: str,
                      timestamp: str, styles: dict) -> list:
    """
    Build the ReportLab story (list of flowables) for the JSON PDF.
    """
    story = []
    W     = PAGE_W - 2 * MARGIN

    # -- Cover / Title --------------------------------------------------------
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("Host Discovery Scan Report", styles["title"]))
    story.append(Paragraph("Network Visibility &amp; Audit Summary", styles["subtitle"]))
    story.append(Spacer(1, 3 * mm))
    story.append(HRFlowable(width=W, thickness=1.5,
                             color=CDAC_LIGHT_BLUE, spaceAfter=6))

    # -- Scan Meta ------------------------------------------------------------
    story.append(_section_header("Scan Information", styles))
    meta    = result.get("metadata", {})
    summary = result.get("summary",  {})

    scan_info_rows = [
        ("Scan Type",         scan_type.replace("_", " ").title()),
        ("Target",            meta.get("target", summary.get("target", "N/A"))),
        ("Scan Strategy",     summary.get("scan_type", "N/A")),
        ("Scan Date",         timestamp[:10]),
        ("Scan Time",         timestamp[11:19]),
        ("Scan Duration",     f"{summary.get('scan_duration', 0):.3f} seconds"),
        ("Report Generated",  datetime.now().strftime("%d %b %Y  %H:%M:%S")),
        # ("Report Format",     "JSON - Tabular"),
    ]
    story.append(_kv_table(scan_info_rows, styles))
    story.append(Spacer(1, 4 * mm))

    # -- Discovery Summary ----------------------------------------------------
    story.append(_section_header("Discovery Summary", styles))
    total    = summary.get("total_hosts",    0)
    active   = summary.get("active_hosts",   0)
    inactive = summary.get("inactive_hosts", 0)
    pct      = f"{(active / total * 100):.1f}%" if total else "0%"

    summary_rows = [
        ("Total Hosts Scanned",   total),
        ("Active Hosts",          active),
        ("Inactive / No Response",inactive),
        ("Active Host Ratio",     pct),
    ]
    story.append(_kv_table(summary_rows, styles))
    story.append(Spacer(1, 4 * mm))

    # -- Host Discovery Results -----------------------------------------------
    # Collect hosts from various response shapes
    hosts: List[dict] = []
    data = result.get("data", [])

    if isinstance(data, dict):
        # scan_single_host -> data is one host dict
        hosts = [data]
    elif isinstance(data, list):
        # scan_ip_range / scan_subnet -> data is list of host dicts
        # scan_subnets_of_subnet -> data is list of subnet dicts, each with "hosts"
        for item in data:
            if isinstance(item, dict):
                if "hosts" in item:
                    hosts.extend(item["hosts"])
                elif "ip_address" in item:
                    hosts.append(item)

    # For range/subnet scans, show all hosts but with empty fields for inactive ones
    # For single host, always show the host

    if hosts:
        story.append(_section_header(
            f"Discovered Hosts  ({len(hosts)} total)", styles))
        story.append(_host_table(hosts, styles))
        story.append(Spacer(1, 4 * mm))

        # -- Per-host Detail Cards --------------------------------------------
        story.append(_section_header("Individual Host Details", styles))
        for idx, host in enumerate(hosts, start=1):
            is_active = host.get("is_active", False)
            if not is_active:
                continue  # Skip inactive hosts in detailed cards
            
            card_colour = colors.HexColor("#EAF7EE") if is_active \
                     else colors.HexColor("#FDF2F2")

            # Build port display
            open_ports = host.get("open_ports", [])
            port_strings = []
            if open_ports:
                for p in open_ports:
                    port_num = p.get("port", 0)
                    banner = p.get("banner", "")
                    banner_str = f" [{banner[:30]}..]" if len(banner) > 30 else f" [{banner}]" if banner else ""
                    port_strings.append(f"{port_num}/{p.get('service', 'unknown').upper()}{banner_str}")
            
            ports_display = ", ".join(port_strings) if port_strings else "None"

            detail_rows = [
                ("IP Address",        host.get("ip_address",    "N/A")),
                ("Hostname",          host.get("hostname",      "Unknown")),
                ("MAC Address",       host.get("mac_address",   "N/A")),
                ("OS Fingerprint",    host.get("os_guess",      "Unknown")),
                ("Detection Method",  host.get("scan_method",   "N/A")),
                ("Open TCP Ports",    ports_display if is_active else "N/A"),
                ("Status",            host.get("status",        "Unknown")),
                ("Response Time",     f"{host.get('response_time_ms') or 0:.2f} ms"),
                ("Scan Timestamp",    host.get("scan_timestamp", "N/A")),
            ]

            card_title = Paragraph(
                f"Host {idx}  -  {host.get('ip_address', 'N/A')}",
                ParagraphStyle("CardTitle", fontName="Helvetica-Bold",
                               fontSize=10, textColor=CDAC_BLUE,
                               spaceBefore=4, spaceAfter=2))

            card_tbl = _kv_table(detail_rows, styles)

            # Wrap in a coloured background via a 1-cell outer table
            outer = Table([[card_tbl]], colWidths=[W])
            outer.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, -1), card_colour),
                ("BOX",          (0, 0), (-1, -1), 0.8, CDAC_BLUE),
                ("TOPPADDING",   (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
                ("LEFTPADDING",  (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))

            story.append(KeepTogether([card_title, outer, Spacer(1, 3 * mm)]))

    # -- Subnets breakdown (scan_subnets only) --------------------------------
    if isinstance(data, list) and data and "subnet" in data[0]:
        story.append(_section_header("Per-Subnet Breakdown", styles))
        for subnet_info in data:
            if "error" in subnet_info:
                story.append(Paragraph(
                    f"<b>{subnet_info['subnet']}</b> - Error: {subnet_info['error']}",
                    styles["value"]))
                story.append(Spacer(1, 2 * mm))
                continue
            sub_rows = [
                ("Subnet",           subnet_info.get("subnet", "N/A")),
                ("Hosts Found",      subnet_info.get("total_found",    0)),
                ("Active",           subnet_info.get("active_hosts",   0)),
                ("Inactive",         subnet_info.get("inactive_hosts", 0)),
            ]
            story.append(_kv_table(sub_rows, styles,
                                   col_widths=[55*mm, 115*mm]))
            story.append(Spacer(1, 2 * mm))

    # -- Additional Metadata --------------------------------------------------
    if meta:
        story.append(_section_header("Scan Metadata", styles))
        meta_rows = [(k.replace("_", " ").title(), str(v))
                     for k, v in meta.items()]
        story.append(_kv_table(meta_rows, styles))

    return story


# -----------------------------------------------------------------------------
# dict -> XML helpers
# -----------------------------------------------------------------------------

def _dict_to_xml(data: Any, parent, doc) -> None:
    """Recursively convert a Python dict / list into XML DOM nodes."""
    if isinstance(data, dict):
        for key in data:
            safe_key = str(key).replace(" ", "_")
            child = doc.createElement(safe_key)
            parent.appendChild(child)
            _dict_to_xml(data[key], child, doc)
    elif isinstance(data, list):
        for item in data:
            child = doc.createElement("item")
            parent.appendChild(child)
            _dict_to_xml(item, child, doc)
    elif data is None:
        parent.appendChild(doc.createTextNode("N/A"))
    else:
        parent.appendChild(doc.createTextNode(str(data)))


def _result_to_pretty_xml(result: dict, scan_type: str) -> str:
    """Convert scan result dict to a pretty-printed XML string."""
    doc  = xml.dom.minidom.getDOMImplementation().createDocument(None, "ScanReport", None)
    root = doc.documentElement
    root.setAttribute("xmlns:cdac",  "http://cdac.rtsg.in/discovery/v1")
    root.setAttribute("scan_type",   scan_type)
    root.setAttribute("generated",   datetime.now().isoformat())
    root.setAttribute("tool",        "CDAC Automation Tool")
    root.setAttribute("department",  "CDAC Bangalore RTSG")

    _dict_to_xml(result, root, doc)
    return doc.toprettyxml(indent="  ", encoding=None)


def _xml_to_story(xml_str: str, scan_type: str,
                  timestamp: str, styles: dict) -> list:
    """Build the ReportLab story for the XML PDF."""
    story = []
    W     = PAGE_W - 2 * MARGIN

    # Title
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("Host Discovery Scan Report", styles["title"]))
    story.append(Paragraph("Raw XML Data Export", styles["subtitle"]))
    story.append(Spacer(1, 3 * mm))
    story.append(HRFlowable(width=W, thickness=1.5,
                             color=CDAC_LIGHT_BLUE, spaceAfter=6))

    # Meta strip
    story.append(_section_header("Export Information", styles))
    meta_rows = [
        ("Scan Type",      scan_type.replace("_", " ").title()),
        ("Scan Date",      timestamp[:10]),
        ("Scan Time",      timestamp[11:19]),
        ("Export Format",  "XML - Machine-readable"),
        ("Schema",         "http://cdac.rtsg.in/discovery/v1"),
        ("Generated",      datetime.now().strftime("%d %b %Y  %H:%M:%S")),
    ]
    story.append(_kv_table(meta_rows, styles))
    story.append(Spacer(1, 4 * mm))

    # XML content
    story.append(_section_header("XML Content", styles))
    story.append(Spacer(1, 2 * mm))

    for raw_line in xml_str.splitlines():
        line = raw_line.rstrip()
        if not line:
            story.append(Spacer(1, 1.5 * mm))
            continue

        # Escape XML special chars for ReportLab Paragraph
        line_safe = (line
                     .replace("&",  "&amp;")
                     .replace("<",  "&lt;")
                     .replace(">",  "&gt;")
                     .replace('"',  "&quot;"))

        # Calculate indent as leading spaces
        n_spaces = len(raw_line) - len(raw_line.lstrip(" "))
        indent   = n_spaces * 4  # points

        # Colour-code tags vs text
        stripped = line.strip()
        if stripped.startswith("&lt;") or stripped.startswith("&amp;lt;"):
            # Looks like a tag line
            p_style = ParagraphStyle(
                "XmlLine", parent=styles["mono"],
                textColor=CDAC_BLUE, leftIndent=indent)
        elif stripped.startswith("&lt;!"):
            p_style = ParagraphStyle(
                "XmlComment", parent=styles["mono"],
                textColor=colors.HexColor("#888888"), leftIndent=indent)
        else:
            p_style = ParagraphStyle(
                "XmlText", parent=styles["mono"],
                textColor=colors.HexColor("#1A1A2E"), leftIndent=indent)

        story.append(Paragraph(line_safe, p_style))

    return story


# -----------------------------------------------------------------------------
# Main generator class
# -----------------------------------------------------------------------------

class ScanReportGenerator:
    """
    Generates JSON PDF + XML PDF for every scan result.

    Args:
        output_dir: Directory where PDFs are saved (created if missing).
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.styles = _build_styles()

    # -- File naming -----------------------------------------------------------

    @staticmethod
    def _make_filename(scan_type: str, fmt: str) -> str:
        """
        Pattern: {scan_type}_{YYYY-MM-DD}_{HH-MM-SS}_{FMT}.pdf
        e.g.    scan_host_2026-03-27_14-30-05_JSON.pdf
        """
        now   = datetime.now()
        # date  = now.strftime("%Y-%m-%d")
        date  = now.strftime("%d-%m-%Y")
        time_ = now.strftime("%H-%M-%S")
        safe  = scan_type.lower().replace(" ", "_")
        return f"{safe}_{date}_{time_}_{fmt}.pdf"

    # -- JSON PDF --------------------------------------------------------------

    def _generate_json_pdf(self, result: dict, scan_type: str,
                           timestamp: str) -> str:
        filename = os.path.join(
            self.output_dir, self._make_filename(scan_type, "JSON"))

        doc = SimpleDocTemplate(
            filename,
            pagesize     = A4,
            leftMargin   = MARGIN,
            rightMargin  = MARGIN,
            topMargin    = 28 * mm,   # space for header
            bottomMargin = 18 * mm,   # space for footer
            title        = "CDAC Host Discovery Report - JSON Format",
            author       = "CDAC Bangalore RTSG Team ",
            subject      = f"Host Discovery: {scan_type}",
        )

        story = _build_json_story(result, scan_type, timestamp, self.styles)
        doc.build(story, onFirstPage=_draw_header_footer,
                         onLaterPages=_draw_header_footer)
        return filename

    # -- XML PDF ---------------------------------------------------------------

    def _generate_xml_pdf(self, result: dict, scan_type: str,
                          timestamp: str) -> str:
        filename = os.path.join(
            self.output_dir, self._make_filename(scan_type, "XML"))

        # For range/subnet scans, include all hosts (active and inactive)
        # XML export shows complete data
        xml_str = _result_to_pretty_xml(result, scan_type)

        doc = SimpleDocTemplate(
            filename,
            pagesize     = A4,
            leftMargin   = MARGIN,
            rightMargin  = MARGIN,
            topMargin    = 28 * mm,
            bottomMargin = 18 * mm,
            title        = "CDAC Host Discovery Report - XML Format",
            author       = "CDAC Bangalore RTSG",
            subject      = f"Host Discovery: {scan_type}",
        )

        story = _xml_to_story(xml_str, scan_type, timestamp, self.styles)
        doc.build(story, onFirstPage=_draw_header_footer,
                         onLaterPages=_draw_header_footer)
        return filename

    # -- Public entry point ----------------------------------------------------

    def generate(self, result: dict, scan_type: str) -> Dict[str, str]:
        """
        Generate both PDF reports for a scan result.

        Args:
            result:    The dict returned by any HostDiscoveryAPI method.
            scan_type: Descriptive name, e.g. 'scan_host', 'scan_subnet'.

        Returns:
            {
              "json_pdf": "/path/to/scan_host_2026-03-27_14-30-05_JSON.pdf",
              "xml_pdf":  "/path/to/scan_host_2026-03-27_14-30-05_XML.pdf",
            }
        """
        timestamp = datetime.now().isoformat()

        try:
            json_path = self._generate_json_pdf(result, scan_type, timestamp)
        except Exception as e:
            json_path = f"ERROR: {e}"

        try:
            xml_path = self._generate_xml_pdf(result, scan_type, timestamp)
        except Exception as e:
            xml_path = f"ERROR: {e}"

        return {"json_pdf": json_path, "xml_pdf": xml_path}
