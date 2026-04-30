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
from typing import Dict, List, Optional, Any, Tuple

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
        status_text = host.get("status") or ("Active" if is_active else "Inactive")
        status_p  = Paragraph(
            status_text,
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


def _resolve_pdf_cve_id(cve: dict) -> str:
    return cve.get("cve_id") or cve.get("cve") or "N/A"


def _resolve_pdf_cve_severity(cve: dict) -> str:
    severity = cve.get("severity")
    if severity:
        return str(severity)

    cvss = cve.get("cvss_score", cve.get("cvss"))
    try:
        cvss = float(cvss)
    except Exception:
        cvss = None

    if cvss is None:
        return "Info"
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss > 0:
        return "Low"
    return "Info"


def _resolve_pdf_cve_package(cve: dict) -> str:
    pkg = cve.get("package") or cve.get("package_name") or cve.get("affected_software")
    if not pkg:
        affected = cve.get("affected")
        if isinstance(affected, (list, tuple)) and affected:
            return ", ".join(str(a) for a in affected[:3])
        if isinstance(affected, str) and affected:
            return affected
    return str(pkg) if pkg else "N/A"


def _resolve_pdf_cve_description(cve: dict) -> str:
    desc = cve.get("description") or cve.get("desc") or ""
    tags = []
    if cve.get("priority_level"):
        tags.append(str(cve.get("priority_level")))
    if cve.get("in_kev"):
        tags.append("KEV")
    if cve.get("has_exploit"):
        tags.append("Exploit")
    epss = cve.get("epss_score")
    try:
        epss_value = float(epss) if epss is not None else 0.0
    except Exception:
        epss_value = 0.0
    if epss_value > 0:
        tags.append(f"EPSS {epss_value:.2f}")
    if tags:
        return f"[{' | '.join(tags)}] {desc}"
    return desc


def _section_header(title: str, styles: dict) -> Paragraph:
    return Paragraph(f"&nbsp; {title}", styles["section"])


def _get_scan_type_label(scan_type: str) -> str:
    """Map technical scan_type names to user-friendly labels."""
    labels = {
        "host_discovery": "Basic Network Scan",
        "asset_discovery": "Asset Discovery Scan",
        "phase_selective_scan": "Advanced Vulnerability Scan",
        "advanced": "Advanced Vulnerability Scan",
        "credentialed_scan": "Credentialed Scan",
        "credentialed": "Credentialed Scan",
        "phase1": "Basic Network Scan",
        "phase2": "Asset Discovery Scan",
        "phase3": "Advanced Vulnerability Scan",
    }
    token = str(scan_type or "").strip().lower()
    return labels.get(token, token.replace("_", " ").title() if token else "N/A")


_SCAN_STRATEGY_LABELS = {
    "PING": "ICMP Ping",
    "ICMP": "ICMP Ping",
    "ARP": "ARP Scan",
    "TCP": "TCP SYN Scan",
    "FULL": "Full Network Sweep",
    "ADAPTIVE": "Adaptive Scan",
    "STEALTH": "Stealth Scan",
}


def _normalize_strategy_token(value: Any) -> str:
    token = str(value or "").strip().upper()
    if not token:
        return ""
    if "ADAPTIVE" in token:
        return "ADAPTIVE"
    if "STEALTH" in token:
        return "STEALTH"
    if "FULL" in token:
        return "FULL"
    if "ARP" in token:
        return "ARP"
    if "PING" in token or "ICMP" in token:
        return "PING"
    if "TCP" in token:
        return "TCP"
    return token


def _format_scan_strategy(value: Any) -> str:
    token = _normalize_strategy_token(value)
    return _SCAN_STRATEGY_LABELS.get(token, "N/A")


def _resolve_scan_strategy(meta: dict, summary: dict) -> str:
    primary = meta.get("scan_method")
    if primary:
        label = _format_scan_strategy(primary)
        if label != "N/A":
            return label

    fallback = (
        meta.get("discovery_scan_method")
        or meta.get("discovery_method")
        or summary.get("discovery_scan_method")
        or summary.get("scan_method")
        or summary.get("discovery_method")
    )
    if fallback:
        label = _format_scan_strategy(fallback)
        if label != "N/A":
            return label

    # Last-safe fallback: only use summary.scan_type when it looks like a discovery method.
    fallback_scan_type = summary.get("scan_type")
    label = _format_scan_strategy(fallback_scan_type)
    return label if label != "N/A" else "N/A"


def _normalize_target_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, list):
        parts = [str(v).strip() for v in value if str(v).strip()]
        return ", ".join(parts) if parts else None
    text = str(value).strip()
    if not text:
        return None
    return text


def _resolve_target(meta: dict, summary: dict) -> str:
    for candidate in (
        meta.get("target"),
        summary.get("target"),
        meta.get("original_targets"),
        summary.get("original_targets"),
    ):
        normalized = _normalize_target_value(candidate)
        if normalized:
            return normalized
    return "N/A"


def _collect_hosts(result: dict) -> List[dict]:
    hosts: List[dict] = []
    data = result.get("data", [])
    if isinstance(data, dict):
        if "credentialed" in data and "report" in data["credentialed"]:
            rep = data["credentialed"]["report"]
            rep["is_active"] = True
            rep["ip_address"] = rep.get("target", "N/A")
            rep["status"] = "Active"
            hosts = [rep]
        else:
            hosts = [data]
    elif isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            if "hosts" in item and isinstance(item.get("hosts"), list):
                hosts.extend(item["hosts"])
            elif "credentialed" in item and "report" in item["credentialed"]:
                rep = item["credentialed"]["report"]
                rep["is_active"] = True
                rep["ip_address"] = rep.get("target", "N/A")
                rep["status"] = "Active"
                hosts.append(rep)
            elif "ip_address" in item:
                hosts.append(item)
            elif "cves" in item or "system_info" in item:
                item["is_active"] = item.get("is_active", True)
                hosts.append(item)

    for host in hosts:
        if host.get("is_active") is None:
            host["is_active"] = bool(str(host.get("status", "")).strip().lower() == "active")

        status_text = str(host.get("status", "")).strip()
        if not status_text or status_text.lower() == "unknown":
            host["status"] = "Active" if host.get("is_active") else "Inactive"

    return hosts


def _as_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _compute_discovery_summary(summary: dict, hosts: List[dict]) -> Tuple[int, int, int, str]:
    total = _as_int(summary.get("total_hosts"))
    active = _as_int(summary.get("active_hosts"))
    inactive = _as_int(summary.get("inactive_hosts"))

    if total is None:
        total = len(hosts)
    if active is None:
        active = sum(1 for h in hosts if h.get("is_active"))
    if inactive is None:
        inactive = max(total - active, 0)

    ratio = f"{(active / total * 100):.1f}%" if total else "0%"
    return total, active, inactive, ratio


def _format_response_time_ms(value: Any) -> str:
    if value in (None, "", "N/A"):
        return "N/A"
    try:
        return f"{float(value):.2f} ms"
    except Exception:
        return "N/A"


def _resolve_detection_method(host: dict) -> str:
    raw = host.get("scan_method") or host.get("method") or host.get("discovery_method")
    token = _normalize_strategy_token(raw)
    if token in {"PING", "ICMP"}:
        return "ICMP"
    if token in {"ARP", "TCP", "FULL", "ADAPTIVE", "STEALTH"}:
        return token
    return str(raw).strip() if raw else "N/A"


def _build_advanced_insights(host: dict, styles: dict) -> list:
    story = []
    W = PAGE_W - 2 * MARGIN

    def mk_header(title):
        return Paragraph(f"<b>{title}</b>", ParagraphStyle("s", parent=styles["normal"], fontSize=10, textColor=CDAC_BLUE, spaceBefore=6, spaceAfter=4))
    
    def mk_table(headers, rows, widths=None):
        header_row = [Paragraph(h, ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=8, textColor=WHITE)) for h in headers]
        data = [header_row]
        for r in rows:
            data.append([Paragraph(str(c), styles["value"]) if not isinstance(c, Paragraph) else c for c in r])
        if not widths:
            widths = [W / len(headers)] * len(headers)
        tbl = Table(data, colWidths=widths, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), TABLE_HEADER_BG),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, BORDER_COLOUR),
            *[("BACKGROUND", (0, i), (-1, i), CDAC_ACCENT if i % 2 == 0 else WHITE) for i in range(1, len(data))],
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return tbl

    sys_info = host.get("system_info")
    if sys_info and isinstance(sys_info, dict) and sys_info.get("os_name"):
        story.append(mk_header("System Information (Credentialed)"))
        rows = [
            ("OS", sys_info.get("os_name", "N/A")),
            ("Version", sys_info.get("os_version_id", "N/A")),
            ("Kernel / Build", sys_info.get("kernel_version", sys_info.get("os_build", "N/A"))),
            ("Hostname", sys_info.get("hostname", "N/A")),
            ("CPU", sys_info.get("cpu_model", "N/A")),
            ("Arch", sys_info.get("cpu_arch", "N/A")),
        ]
        story.append(mk_table(["Property", "Value"], rows, [50*mm, W - 50*mm]))
        story.append(Spacer(1, 4 * mm))

    users = host.get("users", [])
    if users:
        story.append(mk_header(f"System Users ({len(users)})"))
        u_rows = []
        for u in users[:20]:
            if u.get("is_root") or not u.get("is_system"):
                u_type = "Root/Admin" if u.get("is_root") else "User"
                u_rows.append([u.get("username", "N/A"), str(u.get("uid", "")), u.get("shell", "N/A"), u_type])
        if u_rows:
            story.append(mk_table(["Username", "UID", "Shell", "Type"], u_rows, [50*mm, 20*mm, 70*mm, 30*mm]))
            story.append(Spacer(1, 4 * mm))

    svcs = host.get("running_services", [])
    if svcs:
        story.append(mk_header(f"Running Services ({len(svcs)})"))
        s_rows = []
        for s in svcs[:20]:
            s_rows.append([s.get("name", "N/A"), s.get("sub_state", "running"), s.get("description", "")[:60]])
        story.append(mk_table(["Service", "Status", "Description"], s_rows, [50*mm, 25*mm, W - 75*mm]))
        if len(svcs) > 20:
             story.append(Paragraph(f"... and {len(svcs)-20} more services", styles["small"]))
        story.append(Spacer(1, 4 * mm))

    pkgs = host.get("packages", [])
    if pkgs:
        story.append(mk_header(f"Installed Packages ({len(pkgs)})"))
        pkg_rows = []
        cve_pkgs = {
            _resolve_pdf_cve_package(c).lower()
            for c in host.get("cves", [])
            if _resolve_pdf_cve_package(c) != "N/A"
        }
        for p in pkgs[:30]:
            is_vuln = p.get("name", "").lower() in cve_pkgs
            v_str = "YES" if is_vuln else "No"
            pkg_rows.append([p.get("name", "N/A"), p.get("version", "N/A"), v_str])
        story.append(mk_table(["Package", "Version", "Has CVE"], pkg_rows, [70*mm, 70*mm, 30*mm]))
        if len(pkgs) > 30:
             story.append(Paragraph(f"... and {len(pkgs)-30} more packages", styles["small"]))
        story.append(Spacer(1, 4 * mm))

    # CVE table is rendered once at the end of the report (after all host cards).
    # Do not render it here per-host.

    sec_issues = host.get("security_issues", [])
    suid = host.get("suid_binaries", [])
    if sec_issues or host.get("sudo_nopasswd") or host.get("failed_login_count"):
        story.append(mk_header("Security Audit Findings"))
        iss_rows = []
        if host.get("sudo_nopasswd"):
             iss_rows.append(["NOPASSWD Sudo", "Enabled (High Risk)"])
        for iss in sec_issues:
             iss_rows.append(["Misconfiguration", iss])
        if suid:
             iss_rows.append(["SUID Binaries", f"{len(suid)} found"])
        if host.get("failed_login_count"):
             iss_rows.append(["Failed Logins", f"{host.get('failed_login_count')} attempts"])
        story.append(mk_table(["Finding Type", "Detail"], iss_rows, [50*mm, W - 50*mm]))
        story.append(Spacer(1, 4 * mm))

    return story


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
    data    = result.get("data", [])
    hosts   = _collect_hosts(result)

    scan_strategy = _resolve_scan_strategy(meta, summary)
    target_value  = _resolve_target(meta, summary)

    scan_info_rows = [
        ("Scan No.",          meta.get("scan_no", "N/A")),
        ("Scan Type",         _get_scan_type_label(scan_type)),
        ("Target",            target_value),
        ("Scan Strategy",     scan_strategy),
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
    total, active, inactive, pct = _compute_discovery_summary(summary, hosts)

    summary_rows = [
        ("Total Hosts Scanned",   total),
        ("Active Hosts",          active),
        ("Inactive / No Response",inactive),
        ("Active Host Ratio",     pct),
    ]
    story.append(_kv_table(summary_rows, styles))
    story.append(Spacer(1, 4 * mm))

    # -- Host Discovery Results (Active hosts only) ---------------------------
    # Filter to only active hosts for PDF export; inactive hosts are excluded.
    active_hosts = [h for h in hosts if h.get("is_active", False)]

    if active_hosts:
        story.append(_section_header(
            f"Discovered Hosts  ({len(active_hosts)} active)", styles))
        story.append(_host_table(active_hosts, styles))
        story.append(Spacer(1, 4 * mm))

        # -- Per-host Detail Cards --------------------------------------------
        story.append(_section_header("Individual Host Details", styles))
        all_cve_rows: List[tuple] = []  # (ip, cve_id, severity, package, description)
        for idx, host in enumerate(active_hosts, start=1):
            is_active = host.get("is_active", False)
            
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
                ("Detection Method",  _resolve_detection_method(host)),
            ]
            # Only include port information for non-host-discovery scans (phase > 1)
            if result.get("summary", {}).get("phase", 1) > 1:
                detail_rows.append(("Open TCP Ports",    ports_display if is_active else "N/A"))
            
            # --- GAP 06-10 Fields ---
            dev_cat = host.get("device_category") or host.get("snmp_device_type")
            if dev_cat and dev_cat != "unknown":
                detail_rows.append(("Device Category", str(dev_cat).capitalize()))
                
            if host.get("snmp_info", {}).get("vendor"):
                detail_rows.append(("SNMP Vendor", host["snmp_info"]["vendor"]))
                
            if host.get("snmp_info", {}).get("sys_location"):
                detail_rows.append(("SNMP Location", host["snmp_info"]["sys_location"]))
                
            if host.get("firewall_likely"):
                detail_rows.append(("Firewall Detected", f"Yes (confidence: {host.get('firewall_confidence', 'Low')})"))
                
            if host.get("netbios_workgroup"):
                detail_rows.append(("Domain/Workgroup", host["netbios_workgroup"]))
                
            mdns_svcs = host.get("mdns_services", [])
            if mdns_svcs:
                detail_rows.append(("mDNS Services", ", ".join(mdns_svcs[:6])))
                
            ifaces = host.get("snmp_info", {}).get("interfaces", [])
            if ifaces:
                iface_str = " | ".join(
                    f"{i.get('description', 'Unknown')} ({i.get('type', 'Unknown')}, {'Up' if i.get('oper_up') else 'Down'})"
                    for i in ifaces[:3]
                )
                if len(ifaces) > 3:
                    iface_str += f" (+{len(ifaces)-3} more)"
                detail_rows.append(("SNMP Interfaces", iface_str))
                
            if host.get("host_risk_level"):
                detail_rows.append(("Risk Level", f"{host['host_risk_level']} (score: {host.get('host_risk_score', 0)})"))
                
            cves = host.get("cves", [])
            if cves:
                detail_rows.append(("CVEs Found", str(len(cves))))
                
            active_findings = []
            if host.get("heartbleed_info", {}).get("vulnerable"):          active_findings.append("Heartbleed (CVE-2014-0160)")
            if host.get("smb_ms17010_info", {}).get("ms17010_likely"):     active_findings.append("EternalBlue MS17-010")
            if host.get("ldap_info", {}).get("anonymous_bind", {}).get("allowed"): active_findings.append("LDAP Anonymous Bind")
            if host.get("dns_info", {}).get("zone_transfer", {}).get("vulnerable"): active_findings.append("DNS Zone Transfer (AXFR)")
            if host.get("default_creds_info"):                             active_findings.append("Default Credentials")
            # FTP deep-probe findings
            ftp = host.get("ftp_info", {})
            if ftp.get("anonymous_login"):                                 active_findings.append("FTP Anonymous Login")
            if ftp.get("write_access"):                                    active_findings.append("FTP Anonymous Write Access")
            if ftp.get("weak_credentials"):                                active_findings.append(f"FTP Weak Credentials ({len(ftp['weak_credentials'])} pair(s))")
            # HTTP deep-probe findings
            http = host.get("http_audit", {})
            if http.get("exposed_paths"):                                  active_findings.append(f"HTTP Exposed Paths ({len(http['exposed_paths'])} found)")
            if http.get("admin_panels"):                                   active_findings.append(f"HTTP Admin Panels ({len(http['admin_panels'])} detected)")
            if http.get("dangerous_methods"):                              active_findings.append(f"HTTP Dangerous Methods ({len(http['dangerous_methods'])} enabled)")
            if active_findings:
                detail_rows.append(("Active Findings", " | ".join(active_findings)))

            # ── FTP Deep Probe Section ────────────────────────────────────────
            if ftp.get("open"):
                detail_rows.append(("FTP Version", ftp.get("banner", "N/A")[:80]))
                detail_rows.append(("FTP Anonymous Login", "YES — Unauthenticated access allowed" if ftp.get("anonymous_login") else "No"))
                if ftp.get("write_access"):
                    detail_rows.append(("FTP Write Access", "CRITICAL — Anonymous session can upload files"))
                if ftp.get("weak_credentials"):
                    cred_list = ", ".join(
                        f"{c['user']}/{c['password']}" for c in ftp["weak_credentials"][:5]
                    )
                    detail_rows.append(("FTP Weak Credentials", cred_list))
                ftp_issues = ftp.get("issues", [])
                if ftp_issues:
                    detail_rows.append(("FTP Issues", " | ".join(ftp_issues[:4])))

            # ── HTTP Deep Probe Section ───────────────────────────────────────
            if http:
                if http.get("server_header"):
                    detail_rows.append(("HTTP Server", http["server_header"][:80]))
                http_issues = http.get("issues", [])
                if http_issues:
                    # First 4 issues inline; rest summarised as count
                    preview = " | ".join(http_issues[:4])
                    if len(http_issues) > 4:
                        preview += f" (+{len(http_issues) - 4} more)"
                    detail_rows.append(("HTTP Security Issues", preview))
                # Exposed paths
                exposed = http.get("exposed_paths", [])
                if exposed:
                    paths_str = ", ".join(
                        f"{p['path']} [{p['status']}]" for p in exposed[:6]
                    )
                    if len(exposed) > 6:
                        paths_str += f" (+{len(exposed) - 6} more)"
                    detail_rows.append(("HTTP Exposed Paths", paths_str))
                # Admin panels
                panels = http.get("admin_panels", [])
                if panels:
                    panels_str = ", ".join(
                        f"{p['product']} @ {p['path']}" for p in panels[:4]
                    )
                    detail_rows.append(("HTTP Admin Panels", panels_str))
                # Dangerous methods
                methods = http.get("dangerous_methods", [])
                if methods:
                    detail_rows.append(("HTTP Dangerous Methods", " | ".join(methods[:4])))

            # ── SSH Info ──────────────────────────────────────────────────────
            ssh = host.get("ssh_info", {})
            if ssh.get("banner"):
                detail_rows.append(("SSH Banner", ssh["banner"][:80]))
            if ssh.get("auth_methods"):
                detail_rows.append(("SSH Auth Methods", ", ".join(ssh.get("auth_methods", []))))

            # ── SMB Info ─────────────────────────────────────────────────────
            smb = host.get("smb_info", {})
            if smb.get("open"):
                detail_rows.append(("SMB Version", smb.get("version", "Unknown")))
                if smb.get("null_session"):
                    detail_rows.append(("SMB Null Session", "YES — Unauthenticated SMB connection allowed"))

            # ── TLS/SSL Info ─────────────────────────────────────────────────
            tls = host.get("tls_info", {})
            if tls:
                detail_rows.append(("TLS Protocol", tls.get("protocol", "N/A")))
                if tls.get("cert_cn"):
                    detail_rows.append(("TLS Certificate CN", tls.get("cert_cn", "N/A")))
                if tls.get("cert_expired"):
                    detail_rows.append(("TLS Certificate", "EXPIRED — Certificate has passed its expiry date"))

            status_value = host.get("status") or ("Active" if host.get("is_active") else "Inactive")
            detail_rows.extend([
                ("Status",            status_value),
                ("Response Time",     _format_response_time_ms(host.get("response_time_ms"))),
                ("Scan Timestamp",    host.get("scan_timestamp", "N/A")),
            ])


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

            # --- Append Credentials/Advanced insights (CVEs excluded here) ---
            advanced_flowables = _build_advanced_insights(host, styles)
            if advanced_flowables:
                story.extend(advanced_flowables)

            # Accumulate CVEs for the consolidated end-of-report section
            for cve in host.get("cves", []):
                all_cve_rows.append((
                    host.get("ip_address", "N/A"),
                    _resolve_pdf_cve_id(cve),
                    _resolve_pdf_cve_severity(cve),
                    _resolve_pdf_cve_package(cve),
                    (_resolve_pdf_cve_description(cve)[:80] +
                     ("..." if len(_resolve_pdf_cve_description(cve)) > 80 else "")),
                ))


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
        redundant_keys = {
            "target",
            "original_targets",
            "scan_type",
            "scan_method",
            "discovery_scan_method",
        }
        meta_rows = [
            (k.replace("_", " ").title(), str(v))
            for k, v in meta.items()
            if k not in redundant_keys
        ]
        if meta_rows:
            story.append(_section_header("Scan Metadata", styles))
            story.append(_kv_table(meta_rows, styles))

    # -- Consolidated CVE Section (once, at end of report) --------------------
    # all_cve_rows is populated only when active_hosts exist (guarded above).
    if active_hosts and all_cve_rows:
        story.append(PageBreak())
        story.append(_section_header(
            f"Vulnerabilities / CVEs  ({len(all_cve_rows)} total)", styles))

        cve_header_style = ParagraphStyle(
            "CVETh", fontName="Helvetica-Bold", fontSize=8,
            textColor=WHITE, alignment=TA_CENTER)
        cve_headers = ["Host IP", "CVE ID", "Severity", "Package", "Description"]
        cve_col_w   = [28*mm, 32*mm, 18*mm, 28*mm, W - 106*mm]

        cve_table_data = [[Paragraph(h, cve_header_style) for h in cve_headers]]
        for ip, cve_id, sev, pkg, desc in all_cve_rows:
            # Colour-code severity
            sev_upper = str(sev).upper()
            if sev_upper == "CRITICAL":
                sev_color = colors.HexColor("#7B241C")
            elif sev_upper == "HIGH":
                sev_color = colors.HexColor("#C0392B")
            elif sev_upper == "MEDIUM":
                sev_color = colors.HexColor("#D35400")
            elif sev_upper == "LOW":
                sev_color = colors.HexColor("#1A7A3F")
            else:
                sev_color = colors.HexColor("#555555")
            sev_p = Paragraph(sev, ParagraphStyle(
                "SevCell", fontName="Helvetica-Bold", fontSize=8, textColor=sev_color))
            cve_table_data.append([
                Paragraph(str(ip),    styles["value"]),
                Paragraph(str(cve_id), styles["value"]),
                sev_p,
                Paragraph(str(pkg),   styles["value"]),
                Paragraph(str(desc),  styles["value"]),
            ])

        cve_tbl = Table(cve_table_data, colWidths=cve_col_w, repeatRows=1)
        cve_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  TABLE_HEADER_BG),
            ("ALIGN",         (0, 0), (-1, 0),  "CENTER"),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("GRID",          (0, 0), (-1, -1), 0.4, BORDER_COLOUR),
            *[("BACKGROUND",  (0, i), (-1, i),  CDAC_ACCENT if i % 2 == 0 else WHITE)
              for i in range(1, len(cve_table_data))],
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(cve_tbl)
        story.append(Spacer(1, 4 * mm))

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
                  timestamp: str, styles: dict, result: dict = None) -> list:
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
    meta    = result.get("metadata", {}) if result else {}
    summary = result.get("summary", {}) if result else {}
    scan_strategy = _resolve_scan_strategy(meta, summary)
    target_value = _resolve_target(meta, summary)
    
    meta_rows = [
        ("Scan No.",       meta.get("scan_no", "N/A")),
        ("Scan Type",      _get_scan_type_label(scan_type)),
        ("Target",         target_value),
        ("Scan Strategy",  scan_strategy),
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
            title        = "CDAC Host Discovery Report",
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

        story = _xml_to_story(xml_str, scan_type, timestamp, self.styles, result)
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
