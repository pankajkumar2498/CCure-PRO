"""
pdf_generator.py
================
Vulnerability report generator for CCure Audit PRO.

Produces two documents per scan:

  1. Executive Summary  — risk posture, severity distribution charts, host risk
                          ranking, exploited-in-the-wild callout, and a
                          remediation plan ranked by findings-resolved.
  2. Technical Audit    — per-host sections, clickable table of contents, PDF
                          outline bookmarks, and one card per finding with its
                          CVSS vector broken out, detection evidence, and
                          remediation provenance.

Reporting principles enforced here
──────────────────────────────────
  * No score, vector, title, port binding, or remediation string is invented.
    Anything absent from the feed is rendered as an explicit statement that it
    is unavailable.
  * Every finding shows how it was detected and with what confidence, so a
    version-confirmed match is never confused with a service-present guess.
  * Suppressed candidates are counted and explained in a methodology appendix,
    so the reader can see what the tool chose not to report and why.
  * CVSS scores are recomputed from the published vector; any disagreement with
    the feed is disclosed rather than hidden.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List, Optional


from reporting.report_helpers import (
    NumberedCanvas,
    ReportDocTemplate,
    age_in_days as _age_in_days,
    chart_legend,
    clean_control_chars,
    date_only as _date_only,
    escape_for_reportlab,
    host_risk_chart,
    ordinal as _ordinal,
    register_report_fonts,
    severity_bar_chart,
    severity_donut,
    truncate_with_notice,
)
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    CondPageBreak,
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reporting.host_assessment import (
    HostAssessment,
    ListenerExposure,
    exposure_sentence,
    host_assessments,
)
from reportlab.platypus.tableofcontents import TableOfContents
from scans.cvss import SEVERITY_RANK
from scans.finding_normalizer import (
    DETECTION_SEMANTICS,
    QOD_REPORT_THRESHOLD,
    Confidence,
    DetectionMethod,
    RemediationConfidence,
    ScanFindings,
    StandardizedFinding,
    boundary_key,
    build_scan_report,
    group_findings_for_report,
    upgrade_target,
)

# ─────────────────────────────────────────────────────────────────────────────
# Palette
# ─────────────────────────────────────────────────────────────────────────────

NAVY = colors.HexColor("#0F172A")
BLUE = colors.HexColor("#0284C7")
BG_ALT = colors.HexColor("#F8FAFC")
BORDER = colors.HexColor("#E2E8F0")
TEXT = colors.HexColor("#1E293B")
MUTED = colors.HexColor("#64748B")
WHITE = colors.white

SEVERITY_FG: Dict[str, colors.Color] = {
    "Critical": colors.HexColor("#7F1D1D"),
    "High": colors.HexColor("#DC2626"),
    "Medium": colors.HexColor("#EA580C"),
    "Low": colors.HexColor("#CA8A04"),
    "None": colors.HexColor("#0284C7"),
    "Unscored": colors.HexColor("#64748B"),
}

SEVERITY_BG: Dict[str, colors.Color] = {
    "Critical": colors.HexColor("#FEE2E2"),
    "High": colors.HexColor("#FFE4E6"),
    "Medium": colors.HexColor("#FFEDD5"),
    "Low": colors.HexColor("#FEF9C3"),
    "None": colors.HexColor("#DBEAFE"),
    "Unscored": colors.HexColor("#F1F5F9"),
}

CONFIDENCE_COLOR: Dict[Confidence, colors.Color] = {
    Confidence.CONFIRMED: colors.HexColor("#15803D"),
    Confidence.POTENTIAL: colors.HexColor("#B45309"),
    Confidence.INFORMATIONAL: colors.HexColor("#0369A1"),
    Confidence.UNVERIFIED: colors.HexColor("#64748B"),
}

SEVERITY_TIERS = ["Critical", "High", "Medium", "Low", "None", "Unscored"]

#: Where a finding's remediation text came from, printed beneath it so a reader
#: can weigh advice from a vendor advisory differently from advice inferred
#: from a version range. Every ``RemediationConfidence`` member must appear
#: here; ``tests/reports/test_report_integrity.py`` fails if one does not.
REMEDIATION_PROVENANCE: Dict[RemediationConfidence, str] = {
    RemediationConfidence.VENDOR_PATCH: "Source: vendor advisory linked below.",
    RemediationConfidence.VERSION_BOUNDARY: "Source: CPE version range published with this CVE.",
    RemediationConfidence.FEED_SUPPLIED: "Source: vulnerability feed.",
    RemediationConfidence.NONE_PUBLISHED: "No published fix — compensating controls only.",
    RemediationConfidence.CONFIGURATION_GUIDANCE: "Source: configuration rule — apply the change described above.",
}

#: How many suppressed candidates to sample into the methodology appendix. The
#: full list goes to the CSV export; printing hundreds of rows here crowds out
#: the findings the report exists to communicate.
SUPPRESSED_SAMPLE_SIZE = 15

#: Remediation SLA windows. These are organisational policy, not scan data, and
#: are labelled as such wherever they appear in the report.
REMEDIATION_SLA: Dict[str, str] = {
    "Critical": "7 days",
    "High": "15 days",
    "Medium": "30 days",
    "Low": "90 days",
    "None": "Next maintenance window",
    "Unscored": "Triage required",
}

#: Internal pipeline enum names are meaningless to the reader of a client
#: deliverable. They are translated rather than dropped, because *what kind of
#: scan produced this* is material to interpreting the findings.
SCAN_POLICY_LABELS: Dict[str, str] = {
    "phase1": "Host discovery",
    "host_discovery": "Host discovery",
    "phase2": "Asset and service discovery",
    "asset_discovery": "Asset and service discovery",
    "phase3": "Network vulnerability assessment",
    "vulnerability_audit": "Network vulnerability assessment",
    "credentialed": "Credentialed configuration audit",
    "web": "Web application assessment",
    "webscan": "Web application assessment",
}

#: What each policy's report is actually called. A host-discovery scan performs
#: no vulnerability assessment, so titling its report "Vulnerability Assessment"
#: misdescribed the document on its own cover — the body and appendix were
#: already accurate about what did and did not run.
#: Scan policies that match findings against the CVE feed. Everything else is
#: discovery or inventory work, where feed age and detection-quality thresholds
#: describe an analysis that did not run.
VULN_ANALYSIS_POLICIES = frozenset(
    {
        "phase3",
        "vulnerability_audit",
        "credentialed",
        "web",
        "webscan",
    }
)


#: Report keys the pipelines generate under, and the policy each one is.
#: Without these a Vulnerability Audit's report (generated as
#: ``phase_selective_scan``) printed "Scan policy: Phase Selective Scan", was
#: named ``phase_selective_scan_….pdf``, and — because the key matched no
#: policy that consults the CVE feed — omitted the vulnerability feed date,
#: the candidate count and the reporting QoD threshold.
_POLICY_ALIASES: Dict[str, str] = {
    "phase_selective_scan": "vulnerability_audit",
    "credentialed_scan": "credentialed",
}


def _canonical_policy(scan_type: object) -> str:
    key = str(scan_type or "").strip().lower()
    return _POLICY_ALIASES.get(key, key)


def _performs_vulnerability_analysis(scan_type: object) -> bool:
    """True when this scan policy matched services against the CVE feed."""
    return str(scan_type or "").strip().lower() in VULN_ANALYSIS_POLICIES


REPORT_TITLE_BY_POLICY: Dict[str, str] = {
    "phase1": "Network Discovery Report",
    "host_discovery": "Network Discovery Report",
    "phase2": "Asset and Service Inventory",
    "asset_discovery": "Asset and Service Inventory",
    "phase3": "Vulnerability Assessment",
    "vulnerability_audit": "Vulnerability Assessment",
    "credentialed": "Credentialed Configuration Audit",
    "web": "Web Application Assessment",
    "webscan": "Web Application Assessment",
}

#: The one-line description under each title, per policy.
REPORT_SUBTITLE_BY_POLICY: Dict[str, Dict[str, str]] = {
    "discovery": {
        "executive": "Live hosts identified on the target scope, with reachability coverage.",
        "technical": "Per-host discovery evidence: addressing, hardware identity, and probe results.",
    },
    "default": {
        "executive": "Risk posture, exposure ranking, and prioritised remediation plan.",
        "technical": "Per-host findings with detection evidence, scoring provenance, and remediation guidance.",
    },
}


def _report_title(scan_type: str, kind: str) -> str:
    """Return the cover title for this scan policy ('executive' | 'technical')."""
    base = REPORT_TITLE_BY_POLICY.get(
        str(scan_type).lower().strip(), "Vulnerability Assessment"
    )
    suffix = "Executive Summary" if kind == "executive" else "Technical Report"
    return f"{base} — {suffix}"


def _report_subtitle(scan_type: str, kind: str) -> str:
    """Return the standfirst matching the report's actual subject."""
    key = (
        "discovery"
        if str(scan_type).lower().strip() in ("phase1", "host_discovery")
        else "default"
    )
    return REPORT_SUBTITLE_BY_POLICY[key][kind]


DISCOVERY_METHOD_LABELS: Dict[str, str] = {
    "adaptive": "Adaptive (service-guided port selection)",
    "full": "Full TCP port sweep",
    "fast": "Common ports only",
    "quick": "Common ports only",
    "custom": "Operator-defined port list",
}


def _scan_reference_text(meta: Dict[str, Any]) -> str:
    """
    Build an audit reference the report can be traced back by.

    ``scan_no`` alone renders as a bare sequence number ("1"), which is a row
    counter rather than a reference: two organisations both have a scan 1. The
    durable scan identifier is included so a finding can be tied back to the
    run that produced it.
    """
    number = meta.get("scan_no")
    identifier = str(meta.get("scan_id") or "").strip()

    if number is not None and identifier:
        return f"#{number} · {identifier}"
    if identifier:
        return identifier
    if number is not None:
        return f"#{number}"
    return "Not recorded"


#: Report types whose scan policies run no vulnerability checks.
_INVENTORY_ONLY_REPORTS = frozenset({"host_discovery", "asset_discovery"})
#: Report types whose scan policies probe no ports.
_NO_PORT_SCAN_REPORTS = frozenset({"host_discovery"})


def _assesses_vulnerabilities(scan_type: str) -> bool:
    """False for a discovery report: nothing was assessed, so nothing is 0."""
    return scan_type not in _INVENTORY_ONLY_REPORTS


def _scans_ports(scan_type: str) -> bool:
    """False for host discovery, which identifies hosts without port scanning."""
    return scan_type not in _NO_PORT_SCAN_REPORTS


def _network_reachable_count(findings) -> int:
    """
    High/Critical findings in a service the network can actually reach.

    ``attack_surface == "remote"`` describes the *flaw* — its CVSS attack
    vector — not this host. Counting it as "reachable against a network-
    listening service" told an executive that 783 of 802 High/Critical
    findings on a Windows desktop were network-reachable when 12 were bound to
    an open port at all. A finding counts only when it is bound to a port and
    that port's service is not known to be host-only or filtered.
    """
    exposure: dict = {}
    for host in findings.reachable_hosts:
        for service in host.services:
            key = (host.ip, service.port, (service.protocol or "tcp").lower())
            exposure[key] = service.exposure or ""
    count = 0
    for f in findings.vulnerabilities:
        if f.severity not in ("Critical", "High") or f.attack_surface != "remote":
            continue
        if f.port is None:
            continue
        key = (f.host, f.port, (f.protocol or "tcp").lower())
        if exposure.get(key, "") in ("host_only", "filtered"):
            continue
        count += 1
    return count


def _hosts_reported_text(findings) -> str:
    """
    "Hosts reported" counts hosts that answered.

    A target that never responded is kept in the result set so the report can
    say it was probed, but it is not a host that was found. Counting it made a
    scan of a dead address state "Hosts reported 1" and print a full host page
    for a machine that does not exist. When some targets were down the count is
    qualified inline rather than silently dropped.
    """
    reachable = len(findings.reachable_hosts)
    unreachable = len(findings.unreachable_hosts)
    if unreachable:
        return f"{reachable} of {reachable + unreachable} probed"
    return str(reachable)


def _hosts_scanned_text(findings) -> str:
    """Coverage figure: what was probed, and how much of it answered."""
    reachable = len(findings.reachable_hosts)
    unreachable = len(findings.unreachable_hosts)
    if unreachable:
        return f"{reachable + unreachable} probed, {reachable} responded"
    return str(reachable)


def _feed_freshness_text(meta: Dict[str, Any]) -> str:
    """
    State the vulnerability feed date, and its age at report time.

    Findings can only reflect what the feed knew. A reader who is not told the
    feed date has no way to judge how much the scan could not have seen, so the
    age is spelled out rather than left to be inferred from a bare timestamp.
    """
    raw = meta.get("cve_feed_updated") or meta.get("nvd_last_sync")
    if not raw:
        return "Not recorded"

    stamp = raw
    if isinstance(raw, str):
        try:
            stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return str(raw)

    if not isinstance(stamp, datetime):
        return str(raw)

    text = stamp.strftime("%d %b %Y")
    try:
        now = datetime.now(stamp.tzinfo) if stamp.tzinfo else datetime.now()
        days = (now - stamp).days
        if days >= 1:
            text += f" ({days} day{'s' if days != 1 else ''} old)"
        else:
            text += " (current)"
    except (TypeError, ValueError):
        pass

    size = meta.get("cve_feed_size")
    if size:
        try:
            text += f" · {int(size):,} CVEs"
        except (TypeError, ValueError):
            pass
    return text


PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
CONTENT_W = PAGE_W - (2 * MARGIN)

#: Cap on findings rendered as full cards in the technical report. Beyond this
#: the remainder is tabulated instead, and the truncation is stated in-document.
MAX_DETAIL_CARDS = 400


# ─────────────────────────────────────────────────────────────────────────────
# Styles
# ─────────────────────────────────────────────────────────────────────────────


def _build_styles() -> Dict[str, ParagraphStyle]:
    fonts = register_report_fonts()
    regular, bold, mono = fonts["regular"], fonts["bold"], fonts["mono"]
    NumberedCanvas.footer_font = regular

    base = getSampleStyleSheet()

    def style(name, **kwargs) -> ParagraphStyle:
        kwargs.setdefault("fontName", regular)
        kwargs.setdefault("textColor", TEXT)
        # splitLongWords lets ReportLab wrap long URLs and vectors on character
        # boundaries, so they need no artificial spaces injected into them.
        kwargs.setdefault("splitLongWords", 1)
        return ParagraphStyle(name, parent=base["Normal"], **kwargs)

    return {
        "fonts": fonts,
        "title": style(
            "Title_",
            fontName=bold,
            fontSize=21,
            leading=25,
            textColor=NAVY,
            alignment=TA_LEFT,
            spaceAfter=3,
        ),
        "subtitle": style(
            "Subtitle_", fontSize=9.5, leading=13, textColor=MUTED, spaceAfter=10
        ),
        "h1": style(
            "H1_",
            fontName=bold,
            fontSize=13.5,
            leading=17,
            textColor=NAVY,
            spaceBefore=13,
            spaceAfter=7,
            keepWithNext=True,
        ),
        "h2": style(
            "H2_",
            fontName=bold,
            fontSize=10.5,
            leading=14,
            textColor=BLUE,
            spaceBefore=9,
            spaceAfter=5,
            keepWithNext=True,
        ),
        "body": style("Body_", fontSize=8.7, leading=12.4),
        "body_bold": style("BodyB_", fontName=bold, fontSize=8.7, leading=12.4),
        # Table header cells. A ReportLab TEXTCOLOR table command does not reach
        # Paragraph cells — a Paragraph carries its own colour — so header cells
        # built with a body style render dark-on-navy and are unreadable. Every
        # header row in this report must use this style.
        "th": style("Th_", fontName=bold, fontSize=8.7, leading=12.4, textColor=WHITE),
        "small": style("Small_", fontSize=7.6, leading=10.4, textColor=MUTED),
        "mono": style(
            "Mono_",
            fontName=mono,
            fontSize=7.2,
            leading=9.6,
            textColor=colors.HexColor("#0F172A"),
        ),
        "kpi_num": style(
            "KpiN_",
            fontName=bold,
            fontSize=17,
            leading=20,
            alignment=TA_CENTER,
            textColor=WHITE,
        ),
        "kpi_lbl": style(
            "KpiL_",
            fontName=bold,
            fontSize=7,
            leading=9,
            alignment=TA_CENTER,
            textColor=WHITE,
        ),
        "toc1": style(
            "Toc1_",
            fontName=bold,
            fontSize=9.5,
            leading=15,
            textColor=NAVY,
            spaceBefore=5,
        ),
        "toc2": style(
            "Toc2_", fontSize=8.5, leading=12.5, textColor=TEXT, leftIndent=12
        ),
    }


def _p(text: Any, style: ParagraphStyle, escape: bool = True) -> Paragraph:
    """Paragraph shorthand that escapes scan-derived text by default."""
    value = escape_for_reportlab(text) if escape else str(text or "")
    return Paragraph(value, style)


def _heading(text: str, style: ParagraphStyle, level: int) -> Paragraph:
    """A heading tagged for TOC + PDF-outline registration."""
    para = Paragraph(escape_for_reportlab(text), style)
    para.toc_level = level
    return para


def _grid(rows, col_widths, header: bool = True, zebra: bool = True) -> Table:
    """
    Zebra-striped grid whose first row is the header.

    Header cells must be built with ``styles["th"]``: the TEXTCOLOR command
    below only recolours plain-string cells, so a Paragraph header carrying a
    body style stays dark and disappears into the navy fill.
    """
    table = Table(rows, colWidths=col_widths, repeatRows=1 if header else 0)
    commands = [
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        commands += [
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ]
    if zebra:
        commands.append(
            ("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [WHITE, BG_ALT])
        )
    table.setStyle(TableStyle(commands))
    return table


def _boxed(
    flowable, bg: colors.Color, border: colors.Color, width: float = CONTENT_W
) -> Table:
    table = Table([[flowable]], colWidths=[width])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), bg),
                ("BOX", (0, 0), (-1, -1), 0.5, border),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table


# ─────────────────────────────────────────────────────────────────────────────
# Shared blocks
# ─────────────────────────────────────────────────────────────────────────────


def _report_inputs(result: dict) -> dict:
    """
    What the engines contribute to the report, carried by the payload (B7).

    ``scans.report_inputs.with_report_inputs`` attaches it. A payload without
    it is refused rather than rendered without the coverage and truncation
    rows, which would read as a more complete assessment than the scan made.
    """
    inputs = result.get("report_inputs")
    if not isinstance(inputs, dict) or not {
        "coverage_rows",
        "truncated_search_notes",
    } <= set(inputs):
        raise ValueError(
            "the report payload carries no report_inputs; wrap it with "
            "scans.report_inputs.with_report_inputs before rendering"
        )
    return inputs


def _truncated_searches_row(meta: dict, summary: dict, notes: dict) -> tuple | None:
    """
    Which candidate searches stopped at their row cap, or None if unrecorded.

    A truncated search leaves candidates that were never evaluated. Scans
    before 14 Oct 2026 did not record this, and for them the row is left out
    rather than printed as "None", which would claim every search completed.

    ``notes`` describes each truncated search, per source, in the order the
    source lists them (``report_inputs["truncated_search_notes"]``).
    """
    for name, source in (("summary", summary), ("metadata", meta)):
        if isinstance(source, dict) and "candidate_searches_truncated" in source:
            truncated = source.get("candidate_searches_truncated") or []
            described = notes.get(name)
            break
    else:
        return None
    if not truncated:
        return (
            "Candidate searches truncated",
            "None — every candidate search ran to completion",
        )
    if not isinstance(described, list) or len(described) != len(truncated):
        raise ValueError(
            f"report_inputs describe {len(described or [])} of the {len(truncated)} "
            f"truncated searches in the {name}; rebuild them with with_report_inputs"
        )
    shown = "; ".join(described[:6])
    more = f"; and {len(truncated) - 6} more" if len(truncated) > 6 else ""
    return ("Candidate searches truncated", f"{len(truncated)} — {shown}{more}")


def _scan_configuration(
    meta: dict, summary: dict, findings: ScanFindings, scan_type: str, inputs: dict
) -> List[tuple]:
    """
    The scan's own parameters, for the methodology appendix.

    Reports what was configured, never what was assumed: a parameter the scan
    did not record is stated as unrecorded so the reader can tell the
    difference between "all ports scanned" and "we did not write it down".

    ``inputs`` is the payload's ``report_inputs``: the credentialed coverage
    rows and the truncated-search notes, which the renderer does not import.
    """

    def first(*keys, default="Not recorded") -> str:
        for key in keys:
            candidate = meta.get(key)
            if candidate in (None, "", []):
                candidate = summary.get(key)
            if candidate not in (None, "", []):
                if isinstance(candidate, (list, tuple)):
                    return ", ".join(str(c) for c in candidate)
                return str(candidate)
        return default

    # Counted from the reachable set, the same basis as the port inventory.
    total_services = sum(len(h.reachable_services) for h in findings.reachable_hosts)

    rows = [
        (
            "Scan policy",
            SCAN_POLICY_LABELS.get(
                str(scan_type).lower(), str(scan_type).replace("_", " ").title()
            ),
        ),
        ("Port selection", first("port_range", "ports", "port_spec", "scan_ports")),
        ("Host discovery", first("discovery_scan_method", "scan_method", "discovery")),
        # The orchestrator publishes this on every discovery phase and nothing
        # read it. FAST and BALANCED probe different things, so two scans of one
        # host can legitimately disagree about which hosts exist - and without
        # this row the report gives the reader no way to tell why.
        ("Discovery profile", first("discovery_profile")),
        # No defaults here. These state what the scan was configured to do, and
        # a default is a claim: "Enabled (banner and probe fingerprinting)" was
        # printed for scans that performed no service detection at all, and an
        # OS line was inferred from whether any host happened to have an OS
        # recorded. The engines now publish these, so an unrecorded value means
        # the scan genuinely did not record it and the report says so.
        ("Service detection", first("service_detection", "version_detection")),
        ("OS fingerprinting", first("os_detection")),
        ("Timing profile", first("timing_template", "timing", "speed")),
        ("Scanner engine", first("scanner", "engine", "scan_engine")),
    ]

    # CVE-feed age, candidate counts and the QoD threshold only mean something
    # for a scan that matched against the vulnerability feed. Discovery and
    # asset-inventory scans do no such matching, so printing a feed date and a
    # detection-quality threshold implied an analysis that never ran.
    is_vuln_scan = _performs_vulnerability_analysis(scan_type)
    if is_vuln_scan:
        rows.append(("Vulnerability feed", _feed_freshness_text(meta)))

    rows.append(("Hosts scanned", _hosts_scanned_text(findings)))
    # "Fingerprinted" overstated this: the figure counts every reachable service
    # in the inventory, including the ones the report itself marks
    # "Not fingerprinted".
    rows.append(("Services inventoried", str(total_services)))

    if is_vuln_scan:
        rows.append(
            (
                "Candidate matches evaluated",
                # The scan records this when it verifies, and that recorded
                # figure is authoritative: a report rebuilt from the database
                # later reads back only the findings that survived, so counting
                # what is in hand would understate what was actually examined.
                first(
                    "candidates_evaluated",
                    default=str(len(findings.excluded) + len(findings.vulnerabilities)),
                ),
            )
        )
        truncated_row = _truncated_searches_row(
            meta, summary, inputs["truncated_search_notes"]
        )
        if truncated_row is not None:
            rows.append(truncated_row)
        coverage = summary.get("network_plugin_coverage") or meta.get(
            "network_plugin_coverage"
        )
        if isinstance(coverage, dict) and coverage.get("recorded"):
            rows.append(
                (
                    "Network plugin coverage",
                    (
                        "Complete"
                        if coverage.get("complete")
                        else "Incomplete; absence of findings does not establish a clean assessment"
                    ),
                )
            )
            for outcome in coverage.get("incomplete", []):
                rows.append(
                    (
                        f"{outcome.get('host')} / {outcome.get('plugin')}",
                        f"{outcome.get('status')}: {outcome.get('detail', '')}",
                    )
                )
        rows.append(("Reporting QoD threshold", f"{QOD_REPORT_THRESHOLD}%"))

    # Rows a scan that authenticated adds to the above. They are appended only
    # when the scan recorded them: printing "Not recorded" against network
    # reachability on an ordinary port scan would imply the question applied.
    for key, label in inputs["coverage_rows"]:
        value = first(key, default="")
        if value:
            rows.append((label, value))

    # The assessment policy, in the methodology appendix beside the rest of the
    # scan's parameters. The full section is elsewhere; these three rows are
    # what a reader skimming the appendix needs to know the scan was scoped.
    #
    # Note the row above named "Scan policy" is the scan *type* label and
    # predates GAP-12. These are deliberately named differently rather than
    # replacing it: the two answer different questions, and silently changing
    # what an existing row means is worse than adding one.
    policy_meta = (meta.get("scan_policy") or {}) if isinstance(meta, dict) else {}
    if policy_meta.get("recorded"):
        rows.append(
            (
                "Assessment policy",
                policy_meta.get("policy_name") or "None (scan request defaults)",
            )
        )
        rows.append(
            ("Configuration ID", str(policy_meta.get("fingerprint") or "")[:16])
        )
        _psummary = policy_meta.get("summary") or {}
        for _label in ("Benchmarks", "Benchmark profile", "Severity threshold"):
            if _psummary.get(_label):
                rows.append((_label, str(_psummary[_label])))

    # Listener exposure, stated from the counts that were actually recorded.
    #
    # This line previously read "{exposed or 0} ... {host_only or 0} ...", which
    # did two things it must not. `or 0` turns an unrecorded count into a zero —
    # an assertion that none were found where the truth is that nobody counted —
    # and naming two of the four categories drops the listeners whose
    # reachability was never established out of a sentence whose entire job is
    # to add up. `exposure_sentence` omits a clause it has no number for and
    # names the undetermined ones explicitly.
    exposure = ListenerExposure(
        total=_first_int(meta, summary, "listeners_total"),
        exposed=_first_int(meta, summary, "listeners_exposed"),
        host_only=_first_int(meta, summary, "listeners_host_only"),
        filtered=_first_int(meta, summary, "listeners_filtered"),
        undetermined=_first_int(meta, summary, "listeners_undetermined"),
    )
    sentence = exposure_sentence(exposure)
    if sentence:
        rows.append(("Service exposure", sentence))
    return rows


def _first_int(meta: dict, summary: dict, key: str) -> Optional[int]:
    """Read an integer that either the metadata or the summary may carry."""
    for source in (meta, summary):
        if not isinstance(source, dict):
            continue
        value = source.get(key)
        if value in (None, ""):
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _scan_metadata_block(
    meta: dict, summary: dict, findings: ScanFindings, scan_type: str, styles: dict
) -> Table:
    """
    Scan provenance table.

    Every value is read from scan metadata. Where a value was not recorded the
    cell says so rather than defaulting to something that reads as fact — the
    authentication mode in particular must never claim "credentialed" unless
    the scan actually authenticated.
    """

    def value_or_unknown(*keys, default="Not recorded") -> str:
        for key in keys:
            candidate = meta.get(key) or summary.get(key)
            if candidate not in (None, "", []):
                return str(candidate)
        return default

    credentialed_hosts = [h for h in findings.reachable_hosts if h.credentialed]
    if credentialed_hosts and len(credentialed_hosts) == len(findings.reachable_hosts):
        auth_mode = "Authenticated (credentialed audit)"
    elif credentialed_hosts:
        auth_mode = (
            f"Mixed — {len(credentialed_hosts)} of {len(findings.reachable_hosts)} hosts "
            f"scanned with credentials"
        )
    elif meta.get("is_credentialed") is True:
        auth_mode = "Authenticated (credentialed audit)"
    else:
        auth_mode = "Unauthenticated network scan"

    target = value_or_unknown("target", "original_targets", default="Not recorded")
    if isinstance(target, list):
        target = ", ".join(str(t) for t in target)
    if len(target) > 90:
        target = target[:87] + "..."

    duration = meta.get("duration_seconds") or summary.get("scan_duration")
    if duration:
        try:
            seconds = float(duration)
            duration_text = (
                f"{seconds:.0f} seconds"
                if seconds < 90
                else f"{seconds / 60:.1f} minutes"
            )
        except (TypeError, ValueError):
            duration_text = str(duration)
    else:
        duration_text = "Not recorded"

    feed_text = _feed_freshness_text(meta)
    scan_reference = _scan_reference_text(meta)

    pairs = [
        ("Scan reference", scan_reference),
        ("Target scope", target),
        (
            "Scan policy",
            SCAN_POLICY_LABELS.get(
                str(scan_type).lower(), str(scan_type).replace("_", " ").title()
            ),
        ),
        (
            "Discovery method",
            DISCOVERY_METHOD_LABELS.get(
                str(
                    meta.get("scan_method") or meta.get("discovery_scan_method") or ""
                ).lower(),
                value_or_unknown("scan_method", "discovery_scan_method"),
            ),
        ),
        ("Authentication mode", auth_mode),
        # Count hosts that answered. Counting every probed target reported a
        # host as discovered when the scan had in fact found nothing there.
        ("Hosts reported", _hosts_reported_text(findings)),
        ("Scan duration", duration_text),
        # Only meaningful when the scan actually consulted the CVE feed — see
        # _performs_vulnerability_analysis().
        *(
            [("Vulnerability feed", feed_text)]
            if _performs_vulnerability_analysis(scan_type)
            else []
        ),
        ("Report generated", datetime.now().strftime("%d %b %Y %H:%M:%S")),
        ("Classification", "CONFIDENTIAL / RESTRICTED"),
    ]

    rows = []
    for index in range(0, len(pairs), 2):
        chunk = pairs[index : index + 2]
        row = []
        for label, value in chunk:
            row.append(_p(f"<b>{label}</b>", styles["body"], escape=False))
            colour = "#B91C1C" if label == "Classification" else None
            if colour:
                row.append(
                    _p(
                        f"<font color='{colour}'><b>{value}</b></font>",
                        styles["body"],
                        escape=False,
                    )
                )
            else:
                row.append(_p(value, styles["body"]))
        while len(row) < 4:
            row.append(_p("", styles["body"]))
        rows.append(row)

    table = Table(rows, colWidths=[36 * mm, 52 * mm, 38 * mm, 48 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), BG_ALT),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, BORDER),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table


def _kpi_row(counts: Dict[str, int], styles: dict) -> Table:
    """
    The severity strip. Shows the four scored tiers, plus an Unscored cell only
    when findings actually lack a published score — an always-present fifth cell
    invited readers to add it into the vulnerability total.
    """
    tiers = ["Critical", "High", "Medium", "Low"]
    labels = {"Unscored": "UNSCORED"}
    if counts.get("Unscored", 0):
        tiers.append("Unscored")

    data = [
        [_p(str(counts.get(t, 0)), styles["kpi_num"]) for t in tiers],
        [_p(labels.get(t, t.upper()), styles["kpi_lbl"]) for t in tiers],
    ]
    width = CONTENT_W / len(tiers)
    table = Table(data, colWidths=[width] * len(tiers))

    commands = [
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, 0), 6),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 6),
        ("INNERGRID", (0, 0), (-1, -1), 1.2, WHITE),
        ("BOX", (0, 0), (-1, -1), 1.2, WHITE),
    ]
    for index, tier in enumerate(tiers):
        commands.append(
            ("BACKGROUND", (index, 0), (index, -1), SEVERITY_FG.get(tier, MUTED))
        )
    table.setStyle(TableStyle(commands))
    return table


def _severity_badge(severity: str, styles: dict) -> Paragraph:
    colour = SEVERITY_FG.get(severity, MUTED)
    return _p(
        f"<font color='{colour.hexval()}'><b>{severity}</b></font>",
        styles["body"],
        escape=False,
    )


def _confidence_badge(finding: StandardizedFinding, styles: dict) -> Paragraph:
    colour = CONFIDENCE_COLOR.get(finding.confidence, MUTED)
    return _p(
        f"<font color='{colour.hexval()}'><b>{finding.confidence.value}</b></font>",
        styles["body"],
        escape=False,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Remediation planning
# ─────────────────────────────────────────────────────────────────────────────


def _remediation_plan(findings: ScanFindings) -> List[Dict[str, Any]]:
    """
    Group findings by remediation action, ranked by risk eliminated.

    Mirrors how commercial scanners present remediation: one action that clears
    thirty findings outranks thirty separate single-CVE entries.
    """
    groups: Dict[Any, Dict[str, Any]] = {}

    for finding in findings.vulnerabilities:
        remediation = finding.remediation
        if not remediation or not remediation.is_actionable:
            continue

        # Group by the upgrade target, not by the remediation prose. The prose
        # names the CVE it came from, so using it as the key gives every
        # finding its own row and the "plan" degenerates into a CVE list —
        # "Upgrade PostgreSQL to 14.23" appearing five times instead of once
        # against five findings.
        # Roll up to one action per product. Upgrading OpenSSH to 10.4 also
        # clears everything fixed in 9.6, 9.8, 10.0 and 10.3, so listing those
        # as five separate actions overstates the work: an administrator
        # performs a single upgrade. The group therefore tracks the highest
        # boundary any of its findings requires.
        product = (remediation.product or "").strip()
        # The boundary an upgrade must reach: a first fixed release, or — when
        # only an inclusive bound is published — the last affected one.
        boundary = remediation.fixed_version or remediation.last_affected_version
        is_last = not remediation.fixed_version and bool(boundary)
        if product and boundary:
            key: Any = product.lower()
        else:
            key = remediation.summary.strip()

        entry = groups.setdefault(
            key,
            {
                "action": remediation.summary.strip(),
                "product": product,
                "confidence": remediation.confidence,
                "patch_url": remediation.patch_url,
                "fixed_version": boundary,
                "boundary_is_last_affected": is_last,
                "findings": [],
                "hosts": set(),
                "max_rank": 0,
                "max_severity": "Unscored",
                "kev": False,
                "kev_confirmed": False,
                "max_epss": 0.0,
            },
        )
        entry["findings"].append(finding)
        entry["hosts"].add(finding.host)
        if finding.severity_rank > entry["max_rank"]:
            entry["max_rank"] = finding.severity_rank
            entry["max_severity"] = finding.severity
        if finding.in_kev:
            entry["kev"] = True
            if not _unconfirmed(finding):
                entry["kev_confirmed"] = True
        if finding.epss_score and finding.epss_score > entry["max_epss"]:
            entry["max_epss"] = finding.epss_score

        # Keep the highest boundary seen; that is the one upgrade that
        # satisfies every finding in the group.
        if boundary and boundary_key(boundary, is_last) > boundary_key(
            entry.get("fixed_version") or "", entry["boundary_is_last_affected"]
        ):
            entry["fixed_version"] = boundary
            entry["boundary_is_last_affected"] = is_last

    # Restate each grouped action in terms of the upgrade rather than the CVE
    # that happened to be seen first, and name what the upgrade clears.
    for entry in groups.values():
        count = len(entry["findings"])
        if entry["product"] and entry["fixed_version"] and count > 1:
            cves = sorted({f.primary_cve for f in entry["findings"] if f.primary_cve})
            shown = ", ".join(cves[:8])
            if len(cves) > 8:
                shown += f", and {len(cves) - 8} more"
            target = (
                upgrade_target(None, entry["fixed_version"])
                if entry["boundary_is_last_affected"]
                else upgrade_target(entry["fixed_version"])
            )
            entry["action"] = (
                f"Upgrade {entry['product']} to {target}. "
                f"This single upgrade clears all {count} findings recorded against "
                f"this component: {shown}. Version boundaries are taken from the "
                f"CPE ranges published for those CVEs."
            )

    plan = list(groups.values())
    plan.sort(
        key=lambda e: (
            e["kev_confirmed"],
            e["kev"],
            e["max_rank"],
            len(e["findings"]),
            e["max_epss"],
            len(e["hosts"]),
        ),
        reverse=True,
    )
    return plan


# ─────────────────────────────────────────────────────────────────────────────
# Finding card
# ─────────────────────────────────────────────────────────────────────────────


def _cvss_cell(finding: StandardizedFinding, styles: dict) -> Paragraph:
    """Render the score with its provenance, or state that none is published."""
    cvss = finding.cvss
    if cvss is None or cvss.score is None:
        return _p(
            "<b>Not scored</b><br/><font size='6.6' color='#64748B'>"
            "No CVSS score is published for this record.</font>",
            styles["body"],
            escape=False,
        )

    label = f"v{cvss.version}" if cvss.version else ""
    parts = [f"<b>{cvss.score}</b> <font size='6.8' color='#64748B'>{label}</font>"]

    if cvss.vector_string:
        # display_vector drops the undefined (":X") threat/environmental
        # metrics that every published v4.0 vector carries.
        parts.append(
            f"<font size='6.4' color='#475569'>"
            f"{escape_for_reportlab(cvss.display_vector)}</font>"
        )
    else:
        parts.append("<font size='6.4' color='#94A3B8'>No vector published</font>")

    return _p("<br/>".join(parts), styles["body"], escape=False)


def _unconfirmed(finding: StandardizedFinding) -> bool:
    """
    Whether the scan could not confirm this finding applies to the host.

    A known-exploited CVE is shown even when unconfirmed — omitting one that is
    being exploited costs more than one line to verify — but it must say so.
    The executive table listed an nginx CVE whose version was never detected
    (10.180.6.30, 12 Oct 2026) exactly like a confirmed one.
    """
    return finding.confidence != Confidence.CONFIRMED


#: Appended wherever an unconfirmed known-exploited finding is listed.
UNCONFIRMED_KEV_NOTE = "not confirmed on this host — verify the version first"


def _threat_intel_cell(finding: StandardizedFinding, styles: dict) -> Paragraph:
    bits: List[str] = []
    if finding.in_kev:
        due = (
            f" (remediate by {escape_for_reportlab(finding.kev_due_date)})"
            if finding.kev_due_date
            else ""
        )
        bits.append(
            f"<font color='#B91C1C'><b>CISA KEV — actively exploited</b></font>{due}"
            + (f"; <i>{UNCONFIRMED_KEV_NOTE}</i>" if _unconfirmed(finding) else "")
        )
    if finding.epss_score is not None:
        # The percentile is a rank, not a probability. Rendering it as
        # "top {100 - percentile}%" produced "(top 0%)" for the most exploitable
        # finding in the set and "(top 98%)" for the least — both meaningless.
        # State the rank plainly, and only flag membership in a leading band.
        percentile = ""
        if finding.epss_percentile is not None:
            rank = finding.epss_percentile * 100
            percentile = f" · {_ordinal(rank)} percentile"
            if rank >= 90:
                percentile += f" (top {max(100 - rank, 0.1):.1f}% of all CVEs)"
        bits.append(
            f"EPSS <b>{finding.epss_score * 100:.1f}%</b> "
            f"30-day exploitation probability{percentile}"
        )
    # Exploit availability, three-valued.
    #
    # The label is deliberately "availability" and not "exploitable". A public
    # exploit existing for the CVE says nothing about whether *this host* can
    # be exploited, which depends on configuration and reachability no feed
    # knows anything about - so "Exploitable" or "Confirmed exploitation" would
    # be a claim the evidence does not support.
    #
    # `None` adds no line at all. It means the scan recorded nothing, and
    # printing "no public exploit" on that basis states a negative finding on
    # the strength of never having looked.
    if finding.has_exploit is True:
        bits.append(
            "<b>Exploit availability:</b> a public exploit exists for this "
            "vulnerability <font color='#64748B'>(not a statement that this "
            "host is exploitable)</font>"
        )
    elif finding.has_exploit is False:
        bits.append(
            "<b>Exploit availability:</b> no public exploit known to the "
            "exploit feeds"
        )

    if not bits:
        bits.append("<font color='#94A3B8'>No exploit intelligence available</font>")
    return _p("<br/>".join(bits), styles["body"], escape=False)


#: Reference classification. Ordered most to least actionable for someone who
#: has to fix the finding: a vendor advisory names the patch, an exploit link
#: only proves urgency, and the NVD page merely restates what is already on the
#: card. Previously every reference was printed unlabelled in feed order, so
#: the one link that mattered could sit below three that did not.
_REFERENCE_KINDS = (
    (
        "Vendor advisory",
        (
            "security-advisories",
            "security_advisory",
            "/advisories/",
            "advisory",
            "security-bulletin",
            "securitybulletin",
            "msrc.microsoft.com",
            "access.redhat.com/errata",
            "ubuntu.com/security/notices",
            "debian.org/security",
            "lists.",
            "openwall.com",
            "seclists.org",
        ),
    ),
    (
        "Patch / commit",
        (
            "commit",
            "/pull/",
            "patch",
            "git.",
            "changeset",
            "changelog",
        ),
    ),
    (
        "Vendor page",
        (
            "release-notes",
            "releasenotes",
            "/download",
            "/support/",
        ),
    ),
    (
        "Issue tracker",
        (
            "bugzilla",
            "/issues/",
            "jira",
            "tracker",
        ),
    ),
    (
        "Exploit",
        (
            "exploit-db.com",
            "packetstormsecurity",
            "metasploit",
            "github.com/rapid7",
        ),
    ),
    (
        "Catalogue",
        (
            "nvd.nist.gov",
            "cve.org",
            "cve.mitre.org",
            "cvedetails",
        ),
    ),
)


def _classify_reference(url: str) -> tuple:
    """Return ``(rank, label)`` for a reference URL."""
    lowered = url.lower()
    for rank, (label, markers) in enumerate(_REFERENCE_KINDS):
        if any(marker in lowered for marker in markers):
            return rank, label
    return len(_REFERENCE_KINDS), "Reference"


def _ordered_references(references: List[str], limit: int = 6) -> List[tuple]:
    """
    Deduplicate and sort references so remediation-bearing links come first.

    Returns ``[(label, url), ...]`` capped at ``limit``.
    """
    seen = set()
    ranked = []
    for url in references:
        clean = str(url).strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        rank, label = _classify_reference(clean)
        ranked.append((rank, label, clean))
    ranked.sort(key=lambda item: item[0])
    return [(label, url) for _, label, url in ranked[:limit]]


#: Disclosures that describe the tool rather than an individual finding. These
#: are stated once in Appendix A instead of being repeated on every card.
_GLOBAL_DISCLOSURE_MARKERS = ("does not independently recompute v4.0 scores",)


def _is_global_disclosure(warning: str) -> bool:
    return any(marker in warning for marker in _GLOBAL_DISCLOSURE_MARKERS)


#: Colour and wording for each attack-surface classification.
_SURFACE_DISPLAY = {
    "remote": ("#B91C1C", "Network-reachable service"),
    "client": ("#B45309", "Client-side component"),
    "local": ("#B45309", "Requires local access"),
}


def _attack_surface_cell(finding: StandardizedFinding, styles: dict) -> Paragraph:
    """State whether the open port is really the attack path for this CVE."""
    colour, label = _SURFACE_DISPLAY.get(
        finding.attack_surface, _SURFACE_DISPLAY["remote"]
    )
    return _p(f"<font color='{colour}'>{label}</font>", styles["body"], escape=False)


def _published_label(finding: StandardizedFinding) -> str:
    """
    CVE publication date plus its age.

    Age is what turns a date into a decision: a Critical published four years
    ago that is still open says something different about the patch process
    than one published last week.
    """
    published = _date_only(finding.published_at)
    if not published:
        return "<font color='#94A3B8'>Not published in feed</font>"

    age = _age_in_days(finding.published_at)
    if age is None:
        return escape_for_reportlab(published)

    if age < 30:
        human = f"{age} days old"
    elif age < 365:
        human = f"{age // 30} month(s) old"
    else:
        years = age / 365.25
        human = f"{years:.1f} years old"

    colour = "#B91C1C" if age >= 365 else "#64748B"
    return (
        f"{escape_for_reportlab(published)}<br/>"
        f"<font size='6.6' color='{colour}'>{human}</font>"
    )


def _cwe_label(finding: StandardizedFinding) -> str:
    """CWE identifiers, linked to their MITRE catalogue entry."""
    parts = []
    for cwe in finding.cwe_ids:
        safe = escape_for_reportlab(cwe)
        number = cwe.split("-")[-1] if "-" in cwe else ""
        if number.isdigit():
            url = f"https://cwe.mitre.org/data/definitions/{number}.html"
            parts.append(f"<link href='{url}' color='#1D4ED8'>{safe}</link>")
        else:
            parts.append(safe)
    return ", ".join(parts)


def _finding_group_card(group, styles: dict) -> List[Any]:
    """
    One card for the set of findings a single upgrade resolves.

    States the count, what the upgrade clears, and everything a reader needs to
    prioritise it — worst severity, severity spread, anything known-exploited,
    the highest exploitation probability — without printing one card per CVE.
    """
    lead = group.representative
    fg = SEVERITY_FG.get(group.severity, MUTED)
    story: List[Any] = []

    badge = group.severity.upper()
    if group.kev_findings:
        badge = f"KEV · {badge}"

    title = (
        f"{escape_for_reportlab(group.product)} — "
        f"{len(group.findings)} known vulnerabilities"
    )
    header = Table(
        [
            [
                Paragraph(
                    f"<font color='white'><b>{title}</b></font>", styles["body_bold"]
                ),
                Paragraph(
                    f"<font color='white'><b>{badge}</b></font>",
                    ParagraphStyle(
                        "ghdr_r", parent=styles["body_bold"], alignment=TA_RIGHT
                    ),
                ),
            ]
        ],
        colWidths=[CONTENT_W - 40 * mm, 40 * mm],
    )
    header.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), fg),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.append(header)

    spread = ", ".join(
        f"{count} {tier}"
        for tier, count in sorted(
            group.severity_counts.items(),
            key=lambda item: SEVERITY_RANK.get(item[0], 0),
            reverse=True,
        )
    )
    worst_epss = group.max_epss
    epss_text = (
        f"{worst_epss.epss_score * 100:.1f}% ({worst_epss.primary_cve})"
        if worst_epss and worst_epss.epss_score
        else "Not published in feed"
    )
    meta_rows = [
        [
            _p("<b>Findings grouped</b>", styles["body"], escape=False),
            _p(f"{len(group.findings)} CVEs, one upgrade", styles["body"]),
            _p("<b>Affected port</b>", styles["body"], escape=False),
            _p(lead.port_label, styles["body"]),
        ],
        [
            _p("<b>Severity spread</b>", styles["body"], escape=False),
            _p(spread or "Unscored", styles["body"]),
            _p("<b>Detected version</b>", styles["body"], escape=False),
            _p(lead.detected_version or "Not determined", styles["body"]),
        ],
        [
            _p("<b>Highest exploitation</b>", styles["body"], escape=False),
            _p(epss_text, styles["body"]),
            _p("<b>Known exploited</b>", styles["body"], escape=False),
            _p(
                (
                    ", ".join(f.primary_cve for f in group.kev_findings[:4])
                    if group.kev_findings
                    else "None in this group"
                ),
                styles["body"],
            ),
        ],
    ]
    story.append(_grid(meta_rows, [34 * mm, 54 * mm, 34 * mm, 54 * mm], header=False))
    story.append(Spacer(1, 3))

    cves = group.cve_ids
    shown = ", ".join(cves[:18])
    if len(cves) > 18:
        shown += f", and {len(cves) - 18} more (full list in the CSV export)"
    story.append(
        _p(f"<b>Covered by this upgrade:</b> {shown}", styles["small"], escape=False)
    )
    story.append(Spacer(1, 3))

    remediation = lead.remediation
    if remediation:
        story.append(
            _boxed(
                _p(
                    f"<b>Remediation:</b><br/>Upgrade {escape_for_reportlab(group.product)} "
                    f"to {escape_for_reportlab(group.upgrade_target)}. This single "
                    f"action resolves all {len(group.findings)} findings listed above.",
                    styles["body"],
                    escape=False,
                ),
                colors.HexColor("#F0FDF4"),
                colors.HexColor("#86EFAC"),
            )
        )
    story.append(Spacer(1, 6))
    return story


#: Order the comparison table lists its classes in. Deliberately not the order
#: the counts dict happens to iterate: a reader looks for "new" first and
#: "not assessed" last, and a table whose row order moves between reports is
#: one nobody can skim.
_COMPARISON_ROWS = (
    ("new", "New", "Open now and not open at the baseline"),
    ("still_open", "Still open", "Open in both scans"),
    ("fixed", "Fixed", "Was open, this scan looked and did not find it"),
    ("reappeared", "Reappeared", "Was fixed and has come back"),
    (
        "not_assessed",
        "Not assessed",
        "Was open; this scan did not assess the check, so it is NOT reported fixed",
    ),
    (
        "ruled_out",
        "Ruled out",
        "Was open; this scan established it never applied, so it is NOT reported fixed",
    ),
)


#: How a remediation state reads to somebody who did not design it, and what
#: it is *not*. The second half of each pair matters more than the first: an
#: auditor reading "Pending verification" needs to know the product has a
#: claim, not a confirmation.
REMEDIATION_STATE_LABELS = {
    "open": ("Open", "No remediation work has started"),
    "assigned": ("Assigned", "An owner is accountable; work has not started"),
    "in_remediation": ("In remediation", "Work is under way"),
    "pending_verification": (
        "Pending verification",
        "A fix has been applied but NO scan has yet confirmed it",
    ),
    "verified_fixed": (
        "Verified fixed",
        "A subsequent scan assessed the check and found it gone",
    ),
    "reopened": (
        "Reopened",
        "Was verified fixed; a later scan found it again",
    ),
    "risk_accepted": ("Risk accepted", "Carried deliberately, with a reason"),
}

SLA_STATE_LABELS = {
    "within_sla": "Within SLA",
    "due_soon": "Due soon",
    "overdue": "OVERDUE",
    "resolved": "Resolved",
    "pending_verification": "Awaiting verification",
    "not_applicable": "No deadline applies",
}


def _remediation_summary_line(remediation) -> str:
    """
    The one-line executive figure.

    Assembled from counts the API produced, never recomputed here — a report
    and a dashboard disagreeing about how many findings are overdue is worse
    than either number being slightly stale.
    """
    if not isinstance(remediation, dict) or not remediation:
        return ""
    by_state = remediation.get("by_state") or {}
    return (
        f"Open: {by_state.get('open', 0)} | "
        f"In remediation: {by_state.get('in_remediation', 0)} | "
        f"Pending verification: {by_state.get('pending_verification', 0)} | "
        f"Overdue: {remediation.get('overdue', 0)} | "
        f"Verified fixed: {by_state.get('verified_fixed', 0)}"
    )


def _remediation_section(remediation, styles) -> List[Any]:
    """
    The remediation and SLA section.

    **The gap is not closed unless this is in the report.** An auditor has to
    be able to answer, from the artefact in front of them, who owns a finding,
    when it is due, whether it is late, and — the part that makes the rest
    mean anything — whether a fix was *confirmed by an assessment* or merely
    claimed by a person.

    Returns an empty list when the scan carries no remediation data, so a
    report generated for a scan that predates this phase is byte-for-byte what
    it was before — the property `_comparison_section` and `_policy_section`
    both preserve, and for the same reason.
    """
    if not isinstance(remediation, dict) or not remediation:
        return []

    story: List[Any] = [_heading("Remediation and SLA", styles["h1"], 0)]

    line = _remediation_summary_line(remediation)
    if line:
        story.append(_p(escape_for_reportlab(line), styles["body"]))
        story.append(Spacer(1, 3 * mm))

    by_state = remediation.get("by_state") or {}
    rows = [
        [
            _p("<b>State</b>", styles["th"], escape=False),
            _p("<b>Count</b>", styles["th"], escape=False),
            _p("<b>What it means</b>", styles["th"], escape=False),
        ]
    ]
    for state, (label, meaning) in REMEDIATION_STATE_LABELS.items():
        count = int(by_state.get(state, 0) or 0)
        if not count:
            continue
        rows.append(
            [
                _p(label, styles["body"]),
                _p(str(count), styles["body"]),
                _p(meaning, styles["body"]),
            ]
        )
    if len(rows) > 1:
        story.append(_grid(rows, [36 * mm, 18 * mm, 107 * mm]))
        story.append(Spacer(1, 3 * mm))

    overdue = int(remediation.get("overdue", 0) or 0)
    within = int(remediation.get("within_sla", 0) or 0)
    no_sla = int(remediation.get("no_sla", 0) or 0)
    story.append(
        _p(
            f"<b>SLA:</b> {overdue} overdue, {within} within their deadline, "
            f"{no_sla} carrying no deadline. Deadlines are calendar days from "
            f"the date a finding was first seen; rediscovering a finding does "
            f"not restart its clock.",
            styles["body"],
            escape=False,
        )
    )

    # The verification result of this scan, if it ran one. This is the
    # sentence that distinguishes a report where fixes were confirmed from one
    # where nothing could be confirmed because the scan did not look.
    verification = remediation.get("verification") or {}
    if verification:
        story.append(Spacer(1, 3 * mm))
        if not verification.get("comparison_usable", True):
            story.append(
                _p(
                    "<b>No remediation was verified by this scan.</b> "
                    + escape_for_reportlab(str(verification.get("reason") or "")),
                    styles["body"],
                    escape=False,
                )
            )
        else:
            withheld = int(verification.get("withheld_count", 0) or 0)
            text = (
                f"<b>This scan verified {verification.get('verified_count', 0)} "
                f"remediation(s)</b> and reopened "
                f"{verification.get('reopened_count', 0)}."
            )
            if withheld:
                # Said out loud rather than omitted. A reader told "8 verified"
                # and not told "40 could not be" has a number implying progress
                # the scan did not establish.
                text += (
                    f" {withheld} finding(s) could <b>not</b> be verified "
                    "because this scan did not assess the relevant check; "
                    "they remain open."
                )
            story.append(_p(text, styles["body"], escape=False))

    story.append(Spacer(1, 3 * mm))
    story.append(
        _p(
            "A finding is reported as <b>verified fixed</b> only when a "
            "subsequent assessment actually examined the relevant check and "
            "found it gone. A fix reported by a person, with no assessment "
            "behind it, is shown as <b>pending verification</b> and is not "
            "counted as remediated.",
            styles["body"],
            escape=False,
        )
    )

    # Who owns what, where the scan supplied it.
    owners = remediation.get("by_owner") or []
    if owners:
        story.append(Spacer(1, 3 * mm))
        story.append(_heading("Ownership", styles["h2"], 1))
        owner_rows = [
            [
                _p("<b>Owner</b>", styles["th"], escape=False),
                _p("<b>Open</b>", styles["th"], escape=False),
                _p("<b>Overdue</b>", styles["th"], escape=False),
            ]
        ]
        for entry in owners[:20]:
            owner_rows.append(
                [
                    _p(str(entry.get("owner") or "Unassigned"), styles["body"]),
                    _p(str(entry.get("open", 0)), styles["body"]),
                    _p(str(entry.get("overdue", 0)), styles["body"]),
                ]
            )
        story.append(_grid(owner_rows, [101 * mm, 30 * mm, 30 * mm]))

    # The findings an auditor would ask about first.
    rows_detail = remediation.get("findings") or []
    if rows_detail:
        story.append(Spacer(1, 3 * mm))
        story.append(_heading("Findings under remediation", styles["h2"], 1))
        detail = [
            [
                _p("<b>Finding</b>", styles["th"], escape=False),
                _p("<b>Sev</b>", styles["th"], escape=False),
                _p("<b>Owner</b>", styles["th"], escape=False),
                _p("<b>Due</b>", styles["th"], escape=False),
                _p("<b>SLA</b>", styles["th"], escape=False),
                _p("<b>Remediation</b>", styles["th"], escape=False),
            ]
        ]
        for entry in rows_detail[:25]:
            rem = entry.get("remediation") or {}
            sla = entry.get("sla") or {}
            state = str(rem.get("state") or "open")
            detail.append(
                [
                    _p(str(entry.get("vuln_id") or ""), styles["body"]),
                    _p(str(entry.get("severity") or ""), styles["body"]),
                    _p(str(rem.get("owner") or "—"), styles["body"]),
                    _p(str(sla.get("due_at") or "—")[:10], styles["body"]),
                    _p(
                        SLA_STATE_LABELS.get(
                            str(sla.get("state") or ""), str(sla.get("state") or "")
                        ),
                        styles["body"],
                    ),
                    _p(
                        REMEDIATION_STATE_LABELS.get(state, (state, ""))[0],
                        styles["body"],
                    ),
                ]
            )
        story.append(
            _grid(detail, [42 * mm, 16 * mm, 32 * mm, 22 * mm, 22 * mm, 27 * mm])
        )

    return story


def _policy_label(policy) -> str:
    """A short human name for a recorded policy, for a sentence in the report."""
    if not isinstance(policy, dict) or not policy.get("recorded"):
        return "was not recorded"
    name = policy.get("policy_name")
    fingerprint = str(policy.get("fingerprint") or "")[:16]
    if name:
        version = policy.get("version_number")
        suffix = f" v{version}" if version else ""
        return f"used policy {name}{suffix} ({fingerprint})"
    return f"used the scan request defaults ({fingerprint})"


def _policy_section(policy, styles) -> List[Any]:
    """
    The assessment policy section: what this scan was configured to assess.

    **The gap is not closed unless this is in the report.** An auditor reading
    a finding list has to be able to answer "what was actually assessed" from
    the artefact in front of them, not by asking somebody to query a database.
    A report that shows only what was found, with no statement of what was
    looked for, cannot distinguish a clean estate from a narrow scan.

    Returns an empty list when the scan carries no snapshot, so a report
    generated for a scan that predates this phase is byte-for-byte what it was
    before -- the same property ``_comparison_section`` preserves and for the
    same reason.
    """
    if not isinstance(policy, dict) or not policy or not policy.get("recorded"):
        return []

    story: List[Any] = [_heading("Assessment policy", styles["h1"], 0)]

    source = str(policy.get("source") or "request")
    if source == "policy":
        story.append(
            _p(
                "This scan ran under a stored assessment policy. The "
                "configuration below is the one recorded against this scan and "
                "does not change if the policy is later edited.",
                styles["body"],
            )
        )
    else:
        # Stated rather than omitted. "No policy was selected" and "this report
        # does not show policies" are different facts and only the first is a
        # fact about the scan.
        story.append(
            _p(
                "No stored policy was selected for this scan. The configuration "
                "below is the scan request's own parameters, recorded so that "
                "later scans can be compared against it on equal terms.",
                styles["body"],
            )
        )

    summary = policy.get("summary") or {}
    rows = [
        [
            _p("<b>Setting</b>", styles["th"], escape=False),
            _p("<b>Value</b>", styles["th"], escape=False),
        ]
    ]
    for label, value in summary.items():
        rows.append(
            [
                _p(str(label), styles["body"]),
                _p(str(value), styles["body"]),
            ]
        )
    if len(rows) > 1:
        story.append(Spacer(1, 3 * mm))
        story.append(_grid(rows, [56 * mm, 105 * mm]))

    story.append(Spacer(1, 3 * mm))
    story.append(
        _p(
            "The <b>Configuration ID</b> above identifies this exact assessment "
            "configuration. Two scans sharing it were assessed the same way; "
            "two that do not were not, however similar their findings look.",
            styles["small"] if "small" in styles else styles["body"],
            escape=False,
        )
    )
    return story


def _comparison_section(comparison, styles) -> List[Any]:
    """
    The change-since-last-scan section.

    Returns an empty list when there is no comparison, so a report generated
    without one is byte-for-byte what it was before this section existed. That
    is the property to preserve: the delta is an addition, never a rewrite.
    """
    if not isinstance(comparison, dict) or not comparison:
        return []

    story: List[Any] = [_heading("Change since the previous scan", styles["h1"], 0)]

    baseline = comparison.get("baseline_scan_id") or "—"
    current = comparison.get("current_scan_id") or "—"
    story.append(
        _p(
            f"Comparing scan <b>{escape_for_reportlab(str(current))}</b> against "
            f"baseline <b>{escape_for_reportlab(str(baseline))}</b>.",
            styles["body"],
            escape=False,
        )
    )

    # GAP-12. Two scans of the same host are not equivalent assessments if
    # they were configured differently, and a delta between them partly
    # reflects that rather than a change in the estate. Said before the counts,
    # because a reader who sees "37 new" first has already drawn a conclusion.
    if comparison.get("current_policy") or comparison.get("baseline_policy"):
        current_pol = comparison.get("current_policy") or {}
        baseline_pol = comparison.get("baseline_policy") or {}
        if comparison.get("policies_match"):
            story.append(
                _p(
                    "Both scans ran under the same assessment configuration "
                    f"(<b>{escape_for_reportlab(str(current_pol.get('fingerprint') or '')[:16])}</b>), "
                    "so the changes below are changes in the estate.",
                    styles["body"],
                    escape=False,
                )
            )
        elif current_pol.get("recorded") and baseline_pol.get("recorded"):
            story.append(
                _p(
                    "<b>These two scans were assessed under different "
                    "configurations</b> — this scan "
                    f"{escape_for_reportlab(_policy_label(current_pol))}, the "
                    f"baseline {escape_for_reportlab(_policy_label(baseline_pol))}. "
                    "Some of the differences below reflect what was assessed "
                    "rather than what changed on the host.",
                    styles["body"],
                    escape=False,
                )
            )
        else:
            story.append(
                _p(
                    "The assessment configuration of at least one of these "
                    "scans was not recorded, so it cannot be confirmed that "
                    "both assessed the same things.",
                    styles["body"],
                )
            )

    if not comparison.get("comparable"):
        # Said plainly rather than shown as zeroes. A table of noughts reads as
        # "nothing changed", which is a different and much more reassuring
        # claim than "these two scans cannot be compared".
        story.append(
            _p(
                "<b>Not comparable.</b> "
                + escape_for_reportlab(str(comparison.get("reason") or "")),
                styles["body"],
                escape=False,
            )
        )
        return story

    summary = str(comparison.get("summary") or "")
    if summary:
        story.append(
            _p(f"<b>{escape_for_reportlab(summary)}</b>", styles["body"], escape=False)
        )
    story.append(Spacer(1, 3 * mm))

    counts = comparison.get("counts") or {}
    severity_counts = comparison.get("severity_counts") or {}
    rows = [
        [
            _p("<b>Change</b>", styles["th"], escape=False),
            _p("<b>Count</b>", styles["th"], escape=False),
            _p("<b>Crit</b>", styles["th"], escape=False),
            _p("<b>High</b>", styles["th"], escape=False),
            _p("<b>Med</b>", styles["th"], escape=False),
            _p("<b>Low</b>", styles["th"], escape=False),
            _p("<b>Meaning</b>", styles["th"], escape=False),
        ]
    ]
    for key, label, meaning in _COMPARISON_ROWS:
        by_sev = severity_counts.get(key) or {}
        rows.append(
            [
                _p(label, styles["body"]),
                _p(str(counts.get(key, 0)), styles["body"]),
                _p(str(by_sev.get("critical", 0)), styles["body"]),
                _p(str(by_sev.get("high", 0)), styles["body"]),
                _p(str(by_sev.get("medium", 0)), styles["body"]),
                _p(str(by_sev.get("low", 0)), styles["body"]),
                _p(meaning, styles["body"]),
            ]
        )
    story.append(
        _grid(
            rows,
            [26 * mm, 15 * mm, 12 * mm, 12 * mm, 12 * mm, 12 * mm, 72 * mm],
        )
    )
    story.append(Spacer(1, 4 * mm))

    scope = comparison.get("current_scope") or {}
    if scope.get("recorded"):
        story.append(
            _p(
                "Assessment scope for this scan: "
                + escape_for_reportlab(", ".join(scope.get("families") or []) or "none")
                + " across "
                + str(len(scope.get("assets") or []))
                + " host(s).",
                styles["body"],
                escape=False,
            )
        )
    else:
        story.append(
            _p(
                "This scan recorded no assessment scope, so no finding is "
                "reported as fixed: an absent finding cannot be told apart from "
                "one that was never looked for.",
                styles["body"],
            )
        )

    # Representative rows. Bounded, and the classes a reader acts on first.
    interesting = [
        f
        for f in (comparison.get("findings") or [])
        if f.get("classification") in ("new", "reappeared", "fixed")
    ][:15]
    if interesting:
        story.append(Spacer(1, 3 * mm))
        story.append(_heading("Representative changes", styles["h2"], 1))
        detail_rows = [
            [
                _p("<b>Change</b>", styles["th"], escape=False),
                _p("<b>Finding</b>", styles["th"], escape=False),
                _p("<b>Severity</b>", styles["th"], escape=False),
                _p("<b>Host</b>", styles["th"], escape=False),
            ]
        ]
        for f in interesting:
            detail_rows.append(
                [
                    _p(str(f.get("classification") or ""), styles["body"]),
                    _p(str(f.get("vuln_id") or ""), styles["body"]),
                    _p(str(f.get("severity") or ""), styles["body"]),
                    _p(str(f.get("asset_id") or ""), styles["body"]),
                ]
            )
        story.append(_grid(detail_rows, [24 * mm, 74 * mm, 20 * mm, 43 * mm]))
    return story


#: Colours for a hardening verdict. NOT_ASSESSED is grey rather than green:
#: it is not a milder pass, it is the absence of one.
_HARDENING_TONE = {
    "PASS": ("#F0FDF4", "#86EFAC"),
    "FAIL": ("#FEF2F2", "#FECACA"),
    "WARN": ("#FFF7ED", "#FDBA74"),
    "NOT_ASSESSED": ("#F1F5F9", "#CBD5E1"),
}


def _host_assessment_sections(record: HostAssessment, styles: dict) -> List[Any]:
    """
    What the authenticated session examined on this host, and what it could not.

    Three readings the credentialed pipeline has recorded for a long time and
    no report has ever printed. They share a section because they answer one
    question between them — *how much of this host was actually assessed* — and
    because each of them, left out, makes the page read more reassuring than
    the scan was.

    Returns an empty list when the scan recorded none of them, so a report for
    an unauthenticated scan is byte-for-byte what it was before. The same
    property `_comparison_section`, `_policy_section` and `_remediation_section`
    each hold, and for the same reason.
    """
    if record is None or not record.has_content:
        return []

    story: List[Any] = []

    # ── Hardening posture ────────────────────────────────────────────────────
    if record.hardening:
        story.append(_heading("Host hardening posture", styles["h2"], 1))

        counts = record.hardening_counts()
        unassessed = counts.get("NOT_ASSESSED", 0)
        # The count of controls nobody read is stated in the lede, not buried
        # in the table. A reader who takes in one line per section has to be
        # told that this one is partial.
        headline = " · ".join(
            f"{count} {status.replace('_', ' ').lower()}"
            for status, count in sorted(counts.items())
            if count
        )
        story.append(
            _p(
                f"{headline}."
                + (
                    " A control this scan did not read carries no verdict: it is "
                    "reported as not assessed rather than as a pass."
                    if unassessed
                    else ""
                ),
                styles["small"],
            )
        )
        story.append(Spacer(1, 2 * mm))

        rows = [
            [
                _p("<b>Control</b>", styles["th"], escape=False),
                _p("<b>Verdict</b>", styles["th"], escape=False),
                _p("<b>What the scan established</b>", styles["th"], escape=False),
            ]
        ]
        for control in record.hardening_sorted():
            verdict = control.status.replace("_", " ")
            # The detail is the collector's own sentence. Where it is missing,
            # the verdict's meaning is printed instead of an empty cell - an
            # empty cell beside "NOT ASSESSED" reads as a missing value rather
            # than as the state itself.
            rows.append(
                [
                    _p(escape_for_reportlab(control.label), styles["body"]),
                    _p(escape_for_reportlab(verdict), styles["body"]),
                    _p(
                        escape_for_reportlab(control.detail or control.meaning),
                        styles["body"],
                    ),
                ]
            )
        story.append(_grid(rows, [42 * mm, 26 * mm, 93 * mm]))
        story.append(Spacer(1, 4 * mm))

    # ── Collection failures ──────────────────────────────────────────────────
    #
    # The section that stops a failed collection reading as a clean host. A
    # host whose package inventory could not be read produces no package
    # findings, and on the page that is byte-identical to a host with nothing
    # wrong with it.
    if record.collection_failures:
        story.append(_heading("Data this scan could not collect", styles["h2"], 1))

        attempted = [f for f in record.collection_failures if not f.is_unserved_item]
        unserved = [f for f in record.collection_failures if f.is_unserved_item]

        if attempted:
            story.append(
                _p(
                    "These sections were attempted and failed. Anything they "
                    "would have reported is <b>not assessed</b> on this host — "
                    "it is not an absence of findings.",
                    styles["small"],
                    escape=False,
                )
            )
            story.append(Spacer(1, 2 * mm))
            rows = [
                [
                    _p("<b>Collection section</b>", styles["th"], escape=False),
                    _p("<b>Reason reported</b>", styles["th"], escape=False),
                ]
            ]
            for failure in sorted(attempted, key=lambda f: f.display_section):
                rows.append(
                    [
                        _p(
                            escape_for_reportlab(failure.display_section),
                            styles["body"],
                        ),
                        _p(
                            escape_for_reportlab(failure.reason)
                            or "No reason was recorded.",
                            styles["body"],
                        ),
                    ]
                )
            story.append(_grid(rows, [52 * mm, 109 * mm]))
            story.append(Spacer(1, 3 * mm))

        if unserved:
            # A different statement from a failure: the transport used here
            # structurally does not serve these items. Merging the two would
            # make a transport's known limits read as a broken scan.
            story.append(
                _p(
                    "<b>Not served by the transport used:</b> "
                    + escape_for_reportlab(
                        ", ".join(
                            sorted(failure.display_section for failure in unserved)
                        )
                    )
                    + ". These were not attempted on this host, so nothing is "
                    "claimed about them either way.",
                    styles["small"],
                    escape=False,
                )
            )
            story.append(Spacer(1, 3 * mm))

    if record.inventory_complete is False:
        story.append(
            _boxed(
                _p(
                    "<b>The software inventory for this host is incomplete.</b> "
                    "Package-based findings below cover what was collected, not "
                    "everything installed.",
                    styles["small"],
                    escape=False,
                ),
                colors.HexColor("#FEF9C3"),
                colors.HexColor("#FDE047"),
            )
        )
        story.append(Spacer(1, 3 * mm))

    # ── Listener exposure, including the undetermined ones ───────────────────
    sentence = exposure_sentence(record.exposure)
    if sentence:
        story.append(_heading("Listening service exposure", styles["h2"], 1))
        story.append(_p(escape_for_reportlab(sentence), styles["body"]))
        if record.exposure.has_undetermined:
            # Named, and deliberately not resolved in either direction. A
            # listener the scan never reached is not thereby filtered, and it
            # is certainly not exposed.
            story.append(
                _p(
                    "A listener whose reachability was not established is "
                    "reported as such. It is neither exposed nor filtered — the "
                    "scan did not probe the port, so nothing was learned about "
                    "it in either direction.",
                    styles["small"],
                )
            )
        if record.exposure.correlated is False:
            story.append(
                _p(
                    "No network port scan ran alongside this authenticated pass, "
                    "so reachability was not correlated for any listener.",
                    styles["small"],
                )
            )
        story.append(Spacer(1, 4 * mm))

    return story


def _finding_card(finding: StandardizedFinding, styles: dict) -> List[Any]:
    fg = SEVERITY_FG.get(finding.severity, MUTED)

    # ── Title bar ────────────────────────────────────────────────────────────
    title = escape_for_reportlab(finding.plugin_name)
    identifier = escape_for_reportlab(finding.primary_cve or finding.plugin_id)
    heading = (
        f"[{identifier}] {title}" if identifier and identifier not in title else title
    )

    badge = finding.severity.upper()
    if finding.in_kev:
        badge = f"KEV · {badge}"

    header = Table(
        [
            [
                Paragraph(
                    f"<font color='white'><b>{heading}</b></font>", styles["body_bold"]
                ),
                Paragraph(
                    f"<font color='white'><b>{badge}</b></font>",
                    ParagraphStyle(
                        "hdr_r", parent=styles["body_bold"], alignment=TA_RIGHT
                    ),
                ),
            ]
        ],
        colWidths=[CONTENT_W - 40 * mm, 40 * mm],
    )
    header.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), fg),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    # ── Metadata grid ────────────────────────────────────────────────────────
    meta_rows = [
        [
            _p("<b>CVSS base score</b>", styles["body"], escape=False),
            _cvss_cell(finding, styles),
            _p("<b>Affected port</b>", styles["body"], escape=False),
            _p(finding.port_label, styles["body"]),
        ],
        [
            _p("<b>Detection</b>", styles["body"], escape=False),
            _confidence_badge(finding, styles),
            _p("<b>Detected version</b>", styles["body"], escape=False),
            _p(finding.detected_version or "Not determined", styles["body"]),
        ],
        [
            _p("<b>Identifiers</b>", styles["body"], escape=False),
            _p(
                ", ".join(finding.cve_ids) if finding.cve_ids else "None assigned",
                styles["body"],
            ),
            _p("<b>Exploit intelligence</b>", styles["body"], escape=False),
            _threat_intel_cell(finding, styles),
        ],
        [
            _p("<b>Attack surface</b>", styles["body"], escape=False),
            _attack_surface_cell(finding, styles),
            _p("<b>Published</b>", styles["body"], escape=False),
            _p(_published_label(finding), styles["body"], escape=False),
        ],
    ]
    if finding.cwe_ids:
        meta_rows.append(
            [
                _p("<b>Weakness (CWE)</b>", styles["body"], escape=False),
                _p(_cwe_label(finding), styles["body"], escape=False),
                _p("<b>Source</b>", styles["body"], escape=False),
                _p(finding.plugin_family, styles["body"]),
            ]
        )

    meta = Table(meta_rows, colWidths=[30 * mm, 56 * mm, 34 * mm, 56 * mm])
    meta.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), BG_ALT),
                ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )

    elements: List[Any] = [header, meta, Spacer(1, 2 * mm)]

    # ── Score provenance ─────────────────────────────────────────────────────
    if finding.severity_source and finding.severity_source != "unscored":
        elements.append(
            _p(f"Severity basis: {finding.severity_source}.", styles["small"])
        )
        elements.append(Spacer(1, 1.2 * mm))

    # ── Remediation priority ─────────────────────────────────────────────────
    # The backend's own value, printed as it came. It is deliberately not
    # re-derived here: `core.vuln_intel.compute_priority` folds CVSS, EPSS, KEV
    # membership and exploit availability together, and a second implementation
    # in the report layer would sooner or later disagree with the findings
    # queue and the dashboard about the same finding.
    if finding.priority_level:
        elements.append(
            _p(
                f"Remediation priority: <b>"
                f"{escape_for_reportlab(finding.priority_level)}</b>, as assigned "
                f"by the platform's own prioritisation.",
                styles["small"],
                escape=False,
            )
        )
        elements.append(Spacer(1, 1.2 * mm))

    # ── CVSS vector in words ─────────────────────────────────────────────────
    if finding.cvss and finding.cvss.metrics:
        humanised = finding.cvss.humanised()
        if humanised:
            text = " · ".join(f"{name}: <b>{value}</b>" for name, value in humanised)
            elements.append(_p(text, styles["small"], escape=False))
            elements.append(Spacer(1, 1.5 * mm))

    # ── Integrity disclosures ────────────────────────────────────────────────
    # The blanket "v4.0 scores are not recomputed" note is a property of the
    # tool, not of any one finding. It is stated once in the Scoring section of
    # Appendix A, so repeating it on every v4.0 card is dropped here; genuine
    # per-finding discrepancies still surface.
    per_finding_warnings = [
        w for w in finding.integrity_warnings if not _is_global_disclosure(w)
    ]
    if per_finding_warnings:
        warning_text = "<br/>".join(
            f"• {escape_for_reportlab(w)}" for w in per_finding_warnings
        )
        elements.append(
            _boxed(
                _p(
                    f"<b>Data quality note</b><br/>{warning_text}",
                    styles["small"],
                    escape=False,
                ),
                colors.HexColor("#FEF9C3"),
                colors.HexColor("#FDE047"),
            )
        )
        elements.append(Spacer(1, 2 * mm))

    # ── Applicability ────────────────────────────────────────────────────────
    if finding.applicability_note:
        elements.append(
            _boxed(
                _p(
                    f"<b>Attack path:</b> {finding.applicability_note}",
                    styles["small"],
                    escape=False,
                ),
                colors.HexColor("#FFF7ED"),
                colors.HexColor("#FDBA74"),
            )
        )
        elements.append(Spacer(1, 2 * mm))

    # ── Narrative ────────────────────────────────────────────────────────────
    # The synopsis is the first sentence of the description, so printing both
    # repeated a paragraph on nearly every finding. Show the description when
    # there is one, and fall back to the synopsis only when there is not.
    if finding.description:
        body, truncated = truncate_with_notice(finding.description, 1600)
        text = escape_for_reportlab(body)
        if truncated:
            text += " <font color='#94A3B8'>[description truncated]</font>"
        elements.append(_p(f"<b>Description:</b> {text}", styles["body"], escape=False))
        elements.append(Spacer(1, 2 * mm))
    elif finding.synopsis:
        elements.append(
            _p(
                f"<b>Synopsis:</b> {escape_for_reportlab(finding.synopsis)}",
                styles["body"],
                escape=False,
            )
        )
        elements.append(Spacer(1, 2 * mm))

    # ── How this was detected ────────────────────────────────────────────────
    # The full explanation of each detection method is tabulated once in
    # Appendix A. Only the per-finding facts appear here.
    elements.append(
        _p(
            f"Detection: <b>{finding.confidence.value}</b> · quality of "
            f"detection <b>{finding.qod}%</b> · method: "
            f"{escape_for_reportlab(finding.detection_method.value.replace('_', ' '))}",
            styles["small"],
            escape=False,
        )
    )
    elements.append(Spacer(1, 2 * mm))

    # ── Evidence ─────────────────────────────────────────────────────────────
    # Only real scanner output earns a block here. The synthesised fallback
    # merely restated Port / Service / Product / Version, all four of which are
    # already in the metadata grid a few lines above.
    if finding.endpoint_observations and finding.evidence_available:
        from core.checks.endpoint_evidence import render_observations

        for observation in finding.endpoint_observations:
            # Separate flowables preserve every endpoint and allow page breaks.
            output = clean_control_chars(render_observations([observation]))
            for offset in range(0, len(output), 1200):
                elements.append(_p(output[offset : offset + 1200], styles["mono"]))
                elements.append(Spacer(1, 1 * mm))
    elif finding.evidence and finding.evidence_available:
        body, truncated = truncate_with_notice(
            clean_control_chars(finding.evidence), 1400
        )
        content = escape_for_reportlab(body).replace("\n", "<br/>")
        if truncated:
            content += "<br/><font color='#94A3B8'>[output truncated]</font>"
        elements.append(
            _boxed(
                Paragraph(
                    f"<b>Plugin output captured by the scanner:</b>"
                    f"<br/><br/>{content}",
                    styles["mono"],
                ),
                colors.HexColor("#F1F5F9"),
                colors.HexColor("#CBD5E1"),
            )
        )
        elements.append(Spacer(1, 2 * mm))

    # ── Remediation ──────────────────────────────────────────────────────────
    if finding.remediation:
        remediation = finding.remediation
        # Subscripted, this raised KeyError inside PDF generation for any
        # confidence value added to the enum later — a whole report lost to a
        # missing label. `.get` keeps the report renderable; the guarantee that
        # every member has a *specific* label is enforced in the test suite
        # instead, where a missing one is a failing assertion rather than a
        # customer's failed download.
        provenance = REMEDIATION_PROVENANCE.get(
            remediation.confidence, "Source: recorded with the finding."
        )

        actionable = remediation.is_actionable
        bg = colors.HexColor("#F0FDF4") if actionable else colors.HexColor("#FEF2F2")
        edge = colors.HexColor("#86EFAC") if actionable else colors.HexColor("#FECACA")

        text = (
            f"<b>Remediation:</b><br/>{escape_for_reportlab(remediation.summary)}"
            f"<br/><font size='6.8' color='#64748B'>{provenance}</font>"
        )
        if remediation.patch_url:
            url = escape_for_reportlab(remediation.patch_url)
            text += f"<br/><a href='{url}' color='#0284C7'><u>{url}</u></a>"

        elements.append(_boxed(_p(text, styles["body"], escape=False), bg, edge))
        elements.append(Spacer(1, 2 * mm))

    # ── The vendor's own remediation wording ─────────────────────────────────
    #
    # Rendered verbatim and in a block of its own, never merged into the
    # remediation box above. Two reasons, and both have bitten this product:
    #
    #   * The advisory prefix is load-bearing. An enriched advisory covers the
    #     same *CVE*, not necessarily the same *product*: a Chrome CVE appears
    #     in a CISA ICS advisory because an ICS product embeds Chrome, and that
    #     advisory's mitigation is written for the ICS context. The identifier
    #     in front of the text is what stops it reading as the desktop vendor's
    #     own advice, so it is preserved exactly as the matcher composed it.
    #
    #   * It is a different claim from the box above. That one is this
    #     product's normalised upgrade instruction; this one is what the vendor
    #     published. Where they differ, the reader needs to see both and know
    #     which is which.
    #
    # It is its own block rather than a line inside the remediation box because
    # a finding can carry vendor wording and no normalised remediation at all -
    # which is the common case on the CSAF path, where the advisory is the only
    # fix information that exists.
    if finding.vendor_remediation:
        body, truncated = truncate_with_notice(finding.vendor_remediation, 1200)
        text = escape_for_reportlab(body).replace("\n", "<br/>")
        if truncated:
            text += " <font color='#94A3B8'>[advisory text truncated]</font>"
        elements.append(
            _boxed(
                _p(
                    f"<b>Vendor remediation (the advisory's own wording):</b>"
                    f"<br/>{text}",
                    styles["body"],
                    escape=False,
                ),
                colors.HexColor("#EFF6FF"),
                colors.HexColor("#BFDBFE"),
            )
        )
        elements.append(Spacer(1, 2 * mm))

    # ── References ───────────────────────────────────────────────────────────
    if finding.references:
        links = []
        for kind, url in _ordered_references(finding.references, limit=6):
            safe = escape_for_reportlab(url)
            links.append(
                f"<font color='#64748B'>{kind}</font> — "
                f"<a href='{safe}' color='#0284C7'><u>{safe}</u></a>"
            )
        elements.append(
            _p(
                "<b>References:</b><br/>" + "<br/>".join(links),
                styles["small"],
                escape=False,
            )
        )

    elements.append(Spacer(1, 5 * mm))
    return elements


# ─────────────────────────────────────────────────────────────────────────────
# Generator
# ─────────────────────────────────────────────────────────────────────────────


class ScanReportGenerator:
    """Builds the executive and technical PDF reports for a scan result."""

    def __init__(self, output_dir: Optional[str] = None):
        if output_dir is None or output_dir == "reports":
            output_dir = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "reports"
            )
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.styles = _build_styles()

    # ── Filenames ────────────────────────────────────────────────────────────

    @staticmethod
    def _make_filename(scan_type: str, variant: str) -> str:
        """
        Build the on-disk report name.

        ``variant`` is "executive" or "technical" — the report's actual audience.
        It used to be "JSON" or "XML", which named the internal payload parser
        and told a recipient nothing about which of the two PDFs they had opened.
        """
        mapping = {
            "phase1": "host_discovery",
            "host_discovery": "host_discovery",
            "phase2": "asset_discovery",
            "asset_discovery": "asset_discovery",
            "phase3": "vulnerability_audit",
            "vulnerability_audit": "vulnerability_audit",
            "credentialed": "credentialed_audit",
        }
        normalized = str(scan_type or "").strip().lower()
        mapped = mapping.get(normalized, normalized.replace(" ", "_") or "scan")
        stamp = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
        return f"{mapped}_{stamp}_{variant}.pdf"

    def _doc(self, filename: str, title: str, header: str) -> ReportDocTemplate:
        return ReportDocTemplate(
            filename,
            pagesize=A4,
            margin=MARGIN,
            topMargin=20 * mm,
            bottomMargin=18 * mm,
            title=title,
            author="CCure Audit PRO",
            subject="Vulnerability assessment report",
            header_text=header,
        )

    # ── Executive report ─────────────────────────────────────────────────────

    def generate_executive_pdf(self, result: dict, scan_type: str) -> str:
        scan_type = _canonical_policy(scan_type)
        filename = os.path.join(
            self.output_dir, self._make_filename(scan_type, "executive")
        )
        findings = build_scan_report(result)
        meta = result.get("metadata", {}) or {}
        summary = result.get("summary", {}) or {}
        styles = self.styles

        exec_title = _report_title(scan_type, "executive")
        doc = self._doc(
            filename,
            exec_title,
            "CCure Audit PRO — Executive Summary",
        )
        story: List[Any] = []

        story.append(_p(exec_title, styles["title"]))
        story.append(
            _p(
                _report_subtitle(scan_type, "executive"),
                styles["subtitle"],
            )
        )
        story.append(_scan_metadata_block(meta, summary, findings, scan_type, styles))
        story.append(Spacer(1, 5 * mm))

        # One line of change since the previous scan. The executive report
        # answers "is this getting better or worse", and a total with nothing
        # to compare it against cannot. Absent when there is no comparison, so
        # a report generated without one is unchanged.
        _cmp = result.get("scan_comparison") or {}
        if _cmp.get("comparable") and _cmp.get("summary"):
            story.append(
                _p(
                    "<b>Since the previous scan:</b> "
                    + escape_for_reportlab(str(_cmp["summary"])),
                    styles["body"],
                    escape=False,
                )
            )
            if _cmp.get("current_policy") and not _cmp.get("policies_match"):
                # An executive reading "8 fixed" must not conclude the estate
                # improved when the previous scan simply assessed more.
                story.append(
                    _p(
                        "These two scans used different assessment "
                        "configurations, so part of this difference reflects "
                        "what was assessed rather than what changed.",
                        styles["body"],
                    )
                )
            story.append(Spacer(1, 4 * mm))

        # The remediation position, in one line. The executive report answers
        # "are we getting on top of this", and a finding count alone cannot —
        # it says how much there is, not how much anybody is doing about it.
        _rem = (result.get("metadata") or {}).get("remediation") or {}
        _rem_line = _remediation_summary_line(_rem)
        if _rem_line:
            story.append(
                _p(
                    "<b>Remediation:</b> " + escape_for_reportlab(_rem_line),
                    styles["body"],
                    escape=False,
                )
            )
            _ver = _rem.get("verification") or {}
            if _ver and int(_ver.get("withheld_count", 0) or 0):
                # An executive reading "42 verified fixed" must not conclude
                # the estate is clean when the scan could not check the rest.
                story.append(
                    _p(
                        f"{_ver['withheld_count']} finding(s) could not be "
                        "verified by this scan because the relevant checks "
                        "were not assessed.",
                        styles["body"],
                    )
                )
            story.append(Spacer(1, 4 * mm))

        # One line naming the policy. The executive report answers "what did we
        # assess and what did it find"; a finding count with no statement of
        # scope answers only half of that.
        _pol = (result.get("metadata") or {}).get("scan_policy") or {}
        if _pol.get("recorded") and _pol.get("policy_name"):
            story.append(
                _p(
                    "<b>Assessment policy:</b> "
                    + escape_for_reportlab(str(_pol["policy_name"]))
                    + " ("
                    + escape_for_reportlab(str(_pol.get("fingerprint") or "")[:16])
                    + ")",
                    styles["body"],
                    escape=False,
                )
            )
            story.append(Spacer(1, 4 * mm))

        counts = findings.severity_counts()
        vuln_counts = {t: 0 for t in SEVERITY_TIERS}
        for finding in findings.vulnerabilities:
            vuln_counts[finding.severity] = vuln_counts.get(finding.severity, 0) + 1

        # ── Posture statement ────────────────────────────────────────────────
        story.append(_heading("Security posture", styles["h1"], 0))

        total_vulns = len(findings.vulnerabilities)
        kev = findings.kev_findings
        actionable = vuln_counts["Critical"] + vuln_counts["High"]

        assesses = _assesses_vulnerabilities(scan_type)
        coverage = (
            summary.get("network_plugin_coverage")
            or meta.get("network_plugin_coverage")
            or {}
        )
        if coverage.get("recorded") and not coverage.get("complete"):
            story.append(
                _p(
                    "Network plugin coverage is incomplete; absence of findings does not establish a clean assessment.",
                    styles["body"],
                )
            )
            for outcome in coverage.get("incomplete", []):
                story.append(
                    _p(
                        f"{outcome.get('host')} / {outcome.get('plugin')}: {outcome.get('status')} — {outcome.get('detail', '')}",
                        styles["small"],
                    )
                )
        if not assesses:
            # A discovery scan runs no vulnerability checks. Saying "no
            # vulnerabilities were confirmed" over 0/0/0/0 tiles read as a
            # clean bill of health for hosts nobody assessed.
            posture = (
                f"Vulnerability assessment was not part of this scan. The "
                f"{SCAN_POLICY_LABELS.get(scan_type, 'discovery').lower()} policy "
                f"identifies live hosts"
                f"{' and their open services' if _scans_ports(scan_type) else ''}; "
                f"{len(findings.reachable_hosts)} host(s) responded. Run a "
                f"Vulnerability Audit to assess them."
            )
        elif total_vulns == 0:
            posture = (
                f"No vulnerabilities were confirmed across {len(findings.reachable_hosts)} "
                f"scanned host(s). Open ports discovered during the scan are "
                f"inventoried in the technical report for attack-surface review."
            )
        else:
            posture = (
                f"{total_vulns} vulnerabilit{'y' if total_vulns == 1 else 'ies'} "
                f"{'was' if total_vulns == 1 else 'were'} reported across "
                f"{len(findings.reachable_hosts)} host(s), of which "
                f"<b>{findings.confirmed_count}</b> are version-confirmed and "
                f"<b>{findings.potential_count}</b> require version verification. "
                f"<b>{actionable}</b> {'is' if actionable == 1 else 'are'} rated "
                f"High or Critical."
            )
            if kev:
                unconfirmed_kev = sum(1 for f in kev if _unconfirmed(f))
                posture += (
                    f" <font color='#B91C1C'><b>{len(kev)} finding(s) appear in the "
                    f"CISA Known Exploited Vulnerabilities catalog and should be "
                    f"treated as the immediate priority.</b></font>"
                )
                if unconfirmed_kev:
                    posture += (
                        f" {unconfirmed_kev} of them could not be confirmed on "
                        f"this host; verify "
                        f"{'its version' if unconfirmed_kev == 1 else 'their versions'} "
                        f"first."
                    )

        story.append(_boxed(_p(posture, styles["body"], escape=False), BG_ALT, BORDER))
        story.append(Spacer(1, 4 * mm))

        # Severity, exposure and remediation describe an assessment; a
        # discovery scan made none, so they are omitted rather than shown
        # as zeros.
        if assesses:
            # The strip counts vulnerabilities only. It previously mixed the
            # port-inventory entries into the same row as the severity tiers, so the
            # row summed to more than the stated finding total.
            story.append(_kpi_row(vuln_counts, styles))
            story.append(Spacer(1, 1.5 * mm))
            # A vulnerability rated None is still a vulnerability; it used to be
            # added to the port-observation count and called "a further N open
            # port(s)" — 53 CVEs on one Linux host, beside a sentence saying the
            # tiles summed to a total they were 53 short of.
            # The strip shows an Unscored tile whenever there are unscored
            # findings (see _kpi_row), so the only ones it leaves out are rated None.
            untiled = vuln_counts.get("None", 0)
            port_only = sum(
                1
                for f in findings.active
                if f.detection_method == DetectionMethod.PORT_OBSERVATION
            )
            if untiled:
                note = (
                    f"The severity tiers above cover {total_vulns - untiled} of the "
                    f"{total_vulns} vulnerability finding(s). The other {untiled} "
                    f"{'is' if untiled == 1 else 'are'} rated None and listed in the "
                    f"technical report."
                )
            else:
                note = (
                    f"The severity tiers above cover the {total_vulns} vulnerability "
                    f"finding(s) and sum to that total."
                )
            if port_only:
                note += (
                    f" A further {port_only} open port(s) carried no vulnerability "
                    f"finding and are listed in the technical report's port inventory "
                    f"for attack-surface review."
                )
            story.append(_p(note, styles["small"]))
            story.append(Spacer(1, 4 * mm))

            # ── Attack-surface qualification ─────────────────────────────────────
            # A Critical whose attack path is a client binary is a different
            # operational problem from one reachable across the network, and an
            # executive reading only the tier counts cannot tell them apart.
            remote_actionable = _network_reachable_count(findings)
            if actionable and remote_actionable != actionable:
                story.append(
                    _boxed(
                        _p(
                            f"Of the {actionable} High or Critical finding(s), "
                            f"<b>{remote_actionable}</b> {'is' if remote_actionable == 1 else 'are'} "
                            f"in a service this scan found listening on the network. "
                            f"The remainder affect software with no network-reachable "
                            f"listener on this host — client applications, libraries "
                            f"and locally used components — which still require the "
                            f"upgrade but cannot be reached through an open port.",
                            styles["body"],
                            escape=False,
                        ),
                        colors.HexColor("#FFF7ED"),
                        colors.HexColor("#FDBA74"),
                    )
                )
                story.append(Spacer(1, 4 * mm))

            # ── Exposure signal ──────────────────────────────────────────────────
            # Severity alone tells a reader how bad a flaw could be, not how likely
            # it is to be used. KEV membership and EPSS answer that, and they are
            # what an executive actually decides on, so they lead rather than being
            # buried in the per-finding detail.
            kev_findings = [f for f in findings.vulnerabilities if f.in_kev]
            likely = sorted(
                (f for f in findings.vulnerabilities if (f.epss_score or 0) >= 0.10),
                key=lambda f: f.epss_score or 0,
                reverse=True,
            )
            if kev_findings or likely:
                lines = []
                if kev_findings:
                    ids = ", ".join(
                        sorted({f.primary_cve for f in kev_findings if f.primary_cve})[
                            :6
                        ]
                    )
                    unconfirmed_ids = sorted(
                        {f.primary_cve for f in kev_findings if _unconfirmed(f)}
                        - {None, ""}
                    )
                    lines.append(
                        f"<b>{len(kev_findings)}</b> finding(s) appear in the CISA "
                        f"Known Exploited Vulnerabilities catalog and are being "
                        f"exploited in the wild: {escape_for_reportlab(ids)}. "
                        f"Treat these as the first call on remediation capacity."
                        + (
                            f" Not confirmed on this host: "
                            f"{escape_for_reportlab(', '.join(unconfirmed_ids))} — "
                            f"verify the version before acting."
                            if unconfirmed_ids
                            else ""
                        )
                    )
                if likely:
                    top = likely[0]
                    lines.append(
                        f"<b>{len(likely)}</b> finding(s) carry a 10% or greater "
                        f"probability of exploitation within 30 days (EPSS). The "
                        f"highest is {escape_for_reportlab(top.primary_cve or 'a finding')} "
                        f"at {(top.epss_score or 0) * 100:.1f}%."
                    )
                if not kev_findings:
                    lines.append(
                        "No finding in this scope appears in the CISA Known "
                        "Exploited Vulnerabilities catalog."
                    )
                for line in lines:
                    story.append(
                        _boxed(
                            _p(line, styles["body"], escape=False),
                            (
                                colors.HexColor("#FEF2F2")
                                if kev_findings
                                else colors.HexColor("#FFF7ED")
                            ),
                            (
                                colors.HexColor("#FCA5A5")
                                if kev_findings
                                else colors.HexColor("#FDBA74")
                            ),
                        )
                    )
                    story.append(Spacer(1, 2 * mm))
            story.append(Spacer(1, 3 * mm))

            # ── Distribution ─────────────────────────────────────────────────────
            story.append(_heading("Severity distribution", styles["h1"], 0))
            if total_vulns:
                donut = severity_donut(vuln_counts, font=styles["fonts"]["bold"])
                bars = severity_bar_chart(
                    vuln_counts,
                    width=CONTENT_W - 80 * mm,
                    font=styles["fonts"]["regular"],
                    bold_font=styles["fonts"]["bold"],
                )
                row = Table(
                    [[donut or Spacer(1, 1), bars]],
                    colWidths=[76 * mm, CONTENT_W - 76 * mm],
                )
                row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
                story.append(row)
            else:
                story.append(_p("No scored vulnerabilities to plot.", styles["body"]))
            story.append(Spacer(1, 4 * mm))

            # ── Host ranking ─────────────────────────────────────────────────────
            if len(findings.reachable_hosts) > 1:
                rows = [
                    (
                        h.display_name,
                        {
                            t: sum(
                                1 for f in h.vulnerability_findings if f.severity == t
                            )
                            for t in SEVERITY_TIERS
                        },
                    )
                    for h in findings.reachable_hosts
                ]
                chart = host_risk_chart(
                    rows,
                    width=CONTENT_W,
                    font=styles["fonts"]["regular"],
                    bold_font=styles["fonts"]["bold"],
                )
                # Build the chart before writing the heading. Emitting the heading
                # first left a bare "Most affected hosts" title with nothing beneath
                # it on any scan with no vulnerabilities to rank.
                if chart:
                    story.append(_heading("Most affected hosts", styles["h1"], 0))
                    story.append(chart)
                    story.append(Spacer(1, 1.5 * mm))
                    story.append(
                        chart_legend(vuln_counts, font=styles["fonts"]["regular"])
                    )
                    if len(findings.reachable_hosts) > 15:
                        story.append(Spacer(1, 1.5 * mm))
                        story.append(
                            _p(
                                f"Chart shows the 15 most affected hosts. All "
                                f"{len(findings.reachable_hosts)} hosts are listed in the "
                                f"technical report.",
                                styles["small"],
                            )
                        )
                story.append(Spacer(1, 4 * mm))

            # ── Exploited in the wild ────────────────────────────────────────────
            if kev:
                story.append(
                    _heading(
                        "Known exploited vulnerabilities — immediate action",
                        styles["h1"],
                        0,
                    )
                )
                rows = [
                    [
                        _p("<b>CVE</b>", styles["th"], escape=False),
                        _p("<b>Host</b>", styles["th"], escape=False),
                        _p("<b>Finding</b>", styles["th"], escape=False),
                        _p("<b>Severity</b>", styles["th"], escape=False),
                        _p("<b>CISA due date</b>", styles["th"], escape=False),
                    ]
                ]
                for finding in kev[:20]:
                    name = escape_for_reportlab(finding.plugin_name)
                    if _unconfirmed(finding):
                        name += f"<br/><i>{finding.confidence.value}: {UNCONFIRMED_KEV_NOTE}</i>"
                    rows.append(
                        [
                            _p(finding.primary_cve, styles["body"]),
                            _p(finding.host, styles["body"]),
                            _p(name, styles["body"], escape=False),
                            _severity_badge(finding.severity, styles),
                            _p(finding.kev_due_date or "Not specified", styles["body"]),
                        ]
                    )
                story.append(_grid(rows, [26 * mm, 28 * mm, 66 * mm, 20 * mm, 26 * mm]))
                story.append(Spacer(1, 4 * mm))

            # ── Remediation plan ─────────────────────────────────────────────────
            story.append(_heading("Prioritised remediation plan", styles["h1"], 0))
            plan = _remediation_plan(findings)

            if plan:
                story.append(
                    _p(
                        "Actions are ranked by risk eliminated: known-exploited first, "
                        "then by highest severity and the number of findings each "
                        "action resolves.",
                        styles["small"],
                    )
                )
                story.append(Spacer(1, 2 * mm))

                rows = [
                    [
                        _p("<b>#</b>", styles["th"], escape=False),
                        _p("<b>Remediation action</b>", styles["th"], escape=False),
                        _p("<b>Resolves</b>", styles["th"], escape=False),
                        _p("<b>Hosts</b>", styles["th"], escape=False),
                        _p("<b>Highest severity</b>", styles["th"], escape=False),
                        _p("<b>Target window</b>", styles["th"], escape=False),
                    ]
                ]
                for index, entry in enumerate(plan[:12], start=1):
                    action = entry["action"]
                    if entry["kev_confirmed"]:
                        action = "[Actively exploited] " + action
                    elif entry["kev"]:
                        action = "[Exploited elsewhere — unconfirmed here] " + action
                    rows.append(
                        [
                            _p(str(index), styles["body"]),
                            _p(action, styles["body"]),
                            _p(f"{len(entry['findings'])} finding(s)", styles["body"]),
                            _p(str(len(entry["hosts"])), styles["body"]),
                            _severity_badge(entry["max_severity"], styles),
                            _p(
                                REMEDIATION_SLA.get(
                                    entry["max_severity"], "Triage required"
                                ),
                                styles["body"],
                            ),
                        ]
                    )
                story.append(
                    _grid(rows, [8 * mm, 78 * mm, 24 * mm, 14 * mm, 24 * mm, 28 * mm])
                )
                if len(plan) > 12:
                    story.append(Spacer(1, 1.5 * mm))
                    story.append(
                        _p(
                            f"{len(plan) - 12} further remediation action(s) are listed "
                            f"in the technical report.",
                            styles["small"],
                        )
                    )
                story.append(Spacer(1, 2 * mm))
                story.append(
                    _p(
                        "Target windows reflect this organisation's remediation policy "
                        "and are not derived from scan data.",
                        styles["small"],
                    )
                )
            else:
                story.append(
                    _p(
                        "No actionable remediation was published for the findings in "
                        "this scan. Review the technical report for compensating "
                        "controls.",
                        styles["body"],
                    )
                )

            story.append(Spacer(1, 4 * mm))

        # ── Coverage note ────────────────────────────────────────────────────
        story.append(_heading("Assessment coverage", styles["h1"], 0))
        coverage = [
            f"Hosts assessed: <b>{len(findings.reachable_hosts)}</b>"
            + (
                f" of {len(findings.hosts)} probed "
                f"({len(findings.unreachable_hosts)} did not respond)."
                if findings.unreachable_hosts
                else "."
            ),
            (
                f"Open ports inventoried: "
                f"<b>{sum(len(h.reachable_services) for h in findings.reachable_hosts)}</b>."
                if _scans_ports(scan_type)
                else "Open ports inventoried: <b>not scanned</b> (host discovery "
                "does not scan ports)."
            ),
        ]
        if assesses:
            coverage += [
                f"Version-confirmed vulnerabilities: <b>{findings.confirmed_count}</b>.",
                f"Findings requiring version verification: "
                f"<b>{findings.potential_count}</b>.",
            ]
        else:
            coverage.append("Vulnerabilities: <b>not assessed</b> by this scan policy.")
        if findings.excluded:
            coverage.append(
                f"Candidate matches suppressed as not applicable: "
                f"<b>{len(findings.excluded)}</b> "
                f"(see the methodology appendix in the technical report)."
            )
        # What the scan did not look at bounds every conclusion above it. On a
        # host-only credentialed audit this is the line that stops "no network
        # findings" from being read as "no network exposure".
        not_examined = meta.get("unauthenticated_checks") or summary.get(
            "unauthenticated_checks"
        )
        if not_examined:
            coverage.append(f"Unauthenticated network checks: {not_examined}.")
        reachability = meta.get("network_reachability") or summary.get(
            "network_reachability"
        )
        if reachability:
            coverage.append(f"Network reachability: {reachability}.")
        story.append(
            _boxed(
                _p(
                    "<br/>".join(f"• {c}" for c in coverage),
                    styles["body"],
                    escape=False,
                ),
                BG_ALT,
                BORDER,
            )
        )

        doc.build(story, canvasmaker=NumberedCanvas)
        return filename

    # ── Technical report ─────────────────────────────────────────────────────

    def generate_technical_pdf(self, result: dict, scan_type: str) -> str:
        scan_type = _canonical_policy(scan_type)
        assesses = _assesses_vulnerabilities(scan_type)
        scans_ports = _scans_ports(scan_type)
        filename = os.path.join(
            self.output_dir, self._make_filename(scan_type, "technical")
        )
        findings = build_scan_report(result)
        meta = result.get("metadata", {}) or {}
        summary = result.get("summary", {}) or {}
        inputs = _report_inputs(result)
        styles = self.styles

        tech_title = _report_title(scan_type, "technical")
        doc = self._doc(
            filename,
            tech_title,
            "CCure Audit PRO — Technical Report",
        )
        story: List[Any] = []

        story.append(_p(tech_title, styles["title"]))
        story.append(
            _p(
                _report_subtitle(scan_type, "technical"),
                styles["subtitle"],
            )
        )
        story.append(_scan_metadata_block(meta, summary, findings, scan_type, styles))
        story.append(Spacer(1, 6 * mm))

        # ── Table of contents ────────────────────────────────────────────────
        toc = TableOfContents()
        toc.levelStyles = [styles["toc1"], styles["toc2"]]
        story.append(_p("Table of Contents", styles["h1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=6))
        story.append(toc)
        story.append(PageBreak())

        # ── Remediation and SLA ──────────────────────────────────────────────
        # Absent unless the scan carried remediation data, so a report for a
        # scan that predates GAP-14 is unchanged.
        remediation_story = _remediation_section(
            (result.get("metadata") or {}).get("remediation")
            or result.get("remediation"),
            styles,
        )
        if remediation_story:
            story.extend(remediation_story)
            story.append(PageBreak())

        # ── Assessment policy ────────────────────────────────────────────────
        # What this scan was configured to assess. Absent unless the scan
        # carried a policy snapshot, so a report for a scan that predates
        # GAP-12 is unchanged.
        policy_story = _policy_section(
            (result.get("metadata") or {}).get("scan_policy")
            or result.get("scan_policy"),
            styles,
        )
        if policy_story:
            story.extend(policy_story)
            story.append(PageBreak())

        # ── Change since the previous scan ───────────────────────────────────
        # Absent unless the scan carried a comparison, so a report generated
        # without one is unchanged.
        comparison_story = _comparison_section(result.get("scan_comparison"), styles)
        if comparison_story:
            story.extend(comparison_story)
            story.append(PageBreak())

        # ── Host index ───────────────────────────────────────────────────────
        story.append(_heading("Host index", styles["h1"], 0))

        if findings.reachable_hosts:
            rows = [
                [
                    _p("<b>Host</b>", styles["th"], escape=False),
                    _p("<b>Operating system</b>", styles["th"], escape=False),
                    _p("<b>Ports</b>", styles["th"], escape=False),
                    _p("<b>Vulns</b>", styles["th"], escape=False),
                    _p("<b>Crit</b>", styles["th"], escape=False),
                    _p("<b>High</b>", styles["th"], escape=False),
                    _p("<b>Med</b>", styles["th"], escape=False),
                    _p("<b>Low</b>", styles["th"], escape=False),
                ]
            ]
            for host in findings.reachable_hosts:
                # Count severities across vulnerabilities only. Including the
                # port-inventory entries made the row total 48 while the section
                # heading below said 38, because those entries are listed in
                # their own section rather than among the findings.
                counts = {t: 0 for t in SEVERITY_TIERS}
                for f in host.vulnerability_findings:
                    counts[f.severity] = counts.get(f.severity, 0) + 1
                # A column the scan never measured is "—", not 0.
                ports_cell = str(len(host.reachable_services)) if scans_ports else "—"

                def _vuln_cell(value):
                    return str(value) if assesses else "—"

                rows.append(
                    [
                        _p(host.display_name, styles["body"]),
                        _p(host.os_label, styles["body"]),
                        # Reachable only, matching the port inventory. A
                        # loopback-bound daemon is running, not exposed.
                        _p(ports_cell, styles["body"]),
                        _p(
                            _vuln_cell(len(host.vulnerability_findings)), styles["body"]
                        ),
                        _p(_vuln_cell(counts["Critical"]), styles["body"]),
                        _p(_vuln_cell(counts["High"]), styles["body"]),
                        _p(_vuln_cell(counts["Medium"]), styles["body"]),
                        _p(_vuln_cell(counts["Low"]), styles["body"]),
                    ]
                )
            table = _grid(
                rows,
                [
                    44 * mm,
                    38 * mm,
                    13 * mm,
                    14 * mm,
                    13 * mm,
                    13 * mm,
                    13 * mm,
                    13 * mm,
                ],
            )
            table.setStyle(TableStyle([("ALIGN", (2, 0), (-1, -1), "CENTER")]))
            story.append(table)
            story.append(Spacer(1, 1.5 * mm))
            story.append(
                _p(
                    "Vulns is the number of vulnerability findings for the host "
                    "and equals the sum of the severity columns. Open ports are "
                    "inventoried separately in each host's port-inventory section "
                    "and are not vulnerabilities.",
                    styles["small"],
                )
            )
        else:
            story.append(
                _p(
                    "No hosts responded to this scan. Every target listed under "
                    "unreachable targets below was probed and did not answer.",
                    styles["body"],
                )
            )

        # ── Unreachable targets ──────────────────────────────────────────────
        # Disclosed rather than dropped: a target that did not answer is a real
        # coverage limit, and the reader needs to know it was attempted. It is
        # kept out of the host index so it can never be read as a discovery.
        if findings.unreachable_hosts:
            story.append(Spacer(1, 5 * mm))
            story.append(_heading("Targets not reachable", styles["h1"], 0))
            story.append(
                _p(
                    f"{len(findings.unreachable_hosts)} target(s) were probed and "
                    f"did not respond. They are listed here for coverage, and are "
                    f"not counted as discovered hosts anywhere in this report. A "
                    f"target may be offline, firewalled, or filtering the probe "
                    f"types this scan policy uses.",
                    styles["body"],
                )
            )
            story.append(Spacer(1, 2 * mm))
            unreachable_rows = [
                [
                    _p("<b>Target</b>", styles["th"], escape=False),
                    _p("<b>Result</b>", styles["th"], escape=False),
                ]
            ]
            for host in findings.unreachable_hosts:
                unreachable_rows.append(
                    [
                        _p(host.ip, styles["body"]),
                        _p("No response to any probe", styles["body"]),
                    ]
                )
            story.append(_grid(unreachable_rows, [60 * mm, 101 * mm]))

        story.append(Spacer(1, 5 * mm))

        # The credentialed assessment records this scan stored, one per host.
        # Read from the raw payload rather than from `findings`, because
        # `HostReport` carries the network view and these are readings only an
        # authenticated session produces.
        assessment_by_host = {
            record.host: record for record in host_assessments(result) if record.host
        }

        # ── Per-host sections ────────────────────────────────────────────────
        cards_rendered = 0

        for host in findings.reachable_hosts:
            story.append(PageBreak())
            story.append(_heading(f"Host: {host.display_name}", styles["h1"], 0))

            detail_rows = []
            if host.hostname:
                detail_rows.append(("Hostname", host.hostname))
            detail_rows.append(("IP address", host.ip))
            if host.mac:
                detail_rows.append(("MAC address", host.mac))
            if host.vendor:
                detail_rows.append(("Hardware vendor", host.vendor))
            detail_rows.append(("Operating system", host.os_label))
            if host.device_category:
                detail_rows.append(("Device category", host.device_category))
            detail_rows.append(
                (
                    "Scan mode",
                    "Credentialed" if host.credentialed else "Unauthenticated",
                )
            )
            detail_rows.append(
                (
                    "Open ports",
                    (
                        str(len(host.reachable_services))
                        if scans_ports
                        else "Not scanned"
                    ),
                )
            )
            host_only = len(host.services) - len(host.reachable_services)
            if host_only:
                detail_rows.append(
                    (
                        "Host-only services",
                        f"{host_only} bound to loopback — running but not reachable "
                        f"from the network",
                    )
                )

            grid_rows = []
            for index in range(0, len(detail_rows), 2):
                chunk = detail_rows[index : index + 2]
                row = []
                for label, value in chunk:
                    row.append(_p(f"<b>{label}</b>", styles["body"], escape=False))
                    row.append(_p(value, styles["body"]))
                while len(row) < 4:
                    row.append(_p("", styles["body"]))
                grid_rows.append(row)

            info = Table(grid_rows, colWidths=[32 * mm, 56 * mm, 32 * mm, 56 * mm])
            info.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), BG_ALT),
                        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                        ("INNERGRID", (0, 0), (-1, -1), 0.3, BORDER),
                        ("LEFTPADDING", (0, 0), (-1, -1), 5),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(info)
            story.append(Spacer(1, 4 * mm))

            # Service inventory
            if host.services:
                story.append(_heading("Service inventory", styles["h2"], 1))
                rows = [
                    [
                        _p("<b>Port</b>", styles["th"], escape=False),
                        _p("<b>State</b>", styles["th"], escape=False),
                        _p("<b>Service</b>", styles["th"], escape=False),
                        _p(
                            "<b>Product / version detected</b>",
                            styles["th"],
                            escape=False,
                        ),
                    ]
                ]
                for svc in sorted(host.services, key=lambda s: s.port):
                    rows.append(
                        [
                            _p(svc.label, styles["body"]),
                            _p(svc.state, styles["body"]),
                            _p(svc.service_name or "unidentified", styles["body"]),
                            _p(
                                svc.product_label or "Not fingerprinted", styles["body"]
                            ),
                        ]
                    )
                story.append(_grid(rows, [22 * mm, 20 * mm, 40 * mm, 94 * mm]))
                story.append(Spacer(1, 4 * mm))

            # What the authenticated session examined on this host, and
            # what it could not. Keyed on the host's own address so a walk can
            # never attribute one machine's collection failures to another.
            story.extend(
                _host_assessment_sections(assessment_by_host.get(host.ip), styles)
            )

            vulnerabilities = host.vulnerability_findings
            inventory = [
                f
                for f in host.findings
                if f.detection_method == DetectionMethod.PORT_OBSERVATION
            ]

            if not assesses:
                story.append(
                    _boxed(
                        _p(
                            "Vulnerability assessment was not part of this scan; "
                            "this host was not assessed for vulnerabilities.",
                            styles["body"],
                        ),
                        BG_ALT,
                        BORDER,
                    )
                )
                continue

            if not vulnerabilities:
                story.append(
                    _boxed(
                        _p(
                            "No findings were reported on this host. "
                            + (
                                "Plugin coverage is incomplete or unverified; absence of findings does not establish a clean assessment."
                                if not host.plugin_coverage.get("complete")
                                else "Review the recorded scope alongside the open port inventory."
                            ),
                            styles["body"],
                        ),
                        BG_ALT,
                        BORDER,
                    )
                )
                continue

            # Findings that one upgrade resolves are presented as one item. A
            # host well behind on a browser is genuinely affected by hundreds of
            # published CVEs; listing them individually is accurate and useless,
            # and it pushed an ICS component with a Critical out of the document
            # entirely once the card cap was reached. The per-CVE findings are
            # unchanged underneath — this is how they are shown.
            groups = group_findings_for_report(vulnerabilities)
            grouped_count = sum(1 for g in groups if g.is_group)
            heading = f"Findings on {host.ip} ({len(vulnerabilities)})"
            if grouped_count:
                heading = (
                    f"Findings on {host.ip} ({len(vulnerabilities)} in "
                    f"{len(groups)} remediation groups)"
                )
            story.append(_heading(heading, styles["h2"], 1))
            story.append(
                HRFlowable(width="100%", thickness=0.8, color=NAVY, spaceAfter=6)
            )

            for group in groups:
                if cards_rendered >= MAX_DETAIL_CARDS:
                    break
                card = (
                    _finding_group_card(group, styles)
                    if group.is_group
                    else _finding_card(group.representative, styles)
                )
                # KeepTogether is applied only to the header + metadata so a long
                # card can still split across pages instead of overflowing.
                story.append(CondPageBreak(38 * mm))
                story.append(KeepTogether(card[:2]))
                story.extend(card[2:])
                cards_rendered += 1

            if cards_rendered >= MAX_DETAIL_CARDS:
                story.append(
                    _boxed(
                        _p(
                            f"Detailed cards are capped at {MAX_DETAIL_CARDS} findings "
                            f"per report. Remaining findings are summarised in the "
                            f"appendix and available in the CSV export.",
                            styles["body"],
                        ),
                        colors.HexColor("#FEF9C3"),
                        colors.HexColor("#FDE047"),
                    )
                )
                break

            if inventory:
                story.append(
                    _heading("Informational — open port inventory", styles["h2"], 1)
                )
                rows = [
                    [
                        _p("<b>Port</b>", styles["th"], escape=False),
                        _p("<b>Service</b>", styles["th"], escape=False),
                        _p("<b>Observation</b>", styles["th"], escape=False),
                    ]
                ]
                for item in inventory:
                    rows.append(
                        [
                            _p(f"{item.port}/{item.protocol}", styles["body"]),
                            _p(item.service_name or "unidentified", styles["body"]),
                            _p(item.synopsis, styles["body"]),
                        ]
                    )
                story.append(_grid(rows, [22 * mm, 40 * mm, 114 * mm]))

        # ── Appendices ───────────────────────────────────────────────────────
        story.append(PageBreak())
        story.append(_heading("Appendix A — Methodology and coverage", styles["h1"], 0))

        # ── Scan configuration ───────────────────────────────────────────────
        # What was actually run. Without it a reader cannot tell whether an
        # absent finding means "not present" or "not looked for".
        story.append(_p("Scan configuration", styles["h2"]))
        story.append(
            _p(
                "The parameters below describe what this scan examined. Coverage "
                "bounds the conclusions: a service on a port outside the scanned "
                "range, or a check the selected policy does not perform, cannot "
                "produce a finding here.",
                styles["body"],
            )
        )
        story.append(Spacer(1, 2 * mm))
        config_rows = [
            [
                _p("<b>Parameter</b>", styles["th"], escape=False),
                _p("<b>Value</b>", styles["th"], escape=False),
            ]
        ]
        for label, value in _scan_configuration(
            meta, summary, findings, scan_type, inputs
        ):
            config_rows.append(
                [
                    _p(label, styles["body"]),
                    _p(value, styles["body"]),
                ]
            )
        story.append(_grid(config_rows, [52 * mm, 124 * mm]))
        story.append(Spacer(1, 4 * mm))

        story.append(_p("Detection and confidence", styles["h2"]))
        story.append(
            _p(
                f"Each finding carries a quality-of-detection (QoD) score "
                f"describing how reliably the detection method establishes that "
                f"it applies to this host. Findings scoring below "
                f"<b>{QOD_REPORT_THRESHOLD}%</b> are withheld from the body of "
                f"this report and listed under suppressed candidates below, so "
                f"the findings above represent confirmed conditions rather than "
                f"product-name guesses. Vulnerabilities listed in the CISA "
                f"Known Exploited Vulnerabilities catalog are always shown "
                f"regardless of score.",
                styles["body"],
                escape=False,
            )
        )
        story.append(Spacer(1, 2 * mm))
        rows = [
            [
                _p("<b>Confidence</b>", styles["th"], escape=False),
                _p("<b>Meaning</b>", styles["th"], escape=False),
                _p("<b>Count</b>", styles["th"], escape=False),
            ]
        ]
        method_counts: Dict[DetectionMethod, int] = {}
        for finding in findings.vulnerabilities:
            method_counts[finding.detection_method] = (
                method_counts.get(finding.detection_method, 0) + 1
            )
        for method, count in sorted(method_counts.items(), key=lambda kv: -kv[1]):
            confidence, explanation = DETECTION_SEMANTICS[method]
            colour = CONFIDENCE_COLOR.get(confidence, MUTED)
            rows.append(
                [
                    _p(
                        f"<font color='{colour.hexval()}'><b>{confidence.value}</b></font>",
                        styles["body"],
                        escape=False,
                    ),
                    _p(explanation, styles["body"]),
                    _p(str(count), styles["body"]),
                ]
            )
        if len(rows) > 1:
            story.append(_grid(rows, [26 * mm, 132 * mm, 18 * mm]))
        story.append(Spacer(1, 4 * mm))

        story.append(_p("Scoring", styles["h2"]))
        story.append(
            _p(
                "CVSS v2 and v3.x base scores shown in this report are recomputed "
                "from the vector string published for each CVE using the FIRST "
                "CVSS specification, rather than being copied from the feed. Where "
                "the recomputed value disagrees with the feed, the discrepancy is "
                "disclosed on the finding. Records with no published vector are "
                "marked as not scored; no score is estimated or substituted.",
                styles["body"],
            )
        )
        story.append(Spacer(1, 2 * mm))
        v4_count = sum(
            1
            for f in findings.vulnerabilities
            if f.cvss is not None and f.cvss.version.startswith("4")
        )
        if v4_count:
            story.append(
                _p(
                    f"CVSS v4.0 uses a lookup-table scoring model rather than a "
                    f"closed-form equation, so v4.0 base scores are reported as "
                    f"published by the feed and are not independently recomputed. "
                    f"This applies to {v4_count} finding(s) in this report and is "
                    f"stated here once rather than repeated on each of them.",
                    styles["body"],
                )
            )
            story.append(Spacer(1, 2 * mm))
        story.append(
            _p(
                "Attack surface is assessed separately from severity. A CVE whose "
                "published text scopes the flaw to a client or utility binary is "
                "labelled as such on the finding, because the open port it is "
                "listed against is not the attack path for it. The affected "
                "package still requires the stated upgrade.",
                styles["body"],
            )
        )
        story.append(Spacer(1, 3 * mm))

        story.append(_p("Suppressed candidates", styles["h2"]))
        if findings.excluded:
            story.append(
                _p(
                    f"{len(findings.excluded)} candidate CVE match(es) were "
                    f"evaluated and withheld from this report because the observed "
                    f"software version falls outside the published vulnerable "
                    f"range, or because no observed service corresponds to the "
                    f"affected product. Suppressing these is what keeps the "
                    f"false-positive rate low; they are listed here for audit.",
                    styles["body"],
                )
            )
            story.append(Spacer(1, 2 * mm))
            rows = [
                [
                    _p("<b>Host</b>", styles["th"], escape=False),
                    _p("<b>Identifier</b>", styles["th"], escape=False),
                    _p("<b>Reason withheld</b>", styles["th"], escape=False),
                ]
            ]
            # Capped at 15. At 60 this table ran to five pages of a 34-page
            # report to make a point the summary line above already makes; the
            # complete list belongs in the CSV export, which is machine-readable
            # and has no page budget.
            for item in findings.excluded[:SUPPRESSED_SAMPLE_SIZE]:
                rows.append(
                    [
                        _p(item.host, styles["body"]),
                        _p(item.identifier, styles["body"]),
                        _p(item.reason, styles["body"]),
                    ]
                )
            story.append(_grid(rows, [30 * mm, 32 * mm, 114 * mm]))
            if len(findings.excluded) > SUPPRESSED_SAMPLE_SIZE:
                story.append(Spacer(1, 1.5 * mm))
                story.append(
                    _p(
                        f"Sample of {SUPPRESSED_SAMPLE_SIZE} shown; "
                        f"{len(findings.excluded) - SUPPRESSED_SAMPLE_SIZE} further "
                        f"entries are omitted here. The complete list of all "
                        f"{len(findings.excluded)} suppressed candidates is "
                        f"available in the CSV export for this scan.",
                        styles["small"],
                    )
                )
        else:
            story.append(
                _p(
                    "No candidate matches were suppressed during this assessment.",
                    styles["body"],
                )
            )
        story.append(Spacer(1, 4 * mm))

        story.append(_p("Limitations", styles["h2"]))
        story.append(
            _p(
                "A network vulnerability assessment reports conditions observable "
                "at scan time from the scanner's network position. Findings marked "
                "<b>Potential</b> indicate the affected product was detected but "
                "its exact version could not be established; confirm the version "
                "before scheduling remediation. Unauthenticated scans cannot "
                "enumerate installed patches, so absence of a finding is not "
                "evidence that a host is unaffected.",
                styles["body"],
                escape=False,
            )
        )

        # ── Data quality appendix ────────────────────────────────────────────
        # Only genuine per-record discrepancies belong here. The blanket "v4.0
        # scores are not recomputed" statement is a property of the tool and is
        # made once under Scoring; listing it per finding filled this appendix
        # with one repeated sentence and buried any real inconsistency.
        real_warnings = [
            w for w in findings.integrity_warnings if not _is_global_disclosure(w)
        ]
        if real_warnings:
            story.append(Spacer(1, 5 * mm))
            story.append(_heading("Appendix B — Data quality notes", styles["h1"], 0))
            story.append(
                _p(
                    "The following inconsistencies were detected between published "
                    "vulnerability metadata and the values recomputed by this tool. "
                    "They are disclosed rather than silently corrected.",
                    styles["body"],
                )
            )
            story.append(Spacer(1, 2 * mm))
            for warning in real_warnings[:50]:
                story.append(
                    _p(
                        f"• {escape_for_reportlab(warning)}",
                        styles["small"],
                        escape=False,
                    )
                )
            if len(real_warnings) > 50:
                story.append(
                    _p(
                        f"{len(real_warnings) - 50} further notes omitted.",
                        styles["small"],
                    )
                )

        # ── Triaged findings appendix ────────────────────────────────────────
        if findings.mitigated:
            story.append(PageBreak())
            story.append(
                _heading(
                    "Appendix C — Accepted risks and false positives", styles["h1"], 0
                )
            )
            story.append(
                _p(
                    "These findings were triaged out of the active result set. They "
                    "remain on record for audit and re-review.",
                    styles["body"],
                )
            )
            story.append(Spacer(1, 2 * mm))
            rows = [
                [
                    _p("<b>Host</b>", styles["th"], escape=False),
                    _p("<b>Identifier</b>", styles["th"], escape=False),
                    _p("<b>Finding</b>", styles["th"], escape=False),
                    _p("<b>Severity</b>", styles["th"], escape=False),
                    _p("<b>Status</b>", styles["th"], escape=False),
                ]
            ]
            for finding in findings.mitigated:
                rows.append(
                    [
                        _p(finding.host, styles["body"]),
                        _p(finding.primary_cve or finding.plugin_id, styles["body"]),
                        _p(finding.plugin_name, styles["body"]),
                        _severity_badge(finding.severity, styles),
                        _p(finding.mitigation_status, styles["body"]),
                    ]
                )
            story.append(_grid(rows, [28 * mm, 28 * mm, 66 * mm, 20 * mm, 24 * mm]))

        # multiBuild resolves TOC page numbers on the second pass.
        doc.multiBuild(story, canvasmaker=NumberedCanvas)
        return filename

    # ── Entry point ──────────────────────────────────────────────────────────

    def generate(self, result: dict, scan_type: str) -> Dict[str, str]:
        """
        Build both reports.

        Failures are logged and the corresponding key omitted, so a caller can
        never mistake an error string for a usable file path.
        """
        import logging

        logger = logging.getLogger(__name__)
        paths: Dict[str, str] = {}

        try:
            paths["executive_pdf"] = self.generate_executive_pdf(result, scan_type)
        except Exception:
            logger.exception(
                "Executive PDF generation failed for scan_type=%s", scan_type
            )

        try:
            paths["technical_pdf"] = self.generate_technical_pdf(result, scan_type)
        except Exception:
            logger.exception(
                "Technical PDF generation failed for scan_type=%s", scan_type
            )

        return paths
