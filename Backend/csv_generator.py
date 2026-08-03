"""
csv_generator.py
─────────────────────────────────────────────────────────────────────────────
CSV export of scan findings for ticketing and spreadsheet workflows
(Jira, ServiceNow, Excel).

The export carries the same provenance columns as the PDF — detection method,
confidence, scoring basis, and remediation source — so a finding triaged from a
spreadsheet retains the context needed to judge it. Empty cells mean the data
was not published; they are never filled with a placeholder value.
"""

from __future__ import annotations

import csv
import os
from typing import Any, Dict, List

from report_helpers import age_in_days, date_only
from scans.finding_normalizer import (
    DetectionMethod,
    ScanFindings,
    StandardizedFinding,
    build_scan_report,
)

NETWORK_HEADERS = [
    "Host",
    "Hostname",
    "Port",
    "Protocol",
    "Service",
    "Detected Product Version",
    "Finding",
    "CVE",
    "CWE",
    "Severity",
    "CVSS Score",
    "CVSS Version",
    "CVSS Vector",
    "Scoring Basis",
    "Detection Method",
    "Confidence",
    "QoD %",
    "Attack Surface",
    "Attack Path Note",
    "In CISA KEV",
    "KEV Due Date",
    "EPSS Probability",
    "EPSS Percentile",
    "CVE Published",
    "CVE Age (days)",
    "Synopsis",
    "Description",
    "Evidence Captured",
    "Plugin Output",
    "Remediation",
    "Remediation Source",
    "Fixed Version",
    "Patch URL",
    "References",
    "Status",
    "First Found",
    "Last Found",
    "Data Quality Notes",
]

#: Columns for the suppressed-candidate sheet. The PDF appendix now samples
#: these; the complete audit trail lives here, where there is no page budget.
SUPPRESSED_HEADERS = [
    "Host",
    "Identifier",
    "Reason Withheld",
]

WEB_HEADERS = [
    "Target URL",
    "HTTP Method",
    "Vulnerable Parameter",
    "Finding",
    "CVE",
    "Severity",
    "CVSS Score",
    "CVSS Vector",
    "Scoring Basis",
    "Detection Method",
    "Confidence",
    "Synopsis",
    "Evidence Captured",
    "Plugin Output",
    "Remediation",
    "Remediation Source",
    "Status",
]


def _blank(value: Any) -> str:
    """Render missing data as an empty cell rather than a stand-in string."""
    return "" if value is None else str(value)


def _network_row(f: StandardizedFinding) -> List[str]:
    remediation = f.remediation
    return [
        f.host,
        f.hostname,
        _blank(f.port),
        f.protocol,
        f.service_name,
        f.detected_version,
        f.plugin_name,
        ", ".join(f.cve_ids),
        ", ".join(f.cwe_ids),
        f.severity,
        _blank(f.cvss_score),
        f.cvss_version,
        f.cvss_vector,
        f.severity_source,
        f.detection_method.value,
        f.confidence.value,
        str(f.qod),
        f.attack_surface,
        f.applicability_note,
        "Yes" if f.in_kev else "No",
        f.kev_due_date,
        f"{f.epss_score:.4f}" if f.epss_score is not None else "",
        f"{f.epss_percentile:.4f}" if f.epss_percentile is not None else "",
        date_only(f.published_at),
        _blank(age_in_days(f.published_at)),
        f.synopsis,
        f.description,
        "Yes" if f.evidence_available else "No",
        f.evidence,
        remediation.summary if remediation else "",
        remediation.confidence.value if remediation else "",
        (remediation.fixed_version or "") if remediation else "",
        (remediation.patch_url or "") if remediation else "",
        "; ".join(f.references),
        f.mitigation_status,
        f.first_found_at,
        f.last_found_at,
        " | ".join(f.integrity_warnings),
    ]


def _web_row(f: StandardizedFinding) -> List[str]:
    remediation = f.remediation
    return [
        _blank(f.url),
        _blank(f.http_method),
        _blank(f.vulnerable_parameter),
        f.plugin_name,
        ", ".join(f.cve_ids),
        f.severity,
        _blank(f.cvss_score),
        f.cvss_vector,
        f.severity_source,
        f.detection_method.value,
        f.confidence.value,
        f.synopsis,
        "Yes" if f.evidence_available else "No",
        f.evidence,
        remediation.summary if remediation else "",
        remediation.confidence.value if remediation else "",
        f.mitigation_status,
    ]


def suppressed_csv_path(output_path: str) -> str:
    """Sidecar path for the suppressed-candidate export."""
    base, ext = os.path.splitext(output_path)
    return f"{base}_suppressed{ext or '.csv'}"


def generate_scan_csv(
    result_dict: Dict[str, Any],
    output_path: str,
    scan_type: str = "network",
    include_port_inventory: bool = False,
    write_suppressed: bool = True,
) -> str:
    """
    Write scan findings to a CSV file.

    Port-inventory observations are excluded by default so the export contains
    vulnerabilities only; pass ``include_port_inventory=True`` to append them.

    When ``write_suppressed`` is set and the scan ruled any candidates out, a
    ``*_suppressed.csv`` sidecar records every one of them. The PDF appendix
    samples that list and refers the reader here for the complete audit trail,
    so the two must be produced together.
    """
    report: ScanFindings = build_scan_report(result_dict)

    findings = list(report.vulnerabilities)
    if include_port_inventory:
        findings.extend(
            f
            for f in report.active
            if f.detection_method == DetectionMethod.PORT_OBSERVATION
        )
    findings.extend(report.mitigated)

    directory = os.path.dirname(os.path.abspath(output_path))
    if directory:
        os.makedirs(directory, exist_ok=True)

    is_web = str(scan_type).lower() == "web"
    headers = WEB_HEADERS if is_web else NETWORK_HEADERS
    build_row = _web_row if is_web else _network_row

    # utf-8-sig so Excel detects the encoding and renders non-ASCII correctly.
    with open(output_path, mode="w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        for finding in findings:
            writer.writerow(build_row(finding))

    if write_suppressed and not is_web and report.excluded:
        with open(
            suppressed_csv_path(output_path), mode="w", newline="", encoding="utf-8-sig"
        ) as handle:
            writer = csv.writer(handle)
            writer.writerow(SUPPRESSED_HEADERS)
            for item in report.excluded:
                writer.writerow([item.host, item.identifier, item.reason])

    return output_path
