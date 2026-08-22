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

from reporting.report_helpers import age_in_days, date_only
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


#: Columns for a host-inventory export. A host-discovery scan produces no
#: vulnerability findings by design, so the findings sheet above is empty for it
#: — the hosts *are* the result and need a sheet of their own.
HOST_INVENTORY_HEADERS = [
    "IP Address",
    "Hostname",
    "FQDN",
    "MAC Address",
    "Vendor",
    "Device Category",
    "Operating System",
    "Discovery Method",
    "Response Time (ms)",
    "Status",
    "Open Port Count",
    "Open Ports",
    "First Seen",
    "Last Seen",
]


def suppressed_csv_path(output_path: str) -> str:
    """Sidecar path for the suppressed-candidate export."""
    base, ext = os.path.splitext(output_path)
    return f"{base}_suppressed{ext or '.csv'}"


def _clean_cell(value: Any) -> str:
    """
    Render a value, treating scanner placeholders as absent.

    "Unknown" in an export reads as an observation. An empty cell reads as what
    it is: this scan did not establish the field.
    """
    if value is None:
        return ""
    text = str(value).strip()
    if text.lower() in ("unknown", "n/a", "none", "not determined", "-"):
        return ""
    return text


def _port_label(p: Dict[str, Any]) -> str:
    """
    Render one port as ``port/proto service product version``.

    The transport belongs here: an SNMP service on 161/udp and a listener on
    161/tcp are different findings, and a bare "161/snmp" cannot tell a reader
    which one was observed. The product and version are the substance of a
    service scan, so dropping them left the spreadsheet unable to answer the
    question it exists to answer.
    """
    proto = (p.get("protocol") or "tcp").lower()
    label = f"{p.get('port')}/{proto}"
    service = _clean_cell(p.get("service"))
    if service:
        label += f" {service}"
    detail = " ".join(
        part
        for part in (_clean_cell(p.get("product")), _clean_cell(p.get("version")))
        if part
    )
    if detail:
        label += f" ({detail})"
    return label


def _host_inventory_row(host: Dict[str, Any]) -> List[str]:
    ports = [
        p
        for p in (host.get("open_ports") or [])
        if isinstance(p, dict) and p.get("port")
    ]
    port_text = "; ".join(_port_label(p) for p in ports)

    response_time = host.get("response_time_ms") or host.get("response_time")
    if isinstance(response_time, (int, float)):
        response_time = f"{response_time:.3f}"

    return [
        _clean_cell(host.get("ip_address") or host.get("ip")),
        _clean_cell(host.get("hostname")),
        _clean_cell(host.get("fqdn") or host.get("dns_name")),
        _clean_cell(host.get("mac_address") or host.get("mac")),
        _clean_cell(host.get("vendor")),
        _clean_cell(host.get("device_category") or host.get("snmp_device_type")),
        _clean_cell(
            host.get("os_name") or host.get("os_guess") or host.get("os_match")
        ),
        _clean_cell(host.get("discovery_method") or host.get("scan_method")),
        _clean_cell(response_time),
        "Active" if host.get("is_active") or host.get("state") == "up" else "Inactive",
        str(len(ports)),
        port_text,
        _clean_cell(host.get("first_seen_at") or host.get("first_seen")),
        _clean_cell(host.get("last_seen_at") or host.get("scan_timestamp")),
    ]


def _extract_hosts(result_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Pull the host list out of whichever shape the caller passed."""
    data = result_dict.get("data")
    if isinstance(data, list):
        return [h for h in data if isinstance(h, dict)]
    for key in ("hosts", "results"):
        candidate = result_dict.get(key)
        if isinstance(candidate, list):
            return [h for h in candidate if isinstance(h, dict)]
    return []


def generate_host_inventory_csv(
    result_dict: Dict[str, Any],
    output_path: str,
    include_inactive: bool = True,
) -> str:
    """
    Write the discovered-host inventory to a CSV file.

    Used for scans that carry hosts but no vulnerability findings — host
    discovery above all. Inactive hosts are included and labelled so the export
    distinguishes "we probed it and it was down" from "we never looked".
    """
    hosts = _extract_hosts(result_dict)
    if not include_inactive:
        hosts = [h for h in hosts if h.get("is_active") or h.get("state") == "up"]

    directory = os.path.dirname(os.path.abspath(output_path))
    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(output_path, mode="w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(HOST_INVENTORY_HEADERS)
        for host in hosts:
            writer.writerow(_host_inventory_row(host))

    return output_path


def scan_has_findings(result_dict: Dict[str, Any]) -> bool:
    """True when the scan produced vulnerability findings worth exporting."""
    try:
        report: ScanFindings = build_scan_report(result_dict)
    except Exception:
        return False
    return bool(report.vulnerabilities or report.mitigated)


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
