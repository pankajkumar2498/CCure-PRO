"""
A report says what its scan assessed, and its numbers count what they claim to.

From the 13 Oct 2026 end-to-end run against 10.180.6.30 and 10.180.6.45:

* A Basic Network Scan's executive report read "No vulnerabilities were
  confirmed across 1 scanned host(s)" over 0/0/0/0 tiles, with "Open ports
  inventoried: 0" — for a scan that runs no vulnerability checks and probes
  no ports. The technical report's green box said the same per host, and the
  CSV said "Open Port Count 0". Asset Discovery's reports made the same claim.
* "783 of 802 High/Critical are reachable against a network-listening
  service" counted CVSS attack vectors; 12 were bound to an open port.
* "A further 55 open port(s) carried no vulnerability finding" was 53 CVEs
  rated None plus 2 ports, beside "the tiers sum to that total".
"""

from __future__ import annotations

import csv

import pytest
import reporting.pdf_generator as pdf_generator
from reporting.csv_generator import generate_host_inventory_csv
from reporting.pdf_generator import ScanReportGenerator

HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
NONE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"


@pytest.fixture()
def rendered(monkeypatch):
    texts: list[str] = []
    original = pdf_generator._p

    def capture(text, style, escape=True):
        texts.append(str(text))
        return original(text, style, escape)

    monkeypatch.setattr(pdf_generator, "_p", capture)
    return texts


def _discovery_payload(with_ports: bool):
    host = {
        "ip_address": "10.180.6.45",
        "hostname": "atharv-desktop.blr.cdac.in",
        "is_active": True,
    }
    if with_ports:
        host["open_ports"] = [
            {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH"}
        ]
    return {"metadata": {"target": "10.180.6.45", "scan_no": 2}, "data": [host]}


# ── discovery reports do not claim an assessment ────────────────────────────


def test_a_host_discovery_report_says_nothing_was_assessed(tmp_path, rendered):
    ScanReportGenerator(output_dir=str(tmp_path)).generate_executive_pdf(
        _discovery_payload(False), "host_discovery"
    )
    text = "\n".join(rendered)
    assert "Vulnerability assessment was not part of this scan" in text
    assert "No vulnerabilities were confirmed" not in text
    assert "not scanned" in text and "not assessed" in text
    assert "Version-confirmed vulnerabilities" not in text
    # No severity strip of zeros.
    assert "CRITICAL" not in rendered


def test_an_asset_discovery_report_counts_ports_but_not_vulnerabilities(
    tmp_path, rendered
):
    ScanReportGenerator(output_dir=str(tmp_path)).generate_executive_pdf(
        _discovery_payload(True), "asset_discovery"
    )
    text = "\n".join(rendered)
    assert "identifies live hosts and their open services" in text
    assert "No vulnerabilities were confirmed" not in text
    assert "Open ports inventoried: <b>1</b>" in text


def test_the_technical_report_marks_unmeasured_columns(tmp_path, rendered):
    ScanReportGenerator(output_dir=str(tmp_path)).generate_technical_pdf(
        _discovery_payload(False), "host_discovery"
    )
    text = "\n".join(rendered)
    assert "this host was not assessed for vulnerabilities" in text
    assert "No vulnerabilities were confirmed on this host" not in text
    assert "Not scanned" in text


def test_a_host_discovery_csv_does_not_report_zero_open_ports(tmp_path):
    path = tmp_path / "hosts.csv"
    generate_host_inventory_csv(
        {"data": _discovery_payload(False)["data"]}, str(path), ports_scanned=False
    )
    row = next(csv.DictReader(open(path, encoding="utf-8-sig")))
    assert row["Open Port Count"] == "Not scanned"
    assert row["Open Ports"] == "Not scanned"


def test_an_asset_csv_still_counts_ports(tmp_path):
    path = tmp_path / "hosts.csv"
    generate_host_inventory_csv({"data": _discovery_payload(True)["data"]}, str(path))
    row = next(csv.DictReader(open(path, encoding="utf-8-sig")))
    assert row["Open Port Count"] == "1"


# ── an assessment's counts ──────────────────────────────────────────────────


def _package(cve, package, vector=HIGH, port=None):
    finding = {
        "cve_id": cve,
        "description": "A flaw.",
        "cvss_vector": vector,
        "package": package,
        "installed_version": "1.0-1",
        "detected_version": "1.0-1",
        "fixed_version": "1.0-2",
        "detection_method": "credentialed_package",
        "finding_origin": "credentialed",
        "source": "osv_match",
    }
    if port is not None:
        finding.update({"port": port, "protocol": "tcp"})
    return finding


def _assessed_payload():
    return {
        "metadata": {"target": "10.180.6.30", "scan_no": 8, "is_credentialed": True},
        "data": [
            {
                "ip_address": "10.180.6.30",
                "hostname": "PANKAJM-HPNEW",
                "is_active": True,
                "credentialed": True,
                "os_guess": "Microsoft Windows 11 Pro",
                "open_ports": [
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "service": "ssh",
                        "product": "OpenSSH",
                    },
                    {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server"},
                ],
                "cves": [
                    # In the listening sshd.
                    _package("CVE-2026-0001", "OpenSSH", port=22),
                    # In a desktop application: a network attack vector, no listener.
                    _package("CVE-2026-0002", "Google Chrome"),
                    # Rated None.
                    _package("CVE-2026-0003", "Google Chrome", vector=NONE),
                ],
            }
        ],
    }


def test_reachability_counts_findings_bound_to_a_listening_service(tmp_path, rendered):
    ScanReportGenerator(output_dir=str(tmp_path)).generate_executive_pdf(
        _assessed_payload(), "phase_selective_scan"
    )
    text = "\n".join(rendered)
    assert "<b>1</b> is in a service this scan found listening on the network" in text
    assert "reachable against a network-listening service" not in text


def test_findings_rated_none_are_not_called_open_ports(tmp_path, rendered):
    ScanReportGenerator(output_dir=str(tmp_path)).generate_executive_pdf(
        _assessed_payload(), "phase_selective_scan"
    )
    text = "\n".join(rendered)
    assert "cover 2 of the 3 vulnerability finding(s)" in text
    assert "The other 1 is rated None" in text
    # 3389 carried no finding: that, and only that, is a port observation.
    assert "A further 1 open port(s) carried no vulnerability finding" in text


# ── the report key the audit pipeline uses is a real policy ─────────────────


def test_an_audit_report_names_its_policy_and_its_feed(tmp_path, rendered):
    """
    The Vulnerability Audit pipeline generates its reports as
    "phase_selective_scan". That key matched no policy, so the PDF said "Scan
    policy: Phase Selective Scan" and left out the vulnerability feed date —
    the caveat on every finding it lists.
    """
    path = ScanReportGenerator(output_dir=str(tmp_path)).generate_executive_pdf(
        _assessed_payload(), "phase_selective_scan"
    )
    text = "\n".join(rendered)
    assert "Network vulnerability assessment" in text
    assert "Phase Selective Scan" not in text
    assert "<b>Vulnerability feed</b>" in text
    assert path.split("/")[-1].startswith("vulnerability_audit_")
