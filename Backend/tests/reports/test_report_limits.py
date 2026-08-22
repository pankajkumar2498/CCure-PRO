"""
Module: Backend/tests/test_report_limits
Purpose: Tests PDF report generation layout robustness under extreme data loads and empty inputs.
Author:  pair/Senior Full-Stack Engineer
"""

import os
import shutil
import tempfile

import reporting.pdf_generator as pdf_generator
from reporting.pdf_generator import ScanReportGenerator


def test_report_generation_empty_data():
    """Verify that report generation handles empty scan datasets gracefully without crashing."""
    temp_dir = tempfile.mkdtemp()
    try:
        # Minimal empty scan dataset
        result = {
            "metadata": {
                "scan_no": 999,
                "timestamp": "2026-07-13T09:00:00+05:30",
                "scan_method": "CREDENTIALED",
                "target": "10.0.0.1",
            },
            "summary": {
                "scan_duration": 0.0,
                "scan_type": "credentialed",
                "phase": 1,
                "total_hosts": 0,
                "active_hosts": 0,
                "inactive_hosts": 0,
            },
            "data": {
                "credentialed": {
                    "report": {
                        "target": "10.0.0.1",
                        "is_active": False,
                        "system_info": {},
                        "open_ports_credentialed": [],
                        "users": [],
                        "local_groups": [],
                        "security_issues": [],
                        "cves": [],
                    }
                }
            },
        }

        gen = ScanReportGenerator(output_dir=temp_dir)
        paths = gen.generate(result, scan_type="credentialed_scan")

        assert "executive_pdf" in paths
        assert "technical_pdf" in paths
        assert os.path.exists(paths["executive_pdf"])
        assert os.path.exists(paths["technical_pdf"])
    finally:
        shutil.rmtree(temp_dir)


def test_report_generation_extreme_load():
    """Verify report layout handles high CVE counts and long descriptions without grid/cell crashes."""
    temp_dir = tempfile.mkdtemp()
    try:
        # Build 200 mock CVE items with extremely long strings to force text wrapping
        mock_cves = []
        long_string = "A " * 300  # 600 characters string
        for i in range(200):
            mock_cves.append(
                {
                    "cve_id": f"CVE-2026-{10000 + i}",
                    "severity": (
                        "Critical"
                        if i % 4 == 0
                        else ("High" if i % 2 == 0 else "Medium")
                    ),
                    "cvss_score": 9.8 if i % 4 == 0 else 7.5,
                    "package": f"vulnerable-package-name-xyz-{i}",
                    "description": f"Vulnerability {i} description: {long_string}",
                }
            )

        result = {
            "metadata": {
                "scan_no": 888,
                "timestamp": "2026-07-13T10:00:00+05:30",
                "scan_method": "CREDENTIALED",
                "target": "10.0.0.2",
            },
            "summary": {
                "scan_duration": 3600.0,
                "scan_type": "credentialed",
                "phase": 3,
                "total_hosts": 1,
                "active_hosts": 1,
                "inactive_hosts": 0,
            },
            "data": {
                "credentialed": {
                    "report": {
                        "target": "10.0.0.2",
                        "is_active": True,
                        "device_category": "server",
                        "system_info": {
                            "hostname": "extreme-load-target-system-hostname-wrapping-verification-test",
                            "os_name": "Microsoft Windows Server 2022 Datacenter Edition Core version",
                            "os_version_id": "10.0.20348",
                            "serial_number": "Hyper-V-Serial-Number-Extreme-Wrapping-Test-99999999999999999999",
                        },
                        "open_ports_credentialed": [
                            {
                                "port": p,
                                "state": "LISTEN",
                                "process": f"process-{p}",
                                "local_addr": "0.0.0.0",
                            }
                            for p in range(1, 50)
                        ],
                        "users": [
                            {
                                "username": f"user-{u}",
                                "enabled": True,
                                "is_admin": False,
                                "last_logon": "Never",
                            }
                            for u in range(50)
                        ],
                        "local_groups": [],
                        "security_issues": [
                            f"Security configuration issue item {s}: {long_string[:100]}"
                            for s in range(50)
                        ],
                        "cves": mock_cves,
                    }
                }
            },
        }

        gen = ScanReportGenerator(output_dir=temp_dir)
        paths = gen.generate(result, scan_type="credentialed_scan")

        assert "executive_pdf" in paths
        assert "technical_pdf" in paths
        assert os.path.exists(paths["executive_pdf"])
        assert os.path.exists(paths["technical_pdf"])
        assert os.path.getsize(paths["executive_pdf"]) > 0
        assert os.path.getsize(paths["technical_pdf"]) > 0
    finally:
        shutil.rmtree(temp_dir)


def _relative_luminance(colour):
    """WCAG relative luminance, for contrast assertions."""

    def channel(value):
        return value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4

    red, green, blue = channel(colour.red), channel(colour.green), channel(colour.blue)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def test_table_header_text_contrasts_with_the_header_fill():
    """
    Table headers are drawn on a navy fill. A TEXTCOLOR table command does not
    recolour Paragraph cells, so header cells built with a body style rendered
    dark-on-dark and were unreadable in the shipped PDFs. Assert every header
    row a real report emits carries light text.
    """
    header_cells = []
    original_grid = pdf_generator._grid

    def spy(rows, col_widths, header=True, zebra=True):
        if header and rows:
            header_cells.extend(rows[0])
        return original_grid(rows, col_widths, header=header, zebra=zebra)

    result = {
        "metadata": {
            "scan_no": 777,
            "timestamp": "2026-07-30T16:39:00+05:30",
            "scan_method": "ADAPTIVE",
            "target": "10.0.0.3",
        },
        "summary": {
            "scan_duration": 120.0,
            "scan_type": "vulnerability",
            "phase": 3,
            "total_hosts": 1,
            "active_hosts": 1,
            "inactive_hosts": 0,
        },
        "data": [
            {
                "ip_address": "10.0.0.3",
                "hostname": "web-01",
                "is_active": True,
                "os_guess": "Ubuntu 22.04",
                "open_ports": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http",
                        "product": "nginx",
                        "version": "1.26.3",
                    },
                    {"port": 445, "protocol": "tcp", "state": "open", "service": "smb"},
                ],
                "cves": [
                    {
                        # Confirmed: drives the findings and remediation tables.
                        "cve_id": "CVE-2026-40701",
                        "description": "Heap use-after-free in the NGINX worker.",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
                        "affected_software": [
                            {
                                "vendor": "f5",
                                "product": "nginx",
                                "versionEndExcluding": "1.27.4",
                                "cpe23Uri": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                            }
                        ],
                        "port": 80,
                    },
                    {
                        # Suppressed: drives the appendix tables.
                        "cve_id": "CVE-2020-0796",
                        "description": "SMBv3 remote code execution.",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "affected_software": [
                            {
                                "vendor": "microsoft",
                                "product": "windows_10",
                                "cpe23Uri": "cpe:2.3:o:microsoft:windows_10:1903:*:*:*:*:*:*:*",
                            }
                        ],
                        "port": 445,
                    },
                ],
            }
        ],
    }

    temp_dir = tempfile.mkdtemp()
    pdf_generator._grid = spy
    try:
        ScanReportGenerator(output_dir=temp_dir).generate(
            result, scan_type="vulnerability_audit"
        )
    finally:
        pdf_generator._grid = original_grid
        shutil.rmtree(temp_dir)

    assert header_cells, "no header rows were rendered — the payload exercises none"

    fill_luminance = _relative_luminance(pdf_generator.NAVY)
    for cell in header_cells:
        text_luminance = _relative_luminance(cell.style.textColor)
        contrast = (text_luminance + 0.05) / (fill_luminance + 0.05)
        assert contrast >= 4.5, (
            f"header cell {getattr(cell, 'text', cell)!r} has contrast "
            f"{contrast:.1f}:1 against the header fill"
        )
