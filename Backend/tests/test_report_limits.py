"""
Module: Backend/tests/test_report_limits
Purpose: Tests PDF report generation layout robustness under extreme data loads and empty inputs.
Author:  pair/Senior Full-Stack Engineer
"""

import os
import shutil
import tempfile
from pdf_generator import ScanReportGenerator


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

        assert "json_pdf" in paths
        assert "xml_pdf" in paths
        assert os.path.exists(paths["json_pdf"])
        assert os.path.exists(paths["xml_pdf"])
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

        assert "json_pdf" in paths
        assert "xml_pdf" in paths
        assert os.path.exists(paths["json_pdf"])
        assert os.path.exists(paths["xml_pdf"])
        assert os.path.getsize(paths["json_pdf"]) > 0
        assert os.path.getsize(paths["xml_pdf"]) > 0
    finally:
        shutil.rmtree(temp_dir)
