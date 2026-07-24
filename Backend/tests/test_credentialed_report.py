import os
import shutil
import tempfile

from pdf_generator import ScanReportGenerator


def test_credentialed_report_generation_linux():
    """Verify that a Linux credentialed scan report generates successfully in both JSON and XML PDF formats."""
    # Create a temporary directory for output files
    temp_dir = tempfile.mkdtemp()
    try:
        # Mock a rich Linux credentialed scan result
        result = {
            "metadata": {
                "scan_no": 101,
                "timestamp": "2026-06-06T10:00:00+05:30",
                "scan_method": "CREDENTIALED",
                "target": "10.180.6.14",
            },
            "summary": {
                "scan_duration": 45.678,
                "scan_type": "credentialed",
                "phase": 3,
                "total_hosts": 1,
                "active_hosts": 1,
                "inactive_hosts": 0,
            },
            "data": {
                "credentialed": {
                    "report": {
                        "target": "10.180.6.14",
                        "is_active": True,
                        "device_category": "server",
                        "system_info": {
                            "os_confidence": "100",
                            "mac_address": "00:0C:29:43:89:12",
                            "subnet": "255.255.255.0",
                            "hostname": "audit-target-linux",
                            "fqdn": "audit-target-linux.internal.net",
                            "domain": "INTERNAL",
                            "os_family": "linux",
                            "os_name": "Ubuntu",
                            "os_version_id": "22.04",
                            "os_build": "LTS",
                            "kernel_version": "6.2.0-37-generic",
                            "manufacturer": "VMware, Inc.",
                            "hardware_model": "VMware Virtual Platform",
                            "cpu_model": "Intel(R) Xeon(R) Gold 6138 CPU @ 2.00GHz",
                            "cpu_count": "4",
                            "bios_version": "6.00",
                            "serial_number": "VMware-56 4d b8 3f 40 3d e8 cc-b4 fa 72 3b ad f1 ec a9",
                            "memory_summary": {
                                "total": "7.78 GB",
                                "used": "2.12 GB",
                                "free": "3.45 GB",
                                "available": "5.66 GB",
                            },
                            "disk_usage": [
                                {
                                    "mounted_on": "/",
                                    "size": "48.3 GB",
                                    "used": "18.2 GB",
                                    "available": "27.6 GB",
                                    "use_pct": "40%",
                                },
                                {
                                    "mounted_on": "/boot",
                                    "size": "1.8 GB",
                                    "used": "0.3 GB",
                                    "available": "1.4 GB",
                                    "use_pct": "18%",
                                },
                            ],
                        },
                        "open_ports_credentialed": [
                            {
                                "port": 22,
                                "state": "LISTEN",
                                "process": "sshd (PID 842)",
                                "local_addr": "0.0.0.0",
                            },
                            {
                                "port": 80,
                                "state": "LISTEN",
                                "process": "nginx (PID 1102)",
                                "local_addr": "127.0.0.1",
                            },
                        ],
                        "users": [
                            {
                                "username": "root",
                                "uid": "0",
                                "shell": "/bin/bash",
                                "is_system": False,
                                "is_root": True,
                            },
                            {
                                "username": "syslog",
                                "uid": "104",
                                "shell": "/usr/sbin/nologin",
                                "is_system": True,
                                "is_root": False,
                            },
                            {
                                "username": "ccure_audit",
                                "uid": "1001",
                                "shell": "/bin/bash",
                                "is_system": False,
                                "is_root": False,
                            },
                        ],
                        "local_groups": [
                            {"name": "sudo", "gid": "27", "members": ["ccure_audit"]},
                            {"name": "root", "gid": "0", "members": ["root"]},
                        ],
                        "security_issues": [
                            "PermitRootLogin enabled in sshd_config",
                            "PasswordAuthentication allowed over SSH",
                            "Anonymous/null sessions might be allowed on services",
                        ],
                        "sudo_nopasswd": True,
                        "failed_login_count": 14,
                        "suid_binaries": ["/usr/bin/sudo", "/usr/bin/passwd"],
                        "world_writable_dirs": ["/tmp", "/var/tmp"],
                        "cves": [
                            {
                                "cve_id": "CVE-2023-38408",
                                "severity": "High",
                                "cvss_score": 7.8,
                                "package": "openssh-client",
                                "description": "PKCS#11 provider forwarding vulnerability in OpenSSH agent.",
                            },
                            {
                                "cve_id": "CVE-2024-21626",
                                "severity": "Critical",
                                "cvss_score": 9.8,
                                "package": "runc",
                                "description": "Container escape vulnerability in runc via file descriptor leak.",
                            },
                        ],
                    }
                }
            },
        }

        # Initialize the ScanReportGenerator pointing to our temporary directory
        gen = ScanReportGenerator(output_dir=temp_dir)
        paths = gen.generate(result, scan_type="credentialed_scan")

        # Validate that the reports were generated and paths don't contain errors
        assert "json_pdf" in paths
        assert "xml_pdf" in paths
        assert not paths["json_pdf"].startswith("ERROR")
        assert not paths["xml_pdf"].startswith("ERROR")

        # Verify files exist and have content
        assert os.path.exists(paths["json_pdf"])
        assert os.path.getsize(paths["json_pdf"]) > 0
        assert os.path.exists(paths["xml_pdf"])
        assert os.path.getsize(paths["xml_pdf"]) > 0

    finally:
        # Cleanup temporary files
        shutil.rmtree(temp_dir)


def test_credentialed_report_generation_windows():
    """Verify that a Windows credentialed scan report generates successfully in both JSON and XML PDF formats."""
    temp_dir = tempfile.mkdtemp()
    try:
        # Mock a rich Windows credentialed scan result
        result = {
            "metadata": {
                "scan_no": 102,
                "timestamp": "2026-06-06T11:00:00+05:30",
                "scan_method": "CREDENTIALED",
                "target": "10.180.6.15",
            },
            "summary": {
                "scan_duration": 60.123,
                "scan_type": "credentialed",
                "phase": 3,
                "total_hosts": 1,
                "active_hosts": 1,
                "inactive_hosts": 0,
            },
            "data": {
                "credentialed": {
                    "report": {
                        "target": "10.180.6.15",
                        "is_active": True,
                        "device_category": "endpoint",
                        "system_info": {
                            "os_confidence": "95",
                            "mac_address": "00:50:56:AB:CD:EF",
                            "subnet": "255.255.255.0",
                            "hostname": "win-server-2022",
                            "fqdn": "win-server-2022.ad.domain.com",
                            "domain": "AD.DOMAIN.COM",
                            "os_family": "windows",
                            "os_name": "Microsoft Windows Server 2022 Datacenter",
                            "os_version_id": "10.0.20348",
                            "os_build": "20348",
                            "kernel_version": "10.0.20348.1197",
                            "manufacturer": "Microsoft Corporation",
                            "hardware_model": "Virtual Machine",
                            "cpu_model": "Intel(R) Xeon(R) Silver 4214 CPU @ 2.20GHz",
                            "cpu_count": "2",
                            "bios_version": "Hyper-V UEFI Release v4.0",
                            "serial_number": "Hyper-V-Serial-Number-999",
                            "memory_summary": {
                                "total": "8.00 GB",
                                "used": "3.50 GB",
                                "free": "4.50 GB",
                                "available": "4.50 GB",
                            },
                            "disk_usage": [
                                {
                                    "Name": "C:",
                                    "used": "45.2 GB",
                                    "available": "34.8 GB",
                                },
                                {
                                    "Name": "D:",
                                    "used": "10.5 GB",
                                    "available": "89.5 GB",
                                },
                            ],
                        },
                        "open_ports_credentialed": [
                            {
                                "port": 3389,
                                "state": "LISTEN",
                                "process": "TermService (PID 128)",
                                "local_addr": "0.0.0.0",
                            },
                            {
                                "port": 445,
                                "state": "LISTEN",
                                "process": "System (PID 4)",
                                "local_addr": "0.0.0.0",
                            },
                        ],
                        "users": [
                            {
                                "username": "Administrator",
                                "enabled": True,
                                "is_admin": True,
                                "last_logon": "2026-06-06T09:30:15",
                                "pwd_required": True,
                            },
                            {
                                "username": "Guest",
                                "enabled": False,
                                "is_admin": False,
                                "last_logon": "Never",
                                "pwd_required": False,
                            },
                        ],
                        "local_groups": [
                            {
                                "name": "Administrators",
                                "gid": "S-1-5-32-544",
                                "members": ["Administrator"],
                            },
                            {
                                "name": "Remote Desktop Users",
                                "gid": "S-1-5-32-555",
                                "members": [],
                            },
                        ],
                        "security_issues": [
                            "Guest account is not renamed",
                            "Default Administrator account is active",
                            "LSA protection is not enabled",
                        ],
                        "failed_login_count": 2,
                        "cves": [],
                    }
                }
            },
        }

        # Initialize the ScanReportGenerator
        gen = ScanReportGenerator(output_dir=temp_dir)
        paths = gen.generate(result, scan_type="credentialed_scan")

        # Validate that the reports were generated and paths don't contain errors
        assert "json_pdf" in paths
        assert "xml_pdf" in paths
        assert not paths["json_pdf"].startswith("ERROR")
        assert not paths["xml_pdf"].startswith("ERROR")

        # Verify files exist and have content
        assert os.path.exists(paths["json_pdf"])
        assert os.path.getsize(paths["json_pdf"]) > 0
        assert os.path.exists(paths["xml_pdf"])
        assert os.path.getsize(paths["xml_pdf"]) > 0

    finally:
        # Cleanup temporary files
        shutil.rmtree(temp_dir)
