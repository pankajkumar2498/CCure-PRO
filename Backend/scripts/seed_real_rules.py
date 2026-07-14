"""
Script: seed_real_rules.py
Purpose: Seed real compliance rules based on target scan findings, map them to ISO controls,
         create a baseline policy, and immediately evaluate compliance findings for host 10.180.6.14.
Usage:   python -m scripts.seed_real_rules
"""

import os
import sys
from datetime import datetime, timezone

# Ensure the root of the project is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.base import SessionLocal
from db.models import Asset, User
from db.models.rbac import Organization
from db.models.compliance import (
    ComplianceFramework,
    ComplianceControl,
    ComplianceRule,
    ComplianceRuleControl,
    ComplianceRemediation,
    ComplianceTenantFramework,
    CompliancePolicy,
    CompliancePolicyRule,
    ComplianceScanRun,
)
from core.compliance_tasks import run_scan_task


def seed_and_evaluate():
    db = SessionLocal()
    try:
        # 1. Verify framework exists
        framework_id = "cfw_iso27001_2022"
        framework = (
            db.query(ComplianceFramework)
            .filter(ComplianceFramework.id == framework_id)
            .first()
        )
        if not framework:
            print(
                "Error: ISO 27001 framework not found. Please run seed_compliance first."
            )
            return

        # 2. Seed Compliance Rules and Remediation Actions
        rules_data = [
            {
                "id": "crl_vuln_critical_v1",
                "rule_family_code": "VULN-CRITICAL",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "vulnerability_audit",
                "target_platform": "any",
                "check_definition": {
                    "key": "critical_count",
                    "operator": "equals",
                    "expected": 0,
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_vuln_critical_v1",
                "control_id": "cct_iso27001_2022_8.8",
                "recommendation_text": "Identify and patch all software packages with critical vulnerabilities detected in active scans.",
            },
            {
                "id": "crl_vuln_high_v1",
                "rule_family_code": "VULN-HIGH",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "vulnerability_audit",
                "target_platform": "any",
                "check_definition": {
                    "key": "high_count",
                    "operator": "equals",
                    "expected": 0,
                },
                "severity": "high",
                "severity_weight": 7,
                "remediation_id_target": "rem_vuln_high_v1",
                "control_id": "cct_iso27001_2022_8.8",
                "recommendation_text": "Patch or remediate all high-severity vulnerabilities to secure application packages.",
            },
            {
                "id": "crl_malware_agent_v1",
                "rule_family_code": "MALWARE-AGENT",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "malware_scan",
                "target_platform": "any",
                "check_definition": {
                    "key": "anti_malware_agents_active",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "high",
                "severity_weight": 7,
                "remediation_id_target": "rem_malware_agent_v1",
                "control_id": "cct_iso27001_2022_8.7",
                "recommendation_text": "Ensure an EDR or anti-malware agent (Defender, CrowdStrike, ClamAV, Sentinel) is running on the host.",
            },
            {
                "id": "crl_credential_scan_v1",
                "rule_family_code": "CRED-SCAN-SUCCESS",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "credential_validation",
                "target_platform": "any",
                "check_definition": {
                    "key": "credentialed_scan_successful",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "medium",
                "severity_weight": 5,
                "remediation_id_target": "rem_credential_scan_v1",
                "control_id": "cct_iso27001_2022_8.2",
                "recommendation_text": "Configure valid credentials (SSH key or Windows Admin) in CCure Audit PRO settings to allow full authenticated scans.",
            },
            {
                "id": "crl_firewall_active_v1",
                "rule_family_code": "FW-PROFILE-ACTIVE",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "firewall_profile_active",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "high",
                "severity_weight": 7,
                "remediation_id_target": "rem_firewall_active_v1",
                "control_id": "cct_iso27001_2022_8.20",
                "recommendation_text": "Ensure the system firewall profile is enabled and active (Windows Defender Firewall or Linux iptables/ufw).",
            },
            {
                "id": "crl_port_ssh_v1",
                "rule_family_code": "PORT-SSH",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "services_ports",
                "target_platform": "any",
                "check_definition": {
                    "key": "open_ports",
                    "operator": "not_contains",
                    "expected": 22,
                },
                "severity": "medium",
                "severity_weight": 5,
                "remediation_id_target": "rem_port_ssh_v1",
                "control_id": "cct_iso27001_2022_8.20",
                "recommendation_text": "Disable external SSH port 22 or restrict access using IP whitelisting on your border firewall.",
            },
            {
                "id": "crl_port_http_v1",
                "rule_family_code": "PORT-HTTP",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "services_ports",
                "target_platform": "any",
                "check_definition": {
                    "key": "open_ports",
                    "operator": "not_contains",
                    "expected": 80,
                },
                "severity": "medium",
                "severity_weight": 5,
                "remediation_id_target": "rem_port_http_v1",
                "control_id": "cct_iso27001_2022_8.20",
                "recommendation_text": "Disable unencrypted port 80 (HTTP) or configure HTTPS (port 443) redirection.",
            },
            {
                "id": "crl_port_netbios_v1",
                "rule_family_code": "PORT-NETBIOS",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "services_ports",
                "target_platform": "any",
                "check_definition": {
                    "key": "open_ports",
                    "operator": "not_contains",
                    "expected": 139,
                },
                "severity": "high",
                "severity_weight": 7,
                "remediation_id_target": "rem_port_netbios_v1",
                "control_id": "cct_iso27001_2022_8.20",
                "recommendation_text": "Disable NetBIOS over TCP/IP on all active network adapters to prevent credential spoofing.",
            },
            {
                "id": "crl_port_smb_v1",
                "rule_family_code": "PORT-SMB",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "services_ports",
                "target_platform": "any",
                "check_definition": {
                    "key": "open_ports",
                    "operator": "not_contains",
                    "expected": 445,
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_port_smb_v1",
                "control_id": "cct_iso27001_2022_8.20",
                "recommendation_text": "Block inbound port 445 on the network/local firewall, or disable the SMBv1/v2 service if not required.",
            },
            {
                "id": "crl_port_mysql_v1",
                "rule_family_code": "PORT-MYSQL",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "services_ports",
                "target_platform": "any",
                "check_definition": {
                    "key": "open_ports",
                    "operator": "not_contains",
                    "expected": 3306,
                },
                "severity": "high",
                "severity_weight": 7,
                "remediation_id_target": "rem_port_mysql_v1",
                "control_id": "cct_iso27001_2022_8.21",
                "recommendation_text": "Restrict port 3306 exposure by binding MySQL to localhost (127.0.0.1) or blocking external access with a system firewall.",
            },
            {
                "id": "crl_port_postgresql_v1",
                "rule_family_code": "PORT-POSTGRES",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "services_ports",
                "target_platform": "any",
                "check_definition": {
                    "key": "open_ports",
                    "operator": "not_contains",
                    "expected": 5432,
                },
                "severity": "high",
                "severity_weight": 7,
                "remediation_id_target": "rem_port_postgresql_v1",
                "control_id": "cct_iso27001_2022_8.21",
                "recommendation_text": "Restrict port 5432 exposure by binding PostgreSQL to localhost (127.0.0.1) or blocking external access with a system firewall.",
            },
            {
                "id": "crl_port_oracle_v1",
                "rule_family_code": "PORT-ORACLE",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "services_ports",
                "target_platform": "any",
                "check_definition": {
                    "key": "open_ports",
                    "operator": "not_contains",
                    "expected": 1521,
                },
                "severity": "high",
                "severity_weight": 7,
                "remediation_id_target": "rem_port_oracle_v1",
                "control_id": "cct_iso27001_2022_8.21",
                "recommendation_text": "Restrict port 1521 exposure by binding Oracle TNS to localhost or blocking external access with a system firewall.",
            },
            {
                "id": "crl_port_amt_v1",
                "rule_family_code": "PORT-INTEL-AMT",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "services_ports",
                "target_platform": "any",
                "check_definition": {
                    "key": "open_ports",
                    "operator": "not_contains",
                    "expected": 623,
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_port_amt_v1",
                "control_id": "cct_iso27001_2022_8.20",
                "recommendation_text": "Disable Intel AMT hardware-level remote management port 623 unless strictly needed, and isolate management access.",
            },
            {
                "id": "crl_port_winrm_v1",
                "rule_family_code": "PORT-WINRM",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "services_ports",
                "target_platform": "any",
                "check_definition": {
                    "key": "open_ports",
                    "operator": "not_contains",
                    "expected": 5985,
                },
                "severity": "high",
                "severity_weight": 7,
                "remediation_id_target": "rem_port_winrm_v1",
                "control_id": "cct_iso27001_2022_8.20",
                "recommendation_text": "Block unencrypted WinRM port 5985 over HTTP, and use WinRM over HTTPS (port 5986) instead.",
            },
            {
                "id": "crl_port_tomcat_v1",
                "rule_family_code": "PORT-TOMCAT",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "services_ports",
                "target_platform": "any",
                "check_definition": {
                    "key": "open_ports",
                    "operator": "not_contains",
                    "expected": 8080,
                },
                "severity": "medium",
                "severity_weight": 5,
                "remediation_id_target": "rem_port_tomcat_v1",
                "control_id": "cct_iso27001_2022_8.20",
                "recommendation_text": "Bind server processes on port 8080 to localhost (127.0.0.1) or restrict external network access.",
            },
            {
                "id": "crl_port_opcua_v1",
                "rule_family_code": "PORT-OPCUA",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "services_ports",
                "target_platform": "any",
                "check_definition": {
                    "key": "open_ports",
                    "operator": "not_contains",
                    "expected": 4840,
                },
                "severity": "medium",
                "severity_weight": 5,
                "remediation_id_target": "rem_port_opcua_v1",
                "control_id": "cct_iso27001_2022_8.21",
                "recommendation_text": "Secure the OPC UA listener on port 4840 by enforcing encrypted endpoints, certificate validation, and user credentials.",
            },
            {
                "id": "crl_smbv1_disabled_v1",
                "rule_family_code": "CONFIG-SMBV1",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "smbv1_disabled",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "high",
                "severity_weight": 7,
                "remediation_id_target": "rem_smbv1_disabled_v1",
                "control_id": "cct_iso27001_2022_8.20",
                "recommendation_text": "Disable the legacy SMBv1 protocol to mitigate structural remote execution risks (like EternalBlue).",
            },
            {
                "id": "crl_netbios_disabled_v1",
                "rule_family_code": "CONFIG-NETBIOS",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "netbios_disabled",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "medium",
                "severity_weight": 5,
                "remediation_id_target": "rem_netbios_disabled_v1",
                "control_id": "cct_iso27001_2022_8.20",
                "recommendation_text": "Disable NetBIOS over TCP/IP on all active adapters to prevent name resolution hijacking/poisoning.",
            },
            {
                "id": "crl_legacy_tls_disabled_v1",
                "rule_family_code": "CONFIG-LEGACY-TLS",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "legacy_tls_disabled",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "high",
                "severity_weight": 7,
                "remediation_id_target": "rem_legacy_tls_disabled_v1",
                "control_id": "cct_iso27001_2022_8.24",
                "recommendation_text": "Disable legacy protocol versions (SSLv3, TLS 1.0, TLS 1.1) to enforce modern cipher algorithms.",
            },
            {
                "id": "crl_telnet_disabled_v1",
                "rule_family_code": "CONFIG-TELNET",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "telnet_disabled",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "high",
                "severity_weight": 7,
                "remediation_id_target": "rem_telnet_disabled_v1",
                "control_id": "cct_iso27001_2022_8.20",
                "recommendation_text": "Disable Telnet client/server services completely and use SSH (port 22) for remote command lines.",
            },
            {
                "id": "crl_rdp_nla_enforced_v1",
                "rule_family_code": "CONFIG-RDP-NLA",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "offline_configuration",
                "target_platform": "windows",
                "check_definition": {
                    "key": "rdp_nla_enforced",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "high",
                "severity_weight": 7,
                "remediation_id_target": "rem_rdp_nla_enforced_v1",
                "control_id": "cct_iso27001_2022_8.20",
                "recommendation_text": "Configure Network Level Authentication (NLA) requirement on Remote Desktop Services to validate connections before creating sessions.",
            },
        ]

        # Compile a set of controls already mapped to custom rules
        mapped_control_ids = {r["control_id"] for r in rules_data}

        # Dynamically generate manual rules for all remaining ISO 27001 controls in db
        controls_in_db = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == framework_id)
            .all()
        )
        for ctrl in controls_in_db:
            if ctrl.id not in mapped_control_ids:
                # Remove prefix cct_iso27001_2022_ to extract raw standard ID
                raw_num = ctrl.id.split("_")[-1]
                rule_id = f"crl_auto_gen_{raw_num.replace('.', '_')}"

                rules_data.append(
                    {
                        "id": rule_id,
                        "rule_family_code": f"RULE-{raw_num}",
                        "version_number": 1,
                        "check_type": "api_response",
                        "evidence_source": "manual",
                        "target_platform": "any",
                        "check_definition": {},
                        "severity": "medium",
                        "severity_weight": 5,
                        "remediation_id_target": f"rem_auto_gen_{raw_num.replace('.', '_')}",
                        "control_id": ctrl.id,
                        "recommendation_text": f"Review organizational policies, documentation, and processes to verify compliance with control criteria for '{ctrl.title}'.",
                    }
                )

        # Remediation Commands Catalog for Automated check rules
        FIX_COMMANDS = {
            "VULN-CRITICAL": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Install-Module PSWindowsUpdate -Force -Confirm:$false\n"
                "Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo apt-get update && sudo apt-get dist-upgrade -y  # Debian/Ubuntu\n"
                "sudo yum update -y                                    # RHEL/CentOS"
            ),
            "VULN-HIGH": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Install-Module PSWindowsUpdate -Force -Confirm:$false\n"
                "Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo apt-get update && sudo apt-get upgrade -y       # Debian/Ubuntu\n"
                "sudo yum update -y                                    # RHEL/CentOS"
            ),
            "MALWARE-AGENT": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Start-Service -Name WinDefend  # Ensure Windows Defender Antivirus is active\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo systemctl enable --now clamav-daemon clamav-freshclam"
            ),
            "CRED-SCAN-SUCCESS": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Enable-PSRemoting -Force\n"
                "Set-Service WinRM -StartupType Automatic\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo systemctl enable --now ssh\n"
                "echo '[Your Scanner SSH Key]' >> ~/.ssh/authorized_keys"
            ),
            "FW-PROFILE-ACTIVE": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo ufw enable  # Ubuntu/Debian\n"
                "sudo systemctl enable --now firewalld  # CentOS/RHEL"
            ),
            "PORT-SSH": (
                "# --- WINDOWS (PowerShell) ---\n"
                'New-NetFirewallRule -DisplayName "Block SSH" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Block\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw deny 22/tcp\n"
                "sudo iptables -A INPUT -p tcp --dport 22 -j DROP"
            ),
            "PORT-HTTP": (
                "# --- WINDOWS (PowerShell) ---\n"
                'New-NetFirewallRule -DisplayName "Block HTTP" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Block\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw deny 80/tcp\n"
                "sudo iptables -A INPUT -p tcp --dport 80 -j DROP"
            ),
            "PORT-NETBIOS": (
                "# --- WINDOWS (PowerShell) ---\n"
                'New-NetFirewallRule -DisplayName "Block NetBIOS" -Direction Inbound -LocalPort 139 -Protocol TCP -Action Block\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw deny 139/tcp\n"
                "sudo iptables -A INPUT -p tcp --dport 139 -j DROP"
            ),
            "PORT-SMB": (
                "# --- WINDOWS (PowerShell) ---\n"
                'New-NetFirewallRule -DisplayName "Block SMB" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Block\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw deny 445/tcp\n"
                "sudo iptables -A INPUT -p tcp --dport 445 -j DROP"
            ),
            "PORT-MYSQL": (
                "# --- WINDOWS (PowerShell) ---\n"
                'New-NetFirewallRule -DisplayName "Block MySQL" -Direction Inbound -LocalPort 3306 -Protocol TCP -Action Block\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw deny 3306/tcp\n"
                "sudo iptables -A INPUT -p tcp --dport 3306 -j DROP"
            ),
            "PORT-POSTGRES": (
                "# --- WINDOWS (PowerShell) ---\n"
                'New-NetFirewallRule -DisplayName "Block PostgreSQL" -Direction Inbound -LocalPort 5432 -Protocol TCP -Action Block\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw deny 5432/tcp\n"
                "sudo iptables -A INPUT -p tcp --dport 5432 -j DROP"
            ),
            "PORT-ORACLE": (
                "# --- WINDOWS (PowerShell) ---\n"
                'New-NetFirewallRule -DisplayName "Block Oracle DB" -Direction Inbound -LocalPort 1521 -Protocol TCP -Action Block\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw deny 1521/tcp\n"
                "sudo iptables -A INPUT -p tcp --dport 1521 -j DROP"
            ),
            "PORT-INTEL-AMT": (
                "# --- WINDOWS (PowerShell) ---\n"
                'New-NetFirewallRule -DisplayName "Block Intel AMT" -Direction Inbound -LocalPort 623 -Protocol TCP -Action Block\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw deny 623/tcp\n"
                "sudo iptables -A INPUT -p tcp --dport 623 -j DROP"
            ),
            "PORT-WINRM": (
                "# --- WINDOWS (PowerShell) ---\n"
                'New-NetFirewallRule -DisplayName "Block WinRM" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Block\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw deny 5985/tcp\n"
                "sudo iptables -A INPUT -p tcp --dport 5985 -j DROP"
            ),
            "PORT-TOMCAT": (
                "# --- WINDOWS (PowerShell) ---\n"
                'New-NetFirewallRule -DisplayName "Block Tomcat" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Block\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw deny 8080/tcp\n"
                "sudo iptables -A INPUT -p tcp --dport 8080 -j DROP"
            ),
            "PORT-OPCUA": (
                "# --- WINDOWS (PowerShell) ---\n"
                'New-NetFirewallRule -DisplayName "Block OPC UA" -Direction Inbound -LocalPort 4840 -Protocol TCP -Action Block\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw deny 4840/tcp\n"
                "sudo iptables -A INPUT -p tcp --dport 4840 -j DROP"
            ),
            "CONFIG-SMBV1": (
                "# --- WINDOWS (PowerShell) ---\n"
                'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "SMB1" -Value 0 -Force -ErrorAction SilentlyContinue\n'
                "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo sed -i '/\\[global\\]/a \\   server min protocol = SMB2' /etc/samba/smb.conf 2>/dev/null || true\n"
                "sudo systemctl restart smbd 2>/dev/null || true"
            ),
            "CONFIG-NETBIOS": (
                "# --- WINDOWS (PowerShell) ---\n"
                '$adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True"\n'
                "foreach ($adapter in $adapters) {\n"
                "    $adapter.SetTcpipNetbios(2) | Out-Null\n"
                "}\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo systemctl disable --now nmbd 2>/dev/null || true"
            ),
            "CONFIG-LEGACY-TLS": (
                "# --- WINDOWS (PowerShell) ---\n"
                '$protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")\n'
                "foreach ($proto in $protocols) {\n"
                '    foreach ($type in @("Client", "Server")) {\n'
                '        $path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$proto\\$type"\n'
                "        if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }\n"
                '        Set-ItemProperty -Path $path -Name "Enabled" -Value 0 -Type DWORD -Force\n'
                '        Set-ItemProperty -Path $path -Name "DisabledByDefault" -Value 1 -Type DWORD -Force\n'
                "    }\n"
                "}\n\n"
                "# --- LINUX (Bash) ---\n"
                'if grep -q -i "ubuntu\\|debian" /etc/os-release; then\n'
                "    sudo sed -i 's/CipherString = DEFAULT@SECLEVEL=2/CipherString = DEFAULT@SECLEVEL=2\\nMinProtocol = TLSv1.2/g' /etc/ssl/openssl.cnf 2>/dev/null || true\n"
                'elif grep -q -i "rhel\\|centos\\|rocky\\|fedora" /etc/os-release; then\n'
                "    sudo update-crypto-policies --set FUTURE 2>/dev/null || true\n"
                "fi"
            ),
            "CONFIG-TELNET": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart -ErrorAction SilentlyContinue\n"
                "Stop-Service -Name TlntSvr -Force -ErrorAction SilentlyContinue\n"
                "Set-Service -Name TlntSvr -StartupType Disabled -ErrorAction SilentlyContinue\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo systemctl disable --now telnet.socket 2>/dev/null || true\n"
                "sudo systemctl disable --now telnetd 2>/dev/null || true"
            ),
            "CONFIG-RDP-NLA": (
                "# --- WINDOWS (PowerShell) ---\n"
                'Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Force\n\n'
                "# --- LINUX (Bash) ---\n"
                "# Windows-only RDP configuration"
            ),
        }

        for rule in rules_data:
            # 2.1 Upsert Rule first (with no remediation linked)
            existing_rule = (
                db.query(ComplianceRule).filter(ComplianceRule.id == rule["id"]).first()
            )
            if not existing_rule:
                existing_rule = ComplianceRule(
                    id=rule["id"],
                    rule_family_code=rule["rule_family_code"],
                    version_number=rule["version_number"],
                    check_type=rule["check_type"],
                    evidence_source=rule["evidence_source"],
                    target_platform=rule["target_platform"],
                    check_definition=rule["check_definition"],
                    severity=rule["severity"],
                    severity_weight=rule["severity_weight"],
                    remediation_id=None,
                    status="active",
                )
                db.add(existing_rule)
                print(f"  + Created compliance rule: {rule['id']}")
            else:
                existing_rule.check_definition = rule["check_definition"]
                existing_rule.evidence_source = rule["evidence_source"]

            db.flush()

            # 2.2 Upsert Remediation pointing to the rule_id
            rem_id = rule["remediation_id_target"]
            cmd = FIX_COMMANDS.get(rule["rule_family_code"])
            existing_rem = (
                db.query(ComplianceRemediation)
                .filter(ComplianceRemediation.id == rem_id)
                .first()
            )
            if not existing_rem:
                existing_rem = ComplianceRemediation(
                    id=rem_id,
                    rule_id=rule["id"],
                    recommendation_text=rule["recommendation_text"],
                    fix_type="script" if cmd else "manual",
                    fix_command=cmd,
                )
                db.add(existing_rem)
                print(f"  + Created remediation: {rem_id}")
            else:
                existing_rem.rule_id = rule["id"]
                existing_rem.recommendation_text = rule["recommendation_text"]
                existing_rem.fix_type = "script" if cmd else "manual"
                existing_rem.fix_command = cmd

            db.flush()

            # 2.3 Link remediation back to rule
            existing_rule.remediation_id = rem_id
            db.flush()

            # Set junction mappings to ISO controls
            control_id = rule["control_id"]
            control_exists = (
                db.query(ComplianceControl)
                .filter(ComplianceControl.id == control_id)
                .first()
            )
            if not control_exists:
                print(
                    f"Warning: Control {control_id} does not exist in the database! Skipping link."
                )
                continue

            link = (
                db.query(ComplianceRuleControl)
                .filter(
                    ComplianceRuleControl.rule_id == rule["id"],
                    ComplianceRuleControl.control_id == control_id,
                )
                .first()
            )
            if not link:
                new_link = ComplianceRuleControl(
                    rule_id=rule["id"], control_id=control_id
                )
                db.add(new_link)
                print(f"    - Mapped rule {rule['id']} to control {control_id}")

        db.commit()

        # 4. Find scanned target asset: 10.180.6.14
        target_ip = "10.180.5.190"
        asset = db.query(Asset).filter(Asset.ip_address == target_ip).first()
        if not asset:
            print(
                f"\n[Info] Asset with IP address '{target_ip}' was not found in the 'assets' table."
            )
            print(
                "Please make sure you have run the Asset Discovery Scan for this host first."
            )
            return

        print(f"\nFound asset: {asset.ip_address} (ID={asset.id}, Org={asset.org_id})")

        org = db.query(Organization).filter(Organization.id == asset.org_id).first()
        user = db.query(User).filter(User.org_id == org.id).first()
        if not user:
            user = db.query(User).first()

        now = datetime.now(timezone.utc)

        # Register Framework
        tenant_fw = (
            db.query(ComplianceTenantFramework)
            .filter(
                ComplianceTenantFramework.tenant_id == org.id,
                ComplianceTenantFramework.framework_id == framework_id,
            )
            .first()
        )

        if not tenant_fw:
            tenant_fw = ComplianceTenantFramework(
                id=f"ctf_{org.id}_{framework_id}",
                tenant_id=org.id,
                framework_id=framework_id,
                is_enabled=True,
                enabled_by=user.id if user else None,
                enabled_at=now,
            )
            db.add(tenant_fw)
            print(f"  - Registered ISO 27001 framework to tenant: {org.name}")

        # Create Baseline Policy
        policy_id = f"cpl_{org.id}_iso27001_default"
        policy = (
            db.query(CompliancePolicy).filter(CompliancePolicy.id == policy_id).first()
        )
        if not policy:
            policy = CompliancePolicy(
                id=policy_id,
                framework_id=framework_id,
                tenant_id=org.id,
                policy_family_code="POL-ISO27001-DEFAULT",
                version_number=1,
                name="ISO/IEC 27001:2022 Default Compliance Policy",
                target_platform="any",
                status="active",
                is_active=True,
                created_by=user.id if user else None,
                created_at=now,
            )
            db.add(policy)
            print(f"  - Created compliance policy baseline: {policy.name}")
        else:
            policy.name = "ISO/IEC 27001:2022 Default Compliance Policy"
            policy.policy_family_code = "POL-ISO27001-DEFAULT"

        db.flush()

        # Link rules to policy
        for rule in rules_data:
            link = (
                db.query(CompliancePolicyRule)
                .filter(
                    CompliancePolicyRule.policy_id == policy_id,
                    CompliancePolicyRule.rule_id == rule["id"],
                )
                .first()
            )
            if not link:
                new_link = CompliancePolicyRule(policy_id=policy_id, rule_id=rule["id"])
                db.add(new_link)

        # 5. Create compliance scan run and execute compliance evaluation
        scan_run_id = f"run_{org.id[:8]}_{datetime.now().strftime('%M%S%f')}"
        run = ComplianceScanRun(
            id=scan_run_id,
            tenant_id=org.id,
            framework_id=framework_id,
            policy_id=policy_id,
            status="queued",
            scope={"asset_ids": [asset.id]},
            started_at=now,
        )
        db.add(run)
        db.commit()
        print(f"  - Created scan run record: {scan_run_id}")

        # Run compliance task synchronously
        print(
            f"  - Launching compliance evaluation rule check engine for Asset: {asset.ip_address}..."
        )
        result = run_scan_task(scan_run_id, org.id)
        print(f"  - Compliance evaluation finished! Result: {result}")

    except Exception as e:
        db.rollback()
        print(f"Error seeding rules/running evaluation: {str(e)}")
    finally:
        db.close()


if __name__ == "__main__":
    seed_and_evaluate()
