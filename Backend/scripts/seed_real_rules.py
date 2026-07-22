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
                "id": "crl_cert_in_log_180d",
                "rule_family_code": "CERT-LOG-180D",
                "version_number": 1,
                "check_type": "command_output",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "retention_days",
                    "operator": "gte",
                    "expected": 180,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_vuln_critical_v1",
                "control_id": "cct_cert_in_2022_cert_in_log_1",
                "recommendation_text": "Configure system and audit log retention policies to preserve logs for at least 180 days within Indian jurisdiction.",
            },
            {
                "id": "crl_cert_in_ntp_sync",
                "rule_family_code": "CERT-NTP-SYNC",
                "version_number": 1,
                "check_type": "command_output",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "ntp_servers",
                    "operator": "contains",
                    "expected": ["samay.nplindia.in", "nic.in"],
                },
                "severity": "medium",
                "severity_weight": 5,
                "remediation_id_target": "rem_vuln_high_v1",
                "control_id": "cct_cert_in_2022_cert_in_log_2",
                "recommendation_text": "Synchronize system clock with official NPL India (samay.nplindia.in) or NIC time servers.",
            },
            {
                "id": "crl_cert_in_ir_6hr",
                "rule_family_code": "CERT-IR-6HR",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "incident_reporting_sla_hours",
                    "operator": "lte",
                    "expected": 6,
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_vuln_critical_v1",
                "control_id": "cct_cert_in_2022_cert_in_ir_1",
                "recommendation_text": "Ensure incident response procedures enforce mandatory 6-hour incident reporting SLA to CERT-In.",
            },
            {
                "id": "crl_cert_in_vpn_5yr",
                "rule_family_code": "CERT-VPN-5YR",
                "version_number": 1,
                "check_type": "command_output",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "vpn_log_retention_years",
                    "operator": "gte",
                    "expected": 5,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_vuln_critical_v1",
                "control_id": "cct_cert_in_2022_cert_in_am_1",
                "recommendation_text": "Configure VPN access log retention to preserve user subscriber and IP allocation records for at least 5 years.",
            },
            {
                "id": "crl_cert_in_mfa_admin",
                "rule_family_code": "CERT-MFA-ADMIN",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "mfa_enforced_admin",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_vuln_critical_v1",
                "control_id": "cct_cert_in_2022_cert_in_ac_1",
                "recommendation_text": "Enforce Multi-Factor Authentication (MFA) across all administrative accounts and management portals.",
            },
            {
                "id": "crl_cert_in_vm_audit",
                "rule_family_code": "CERT-VM-AUDIT",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "last_scan_days_ago",
                    "operator": "lte",
                    "expected": 90,
                },
                "severity": "medium",
                "severity_weight": 5,
                "remediation_id_target": "rem_vuln_high_v1",
                "control_id": "cct_cert_in_2022_cert_in_vm_1",
                "recommendation_text": "Conduct periodic ICT vulnerability assessments and security posture audits at least every 90 days.",
            },
            {
                "id": "crl_pci_log_daily",
                "rule_family_code": "PCI-LOG-DAILY",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "pci_log_daily_reviewed",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_pci_log_daily_v1",
                "control_id": "cct_pci_dss_v4_pci_10_4_1",
                "recommendation_text": "Establish and enforce daily log review procedures for all security events and critical CDE system logs.",
            },
            {
                "id": "crl_pci_auth_mfa",
                "rule_family_code": "PCI-AUTH-MFA",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "pam_mfa_enforced",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_pci_auth_mfa_v1",
                "control_id": "cct_pci_dss_v4_pci_8_4_2",
                "recommendation_text": "Enforce Multi-Factor Authentication (MFA) for all administrative and user access to the cardholder data environment (CDE).",
            },
            {
                "id": "crl_pci_asv_fresh",
                "rule_family_code": "PCI-ASV-FRESH",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "asv_scan_fresh",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_pci_asv_fresh_v1",
                "control_id": "cct_pci_dss_v4_pci_11_3_2",
                "recommendation_text": "Ensure passing ASV external vulnerability scans are executed at least once every 90 days (quarterly) by an Approved Scanning Vendor.",
            },
            {
                "id": "crl_pci_fim_active",
                "rule_family_code": "PCI-FIM-ACTIVE",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "fim_active",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_pci_fim_active_v1",
                "control_id": "cct_pci_dss_v4_pci_11_5_1_1",
                "recommendation_text": "Deploy a File Integrity Monitoring (FIM) mechanism to monitor and alert on unauthorized changes to critical system and configuration files.",
            },
            {
                "id": "crl_pci_ir_test_365d",
                "rule_family_code": "PCI-IR-TEST-365D",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "ir_test_fresh_365d",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "medium",
                "severity_weight": 5,
                "remediation_id_target": "rem_pci_ir_test_365d_v1",
                "control_id": "cct_pci_dss_v4_pci_12_10_2",
                "recommendation_text": "Conduct and document an incident response plan tabletop test exercise at least once every 365 days (annually).",
            },
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

        # Dynamically generate rules for all remaining controls in db
        controls_in_db = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == framework_id)
            .all()
        )
        for ctrl in controls_in_db:
            if ctrl.id not in mapped_control_ids:
                # Extract clean control number suffix (e.g. 5_1, 8_34, gv_oc_01)
                raw_num = ctrl.id.replace("cct_iso27001_2022_", "").replace(
                    "cct_nist_csf_v2_", ""
                )
                rule_id = f"crl_auto_gen_{raw_num.replace('.', '_')}"

                rules_data.append(
                    {
                        "id": rule_id,
                        "rule_family_code": f"RULE-{raw_num.replace('_', '.')}",
                        "version_number": 1,
                        "check_type": "api_response",
                        "evidence_source": (
                            "auto_scan"
                            if getattr(ctrl, "scannable_type", "auto") == "auto"
                            else "manual"
                        ),
                        "target_platform": "any",
                        "check_definition": {
                            "key": "status",
                            "operator": "==",
                            "expected": "PASS",
                        },
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
            "PCI-FIM-ACTIVE": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Write-Host 'Deploying and configuring Microsoft FIM / audit policy...'\n"
                "Auditpol /set /subcategory:'File System' /success:enable /failure:enable\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo apt-get install -y aide || sudo yum install -y aide\n"
                "sudo aideinit"
            ),
            "PCI-AUTH-MFA": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Write-Host 'Enforcing MFA via Azure AD or Duo PAM agent...'\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo apt-get install -y libpam-duo || sudo yum install -y duo_unix\n"
                "sudo sed -i 's/auth       stack          password-auth/auth       required       pam_duo.so/' /etc/pam.d/sshd"
            ),
            "PCI-LOG-DAILY": (
                "# --- MANUAL CHECK ---\n"
                "# Ensure daily log review checklists are signed off and saved to evidentiary logs repository."
            ),
            "PCI-ASV-FRESH": (
                "# --- MANUAL CHECK ---\n"
                "# Contact Approved Scanning Vendor (ASV) and schedule external scans. Upload passing attestation scan reports."
            ),
            "PCI-IR-TEST-365D": (
                "# --- MANUAL CHECK ---\n"
                "# Schedule and coordinate annual incident response plan tabletop simulation exercise."
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

        # Also map rules to NIST CSF 2.0 controls via crosswalk references and auto-generate NIST rules
        nist_framework = (
            db.query(ComplianceFramework)
            .filter(ComplianceFramework.id == "cfw_nist_csf_v2")
            .first()
        )
        if nist_framework:
            nist_controls = (
                db.query(ComplianceControl)
                .filter(ComplianceControl.framework_id == "cfw_nist_csf_v2")
                .all()
            )
            for nist_ctrl in nist_controls:
                # 1. Check crosswalk for ISO controls mapped to existing rules
                mapped = False
                if nist_ctrl.crosswalk:
                    for iso_num in nist_ctrl.crosswalk:
                        iso_ctrl_id = f"cct_iso27001_2022_{iso_num.lower().replace('a.', '').replace('.', '_')}"
                        linked_rules = (
                            db.query(ComplianceRuleControl)
                            .filter(ComplianceRuleControl.control_id == iso_ctrl_id)
                            .all()
                        )
                        for r_link in linked_rules:
                            n_link = (
                                db.query(ComplianceRuleControl)
                                .filter(
                                    ComplianceRuleControl.rule_id == r_link.rule_id,
                                    ComplianceRuleControl.control_id == nist_ctrl.id,
                                )
                                .first()
                            )
                            if not n_link:
                                db.add(
                                    ComplianceRuleControl(
                                        rule_id=r_link.rule_id,
                                        control_id=nist_ctrl.id,
                                    )
                                )
                                mapped = True

                # 2. Auto-generate manual rule for unmapped NIST controls
                if not mapped:
                    raw_id = (
                        nist_ctrl.control_number.lower()
                        .replace(".", "_")
                        .replace("-", "_")
                    )
                    rule_id = f"crl_nist_auto_gen_{raw_id}"
                    rule_exists = (
                        db.query(ComplianceRule)
                        .filter(ComplianceRule.id == rule_id)
                        .first()
                    )
                    if not rule_exists:
                        n_rule = ComplianceRule(
                            id=rule_id,
                            rule_family_code=f"RULE-NIST-{nist_ctrl.control_number}",
                            version_number=1,
                            check_type="api_response",
                            evidence_source="manual",
                            target_platform="any",
                            check_definition={},
                            severity="medium",
                            severity_weight=5,
                            status="active",
                        )
                        db.add(n_rule)
                        db.flush()

                    n_link = (
                        db.query(ComplianceRuleControl)
                        .filter(
                            ComplianceRuleControl.rule_id == rule_id,
                            ComplianceRuleControl.control_id == nist_ctrl.id,
                        )
                        .first()
                    )
                    if not n_link:
                        db.add(
                            ComplianceRuleControl(
                                rule_id=rule_id, control_id=nist_ctrl.id
                            )
                        )

            db.commit()
            print("  - Successfully mapped rules and controls for NIST CSF v2.0")

        # Also map rules to CIS Controls v8.1 via crosswalk references and auto-generate CIS rules
        cis_framework = (
            db.query(ComplianceFramework)
            .filter(ComplianceFramework.id == "cfw_cis_v8_1")
            .first()
        )
        if cis_framework:
            cis_controls = (
                db.query(ComplianceControl)
                .filter(ComplianceControl.framework_id == "cfw_cis_v8_1")
                .all()
            )
            for cis_ctrl in cis_controls:
                mapped = False
                if cis_ctrl.crosswalk:
                    for iso_num in cis_ctrl.crosswalk:
                        iso_ctrl_id = f"cct_iso27001_2022_{iso_num.lower().replace('a.', '').replace('.', '_')}"
                        linked_rules = (
                            db.query(ComplianceRuleControl)
                            .filter(ComplianceRuleControl.control_id == iso_ctrl_id)
                            .all()
                        )
                        for r_link in linked_rules:
                            c_link = (
                                db.query(ComplianceRuleControl)
                                .filter(
                                    ComplianceRuleControl.rule_id == r_link.rule_id,
                                    ComplianceRuleControl.control_id == cis_ctrl.id,
                                )
                                .first()
                            )
                            if not c_link:
                                db.add(
                                    ComplianceRuleControl(
                                        rule_id=r_link.rule_id,
                                        control_id=cis_ctrl.id,
                                    )
                                )
                                mapped = True

                # Ensure every CIS Safeguard has a dedicated 1:1 baseline rule
                raw_id = (
                    cis_ctrl.control_number.lower().replace(".", "_").replace("-", "_")
                )
                rule_id = f"crl_cis_auto_gen_{raw_id}"
                rule_exists = (
                    db.query(ComplianceRule)
                    .filter(ComplianceRule.id == rule_id)
                    .first()
                )
                if not rule_exists:
                    c_rule = ComplianceRule(
                        id=rule_id,
                        rule_family_code=f"RULE-CIS-{cis_ctrl.control_number}",
                        version_number=1,
                        check_type="api_response",
                        evidence_source=(
                            cis_ctrl.scannability
                            if cis_ctrl.scannability != "manual"
                            else "manual"
                        ),
                        target_platform="any",
                        check_definition={},
                        severity="medium",
                        severity_weight=5,
                        status="active",
                    )
                    db.add(c_rule)
                    db.flush()

                c_link = (
                    db.query(ComplianceRuleControl)
                    .filter(
                        ComplianceRuleControl.rule_id == rule_id,
                        ComplianceRuleControl.control_id == cis_ctrl.id,
                    )
                    .first()
                )
                if not c_link:
                    db.add(
                        ComplianceRuleControl(rule_id=rule_id, control_id=cis_ctrl.id)
                    )

            db.commit()
            print("  - Successfully mapped rules and controls for CIS Controls v8.1")

        # Also map rules to SOC 2 Type II via crosswalk references and auto-generate SOC 2 rules
        soc2_framework = (
            db.query(ComplianceFramework)
            .filter(ComplianceFramework.id == "cfw_soc2_type2")
            .first()
        )
        if soc2_framework:
            soc2_controls = (
                db.query(ComplianceControl)
                .filter(ComplianceControl.framework_id == "cfw_soc2_type2")
                .all()
            )
            for soc2_ctrl in soc2_controls:
                if soc2_ctrl.crosswalk:
                    for iso_num in soc2_ctrl.crosswalk:
                        iso_ctrl_id = f"cct_iso27001_2022_{iso_num.lower().replace('a.', '').replace('.', '_')}"
                        linked_rules = (
                            db.query(ComplianceRuleControl)
                            .filter(ComplianceRuleControl.control_id == iso_ctrl_id)
                            .all()
                        )
                        for r_link in linked_rules:
                            c_link = (
                                db.query(ComplianceRuleControl)
                                .filter(
                                    ComplianceRuleControl.rule_id == r_link.rule_id,
                                    ComplianceRuleControl.control_id == soc2_ctrl.id,
                                )
                                .first()
                            )
                            if not c_link:
                                db.add(
                                    ComplianceRuleControl(
                                        rule_id=r_link.rule_id,
                                        control_id=soc2_ctrl.id,
                                    )
                                )

                # Ensure every SOC 2 Criterion has a dedicated 1:1 baseline rule
                raw_id = (
                    soc2_ctrl.control_number.lower().replace(".", "_").replace("-", "_")
                )
                rule_id = f"crl_soc2_auto_gen_{raw_id}"
                rule_exists = (
                    db.query(ComplianceRule)
                    .filter(ComplianceRule.id == rule_id)
                    .first()
                )
                if not rule_exists:
                    c_rule = ComplianceRule(
                        id=rule_id,
                        rule_family_code=f"RULE-SOC2-{soc2_ctrl.control_number}",
                        version_number=1,
                        check_type="api_response",
                        evidence_source=(
                            soc2_ctrl.scannability
                            if soc2_ctrl.scannability != "manual"
                            else "manual"
                        ),
                        target_platform="any",
                        check_definition={},
                        severity="medium",
                        severity_weight=5,
                        status="active",
                    )
                    db.add(c_rule)
                    db.flush()

                c_link = (
                    db.query(ComplianceRuleControl)
                    .filter(
                        ComplianceRuleControl.rule_id == rule_id,
                        ComplianceRuleControl.control_id == soc2_ctrl.id,
                    )
                    .first()
                )
                if not c_link:
                    db.add(
                        ComplianceRuleControl(rule_id=rule_id, control_id=soc2_ctrl.id)
                    )

            db.commit()
            print("  - Successfully mapped rules and controls for SOC 2 Type II")

        # Map rules and controls for CERT-In Directions 2022
        certin_controls = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == "cfw_cert_in_2022")
            .all()
        )
        if certin_controls:
            for certin_ctrl in certin_controls:
                raw_id = (
                    certin_ctrl.control_number.lower()
                    .replace(".", "_")
                    .replace("-", "_")
                )
                rule_id = f"crl_cert_in_auto_gen_{raw_id}"
                rule_exists = (
                    db.query(ComplianceRule)
                    .filter(ComplianceRule.id == rule_id)
                    .first()
                )
                if not rule_exists:
                    c_rule = ComplianceRule(
                        id=rule_id,
                        rule_family_code=f"RULE-CERTIN-{certin_ctrl.control_number}",
                        version_number=1,
                        check_type="api_response",
                        evidence_source=(
                            certin_ctrl.scannability
                            if certin_ctrl.scannability != "manual"
                            else "manual"
                        ),
                        target_platform="any",
                        check_definition={},
                        severity="medium",
                        severity_weight=5,
                        status="active",
                    )
                    db.add(c_rule)
                    db.flush()

                c_link = (
                    db.query(ComplianceRuleControl)
                    .filter(
                        ComplianceRuleControl.rule_id == rule_id,
                        ComplianceRuleControl.control_id == certin_ctrl.id,
                    )
                    .first()
                )
                if not c_link:
                    db.add(
                        ComplianceRuleControl(
                            rule_id=rule_id, control_id=certin_ctrl.id
                        )
                    )

            db.commit()
            print(
                "  - Successfully mapped rules and controls for CERT-In Directions 2022"
            )

        # Map rules and controls for PCI-DSS v4.0
        pci_controls = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == "cfw_pci_dss_v4")
            .all()
        )
        if pci_controls:
            for pci_ctrl in pci_controls:
                # Crosswalk mapping from ISO 27001 rules
                if pci_ctrl.crosswalk:
                    for iso_num in pci_ctrl.crosswalk:
                        if not iso_num.startswith("ISO27001:"):
                            continue
                        iso_ref = iso_num.replace("ISO27001:", "").strip()
                        iso_ctrl_id = f"cct_iso27001_2022_{iso_ref.lower().replace('a.', '').replace('.', '_')}"
                        linked_rules = (
                            db.query(ComplianceRuleControl)
                            .filter(ComplianceRuleControl.control_id == iso_ctrl_id)
                            .all()
                        )
                        for r_link in linked_rules:
                            p_link = (
                                db.query(ComplianceRuleControl)
                                .filter(
                                    ComplianceRuleControl.rule_id == r_link.rule_id,
                                    ComplianceRuleControl.control_id == pci_ctrl.id,
                                )
                                .first()
                            )
                            if not p_link:
                                db.add(
                                    ComplianceRuleControl(
                                        rule_id=r_link.rule_id,
                                        control_id=pci_ctrl.id,
                                    )
                                )

                # Ensure every PCI control has a dedicated 1:1 baseline rule
                raw_id = (
                    pci_ctrl.control_number.lower().replace(".", "_").replace("-", "_")
                )
                rule_id = f"crl_pci_auto_gen_{raw_id}"
                rule_exists = (
                    db.query(ComplianceRule)
                    .filter(ComplianceRule.id == rule_id)
                    .first()
                )
                if not rule_exists:
                    c_rule = ComplianceRule(
                        id=rule_id,
                        rule_family_code=f"RULE-PCI-{pci_ctrl.control_number}",
                        version_number=1,
                        check_type="api_response",
                        evidence_source=(
                            pci_ctrl.scannability
                            if pci_ctrl.scannability != "manual"
                            else "manual"
                        ),
                        target_platform="any",
                        check_definition={},
                        severity="medium",
                        severity_weight=5,
                        status="active",
                    )
                    db.add(c_rule)
                    db.flush()

                p_link = (
                    db.query(ComplianceRuleControl)
                    .filter(
                        ComplianceRuleControl.rule_id == rule_id,
                        ComplianceRuleControl.control_id == pci_ctrl.id,
                    )
                    .first()
                )
                if not p_link:
                    db.add(
                        ComplianceRuleControl(rule_id=rule_id, control_id=pci_ctrl.id)
                    )

            db.commit()
            print("  - Successfully mapped rules and controls for PCI-DSS v4.0")

        now = datetime.now(timezone.utc)

        orgs = db.query(Organization).all()
        for org in orgs:
            user = db.query(User).filter(User.org_id == org.id).first()
            if not user:
                user = db.query(User).first()

            # Register Frameworks and Bootstrap Baseline Policies (ISO 27001, NIST CSF v2.0, CIS Controls v8.1, SOC 2 Type II, CERT-In 2022)
            for fw_code_id in [
                "cfw_iso27001_2022",
                "cfw_nist_csf_v2",
                "cfw_cis_v8_1",
                "cfw_soc2_type2",
                "cfw_cert_in_2022",
                "cfw_pci_dss_v4",
            ]:
                fw_obj = (
                    db.query(ComplianceFramework)
                    .filter(ComplianceFramework.id == fw_code_id)
                    .first()
                )
                if not fw_obj:
                    continue

                tenant_fw = (
                    db.query(ComplianceTenantFramework)
                    .filter(
                        ComplianceTenantFramework.tenant_id == org.id,
                        ComplianceTenantFramework.framework_id == fw_code_id,
                    )
                    .first()
                )

                if not tenant_fw:
                    tenant_fw = ComplianceTenantFramework(
                        id=f"ctf_{org.id}_{fw_code_id}",
                        tenant_id=org.id,
                        framework_id=fw_code_id,
                        is_enabled=True,
                        enabled_by=user.id if user else None,
                        enabled_at=now,
                    )
                    db.add(tenant_fw)

                # Create Baseline Policy
                policy_id = f"cpl_{org.id}_{fw_obj.code.lower()}_default"
                policy = (
                    db.query(CompliancePolicy)
                    .filter(CompliancePolicy.id == policy_id)
                    .first()
                )
                if not policy:
                    policy = CompliancePolicy(
                        id=policy_id,
                        framework_id=fw_code_id,
                        tenant_id=org.id,
                        policy_family_code=f"POL-{org.id.upper().replace('.', '_')}-{fw_obj.code.upper()}-DEFAULT",
                        version_number=1,
                        name=f"{fw_obj.name} Default Policy Baseline",
                        target_platform="any",
                        status="active",
                        is_active=True,
                        created_by=user.id if user else None,
                        created_at=now,
                    )
                    db.add(policy)
                else:
                    policy.name = f"{fw_obj.name} Default Policy Baseline"

                db.flush()

                # Link framework rules to policy
                fw_rules = (
                    db.query(ComplianceRule)
                    .join(
                        ComplianceRuleControl,
                        ComplianceRuleControl.rule_id == ComplianceRule.id,
                    )
                    .join(
                        ComplianceControl,
                        ComplianceControl.id == ComplianceRuleControl.control_id,
                    )
                    .filter(ComplianceControl.framework_id == fw_code_id)
                    .distinct()
                    .all()
                )
                for rule in fw_rules:
                    link = (
                        db.query(CompliancePolicyRule)
                        .filter(
                            CompliancePolicyRule.policy_id == policy.id,
                            CompliancePolicyRule.rule_id == rule.id,
                        )
                        .first()
                    )
                    if not link:
                        new_link = CompliancePolicyRule(
                            policy_id=policy.id, rule_id=rule.id
                        )
                        db.add(new_link)
                db.commit()

        # 4. Find scanned target asset: 10.180.6.14
        target_ip = "10.180.6.14"
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
