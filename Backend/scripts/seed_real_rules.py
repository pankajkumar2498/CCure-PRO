"""
Script: seed_real_rules.py
Purpose: Seed real compliance rules based on target scan findings, map them to ISO controls,
         create a baseline policy, and immediately evaluate compliance findings for host 10.180.6.14.
Usage:   python -m scripts.seed_real_rules
"""

import os
import sys
from datetime import datetime, timezone
from typing import Optional

# Ensure the root of the project is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.compliance_tasks import run_scan_task
from core.compliance_frameworks import is_active as is_active_framework
from core.nist_csf import FUNCTION_NAMES
from db.base import SessionLocal
from db.models import Asset, User
from db.models.compliance import (
    ComplianceControl,
    ComplianceFinding,
    ComplianceFramework,
    CompliancePolicy,
    CompliancePolicyRule,
    ComplianceRemediation,
    ComplianceRule,
    ComplianceRuleControl,
    ComplianceScanRun,
    ComplianceTenantFramework,
)
from db.models.rbac import Organization


def _drop_rule_from_control(db, control_id: str, rule_id: str) -> None:
    """Unlinks a rule from a control and removes the findings it produced.

    Leaving the findings behind makes the unlink cosmetic: `roll_up_statuses`
    reads every finding on the control, so a revoked rule's verdict keeps
    deciding the control long after the rule stopped applying to it. The rule
    itself is left alone — it is shared across frameworks.
    """
    db.query(ComplianceFinding).filter(
        ComplianceFinding.control_id == control_id,
        ComplianceFinding.rule_id == rule_id,
    ).delete(synchronize_session=False)
    db.query(ComplianceRuleControl).filter(
        ComplianceRuleControl.rule_id == rule_id,
        ComplianceRuleControl.control_id == control_id,
    ).delete(synchronize_session=False)


def seed_and_evaluate(target_ip: Optional[str] = None):
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
                "id": "crl_dpdp_pii_enc",
                "rule_family_code": "DPDP-PII-ENC",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "pii_encryption_enabled",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_vuln_critical_v1",
                "control_id": "cct_dpdp_2023_dpdp_5_1",
                "recommendation_text": "Enforce mandatory AES-256 encryption at rest and TLS 1.2+ in transit for all Personal Identifiable Information (PII) databases.",
            },
            {
                "id": "crl_dpdp_dpo_app",
                "rule_family_code": "DPDP-DPO-APP",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "dpo_designated",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_vuln_high_v1",
                "control_id": "cct_dpdp_2023_dpdp_6_1",
                "recommendation_text": "Formally designate a resident Data Protection Officer (DPO) and publish contact details to ensure statutory compliance under DPDP Act Section 10.",
            },
            {
                "id": "crl_gdpr_art32_enc",
                "rule_family_code": "GDPR-ART32-ENC",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "pii_encryption_enabled",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_vuln_critical_v1",
                "control_id": "cct_gdpr_gdpr_5_1",
                "recommendation_text": "Implement technical measures under GDPR Art. 32 including state-of-the-art encryption and pseudonymization for personal data processing.",
            },
            {
                "id": "crl_web_sqli_privacy",
                "rule_family_code": "PRIV-WEB-SQLI",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "web_vulnerability_audit",
                "target_platform": "any",
                "check_definition": {
                    "key": "sqli_detected",
                    "operator": "equals",
                    "expected": False,
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_vuln_critical_v1",
                "control_id": "cct_dpdp_2023_dpdp_2_1",
                "recommendation_text": "Remediate SQL Injection vulnerabilities in web applications to protect PII against unauthorized data exfiltration.",
            },
            # NIST SP 800-53 Rev. 5 Rules
            {
                "id": "crl_nist_ac2_acct_mgmt",
                "rule_family_code": "NIST-AC-2-ACCT",
                "version_number": 1,
                "check_type": "command_output",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "account_review_completed",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_vuln_high_v1",
                "control_id": "cct_nist_800_53_r5_ac_2",
                "recommendation_text": "Establish automated account management workflows and conduct regular user account reviews per NIST AC-2.",
            },
            {
                "id": "crl_nist_au6_log_review",
                "rule_family_code": "NIST-AU-6-LOG",
                "version_number": 1,
                "check_type": "command_output",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "log_review_frequency_days",
                    "operator": "lte",
                    "expected": 7,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_vuln_high_v1",
                "control_id": "cct_nist_800_53_r5_au_6",
                "recommendation_text": "Analyze audit log records at least weekly to detect suspicious behavior per NIST AU-6.",
            },
            {
                "id": "crl_nist_si2_patch",
                "rule_family_code": "NIST-SI-2-PATCH",
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
                "control_id": "cct_nist_800_53_r5_si_2",
                "recommendation_text": "Remediate system security flaws and patch critical vulnerabilities within mandatory timelines per NIST SI-2.",
            },
            {
                "id": "crl_nist_ia5_pwd_complex",
                "rule_family_code": "NIST-IA-5-PWD",
                "version_number": 1,
                "check_type": "command_output",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "password_complexity_enforced",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_vuln_critical_v1",
                "control_id": "cct_nist_800_53_r5_ia_5",
                "recommendation_text": "Enforce strong password complexity and authenticator management standards per NIST IA-5.",
            },
            {
                "id": "crl_nist_sc28_enc_rest",
                "rule_family_code": "NIST-SC-28-ENC",
                "version_number": 1,
                "check_type": "command_output",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "disk_encryption_enabled",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_vuln_critical_v1",
                "control_id": "cct_nist_800_53_r5_sc_28",
                "recommendation_text": "Enable FIPS-validated disk encryption at rest for sensitive federal data per NIST SC-28.",
            },
            {
                "id": "crl_nist_cp9_backup",
                "rule_family_code": "NIST-CP-9-BAK",
                "version_number": 1,
                "check_type": "command_output",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "backup_frequency_days",
                    "operator": "lte",
                    "expected": 1,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_vuln_high_v1",
                "control_id": "cct_nist_800_53_r5_cp_9",
                "recommendation_text": "Execute daily automated system backups and test restoration integrity per NIST CP-9.",
            },
            {
                "id": "crl_nist_sr3_scrm_plan",
                "rule_family_code": "NIST-SR-3-SCRM",
                "version_number": 1,
                "check_type": "command_output",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "scrm_plan_documented",
                    "operator": "equals",
                    "expected": True,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_vuln_high_v1",
                "control_id": "cct_nist_800_53_r5_sr_3",
                "recommendation_text": "Document and enforce Supply Chain Risk Management (SCRM) controls and Software Bill of Materials (SBOM) tracking per NIST SR-3.",
            },
            {
                "id": "crl_nist_ra5_vuln_scan",
                "rule_family_code": "NIST-RA-5-SCAN",
                "version_number": 1,
                "check_type": "command_output",
                "evidence_source": "offline_configuration",
                "target_platform": "any",
                "check_definition": {
                    "key": "last_scan_days_ago",
                    "operator": "lte",
                    "expected": 30,
                },
                "severity": "medium",
                "severity_weight": 5,
                "remediation_id_target": "rem_vuln_high_v1",
                "control_id": "cct_nist_800_53_r5_ra_5",
                "recommendation_text": "Perform automated vulnerability monitoring and scanning at least every 30 days per NIST RA-5.",
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
            {
                "id": "crl_ot_modbus_502",
                "rule_family_code": "OT-MODBUS-502",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "services_ports",
                "target_platform": "any",
                "check_definition": {
                    "key": "open_ports",
                    "operator": "not_contains",
                    "expected": 502,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_ot_modbus_502_v1",
                "control_id": "cct_iec_62443_sr_2_3",
                "recommendation_text": "Restrict or eliminate unauthenticated Modbus TCP port 502 exposure across control zone boundaries.",
            },
            {
                "id": "crl_ot_siemens_s7_102",
                "rule_family_code": "OT-SIEMENS-S7-102",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "services_ports",
                "target_platform": "any",
                "check_definition": {
                    "key": "open_ports",
                    "operator": "not_contains",
                    "expected": 102,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_ot_siemens_s7_102_v1",
                "control_id": "cct_iec_62443_sr_5_1",
                "recommendation_text": "Restrict Siemens S7 protocol port 102 to designated Engineering Workstations using zone firewalls.",
            },
            {
                "id": "crl_ot_ethernet_ip_44818",
                "rule_family_code": "OT-ETHERNET-IP-44818",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "services_ports",
                "target_platform": "any",
                "check_definition": {
                    "key": "open_ports",
                    "operator": "not_contains",
                    "expected": 44818,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_ot_ethernet_ip_44818_v1",
                "control_id": "cct_iec_62443_sr_5_1",
                "recommendation_text": "Restrict EtherNet/IP CIP port 44818 access using industrial firewall ACLs.",
            },
            {
                "id": "crl_ot_bacnet_47808",
                "rule_family_code": "OT-BACNET-47808",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "services_ports",
                "target_platform": "any",
                "check_definition": {
                    "key": "open_ports",
                    "operator": "not_contains",
                    "expected": 47808,
                },
                "severity": "medium",
                "severity_weight": 6,
                "remediation_id_target": "rem_ot_bacnet_47808_v1",
                "control_id": "cct_iec_62443_sr_5_3",
                "recommendation_text": "Isolate BACnet building automation UDP port 47808 traffic from external networks.",
            },
            {
                "id": "crl_ot_jump_host_mfa",
                "rule_family_code": "OT-JUMP-HOST-MFA",
                "version_number": 1,
                "check_type": "command_output",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "attestation_criteria": {
                        "requirement": "Multi-factor authentication is enforced on the OT jump host.",
                        "verify": "Screenshot or configuration export of the jump host MFA policy.",
                    }
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_ot_jump_host_mfa_v1",
                "control_id": "cct_iec_62443_sr_1_1_re2",
                "recommendation_text": "Enforce mandatory Multi-Factor Authentication (MFA) for OT DMZ Jump Host access.",
            },
            {
                "id": "crl_sp82_modbus_502",
                "rule_family_code": "OT-SP82-MODBUS-502",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "services_ports",
                "target_platform": "any",
                "check_definition": {
                    "key": "open_ports",
                    "operator": "not_contains",
                    "expected": 502,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_sp82_modbus_502_v1",
                "control_id": "cct_nist_800_82_r3_sp82_sc_2",
                "recommendation_text": "Block or restrict unauthenticated Modbus TCP port 502 at OT zone boundaries per NIST SP 800-82 Rev. 3 network segmentation guidance.",
            },
            {
                "id": "crl_sp82_s7_102",
                "rule_family_code": "OT-SP82-S7-102",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "services_ports",
                "target_platform": "any",
                "check_definition": {
                    "key": "open_ports",
                    "operator": "not_contains",
                    "expected": 102,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_sp82_s7_102_v1",
                "control_id": "cct_nist_800_82_r3_sp82_sc_2",
                "recommendation_text": "Restrict Siemens S7 protocol port 102 to designated Engineering Workstations using industrial zone firewalls.",
            },
            {
                "id": "crl_sp82_cip_44818",
                "rule_family_code": "OT-SP82-CIP-44818",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "services_ports",
                "target_platform": "any",
                "check_definition": {
                    "key": "open_ports",
                    "operator": "not_contains",
                    "expected": 44818,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_sp82_cip_44818_v1",
                "control_id": "cct_nist_800_82_r3_sp82_sc_2",
                "recommendation_text": "Restrict EtherNet/IP CIP port 44818 access using industrial firewall ACLs per NIST SP 800-82 Rev. 3.",
            },
            {
                "id": "crl_sp82_sis_isolation",
                "rule_family_code": "OT-SP82-SIS-ISOLATION",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "attestation_criteria": {
                        "requirement": "The Safety Instrumented System network is isolated from the process control network.",
                        "verify": "Network diagram and firewall rule export showing the SIS boundary.",
                    }
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_sp82_sis_isolation_v1",
                "control_id": "cct_nist_800_82_r3_sp82_sc_4",
                "recommendation_text": "Ensure Safety Instrumented Systems (SIS) are physically or logically isolated from standard OT and IT networks per NIST SP 800-82 Rev. 3.",
            },
            {
                "id": "crl_sp82_jump_host_mfa",
                "rule_family_code": "OT-SP82-JUMP-HOST-MFA",
                "version_number": 1,
                "check_type": "command_output",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "attestation_criteria": {
                        "requirement": "Multi-factor authentication is enforced on the OT jump host.",
                        "verify": "Screenshot or configuration export of the jump host MFA policy.",
                    }
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_sp82_jump_host_mfa_v1",
                "control_id": "cct_nist_800_82_r3_sp82_ac_5",
                "recommendation_text": "Enforce mandatory Multi-Factor Authentication (MFA) on all OT bastion hosts and jump servers per NIST SP 800-82 Rev. 3.",
            },
            {
                "id": "crl_nerc_cip_005_esp",
                "rule_family_code": "NERC-CIP-005-ESP",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "manual",
                "target_platform": "network_device",
                "check_definition": {
                    "eacms_enabled": True,
                    "default_policy": "deny_all",
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_nerc_cip_005_esp_v1",
                "control_id": "cct_nerc_cip_cip_005_r1",
                "recommendation_text": "Enforce Electronic Security Perimeter (ESP) isolation and default-deny firewall ACLs on EACMS boundaries per NERC CIP-005-7.",
            },
            {
                "id": "crl_nerc_cip_005_mfa",
                "rule_family_code": "NERC-CIP-005-MFA",
                "version_number": 1,
                "check_type": "command_output",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "jump_host_mfa": True,
                    "session_recording": True,
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_nerc_cip_005_mfa_v1",
                "control_id": "cct_nerc_cip_cip_005_r2",
                "recommendation_text": "Require Multi-Factor Authentication (MFA) and OT DMZ jump host session recording for Interactive Remote Access per NERC CIP-005-7.",
            },
            {
                "id": "crl_nerc_cip_006_pacs",
                "rule_family_code": "NERC-CIP-006-PACS",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "pacs_alarm_monitoring": True,
                    "retention_days": 90,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_nerc_cip_006_pacs_v1",
                "control_id": "cct_nerc_cip_cip_006_r2",
                "recommendation_text": "Verify Physical Access Control System (PACS) electronic monitoring and intrusion alarm logging per NERC CIP-006-6.",
            },
            {
                "id": "crl_nerc_cip_007_ports",
                "rule_family_code": "NERC-CIP-007-PORTS",
                "version_number": 1,
                "check_type": "port_state",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "unused_ports_disabled": True,
                    "unnecessary_services_stopped": True,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_nerc_cip_007_ports_v1",
                "control_id": "cct_nerc_cip_cip_007_r1",
                "recommendation_text": "Disable all unused logical ports, physical interfaces, and unneeded network services per NERC CIP-007-6.",
            },
            {
                "id": "crl_nerc_cip_007_patch",
                "rule_family_code": "NERC-CIP-007-PATCH",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "patch_evaluation_max_days": 35,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_nerc_cip_007_patch_v1",
                "control_id": "cct_nerc_cip_cip_007_r2",
                "recommendation_text": "Evaluate security patches at least once every 35 calendar days and apply or document mitigation plans per NERC CIP-007-6.",
            },
            {
                "id": "crl_nerc_cip_007_malware",
                "rule_family_code": "NERC-CIP-007-MALWARE",
                "version_number": 1,
                "check_type": "service_status",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "antimalware_active": True,
                    "allowlisting_active": True,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_nerc_cip_007_malware_v1",
                "control_id": "cct_nerc_cip_cip_007_r3",
                "recommendation_text": "Deploy anti-malware software or application allowlisting on BES Cyber Assets per NERC CIP-007-6.",
            },
            {
                "id": "crl_nerc_cip_007_logs",
                "rule_family_code": "NERC-CIP-007-LOGS",
                "version_number": 1,
                "check_type": "file_content",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "log_retention_days": 90,
                    "login_events_logged": True,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_nerc_cip_007_logs_v1",
                "control_id": "cct_nerc_cip_cip_007_r4",
                "recommendation_text": "Enforce security event logging and 90-calendar-day audit log retention per NERC CIP-007-6.",
            },
            {
                "id": "crl_nerc_cip_010_baseline",
                "rule_family_code": "NERC-CIP-010-BASELINE",
                "version_number": 1,
                "check_type": "command_output",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "baseline_monitoring_max_days": 35,
                    "unauthorized_drift_alert": True,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_nerc_cip_010_baseline_v1",
                "control_id": "cct_nerc_cip_cip_010_r2",
                "recommendation_text": "Monitor baseline configurations every 35 calendar days and alert on unauthorized configuration drift per NERC CIP-010-4.",
            },
            {
                "id": "crl_nerc_cip_011_bcsi",
                "rule_family_code": "NERC-CIP-011-BCSI",
                "version_number": 1,
                "check_type": "file_content",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "encryption_algorithm": "AES-256",
                    "bcsi_encrypted_at_rest": True,
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_nerc_cip_011_bcsi_v1",
                "control_id": "cct_nerc_cip_cip_011_r1",
                "recommendation_text": "Encrypt BES Cyber System Information (BCSI) at rest and in transit using AES-256 per NERC CIP-011-3.",
            },
            {
                "id": "crl_nerc_cip_012_link",
                "rule_family_code": "NERC-CIP-012-LINK",
                "version_number": 1,
                "check_type": "tls_config",
                "evidence_source": "manual",
                "target_platform": "network_device",
                "check_definition": {
                    "tunnel_protocol": "IPsec_TLS",
                    "link_encryption": True,
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_nerc_cip_012_link_v1",
                "control_id": "cct_nerc_cip_cip_012_r1",
                "recommendation_text": "Encrypt real-time Control Center to Control Center communication links carrying operational data per NERC CIP-012-1.",
            },
            {
                "id": "crl_nis2_gov_risk",
                "rule_family_code": "NIS2-GOV-RISK",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "board_approval_required": True,
                    "risk_assessment_active": True,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_nis2_gov_risk_v1",
                "control_id": "cct_nis2_gov_01",
                "recommendation_text": "Maintain an approved cybersecurity risk policy and executive board governance oversight per EU NIS 2 Article 21.2(a).",
            },
            {
                "id": "crl_nis2_inc_24h",
                "rule_family_code": "NIS2-INC-24H",
                "version_number": 1,
                "check_type": "service_status",
                "evidence_source": "manual",
                "target_platform": "linux",
                "check_definition": {
                    "csirt_warning_sla_hours": 24,
                    "incident_triage_enabled": True,
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_nis2_inc_24h_v1",
                "control_id": "cct_nis2_inc_01",
                "recommendation_text": "Configure 24-hour Early Warning CSIRT notification integration per EU NIS 2 Article 21.2(b).",
            },
            {
                "id": "crl_nis2_inc_logs",
                "rule_family_code": "NIS2-INC-LOGS",
                "version_number": 1,
                "check_type": "file_content",
                "evidence_source": "manual",
                "target_platform": "linux",
                "check_definition": {
                    "syslog_active": True,
                    "min_retention_days": 180,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_nis2_inc_logs_v1",
                "control_id": "cct_nis2_inc_03",
                "recommendation_text": "Enforce central SIEM log forwarding and 180-day retention per EU NIS 2 Article 21.2(b).",
            },
            {
                "id": "crl_nis2_bc_backup",
                "rule_family_code": "NIS2-BC-BACKUP",
                "version_number": 1,
                "check_type": "file_content",
                "evidence_source": "manual",
                "target_platform": "windows",
                "check_definition": {
                    "backup_immutable": True,
                    "backup_frequency_hours": 24,
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_nis2_bc_backup_v1",
                "control_id": "cct_nis2_bc_01",
                "recommendation_text": "Enforce automated, immutable off-site backups with 24-hour frequency per EU NIS 2 Article 21.2(c).",
            },
            {
                "id": "crl_nis2_sec_vuln",
                "rule_family_code": "NIS2-SEC-VULN",
                "version_number": 1,
                "check_type": "command_output",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "max_critical_vuln_age_days": 7,
                    "continuous_scanning_enabled": True,
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_nis2_sec_vuln_v1",
                "control_id": "cct_nis2_sec_01",
                "recommendation_text": "Conduct continuous vulnerability scanning and remediate critical vulnerabilities within 7 days per EU NIS 2 Article 21.2(e).",
            },
            {
                "id": "crl_nis2_crypto_tls",
                "rule_family_code": "NIS2-CRYPTO-TLS",
                "version_number": 1,
                "check_type": "tls_config",
                "evidence_source": "manual",
                "target_platform": "network_device",
                "check_definition": {
                    "min_tls_version": "TLSv1.2",
                    "tls13_preferred": True,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_nis2_crypto_tls_v1",
                "control_id": "cct_nis2_crypto_01",
                "recommendation_text": "Enforce TLS 1.2+ / TLS 1.3 encryption and disable SSLv3/TLS 1.0/1.1 per EU NIS 2 Article 21.2(h).",
            },
            {
                "id": "crl_nis2_iam_rbac",
                "rule_family_code": "NIS2-IAM-RBAC",
                "version_number": 1,
                "check_type": "command_output",
                "evidence_source": "manual",
                "target_platform": "windows",
                "check_definition": {
                    "disable_inactive_days": 90,
                    "root_login_disabled": True,
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_nis2_iam_rbac_v1",
                "control_id": "cct_nis2_iam_01",
                "recommendation_text": "Enforce Least Privilege RBAC and auto-disable inactive accounts after 90 days per EU NIS 2 Article 21.2(i).",
            },
            {
                "id": "crl_nis2_mfa_enforce",
                "rule_family_code": "NIS2-MFA-ENFORCE",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "mfa_enforced_all_users": True,
                    "mfa_enforced_admins": True,
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_nis2_mfa_enforce_v1",
                "control_id": "cct_nis2_mfa_01",
                "recommendation_text": "Enforce mandatory Multi-Factor Authentication (MFA) across all administrative and user connections per EU NIS 2 Article 21.2(j).",
            },
            {
                "id": "crl_nis2_supply_sbom",
                "rule_family_code": "NIS2-SUPPLY-SBOM",
                "version_number": 1,
                "check_type": "command_output",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "sbom_generation_active": True,
                    "vulnerability_manifest_audit": True,
                    "platforms": ["windows", "linux", "any"],
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_nis2_supply_sbom_v1",
                "control_id": "cct_nis2_supply_02",
                "recommendation_text": "Maintain automated Software Bill of Materials (SBOM) manifests and audit third-party dependencies per EU NIS 2 Article 21.2(d).",
            },
            {
                "id": "crl_nis2_sec_cvd",
                "rule_family_code": "NIS2-SEC-CVD",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "security_txt_rfc9116_valid": True,
                    "cvd_policy_published": True,
                    "platforms": ["any"],
                },
                "severity": "medium",
                "severity_weight": 6,
                "remediation_id_target": "rem_nis2_sec_cvd_v1",
                "control_id": "cct_nis2_sec_02",
                "recommendation_text": "Publish a RFC 9116 security.txt file and Coordinated Vulnerability Disclosure (CVD) policy per EU NIS 2 Article 21.2(e).",
            },
            {
                "id": "crl_nis2_bc_dr_test",
                "rule_family_code": "NIS2-BC-DR-TEST",
                "version_number": 1,
                "check_type": "file_content",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "dr_test_frequency_days": 90,
                    "recovery_time_objective_minutes": 60,
                    "platforms": ["windows", "linux", "any"],
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_nis2_bc_dr_test_v1",
                "control_id": "cct_nis2_bc_03",
                "recommendation_text": "Conduct quarterly disaster recovery restoration testing and validate RTO/RPO metrics per EU NIS 2 Article 21.2(c).",
            },
            {
                "id": "crl_nis2_hygiene_pwd",
                "rule_family_code": "NIS2-HYGIENE-PWD",
                "version_number": 1,
                "check_type": "registry",
                "evidence_source": "manual",
                "target_platform": "windows",
                "check_definition": {
                    "min_password_length": 14,
                    "password_complexity_enabled": True,
                    "max_password_age_days": 90,
                    "platforms": ["windows"],
                },
                "severity": "medium",
                "severity_weight": 6,
                "remediation_id_target": "rem_nis2_hygiene_pwd_v1",
                "control_id": "cct_nis2_hygiene_02",
                "recommendation_text": "Enforce strong password policy parameters (min 14 chars, complexity, 90-day max age) per EU NIS 2 Article 21.2(g).",
            },
            {
                "id": "crl_nis2_crypto_rest",
                "rule_family_code": "NIS2-CRYPTO-REST",
                "version_number": 1,
                "check_type": "command_output",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "data_at_rest_encryption": "AES-256",
                    "bitlocker_luks_active": True,
                    "platforms": ["windows", "linux", "any"],
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_nis2_crypto_rest_v1",
                "control_id": "cct_nis2_crypto_02",
                "recommendation_text": "Enforce AES-256 data-at-rest encryption across system volumes and databases per EU NIS 2 Article 21.2(h).",
            },
            {
                "id": "crl_nis2_iam_pam",
                "rule_family_code": "NIS2-IAM-PAM",
                "version_number": 1,
                "check_type": "file_content",
                "evidence_source": "manual",
                "target_platform": "linux",
                "check_definition": {
                    "sudoers_strict_audit": True,
                    "ssh_root_login_disabled": True,
                    "platforms": ["linux"],
                },
                "severity": "high",
                "severity_weight": 8,
                "remediation_id_target": "rem_nis2_iam_pam_v1",
                "control_id": "cct_nis2_iam_02",
                "recommendation_text": "Enforce Privileged Access Management (PAM), disable direct root SSH, and audit sudoers policy per EU NIS 2 Article 21.2(i).",
            },
            {
                "id": "crl_nis2_mfa_fido2",
                "rule_family_code": "NIS2-MFA-FIDO2",
                "version_number": 1,
                "check_type": "api_response",
                "evidence_source": "manual",
                "target_platform": "any",
                "check_definition": {
                    "hardware_token_fido2_required": True,
                    "phishing_resistant_mfa": True,
                    "platforms": ["any"],
                },
                "severity": "critical",
                "severity_weight": 10,
                "remediation_id_target": "rem_nis2_mfa_fido2_v1",
                "control_id": "cct_nis2_mfa_02",
                "recommendation_text": "Enforce FIDO2/WebAuthn phishing-resistant hardware tokens for privileged administrative access per EU NIS 2 Article 21.2(j).",
            },
        ]

        # ─────────────────────────────────────────────────────────────────
        # ISO/IEC 27001:2022 — real technical rules for the Annex A controls
        # whose catalogue scannability promises automation.
        #
        # Before this block, all fourteen `auto` controls were covered only by
        # a generated placeholder pointing at an evidence source with no
        # adapter, so every one of them reported `manual_review` forever. Each
        # rule below reads a key an adapter genuinely emits — the wiring test
        # in tests/test_compliance_rule_wiring.py enforces that.
        #
        # A.8.19 and A.8.22 are deliberately absent: neither can be verified
        # from the evidence this product collects (an approved software
        # allow-list, and the intended segmentation design), and both have been
        # downgraded to semi_auto in the catalogue rather than given a rule
        # that would answer a question it cannot actually see.
        # ─────────────────────────────────────────────────────────────────
        rules_data.extend(
            [
                # A.8.1 User endpoint devices
                {
                    "id": "crl_iso_endpoint_uac_v1",
                    "rule_family_code": "ISO-ENDPOINT-UAC",
                    "version_number": 1,
                    "check_type": "registry",
                    "evidence_source": "offline_configuration",
                    "target_platform": "windows",
                    "check_definition": {
                        "key": "uac_enabled",
                        "operator": "equals",
                        "expected": True,
                    },
                    "severity": "high",
                    "severity_weight": 8,
                    "remediation_id_target": "rem_iso_endpoint_uac_v1",
                    "control_id": "cct_iso27001_2022_8.1",
                    "recommendation_text": "Enable User Account Control so that privilege elevation on user endpoint devices requires explicit consent.",
                },
                {
                    "id": "crl_iso_endpoint_disk_enc_v1",
                    "rule_family_code": "ISO-ENDPOINT-DISKENC",
                    "version_number": 1,
                    "check_type": "command_output",
                    "evidence_source": "offline_configuration",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "disk_encryption_enabled",
                        "operator": "equals",
                        "expected": True,
                    },
                    "severity": "high",
                    "severity_weight": 8,
                    "remediation_id_target": "rem_iso_endpoint_disk_enc_v1",
                    "control_id": "cct_iso27001_2022_8.1",
                    "recommendation_text": "Enable full-disk encryption (BitLocker or LUKS) on user endpoint devices so information remains protected if a device is lost.",
                },
                # A.8.2 Privileged access rights
                {
                    "id": "crl_iso_priv_lockout_v1",
                    "rule_family_code": "ISO-PRIV-LOCKOUT",
                    "version_number": 1,
                    "check_type": "command_output",
                    "evidence_source": "credential_validation",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "account_lockout_threshold",
                        "operator": "gte",
                        "expected": 1,
                    },
                    "severity": "high",
                    "severity_weight": 8,
                    "remediation_id_target": "rem_iso_priv_lockout_v1",
                    "control_id": "cct_iso27001_2022_8.2",
                    "recommendation_text": "Configure an account lockout threshold so repeated failed authentication against privileged accounts is stopped rather than allowed to continue indefinitely.",
                },
                {
                    "id": "crl_iso_priv_mfa_v1",
                    "rule_family_code": "ISO-PRIV-MFA",
                    "version_number": 1,
                    "check_type": "command_output",
                    "evidence_source": "offline_configuration",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "mfa_enforced_admin",
                        "operator": "equals",
                        "expected": True,
                    },
                    "severity": "critical",
                    "severity_weight": 10,
                    "remediation_id_target": "rem_iso_priv_mfa_v1",
                    "control_id": "cct_iso27001_2022_8.2",
                    "recommendation_text": "Require multi-factor authentication for all privileged and administrative access.",
                },
                # A.8.5 Secure authentication
                {
                    "id": "crl_iso_auth_min_length_v1",
                    "rule_family_code": "ISO-AUTH-MINLEN",
                    "version_number": 1,
                    "check_type": "command_output",
                    "evidence_source": "credential_validation",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "minimum_password_length",
                        "operator": "gte",
                        "expected": 12,
                    },
                    "severity": "high",
                    "severity_weight": 8,
                    "remediation_id_target": "rem_iso_auth_min_length_v1",
                    "control_id": "cct_iso27001_2022_8.5",
                    "recommendation_text": "Enforce a minimum password length of at least 12 characters in the local or domain password policy.",
                },
                {
                    "id": "crl_iso_auth_complexity_v1",
                    "rule_family_code": "ISO-AUTH-COMPLEXITY",
                    "version_number": 1,
                    "check_type": "command_output",
                    "evidence_source": "credential_validation",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "password_complexity_configured",
                        "operator": "equals",
                        "expected": True,
                    },
                    "severity": "medium",
                    "severity_weight": 5,
                    "remediation_id_target": "rem_iso_auth_complexity_v1",
                    "control_id": "cct_iso27001_2022_8.5",
                    "recommendation_text": "Enable password complexity enforcement (pam_pwquality on Linux, password policy on Windows).",
                },
                # A.8.9 Configuration management — the baseline hardening set
                {
                    "id": "crl_iso_config_firewall_v1",
                    "rule_family_code": "ISO-CONFIG-FIREWALL",
                    "version_number": 1,
                    "check_type": "service_status",
                    "evidence_source": "offline_configuration",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "firewall_profile_active",
                        "operator": "equals",
                        "expected": True,
                    },
                    "severity": "high",
                    "severity_weight": 8,
                    "remediation_id_target": "rem_iso_config_firewall_v1",
                    "control_id": "cct_iso27001_2022_8.9",
                    "recommendation_text": "Enable the host firewall so the configured baseline is enforced at the network boundary of each host.",
                },
                {
                    "id": "crl_iso_config_smbv1_v1",
                    "rule_family_code": "ISO-CONFIG-SMBV1",
                    "version_number": 1,
                    "check_type": "registry",
                    "evidence_source": "offline_configuration",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "smbv1_disabled",
                        "operator": "equals",
                        "expected": True,
                    },
                    "severity": "high",
                    "severity_weight": 8,
                    "remediation_id_target": "rem_iso_config_smbv1_v1",
                    "control_id": "cct_iso27001_2022_8.9",
                    "recommendation_text": "Disable the legacy SMBv1 protocol as part of the secure configuration baseline.",
                },
                {
                    "id": "crl_iso_config_telnet_v1",
                    "rule_family_code": "ISO-CONFIG-TELNET",
                    "version_number": 1,
                    "check_type": "service_status",
                    "evidence_source": "offline_configuration",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "telnet_disabled",
                        "operator": "equals",
                        "expected": True,
                    },
                    "severity": "high",
                    "severity_weight": 8,
                    "remediation_id_target": "rem_iso_config_telnet_v1",
                    "control_id": "cct_iso27001_2022_8.9",
                    "recommendation_text": "Remove or disable Telnet; it transmits credentials in clear text and has no place in a secure baseline.",
                },
                # A.8.15 Logging
                {
                    "id": "crl_iso_log_audit_policy_v1",
                    "rule_family_code": "ISO-LOG-AUDITPOLICY",
                    "version_number": 1,
                    "check_type": "command_output",
                    "evidence_source": "offline_configuration",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "audit_policy_configured",
                        "operator": "equals",
                        "expected": True,
                    },
                    "severity": "high",
                    "severity_weight": 8,
                    "remediation_id_target": "rem_iso_log_audit_policy_v1",
                    "control_id": "cct_iso27001_2022_8.15",
                    "recommendation_text": "Configure the host audit policy so security-relevant events are recorded (auditpol on Windows, auditd on Linux).",
                },
                {
                    "id": "crl_iso_log_retention_v1",
                    "rule_family_code": "ISO-LOG-RETENTION",
                    "version_number": 1,
                    "check_type": "file_content",
                    "evidence_source": "offline_configuration",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "retention_days",
                        "operator": "gte",
                        "expected": 180,
                    },
                    "severity": "medium",
                    "severity_weight": 5,
                    "remediation_id_target": "rem_iso_log_retention_v1",
                    "control_id": "cct_iso27001_2022_8.15",
                    "recommendation_text": "Retain security logs for at least 180 days so an investigation can reach back beyond the typical dwell time of an intrusion.",
                },
                # ── Controls the collectors could already answer ────────
                #
                # Eighteen Annex A controls carried `semi_auto` while having no
                # automated rule at all. Fourteen genuinely cannot be decided by
                # a scan and are now `manual`. These four can: the evidence was
                # already being collected by `_adapt_offline_configuration` and
                # simply was not wired to the control it answers.
                {
                    "id": "crl_iso_access_review_v1",
                    "rule_family_code": "ISO-ACCESS-REVIEW",
                    "version_number": 1,
                    "check_type": "command_output",
                    "evidence_source": "offline_configuration",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "account_review_completed",
                        "operator": "equals",
                        "expected": True,
                    },
                    "severity": "medium",
                    "severity_weight": 5,
                    "remediation_id_target": "rem_iso_access_review_v1",
                    "control_id": "cct_iso27001_2022_5.18",
                    "recommendation_text": "Review the accounts on this host and remove or disable those no longer required. A.8.5 checks how strong a credential must be; this checks that the account should still exist at all, which is the failure mode that leaves a leaver's access live.",
                },
                {
                    "id": "crl_iso_backup_frequency_v1",
                    "rule_family_code": "ISO-BACKUP-FREQ",
                    "version_number": 1,
                    "check_type": "command_output",
                    "evidence_source": "offline_configuration",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "backup_frequency_days",
                        "operator": "lte",
                        "expected": 7,
                    },
                    "severity": "high",
                    "severity_weight": 8,
                    "remediation_id_target": "rem_iso_backup_frequency_v1",
                    "control_id": "cct_iso27001_2022_8.13",
                    "recommendation_text": "Back this host up at least weekly. The interval is the data loss the organisation has accepted in advance, so a backup job that has not run inside its own window is an accepted loss nobody agreed to. Restore testing remains an attestation.",
                },
                {
                    "id": "crl_iso_priv_utility_uac_v1",
                    "rule_family_code": "ISO-PRIV-UTILITY",
                    "version_number": 1,
                    "check_type": "registry",
                    "evidence_source": "offline_configuration",
                    "target_platform": "windows",
                    "check_definition": {
                        "key": "uac_enabled",
                        "operator": "equals",
                        "expected": True,
                    },
                    "severity": "high",
                    "severity_weight": 8,
                    "remediation_id_target": "rem_iso_priv_utility_uac_v1",
                    "control_id": "cct_iso27001_2022_8.18",
                    "recommendation_text": "Enable User Account Control so utility programs capable of overriding system and application controls cannot run elevated without an explicit decision.",
                },
                {
                    "id": "crl_iso_session_timeout_v1",
                    "rule_family_code": "ISO-SESSION-TIMEOUT",
                    "version_number": 1,
                    "check_type": "registry",
                    "evidence_source": "offline_configuration",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "session_timeout_minutes",
                        "operator": "lte",
                        "expected": 15,
                    },
                    "severity": "medium",
                    "severity_weight": 5,
                    "remediation_id_target": "rem_iso_session_timeout_v1",
                    "control_id": "cct_iso27001_2022_8.1",
                    "recommendation_text": "Lock the session after at most 15 minutes idle. An unattended unlocked endpoint defeats every authentication control in front of it.",
                },
                # A.8.16 Monitoring activities
                {
                    "id": "crl_iso_monitor_agent_v1",
                    "rule_family_code": "ISO-MONITOR-AGENT",
                    "version_number": 1,
                    "check_type": "service_status",
                    "evidence_source": "malware_scan",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "anti_malware_agents_active",
                        "operator": "equals",
                        "expected": True,
                    },
                    "severity": "high",
                    "severity_weight": 8,
                    "remediation_id_target": "rem_iso_monitor_agent_v1",
                    "control_id": "cct_iso27001_2022_8.16",
                    "recommendation_text": "Deploy and run an endpoint monitoring agent so anomalous behaviour on this host is observed rather than inferred after the fact.",
                },
                {
                    "id": "crl_iso_monitor_ids_v1",
                    "rule_family_code": "ISO-MONITOR-IDS",
                    "version_number": 1,
                    "check_type": "service_status",
                    "evidence_source": "offline_configuration",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "ids_ips_active",
                        "operator": "equals",
                        "expected": True,
                    },
                    "severity": "medium",
                    "severity_weight": 5,
                    "remediation_id_target": "rem_iso_monitor_ids_v1",
                    "control_id": "cct_iso27001_2022_8.16",
                    "recommendation_text": "Enable intrusion detection or prevention covering this host so network-level anomalies are detected.",
                },
                # A.8.17 Clock synchronization
                {
                    "id": "crl_iso_clock_ntp_v1",
                    "rule_family_code": "ISO-CLOCK-NTP",
                    "version_number": 1,
                    "check_type": "command_output",
                    "evidence_source": "offline_configuration",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "ntp_servers",
                        "operator": "not_empty",
                        "expected": None,
                    },
                    "severity": "medium",
                    "severity_weight": 5,
                    "remediation_id_target": "rem_iso_clock_ntp_v1",
                    "control_id": "cct_iso27001_2022_8.17",
                    "recommendation_text": "Configure at least one approved NTP time source so log timestamps can be correlated across systems during an investigation.",
                },
                # A.8.24 Use of cryptography — this is what the TLS evidence
                # adapter was built for. Until now A.8.24 was answered solely by
                # a registry flag, and the adapter's expired-certificate,
                # weak-cipher and self-signed counts were consumed by nothing.
                {
                    "id": "crl_iso_crypto_weak_ciphers_v1",
                    "rule_family_code": "ISO-CRYPTO-WEAKCIPHER",
                    "version_number": 1,
                    "check_type": "tls_config",
                    "evidence_source": "tls_certificates",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "weak_ciphers_count",
                        "operator": "equals",
                        "expected": 0,
                    },
                    "severity": "high",
                    "severity_weight": 8,
                    "remediation_id_target": "rem_iso_crypto_weak_ciphers_v1",
                    "control_id": "cct_iso27001_2022_8.24",
                    "recommendation_text": "Remove weak cipher suites from the TLS configuration of every listening service on this host.",
                },
                {
                    "id": "crl_iso_crypto_expired_cert_v1",
                    "rule_family_code": "ISO-CRYPTO-EXPIREDCERT",
                    "version_number": 1,
                    "check_type": "tls_config",
                    "evidence_source": "tls_certificates",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "expired_certificates_count",
                        "operator": "equals",
                        "expected": 0,
                    },
                    "severity": "high",
                    "severity_weight": 8,
                    "remediation_id_target": "rem_iso_crypto_expired_cert_v1",
                    "control_id": "cct_iso27001_2022_8.24",
                    "recommendation_text": "Renew or replace expired certificates; an expired certificate provides no assurance of identity.",
                },
                {
                    "id": "crl_iso_crypto_self_signed_v1",
                    "rule_family_code": "ISO-CRYPTO-SELFSIGNED",
                    "version_number": 1,
                    "check_type": "tls_config",
                    "evidence_source": "tls_certificates",
                    "target_platform": "any",
                    "check_definition": {
                        "key": "self_signed_count",
                        "operator": "equals",
                        "expected": 0,
                    },
                    "severity": "medium",
                    "severity_weight": 5,
                    "remediation_id_target": "rem_iso_crypto_self_signed_v1",
                    "control_id": "cct_iso27001_2022_8.24",
                    "recommendation_text": "Replace self-signed certificates with certificates issued by a trusted certificate authority, internal or public.",
                },
            ]
        )

        # Compile a set of controls already mapped to custom rules.
        #
        # Normalised, because `rules_data` writes control ids in dotted form
        # (`cct_iso27001_2022_8.20`) while the seeder generates them with
        # underscores (`cct_iso27001_2022_8_20`). The membership test below
        # therefore never matched, and *every* control — including the twelve
        # ISO controls that carry real automated rules — also received a manual
        # attestation placeholder. That placeholder is an org-level
        # `manual_review` finding, which outranks `pass` in the score rollup, so
        # a control whose twelve automated checks all passed still reported as
        # awaiting review.
        def _normalize_ctrl_id(value: str) -> str:
            return str(value).replace(".", "_").replace("-", "_")

        mapped_control_ids = {_normalize_ctrl_id(r["control_id"]) for r in rules_data}

        # Dynamically generate rules for all remaining controls in db
        controls_in_db = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == framework_id)
            .all()
        )
        for ctrl in controls_in_db:
            if _normalize_ctrl_id(ctrl.id) not in mapped_control_ids:
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
                        # Always `manual`. This branch runs precisely for
                        # controls that have *no* explicit rule, so there is by
                        # definition nothing to evaluate. It used to emit
                        # `auto_scan` for controls whose catalogue scannability
                        # said `auto` — a source with no adapter, checking a key
                        # ("status") no adapter emits, against an expected value
                        # ("PASS") that is not an evidence value at all. Every
                        # one of the 14 ISO controls marked `auto` got one of
                        # these and reported `manual_review` forever, which read
                        # in the dashboard as coverage the product did not have.
                        #
                        # A control that genuinely can be scanned gets a real
                        # rule above, in `rules_data`, wired to a real adapter
                        # key. Anything reaching this branch is attestation work.
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
            "OT-MODBUS-502": (
                "# --- WINDOWS (PowerShell) ---\n"
                'New-NetFirewallRule -DisplayName "Block Unauthenticated Modbus" -Direction Inbound -LocalPort 502 -Protocol TCP -Action Block\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw deny 502/tcp\n"
                "sudo iptables -A INPUT -p tcp --dport 502 -j DROP"
            ),
            "OT-SIEMENS-S7-102": (
                "# --- WINDOWS (PowerShell) ---\n"
                'New-NetFirewallRule -DisplayName "Restrict Siemens S7 Port 102" -Direction Inbound -LocalPort 102 -Protocol TCP -Action Block\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw deny 102/tcp\n"
                "sudo iptables -A INPUT -p tcp --dport 102 -j DROP"
            ),
            "OT-ETHERNET-IP-44818": (
                "# --- WINDOWS (PowerShell) ---\n"
                'New-NetFirewallRule -DisplayName "Restrict EtherNet/IP Port 44818" -Direction Inbound -LocalPort 44818 -Protocol TCP -Action Block\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw deny 44818/tcp\n"
                "sudo iptables -A INPUT -p tcp --dport 44818 -j DROP"
            ),
            "OT-BACNET-47808": (
                "# --- WINDOWS (PowerShell) ---\n"
                'New-NetFirewallRule -DisplayName "Restrict BACnet Port 47808" -Direction Inbound -LocalPort 47808 -Protocol UDP -Action Block\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw deny 47808/udp\n"
                "sudo iptables -A INPUT -p udp --dport 47808 -j DROP"
            ),
            "OT-JUMP-HOST-MFA": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name 'fPromptForPassword' -Value 1\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo apt-get install -y libpam-duo || sudo yum install -y duo_unix\n"
                "sudo sed -i 's/auth       required       pam_env.so/auth       required       pam_duo.so/' /etc/pam.d/sshd"
            ),
            "OT-SP82-MODBUS-502": (
                "# --- INDUSTRIAL FIREWALL ---\n"
                "# Block Modbus TCP port 502 at Purdue L3/L3.5 zone boundary firewalls\n"
                'New-NetFirewallRule -DisplayName "Block Modbus TCP 502" -Direction Inbound -LocalPort 502 -Protocol TCP -Action Block\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw deny 502/tcp\n"
                "sudo iptables -A INPUT -p tcp --dport 502 -j DROP"
            ),
            "OT-SP82-S7-102": (
                "# --- INDUSTRIAL FIREWALL ---\n"
                "# Restrict Siemens S7 protocol port 102 to designated engineering workstations only\n"
                'New-NetFirewallRule -DisplayName "Restrict S7 Port 102" -Direction Inbound -LocalPort 102 -Protocol TCP -Action Block\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw deny 102/tcp\n"
                "sudo iptables -A INPUT -p tcp --dport 102 -j DROP"
            ),
            "OT-SP82-CIP-44818": (
                "# --- INDUSTRIAL FIREWALL ---\n"
                "# Restrict EtherNet/IP CIP port 44818 using industrial zone firewall ACLs\n"
                'New-NetFirewallRule -DisplayName "Restrict CIP Port 44818" -Direction Inbound -LocalPort 44818 -Protocol TCP -Action Block\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw deny 44818/tcp\n"
                "sudo iptables -A INPUT -p tcp --dport 44818 -j DROP"
            ),
            "OT-SP82-SIS-ISOLATION": (
                "# --- NETWORK ARCHITECTURE ---\n"
                "# Verify SIS is physically air-gapped or behind unidirectional security gateway\n"
                "# Ensure no IP routing exists between SIS controllers and enterprise/internet zones\n"
                "# Document air gap or unidirectional gateway deployment in network architecture diagram"
            ),
            "OT-SP82-JUMP-HOST-MFA": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name 'fPromptForPassword' -Value 1\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo apt-get install -y libpam-duo || sudo yum install -y duo_unix\n"
                "sudo sed -i 's/auth       required       pam_env.so/auth       required       pam_duo.so/' /etc/pam.d/sshd"
            ),
            "NERC-CIP-005-ESP": (
                "# --- WINDOWS (PowerShell) ---\n"
                'New-NetFirewallRule -DisplayName "NERC CIP-005 ESP Default Deny" -Direction Inbound -Action Block -Profile Any\n\n'
                "# --- LINUX (Bash) ---\n"
                "sudo ufw default deny incoming\n"
                "sudo iptables -P INPUT DROP"
            ),
            "NERC-CIP-005-MFA": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name 'fPromptForPassword' -Value 1\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo apt-get install -y libpam-duo || sudo yum install -y duo_unix\n"
                "sudo sed -i 's/auth       required       pam_env.so/auth       required       pam_duo.so/' /etc/pam.d/sshd"
            ),
            "NERC-CIP-006-PACS": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Write-Host 'Audit PACS controller event logs and enable intrusion alarm telemetry...'\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo systemctl status pacs-alarm-daemon.service || true"
            ),
            "NERC-CIP-007-PORTS": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Disable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6  # Disable unused IPv6 if unneeded\n"
                "Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo systemctl disable --now cups 2>/dev/null || true\n"
                "sudo systemctl disable --now avahi-daemon 2>/dev/null || true"
            ),
            "NERC-CIP-007-PATCH": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Install-Module PSWindowsUpdate -Force -Confirm:$false\n"
                "Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo apt-get update && sudo apt-get upgrade -y\n"
                "sudo yum update -y"
            ),
            "NERC-CIP-007-MALWARE": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Start-Service -Name WinDefend\n"
                "Update-MpSignature\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo systemctl enable --now freshclam clamav-daemon"
            ),
            "NERC-CIP-007-LOGS": (
                "# --- WINDOWS (PowerShell) ---\n"
                "wevtutil sl Security /ms:1073741824  # Expand Security Log size to 1GB\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo sed -i 's/rotate 4/rotate 13/' /etc/logrotate.conf  # 90-day retention"
            ),
            "NERC-CIP-010-BASELINE": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Get-WmiObject -Class Win32_Product | Select-Object Name, Version | Export-Csv -Path 'C:\\NERC_Baseline.csv'\n\n"
                "# --- LINUX (Bash) ---\n"
                "dpkg -l > /etc/nerc_baseline.txt || rpm -qa > /etc/nerc_baseline.txt"
            ),
            "NERC-CIP-011-BCSI": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod Aes256 -UsedSpaceOnly\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo cryptsetup luksFormat --cipher aes-xts-plain64 --key-size 512 /dev/sdb1"
            ),
            "NERC-CIP-012-LINK": (
                "# --- NETWORK ARCHITECTURE ---\n"
                "# Configure IPsec IKEv2 AES-256 tunnel on Inter-Control Center router interfaces\n"
                "# Enforce TLS 1.3 encryption on ICCP / TASE.2 operational data links"
            ),
            "NIS2-GOV-RISK": (
                "# --- WINDOWS (PowerShell) ---\n"
                "New-Item -Path 'C:\\ProgramData\\CCure\\Policies' -ItemType Directory -Force\n"
                "Set-Content -Path 'C:\\ProgramData\\CCure\\Policies\\nis2_security_policy.txt' -Value 'APPROVED_NIS2_RISK_POLICY_V1'\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo mkdir -p /etc/ccure/policies\n"
                "echo 'APPROVED_NIS2_RISK_POLICY_V1' | sudo tee /etc/ccure/policies/nis2_security_policy.txt"
            ),
            "NIS2-INC-24H": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Set-Service -Name EventLog -StartupType Automatic; Start-Service -Name EventLog\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo systemctl enable rsyslog || sudo systemctl enable systemd-journald\n"
                "sudo systemctl start rsyslog || sudo systemctl start systemd-journald"
            ),
            "NIS2-INC-LOGS": (
                "# --- WINDOWS (PowerShell) ---\n"
                "wevtutil sl Security /ms:104857600\n\n"
                "# --- LINUX (Bash) ---\n"
                "echo '*.* @siem.internal:514' | sudo tee -a /etc/rsyslog.d/nis2_siem.conf\n"
                "sudo systemctl restart rsyslog"
            ),
            "NIS2-BC-BACKUP": (
                "# --- WINDOWS (PowerShell) ---\n"
                "wbadmin enable backup -addtarget:E: -include:C: -quiet\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo systemctl enable rsync-backup.timer\n"
                "sudo systemctl start rsync-backup.timer"
            ),
            "NIS2-SEC-VULN": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Install-Module -Name PSWindowsUpdate -Force; Get-WindowsUpdate -AcceptAll -Install -AutoReboot\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo apt-get update && sudo apt-get dist-upgrade -y || sudo yum update -y"
            ),
            "NIS2-CRYPTO-TLS": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Name 'Enabled' -Value 0\n"
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server' -Name 'Enabled' -Value 0\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo sed -i 's/MinProtocol = .*/MinProtocol = TLSv1.2/' /etc/ssl/openssl.cnf\n"
                "sudo systemctl reload nginx || sudo systemctl reload apache2"
            ),
            "NIS2-IAM-RBAC": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 | Disable-ADAccount\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config\n"
                "sudo systemctl reload sshd"
            ),
            "NIS2-MFA-ENFORCE": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo sed -i 's/^#*AuthenticationMethods.*/AuthenticationMethods publickey,keyboard-interactive/' /etc/ssh/sshd_config\n"
                "sudo systemctl reload sshd"
            ),
            "NIS2-SUPPLY-SBOM": (
                "# --- WINDOWS (PowerShell) ---\n"
                "syft packages dir:C:\\Apps -o spdx-json > C:\\ProgramData\\CCure\\SBOM_manifest.json\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo syft packages dir:/opt/apps -o spdx-json > /etc/ccure/sbom_manifest.json"
            ),
            "NIS2-SEC-CVD": (
                "# --- WINDOWS (PowerShell / IIS) ---\n"
                "New-Item -Path 'C:\\inetpub\\wwwroot\\.well-known' -ItemType Directory -Force\n"
                "Set-Content -Path 'C:\\inetpub\\wwwroot\\.well-known\\security.txt' -Value 'Contact: mailto:security@company.eu\\nExpires: 2027-12-31T23:59:59.000Z\\nCSIRT: https://csirt.company.eu'\n\n"
                "# --- LINUX (Bash / Nginx) ---\n"
                "sudo mkdir -p /var/www/html/.well-known\n"
                "echo -e 'Contact: mailto:security@company.eu\\nExpires: 2027-12-31T23:59:59.000Z\\nCSIRT: https://csirt.company.eu' | sudo tee /var/www/html/.well-known/security.txt"
            ),
            "NIS2-BC-DR-TEST": (
                "# --- WINDOWS (PowerShell) ---\n"
                "wbadmin start recovery -version:10/18/2024-00:00 -itemType:Volume -items:C: -recoveryTarget:D:\\DR_Test -quiet\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo systemctl enable --now rsync-dr-test.service\n"
                "sudo systemctl status rsync-dr-test.service"
            ),
            "NIS2-HYGIENE-PWD": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14 -ComplexityEnabled $true -MaxPasswordAge 90.00:00:00\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo sed -i 's/^#*minlen = .*/minlen = 14/' /etc/security/pwquality.conf\n"
                "sudo authselect apply-changes"
            ),
            "NIS2-CRYPTO-REST": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod Aes256 -UsedSpaceOnly\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo cryptsetup luksFormat --cipher aes-xts-plain64 --key-size 512 /dev/sdb1"
            ),
            "NIS2-IAM-PAM": (
                "# --- WINDOWS (PowerShell) ---\n"
                "Remove-LocalGroupMember -Group 'Administrators' -Member 'OrphanedUser'\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config\n"
                "sudo systemctl reload sshd"
            ),
            "NIS2-MFA-FIDO2": (
                "# --- WINDOWS (PowerShell / Azure AD) ---\n"
                "Set-MgPolicyAuthenticationMethodPolicy -Fido2 -State 'enabled'\n\n"
                "# --- LINUX (Bash) ---\n"
                "sudo pam_u2f_config --origin=https://corp.eu --appid=https://corp.eu > ~/.config/Yubico/u2f_keys\n"
                "sudo sed -i 's/^auth required pam_unix.so/auth required pam_u2f.so cue/' /etc/pam.d/common-auth"
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
                # `run_scan_task` evaluates `active` rules only, which is right:
                # a draft is unpublished and an archived version has been
                # replaced. But an archived rule that supersedes nothing and
                # names no successor is not a lifecycle state — it is a check
                # switched off by accident, and it makes its control silently
                # unassessable. 24 of ISO's 93 controls were in exactly that
                # position, their single placeholder archived, so they produced
                # no finding on any run and sat at "not assessed" with nothing
                # in the UI able to say why. A seeder that only ever inserts
                # cannot repair this; converging the row is the point of
                # re-seeding.
                if (
                    existing_rule.status == "archived"
                    and not existing_rule.superseded_by_rule_id
                ):
                    existing_rule.status = "active"
                    print(f"  ~ Reactivated orphaned archived rule: {rule['id']}")

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

            raw_ctrl_id = rule["control_id"]
            normalized_ctrl_id = raw_ctrl_id.replace(".", "_").replace("-", "_")
            control_exists = (
                db.query(ComplianceControl)
                .filter(
                    (ComplianceControl.id == raw_ctrl_id)
                    | (ComplianceControl.id == normalized_ctrl_id)
                )
                .first()
            )
            if not control_exists:
                continue
            control_id = control_exists.id

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

        # An Annex A control that has gained a real check must not keep the
        # attestation placeholder it was given when it had none. A
        # `manual_review` finding outranks `pass` in `roll_up_statuses`, so the
        # placeholder silently suppresses the verdict the new check produces —
        # the control's automated rules can all pass and it still reports as
        # awaiting review. A.8.13 and A.8.18 landed in exactly that state the
        # moment they were wired up.
        #
        # The dynamic generator above only skips *creating* a placeholder for a
        # control that is mapped; it cannot remove one an earlier run created.
        iso_controls = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == framework_id)
            .all()
        )
        for ctrl in iso_controls:
            links = (
                db.query(ComplianceRuleControl, ComplianceRule)
                .join(
                    ComplianceRule, ComplianceRule.id == ComplianceRuleControl.rule_id
                )
                .filter(ComplianceRuleControl.control_id == ctrl.id)
                .all()
            )
            has_automation = any(
                r.status == "active"
                and r.evidence_source
                and r.evidence_source != "manual"
                for _, r in links
            )
            if not has_automation:
                continue
            for _link, rule_row in links:
                if not rule_row.id.startswith("crl_auto_gen_"):
                    continue
                _drop_rule_from_control(db, ctrl.id, rule_row.id)
                print(
                    f"    - Removed redundant placeholder {rule_row.id} from "
                    f"{ctrl.control_number} (it now has automated checks)"
                )

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
            # Only rules that can actually produce a verdict are inherited
            # across the crosswalk. Inheriting ISO's *manual* placeholders too
            # did two things wrong: it satisfied the "is this control mapped?"
            # test with a rule that evaluates nothing, and it put ISO's own
            # control title into the remediation text a NIST reviewer reads.
            # NIST gets its own placeholder, with its own wording, below.
            inheritable_rule_ids = {
                r_id
                for (r_id,) in db.query(ComplianceRule.id).filter(
                    ComplianceRule.evidence_source.isnot(None),
                    ComplianceRule.evidence_source != "manual",
                )
            }

            for nist_ctrl in nist_controls:
                # 1. Inherit automated rules from the ISO controls this
                #    Subcategory crosswalks to.
                #
                #    `mapped` is computed from the links that *exist* after this
                #    step, not from the ones this run happened to insert. It
                #    used to be set inside `if not n_link:`, so on any second
                #    run every link already existed, nothing set the flag, and
                #    all 106 Subcategories were handed an attestation
                #    placeholder — including the 27 with real automated checks.
                #    A `manual_review` finding outranks `pass` in the rollup, so
                #    a Subcategory whose checks all passed still reported as
                #    awaiting review, and the framework could never score above
                #    zero no matter what the scan found. This is the same defect
                #    the ISO seeder was fixed for; it survived here because the
                #    NIST branch decides "mapped" differently.
                inherited: set = set()
                for iso_num in nist_ctrl.crosswalk or []:
                    # Tolerate both the bare `A.5.1` form this catalogue uses
                    # and the `ISO27001:A.5.1` form the other seeds use.
                    ref = str(iso_num).split(":")[-1].strip()
                    if ref.upper().startswith("A."):
                        ref = ref[2:]
                    iso_ctrl_id = f"cct_iso27001_2022_{ref.lower().replace('.', '_')}"
                    for (rule_id_,) in db.query(ComplianceRuleControl.rule_id).filter(
                        ComplianceRuleControl.control_id == iso_ctrl_id
                    ):
                        if rule_id_ in inheritable_rule_ids:
                            inherited.add(rule_id_)

                existing_links = {
                    r_id
                    for (r_id,) in db.query(ComplianceRuleControl.rule_id).filter(
                        ComplianceRuleControl.control_id == nist_ctrl.id
                    )
                }
                for rule_id_ in sorted(inherited - existing_links):
                    db.add(
                        ComplianceRuleControl(rule_id=rule_id_, control_id=nist_ctrl.id)
                    )

                # Inheritance has to be revocable, not just additive. When a
                # crosswalk is corrected the rules it used to carry are still
                # linked, and their findings still count: ID.AM-07,
                # "inventories of data are maintained", was answering with
                # A.8.8's critical-vulnerability count because an earlier
                # catalogue crosswalked it there. Drop the link and the
                # findings behind it, or the correction has no effect on any
                # verdict.
                revoked = (existing_links & inheritable_rule_ids) - inherited

                # A Subcategory's only permitted manual rule is its own
                # placeholder. Earlier runs inherited ISO's manual placeholders
                # across the crosswalk too, so a NIST Subcategory could carry
                # `crl_auto_gen_5_1` — whose remediation text names ISO A.5.1 —
                # and, because those ISO placeholders are shared, one archived
                # rule could be the only rule on several Subcategories at once.
                # That is how GV.OC-01, GV.OV-01, GV.PO-01, GV.PO-02 and
                # ID.RA-03 ended up producing no finding on any run.
                own_placeholder = (
                    "crl_nist_auto_gen_"
                    + nist_ctrl.control_number.lower()
                    .replace(".", "_")
                    .replace("-", "_")
                )
                revoked |= {
                    r_id
                    for r_id in existing_links
                    if r_id not in inheritable_rule_ids and r_id != own_placeholder
                }

                for rule_id_ in sorted(revoked):
                    _drop_rule_from_control(db, nist_ctrl.id, rule_id_)
                existing_links -= revoked

                mapped = bool(inherited)

                # 2. Attestation placeholder, but only where there is nothing to
                #    evaluate. A Subcategory carrying real automated checks must
                #    not also carry one of these.
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
                        rule_exists = ComplianceRule(
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
                        db.add(rule_exists)
                        db.flush()
                    elif (
                        rule_exists.status == "archived"
                        and not rule_exists.superseded_by_rule_id
                    ):
                        # `run_scan_task` evaluates `active` rules only, which is
                        # correct — a draft is unpublished and an archived
                        # version has been replaced. But an archived rule that
                        # supersedes nothing and names no successor is not a
                        # lifecycle state, it is a control switched off by
                        # accident, and the placeholder is the *only* rule on an
                        # attestation-only Subcategory. Five of the 79 were in
                        # that state, so GV.OC-01, GV.OV-01, GV.PO-01, GV.PO-02
                        # and ID.RA-03 produced no finding on any run and sat at
                        # "not assessed" forever with no way for the UI to say
                        # why. A seeder that only ever inserts cannot repair
                        # this; converging the row is the point of re-seeding.
                        rule_exists.status = "active"

                    # These 79 placeholders shipped with no remediation record
                    # at all, so the attestation queue offered the reviewer a
                    # Subcategory number and no statement of what to gather.
                    # The evidence checklist is on the control; the
                    # recommendation names the outcome being attested to.
                    rem_id = f"rem_nist_auto_gen_{raw_id}"
                    rem = (
                        db.query(ComplianceRemediation)
                        .filter(ComplianceRemediation.id == rem_id)
                        .first()
                    )
                    rem_text = (
                        f"Attest {nist_ctrl.control_number} "
                        f"({FUNCTION_NAMES.get(nist_ctrl.theme, nist_ctrl.theme)}): "
                        f"{nist_ctrl.title}. Attach the evidence listed on the "
                        "Subcategory and record the reviewer, date and "
                        "justification."
                    )
                    if not rem:
                        db.add(
                            ComplianceRemediation(
                                id=rem_id,
                                rule_id=rule_id,
                                recommendation_text=rem_text,
                                fix_type="manual",
                            )
                        )
                        db.flush()
                    else:
                        rem.rule_id = rule_id
                        rem.recommendation_text = rem_text
                        rem.fix_type = "manual"
                    rule_exists.remediation_id = rem_id

                    if rule_id not in existing_links:
                        db.add(
                            ComplianceRuleControl(
                                rule_id=rule_id, control_id=nist_ctrl.id
                            )
                        )
                else:
                    # A Subcategory that gained automation since the last run
                    # still carries the placeholder from when it had none.
                    # Leaving it there re-creates the suppressed-`pass` bug one
                    # control at a time.
                    stale_id = (
                        "crl_nist_auto_gen_"
                        + nist_ctrl.control_number.lower()
                        .replace(".", "_")
                        .replace("-", "_")
                    )
                    if stale_id in existing_links:
                        _drop_rule_from_control(db, nist_ctrl.id, stale_id)

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
                        iso_ref = (
                            iso_num.replace("ISO27001:", "")
                            .strip()
                            .lower()
                            .replace("a.", "")
                            .replace(".", "_")
                        )
                        iso_ctrl_ids = [
                            f"cct_iso27001_2022_a_{iso_ref}",
                            f"cct_iso27001_2022_{iso_ref}",
                        ]
                        linked_rules = (
                            db.query(ComplianceRuleControl)
                            .filter(ComplianceRuleControl.control_id.in_(iso_ctrl_ids))
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

        # Map rules and controls for DPDP Act 2023
        dpdp_controls = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == "cfw_dpdp_2023")
            .all()
        )
        if dpdp_controls:
            for dpdp_ctrl in dpdp_controls:
                if dpdp_ctrl.crosswalk:
                    for iso_num in dpdp_ctrl.crosswalk:
                        if not iso_num.startswith("ISO27001:"):
                            continue
                        iso_ref = (
                            iso_num.replace("ISO27001:", "")
                            .strip()
                            .lower()
                            .replace("a.", "")
                            .replace(".", "_")
                        )
                        iso_ctrl_ids = [
                            f"cct_iso27001_2022_a_{iso_ref}",
                            f"cct_iso27001_2022_{iso_ref}",
                        ]
                        linked_rules = (
                            db.query(ComplianceRuleControl)
                            .filter(ComplianceRuleControl.control_id.in_(iso_ctrl_ids))
                            .all()
                        )
                        for r_link in linked_rules:
                            d_link = (
                                db.query(ComplianceRuleControl)
                                .filter(
                                    ComplianceRuleControl.rule_id == r_link.rule_id,
                                    ComplianceRuleControl.control_id == dpdp_ctrl.id,
                                )
                                .first()
                            )
                            if not d_link:
                                db.add(
                                    ComplianceRuleControl(
                                        rule_id=r_link.rule_id,
                                        control_id=dpdp_ctrl.id,
                                    )
                                )

                raw_id = (
                    dpdp_ctrl.control_number.lower().replace(".", "_").replace("-", "_")
                )
                rule_id = f"crl_dpdp_auto_gen_{raw_id}"
                rule_exists = (
                    db.query(ComplianceRule)
                    .filter(ComplianceRule.id == rule_id)
                    .first()
                )
                if not rule_exists:
                    c_rule = ComplianceRule(
                        id=rule_id,
                        rule_family_code=f"RULE-DPDP-{dpdp_ctrl.control_number}",
                        version_number=1,
                        check_type="api_response",
                        evidence_source=(
                            dpdp_ctrl.scannability
                            if dpdp_ctrl.scannability != "manual"
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

                d_link = (
                    db.query(ComplianceRuleControl)
                    .filter(
                        ComplianceRuleControl.rule_id == rule_id,
                        ComplianceRuleControl.control_id == dpdp_ctrl.id,
                    )
                    .first()
                )
                if not d_link:
                    db.add(
                        ComplianceRuleControl(rule_id=rule_id, control_id=dpdp_ctrl.id)
                    )

            db.commit()
            print("  - Successfully mapped rules and controls for DPDP Act 2023")

        # Map rules and controls for GDPR
        gdpr_controls = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == "cfw_gdpr")
            .all()
        )
        if gdpr_controls:
            for gdpr_ctrl in gdpr_controls:
                if gdpr_ctrl.crosswalk:
                    for iso_num in gdpr_ctrl.crosswalk:
                        if not iso_num.startswith("ISO27001:"):
                            continue
                        iso_ref = (
                            iso_num.replace("ISO27001:", "")
                            .strip()
                            .lower()
                            .replace("a.", "")
                            .replace(".", "_")
                        )
                        iso_ctrl_ids = [
                            f"cct_iso27001_2022_a_{iso_ref}",
                            f"cct_iso27001_2022_{iso_ref}",
                        ]
                        linked_rules = (
                            db.query(ComplianceRuleControl)
                            .filter(ComplianceRuleControl.control_id.in_(iso_ctrl_ids))
                            .all()
                        )
                        for r_link in linked_rules:
                            g_link = (
                                db.query(ComplianceRuleControl)
                                .filter(
                                    ComplianceRuleControl.rule_id == r_link.rule_id,
                                    ComplianceRuleControl.control_id == gdpr_ctrl.id,
                                )
                                .first()
                            )
                            if not g_link:
                                db.add(
                                    ComplianceRuleControl(
                                        rule_id=r_link.rule_id,
                                        control_id=gdpr_ctrl.id,
                                    )
                                )

                raw_id = (
                    gdpr_ctrl.control_number.lower().replace(".", "_").replace("-", "_")
                )
                rule_id = f"crl_gdpr_auto_gen_{raw_id}"
                rule_exists = (
                    db.query(ComplianceRule)
                    .filter(ComplianceRule.id == rule_id)
                    .first()
                )
                if not rule_exists:
                    c_rule = ComplianceRule(
                        id=rule_id,
                        rule_family_code=f"RULE-GDPR-{gdpr_ctrl.control_number}",
                        version_number=1,
                        check_type="api_response",
                        evidence_source=(
                            gdpr_ctrl.scannability
                            if gdpr_ctrl.scannability != "manual"
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

                g_link = (
                    db.query(ComplianceRuleControl)
                    .filter(
                        ComplianceRuleControl.rule_id == rule_id,
                        ComplianceRuleControl.control_id == gdpr_ctrl.id,
                    )
                    .first()
                )
                if not g_link:
                    db.add(
                        ComplianceRuleControl(rule_id=rule_id, control_id=gdpr_ctrl.id)
                    )

            db.commit()
            print("  - Successfully mapped rules and controls for GDPR")

        # Map rules and controls for NIST SP 800-53 Rev. 5
        nist53_controls = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == "cfw_nist_800_53_r5")
            .all()
        )
        if nist53_controls:
            for nist53_ctrl in nist53_controls:
                if nist53_ctrl.crosswalk:
                    for cross_num in nist53_ctrl.crosswalk:
                        clean_cross_num = (
                            cross_num.split(":", 1)[1]
                            if ":" in cross_num
                            else cross_num
                        )
                        if not clean_cross_num.startswith("A."):
                            continue
                        iso_ref = (
                            clean_cross_num.replace("A.", "")
                            .strip()
                            .lower()
                            .replace(".", "_")
                        )
                        iso_ctrl_ids = [
                            f"cct_iso27001_2022_a_{iso_ref}",
                            f"cct_iso27001_2022_{iso_ref}",
                        ]
                        linked_rules = (
                            db.query(ComplianceRuleControl)
                            .filter(ComplianceRuleControl.control_id.in_(iso_ctrl_ids))
                            .all()
                        )
                        for r_link in linked_rules:
                            n_link = (
                                db.query(ComplianceRuleControl)
                                .filter(
                                    ComplianceRuleControl.rule_id == r_link.rule_id,
                                    ComplianceRuleControl.control_id == nist53_ctrl.id,
                                )
                                .first()
                            )
                            if not n_link:
                                db.add(
                                    ComplianceRuleControl(
                                        rule_id=r_link.rule_id,
                                        control_id=nist53_ctrl.id,
                                    )
                                )

                raw_id = (
                    nist53_ctrl.control_number.lower()
                    .replace(".", "_")
                    .replace("-", "_")
                )
                rule_id = f"crl_nist53_auto_gen_{raw_id}"
                rule_exists = (
                    db.query(ComplianceRule)
                    .filter(ComplianceRule.id == rule_id)
                    .first()
                )
                if not rule_exists:
                    c_rule = ComplianceRule(
                        id=rule_id,
                        rule_family_code=f"RULE-NIST53-{nist53_ctrl.control_number}",
                        version_number=1,
                        check_type="api_response",
                        evidence_source=(
                            nist53_ctrl.scannability
                            if nist53_ctrl.scannability != "manual"
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

                n_link = (
                    db.query(ComplianceRuleControl)
                    .filter(
                        ComplianceRuleControl.rule_id == rule_id,
                        ComplianceRuleControl.control_id == nist53_ctrl.id,
                    )
                    .first()
                )
                if not n_link:
                    db.add(
                        ComplianceRuleControl(
                            rule_id=rule_id, control_id=nist53_ctrl.id
                        )
                    )

            db.commit()
            print(
                "  - Successfully mapped rules and controls for NIST SP 800-53 Rev. 5"
            )

        # Map rules and controls for IEC 62443
        iec_controls = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == "cfw_iec_62443")
            .all()
        )
        if iec_controls:
            for iec_ctrl in iec_controls:
                if iec_ctrl.crosswalk:
                    for cross_num in iec_ctrl.crosswalk:
                        clean_cross_num = (
                            cross_num.split(":", 1)[1]
                            if ":" in cross_num
                            else cross_num
                        )
                        if clean_cross_num.startswith("A."):
                            iso_ref = (
                                clean_cross_num.replace("A.", "")
                                .strip()
                                .lower()
                                .replace(".", "_")
                            )
                            iso_ctrl_ids = [
                                f"cct_iso27001_2022_a_{iso_ref}",
                                f"cct_iso27001_2022_{iso_ref}",
                            ]
                            linked_rules = (
                                db.query(ComplianceRuleControl)
                                .filter(
                                    ComplianceRuleControl.control_id.in_(iso_ctrl_ids)
                                )
                                .all()
                            )
                            for r_link in linked_rules:
                                i_link = (
                                    db.query(ComplianceRuleControl)
                                    .filter(
                                        ComplianceRuleControl.rule_id == r_link.rule_id,
                                        ComplianceRuleControl.control_id == iec_ctrl.id,
                                    )
                                    .first()
                                )
                                if not i_link:
                                    db.add(
                                        ComplianceRuleControl(
                                            rule_id=r_link.rule_id,
                                            control_id=iec_ctrl.id,
                                        )
                                    )

                raw_id = (
                    iec_ctrl.control_number.lower().replace(".", "_").replace("-", "_")
                )
                rule_id = f"crl_iec_auto_gen_{raw_id}"
                rule_exists = (
                    db.query(ComplianceRule)
                    .filter(ComplianceRule.id == rule_id)
                    .first()
                )
                if not rule_exists:
                    c_rule = ComplianceRule(
                        id=rule_id,
                        rule_family_code=f"RULE-IEC-{iec_ctrl.control_number}",
                        version_number=1,
                        check_type="api_response",
                        evidence_source=(
                            iec_ctrl.scannability
                            if iec_ctrl.scannability != "manual"
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

                i_link = (
                    db.query(ComplianceRuleControl)
                    .filter(
                        ComplianceRuleControl.rule_id == rule_id,
                        ComplianceRuleControl.control_id == iec_ctrl.id,
                    )
                    .first()
                )
                if not i_link:
                    db.add(
                        ComplianceRuleControl(rule_id=rule_id, control_id=iec_ctrl.id)
                    )

            db.commit()
            print("  - Successfully mapped rules and controls for IEC 62443")

        # Map rules and controls for NIST SP 800-82 Rev. 3
        nist82_controls = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == "cfw_nist_800_82_r3")
            .all()
        )
        if nist82_controls:
            for n82_ctrl in nist82_controls:
                if n82_ctrl.crosswalk:
                    for cross_num in n82_ctrl.crosswalk:
                        clean_cross_num = (
                            cross_num.split(":", 1)[1]
                            if ":" in cross_num
                            else cross_num
                        )
                        # Resolve ISO 27001 crosswalks
                        if clean_cross_num.startswith("A."):
                            iso_ref = (
                                clean_cross_num.replace("A.", "")
                                .strip()
                                .lower()
                                .replace(".", "_")
                            )
                            iso_ctrl_ids = [
                                f"cct_iso27001_2022_a_{iso_ref}",
                                f"cct_iso27001_2022_{iso_ref}",
                            ]
                            linked_rules = (
                                db.query(ComplianceRuleControl)
                                .filter(
                                    ComplianceRuleControl.control_id.in_(iso_ctrl_ids)
                                )
                                .all()
                            )
                            for r_link in linked_rules:
                                n82_link = (
                                    db.query(ComplianceRuleControl)
                                    .filter(
                                        ComplianceRuleControl.rule_id == r_link.rule_id,
                                        ComplianceRuleControl.control_id == n82_ctrl.id,
                                    )
                                    .first()
                                )
                                if not n82_link:
                                    db.add(
                                        ComplianceRuleControl(
                                            rule_id=r_link.rule_id,
                                            control_id=n82_ctrl.id,
                                        )
                                    )

                # Auto-generate fallback rule for unmapped controls
                raw_id = (
                    n82_ctrl.control_number.lower().replace(".", "_").replace("-", "_")
                )
                rule_id = f"crl_nist82_auto_gen_{raw_id}"
                rule_exists = (
                    db.query(ComplianceRule)
                    .filter(ComplianceRule.id == rule_id)
                    .first()
                )
                if not rule_exists:
                    c_rule = ComplianceRule(
                        id=rule_id,
                        rule_family_code=f"RULE-NIST82-{n82_ctrl.control_number}",
                        version_number=1,
                        check_type="api_response",
                        evidence_source=(
                            n82_ctrl.scannability
                            if n82_ctrl.scannability != "manual"
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

                n82_link = (
                    db.query(ComplianceRuleControl)
                    .filter(
                        ComplianceRuleControl.rule_id == rule_id,
                        ComplianceRuleControl.control_id == n82_ctrl.id,
                    )
                    .first()
                )
                if not n82_link:
                    db.add(
                        ComplianceRuleControl(rule_id=rule_id, control_id=n82_ctrl.id)
                    )

            db.commit()
            print(
                "  - Successfully mapped rules and controls for NIST SP 800-82 Rev. 3"
            )

        # Map rules and controls for NERC CIP (Critical Infrastructure Protection)
        nerc_cip_controls = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == "cfw_nerc_cip")
            .all()
        )
        if nerc_cip_controls:
            for cip_ctrl in nerc_cip_controls:
                if cip_ctrl.crosswalk:
                    for cross_num in cip_ctrl.crosswalk:
                        clean_cross_num = (
                            cross_num.split(":")[-1].strip()
                            if ":" in cross_num
                            else cross_num.strip()
                        )
                        # Resolve ISO 27001 crosswalks
                        if clean_cross_num.startswith("A."):
                            iso_ref = (
                                clean_cross_num.replace("A.", "")
                                .strip()
                                .lower()
                                .replace(".", "_")
                            )
                            iso_ctrl_ids = [
                                f"cct_iso27001_2022_a_{iso_ref}",
                                f"cct_iso27001_2022_{iso_ref}",
                            ]
                            linked_rules = (
                                db.query(ComplianceRuleControl)
                                .filter(
                                    ComplianceRuleControl.control_id.in_(iso_ctrl_ids)
                                )
                                .all()
                            )
                            for r_link in linked_rules:
                                cip_link = (
                                    db.query(ComplianceRuleControl)
                                    .filter(
                                        ComplianceRuleControl.rule_id == r_link.rule_id,
                                        ComplianceRuleControl.control_id == cip_ctrl.id,
                                    )
                                    .first()
                                )
                                if not cip_link:
                                    db.add(
                                        ComplianceRuleControl(
                                            rule_id=r_link.rule_id,
                                            control_id=cip_ctrl.id,
                                        )
                                    )

                # Auto-generate fallback rule for unmapped controls
                raw_id = (
                    cip_ctrl.control_number.lower().replace(".", "_").replace("-", "_")
                )
                rule_id = f"crl_nerc_cip_auto_gen_{raw_id}"
                rule_exists = (
                    db.query(ComplianceRule)
                    .filter(ComplianceRule.id == rule_id)
                    .first()
                )
                if not rule_exists:
                    c_rule = ComplianceRule(
                        id=rule_id,
                        rule_family_code=f"RULE-NERC-{cip_ctrl.control_number}",
                        version_number=1,
                        check_type="api_response",
                        evidence_source=(
                            cip_ctrl.scannability
                            if cip_ctrl.scannability != "manual"
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

                cip_link = (
                    db.query(ComplianceRuleControl)
                    .filter(
                        ComplianceRuleControl.rule_id == rule_id,
                        ComplianceRuleControl.control_id == cip_ctrl.id,
                    )
                    .first()
                )
                if not cip_link:
                    db.add(
                        ComplianceRuleControl(rule_id=rule_id, control_id=cip_ctrl.id)
                    )

            db.commit()
            print("  - Successfully mapped rules and controls for NERC CIP")

        # Map rules and controls for EU NIS 2 Directive
        nis2_controls = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == "cfw_nis2")
            .all()
        )
        if nis2_controls:
            added_links = set()
            for nis_ctrl in nis2_controls:
                if nis_ctrl.crosswalk:
                    for cross_num in nis_ctrl.crosswalk:
                        clean_cross_num = (
                            cross_num.split(":")[-1].strip()
                            if ":" in cross_num
                            else cross_num.strip()
                        )
                        target_ctrl_ids = []
                        # 1. Resolve ISO 27001 crosswalks
                        if clean_cross_num.startswith("A."):
                            iso_ref = (
                                clean_cross_num.replace("A.", "")
                                .strip()
                                .lower()
                                .replace(".", "_")
                            )
                            target_ctrl_ids = [
                                f"cct_iso27001_2022_a_{iso_ref}",
                                f"cct_iso27001_2022_{iso_ref}",
                            ]
                        # 2. Resolve NIST CSF v2.0 crosswalks (e.g. GV.PO-01, PR.AT-01)
                        elif any(
                            clean_cross_num.startswith(p)
                            for p in ["GV.", "ID.", "PR.", "DE.", "RS.", "RC."]
                        ):
                            nist_ref = (
                                clean_cross_num.lower()
                                .replace(".", "_")
                                .replace("-", "_")
                            )
                            target_ctrl_ids = [f"cct_nist_csf_v2_{nist_ref}"]
                        # 3. Resolve CIS Controls v8.1 crosswalks (e.g. 12.1, 14.1)
                        elif (
                            clean_cross_num.replace(".", "").isdigit()
                            or "cis" in cross_num.lower()
                        ):
                            cis_ref = clean_cross_num.lower().replace(".", "_")
                            target_ctrl_ids = [f"cct_cis_v8_1_{cis_ref}"]

                        if target_ctrl_ids:
                            # Only rules that evaluate something are inherited.
                            # Copying another framework's attestation
                            # placeholders across pulled 20 NIST CSF
                            # placeholders onto NIS 2 controls, where their
                            # remediation text told the reviewer to attest a
                            # NIST Subcategory — and duplicated the NIS 2
                            # placeholder generated a few lines below.
                            linked_rules = (
                                db.query(ComplianceRuleControl)
                                .join(
                                    ComplianceRule,
                                    ComplianceRule.id == ComplianceRuleControl.rule_id,
                                )
                                .filter(
                                    ComplianceRuleControl.control_id.in_(
                                        target_ctrl_ids
                                    ),
                                    ComplianceRule.evidence_source.isnot(None),
                                    ComplianceRule.evidence_source != "manual",
                                )
                                .all()
                            )
                            for r_link in linked_rules:
                                pair = (r_link.rule_id, nis_ctrl.id)
                                if pair in added_links:
                                    continue
                                nis_link = (
                                    db.query(ComplianceRuleControl)
                                    .filter(
                                        ComplianceRuleControl.rule_id == r_link.rule_id,
                                        ComplianceRuleControl.control_id == nis_ctrl.id,
                                    )
                                    .first()
                                )
                                if not nis_link:
                                    db.add(
                                        ComplianceRuleControl(
                                            rule_id=r_link.rule_id,
                                            control_id=nis_ctrl.id,
                                        )
                                    )
                                added_links.add(pair)

                # Auto-generate fallback rule for unmapped controls
                raw_id = (
                    nis_ctrl.control_number.lower().replace(".", "_").replace("-", "_")
                )
                rule_id = f"crl_nis2_auto_gen_{raw_id}"
                rule_exists = (
                    db.query(ComplianceRule)
                    .filter(ComplianceRule.id == rule_id)
                    .first()
                )
                if not rule_exists:
                    c_rule = ComplianceRule(
                        id=rule_id,
                        rule_family_code=f"RULE-NIS2-{nis_ctrl.control_number}",
                        version_number=1,
                        check_type="api_response",
                        evidence_source=(
                            nis_ctrl.scannability
                            if nis_ctrl.scannability != "manual"
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

                nis_link = (
                    db.query(ComplianceRuleControl)
                    .filter(
                        ComplianceRuleControl.rule_id == rule_id,
                        ComplianceRuleControl.control_id == nis_ctrl.id,
                    )
                    .first()
                )
                if not nis_link:
                    db.add(
                        ComplianceRuleControl(rule_id=rule_id, control_id=nis_ctrl.id)
                    )

            db.commit()
            print("  - Successfully mapped rules and controls for EU NIS 2 Directive")

        now = datetime.now(timezone.utc)

        orgs = db.query(Organization).all()
        for org in orgs:
            user = db.query(User).filter(User.org_id == org.id).first()
            if not user:
                user = db.query(User).first()

            # Register Frameworks and Bootstrap Baseline Policies
            for fw_code_id in [
                "cfw_iso27001_2022",
                "cfw_nist_csf_v2",
                "cfw_cis_v8_1",
                "cfw_soc2_type2",
                "cfw_cert_in_2022",
                "cfw_pci_dss_v4",
                "cfw_dpdp_2023",
                "cfw_gdpr",
                "cfw_nist_800_53_r5",
                "cfw_iec_62443",
                "cfw_nist_800_82_r3",
                "cfw_nerc_cip",
                "cfw_nis2",
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
                    # A parked catalogue is still seeded, still crosswalked and
                    # still installed — it is simply not enabled. Creating it
                    # enabled and relying on someone to turn it off afterwards
                    # meant a fresh deployment came up offering all thirteen,
                    # which is the state this parking exists to avoid.
                    #
                    # An *existing* row is deliberately left alone: an operator
                    # who enabled a framework by hand should not have it
                    # switched back by the next seeder run. `--apply` on
                    # `scripts/set_active_frameworks.py` is the explicit way to
                    # realign them.
                    tenant_fw = ComplianceTenantFramework(
                        id=f"ctf_{org.id}_{fw_code_id}",
                        tenant_id=org.id,
                        framework_id=fw_code_id,
                        is_enabled=is_active_framework(fw_code_id),
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

        # 4. Find scanned target asset if specified
        if not target_ip:
            return

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
        # Reset policy_id to ISO 27001 default policy ID (fixes leaky loop variable bug)
        iso_policy_id = f"cpl_{org.id}_iso27001_2022_default"
        scan_run_id = f"run_{org.id[:8]}_{datetime.now().strftime('%M%S%f')}"
        run = ComplianceScanRun(
            id=scan_run_id,
            tenant_id=org.id,
            framework_id=framework_id,
            policy_id=iso_policy_id,
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
        print(f"Error seeding rules/running evaluation: {e!s}")
    finally:
        db.close()


if __name__ == "__main__":
    seed_and_evaluate()
