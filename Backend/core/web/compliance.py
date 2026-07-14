"""
core/web/compliance.py
────────────────────────────────────────────────────────────────────────────
Compliance mapping engine for web application security findings.

Maps finding types to:
  - OWASP Top 10 (2021 edition)
  - PCI-DSS 4.0
  - SOC 2 Trust Service Criteria
"""

import logging
from typing import Dict, List

log = logging.getLogger("ccure.web.compliance")

# ── OWASP Top 10 2021 Mapping ────────────────────────────────────────────────

OWASP_MAP: Dict[str, str] = {
    "sqli": "A03:2021 – Injection",
    "xss": "A03:2021 – Injection",
    "command_injection": "A03:2021 – Injection",
    "xxe": "A03:2021 – Injection",
    "ssrf": "A10:2021 – SSRF",
    "broken_auth": "A07:2021 – Identification and Authentication Failures",
    "default_creds": "A07:2021 – Identification and Authentication Failures",
    "misconfig": "A05:2021 – Security Misconfiguration",
    "exposed_panel": "A01:2021 – Broken Access Control",
    "idor": "A01:2021 – Broken Access Control",
    "path_traversal": "A01:2021 – Broken Access Control",
    "file_inclusion": "A01:2021 – Broken Access Control",
    "tls_issue": "A02:2021 – Cryptographic Failures",
    "cors": "A05:2021 – Security Misconfiguration",
    "cve": "A06:2021 – Vulnerable and Outdated Components",
    "information_disclosure": "A01:2021 – Broken Access Control",
    "csrf": "A01:2021 – Broken Access Control",
    "open_redirect": "A01:2021 – Broken Access Control",
    "header_injection": "A03:2021 – Injection",
    "technology_detected": "",  # Informational, no OWASP mapping
    "rce": "A03:2021 – Injection",
    "lfi": "A01:2021 – Broken Access Control",
    "rfi": "A01:2021 – Broken Access Control",
}

# ── PCI-DSS 4.0 Mapping ──────────────────────────────────────────────────────

PCI_DSS_MAP: Dict[str, List[str]] = {
    "sqli": ["PCI-DSS-6.2.4", "PCI-DSS-6.5.1"],
    "xss": ["PCI-DSS-6.2.4", "PCI-DSS-6.5.7"],
    "command_injection": ["PCI-DSS-6.2.4"],
    "xxe": ["PCI-DSS-6.2.4"],
    "tls_issue": ["PCI-DSS-4.2.1", "PCI-DSS-4.2.2"],
    "default_creds": ["PCI-DSS-2.2.2", "PCI-DSS-8.2.2"],
    "misconfig": ["PCI-DSS-2.2.1"],
    "cve": ["PCI-DSS-6.3.3"],
    "cors": ["PCI-DSS-6.2.4"],
    "csrf": ["PCI-DSS-6.2.4"],
    "information_disclosure": ["PCI-DSS-3.4.1"],
    "exposed_panel": ["PCI-DSS-1.3.1"],
    "broken_auth": ["PCI-DSS-8.3.1", "PCI-DSS-8.3.6"],
}

# ── SOC 2 Trust Service Criteria Mapping ──────────────────────────────────────

SOC2_MAP: Dict[str, List[str]] = {
    "sqli": ["SOC2-CC6.1", "SOC2-CC6.6"],
    "xss": ["SOC2-CC6.1"],
    "tls_issue": ["SOC2-CC6.7"],
    "default_creds": ["SOC2-CC6.1", "SOC2-CC6.3"],
    "misconfig": ["SOC2-CC6.1"],
    "cve": ["SOC2-CC7.1"],
    "information_disclosure": ["SOC2-CC6.5"],
    "broken_auth": ["SOC2-CC6.1", "SOC2-CC6.3"],
}


def map_compliance(finding_type: str) -> Dict:
    """
    Map a finding type to compliance framework tags.

    Args:
        finding_type: e.g., "sqli", "xss", "tls_issue"

    Returns:
        {
            "owasp": "A03:2021 – Injection",
            "tags": ["OWASP-A03", "PCI-DSS-6.5.1", "SOC2-CC6.1"]
        }
    """
    owasp = OWASP_MAP.get(finding_type, "")
    pci = PCI_DSS_MAP.get(finding_type, [])
    soc2 = SOC2_MAP.get(finding_type, [])

    tags: List[str] = []

    if owasp:
        # Extract short code (e.g., "A03" from "A03:2021 – Injection")
        owasp_code = owasp.split(":")[0] if ":" in owasp else owasp
        tags.append(f"OWASP-{owasp_code}")

    tags.extend(pci)
    tags.extend(soc2)

    return {
        "owasp": owasp,
        "pci_dss": pci,
        "soc2": soc2,
        "tags": tags,
    }


def generate_compliance_scorecard(findings: List[Dict]) -> Dict:
    """
    Generate a compliance scorecard from scan findings.

    Returns coverage status for each OWASP Top 10 category.
    """
    owasp_categories = {
        "A01": {"name": "Broken Access Control", "findings": 0, "critical": 0},
        "A02": {"name": "Cryptographic Failures", "findings": 0, "critical": 0},
        "A03": {"name": "Injection", "findings": 0, "critical": 0},
        "A04": {"name": "Insecure Design", "findings": 0, "critical": 0},
        "A05": {"name": "Security Misconfiguration", "findings": 0, "critical": 0},
        "A06": {
            "name": "Vulnerable and Outdated Components",
            "findings": 0,
            "critical": 0,
        },
        "A07": {
            "name": "Identification and Auth Failures",
            "findings": 0,
            "critical": 0,
        },
        "A08": {
            "name": "Software and Data Integrity Failures",
            "findings": 0,
            "critical": 0,
        },
        "A09": {
            "name": "Security Logging and Monitoring",
            "findings": 0,
            "critical": 0,
        },
        "A10": {"name": "Server-Side Request Forgery", "findings": 0, "critical": 0},
    }

    for f in findings:
        owasp = f.get("owasp_category", "")
        if not owasp:
            continue
        code = owasp.split(":")[0] if ":" in owasp else ""
        if code in owasp_categories:
            owasp_categories[code]["findings"] += 1
            if f.get("severity", "").lower() in ("critical", "high"):
                owasp_categories[code]["critical"] += 1

    return owasp_categories
