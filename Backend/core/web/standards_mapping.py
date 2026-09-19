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
import re
from typing import Dict, List, Optional

log = logging.getLogger("ccure.web.compliance")

# ── CWE (Common Weakness Enumeration) Mapping ────────────────────────────────
#
# One authoritative table from finding_type to a canonical CWE identifier, so
# the weakness class a finding carries is decided in a single place rather than
# hardcoded independently inside each detection engine (where it drifted: the
# legacy nuclei/sqlmap/sslyze/ffuf paths and the orchestrator's own
# header/CORS/redirect checks set no CWE at all, so SQL injection, TLS
# weaknesses, CORS and missing security headers all reached the report with an
# empty CWE).
#
# Rules this table is built to enforce (see resolve_cwe/normalize_cwe below):
#   • a CWE an engine or source tool already supplied wins — it is more
#     specific than a per-type default (insecure_http_method is CWE-693 for
#     TRACE but CWE-650 for a dangerous verb; a nuclei template and an NVD
#     record each name their own), so the map is a *fallback*, never an
#     override;
#   • only well-formed "CWE-<n>" identifiers survive — a fabricated or
#     malformed value is dropped, never stored;
#   • a finding_type with no single defensible CWE is deliberately absent, and
#     absence yields None rather than a guessed identifier.
#
# Every entry is the primary weakness for that class. finding_types that are
# intentionally unmapped, with the reason, are pinned by the Phase 8 tests:
#   misconfig           — nuclei catch-all spanning many unrelated weaknesses
#   cve                 — the CWE travels per-CVE from the vuln feed / template
#   exposed_panel       — a reachable panel is not itself a weakness
#   technology_detected — informational, not a weakness
CWE_MAP: dict[str, str] = {
    # Injection family
    "sqli": "CWE-89",  # SQL Injection
    "xss": "CWE-79",  # Cross-site Scripting
    "command_injection": "CWE-78",  # OS Command Injection
    "rce": "CWE-94",  # Code Injection
    "ssti": "CWE-1336",  # Server-Side Template Injection
    "xxe": "CWE-611",  # XML External Entity
    "ldap_injection": "CWE-90",  # LDAP Injection
    "xpath_injection": "CWE-643",  # XPath Injection
    "header_injection": "CWE-113",  # HTTP Response Splitting
    # Access control family
    "idor": "CWE-639",  # Authorization Bypass Through User-Controlled Key
    "broken_access_control": "CWE-284",  # Improper Access Control
    "privilege_escalation": "CWE-269",  # Improper Privilege Management
    "path_traversal": "CWE-22",  # Path Traversal
    "lfi": "CWE-98",  # PHP Local File Inclusion
    "rfi": "CWE-98",  # PHP Remote File Inclusion
    "file_inclusion": "CWE-98",
    "open_redirect": "CWE-601",  # URL Redirection to Untrusted Site
    "csrf": "CWE-352",  # Cross-Site Request Forgery
    "http_method_auth_bypass": "CWE-288",  # Auth Bypass Using Alternate Path
    # Server-side request / misconfiguration
    "ssrf": "CWE-918",  # Server-Side Request Forgery
    "cors": "CWE-942",  # Permissive Cross-domain Policy
    "insecure_http_method": "CWE-693",  # Protection Mechanism Failure (TRACE/XST)
    # Cryptographic failures
    "tls_issue": "CWE-326",  # Inadequate Encryption Strength (umbrella)
    "insecure_cookie": "CWE-614",  # Sensitive Cookie Without Secure (umbrella)
    # Information exposure
    "information_disclosure": "CWE-200",  # Exposure of Sensitive Information
    "graphql_introspection": "CWE-200",
    "excessive_data_exposure": "CWE-213",  # Exposure of Sensitive Information Due to Incompatible Policies
    # Authentication
    "broken_auth": "CWE-287",  # Improper Authentication
    "default_creds": "CWE-1392",  # Use of Default Credentials
    "api_missing_auth": "CWE-306",  # Missing Authentication for Critical Function
    # Vulnerable components
    "vulnerable_js_library": "CWE-1395",  # Dependency on Vulnerable Third-Party Component
}

#: finding_types that carry no single defensible CWE, and the reason. Pinned by
#: a test so a new type is a deliberate decision (map it, or record it here),
#: never a silent gap.
CWE_UNMAPPED: dict[str, str] = {
    "misconfig": "nuclei catch-all spanning many unrelated weaknesses",
    "cve": "CWE travels per-CVE from the vuln feed / template classification",
    "exposed_panel": "a reachable panel is not itself a weakness",
    "technology_detected": "informational, not a weakness",
    "unknown": "unclassified finding",
}

_CWE_RE = re.compile(r"^CWE-(\d+)$", re.IGNORECASE)


def normalize_cwe(value) -> Optional[str]:
    """
    Canonicalise a CWE identifier to ``CWE-<n>`` or return None.

    Accepts ``"CWE-79"``, ``"cwe-79"``, the bare ``"79"`` and a list/tuple
    (the first well-formed entry wins — nuclei publishes ``cwe-id`` as a list).
    Anything that is not a well-formed CWE number is rejected, which is how a
    fabricated or malformed identifier is prevented from ever being stored.
    """
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        for v in value:
            n = normalize_cwe(v)
            if n:
                return n
        return None
    s = str(value).strip()
    if not s:
        return None
    if s.isdigit():
        return f"CWE-{int(s)}"
    m = _CWE_RE.match(s)
    if m:
        return f"CWE-{int(m.group(1))}"
    return None


def cwe_for(finding_type: str) -> Optional[str]:
    """Central default CWE for a finding_type, or None when none is defensible."""
    return CWE_MAP.get((finding_type or "").strip().lower())


def resolve_cwe(finding: dict) -> Optional[str]:
    """
    The CWE for a finding, most-specific first:

      1. a well-formed CWE the engine or source tool already supplied
         (preserves specificity and source-tool classification);
      2. the centralized finding_type default;
      3. None — a missing CWE is represented honestly, never fabricated.
    """
    supplied = normalize_cwe(finding.get("cwe_id"))
    if supplied:
        return supplied
    return cwe_for(finding.get("finding_type", ""))


# ── OWASP Top 10 2021 Mapping ────────────────────────────────────────────────

OWASP_MAP: dict[str, str] = {
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
    "privilege_escalation": "A01:2021 – Broken Access Control",
    "broken_access_control": "A01:2021 – Broken Access Control",
    "graphql_introspection": "A05:2021 – Security Misconfiguration",
    "excessive_data_exposure": "A01:2021 – Broken Access Control",
    "api_missing_auth": "A07:2021 – Identification and Authentication Failures",
    "insecure_http_method": "A05:2021 – Security Misconfiguration",
    "http_method_auth_bypass": "A01:2021 – Broken Access Control",
    "path_traversal": "A01:2021 – Broken Access Control",
    "file_inclusion": "A01:2021 – Broken Access Control",
    "tls_issue": "A02:2021 – Cryptographic Failures",
    "insecure_cookie": "A05:2021 – Security Misconfiguration",
    "cors": "A05:2021 – Security Misconfiguration",
    "cve": "A06:2021 – Vulnerable and Outdated Components",
    "vulnerable_js_library": "A06:2021 – Vulnerable and Outdated Components",
    "information_disclosure": "A01:2021 – Broken Access Control",
    "csrf": "A01:2021 – Broken Access Control",
    "open_redirect": "A01:2021 – Broken Access Control",
    "header_injection": "A03:2021 – Injection",
    "technology_detected": "",  # Informational, no OWASP mapping
    "rce": "A03:2021 – Injection",
    "lfi": "A01:2021 – Broken Access Control",
    "rfi": "A01:2021 – Broken Access Control",
    # Phase 2 active-injection classes — all Injection (A03).
    "ssti": "A03:2021 – Injection",
    "ldap_injection": "A03:2021 – Injection",
    "xpath_injection": "A03:2021 – Injection",
}

# ── PCI-DSS 4.0 Mapping ──────────────────────────────────────────────────────

PCI_DSS_MAP: dict[str, list[str]] = {
    "sqli": ["PCI-DSS-6.2.4", "PCI-DSS-6.5.1"],
    "xss": ["PCI-DSS-6.2.4", "PCI-DSS-6.5.7"],
    "command_injection": ["PCI-DSS-6.2.4"],
    "xxe": ["PCI-DSS-6.2.4"],
    "ssti": ["PCI-DSS-6.2.4"],
    "ldap_injection": ["PCI-DSS-6.2.4"],
    "xpath_injection": ["PCI-DSS-6.2.4"],
    "tls_issue": ["PCI-DSS-4.2.1", "PCI-DSS-4.2.2"],
    "default_creds": ["PCI-DSS-2.2.2", "PCI-DSS-8.2.2"],
    "misconfig": ["PCI-DSS-2.2.1"],
    "cve": ["PCI-DSS-6.3.3"],
    "cors": ["PCI-DSS-6.2.4"],
    "csrf": ["PCI-DSS-6.2.4"],
    "information_disclosure": ["PCI-DSS-3.4.1"],
    "exposed_panel": ["PCI-DSS-1.3.1"],
    "broken_auth": ["PCI-DSS-8.3.1", "PCI-DSS-8.3.6"],
    "idor": ["PCI-DSS-7.2.1", "PCI-DSS-6.2.4"],
    "privilege_escalation": ["PCI-DSS-7.2.1", "PCI-DSS-7.2.2"],
    "broken_access_control": ["PCI-DSS-7.2.1"],
}

# ── SOC 2 Trust Service Criteria Mapping ──────────────────────────────────────

SOC2_MAP: dict[str, list[str]] = {
    "sqli": ["SOC2-CC6.1", "SOC2-CC6.6"],
    "xss": ["SOC2-CC6.1"],
    "tls_issue": ["SOC2-CC6.7"],
    "default_creds": ["SOC2-CC6.1", "SOC2-CC6.3"],
    "misconfig": ["SOC2-CC6.1"],
    "cve": ["SOC2-CC7.1"],
    "information_disclosure": ["SOC2-CC6.5"],
    "broken_auth": ["SOC2-CC6.1", "SOC2-CC6.3"],
}

# ── DPDP Act 2023 Mapping ────────────────────────────────────────────────────

DPDP_MAP: dict[str, list[str]] = {
    "sqli": ["DPDP-SEC-5.1", "DPDP-SEC-5.3"],
    "xss": ["DPDP-SEC-5.1"],
    "tls_issue": ["DPDP-SEC-5.1"],
    "default_creds": ["DPDP-SEC-5.2"],
    "information_disclosure": ["DPDP-PRIV-1.1", "DPDP-PRIV-2.1"],
    "broken_auth": ["DPDP-SEC-5.2"],
}

# ── GDPR Mapping ─────────────────────────────────────────────────────────────

GDPR_MAP: dict[str, list[str]] = {
    "sqli": ["GDPR-Art-32", "GDPR-Art-5.1.f"],
    "xss": ["GDPR-Art-32"],
    "tls_issue": ["GDPR-Art-32.1.a"],
    "default_creds": ["GDPR-Art-32.1.b"],
    "information_disclosure": ["GDPR-Art-5.1.a", "GDPR-Art-13"],
    "broken_auth": ["GDPR-Art-32.1.b"],
}

# ── NIST SP 800-53 Rev. 5 Mapping ────────────────────────────────────────────

NIST_800_53_MAP: dict[str, list[str]] = {
    "sqli": ["NIST800-53-SI-10", "NIST800-53-SA-11"],
    "xss": ["NIST800-53-SI-10", "NIST800-53-SC-28"],
    "command_injection": ["NIST800-53-SI-10", "NIST800-53-SA-11"],
    "xxe": ["NIST800-53-SI-10"],
    "ssti": ["NIST800-53-SI-10", "NIST800-53-SA-11"],
    "ldap_injection": ["NIST800-53-SI-10"],
    "xpath_injection": ["NIST800-53-SI-10"],
    "ssrf": ["NIST800-53-SC-7", "NIST800-53-AC-4"],
    "broken_auth": ["NIST800-53-IA-5", "NIST800-53-AC-7"],
    "default_creds": ["NIST800-53-IA-5", "NIST800-53-CM-6"],
    "misconfig": ["NIST800-53-CM-6", "NIST800-53-CM-7"],
    "exposed_panel": ["NIST800-53-AC-17", "NIST800-53-AC-3"],
    "idor": ["NIST800-53-AC-3", "NIST800-53-AC-6"],
    "privilege_escalation": ["NIST800-53-AC-6", "NIST800-53-AC-3"],
    "broken_access_control": ["NIST800-53-AC-3", "NIST800-53-AC-2"],
    "graphql_introspection": ["NIST800-53-CM-6", "NIST800-53-SC-28"],
    "excessive_data_exposure": ["NIST800-53-AC-3", "NIST800-53-SC-28"],
    "api_missing_auth": ["NIST800-53-IA-2", "NIST800-53-AC-3"],
    "insecure_http_method": ["NIST800-53-CM-6", "NIST800-53-CM-7"],
    "http_method_auth_bypass": ["NIST800-53-AC-3", "NIST800-53-AC-6"],
    "path_traversal": ["NIST800-53-AC-3", "NIST800-53-SI-10"],
    "tls_issue": ["NIST800-53-SC-8", "NIST800-53-SC-28"],
    "cors": ["NIST800-53-SC-7", "NIST800-53-CM-7"],
    "cve": ["NIST800-53-SI-2", "NIST800-53-RA-5"],
    "vulnerable_js_library": ["NIST800-53-SI-2", "NIST800-53-RA-5"],
    "information_disclosure": ["NIST800-53-AC-3", "NIST800-53-SC-28"],
    "csrf": ["NIST800-53-SI-10", "NIST800-53-SC-8"],
}


def map_compliance(finding_type: str) -> dict:
    """
    Map a finding type to compliance framework tags.

    Args:
        finding_type: e.g., "sqli", "xss", "tls_issue"

    Returns:
        {
            "owasp": "A03:2021 – Injection",
            "pci_dss": [...],
            "soc2": [...],
            "dpdp": [...],
            "gdpr": [...],
            "nist_800_53": [...],
            "tags": ["OWASP-A03", "PCI-DSS-6.5.1", "SOC2-CC6.1", "DPDP-SEC-5.1", "GDPR-Art-32", "NIST800-53-SI-10"]
        }
    """
    owasp = OWASP_MAP.get(finding_type, "")
    pci = PCI_DSS_MAP.get(finding_type, [])
    soc2 = SOC2_MAP.get(finding_type, [])
    dpdp = DPDP_MAP.get(finding_type, [])
    gdpr = GDPR_MAP.get(finding_type, [])
    nist53 = NIST_800_53_MAP.get(finding_type, [])

    tags: list[str] = []

    if owasp:
        # Extract short code (e.g., "A03" from "A03:2021 – Injection")
        owasp_code = owasp.split(":")[0] if ":" in owasp else owasp
        tags.append(f"OWASP-{owasp_code}")

    tags.extend(pci)
    tags.extend(soc2)
    tags.extend(dpdp)
    tags.extend(gdpr)
    tags.extend(nist53)

    return {
        "owasp": owasp,
        "pci_dss": pci,
        "soc2": soc2,
        "dpdp": dpdp,
        "gdpr": gdpr,
        "nist_800_53": nist53,
        "cwe": cwe_for(finding_type),
        "tags": tags,
    }


def generate_compliance_scorecard(findings: list[dict]) -> dict:
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
