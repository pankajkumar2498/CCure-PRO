"""
cve_engine package — Live NVD 2.0 API sync, CPE 2.3 version matcher, and per-CVE remediation resolver.
"""

from .models import (
    CveRecord,
    CvssVector,
    CpeMatch,
    CveReference,
    ReferenceTag,
    Remediation,
    RemediationConfidence,
    DetectedService,
    VulnerabilityFinding,
)
from .nvd_client import NvdClient
from .cpe_matcher import match_service_to_cves, build_findings
from .remediation_resolver import resolve_remediation
from .cvss_validator import integrity_warnings

__all__ = [
    "CveRecord",
    "CvssVector",
    "CpeMatch",
    "CveReference",
    "ReferenceTag",
    "Remediation",
    "RemediationConfidence",
    "DetectedService",
    "VulnerabilityFinding",
    "NvdClient",
    "match_service_to_cves",
    "build_findings",
    "resolve_remediation",
    "integrity_warnings",
]
