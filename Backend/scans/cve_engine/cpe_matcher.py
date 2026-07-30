"""
CPE 2.3 Version-Range Matcher for Detected Services.
"""

from packaging.version import Version, InvalidVersion
from typing import List, Tuple

from .models import CveRecord, CpeMatch, DetectedService, VulnerabilityFinding

SERVICE_TO_CPE_PRODUCT: dict[str, tuple[str, str]] = {
    "postgresql": ("postgresql", "postgresql"),
    "postgres": ("postgresql", "postgresql"),
    "mysql": ("mysql", "mysql"),
    "openssh": ("openbsd", "openssh"),
    "apache": ("apache", "http_server"),
    "nginx": ("f5", "nginx"),
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
}


def _version_in_range(version: str, cpe: CpeMatch) -> bool:
    try:
        v = Version(version)
    except InvalidVersion:
        return False

    if cpe.version_start_including:
        try:
            if v < Version(cpe.version_start_including):
                return False
        except InvalidVersion:
            pass
    if cpe.version_start_excluding:
        try:
            if v <= Version(cpe.version_start_excluding):
                return False
        except InvalidVersion:
            pass
    if cpe.version_end_including:
        try:
            if v > Version(cpe.version_end_including):
                return False
        except InvalidVersion:
            pass
    if cpe.version_end_excluding:
        try:
            if v >= Version(cpe.version_end_excluding):
                return False
        except InvalidVersion:
            pass
    return True


def match_service_to_cves(
    service: DetectedService, cve_candidates: List[CveRecord]
) -> List[Tuple[CveRecord, CpeMatch, float]]:
    key = service.product.lower() if service.product else service.service_name.lower()
    canonical = SERVICE_TO_CPE_PRODUCT.get(key)
    if canonical is None:
        return []

    vendor, product = canonical
    results = []

    for cve in cve_candidates:
        for cpe in cve.cpe_matches:
            if cpe.vendor != vendor or cpe.product != product:
                continue

            if service.version:
                if _version_in_range(service.version, cpe):
                    results.append((cve, cpe, 1.0))
            else:
                results.append((cve, cpe, 0.6))

    return results


def build_findings(
    service: DetectedService, cve_candidates: List[CveRecord]
) -> List[VulnerabilityFinding]:
    from .remediation_resolver import resolve_remediation

    findings = []
    for cve, cpe, confidence in match_service_to_cves(service, cve_candidates):
        findings.append(
            VulnerabilityFinding(
                cve=cve,
                matched_service=service,
                matched_cpe=cpe,
                remediation=resolve_remediation(cve, cpe),
                match_confidence=confidence,
            )
        )
    return findings
