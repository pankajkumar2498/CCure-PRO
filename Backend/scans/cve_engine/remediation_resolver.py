"""
Resolves remediation text PER CVE using CPE version boundaries and NVD patch links.
"""

from .models import CveRecord, CpeMatch, Remediation, RemediationConfidence


def resolve_remediation(cve: CveRecord, cpe: CpeMatch) -> Remediation:
    patch_refs = cve.patch_references()
    if patch_refs:
        return Remediation(
            summary=(
                f"Apply the vendor patch/advisory for {cve.cve_id} "
                f"({cpe.vendor}:{cpe.product}). See reference link."
            ),
            confidence=RemediationConfidence.CVE_SPECIFIC,
            patch_url=patch_refs[0].url,
        )

    if cpe.version_end_excluding:
        return Remediation(
            summary=(
                f"Upgrade {cpe.vendor} {cpe.product} to version "
                f"{cpe.version_end_excluding} or later to remediate {cve.cve_id}."
            ),
            confidence=RemediationConfidence.CPE_RANGE_INFERRED,
            fixed_version=cpe.version_end_excluding,
        )
    if cpe.version_end_including:
        return Remediation(
            summary=(
                f"Upgrade {cpe.vendor} {cpe.product} past version "
                f"{cpe.version_end_including} to remediate {cve.cve_id}."
            ),
            confidence=RemediationConfidence.CPE_RANGE_INFERRED,
            fixed_version=cpe.version_end_including,
        )

    return Remediation(
        summary=(
            f"No vendor patch or version boundary is published for {cve.cve_id}. "
            f"Apply compensating controls (network segmentation, WAF/IPS rules, "
            f"or vendor mitigation guidance) and monitor for an official fix."
        ),
        confidence=RemediationConfidence.GENERIC_FALLBACK,
    )
