"""
Data models for the CVE matching / remediation engine.

Design principle: every field a report needs (title, CVSS vector, remediation)
must be resolvable FROM structured data tied to a specific CVE — never from a
per-service template. Templates are only a last-resort fallback and are
explicitly flagged as such (`remediation_confidence = "generic_fallback"`).
"""

from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class CvssVector(BaseModel):
    version: str  # "3.1", "3.0", "2.0"
    vector_string: str
    base_score: float
    attack_vector: str  # N / A / L / P
    attack_complexity: str  # L / H
    privileges_required: str  # N / L / H
    user_interaction: str  # N / R
    scope: str  # U / C
    confidentiality: str  # N / L / H
    integrity: str  # N / L / H
    availability: str  # N / L / H

    @property
    def is_locally_exploitable_only(self) -> bool:
        return self.attack_vector in ("L", "P")


class CpeMatch(BaseModel):
    """A single CPE 2.3 URI + the version range NVD says is vulnerable."""

    cpe23_uri: str  # cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*
    vendor: str
    product: str
    version_start_including: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    version_end_excluding: Optional[str] = None
    vulnerable: bool = True


class ReferenceTag(str, Enum):
    PATCH = "Patch"
    VENDOR_ADVISORY = "Vendor Advisory"
    THIRD_PARTY_ADVISORY = "Third Party Advisory"
    EXPLOIT = "Exploit"
    MITIGATION = "Mitigation"
    RELEASE_NOTES = "Release Notes"
    ISSUE_TRACKING = "Issue Tracking"


class CveReference(BaseModel):
    url: str
    tags: List[ReferenceTag] = Field(default_factory=list)
    source: Optional[str] = None


class CveRecord(BaseModel):
    """Cached, structured NVD record. This is what everything else resolves against."""

    cve_id: str
    title: str  # curated title
    description: str
    published_date: datetime
    last_modified_date: datetime
    cvss: CvssVector
    cpe_matches: List[CpeMatch] = Field(default_factory=list)
    references: List[CveReference] = Field(default_factory=list)
    cwe_ids: List[str] = Field(default_factory=list)
    in_kev: bool = False
    epss_score: float = 0.0

    def patch_references(self) -> List[CveReference]:
        return [
            r
            for r in self.references
            if ReferenceTag.PATCH in r.tags or ReferenceTag.VENDOR_ADVISORY in r.tags
        ]


class RemediationConfidence(str, Enum):
    CVE_SPECIFIC = (
        "cve_specific"  # derived from this exact CVE's fix version / patch link
    )
    CPE_RANGE_INFERRED = (
        "cpe_range_inferred"  # derived from the versionEndExcluding boundary
    )
    GENERIC_FALLBACK = (
        "generic_fallback"  # no per-CVE data found — must be visibly flagged
    )


class Remediation(BaseModel):
    summary: str
    confidence: RemediationConfidence
    patch_url: Optional[str] = None
    fixed_version: Optional[str] = None


class DetectedService(BaseModel):
    """What your scanner actually observed on the wire — the input to matching."""

    host: str
    port: int
    protocol: str  # tcp/udp
    service_name: str  # banner-derived, e.g. "postgresql"
    product: Optional[str] = None
    version: Optional[str] = None
    raw_banner: Optional[str] = None


class VulnerabilityFinding(BaseModel):
    cve: CveRecord
    matched_service: DetectedService
    matched_cpe: CpeMatch
    remediation: Remediation
    match_confidence: float  # 0-1
