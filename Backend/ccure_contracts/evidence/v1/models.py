"""
``GET /api/v1/integrations/evidence/{evidence_id}`` — one evidence record.

SRS 7.6.4 (evidence for audit trails), 7.3.8.6 (documentation of required
artefacts). Contracts 2, 3 and 4 reference evidence by ``evidence_id`` rather
than embedding it, so a large or sensitive record reaches only a caller
entitled to it (``audit:evidence:read``, same tenant).

**Evidence text is redacted before it leaves Audit.** Command output collected
off a host can carry credentials, tokens and personal data; the record says
whether redaction was applied, and never carries the unredacted text. A file is
described here and downloaded from ``download_path`` on the same authenticated
API — Audit never hands another module a URL to fetch elsewhere.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import AwareDatetime, model_validator

from ccure_contracts.common.v1.envelope import (
    CcureAssessmentRefV1,
    CcureAssetRefV1,
    CcureControlRefV1,
    CcureEnvelopeV1,
    CcureFindingRefV1,
    ContractModel,
    LongText,
    OpaqueId,
    Sha256,
    ShortText,
)
from ccure_contracts.common.v1.fields import owned
from ccure_contracts.common.v1.vocabulary import Module

EVIDENCE_RECORD_CONTRACT = "ccure.audit.evidence_record"


class CcureEvidenceFileV1(ContractModel):
    name: ShortText = owned("audit", "File name as stored (sanitised).")
    media_type: ShortText = owned(
        "audit", "Verified media type (content-sniffed, not declared)."
    )
    size_bytes: int = owned("audit", "Size.", ge=0)
    sha256: Sha256 = owned("audit", "Digest.")
    download_path: ShortText = owned(
        "audit", "Path on this API, e.g. /api/v1/integrations/evidence/{id}/content."
    )
    malware_scan: Literal["clean", "not_configured", "not_scanned"] = owned(
        "audit",
        "Upload-guard result. 'not_configured' is not 'clean' (CLAUDE.md, file uploads).",
    )


class CcureEvidenceRecordDataV1(ContractModel):
    evidence_id: OpaqueId = owned("audit", "Identifier.")
    kind: Literal[
        "check_observation",
        "finding_proof",
        "uploaded_file",
        "attestation",
        "incident_evidence",
    ] = owned("audit", "What the evidence is.")
    origin_module: Module = owned(
        "audit",
        "Who produced the content. 'ir' for evidence received through contract 5 "
        "— stored read-only, never edited by Audit.",
    )
    collected_at: AwareDatetime = owned("audit", "When collected or received.")
    assessment: Optional[CcureAssessmentRefV1] = owned(
        "audit", "The assessment that collected it.", default=None
    )
    asset: Optional[CcureAssetRefV1] = owned(
        "audit", "The asset it concerns.", default=None
    )
    finding_refs: List[CcureFindingRefV1] = owned(
        "audit", "Findings it supports.", default_factory=list
    )
    control_refs: List[CcureControlRefV1] = owned(
        "platform", "Controls it supports.", default_factory=list
    )
    text: Optional[LongText] = owned(
        "audit", "Redacted textual evidence, e.g. an observed setting.", default=None
    )
    redaction_applied: bool = owned(
        "audit", "Whether anything was masked from text before it was returned."
    )
    file: Optional[CcureEvidenceFileV1] = owned(
        "audit", "Present when the evidence is a stored file.", default=None
    )

    @model_validator(mode="after")
    def _has_content(self) -> "CcureEvidenceRecordDataV1":
        if self.text is None and self.file is None:
            raise ValueError("an evidence record carries text, a file, or both")
        return self


class CcureEvidenceRecordV1(CcureEnvelopeV1):
    contract: Literal["ccure.audit.evidence_record"] = owned(
        "producer", "Contract name."
    )
    data: CcureEvidenceRecordDataV1 = owned("audit", "The record.")
