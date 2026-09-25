"""
Contract 5 — IR → Audit: ``IncidentEvidence``, and Audit's ``Receipt``.

SRS 7.6.4 ("incident logs and response effectiveness evidence … formal evidence
for audit trails and compliance reporting"), 7.3.5.8, 7.4.5, 7.4.6.

Audit stores what IR sends as **read-only evidence** attached to the findings
and assets it names (SRS 7.6.1). IR owns the incident; Audit never edits it.

**IR can never close a finding.** A remediation claim is recorded as a claim.
At most it moves a finding to ``pending_verification`` and requests a targeted
re-scan (SRS 7.3.5.8); only an Audit scan can reach ``verified_fixed``. The
claim vocabulary below has no member meaning "verified", so it cannot be said.

**No binary attachments in v1.** Audit does not fetch URLs a caller supplies —
that would let another module aim this host's network access — and inline
files need the upload guard's full treatment (type sniffing, AV, quota). v1
carries IR-side references and digests; the files stay in IR.

Idempotent per (incident_id, incident_version): a replay with identical
content returns the original receipt; different content is ``version_conflict``.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Literal, Optional

from pydantic import AwareDatetime, model_validator

from ccure_contracts.common.v1.envelope import (
    CcureAssetRefV1,
    CcureEnvelopeV1,
    CcureFindingRefV1,
    CcureMeasuredValueV1,
    ContractModel,
    LongText,
    OpaqueId,
    Sha256,
    ShortText,
)
from ccure_contracts.common.v1.fields import owned
from ccure_contracts.common.v1.vocabulary import RemediationState

INCIDENT_EVIDENCE_CONTRACT = "ccure.audit.incident_evidence"
INCIDENT_EVIDENCE_RECEIPT_CONTRACT = "ccure.audit.incident_evidence_receipt"


class IncidentStatus(str, Enum):
    OPEN = "open"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class RemediationClaimKind(str, Enum):
    """What IR says it did about a finding. There is no 'verified'."""

    REMEDIATED = "remediated"
    MITIGATED = "mitigated"
    NOT_REMEDIATED = "not_remediated"


class CcureIncidentTimelineV1(ContractModel):
    """SRS 7.4.5 — the timestamps IR's effectiveness scoring uses."""

    occurred_at: Optional[AwareDatetime] = owned("ir", "Estimated start.", default=None)
    detected_at: AwareDatetime = owned("ir", "Detection.")
    contained_at: Optional[AwareDatetime] = owned("ir", "Containment.", default=None)
    recovered_at: Optional[AwareDatetime] = owned("ir", "Recovery.", default=None)
    closed_at: Optional[AwareDatetime] = owned("ir", "Case closure.", default=None)


class CcureResponseActionV1(ContractModel):
    action_id: OpaqueId = owned("ir", "IR's action identifier.")
    action_type: ShortText = owned(
        "ir", "e.g. isolate_host, block_ip, patch, reset_credential."
    )
    description: LongText = owned("ir", "What was done.")
    performed_at: AwareDatetime = owned("ir", "When.")
    performed_by_ref: Optional[OpaqueId] = owned(
        "ir", "Opaque reference to who or what performed it.", default=None
    )
    outcome: Literal["succeeded", "failed", "partial"] = owned("ir", "Result.")


class CcureRemediationClaimV1(ContractModel):
    finding: CcureFindingRefV1 = owned(
        "audit", "An Audit finding IR received in contract 4."
    )
    claim: RemediationClaimKind = owned("ir", "What IR claims.")
    claimed_at: AwareDatetime = owned("ir", "When the claim was made.")
    description: LongText = owned("ir", "What was done, in words.")
    request_rescan: bool = owned(
        "ir",
        "Ask Audit to schedule a targeted re-scan of the affected asset "
        "(SRS 7.3.5.8). A request, not an order: Audit's scope and quota apply.",
        default=False,
    )


class CcureExternalEvidenceV1(ContractModel):
    """A file IR holds. Audit records the reference and digest, not the bytes."""

    ir_evidence_id: OpaqueId = owned("ir", "IR's identifier for the file.")
    name: ShortText = owned("ir", "File name.")
    media_type: ShortText = owned("ir", "MIME type.")
    size_bytes: int = owned("ir", "Size.", ge=0)
    sha256: Sha256 = owned(
        "ir", "Digest, so an auditor can match the file IR produces."
    )


class CcureIncidentEvidenceDataV1(ContractModel):
    incident_id: OpaqueId = owned("ir", "IR's incident identifier.")
    incident_version: int = owned(
        "ir", "Monotonic; each update is a new immutable record.", ge=1
    )
    title: ShortText = owned("ir", "Incident title.")
    status: IncidentStatus = owned("ir", "Incident status.")
    severity: Literal["critical", "high", "medium", "low"] = owned(
        "ir", "IR's severity."
    )
    timeline: CcureIncidentTimelineV1 = owned("ir", "Key timestamps.", srs=("7.4.5",))
    summary: LongText = owned("ir", "Incident summary / log digest.", srs=("7.4.6",))
    related_findings: List[CcureFindingRefV1] = owned(
        "audit", "Audit findings the incident concerns.", default_factory=list
    )
    related_assets: List[CcureAssetRefV1] = owned(
        "audit", "Audit assets the incident concerns.", default_factory=list
    )
    response_actions: List[CcureResponseActionV1] = owned(
        "ir", "Response actions taken.", default_factory=list
    )
    remediation_claims: List[CcureRemediationClaimV1] = owned(
        "ir", "Claims about Audit findings.", default_factory=list
    )
    effectiveness_score: CcureMeasuredValueV1 = owned(
        "ir", "IR's response effectiveness score (SRS 7.4.5).", srs=("7.4.5",)
    )
    evidence_files: List[CcureExternalEvidenceV1] = owned(
        "ir", "Files IR holds, by reference and digest.", default_factory=list
    )

    @model_validator(mode="after")
    def _coherent(self) -> "CcureIncidentEvidenceDataV1":
        claimed = {c.finding.finding_id for c in self.remediation_claims}
        related = {f.finding_id for f in self.related_findings}
        if not claimed <= related:
            raise ValueError("every remediation claim must name a related finding")
        if self.status is IncidentStatus.CLOSED and self.timeline.closed_at is None:
            raise ValueError("a closed incident needs timeline.closed_at")
        return self


class CcureIncidentEvidenceV1(CcureEnvelopeV1):
    """``POST /api/v1/integrations/incident-evidence`` request body."""

    contract: Literal["ccure.audit.incident_evidence"] = owned(
        "producer", "Contract name."
    )
    data: CcureIncidentEvidenceDataV1 = owned("ir", "The incident evidence.")


# ── Receipt ───────────────────────────────────────────────────────────────────


class CcureLinkOutcomeV1(ContractModel):
    finding_id: OpaqueId = owned("ir", "Echo of the referenced finding.")
    linked: bool = owned(
        "audit",
        "Whether the finding exists in this tenant. An unknown id is simply "
        "not linked; the receipt never says whether it exists elsewhere.",
    )


class CcureClaimOutcomeV1(ContractModel):
    finding_id: OpaqueId = owned("ir", "Echo of the finding.")
    disposition: Literal[
        "recorded",
        "recorded_pending_verification",
        "rescan_requested",
        "rejected",
    ] = owned(
        "audit",
        "What Audit did. 'recorded_pending_verification' moves the finding to "
        "pending_verification; nothing here reaches verified_fixed.",
    )
    remediation_state_after: Optional[RemediationState] = owned(
        "audit", "The finding's remediation state after the claim.", default=None
    )
    reason: Optional[ShortText] = owned("audit", "Why, when rejected.", default=None)

    @model_validator(mode="after")
    def _never_verified(self) -> "CcureClaimOutcomeV1":
        if self.remediation_state_after is RemediationState.VERIFIED_FIXED:
            raise ValueError("an IR claim can never make a finding verified_fixed")
        if self.disposition == "rejected" and not self.reason:
            raise ValueError("a rejected claim must say why")
        return self


class CcureIncidentEvidenceReceiptDataV1(ContractModel):
    receipt_id: OpaqueId = owned("audit", "Audit's identifier for the stored record.")
    incident_id: OpaqueId = owned("ir", "Echo.")
    incident_version: int = owned("ir", "Echo.", ge=1)
    content_sha256: Sha256 = owned("audit", "Digest of the evidence as stored.")
    received_at: AwareDatetime = owned("audit", "When Audit first stored this version.")
    findings: List[CcureLinkOutcomeV1] = owned(
        "audit", "Link outcome per related finding."
    )
    claims: List[CcureClaimOutcomeV1] = owned(
        "audit", "Outcome per remediation claim.", default_factory=list
    )


class CcureIncidentEvidenceReceiptV1(CcureEnvelopeV1):
    contract: Literal["ccure.audit.incident_evidence_receipt"] = owned(
        "producer", "Contract name."
    )
    data: CcureIncidentEvidenceReceiptDataV1 = owned("audit", "The receipt.")
