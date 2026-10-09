"""
Audit-owned result shapes shared by the outbound contracts (2, 3 and 4).

Three rules are enforced here rather than left to the reader, because each was
a defect that reached this product in some other form:

* **A control is PASS only when every in-scope asset reached a verdict and none
  failed.** A control that passed on the assets reached and was never run on
  the rest has not passed.
* **An asset nobody assessed carries no finding counts** — ``null``, not
  zeros. Zero findings on an unassessed asset means nothing was learned; the
  consumer must be able to tell that from the payload alone.
* **Every non-verdict state says why.**
"""

from __future__ import annotations

from datetime import date
from typing import List, Literal, Optional

from pydantic import AwareDatetime, model_validator

from ccure_contracts.common.v1.envelope import (
    CcureAssessmentRefV1,
    CcureAssetRefV1,
    CcureControlRefV1,
    CcureEvidenceRefV1,
    CcureFindingRefV1,
    CcureMeasuredValueV1,
    ContractModel,
    LongText,
    OpaqueId,
    ShortText,
)
from ccure_contracts.common.v1.fields import owned
from ccure_contracts.common.v1.vocabulary import (
    VERDICT_STATES,
    AssessmentMethod,
    AssessmentState,
    ComplianceDisposition,
    CoverageState,
    CredentialOutcome,
    DefinitionType,
    DetectionConfidence,
    DetectionMethod,
    DetectionStatus,
    ExploitAvailability,
    MethodOutcome,
    RemediationState,
    Severity,
    SlaState,
)

# ── Counts ────────────────────────────────────────────────────────────────────


class CcureStateCountsV1(ContractModel):
    """How many assets (or rules) ended in each assessment state."""

    pass_: int = owned("audit", "PASS.", ge=0, alias="PASS")
    fail: int = owned("audit", "FAIL.", ge=0, alias="FAIL")
    not_assessed: int = owned("audit", "NOT_ASSESSED.", ge=0, alias="NOT_ASSESSED")
    not_applicable: int = owned(
        "audit", "NOT_APPLICABLE.", ge=0, alias="NOT_APPLICABLE"
    )
    manual_review: int = owned("audit", "MANUAL_REVIEW.", ge=0, alias="MANUAL_REVIEW")
    error: int = owned("audit", "ERROR.", ge=0, alias="ERROR")


class CcureSeverityCountsV1(ContractModel):
    critical: int = owned("audit", "Critical.", ge=0)
    high: int = owned("audit", "High.", ge=0)
    medium: int = owned("audit", "Medium.", ge=0)
    low: int = owned("audit", "Low.", ge=0)
    none: int = owned("audit", "Published rating of zero.", ge=0)
    unscored: int = owned("audit", "No rating published.", ge=0)


class CcureCoverageStateCountsV1(ContractModel):
    """Assets per coverage state. Every state is present; zero is a real count."""

    assessed: int = owned("audit", "ASSESSED.", ge=0, alias="ASSESSED")
    partially_assessed: int = owned(
        "audit", "PARTIALLY_ASSESSED.", ge=0, alias="PARTIALLY_ASSESSED"
    )
    not_assessed: int = owned("audit", "NOT_ASSESSED.", ge=0, alias="NOT_ASSESSED")
    error: int = owned("audit", "ERROR.", ge=0, alias="ERROR")

    def as_map(self) -> dict[CoverageState, int]:
        return {
            CoverageState.ASSESSED: self.assessed,
            CoverageState.PARTIALLY_ASSESSED: self.partially_assessed,
            CoverageState.NOT_ASSESSED: self.not_assessed,
            CoverageState.ERROR: self.error,
        }


class CcureRemediationStateCountsV1(ContractModel):
    """Findings per remediation state."""

    open: int = owned("audit", "open.", ge=0)
    assigned: int = owned("audit", "assigned.", ge=0)
    in_remediation: int = owned("audit", "in_remediation.", ge=0)
    pending_verification: int = owned("audit", "pending_verification.", ge=0)
    verified_fixed: int = owned("audit", "verified_fixed.", ge=0)
    reopened: int = owned("audit", "reopened.", ge=0)
    risk_accepted: int = owned("audit", "risk_accepted.", ge=0)


class CcureSlaStateCountsV1(ContractModel):
    """Open findings per SLA state. ``not_applicable`` is never folded into ``within_sla``."""

    within_sla: int = owned("audit", "within_sla.", ge=0)
    due_soon: int = owned("audit", "due_soon.", ge=0)
    overdue: int = owned("audit", "overdue.", ge=0)
    resolved: int = owned("audit", "resolved.", ge=0)
    pending_verification: int = owned("audit", "pending_verification.", ge=0)
    not_applicable: int = owned("audit", "not_applicable (no deadline).", ge=0)


# ── Controls ──────────────────────────────────────────────────────────────────


class CcureRuleResultV1(ContractModel):
    """One Audit rule's outcome across the assessed scope, within a control."""

    rule_id: OpaqueId = owned(
        "audit",
        "Audit's rule identifier — the same namespace as "
        "BaselineCoverage.controls[].audit_rules[].rule_id, so a result can be "
        "matched to the coverage that promised it.",
    )
    title: ShortText = owned("audit", "Rule title.")
    severity: Severity = owned("audit", "Rule severity.")
    state: AssessmentState = owned("audit", "The rule's rolled-up state.")
    asset_counts: CcureStateCountsV1 = owned("audit", "Per-asset outcomes.")
    reason: Optional[ShortText] = owned(
        "audit", "Why, for a state that is not a verdict.", default=None
    )


class CcureControlResultV1(ContractModel):
    """
    The result for one framework control.

    ``state`` is rolled up over the control's rules and assets with the
    precedence ``FAIL > ERROR > NOT_ASSESSED > MANUAL_REVIEW > PASS >
    NOT_APPLICABLE``: a confirmed failure is reported whatever else is unknown,
    and anything unknown outranks a pass.
    """

    control: CcureControlRefV1 = owned("platform", "The control.")
    requirement_id: Optional[OpaqueId] = owned(
        "policy_pro",
        "The baseline requirement this answers, when assessed against a baseline.",
        default=None,
    )
    state: AssessmentState = owned("audit", "Rolled-up state.", srs=("7.3.8.6",))
    state_reason: Optional[ShortText] = owned(
        "audit", "Why, for any state other than PASS or FAIL.", default=None
    )
    basis: Literal["automated", "attestation", "mixed"] = owned(
        "audit",
        "Whether the state comes from automated checks, a human attestation, "
        "or both.",
    )
    disposition: ComplianceDisposition = owned(
        "audit",
        "A recorded human/workflow decision kept beside the state, never in "
        "place of it.",
        default=ComplianceDisposition.NONE,
    )
    asset_counts: CcureStateCountsV1 = owned(
        "audit", "Per-asset outcomes across the control's automated rules."
    )
    rules: List[CcureRuleResultV1] = owned(
        "audit", "Per-rule results.", default_factory=list
    )
    gap_description: Optional[LongText] = owned(
        "audit", "What failed, for a FAIL. Plain language.", default=None
    )
    finding_refs: Optional[List[CcureFindingRefV1]] = owned(
        "audit",
        "Findings that caused a FAIL. null: Audit does not link control results "
        "to findings yet — which is not the same as an empty list, which would "
        "state that no finding caused it.",
        default=None,
        availability="not_implemented",
    )
    evidence_refs: Optional[List[CcureEvidenceRefV1]] = owned(
        "audit",
        "Evidence supporting the state. null: Audit does not issue evidence "
        "references yet — which is not the same as an empty list, which would "
        "state that no evidence exists.",
        default=None,
        availability="not_implemented",
    )

    @model_validator(mode="after")
    def _states_are_earned(self) -> "CcureControlResultV1":
        if self.state not in VERDICT_STATES and not self.state_reason:
            raise ValueError(f"{self.state.value} must carry a state_reason")
        counts = self.asset_counts
        if self.basis == "automated":
            if self.state is AssessmentState.PASS and (
                counts.pass_ == 0
                or counts.fail
                or counts.error
                or counts.not_assessed
                or counts.manual_review
            ):
                raise ValueError(
                    "PASS requires at least one passing asset and no asset that "
                    "failed, errored, needs review or was not assessed"
                )
            if self.state is AssessmentState.FAIL and counts.fail == 0:
                raise ValueError("an automated FAIL requires a failing asset")
        return self


# ── Assets ────────────────────────────────────────────────────────────────────


class CcureMethodResultV1(ContractModel):
    method: AssessmentMethod = owned("audit", "The method.")
    outcome: MethodOutcome = owned(
        "audit",
        "What happened. 'unknown' where Audit recorded no structured outcome — "
        "never read it as completed.",
        availability="partial",
    )
    reason: Optional[ShortText] = owned("audit", "Why, unless completed.", default=None)

    @model_validator(mode="after")
    def _explained(self) -> "CcureMethodResultV1":
        if self.outcome is not MethodOutcome.COMPLETED and not self.reason:
            raise ValueError(f"method outcome {self.outcome.value} must give a reason")
        return self


class CcurePrivilegeContextV1(ContractModel):
    """
    Which token the authenticated session held. ``null`` means it could not be
    read — not "no": a partial audit must not be mistaken for a complete one.
    """

    is_administrator: Optional[bool] = owned(
        "audit",
        "Member of the local administrators / root.",
        default=None,
        availability="partial",
    )
    is_system: Optional[bool] = owned(
        "audit", "Windows SYSTEM token.", default=None, availability="partial"
    )
    elevation: Optional[Literal["sudo", "dzdo", "pfexec", "none"]] = owned(
        "audit",
        "Elevation mechanism used on Unix.",
        default=None,
        availability="partial",
    )


class CcureCredentialedAccessV1(ContractModel):
    """
    The authenticated session a credentialed assessment ran over.

    ``outcome`` is the authentication result; coverage is separate
    (``inventory_complete`` here and the asset's method results), because a
    session that authenticated can still collect only part of what it asked for.
    """

    outcome: CredentialOutcome = owned(
        "audit",
        "Authentication result. Audit stores success/failure today; the "
        "failure sub-class is available where the transport classified it, "
        "otherwise FAILED_UNCLASSIFIED.",
        srs=("7.3.1.10", "7.3.6.4"),
        availability="partial",
    )
    credential_ref: Optional[OpaqueId] = owned(
        "audit", "Audit's credential identifier. Never the secret.", default=None
    )
    transport: Optional[
        Literal["ssh", "winrm", "smb", "postgresql", "mysql", "mssql"]
    ] = owned("audit", "The transport that was used or attempted.", default=None)
    port: Optional[int] = owned("audit", "TCP port.", default=None, ge=1, le=65535)
    auth_method: Optional[ShortText] = owned(
        "audit", "e.g. password, private_key, ntlm, ntlm_hash.", default=None
    )
    privilege: Optional[CcurePrivilegeContextV1] = owned(
        "audit", "Token held, when authenticated.", default=None
    )
    inventory_complete: Optional[bool] = owned(
        "audit",
        "Whether collection completed. null when not authenticated or not recorded.",
        default=None,
        availability="partial",
    )
    failure_detail: Optional[ShortText] = owned(
        "audit",
        "Operator-facing failure text. Never contains the secret.",
        default=None,
    )

    @model_validator(mode="after")
    def _consistent(self) -> "CcureCredentialedAccessV1":
        if (
            self.outcome is not CredentialOutcome.SUCCEEDED
            and self.privilege is not None
        ):
            raise ValueError("a session that did not authenticate holds no privilege")
        return self


class CcureAssetRiskV1(ContractModel):
    """Asset-level risk inputs (SRS 7.3.7.3, 7.3.7.5)."""

    audit_host_risk_score: CcureMeasuredValueV1 = owned(
        "audit",
        "Audit's own additive 0–100 host score (core/risk.calculate_risk). It is "
        "NOT the SRS weighted risk score.",
    )
    asset_criticality: CcureMeasuredValueV1 = owned(
        "audit",
        "Business criticality 1–10 (SRS 7.3.7.3). Audit has no criticality "
        "attribute yet: not_implemented.",
        srs=("7.3.7.3",),
        availability="not_implemented",
    )
    exposure: CcureMeasuredValueV1 = owned(
        "audit",
        "Network exposure factor (SRS 7.3.7.5). Not computed yet: not_implemented.",
        srs=("7.3.7.5",),
        availability="not_implemented",
    )
    network_zone: Optional[ShortText] = owned(
        "audit",
        "Network segment / Purdue zone (SRS 7.3.1.3). Not modelled yet; always null.",
        default=None,
        srs=("7.3.1.3",),
        availability="not_implemented",
    )


class CcureOsV1(ContractModel):
    family: Optional[ShortText] = owned("audit", "e.g. windows, linux.", default=None)
    name: Optional[ShortText] = owned("audit", "Product name.", default=None)
    version: Optional[ShortText] = owned("audit", "Version or build.", default=None)


class CcureAssetAssessmentV1(ContractModel):
    asset: CcureAssetRefV1 = owned("audit", "The asset.")
    os: Optional[CcureOsV1] = owned(
        "audit", "Operating system, where identified.", default=None
    )
    device_category: Optional[ShortText] = owned(
        "audit", "Audit's device classification.", default=None
    )
    coverage: CoverageState = owned(
        "audit",
        "How completely the asset was assessed. ASSESSED only when every method "
        "the scan's policy selected completed.",
    )
    coverage_reason: Optional[ShortText] = owned(
        "audit", "Why, unless ASSESSED.", default=None
    )
    methods: List[CcureMethodResultV1] = owned(
        "audit", "Per-method outcomes.", default_factory=list, availability="partial"
    )
    credentialed: Optional[CcureCredentialedAccessV1] = owned(
        "audit",
        "The authenticated session. null when no credential was in scope for "
        "this asset — which is different from a refused credential.",
        default=None,
    )
    finding_counts: Optional[CcureSeverityCountsV1] = owned(
        "audit",
        "Open findings by severity. null when the asset was NOT_ASSESSED or "
        "ERROR: nothing was learned, which is not zero.",
        default=None,
    )
    risk: CcureAssetRiskV1 = owned("audit", "Risk inputs.")

    @model_validator(mode="after")
    def _unknown_is_not_zero(self) -> "CcureAssetAssessmentV1":
        if self.coverage in (CoverageState.NOT_ASSESSED, CoverageState.ERROR):
            if self.finding_counts is not None:
                raise ValueError(
                    f"an asset with coverage {self.coverage.value} must carry "
                    "finding_counts=null — nothing was learned, which is not zero"
                )
        if self.coverage is not CoverageState.ASSESSED and not self.coverage_reason:
            raise ValueError(f"coverage {self.coverage.value} must give a reason")
        return self


# ── Findings ──────────────────────────────────────────────────────────────────


class CcureDefinitionV1(ContractModel):
    definition_id: OpaqueId = owned(
        "audit",
        "Catalogue identifier: a CVE id, or an Audit-minted CCURE-CFG-/CCURE-PRV-/"
        "CCURE-CHK- identifier.",
    )
    definition_type: DefinitionType = owned("audit", "What kind of entry it is.")
    cve_id: Optional[ShortText] = owned(
        "audit", "The CVE, only when definition_type is cve.", default=None
    )
    title: ShortText = owned("audit", "Title.")

    @model_validator(mode="after")
    def _cve_only_for_cves(self) -> "CcureDefinitionV1":
        if (self.definition_type is DefinitionType.CVE) != (self.cve_id is not None):
            raise ValueError("cve_id is present exactly when definition_type is cve")
        return self


class CcureCvssV1(ContractModel):
    score: Optional[float] = owned("audit", "Base score.", default=None, ge=0, le=10)
    vector: Optional[ShortText] = owned("audit", "Vector string.", default=None)
    version: Optional[ShortText] = owned("audit", "2.0, 3.0, 3.1 or 4.0.", default=None)


class CcureDetectionV1(ContractModel):
    method: DetectionMethod = owned("audit", "How the finding was established.")
    confidence: DetectionConfidence = owned("audit", "Confidence class.")
    qod: Optional[int] = owned(
        "audit", "Quality of detection 0–100.", default=None, ge=0, le=100
    )
    detected_version: Optional[ShortText] = owned(
        "audit", "Version observed on the host.", default=None
    )


class CcureExploitIntelV1(ContractModel):
    """Threat intelligence about the vulnerability — not about this host."""

    availability: ExploitAvailability = owned(
        "audit", "Strongest exploit evidence known.", srs=("7.3.7.4",)
    )
    in_cisa_kev: Optional[bool] = owned(
        "audit", "Listed in CISA KEV. null for non-CVE findings.", default=None
    )
    kev_due_date: Optional[date] = owned(
        "audit", "CISA BOD 22-01 due date, when listed.", default=None
    )
    epss_score: Optional[float] = owned(
        "audit", "EPSS probability.", default=None, ge=0, le=1
    )
    ransomware_linked: Optional[bool] = owned(
        "audit", "Known ransomware use.", default=None
    )


class CcureFindingRiskV1(ContractModel):
    """
    SRS 7.3.7.5: ``risk = CVSS×0.4 + Criticality×0.3 + Exposure×0.2 +
    Exploit×0.1``. Each component is published separately. Audit can populate
    only CVSS and exploit availability today, so the composite, the category and
    the residual score are ``not_implemented`` — never computed from zeros.
    """

    cvss_component: CcureMeasuredValueV1 = owned(
        "audit", "CVSS base score.", srs=("7.3.7.2",)
    )
    asset_criticality_component: CcureMeasuredValueV1 = owned(
        "audit", "Asset criticality.", srs=("7.3.7.3",), availability="not_implemented"
    )
    exposure_component: CcureMeasuredValueV1 = owned(
        "audit", "Exposure.", srs=("7.3.7.5",), availability="not_implemented"
    )
    srs_risk_score: CcureMeasuredValueV1 = owned(
        "audit",
        "The SRS weighted score.",
        srs=("7.3.7.5",),
        availability="not_implemented",
    )
    risk_category: Optional[Literal["critical", "high", "medium", "low"]] = owned(
        "audit",
        "SRS 7.3.7.6 tier. Not implemented; always null.",
        default=None,
        srs=("7.3.7.6",),
        availability="not_implemented",
    )
    residual_risk_score: CcureMeasuredValueV1 = owned(
        "audit",
        "After compensating controls (SRS 7.3.7.8).",
        srs=("7.3.7.8",),
        availability="not_implemented",
    )
    audit_priority: Optional[Literal["P0", "P1", "P2", "P3", "P4"]] = owned(
        "audit",
        "Audit's own KEV/EPSS/exploit priority (core/vuln_intel.compute_priority). "
        "Not the SRS score. Computed for display and not stored on the finding, "
        "so not published yet; always null.",
        default=None,
        availability="not_implemented",
    )


class CcureRiskAcceptanceV1(ContractModel):
    accepted_at: AwareDatetime = owned(
        "audit", "When the risk was accepted.", srs=("7.3.5.10", "7.3.7.9")
    )
    expires_at: Optional[AwareDatetime] = owned(
        "audit", "Expiry; null for an indefinite acceptance.", default=None
    )
    reason: LongText = owned("audit", "Justification for non-remediation.")
    accepted_by_ref: Optional[OpaqueId] = owned(
        "audit", "Opaque user reference of the approver.", default=None
    )
    compensating_controls: Optional[LongText] = owned(
        "audit",
        "Mandatory in the SRS; not captured on vulnerability findings today — null.",
        default=None,
        srs=("7.3.5.10", "7.3.7.7"),
        availability="not_implemented",
    )


class CcureRemediationV1(ContractModel):
    state: RemediationState = owned("audit", "Remediation workflow state.")
    sla_state: SlaState = owned("audit", "Deadline state.")
    sla_due_at: Optional[AwareDatetime] = owned(
        "audit", "Due date; null when no SLA applies.", default=None
    )
    verified_at: Optional[AwareDatetime] = owned(
        "audit", "When a scan verified the fix (SRS 7.3.5.8).", default=None
    )
    verified_by: Optional[CcureAssessmentRefV1] = owned(
        "audit", "The verifying assessment.", default=None
    )
    reopened_count: int = owned(
        "audit", "Times the finding returned after a fix.", ge=0
    )
    guidance: Optional[LongText] = owned(
        "audit",
        "Remediation guidance (vendor advisory or check remediation).",
        default=None,
    )
    risk_acceptance: Optional[CcureRiskAcceptanceV1] = owned(
        "audit", "Present only while an acceptance is in force.", default=None
    )

    @model_validator(mode="after")
    def _verified_only_by_a_scan(self) -> "CcureRemediationV1":
        if self.state is RemediationState.VERIFIED_FIXED and self.verified_by is None:
            raise ValueError("verified_fixed must name the assessment that verified it")
        if (self.state is RemediationState.RISK_ACCEPTED) != (
            self.risk_acceptance is not None
        ):
            raise ValueError(
                "risk_acceptance is present exactly in state risk_accepted"
            )
        return self


class CcureFindingV1(ContractModel):
    finding: CcureFindingRefV1 = owned("audit", "Identity.")
    definition: CcureDefinitionV1 = owned("audit", "What was found.")
    asset: CcureAssetRefV1 = owned("audit", "Where.")
    severity: Severity = owned("audit", "Technical severity.")
    cvss: Optional[CcureCvssV1] = owned("audit", "CVSS, where published.", default=None)
    detection: CcureDetectionV1 = owned("audit", "How it was established.")
    exploit: CcureExploitIntelV1 = owned("audit", "Threat intelligence.")
    status: DetectionStatus = owned("audit", "Present on the host or not.")
    first_found_at: AwareDatetime = owned("audit", "First detection (SLA clock start).")
    last_found_at: AwareDatetime = owned("audit", "Most recent detection.")
    fixed_at: Optional[AwareDatetime] = owned(
        "audit", "When a scan last found it absent.", default=None
    )
    remediation: CcureRemediationV1 = owned("audit", "Remediation workflow.")
    risk: CcureFindingRiskV1 = owned("audit", "Risk components.")
    last_assessment: CcureAssessmentRefV1 = owned(
        "audit", "The assessment that last detected it."
    )
    evidence_refs: Optional[List[CcureEvidenceRefV1]] = owned(
        "audit",
        "Evidence supporting the finding. null: Audit does not issue evidence "
        "references yet — which is not the same as an empty list, which would "
        "state that no evidence exists.",
        default=None,
        availability="not_implemented",
    )
