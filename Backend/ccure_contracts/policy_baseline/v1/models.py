"""
Contract 1 — Policy Pro → Audit: ``PolicyBaseline``, and Audit's synchronous
answer, ``BaselineCoverage``.

SRS 7.6.2, 7.3.1.2, 7.3.2.2, 7.2.6.1.

**Policy Pro decides what is required; Audit decides how it is checked.** A
baseline names framework controls, says which apply to the organisation, and
carries the organisation's chosen parameter values. It carries **no executable
check** — no command, query, registry path, OVAL definition or rule body — and
the model forbids unknown fields, so one cannot be smuggled in. Audit maps each
control onto its own assessment rules and reports, control by control, what it
can and cannot assess.

A received baseline is immutable (SRS 7.6.1). The same ``baseline_id`` and
``baseline_version`` sent again with the same content is an idempotent replay;
with different content it is refused with ``version_conflict``. A change is a
new ``baseline_version``.
"""

from __future__ import annotations

from typing import List, Literal, Optional, Union

from pydantic import AwareDatetime, model_validator

from ccure_contracts.common.v1.envelope import (
    CcureBaselineRefV1,
    CcureControlRefV1,
    CcureEnvelopeV1,
    CcureFrameworkRefV1,
    ContractModel,
    LongText,
    OpaqueId,
    ShortText,
)
from ccure_contracts.common.v1.fields import owned
from ccure_contracts.common.v1.vocabulary import (
    Applicability,
    BaselineMappingState,
    ParameterHandling,
)

POLICY_BASELINE_CONTRACT = "ccure.audit.policy_baseline"
BASELINE_COVERAGE_CONTRACT = "ccure.audit.baseline_coverage"

# ── Request: PolicyBaseline ───────────────────────────────────────────────────


class CcureBaselineParameterV1(ContractModel):
    """
    One organisation parameter, e.g. minimum password length = 12.

    Parameter names come from Audit's published vocabulary
    (``GET /api/v1/integrations/capabilities``), not from a list Policy Pro
    keeps: a vocabulary is fetched, not copied.
    """

    name: ShortText = owned(
        "policy_pro", "Parameter name from Audit's published parameter vocabulary."
    )
    value: Union[int, float, bool, ShortText] = owned(
        "policy_pro", "The organisation's chosen value."
    )
    unit: Optional[ShortText] = owned(
        "policy_pro", "Unit, e.g. 'characters', 'days', 'minutes'.", default=None
    )


class CcureBaselineControlV1(ContractModel):
    """One control requirement of the baseline."""

    requirement_id: OpaqueId = owned(
        "policy_pro", "Policy Pro's identifier for this requirement of the policy."
    )
    control: CcureControlRefV1 = owned("policy_pro", "The framework control required.")
    applicability: Applicability = owned(
        "policy_pro", "Whether the organisation declares the control applicable."
    )
    applicability_justification: Optional[LongText] = owned(
        "policy_pro",
        "Required when not applicable: the reason, as the Statement of "
        "Applicability records it (ISO/IEC 27001 6.1.3(d)).",
        default=None,
    )
    requirement_text: Optional[LongText] = owned(
        "policy_pro",
        "The policy's wording, for display to Audit users only. Audit never "
        "derives an executable check from it.",
        default=None,
    )
    parameters: List[CcureBaselineParameterV1] = owned(
        "policy_pro", "Organisation parameters for this control.", default_factory=list
    )

    @model_validator(mode="after")
    def _exclusion_needs_a_reason(self) -> "CcureBaselineControlV1":
        if (
            self.applicability is Applicability.NOT_APPLICABLE
            and not self.applicability_justification
        ):
            raise ValueError("a control declared not applicable must say why")
        return self


class CcureBaselineScopeV1(ContractModel):
    """
    Where the baseline applies. It can only **narrow** the organisation's
    authorised scan scope, never widen it: Policy Pro is not a scan
    authorisation, and an entry outside the authorised scope is reported back
    as rejected.
    """

    cidrs: List[ShortText] = owned(
        "policy_pro", "IP ranges in CIDR notation.", default_factory=list
    )
    asset_tags: List[ShortText] = owned(
        "policy_pro", "Audit asset tags.", default_factory=list
    )


class CcurePolicyRefV1(ContractModel):
    """The Policy Pro policy document this baseline was derived from (SRS 7.2.6.1)."""

    policy_id: OpaqueId = owned("policy_pro", "Policy Pro's policy identifier.")
    policy_version: ShortText = owned(
        "policy_pro", "The policy document's version label."
    )
    title: ShortText = owned("policy_pro", "Policy title, for display.")


class CcurePolicyBaselineDataV1(ContractModel):
    baseline_id: OpaqueId = owned("policy_pro", "Stable identifier of the baseline.")
    baseline_version: int = owned(
        "policy_pro",
        "Monotonic version. A new version is a new immutable record; a version "
        "is never edited.",
        ge=1,
    )
    supersedes_version: Optional[int] = owned(
        "policy_pro", "The version this one replaces, if any.", default=None, ge=1
    )
    policy: CcurePolicyRefV1 = owned("policy_pro", "The source policy document.")
    status: Literal["approved"] = owned(
        "policy_pro",
        "Only an approved policy is sent (SRS 7.6.2: 'once a policy has been "
        "finalized and approved').",
    )
    approved_at: AwareDatetime = owned("policy_pro", "When the policy was approved.")
    approver_ref: Optional[OpaqueId] = owned(
        "policy_pro",
        "Policy Pro's opaque reference to the approver. No personal data.",
        default=None,
    )
    effective_from: AwareDatetime = owned(
        "policy_pro", "From when the baseline is meant to govern assessments."
    )
    frameworks: List[CcureFrameworkRefV1] = owned(
        "policy_pro", "Frameworks the baseline draws controls from.", min_length=1
    )
    controls: List[CcureBaselineControlV1] = owned(
        "policy_pro", "The controls the baseline requires.", min_length=1
    )
    scope: Optional[CcureBaselineScopeV1] = owned(
        "policy_pro", "Optional narrowing of where the baseline applies.", default=None
    )

    @model_validator(mode="after")
    def _controls_belong_to_declared_frameworks(self) -> "CcurePolicyBaselineDataV1":
        declared = {(f.code, f.version) for f in self.frameworks}
        for control in self.controls:
            key = (control.control.framework.code, control.control.framework.version)
            if key not in declared:
                raise ValueError(
                    f"control {control.requirement_id} names framework {key}, "
                    "which the baseline does not declare"
                )
        seen: set[str] = set()
        for control in self.controls:
            if control.requirement_id in seen:
                raise ValueError(f"duplicate requirement_id {control.requirement_id}")
            seen.add(control.requirement_id)
        if self.supersedes_version is not None and (
            self.supersedes_version >= self.baseline_version
        ):
            raise ValueError("supersedes_version must be lower than baseline_version")
        return self


class CcurePolicyBaselineV1(CcureEnvelopeV1):
    """``POST /api/v1/integrations/policy-baselines`` request body."""

    contract: Literal["ccure.audit.policy_baseline"] = owned(
        "producer", "Contract name."
    )
    data: CcurePolicyBaselineDataV1 = owned("policy_pro", "The baseline.")


# ── Response: BaselineCoverage ────────────────────────────────────────────────


class CcureAuditRuleRefV1(ContractModel):
    """An Audit assessment rule a control maps to. Audit's, and opaque."""

    rule_id: OpaqueId = owned(
        "audit",
        "Audit's rule identifier — the same namespace as "
        "ControlResult.rules[].rule_id, so a result can be matched to the "
        "coverage that promised it.",
    )
    title: ShortText = owned("audit", "Rule title, for display.")
    check_type: ShortText = owned(
        "audit",
        "The kind of check, e.g. 'registry', 'config_file', 'scap_rule', "
        "'database_query', 'evidence_key'. Descriptive only.",
    )
    platforms: List[ShortText] = owned(
        "audit",
        "Platforms the rule can assess, e.g. 'windows', 'linux'.",
        default_factory=list,
    )


class CcureControlMappingV1(ContractModel):
    requirement_id: OpaqueId = owned(
        "policy_pro", "Echo of the baseline requirement this entry answers."
    )
    control: CcureControlRefV1 = owned("policy_pro", "Echo of the control.")
    applicability: Applicability = owned(
        "policy_pro",
        "Echo of the applicability the baseline declared. A not-applicable "
        "control is still mapped, so the owner can see what Audit could have "
        "assessed; Audit does not assess it.",
    )
    mapping_state: BaselineMappingState = owned(
        "audit", "How Audit can assess the control.", srs=("7.3.1.2", "7.3.2.1")
    )
    audit_rules: List[CcureAuditRuleRefV1] = owned(
        "audit",
        "The Audit rules the control maps to. Empty for ATTESTATION_REQUIRED, "
        "UNKNOWN_CONTROL and UNSUPPORTED.",
        default_factory=list,
    )
    reason: Optional[ShortText] = owned(
        "audit",
        "Why the control is not (fully) automated. Required unless AUTOMATED.",
        default=None,
    )
    notes: List[ShortText] = owned(
        "audit",
        "Anything else the owner must know about this control, whatever its "
        "mapping state — e.g. that its framework is not installed for this "
        "tenant, so Audit will not assess it until it is.",
        default_factory=list,
    )

    @model_validator(mode="after")
    def _rules_match_state(self) -> "CcureControlMappingV1":
        automated = {
            BaselineMappingState.AUTOMATED,
            BaselineMappingState.PARTIALLY_AUTOMATED,
        }
        if self.mapping_state in automated and not self.audit_rules:
            raise ValueError(f"{self.mapping_state.value} must name its Audit rules")
        if self.mapping_state not in automated and self.audit_rules:
            raise ValueError(f"{self.mapping_state.value} cannot name Audit rules")
        if self.mapping_state is not BaselineMappingState.AUTOMATED and not self.reason:
            raise ValueError(f"{self.mapping_state.value} must give a reason")
        return self


class CcureParameterOutcomeV1(ContractModel):
    requirement_id: OpaqueId = owned("policy_pro", "Echo of the requirement.")
    name: ShortText = owned("policy_pro", "Echo of the parameter name.")
    handling: ParameterHandling = owned(
        "audit",
        "What Audit does with the value. Until Audit's rules take parameters "
        "(plan Phase 17) every known parameter is RECORDED_NOT_HONOURED — "
        "recorded, reported, and never silently ignored.",
        availability="partial",
    )
    reason: Optional[ShortText] = owned(
        "audit", "Why, when not HONOURED.", default=None
    )


class CcureScopeRejectionV1(ContractModel):
    entry: ShortText = owned("policy_pro", "Echo of the refused scope entry.")
    reason: ShortText = owned(
        "audit",
        "Why it was refused — outside the authorised scope, or not a valid "
        "CIDR. Each needs a different fix.",
    )


class CcureScopeOutcomeV1(ContractModel):
    applied: bool = owned("audit", "Whether any scope narrowing was applied.")
    organisation_scope_configured: bool = owned(
        "audit",
        "Whether the organisation has an authorised scan scope at all. When "
        "false, a CIDR is narrowing an unrestricted scope and was not checked "
        "against one — which is different from having passed a check.",
    )
    rejected_entries: List[CcureScopeRejectionV1] = owned(
        "audit",
        "Scope entries refused, each with its reason.",
        default_factory=list,
    )
    unmatched_asset_tags: List[ShortText] = owned(
        "audit",
        "Asset tags no asset of this tenant carries today. Not refused — a tag "
        "may be applied later — but a scope made only of these assesses "
        "nothing.",
        default_factory=list,
    )


class CcureCoverageSummaryV1(ContractModel):
    controls_total: int = owned("audit", "Controls in the baseline.", ge=0)
    automated: int = owned("audit", "Controls mapped AUTOMATED.", ge=0)
    partially_automated: int = owned(
        "audit", "Controls mapped PARTIALLY_AUTOMATED.", ge=0
    )
    attestation_required: int = owned("audit", "Controls needing attestation.", ge=0)
    unknown_control: int = owned(
        "audit", "Controls Audit's catalogue does not know.", ge=0
    )
    unsupported: int = owned("audit", "Known controls Audit cannot assess.", ge=0)

    @model_validator(mode="after")
    def _adds_up(self) -> "CcureCoverageSummaryV1":
        parts = (
            self.automated
            + self.partially_automated
            + self.attestation_required
            + self.unknown_control
            + self.unsupported
        )
        if parts != self.controls_total:
            raise ValueError("coverage summary does not add up to controls_total")
        return self


class CcureBaselineCoverageDataV1(ContractModel):
    baseline: CcureBaselineRefV1 = owned(
        "audit", "The baseline answered, with the digest Audit computed."
    )
    received_at: AwareDatetime = owned(
        "audit", "When Audit first accepted this version."
    )
    mapping_revision: int = owned(
        "audit",
        "Increments when Audit re-maps the same baseline version because its own "
        "rule catalogue changed (a benchmark loaded, a rule retired). The "
        "baseline is immutable; its coverage is not.",
        ge=1,
    )
    mapped_at: AwareDatetime = owned(
        "audit", "When this mapping revision was computed."
    )
    activation: Literal["pending_review", "active", "superseded", "rejected"] = owned(
        "audit",
        "Whether the baseline governs Audit's assessments. A received baseline "
        "starts as pending_review and governs nothing until an Audit "
        "administrator explicitly activates it (Phase 4 review, Q1).",
    )
    summary: CcureCoverageSummaryV1 = owned("audit", "Counts per mapping state.")
    controls: List[CcureControlMappingV1] = owned(
        "audit", "One entry per baseline control, in baseline order."
    )
    parameters: List[CcureParameterOutcomeV1] = owned(
        "audit", "One entry per parameter received.", default_factory=list
    )
    scope: CcureScopeOutcomeV1 = owned("audit", "What happened to the scope narrowing.")

    @model_validator(mode="after")
    def _summary_matches_controls(self) -> "CcureBaselineCoverageDataV1":
        if self.summary.controls_total != len(self.controls):
            raise ValueError("summary.controls_total must equal len(controls)")
        return self


class CcureBaselineCoverageV1(CcureEnvelopeV1):
    """Response to a PolicyBaseline, and ``GET …/coverage``."""

    contract: Literal["ccure.audit.baseline_coverage"] = owned(
        "producer", "Contract name."
    )
    data: CcureBaselineCoverageDataV1 = owned(
        "audit", "Audit's coverage of the baseline."
    )


__all__ = [
    "BASELINE_COVERAGE_CONTRACT",
    "POLICY_BASELINE_CONTRACT",
    "CcureBaselineCoverageV1",
    "CcurePolicyBaselineV1",
]
