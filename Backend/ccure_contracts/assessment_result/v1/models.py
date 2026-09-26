"""
Contract 3 — Audit → Rank: ``AssessmentResult`` (immutable, one per completed
assessment) and ``PostureSnapshot`` (current state, pull only).

SRS 7.6.5, 7.5.1, 7.3.7, 7.3.8.7, 7.3.8.8. Design document §3 Interface 3
("vulnerability counts by category, overall compliance score, MTTR data, asset
criticality distribution").

**AssessmentResult is immutable.** It is published once, when an assessment
reaches a terminal state, and never edited: it records what that assessment
established, which is what a maturity score needs to be reproducible. Findings
and control results are paged through their own resources, so the message
itself stays bounded however large the assessment was.

**A correction is a new result, never an edit.** If an Audit defect made a
published result wrong, Audit publishes a new result naming the old one in
``supersedes_result_id`` with a ``correction_reason``; the old result stays
exactly as it was published (Phase 4 review, Q9).

**PostureSnapshot is current state.** Findings change after a scan —
remediation, verification, acceptance — and a scan-time result cannot answer
"what is open now". The snapshot is generated on request and carries the time
it is valid for.

**Coverage travels with every count.** Rank must be able to tell "no findings
on an assessed asset" from "nothing was learned about this asset" from the
payload alone.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import AwareDatetime, model_validator

from ccure_contracts.common.v1.assessment import (
    CcureAssetAssessmentV1,
    CcureControlResultV1,
    CcureCoverageStateCountsV1,
    CcureFindingV1,
    CcureRemediationStateCountsV1,
    CcureSeverityCountsV1,
    CcureSlaStateCountsV1,
    CcureStateCountsV1,
)
from ccure_contracts.common.v1.envelope import (
    CcureAssessmentRefV1,
    CcureBaselineRefV1,
    CcureEnvelopeV1,
    CcureFrameworkRefV1,
    CcureMeasuredValueV1,
    ContractModel,
    OpaqueId,
    Sha256,
    ShortText,
)
from ccure_contracts.common.v1.feeds import CcureFeedPositionV1
from ccure_contracts.common.v1.fields import owned
from ccure_contracts.common.v1.vocabulary import (
    AssessmentKind,
    AssessmentOrigin,
    AssessmentStatus,
    CoverageState,
    DefinitionType,
)

ASSESSMENT_RESULT_CONTRACT = "ccure.audit.assessment_result"
ASSESSMENT_FINDINGS_PAGE_CONTRACT = "ccure.audit.assessment_findings_page"
ASSESSMENT_CONTROLS_PAGE_CONTRACT = "ccure.audit.assessment_controls_page"
POSTURE_SNAPSHOT_CONTRACT = "ccure.audit.posture_snapshot"


# ── AssessmentResult ─────────────────────────────────────────────────────────


class CcureAssessmentDescriptorV1(ContractModel):
    assessment: CcureAssessmentRefV1 = owned("audit", "Identity and completion time.")
    kind: AssessmentKind = owned("audit", "What kind of assessment.")
    status: AssessmentStatus = owned("audit", "How it ended.")
    status_reason: Optional[ShortText] = owned(
        "audit", "Why, unless completed.", default=None
    )
    origin: AssessmentOrigin = owned("audit", "What started it.")
    started_at: AwareDatetime = owned("audit", "Start.")
    scan_policy_name: Optional[ShortText] = owned(
        "audit", "Name of the scan policy, if one was chosen.", default=None
    )
    baseline: Optional[CcureBaselineRefV1] = owned(
        "audit", "The Policy Pro baseline in force, if any.", default=None
    )

    @model_validator(mode="after")
    def _explained(self) -> "CcureAssessmentDescriptorV1":
        if self.status is not AssessmentStatus.COMPLETED and not self.status_reason:
            raise ValueError(f"status {self.status.value} must give a reason")
        if self.assessment.completed_at is None:
            raise ValueError("an assessment result describes a terminal assessment")
        return self


class CcureCoverageCountsV1(ContractModel):
    assets_targeted: CcureMeasuredValueV1 = owned(
        "audit",
        "Addresses the assessment was asked to cover. Available for network "
        "scans; a range target's size is known, a hostname list's may not be.",
        availability="partial",
    )
    assets_discovered: int = owned("audit", "Live assets found.", ge=0)
    by_coverage: CcureCoverageStateCountsV1 = owned(
        "audit", "Discovered assets per coverage state."
    )


class CcureCategoryCountV1(ContractModel):
    definition_type: DefinitionType = owned("audit", "Finding category.")
    counts: CcureSeverityCountsV1 = owned("audit", "By severity.")


class CcureFindingTotalsV1(ContractModel):
    """Open findings detected by this assessment. Counted only over assessed assets."""

    by_severity: CcureSeverityCountsV1 = owned(
        "audit", "Open findings by severity.", srs=("7.3.8.7",)
    )
    by_category: List[CcureCategoryCountV1] = owned(
        "audit", "By finding category (CVE, configuration, privilege, network check)."
    )
    new_since_baseline_assessment: CcureMeasuredValueV1 = owned(
        "audit",
        "New relative to the previous comparable assessment (GAP-13). "
        "not_applicable when there is none.",
        availability="partial",
    )


class CcureFrameworkSummaryV1(ContractModel):
    framework: CcureFrameworkRefV1 = owned("platform", "The framework.")
    controls: CcureStateCountsV1 = owned(
        "audit", "Controls per state.", srs=("7.3.8.6",)
    )
    compliance_score: CcureMeasuredValueV1 = owned(
        "audit",
        "Audit's framework score, where a compliance scoring run produced one.",
        availability="partial",
    )


class CcureProgrammeMetricsV1(ContractModel):
    """
    Vulnerability-management KPIs (SRS 7.3.8.7, 7.3.8.8; design Interface 3).

    Audit stores the timestamps each is derived from (first_found_at,
    verified_at, reopened_count, sla_due_at) but computes none of these
    aggregates yet, so all are ``not_implemented``. Rank can compute them from
    the per-finding lifecycle fields in the findings pages meanwhile.
    """

    mttr: CcureMeasuredValueV1 = owned(
        "audit",
        "Mean time to remediate, seconds.",
        srs=("7.3.8.8",),
        availability="not_implemented",
    )
    sla_compliance_rate: CcureMeasuredValueV1 = owned(
        "audit",
        "Percent remediated within SLA.",
        srs=("7.3.8.7",),
        availability="not_implemented",
    )
    reopen_rate: CcureMeasuredValueV1 = owned(
        "audit",
        "Percent of fixed findings that reappeared.",
        srs=("7.3.8.7",),
        availability="not_implemented",
    )
    vulnerability_density: CcureMeasuredValueV1 = owned(
        "audit",
        "Findings per assessed asset.",
        srs=("7.3.8.7",),
        availability="not_implemented",
    )
    criticality_distribution: CcureMeasuredValueV1 = owned(
        "audit",
        "Assets per criticality band. Requires asset criticality, which Audit "
        "does not have.",
        srs=("7.3.7.3",),
        availability="not_implemented",
    )


class CcureAssessmentResultDataV1(ContractModel):
    result_id: OpaqueId = owned("audit", "Identifier of this immutable result.")
    content_sha256: Sha256 = owned(
        "audit", "Digest of the canonical JSON of this data object without this field."
    )
    supersedes_result_id: Optional[OpaqueId] = owned(
        "audit",
        "Set only on a correction: the earlier result this one replaces, because "
        "an Audit defect made it wrong. The earlier result is never edited or "
        "withdrawn; consumers prefer the newest result in a supersession chain.",
        default=None,
    )
    correction_reason: Optional[ShortText] = owned(
        "audit",
        "Why the earlier result was superseded. Required with supersedes_result_id.",
        default=None,
    )
    descriptor: CcureAssessmentDescriptorV1 = owned("audit", "The assessment.")
    coverage: CcureCoverageCountsV1 = owned("audit", "What was covered.")
    assets: List[CcureAssetAssessmentV1] = owned(
        "audit", "Every discovered asset, with its coverage."
    )
    findings: CcureFindingTotalsV1 = owned("audit", "Finding totals.")
    finding_count: int = owned(
        "audit",
        "Findings in the findings pages (all detected by this assessment).",
        ge=0,
    )
    frameworks: List[CcureFrameworkSummaryV1] = owned(
        "audit", "Per-framework control summaries.", default_factory=list
    )
    control_result_count: int = owned(
        "audit", "Control results in the controls pages.", ge=0
    )
    metrics: CcureProgrammeMetricsV1 = owned("audit", "Programme KPIs.")

    @model_validator(mode="after")
    def _coverage_accounts_for_assets(self) -> "CcureAssessmentResultDataV1":
        if (self.supersedes_result_id is None) != (self.correction_reason is None):
            raise ValueError(
                "supersedes_result_id and correction_reason go together: a "
                "correction must say why"
            )
        if self.supersedes_result_id == self.result_id:
            raise ValueError("a result cannot supersede itself")
        tally = {state: 0 for state in CoverageState}
        for asset in self.assets:
            tally[asset.coverage] += 1
        declared = self.coverage.by_coverage.as_map()
        if tally != declared:
            raise ValueError("coverage.by_coverage does not match the assets listed")
        if self.coverage.assets_discovered != len(self.assets):
            raise ValueError("coverage.assets_discovered must equal len(assets)")
        return self


class CcureAssessmentResultV1(CcureEnvelopeV1):
    contract: Literal["ccure.audit.assessment_result"] = owned(
        "producer", "Contract name."
    )
    data: CcureAssessmentResultDataV1 = owned("audit", "The result.")


class CcureAssessmentFindingsPageV1(CcureEnvelopeV1):
    """``GET /api/v1/integrations/assessment-results/{result_id}/findings?cursor=``"""

    contract: Literal["ccure.audit.assessment_findings_page"] = owned(
        "producer", "Contract name."
    )
    result_id: OpaqueId = owned("audit", "The result these findings belong to.")
    items: List[CcureFindingV1] = owned(
        "audit",
        "Findings as they stood when the result was produced. Frozen with the result.",
    )
    position: CcureFeedPositionV1 = owned("audit", "Paging.")


class CcureAssessmentControlsPageV1(CcureEnvelopeV1):
    """``GET /api/v1/integrations/assessment-results/{result_id}/controls?cursor=``"""

    contract: Literal["ccure.audit.assessment_controls_page"] = owned(
        "producer", "Contract name."
    )
    result_id: OpaqueId = owned("audit", "The result these control results belong to.")
    items: List[CcureControlResultV1] = owned("audit", "Control results.")
    position: CcureFeedPositionV1 = owned("audit", "Paging.")


class CcureAssessmentResultPageV1(ContractModel):
    """``GET /api/v1/integrations/assessment-results?cursor=``"""

    items: List[CcureAssessmentResultV1] = owned("audit", "Results, oldest first.")
    position: CcureFeedPositionV1 = owned("audit", "Paging.")


# ── PostureSnapshot ───────────────────────────────────────────────────────────


class CcureAssetInventoryPostureV1(ContractModel):
    assets_known: int = owned("audit", "Active assets in the inventory.", ge=0)
    by_last_coverage: CcureCoverageStateCountsV1 = owned(
        "audit", "Assets per coverage state at their most recent assessment."
    )
    never_assessed: int = owned(
        "audit", "Inventory assets no completed assessment has covered.", ge=0
    )
    stale_after_days: int = owned(
        "audit", "Threshold used for 'stale' below, in days.", ge=1
    )
    stale: int = owned(
        "audit", "Assets whose last assessment is older than the threshold.", ge=0
    )


class CcureFindingPostureV1(ContractModel):
    open_by_severity: CcureSeverityCountsV1 = owned(
        "audit", "Open findings now, by severity."
    )
    by_remediation_state: CcureRemediationStateCountsV1 = owned(
        "audit", "Findings per remediation state."
    )
    by_sla_state: CcureSlaStateCountsV1 = owned(
        "audit", "Open findings per SLA state. not_applicable is kept separate."
    )
    accepted_risk: int = owned(
        "audit",
        "Findings under risk acceptance — tracked separately and excluded from "
        "operational risk metrics (SRS 7.3.5.10).",
        ge=0,
    )


class CcurePostureSnapshotDataV1(ContractModel):
    snapshot_id: OpaqueId = owned("audit", "Identifier of this snapshot.")
    valid_as_of: AwareDatetime = owned(
        "audit",
        "The instant the snapshot describes. Not immutable: re-request for later.",
    )
    inventory: CcureAssetInventoryPostureV1 = owned("audit", "Inventory coverage.")
    findings: CcureFindingPostureV1 = owned("audit", "Current findings.")
    frameworks: List[CcureFrameworkSummaryV1] = owned(
        "audit", "Current per-framework state.", default_factory=list
    )
    latest_results: List[CcureAssessmentRefV1] = owned(
        "audit",
        "The assessment results this snapshot reflects most recently.",
        default_factory=list,
    )
    metrics: CcureProgrammeMetricsV1 = owned("audit", "Programme KPIs.")


class CcurePostureSnapshotV1(CcureEnvelopeV1):
    """``GET /api/v1/integrations/posture`` — pull only."""

    contract: Literal["ccure.audit.posture_snapshot"] = owned(
        "producer", "Contract name."
    )
    data: CcurePostureSnapshotDataV1 = owned("audit", "The snapshot.")
