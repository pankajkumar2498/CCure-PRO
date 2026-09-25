"""
Contract 2 — Audit → Policy Pro: ``ComplianceGapReport``.

SRS 7.6.2 ("which policy controls failed during the audit"), 7.2.2.4, 7.2.3.2,
7.3.8.6.

Produced when an assessment completes **against a received policy baseline**.
Audit's own framework catalogues keep working without Policy Pro and are
reported to Rank (contract 3), not here: a gap report is about Policy Pro's
controls.

Every baseline control appears exactly once, including the ones Audit could not
assess — a report listing only failures would read as "everything else
passed". A control whose checks could not run is ``ERROR`` or
``NOT_ASSESSED``, never ``FAIL`` and never ``PASS``.

Immutable: one report per (assessment, baseline version). A later assessment
produces a new report.
"""

from __future__ import annotations

from typing import List, Literal

from pydantic import AwareDatetime, model_validator

from ccure_contracts.common.v1.assessment import (
    CcureControlResultV1,
    CcureStateCountsV1,
)
from ccure_contracts.common.v1.envelope import (
    CcureAssessmentRefV1,
    CcureBaselineRefV1,
    CcureEnvelopeV1,
    CcureMeasuredValueV1,
    ContractModel,
    OpaqueId,
    Sha256,
)
from ccure_contracts.common.v1.feeds import CcureFeedPositionV1
from ccure_contracts.common.v1.fields import owned
from ccure_contracts.common.v1.vocabulary import AssessmentState

COMPLIANCE_GAP_REPORT_CONTRACT = "ccure.audit.compliance_gap_report"


class CcureGapScopeV1(ContractModel):
    assets_in_scope: int = owned("audit", "Assets the baseline scope selected.", ge=0)
    assets_assessed: int = owned("audit", "Of those, fully assessed.", ge=0)
    assets_partially_assessed: int = owned("audit", "Partially assessed.", ge=0)
    assets_not_assessed: int = owned("audit", "Not assessed at all.", ge=0)
    assets_error: int = owned("audit", "Assessment failed.", ge=0)

    @model_validator(mode="after")
    def _adds_up(self) -> "CcureGapScopeV1":
        parts = (
            self.assets_assessed
            + self.assets_partially_assessed
            + self.assets_not_assessed
            + self.assets_error
        )
        if parts != self.assets_in_scope:
            raise ValueError("asset coverage counts do not add up to assets_in_scope")
        return self


class CcureComplianceGapReportDataV1(ContractModel):
    report_id: OpaqueId = owned("audit", "Audit's report identifier. Immutable.")
    content_sha256: Sha256 = owned(
        "audit", "Digest of the canonical JSON of this data object without this field."
    )
    generated_at: AwareDatetime = owned("audit", "When the report was produced.")
    assessment: CcureAssessmentRefV1 = owned("audit", "The assessment reported on.")
    baseline: CcureBaselineRefV1 = owned(
        "audit", "The exact baseline version and content assessed against."
    )
    mapping_revision: int = owned(
        "audit", "The BaselineCoverage mapping revision used.", ge=1
    )
    scope: CcureGapScopeV1 = owned("audit", "Asset coverage.")
    summary: CcureStateCountsV1 = owned("audit", "Controls per state.")
    compliance_score: CcureMeasuredValueV1 = owned(
        "audit",
        "Percentage of assessed, applicable controls that passed. Audit scores "
        "per framework today, not per received baseline: not_implemented.",
        srs=("7.2.3.2",),
        availability="not_implemented",
    )
    controls: List[CcureControlResultV1] = owned(
        "audit",
        "Every baseline control, exactly once, in baseline order.",
        min_length=1,
    )

    @model_validator(mode="after")
    def _every_control_once(self) -> "CcureComplianceGapReportDataV1":
        seen: set[str] = set()
        for result in self.controls:
            if result.requirement_id is None:
                raise ValueError("a gap report control must echo its requirement_id")
            if result.requirement_id in seen:
                raise ValueError(f"requirement {result.requirement_id} reported twice")
            seen.add(result.requirement_id)
        tally = {state: 0 for state in AssessmentState}
        for result in self.controls:
            tally[result.state] += 1
        s = self.summary
        expected = {
            AssessmentState.PASS: s.pass_,
            AssessmentState.FAIL: s.fail,
            AssessmentState.NOT_ASSESSED: s.not_assessed,
            AssessmentState.NOT_APPLICABLE: s.not_applicable,
            AssessmentState.MANUAL_REVIEW: s.manual_review,
            AssessmentState.ERROR: s.error,
        }
        if tally != expected:
            raise ValueError("summary does not match the per-control states")
        return self


class CcureComplianceGapReportV1(CcureEnvelopeV1):
    """Pushed to Policy Pro; also served by the gap-report feed."""

    contract: Literal["ccure.audit.compliance_gap_report"] = owned(
        "producer", "Contract name."
    )
    data: CcureComplianceGapReportDataV1 = owned("audit", "The report.")


class CcureComplianceGapReportPageV1(ContractModel):
    """``GET /api/v1/integrations/compliance-gap-reports?cursor=``"""

    items: List[CcureComplianceGapReportV1] = owned("audit", "Reports, oldest first.")
    position: CcureFeedPositionV1 = owned("audit", "Paging.")
