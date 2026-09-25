"""
Contract 4 — Audit → IR: ``FindingEvent``.

SRS 7.6.4 ("which systems are vulnerable, which compliance controls are
failing, and where the highest-risk assets are"), 7.3.5.12. Design document §3
Interface 2.

**Events, not a list.** IR needs to know when something *changes* — a finding
appeared, came back, was verified fixed, was accepted, breached its deadline —
and a snapshot cannot say that. Each event carries the finding as it stood at
that moment, so IR never has to call back to interpret one.

``assessment.completed`` is the audit-data event: per asset, whether it was
assessed, whether authentication succeeded, and which controls failed. IR uses
it to tell "this host has no known weaknesses" from "nobody looked at this host".

Delivery is at least once. ``message_id`` is the deduplication key and
``sequence`` orders events per tenant.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Literal, Optional

from pydantic import AwareDatetime, model_validator

from ccure_contracts.common.v1.assessment import CcureAssetAssessmentV1, CcureFindingV1
from ccure_contracts.common.v1.envelope import (
    CcureAssessmentRefV1,
    CcureControlRefV1,
    CcureEnvelopeV1,
    ContractModel,
    ShortText,
)
from ccure_contracts.common.v1.feeds import CcureFeedPositionV1
from ccure_contracts.common.v1.fields import owned
from ccure_contracts.common.v1.vocabulary import AssessmentStatus

FINDING_EVENT_CONTRACT = "ccure.audit.finding_event"


class FindingEventType(str, Enum):
    ASSESSMENT_COMPLETED = "assessment.completed"
    FINDING_DETECTED = "finding.detected"
    FINDING_REAPPEARED = "finding.reappeared"
    FINDING_VERIFIED_FIXED = "finding.verified_fixed"
    FINDING_RISK_ACCEPTED = "finding.risk_accepted"
    FINDING_RISK_ACCEPTANCE_WITHDRAWN = "finding.risk_acceptance_withdrawn"
    FINDING_RISK_ACCEPTANCE_EXPIRED = "finding.risk_acceptance_expired"
    FINDING_SLA_BREACHED = "finding.sla_breached"


_FINDING_EVENTS = {t for t in FindingEventType if t.value.startswith("finding.")}


class CcureFailedControlV1(ContractModel):
    control: CcureControlRefV1 = owned(
        "platform", "A control that failed on the asset."
    )
    rule_ids: List[ShortText] = owned(
        "audit", "The Audit rules that failed.", default_factory=list
    )


class CcureAssetContextV1(ContractModel):
    assessment: CcureAssetAssessmentV1 = owned(
        "audit", "Coverage, access, counts, risk."
    )
    failed_controls: List[CcureFailedControlV1] = owned(
        "audit", "Controls failing on this asset.", default_factory=list
    )


class CcureAssessmentCompletedV1(ContractModel):
    assessment: CcureAssessmentRefV1 = owned("audit", "The assessment.")
    status: AssessmentStatus = owned("audit", "How it ended.")
    assets: List[CcureAssetContextV1] = owned("audit", "Every discovered asset.")
    result_id: Optional[ShortText] = owned(
        "audit", "The AssessmentResult (contract 3) with the full detail.", default=None
    )


class CcureFindingEventDataV1(ContractModel):
    event_type: FindingEventType = owned("audit", "What happened.")
    occurred_at: AwareDatetime = owned(
        "audit", "When it happened in Audit (not when it was delivered)."
    )
    sequence: int = owned(
        "audit",
        "Per-tenant monotonic sequence. Gaps are allowed (events filtered out by "
        "subscription); a lower number never follows a higher one.",
        ge=1,
    )
    finding: Optional[CcureFindingV1] = owned(
        "audit",
        "The finding as it stood at occurred_at. Present for finding.* events.",
        default=None,
    )
    previous_state: Optional[ShortText] = owned(
        "audit",
        "The remediation state before the change, where one changed.",
        default=None,
    )
    assessment_completed: Optional[CcureAssessmentCompletedV1] = owned(
        "audit", "Present for assessment.completed.", default=None
    )

    @model_validator(mode="after")
    def _payload_matches_type(self) -> "CcureFindingEventDataV1":
        if self.event_type in _FINDING_EVENTS:
            if self.finding is None or self.assessment_completed is not None:
                raise ValueError(
                    f"{self.event_type.value} carries a finding and nothing else"
                )
        else:
            if self.assessment_completed is None or self.finding is not None:
                raise ValueError(
                    "assessment.completed carries assessment_completed only"
                )
        return self


class CcureFindingEventV1(CcureEnvelopeV1):
    """Pushed to IR; also served by the finding-event feed."""

    contract: Literal["ccure.audit.finding_event"] = owned("producer", "Contract name.")
    data: CcureFindingEventDataV1 = owned("audit", "The event.")


class CcureFindingEventPageV1(ContractModel):
    """``GET /api/v1/integrations/finding-events?cursor=&min_severity=``"""

    items: List[CcureFindingEventV1] = owned("audit", "Events in sequence order.")
    position: CcureFeedPositionV1 = owned("audit", "Paging.")
