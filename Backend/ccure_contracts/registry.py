"""
Every published contract message, its schema file and its examples.

``scripts/contracts/generate_schemas.py`` writes one JSON Schema per entry and
``tests/repo/test_integration_contracts.py`` checks the committed schemas and
examples against these models. Adding a message type means adding it here.

``status`` is ``draft`` for the whole of v1 until the Phase 4 review signs the
contracts off. While a contract is a draft its schema may change without a
version bump; once ``published``, the schema digest is pinned in
``schema_lock.json`` and any change needs a new ``schema_version``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Type

from pydantic import BaseModel

from ccure_contracts.assessment_result.v1.models import (
    CcureAssessmentControlsPageV1,
    CcureAssessmentFindingsPageV1,
    CcureAssessmentResultPageV1,
    CcureAssessmentResultV1,
    CcurePostureSnapshotV1,
)
from ccure_contracts.capabilities.v1.models import CcureCapabilitiesV1
from ccure_contracts.common.v1.errors import CcureProblemV1
from ccure_contracts.evidence.v1.models import CcureEvidenceRecordV1
from ccure_contracts.compliance_gap.v1.models import (
    CcureComplianceGapReportPageV1,
    CcureComplianceGapReportV1,
)
from ccure_contracts.finding_events.v1.models import (
    CcureFindingEventPageV1,
    CcureFindingEventV1,
)
from ccure_contracts.incident_evidence.v1.models import (
    CcureIncidentEvidenceReceiptV1,
    CcureIncidentEvidenceV1,
)
from ccure_contracts.policy_baseline.v1.models import (
    CcureBaselineCoverageV1,
    CcurePolicyBaselineV1,
)

PACKAGE_ROOT = Path(__file__).resolve().parent

#: The schema version every v1 message carries today.
SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class ContractSpec:
    area: str  # package directory, e.g. "policy_baseline"
    name: str  # schema file stem
    model: Type[BaseModel]
    examples: tuple[str, ...]  # file names under <area>/v1/examples/
    status: Literal["draft", "published"] = "draft"

    @property
    def schema_path(self) -> Path:
        return PACKAGE_ROOT / self.area / "v1" / "schemas" / f"{self.name}.schema.json"

    def example_paths(self) -> list[Path]:
        return [PACKAGE_ROOT / self.area / "v1" / "examples" / e for e in self.examples]


CONTRACTS: tuple[ContractSpec, ...] = (
    # Contract 1 — Policy Pro → Audit
    ContractSpec(
        "policy_baseline",
        "PolicyBaseline",
        CcurePolicyBaselineV1,
        ("policy_baseline.request.json",),
    ),
    ContractSpec(
        "policy_baseline",
        "BaselineCoverage",
        CcureBaselineCoverageV1,
        ("baseline_coverage.response.json",),
    ),
    # Contract 2 — Audit → Policy Pro
    ContractSpec(
        "compliance_gap",
        "ComplianceGapReport",
        CcureComplianceGapReportV1,
        ("compliance_gap_report.json",),
    ),
    ContractSpec(
        "compliance_gap", "ComplianceGapReportPage", CcureComplianceGapReportPageV1, ()
    ),
    # Contract 3 — Audit → Rank
    ContractSpec(
        "assessment_result",
        "AssessmentResult",
        CcureAssessmentResultV1,
        ("assessment_result.json",),
    ),
    ContractSpec(
        "assessment_result",
        "AssessmentFindingsPage",
        CcureAssessmentFindingsPageV1,
        ("assessment_findings_page.json",),
    ),
    ContractSpec(
        "assessment_result", "AssessmentControlsPage", CcureAssessmentControlsPageV1, ()
    ),
    ContractSpec(
        "assessment_result", "AssessmentResultPage", CcureAssessmentResultPageV1, ()
    ),
    ContractSpec(
        "assessment_result",
        "PostureSnapshot",
        CcurePostureSnapshotV1,
        ("posture_snapshot.json",),
    ),
    # Contract 4 — Audit → IR
    ContractSpec(
        "finding_events",
        "FindingEvent",
        CcureFindingEventV1,
        ("finding_detected.json", "assessment_completed.json"),
    ),
    ContractSpec("finding_events", "FindingEventPage", CcureFindingEventPageV1, ()),
    # Contract 5 — IR → Audit
    ContractSpec(
        "incident_evidence",
        "IncidentEvidence",
        CcureIncidentEvidenceV1,
        ("incident_evidence.request.json",),
    ),
    ContractSpec(
        "incident_evidence",
        "IncidentEvidenceReceipt",
        CcureIncidentEvidenceReceiptV1,
        ("incident_evidence_receipt.response.json",),
    ),
    # Evidence referenced by contracts 2, 3 and 4
    ContractSpec(
        "evidence", "EvidenceRecord", CcureEvidenceRecordV1, ("evidence_record.json",)
    ),
    # Shared
    ContractSpec(
        "capabilities", "Capabilities", CcureCapabilitiesV1, ("capabilities.json",)
    ),
    ContractSpec(
        "common", "Problem", CcureProblemV1, ("problem.version_conflict.json",)
    ),
)

SCHEMA_LOCK = PACKAGE_ROOT / "schema_lock.json"
