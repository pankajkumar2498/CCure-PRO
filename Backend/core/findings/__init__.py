"""
core.findings
─────────────────────────────────────────────────────────────────────────────
Reading the finding record over time.

Nothing here collects, evaluates or stores a finding — ``asset_vulnerabilities``
and the paths that write it are unchanged. This package answers a question that
model already contains the data for and never exposed: *what changed between
two scans*.
"""

from core.findings.comparison import (
    CLASS_FIXED,
    CLASS_NEW,
    CLASS_NOT_ASSESSED,
    CLASS_REAPPEARED,
    CLASS_STILL_OPEN,
    CLASSIFICATIONS,
    AssessmentScope,
    FindingDelta,
    ScanComparison,
    compare_scans,
    read_assessment_scope,
    record_assessment_scope,
)

__all__ = [
    "CLASS_FIXED",
    "CLASS_NEW",
    "CLASS_NOT_ASSESSED",
    "CLASS_REAPPEARED",
    "CLASS_STILL_OPEN",
    "CLASSIFICATIONS",
    "AssessmentScope",
    "FindingDelta",
    "ScanComparison",
    "compare_scans",
    "read_assessment_scope",
    "record_assessment_scope",
]
