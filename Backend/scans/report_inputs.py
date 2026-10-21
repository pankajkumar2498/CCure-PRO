"""
scans/report_inputs.py
─────────────────────────────────────────────────────────────────────────────
What the scan-report renderer needs from the engines, attached to its payload.

``reporting/pdf_generator.py`` is a renderer: a payload in, a document out. It
used to import two things from the engines to write its methodology appendix:
the credentialed audit's coverage rows (``engines.credentialed.coverage``) and
the sentence describing a truncated candidate search
(``core.candidate_enumeration``, which loads the vulnerability-intelligence
database layer). B7 moved both here, into the payload, so the renderer imports
no engine (docs/architecture/MODULAR_REFACTORING_LOG.md §6).

Every caller of ``ScanReportGenerator`` wraps its payload with
:func:`with_report_inputs`. The renderer refuses a payload without them rather
than leaving their rows out: a report that silently drops its coverage or
truncation rows reads as a more complete assessment than the scan made.

The inputs are built when the report is rendered, never stored with the scan:
a report regenerated for an old scan gets them exactly as a new one does.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from core.candidate_enumeration import describe as describe_truncated_search
from engines.credentialed.coverage import COVERAGE_ROWS

__all__ = ["REPORT_INPUTS_KEY", "report_inputs", "with_report_inputs"]

#: The payload key the renderer reads.
REPORT_INPUTS_KEY = "report_inputs"

_TRUNCATED = "candidate_searches_truncated"


def report_inputs(metadata: Any, summary: Any) -> Dict[str, Any]:
    """
    The renderer's inputs for one scan's metadata and summary.

    ``coverage_rows`` are the ordered ``(metadata key, label)`` pairs of the
    credentialed coverage claims. ``truncated_search_notes`` describe each
    truncated candidate search, for the summary's list and the metadata's
    separately, because the renderer chooses between them.
    """
    notes: Dict[str, List[str]] = {}
    for name, source in (("summary", summary), ("metadata", metadata)):
        if isinstance(source, Mapping) and _TRUNCATED in source:
            notes[name] = [
                describe_truncated_search(entry)
                for entry in (source.get(_TRUNCATED) or [])
            ]
    return {
        "coverage_rows": [[key, label] for key, label in COVERAGE_ROWS],
        "truncated_search_notes": notes,
    }


def with_report_inputs(result: Mapping[str, Any]) -> Dict[str, Any]:
    """A shallow copy of a report payload, carrying its renderer inputs."""
    payload = dict(result)
    payload[REPORT_INPUTS_KEY] = report_inputs(
        result.get("metadata") or {}, result.get("summary") or {}
    )
    return payload
