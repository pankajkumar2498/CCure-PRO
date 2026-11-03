"""
core/asset_scans.py — the scans an asset's timeline names, as the asset
registry reads them.

An asset's change log records which scan saw each change, and the timeline
labels a group of changes with that scan's pipeline mode. The assets router
used to read the mode from the scan model itself, an upward edge from the
asset registry into the scans capability, which depends on the registry
(its tasks sync assets). The scans capability answers here instead
(``scans.reads.pipeline_modes``), registered by Audit's composition root,
``ccure_audit/scan_directory.py``, as ``core.findings.scan_directory`` is.

Nothing here imports the scan model. A process that builds a timeline
without the registration raises ``AssetScanLabelsMissing``; an unlabelled
timeline would read as one whose scans had no mode.
"""

from __future__ import annotations

from typing import Callable, Dict, Iterable, Optional

from sqlalchemy.orm import Session

#: ``pipeline_modes(db, scan_ids) -> {scan_id: pipeline_mode}``, for the scans
#: that exist among *scan_ids*; a scan recording no mode maps to None.
PipelineModes = Callable[[Session, Iterable[str]], Dict[str, Optional[str]]]


class AssetScanLabelsMissing(RuntimeError):
    """The asset timeline read scans in a process that registered no answer."""


_pipeline_modes: Optional[PipelineModes] = None


def register_pipeline_modes(answer: PipelineModes) -> None:
    """Register who answers; the same answer again is a no-op, another refused."""
    global _pipeline_modes
    if _pipeline_modes is answer:
        return
    if _pipeline_modes is not None:
        raise ValueError("an asset scan-label answer is already registered")
    _pipeline_modes = answer


def pipeline_modes(db: Session, scan_ids: Iterable[str]) -> Dict[str, Optional[str]]:
    """The pipeline mode of each scan among *scan_ids* that exists."""
    if _pipeline_modes is None:
        raise AssetScanLabelsMissing(
            "No scan-label answer is registered in this process. Audit's "
            "composition root, ccure_audit/scan_directory.py, registers the "
            "scans capability's: main.py and the worker load it."
        )
    return _pipeline_modes(db, scan_ids)
