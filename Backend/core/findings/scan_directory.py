"""
core/findings/scan_directory.py
─────────────────────────────────────────────────────────────────────────────
The scan records a comparison reads, as the findings capability reads them.

A comparison (``core.findings.comparison``) reads two things about scans that
are not its own: which earlier scans could be a scan's baseline, and the
assessment configuration a scan ran under. It used to read the first from the
scan model and the second from the scan-policy snapshot. But the scans
capability depends on findings — its tasks write findings and compare scans —
and scan policy reaches findings through compliance, so findings sat in a
cycle with both.

A scan's assessment scope — the record a comparison reads of what the scan
looked at — is written onto the scan record by whoever synced its findings,
the asset registry's syncer among them, which finds the record here by id.

This module is the port between them, the way ``core.findings.hosts`` is the
port to the asset registry. The comparison keeps its own judgement — which
candidate overlaps the scan's targets, whether two configurations match — and
the scans capability answers the two questions (``scans/scan_directory.py``),
registered by Audit's composition root, ``ccure_audit/scan_directory.py``.
Nothing here, and nothing that reads scans through it, imports the scan model
or the scan-policy code.

A process that compares scans without the registration raises
``ScanDirectoryMissing``: the API loads it from ``main.py`` and the worker
through Celery's ``imports`` (``core/celery_app.py``), where a credentialed
scan compares itself with its baseline.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional, Protocol

from sqlalchemy.orm import Session

__all__ = [
    "ScanDirectory",
    "ScanDirectoryMissing",
    "earlier_completed_scans",
    "policy_context",
    "register_scan_directory",
    "scan_record",
]


class ScanDirectory(Protocol):
    """What the scans capability answers for the findings side."""

    def earlier_completed_scans(
        self, db: Session, scan: Any, limit: int
    ) -> Iterable[Any]:
        """Completed scans of *scan*'s organisation and pipeline mode, created
        before it, newest first, at most *limit*."""

    def policy_context(self, scan: Any) -> Dict[str, Any]:
        """The assessment configuration *scan* ran under, for the comparison
        payload: ``{"recorded": False}`` when it recorded none."""

    def scan_record(self, db: Session, scan_id: str) -> Optional[Any]:
        """The scan record with this id, or None; its ``options`` are where
        ``record_assessment_scope`` writes."""


class ScanDirectoryMissing(RuntimeError):
    """The findings side read scans in a process that registered no directory."""


_directory: Optional[ScanDirectory] = None


def register_scan_directory(directory: ScanDirectory) -> None:
    """
    Register who answers for scans. Registering the same directory again does
    nothing; a second, different one is refused, because which of the two
    answered would then depend on import order.
    """
    global _directory
    if _directory is directory:
        return
    if _directory is not None:
        raise ValueError("a scan directory is already registered")
    _directory = directory


def _registered() -> ScanDirectory:
    if _directory is None:
        raise ScanDirectoryMissing(
            "No scan directory is registered in this process. Audit's "
            "composition root, ccure_audit/scan_directory.py, registers the "
            "scans capability's: main.py and the worker load it."
        )
    return _directory


def earlier_completed_scans(db: Session, scan: Any, limit: int) -> Iterable[Any]:
    """The candidates a comparison chooses *scan*'s baseline from."""
    return _registered().earlier_completed_scans(db, scan, limit)


def policy_context(scan: Any) -> Dict[str, Any]:
    """The assessment configuration *scan* ran under."""
    return _registered().policy_context(scan)


def scan_record(db: Session, scan_id: str) -> Optional[Any]:
    """The scan record whose assessment scope a findings sync records."""
    return _registered().scan_record(db, scan_id)
