"""
core/scheduling/scan_records.py — the scan record a scheduled run creates,
as the scans capability creates it.

A scheduled run is an ordinary scan: the dispatcher creates the scan row and
dispatches the same tasks the manual routes do. It used to import
``scans.db_helpers.create_scan`` for the row, an upward edge from scheduling
into the scans capability, which depends on scheduling (its beat task runs the
dispatcher). The scans capability answers here instead, with the same
function, registered by Audit's composition root,
``ccure_audit/scan_directory.py``.

The command is unchanged: ``create_scan`` builds a running scan, numbers it
and commits, on the dispatcher's own session. Nothing here imports the scan
model. A process that dispatches a schedule without the registration raises
``ScanCreatorMissing`` before any row is written; the dispatcher records it as
a failed run, as it records any other refusal.
"""

from __future__ import annotations

from typing import Any, Callable, List, Optional

from sqlalchemy.orm import Session

#: ``create(db=, user_id=, target=, targets=, scan_type=, pipeline_mode=,
#: org_id=) -> scan``: a committed running scan row, the one the scan
#: tasks then update.
ScanCreator = Callable[..., Any]


class ScanCreatorMissing(RuntimeError):
    """A schedule was dispatched in a process that registered no scan creator."""


_creator: Optional[ScanCreator] = None


def register_scan_creator(creator: ScanCreator) -> None:
    """Register who creates scans; the same one again is a no-op, another refused."""
    global _creator
    if _creator is creator:
        return
    if _creator is not None:
        raise ValueError("a scan creator is already registered")
    _creator = creator


def create_scan(
    db: Session,
    *,
    user_id: str,
    target: str,
    targets: List[str],
    scan_type: str,
    pipeline_mode: str,
    org_id: str,
) -> Any:
    """Create the running scan row a scheduled run dispatches."""
    if _creator is None:
        raise ScanCreatorMissing(
            "No scan creator is registered in this process. Audit's "
            "composition root, ccure_audit/scan_directory.py, registers the "
            "scans capability's: main.py and the worker load it."
        )
    return _creator(
        db=db,
        user_id=user_id,
        target=target,
        targets=targets,
        scan_type=scan_type,
        pipeline_mode=pipeline_mode,
        org_id=org_id,
    )
