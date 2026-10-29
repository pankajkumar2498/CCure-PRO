"""
core/topology/directory.py
─────────────────────────────────────────────────────────────────────────────
The assets and scans the topology engine reads and enrols, as it asks for them
(G3, docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

The engine resolves every link endpoint against the organisation's assets,
enrols a placeholder for an LLDP or CDP neighbour the inventory lacks, and,
when it is handed no targets, maps the hosts its scan named. It used to import
the asset and scan models for that — which loaded the whole model registry —
and query them itself. It asks here now. The asset registry answers the asset
half (``core/topology_assets.py``) and the scans capability the scan half
(``scans.reads.target_hosts``, and ``scan_by_id`` for the topology API, which
checks who may see a scan's map); Audit's composition root registers them
together (``ccure_audit/topology_directory.py``). What crosses is the asset
registry's own row, which the engine fills gaps on in place, as before.

A process that maps topology without the registration raises
``TopologyDirectoryMissing``: the worker loads it through Celery's
``imports``, and the API through the same loader call.
"""

from __future__ import annotations

from typing import Any, List, Optional, Protocol

from sqlalchemy.orm import Session

__all__ = [
    "TopologyDirectory",
    "TopologyDirectoryMissing",
    "directory",
    "register_topology_directory",
]


class TopologyDirectory(Protocol):
    def organisation_assets(self, db: Session, org_id: str) -> List[Any]:
        """Every asset of the organisation."""

    def asset(self, db: Session, asset_id: str) -> Optional[Any]:
        """The asset with this id, or None."""

    def enrol(self, db: Session, **fields: Any) -> Any:
        """A new asset with *fields*, added and flushed, so its key exists."""

    def scan_targets(self, db: Session, scan_id: str) -> List[str]:
        """The hosts the scan was asked to cover, or none."""

    def scan(self, db: Session, scan_id: str) -> Optional[Any]:
        """The scan record, or None: the topology API checks who may see it."""


class TopologyDirectoryMissing(RuntimeError):
    """The topology engine ran in a process that registered no directory."""


_directory: Optional[TopologyDirectory] = None


def register_topology_directory(directory: TopologyDirectory) -> None:
    """Register who answers. The same directory again does nothing; a second,
    different one is refused, because which answered would depend on import
    order."""
    global _directory
    if _directory is directory:
        return
    if _directory is not None:
        raise ValueError("a topology directory is already registered")
    _directory = directory


def directory() -> TopologyDirectory:
    if _directory is None:
        raise TopologyDirectoryMissing(
            "No topology directory is registered in this process. Audit's "
            "composition root, ccure_audit/topology_directory.py, registers the "
            "asset registry's and the scans capability's: the worker and the API "
            "load it."
        )
    return _directory
