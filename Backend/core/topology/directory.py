"""
core/topology/directory.py
─────────────────────────────────────────────────────────────────────────────
What the topology engine reads, and what it hands over to be written, as it
asks for them (G3, then the persistence split of 2 Nov 2026;
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

The engine resolves every link endpoint against the organisation's assets,
enrols a placeholder for an LLDP or CDP neighbour the inventory lacks, fills
gaps on the assets it resolves, and, when it is handed no targets, maps the
hosts its scan named. It computes all of that on plain values and writes
nothing itself:

* **Reads** come back as :class:`AssetRecord` and :class:`StoredLink` — plain
  values, never an ORM row, so filling a gap on one is not a database write.
* **Writes** go over as one :class:`TopologyPlan` — the assets to enrol, the
  gaps filled on assets, the links to upsert — which ``record_topology``
  writes in one transaction and commits, or rolls back and raises.

The owners answer: the asset registry the asset half
(``core/topology_assets.py``), the topology store the links
(``core/topology/links.py``), and the scans capability the scan half
(``scans.reads.target_hosts``, and ``scan_by_id`` for the topology API, which
checks who may see a scan's map). Audit's composition root registers them
together (``ccure_audit/topology_directory.py``). ``db`` is whatever the
caller's directory reads and writes with; the engine only passes it along.

A process that maps topology without the registration raises
``TopologyDirectoryMissing``: the worker loads it through Celery's
``imports``, and the API through the same loader call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional, Protocol, Tuple

__all__ = [
    "AssetRecord",
    "StoredLink",
    "TopologyDirectory",
    "TopologyDirectoryMissing",
    "TopologyPlan",
    "asset_record",
    "directory",
    "register_topology_directory",
]


@dataclass(slots=True)
class AssetRecord:
    """The asset fields topology reads, as plain values. The engine fills gaps
    on it (and records each in its plan); nothing is written by doing so."""

    id: str
    ip_address: Any = None
    mac_address: Any = None
    hostname: Any = None
    device_category: Any = None
    vlan_id: Any = None
    os_name: Any = None
    vendor: Any = None
    manufacturer: Any = None


#: The fields an :class:`AssetRecord` carries, read off an asset row by name.
ASSET_RECORD_FIELDS = tuple(AssetRecord.__dataclass_fields__)


def asset_record(row: Any) -> Optional[AssetRecord]:
    """The record of an asset row, or None for no row."""
    if row is None:
        return None
    return AssetRecord(
        **{name: getattr(row, name, None) for name in ASSET_RECORD_FIELDS}
    )


@dataclass(frozen=True, slots=True)
class StoredLink:
    """A stored ``network_links`` row and its two resolved assets, as plain
    values: what the graph is drawn from."""

    id: str
    org_id: str
    scan_id: Optional[str] = None
    source_key: Optional[str] = None
    source_mac: Optional[str] = None
    source_port: Optional[str] = None
    source_ip: Optional[str] = None
    source_asset_id: Optional[str] = None
    target_key: Optional[str] = None
    target_mac: Optional[str] = None
    target_port: Optional[str] = None
    target_ip: Optional[str] = None
    target_asset_id: Optional[str] = None
    source_port_desc: Optional[str] = None
    target_port_desc: Optional[str] = None
    vlan_id: Optional[int] = None
    speed_bps: Optional[int] = None
    link_type: Optional[str] = None
    observed_types: Optional[str] = None
    first_seen_at: Any = None
    last_seen_at: Any = None
    created_at: Any = None
    source_asset: Optional[AssetRecord] = None
    target_asset: Optional[AssetRecord] = None


@dataclass(slots=True)
class TopologyPlan:
    """
    Everything one mapping run writes, in the order it was decided.

    ``enrolments`` are the fields of each asset to enrol (no timestamps: the
    writer stamps them); ``asset_changes`` the gaps filled, asset id → field →
    value, on enrolled and existing assets alike; ``links`` the values of each
    ``network_links`` row to upsert, without its timestamps.
    """

    enrolments: List[dict] = field(default_factory=list)
    asset_changes: dict = field(default_factory=dict)
    links: List[dict] = field(default_factory=list)


class TopologyDirectory(Protocol):
    def organisation_assets(self, db: Any, org_id: str) -> List[AssetRecord]:
        """Every asset of the organisation."""

    def asset(self, db: Any, asset_id: str) -> Optional[AssetRecord]:
        """The asset with this id, or None."""

    def record_topology(
        self, db: Any, *, org_id: str, scan_id: str, plan: TopologyPlan
    ) -> Tuple[int, int]:
        """Write the plan in one transaction and commit: (links created, links
        updated). On failure, roll back and raise."""

    def stored_links(
        self,
        db: Any,
        *,
        org_id: str,
        scan_id: Optional[str],
        active_within_days: Optional[int],
    ) -> List[StoredLink]:
        """The organisation's stored links — the scan's alone when one is
        named, and only those seen within the days when that is given."""

    def scan_targets(self, db: Any, scan_id: str) -> List[str]:
        """The hosts the scan was asked to cover, or none."""

    def scan(self, db: Any, scan_id: str) -> Optional[Any]:
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
            "asset registry's, the topology store's and the scans capability's: "
            "the worker and the API load it."
        )
    return _directory
