"""
core/phase_handoff.py
─────────────────────────────────────────────────────────────────────────────
What one network-scan phase hands the next (C6 of
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

    host discovery ──HostRecord──▶ asset discovery ──ServiceInventory──▶ vulnerability audit

Until C6 each phase task handed the next a list of dicts, picked the active
ones with ``h.get("is_active")``, and the vulnerability audit restored the
hosts' identity with a merge written inside its task. Nothing said what
crossed the boundary. This module does, and ``scans/pipeline.py`` is the one
place that hands it over.

The wire form is unchanged, deliberately
────────────────────────────────────────
Celery carries JSON, the phase tasks' signatures are pinned
(``scripts/architecture/task_registry.json``), the browser continues an
interactive scan by posting back the records it was shown, and a message
queued before a deploy is read after it. So a record crosses as the dict it
always was, with every key its producer wrote, in the producer's order.

``HostRecord.wire()`` returns **that dict, not a copy**. The phase that
receives a record hands it to its engines, which add to it and edit its port
records in place, and the vulnerability audit reads those edits back when it
restores identity. A copy would lose them. The typed fields are what the
pipeline decides on, read when the record is handed over.

A record that is not a mapping is refused with ``HandoffError``. Before C6 it
reached the receiving phase's engines and failed there; either way the phase
fails and the scan is settled as failed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

__all__ = [
    "HOST_IDENTITY_FIELDS",
    "HandoffError",
    "HostRecord",
    "ServiceInventory",
    "ServiceRecord",
    "active",
    "host_records",
    "merge_host_identity",
]


class HandoffError(ValueError):
    """A phase was handed something that is not a list of host records."""


def _text(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _port(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


@dataclass(frozen=True)
class ServiceRecord:
    """One service asset discovery found on a host: an entry of ``open_ports``."""

    port: Optional[int]
    protocol: Optional[str]
    state: Optional[str]
    service: Optional[str]
    product: Optional[str]
    version: Optional[str]

    @classmethod
    def from_wire(cls, entry: Mapping[str, Any]) -> "ServiceRecord":
        return cls(
            port=_port(entry.get("port")),
            protocol=_text(entry.get("protocol")),
            state=_text(entry.get("state")),
            service=_text(entry.get("service")),
            product=_text(entry.get("product")),
            version=_text(entry.get("version")),
        )


@dataclass(frozen=True, eq=False)
class HostRecord:
    """
    One host, as a phase hands it to the next.

    ``ip_address`` is the record's ``ip_address``, or ``ip`` where only that
    is written (the browser's continuation can send either). ``is_active`` is
    the record's own flag read for truth, as the pipeline always read it.
    ``services`` is empty until asset discovery has run.
    """

    ip_address: Optional[str]
    is_active: bool
    services: Tuple[ServiceRecord, ...]
    record: Dict[str, Any] = field(repr=False)

    @classmethod
    def from_wire(cls, record: Any) -> "HostRecord":
        if not isinstance(record, Mapping):
            raise HandoffError(
                f"a host record must be a mapping, not {type(record).__name__}"
            )
        ports = record.get("open_ports")
        services = tuple(
            ServiceRecord.from_wire(entry)
            for entry in (ports if isinstance(ports, list) else ())
            if isinstance(entry, Mapping)
        )
        return cls(
            ip_address=_text(record.get("ip_address") or record.get("ip")),
            is_active=bool(record.get("is_active")),
            services=services,
            record=record,
        )

    def wire(self) -> Dict[str, Any]:
        """The record as it crosses: the producer's own dict, not a copy."""
        return self.record


def host_records(records: Any) -> Tuple[HostRecord, ...]:
    """Every record of a hand-off, in its order."""
    if not isinstance(records, (list, tuple)):
        raise HandoffError(
            f"a hand-off is a list of host records, not {type(records).__name__}"
        )
    return tuple(HostRecord.from_wire(record) for record in records)


def active(records: Iterable[HostRecord]) -> Tuple[HostRecord, ...]:
    """The records whose host answered, in their order: what the next phase scans."""
    return tuple(record for record in records if record.is_active)


#: What host discovery establishes about a host and every later phase keeps:
#: the vulnerability audit returns partial records, and these are restored
#: from the inventory it was handed wherever its own record left them empty.
HOST_IDENTITY_FIELDS: Tuple[str, ...] = (
    "ip",
    "ip_address",
    "hostname",
    "mac",
    "mac_address",
    "vendor",
    "is_active",
    "status",
    "open_ports",
    "os_guess",
    "os_confidence",
    "device_category",
    "snmp_device_type",
    "mdns_name",
    "netbios_names",
    "os_fingerprint_full",
    "tcp_fingerprint",
    "port_states",
)


def merge_host_identity(
    enriched_hosts: list[dict], source_hosts: list[dict]
) -> list[dict]:
    """
    Preserve identity/context fields from the previous phase when the next phase
    returns only partial host records.
    """
    by_ip: dict[str, dict] = {}
    for host in source_hosts or []:
        ip = host.get("ip_address") or host.get("ip")
        if ip:
            by_ip[ip] = host

    merged: list[dict] = []
    for idx, host in enumerate(enriched_hosts or []):
        base = {}
        ip = host.get("ip_address") or host.get("ip")
        if ip and ip in by_ip:
            base = dict(by_ip[ip])
        elif idx < len(source_hosts or []):
            base = dict(source_hosts[idx])

        combined = dict(base)
        combined.update(host or {})

        # Restore important phase-1/2 identity if phase-3 output omitted it.
        for key in HOST_IDENTITY_FIELDS:
            if combined.get(key) in (None, "", [], {}):
                if key in base:
                    combined[key] = base.get(key)

        merged.append(combined)
    return merged


@dataclass(frozen=True, eq=False)
class ServiceInventory:
    """
    What asset discovery hands the vulnerability audit: the hosts it scanned,
    each with the services found on it, in the order it scanned them.
    """

    hosts: Tuple[HostRecord, ...]

    @classmethod
    def from_wire(cls, records: Any) -> "ServiceInventory":
        return cls(hosts=host_records(records))

    def wire(self) -> List[Dict[str, Any]]:
        """The records as they cross, each the producer's own dict."""
        return [host.wire() for host in self.hosts]

    def active(self) -> "ServiceInventory":
        return ServiceInventory(hosts=active(self.hosts))

    @property
    def service_count(self) -> int:
        return sum(len(host.services) for host in self.hosts)

    def restore_identity(self, enriched_hosts: list[dict]) -> list[dict]:
        """The audit's host records, with the identity this inventory carried."""
        return merge_host_identity(enriched_hosts, self.wire())
