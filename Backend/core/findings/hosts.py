"""
core/findings/hosts.py
─────────────────────────────────────────────────────────────────────────────
The hosts findings are on, as the findings capability reads them (G6, C7 of
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

A finding belongs to an asset, and the findings side scopes, labels and
searches findings by their host: a finding is in the organisation its asset is
in, and the findings list shows each one's address and name. It used to read
those from the asset model. But the asset registry depends on findings — its
syncer hands a scan's findings to the findings writer (G3) — so the two
capabilities sat in each other's cycle.

This module is the port between them. The findings side names the host columns
it reads (``HOST_COLUMNS``) and the asset registry supplies them: Audit's
composition root, ``ccure_audit/host_directory.py``, registers the asset
registry's answer here, the way compliance's evidence providers are registered
(G4). Nothing here, and nothing that reads hosts through it, imports the asset
model or names its table.

What crosses is a projection — a subquery whose columns are exactly
``HOST_COLUMNS`` — so a findings query still joins its hosts in one statement.
PostgreSQL pulls a plain subquery up into the join, so the plan, and with it
the order of rows that tie under a sort, is the one a direct join to the table
gets.

The one write the findings side asks of the asset registry is
:func:`record_open_findings`: after a person changes a finding's status, the
asset's open-finding counts and the risk derived from them are recomputed. The
counts are the findings side's own query; the asset's columns are the asset
registry's to write.

A process that reads hosts without the registration raises
``HostDirectoryMissing``: the API loads it from ``main.py`` and the worker
through Celery's ``imports`` (``core/celery_app.py``), where the remediation
section of a credentialed scan's report reads hosts.
"""

from __future__ import annotations

from typing import Mapping, Optional, Protocol

from sqlalchemy.orm import Session
from sqlalchemy.sql.selectable import Subquery

__all__ = [
    "HOST_COLUMNS",
    "HostDirectory",
    "HostDirectoryMissing",
    "hosts",
    "record_open_findings",
    "register_host_directory",
]

#: The host columns the findings side reads, and nothing else.
HOST_COLUMNS = (
    "id",
    "org_id",
    "ip_address",
    "hostname",
    "os_name",
    "risk_score",
    "risk_level",
    "device_category",
    "subnet",
)


class HostDirectory(Protocol):
    """What the asset registry answers for the findings side."""

    def projection(self) -> Subquery:
        """A subquery of every host, with exactly ``HOST_COLUMNS``."""

    def record_open_findings(
        self, db: Session, asset_id: str, severity_counts: Mapping[str, int]
    ) -> bool:
        """Record an asset's open findings by severity, and the risk they give
        it. False when there is no such asset; the caller commits."""


class HostDirectoryMissing(RuntimeError):
    """The findings side read hosts in a process that registered no directory."""


_directory: Optional[HostDirectory] = None


def register_host_directory(directory: HostDirectory) -> None:
    """
    Register who answers for hosts. Registering the same directory again does
    nothing; a second, different one is refused, because which of the two
    answered would then depend on import order. A projection whose columns are
    not ``HOST_COLUMNS`` is refused too.
    """
    global _directory
    if _directory is directory:
        return
    if _directory is not None:
        raise ValueError("a host directory is already registered")
    columns = tuple(directory.projection().c.keys())
    if columns != HOST_COLUMNS:
        raise ValueError(
            f"a host projection has the columns {', '.join(HOST_COLUMNS)}, "
            f"not {', '.join(columns)}"
        )
    _directory = directory


def _registered() -> HostDirectory:
    if _directory is None:
        raise HostDirectoryMissing(
            "No host directory is registered in this process. Audit's "
            "composition root, ccure_audit/host_directory.py, registers the "
            "asset registry's: main.py and the worker load it."
        )
    return _directory


def hosts() -> Subquery:
    """Every host, as a subquery of ``HOST_COLUMNS`` to join findings to."""
    return _registered().projection()


def record_open_findings(
    db: Session, asset_id: str, severity_counts: Mapping[str, int]
) -> bool:
    """Hand the asset registry an asset's open findings by severity."""
    return _registered().record_open_findings(db, asset_id, severity_counts)
