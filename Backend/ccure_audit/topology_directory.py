"""
The topology engine's directory, registered (G3,
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

The engine reads and enrols assets, and reads its scan's targets, only through
``core.topology.directory``. The asset registry answers the assets
(``core/topology_assets.py``) and the scans capability the targets
(``scans.reads.target_hosts``). Registered here, as the host directory is, so
that what Audit plugs into what is said in its composition root.

Loaded by name in every process that maps topology: ``core/celery_app.py``
names it in Celery's ``imports``, which the worker loads at start-up, and
``main.py`` loads through the same call.
"""

from __future__ import annotations

from core import topology_assets
from core.topology.directory import register_topology_directory
from scans import reads as scan_reads


class _Directory:
    organisation_assets = staticmethod(topology_assets.organisation_assets)
    asset = staticmethod(topology_assets.asset)
    enrol = staticmethod(topology_assets.enrol)
    scan_targets = staticmethod(scan_reads.target_hosts)
    scan = staticmethod(scan_reads.scan_by_id)


DIRECTORY = _Directory()

register_topology_directory(DIRECTORY)
