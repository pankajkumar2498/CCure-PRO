"""
The topology engine's directory, registered (G3,
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

The engine reads assets and its scan's targets, and hands over what a run
writes, only through ``core.topology.directory``. The asset registry answers
the assets (``core/topology_assets.py``), the topology store the links
(``core/topology/links.py``) and the scans capability the targets
(``scans.reads.target_hosts``). Registered here, as the host directory is, so
that what Audit plugs into what is said in its composition root — including
that a run's asset writes and link writes are one transaction, the store's.

Loaded by name in every process that maps topology: ``core/celery_app.py``
names it in Celery's ``imports``, which the worker loads at start-up, and
``main.py`` loads through the same call.
"""

from __future__ import annotations

from core import topology_assets
from core.topology import links as topology_links
from core.topology.directory import register_topology_directory
from scans import reads as scan_reads


def _record_topology(db, *, org_id, scan_id, plan):
    return topology_links.record_links(
        db,
        org_id=org_id,
        scan_id=scan_id,
        links=plan.links,
        write_assets=lambda now: topology_assets.write_topology_assets(
            db, plan.enrolments, plan.asset_changes, now=now
        ),
    )


class _Directory:
    organisation_assets = staticmethod(topology_assets.organisation_assets)
    asset = staticmethod(topology_assets.asset)
    record_topology = staticmethod(_record_topology)
    stored_links = staticmethod(topology_links.stored_links)
    scan_targets = staticmethod(scan_reads.target_hosts)
    scan = staticmethod(scan_reads.scan_by_id)


DIRECTORY = _Directory()

register_topology_directory(DIRECTORY)
