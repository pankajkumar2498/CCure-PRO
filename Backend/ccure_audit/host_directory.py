"""
The asset registry, registered as the findings side's host directory (G6, C7
of docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

The findings side scopes, labels and searches findings by their host, and
reads hosts only through its port, ``core.findings.hosts``. The asset registry
answers it (``core/asset_hosts.py``). Registered here, not by the asset
registry itself, so that what Audit plugs into what is said in its composition
root, as G4 left compliance's evidence providers.

Loaded by name in every process that reads hosts: ``core/celery_app.py`` names
it in Celery's ``imports``, which the worker loads at start-up (the
remediation section of a credentialed scan's report reads hosts) and
``main.py`` loads through the same call. A process without it raises
``HostDirectoryMissing``.
"""

from __future__ import annotations

from core import asset_hosts
from core.findings.hosts import register_host_directory

register_host_directory(asset_hosts.DIRECTORY)
