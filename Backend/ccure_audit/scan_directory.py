"""
The scans capability, registered as the answer to the ports of the
capabilities below it.

Four capabilities beneath scans read or create scan records, each only
through a port of its own, which the scans capability answers:

* the findings side's scan directory, ``core.findings.scan_directory``: which
  earlier scans could be a scan's baseline, and the configuration a scan ran
  under (``scans/scan_directory.py``);
* the asset timeline's scan labels, ``core.asset_scans``
  (``scans.reads.pipeline_modes``);
* a scan policy's scan usage, ``core.scan_policy.scan_usage``
  (``scans.reads.scans_recorded_under``);
* the scan row a scheduled run creates, ``core.scheduling.scan_records``
  (``scans.db_helpers.create_scan``).

Registered here, not by the scans capability itself, so that what Audit plugs
into what is said in its composition root, as ``ccure_audit/host_directory.py``
registers the asset registry's hosts.

Loaded by name in every process that reads scans through them:
``core/celery_app.py`` names it in Celery's ``imports``, which the worker loads
at start-up (a credentialed scan compares itself with its baseline, and beat's
schedule task dispatches) and ``main.py`` loads through the same call. A
process without it raises the port's ``...Missing`` error.
"""

from __future__ import annotations

from core.asset_scans import register_pipeline_modes
from core.findings.scan_directory import register_scan_directory
from core.scan_policy.scan_usage import register_scan_usage
from core.scheduling.scan_records import register_scan_creator
from scans import db_helpers, reads, scan_directory


def _create_scan(**kwargs):
    # Looked up at call time, so a patch of scans.db_helpers.create_scan still
    # reaches the dispatcher, as it did through the dispatcher's own import.
    return db_helpers.create_scan(**kwargs)


register_scan_directory(scan_directory.DIRECTORY)
register_pipeline_modes(reads.pipeline_modes)
register_scan_usage(reads.scans_recorded_under)
register_scan_creator(_create_scan)
