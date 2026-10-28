"""
Registered names of the scan tasks that code outside their own module dispatches.

Added in Phase 3 of the modular-platform programme. The scheduler and the
scan persistence helpers used to import ``core.tasks`` to call ``.delay()`` —
and ``core.tasks`` imports both of them, which made the three one import
cycle. They now look the task up by name (``core.celery_app.registered_task``)
and this module is the one place the names are spelled: the task modules
register under these constants, so the two sides cannot drift apart.

Since G1 (C1) the routers dispatch the same way, so no router imports a task
module: ``routers.phase_scans``, ``routers.traditional_scans``,
``routers.credentialed`` and ``routers.assets`` name the tasks they start
here.

Only tasks dispatched from outside the module defining them are listed. The
values are the names the tasks were already registered under — messages in
flight and the worker's registry are unaffected.
"""

RUN_HOST_DISCOVERY = "ccure.tasks.run_host_discovery"
RUN_ASSET_DISCOVERY = "ccure.tasks.run_asset_discovery"
RUN_VULNERABILITY_AUDIT = "ccure.tasks.run_vulnerability_audit"
RUN_TRADITIONAL_SCAN = "ccure.tasks.run_traditional_scan"
RUN_CREDENTIALED_SCAN = "ccure.tasks.run_credentialed_scan"
RECONCILE_AMT_INVENTORY = "ccure.tasks.reconcile_amt_inventory_task"
SYNC_HOST_DISCOVERY = "ccure.tasks.sync_host_discovery_task"
SYNC_ASSET_DISCOVERY = "ccure.tasks.sync_asset_discovery_task"
SYNC_VULNERABILITY_AUDIT = "ccure.tasks.sync_vulnerability_audit_task"
