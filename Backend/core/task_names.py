"""
Registered names of the task-hub tasks that code *below* the hub dispatches.

Added in Phase 3 of the modular-platform programme. The scheduler and the
scan persistence helpers used to import ``core.tasks`` to call ``.delay()`` —
and ``core.tasks`` imports both of them, which made the three one import
cycle. They now look the task up by name (``core.celery_app.registered_task``)
and this module is the one place the names are spelled: ``core.tasks``
registers under these constants, so the two sides cannot drift apart.

Only the tasks something below the hub dispatches are listed. The values are
the names the tasks were already registered under — messages in flight and
the worker's registry are unaffected.
"""

RUN_HOST_DISCOVERY = "ccure.tasks.run_host_discovery"
RUN_CREDENTIALED_SCAN = "ccure.tasks.run_credentialed_scan"
SYNC_HOST_DISCOVERY = "ccure.tasks.sync_host_discovery_task"
SYNC_ASSET_DISCOVERY = "ccure.tasks.sync_asset_discovery_task"
SYNC_VULNERABILITY_AUDIT = "ccure.tasks.sync_vulnerability_audit_task"
