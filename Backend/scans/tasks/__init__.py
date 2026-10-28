"""
The Celery tasks of every scan phase, by area. Split from core/tasks.py in G1
(C2, docs/architecture/MODULAR_REFACTORING_LOG.md §6), the code unchanged:

=====================  =========================================================
``common``             the helpers every task shares: the scoped orchestrator,
                       cancellation, task ids, settling a failure
``credentialed_sync``  writing a credentialed audit's identity, services and
                       findings
``credentialed``       the credentialed scan task, the host and database audits,
                       the configuration audit, phase 3.5's enrichment
``topology``           SNMP topology mapping and when a scan chains it
``phases``             host discovery, asset discovery, the vulnerability audit,
                       the phase sync tasks, the traditional scan
``maintenance``        risk-acceptance expiry, AMT reconciliation, MAC vendors
``schedules``          dispatching the recurring scans that are due
``reapers``            settling scans nothing is working on
=====================  =========================================================

Every task keeps its registered name, queue, time limits and signature;
``scripts/architecture/task_registry.json`` pins them and
``tests/repo/test_task_registry.py`` compares. The worker loads these modules
from ``core/celery_app.py``'s include list. Nothing outside this package
imports them (layer_rules: ``task-hub-is-a-leaf``): code that starts a task
dispatches it by registered name (``core/task_names.py``).

The modules import each other one way only — ``common`` below everything,
``credentialed_sync`` below ``credentialed``, ``credentialed`` and
``topology`` below ``phases`` — so a test patches a name in the module whose
code reads it (``tests/repo/test_task_modules.py``). ``core/tasks.py`` remains
as a compatibility facade that re-exports every name the hub defined and
refuses to be patched.

This file imports nothing, so loading one task module does not load the rest.
"""
