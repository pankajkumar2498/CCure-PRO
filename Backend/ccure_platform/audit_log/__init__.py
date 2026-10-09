"""
ccure_platform/audit_log — the platform's audit log, as a platform capability.

The ``audit_logs`` table is the platform's (``scripts/architecture/table_ownership.yaml``)
and every module writes to it. Only its scheduled retention task lives here so
far (``tasks.py``); the rest of the audit-log service — ``core/audit.py``,
``core/audit_retention.py``, ``core/audit_taxonomy.py`` and the viewer router —
moves in later steps of the backend alignment, one at a time.
"""
