"""
ccure_audit — the CCure Audit module's own boundary layers.

Phase 5 of the modular-platform programme. Design:
``docs/architecture/PHASE5_AUDIT_INTEGRATION_BOUNDARIES.md``.

    External contract            ccure_contracts/            shared by all four modules
            ▼
    Audit integration adapter    ccure_audit/integration/    views → contract models, and back
            ▼
    Audit application services   ccure_audit/services/       queries → frozen views
            ▼
    Audit capabilities           core/, engines/, scans/, reporting/   (used, not moved)
            ▼
    Infrastructure               db/, Celery, Redis

Three layer rules hold these apart (``scripts/architecture/layer_rules.py``):

* ``integration-is-an-adapter`` — the adapter imports ``ccure_contracts`` and
  ``ccure_audit.services`` only. Reaching past the services to the database is
  how an ORM row ends up inside a contract.
* ``services-do-not-speak-contracts`` — services return Audit's own views and
  never import a contract type, so a new contract version never forces a
  service change.
* ``foundations-do-not-import-audit-module`` — ``core``, ``engines``, ``scans``,
  ``orchestrator``, ``db`` and ``auth`` sit below this package and never import
  it, which would re-create the cycles Phase 3 removed.

**Nothing in production uses the adapter yet.** It is exercised by tests until
the integration phase (service identity, tenant check, outbox, feeds) wires it
to routes; a guard test fails if anything imports it before then.
"""
