"""
Audit integration adapter.

Translates between the external contracts (``ccure_contracts``) and Audit's
application-service views. Pure functions only: no database session, no
request, no delivery. Routes, service identity, the outbox and the feeds that
will call these mappers belong to the integration phase (plan Phase 7).

May import ``ccure_contracts`` and ``ccure_audit.services`` — nothing else from
the application (layer rule ``integration-is-an-adapter``). Nothing in
production imports this package yet, and a guard test keeps it that way until
the integration phase.
"""
