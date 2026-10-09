"""
ccure_contracts — the integration contracts between the four CCure modules.

Phase 4 of the modular-platform programme. **Draft for review**: nothing in the
application imports this package yet, no route serves it and no worker emits
it. It is the reviewable definition of what Policy Pro, Audit, Rank and IR
will exchange once the integration layer is built (plan Phase 14).

Design document: ``docs/architecture/contracts/PHASE4_INTEGRATION_CONTRACTS.md``.

Rules this package keeps, and which ``tests/repo/test_integration_contracts.py``
and the ``contracts-are-leaves`` layer rule enforce:

* It imports the standard library and Pydantic only. Every module may import
  it, so it may import no module's code — least of all Audit's SQLAlchemy
  models, which a contract must never expose.
* Every field names the module that owns its value (``x-ccure-owner`` in the
  generated schema) and, for values Audit produces, whether Audit can populate
  it today (``x-ccure-availability``).
* Unknown is never zero. A value Audit cannot produce is carried as an
  explicit ``not_implemented`` / ``not_collected`` state, never as ``0``,
  ``false`` or an empty list.
* The JSON Schemas under ``<contract>/v1/schemas/`` are generated from these
  models by ``scripts/contracts/generate_schemas.py`` and committed; a test
  fails when they drift.
"""
