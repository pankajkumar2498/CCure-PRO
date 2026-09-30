"""
TEST-ONLY proof module (Phase 11.2). Not an application package, never
registered in production, never shipped: it lives under Backend/tests/, which
the import graph and the application do not load.

It is shaped exactly like ccure_policy/ and ccure_rank/ and adds one of each
thing a future team adds — a route, a table, a migration and a Celery task —
using only files inside this folder. tests/modules/example/
test_module_example_proof.py proves each one works and that the guardrails
catch the ways a module could break its boundary.
"""
