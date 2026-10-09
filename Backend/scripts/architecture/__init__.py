"""
Architecture measurement and guardrails for the modular-platform programme.

``import_graph`` measures how the backend's modules depend on each other;
``layer_rules`` states which dependencies are forbidden and lists the ones that
exist today; ``table_ownership.yaml`` records which module owns every table.
``tests/repo/test_architecture_guardrails.py`` enforces all three in CI.
"""
