"""
core/compliance_catalogue
─────────────────────────────────────────────────────────────────────────────
The compliance catalogue's own code: what writes benchmark content into it and
what other capabilities read from it. G4 (C4 of
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md) gathered it here.

Module map
──────────
``benchmark_loader``     writing a benchmark pack into the catalogue
                         (from ``core/benchmarks/loader.py``, still an alias)
``benchmark_selection``  which benchmark checks apply to a scan, read from it
                         (from ``core/benchmarks/selection.py``, still an alias)

The package imports nothing, so a module here loads only what it needs.
"""
