"""
CCure Home — the platform's product hub (Phase 12).

``router.py`` serves the list of products CCure Home shows, read from the module
registry (``ccure_platform.modules``), which stays the only place that says what
the products are. The registry itself is a stdlib-only leaf, so the HTTP layer
lives here rather than beside it.
"""
