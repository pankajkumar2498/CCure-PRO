"""
Moved to ``core/compliance_catalogue/benchmark_selection.py`` (G4, C4 of the module
independence plan).

Benchmark selection reads and writes the compliance catalogue's tables, so it is
compliance's code; under ``core/benchmarks`` it put the configuration audit's
content package on top of the compliance catalogue.

This path is an alias of the **same module object**, not a copy and not a star
re-export: every existing import, private name and ``patch.object`` target
behaves exactly as before. New code imports from
``core.compliance_catalogue.benchmark_selection``.
"""

import sys

from core.compliance_catalogue import benchmark_selection as _module

sys.modules[__name__] = _module
