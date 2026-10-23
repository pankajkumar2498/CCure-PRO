"""
The compliance catalogue's boundary (G4, C4;
docs/architecture/MODULAR_REFACTORING_LOG.md §6).

* **Configuration audit imports nothing above it.** The benchmark loader and
  selection, which write and read the catalogue, are compliance's code in
  ``core/compliance_catalogue/``; the benchmark pack defines the framework-id
  prefix it needs; the SCAP crosswalk is handed the NIST catalogue.
* **Scan policy reads the catalogue only through compliance's read module**,
  ``core.compliance_catalogue.reads``, never a compliance model or table.
* **Module code imports the moved modules by their new paths.** The old ones,
  ``core.benchmarks.loader`` and ``.selection``, stay as aliases for tests,
  patch targets and operator scripts.

Lazy imports count: they are how this codebase hid its cycles.
"""

import ast

from scripts.architecture import capability_map
from scripts.architecture.import_graph import collect_edges
from testpaths import BACKEND_ROOT


def _edges():
    _, edges = collect_edges()
    return edges


def _layer(capability: str) -> int:
    return capability_map.CAPABILITIES[capability][0]


def test_configuration_audit_imports_nothing_above_it():
    above = sorted(
        (e.src, e.dst)
        for e in _edges()
        if capability_map.capability_of(e.src) == "config_audit"
        and capability_map.capability_of(e.dst) is not None
        and _layer(capability_map.capability_of(e.dst)) > _layer("config_audit")
    )
    assert above == []


def test_the_benchmark_modules_that_touch_the_catalogue_are_compliances():
    for module in (
        "core.compliance_catalogue.benchmark_loader",
        "core.compliance_catalogue.benchmark_selection",
        "core.compliance_catalogue.reads",
        "core.benchmarks.loader",
        "core.benchmarks.selection",
    ):
        assert capability_map.capability_of(module) == "compliance", module
    for module in ("core.benchmarks", "core.benchmarks.pack", "core.scap.cci"):
        assert capability_map.capability_of(module) == "config_audit", module


def test_scan_policy_reads_the_catalogue_only_through_compliances_reads():
    into_compliance = {
        (e.src, e.dst)
        for e in _edges()
        if capability_map.capability_of(e.src) == "scan_policy"
        and capability_map.capability_of(e.dst) == "compliance"
    }
    # The graph records the package an import passes through as well; the
    # package's __init__ is a docstring and imports nothing.
    assert into_compliance <= {
        ("core.scan_policy.validation", "core.compliance_catalogue"),
        ("core.scan_policy.validation", "core.compliance_catalogue.reads"),
    }
    assert ("core.scan_policy.validation", "core.compliance_catalogue.reads") in (
        into_compliance
    )


def test_scan_policy_names_no_compliance_table():
    measurement = capability_map.measure()
    owners = capability_map.table_owners()
    named = sorted(
        table
        for capability, table in measurement["foreign_table_references"]
        if capability == "scan_policy" and owners.get(table) == "compliance"
    )
    assert named == []


_ALIASES = ("core.benchmarks.loader", "core.benchmarks.selection")
_MODULE_CODE_DIRS = (
    "routers",
    "scans",
    "core",
    "engines",
    "orchestrator",
    "reporting",
    "ccure_audit",
    "ccure_platform",
    "db",
)


def _imported_modules(path) -> set:
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
            found.update(f"{node.module}.{a.name}" for a in node.names)
        elif isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
    return found


def test_module_code_imports_the_moved_modules_by_their_new_paths():
    candidates = [BACKEND_ROOT / "main.py"]
    for directory in _MODULE_CODE_DIRS:
        candidates += list((BACKEND_ROOT / directory).rglob("*.py"))
    importers = sorted(
        str(path.relative_to(BACKEND_ROOT))
        for path in candidates
        if _imported_modules(path) & set(_ALIASES)
    )
    assert importers == []
