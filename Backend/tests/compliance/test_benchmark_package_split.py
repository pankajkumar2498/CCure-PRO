"""
B4: the benchmark package no longer re-exports its database loader.

``core/benchmarks/__init__.py`` re-exported ``core.benchmarks.loader``, which
imports SQLAlchemy and the compliance models. Importing any submodule runs the
package's ``__init__`` first, so ``core.benchmarks.pack`` (the pure content
parser) and the SCAP compiler, which imports it, loaded the database layer and
most of the model registry. The package now exports the ``pack`` names only;
the loader's callers import ``core.benchmarks.loader`` by name.

These pin the purpose (the parser and the compiler import and run without the
database layer), the package's remaining API, and the callers: a script that
still imported a loader name from the package would fail only when an
operator ran it, because nothing in the suite imports the scripts.
"""

import ast
import importlib
import json
import subprocess
import sys

import pytest

import core.benchmarks as benchmarks
import core.benchmarks.loader as loader
import core.benchmarks.pack as pack
from testpaths import BACKEND_ROOT

#: What the package re-exported from the loader until B4.
LOADER_NAMES = (
    "BENCHMARK_EVIDENCE_SOURCE",
    "BENCHMARK_THEME",
    "LoadResult",
    "control_row_id",
    "load_pack_into_db",
    "rule_row_id",
)
PACK_NAMES = (
    "ASSESSMENT_STATES",
    "BenchmarkControl",
    "BenchmarkPack",
    "BenchmarkProfile",
    "PackError",
    "discover_packs",
    "dump_pack",
    "load_pack",
    "parse_pack",
)
DATABASE_LAYER = (
    "sqlalchemy",
    "config",
    "db.base",
    "db.models",
    "db.models.compliance",
    "core.benchmarks.loader",
    "core.benchmarks.selection",
    "core.compliance_catalogue.benchmark_loader",
    "core.compliance_catalogue.benchmark_selection",
)


def test_the_package_imports_nothing_but_the_pack_module():
    tree = ast.parse((BACKEND_ROOT / "core" / "benchmarks" / "__init__.py").read_text())
    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    } | {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert imported == {"__future__", "core.benchmarks.pack"}


def test_the_loader_and_selection_paths_are_the_compliance_modules():
    """
    G4: the loader and selection are compliance's catalogue code, in
    ``core/compliance_catalogue/``. The old names are aliases of the same
    module objects, so an import or a patch through either reaches one module.
    """
    import core.benchmarks.selection as old_selection
    import core.compliance_catalogue.benchmark_loader as new_loader
    import core.compliance_catalogue.benchmark_selection as new_selection

    assert loader is new_loader
    assert old_selection is new_selection
    assert new_loader.__name__ == "core.compliance_catalogue.benchmark_loader"


def test_the_package_exports_the_pack_api_as_the_same_objects():
    assert sorted(benchmarks.__all__) == sorted(PACK_NAMES)
    for name in PACK_NAMES:
        assert getattr(benchmarks, name) is getattr(pack, name), name
    for name in LOADER_NAMES:
        assert not hasattr(benchmarks, name), name
        assert hasattr(loader, name), name


_IMPORT_AND_RUN = r"""
import json, sys
sys.path.insert(0, "tests/scans")
watched = %r
import core.benchmarks, core.benchmarks.pack, core.scap
after_import = {m: m in sys.modules for m in watched}

from core.benchmarks import dump_pack, load_pack, parse_pack
from core.scap import parse_content, to_pack
from test_scap_parsers import BENCHMARK, datastream

converted, _report = to_pack(
    parse_content(datastream(BENCHMARK), origin="fixture"),
    code="fixture_stig",
    publisher="CCURE (synthetic fixture)",
    licence="synthetic test fixture, not benchmark content",
    profile_id="stig",
)
restored = parse_pack(json.loads(json.dumps(dump_pack(converted))))
shipped = load_pack("data/benchmarks/ccure_linux_baseline.benchmark.json")
after_run = {m: m in sys.modules for m in watched}
print(json.dumps({
    "after_import": after_import,
    "after_run": after_run,
    "controls": sorted(c.control_id for c in restored.controls),
    "shipped_controls": len(shipped.controls),
}))
"""


def test_the_scap_compiler_and_the_pack_parser_run_without_the_database_layer():
    """Import the compiler, convert a benchmark, round-trip it, read a shipped pack."""
    done = subprocess.run(
        [sys.executable, "-c", _IMPORT_AND_RUN % (DATABASE_LAYER,)],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    result = json.loads(done.stdout.strip().splitlines()[-1])
    assert result["controls"] == ["one", "two"]
    assert result["shipped_controls"] > 0
    for stage in ("after_import", "after_run"):
        loaded = sorted(m for m, seen in result[stage].items() if seen)
        assert loaded == [], f"{stage}: {loaded}"


def _python_sources():
    for path in BACKEND_ROOT.rglob("*.py"):
        parts = path.relative_to(BACKEND_ROOT).parts
        if parts[0] in (".venv", "venv", "node_modules") or "__pycache__" in parts:
            continue
        yield path


def test_no_caller_imports_a_loader_name_from_the_package():
    """
    Lazy imports count, and so do the operator scripts nothing else imports:
    ``from core.benchmarks import load_pack_into_db`` now fails at run time.
    """
    offenders = []
    for path in _python_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "core.benchmarks":
                wrong = [a.name for a in node.names if a.name not in PACK_NAMES]
                if wrong:
                    offenders.append(
                        f"{path.relative_to(BACKEND_ROOT)}:{node.lineno} {wrong}"
                    )
    assert offenders == []


@pytest.mark.parametrize(
    "script", ["scripts.benchmarks.load_benchmark", "scripts.benchmarks.load_stig"]
)
def test_the_operator_scripts_import_the_loader_from_the_loader(script):
    module = importlib.import_module(script)
    assert callable(module.main)
    assert module.load_pack_into_db is loader.load_pack_into_db
