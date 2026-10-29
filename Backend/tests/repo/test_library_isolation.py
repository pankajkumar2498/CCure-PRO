"""
D1 and E2 (docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md §10, Phases D
and E): the engine libraries work with nothing but what they declare
(scripts/architecture/library_isolation.py), and none of them loads SQLAlchemy,
FastAPI, Celery or Redis (capability_map.library_problems).

The harness itself runs in scripts/ci/local_guard_tests.sh, in the backend
image. These tests prove that it and the pin can fail: an engine library that
imports SQLAlchemy, and discovery importing the settings module, are each
caught, and the same copy without the mutation passes first, so a pass is not
vacuous.
"""

import copy
import shutil
from pathlib import Path

import pytest
from scripts.architecture import capability_map as cm
from scripts.architecture import library_isolation as li
from scripts.architecture.import_graph import collect_edges
from testpaths import BACKEND_ROOT

#: The scan engines that are not D1 libraries. Since Group 3 four of them are
#: pinned statically by E2 (capability_map.PINNED_ENGINES) and the topology
#: engine still persists its own links; none is declared, nothing exempts them.
DEFERRED = {
    "engines.port.port_engine",
    "engines.vulnerability.vulnerability_engine",
    "core.nmap.wrapper",
    "engines.credentialed.vuln_matcher",
    "core.topology.engine",
}


# ── The declarations ──────────────────────────────────────────────────────────


def test_the_libraries_are_declared():
    # Group 1's eight, and web DAST since Group 4.
    assert set(li.LIBRARIES) == {
        "ssh_transport",
        "winrm_transport",
        "smb_transport",
        "config_audit",
        "scap_compiler",
        "check_kernel",
        "renderers",
        "discovery",
        "web_dast",
    }


def test_no_deferred_engine_is_declared():
    declared = {e for lib in li.LIBRARIES.values() for e in lib.entry_points}
    assert not declared & DEFERRED


def test_every_entry_point_has_a_load_profile_to_pin():
    for library in li.LIBRARIES.values():
        assert set(library.entry_points) <= set(cm.ENTRY_POINTS)


def test_the_forbidden_packages_are_ones_a_load_profile_records():
    assert li.FORBIDDEN <= cm.HEAVY


def test_every_declared_test_exists():
    for library in li.LIBRARIES.values():
        assert library.tests
        for test in library.tests:
            assert (BACKEND_ROOT / test.split("::")[0]).is_file(), test


def test_a_declaration_admits_the_packages_above_a_prefix_and_nothing_beside_it():
    guard = li._Guard(
        {
            "root": str(BACKEND_ROOT),
            "first_party_tops": ["core", "config", "db"],
            "first_party": ["core.discovery"],
            "third_party": ["scapy"],
            "phase": "import",
        }
    )
    assert guard.permits("core")
    assert guard.permits("core.discovery.techniques.arp")
    assert guard.permits("scapy.all")
    assert guard.permits("json")
    assert not guard.permits("core.oui_lookup")
    assert not guard.permits("config")
    assert not guard.permits("psutil")
    assert not guard.permits("sqlalchemy.orm")


# ── E2: the static pin ────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def graph():
    return collect_edges()


def test_no_library_loads_a_forbidden_package(graph):
    modules, raw = graph
    assert cm.library_problems(cm.load_profiles(modules, raw)) == []


def test_sqlalchemy_in_an_engine_library_fails_e2(graph, tmp_path):
    modules, raw = graph
    entry = "core.config_audit.engine"
    mutated = tmp_path / "engine.py"
    source = modules[entry].read_text(encoding="utf-8")
    mutated.write_text(source + "\nimport sqlalchemy  # mutation\n", encoding="utf-8")

    problems = cm.library_problems(cm.load_profiles({**modules, entry: mutated}, raw))

    assert (
        f"library config_audit: importing {entry} loads ['sqlalchemy'], "
        "which an engine library may never load (E2)"
    ) in problems
    assert all("['sqlalchemy']" in p for p in problems)


def test_a_rewritten_baseline_cannot_admit_a_forbidden_package(graph):
    modules, raw = graph
    profiles = copy.deepcopy(cm.load_profiles(modules, raw))
    profiles["core.discovery.engine"]["third_party"].append("redis")
    measurement = {"unmapped": [], "load_profiles": profiles}
    for key in cm._BASELINE_KEYS[:-1]:
        measurement[key] = cm.load_baseline()[key]
    measurement["scan_helpers_importers"] = []
    # As if --write-baseline had recorded the new profile.
    baseline = cm.baseline_from(measurement)

    problems = cm.ratchet_problems(measurement, baseline)

    assert (
        "library discovery: importing core.discovery.engine loads ['redis'], "
        "which an engine library may never load (E2)"
    ) in problems


# ── D1: the harness, run ──────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def backend_copy(tmp_path_factory):
    """The backend's Python source, without tests or data: enough to import
    every library, and safe to mutate."""
    root = tmp_path_factory.mktemp("isolation") / "Backend"
    skip_top = {"tests", "data", "reports", "logs"}

    def ignore(directory, names):
        here = Path(directory)
        return [
            n
            for n in names
            if n.startswith(".")
            or n == "__pycache__"
            or (here == BACKEND_ROOT and n in skip_top)
            or ((here / n).is_file() and not n.endswith(".py"))
        ]

    shutil.copytree(BACKEND_ROOT, root, ignore=ignore)
    return root


@pytest.mark.parametrize(
    "library, module, mutation, refused",
    [
        (
            "config_audit",
            "core/config_audit/engine.py",
            "import sqlalchemy",
            "sqlalchemy",
        ),
        ("discovery", "core/discovery/engine.py", "import config", "config"),
        # Group 4: the web engine reading the global configuration again.
        (
            "web_dast",
            "core/web/sqlmap/wrapper.py",
            "from config import WebScanConfig",
            "config",
        ),
    ],
)
def test_an_undeclared_import_fails_isolation(
    backend_copy, library, module, mutation, refused
):
    declaration = li.LIBRARIES[library]
    problems, _ = li.check(library, declaration, root=backend_copy, import_only=True)
    assert (
        problems == []
    ), "the copy must pass unmutated, or the mutation proves nothing"

    path = backend_copy / module
    original = path.read_text(encoding="utf-8")
    path.write_text(original + f"\n{mutation}  # mutation\n", encoding="utf-8")
    try:
        problems, _ = li.check(
            library, declaration, root=backend_copy, import_only=True
        )
    finally:
        path.write_text(original, encoding="utf-8")

    importer = module.removesuffix(".py").replace("/", ".")
    assert f"{library}: {importer} may not import {refused} (not declared)" in problems


def test_a_lazy_import_of_an_already_loaded_module_is_still_refused(tmp_path):
    """The case a finder alone misses: the test loads a module first, and the
    library imports it later, inside a function. ``sys.modules`` would answer
    without asking any finder, so the guard checks the import statement."""
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (tmp_path / "neighbour.py").write_text("VALUE = 1\n", encoding="utf-8")
    package = tmp_path / "toylib"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "engine.py").write_text(
        "def run():\n    import neighbour\n\n    return neighbour.VALUE\n",
        encoding="utf-8",
    )
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_toylib.py").write_text(
        "import neighbour\nfrom toylib import engine\n\n\n"
        "def test_run():\n    assert engine.run() == neighbour.VALUE\n",
        encoding="utf-8",
    )
    toylib = li.Library(
        entry_points=("toylib.engine",),
        first_party=("toylib",),
        third_party=frozenset(),
        tests=("tests/test_toylib.py",),
    )

    problems, _ = li.check("toylib", toylib, root=tmp_path)

    assert "toylib: toylib.engine may not import neighbour (exercise)" in problems
