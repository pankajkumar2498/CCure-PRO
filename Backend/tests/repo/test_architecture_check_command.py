"""
``scripts/architecture/check.py`` — the stdlib-only twin of the architecture
ratchets, run by the ``architecture-guards`` pre-commit hook.

It exists because the ratchets in tests/repo need a disposable PostgreSQL and
the backend's dependencies, and while hosted CI was unavailable nothing ran
them (docs/ci/LOCAL_ENFORCEMENT.md). These pin the three properties that make
it worth having: it passes on this tree, it fails on a breach, and it needs
nothing but the standard library — so it can never fail a commit because of
the environment it runs in.
"""

import ast
import sys

import pytest
from scripts.architecture import check
from scripts.architecture.import_graph import Edge, collect_edges
from testpaths import BACKEND_ROOT, REPO_ROOT


def test_the_command_passes_on_this_tree():
    results = check.run()
    assert set(results) == {
        "layering",
        "import cycles",
        "identity boundary",
        "organisation settings",
        "secret handling",
    }
    assert {name: problems for name, problems in results.items() if problems} == {}


def test_the_layering_check_reports_a_new_violation():
    _, edges = collect_edges()
    breach = Edge("engines.port.port_engine", "routers.assets", lazy=False)
    problems = check.check_layering(edges + [breach])
    assert any("engines.port.port_engine -> routers.assets" in p for p in problems)


def test_the_cycle_check_reports_a_new_cycle():
    edges = [
        Edge("core.example_a", "core.example_b", lazy=True),
        Edge("core.example_b", "core.example_a", lazy=False),
    ]
    problems = check.check_cycles(edges)
    assert any("core.example_a <-> core.example_b" in p for p in problems)


def test_the_hook_is_configured():
    import yaml

    config_path = REPO_ROOT / ".pre-commit-config.yaml"
    if not config_path.is_file():
        pytest.skip(".pre-commit-config.yaml is not reachable from this runtime")
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    hooks = {h["id"]: h for repo in config["repos"] for h in repo["hooks"]}
    hook = hooks["architecture-guards"]
    assert hook["entry"] == "python Backend/scripts/architecture/check.py"
    assert hook["pass_filenames"] is False
    assert (REPO_ROOT / "Backend/scripts/architecture/check.py").is_file()


def _imported_roots(path) -> set[str]:
    roots = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            roots |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def test_the_command_needs_only_the_standard_library():
    """
    The hook runs in pre-commit's own bare environment. A third-party import
    anywhere in the command's closure would make every backend commit depend on
    that package being installed there.
    """
    closure = [
        "check",
        "secret_guards",
        "import_graph",
        "layer_rules",
        "identity_boundary",
    ]
    allowed = set(sys.stdlib_module_names) | {"scripts", "__future__"}
    for name in closure:
        path = BACKEND_ROOT / "scripts" / "architecture" / f"{name}.py"
        foreign = _imported_roots(path) - allowed
        assert not foreign, f"{name}.py imports {sorted(foreign)}"
