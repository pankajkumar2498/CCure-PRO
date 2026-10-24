"""
One pipeline definition, and a typed hand-off between phases (C6;
docs/architecture/MODULAR_REFACTORING_LOG.md §6).

* **Only the pipeline starts a later phase.** Asset discovery and the
  vulnerability audit are dispatched by ``scans.pipeline.hand_over`` and
  nowhere else: not by the phase task before them, not by the router that
  continues an interactive scan. Host discovery starts a scan and is
  dispatched by the routes and the scheduler, as before.
* **The hand-off is the scan kernel's**, and imports nothing but the standard
  library, so every phase, engine and route can speak it.
"""

import ast

from testpaths import BACKEND_ROOT

LATER_PHASE_NAMES = ("RUN_ASSET_DISCOVERY", "RUN_VULNERABILITY_AUDIT")
LATER_PHASE_TASKS = ("run_asset_discovery_task", "run_vulnerability_audit_task")
#: Where a later phase's registered name may be read: its definition, the
#: pipeline that dispatches it, and the task module that registers it.
NAME_READERS = {"core/task_names.py", "scans/pipeline.py", "scans/tasks/phases.py"}
SOURCE_DIRS = (
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


def _sources():
    files = [BACKEND_ROOT / "main.py", BACKEND_ROOT / "scan_helpers.py"]
    for directory in SOURCE_DIRS:
        files += sorted((BACKEND_ROOT / directory).rglob("*.py"))
    return files


def _rel(path) -> str:
    return str(path.relative_to(BACKEND_ROOT))


def test_only_the_pipeline_reads_a_later_phases_registered_name():
    readers = set()
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in LATER_PHASE_NAMES:
                readers.add(_rel(path))
            elif isinstance(node, ast.Attribute) and node.attr in LATER_PHASE_NAMES:
                readers.add(_rel(path))
            elif isinstance(node, ast.ImportFrom) and any(
                a.name in LATER_PHASE_NAMES for a in node.names
            ):
                readers.add(_rel(path))
    assert readers <= NAME_READERS, sorted(readers - NAME_READERS)


def test_no_module_dispatches_a_later_phase_task_directly():
    dispatchers = []
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and node.attr in ("delay", "apply_async", "s", "si", "signature")
                and isinstance(node.value, ast.Name)
                and node.value.id in LATER_PHASE_TASKS
            ):
                dispatchers.append(f"{_rel(path)}:{node.lineno}")
    assert dispatchers == []


def test_the_phase_tasks_hand_over_through_the_pipeline():
    source = (BACKEND_ROOT / "scans" / "tasks" / "phases.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    calls = [
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    assert calls.count("hand_over") == 2  # host discovery, asset discovery


def test_the_router_continues_a_scan_through_the_pipeline():
    source = (BACKEND_ROOT / "routers" / "phase_scans.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    calls = [
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    assert calls.count("hand_over") == 2  # asset discovery, vulnerability audit


def _module_imports(path) -> set:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = set()
    for node in tree.body:  # module level only
        if isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
        elif isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
    return found


def test_the_hand_off_imports_only_the_standard_library():
    imports = _module_imports(BACKEND_ROOT / "core" / "phase_handoff.py")
    assert imports <= {"__future__", "dataclasses", "typing"}, imports


def test_the_pipeline_definition_loads_nothing_heavy():
    imports = _module_imports(BACKEND_ROOT / "scans" / "pipeline.py")
    assert imports <= {
        "__future__",
        "logging",
        "dataclasses",
        "typing",
        "core",
        "core.phase_handoff",
    }, imports
