"""
The scan tasks split out of core/tasks.py (G1, C2), and the facade's removal.

G1 moved every scan task and its helpers into ``scans/tasks/``
(docs/architecture/MODULAR_REFACTORING_LOG.md §6) and left ``core/tasks.py``
re-exporting them. That facade was removed on 2 Nov 2026: every caller imports
a name from the module that owns it. These hold that:

* **The facade stays gone.** Nothing in the application, the tests, the
  scripts or the documents' scripts imports or patches ``core.tasks``, and
  every name it offered is importable from exactly one owner, as the same task
  Celery registered under its unchanged name.
* **A patch on the wrong task module replaces nothing.**
  ``scans.tasks.phases`` imports ``_settle_failure`` from ``common``;
  ``mark_scan_failed`` is read inside ``_settle_failure``, so it must be
  patched on ``common``. A patch must name a module whose own code reads the
  name. One test checks every patch on a task module does.

Also here: the worker loads the task modules, and every beat entry and route
names a registered task.
"""

import ast
import importlib
import importlib.util
import pkgutil
from pathlib import Path

import pytest
from scripts.architecture.import_graph import discover_modules
from testpaths import BACKEND_ROOT, REPO_ROOT

TESTS_DIR = BACKEND_ROOT / "tests"
TASKS_DIR = BACKEND_ROOT / "scans" / "tasks"
FACADE = "core.tasks"

#: Every top-level name core/tasks.py defined before G1 (92c224c) — its
#: functions, tasks and constants, and the five mail tasks it re-exported — by
#: the module that owns it now, as the facade imported them until 2 Nov 2026.
OWNERS: dict[str, tuple[str, ...]] = {
    "ccure_platform.identity.mail_tasks": (
        "send_account_approved_email_task",
        "send_mfa_otp_task",
        "send_password_changed_email_task",
        "send_password_reset_email_task",
        "send_verification_email_task",
    ),
    "scans.tasks.common": (
        "_bind_scan_scope",
        "_check_cancelled",
        "_finalize_cancelled",
        "_new_orchestrator",
        "_run_async",
        "_settle_failure",
        "_strip_nul",
        "_update_task_id",
        "log",
    ),
    "core.findings.writer": (
        "_assessed_config_definition_ids",
        "_first_advisory",
        "_sync_credentialed_vulnerabilities",
    ),
    "scans.tasks.credentialed_sync": (
        "_clean_text",
        "_credentialed_sections_with_identity",
        "_extract_credentialed_identity_names",
        "_normalize_mac",
        "_port_int",
        "_sync_credentialed_asset_identity",
        "_sync_credentialed_services",
    ),
    "scans.tasks.credentialed": (
        "_apply_credentialed_enrichment",
        "_as_credentialed_findings",
        "_audit_host_over_transport",
        "_classify_credentialed_failure",
        "_credential_for_host",
        "_credentialed_hardening_audits",
        "_credentialed_plan_for_scan",
        "_hardening_row",
        "_is_transport_failure",
        "_ports_probed_in_phase2",
        "_resolve_stored_credential",
        "_restate_findings_for_corrected_ports",
        "_run_configuration_audit",
        "_sync_configuration_compliance",
        "_unique_lines",
        "_upgrade_network_fingerprints",
        "audit_credentialed_host",
        "audit_database_target",
        "run_credentialed_scan_task",
    ),
    "scans.tasks.topology": (
        "_chain_topology_if_needed",
        "_should_chain_topology",
        "run_topology_mapping_task",
    ),
    "scans.tasks.phases": (
        "_merge_host_identity",
        "run_asset_discovery_task",
        "run_host_discovery_task",
        "run_traditional_scan_task",
        "run_vulnerability_audit_task",
        "sync_asset_discovery_task",
        "sync_host_discovery_task",
        "sync_vulnerability_audit_task",
    ),
    "scans.tasks.maintenance": (
        "expire_risk_acceptances",
        "reconcile_amt_inventory_task",
        "update_mac_vendor_registry_task",
    ),
    "scans.tasks.schedules": ("_SCAN_SCHEDULER_LOCK_KEY", "run_due_scan_schedules"),
    "scans.tasks.reapers": ("reap_stalled_scans", "reap_stalled_web_scans"),
    "scans.scan_creation": ("MAX_CREDENTIALED_TARGETS",),
}

_PATCHERS = {"patch", "mock.patch", "unittest.mock.patch", "mocker.patch"}
_OBJECT_PATCHERS = {
    "patch.object",
    "mock.patch.object",
    "unittest.mock.patch.object",
    "mocker.patch.object",
}


def _task_modules() -> list[str]:
    return sorted(
        f"scans.tasks.{info.name}" for info in pkgutil.iter_modules([str(TASKS_DIR)])
    )


class _Patches(ast.NodeVisitor):
    """
    Every replacement of a module attribute in one test file, with the module
    resolved through the import aliases in scope where the replacement is made
    (a function's own imports shadow the file's).
    """

    def __init__(self):
        self.scopes: list[dict[str, str]] = [{}]
        #: (line, module, attribute path after the module)
        self.found: list[tuple[int, str, str]] = []

    def _bind(self, name: str, module: str) -> None:
        self.scopes[-1][name] = module

    def _resolve(self, expr: ast.expr) -> str | None:
        text = ast.unparse(expr)
        for scope in reversed(self.scopes):
            if text in scope:
                return scope[text]
        return None

    def visit_Import(self, node):
        for a in node.names:
            if a.asname:
                self._bind(a.asname, a.name)
            else:  # `import core.tasks` binds `core`; the dotted use resolves
                self._bind(a.name, a.name)

    def visit_ImportFrom(self, node):
        for a in node.names:
            if node.module:
                self._bind(a.asname or a.name, f"{node.module}.{a.name}")

    def _scoped(self, node):
        self.scopes.append({})
        self.generic_visit(node)
        self.scopes.pop()

    visit_FunctionDef = _scoped
    visit_AsyncFunctionDef = _scoped
    visit_ClassDef = _scoped

    def visit_Call(self, node):
        fn = ast.unparse(node.func)
        args = node.args
        string_patcher = fn in _PATCHERS or fn.endswith("monkeypatch.setattr")
        if (
            string_patcher
            and args
            and isinstance(args[0], ast.Constant)
            and isinstance(args[0].value, str)
            and "." in args[0].value
        ):
            self.found.append((node.lineno, *self._split(args[0].value)))
        elif (
            fn in _OBJECT_PATCHERS
            or fn.endswith("monkeypatch.setattr")
            or fn.endswith("monkeypatch.delattr")
        ) and len(args) >= 2:
            module = self._resolve(args[0])
            if module and isinstance(args[1], ast.Constant):
                self.found.append((node.lineno, module, str(args[1].value)))
        self.generic_visit(node)

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                module = self._resolve(target.value)
                if module:
                    self.found.append((node.lineno, module, target.attr))
        self.generic_visit(node)

    @staticmethod
    def _split(dotted: str) -> tuple[str, str]:
        """``scans.tasks.common.mark_scan_failed`` -> the module, the rest."""
        parts = dotted.split(".")
        for i in range(len(parts) - 1, 0, -1):
            module = ".".join(parts[:i])
            if module == FACADE or module.startswith("scans.tasks."):
                return module, ".".join(parts[i:])
        return ".".join(parts[:-1]), parts[-1]


def _all_patches() -> list[tuple[str, int, str, str]]:
    found = []
    for path in sorted(TESTS_DIR.rglob("*.py")):
        if path.resolve() == Path(__file__).resolve():
            continue  # this file's self-test names patches on purpose
        visitor = _Patches()
        visitor.visit(ast.parse(path.read_text(encoding="utf-8")))
        rel = str(path.relative_to(BACKEND_ROOT))
        found += [(rel, line, module, attr) for line, module, attr in visitor.found]
    return found


def _names_read(module: str) -> set[str]:
    path = TASKS_DIR / (module.rsplit(".", 1)[1] + ".py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }


def test_every_patch_on_a_task_module_replaces_a_name_that_module_reads():
    """
    A module that imports a name and never reads it is re-exporting it: a patch
    there runs the real code. Patches of an attribute *of* an object
    (``scans.tasks.phases.run_host_discovery_task.delay``) replace it on the
    shared object, wherever it was reached from, and are not checked here.
    """
    modules = set(_task_modules())
    unread = []
    checked = 0
    for path, line, module, attr in _all_patches():
        if module not in modules or "." in attr:
            continue
        checked += 1
        if attr not in _names_read(module):
            unread.append(f"{path}:{line}: {module}.{attr}")
    assert (
        checked >= 40
    ), f"only {checked} patches on task modules seen; is the scan broken?"
    assert not unread, (
        "these patches replace a name the module's own code never reads, so "
        "they replace nothing the code under test sees:\n  " + "\n  ".join(unread)
    )


def test_the_scan_finds_patches_in_every_form_it_claims_to(tmp_path):
    source = """
import core.tasks as hub
from scans.tasks import credentialed as cred

def test_a(monkeypatch):
    monkeypatch.setattr(hub, "x", 1)
    monkeypatch.setattr("core.tasks.y", 1)

def test_b(monkeypatch):
    import scans.tasks.common as hub
    monkeypatch.setattr(hub, "mark_scan_failed", 1)
    with patch("scans.tasks.phases.SessionLocal"), patch.object(cred, "z"):
        cred.w = 2
"""
    visitor = _Patches()
    visitor.visit(ast.parse(source))
    assert [(m, a) for _, m, a in visitor.found] == [
        ("core.tasks", "x"),
        ("core.tasks", "y"),
        ("scans.tasks.common", "mark_scan_failed"),
        ("scans.tasks.phases", "SessionLocal"),
        ("scans.tasks.credentialed", "z"),
        ("scans.tasks.credentialed", "w"),
    ]


def test_the_worker_loads_the_task_modules_and_not_the_facade():
    from core.celery_app import celery_app

    included = set(celery_app.conf.include)
    defining = {
        module
        for module in _task_modules()
        if "@celery_app.task("
        in (TASKS_DIR / (module.rsplit(".", 1)[1] + ".py")).read_text(encoding="utf-8")
    }
    assert defining == {
        "scans.tasks.credentialed",
        "scans.tasks.maintenance",
        "scans.tasks.phases",
        "scans.tasks.reapers",
        "scans.tasks.schedules",
        "scans.tasks.topology",
    }
    assert defining <= included, sorted(defining - included)


# ── The facade is gone, and nothing reached through it ───────────────────────


def test_the_facade_is_gone():
    assert not (BACKEND_ROOT / "core" / "tasks.py").exists()
    assert importlib.util.find_spec(FACADE) is None


def _python_files_outside_the_application():
    yield from TESTS_DIR.rglob("*.py")
    yield from (BACKEND_ROOT / "scripts").rglob("*.py")
    for directory in ("scripts", "docs"):
        yield from (REPO_ROOT / directory).rglob("*.py")


def _facade_imports(tree: ast.AST) -> list[int]:
    lines = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(
            a.name == FACADE or a.name.startswith(FACADE + ".") for a in node.names
        ):
            lines.append(node.lineno)
        elif isinstance(node, ast.ImportFrom) and (
            node.module == FACADE
            or (node.module == "core" and any(a.name == "tasks" for a in node.names))
        ):
            lines.append(node.lineno)
    return lines


def test_nothing_imports_or_patches_the_facade():
    """The application, the tests, both scripts trees and the documents'
    scripts: a ``core.tasks`` import or patch would fail now, at the first run
    of whatever holds it."""
    found = []
    modules = [path for _, path in sorted(discover_modules().items())]
    for path in [*modules, *_python_files_outside_the_application()]:
        if "__pycache__" in path.parts or path.resolve() == Path(__file__).resolve():
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        found += [f"{path}:{line}" for line in _facade_imports(tree)]
    found += [
        f"{path}:{line}: {module}.{attr}"
        for path, line, module, attr in _all_patches()
        if module == FACADE
    ]
    assert not found, "core.tasks is gone; import from the owner:\n  " + "\n  ".join(
        found
    )


def test_the_scan_finds_a_facade_import_in_each_form():
    source = "import core.tasks\nimport core.tasks as hub\nfrom core.tasks import x\nfrom core import tasks\n"
    assert _facade_imports(ast.parse(source)) == [1, 2, 3, 4]
    assert _facade_imports(ast.parse("from core import task_names\n")) == []


@pytest.mark.parametrize("module", sorted(OWNERS))
def test_every_name_the_hub_defined_has_its_owner(module):
    """Import compatibility: each name the facade offered is importable from
    the module that owns it — the one the facade imported it from."""
    owner = importlib.import_module(module)
    missing = [name for name in OWNERS[module] if not hasattr(owner, name)]
    assert not missing, f"{module} no longer offers {missing}"


def test_each_name_has_one_owner():
    names = [name for group in OWNERS.values() for name in group]
    assert len(names) == len(set(names)) == 62


def test_every_task_the_hub_offered_is_registered_under_its_name():
    from core.celery_app import celery_app

    celery_app.loader.import_default_modules()
    tasks = {}
    for module, names in OWNERS.items():
        owner = importlib.import_module(module)
        for name in names:
            value = getattr(owner, name)
            if hasattr(value, "delay") and hasattr(value, "name"):
                tasks[name] = value
    assert len(tasks) == 20, sorted(tasks)
    for name, task in tasks.items():
        assert task.name.startswith("ccure."), (name, task.name)
        registered = celery_app.tasks[task.name]
        assert registered is task or registered is task._get_current_object(), name


def test_every_beat_entry_and_route_names_a_registered_task():
    from core.celery_app import celery_app

    celery_app.loader.import_default_modules()
    registered = set(celery_app.tasks)
    beat = {entry["task"] for entry in celery_app.conf.beat_schedule.values()}
    assert beat and beat <= registered, sorted(beat - registered)
    routes = set(celery_app.conf.task_routes or {})
    assert routes <= registered, sorted(routes - registered)
