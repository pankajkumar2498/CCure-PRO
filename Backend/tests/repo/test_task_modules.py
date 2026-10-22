"""
The scan tasks split out of core/tasks.py (G1, C2), and the facade left behind.

G1 moved every scan task and its helpers into ``scans/tasks/``
(docs/architecture/MODULAR_REFACTORING_LOG.md §6). ``core/tasks.py`` now
re-exports them, which keeps ``from core.tasks import X`` working — and
creates the hazard these tests exist for:

* **A patch through the facade replaces nothing.** ``patch("core.tasks.X")``
  rebinds the facade's name; the task code reads its own module's binding and
  runs the real ``X``. The test passes believing it replaced it. The facade
  refuses such a patch at run time, and the first test below refuses one in the
  source, whatever form it takes.
* **A patch on the wrong task module replaces nothing either.**
  ``scans.tasks.phases`` imports ``_settle_failure`` from ``common``;
  ``mark_scan_failed`` is read inside ``_settle_failure``, so it must be
  patched on ``common``. A patch must name a module whose own code reads the
  name. The second test checks every patch on a task module does.

Also here: the facade still offers every name the hub defined, as the same
objects, and the worker loads the task modules, not the facade.
"""

import ast
import importlib
import pkgutil
from pathlib import Path

import pytest
from testpaths import BACKEND_ROOT

TESTS_DIR = BACKEND_ROOT / "tests"
TASKS_DIR = BACKEND_ROOT / "scans" / "tasks"
FACADE = "core.tasks"

#: Every top-level name core/tasks.py defined before G1 (92c224c): its
#: functions, tasks and constants, and the five mail tasks it re-exported.
HUB_NAMES = frozenset(
    {
        "log",
        "_strip_nul",
        "_new_orchestrator",
        "_bind_scan_scope",
        "_run_async",
        "_finalize_cancelled",
        "_settle_failure",
        "_check_cancelled",
        "_update_task_id",
        "_merge_host_identity",
        "_assessed_config_definition_ids",
        "_sync_credentialed_asset_identity",
        "_extract_credentialed_identity_names",
        "_unique_lines",
        "_clean_text",
        "_normalize_mac",
        "_credentialed_sections_with_identity",
        "_port_int",
        "_sync_credentialed_services",
        "_first_advisory",
        "_sync_credentialed_vulnerabilities",
        "sync_asset_discovery_task",
        "sync_vulnerability_audit_task",
        "sync_host_discovery_task",
        "run_host_discovery_task",
        "run_asset_discovery_task",
        "_credentialed_plan_for_scan",
        "_restate_findings_for_corrected_ports",
        "_upgrade_network_fingerprints",
        "_ports_probed_in_phase2",
        "_credential_for_host",
        "_as_credentialed_findings",
        "_apply_credentialed_enrichment",
        "run_vulnerability_audit_task",
        "_should_chain_topology",
        "_chain_topology_if_needed",
        "run_topology_mapping_task",
        "run_traditional_scan_task",
        "MAX_CREDENTIALED_TARGETS",
        "_run_configuration_audit",
        "_sync_configuration_compliance",
        "_hardening_row",
        "_credentialed_hardening_audits",
        "_resolve_stored_credential",
        "audit_credentialed_host",
        "audit_database_target",
        "_classify_credentialed_failure",
        "_is_transport_failure",
        "_audit_host_over_transport",
        "run_credentialed_scan_task",
        "send_account_approved_email_task",
        "send_mfa_otp_task",
        "send_password_changed_email_task",
        "send_password_reset_email_task",
        "send_verification_email_task",
        "expire_risk_acceptances",
        "reconcile_amt_inventory_task",
        "update_mac_vendor_registry_task",
        "_SCAN_SCHEDULER_LOCK_KEY",
        "run_due_scan_schedules",
        "reap_stalled_scans",
        "reap_stalled_web_scans",
    }
)

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
            continue  # this file patches the facade on purpose, to see it refuse
        visitor = _Patches()
        visitor.visit(ast.parse(path.read_text(encoding="utf-8")))
        rel = str(path.relative_to(BACKEND_ROOT))
        found += [(rel, line, module, attr) for line, module, attr in visitor.found]
    return found


def test_no_test_patches_through_the_facade():
    """
    Rebinding a name on the facade is what replaces nothing. Replacing an
    attribute *of* an object reached through it (a task's ``.delay``) changes
    the shared object and works from anywhere, so it is not refused.
    """
    through = [
        f"{path}:{line}: {module}.{attr}"
        for path, line, module, attr in _all_patches()
        if module == FACADE and "." not in attr
    ]
    assert not through, (
        "core.tasks is a facade: a patch through it replaces nothing the task "
        "code reads. Patch the scans.tasks module whose code reads the name:\n  "
        + "\n  ".join(through)
    )


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


def test_the_facade_refuses_a_patch_and_names_where_to_make_it():
    from unittest.mock import patch

    import core.tasks as facade

    # monkeypatch.setattr calls setattr, which is refused; it also records the
    # attribute first and refused again restoring it at teardown, so a test
    # trying it fails twice, loudly. Plain setattr shows the refusal alone.
    with pytest.raises(AttributeError, match="scans.tasks.credentialed"):
        setattr(facade, "_resolve_stored_credential", lambda *a: {})
    with pytest.raises(AttributeError, match="compatibility facade"):
        with patch("core.tasks.SessionLocal_never_defined", create=True):
            pass
    with pytest.raises(AttributeError):
        del facade.run_host_discovery_task
    # Nothing was replaced, and reading works as before.
    from scans.tasks.credentialed import _resolve_stored_credential

    assert facade._resolve_stored_credential is _resolve_stored_credential


def test_the_facade_offers_every_name_the_hub_defined_as_the_same_object():
    import core.tasks as facade

    offered = {n for n in vars(facade) if not n.startswith("__")}
    assert HUB_NAMES <= offered, sorted(HUB_NAMES - offered)
    loaded = {m: importlib.import_module(m) for m in _task_modules()}
    loaded["scans.scan_creation"] = importlib.import_module("scans.scan_creation")
    loaded["ccure_platform.identity.mail_tasks"] = importlib.import_module(
        "ccure_platform.identity.mail_tasks"
    )
    for name in HUB_NAMES:
        owners = [
            m
            for m, module in loaded.items()
            if name in vars(module) and vars(module)[name] is getattr(facade, name)
        ]
        assert owners, f"core.tasks.{name} is not the object its module defines"


def test_the_worker_loads_the_task_modules_and_not_the_facade():
    from core.celery_app import celery_app

    included = set(celery_app.conf.include)
    assert FACADE not in included
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
