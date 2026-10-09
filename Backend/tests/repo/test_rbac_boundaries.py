"""
RBAC boundaries — RBAC-1.

Beyond the layer rules (``tests/rbac/test_rbac_independence.py``), three things a
dependency graph cannot see:

* **rbac-tables-are-private** — no module code names an ``rbac_*`` table or imports
  one of its models, so a module cannot read roles and assignments and decide for
  itself;
* **no-module-decision-engine** — no module defines its own permission or role
  check; the decision is the platform's;
* **ownership** — every new table is the platform's, in the registry.

Measured from source; nothing is imported.
"""

from __future__ import annotations

import ast
import re

import yaml

from scripts.architecture import identity_boundary as ib
from testpaths import BACKEND_ROOT

RBAC_TABLES = (
    "rbac_permissions",
    "rbac_roles",
    "rbac_role_revisions",
    "rbac_role_permissions",
    "rbac_user_roles",
    "rbac_default_roles",
)
FORBIDDEN_TABLES = (*RBAC_TABLES, "rbac_legacy_map")
RBAC_MODELS = (
    "RbacPermission",
    "RbacRole",
    "RbacRoleRevision",
    "RbacRolePermission",
    "RbacUserRole",
    "RbacDefaultRole",
    "RbacLegacyMap",
)

#: Code that is the platform, the composition root, the schema layer or operator
#: tooling — allowed to name the tables.
PLATFORM_SIDE = ("ccure_platform", "db", "alembic", "tests", "scripts", "__pycache__")


def module_code():
    for path in sorted(BACKEND_ROOT.rglob("*.py")):
        parts = path.relative_to(BACKEND_ROOT).parts
        if parts[0] in PLATFORM_SIDE or parts[0] in {".venv", "venv", "node_modules"}:
            continue
        if parts == ("main.py",):
            continue
        yield path


def test_no_module_code_names_an_rbac_table():
    pattern = re.compile(r"\b(" + "|".join(FORBIDDEN_TABLES) + r")\b")
    offenders = []
    for path in module_code():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                offenders.append(
                    f"{path.relative_to(BACKEND_ROOT)}:{lineno}: {line.strip()[:80]}"
                )
    assert not offenders, offenders


def test_no_module_code_imports_an_rbac_model():
    offenders = []
    for path in module_code():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom):
                if {a.name for a in node.names} & set(RBAC_MODELS):
                    offenders.append(str(path.relative_to(BACKEND_ROOT)))
                if (node.module or "").startswith("ccure_platform.models.rbac_tables"):
                    offenders.append(str(path.relative_to(BACKEND_ROOT)))
    assert not offenders, offenders


def test_the_identity_ratchet_counts_a_module_importing_an_rbac_model():
    """The models are in IDENTITY_MODELS, so the existing ratchet would also see it."""
    assert set(RBAC_MODELS) <= ib.IDENTITY_MODELS
    sites = ib.scan_source("core.example", "from db.models import RbacRole\n")
    assert [(s.kind, s.what) for s in sites] == [("import", "db.models.RbacRole")]
    # while an ordinary Audit model is not an identity import
    assert ib.scan_source("core.example", "from db.models import Scan\n") == []


#: Names that mean "decide whether this account may do that". A module defines
#: none of them: it declares permissions and asks the platform.
DECISION_NAMES = re.compile(
    r"^(authorize|has_permission|user_has_permission|check_permission|can_user|"
    r"require_permission|require_role|is_authorized|effective_permissions)$"
)


def test_no_module_defines_its_own_decision_function():
    offenders = []
    for path in module_code():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and DECISION_NAMES.match(node.name):
                offenders.append(
                    f"{path.relative_to(BACKEND_ROOT)}:{node.lineno} {node.name}"
                )
    assert not offenders, offenders


def test_the_decision_name_check_bites():
    src = "def user_has_permission(db, user, a, b):\n    return True\n"
    names = [n.name for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)]
    assert any(DECISION_NAMES.match(n) for n in names)
    assert not DECISION_NAMES.match("can_export_report")


def test_every_rbac_table_is_in_the_ownership_registry_as_the_platforms():
    data = yaml.safe_load(
        (BACKEND_ROOT / "scripts" / "architecture" / "table_ownership.yaml").read_text()
    )
    for table in RBAC_TABLES:
        assert data["tables"][table] == {"owner": "platform", "capability": "rbac"}


def test_the_new_tables_are_not_in_any_module_schema():
    from ccure_platform.modules import registry

    for module in registry.modules():
        for md in registry.module_metadatas(module):
            assert not set(RBAC_TABLES) & {t.name for t in md.tables.values()}


def test_the_platform_api_exports_no_rbac_model_or_implementation_class():
    import ccure_platform.api as api

    exported = set(api.__all__)
    assert not exported & set(RBAC_MODELS)
    for name in ("RbacRole", "ShadowRecorder", "Violation", "CatalogueError", "decide"):
        assert name not in exported


# ── RBAC-3: where shadow authorization is reached from ───────────────────────


def test_only_the_legacy_guards_reach_the_shadow_runtime():
    """RBAC-3 hooks shadow comparison into the legacy guards and nowhere else: no
    router, task, service or module calls the shadow."""
    offenders = []
    for path in sorted(BACKEND_ROOT.rglob("*.py")):
        parts = path.relative_to(BACKEND_ROOT).parts
        if parts[0] in {"tests", ".venv", "venv", "alembic", "__pycache__", "scripts"}:
            continue
        rel = path.relative_to(BACKEND_ROOT).as_posix()
        if rel in ("ccure_platform/rbac/dependencies.py",) or rel.startswith(
            "ccure_platform/rbac/shadow"
        ):
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.ImportFrom):
                names = [node.module or "", *[a.name for a in node.names]]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.Name):
                names = [node.id]
            if any(
                "shadow_runtime" in n
                or n in ("shadow_compare", "observe_permission", "observe_role_check")
                or n.endswith("rbac.shadow")
                for n in names
            ):
                offenders.append(rel)
    assert not offenders, sorted(set(offenders))


def test_the_platform_api_exports_nothing_about_shadow():
    import ccure_platform.api as api

    assert not [n for n in api.__all__ if "shadow" in n.lower()]


def test_modules_cannot_import_the_shadow_or_the_legacy_map():
    from scripts.architecture.import_graph import Edge
    from scripts.architecture.layer_rules import violations

    for dst in (
        "ccure_platform.rbac.shadow",
        "ccure_platform.rbac.shadow_runtime",
        "ccure_platform.rbac.legacy_map",
        "ccure_platform.rbac.offboarding",
    ):
        found = {r for r, _ in violations([Edge("routers.scans", dst, False)])}
        assert "modules-use-rbac-api-only" in found, dst
        found = {r for r, _ in violations([Edge("ccure_audit.services.x", dst, False)])}
        assert "modules-use-rbac-api-only" in found, dst


def test_the_rbac_package_stays_independent_of_every_product():
    for path in sorted((BACKEND_ROOT / "ccure_platform" / "rbac").glob("*.py")):
        name = path.name
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            mods = (
                [node.module or ""]
                if isinstance(node, ast.ImportFrom)
                else (
                    [a.name for a in node.names] if isinstance(node, ast.Import) else []
                )
            )
            for mod in mods:
                assert not mod.startswith(
                    (
                        "ccure_audit",
                        "ccure_policy",
                        "ccure_rank",
                        "ccure_ir",
                        "routers",
                        "scans",
                        "core",
                        "engines",
                    )
                ), (name, mod)
