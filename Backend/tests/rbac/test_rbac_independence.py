"""
RBAC-1 — independence: RBAC is a platform capability that loads, runs and is
tested without any product module.

Two kinds of proof. A **poisoned import** (a fresh interpreter in which importing
any product module raises) shows the capability really loads without them, which
no static rule can show. And the **layer rules** are exercised against synthetic
edges, so each one is shown to bite — a rule that never fails proves nothing.
"""

from __future__ import annotations

import ast
import subprocess
import sys
import textwrap

import pytest

from scripts.architecture.import_graph import Edge, collect_edges
from scripts.architecture.layer_rules import RULES, violations
from testpaths import BACKEND_ROOT

RBAC = BACKEND_ROOT / "ccure_platform" / "rbac"
RBAC_RULES = {
    "rbac-is-module-agnostic",
    "modules-use-rbac-api-only",
    "rbac-tables-are-private",
}

PRODUCT_PREFIXES = (
    "ccure_audit",
    "ccure_policy",
    "ccure_rank",
    "ccure_example",
    "ccure_contracts",
    "routers",
    "scans",
    "engines",
    "orchestrator",
    "reporting",
    "scan_helpers",
    "main",
)

POISON = textwrap.dedent(
    """
    import importlib.abc, sys

    BLOCKED = {blocked!r}

    class Poison(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path, target=None):
            if name.split(".")[0] in BLOCKED:
                raise ImportError("RBAC reached a product module: " + name)
            return None

    sys.meta_path.insert(0, Poison())

    from ccure_platform.rbac import (
        audit, catalogue, contract, engine, governance, model, resolver, shadow,
    )
    from ccure_platform.rbac import contract as c

    cat = {{
        "x.y.read": c.Permission(
            key="x.y.read", module="x", resource="y", action="read", description="d",
            scope_kind="organization", sensitivity="normal", delegable_to_org_roles=True,
            continuity=False, status="active"),
    }}
    me = c.Principal(kind="human", principal_id="u", home_org_id="o")
    grant = c.Grant(permission_key="x.y.read", assignment_scope="organization", scope_org_id="o")
    assert engine.decide(me, [grant], cat, "x.y.read").allowed
    assert not engine.decide(me, [], cat, "x.y.read").allowed

    problems = catalogue.validate_declarations(
        [c.ModuleDeclarations(module_key="m", namespace="x", permissions=(
            c.PermissionDecl(key="x.y.read", description="d", scope_kind="organization"),))],
        known_roles={{}},
    )
    assert problems == [], problems

    leaked = sorted(n for n in sys.modules if n.split(".")[0] in BLOCKED)
    assert not leaked, leaked
    print("INDEPENDENT")
    """
)


def run_poisoned():
    return subprocess.run(
        [sys.executable, "-c", POISON.format(blocked=PRODUCT_PREFIXES)],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        timeout=180,
    )


def test_rbac_loads_and_decides_with_every_product_module_unimportable():
    result = run_poisoned()
    assert result.returncode == 0, result.stderr[-2000:]
    assert "INDEPENDENT" in result.stdout


def test_the_poison_actually_bites():
    """A poisoned import that cannot fail proves nothing: importing a product
    module in the same interpreter must raise."""
    script = POISON.format(blocked=PRODUCT_PREFIXES).split(
        "from ccure_platform.rbac import ("
    )[0]
    script += "import ccure_audit\n"
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode != 0 and "RBAC reached a product module" in result.stderr


def test_no_rbac_source_imports_a_product_module():
    offenders = []
    for path in sorted(RBAC.glob("*.py")):
        if path.name in ("dependencies.py", "__init__.py"):
            continue  # the legacy authority, until RBAC-8
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            for name in names:
                if name.split(".")[0] in PRODUCT_PREFIXES or name.startswith(
                    (
                        "ccure_platform.modules",
                        "ccure_platform.composition",
                        "ccure_platform.api",
                    )
                ):
                    offenders.append(f"{path.name}: {name}")
    assert not offenders, offenders


def test_rbac_knows_no_list_of_modules():
    """The registry's product names do not appear in the capability's code."""
    for path in sorted(RBAC.glob("*.py")):
        if path.name in ("dependencies.py", "__init__.py"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert node.value not in {
                    "audit",
                    "policy_pro",
                    "policy",
                    "rank",
                    "ir",
                }, (
                    path.name,
                    node.value,
                )


def test_the_capability_has_the_responsibilities_the_design_names():
    assert {p.stem for p in RBAC.glob("*.py")} >= {
        "contract",
        "catalogue",
        "model",
        "resolver",
        "engine",
        "governance",
        "audit",
        "shadow",
        "dependencies",  # legacy, kept until RBAC-8
    }


def test_the_contract_module_is_standard_library_only():
    tree = ast.parse((RBAC / "contract.py").read_text(encoding="utf-8"))
    allowed = {"__future__", "re", "dataclasses", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module
        elif isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name


# ── the layer rules, shown to bite ───────────────────────────────────────────


def test_the_repository_has_no_rbac_layer_violations():
    _, edges = collect_edges()
    found = {(r, e.src, e.dst) for r, e in violations(edges) if r in RBAC_RULES}
    assert not found, sorted(found)


@pytest.mark.parametrize("name", sorted(RBAC_RULES))
def test_the_rbac_rules_are_registered(name):
    assert name in {rule.name for rule in RULES}


@pytest.mark.parametrize(
    "src,dst,rule",
    [
        (
            "ccure_platform.rbac.engine",
            "ccure_audit.services.assets",
            "rbac-is-module-agnostic",
        ),
        (
            "ccure_platform.rbac.catalogue",
            "ccure_policy.models",
            "rbac-is-module-agnostic",
        ),
        (
            "ccure_platform.rbac.resolver",
            "scans.scan_access",
            "rbac-is-module-agnostic",
        ),
        (
            "ccure_platform.rbac.governance",
            "db.models.scans",
            "platform-is-shared-foundation",
        ),
        (
            "ccure_platform.rbac.engine",
            "ccure_platform.modules.registry",
            "rbac-is-module-agnostic",
        ),
        (
            "ccure_platform.rbac.catalogue",
            "ccure_platform.composition",
            "rbac-is-module-agnostic",
        ),
        ("ccure_platform.rbac.engine", "ccure_platform.api", "rbac-is-module-agnostic"),
        (
            "ccure_platform.rbac.model",
            "ccure_platform.identity.dependencies",
            "rbac-is-module-agnostic",
        ),
        ("routers.scans", "ccure_platform.rbac.engine", "modules-use-rbac-api-only"),
        ("core.tasks", "ccure_platform.rbac.resolver", "modules-use-rbac-api-only"),
        (
            "ccure_audit.services.x",
            "ccure_platform.rbac.governance",
            "modules-use-rbac-api-only",
        ),
        (
            "ccure_policy.api",
            "ccure_platform.rbac.contract",
            "modules-use-rbac-api-only",
        ),
        (
            "routers.scans",
            "ccure_platform.models.rbac_tables",
            "rbac-tables-are-private",
        ),
        (
            "ccure_audit.x",
            "ccure_platform.models.rbac_tables",
            "rbac-tables-are-private",
        ),
        (
            "ccure_rank.models",
            "ccure_platform.models.rbac_tables",
            "rbac-tables-are-private",
        ),
    ],
)
def test_each_rule_catches_the_edge_it_exists_for(src, dst, rule):
    found = {r for r, _ in violations([Edge(src, dst, False)])}
    assert rule in found, (src, dst, found)


@pytest.mark.parametrize(
    "src,dst",
    [
        ("ccure_platform.api", "ccure_platform.rbac.contract"),
        ("ccure_platform.api", "ccure_platform.rbac.resolver"),
        ("ccure_platform.composition", "ccure_platform.rbac.catalogue"),
        ("ccure_platform.composition", "ccure_platform.modules.registry"),
        ("db.models", "ccure_platform.models.rbac_tables"),
        ("ccure_platform.rbac.model", "ccure_platform.models.rbac_tables"),
        ("ccure_platform.rbac.audit", "ccure_platform.audit_log.writer"),
        ("ccure_platform.rbac.dependencies", "ccure_platform.identity.dependencies"),
        ("routers.scans", "ccure_platform.api"),
        ("ccure_audit.x", "ccure_platform.api"),
    ],
)
def test_what_is_allowed_stays_allowed(src, dst):
    assert not {r for r, _ in violations([Edge(src, dst, False)]) if r in RBAC_RULES}


def test_a_module_cannot_import_rbac_internals_even_inside_a_function():
    _, edges = collect_edges()
    lazy = [e for e in edges if e.lazy and e.dst.startswith("ccure_platform.rbac.")]
    assert all(
        e.src.startswith("ccure_platform") or e.src == "db.models" for e in lazy
    ), lazy
