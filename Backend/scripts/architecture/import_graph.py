"""
The backend's import graph, measured from source.

Every application module under ``Backend/`` is parsed with ``ast`` — nothing is
imported, so measuring never runs application code. An edge is recorded for each
``import`` / ``from … import`` that names another application module, and is
marked *lazy* when the import sits inside a function. Lazy imports count as real
dependencies: they are how this codebase hides its cycles from the interpreter,
and a dependency that only resolves at call time is still a dependency.

This is the measurement behind ``docs/architecture/MODULE_INDEPENDENCE_BASELINE.md``
and the input to ``tests/repo/test_architecture_guardrails.py``.

    python -m scripts.architecture.import_graph            # summary
    python -m scripts.architecture.import_graph --json     # machine-readable
    python -m scripts.architecture.import_graph --violations

Run from ``Backend/``.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[2]

#: Directories under Backend/ that are not application code.
SKIP_DIRS = frozenset(
    {"tests", "scripts", "alembic", "__pycache__", "logs", "reports", "data"}
)

# ── Component grouping ────────────────────────────────────────────────────────
# Flat modules in core/ grouped by what they are for, so the component graph
# reads as capabilities rather than 70 files. Packages under core/ and engines/
# are components in their own right.
_CORE_GROUPS = {
    "core.infra": {
        "celery_app",
        "redis_client",
        "rate_limit_middleware",
        "rate_limit_audit",
        "ip_resolver",
        "throttle",
        "security_crypto",
        "utils",
        "constants",
        "user_agent",
        "upload_guard",
        "models",
    },
    "core.audit": {
        "audit",
        "audit_retention",
        "audit_taxonomy",
        "audit_event_translator",
    },
    "core.compliance": {
        "compliance_evidence",
        "compliance_sync",
        "compliance_frameworks",
        "compliance_seeds",
        "compliance_tasks",
        "nist_csf",
        "nist_csf_catalogue",
    },
    "core.assets": {
        "asset_correlation",
        "amt_reconciliation",
        "device_classifier",
        "mac",
        "oui_lookup",
    },
    "core.scanctl": {"scan_control", "scan_scope", "risk"},
    "core.vulnintel": {"cve_database", "vuln_intel"},
    "core.email_security": {"email_security_tasks"},
    "core.tasks": {"tasks"},
}
_CORE_LOOKUP = {name: group for group, names in _CORE_GROUPS.items() for name in names}


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    lazy: bool


def component(module: str) -> str:
    """The component a dotted module name belongs to."""
    parts = module.split(".")
    top = parts[0]
    if top == "core":
        if len(parts) == 1:
            return "core"
        return _CORE_LOOKUP.get(parts[1], f"core.{parts[1]}")
    if top == "db":
        return "db.models" if len(parts) >= 3 and parts[1] == "models" else "db"
    if top == "engines":
        return f"engines.{parts[1]}" if len(parts) > 1 else "engines"
    if top == "ccure_platform":
        # identity, rbac and the models are separate components: the legacy
        # db.models stubs import the platform's models, not its sign-in router.
        return f"ccure_platform.{parts[1]}" if len(parts) > 1 else "ccure_platform"
    if top == "routers":
        return "routers"
    return top


def discover_modules(root: Path = BACKEND_ROOT) -> dict[str, Path]:
    """Every application module: dotted name → file."""
    modules: dict[str, Path] = {}
    for path in root.rglob("*.py"):
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS or part.startswith(".") for part in rel.parts[:-1]):
            continue
        name = ".".join(rel.with_suffix("").parts)
        if name.endswith(".__init__"):
            name = name[: -len(".__init__")]
        modules[name] = path
    return modules


def _resolve(target: str, modules: dict[str, Path]) -> str | None:
    """The longest application module that `target` names, if any."""
    parts = target.split(".")
    for i in range(len(parts), 0, -1):
        candidate = ".".join(parts[:i])
        if candidate in modules:
            return candidate
    return None


def collect_edges(root: Path = BACKEND_ROOT) -> tuple[dict[str, Path], list[Edge]]:
    """Parse every module and return (modules, edges between them)."""
    modules = discover_modules(root)
    tops = {name.split(".")[0] for name in modules}
    edges: list[Edge] = []
    for module, path in sorted(modules.items()):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):  # pragma: no cover
            continue
        package = module if path.name == "__init__.py" else module.rpartition(".")[0]

        inside_function: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                inside_function.update(id(child) for child in ast.walk(node))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    anchor = package.split(".") if package else []
                    if node.level > 1:
                        anchor = anchor[: len(anchor) - (node.level - 1)]
                    base = ".".join(anchor + ([base] if base else []))
                targets = [f"{base}.{alias.name}" for alias in node.names] + [base]
            else:
                continue
            seen: set[str] = set()
            for target in targets:
                if not target or target.split(".")[0] not in tops:
                    continue
                resolved = _resolve(target, modules)
                if resolved and resolved != module and resolved not in seen:
                    seen.add(resolved)
                    edges.append(Edge(module, resolved, id(node) in inside_function))
    return modules, edges


def strongly_connected(graph: dict[str, set[str]]) -> list[frozenset[str]]:
    """Tarjan's algorithm, iterative. Returns only components larger than one."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    result: list[frozenset[str]] = []
    counter = 0

    for start in sorted(graph):
        if start in index:
            continue
        work = [(start, iter(sorted(graph.get(start, ()))))]
        index[start] = low[start] = counter
        counter += 1
        stack.append(start)
        on_stack.add(start)
        while work:
            node, children = work[-1]
            advanced = False
            for child in children:
                if child not in index:
                    index[child] = low[child] = counter
                    counter += 1
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, iter(sorted(graph.get(child, ())))))
                    advanced = True
                    break
                if child in on_stack:
                    low[node] = min(low[node], index[child])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                members = set()
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    members.add(member)
                    if member == node:
                        break
                if len(members) > 1:
                    result.append(frozenset(members))
    return result


def module_cycles(edges: list[Edge]) -> list[frozenset[str]]:
    graph: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        graph[edge.src].add(edge.dst)
    return strongly_connected(graph)


def summary(modules: dict[str, Path], edges: list[Edge]) -> dict:
    """The figures the baseline document reports."""
    all_graph: dict[str, set[str]] = defaultdict(set)
    top_graph: dict[str, set[str]] = defaultdict(set)
    lazy_cross = 0
    for edge in edges:
        a, b = component(edge.src), component(edge.dst)
        if a == b:
            continue
        all_graph[a].add(b)
        if edge.lazy:
            lazy_cross += 1
        else:
            top_graph[a].add(b)
    components = sorted({component(m) for m in modules})
    for c in components:
        all_graph.setdefault(c, set())
        top_graph.setdefault(c, set())
    fan_in = Counter(dst for deps in all_graph.values() for dst in deps)
    largest_all = max((len(s) for s in strongly_connected(all_graph)), default=1)
    largest_top = max((len(s) for s in strongly_connected(top_graph)), default=1)
    return {
        "modules": len(modules),
        "edges": len(edges),
        "components": len(components),
        "largest_component_cycle_all_imports": largest_all,
        "largest_component_cycle_top_level_only": largest_top,
        "cross_component_lazy_imports": lazy_cross,
        "fan_out": {c: len(all_graph[c]) for c in components},
        "fan_in": {c: fan_in.get(c, 0) for c in components},
        "module_cycles": sorted(sorted(c) for c in module_cycles(edges)),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--json", action="store_true", help="print the summary as JSON")
    parser.add_argument(
        "--violations",
        action="store_true",
        help="list every edge that breaks a layer rule in layer_rules.py",
    )
    args = parser.parse_args(argv)

    modules, edges = collect_edges()
    if args.violations:
        from scripts.architecture.layer_rules import violations

        for rule, edge in sorted(
            violations(edges), key=lambda v: (v[0], v[1].src, v[1].dst)
        ):
            print(
                f"{rule:24s} {edge.src} -> {edge.dst}{'  (lazy)' if edge.lazy else ''}"
            )
        return 0

    data = summary(modules, edges)
    if args.json:
        json.dump(data, sys.stdout, indent=2, sort_keys=True)
        print()
        return 0
    print(
        f"modules {data['modules']}  edges {data['edges']}  components {data['components']}"
    )
    print(
        f"largest component cycle: {data['largest_component_cycle_all_imports']} "
        f"(all imports), {data['largest_component_cycle_top_level_only']} (top-level only)"
    )
    print(f"cross-component lazy imports: {data['cross_component_lazy_imports']}")
    print("module-level cycles:")
    for cycle in data["module_cycles"]:
        print("  ", " <-> ".join(cycle))
    print("component fan-out / fan-in:")
    for c in sorted(data["fan_out"], key=lambda k: -data["fan_out"][k]):
        print(f"   {c:26s} out={data['fan_out'][c]:2d} in={data['fan_in'][c]:2d}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
