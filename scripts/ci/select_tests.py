#!/usr/bin/env python3
"""Choose the smallest meaningful test set for a change.

One mapping, used by the pull-request CI jobs and by AI agents and developers
working locally, so that "which tests does this change need" has one answer.

    python scripts/ci/select_tests.py --base origin/master          # a branch
    python scripts/ci/select_tests.py --files Backend/core/risk.py  # explicit
    python scripts/ci/select_tests.py --full                        # everything

Output is JSON on stdout. With --github-output the same values are appended to
$GITHUB_OUTPUT for a workflow step.

The rule is conservative in one direction only: a path this file does not
recognise widens the selection (backend: the whole suite; frontend: the whole
vitest run). It never narrows it. A change that touches the test harness,
the database models, a migration, a dependency pin or application wiring is
cross-cutting and also selects everything.

Stdlib only: it runs before any dependency is installed.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import subprocess
import sys
from functools import lru_cache
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND = REPO_ROOT / "Backend"

# Every backend selection includes these. They hold the repository-wide
# invariants (architecture ratchets, documentation integrity, route inventory,
# RBAC route coverage, tenant isolation) that a change anywhere can break.
BASELINE = ("repo", "security")

# A change to shared platform code can break any module that consumes it, but
# not scanning internals.
PLATFORM = BASELINE + ("auth", "rbac", "audit", "audit_boundary", "modules")

SCANNING = BASELINE + ("scans", "credentialed")

KNOWN_GROUPS = frozenset(
    "auth security compliance scans assets topology credentialed web reports repo rbac audit audit_boundary modules".split()
)

# Backend/<top-level> -> test groups. A key ending in "/" is a directory prefix.
BACKEND_AREAS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ccure_platform/", PLATFORM),
    ("auth/", PLATFORM),
    ("ccure_audit/", BASELINE + ("audit", "audit_boundary")),
    ("ccure_contracts/", BASELINE + ("audit_boundary",)),
    ("ccure_policy/", BASELINE + ("modules",)),
    ("ccure_rank/", BASELINE + ("modules",)),
    ("reporting/", BASELINE + ("reports", "scans")),
    ("scans/", SCANNING + ("reports",)),
    ("orchestrator/", SCANNING),
    ("scan_helpers.py", SCANNING + ("reports",)),
    ("engines/credentialed/", SCANNING),
    ("engines/web/", BASELINE + ("web",)),
    ("engines/", SCANNING + ("web",)),
    ("core/web/", BASELINE + ("web",)),
    ("core/compliance", BASELINE + ("compliance",)),
    ("core/topology", BASELINE + ("topology",)),
    ("core/", SCANNING + ("compliance", "assets")),
    ("data/compliance_seeds/", BASELINE + ("compliance",)),
    ("data/benchmarks/", BASELINE + ("compliance", "scans")),
    ("data/", BASELINE + ("compliance", "scans")),
    ("Dockerfile", BASELINE),
    # The generated API contract: CI's OpenAPI diff step is the gate; these are
    # the groups that read the documented surface.
    ("openapi.json", BASELINE + ("web", "reports")),
    # A migration is proven by the round-trip step (migrations=true), the
    # schema-drift and ownership tests in repo/, and the modules that own tables.
    ("alembic/", PLATFORM + ("compliance",)),
    ("scripts/architecture/", BASELINE),
    ("scripts/", BASELINE + ("compliance",)),
)

# Routers are the HTTP edge: the file name says which group exercises it.
ROUTER_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("compliance", BASELINE + ("compliance",)),
    ("report", BASELINE + ("reports",)),
    ("asset", BASELINE + ("assets",)),
    ("topology", BASELINE + ("topology",)),
    ("web", BASELINE + ("web",)),
    ("credential", BASELINE + ("credentialed",)),
    ("scan", SCANNING),
    ("finding", SCANNING),
    ("remediation", SCANNING),
)

# Backend paths whose change can alter every module's behaviour.
BACKEND_CROSS_CUTTING = (
    "db/",
    "main.py",
    "config.py",
    "requirements.txt",
    "pytest.ini",
    "tests/conftest.py",
    "tests/native_rbac.py",
    "tests/rbac_testing.py",
    "tests/testpaths.py",
)

# Paths that need no backend test beyond the baseline (documentation, CI
# definitions, the frontend). The baseline already carries the docs-integrity
# and workflow tests that read them.
BASELINE_ONLY = (
    "docs/",
    "Frontend/",
    "gateway/",
    ".github/",
    "scripts/",
    "README.md",
    "CLAUDE.md",
    "AGENTS.md",
)

# Frontend paths that change what every vitest file sees.
FRONTEND_CROSS_CUTTING = (
    "package.json",
    "package-lock.json",
    "vite.config.js",
    "modules.config.js",
    "jsconfig.json",
    "ux4g-baseline.json",
    "ux4g-ui-exceptions.json",
    "authorization-inventory.json",
    "src/__tests__/setupTests.js",
    "src/__tests__/testPaths.js",
    "src/__tests__/helpers/",
    "src/__tests__/fixtures/",
    "src/design-system/",
    "src/shell/",
    "src/styles/",
    "src/App.jsx",
    "src/main.jsx",
    "scripts/",
)

# Frontend paths whose effect is visual or accessibility-related, so the unit
# tests cannot vouch for them. A pull request touching one runs the Chromium
# suite; otherwise Chromium runs only in the full scope.
FRONTEND_BROWSER_PATHS = (
    "browser-tests/",
    "playwright.config.mjs",
    "scripts/ux4g-harness/",
    "src/design-system/",
    "src/styles/",
    "ux4g-ui-exceptions.json",
)

MIGRATION_PATHS = (
    "Backend/alembic/",
    "Backend/db/",
    "Backend/ccure_policy/migrations/",
    "Backend/ccure_rank/migrations/",
)
CODE_SUFFIXES = (".js", ".jsx", ".mjs")


def changed_files(base: str) -> list[str]:
    out = subprocess.check_output(
        ["git", "diff", "--name-only", base, "HEAD"], text=True
    )
    return [line.strip() for line in out.splitlines() if line.strip()]


def _startswith_any(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(
        path.startswith(p) if p.endswith("/") or "." not in p else path == p
        for p in prefixes
    )


def backend_groups(path: str) -> tuple[str, ...] | None:
    """Test groups for one Backend-relative path; None means "run everything"."""
    if _startswith_any(path, BACKEND_CROSS_CUTTING):
        return None
    if path.startswith("tests/"):
        parts = PurePosixPath(path).parts
        if len(parts) > 2 and parts[1] in KNOWN_GROUPS:
            return (parts[1],) + BASELINE
        if path.endswith((".md", ".txt")):
            return BASELINE  # documentation beside the tests, e.g. tests/README.md
        return None
    if path.startswith("routers/"):
        stem = PurePosixPath(path).stem
        for hint, groups in ROUTER_HINTS:
            if hint in stem:
                return groups
        return PLATFORM
    for prefix, groups in BACKEND_AREAS:
        if path.startswith(prefix):
            return groups
    return None


def _module_name(rel: str) -> str | None:
    """Dotted module for a Backend-relative .py path, or None."""
    if not rel.endswith(".py"):
        return None
    parts = list(PurePosixPath(rel).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or None


@lru_cache(maxsize=1)
def _test_references() -> tuple[dict[str, set[str]], dict[str, str]]:
    """(group -> every dotted name its tests import or patch, test module -> group).

    The ownership table above says who a file belongs to; this says who
    actually uses it. A test that imports `core.tasks` or patches
    "scans.progress.x" exercises that module whichever group it lives in, and
    a hand-kept table cannot keep up with that (87 such cases were missing when
    it was first checked against the tests). Names are collected from imports
    and from string constants, which is how mock.patch refers to a module.
    """
    refs: dict[str, set[str]] = {}
    test_mod_group: dict[str, str] = {}
    tests = BACKEND / "tests"
    if not tests.is_dir():
        return refs, test_mod_group
    for path in tests.rglob("test_*.py"):
        rel = path.relative_to(tests).parts
        if len(rel) < 2 or rel[0] not in KNOWN_GROUPS:
            continue
        group = rel[0]
        test_mod_group[path.stem] = group
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        names = refs.setdefault(group, set())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module)
                names.update(f"{node.module}.{a.name}" for a in node.names)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                v = node.value
                if (
                    "." in v
                    and len(v) < 200
                    and v.replace(".", "").replace("_", "").isalnum()
                ):
                    names.add(v)
    return refs, test_mod_group


def importer_groups(module: str) -> set[str]:
    """Groups whose tests import or patch `module`, or something inside it."""
    refs, test_mod_group = _test_references()
    found = {
        group
        for group, names in refs.items()
        if module in names or any(n.startswith(module + ".") for n in names)
    }
    # A test file that other tests import by its bare name.
    leaf = module.rsplit(".", 1)[-1]
    if leaf in test_mod_group:
        found.add(test_mod_group[leaf])
        found.update(
            g
            for g, n in refs.items()
            if leaf in n or any(x.endswith("." + leaf) for x in n)
        )
    return found


def select_backend(files: list[str]) -> dict:
    groups: set[str] = set(BASELINE)
    reasons: list[str] = []
    for f in files:
        if f.startswith("Backend/"):
            rel = f[len("Backend/") :]
            chosen = backend_groups(rel)
            if chosen is None:
                return {
                    "scope": "full",
                    "groups": [],
                    "reason": f"{f} is cross-cutting or unmapped",
                }
            groups.update(chosen)
            module = _module_name(rel)
            if module:
                groups.update(importer_groups(module))
        elif not _startswith_any(f, BASELINE_ONLY) and "/" in f:
            # A top-level directory this file does not know: widen.
            return {"scope": "full", "groups": [], "reason": f"{f} is not mapped"}
    return {"scope": "targeted", "groups": sorted(groups), "reason": "; ".join(reasons)}


def select_frontend(files: list[str]) -> dict:
    rel = [f[len("Frontend/") :] for f in files if f.startswith("Frontend/")]
    if not rel:
        return {
            "scope": "none",
            "related": [],
            "browser": False,
            "reason": "no Frontend/ change",
        }
    browser = any(_startswith_any(f, FRONTEND_BROWSER_PATHS) for f in rel)
    for f in rel:
        if _startswith_any(f, FRONTEND_CROSS_CUTTING):
            reason = f"Frontend/{f} is cross-cutting"
            return {
                "scope": "full",
                "related": [],
                "browser": browser,
                "reason": reason,
            }
    related = [f for f in rel if f.startswith("src/") and f.endswith(CODE_SUFFIXES)]
    return {"scope": "targeted", "related": related, "browser": browser, "reason": ""}


def select(files: list[str], full: bool = False) -> dict:
    if full:
        return {
            "files": files,
            "backend": {"scope": "full", "groups": [], "reason": "full run requested"},
            "frontend": {
                "scope": "full",
                "related": [],
                "browser": True,
                "reason": "full run requested",
            },
            "migrations": True,
            "gateway": True,
        }
    return {
        "files": files,
        "backend": select_backend(files),
        "frontend": select_frontend(files),
        "migrations": any(f.startswith(MIGRATION_PATHS) for f in files),
        "gateway": any(
            f.startswith(("gateway/", "Backend/ccure_platform/identity/"))
            for f in files
        ),
    }


def pytest_args(backend: dict) -> list[str]:
    if backend["scope"] == "full":
        return []
    return [f"tests/{g}" for g in backend["groups"]]


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--base", help="git ref to diff HEAD against")
    ap.add_argument("--files", nargs="*", help="explicit repo-relative paths")
    ap.add_argument("--full", action="store_true", help="select everything")
    ap.add_argument("--github-output", action="store_true")
    args = ap.parse_args()

    if args.full:
        files: list[str] = []
    elif args.files is not None:
        files = args.files
    elif args.base:
        files = changed_files(args.base)
    else:
        ap.error("give --base, --files or --full")
    result = select(files, full=args.full)
    result["pytest_args"] = pytest_args(result["backend"])
    json.dump(result, sys.stdout, indent=2)
    print()

    out = os.environ.get("GITHUB_OUTPUT")
    if args.github_output and out:
        be, fe = result["backend"], result["frontend"]
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"backend_scope={be['scope']}\n")
            fh.write(f"pytest_args={' '.join(result['pytest_args'])}\n")
            fh.write(f"frontend_scope={fe['scope']}\n")
            fh.write(f"frontend_related={' '.join(fe['related'])}\n")
            fh.write(f"frontend_browser={str(fe['browser']).lower()}\n")
            fh.write(f"migrations={str(result['migrations']).lower()}\n")
            fh.write(f"gateway={str(result['gateway']).lower()}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
