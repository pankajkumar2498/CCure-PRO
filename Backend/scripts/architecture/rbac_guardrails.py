"""
RBAC guardrails, measured from source — RBAC-1 of the RBAC programme.

The frozen RBAC-0 design says authorization must never depend on a role's
identity: not its display name, not its key, not a legacy role name. Authorization
is permissions and scope. This file measures two things, and
``tests/repo/test_rbac_role_identity.py`` turns them into tests:

**1. The new RBAC implementation — zero tolerance.**
Everything under ``ccure_platform/rbac/`` except the legacy ``dependencies.py``.
In it:

* no string literal may be one of the five legacy role names or the five new
  system role keys. They are *seed data*, and the one place they may be written
  is ``contract.py``;
* no comparison may involve a role's ``name``, ``key``, ``display_name`` or
  ``role_key`` — outside ``catalogue.py``, whose sync reconciles the system roles
  to their declared grants and is seed-time code, not a request-time decision.

**2. The legacy authorization code — a ratchet.**
Existing code compares ``role.name`` to ``"superadmin"`` in a number of places and
calls ``require_role``. RBAC-1 is dark and must not fail the repository merely
because the legacy checks still exist; RBAC-4 removes them. So their count is
recorded per file and may only **fall**: a new site fails, and a recorded one that
disappears also fails until the baseline is lowered, so a removed check cannot
quietly come back.

Seed and migration contexts are exempt from the ratchet by design: ``alembic/``,
``tests/``, ``scripts/`` (operator tooling and bootstrap), and the legacy seed
``db/migrate_production_schema.py``.

Nothing is imported; every file is parsed with ``ast``. Run from ``Backend/``::

    python -m scripts.architecture.rbac_guardrails            # counts
    python -m scripts.architecture.rbac_guardrails --list     # every site
    python -m scripts.architecture.rbac_guardrails --baseline # paste-able dict
"""

from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from scripts.architecture.import_graph import BACKEND_ROOT

#: The five original role names — seed and legacy-map data, never a decision.
LEGACY_ROLE_NAMES = frozenset(
    {"superadmin", "org_admin", "analyst", "viewer", "scanner"}
)
#: The five system role keys of the new model.
SYSTEM_ROLE_KEYS = frozenset({f"platform.{n}" for n in LEGACY_ROLE_NAMES})
FORBIDDEN_LITERALS = LEGACY_ROLE_NAMES | SYSTEM_ROLE_KEYS

#: Attributes that name a role's identity (as opposed to its state or scope).
ROLE_IDENTITY_ATTRS = frozenset(
    {"name", "key", "display_name", "role_key", "role_name"}
)

RBAC_PACKAGE = "ccure_platform/rbac"
#: Legacy authority, still in the package until RBAC-8: not the new capability.
RBAC_LEGACY_FILES = frozenset(
    {"ccure_platform/rbac/dependencies.py", "ccure_platform/rbac/__init__.py"}
)
#: May hold role keys as seed data.
RBAC_SEED_FILES = frozenset({"ccure_platform/rbac/contract.py"})
#: Seed-time reconciliation; may compare a role's key to its declared grants.
RBAC_SYNC_FILES = frozenset({"ccure_platform/rbac/catalogue.py"})

#: Seed, bootstrap, migration and test contexts the ratchet does not measure.
EXEMPT_DIRS = frozenset(
    {
        ".venv",
        "venv",
        "tests",
        "alembic",
        "scripts",
        "__pycache__",
        "node_modules",
        "logs",
        "reports",
        "data",
    }
)
EXEMPT_FILES = frozenset(
    {
        "db/migrate_production_schema.py",  # the legacy role seed
        "ccure_platform/models/rbac_tables.py",
    }
)


@dataclass(frozen=True)
class Site:
    path: str
    line: int
    kind: str  # "role_literal" | "role_identity_compare" | "require_role"
    what: str


def _is_identity_expr(node: ast.AST) -> bool:
    """Whether ``node`` reads a role's identity: ``x.name`` / ``x.key`` /
    ``x.display_name``, ``getattr(x, "name")``, or a variable named for one."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and sub.attr in ROLE_IDENTITY_ATTRS:
            return True
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Name)
            and sub.func.id == "getattr"
            and len(sub.args) >= 2
            and isinstance(sub.args[1], ast.Constant)
            and sub.args[1].value in ROLE_IDENTITY_ATTRS
        ):
            return True
        if isinstance(sub, ast.Name) and (sub.id in ("role_name", "role_key")):
            return True
    return False


def _role_attr_expr(node: ast.AST) -> bool:
    """Stricter, for the new implementation: an identity attribute read off
    something role-shaped (``role.key``, ``self.role.name``, ``r.display_name``)."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and sub.attr in ROLE_IDENTITY_ATTRS:
            base = ast.unparse(sub.value).lower()
            if sub.attr == "display_name" or "role" in base or base in ("r", "row"):
                return True
    return False


def _literals(node: ast.AST) -> list[str]:
    out = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            if sub.value.lower() in FORBIDDEN_LITERALS:
                out.append(sub.value)
    return out


def scan_legacy_source(path: str, source: str) -> list[Site]:
    """Role-identity comparisons and ``require_role`` calls in legacy code."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    sites: list[Site] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            if any(_is_identity_expr(o) for o in operands):
                lits = [lit for o in operands for lit in _literals(o)]
                if lits:
                    sites.append(
                        Site(
                            path,
                            node.lineno,
                            "role_identity_compare",
                            ",".join(sorted(set(lits))),
                        )
                    )
        elif isinstance(node, ast.Call):
            func = node.func
            name = (
                func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            )
            if name == "require_role":
                sites.append(
                    Site(path, node.lineno, "require_role", "require_role(...)")
                )
    return sites


def scan_new_source(path: str, source: str) -> list[Site]:
    """Violations in the new RBAC implementation (zero tolerated)."""
    tree = ast.parse(source)
    sites: list[Site] = []
    if path not in RBAC_SEED_FILES:
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value.lower() in FORBIDDEN_LITERALS
            ):
                sites.append(Site(path, node.lineno, "role_literal", node.value))
    if path not in RBAC_SYNC_FILES and path not in RBAC_SEED_FILES:
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                if any(_role_attr_expr(o) for o in [node.left, *node.comparators]):
                    sites.append(
                        Site(
                            path,
                            node.lineno,
                            "role_identity_compare",
                            ast.unparse(node)[:80],
                        )
                    )
    return sites


def _rel(path: Path) -> str:
    return path.relative_to(BACKEND_ROOT).as_posix()


def _python_files():
    for path in sorted(BACKEND_ROOT.rglob("*.py")):
        rel = _rel(path)
        if any(
            part in EXEMPT_DIRS for part in path.relative_to(BACKEND_ROOT).parts[:-1]
        ):
            continue
        yield path, rel


def measure_new() -> list[Site]:
    out: list[Site] = []
    for path in sorted((BACKEND_ROOT / RBAC_PACKAGE).glob("*.py")):
        rel = _rel(path)
        if rel in RBAC_LEGACY_FILES:
            continue
        out.extend(scan_new_source(rel, path.read_text(encoding="utf-8")))
    return out


def measure_legacy() -> dict[str, dict[str, int]]:
    """``{file: {kind: count}}`` for legacy authorization code."""
    counts: dict[str, Counter] = defaultdict(Counter)
    for path, rel in _python_files():
        if rel in EXEMPT_FILES:
            continue
        if rel.startswith(RBAC_PACKAGE + "/") and rel not in RBAC_LEGACY_FILES:
            continue  # the new implementation: measured strictly, not here
        for site in scan_legacy_source(rel, path.read_text(encoding="utf-8")):
            counts[rel][site.kind] += 1
    return {f: dict(sorted(c.items())) for f, c in sorted(counts.items())}


def legacy_sites() -> list[Site]:
    out = []
    for path, rel in _python_files():
        if rel in EXEMPT_FILES or (
            rel.startswith(RBAC_PACKAGE + "/") and rel not in RBAC_LEGACY_FILES
        ):
            continue
        out.extend(scan_legacy_source(rel, path.read_text(encoding="utf-8")))
    return out


#: The legacy sites measured when RBAC-1 landed (3 Oct 2026). RBAC-4 removes them;
#: until then the count may only fall. Generated by ``--baseline``.
KNOWN_LEGACY_ROLE_IDENTITY_SITES: dict[str, dict[str, int]] = {
    "ccure_platform/administration/email_domains.py": {"require_role": 7},
    "ccure_platform/administration/organizations.py": {"role_identity_compare": 1},
    "ccure_platform/administration/users.py": {"role_identity_compare": 5},
    "ccure_platform/audit_log/router.py": {
        "require_role": 1,
        "role_identity_compare": 1,
    },
    "ccure_platform/identity/router.py": {"role_identity_compare": 1},
    "ccure_platform/rbac/dependencies.py": {"role_identity_compare": 1},
    "main.py": {"role_identity_compare": 1},
    "routers/admin_nvd.py": {"require_role": 1},
    "routers/assets.py": {"role_identity_compare": 1},
    "routers/compliance.py": {"role_identity_compare": 2},
    "routers/credentialed.py": {"role_identity_compare": 3},
    "routers/credentials.py": {"role_identity_compare": 1},
    "routers/dashboard.py": {"role_identity_compare": 1},
    "routers/findings.py": {"role_identity_compare": 1},
    "routers/phase_scans.py": {"role_identity_compare": 1},
    "routers/remediation.py": {"role_identity_compare": 1},
    "routers/reports.py": {"role_identity_compare": 3},
    "routers/scan_history.py": {"role_identity_compare": 2},
    "routers/scan_policies.py": {"role_identity_compare": 1},
    "routers/scan_schedules.py": {"role_identity_compare": 1},
    "routers/web_scans.py": {"role_identity_compare": 2},
    "scans/scan_access.py": {"role_identity_compare": 1},
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--list", action="store_true", help="print every site")
    parser.add_argument(
        "--baseline", action="store_true", help="print the baseline dict"
    )
    args = parser.parse_args()

    new = measure_new()
    legacy = measure_legacy()
    if args.baseline:
        print("KNOWN_LEGACY_ROLE_IDENTITY_SITES = {")
        for f, kinds in legacy.items():
            print(f"    {f!r}: {kinds!r},")
        print("}")
        return
    print(f"new RBAC implementation: {len(new)} violation(s) (must be 0)")
    total = sum(sum(v.values()) for v in legacy.values())
    print(f"legacy authorization code: {total} site(s) in {len(legacy)} file(s)")
    if args.list:
        for s in new + legacy_sites():
            print(f"  {s.path}:{s.line}  [{s.kind}]  {s.what}")


if __name__ == "__main__":
    main()
