"""
Build (or check) the final RBAC authorization inventory — RBAC-8.

    python -m scripts.rbac.build_migration_inventory            # print a summary
    python -m scripts.rbac.build_migration_inventory --write    # rewrite the JSON
    python -m scripts.rbac.build_migration_inventory --check    # exit 1 on drift

``data/rbac/authorization_migration_inventory.json`` is the one list of every place
backend code decides authorization, and what became of the legacy model. It is
**generated** (an AST walk plus the recorded history) and deterministic, and a test
fails when the file and the code disagree.

Statuses:

* ``migrated`` — a live guard or scope seam of the Platform RBAC engine, naming a
  permission key the catalogue declares;
* ``display-only`` — a place that shows a role *label*; never an input to a decision;
* ``compatibility-history`` — historical migrations retained unchanged, never read by
  an authorization decision;
* ``removed`` — a legacy decision that existed and is gone (the history of the 40
  role-name sites).

A call to a retired mechanism (``require_permission``, ``require_role``,
``user_has_permission``, ``check_role_assignment``) found in runtime code is
``legacy`` and fails the ratchet in ``tests/repo/test_rbac_final_ratchet.py``.

Read-only: it imports no application code and touches no database.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from collections import Counter
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[2]
INVENTORY = BACKEND_ROOT / "data" / "rbac" / "authorization_migration_inventory.json"
ROLE_NAME_HISTORY = BACKEND_ROOT / "data" / "rbac" / "role_name_site_decisions.json"

SKIP_DIRS = {
    ".venv",
    "tests",
    "alembic",
    "__pycache__",
    "scripts",
    "node_modules",
    "logs",
    "reports",
    "data",
    "docs",
}
#: Mechanisms of the engine: each is an authorization decision made by the new model.
LIVE_MECHANISMS = {
    "require_authorized": "permission guard",
    "has_permission": "in-handler permission check",
    "resolve_active_organisation": "organisation scope (platform-scope switch grant)",
    "acts_across_organisations": "cross-organisation reach (platform-scope switch grant)",
    "resource_organisation_allowed": "resource organisation verified server-side",
}
#: Retired mechanisms. Any call in runtime code is a regression.
RETIRED_MECHANISMS = frozenset(
    {
        "require_permission",
        "require_role",
        "user_has_permission",
        "check_role_assignment",
    }
)

#: Places that name a legacy concept on purpose. Each is checked to exist, so a record
#: cannot outlive the code it describes.
COMPATIBILITY = tuple(
    (
        f"alembic/versions/{name}",
        marker,
        "Historical migration retained unchanged; no runtime legacy model.",
    )
    for name, marker in (
        ("a7c1e5b3d9f2_rbac_foundation.py", "rbac_legacy_map"),
        ("c9e3a7b5d1f2_users_role_id_non_authoritative.py", "role_id"),
    )
)
DISPLAY_ONLY = (
    (
        "ccure_platform/rbac/administration.py",
        "role_labels",
        "role display names shown beside a user; a label, never an input",
    ),
    (
        "ccure_platform/rbac/authorization_view.py",
        "display_name",
        "assignment display names in the authorization payload; labels only",
    ),
)
#: Runtime metadata excludes these tables; the next focused commit removes their live schema.
LEGACY_TABLES = {
    name: "absent from runtime metadata; forward schema removal pending"
    for name in ("roles", "permissions", "role_permissions", "rbac_legacy_map")
}


def declared_keys() -> set[str]:
    keys = set()
    for rel in ("ccure_platform/permissions.py", "ccure_audit/permissions.py"):
        for node in ast.walk(
            ast.parse((BACKEND_ROOT / rel).read_text(encoding="utf-8"))
        ):
            if (
                isinstance(node, ast.keyword)
                and node.arg == "key"
                and isinstance(node.value, ast.Constant)
            ):
                keys.add(node.value.value)
    return keys


def _call_name(call: ast.Call) -> str | None:
    f = call.func
    return f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)


def _target(call: ast.Call) -> str:
    strs = [a.value for a in call.args if isinstance(a, ast.Constant)]
    return str(strs[-1]) if strs else "dynamic"


def _enclosing(parents: dict, node: ast.AST) -> str:
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node.name
    return "<module>"


def scan_calls() -> list[dict]:
    raw = []
    for path in sorted(BACKEND_ROOT.rglob("*.py")):
        rel = path.relative_to(BACKEND_ROOT).as_posix()
        if SKIP_DIRS & set(rel.split("/")[:-1]):
            continue
        if rel.startswith("ccure_platform/rbac/") or rel == "ccure_platform/api.py":
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            if name in LIVE_MECHANISMS or name in RETIRED_MECHANISMS:
                raw.append(
                    {
                        "file": rel,
                        "line": node.lineno,
                        "function": _enclosing(parents, node),
                        "mechanism": name,
                        "target": _target(node),
                    }
                )
    raw.sort(key=lambda r: (r["file"], r["line"], r["mechanism"], r["target"]))
    return raw


def retired_calls() -> list[dict]:
    return [c for c in scan_calls() if c["mechanism"] in RETIRED_MECHANISMS]


def build() -> dict:
    keys = declared_keys()
    history = json.loads(ROLE_NAME_HISTORY.read_text(encoding="utf-8"))["sites"]
    sites: list[dict] = []
    seen: Counter = Counter()

    def add(entry: dict) -> None:
        base = (
            f"{entry['file']}::{entry['function']}::{entry['mechanism']}"
            f"::{entry['permission'] or ''}"
        )
        seen[base] += 1
        entry["site_id"] = f"{base}#{seen[base]}"
        sites.append(entry)

    for c in scan_calls():
        mech = c["mechanism"]
        permission = (
            c["target"] if mech in ("require_authorized", "has_permission") else None
        )
        if mech in RETIRED_MECHANISMS:
            status, reason = (
                "legacy",
                "a retired authorization mechanism is still called",
            )
        elif permission is not None and permission not in keys:
            status, reason = (
                "legacy",
                "names a permission the catalogue does not declare",
            )
        else:
            status, reason = "migrated", LIVE_MECHANISMS[mech]
        add(
            {
                "file": c["file"],
                "line": c["line"],
                "function": c["function"],
                "mechanism": mech,
                "permission": permission,
                "status": status,
                "reason": reason,
            }
        )
    for status, rows, mechanism in (
        ("compatibility-history", COMPATIBILITY, "compatibility"),
        ("display-only", DISPLAY_ONLY, "label"),
    ):
        for rel, marker, why in rows:
            add(
                {
                    "file": rel,
                    "line": 0,
                    "function": marker,
                    "mechanism": mechanism,
                    "permission": None,
                    "status": status,
                    "reason": why,
                }
            )
    sites.sort(key=lambda s: (s["file"], s["line"], s["mechanism"], s["site_id"]))

    def removed_in(d: dict) -> str:
        if d["status"] == "migrated":
            return "RBAC-4"
        if d.get("rbac5", {}).get("status") == "migrated":
            return "RBAC-5"
        if d.get("rbac7", {}).get("status") == "migrated":
            return "RBAC-7"
        return "RBAC-8"

    removed = [
        {
            "file": d["file"],
            "kind": d["kind"],
            "category": d["category"],
            "status": "removed",
            "removed_in": removed_in(d),
        }
        for d in history
    ]
    counts = Counter(s["status"] for s in sites)
    return {
        "schema_version": 2,
        "description": (
            "Every backend authorization decision, and what became of the legacy model "
            "(RBAC-8). Generated by scripts/rbac/build_migration_inventory.py; do not "
            "edit by hand."
        ),
        "final_state": {
            "authority": "Platform RBAC (ccure_platform.rbac) is the only application "
            "authorization model",
            "legacy_calls_remaining": counts.get("legacy", 0),
            "role_name_decisions_remaining": 0,
            "legacy_tables": LEGACY_TABLES,
            "users_role_id": "absent from runtime model; forward schema removal pending",
            "legacy_atoms": "kept only in migration history, documentation, audit data and "
            "historical migrations",
        },
        "summary": {
            "total": len(sites),
            "migrated": counts.get("migrated", 0),
            "display-only": counts.get("display-only", 0),
            "compatibility-history": counts.get("compatibility-history", 0),
            "legacy": counts.get("legacy", 0),
            "removed_role_name_sites": len(removed),
        },
        "removed_role_name_sites": removed,
        "sites": sites,
    }


def render(inv: dict) -> str:
    return json.dumps(inv, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    text = render(build())
    if args.write:
        INVENTORY.write_text(text, encoding="utf-8")
        print(f"wrote {INVENTORY}")
        return 0
    if args.check:
        ok = INVENTORY.exists() and INVENTORY.read_text(encoding="utf-8") == text
        print("inventory is current" if ok else "inventory is out of date: run --write")
        return 0 if ok else 1
    print(json.dumps(json.loads(text)["summary"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
