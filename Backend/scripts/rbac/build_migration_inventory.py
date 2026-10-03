"""
Build (or check) the RBAC-4 authorization migration inventory.

    python -m scripts.rbac.build_migration_inventory            # print a summary
    python -m scripts.rbac.build_migration_inventory --write    # rewrite the JSON
    python -m scripts.rbac.build_migration_inventory --check    # exit 1 on drift

The inventory (``data/rbac/authorization_migration_inventory.json``) is the one list
of every place module code decides authorization, with its migration status. It is
**generated** from source (an AST walk) and the golden mapping, deterministically, and
a test fails when the file and the code disagree — so a new guard cannot be added
without a recorded decision, and the runtime (``rbac/authority.py``) only ever
switches on paths this file marks ``migrated``.

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
GOLDEN = BACKEND_ROOT / "data" / "rbac" / "golden_legacy_mapping.json"
ROLE_NAME_EVIDENCE = BACKEND_ROOT / "data" / "rbac" / "role_name_site_decisions.json"
REMAINING_ROLE_NAME = (
    BACKEND_ROOT / "data" / "rbac" / "legacy_role_name_dependencies.json"
)

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
#: Call names that are an authorization decision made in module code.
MECHANISMS = {
    "require_permission": "require_permission",
    "user_has_permission": "user_has_permission",
    "require_role": "require_role",
    "require_authorized": "require_authorized",
    "has_permission": "has_permission",
}

#: Legacy resources whose atoms are NOT migrated in RBAC-4, with the reason. The
#: atom is mapped, but the *decision* is entangled with something RBAC-4 may not
#: touch (assignment hierarchy, provisioning, cross-organisation visibility) or the
#: atom is not one-to-one with a key (so a guard cannot name the key it enforces).
DEFERRED_RESOURCES = {
    "users": "assignment hierarchy and provisioning: user administration decides who may "
    "hand out which role (escalation ceiling, continuity); RBAC-5",
    "organizations": "organisation provisioning and cross-organisation administration "
    "(scope model); RBAC-5",
    "roles": "role administration: the legacy atom splits across several keys "
    "(platform-scope role creation is continuity-protected); RBAC-5",
    "settings": "the legacy atom was split into distinct capabilities "
    "(audit.asset.import_amt / audit.remediation.manage_sla); a guard cannot name which",
    "audit": "audit-log visibility is scoped by organisation and superadmin "
    "cross-organisation reads (scope model); RBAC-5",
    "audit_logs": "retired atom; no route enforces it",
}
#: Role-name site categories → (status, target phase, reason).
ROLE_NAME_DEFERRALS = {
    "scope_cross_org": (
        "RBAC-5",
        "the superadmin widens which organisation's data a query returns: scope, not a "
        "permission",
    ),
    "assignment_hierarchy": (
        "RBAC-5",
        "which roles may be assigned: the escalation ceiling and "
        "platform.role.assign_platform need the scope model first",
    ),
    "organization_switch": (
        "RBAC-5",
        "acting in another organisation: platform.organization.switch plus the scope model",
    ),
    "provisioning_lookup": (
        "RBAC-8",
        "a role looked up by name to give to a new account: provisioning, not authorization",
    ),
    "default_role": (
        "RBAC-8",
        "the self-registration default: provisioning, not authorization",
    ),
    "bootstrap": (
        "RBAC-8",
        "first-run provisioning of the initial administrator: a permitted bootstrap context",
    ),
    "legacy_authority": (
        "RBAC-8",
        "the legacy check itself, kept as the rollback path until the legacy model is removed",
    ),
}
RBAC3_EVIDENCE_MATCH = (
    "RBAC-3 equivalence: MATCH for all five legacy roles, zero mismatches "
    "(tests/rbac/test_rbac_authority_equivalence.py)"
)


def _golden() -> dict:
    return json.loads(GOLDEN.read_text(encoding="utf-8"))


def _target(call: ast.Call, name: str) -> str:
    """The permission this call names: ``resource:action`` or a key or role names."""
    args = [a.value for a in call.args if isinstance(a, ast.Constant)]
    if name == "require_permission" and len(args) >= 2:
        return f"{args[0]}:{args[1]}"
    if name == "user_has_permission":
        strs = [a.value for a in call.args if isinstance(a, ast.Constant)]
        if len(strs) >= 2:
            return f"{strs[-2]}:{strs[-1]}"
        return "dynamic"
    if name in ("require_authorized", "has_permission"):
        strs = [a.value for a in call.args if isinstance(a, ast.Constant)]
        return str(strs[-1]) if strs else "dynamic"
    if name == "require_role":
        if call.args and isinstance(call.args[0], (ast.List, ast.Tuple)):
            return ",".join(
                sorted(
                    e.value for e in call.args[0].elts if isinstance(e, ast.Constant)
                )
            )
        if call.args and isinstance(call.args[0], ast.Constant):
            return str(call.args[0].value)
    return "dynamic"


def _authoritative_kw(call: ast.Call) -> bool:
    return any(
        k.arg == "authoritative"
        and isinstance(k.value, ast.Constant)
        and k.value.value is True
        for k in call.keywords
    )


def _call_name(call: ast.Call) -> str | None:
    f = call.func
    return f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)


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
        if SKIP_DIRS & set(rel.split("/")[:-1]) or rel.startswith(
            "ccure_platform/rbac/"
        ):
            continue
        if rel.startswith(("ccure_platform/api.py",)):
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
            if name not in MECHANISMS:
                continue
            # `def user_has_permission(...)` wrappers are definitions, not calls
            raw.append(
                {
                    "file": rel,
                    "line": node.lineno,
                    "function": _enclosing(parents, node),
                    "mechanism": MECHANISMS[name],
                    "target": _target(node, name),
                    "authoritative": _authoritative_kw(node),
                }
            )
    raw.sort(key=lambda r: (r["file"], r["line"], r["mechanism"], r["target"]))
    return raw


def _scope_files(decisions: list[dict]) -> set[str]:
    return {d["file"] for d in decisions if d["category"] == "scope_cross_org"}


def build() -> dict:
    golden = _golden()
    atoms = {a["atom"]: a for a in golden["atoms"]}
    keys = {p["key"] for p in golden["permissions"]}
    decisions = json.loads(ROLE_NAME_EVIDENCE.read_text(encoding="utf-8"))
    scope_files = _scope_files(decisions["sites"])
    sites: list[dict] = []
    seen: Counter = Counter()

    def add(entry: dict) -> None:
        base = f"{entry['file']}::{entry['function']}::{entry['mechanism']}::{entry['legacy_permission'] or entry['new_permission']}"
        seen[base] += 1
        entry["site_id"] = f"{base}#{seen[base]}"
        sites.append(entry)

    for c in scan_calls():
        mech, target = c["mechanism"], c["target"]
        entry = {
            "file": c["file"],
            "line": c["line"],
            "function": c["function"],
            "mechanism": mech,
            "legacy_permission": None,
            "new_permission": None,
            "path_id": None,
            "scope": "organization",
            "status": "deferred",
            "migrated": False,
            "reason": "",
            "rbac3_evidence": None,
            "rbac5_dependency": c["file"] in scope_files,
        }
        if mech in ("require_authorized", "has_permission"):
            entry.update(
                new_permission=target,
                path_id=target,
                scope="platform",
                status="migrated" if target in keys else "deferred",
                migrated=target in keys,
                reason="replaced a role-name check with a permission key; the legacy "
                "rule remains the fallback (rbac/authority.py)",
                rbac3_evidence=(
                    "role-name check recorded by RBAC-3; key held only by the role the "
                    "legacy check named (tests/rbac/test_rbac_authority_migration.py)"
                ),
            )
            if target not in keys:
                entry["reason"] = "names a permission the catalogue does not declare"
        elif mech == "require_role":
            entry.update(
                reason="a role-name guard with no replacement key assigned; "
                "RBAC-5 or later",
            )
        else:  # require_permission / user_has_permission
            entry["legacy_permission"] = target
            atom = atoms.get(target)
            resource = target.split(":")[0]
            if atom is None:
                entry["reason"] = "dynamic or unknown atom"
            else:
                entry["new_permission"] = ",".join(atom["new_keys"]) or None
                entry["scope"] = (
                    "platform"
                    if resource in ("users", "organizations")
                    else "organization"
                )
                if atom["status"] != "mapped" or len(atom["new_keys"]) != 1:
                    entry["reason"] = (
                        f"atom is {atom['status']} with {len(atom['new_keys'])} key(s): "
                        "a guard cannot name the single key it enforces"
                    )
                elif resource in DEFERRED_RESOURCES:
                    entry["reason"] = DEFERRED_RESOURCES[resource]
                elif mech == "user_has_permission" and not c["authoritative"]:
                    entry["reason"] = (
                        "in-handler check coupled to organisation-scope visibility "
                        "(per-user versus organisation-wide reads); RBAC-5"
                    )
                    entry["rbac5_dependency"] = True
                else:
                    entry.update(
                        status="migrated",
                        migrated=True,
                        path_id=target,
                        reason="one-to-one mapped atom, no hierarchy, switching or "
                        "cross-organisation dependence",
                        rbac3_evidence=RBAC3_EVIDENCE_MATCH,
                    )
        add(entry)

    # role-name decisions still in the code: the sites RBAC-4 did not migrate
    remaining = json.loads(REMAINING_ROLE_NAME.read_text(encoding="utf-8"))
    for d in remaining["sites"]:
        phase, why = ROLE_NAME_DEFERRALS[d["category"]]
        add(
            {
                "file": d["file"],
                "line": d["line"],
                "function": "",
                "mechanism": "role_name_" + d["kind"],
                "legacy_permission": None,
                "new_permission": None,
                "path_id": None,
                "scope": "organization",
                "status": "deferred",
                "migrated": False,
                "reason": why,
                "rbac3_evidence": "recorded by RBAC-3 (legacy_role_name_dependencies.json)",
                "rbac5_dependency": d["category"]
                in ("scope_cross_org", "assignment_hierarchy", "organization_switch"),
                "category": d["category"],
                "deferred_to": phase,
            }
        )
    rbac3_sites = [
        {
            k: d[k]
            for k in (
                "file",
                "rbac3_line",
                "function",
                "kind",
                "category",
                "status",
                "new_permission",
                "reason",
            )
        }
        for d in decisions["sites"]
    ]

    sites.sort(key=lambda s: (s["file"], s["line"], s["mechanism"], s["site_id"]))
    summary = Counter(s["status"] for s in sites)
    return {
        "schema_version": 1,
        "description": (
            "Every module-code authorization decision and its RBAC-4 migration status. "
            "Generated by scripts/rbac/build_migration_inventory.py; do not edit by hand."
        ),
        "rules": {
            "migrated_atom": "mapped to exactly one key, resource not in deferred_resources, "
            "not an in-handler check coupled to organisation scope",
            "deferred_resources": DEFERRED_RESOURCES,
            "role_name_deferrals": {k: list(v) for k, v in ROLE_NAME_DEFERRALS.items()},
        },
        "summary": {
            "total": len(sites),
            "rbac3_role_name_sites": len(rbac3_sites),
            "rbac3_role_name_migrated": sum(
                1 for d in rbac3_sites if d["status"] == "migrated"
            ),
            "migrated": summary.get("migrated", 0),
            "deferred": summary.get("deferred", 0),
            "migrated_paths": sorted(
                {s["path_id"] for s in sites if s["migrated"] and s["path_id"]}
            ),
        },
        "rbac3_role_name_sites": rbac3_sites,
        "sites": sites,
    }


def render(inv: dict) -> str:
    return json.dumps(inv, indent=2, sort_keys=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    text = render(build())
    if args.write:
        INVENTORY.write_text(text, encoding="utf-8")
        print(f"wrote {INVENTORY}")
    elif args.check:
        if not INVENTORY.exists() or INVENTORY.read_text(encoding="utf-8") != text:
            print("inventory is out of date: run --write", file=sys.stderr)
            return 1
        print("inventory is current")
    else:
        s = json.loads(text)["summary"]
        print({k: v for k, v in s.items() if k != "migrated_paths"})
        print(len(s["migrated_paths"]), "migrated paths")
    return 0


if __name__ == "__main__":
    sys.exit(main())
