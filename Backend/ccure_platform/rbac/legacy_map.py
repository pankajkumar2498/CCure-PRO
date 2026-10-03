"""
ccure_platform/rbac/legacy_map.py — the golden mapping from the legacy RBAC
vocabulary to the new one.

TEMPORARY, like ``rbac_legacy_map``: both are removed in RBAC-8. They exist so the
migration is **mechanically verifiable** instead of argued: RBAC-3 compares the new
decision with the legacy one per request, RBAC-4 moves routes, and both need to
know, for every legacy role and every legacy atom, what it becomes.

The mapping is **data** — ``Backend/data/rbac/golden_legacy_mapping.json`` — not
code, so this module names no legacy atom and no product capability. It holds:

* ``roles``: each legacy role → its new role key, scope and intent;
* ``atoms``: every legacy ``resource:action`` with exactly one status —
  ``mapped``, ``replaced`` or ``retired`` — the new keys it becomes, and why. **No
  atom is dropped silently**, including the ones nothing enforces;
* ``permissions``: every key of the new catalogue — owner, scope, sensitivity,
  delegation, continuity, the legacy atoms it derives from, who holds it and the
  reason it exists;
* ``role_grants``: the expected permission set of each role, written out so it is
  reviewable and diffable;
* ``intentional_differences``: every place the new model deliberately differs.

Three ways it is checked, deliberately independent of each other:

1. ``validate_golden`` — the file is internally consistent and accounts for every
   legacy atom and every catalogue key;
2. ``derive_role_grants`` — the expected sets are *recomputed* from what each legacy
   role holds and the atom→key mapping (a key is held when **all** the atoms it
   derives from are), and must equal the written-out sets;
3. the declarations' own ``default_grants`` must equal both.

If those three agree, "old effective permission set == new effective permission
set" holds for every role, subject to the listed differences.

**RBAC-2: prepared, not live.** Nothing reads this in a request.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Collection, Iterable, Mapping

from ccure_platform.rbac import contract as c
from ccure_platform.rbac.audit import EventDraft, emit
from ccure_platform.rbac.model import RbacLegacyMap, RbacPermission, RbacRole
from sqlalchemy import select
from sqlalchemy.orm import Session

#: ``Backend/``, from ``Backend/ccure_platform/rbac/legacy_map.py``.
BACKEND_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_GOLDEN_PATH = BACKEND_ROOT / "data" / "rbac" / "golden_legacy_mapping.json"

#: ``role_grants`` value meaning "every active permission" — expressed in the
#: database as materialised grant rows, never as a wildcard.
ALL_ACTIVE = "ALL_ACTIVE"

ATOM_STATUSES = ("mapped", "replaced", "retired")
ORIGINS = ("legacy", "name_check", "new_governance")
SCHEMA_VERSION = 1
SYNC_ACTOR = "system:rbac-legacy-map"


class GoldenError(ValueError):
    """The golden mapping cannot be used. ``problems`` lists every reason."""

    def __init__(self, problems: Iterable[str]):
        self.problems = tuple(problems)
        super().__init__(
            "RBAC golden mapping refused:\n"
            + "\n".join(f"  - {p}" for p in self.problems)
        )


def load_golden(path: Path | str | None = None) -> dict:
    """Read the golden mapping. A missing or unreadable file raises — there is no
    fallback to an empty mapping."""
    target = Path(path) if path else DEFAULT_GOLDEN_PATH
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise GoldenError([f"{target}: {exc}"]) from exc


def atom_of(resource: str, action: str) -> str:
    return f"{resource}:{action}"


# ── validation (pure) ─────────────────────────────────────────────────────────


def validate_golden(
    golden: Mapping,
    *,
    declarations: Iterable[c.PermissionDecl],
    legacy_atoms: Collection[str] | None = None,
) -> list[str]:
    """
    Every inconsistency between the golden mapping, the catalogue declarations and
    (when given) the set of legacy atoms that exist. An empty list means the
    mapping accounts for everything: **no unexplained unmapped permission and no
    undeclared key**.
    """
    problems: list[str] = []
    decls = {d.key: d for d in declarations}

    if golden.get("schema_version") != SCHEMA_VERSION:
        problems.append(f"schema_version must be {SCHEMA_VERSION}")

    # roles ---------------------------------------------------------------------
    roles = golden.get("roles", [])
    role_keys = [r.get("role_key") for r in roles]
    legacy_names = [r.get("legacy_role") for r in roles]
    if len(set(role_keys)) != len(role_keys) or len(set(legacy_names)) != len(
        legacy_names
    ):
        problems.append("a role appears twice in roles")
    role_scope = {}
    for r in roles:
        key = r.get("role_key")
        if c.role_key_kind(key) != "system":
            problems.append(f"role {key!r} is not a system role key")
        if r.get("assignable_scope") not in c.ASSIGNABLE_SCOPES:
            problems.append(f"role {key!r} has an invalid assignable_scope")
        role_scope[key] = r.get("assignable_scope")

    # atoms ---------------------------------------------------------------------
    atoms = golden.get("atoms", [])
    atom_ids = [a.get("atom") for a in atoms]
    if len(set(atom_ids)) != len(atom_ids):
        problems.append("an atom appears twice in atoms")
    atom_keys: dict[str, set[str]] = {}
    for a in atoms:
        atom = a.get("atom")
        keys = a.get("new_keys", [])
        atom_keys[atom] = set(keys)
        if not isinstance(atom, str) or atom.count(":") != 1:
            problems.append(f"atom {atom!r} is not 'resource:action'")
        if a.get("status") not in ATOM_STATUSES:
            problems.append(f"atom {atom!r} has status {a.get('status')!r}")
        if not str(a.get("reason", "")).strip():
            problems.append(f"atom {atom!r} has no reason")
        if a.get("status") == "retired":
            if keys:
                problems.append(f"atom {atom!r} is retired but names new keys")
        elif not keys:
            problems.append(f"atom {atom!r} is {a.get('status')} but names no new key")
        if len(set(keys)) != len(keys):
            problems.append(f"atom {atom!r} names a key twice")
        for key in keys:
            if key not in decls:
                problems.append(f"atom {atom!r} maps to {key!r}, which is not declared")
    if legacy_atoms is not None:
        for atom in sorted(set(legacy_atoms) - set(atom_ids)):
            problems.append(f"legacy atom {atom!r} is not accounted for")
        for atom in sorted(set(atom_ids) - set(legacy_atoms)):
            problems.append(f"{atom!r} is in the mapping but is not a legacy atom")

    # permissions ---------------------------------------------------------------
    perms = {p.get("key"): p for p in golden.get("permissions", [])}
    if len(perms) != len(golden.get("permissions", [])):
        problems.append("a permission appears twice in permissions")
    for key in sorted(set(decls) - set(perms)):
        problems.append(
            f"declared key {key!r} has no entry (no documented reason or owner)"
        )
    for key in sorted(set(perms) - set(decls)):
        problems.append(f"{key!r} is in the mapping but is not declared")
    role_grants = golden.get("role_grants", {})
    for key, p in perms.items():
        d = decls.get(key)
        if d is None:
            continue
        if p.get("owner") != key.split(".")[0]:
            problems.append(f"{key!r} owner {p.get('owner')!r} is not its namespace")
        if p.get("origin") not in ORIGINS:
            problems.append(f"{key!r} has origin {p.get('origin')!r}")
        if not str(p.get("reason", "")).strip():
            problems.append(f"{key!r} has no documented reason")
        for field_, actual in (
            ("scope_kind", d.scope_kind),
            ("sensitivity", d.sensitivity),
            ("delegable_to_org_roles", d.delegable_to_org_roles),
            ("continuity", d.continuity),
        ):
            if p.get(field_) != actual:
                problems.append(
                    f"{key!r} {field_} is {p.get(field_)!r} in the mapping but {actual!r} in the declaration"
                )
        sources = set(p.get("sources", []))
        if p.get("origin") == "legacy" and not sources:
            problems.append(f"{key!r} is derived from legacy atoms but lists none")
        for atom in sources:
            if key not in atom_keys.get(atom, set()):
                problems.append(
                    f"{key!r} lists source {atom!r}, which does not map to it"
                )
        for atom, keys in atom_keys.items():
            if key in keys and atom not in sources:
                problems.append(
                    f"atom {atom!r} maps to {key!r}, which does not list it as a source"
                )
        granted = set(p.get("granted_to", []))
        expected = {r for r, v in role_grants.items() if v == ALL_ACTIVE or key in v}
        if granted != expected:
            problems.append(f"{key!r} granted_to disagrees with role_grants")
        if (
            set(d.default_grants)
            | {r for r in role_scope if r in granted and _auto(golden, r)}
            != granted
        ):
            problems.append(
                f"{key!r} granted_to disagrees with the declaration's default_grants"
            )
        if d.default_grants and not set(d.default_grants) <= set(role_scope):
            problems.append(
                f"{key!r} default_grants names a role the mapping does not know"
            )

    # role grants ---------------------------------------------------------------
    for r in role_keys:
        if r not in role_grants:
            problems.append(f"role {r!r} has no entry in role_grants")
    for r, grants in role_grants.items():
        if r not in role_scope:
            problems.append(f"role_grants names unknown role {r!r}")
            continue
        if grants == ALL_ACTIVE:
            if role_scope[r] != "platform":
                problems.append(f"{r!r} holds ALL_ACTIVE but is not platform-scope")
            continue
        if list(grants) != sorted(set(grants)):
            problems.append(f"role_grants for {r!r} is not sorted and unique")
        for key in grants:
            d = decls.get(key)
            if d is None:
                problems.append(f"{r!r} is granted undeclared key {key!r}")
            elif role_scope[r] == "organization" and (
                d.scope_kind != "organization" or not d.delegable_to_org_roles
            ):
                problems.append(
                    f"{r!r} (organisation-scope) is granted {key!r}, which it may not hold"
                )

    if not golden.get("intentional_differences"):
        problems.append(
            "intentional_differences is empty: every difference must be listed"
        )
    return problems


def _auto(golden: Mapping, role_key: str) -> bool:
    """Whether a role holds everything by materialisation (``ALL_ACTIVE``)."""
    return golden.get("role_grants", {}).get(role_key) == ALL_ACTIVE


# ── derivation (pure) ─────────────────────────────────────────────────────────


def derive_role_grants(
    golden: Mapping, legacy_role_sets: Mapping[str, Collection[str]]
) -> dict[str, frozenset[str] | str]:
    """
    Recompute each role's expected permission set from what its **legacy** role
    holds, using only the atom→key mapping.

    A key is held when *every* legacy atom it derives from is held — which is why
    a merge is only legal where every role holds all of the merged atoms or none,
    and a split gives each part the same holders. A key with no legacy source
    (a name check or a governance permission) is held by no organisation-scope
    role. Platform-scope keys are never given to an organisation-scope role. The
    superadmin role is ``ALL_ACTIVE``.

    ``legacy_role_sets`` maps a legacy role name to the atoms it holds.
    """
    sources: dict[str, set[str]] = {}
    for a in golden["atoms"]:
        for key in a["new_keys"]:
            sources.setdefault(key, set()).add(a["atom"])
    scope = {p["key"]: p["scope_kind"] for p in golden["permissions"]}
    out: dict[str, frozenset[str] | str] = {}
    for r in golden["roles"]:
        if r["assignable_scope"] == "platform":
            out[r["role_key"]] = ALL_ACTIVE
            continue
        held = set(legacy_role_sets.get(r["legacy_role"], ()))
        out[r["role_key"]] = frozenset(
            key
            for key, srcs in sources.items()
            if srcs and srcs <= held and scope.get(key) == "organization"
        )
    return out


# ── sync ──────────────────────────────────────────────────────────────────────


@dataclass(slots=True)
class LegacyMapReport:
    roles_added: tuple[str, ...] = ()
    atoms_added: tuple[str, ...] = ()
    atoms_updated: tuple[str, ...] = ()
    #: Rows in the table for an atom the mapping no longer lists. Never deleted
    #: here; reported.
    stale: tuple[str, ...] = ()
    events_written: int = 0

    @property
    def changed(self) -> bool:
        return bool(self.roles_added or self.atoms_added or self.atoms_updated)


def sync_legacy_map(
    db: Session, golden: Mapping, *, audit: bool = True, actor=None
) -> LegacyMapReport:
    """
    Write the golden mapping into ``rbac_legacy_map``: one ``role`` row per legacy
    role and one ``permission`` row per (atom, new key) — or one keyless row for a
    retired atom, so it is *preserved*, with its reason. Idempotent; does not
    commit. The catalogue must already be synced: a mapping that names a key the
    catalogue lacks raises with the keys listed.
    """
    have_keys = set(db.execute(select(RbacPermission.key)).scalars())
    have_roles = set(db.execute(select(RbacRole.key)).scalars())
    problems = []
    for a in golden["atoms"]:
        for key in a["new_keys"]:
            if key not in have_keys:
                problems.append(
                    f"{a['atom']!r} maps to {key!r}, which is not in the catalogue (sync it first)"
                )
    for r in golden["roles"]:
        if r["role_key"] not in have_roles:
            problems.append(
                f"role {r['role_key']!r} does not exist (seed the roles first)"
            )
    if problems:
        raise GoldenError(problems)

    report = LegacyMapReport()
    existing_roles = {
        row.legacy_role_name: row
        for row in db.execute(
            select(RbacLegacyMap).where(RbacLegacyMap.kind == "role")
        ).scalars()
    }
    added_roles = []
    for r in golden["roles"]:
        if r["legacy_role"] not in existing_roles:
            db.add(
                RbacLegacyMap(
                    kind="role",
                    legacy_role_name=r["legacy_role"],
                    role_key=r["role_key"],
                    status="mapped",
                    reason=r["intended_permissions"],
                )
            )
            added_roles.append(r["legacy_role"])

    existing = {
        (row.legacy_resource, row.legacy_action, row.permission_key): row
        for row in db.execute(
            select(RbacLegacyMap).where(RbacLegacyMap.kind == "permission")
        ).scalars()
    }
    wanted: set[tuple[str, str, str | None]] = set()
    added, updated = [], []
    for a in golden["atoms"]:
        resource, action = a["atom"].split(":")
        keys = a["new_keys"] or [None]
        for key in keys:
            ident = (resource, action, key)
            wanted.add(ident)
            row = existing.get(ident)
            if row is None:
                db.add(
                    RbacLegacyMap(
                        kind="permission",
                        legacy_resource=resource,
                        legacy_action=action,
                        permission_key=key,
                        status=a["status"],
                        reason=a["reason"],
                    )
                )
                added.append(a["atom"])
            elif row.status != a["status"] or row.reason != a["reason"]:
                row.status, row.reason = a["status"], a["reason"]
                updated.append(a["atom"])
    db.flush()
    report.roles_added = tuple(added_roles)
    report.atoms_added = tuple(sorted(set(added)))
    report.atoms_updated = tuple(sorted(set(updated)))
    report.stale = tuple(sorted(atom_of(r, a) for (r, a, k) in set(existing) - wanted))
    if audit and report.changed:
        draft = EventDraft(
            action="rbac.legacy_map.synced",
            resource_type="rbac_legacy_map",
            changes={
                "roles_added": list(report.roles_added),
                "atoms_added": len(report.atoms_added),
                "atoms_updated": len(report.atoms_updated),
            },
        )
        report.events_written = emit(
            db,
            [draft],
            actor=actor,
            system_actor=None if actor is not None else SYNC_ACTOR,
        ).total
    return report


def system_role_key_for_legacy(legacy_role_name: str | None) -> str | None:
    """The system role key the golden mapping gives a legacy role, or None for a
    legacy role it does not name. The only place a legacy role identity is translated
    to the new model."""
    if not legacy_role_name:
        return None
    for entry in load_golden()["roles"]:
        if entry["legacy_role"] == str(legacy_role_name).lower():
            return entry["role_key"]
    return None
