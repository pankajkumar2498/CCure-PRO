"""
ccure_platform/rbac/catalogue.py — the permission catalogue, and its sync.

Permissions are *declared* by whoever owns the capability — the platform, Audit,
Policy Pro, Rank, and later IR — and *owned* by RBAC. A declaration is data
(``contract.PermissionDecl``). The composition root
(``ccure_platform/composition.py``) reads each enabled module's manifest, loads
the module that declares its permissions, and hands RBAC the result:

    module manifest → permission declarations (data) → composition root
        → rbac.catalogue.sync(...) → rbac_permissions / rbac_role_permissions

RBAC never imports a module and has no list of them. This file validates
**generic** rules only and knows no product by name: the grammar, that a key's
first segment is the namespace its source owns, no duplicates across sources,
sane scope metadata, and that every role a declaration grants to is a real
code-managed system role.

**Nothing is applied unless everything is valid.** A source that fails to load
or declares something invalid stops the whole sync with every problem listed;
there is no fallback to "the declarations that were fine". A half-synced
catalogue would be a silently half-granted one.

What sync writes, in the caller's transaction (it never commits):

* new permissions are inserted; changed metadata is updated; a permission a
  synced namespace no longer declares becomes ``deprecated`` — never deleted, and
  still honoured where granted;
* code-managed system roles are reconciled to their ``default_grants``;
* a role with ``auto_grant_new_permissions`` is granted every active permission
  — materialised rows, because **the engine reads grants and never a flag**;
* every changed role gets a revision, and a retired role is skipped (and
  reported), never resurrected.

``ensure_system_roles`` / ``ensure_default_roles`` seed the five system roles and
the self-registration default on an install that does not have them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from ccure_platform.rbac import contract as c
from ccure_platform.rbac.audit import EventDraft, RoleSnapshot, emit, role_event
from ccure_platform.rbac.model import (
    RbacDefaultRole,
    RbacPermission,
    RbacRole,
    RbacRolePermission,
    append_revision,
    granted_keys,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

SYNC_ACTOR = "system:rbac-sync"


class CatalogueError(ValueError):
    """The declarations cannot be applied. ``problems`` lists every reason."""

    def __init__(self, problems: Sequence[str]):
        self.problems = tuple(problems)
        super().__init__(
            "RBAC catalogue refused:\n" + "\n".join(f"  - {p}" for p in self.problems)
        )


# ── validation (pure) ─────────────────────────────────────────────────────────


def declaration_problems(
    namespace: str,
    decl: c.PermissionDecl,
    known_roles: Mapping[str, str],
) -> list[str]:
    """Everything wrong with one declaration, as sentences naming the key."""
    out: list[str] = []
    key = decl.key
    label = f"{key!r}"
    if not isinstance(key, str) or not c.PERMISSION_KEY.match(key):
        return [
            f"{label} is not a three-segment key '<namespace>.<resource>.<action>' "
            "(lower-case letters, digits, underscores; no wildcards)"
        ]
    if len(key) > c.PERMISSION_KEY_MAX:
        out.append(f"{label} is longer than {c.PERMISSION_KEY_MAX} characters")
    if key.split(".", 1)[0] != namespace:
        out.append(
            f"{label} is declared by a source that owns namespace {namespace!r}; "
            "a key's first segment must be the declaring namespace"
        )
    if not isinstance(decl.description, str) or not decl.description.strip():
        out.append(f"{label} has no description")
    elif len(decl.description) > c.DESCRIPTION_MAX:
        out.append(f"{label} description is longer than {c.DESCRIPTION_MAX} characters")
    if decl.scope_kind not in c.SCOPE_KINDS:
        out.append(
            f"{label} scope_kind {decl.scope_kind!r} is not one of {c.SCOPE_KINDS}"
        )
    if decl.sensitivity not in c.SENSITIVITIES:
        out.append(
            f"{label} sensitivity {decl.sensitivity!r} is not one of {c.SENSITIVITIES}"
        )
    for name in ("delegable_to_org_roles", "continuity"):
        if not isinstance(getattr(decl, name), bool):
            out.append(f"{label} {name} must be a boolean")
    if decl.scope_kind == "platform" and decl.delegable_to_org_roles is True:
        out.append(
            f"{label} is platform-scope, so it cannot be delegable to organisation roles"
        )
    if decl.continuity and key not in c.CONTINUITY_KEYS:
        out.append(f"{label} is flagged continuity but is not a frozen continuity key")
    if key in c.CONTINUITY_KEYS and not decl.continuity:
        out.append(f"{label} is a frozen continuity key and must be flagged continuity")
    seen: set[str] = set()
    for role_key in decl.default_grants:
        if role_key in seen:
            out.append(f"{label} grants to {role_key!r} twice")
        seen.add(role_key)
        if c.role_key_kind(role_key) != "system":
            out.append(
                f"{label} default_grants names {role_key!r}, which is not a "
                "code-managed system role key"
            )
        elif role_key not in known_roles:
            out.append(
                f"{label} default_grants names {role_key!r}, which does not exist"
            )
        elif known_roles[role_key] == "organization" and (
            decl.scope_kind != "organization" or not decl.delegable_to_org_roles
        ):
            out.append(
                f"{label} cannot be granted to the organisation-scope role {role_key!r} "
                "(it is platform-scope or not delegable)"
            )
    return out


def validate_declarations(
    sources: Sequence[c.ModuleDeclarations],
    *,
    known_roles: Mapping[str, str],
) -> list[str]:
    """
    Every problem across ``sources``; an empty list means they may be applied.
    ``known_roles`` maps each code-managed system role key to its assignable
    scope. Generic rules only: this function names no module.
    """
    problems: list[str] = []
    namespaces: dict[str, str] = {}
    keys: dict[str, str] = {}
    for src in sources:
        who = f"source {src.module_key!r}"
        if not src.module_key or not isinstance(src.module_key, str):
            problems.append("a source has no module_key")
        if not c.NAMESPACE.match(src.namespace or ""):
            problems.append(f"{who} has an invalid namespace {src.namespace!r}")
            continue
        if src.namespace in namespaces:
            problems.append(
                f"sources {namespaces[src.namespace]!r} and {src.module_key!r} "
                f"both own namespace {src.namespace!r}"
            )
        namespaces[src.namespace] = src.module_key
        for decl in src.permissions:
            if not isinstance(decl, c.PermissionDecl):
                problems.append(
                    f"{who} declares {decl!r}, which is not a PermissionDecl"
                )
                continue
            problems.extend(
                f"{who}: {p}"
                for p in declaration_problems(src.namespace, decl, known_roles)
            )
            if decl.key in keys:
                problems.append(
                    f"{decl.key!r} is declared by both {keys[decl.key]!r} and {src.module_key!r}"
                )
            keys[decl.key] = src.module_key
    return problems


# ── seeding ───────────────────────────────────────────────────────────────────


def ensure_system_roles(
    db: Session, *, changed_by: str | None = None
) -> tuple[str, ...]:
    """
    Create any of the five system roles that does not exist, as code-managed,
    active roles with a ``created`` revision. An existing role is left exactly as
    it is — a display name an administrator changed is never reset. Returns the
    keys created.
    """
    existing = set(db.execute(select(RbacRole.key)).scalars())
    created = []
    for seed in c.SYSTEM_ROLE_SEEDS:
        if seed.key in existing:
            continue
        role = RbacRole(
            key=seed.key,
            display_name=seed.display_name,
            description=seed.description,
            kind="system",
            assignable_scope=seed.assignable_scope,
            managed_by="code",
            state="active",
            auto_grant_new_permissions=seed.auto_grant_new_permissions,
            revision=1,
            created_by=changed_by,
        )
        db.add(role)
        db.flush()
        append_revision(db, role, "created", changed_by=changed_by)
        created.append(seed.key)
    return tuple(created)


def ensure_default_roles(
    db: Session, *, updated_by: str | None = None
) -> tuple[str, ...]:
    """Configure any default-role purpose that is not configured, from
    ``DEFAULT_ROLE_SEEDS`` (self-registration → the Viewer role), so today's
    behaviour is preserved. Returns the purposes configured."""
    configured = set(db.execute(select(RbacDefaultRole.purpose)).scalars())
    done = []
    for purpose, role_key in c.DEFAULT_ROLE_SEEDS.items():
        if purpose in configured:
            continue
        role_id = db.execute(
            select(RbacRole.id).where(RbacRole.key == role_key)
        ).scalar_one_or_none()
        if role_id is None:
            raise CatalogueError(
                [f"default role for {purpose!r} is {role_key!r}, which does not exist"]
            )
        db.add(RbacDefaultRole(purpose=purpose, role_id=role_id, updated_by=updated_by))
        db.flush()
        done.append(purpose)
    return tuple(done)


# ── sync ──────────────────────────────────────────────────────────────────────


@dataclass(slots=True)
class SyncReport:
    registered: tuple[str, ...] = ()
    updated: tuple[str, ...] = ()
    deprecated: tuple[str, ...] = ()
    grants_added: dict[str, tuple[str, ...]] = field(default_factory=dict)
    grants_removed: dict[str, tuple[str, ...]] = field(default_factory=dict)
    skipped_retired_roles: tuple[str, ...] = ()
    roles_created: tuple[str, ...] = ()
    #: The audit events the sync produced. A sync belongs to no organisation, so
    #: they go to the platform ledger (RBAC-2, ``rbac/audit.py``); always returned,
    #: so a caller can see what happened.
    events: tuple[EventDraft, ...] = ()
    events_written: int = 0

    @property
    def changed(self) -> bool:
        return bool(
            self.registered
            or self.updated
            or self.deprecated
            or self.grants_added
            or self.grants_removed
            or self.roles_created
        )


def _known_roles(db: Session) -> dict[str, str]:
    known = {s.key: s.assignable_scope for s in c.SYSTEM_ROLE_SEEDS}
    for key, scope in db.execute(
        select(RbacRole.key, RbacRole.assignable_scope).where(
            RbacRole.managed_by == "code"
        )
    ):
        known[key] = scope
    return known


def sync(
    db: Session,
    sources: Sequence[c.ModuleDeclarations],
    *,
    actor=None,
    audit: bool = True,
) -> SyncReport:
    """
    Apply ``sources`` to the catalogue. Raises ``CatalogueError`` — having written
    nothing — if any declaration is invalid. Does not commit.

    ``actor`` is the signed-in account running it (an operator script passes none
    and is recorded as ``system:rbac-sync``). With ``audit`` (the default) the
    events go to the platform ledger: a catalogue sync is owned by no organisation.
    """
    sources = tuple(sources)
    actor_label = getattr(actor, "id", None) or SYNC_ACTOR

    problems = validate_declarations(sources, known_roles=_known_roles(db))
    declared: dict[str, tuple[c.ModuleDeclarations, c.PermissionDecl]] = {
        d.key: (s, d) for s in sources for d in s.permissions
    }
    existing = {r.key: r for r in db.execute(select(RbacPermission)).scalars()}
    for key in declared:
        row = existing.get(key)
        if row is not None and row.status == "retired":
            problems.append(f"{key!r} is retired and cannot be declared again")
    default_role_ids = set(
        str(i) for i in db.execute(select(RbacDefaultRole.role_id)).scalars()
    )
    if default_role_ids:
        role_key_by_id = {
            str(i): k for i, k in db.execute(select(RbacRole.id, RbacRole.key))
        }
        for key, (_, d) in declared.items():
            if not (d.continuity or not d.delegable_to_org_roles):
                continue
            for role_key in d.default_grants:
                rid = next(
                    (i for i, k in role_key_by_id.items() if k == role_key), None
                )
                if rid in default_role_ids:
                    problems.append(
                        f"{key!r} cannot be granted to {role_key!r}: that role is a "
                        "configured default role"
                    )
    if problems:
        raise CatalogueError(problems)

    report = SyncReport()
    drafts: list[EventDraft] = []
    report.roles_created = ensure_system_roles(db, changed_by=actor_label)

    # permissions ---------------------------------------------------------------
    registered, updated = [], []
    for key, (src, d) in declared.items():
        _, resource, action = key.split(".")
        row = existing.get(key)
        if row is None:
            db.add(
                RbacPermission(
                    key=key,
                    module=src.namespace,
                    resource=resource,
                    action=action,
                    description=d.description,
                    scope_kind=d.scope_kind,
                    sensitivity=d.sensitivity,
                    delegable_to_org_roles=d.delegable_to_org_roles,
                    continuity=d.continuity,
                    status="active",
                )
            )
            registered.append(key)
            continue
        changed = False
        for attr, value in (
            ("description", d.description),
            ("scope_kind", d.scope_kind),
            ("sensitivity", d.sensitivity),
            ("delegable_to_org_roles", d.delegable_to_org_roles),
            ("continuity", d.continuity),
            ("status", "active"),
        ):
            if getattr(row, attr) != value:
                setattr(row, attr, value)
                changed = True
        if changed:
            row.updated_at = func.now()
            updated.append(key)
    synced_namespaces = {s.namespace for s in sources}
    deprecated = []
    for key, row in existing.items():
        if (
            key not in declared
            and row.module in synced_namespaces
            and row.status == "active"
        ):
            row.status = "deprecated"
            row.updated_at = func.now()
            deprecated.append(key)
    db.flush()
    report.registered = tuple(sorted(registered))
    report.updated = tuple(sorted(updated))
    report.deprecated = tuple(sorted(deprecated))
    for action, keys, noun in (
        ("rbac.catalogue.permission_registered", report.registered, "registered"),
        ("rbac.catalogue.permission_updated", report.updated, "updated"),
        ("rbac.catalogue.permission_deprecated", report.deprecated, "deprecated"),
    ):
        if keys:
            drafts.append(
                EventDraft(
                    action=action,
                    resource_type="rbac_permission",
                    changes={noun: list(keys)},
                )
            )

    # a changed permission must still fit the roles that hold it
    misfit = db.execute(
        select(RbacRole.key, RbacRolePermission.permission_key)
        .join(RbacRolePermission, RbacRolePermission.role_id == RbacRole.id)
        .join(RbacPermission, RbacPermission.key == RbacRolePermission.permission_key)
        .where(
            RbacRole.assignable_scope == "organization",
            (RbacPermission.scope_kind != "organization")
            | (~RbacPermission.delegable_to_org_roles),
        )
    ).all()
    if misfit:
        raise CatalogueError(
            [
                f"role {role_key!r} holds {perm!r}, which is now platform-scope or "
                "not delegable to organisation roles"
                for role_key, perm in misfit
            ]
        )

    # grants --------------------------------------------------------------------
    all_active = set(
        db.execute(
            select(RbacPermission.key).where(RbacPermission.status == "active")
        ).scalars()
    )
    synced_keys = set(declared)
    skipped = []
    for role in db.execute(
        select(RbacRole).where(RbacRole.managed_by == "code").order_by(RbacRole.key)
    ).scalars():
        desired_default = {
            k for k, (_, d) in declared.items() if role.key in d.default_grants
        }
        if role.state == "retired":
            if desired_default or role.auto_grant_new_permissions:
                skipped.append(role.key)
                drafts.append(
                    role_event(
                        "rbac.system_role.sync_skipped_retired",
                        RoleSnapshot(
                            role_id=str(role.id),
                            role_key=role.key,
                            display_name=role.display_name,
                        ),
                    )
                )
            continue
        current = set(granted_keys(db, role.id))
        add = set(desired_default)
        remove: set[str] = set()
        if role.auto_grant_new_permissions:
            add |= all_active
        else:
            remove = {
                k for k in current if k in synced_keys and k not in desired_default
            }
        add -= current
        if not add and not remove:
            continue
        for key in sorted(add):
            db.add(
                RbacRolePermission(
                    role_id=role.id, granted_by=actor_label, permission_key=key
                )
            )
        if remove:
            db.query(RbacRolePermission).filter(
                RbacRolePermission.role_id == role.id,
                RbacRolePermission.permission_key.in_(sorted(remove)),
            ).delete(synchronize_session=False)
        db.flush()
        append_revision(
            db,
            role,
            "synced" if role.managed_by == "code" else "permissions_changed",
            changed_by=actor_label,
        )
        report.grants_added[role.key] = tuple(sorted(add))
        report.grants_removed[role.key] = tuple(sorted(remove))
        drafts.append(
            role_event(
                "rbac.system_role.synced",
                RoleSnapshot(
                    role_id=str(role.id),
                    role_key=role.key,
                    display_name=role.display_name,
                ),
                added=sorted(add),
                removed=sorted(remove),
            )
        )
    report.grants_added = {k: v for k, v in report.grants_added.items() if v}
    report.grants_removed = {k: v for k, v in report.grants_removed.items() if v}
    report.skipped_retired_roles = tuple(skipped)
    report.events = tuple(drafts)
    if audit and drafts:
        result = emit(
            db,
            drafts,
            actor=actor,
            system_actor=None if actor is not None else SYNC_ACTOR,
        )
        report.events_written = result.total
    return report
