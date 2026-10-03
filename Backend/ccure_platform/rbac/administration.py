"""
ccure_platform/rbac/administration.py — governed RBAC administration (RBAC-7).

The service layer behind the Platform RBAC administration API: list and inspect roles,
create custom organisation roles, rename, change permissions, retire/reactivate,
assign and revoke, replace a role, and say which roles an actor may hand out. Every
mutation is **decided by the RBAC-2 governance rules** (``governance.check_*``,
``transition_role``, the continuity invariants and the database triggers) over the
actor's *grants* — no role name, key or display name is an input — and every one returns
the audit events it earned. Nothing here commits: the caller owns the transaction.

What this layer adds to governance is only the database work governance deliberately
left to the caller (writing a rename, a permission change, an assignment, a revocation,
a replacement), and the read models the UI needs. It adds no rule: a rule that is not in
``governance`` is not a rule.

Visibility is scoped: a role of an organisation is visible with the read permission *in
that organisation*; system roles are global. A principal with no RBAC assignment (the
legacy-only accounts RBAC-8 provisions) holds no RBAC permission, so it can read and
change nothing here — administration needs the new model by design.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

from ccure_platform.rbac import contract as c
from ccure_platform.rbac import engine, governance, resolver
from ccure_platform.rbac.audit import (
    EventDraft,
    RoleSnapshot,
    assignment_event,
    role_event,
)
from ccure_platform.rbac.governance import GovernanceError, Violation
from ccure_platform.rbac.model import (
    RbacPermission,
    RbacRole,
    RbacRolePermission,
    RbacRoleRevision,
    RbacUserRole,
    append_revision,
    granted_keys,
    to_role,
)
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

#: Violation codes that are a privilege-escalation attempt (audited as such); every
#: other refusal is an ordinary denial.
ESCALATION_CODES = frozenset(
    {
        "escalation_ceiling",
        "self_assignment",
        "self_modification",
        "scope_mismatch",
        "role_org_mismatch",
        "cross_org_assignment",
        "not_delegable",
    }
)


# ── the actor ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Actor:
    user: object
    principal: c.Principal
    grants: tuple[c.Grant, ...]
    catalogue: dict

    @property
    def provisioned(self) -> bool:
        return bool(self.grants)


def actor_for(db: Session, user) -> Actor:
    principal = resolver.principal_for_user(user)
    return Actor(
        user=user,
        principal=principal,
        grants=resolver.resolve_grants(db, principal),
        catalogue=resolver.load_catalogue(db),
    )


def holds(actor: Actor, key: str, org_id: str | None = None) -> bool:
    """Whether the actor is allowed ``key`` in ``org_id`` (its own organisation when
    None) — exactly the engine's rule."""
    scope = c.ScopeContext(requested_org_id=org_id) if org_id else c.ScopeContext()
    return engine.decide(
        actor.principal, actor.grants, actor.catalogue, key, scope
    ).allowed


# ── read models ───────────────────────────────────────────────────────────────


def _summary(db: Session, row: RbacRole, counts: dict[str, int]) -> dict:
    return {
        "id": str(row.id),
        "key": row.key,
        "display_name": row.display_name,
        "description": row.description,
        "kind": row.kind,
        "assignable_scope": row.assignable_scope,
        "org_id": row.org_id,
        "state": row.state,
        "revision": row.revision,
        "permission_count": counts.get(("p", str(row.id)), 0),
        "assignment_count": counts.get(("a", str(row.id)), 0),
        "replaced_by_role_id": (
            str(row.replaced_by_role_id) if row.replaced_by_role_id else None
        ),
    }


def _counts(db: Session) -> dict:
    out: dict = {}
    for rid, n in db.execute(
        text("SELECT role_id::text, count(*) FROM rbac_role_permissions GROUP BY 1")
    ):
        out[("p", rid)] = n
    for rid, n in db.execute(
        text(
            "SELECT role_id::text, count(*) FROM rbac_user_roles "
            "WHERE revoked_at IS NULL GROUP BY 1"
        )
    ):
        out[("a", rid)] = n
    return out


def list_roles(db: Session, actor: Actor, org_id: str | None, *, include_retired=False):
    """Roles the actor may see in ``org_id``: every system role and platform custom
    role, and that organisation's custom roles. Empty (not an error) without
    ``platform.role.read``."""
    if not holds(actor, "platform.role.read", org_id):
        return []
    counts = _counts(db)
    q = select(RbacRole).where(
        (RbacRole.org_id.is_(None)) | (RbacRole.org_id == org_id)
    )
    if not include_retired:
        q = q.where(RbacRole.state != "retired")
    rows = db.execute(q.order_by(RbacRole.kind, RbacRole.display_name)).scalars().all()
    return [_summary(db, r, counts) for r in rows]


def role_detail(db: Session, actor: Actor, role_id: str, org_id: str | None):
    row = db.get(RbacRole, role_id)
    if row is None or (row.org_id and row.org_id != org_id):
        return None
    if not holds(actor, "platform.role.read", org_id):
        return None
    detail = _summary(db, row, _counts(db))
    keys = sorted(granted_keys(db, row.id))
    detail["permissions"] = keys
    detail["history"] = role_history(db, row.id)
    detail["retirement_blockers"] = (
        [v.code for v in governance.retirement_blockers(db, row.id)]
        if row.state != "retired"
        else []
    )
    detail["sensitive"] = is_sensitive_role(db, row, actor.catalogue)
    return detail


def role_history(db: Session, role_id: str) -> list[dict]:
    rows = db.execute(
        select(RbacRoleRevision)
        .where(RbacRoleRevision.role_id == role_id)
        .order_by(RbacRoleRevision.revision.desc(), RbacRoleRevision.changed_at.desc())
    ).scalars()
    return [
        {
            "revision": r.revision,
            "change_kind": r.change_kind,
            "display_name": r.display_name,
            "state": r.state,
            "changed_by": r.changed_by,
            "changed_at": r.changed_at.isoformat() if r.changed_at else None,
        }
        for r in rows
    ]


def list_permissions(db: Session, actor: Actor) -> list[dict]:
    """The permission catalogue as the UI needs it — keys, never structure."""
    if not holds(actor, "platform.permission.read"):
        return []
    rows = db.execute(
        select(RbacPermission).order_by(
            RbacPermission.module, RbacPermission.resource, RbacPermission.action
        )
    ).scalars()
    return [
        {
            "key": r.key,
            "module": r.module,
            "resource": r.resource,
            "action": r.action,
            "description": r.description,
            "scope": r.scope_kind,
            "sensitivity": r.sensitivity,
            "delegable": bool(r.delegable_to_org_roles),
            "status": r.status,
        }
        for r in rows
    ]


def is_sensitive_role(db: Session, row: RbacRole, catalogue) -> bool:
    """A role whose change is a sensitive governance operation: a system role, a
    platform-scope role, or one holding any privileged permission."""
    if row.kind == "system" or row.assignable_scope == "platform":
        return True
    return any(
        catalogue.get(k) is not None and catalogue[k].sensitivity == "privileged"
        for k in granted_keys(db, row.id)
    )


# ── assignments: read ─────────────────────────────────────────────────────────


def user_assignments(db: Session, actor: Actor, user_id: str) -> list[dict] | None:
    """A user's role assignments for management and display. None when the target is
    not visible to the actor (another organisation, no read permission)."""
    org = db.execute(
        text("SELECT org_id FROM users WHERE id = :u"), {"u": user_id}
    ).scalar()
    if org is None or not holds(actor, "platform.user.read", org):
        return None
    now = datetime.now(timezone.utc)
    rows = db.execute(
        select(RbacUserRole, RbacRole)
        .join(RbacRole, RbacRole.id == RbacUserRole.role_id)
        .where(RbacUserRole.user_id == user_id)
        .order_by(RbacUserRole.granted_at.desc())
    ).all()
    out = []
    for a, r in rows:
        if a.revoked_at is not None:
            st = "revoked"
        elif a.expires_at is not None and a.expires_at <= now:
            st = "expired"
        else:
            st = "active"
        out.append(
            {
                "id": str(a.id),
                "role": {
                    "id": str(r.id),
                    "display_name": r.display_name,
                    "state": r.state,
                    "kind": r.kind,
                },
                "scope_type": a.scope_type,
                "scope_org_id": a.scope_org_id,
                "status": st,
                "granted_at": a.granted_at.isoformat() if a.granted_at else None,
                "expires_at": a.expires_at.isoformat() if a.expires_at else None,
                "revoked_at": a.revoked_at.isoformat() if a.revoked_at else None,
                "revoke_reason": a.revoke_reason,
            }
        )
    return out


# ── assignable roles / delegation ─────────────────────────────────────────────


def assignable_roles(
    db: Session, actor: Actor, target_user_id: str | None, org_id: str
) -> dict:
    """Which roles ``actor`` may give an account in ``org_id`` — the governance rules
    applied per role — plus the actor's delegation summary. The UI offers exactly the
    roles marked ``assignable``; the assignment itself is checked again."""
    role_rows = db.execute(
        select(RbacRole)
        .where(
            RbacRole.state == "active",
            (RbacRole.org_id.is_(None)) | (RbacRole.org_id == org_id),
        )
        .order_by(RbacRole.display_name)
    ).scalars()
    roles = []
    for row in role_rows:
        scope_type = row.assignable_scope
        problems = governance.check_assignment(
            actor.principal,
            actor.grants,
            actor.catalogue,
            target_user_id=target_user_id or "",
            target_user_org_id=org_id,
            role=to_role(row),
            role_permission_keys=granted_keys(db, row.id),
            scope_type=scope_type,
            scope_org_id=org_id if scope_type == "organization" else None,
        )
        roles.append(
            {
                "id": str(row.id),
                "display_name": row.display_name,
                "kind": row.kind,
                "assignable_scope": scope_type,
                "assignable": not problems,
                "reasons": sorted({v.code for v in problems}),
            }
        )
    reach = engine.held_keys(actor.principal, actor.grants, actor.catalogue, org_id)
    return {
        "org_id": org_id,
        "roles": roles,
        "delegation": {
            "can_assign_in_organisation": c.ASSIGN_ROLE_KEY in reach,
            "can_assign_platform_roles": c.ASSIGN_PLATFORM_ROLE_KEY
            in engine.platform_held_keys(
                actor.principal, actor.grants, actor.catalogue
            ),
            "can_create_roles": c.CREATE_ROLE_KEY in reach,
            "ceiling": sorted(reach),
        },
    }


# ── mutations ─────────────────────────────────────────────────────────────────


def _snap(row: RbacRole) -> RoleSnapshot:
    return RoleSnapshot(
        role_id=str(row.id),
        role_key=row.key,
        display_name=row.display_name,
        org_id=row.org_id,
    )


def _require_visible(row: RbacRole | None, org_id: str | None) -> RbacRole:
    if row is None or (row.org_id and row.org_id != org_id):
        raise GovernanceError([Violation("unknown_role", "no such role")])
    return row


def _slug(display_name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", display_name.lower()).strip("-")[:40]
    return slug or "role"


def create_custom_role(
    db: Session,
    actor: Actor,
    *,
    org_id: str,
    display_name: str,
    permission_keys,
    description: str | None = None,
) -> tuple[RbacRole, list[EventDraft]]:
    """A custom role belonging to ``org_id``, holding only permissions the actor may
    delegate there (``governance.define_custom_org_role``). The key is derived from the
    display name; a clash adds a suffix."""
    base = _slug(display_name)
    slug, n = base, 1
    while db.execute(
        select(RbacRole.id).filter_by(key=f"custom.{org_id}.{slug}")
    ).first():
        n += 1
        slug = f"{base}-{n}"
    try:
        with db.begin_nested():
            row, event = governance.define_custom_org_role(
                db,
                actor.principal,
                actor.grants,
                actor.catalogue,
                org_id=org_id,
                slug=slug,
                display_name=display_name,
                permission_keys=list(permission_keys),
                description=description,
            )
    except IntegrityError:
        raise GovernanceError(
            [
                Violation(
                    "display_name_in_use", "another live role has this display name"
                )
            ]
        ) from None
    return row, [event]


def rename_role(
    db: Session,
    actor: Actor,
    row: RbacRole,
    *,
    display_name: str | None,
    description: str | None,
) -> list[EventDraft]:
    """Change a role's *label* (and description). A display name is presentation: it
    changes nothing a principal may do. A custom role needs ``platform.role.update`` in
    its organisation; a system role needs ``platform.role.rename_system``, platform-wide.
    """
    problems: list[Violation] = []
    if row.state == "retired":
        problems.append(Violation("role_retired", "a retired role cannot be edited"))
    if row.kind == "system":
        if "platform.role.rename_system" not in engine.platform_held_keys(
            actor.principal, actor.grants, actor.catalogue
        ):
            problems.append(
                Violation(
                    "missing_authority",
                    "the actor does not hold platform.role.rename_system",
                )
            )
    elif row.assignable_scope == "platform":
        if c.CREATE_PLATFORM_ROLE_KEY not in engine.platform_held_keys(
            actor.principal, actor.grants, actor.catalogue
        ):
            problems.append(
                Violation("missing_authority", "platform role authority required")
            )
    elif not holds(actor, c.UPDATE_ROLE_KEY, row.org_id):
        problems.append(
            Violation(
                "missing_authority", f"the actor does not hold {c.UPDATE_ROLE_KEY}"
            )
        )
    name = None if display_name is None else display_name.strip()
    if name is not None and not (1 <= len(name) <= c.DISPLAY_NAME_MAX):
        problems.append(
            Violation("invalid_display_name", "a display name is 1 to 100 characters")
        )
    if name is None and description is None:
        problems.append(Violation("nothing_to_change", "no change requested"))
    if problems:
        raise GovernanceError(problems)
    events: list[EventDraft] = []
    before = row.display_name
    kind = "described"
    if name is not None and name != before:
        row.display_name = name
        kind = "renamed"
    if description is not None:
        row.description = description
    try:
        with db.begin_nested():
            db.flush()
    except IntegrityError:
        raise GovernanceError(
            [
                Violation(
                    "display_name_in_use", "another live role has this display name"
                )
            ]
        ) from None
    append_revision(db, row, kind, changed_by=actor.principal.principal_id)
    events.append(
        role_event(
            "rbac.role.renamed" if kind == "renamed" else "rbac.role.updated",
            _snap(row),
            from_display_name=before,
            to_display_name=row.display_name,
        )
    )
    return events


def set_role_permissions(
    db: Session, actor: Actor, row: RbacRole, permission_keys
) -> tuple[list[EventDraft], dict]:
    """Make ``row`` hold exactly ``permission_keys``. Custom roles only (a system role's
    permissions change with a catalogue release). Taking away is always allowed; adding
    is checked against the delegation ceiling and the role's scope
    (``governance.check_role_permissions``), and an actor cannot add to a role it holds.
    """
    wanted = set(permission_keys)
    current = set(granted_keys(db, row.id))
    added, removed = sorted(wanted - current), sorted(current - wanted)
    held_by_actor = bool(
        db.execute(
            select(RbacUserRole.id).where(
                RbacUserRole.user_id == actor.principal.principal_id,
                RbacUserRole.role_id == row.id,
                RbacUserRole.revoked_at.is_(None),
            )
        ).first()
    )
    problems = list(
        governance.check_role_permissions(
            actor.principal,
            actor.grants,
            actor.catalogue,
            operation="update",
            kind=row.kind,
            assignable_scope=row.assignable_scope,
            org_id=row.org_id,
            permission_keys=added,
            actor_holds_this_role=held_by_actor,
        )
    )
    if removed and not added and not problems:
        pass
    if row.kind != "system" and removed:
        # removing needs the same authority to edit the role
        edit_key = (
            c.CREATE_PLATFORM_ROLE_KEY
            if row.assignable_scope == "platform"
            else c.UPDATE_ROLE_KEY
        )
        if not holds(actor, edit_key, row.org_id) and not any(
            v.code == "missing_authority" for v in problems
        ):
            problems.append(
                Violation("missing_authority", f"the actor does not hold {edit_key}")
            )
    if row.state != "active":
        problems.append(
            Violation("role_not_active", f"a {row.state} role cannot be edited")
        )
    if not added and not removed:
        problems.append(
            Violation(
                "nothing_to_change", "the role already holds exactly these permissions"
            )
        )
    if problems:
        raise GovernanceError(problems)
    for key in removed:
        db.execute(
            text(
                "DELETE FROM rbac_role_permissions WHERE role_id = :r AND permission_key = :k"
            ),
            {"r": row.id, "k": key},
        )
    for key in added:
        db.add(
            RbacRolePermission(
                role_id=row.id,
                permission_key=key,
                granted_by=actor.principal.principal_id,
            )
        )
    db.flush()
    append_revision(
        db, row, "permissions_changed", changed_by=actor.principal.principal_id
    )
    event = role_event(
        "rbac.role.permissions_changed", _snap(row), added=added, removed=removed
    )
    return [event], {"added": added, "removed": removed}


def transition(
    db: Session,
    actor: Actor,
    row: RbacRole,
    target: str,
    *,
    reason: str | None = None,
    replacement_role_id: str | None = None,
) -> list[EventDraft]:
    """Retire (``retiring`` then ``retired``) or reactivate a role: authority and
    ceiling from ``governance.check_role_lifecycle``, the retirement gate (no live
    assignments, not a default role, no continuity regression) from ``transition_role``.
    A replacement, when named, must be an active role of the same scope."""
    problems = list(
        governance.check_role_lifecycle(
            actor.principal,
            actor.grants,
            actor.catalogue,
            role=to_role(row),
            target=target,
            role_permission_keys=granted_keys(db, row.id),
        )
    )
    if replacement_role_id:
        rep = db.get(RbacRole, replacement_role_id)
        if (
            rep is None
            or rep.state != "active"
            or rep.assignable_scope != row.assignable_scope
            or str(rep.id) == str(row.id)
            or (rep.org_id and rep.org_id != row.org_id)
        ):
            problems.append(
                Violation(
                    "invalid_replacement",
                    "the replacement must be another active role of the same scope",
                )
            )
    if problems:
        raise GovernanceError(problems)
    event = governance.transition_role(
        db,
        row,
        target,
        changed_by=actor.principal.principal_id,
        reason=reason,
        replaced_by_role_id=replacement_role_id,
    )
    return [event]


def _check_and_build(
    db: Session, actor: Actor, row: RbacRole, user_id, user_org, scope_org
):
    scope_type = row.assignable_scope
    return governance.check_assignment(
        actor.principal,
        actor.grants,
        actor.catalogue,
        target_user_id=user_id,
        target_user_org_id=user_org,
        role=to_role(row),
        role_permission_keys=granted_keys(db, row.id),
        scope_type=scope_type,
        scope_org_id=scope_org if scope_type == "organization" else None,
    )


def assign(
    db: Session, actor: Actor, user_id: str, role_id: str
) -> tuple[RbacUserRole, list[EventDraft]]:
    """Give ``role_id`` to a user: an organisation role in the user's own organisation,
    a platform role platform-wide. Every governance rule applies — organisation
    boundary, scope and permission ceilings, system-role restrictions,
    self-assignment, escalation."""
    row = db.get(RbacRole, role_id)
    user_org = db.execute(
        text("SELECT org_id FROM users WHERE id = :u AND NOT is_deleted"),
        {"u": user_id},
    ).scalar()
    if row is None or user_org is None:
        raise GovernanceError([Violation("unknown_target", "no such role or account")])
    scope_org = user_org if row.assignable_scope == "organization" else None
    problems = list(_check_and_build(db, actor, row, user_id, user_org, scope_org))
    if row.org_id and row.org_id != user_org:
        problems.append(
            Violation("role_org_mismatch", "the role belongs to another organisation")
        )
    if problems:
        raise GovernanceError(problems)
    assignment = RbacUserRole(
        user_id=user_id,
        role_id=row.id,
        scope_type=row.assignable_scope,
        scope_org_id=scope_org,
        granted_by=actor.principal.principal_id,
    )
    try:
        with db.begin_nested():
            db.add(assignment)
            db.flush()
    except IntegrityError as exc:
        raise GovernanceError(
            [
                Violation(
                    (
                        "already_assigned"
                        if "uq_rbac_user_roles_live" in str(exc)
                        else "refused_by_database"
                    ),
                    "the assignment was refused",
                )
            ]
        ) from None
    action = (
        "rbac.platform_role.assigned"
        if row.assignable_scope == "platform"
        else "rbac.role.assigned"
    )
    return assignment, [
        assignment_event(
            action,
            _snap(row),
            user_id=user_id,
            user_org_id=user_org,
            scope_type=row.assignable_scope,
            scope_org_id=scope_org,
        )
    ]


def revoke(
    db: Session, actor: Actor, assignment_id: str, *, reason: str = "manual"
) -> list[EventDraft]:
    """End an assignment (never delete it). Needs the authority to assign that role;
    refused when it would leave a continuity invariant broken — the last active
    superadmin, or the last account able to assign roles in an organisation."""
    a = db.get(RbacUserRole, assignment_id)
    if a is None or a.revoked_at is not None:
        raise GovernanceError(
            [Violation("unknown_assignment", "no such active assignment")]
        )
    row = db.get(RbacRole, a.role_id)
    user_org = db.execute(
        text("SELECT org_id FROM users WHERE id = :u"), {"u": a.user_id}
    ).scalar()
    problems: list[Violation] = []
    if a.scope_type == "platform":
        key = c.ASSIGN_PLATFORM_ROLE_KEY
        ok = key in engine.platform_held_keys(
            actor.principal, actor.grants, actor.catalogue
        )
    else:
        key = c.ASSIGN_ROLE_KEY
        ok = holds(actor, key, a.scope_org_id)
    if not ok:
        problems.append(
            Violation("missing_authority", f"the actor does not hold {key}")
        )
    broken = governance.continuity_regressions(db, exclude_assignment_ids=(str(a.id),))
    if broken:
        problems.append(
            Violation(
                "continuity",
                "removing it would leave nobody with: " + ", ".join(broken),
            )
        )
    if problems:
        raise GovernanceError(problems)
    a.revoked_at = datetime.now(timezone.utc)
    a.revoked_by = actor.principal.principal_id
    a.revoke_reason = reason
    db.flush()
    action = (
        "rbac.platform_role.revoked"
        if a.scope_type == "platform"
        else "rbac.role.revoked"
    )
    return [
        assignment_event(
            action,
            _snap(row),
            user_id=a.user_id,
            user_org_id=user_org,
            scope_type=a.scope_type,
            scope_org_id=a.scope_org_id,
        )
    ]


def replace_role(
    db: Session, actor: Actor, from_role_id: str, to_role_id: str
) -> tuple[int, list[EventDraft]]:
    """The replacement workflow: move every live assignment from one role to another
    (create the new assignment, then end the old with reason ``migrated``), each one
    governed, then verify no continuity invariant broke. The old role is *not* retired
    here — retire it afterwards (the gate now passes). All or nothing."""
    old, new = db.get(RbacRole, from_role_id), db.get(RbacRole, to_role_id)
    if old is None or new is None or old.id == new.id:
        raise GovernanceError(
            [Violation("unknown_role", "two different existing roles are required")]
        )
    if new.state != "active" or new.assignable_scope != old.assignable_scope:
        raise GovernanceError(
            [
                Violation(
                    "invalid_replacement",
                    "the replacement must be an active role of the same scope",
                )
            ]
        )
    live = (
        db.execute(
            select(RbacUserRole).where(
                RbacUserRole.role_id == old.id, RbacUserRole.revoked_at.is_(None)
            )
        )
        .scalars()
        .all()
    )
    events: list[EventDraft] = []
    before = governance.continuity_report(db).violations
    for a in live:
        user_org = db.execute(
            text("SELECT org_id FROM users WHERE id = :u"), {"u": a.user_id}
        ).scalar()
        problems = list(
            _check_and_build(db, actor, new, a.user_id, user_org, a.scope_org_id)
        )
        if new.org_id and new.org_id != user_org:
            problems.append(
                Violation(
                    "role_org_mismatch",
                    "the replacement belongs to another organisation",
                )
            )
        if problems:
            raise GovernanceError(
                [Violation(v.code, f"{a.user_id}: {v.message}") for v in problems]
            )
        db.add(
            RbacUserRole(
                user_id=a.user_id,
                role_id=new.id,
                scope_type=a.scope_type,
                scope_org_id=a.scope_org_id,
                granted_by=actor.principal.principal_id,
            )
        )
        db.flush()
        a.revoked_at = datetime.now(timezone.utc)
        a.revoked_by = actor.principal.principal_id
        a.revoke_reason = "migrated"
        db.flush()
        events.append(
            assignment_event(
                "rbac.role.reassigned",
                _snap(new),
                user_id=a.user_id,
                user_org_id=user_org,
                scope_type=a.scope_type,
                scope_org_id=a.scope_org_id,
                from_role_id=str(old.id),
                to_role_id=str(new.id),
            )
        )
    introduced = governance.continuity_report(db).violations - before
    if introduced:
        raise GovernanceError(
            [
                Violation(
                    "continuity",
                    "the replacement would leave: " + ", ".join(sorted(introduced)),
                )
            ]
        )
    events.append(
        role_event(
            "rbac.role.replaced",
            _snap(old),
            replacement_role_id=str(new.id),
            replacement_display_name=new.display_name,
            migrated_assignments=len(live),
        )
    )
    return len(live), events
