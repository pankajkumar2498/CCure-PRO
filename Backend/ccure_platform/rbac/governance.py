"""
ccure_platform/rbac/governance.py — the rules that stop RBAC being used to
escalate, and that keep it administrable.

RBAC-1 builds the **primitives** and exposes no administration API (that is
RBAC-7). Putting the rules here, once, is what stops a later endpoint
re-implementing them slightly differently. Everything is expressed in
permissions and scope — never in a role's id, key or name.

The checks are pure functions over what the engine already has (a principal, its
grants, the catalogue) plus the facts about the change, and each returns a list
of ``Violation`` rather than raising, so a caller can show all of them and an
audit event can carry them:

* **assignment** — who may give a role to whom, and where:
  the actor holds ``platform.user.assign_role`` in the organisation (or
  ``platform.role.assign_platform`` for a platform-scope role); the role is
  ``active`` and assignable at that scope; no self-assignment; the target is in
  the organisation (v1 is single-organisation membership); and the **escalation
  ceiling** — every permission the role carries is one the actor holds in that
  scope. An administrator cannot grant what they do not have.
* **role permissions** — creating a role or changing what it holds: system roles
  are immutable to administrators; an organisation role holds only delegable,
  organisation-scope permissions; the same ceiling; and an actor may not add
  permissions to a role they currently hold.
* **lifecycle** — ``active → retiring → retired``, with reactivation; the same
  table the database trigger enforces.
* **continuity** — the capability-based invariant (RBAC-0 §9): the platform
  always has an active, verified human holding each continuity permission at
  platform scope, and each active organisation always has a holder of
  ``platform.user.assign_role``. A change that would *newly* break it is a
  blocker. **When nothing is declared the answer is "not assessable", never
  "ok"** — an absent answer is not a passing one.
* **retirement** — what must be true before a role can be retired.
* **default role** — the safety rules for the role a purpose assigns.

Nothing here retires, renames or deletes anything. Destructive lifecycle
operations belong to later phases and will call these.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Collection, Iterable

from ccure_platform.rbac import contract as c
from ccure_platform.rbac import engine
from ccure_platform.rbac.audit import EventDraft, emit
from ccure_platform.rbac.model import RbacDefaultRole, RbacRole
from sqlalchemy import select, text
from sqlalchemy.orm import Session


@dataclass(frozen=True, slots=True)
class Violation:
    code: str
    message: str


class GovernanceError(ValueError):
    """A change governance refuses. ``violations`` lists every reason."""

    def __init__(self, violations: Iterable[Violation]):
        self.violations = tuple(violations)
        super().__init__("; ".join(f"{v.code}: {v.message}" for v in self.violations))


# ── lifecycle ─────────────────────────────────────────────────────────────────


def validate_transition(current: str, target: str) -> Violation | None:
    """None if ``current → target`` is allowed; otherwise why not. The same
    table the database trigger enforces (``contract.ROLE_TRANSITIONS``)."""
    if current not in c.ROLE_STATES or target not in c.ROLE_STATES:
        return Violation("unknown_state", f"{current!r} → {target!r}")
    if current == target:
        return Violation("no_change", f"role is already {current}")
    if target not in c.ROLE_TRANSITIONS[current]:
        return Violation(
            "invalid_transition",
            f"a {current} role cannot become {target} "
            f"(allowed: {', '.join(c.ROLE_TRANSITIONS[current]) or 'none'})",
        )
    return None


# ── assignment ────────────────────────────────────────────────────────────────


def _unknown_or_retired(
    catalogue: engine.Catalogue, keys: Collection[str]
) -> list[Violation]:
    out = []
    for key in sorted(keys):
        perm = catalogue.get(key)
        if perm is None:
            out.append(
                Violation("unknown_permission", f"{key} is not in the catalogue")
            )
        elif perm.status == "retired":
            out.append(Violation("retired_permission", f"{key} is retired"))
    return out


def check_assignment(
    actor: c.Principal,
    actor_grants: Iterable[c.Grant],
    catalogue: engine.Catalogue,
    *,
    target_user_id: str,
    target_user_org_id: str | None,
    role: c.Role,
    role_permission_keys: Collection[str],
    scope_type: str,
    scope_org_id: str | None = None,
) -> tuple[Violation, ...]:
    """Every reason ``actor`` may not give ``role`` to the target at this scope.
    An empty tuple means the assignment is permitted."""
    grants = tuple(actor_grants)
    out: list[Violation] = []

    if actor.kind != "human":
        out.append(Violation("service_actor", "a service identity cannot assign roles"))
    if actor.principal_id == target_user_id:
        out.append(
            Violation("self_assignment", "an account cannot assign its own roles")
        )
    if role.state != "active":
        out.append(
            Violation("role_not_assignable", f"a {role.state} role cannot be assigned")
        )
    if scope_type != role.assignable_scope:
        out.append(
            Violation(
                "scope_mismatch",
                f"the role is assignable at {role.assignable_scope} scope, not {scope_type}",
            )
        )
    if scope_type == "organization":
        if not scope_org_id:
            out.append(
                Violation("scope_org_missing", "an organisation assignment names one")
            )
        else:
            if role.org_id is not None and role.org_id != scope_org_id:
                out.append(
                    Violation(
                        "role_org_mismatch",
                        "an organisation role cannot be assigned outside its organisation",
                    )
                )
            if target_user_org_id != scope_org_id:
                out.append(
                    Violation(
                        "cross_org_assignment",
                        "the user is not a member of that organisation",
                    )
                )
    elif scope_type == "platform" and scope_org_id:
        out.append(
            Violation(
                "scope_org_unexpected", "a platform assignment names no organisation"
            )
        )

    # authority and ceiling, from exactly what the engine would allow the actor
    if scope_type == "platform":
        reach = engine.platform_held_keys(actor, grants, catalogue)
        authority = c.ASSIGN_PLATFORM_ROLE_KEY
    else:
        reach = engine.held_keys(actor, grants, catalogue, scope_org_id)
        authority = c.ASSIGN_ROLE_KEY
    if authority not in reach:
        out.append(
            Violation("missing_authority", f"the actor does not hold {authority}")
        )
    out.extend(_unknown_or_retired(catalogue, role_permission_keys))
    live_keys = {
        k
        for k in role_permission_keys
        if k in catalogue and catalogue[k].status != "retired"
    }
    missing = sorted(live_keys - reach)
    if missing:
        out.append(
            Violation(
                "escalation_ceiling",
                "the actor does not hold " + ", ".join(missing),
            )
        )
    return tuple(out)


# ── role definition ───────────────────────────────────────────────────────────


def check_role_permissions(
    actor: c.Principal,
    actor_grants: Iterable[c.Grant],
    catalogue: engine.Catalogue,
    *,
    operation: str,
    kind: str,
    assignable_scope: str,
    org_id: str | None,
    permission_keys: Collection[str],
    actor_holds_this_role: bool = False,
) -> tuple[Violation, ...]:
    """
    Every reason ``actor`` may not create a role (``operation='create'``) or add
    permissions to one (``'update'``) with ``permission_keys``. Removing
    permissions is never checked against the ceiling — taking away is always
    within an actor's power; call this only with the keys being *added*.
    """
    if operation not in ("create", "update"):
        raise ValueError(f"unknown operation {operation!r}")
    grants = tuple(actor_grants)
    out: list[Violation] = []

    if kind == "system":
        out.append(
            Violation(
                "system_role_immutable",
                "a system role's permissions change only with a catalogue release",
            )
        )
    if actor.kind != "human":
        out.append(Violation("service_actor", "a service identity cannot edit roles"))
    if actor_holds_this_role and permission_keys and operation == "update":
        out.append(
            Violation(
                "self_modification",
                "an account cannot add permissions to a role it holds",
            )
        )

    if assignable_scope == "platform":
        reach = engine.platform_held_keys(actor, grants, catalogue)
        authority = c.CREATE_PLATFORM_ROLE_KEY
    else:
        if not org_id:
            out.append(
                Violation(
                    "scope_org_missing", "an organisation role names its organisation"
                )
            )
        reach = engine.held_keys(actor, grants, catalogue, org_id)
        authority = c.CREATE_ROLE_KEY if operation == "create" else c.UPDATE_ROLE_KEY
    if authority not in reach:
        out.append(
            Violation("missing_authority", f"the actor does not hold {authority}")
        )

    out.extend(_unknown_or_retired(catalogue, permission_keys))
    live = {
        k
        for k in permission_keys
        if k in catalogue and catalogue[k].status != "retired"
    }
    if assignable_scope == "organization":
        for key in sorted(live):
            perm = catalogue[key]
            if perm.scope_kind != "organization" or not perm.delegable_to_org_roles:
                out.append(
                    Violation(
                        "not_delegable",
                        f"{key} cannot be held by an organisation-scope role",
                    )
                )
    missing = sorted(live - reach)
    if missing:
        out.append(
            Violation(
                "escalation_ceiling", "the actor does not hold " + ", ".join(missing)
            )
        )
    return tuple(out)


# ── continuity ────────────────────────────────────────────────────────────────

_HOLDERS_SQL = """
SELECT DISTINCT ur.user_id
  FROM rbac_user_roles ur
  JOIN rbac_roles r ON r.id = ur.role_id
  JOIN rbac_role_permissions rp ON rp.role_id = r.id AND rp.permission_key = :key
  JOIN rbac_permissions p ON p.key = rp.permission_key AND p.status <> 'retired'
  JOIN users u ON u.id = ur.user_id
 WHERE ur.revoked_at IS NULL
   AND (ur.expires_at IS NULL OR ur.expires_at > now())
   AND r.state IN ('active', 'retiring')
   AND u.is_active AND NOT u.is_deleted AND u.is_verified AND u.approved_at IS NOT NULL
   AND ur.user_id <> ALL(:ex_users)
   AND ur.role_id::text <> ALL(:ex_roles)
   AND ur.id::text <> ALL(:ex_assignments)
   AND (
        (:platform AND ur.scope_type = 'platform')
     OR (NOT :platform AND (
            (ur.scope_type = 'organization' AND ur.scope_org_id = :org)
         OR (ur.scope_type = 'platform' AND u.org_id = :org)))
   )
"""


def holders(
    db: Session,
    permission_key: str,
    *,
    platform: bool,
    org_id: str | None = None,
    exclude_user_ids: Collection[str] = (),
    exclude_role_ids: Collection[str] = (),
    exclude_assignment_ids: Collection[str] = (),
) -> frozenset[str]:
    """The **active, verified human** accounts holding ``permission_key`` — at
    platform scope, or in ``org_id`` (an organisation-scope assignment there, or
    a platform-scope holder whose own organisation it is). The ``exclude_*``
    arguments simulate a change: who would still hold it if these went away."""
    rows = db.execute(
        text(_HOLDERS_SQL),
        {
            "key": permission_key,
            "platform": platform,
            "org": org_id,
            "ex_users": list(exclude_user_ids),
            "ex_roles": [str(i) for i in exclude_role_ids],
            "ex_assignments": [str(i) for i in exclude_assignment_ids],
        },
    ).scalars()
    return frozenset(rows)


@dataclass(frozen=True, slots=True)
class ContinuityReport:
    #: ``ok`` · ``violated`` · ``incomplete`` (what is declared holds, but a
    #: frozen continuity key is not declared yet) · ``not_assessable`` (nothing
    #: is declared, so nothing can be said — never reported as ok).
    status: str
    platform_holder_counts: dict[str, int] = field(default_factory=dict)
    platform_violations: tuple[str, ...] = ()
    org_violations: tuple[str, ...] = ()
    undeclared_keys: tuple[str, ...] = ()
    org_assessable: bool = False

    @property
    def violations(self) -> frozenset[str]:
        return frozenset(
            [f"platform:{k}" for k in self.platform_violations]
            + [f"org:{o}" for o in self.org_violations]
        )


def continuity_report(
    db: Session,
    *,
    exclude_user_ids: Collection[str] = (),
    exclude_role_ids: Collection[str] = (),
    exclude_assignment_ids: Collection[str] = (),
) -> ContinuityReport:
    """Measure the continuity invariants, optionally as if some users, roles or
    assignments were gone."""
    from ccure_platform.rbac.model import RbacPermission

    declared = set(
        db.execute(
            select(RbacPermission.key).where(
                RbacPermission.continuity.is_(True), RbacPermission.status != "retired"
            )
        ).scalars()
    )
    undeclared = tuple(sorted(c.CONTINUITY_KEYS - declared))
    if not declared:
        return ContinuityReport(status="not_assessable", undeclared_keys=undeclared)

    ex = dict(
        exclude_user_ids=exclude_user_ids,
        exclude_role_ids=exclude_role_ids,
        exclude_assignment_ids=exclude_assignment_ids,
    )
    counts, bad = {}, []
    for key in sorted(declared):
        n = len(holders(db, key, platform=True, **ex))
        counts[key] = n
        if n == 0:
            bad.append(key)

    org_bad: list[str] = []
    org_assessable = c.ASSIGN_ROLE_KEY in declared
    if org_assessable:
        for (org_id,) in db.execute(
            text("SELECT id FROM organizations WHERE is_active AND archived_at IS NULL")
        ):
            if not holders(db, c.ASSIGN_ROLE_KEY, platform=False, org_id=org_id, **ex):
                org_bad.append(org_id)

    if bad or org_bad:
        status = "violated"
    elif undeclared or not org_assessable:
        status = "incomplete"
    else:
        status = "ok"
    return ContinuityReport(
        status=status,
        platform_holder_counts=counts,
        platform_violations=tuple(bad),
        org_violations=tuple(org_bad),
        undeclared_keys=undeclared,
        org_assessable=org_assessable,
    )


def continuity_regressions(
    db: Session,
    *,
    exclude_user_ids: Collection[str] = (),
    exclude_role_ids: Collection[str] = (),
    exclude_assignment_ids: Collection[str] = (),
) -> tuple[str, ...]:
    """The continuity violations a change would *introduce*: present with the
    exclusions, absent without. A system that is already broken does not block a
    change that does not make it worse."""
    before = continuity_report(db).violations
    after = continuity_report(
        db,
        exclude_user_ids=exclude_user_ids,
        exclude_role_ids=exclude_role_ids,
        exclude_assignment_ids=exclude_assignment_ids,
    ).violations
    return tuple(sorted(after - before))


# ── retirement ────────────────────────────────────────────────────────────────


def retirement_blockers(db: Session, role_id: str) -> tuple[Violation, ...]:
    """
    What must change before ``role_id`` can be retired. Empty means it may be.
    The gate (RBAC-0 R3): no live assignments, not a configured default role, and
    no continuity invariant newly broken. Read-only — it retires nothing.
    """
    out: list[Violation] = []
    live = db.execute(
        text(
            "SELECT count(*) FROM rbac_user_roles WHERE role_id = :r AND revoked_at IS NULL"
        ),
        {"r": role_id},
    ).scalar_one()
    if live:
        out.append(
            Violation(
                "active_assignments",
                f"{live} active assignment(s) must be reassigned or revoked first",
            )
        )
    purposes = list(
        db.execute(
            select(RbacDefaultRole.purpose).where(RbacDefaultRole.role_id == role_id)
        ).scalars()
    )
    if purposes:
        out.append(
            Violation(
                "default_role",
                "the role is the configured default for " + ", ".join(sorted(purposes)),
            )
        )
    broken = continuity_regressions(db, exclude_role_ids=(role_id,))
    if broken:
        out.append(
            Violation("continuity", "retiring it would break: " + ", ".join(broken))
        )
    return tuple(out)


# ── default role ──────────────────────────────────────────────────────────────


def default_role_violations(db: Session, role_id: str) -> tuple[Violation, ...]:
    """Why ``role_id`` may not be a default role: it must exist, be active and
    organisation-assignable, and hold no non-delegable or continuity permission.
    (The database trigger enforces the same rules; this is the readable form.)"""
    role = db.get(RbacRole, role_id)
    if role is None:
        return (Violation("unknown_role", "no such role"),)
    out: list[Violation] = []
    if role.state != "active":
        out.append(Violation("not_active", f"the role is {role.state}"))
    if role.assignable_scope != "organization":
        out.append(
            Violation(
                "not_org_assignable",
                "a default role is assigned within an organisation",
            )
        )
    bad = (
        db.execute(
            text(
                "SELECT p.key FROM rbac_role_permissions rp "
                "JOIN rbac_permissions p ON p.key = rp.permission_key "
                "WHERE rp.role_id = :r AND (NOT p.delegable_to_org_roles OR p.continuity) "
                "ORDER BY p.key"
            ),
            {"r": role_id},
        )
        .scalars()
        .all()
    )
    if bad:
        out.append(
            Violation(
                "privileged_permissions",
                "the role holds non-delegable or continuity permissions: "
                + ", ".join(bad),
            )
        )
    return tuple(out)


def configure_default_role(
    db: Session,
    purpose: str,
    role_id: str,
    *,
    updated_by: str | None = None,
    audit_actor=None,
) -> EventDraft:
    """
    Point ``purpose`` at ``role_id`` after the safety rules pass, and return the
    ``rbac.default_role.changed`` event. The event is written when ``audit_actor``
    (the signed-in account making the change) is given. Refuses with
    ``GovernanceError``; changes nothing then. The caller commits.
    """
    if purpose not in c.DEFAULT_ROLE_PURPOSES:
        raise GovernanceError([Violation("unknown_purpose", f"{purpose!r}")])
    problems = default_role_violations(db, role_id)
    if problems:
        raise GovernanceError(problems)
    row = db.get(RbacDefaultRole, purpose)
    before = str(row.role_id) if row is not None else None
    if row is None:
        db.add(RbacDefaultRole(purpose=purpose, role_id=role_id, updated_by=updated_by))
    else:
        row.role_id = role_id
        row.updated_by = updated_by
    db.flush()
    draft = EventDraft(
        action="rbac.default_role.changed",
        resource_type="rbac_default_role",
        resource_id=purpose,
        changes={"purpose": purpose, "from_role_id": before, "to_role_id": role_id},
    )
    if audit_actor is not None:
        emit(db, [draft], actor=audit_actor)
    return draft
