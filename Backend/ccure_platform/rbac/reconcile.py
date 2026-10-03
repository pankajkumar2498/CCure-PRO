"""
ccure_platform/rbac/reconcile.py — comparing who the legacy model says holds which role
with who the new model has assigned. RBAC-4.

The mapping is the golden one (legacy role → system role key; ``legacy_map``): a
super administrator is the platform-scope role, every other legacy role an
organisation-scope role in the account's own organisation. Nothing is inferred beyond
that.

**``reconcile`` only reads.** It reports five conditions and writes nothing:

``missing``             an active legacy account with a role and no live RBAC assignment
``incorrect``           live RBAC assignments that are not the expected one (wrong role
                        or wrong scope) for an account that has a legacy role
``duplicate``           an account holding several live assignments that conflict (the
                        same role twice is impossible — the database forbids it — so
                        this is two *different* system roles, or one role at two scopes)
``revoked_but_assigned``a legacy account that is deleted or disabled and still holds a
                        live RBAC assignment
``without_legacy``      an account with a live RBAC assignment and no legacy role

``plan`` turns ``missing`` into the assignments that would close it. ``apply`` writes
exactly those, and nothing else; it never touches the other four lists and never
assigns an account that is not in ``missing``. It is for a **controlled environment**:
the caller (``scripts/rbac/reconcile_assignments.py``) refuses to run it against a
database that holds real data unless told, by name, that it may.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ccure_platform.rbac import legacy_map
from ccure_platform.rbac.model import RbacRole, RbacUserRole
from sqlalchemy import text
from sqlalchemy.orm import Session

APPLY_ACTOR = "system:rbac-reconcile"


@dataclass(frozen=True, slots=True)
class Discrepancy:
    user_id: str
    legacy_role: str | None
    detail: str = ""
    expected_role_key: str | None = None
    held: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PlannedAssignment:
    user_id: str
    role_key: str
    scope_type: str
    scope_org_id: str | None


@dataclass
class Report:
    users_examined: int = 0
    missing: list[Discrepancy] = field(default_factory=list)
    incorrect: list[Discrepancy] = field(default_factory=list)
    duplicate: list[Discrepancy] = field(default_factory=list)
    revoked_but_assigned: list[Discrepancy] = field(default_factory=list)
    without_legacy: list[Discrepancy] = field(default_factory=list)

    @property
    def consistent(self) -> bool:
        return not (
            self.missing
            or self.incorrect
            or self.duplicate
            or self.revoked_but_assigned
            or self.without_legacy
        )

    def counts(self) -> dict[str, int]:
        return {
            "users_examined": self.users_examined,
            "missing": len(self.missing),
            "incorrect": len(self.incorrect),
            "duplicate": len(self.duplicate),
            "revoked_but_assigned": len(self.revoked_but_assigned),
            "without_legacy": len(self.without_legacy),
        }


def _expected_by_legacy_role() -> dict[str, tuple[str, str]]:
    """``{legacy role name: (system role key, assignable scope)}`` from the golden mapping."""
    return {
        r["legacy_role"]: (r["role_key"], r["assignable_scope"])
        for r in legacy_map.load_golden()["roles"]
    }


def reconcile(db: Session) -> Report:
    """Read-only comparison of every account. Writes nothing."""
    expected = _expected_by_legacy_role()
    now = datetime.now(timezone.utc)
    users = db.execute(
        text(
            "SELECT u.id, u.org_id, u.is_active, u.is_deleted, r.name "
            "FROM users u LEFT JOIN roles r ON r.id = u.role_id ORDER BY u.id"
        )
    ).all()
    held: dict[str, list[tuple[str, str, str | None]]] = {}
    rows = (
        db.query(
            RbacUserRole.user_id,
            RbacRole.key,
            RbacUserRole.scope_type,
            RbacUserRole.scope_org_id,
            RbacUserRole.expires_at,
        )
        .join(RbacRole, RbacRole.id == RbacUserRole.role_id)
        .filter(RbacUserRole.revoked_at.is_(None))
        .all()
    )
    for user_id, key, scope, org, expires in rows:
        if expires is not None and expires <= now:
            continue
        held.setdefault(user_id, []).append((key, scope, org))

    report = Report(users_examined=len(users))
    seen = set()
    for user_id, org_id, active, deleted, legacy_name in users:
        seen.add(user_id)
        mine = held.get(user_id, [])
        keys = tuple(sorted(k for k, _, _ in mine))
        live_legacy = bool(legacy_name) and active and not deleted
        if not live_legacy and mine:
            if legacy_name:
                report.revoked_but_assigned.append(
                    Discrepancy(
                        user_id,
                        legacy_name,
                        "the account is deleted or disabled",
                        held=keys,
                    )
                )
            else:
                report.without_legacy.append(
                    Discrepancy(user_id, None, "no legacy role", held=keys)
                )
            continue
        if not live_legacy:
            continue
        want = expected.get(legacy_name)
        if want is None:
            report.incorrect.append(
                Discrepancy(
                    user_id, legacy_name, "legacy role has no golden mapping", held=keys
                )
            )
            continue
        role_key, scope = want
        want_org = org_id if scope == "organization" else None
        if not mine:
            report.missing.append(
                Discrepancy(user_id, legacy_name, "no live RBAC assignment", role_key)
            )
            continue
        if len({(k, s, o) for k, s, o in mine}) > 1:
            report.duplicate.append(
                Discrepancy(
                    user_id,
                    legacy_name,
                    "several live assignments conflict",
                    role_key,
                    keys,
                )
            )
        if (role_key, scope, want_org) not in mine:
            report.incorrect.append(
                Discrepancy(
                    user_id,
                    legacy_name,
                    "no live assignment of the expected role at the expected scope",
                    role_key,
                    keys,
                )
            )
    for user_id, mine in held.items():
        if user_id not in seen:
            report.without_legacy.append(
                Discrepancy(
                    user_id,
                    None,
                    "an assignment for an account that does not exist",
                    held=tuple(sorted(k for k, _, _ in mine)),
                )
            )
    return report


def plan(db: Session, report: Report | None = None) -> list[PlannedAssignment]:
    """The assignments that would close ``missing`` — and nothing else."""
    report = report or reconcile(db)
    expected = _expected_by_legacy_role()
    orgs = {
        uid: org for uid, org in db.execute(text("SELECT id, org_id FROM users")).all()
    }
    out = []
    for f in report.missing:
        key, scope = expected[f.legacy_role]
        out.append(
            PlannedAssignment(
                user_id=f.user_id,
                role_key=key,
                scope_type=scope,
                scope_org_id=orgs[f.user_id] if scope == "organization" else None,
            )
        )
    return out


def apply(db: Session, planned: list[PlannedAssignment]) -> int:
    """Insert exactly the planned assignments, each audited. Commits nothing — the
    caller owns the transaction. Refuses a plan for an account that is no longer
    missing, or a role that is not active."""
    from ccure_platform.rbac.audit import RoleSnapshot, assignment_event, emit

    created = 0
    by_key = {r.key: r for r in db.query(RbacRole).all()}
    for p in planned:
        role = by_key.get(p.role_key)
        if role is None or role.state != "active":
            raise ValueError(f"role {p.role_key!r} is not an active system role")
        exists = (
            db.query(RbacUserRole)
            .filter(
                RbacUserRole.user_id == p.user_id, RbacUserRole.revoked_at.is_(None)
            )
            .first()
        )
        if exists is not None:
            continue
        db.add(
            RbacUserRole(
                user_id=p.user_id,
                role_id=role.id,
                scope_type=p.scope_type,
                scope_org_id=p.scope_org_id,
            )
        )
        user_org = db.execute(
            text("SELECT org_id FROM users WHERE id = :u"), {"u": p.user_id}
        ).scalar()
        emit(
            db,
            [
                assignment_event(
                    "rbac.role.assigned",
                    RoleSnapshot(
                        role_id=role.id,
                        role_key=role.key,
                        display_name=role.display_name,
                        org_id=role.org_id,
                    ),
                    user_id=p.user_id,
                    user_org_id=user_org,
                    scope_type=p.scope_type,
                    scope_org_id=p.scope_org_id,
                    source="reconciliation",
                )
            ],
            system_actor=APPLY_ACTOR,
        )
        created += 1
    db.flush()
    return created
