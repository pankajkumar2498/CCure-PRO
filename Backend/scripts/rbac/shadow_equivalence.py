"""
Run the RBAC-2 equivalence matrix through the actual RBAC-3 shadow mechanism.

    python -m scripts.rbac.shadow_equivalence

Run from ``Backend/`` (in the API container: ``docker exec ccure-api python -m
scripts.rbac.shadow_equivalence``) against a database whose RBAC catalogue has been
synced (``scripts/rbac/sync_catalogue.py --apply``).

For each of the five legacy roles it creates a throwaway user holding **both** that
legacy role and the matching new RBAC role, then asks the real legacy check
(``user_has_permission``) about every legacy atom in the golden mapping **with shadow
mode on**, so each answer is compared by the real hook, evaluator and recorder.
Everything runs in one transaction that is **always rolled back**: nothing is
written, no production user is assigned to a new role, and the shadow flag is only
set for the duration of the run, in this process.

Expected: every enforced atom MATCHes, every retired atom is NOT_COMPARABLE
(``retired_atom``), and there is no MISMATCH and no ERROR. The exit status is 1
otherwise, and every disagreement is printed with its classification.

RBAC-3 = SHADOW ONLY. Legacy authorization remains authoritative.
"""

from __future__ import annotations

import sys
import uuid
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class RoleOutcome:
    legacy_role: str
    role_key: str
    counts: Counter = field(default_factory=Counter)
    mismatches: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    matches: int = 0
    retired: int = 0
    total: int = 0


@dataclass
class EquivalenceReport:
    roles: list[RoleOutcome]

    @property
    def ok(self) -> bool:
        return all(not r.mismatches and not r.errors for r in self.roles)

    def as_rows(self) -> list[tuple]:
        return [
            (
                r.legacy_role,
                r.role_key,
                r.total,
                r.matches,
                r.retired,
                len(r.mismatches),
                len(r.errors),
            )
            for r in self.roles
        ]


def run_equivalence(db, golden=None) -> EquivalenceReport:
    """Run the matrix on ``db`` (the caller rolls back). Returns the report."""
    from ccure_platform.rbac import legacy_map, shadow, shadow_runtime
    from ccure_platform.rbac import dependencies as legacy
    from ccure_platform.rbac.catalogue import ensure_system_roles
    from config import AppConfig
    from db.base import gen_user_id, utcnow
    from db.models import Organization, Role, User
    from ccure_platform.rbac.model import RbacRole, RbacUserRole

    golden = golden or legacy_map.load_golden()
    ensure_system_roles(db)
    tag = uuid.uuid4().hex[:8]
    org = Organization(
        id=f"org_eq{tag}",
        name=f"Equivalence {tag}",
        slug=f"equivalence-{tag}",
        max_assets=1,
        max_users=10,
        is_active=True,
    )
    db.add(org)
    db.flush()

    shadow_runtime.reset_recorder()
    previous = AppConfig.RBAC_SHADOW_MODE, AppConfig.RBAC_SHADOW_SAMPLE_RATE
    AppConfig.RBAC_SHADOW_MODE, AppConfig.RBAC_SHADOW_SAMPLE_RATE = "observe", 1.0
    outcomes = []
    try:
        with shadow_runtime.use_session(db):
            for entry in golden["roles"]:
                legacy_name, role_key = entry["legacy_role"], entry["role_key"]
                legacy_role = db.query(Role).filter(Role.name == legacy_name).one()
                rbac_role = db.query(RbacRole).filter(RbacRole.key == role_key).one()
                user = User(
                    id=gen_user_id(org.slug, f"eq{legacy_name}"),
                    username=f"eq_{legacy_name}_{tag}",
                    email=f"eq_{legacy_name}_{tag}@equivalence.invalid",
                    full_name="Equivalence",
                    password_hash="not-a-real-hash",
                    org_id=org.id,
                    role_id=legacy_role.id,
                    is_active=True,
                    is_verified=True,
                    approved_at=utcnow(),
                    approved_by="equivalence",
                )
                db.add(user)
                db.flush()
                db.add(
                    RbacUserRole(
                        user_id=user.id,
                        role_id=rbac_role.id,
                        scope_type=entry["assignable_scope"],
                        scope_org_id=(
                            org.id
                            if entry["assignable_scope"] == "organization"
                            else None
                        ),
                    )
                )
                db.flush()
                db.refresh(user)
                outcome = RoleOutcome(legacy_name, role_key)
                shadow_runtime.reset_recorder()
                for atom in golden["atoms"]:
                    resource, action = atom["atom"].split(":")
                    legacy.user_has_permission(db, user, resource, action)
                snap = shadow_runtime.recorder().snapshot()
                rec = shadow_runtime.recorder()
                outcome.total = rec.total()
                outcome.matches = rec.total(shadow.MATCH)
                outcome.retired = rec.counts[
                    (shadow.NOT_COMPARABLE, shadow.RETIRED_ATOM)
                ]
                outcome.counts = Counter({k: v for k, v in rec.counts.items()})
                outcome.mismatches = snap["mismatches"]
                outcome.errors = snap["errors"]
                outcomes.append(outcome)
    finally:
        AppConfig.RBAC_SHADOW_MODE, AppConfig.RBAC_SHADOW_SAMPLE_RATE = previous
        shadow_runtime.reset_recorder()
    return EquivalenceReport(roles=outcomes)


def main() -> int:
    from db.base import SessionLocal

    db = SessionLocal()
    try:
        report = run_equivalence(db)
    finally:
        db.rollback()  # nothing is ever written
        db.close()
    print(
        f"{'legacy role':<12} {'new role':<22} {'atoms':>5} {'match':>6} {'retired':>8} {'mismatch':>9} {'error':>6}"
    )
    for row in report.as_rows():
        print(
            f"{row[0]:<12} {row[1]:<22} {row[2]:>5} {row[3]:>6} {row[4]:>8} {row[5]:>9} {row[6]:>6}"
        )
    for r in report.roles:
        for m in (*r.mismatches, *r.errors):
            print(
                f"  {r.legacy_role}: {m['kind']}/{m['classification']} {m['legacy_atom']} {m['reason']}"
            )
    print("equivalent." if report.ok else "NOT EQUIVALENT.")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
