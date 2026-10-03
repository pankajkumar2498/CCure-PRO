"""Read-only native catalogue, administrator and continuity checks."""

from __future__ import annotations

from dataclasses import dataclass, field

from ccure_platform.rbac import governance, resolver
from ccure_platform.rbac.model import RbacRole, RbacUserRole
from sqlalchemy import func, select
from sqlalchemy.orm import Session


@dataclass
class Readiness:
    ready: bool
    blockers: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    counts: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "ready": self.ready,
            "blockers": self.blockers,
            "notes": self.notes,
            "counts": self.counts,
        }


def assess(db: Session, sources=None) -> Readiness:
    """``sources`` are the modules' permission declarations (``composition.load_permission_sources()``);
    RBAC does not read the module registry, so the composition root hands them in. Left
    out, the catalogue's own completeness is not compared against the declarations."""
    from ccure_platform.rbac import contract as c
    from ccure_platform.rbac import provisioning

    blockers: list[str] = []
    notes: list[str] = []

    declared = {d.key for src in (sources or ()) for d in src.permissions}
    catalogue = resolver.load_catalogue(db)
    missing_keys = sorted(declared - set(catalogue))
    if not catalogue:
        blockers.append("the permission catalogue is empty: run the catalogue sync")
    elif missing_keys:
        blockers.append(
            f"{len(missing_keys)} declared permission(s) are not in the catalogue: run the catalogue sync"
        )
    system_keys = {s.key for s in c.SYSTEM_ROLE_SEEDS}
    present = set(
        db.execute(select(RbacRole.key).where(RbacRole.kind == "system")).scalars()
    )
    if system_keys - present:
        blockers.append(
            "a system role is missing: " + ", ".join(sorted(system_keys - present))
        )

    admins = provisioning.active_administrators(db)
    if not admins:
        blockers.append(
            "no active account holds platform.role.assign_platform: the platform cannot be "
            "administered (bootstrap the first administrator)"
        )

    continuity = governance.continuity_report(db)
    if continuity.status == "violated":
        blockers.append(
            "continuity is violated: " + ", ".join(sorted(continuity.violations))
        )
    if provisioning.default_role(db) is None:
        notes.append(
            "no valid self-registration default role is configured (new registrations hold no role)"
        )

    counts = {
        "administrators": len(admins),
        "permissions": len(catalogue),
        "live_assignments": db.execute(
            select(func.count())
            .select_from(RbacUserRole)
            .where(RbacUserRole.revoked_at.is_(None))
        ).scalar_one(),
        "continuity": continuity.status,
    }
    return Readiness(ready=not blockers, blockers=blockers, notes=notes, counts=counts)
