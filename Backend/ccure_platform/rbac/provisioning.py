"""
ccure_platform/rbac/provisioning.py — how accounts and organisations come to hold RBAC
roles (RBAC-8). Nothing here consults ``users.role_id``, a legacy role or a role name.

**Default role** (``rbac_default_roles``, purpose ``self_registration``). A self-registered
account is given the configured default role *as an organisation-scope assignment in its
own organisation* — only if that role exists, is active, is organisation-assignable and holds
no privileged (non-delegable or continuity) permission (``governance.default_role_violations``,
the same rules the database trigger enforces). With no valid default configured the account is
created with **no role** and therefore no access; it never receives one by guesswork.

**First administrator** (``grant_platform_administrator``). The only ways a
``platform.superadmin`` assignment is made outside the governed API are this function's two
callers: first-run bootstrap (an empty installation) and the operator's recovery script. It
is idempotent (never a duplicate live assignment), audited
(``rbac.bootstrap.administrator`` / ``rbac.recovery.administrator``, system actor, the
member's own organisation as owner), and **refuses to add an administrator to a system that
already has one** unless the operator says so explicitly. There is no permanent bypass:
the grant is an ordinary assignment, revocable through the API.

**Organisation defaults** (``provision_organisation_admin``). Creating an organisation with a
first administrator gives that administrator the organisation-administrator role *through the
governed assignment API*, by the actor creating the organisation (who must hold the authority
to assign it there), inside the same transaction: an organisation never exists with a
half-provisioned administrator, and nothing privileged is granted automatically — the
actor's explicit input is what names the administrator.
"""

from __future__ import annotations

import logging

from ccure_platform.rbac import administration as admin
from ccure_platform.rbac import contract as c
from ccure_platform.rbac import governance
from ccure_platform.rbac.audit import (
    EventDraft,
    RoleSnapshot,
    assignment_event,
    emit,
)
from ccure_platform.rbac.governance import GovernanceError
from ccure_platform.rbac.model import RbacDefaultRole, RbacRole, RbacUserRole
from sqlalchemy import select, text
from sqlalchemy.orm import Session

logger = logging.getLogger("ccure.rbac.provisioning")

SELF_REGISTRATION = "self_registration"
DEFAULT_ROLE_ACTOR = "system:default-role"
BOOTSTRAP_ACTOR = "system:rbac-bootstrap"
SUPERADMIN_KEY = c.PLATFORM_ADMIN_ROLE_KEY
ORG_ADMIN_KEY = c.ORGANISATION_ADMIN_ROLE_KEY


def _snap(row: RbacRole) -> RoleSnapshot:
    return RoleSnapshot(
        role_id=str(row.id),
        role_key=row.key,
        display_name=row.display_name,
        org_id=row.org_id,
    )


# ── default role ──────────────────────────────────────────────────────────────


def default_role(db: Session, purpose: str = SELF_REGISTRATION) -> RbacRole | None:
    """The configured default role for ``purpose`` if it is valid *now*, else None.
    Validity is re-checked every time: a role retired or made privileged after it was
    configured stops being a default."""
    ref = db.get(RbacDefaultRole, purpose)
    if ref is None:
        return None
    row = db.get(RbacRole, ref.role_id)
    if row is None or governance.default_role_violations(db, str(row.id)):
        logger.warning("The %s default role is not valid; no role is assigned", purpose)
        return None
    return row


def assign_default_role(
    db: Session, user, purpose: str = SELF_REGISTRATION
) -> RbacUserRole | None:
    """
    Give ``user`` the default role for ``purpose``: an organisation-scope assignment in the
    user's own organisation. Idempotent (an existing live assignment of that role is
    returned), writes the audit event in the caller's transaction, commits nothing, and
    returns None — granting nothing — when no valid default exists.
    """
    row = default_role(db, purpose)
    if row is None or not getattr(user, "org_id", None):
        return None
    existing = db.execute(
        select(RbacUserRole).where(
            RbacUserRole.user_id == user.id,
            RbacUserRole.role_id == row.id,
            RbacUserRole.revoked_at.is_(None),
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    assignment = RbacUserRole(
        user_id=user.id,
        role_id=row.id,
        scope_type="organization",
        scope_org_id=user.org_id,
        granted_by=DEFAULT_ROLE_ACTOR,
    )
    db.add(assignment)
    db.flush()
    emit(
        db,
        [
            assignment_event(
                "rbac.role.assigned",
                _snap(row),
                user_id=user.id,
                user_org_id=user.org_id,
                scope_type="organization",
                scope_org_id=user.org_id,
                source="default_role",
                purpose=purpose,
            )
        ],
        system_actor=DEFAULT_ROLE_ACTOR,
    )
    return assignment


# ── the first administrator ───────────────────────────────────────────────────


def active_administrators(db: Session) -> frozenset[str]:
    """Active, verified accounts holding ``platform.role.assign_platform`` platform-wide
    — the accounts that can govern the platform. Empty means the system cannot be
    administered."""
    return governance.holders(db, c.ASSIGN_PLATFORM_ROLE_KEY, platform=True)


def grant_platform_administrator(
    db: Session,
    user_id: str,
    *,
    reason: str,
    recovery: bool = False,
    allow_additional: bool = False,
) -> tuple[RbacUserRole, bool]:
    """
    Make ``user_id`` a platform administrator (the ``platform.superadmin`` system role,
    platform scope). Returns ``(assignment, created)``. Idempotent: the same account asked
    twice gets the same live assignment and one event only.

    Refuses (``GovernanceError``) when the system already has an active administrator and
    ``allow_additional`` is not set — bootstrap and recovery are for a system that
    cannot otherwise be administered; adding to a working one is the governed API's job.
    Refuses an unknown, deleted, inactive or unverified account, and a missing system
    role (the catalogue has not been synced). Commits nothing.
    """
    from ccure_platform.rbac.catalogue import ensure_system_roles

    ensure_system_roles(db)
    role = db.query(RbacRole).filter_by(key=SUPERADMIN_KEY).one_or_none()
    row = db.execute(
        text(
            "SELECT org_id, is_active, is_deleted, is_verified, approved_at "
            "FROM users WHERE id = :u"
        ),
        {"u": user_id},
    ).first()
    problems: list[governance.Violation] = []
    if role is None or role.state != "active":
        problems.append(
            governance.Violation("no_system_role", "the system role is not available")
        )
    if row is None:
        problems.append(governance.Violation("unknown_account", "no such account"))
    elif not (row[1] and not row[2] and row[3] and row[4]):
        problems.append(
            governance.Violation(
                "account_unusable", "the account must be active, verified and approved"
            )
        )
    if problems:
        raise GovernanceError(problems)
    existing = db.execute(
        select(RbacUserRole).where(
            RbacUserRole.user_id == user_id,
            RbacUserRole.role_id == role.id,
            RbacUserRole.revoked_at.is_(None),
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing, False
    if active_administrators(db) and not allow_additional:
        raise GovernanceError(
            [
                governance.Violation(
                    "administrator_exists",
                    "the platform already has an active administrator; use the governed API",
                )
            ]
        )
    assignment = RbacUserRole(
        user_id=user_id,
        role_id=role.id,
        scope_type="platform",
        scope_org_id=None,
        granted_by=BOOTSTRAP_ACTOR,
    )
    db.add(assignment)
    db.flush()
    emit(
        db,
        [
            assignment_event(
                "rbac.platform_role.assigned",
                _snap(role),
                user_id=user_id,
                user_org_id=row[0],
                scope_type="platform",
                source="recovery" if recovery else "bootstrap",
                reason=reason,
            ),
            EventDraft(
                action=(
                    "rbac.recovery.administrator"
                    if recovery
                    else "rbac.bootstrap.administrator"
                ),
                resource_type="rbac_user_role",
                resource_id=user_id,
                changes={"reason": reason, "role_id": str(role.id)},
                org_id=row[0],
            ),
        ],
        system_actor=BOOTSTRAP_ACTOR,
    )
    return assignment, True


# ── organisation provisioning ─────────────────────────────────────────────────


def provision_organisation_admin(
    db: Session, actor_user, admin_user_id: str
) -> list[EventDraft]:
    """
    Give a new organisation's first administrator the organisation-administrator role,
    through the governed assignment (organisation boundary, ceilings, escalation rules),
    by ``actor_user``. Raises ``GovernanceError`` — the caller's transaction then rolls the
    whole organisation back — if the actor may not. Returns the events to emit.
    """
    actor = admin.actor_for(db, actor_user)
    role = db.query(RbacRole).filter_by(key=ORG_ADMIN_KEY).one_or_none()
    if role is None:
        raise GovernanceError(
            [
                governance.Violation(
                    "no_system_role",
                    "the organisation-administrator role is not available",
                )
            ]
        )
    _, events = admin.assign(db, actor, admin_user_id, str(role.id))
    return events
