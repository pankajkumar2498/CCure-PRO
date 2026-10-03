"""
ccure_platform/rbac/offboarding.py — RBAC's answer to a user purge.

``purge_user`` permanently deletes an account, and ``rbac_user_roles.user_id`` is a
foreign key to ``users`` with ``ON DELETE RESTRICT`` — deliberately: an assignment
must never silently lose its user. So a purge has to deal with the account's
assignments *before* the user row goes, and it does so through the platform's
offboarding contract (``ccure_platform/offboarding.py``): this hook runs on the
purge's own session, in the purge's own transaction, and commits nothing.

**What it does, and what it preserves.** For each assignment the account holds —
live, revoked or expired — it records an audit event, then removes the row:

* the **history is preserved in the audit trail**, not in ``rbac_user_roles``: each
  event carries the role's id, key and display name *at that moment*, the scope,
  who granted it and when, and whether it was still live. It is owned by the
  organisation the assignment was in (or, for a platform-scope assignment, by the
  member's own organisation — see ``rbac/audit.py``), so it lands in a real
  tenant's trail;
* the **role history is untouched**: roles are never deleted and
  ``rbac_role_revisions`` is append-only, so what a role was and held when the
  person had it can still be reconstructed;
* ``ON DELETE RESTRICT`` is **not weakened**. The FK still refuses to delete a user
  who has assignments; the hook is what makes the assignments go first. A user
  deleted any other way, with assignments still present, is still refused.

A person erased on request cannot keep a row naming them in a live table, which is
why the rows go and the trail stays: the trail already follows the platform's own
erasure rules (``audit_logs.user_id`` is set NULL; the actor snapshot keeps an id,
never an email).

Registered at import; ``ccure_platform/administration/users.py`` imports this
module, because that is where the purge lives.
"""

from __future__ import annotations

from ccure_platform.offboarding import register_user_purge_hook
from ccure_platform.rbac.audit import RoleSnapshot, assignment_event, emit
from ccure_platform.rbac.model import RbacRole, RbacUserRole
from sqlalchemy import text
from sqlalchemy.orm import Session

PURGE_ACTOR = "system:user-purge"


def detach_user_from_rbac(db: Session, user_id: str) -> None:
    rows = (
        db.query(RbacUserRole, RbacRole)
        .join(RbacRole, RbacRole.id == RbacUserRole.role_id)
        .filter(RbacUserRole.user_id == user_id)
        .all()
    )
    if not rows:
        return
    user_org_id = db.execute(
        text("SELECT org_id FROM users WHERE id = :u"), {"u": user_id}
    ).scalar()
    drafts = []
    for assignment, role in rows:
        platform = assignment.scope_type == "platform"
        drafts.append(
            assignment_event(
                "rbac.platform_role.revoked" if platform else "rbac.role.revoked",
                RoleSnapshot(
                    role_id=str(role.id),
                    role_key=role.key,
                    display_name=role.display_name,
                    org_id=role.org_id,
                ),
                user_id=user_id,
                user_org_id=user_org_id,
                scope_type=assignment.scope_type,
                scope_org_id=assignment.scope_org_id,
                reason="user_purged",
                assignment_id=str(assignment.id),
                granted_by=assignment.granted_by,
                granted_at=(
                    assignment.granted_at.isoformat() if assignment.granted_at else None
                ),
                was_live=assignment.revoked_at is None,
                revoked_reason=assignment.revoke_reason,
            )
        )
    # events first, then the rows: the events read the rows
    emit(db, drafts, system_actor=PURGE_ACTOR)
    db.query(RbacUserRole).filter(RbacUserRole.user_id == user_id).delete(
        synchronize_session=False
    )
    db.flush()


register_user_purge_hook("rbac", detach_user_from_rbac)
