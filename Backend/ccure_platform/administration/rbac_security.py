"""Shared HTTP security checks for every platform role-management entry point."""

from ccure_platform.identity import reauth
from ccure_platform.rbac import administration as admin
from ccure_platform.rbac import governance
from ccure_platform.rbac.audit import EventDraft
from ccure_platform.rbac.model import RbacRole, RbacUserRole
from ccure_platform.rbac.scope import audit_isolated, resolve_active_organisation
from fastapi import HTTPException


def record_assignment_denial(user, error, target_org):
    codes = sorted({v.code for v in error.violations})
    recorded = audit_isolated(
        user,
        EventDraft(
            action=(
                "rbac.escalation.refused"
                if set(codes) & admin.ESCALATION_CODES
                else "rbac.assignment.denied"
            ),
            resource_type="rbac_user_role",
            changes={"violations": codes, "target_org_id": str(target_org)},
            org_id=getattr(user, "org_id", None),
        ),
    )
    if not recorded:
        raise HTTPException(503, detail="The refused assignment could not be audited.")


def mutation_organisation(user, requested_org_id=None):
    """Writes must never reinterpret a refused tenant selection as the home tenant."""
    org = resolve_active_organisation(user, requested_org_id)
    if requested_org_id and str(requested_org_id) != org:
        raise HTTPException(403, detail="The requested organisation is not authorised.")
    return org


def step_up(user, request, sensitive):
    if not sensitive:
        return "not_required"
    try:
        return reauth.check(user, request)
    except HTTPException as error:
        recorded = audit_isolated(
            user,
            EventDraft(
                action="rbac.reauth.failed",
                resource_type="rbac_role",
                changes={
                    "operation": request.method + " " + request.url.path,
                    "reason": error.detail.get("code", "reauth_required"),
                },
                org_id=getattr(user, "org_id", None),
            ),
        )
        if not recorded:
            raise HTTPException(
                503, detail="The step-up refusal could not be audited."
            ) from error
        raise


def assignment_step_up(db, user, request, role_id, target_org, *, replacing_user=None):
    governance.lock_continuity(db)
    db.expire_all()
    actor = admin.actor_for(db, user)
    roles = [db.get(RbacRole, role_id)]
    if replacing_user:
        roles.extend(
            db.query(RbacRole)
            .join(RbacUserRole, RbacUserRole.role_id == RbacRole.id)
            .filter(
                RbacUserRole.user_id == replacing_user,
                RbacUserRole.revoked_at.is_(None),
            )
            .all()
        )
    sensitive = str(target_org) != str(user.org_id) or any(
        row is not None and admin.is_sensitive_role(db, row, actor.catalogue)
        for row in roles
    )
    return step_up(user, request, sensitive)


def retain_user_administrator(db, actor, user_id):
    _retain_administrators(db, actor, (str(user_id),), str(user_id))


def retain_organisation_administrators(db, actor, org_id):
    from ccure_platform.models import User

    governance.lock_continuity(db)
    users = tuple(u for (u,) in db.query(User.id).filter(User.org_id == org_id))
    _retain_administrators(db, actor, users, str(org_id), ending_org=str(org_id))


def _retain_administrators(db, actor, user_ids, target, *, ending_org=None):
    """Account lifecycle operations share the assignment/permission continuity lock."""
    governance.lock_continuity(db)
    broken = tuple(
        key
        for key in governance.continuity_regressions(db, exclude_user_ids=user_ids)
        if key != f"org:{ending_org}"
    )
    if broken:
        recorded = audit_isolated(
            actor,
            EventDraft(
                action="rbac.assignment.denied",
                resource_type="organization" if ending_org else "user",
                resource_id=target,
                changes={"violations": ["continuity"], "invariants": list(broken)},
                org_id=getattr(actor, "org_id", None),
            ),
        )
        if not recorded:
            raise HTTPException(
                503, detail="The continuity refusal could not be audited."
            )
        raise HTTPException(
            403,
            detail="This operation would remove the last viable role administrator.",
        )
