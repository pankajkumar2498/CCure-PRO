"""
ccure_platform/administration/rbac_admin.py — the Platform RBAC administration API (RBAC-7).

``/platform/rbac/*``. A thin HTTP layer over ``rbac/administration.py``: authenticate,
resolve the organisation the backend accepts (never the client's word), build the actor's
grants, call the governed operation, audit it, commit. Authorization is the RBAC engine's
alone — there is no legacy path here — so an account with no RBAC role assignment can read
and change nothing (it is told why).

Contract: roles, permissions, assignments and the assignable-role list are returned as
keys, labels and states. No table name, no internal row structure beyond the ids a
management call needs, and no legacy atom.

Sensitive operations (a system or platform role, a privileged permission, a cross-
organisation change) need step-up (``identity/reauth``): a current authenticator code in
``X-Reauth-Code`` for an account with MFA enrolled. Every refusal and every mutation is
audited; platform-owned events go to the platform ledger, never to an invented tenant.
"""

from __future__ import annotations

from typing import Literal

from ccure_platform.administration.rbac_security import (
    mutation_organisation,
    step_up as _step_up,
)
from ccure_platform.identity.dependencies import get_current_user
from ccure_platform.rbac import administration as admin
from ccure_platform.rbac import contract as c
from ccure_platform.rbac.audit import EventDraft, emit
from ccure_platform.rbac.governance import GovernanceError, lock_continuity
from ccure_platform.rbac.model import RbacRole, RbacUserRole
from ccure_platform.rbac.scope import audit_isolated, resolve_active_organisation
from db.base import get_db
from ccure_platform.models import User
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

router = APIRouter(prefix="/platform/rbac", tags=["Platform RBAC Administration"])


class RbacRoleCreateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str = Field(min_length=1, max_length=100)
    permission_keys: list[str] = Field(default_factory=list, max_length=200)
    description: str | None = Field(default=None, max_length=1000)
    org_id: str | None = None


class RbacRoleUpdateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=1000)


class RbacRolePermissionsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    permission_keys: list[str] = Field(max_length=200)
    expected_revision: int | None = Field(
        default=None,
        ge=1,
        description="Current role revision; required for permission updates (428 if omitted, 409 if stale).",
    )


class RbacRoleTransitionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: Literal["retiring", "retired", "active"]
    reason: str | None = Field(default=None, max_length=500)
    replacement_role_id: str | None = None


class RbacRoleReplaceBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    to_role_id: str


class RbacAssignBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role_id: str


# ── plumbing ──────────────────────────────────────────────────────────────────


def _context(db: Session, user: User, org_id: str | None, *, mutation=False):
    if mutation:
        lock_continuity(db)
        db.expire_all()
    org = (mutation_organisation if mutation else resolve_active_organisation)(
        user, org_id
    )
    actor = admin.actor_for(db, user)
    if not actor.provisioned:
        if mutation:
            recorded = audit_isolated(
                user,
                EventDraft(
                    action="rbac.role.denied",
                    resource_type="rbac_role",
                    changes={
                        "operation": "rbac_management",
                        "violations": ["no_effective_grants"],
                    },
                    org_id=getattr(user, "org_id", None),
                ),
            )
            if not recorded:
                raise HTTPException(
                    503, detail="The refused operation could not be audited."
                )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="RBAC administration needs an RBAC role assignment for this account.",
        )
    return org, actor


def _need(actor: admin.Actor, key: str, org: str | None = None) -> None:
    if not admin.holds(actor, key, org):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient privileges. Missing permission: {key}.",
        )


def _refuse(
    user: User, error: GovernanceError, *, op: str, target: str | None, assignment: bool
):
    """Audit a refusal (in its own transaction, so the rollback cannot erase it) and
    answer 403 with the reasons."""
    codes = sorted({v.code for v in error.violations})
    escalation = bool(set(codes) & admin.ESCALATION_CODES)
    recorded = audit_isolated(
        user,
        EventDraft(
            action=(
                "rbac.escalation.refused"
                if escalation
                else "rbac.assignment.denied" if assignment else "rbac.role.denied"
            ),
            resource_type="rbac_user_role" if assignment else "rbac_role",
            resource_id=target,
            changes={"operation": op, "violations": codes},
            org_id=getattr(user, "org_id", None),
        ),
    )
    if not recorded:
        raise HTTPException(503, detail="The refused operation could not be audited.")
    raise HTTPException(
        status_code=(
            409
            if "stale_revision" in codes
            else 428 if "revision_required" in codes else status.HTTP_403_FORBIDDEN
        ),
        detail={
            "code": (
                "revision_conflict"
                if "stale_revision" in codes
                else (
                    "revision_required"
                    if "revision_required" in codes
                    else "governance_refused"
                )
            ),
            "violations": [
                {"code": v.code, "message": v.message} for v in error.violations
            ],
        },
    )


def _govern(
    db: Session, user: User, fn, *, op: str, target: str | None, assignment: bool
):
    """Run one governed operation in a savepoint: a refusal undoes only its own partial
    work, is audited, and answers 403."""
    try:
        with db.begin_nested():
            return fn()
    except GovernanceError as error:
        _refuse(user, error, op=op, target=target, assignment=assignment)


def _finish(db, user, request, drafts, step_up: str):
    for d in drafts:
        d.changes["reauth"] = step_up
    try:
        emit(db, drafts, actor=user, request=request)
        db.commit()
    except Exception:
        db.rollback()
        raise


def _role_or_404(db: Session, role_id: str, org: str) -> RbacRole:
    row = db.get(RbacRole, role_id)
    if row is None or (row.org_id and row.org_id != org):
        raise HTTPException(status_code=404, detail="Role not found.")
    return row


# ── reading ───────────────────────────────────────────────────────────────────


@router.get("/permissions")
def list_permissions(
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org, actor = _context(db, user, org_id)
    _need(actor, "platform.permission.read", org)
    return {"permissions": admin.list_permissions(db, actor, org)}


@router.get("/roles")
def list_roles(
    org_id: str | None = Query(None),
    include_retired: bool = Query(False),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org, actor = _context(db, user, org_id)
    _need(actor, "platform.role.read", org)
    return {
        "org_id": org,
        "roles": admin.list_roles(db, actor, org, include_retired=include_retired),
    }


@router.get("/roles/{role_id}")
def get_role(
    role_id: str,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org, actor = _context(db, user, org_id)
    _need(actor, "platform.role.read", org)
    detail = admin.role_detail(db, actor, role_id, org)
    if detail is None:
        raise HTTPException(status_code=404, detail="Role not found.")
    return detail


@router.get("/assignable-roles")
def assignable_roles(
    user_id: str | None = Query(None),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org, actor = _context(db, user, org_id)
    _need(actor, "platform.role.read", org)
    return admin.assignable_roles(db, actor, user_id, org)


@router.get("/users/{user_id}/assignments")
def get_user_assignments(
    user_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _, actor = _context(db, user, None)
    rows = admin.user_assignments(db, actor, user_id)
    if rows is None:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"user_id": user_id, "assignments": rows}


# ── roles ─────────────────────────────────────────────────────────────────────


@router.post("/roles", status_code=status.HTTP_201_CREATED)
def create_role(
    body: RbacRoleCreateBody,
    request: Request,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if body.org_id and org_id and body.org_id != org_id:
        raise HTTPException(400, detail="Conflicting organisation selections.")
    org, actor = _context(db, user, body.org_id or org_id, mutation=True)
    step = _step_up(
        user,
        request,
        sensitive=org != str(user.org_id) or _privileged(actor, body.permission_keys),
    )
    row, drafts = _govern(
        db,
        user,
        lambda: admin.create_custom_role(
            db,
            actor,
            org_id=org,
            display_name=body.display_name,
            permission_keys=body.permission_keys,
            description=body.description,
        ),
        op="create_role",
        target=None,
        assignment=False,
    )
    _finish(db, user, request, drafts, step)
    return admin.role_detail(db, actor, str(row.id), org)


def _privileged(actor: admin.Actor, keys) -> bool:
    return any(
        actor.catalogue.get(k) is not None
        and actor.catalogue[k].sensitivity == "privileged"
        for k in keys
    )


@router.patch("/roles/{role_id}")
def update_role(
    role_id: str,
    body: RbacRoleUpdateBody,
    request: Request,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org, actor = _context(db, user, org_id, mutation=True)
    row = _role_or_404(db, role_id, org)
    step = _step_up(
        user,
        request,
        sensitive=org != str(user.org_id)
        or admin.is_sensitive_role(db, row, actor.catalogue),
    )
    drafts = _govern(
        db,
        user,
        lambda: admin.rename_role(
            db, actor, row, display_name=body.display_name, description=body.description
        ),
        op="update_role",
        target=role_id,
        assignment=False,
    )
    _finish(db, user, request, drafts, step)
    return admin.role_detail(db, actor, role_id, org)


def _set_permissions(db, actor, row, body):
    from ccure_platform.rbac.governance import Violation

    if body.expected_revision is None:
        raise GovernanceError(
            [
                Violation(
                    "revision_required",
                    "Reload this role and submit its current revision before saving permissions.",
                )
            ]
        )
    return admin.set_role_permissions(
        db, actor, row, body.permission_keys, expected_revision=body.expected_revision
    )


@router.put("/roles/{role_id}/permissions")
def set_permissions(
    role_id: str,
    body: RbacRolePermissionsBody,
    request: Request,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org, actor = _context(db, user, org_id, mutation=True)
    row = _role_or_404(db, role_id, org)
    changed = set(body.permission_keys) ^ set(admin.granted_keys(db, row.id))
    step = _step_up(
        user,
        request,
        sensitive=org != str(user.org_id)
        or admin.is_sensitive_role(db, row, actor.catalogue)
        or _privileged(actor, changed),
    )
    drafts, delta = _govern(
        db,
        user,
        lambda: _set_permissions(db, actor, row, body),
        op="set_permissions",
        target=role_id,
        assignment=False,
    )
    _finish(db, user, request, drafts, step)
    detail = admin.role_detail(db, actor, role_id, org)
    detail["change"] = delta
    return detail


@router.post("/roles/{role_id}/transition")
def transition_role(
    role_id: str,
    body: RbacRoleTransitionBody,
    request: Request,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org, actor = _context(db, user, org_id, mutation=True)
    row = _role_or_404(db, role_id, org)
    step = _step_up(
        user,
        request,
        sensitive=org != str(user.org_id)
        or admin.is_sensitive_role(db, row, actor.catalogue),
    )
    drafts = _govern(
        db,
        user,
        lambda: admin.transition(
            db,
            actor,
            row,
            body.target,
            reason=body.reason,
            replacement_role_id=body.replacement_role_id,
        ),
        op="transition_role",
        target=role_id,
        assignment=False,
    )
    _finish(db, user, request, drafts, step)
    return admin.role_detail(db, actor, role_id, org)


@router.post("/roles/{role_id}/replace")
def replace_role(
    role_id: str,
    body: RbacRoleReplaceBody,
    request: Request,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org, actor = _context(db, user, org_id, mutation=True)
    row = _role_or_404(db, role_id, org)
    replacement = _role_or_404(db, body.to_role_id, org)
    step = _step_up(
        user,
        request,
        sensitive=org != str(user.org_id)
        or admin.is_sensitive_role(db, row, actor.catalogue)
        or admin.is_sensitive_role(db, replacement, actor.catalogue),
    )
    moved, drafts = _govern(
        db,
        user,
        lambda: admin.replace_role(db, actor, role_id, body.to_role_id),
        op="replace_role",
        target=role_id,
        assignment=True,
    )
    _finish(db, user, request, drafts, step)
    return {
        "migrated_assignments": moved,
        "role": admin.role_detail(db, actor, role_id, org),
    }


# ── assignments ───────────────────────────────────────────────────────────────


@router.post("/users/{user_id}/assignments", status_code=status.HTTP_201_CREATED)
def assign_role(
    user_id: str,
    body: RbacAssignBody,
    request: Request,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _, actor = _context(db, user, org_id, mutation=True)
    row = db.get(RbacRole, body.role_id)
    sensitive = row is not None and admin.is_sensitive_role(db, row, actor.catalogue)
    target_org = db.execute(
        text("SELECT org_id FROM users WHERE id = :u"), {"u": user_id}
    ).scalar()
    sensitive = sensitive or (target_org is not None and target_org != str(user.org_id))
    step = _step_up(user, request, sensitive=sensitive)
    assignment, drafts = _govern(
        db,
        user,
        lambda: admin.assign(db, actor, user_id, body.role_id),
        op="assign_role",
        target=user_id,
        assignment=True,
    )
    _finish(db, user, request, drafts, step)
    return {
        "assignment_id": str(assignment.id),
        "assignments": admin.user_assignments(db, actor, user_id),
    }


@router.delete("/assignments/{assignment_id}")
def revoke_assignment(
    assignment_id: str,
    request: Request,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _, actor = _context(db, user, org_id, mutation=True)
    a = db.get(RbacUserRole, assignment_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Assignment not found.")
    row = db.get(RbacRole, a.role_id)
    step = _step_up(
        user,
        request,
        sensitive=(a.scope_org_id is not None and a.scope_org_id != str(user.org_id))
        or (row is not None and admin.is_sensitive_role(db, row, actor.catalogue)),
    )
    user_id = a.user_id
    drafts = _govern(
        db,
        user,
        lambda: admin.revoke(db, actor, assignment_id),
        op="revoke_assignment",
        target=user_id,
        assignment=True,
    )
    _finish(db, user, request, drafts, step)
    return {"assignments": admin.user_assignments(db, actor, user_id)}
