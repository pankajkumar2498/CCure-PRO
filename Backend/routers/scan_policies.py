"""
routers/scan_policies.py
─────────────────────────────────────────────────────────────────────────────
Reusable scan policies — CRUD, validation, versioning, and what uses one.

Endpoints
─────────
  GET    /scan-policies                    list (tenant-scoped)
  POST   /scan-policies                    create
  GET    /scan-policies/settings           the vocabularies this build honours
  POST   /scan-policies/validate           validate a configuration, no write
  GET    /scan-policies/{id}               one policy
  PATCH  /scan-policies/{id}               edit
  POST   /scan-policies/{id}/enable        enable / disable
  POST   /scan-policies/{id}/status        draft → active → archived
  POST   /scan-policies/{id}/version       supersede with a new version
  GET    /scan-policies/{id}/usage         schedules and scans referencing it
  DELETE /scan-policies/{id}               delete

Four properties this module is responsible for
──────────────────────────────────────────────
**Tenant isolation is applied in the query, never after it.** Every lookup
filters on ``org_id`` inside the ``WHERE``, so another organisation's policy
answers 404 rather than 403. A 403 confirms the id exists, which is a
cross-tenant enumeration oracle — the rule ``routers/scan_schedules.py``
already states and this router copies rather than reinvents.

**A policy never accepts a secret.** There is no credential field of any kind.
``config`` is copied into ``scans.options``, which is client-visible, rendered
into the generated report, and echoed by the comparison API. A credential is
referenced by ``compliance_credentials.id`` on the scan or the schedule, and
that reference is resolved and decrypted worker-side.

**An unknown setting is refused, not stored.** ``config`` is JSONB, which
would otherwise accept a misspelled key silently — and a setting the operator
believes is in force that nothing reads is worse than a missing one.
``validate_policy`` runs on every create and every edit.

**Every limited route declares ``response: Response``.** The limiter is built
``headers_enabled=True``; a handler that returns a dict and declares neither a
returned ``Response`` nor the parameter hands slowapi ``None`` and raises from
inside the endpoint call — a 500 on every request to that route. CLAUDE.md
records 21 routes shipping in exactly that state.

Editing a policy that has already run scans
───────────────────────────────────────────
Permitted, and it does not rewrite history: a completed scan carries its own
immutable snapshot in ``scans.options``, so what produced it is settled. What
an edit *does* change is every future run, including a schedule that fires
tonight — so ``PATCH`` on a policy with a non-zero ``use_count`` returns a
``warning`` naming how many scans have used it. ``POST /{id}/version`` is the
alternative for an operator who wants the old configuration left alone.
"""

import logging
from typing import Any, Dict, List, Optional

from ccure_platform.api import (
    CurrentUser,
    require_permission,
    resolve_active_organisation,
)
from ccure_platform.api import log_audit_event
from core.scan_policy.spec import (
    CHECK_FAMILIES,
    CONFIG_KEYS,
    POLICY_SCAN_KINDS,
    SEVERITY_ORDER,
    effective_from_config,
    next_version_number,
)
from core.scan_policy.validation import validate_policy
from db.base import gen_org_token, get_db
from ccure_platform import api as platform_api
from db.models import ScanSchedule
from db.models.scan_policies import (
    POLICY_STATUS_ACTIVE,
    POLICY_STATUS_ARCHIVED,
    POLICY_STATUS_DRAFT,
    POLICY_STATUSES,
    ScanPolicy,
)
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, field_validator
from scan_helpers import limiter
from sqlalchemy.orm import Session

log = logging.getLogger("ccure.scan_policies")

router = APIRouter(prefix="/scan-policies", tags=["Scan Policies"])


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _resolve_org(user: CurrentUser, requested: Optional[str]) -> str:
    """Only a superadmin may act on another organisation; everyone else is pinned."""
    # Scope is decided by the platform (RBAC-5): a client-named organisation is a
    # request, honoured only with cross-organisation reach and an active target.
    return resolve_active_organisation(user, requested)


def _get_policy(db: Session, policy_id: str, org_id: str) -> ScanPolicy:
    """
    Fetch one policy inside its tenant.

    The org filter is part of the query. Fetching by id and comparing
    afterwards answers 403 for another tenant's policy, which confirms the id
    exists — so this answers 404 for both "no such policy" and "not yours", and
    they are indistinguishable from outside.
    """
    policy = (
        db.query(ScanPolicy)
        .filter(ScanPolicy.id == policy_id, ScanPolicy.org_id == org_id)
        .first()
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="Scan policy not found.")
    return policy


def _gen_policy_id(org_slug: str) -> str:
    """``spol_{org_token}_{rand}`` — the shape every other id in this schema has."""
    from db.base import _rand

    return f"spol_{gen_org_token(org_slug)}_{_rand()}"


def _audit_policy_change(
    db: Session,
    user: CurrentUser,
    action: str,
    policy: ScanPolicy,
    request: Request,
    changes: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Record a policy change in the audit trail.

    The **configuration** is recorded, not only the fact that something
    changed: a policy edit silently narrows what every future scan assesses,
    and "who quietly stopped us checking the STIG" is a question an audit trail
    has to be able to answer. There is no secret in ``config`` — the model
    forbids one — so recording it whole is safe.
    """
    payload: Dict[str, Any] = {
        "name": policy.name,
        "policy_family_code": policy.policy_family_code,
        "version_number": policy.version_number,
        "scan_kind": policy.scan_kind,
        "status": policy.status,
        "is_enabled": policy.is_enabled,
        "config": dict(policy.config or {}),
    }
    payload.update(changes or {})
    log_audit_event(
        db,
        user,
        action,
        "scan_policy",
        str(policy.id),
        changes=payload,
        request=request,
    )


def _serialize(policy: ScanPolicy, db: Optional[Session] = None) -> Dict[str, Any]:
    effective = effective_from_config(
        policy.config or {},
        policy_id=str(policy.id),
        policy_name=str(policy.name or ""),
        policy_family_code=str(policy.policy_family_code or ""),
        version_number=int(policy.version_number or 1),
        scan_kind=str(policy.scan_kind or "any"),
    )
    payload: Dict[str, Any] = {
        "id": policy.id,
        "org_id": policy.org_id,
        "name": policy.name,
        "description": policy.description,
        "policy_family_code": policy.policy_family_code,
        "version_number": policy.version_number,
        "scan_kind": policy.scan_kind,
        "status": policy.status,
        "is_enabled": policy.is_enabled,
        "is_usable": policy.is_usable,
        "superseded_by_policy_id": policy.superseded_by_policy_id,
        "use_count": policy.use_count,
        "config": dict(policy.config or {}),
        # The identifier a report prints and a comparison keys on. Returned so
        # a client can tell two configurations apart without re-deriving it.
        "fingerprint": effective.fingerprint(),
        "summary": effective.describe(),
        "created_by": policy.created_by,
        "created_at": policy.created_at.isoformat() if policy.created_at else None,
        "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
    }
    if db is not None:
        payload["schedule_count"] = (
            db.query(ScanSchedule.id)
            .filter(ScanSchedule.policy_id == policy.id)
            .count()
        )
    return payload


# ─────────────────────────────────────────────────────────────────────────────
# Bodies
#
# Prefixed ``ScanPolicy`` and they must stay that way. FastAPI keys OpenAPI
# component schemas by class name, so a bare ``PolicyCreate`` here would
# silently replace one elsewhere in the generated contract — the defect the CI
# contract gate caught when ``scan_schedules`` shipped a ``ScheduleCreate``.
# ─────────────────────────────────────────────────────────────────────────────


class ScanPolicyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=4000)
    #: Defaults to a slug of the name. Stable across versions, so a scan
    #: snapshot can name the family that produced it after every later edit.
    policy_family_code: Optional[str] = Field(None, max_length=100)
    scan_kind: str = Field("any", description=" | ".join(POLICY_SCAN_KINDS))
    config: Dict[str, Any] = Field(default_factory=dict)
    status: str = Field(POLICY_STATUS_DRAFT, description=" | ".join(POLICY_STATUSES))
    is_enabled: bool = True

    @field_validator("scan_kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in POLICY_SCAN_KINDS:
            raise ValueError(f"scan_kind must be one of {', '.join(POLICY_SCAN_KINDS)}")
        return v

    @field_validator("status")
    @classmethod
    def _status(cls, v: str) -> str:
        if v not in POLICY_STATUSES:
            raise ValueError(f"status must be one of {', '.join(POLICY_STATUSES)}")
        if v == POLICY_STATUS_ARCHIVED:
            # Creating something already retired is a mistake every time, and
            # allowing it would put an unusable row in the list with no way to
            # tell it from a policy somebody retired deliberately.
            raise ValueError("a new policy cannot be created already archived")
        return v


class ScanPolicyUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=4000)
    scan_kind: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    is_enabled: Optional[bool] = None

    @field_validator("scan_kind")
    @classmethod
    def _kind(cls, v):
        if v is not None and v not in POLICY_SCAN_KINDS:
            raise ValueError(f"scan_kind must be one of {', '.join(POLICY_SCAN_KINDS)}")
        return v


class ScanPolicyEnable(BaseModel):
    is_enabled: bool


class ScanPolicyStatus(BaseModel):
    status: str

    @field_validator("status")
    @classmethod
    def _status(cls, v: str) -> str:
        if v not in POLICY_STATUSES:
            raise ValueError(f"status must be one of {', '.join(POLICY_STATUSES)}")
        return v


class ScanPolicyValidate(BaseModel):
    config: Dict[str, Any] = Field(default_factory=dict)
    scan_kind: str = "any"


class ScanPolicyVersion(BaseModel):
    """A new version of an existing family, superseding the current one."""

    config: Dict[str, Any]
    name: Optional[str] = None
    description: Optional[str] = None
    activate: bool = True


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────


@router.get("")
@limiter.limit("60/minute")
def list_policies(
    request: Request,
    response: Response,
    org_id: Optional[str] = Query(None),
    scan_kind: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    enabled: Optional[bool] = Query(None),
    usable_only: bool = Query(False, description="Only policies a scan may use now"),
    user: CurrentUser = Depends(require_permission("scan_policies", "read")),
    db: Session = Depends(get_db),
):
    resolved_org = _resolve_org(user, org_id)
    query = db.query(ScanPolicy).filter(ScanPolicy.org_id == resolved_org)
    if scan_kind:
        query = query.filter(ScanPolicy.scan_kind == scan_kind)
    if status:
        query = query.filter(ScanPolicy.status == status)
    if enabled is not None:
        query = query.filter(ScanPolicy.is_enabled.is_(enabled))
    if usable_only:
        query = query.filter(
            ScanPolicy.is_enabled.is_(True),
            ScanPolicy.status == POLICY_STATUS_ACTIVE,
        )
    rows = query.order_by(
        ScanPolicy.policy_family_code, ScanPolicy.version_number.desc()
    ).all()
    return {"policies": [_serialize(p, db) for p in rows], "total": len(rows)}


@router.get("/settings")
@limiter.limit("60/minute")
def policy_settings(
    request: Request,
    response: Response,
    user: CurrentUser = Depends(require_permission("scan_policies", "read")),
):
    """
    The vocabularies this build honours, read from the code that honours them.

    A UI building a policy editor needs this, and hardcoding the lists there
    means a family added by a later phase is unselectable until somebody
    notices. Everything below is derived, not restated.
    """
    return {
        "scan_kinds": list(POLICY_SCAN_KINDS),
        "statuses": list(POLICY_STATUSES),
        "config_keys": sorted(CONFIG_KEYS),
        "check_families": list(CHECK_FAMILIES),
        "severities": list(SEVERITY_ORDER),
    }


@router.post("/validate")
@limiter.limit("30/minute")
def validate_policy_body(
    request: Request,
    response: Response,
    body: ScanPolicyValidate,
    user: CurrentUser = Depends(require_permission("scan_policies", "read")),
):
    """
    Check a configuration without storing it.

    Static validation only — vocabularies and internal consistency. Whether the
    named frameworks are installed for this organisation is checked again at
    dispatch, because an installation removed in June must stop a scan in July
    and a validation cached at authoring time cannot know that.
    """
    result = validate_policy(body.config, scan_kind=body.scan_kind)
    return result.as_dict()


@router.post("", status_code=201)
@limiter.limit("20/minute")
def create_policy(
    request: Request,
    response: Response,
    body: ScanPolicyCreate,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_permission("scan_policies", "create")),
    db: Session = Depends(get_db),
):
    resolved_org = _resolve_org(user, org_id)

    validation = validate_policy(body.config, scan_kind=body.scan_kind)
    if not validation.valid:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Scan policy configuration is not valid.",
                "errors": validation.errors,
            },
        )

    family = (body.policy_family_code or _slug(body.name)).strip()
    duplicate = (
        db.query(ScanPolicy.id)
        .filter(ScanPolicy.org_id == resolved_org, ScanPolicy.name == body.name)
        .first()
    )
    if duplicate:
        raise HTTPException(
            status_code=409, detail=f"A scan policy named {body.name!r} already exists."
        )

    existing_versions = [
        row[0]
        for row in db.query(ScanPolicy.version_number)
        .filter(
            ScanPolicy.org_id == resolved_org,
            ScanPolicy.policy_family_code == family,
        )
        .all()
    ]

    org = platform_api.organisation(db, resolved_org)
    policy = ScanPolicy(
        id=_gen_policy_id(org.slug if org else resolved_org),
        org_id=resolved_org,
        created_by=str(user.id),
        name=body.name,
        description=body.description,
        policy_family_code=family,
        version_number=next_version_number(existing_versions),
        scan_kind=body.scan_kind,
        config=dict(body.config or {}),
        status=body.status,
        is_enabled=body.is_enabled,
    )
    db.add(policy)
    _audit_policy_change(db, user, "scan_policy.created", policy, request)
    db.commit()
    db.refresh(policy)

    payload = _serialize(policy, db)
    payload["warnings"] = validation.warnings
    return payload


@router.get("/{policy_id}")
@limiter.limit("60/minute")
def get_policy(
    request: Request,
    response: Response,
    policy_id: str,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_permission("scan_policies", "read")),
    db: Session = Depends(get_db),
):
    policy = _get_policy(db, policy_id, _resolve_org(user, org_id))
    return _serialize(policy, db)


@router.patch("/{policy_id}")
@limiter.limit("30/minute")
def update_policy(
    request: Request,
    response: Response,
    policy_id: str,
    body: ScanPolicyUpdate,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_permission("scan_policies", "update")),
    db: Session = Depends(get_db),
):
    resolved_org = _resolve_org(user, org_id)
    policy = _get_policy(db, policy_id, resolved_org)

    if policy.status == POLICY_STATUS_ARCHIVED:
        # An archived policy is the record of what some historical scans ran
        # under. Editing it would not change those scans — they carry their own
        # snapshot — but it would make the row disagree with them, which is
        # worse than refusing.
        raise HTTPException(
            status_code=409,
            detail=(
                "This policy is archived. Archived policies are the record of "
                "what earlier scans ran under and are not edited; create a new "
                "version instead."
            ),
        )

    warnings: List[str] = []
    new_config = policy.config if body.config is None else dict(body.config)
    new_kind = body.scan_kind or policy.scan_kind
    if body.config is not None or body.scan_kind is not None:
        validation = validate_policy(new_config, scan_kind=new_kind)
        if not validation.valid:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "Scan policy configuration is not valid.",
                    "errors": validation.errors,
                },
            )
        warnings.extend(validation.warnings)

    if body.name is not None and body.name != policy.name:
        clash = (
            db.query(ScanPolicy.id)
            .filter(
                ScanPolicy.org_id == resolved_org,
                ScanPolicy.name == body.name,
                ScanPolicy.id != policy.id,
            )
            .first()
        )
        if clash:
            raise HTTPException(
                status_code=409,
                detail=f"A scan policy named {body.name!r} already exists.",
            )
        policy.name = body.name

    if body.description is not None:
        policy.description = body.description
    if body.scan_kind is not None:
        policy.scan_kind = body.scan_kind
    if body.config is not None:
        policy.config = new_config
    if body.is_enabled is not None:
        policy.is_enabled = body.is_enabled

    if policy.use_count:
        # Said out loud rather than blocked. Editing is legitimate — that is
        # what a reusable policy is for — but an operator should know that the
        # next scheduled run assesses something different from the last one,
        # and that GAP-13's comparison will report the two as configured
        # differently rather than as a change in the estate.
        warnings.append(
            f"This policy has already driven {policy.use_count} scan(s). "
            "Editing it changes every future run; completed scans keep their "
            "own recorded configuration and are unaffected."
        )

    _audit_policy_change(db, user, "scan_policy.updated", policy, request)
    db.commit()
    db.refresh(policy)

    payload = _serialize(policy, db)
    payload["warnings"] = warnings
    return payload


@router.post("/{policy_id}/enable")
@limiter.limit("30/minute")
def enable_policy(
    request: Request,
    response: Response,
    policy_id: str,
    body: ScanPolicyEnable,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_permission("scan_policies", "update")),
    db: Session = Depends(get_db),
):
    """
    Switch a policy off without retiring it.

    Disabling is deliberately **not** silent for anything pointing at it: the
    response names the schedules that will now fail to dispatch. A schedule
    running unnoticed under the request defaults because its policy was
    disabled would assess something other than what was authorised, which is
    exactly what this phase exists to stop.
    """
    resolved_org = _resolve_org(user, org_id)
    policy = _get_policy(db, policy_id, resolved_org)
    policy.is_enabled = bool(body.is_enabled)

    affected = (
        db.query(ScanSchedule)
        .filter(
            ScanSchedule.policy_id == policy.id,
            ScanSchedule.org_id == resolved_org,
            ScanSchedule.is_enabled.is_(True),
        )
        .all()
    )

    _audit_policy_change(
        db,
        user,
        "scan_policy.enabled" if policy.is_enabled else "scan_policy.disabled",
        policy,
        request,
        changes={"affected_schedules": [s.id for s in affected]},
    )
    db.commit()
    db.refresh(policy)

    payload = _serialize(policy, db)
    if not policy.is_enabled and affected:
        payload["warnings"] = [
            f"{len(affected)} enabled schedule(s) reference this policy and "
            "will fail to dispatch until it is re-enabled: "
            + ", ".join(s.name for s in affected)
        ]
    return payload


@router.post("/{policy_id}/status")
@limiter.limit("30/minute")
def set_policy_status(
    request: Request,
    response: Response,
    policy_id: str,
    body: ScanPolicyStatus,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_permission("scan_policies", "update")),
    db: Session = Depends(get_db),
):
    """
    Move a policy through draft → active → archived.

    Archiving is this product's soft delete for a policy, and it is what an
    operator should reach for: the row survives, so a completed scan's snapshot
    can still be matched against a policy a reader can look up, while nothing
    new can start under it.
    """
    resolved_org = _resolve_org(user, org_id)
    policy = _get_policy(db, policy_id, resolved_org)
    previous = policy.status

    if body.status == POLICY_STATUS_DRAFT and previous != POLICY_STATUS_DRAFT:
        # Going back to draft would make a policy that has already run scans
        # unusable while leaving schedules pointing at it, and "draft" would
        # then mean two different things depending on history.
        raise HTTPException(
            status_code=409,
            detail=(
                "A policy cannot return to draft once it has been activated. "
                "Disable it, or create a new version."
            ),
        )

    if body.status == POLICY_STATUS_ARCHIVED:
        blocking = (
            db.query(ScanSchedule)
            .filter(
                ScanSchedule.policy_id == policy.id,
                ScanSchedule.org_id == resolved_org,
                ScanSchedule.is_enabled.is_(True),
            )
            .all()
        )
        if blocking:
            # Refused rather than cascaded. Archiving here would leave enabled
            # schedules failing every night with an error about a policy nobody
            # remembers archiving.
            raise HTTPException(
                status_code=409,
                detail=(
                    f"{len(blocking)} enabled schedule(s) still use this policy: "
                    + ", ".join(s.name for s in blocking)
                    + ". Point them at another policy or disable them first."
                ),
            )

    policy.status = body.status
    _audit_policy_change(
        db,
        user,
        "scan_policy.status_changed",
        policy,
        request,
        changes={"from": previous, "to": body.status},
    )
    db.commit()
    db.refresh(policy)
    return _serialize(policy, db)


@router.post("/{policy_id}/version", status_code=201)
@limiter.limit("20/minute")
def new_policy_version(
    request: Request,
    response: Response,
    policy_id: str,
    body: ScanPolicyVersion,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_permission("scan_policies", "create")),
    db: Session = Depends(get_db),
):
    """
    Supersede a policy with a new version of the same family.

    The old row is archived and points at the new one, so a scan that ran under
    version 2 still resolves to a policy a reader can look up, while everything
    new runs version 3. That is what the family/version pair is for, and it is
    the shape ``CompliancePolicy`` already uses.

    Schedules are **not** repointed automatically. A schedule is an
    authorisation to scan unattended, and silently moving one onto a
    configuration nobody reviewed is precisely the substitution this phase
    refuses everywhere else. The response names them so an operator can.
    """
    resolved_org = _resolve_org(user, org_id)
    current = _get_policy(db, policy_id, resolved_org)

    validation = validate_policy(body.config, scan_kind=current.scan_kind)
    if not validation.valid:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Scan policy configuration is not valid.",
                "errors": validation.errors,
            },
        )

    versions = [
        row[0]
        for row in db.query(ScanPolicy.version_number)
        .filter(
            ScanPolicy.org_id == resolved_org,
            ScanPolicy.policy_family_code == current.policy_family_code,
        )
        .all()
    ]
    version = next_version_number(versions)

    org = platform_api.organisation(db, resolved_org)
    successor = ScanPolicy(
        id=_gen_policy_id(org.slug if org else resolved_org),
        org_id=resolved_org,
        created_by=str(user.id),
        name=body.name or f"{current.policy_family_code} v{version}",
        description=body.description or current.description,
        policy_family_code=current.policy_family_code,
        version_number=version,
        scan_kind=current.scan_kind,
        config=dict(body.config),
        status=POLICY_STATUS_ACTIVE if body.activate else POLICY_STATUS_DRAFT,
        is_enabled=True,
    )
    db.add(successor)
    db.flush()

    current.superseded_by_policy_id = successor.id
    if body.activate:
        current.status = POLICY_STATUS_ARCHIVED

    schedules = (
        db.query(ScanSchedule)
        .filter(
            ScanSchedule.policy_id == current.id,
            ScanSchedule.org_id == resolved_org,
        )
        .all()
    )

    _audit_policy_change(
        db,
        user,
        "scan_policy.versioned",
        successor,
        request,
        changes={
            "supersedes": current.id,
            "supersedes_version": current.version_number,
            "schedules_still_on_previous": [s.id for s in schedules],
        },
    )
    db.commit()
    db.refresh(successor)

    payload = _serialize(successor, db)
    payload["supersedes"] = current.id
    payload["warnings"] = list(validation.warnings)
    if schedules:
        payload["warnings"].append(
            f"{len(schedules)} schedule(s) still reference version "
            f"{current.version_number} and were not moved: "
            + ", ".join(s.name for s in schedules)
        )
    return payload


@router.get("/{policy_id}/usage")
@limiter.limit("60/minute")
def policy_usage(
    request: Request,
    response: Response,
    policy_id: str,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_permission("scan_policies", "read")),
    db: Session = Depends(get_db),
):
    """
    What depends on this policy: schedules now, and how many scans have run.

    ``scan_count`` counts scans whose *snapshot* names this policy id, read
    from ``scans.options``, not a join — the snapshot is the record and a scan
    keeps it after the policy is deleted.
    """
    from db.models.scans import Scan

    resolved_org = _resolve_org(user, org_id)
    policy = _get_policy(db, policy_id, resolved_org)

    schedules = (
        db.query(ScanSchedule)
        .filter(
            ScanSchedule.policy_id == policy.id, ScanSchedule.org_id == resolved_org
        )
        .all()
    )
    scan_count = (
        db.query(Scan.id)
        .filter(
            Scan.org_id == resolved_org,
            Scan.options["scan_policy"]["policy_id"].astext == str(policy.id),
        )
        .count()
    )
    return {
        "policy_id": policy.id,
        "use_count": policy.use_count,
        "scan_count": scan_count,
        "schedules": [
            {"id": s.id, "name": s.name, "is_enabled": s.is_enabled} for s in schedules
        ],
    }


@router.delete("/{policy_id}")
@limiter.limit("20/minute")
def delete_policy(
    request: Request,
    response: Response,
    policy_id: str,
    org_id: Optional[str] = Query(None),
    force: bool = Query(
        False, description="Delete even though schedules reference this policy"
    ),
    user: CurrentUser = Depends(require_permission("scan_policies", "delete")),
    db: Session = Depends(get_db),
):
    """
    Delete a policy.

    Refused by default while a schedule references it. The foreign key is
    ``ON DELETE SET NULL``, so deleting anyway leaves the schedule running
    under the request defaults — a silent broadening of what it assesses, which
    is the thing this phase exists to prevent. ``force=true`` is the deliberate
    way through, and the response names what it changed.

    Completed scans are never affected: their configuration lives in their own
    ``options`` snapshot, which is why the snapshot is stored there rather than
    as a foreign key to this table.
    """
    resolved_org = _resolve_org(user, org_id)
    policy = _get_policy(db, policy_id, resolved_org)

    schedules = (
        db.query(ScanSchedule)
        .filter(
            ScanSchedule.policy_id == policy.id, ScanSchedule.org_id == resolved_org
        )
        .all()
    )
    if schedules and not force:
        raise HTTPException(
            status_code=409,
            detail=(
                f"{len(schedules)} schedule(s) reference this policy: "
                + ", ".join(s.name for s in schedules)
                + ". Archive the policy instead, repoint the schedules, or "
                "pass force=true to delete anyway — those schedules will then "
                "run under the scan request defaults."
            ),
        )

    _audit_policy_change(
        db,
        user,
        "scan_policy.deleted",
        policy,
        request,
        changes={"orphaned_schedules": [s.id for s in schedules]},
    )
    db.delete(policy)
    db.commit()
    return {
        "success": True,
        "deleted": policy_id,
        "orphaned_schedules": [s.id for s in schedules],
    }


def _slug(value: str) -> str:
    """A family code from a name. Lowercase, hyphenated, bounded to the column."""
    import re

    slug = re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-")
    return (slug or "policy")[:100]


#: Coverage areas each route answers, read by
#: ``scripts/measure_scan_policy_coverage.py``. Declared here so an area cannot
#: claim coverage from a route that was removed.
ROUTE_AREAS = {
    ("/scan-policies", "POST"): "pol.crud.create",
    ("/scan-policies", "GET"): "pol.crud.read",
    ("/scan-policies/{policy_id}", "PATCH"): "pol.crud.update",
    ("/scan-policies/{policy_id}", "DELETE"): "pol.crud.archive",
    ("/scan-policies/{policy_id}/enable", "POST"): "pol.crud.enable",
    ("/scan-policies/validate", "POST"): "pol.bind.validation",
    ("/scan-policies/{policy_id}/version", "POST"): "pol.lifecycle.version",
    ("/scan-policies/{policy_id}", "GET"): "pol.authz.rbac",
}
