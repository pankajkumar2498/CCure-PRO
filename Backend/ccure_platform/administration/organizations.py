from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "routers.admin_orgs")

import logging
from typing import Optional

from ccure_platform.administration.rbac_security import (
    retain_organisation_administrators,
    record_assignment_denial,
    step_up,
)
from ccure_platform.identity.dependencies import get_current_user
from ccure_platform.identity.email_utils import (
    email_matches,
    normalize_email,
    username_matches,
)
from ccure_platform.identity.jwt_handler import hash_password
from ccure_platform.rbac.dependencies import require_authorized
from ccure_platform.rbac.scope import acts_across_organisations
from ccure_platform.audit_log.writer import log_audit_event
from db.base import gen_org_id, gen_user_id, get_db, utcnow
from ccure_platform.models import Organization, RefreshTokenSession, User
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/organizations", tags=["Organization Management"])


class OrganizationCreateSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=3, max_length=255)
    slug: str = Field(..., min_length=2, max_length=100)

    admin_username: str | None = None
    admin_email: EmailStr | None = None
    admin_password: str | None = None
    admin_full_name: str | None = None

    @field_validator("name", "slug")
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Value cannot be empty")
        return value


class OrganizationUpdateSchema(BaseModel):
    """Update organization metadata."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=3, max_length=255)
    slug: str | None = Field(default=None, min_length=2, max_length=100)

    @field_validator("name", "slug")
    @classmethod
    def strip_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return value
        value = value.strip()
        if not value:
            raise ValueError("Value cannot be empty")
        return value


class OrganizationStatusSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_active: bool


def _scoped_organization_query(db: Session, org_id: str, current_user: User):
    query = db.query(Organization).filter(Organization.id == org_id)
    # cross-organisation reach is the platform-scope switch grant (RBAC-5/7)
    if not acts_across_organisations(current_user):
        query = query.filter(Organization.id == current_user.org_id)
    return query


def _serialize_org(org: Organization) -> dict:
    return {
        "id": str(org.id),
        "name": org.name,
        "slug": org.slug,
        "is_active": org.is_active,
        "created_at": org.created_at,
        "archived_at": org.archived_at,
        "detail": "Organization updated successfully",
    }


@router.get("")
@router.get("/")
def list_organizations(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authorized("platform.organization.read")),
    include_archived: bool = False,
):
    """
    List organisations. Archived tenants are excluded unless asked for.

    An archived organisation is not deleted — it and all of its data are still
    present — so it has to be filtered out here or the list would show
    terminated tenants alongside live ones. `include_archived=true` is how a
    superadmin finds one to restore.
    """
    if acts_across_organisations(current_user):
        query = db.query(Organization)
    else:
        query = db.query(Organization).filter(Organization.id == current_user.org_id)

    if not include_archived:
        query = query.filter(Organization.archived_at.is_(None))

    orgs = query.order_by(Organization.created_at.desc()).all()
    return {
        "organizations": [
            {
                "id": str(o.id),
                "name": o.name,
                "slug": o.slug,
                "is_active": o.is_active,
                "created_at": o.created_at,
                "archived_at": o.archived_at,
            }
            for o in orgs
        ]
    }


@router.post("")
@router.post("/")
def create_organization(
    request: Request,
    org_data: OrganizationCreateSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authorized("platform.organization.create")),
):
    creates_admin = bool(
        org_data.admin_username and org_data.admin_email and org_data.admin_password
    )
    step = step_up(current_user, request, sensitive=creates_admin)

    # Check for duplicate slug
    if db.query(Organization).filter(Organization.slug == org_data.slug).first():
        raise HTTPException(
            status_code=400,
            detail=f"Organization slug '{org_data.slug}' is already in use",
        )

    # Check for duplicate name
    if db.query(Organization).filter(Organization.name == org_data.name).first():
        raise HTTPException(
            status_code=400,
            detail=f"Organization name '{org_data.name}' is already in use",
        )

    # Check if we need to create an admin user and if their info is valid
    org_admin_role = None
    admin_email = (
        normalize_email(org_data.admin_email) if org_data.admin_email else None
    )
    if org_data.admin_username and org_data.admin_email and org_data.admin_password:
        if (
            db.query(User)
            .filter(username_matches(User.username, org_data.admin_username))
            .first()
        ):
            raise HTTPException(
                status_code=400,
                detail=f"Admin username '{org_data.admin_username}' is already in use",
            )
        if db.query(User).filter(email_matches(User.email, admin_email)).first():
            raise HTTPException(
                status_code=400, detail=f"Admin email '{admin_email}' is already in use"
            )

    try:
        new_org = Organization(
            id=gen_org_id(org_data.slug),  # e.g. org_acme_corp
            name=org_data.name,
            slug=org_data.slug,
            is_active=True,
            settings={},
        )
        db.add(new_org)
        db.flush()

        log_audit_event(
            db,
            current_user,
            "organization.created",
            "organization",
            str(new_org.id),
            request=request,
        )

        # Create admin user if requested
        if org_data.admin_username and org_data.admin_email and org_data.admin_password:
            # Verified and approved at creation, for the same reason as
            # POST /admin/users: a superadmin deliberately provisioning an
            # organisation's first administrator *is* the approval, and they set
            # the password out-of-band rather than mailing a link.
            #
            # This was missed when the login gates were added, and the result was
            # an account that appeared to be created successfully and then could
            # not sign in — "Verify your email address" for an address nobody had
            # been asked to verify. An organisation whose only administrator is
            # locked out cannot be administered at all.
            new_admin = User(
                id=gen_user_id(new_org.slug, org_data.admin_username),
                username=org_data.admin_username,
                email=admin_email,
                full_name=org_data.admin_full_name,
                password_hash=hash_password(org_data.admin_password),
                org_id=new_org.id,
                is_active=True,
                is_verified=True,
                approved_at=utcnow(),
                approved_by=str(current_user.id),
            )
            db.add(new_admin)
            db.flush()
            # The administrator's role is an RBAC assignment made through the governed
            # API by the actor creating the organisation (RBAC-8): if that actor may
            # not hand it out, the whole organisation rolls back — never a half-
            # provisioned administrator, and nothing privileged granted by default.
            from ccure_platform.rbac.governance import GovernanceError
            from ccure_platform.rbac.audit import emit as _emit_rbac
            from ccure_platform.rbac.provisioning import provision_organisation_admin

            try:
                with db.begin_nested():
                    rbac_events = provision_organisation_admin(
                        db, current_user, str(new_admin.id)
                    )
            except GovernanceError as error:
                record_assignment_denial(current_user, error, str(new_org.id))
                raise HTTPException(
                    status_code=403,
                    detail="The organisation administrator could not be provisioned: "
                    + ", ".join(sorted({v.code for v in error.violations})),
                ) from None
            for event in rbac_events:
                event.changes["reauth"] = step
            _emit_rbac(db, rbac_events, actor=current_user, request=request)
            log_audit_event(
                db,
                current_user,
                "user.created",
                "user",
                str(new_admin.id),
                request=request,
                changes={"note": "Initial org admin created"},
            )

        db.commit()
        db.refresh(new_org)

        return {"id": str(new_org.id), "slug": new_org.slug}
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create organization: {e}")
        raise HTTPException(
            status_code=500, detail="Internal server error while creating organization"
        )


@router.put("/{org_id}")
@router.put("/{org_id}/")
def update_organization(
    org_id: str,
    request: Request,
    org_data: OrganizationUpdateSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authorized("platform.organization.update")),
):
    org = _scoped_organization_query(db, org_id, current_user).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    update_payload = org_data.model_dump(exclude_unset=True)

    if "slug" in update_payload:
        if update_payload["slug"] != org.slug:
            if (
                db.query(Organization)
                .filter(
                    Organization.slug == update_payload["slug"],
                    Organization.id != org.id,
                )
                .first()
            ):
                raise HTTPException(
                    status_code=400,
                    detail=f"Organization slug '{update_payload['slug']}' is already in use",
                )

    if "name" in update_payload and update_payload["name"] != org.name:
        if (
            db.query(Organization)
            .filter(
                Organization.name == update_payload["name"], Organization.id != org.id
            )
            .first()
        ):
            raise HTTPException(
                status_code=400,
                detail=f"Organization name '{update_payload['name']}' is already in use",
            )

    changes = {}
    for attr, value in update_payload.items():
        old_val = getattr(org, attr)
        if old_val != value:
            changes[attr] = {"old": old_val, "new": value}
            setattr(org, attr, value)

    if changes:
        log_audit_event(
            db,
            current_user,
            "organization.updated",
            "organization",
            str(org.id),
            changes,
            request,
        )
        db.commit()
        db.refresh(org)

    return _serialize_org(org)


@router.patch("/{org_id}/status")
@router.patch("/{org_id}/status/")
def change_organization_status(
    org_id: str,
    request: Request,
    status_data: OrganizationStatusSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authorized("platform.organization.update")),
):
    """
    Update organization's active/inactive status.

    Production Deactivation Flow:
    ─────────────────────────────────────────────────────────────────────────────

    DEACTIVATION (is_active: false):
      • All users in the organization lose access IMMEDIATELY
      • Existing sessions/tokens become invalid on next request
      • New login attempts are rejected with HTTP 403
      • Token refresh fails with HTTP 401
      • Individual user statuses remain UNCHANGED
      • Audit trail logs the deactivation event

    REACTIVATION (is_active: true):
      • Users regain access without modification
      • No need to re-enable individual users
      • Existing tokens remain valid (if not expired)
      • Full reversal of deactivation state

    Benefits:
      ✓ Instant access revocation without manual user modifications
      ✓ Reversible state - no data loss or extra cleanup
      ✓ Scalable - handles thousands of users in deactivated orgs
      ✓ Clean audit trail - org status change is primary audit event
      ✓ No token invalidation needed - checked on every request

    Returns:
      Organization object with updated status
    """
    org = _scoped_organization_query(db, org_id, current_user).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    if org.is_active != status_data.is_active:
        if not status_data.is_active:
            retain_organisation_administrators(db, current_user, str(org.id))
        changes = {"is_active": {"old": org.is_active, "new": status_data.is_active}}
        org.is_active = status_data.is_active

        # Log audit event with detailed context
        action = (
            "organization.deactivated"
            if not status_data.is_active
            else "organization.activated"
        )
        log_audit_event(
            db, current_user, action, "organization", str(org.id), changes, request
        )
        db.commit()
        db.refresh(org)

    return _serialize_org(org)


@router.delete("/{org_id}")
@router.delete("/{org_id}/")
def archive_organization(
    org_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authorized("platform.organization.archive")),
    reason: Optional[str] = None,
):
    """
    End a tenancy by **archiving** the organisation. Nothing is deleted.

    This route used to call ``db.delete(org)``. Thirty foreign keys reference
    ``organizations`` and every one of them is ``ON DELETE CASCADE``, so that
    single statement destroyed the tenant's users, assets, scans, every
    ``compliance_*`` record including findings and evidence, and its entire
    audit trail — irreversibly, with no undo, at exactly the moment an
    offboarding is most likely to be disputed. For an audit and compliance
    product that is the wrong default.

    Archiving sets ``is_active = False`` as well as ``archived_at``, and that
    flag is what actually denies access: it is already enforced in
    ``auth/jwt_handler.py`` (twice) and ``auth/router.py``. No new
    authorisation code is introduced here, and therefore no new bypass surface.

    ``archived_at`` is deliberately not ``is_active`` on its own —
    deactivation is a reversible suspension used for billing and temporary
    lockout, archival is the end of the tenancy, and collapsing the two makes
    a suspended tenant indistinguishable from a terminated one in the audit
    trail.

    Hard deletion is **not** available. When it is built it will be a separate,
    explicitly named purge that first exports the trail and seals the tenant's
    hash chain — the same delete-then-purge shape ``users`` already has.

    The ``ON DELETE CASCADE`` relationships are left exactly as they were; this
    route simply stops invoking them.
    """
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    if str(org.id) == str(current_user.org_id):
        raise HTTPException(
            status_code=400, detail="Cannot archive your own organization"
        )

    # Both pre-existing guards are kept. The second counts only live
    # organisations: once archival exists, "the last organization" has to mean
    # the last one still in use, or archiving every tenant but one would be
    # blocked by tenants that are already gone.
    live_orgs = (
        db.query(Organization).filter(Organization.archived_at.is_(None)).count()
    )
    if live_orgs <= 1:
        raise HTTPException(
            status_code=400, detail="Cannot archive the last active organization"
        )

    if org.archived_at is not None:
        return {"detail": "Organization is already archived", "archived": False}

    retain_organisation_administrators(db, current_user, str(org.id))
    now = utcnow()
    previous_active = bool(org.is_active)
    org.archived_at = now
    org.archived_by_user_id = str(current_user.id)
    org.archive_reason = (reason or "").strip() or None
    org.is_active = False
    org.updated_at = now

    # Members lose access immediately, using the semantics `users` already has
    # (see admin_users.delete_user): soft-deleted and deactivated, never
    # removed. Their audit history stays attributable because the actor
    # snapshot is frozen on each event.
    members = db.query(User).filter(User.org_id == org.id).all()
    for member in members:
        if not member.is_deleted:
            member.is_deleted = True
            member.deleted_at = now
        member.is_active = False
        member.updated_at = now

    # Sessions are revoked rather than left to expire: an access token already
    # issued stays valid for up to 30 minutes, and the refresh cookie for 7
    # days, so without this an archived tenant keeps working for the rest of
    # the access-token lifetime.
    revoked = (
        db.query(RefreshTokenSession)
        .filter(RefreshTokenSession.org_id == org.id)
        .delete(synchronize_session=False)
    )

    log_audit_event(
        db,
        current_user,
        "organization.archived",
        "organization",
        str(org.id),
        {
            "name": org.name,
            "slug": org.slug,
            "is_active": {"old": previous_active, "new": False},
            "archived_at": {"old": None, "new": now.isoformat()},
            "reason": org.archive_reason,
            "members_deactivated": len(members),
            "sessions_revoked": revoked,
        },
        request,
    )
    db.commit()
    return {
        "detail": "Organization archived",
        "archived": True,
        "members_deactivated": len(members),
        "sessions_revoked": revoked,
    }


@router.post("/{org_id}/restore")
@router.post("/{org_id}/restore/")
def restore_organization(
    org_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authorized("platform.organization.archive")),
):
    """
    Reverse an archival.

    Member accounts are **not** silently reactivated. Archiving soft-deleted
    them, and restoring an account is a decision about that person, not about
    the tenancy — the same reason ``admin_users.restore_user`` leaves a
    restored account inactive until someone explicitly reactivates it. A bulk
    reactivation here would quietly re-enable an account that had been disabled
    for its own reasons before the organisation was archived.
    """
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    if org.archived_at is None:
        return {"detail": "Organization is not archived", "restored": False}

    previous_archived_at = org.archived_at
    org.archived_at = None
    org.archived_by_user_id = None
    org.archive_reason = None
    org.is_active = True
    org.updated_at = utcnow()

    log_audit_event(
        db,
        current_user,
        "organization.restored",
        "organization",
        str(org.id),
        {
            "archived_at": {"old": previous_archived_at.isoformat(), "new": None},
            "is_active": {"old": False, "new": True},
            "note": "member accounts remain deactivated until reactivated individually",
        },
        request,
    )
    db.commit()
    return {"detail": "Organization restored", "restored": True}


# ── Authorised scan scope ─────────────────────────────────────────────────────


class ScanScopeSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # None clears the scope (legacy unrestricted / denied under
    # REQUIRE_SCAN_SCOPE). [] denies all scanning. Both are meaningful, so the
    # field distinguishes "absent" from "empty".
    cidrs: Optional[list[str]] = Field(
        default=None,
        description="CIDR blocks this organisation may scan, e.g. ['10.180.6.0/24']",
    )


@router.get("/{org_id}/scan-scope")
@router.get("/{org_id}/scan-scope/")
def get_scan_scope(
    org_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authorized("platform.organization.read")),
):
    """Return the CIDR blocks this organisation is authorised to scan."""
    org = _scoped_organization_query(db, org_id, current_user).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    from config import AppConfig

    return {
        "org_id": str(org.id),
        "cidrs": org.scan_scope_cidrs,
        "configured": org.scan_scope_cidrs is not None,
        "enforcement_required": AppConfig.REQUIRE_SCAN_SCOPE,
    }


@router.put("/{org_id}/scan-scope")
@router.put("/{org_id}/scan-scope/")
def set_scan_scope(
    org_id: str,
    request: Request,
    payload: ScanScopeSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_authorized("platform.organization.set_scan_scope")
    ),
):
    """
    Set the CIDR blocks this organisation may scan. **Superadmin only.**

    Gated on the role directly rather than on the `organizations:update`
    permission, because org_admin holds that permission for its own
    organisation. Letting an org_admin write this field would mean the subject
    of a restriction can widen it — which is not a restriction. This is the one
    org attribute a tenant administrator must not control, and it is why the
    value lives in its own column instead of the org_admin-writable `settings`
    bag.
    """
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    from ccure_platform.organisation_settings.scan_scope import normalise_scope

    if payload.cidrs is None:
        new_scope = None
    else:
        try:
            new_scope = normalise_scope(payload.cidrs)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    old_scope = org.scan_scope_cidrs
    org.scan_scope_cidrs = new_scope

    log_audit_event(
        db,
        current_user,
        "organization.scan_scope_changed",
        "organization",
        str(org.id),
        {"old": old_scope, "new": new_scope},
        request,
    )
    db.commit()

    return {
        "org_id": str(org.id),
        "cidrs": new_scope,
        "detail": "Scan scope updated",
    }
