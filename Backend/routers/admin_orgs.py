import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, EmailStr
from sqlalchemy.orm import Session

from auth.rbac import require_permission
from auth.dependencies import get_current_user
from auth.email_utils import email_matches, normalize_email
from auth.jwt_handler import hash_password
from db.base import get_db, gen_org_id, gen_user_id
from db.models import Organization, User, Role
from core.audit import log_audit_event

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/organizations", tags=["Organization Management"])

class OrganizationCreateSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=3, max_length=255)
    slug: str = Field(..., min_length=2, max_length=100)
    plan: Optional[str] = "community"
    max_assets: Optional[int] = Field(default=500, ge=1)
    max_users: Optional[int] = Field(default=10, ge=1)

    admin_username: Optional[str] = None
    admin_email: Optional[EmailStr] = None
    admin_password: Optional[str] = None
    admin_full_name: Optional[str] = None

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

    name: Optional[str] = Field(default=None, min_length=3, max_length=255)
    slug: Optional[str] = Field(default=None, min_length=2, max_length=100)
    plan: Optional[str] = None
    max_assets: Optional[int] = Field(default=None, ge=1)
    max_users: Optional[int] = Field(default=None, ge=1)

    @field_validator("name", "slug")
    @classmethod
    def strip_optional_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        value = value.strip()
        if not value:
            raise ValueError("Value cannot be empty")
        return value

class OrganizationStatusSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_active: bool

def _role_name(user: User) -> str:
    return (getattr(getattr(user, "role", None), "name", "") or "").lower()

def _scoped_organization_query(db: Session, org_id: str, current_user: User):
    query = db.query(Organization).filter(Organization.id == org_id)
    if _role_name(current_user) != "superadmin":
        query = query.filter(Organization.id == current_user.org_id)
    return query

def _serialize_org(org: Organization) -> dict:
    return {
        "id": str(org.id),
        "name": org.name,
        "slug": org.slug,
        "plan": org.plan,
        "max_assets": org.max_assets,
        "max_users": org.max_users,
        "is_active": org.is_active,
        "created_at": org.created_at,
        "detail": "Organization updated successfully"
    }

@router.get("")
@router.get("/")
def list_organizations(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("organizations", "read"))
):
    if _role_name(current_user) == "superadmin":
        query = db.query(Organization)
    else:
        query = db.query(Organization).filter(Organization.id == current_user.org_id)

    orgs = query.order_by(Organization.created_at.desc()).all()
    return {
        "organizations": [
            {
                "id": str(o.id),
                "name": o.name,
                "slug": o.slug,
                "plan": o.plan,
                "max_assets": o.max_assets,
                "max_users": o.max_users,
                "is_active": o.is_active,
                "created_at": o.created_at
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
    current_user: User = Depends(require_permission("organizations", "create"))
):
    # Check for duplicate slug
    if db.query(Organization).filter(Organization.slug == org_data.slug).first():
        raise HTTPException(status_code=400, detail=f"Organization slug '{org_data.slug}' is already in use")
    
    # Check for duplicate name
    if db.query(Organization).filter(Organization.name == org_data.name).first():
        raise HTTPException(status_code=400, detail=f"Organization name '{org_data.name}' is already in use")
        
    # Check if we need to create an admin user and if their info is valid
    org_admin_role = None
    admin_email = normalize_email(org_data.admin_email) if org_data.admin_email else None
    if org_data.admin_username and org_data.admin_email and org_data.admin_password:
        if db.query(User).filter(User.username == org_data.admin_username).first():
            raise HTTPException(status_code=400, detail=f"Admin username '{org_data.admin_username}' is already in use")
        if db.query(User).filter(email_matches(User.email, admin_email)).first():
            raise HTTPException(status_code=400, detail=f"Admin email '{admin_email}' is already in use")
        
        org_admin_role = db.query(Role).filter(Role.name == "org_admin").first()
        if not org_admin_role:
            raise HTTPException(status_code=500, detail="The 'org_admin' role does not exist in the system.")
    
    try:
        new_org = Organization(
            id=gen_org_id(org_data.slug),   # e.g. org_acme_corp
            name=org_data.name,
            slug=org_data.slug,
            plan=org_data.plan,
            max_assets=org_data.max_assets,
            max_users=org_data.max_users,
            is_active=True,
            settings={}
        )
        db.add(new_org)
        db.flush()

        log_audit_event(db, current_user, "organization.created", "organization", str(new_org.id), request=request)
        
        # Create admin user if requested
        if org_data.admin_username and org_data.admin_email and org_data.admin_password:
            new_admin = User(
                id=gen_user_id(org_data.admin_username),
                username=org_data.admin_username,
                email=admin_email,
                full_name=org_data.admin_full_name,
                password_hash=hash_password(org_data.admin_password),
                role_id=org_admin_role.id,
                org_id=new_org.id,
                is_active=True
            )
            db.add(new_admin)
            db.flush()
            log_audit_event(db, current_user, "user.created", "user", str(new_admin.id), request=request, details={"note": "Initial org admin created"})

        db.commit()
        db.refresh(new_org)
        
        return {"id": str(new_org.id), "slug": new_org.slug}
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create organization: {e}")
        raise HTTPException(status_code=500, detail="Internal server error while creating organization")

@router.put("/{org_id}")
@router.put("/{org_id}/")
def update_organization(
    org_id: str,
    request: Request,
    org_data: OrganizationUpdateSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("organizations", "update"))
):
    org = _scoped_organization_query(db, org_id, current_user).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
        
    update_payload = org_data.model_dump(exclude_unset=True)

    if "slug" in update_payload:
        if update_payload["slug"] != org.slug:
            if db.query(Organization).filter(Organization.slug == update_payload["slug"], Organization.id != org.id).first():
                raise HTTPException(status_code=400, detail=f"Organization slug '{update_payload['slug']}' is already in use")

    if "name" in update_payload and update_payload["name"] != org.name:
        if db.query(Organization).filter(Organization.name == update_payload["name"], Organization.id != org.id).first():
            raise HTTPException(status_code=400, detail=f"Organization name '{update_payload['name']}' is already in use")

    changes = {}
    for attr, value in update_payload.items():
        old_val = getattr(org, attr)
        if old_val != value:
            changes[attr] = {"old": old_val, "new": value}
            setattr(org, attr, value)
            
    if changes:
        log_audit_event(db, current_user, "organization.updated", "organization", str(org.id), changes, request)
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
    current_user: User = Depends(require_permission("organizations", "update"))
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
        changes = {"is_active": {"old": org.is_active, "new": status_data.is_active}}
        org.is_active = status_data.is_active
        
        # Log audit event with detailed context
        action = "organization.deactivated" if not status_data.is_active else "organization.activated"
        log_audit_event(db, current_user, action, "organization", str(org.id), changes, request)
        db.commit()
        db.refresh(org)

    return _serialize_org(org)

@router.delete("/{org_id}")
@router.delete("/{org_id}/")
def delete_organization(
    org_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if _role_name(current_user) != "superadmin":
        raise HTTPException(status_code=403, detail="Only superadmins can delete organizations")

    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    if str(org.id) == str(current_user.org_id):
        raise HTTPException(status_code=400, detail="Cannot delete your own organization")

    org_count = db.query(Organization).count()
    if org_count <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete the last organization")

    changes = {
        "name": org.name,
        "slug": org.slug,
        "plan": org.plan,
        "is_active": org.is_active,
    }
    log_audit_event(db, current_user, "organization.deleted", "organization", str(org.id), changes, request)
    db.delete(org)
    db.commit()
    return {"detail": "Organization deleted successfully"}
