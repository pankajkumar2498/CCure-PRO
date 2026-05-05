import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from auth.rbac import require_permission
from auth.dependencies import get_current_user
from db.base import get_db
from db.models import Organization, User
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
    
    try:
        new_org = Organization(
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
    org = _scoped_organization_query(db, org_id, current_user).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    if org.is_active != status_data.is_active:
        changes = {"is_active": {"old": org.is_active, "new": status_data.is_active}}
        org.is_active = status_data.is_active
        log_audit_event(db, current_user, "organization.status_changed", "organization", str(org.id), changes, request)
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
