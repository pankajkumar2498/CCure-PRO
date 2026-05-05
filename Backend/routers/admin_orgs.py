import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from auth.rbac import require_permission
from auth.dependencies import get_current_user
from db.base import get_db, utcnow
from db.models import Organization, User
from core.audit import log_audit_event

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/organizations", tags=["Organization Management"])

class OrganizationCreateSchema(BaseModel):
    name: str
    slug: str
    plan: Optional[str] = "community"
    max_assets: Optional[int] = 500
    max_users: Optional[int] = 10

class OrganizationUpdateSchema(BaseModel):
    name: Optional[str] = None
    plan: Optional[str] = None
    max_assets: Optional[int] = None
    max_users: Optional[int] = None
    is_active: Optional[bool] = None

@router.get("")
def list_organizations(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("organizations", "read"))
):
    orgs = db.query(Organization).order_by(Organization.created_at.desc()).all()
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
def update_organization(
    org_id: str,
    request: Request,
    org_data: OrganizationUpdateSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("organizations", "update"))
):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
        
    changes = {}
    for attr, value in org_data.model_dump(exclude_unset=True).items():
        old_val = getattr(org, attr)
        if old_val != value:
            changes[attr] = {"old": old_val, "new": value}
            setattr(org, attr, value)
            
    if changes:
        log_audit_event(db, current_user, "organization.updated", "organization", str(org.id), changes, request)
        db.commit()
        
    return {"detail": "Organization updated successfully"}
