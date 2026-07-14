from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload

from auth.rbac import require_permission
from db.base import get_db
from db.models import AuditLog, User

router = APIRouter(prefix="/admin/audit-logs", tags=["Audit Logs"])


def _is_superadmin(user: User) -> bool:
    return (
        getattr(getattr(user, "role", None), "name", "") or ""
    ).lower() == "superadmin"


@router.get("")
@router.get("/")
def list_audit_logs(
    user_id: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("audit", "read")),
):
    query = db.query(AuditLog).options(joinedload(AuditLog.user))

    if not _is_superadmin(current_user):
        query = (
            query.outerjoin(User, AuditLog.user_id == User.id)
            .filter(
                or_(
                    AuditLog.org_id == current_user.org_id,
                    User.org_id == current_user.org_id,
                )
            )
            .distinct()
        )

    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if action:
        query = query.filter(AuditLog.action == action)
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)
    if status:
        query = query.filter(AuditLog.status == status)

    total = query.count()
    logs = query.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit).all()

    return {
        "total": total,
        "logs": [
            {
                "id": str(log.id),
                "user_id": str(log.user_id) if log.user_id else None,
                "username": log.user.username if log.user else None,
                "user_email": log.user.email if log.user else None,
                "user_agent": log.user_agent,
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "status": log.status,
                "ip_address": log.ip_address,
                "changes": log.changes,
                "created_at": log.created_at,
            }
            for log in logs
        ],
    }
