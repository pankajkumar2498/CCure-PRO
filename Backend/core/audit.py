import logging
from fastapi import Request
from sqlalchemy.orm import Session
from db.models import AuditLog, User
from core.ip_resolver import get_client_ip

logger = logging.getLogger(__name__)


def log_audit_event(
    db: Session,
    user: User,
    action: str,
    resource_type: str = None,
    resource_id: str = None,
    changes: dict = None,
    request: Request = None,
    status: str = "success",
):
    ip_address = None
    user_agent = None

    if request:
        ip_address = get_client_ip(request)
        if ip_address == "testclient" or not ip_address:
            ip_address = "127.0.0.1"
        else:
            import ipaddress

            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                ip_address = "127.0.0.1"
        user_agent = request.headers.get("user-agent")

    try:
        log_entry = AuditLog(
            org_id=user.org_id if user else None,
            user_id=user.id if user else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            changes=changes,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
        )
        db.add(log_entry)
        # We don't necessarily commit here, we rely on the caller to commit
        db.flush()
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")
