"""
admin_nvd.py
─────────────────────────────────────────────────────────────────────────────
Admin API Endpoints for NVD Vulnerability Catalog Live Sync.

Endpoints:
  POST /api/v1/admin/sync-nvd       → Manually trigger NVD catalog sync into vuln_intel DB
  GET  /api/v1/admin/nvd-sync-status → Check NVD sync status and DB catalog metrics
"""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user_flexible
from db.base import get_db
from db.models import User
from scans.nvd_sync import get_nvd_sync_status, sync_nvd_to_vuln_intel

router = APIRouter(prefix="/api/v1/admin", tags=["Admin NVD Catalog"])


def _verify_admin(user: User = Depends(get_current_user_flexible)) -> User:
    """Ensure caller has admin privileges."""
    is_admin = getattr(user, "is_superadmin", False) or getattr(user, "role", "") in (
        "superadmin",
        "org_admin",
    )
    if not is_admin:
        raise HTTPException(
            status_code=403,
            detail="Admin privileges required to manage NVD catalog sync.",
        )
    return user


@router.post("/sync-nvd")
async def trigger_nvd_sync(
    background_tasks: BackgroundTasks,
    days_back: int = Query(
        90, ge=1, le=3650, description="Days of historical CVE modifications to pull"
    ),
    current_user: User = Depends(_verify_admin),
):
    """
    Manually trigger live NVD 2.0 API vulnerability sync into vuln_intel database.
    Runs asynchronously in the background.
    """
    status = get_nvd_sync_status()
    if status["status"] == "SYNCING":
        return {
            "success": True,
            "status": "SYNCING",
            "message": "NVD catalog sync is already running in background.",
            "details": status,
        }

    # Launch background task
    background_tasks.add_task(sync_nvd_to_vuln_intel, days_back)

    return {
        "success": True,
        "status": "STARTED",
        "message": f"NVD 2.0 vulnerability catalog sync initiated for past {days_back} days.",
        "triggered_by": current_user.email,
    }


@router.get("/nvd-sync-status")
async def get_sync_status(
    current_user: User = Depends(_verify_admin),
):
    """
    Check NVD 2.0 vulnerability sync progress, last sync timestamp, and total CVE count in vuln_intel DB.
    """
    status = get_nvd_sync_status()
    return {
        "success": True,
        "data": status,
    }
