"""
admin_nvd.py
─────────────────────────────────────────────────────────────────────────────
Admin API Endpoints for NVD Vulnerability Catalog Live Sync.

The catalogue synced here is ``vulnerability_definitions`` in the **application**
database — the table ``asset_vulnerabilities.vuln_id`` references. The
vulnerability-intelligence database (``cve``/``cpe``/``kev``/``epss``/…) is a
separate store loaded by the feed scripts, and this endpoint neither reads nor
writes it; its freshness is reported alongside so drift between the two is
visible rather than assumed.

Endpoints:
  POST /api/v1/admin/sync-nvd        → Trigger an incremental sync, or a backfill
  GET  /api/v1/admin/nvd-sync-status → Check NVD sync status and catalogue metrics
"""

from typing import Optional

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
    days_back: Optional[int] = Query(
        None,
        ge=1,
        le=3650,
        description=(
            "Historical lookback in days. Omit to run the normal incremental "
            "sync, which resumes from the stored checkpoint. Supply a value to "
            "backfill exactly that many days: the checkpoint is then ignored "
            "and never advanced, so a backfill cannot move the incremental "
            "frontier past anything it failed to retrieve."
        ),
    ),
    current_user: User = Depends(_verify_admin),
):
    """
    Trigger a live NVD 2.0 sync into the application vulnerability catalogue.
    Runs asynchronously in the background.

    ``days_back`` is the mode selector, and deliberately so. It used to be a
    plain int with a default of 90 that the sync read and then discarded,
    because the stored checkpoint overrode it on every deployment that had ever
    synced — an operator could ask for a year of history, receive a 202, and get
    the last few hours. Presence now means "backfill this window"; absence means
    "carry on from the checkpoint".
    """
    status = get_nvd_sync_status()
    if status["status"] == "SYNCING":
        return {
            "success": True,
            "status": "SYNCING",
            "message": "NVD catalog sync is already running in background.",
            "details": status,
        }

    if days_back is None:
        background_tasks.add_task(sync_nvd_to_vuln_intel)
        message = "Incremental NVD catalogue sync initiated from the stored checkpoint."
        mode = "incremental"
    else:
        background_tasks.add_task(
            sync_nvd_to_vuln_intel, days_back=days_back, backfill=True
        )
        message = (
            f"NVD catalogue backfill initiated for the past {days_back} day(s). "
            "The incremental checkpoint is left untouched."
        )
        mode = "backfill"

    return {
        "success": True,
        "status": "STARTED",
        "mode": mode,
        "message": message,
        "triggered_by": current_user.email,
    }


@router.get("/nvd-sync-status")
async def get_sync_status(
    current_user: User = Depends(_verify_admin),
):
    """
    Check NVD 2.0 sync progress, last sync timestamp, and the catalogue count.

    ``database_total_cves`` is the application catalogue. The intelligence feed
    is reported separately as ``scanner_feed_total_cves`` /
    ``scanner_feed_last_modified``; the two are different stores and neither
    number stands in for the other.
    """
    status = get_nvd_sync_status()
    return {
        "success": True,
        "data": status,
    }
