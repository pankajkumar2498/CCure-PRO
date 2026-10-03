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

Endpoints (both superadmin-only — see ``_superadmin_only`` below):
  POST /api/v1/admin/sync-nvd        → Trigger an incremental sync, or a backfill
  GET  /api/v1/admin/nvd-sync-status → Check NVD sync status and catalogue metrics
"""

from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from sqlalchemy.orm import Session

from ccure_platform.api import CurrentUser, require_authorized
from db.base import get_db
from scans.nvd_sync import get_nvd_sync_status, sync_nvd_to_vuln_intel

router = APIRouter(prefix="/api/v1/admin", tags=["Admin NVD Catalog"])

#: Both routes here are superadmin-only, through the application's own role
#: guard. Three things about that, because the guard these replaced was wrong
#: in a way that was invisible:
#:
#: **It refused everybody, including a superadmin.** The previous local
#: ``_verify_admin`` tested ``getattr(user, "is_superadmin", False)`` and
#: ``getattr(user, "role", "") in ("superadmin", "org_admin")``. ``User`` has no
#: ``is_superadmin`` attribute, and ``User.role`` is a relationship to a
#: ``Role`` object, so the membership test compared a ``Role`` instance against
#: two strings and was false for every account there is. It failed closed, which
#: is the right direction to fail — but a permanently closed door is still a
#: broken one, and nothing said so: the endpoint answered 403 with
#: "Admin privileges required", which reads as a correct refusal.
#:
#: **Superadmin-only is the established policy, not a choice made here.** The
#: catalogue this syncs — ``vulnerability_definitions`` — carries no ``org_id``
#: and is shared by every tenant, so one workspace's administrator triggering a
#: sync acts on all of them. That is the same reasoning recorded for
#: ``/admin/email-domains``, which is superadmin-only for exactly this reason
#: and deliberately guarded by role rather than by permission: superadmin holds
#: every permission, so any atom an org_admin also held would let them through.
#: ``tests/security/test_endpoint_limit_inventory.py`` already records these two
#: routes as "Feed synchronisation. Superadmin-only" in the rationale for not
#: rate-limiting them.
#:
#: **``require_authorized`` authenticates with ``get_current_user``, not
#: ``get_current_user_flexible``**, and that narrowing is deliberate. The
#: flexible dependency also accepts a short-lived download ticket, which exists
#: so a browser can fetch a report from a URL. A ticket that can be put in a URL
#: must not be able to start an outbound synchronisation.
_superadmin_only = require_authorized("audit.vuln_feed.manage")


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
    current_user: CurrentUser = Depends(_superadmin_only),
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
    current_user: CurrentUser = Depends(_superadmin_only),
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
