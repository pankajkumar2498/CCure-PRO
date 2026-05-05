"""
routers/health.py
─────────────────────────────────────────────────────────────────────────────
Health / info endpoints and real-time scan progress.

Endpoints
─────────
  GET /                         → system health + info
  GET /scan/progress/{scan_id}  → real-time progress (DB-backed, multi-worker safe)
  GET /api/pipeline-modes       → documentation: available pipeline modes
  GET /api/workflow-example     → documentation: frontend orchestration example
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from db.base import get_db
from db.models import User
from auth.rbac import require_permission
from scan_helpers import get_api, PIPELINE_PHASES
from scans.progress import read_progress as _db_read_progress

router = APIRouter()


# ── Health ────────────────────────────────────────────────────────────────────

@router.get("/", tags=["Health"])
async def root():
    return get_api().get_system_info()


# ── Real-time progress ───────────────────────────────────────────────────────

@router.get("/scan/progress/{scan_id}", tags=["Progress"])
async def get_scan_progress(
    scan_id: str,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(require_permission("scans", "read")),
):
    """
    Get real-time progress for an ongoing scan (multi-worker safe).

    Reads progress from PostgreSQL instead of an in-memory dict,
    so any worker can serve this request regardless of which worker
    started the scan.

    Returns:
      - total_ips: total IPs being scanned
      - discovered: IPs discovered so far
      - active: active IPs discovered so far
      - status: "running" or "complete"
      - elapsed_time: seconds elapsed
      - percentage: progress percentage (0-100)
    """
    return _db_read_progress(db, scan_id, str(current_user.id))


# ── Documentation ─────────────────────────────────────────────────────────────

@router.get("/api/pipeline-modes", tags=["Documentation"])
async def pipeline_modes():
    """
    Lists all valid pipeline modes and their phase sequences.
    Useful for frontend validation or debugging.
    """
    return {
        "pipeline_modes": {
            mode: {
                "phases":         phases,
                "terminal_phase": max(phases),
                "description": {
                    "basic":    "Host Discovery only. Scan is marked complete after Phase 1.",
                    "asset":    "Host Discovery then Port Scanning. Marked complete after Phase 2.",
                    "advanced": "Full pipeline. Marked complete after Phase 3 (vuln + risk).",
                }[mode],
            }
            for mode, phases in PIPELINE_PHASES.items()
        }
    }


@router.get("/api/workflow-example", tags=["Documentation"])
async def workflow_example():
    return {
        "workflow": "Frontend-Driven Phase Orchestration",
        "pipeline_modes": {
            "basic":    {"phases": [1], "description": "Host Discovery only"},
            "asset":    {"phases": [1, 2], "description": "Discovery → Port Scan"},
            "advanced": {"phases": [1, 2, 3, 4], "description": "Full pipeline"},
        },
        "note": "Each phase endpoint now validates that the incoming phase is "
                "part of the declared pipeline_mode.",
    }
