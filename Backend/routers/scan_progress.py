"""
routers/scan_progress.py
─────────────────────────────────────────────────────────────────────────────
Audit's real-time scan progress and pipeline documentation.

Split from ``routers/health.py``: these three routes are Audit's scan pipeline,
not service health. Paths, tags, permissions and responses are unchanged.

Endpoints
─────────
  GET /scan/progress/{scan_id}  → real-time progress (DB-backed, multi-worker safe)
  GET /api/pipeline-modes       → documentation: available pipeline modes
  GET /api/workflow-example     → documentation: frontend orchestration example
"""

from ccure_platform.api import CurrentUser, require_authorized
from db.base import get_db
from fastapi import APIRouter, Depends
from scan_helpers import PIPELINE_PHASES
from scans.progress import read_progress as _db_read_progress
from sqlalchemy.orm import Session

router = APIRouter()

#: Prose for each pipeline mode, keyed as in PIPELINE_PHASES. Kept beside the
#: router rather than inline in the handler so the two stay visibly paired.
_PIPELINE_MODE_DESCRIPTIONS = {
    "basic": "Host Discovery only. Scan is marked complete after Phase 1.",
    "asset": "Host Discovery then Port Scanning. Marked complete after Phase 2.",
    "vulnerability_audit": "Full pipeline. Marked complete after Phase 3 (vuln + risk).",
    "credentialed": (
        "Standalone credentialed audit. Runs Phase 3 only — no host discovery "
        "and no port scan."
    ),
}


# ── Real-time progress ───────────────────────────────────────────────────────


@router.get("/scan/progress/{scan_id}", tags=["Progress"])
async def get_scan_progress(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_authorized("audit.scan.read")),
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
                "phases": phases,
                "terminal_phase": max(phases),
                # Looked up rather than indexed: a mode added to
                # PIPELINE_PHASES without a description here used to raise
                # KeyError and return 500 for every mode, not just the new one.
                # "credentialed" did exactly that.
                "description": _PIPELINE_MODE_DESCRIPTIONS.get(
                    mode, "No description recorded for this pipeline mode."
                ),
            }
            for mode, phases in PIPELINE_PHASES.items()
        }
    }


@router.get("/api/workflow-example", tags=["Documentation"])
async def workflow_example():
    return {
        "workflow": "Frontend-Driven Phase Orchestration",
        "pipeline_modes": {
            "basic": {"phases": [1], "description": "Host Discovery only"},
            "asset": {"phases": [1, 2], "description": "Discovery → Port Scan"},
            "vulnerability_audit": {
                "phases": [1, 2, 3, 4],
                "description": "Full pipeline",
            },
        },
        "note": "Each phase endpoint now validates that the incoming phase is "
        "part of the declared pipeline_mode.",
    }
