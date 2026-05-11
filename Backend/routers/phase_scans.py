"""
routers/phase_scans.py
─────────────────────────────────────────────────────────────────────────────
Phase-selective scan endpoints (frontend-orchestrated pipeline).

Endpoints
─────────
  POST /scan/host-discovery   → Phase 1: Host Discovery
  POST /scan/asset-discovery  → Phase 2: Port Scanning & Service Detection
  POST /scan/advanced-scan    → Phase 3: Vulnerability Audit & Risk Scoring
  POST /scan/phases           → Convenience: run any combination of phases
"""

import asyncio
import logging
import os
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from db.base import get_db
from db.models import User
from auth.rbac import require_permission
from scans.db_helpers import (
    create_scan,
    update_scan_phase,
    mark_scan_failed,
)
from scan_helpers import (
    get_api,
    limiter,
    resolve_pipeline_mode,
    get_terminal_phase,
    is_phase_in_pipeline,
    resolve_report_context,
    apply_phase1_summary_hints,
    validate_total_targets,
    PIPELINE_PHASES,
    log,
)

router = APIRouter(tags=["Phase-Selective Scans"])


# ── Request models ────────────────────────────────────────────────────────────

class HostDiscoveryRequest(BaseModel):
    """
    Host Discovery — Phase 1.

    `pipeline_mode` tells the backend which pipeline this scan belongs to:
      "basic"    → only Host Discovery will run; scan is immediately marked complete.
      "asset"    → Host Discovery then Asset Discovery; scan stays 'running' after host discovery.
      "advanced" → Full pipeline; scan stays 'running' until advanced scan.

    `phases` is the authoritative list from the frontend (informational / audit).

    `discovery_intensity` controls Asset Discovery Phase 1 strategy (asset pipeline only):
      "light"  → FAST profile only — fastest, may miss firewalled/restricted hosts.
      "normal" → FAST first, BALANCED fallback only for still-inactive IPs (default).
      "deep"   → Full BALANCED — maximum coverage, slower.
    Ignored for basic and advanced pipelines.
    """
    targets:             List[str]      = Field(..., example=["192.168.1.0/24"])
    scan_type:           str            = Field("adaptive", example="adaptive")
    pipeline_mode:       Optional[str]  = Field("basic",
                                                example="basic",
                                                description="basic | asset | advanced")
    phases:              Optional[List[int]] = Field(None,
                                                     example=[1, 2],
                                                     description="Phase list from frontend (informational)")
    discovery_intensity: Optional[str]  = Field("normal",
                                                example="normal",
                                                description="light | normal | deep (asset pipeline only)")
    rate_limit:          Optional[float] = Field(None, description="Optional rate limit for probes per second (PPS).")
    max_concurrency:     Optional[int]   = Field(None, description="Max concurrent threads (e.g. TCP connect probes).")
    wait:                bool            = Field(False, description="If true, wait for task completion (up to 300s) before returning.")


class AssetDiscoveryRequest(BaseModel):
    """
    Asset Discovery — Phase 2.

    Must include the same `pipeline_mode` used in the Host Discovery request so the
    backend can decide whether this is the terminal phase (asset) or not (advanced).
    """
    hosts:         List[dict]     = Field(..., description="Host dicts from Host Discovery")
    intensity:     str            = Field("normal", example="normal")
    scan_id:       Optional[str]  = Field(None)
    pipeline_mode: Optional[str]  = Field("asset",
                                          example="asset",
                                          description="basic | asset | advanced")
    phases:        Optional[List[int]] = Field(None, description="Phase list from frontend (informational)")


class AdvancedScanRequest(BaseModel):
    """
    Advanced Scan — Phase 3.

    Only reached when pipeline_mode is "advanced". Always marks the scan complete.
    """
    hosts:         List[dict]     = Field(..., description="Host dicts from Asset Discovery")
    scan_id:       Optional[str]  = Field(None)
    pipeline_mode: Optional[str]  = Field("advanced",
                                          example="advanced",
                                          description="basic | asset | advanced")
    phases:        Optional[List[int]] = Field(None, description="Phase list from frontend (informational)")


class PhasesRequest(BaseModel):
    """Convenience endpoint — run any combination of phases in one call."""
    targets:    List[str] = Field(..., example=["192.168.1.0/24"])
    phases:     str       = Field("1", example="1+2",
                                 description="'1' | '1+2' | '1+2+3+4'")
    scan_type:  str       = Field("adaptive", example="adaptive")
    intensity:  str       = Field("normal",   example="normal")


# ── Endpoints ─────────────────────────────────────────────────────────────────

from core.tasks import (
    run_host_discovery_task,
    run_asset_discovery_task,
    run_advanced_scan_task,
    run_traditional_scan_task,
)

@router.post("/scan/host-discovery")
@limiter.limit("5/minute")
async def scan_host_discovery(
    request: Request,
    req:  HostDiscoveryRequest,
    user: User    = Depends(require_permission("scans", "execute")),
    db: Session = Depends(get_db),
):
    """
    Host Discovery: Phase 1 (Trigger and Return Immediately).
    """
    validate_total_targets(req.targets)
    raw_intensity = (req.discovery_intensity or "normal").strip().lower()
    discovery_intensity = raw_intensity if raw_intensity in ("light", "normal", "deep") else "normal"

    scan = create_scan(
        db=db,
        user_id=str(user.id),
        target=", ".join(req.targets),
        targets=req.targets,
        scan_type=req.scan_type,
        pipeline_mode=req.pipeline_mode,
    )
    scan_id = str(scan.id)
    scan_no = scan.scan_no

    # Dispatch to Celery
    task = run_host_discovery_task.delay(
        user_id             = str(user.id),
        targets             = req.targets,
        scan_type           = req.scan_type,
        pipeline_mode       = req.pipeline_mode,
        discovery_intensity = discovery_intensity,
        scan_id             = scan_id,
        rate_limit          = req.rate_limit,
        max_concurrency     = req.max_concurrency,
    )

    log.info("Host Discovery triggered — task_id=%s, scan_id=%s, wait=%s", task.id, scan_id, req.wait)

    if req.wait:
        try:
            # Synchronous wait for frontend compatibility (legacy blocking behavior)
            from celery.result import AsyncResult
            res = AsyncResult(task.id).get(timeout=300)
            if res.get("success"):
                # Reload results to return them inline
                from scans.legacy_json_builder import build_legacy_scan_results
                results = build_legacy_scan_results(db, scan_id)
                return {
                    "success": True,
                    "scan_id": scan_id,
                    "scan_no": scan_no,
                    "task_id": task.id,
                    "status": "complete",
                    "results": results
                }
        except Exception as e:
            log.warning("Wait timed out or failed for scan %s: %s", scan_id, e)

    return {
        "success": True,
        "task_id": task.id,
        "scan_id": scan_id,
        "scan_no": scan_no,
        "status": "running"
    }


@router.post("/scan/asset-discovery")
@limiter.limit("5/minute")
async def scan_asset_discovery(
    request: Request,
    req:  AssetDiscoveryRequest,
    user: User    = Depends(require_permission("scans", "execute")),
):
    """
    Asset Discovery: Phase 2 (Trigger and Return Immediately).
    """
    mode = resolve_pipeline_mode(req.pipeline_mode)
    if not is_phase_in_pipeline(mode, 2):
        raise HTTPException(status_code=400, detail=f"Asset Discovery is not part of the '{mode}' pipeline.")

    task = run_asset_discovery_task.delay(
        user_id       = str(user.id),
        hosts         = req.hosts,
        intensity     = req.intensity,
        scan_id       = req.scan_id,
        pipeline_mode = req.pipeline_mode,
    )

    return {
        "success": True,
        "task_id": task.id,
        "status": "running"
    }


@router.post("/scan/advanced-scan")
@limiter.limit("5/minute")
async def scan_advanced_scan(
    request: Request,
    req:  AdvancedScanRequest,
    user: User    = Depends(require_permission("scans", "execute")),
):
    """
    Advanced Scan: Phase 3 (Trigger and Return Immediately).
    """
    mode = resolve_pipeline_mode(req.pipeline_mode)
    if not is_phase_in_pipeline(mode, 3):
        raise HTTPException(status_code=400, detail=f"Advanced Scan is not part of the '{mode}' pipeline.")

    task = run_advanced_scan_task.delay(
        user_id       = str(user.id),
        hosts         = req.hosts,
        scan_id       = req.scan_id,
        pipeline_mode = req.pipeline_mode,
    )

    return {
        "success": True,
        "task_id": task.id,
        "status": "running"
    }


@router.post("/scan/phases")
@limiter.limit("5/minute")
async def scan_phases(
    request: Request,
    req: PhasesRequest,
    current_user: User = Depends(require_permission("scans", "execute")),
):
    """Convenience endpoint — run any combination of phases in one call (Background)."""
    validate_total_targets(req.targets)
    task = run_traditional_scan_task.delay(
        user_id=str(current_user.id),
        targets=req.targets,
        phases=req.phases,
        scan_type=req.scan_type,
        intensity=req.intensity
    )
    return {
        "success": True,
        "detail":  "Combined phase scan initiated in background.",
        "task_id": task.id,
        "status":  "running"
    }
