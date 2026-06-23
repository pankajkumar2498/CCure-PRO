"""
routers/phase_scans.py
─────────────────────────────────────────────────────────────────────────────
Phase-selective scan endpoints (frontend-orchestrated pipeline).

Endpoints
─────────
  POST /scan/host-discovery   → Phase 1: Host Discovery
  POST /scan/asset-discovery  → Phase 2: Port Scanning & Service Detection
    POST /scan/vulnerability-audit    → Phase 3: Vulnerability Audit & Risk Scoring
"""

import asyncio
import logging
import os
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Request, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from db.base import get_db
from db.models import User, Scan
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
from core.quota import check_scan_quota, get_quota_status
from core.tasks import (
    run_host_discovery_task,
    run_asset_discovery_task,
    run_vulnerability_audit_task,
    run_traditional_scan_task,
)

router = APIRouter(tags=["Phase-Selective Scans"])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_superadmin(user: User) -> bool:
    return (getattr(getattr(user, "role", None), "name", "") or "").lower() == "superadmin"


def _resolve_org(user: User, requested_org: Optional[str]) -> str:
    if _is_superadmin(user) and requested_org:
        return requested_org
    return str(user.org_id)


# ── Quota status endpoint ─────────────────────────────────────────────────────

@router.get("/scan/quota")
def get_scan_quota(
    org_id: Optional[str] = Query(None),
    db:   Session = Depends(get_db),
    user: User    = Depends(require_permission("scans", "read")),
):
    """
    Return the organisation's current scan quota status.

    Response::

        {
          "plan": "community",
          "scans_used_24h": 3,
          "scans_limit_24h": 5,
          "concurrent_running": 1,
          "concurrent_limit": 1,
          "max_ips_per_scan": 254,
          "max_subnet_prefix": 24,
          "quota_exceeded": false,
          "concurrent_exceeded": false
        }
    """
    resolved_org = _resolve_org(user, org_id)
    return get_quota_status(db, org_id=resolved_org)




# ── Request models ────────────────────────────────────────────────────────────

class HostDiscoveryRequest(BaseModel):
    """
    Host Discovery — Phase 1.

    `pipeline_mode` tells the backend which pipeline this scan belongs to:
      "basic"              → only Host Discovery will run; scan is immediately marked complete.
      "asset"              → Host Discovery then Asset Discovery; scan stays 'running' after host discovery.
      "vulnerability_audit" → Full pipeline; scan stays 'running' until vulnerability audit.

    `phases` is the authoritative list from the frontend (informational / audit).

    `discovery_intensity` controls Asset Discovery Phase 1 strategy (asset pipeline only):
      "light"  → FAST profile only — fastest, may miss firewalled/restricted hosts.
      "normal" → FAST first, BALANCED fallback only for still-inactive IPs (default).
      "deep"   → Full BALANCED — maximum coverage, slower.
    Ignored for basic and vulnerability_audit pipelines.
    """
    targets:             List[str]      = Field(..., examples=[["10.180.6.0/24"]])
    scan_type:           str            = Field("adaptive", examples=["adaptive"])
    pipeline_mode:       Optional[str]  = Field("basic",
                                                examples=["basic"],
                                                description="basic | asset | vulnerability_audit")
    phases:              Optional[List[int]] = Field(None,
                                                     examples=[[1, 2]],
                                                     description="Phase list from frontend (informational)")
    discovery_intensity: Optional[str]  = Field("normal",
                                                examples=["normal"],
                                                description="light | normal | deep (asset pipeline only)")
    port_scan_intensity: Optional[str]  = Field("normal",
                                                examples=["normal"],
                                                description="light | normal | deep — intensity for Phase 2 port scan (asset pipeline only)")
    os_detection:        bool           = Field(True, description="Enable Nmap -O OS fingerprinting in Phase 2 (passed through auto-chained task)")
    execution_mode:      Optional[str]  = Field("automatic", description="automatic | interactive")
    rate_limit:          Optional[float] = Field(None, description="Optional rate limit for probes per second (PPS).")
    max_concurrency:     Optional[int]   = Field(None, description="Max concurrent threads (e.g. TCP connect probes).")
    wait:                bool            = Field(False, description="If true, wait for task completion (up to 300s) before returning.")
    custom_ports:        Optional[str]   = Field(None, description="Custom ports/ranges to scan (e.g. '22,80,443')")
    exclude_ports:       Optional[str]   = Field(None, description="Ports/ranges to exclude from scan (e.g. '2375,6443')")
    options:             Optional[dict]  = Field(None, description="Additional scan configurations including SNMP credentials for topology mapping")


class AssetDiscoveryRequest(BaseModel):
    """
    Asset Discovery — Phase 2.

    Must include the same `pipeline_mode` used in the Host Discovery request so the
    backend can decide whether this is the terminal phase (asset) or not (vulnerability_audit).
    """
    hosts:         List[dict]     = Field(..., description="Host dicts from Host Discovery")
    intensity:     str            = Field("normal", examples=["normal"])
    scan_id:       Optional[str]  = Field(None)
    pipeline_mode: Optional[str]  = Field("asset",
                                          examples=["asset"],
                                          description="basic | asset | vulnerability_audit")
    os_detection:  bool           = Field(True, description="Enable Nmap -O OS fingerprinting during port scan")
    phases:        Optional[List[int]] = Field(None, description="Phase list from frontend (informational)")
    custom_ports:  Optional[str]  = Field(None, description="Custom ports/ranges to scan (e.g. '22,80,443')")
    exclude_ports: Optional[str]  = Field(None, description="Ports/ranges to exclude from scan (e.g. '2375,6443')")


class VulnerabilityAuditRequest(BaseModel):
    """
    Vulnerability Audit — Phase 3.

    Only reached when pipeline_mode is "vulnerability_audit". Always marks the scan complete.
    """
    hosts:         List[dict]     = Field(..., description="Host dicts from Asset Discovery")
    scan_id:       Optional[str]  = Field(None)
    pipeline_mode: Optional[str]  = Field("vulnerability_audit",
                                          examples=["vulnerability_audit"],
                                          description="basic | asset | vulnerability_audit")
    vulnerability_profile: Optional[str] = Field("recommended",
                                                 examples=["recommended"],
                                                 description="recommended | conservative | deep")
    phases:        Optional[List[int]] = Field(None, description="Phase list from frontend (informational)")


class PhasesRequest(BaseModel):
    """Convenience endpoint — run any combination of phases in one call."""
    targets:    List[str] = Field(..., examples=[["10.180.6.0/24"]])
    phases:     str       = Field("1", examples=["1+2"],
                                 description="'1' | '1+2' | '1+2+3+4'")
    scan_type:  str       = Field("adaptive", examples=["adaptive"])
    intensity:  str       = Field("normal",   examples=["normal"])


# ── Endpoints ─────────────────────────────────────────────────────────────────

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

    Quota enforcement runs BEFORE the scan row is created, so rejected
    requests never produce orphaned DB rows.
    """
    # Normalise intensities
    raw_disc_intensity = (req.discovery_intensity or "normal").strip().lower()
    discovery_intensity = raw_disc_intensity if raw_disc_intensity in ("light", "normal", "deep") else "normal"
    raw_port_intensity = (req.port_scan_intensity or "normal").strip().lower()
    port_scan_intensity = raw_port_intensity if raw_port_intensity in ("light", "normal", "deep") else "normal"

    # ── Quota gate — raises HTTP 400/429 if over limit ────────────────────────
    check_scan_quota(db, org_id=str(user.org_id), targets=req.targets, custom_ports=req.custom_ports)

    scan = create_scan(
        db=db,
        user_id=str(user.id),
        target=", ".join(req.targets),
        targets=req.targets,
        scan_type=req.scan_type,
        pipeline_mode=req.pipeline_mode,
    )
    scan.options = {
        **(scan.options or {}),
        "execution_mode": req.execution_mode or "automatic",
        **({"custom_ports": req.custom_ports} if req.custom_ports else {}),
        **({"exclude_ports": req.exclude_ports} if req.exclude_ports else {}),
        **(req.options or {}),
    }
    db.commit()
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
        os_detection        = req.os_detection,
        port_scan_intensity = port_scan_intensity,
        custom_ports        = req.custom_ports,
        exclude_ports       = req.exclude_ports,
    )

    # Store the task ID so it can be revoked if needed
    scan.current_task_id = task.id
    db.commit()

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
    db: Session = Depends(get_db),
):
    """
    Asset Discovery: Phase 2 (Trigger and Return Immediately).
    """
    mode = resolve_pipeline_mode(req.pipeline_mode)
    if not is_phase_in_pipeline(mode, 2):
        raise HTTPException(status_code=400, detail=f"Asset Discovery is not part of the '{mode}' pipeline.")

    # SaaS Stability: Prevent duplicate phase triggers if the backend is already chaining
    scan = db.query(Scan).filter(Scan.id == req.scan_id).first()
    if scan and scan.status == "running" and scan.current_task_id:
        log.info("Phase 2 already in progress (chained) for scan %s, skipping redundant trigger.", req.scan_id)
        return {
            "success": True,
            "task_id": scan.current_task_id,
            "status": "running"
        }

    # ── Quota gate for custom ports (Phase 2 manually triggered) ──────────────
    if req.custom_ports:
        check_scan_quota(db, org_id=str(user.org_id), custom_ports=req.custom_ports)

    task = run_asset_discovery_task.delay(
        user_id       = str(user.id),
        hosts         = req.hosts,
        intensity     = req.intensity,
        scan_id       = req.scan_id,
        pipeline_mode = req.pipeline_mode,
        os_detection  = req.os_detection,
        custom_ports  = req.custom_ports,
        exclude_ports = req.exclude_ports,
    )

    # Track active task for termination
    if req.scan_id and scan:
        options = dict(scan.options or {})
        if req.custom_ports:
            options["custom_ports"] = req.custom_ports
        if req.exclude_ports:
            options["exclude_ports"] = req.exclude_ports
        scan.current_task_id = task.id
        scan.status = "running"
        scan.options = options
        db.commit()

    return {
        "success": True,
        "task_id": task.id,
        "status": "running"
    }


@router.post("/scan/vulnerability-audit")
@limiter.limit("5/minute")
async def scan_vulnerability_audit(
    request: Request,
    req:  VulnerabilityAuditRequest,
    user: User    = Depends(require_permission("scans", "execute")),
    db: Session = Depends(get_db),
):
    """
    Vulnerability Audit: Phase 3 (Trigger and Return Immediately).
    """
    mode = resolve_pipeline_mode(req.pipeline_mode)
    if not is_phase_in_pipeline(mode, 3):
        raise HTTPException(status_code=400, detail=f"Vulnerability Audit is not part of the '{mode}' pipeline.")

    # SaaS Stability: Prevent duplicate phase triggers if the backend is already chaining
    scan = db.query(Scan).filter(Scan.id == req.scan_id).first()
    if scan and scan.status == "running" and scan.current_task_id:
        log.info("Phase 3 already in progress (chained) for scan %s, skipping redundant trigger.", req.scan_id)
        return {
            "success": True,
            "task_id": scan.current_task_id,
            "status": "running"
        }

    task = run_vulnerability_audit_task.delay(
        user_id       = str(user.id),
        hosts         = req.hosts,
        scan_id       = req.scan_id,
        pipeline_mode = req.pipeline_mode,
    )

    # Track active task for termination
    if req.scan_id:
        db.query(Scan).filter(Scan.id == req.scan_id).update({
            "current_task_id": task.id,
            "status": "running"
        })
        db.commit()

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
