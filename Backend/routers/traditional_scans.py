"""
routers/traditional_scans.py
─────────────────────────────────────────────────────────────────────────────
Backward-compatible traditional scan endpoints.

Endpoints
─────────
  POST /scan/host      → single host (all 4 phases)
  POST /scan/range     → IP range (discovery only)
  POST /scan/subnet    → CIDR subnet (discovery only)
  POST /scan/subnets   → sub-networks of a parent CIDR (discovery only)
"""

from ccure_platform.api import CurrentUser, require_authorized
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from core.rate_limiter import limiter
from scan_helpers import log

router = APIRouter(tags=["Traditional Scans"])


# ── Request models ────────────────────────────────────────────────────────────


class SingleHostRequest(BaseModel):
    target: str = Field(..., examples=["10.180.6.14"])
    scan_type: str = Field("adaptive", examples=["adaptive"])


class RangeRequest(BaseModel):
    target: str = Field(..., examples=["10.180.6.14-50"])
    scan_type: str = Field("adaptive", examples=["adaptive"])


class SubnetRequest(BaseModel):
    target: str = Field(..., examples=["10.180.6.0/24"])
    scan_type: str = Field("adaptive", examples=["adaptive"])


class SubnetsRequest(BaseModel):
    target: str = Field(..., examples=["10.0.0.0/16"])
    subnet_prefix: int = Field(24, ge=1, le=30)
    scan_type: str = Field("adaptive", examples=["adaptive"])


# ── Endpoints ─────────────────────────────────────────────────────────────────

# Dispatched by registered name (G1): importing a task module from a router
# loaded the whole scan pipeline into every process that serves HTTP.
from core.celery_app import registered_task
from core.task_names import RUN_TRADITIONAL_SCAN


@router.post("/scan/host")
@limiter.limit("5/minute")
async def scan_host(
    request: Request,
    response: Response,
    req: SingleHostRequest,
    current_user: CurrentUser = Depends(require_authorized("audit.scan.run")),
):
    task = registered_task(RUN_TRADITIONAL_SCAN).delay(
        user_id=str(current_user.id),
        targets=[req.target],
        phases="1+2+3+4",
        scan_type=req.scan_type,
        intensity="normal",
    )
    try:
        result = task.get(timeout=180)
        return result
    except Exception:
        log.error("Traditional scan failed", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while processing the host scan request. Please contact support.",
        )


@router.post("/scan/range")
@limiter.limit("5/minute")
async def scan_range(
    request: Request,
    response: Response,
    req: RangeRequest,
    current_user: CurrentUser = Depends(require_authorized("audit.scan.run")),
):
    task = registered_task(RUN_TRADITIONAL_SCAN).delay(
        user_id=str(current_user.id),
        targets=[req.target],
        phases="1",
        scan_type=req.scan_type,
        intensity="normal",
    )
    try:
        result = task.get(timeout=120)
        return result
    except Exception:
        log.error("Range scan failed", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while processing the range scan request. Please contact support.",
        )


@router.post("/scan/subnet")
@limiter.limit("5/minute")
async def scan_subnet(
    request: Request,
    response: Response,
    req: SubnetRequest,
    current_user: CurrentUser = Depends(require_authorized("audit.scan.run")),
):
    task = registered_task(RUN_TRADITIONAL_SCAN).delay(
        user_id=str(current_user.id),
        targets=[req.target],
        phases="1",
        scan_type=req.scan_type,
        intensity="normal",
    )
    try:
        result = task.get(timeout=120)
        return result
    except Exception:
        log.error("Subnet scan failed", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while processing the subnet scan request. Please contact support.",
        )


@router.post("/scan/subnets")
@limiter.limit("5/minute")
async def scan_subnets(
    request: Request,
    response: Response,
    req: SubnetsRequest,
    current_user: CurrentUser = Depends(require_authorized("audit.scan.run")),
):
    # Note: run_phases doesn't natively handle subnet_prefix expansion in the same way,
    # but for compatibility we trigger it as Phase 1.
    task = registered_task(RUN_TRADITIONAL_SCAN).delay(
        user_id=str(current_user.id),
        targets=[req.target],
        phases="1",
        scan_type=req.scan_type,
        intensity="normal",
    )
    try:
        result = task.get(timeout=120)
        return result
    except Exception:
        log.error("Subnets scan failed", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while processing the subnets scan request. Please contact support.",
        )
