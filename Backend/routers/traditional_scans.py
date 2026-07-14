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

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from db.models import User
from auth.rbac import require_permission
from scan_helpers import limiter, log

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

from core.tasks import run_traditional_scan_task


@router.post("/scan/host")
@limiter.limit("5/minute")
async def scan_host(
    request: Request,
    req: SingleHostRequest,
    current_user: User = Depends(require_permission("scans", "execute")),
):
    task = run_traditional_scan_task.delay(
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
    req: RangeRequest,
    current_user: User = Depends(require_permission("scans", "execute")),
):
    task = run_traditional_scan_task.delay(
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
    req: SubnetRequest,
    current_user: User = Depends(require_permission("scans", "execute")),
):
    task = run_traditional_scan_task.delay(
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
    req: SubnetsRequest,
    current_user: User = Depends(require_permission("scans", "execute")),
):
    # Note: run_phases doesn't natively handle subnet_prefix expansion in the same way,
    # but for compatibility we trigger it as Phase 1.
    task = run_traditional_scan_task.delay(
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
