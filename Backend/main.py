"""
main.py
─────────────────────────────────────────────────────────────────────────────
FastAPI entry point for Ccure Audit Pro Edition v1.

ENDPOINT GROUPS:

1. HEALTH & INFO
   GET   /                         → health + system info

2. TRADITIONAL SCANS (Backward Compatible)
   POST  /scan/host                → single host (all 4 phases)
   POST  /scan/range               → IP range (discovery only)
   POST  /scan/subnet              → CIDR subnet (discovery only)
   POST  /scan/subnets             → sub-networks of a parent CIDR (discovery only)

3. PHASE-SELECTIVE SCANS (Frontend Orchestration)
   POST  /scan/host-discovery     → Host Discovery only
   POST  /scan/asset-discovery    → Asset Discovery (host + port scan)
   POST  /scan/advanced-scan      → Advanced Scan (vulnerability + risk)
   POST  /scan/phases             → Flexible phase combination

PIPELINE MODES (NEW)
─────────────────────
  Sent by the frontend as `pipeline_mode` in every request:

  "basic"    → phases: [1]          Only Phase 1 runs; scan marked complete after phase1.
  "asset"    → phases: [1, 2]       Phase 1 then Phase 2; marked complete after phase2.
  "advanced" → phases: [1, 2, 3, 4] Full pipeline; marked complete after phase3.

  The backend uses pipeline_mode to:
    - Validate that the incoming phase is part of the declared pipeline.
    - Decide `is_final` when calling update_scan_phase() — so the scan row
      is only marked "complete" when its true terminal phase is reached.
    - Store the mode on the Scan row for use in history / reports.
"""

import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Optional, List, Dict
import asyncio
import time
from threading import Lock

from fastapi import FastAPI, HTTPException, Query, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pathlib import Path
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from api.host_discovery_api import HostDiscoveryAPI
from auth.router import router as auth_router
from auth.models import create_tables, User, get_db
from auth.dependencies import get_current_user, get_current_user_flexible
from scans.router import router as scans_router
from scans.models import Scan, ensure_scan_schema
from scans.db_helpers import (
    create_scan,
    create_completed_scan,
    mark_scan_failed,
    update_scan_phase,
)
from scans.legacy_json_builder import build_legacy_scan_results
from pdf_generator import ScanReportGenerator
from engines.credentialed.ssh_scanner     import SSHScanner, PARAMIKO_AVAILABLE
from engines.credentialed.linux_collector   import LinuxCollector
from engines.credentialed.windows_collector import WindowsCollector
from engines.credentialed.vuln_matcher      import VulnMatcher

# -- Logging -------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s - %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ccure.api")

# -- Application state ---------------------------------------------------------
_api_instance: Optional[HostDiscoveryAPI] = None

# ─── Pipeline configuration (mirrors src/config/scanConfig.js) ───────────────
#
# This is the backend authority on which phases belong to each mode and
# which phase is the TERMINAL (final) phase that closes the scan record.
#
PIPELINE_PHASES: dict[str, list[int]] = {
    "basic":    [1],
    "asset":    [1, 2],
    "advanced": [1, 2, 3, 4],
}

VALID_PIPELINE_MODES = set(PIPELINE_PHASES.keys())

# ─── Real-time progress tracking ───────────────────────────────────────────
# In-memory store for scan progress (scan_id -> progress dict)
_scan_progress: dict[str, dict] = {}
_progress_lock = Lock()


def get_terminal_phase(pipeline_mode: str) -> int:
    """Return the last phase number for a given pipeline mode.
    Note: For 'advanced', the terminal phase is 3 (Vulnerability & Risk), not 4."""
    if pipeline_mode == "advanced":
        return 3
    phases = PIPELINE_PHASES.get(pipeline_mode, [1])
    return max(phases)


def is_phase_in_pipeline(pipeline_mode: str, phase: int) -> bool:
    """Return True if the given phase belongs to the declared pipeline."""
    return phase in PIPELINE_PHASES.get(pipeline_mode, [1])


def resolve_pipeline_mode(raw: Optional[str]) -> str:
    """
    Normalise and validate the pipeline_mode from a request.
    Falls back to 'basic' for unknown / missing values.
    """
    if raw and raw.lower() in VALID_PIPELINE_MODES:
        return raw.lower()
    if raw:
        log.warning("Unknown pipeline_mode '%s' — defaulting to 'basic'.", raw)
    return "basic"


def init_progress(scan_id: str, total_ips: int):
    """Initialize progress tracking for a scan."""
    with _progress_lock:
        _scan_progress[scan_id] = {
            "total_ips": total_ips,
            "discovered": 0,
            "active": 0,
            "status": "running",
            "start_time": time.time(),
        }


def update_progress(scan_id: str, discovered: int, active: int = None):
    """Update progress for a scan."""
    with _progress_lock:
        if scan_id in _scan_progress:
            _scan_progress[scan_id]["discovered"] = discovered
            if active is not None:
                _scan_progress[scan_id]["active"] = active
            _scan_progress[scan_id]["elapsed_time"] = time.time() - _scan_progress[scan_id]["start_time"]


def _safe_json_loads(text: Optional[str], default):
    try:
        return json.loads(text or "")
    except Exception:
        return default


def _normalize_scan_method(value: Optional[str]) -> Optional[str]:
    token = str(value or "").strip().upper()
    if not token:
        return None
    if "ADAPTIVE" in token:
        return "ADAPTIVE"
    if "STEALTH" in token:
        return "STEALTH"
    if "FULL" in token:
        return "FULL"
    if "ARP" in token:
        return "ARP"
    if "PING" in token or "ICMP" in token:
        return "PING"
    if "TCP" in token:
        return "TCP"
    return None


def _extract_host_ip(host: dict) -> Optional[str]:
    return host.get("ip_address") or host.get("ip")


def _target_from_hosts(hosts: List[dict]) -> Optional[str]:
    ips = []
    for host in hosts or []:
        ip = _extract_host_ip(host)
        if ip and ip not in ips:
            ips.append(ip)
    if not ips:
        return None
    return ", ".join(ips)


def _scan_method_from_hosts(hosts: List[dict]) -> Optional[str]:
    for host in hosts or []:
        method = (
            host.get("scan_method")
            or host.get("discovery_method")
            or host.get("method")
        )
        normalized = _normalize_scan_method(method)
        if normalized:
            return normalized
    return None


def _resolve_report_context(
    db: Session,
    user_id: str,
    *,
    scan_id: Optional[str] = None,
    hosts: Optional[List[dict]] = None,
    requested_targets: Optional[List[str]] = None,
    requested_scan_type: Optional[str] = None,
) -> dict:
    """
    Build report metadata with human-meaningful context:
      - target (prefer original user input)
      - scan_method/discovery_scan_method (discovery strategy)
    """
    context: dict = {}
    scan_row: Optional[Scan] = None
    summary_blob: dict = {}

    if scan_id:
        scan_row = (
            db.query(Scan)
            .filter(Scan.id == scan_id, Scan.created_by == user_id)
            .first()
        )
        if scan_row:
            summary_blob = _phase1_summary_from_scan(scan_row)

    # Target priority: request targets > scan row target/original_targets > host list
    if requested_targets:
        context["target"] = ", ".join([str(t).strip() for t in requested_targets if str(t).strip()])
        context["original_targets"] = requested_targets
    elif scan_row:
        target = (scan_row.target_str or "").strip()
        if target:
            context["target"] = target
        original_targets = summary_blob.get("original_targets") or (scan_row.target_hosts or [])
        if original_targets:
            context["original_targets"] = original_targets
            if "target" not in context:
                context["target"] = ", ".join([str(t).strip() for t in original_targets if str(t).strip()])
    elif hosts:
        host_target = _target_from_hosts(hosts)
        if host_target:
            context["target"] = host_target

    # Scan strategy priority: request scan_type > stored scan_type > host-level method
    scan_method = _normalize_scan_method(requested_scan_type)
    if not scan_method and scan_row:
        scan_method = (
            _normalize_scan_method(scan_row.scan_type)
            or _normalize_scan_method(summary_blob.get("discovery_scan_method"))
            or _normalize_scan_method(summary_blob.get("scan_method"))
            or _normalize_scan_method(summary_blob.get("scan_type"))
        )
    if not scan_method and hosts:
        scan_method = _scan_method_from_hosts(hosts)

    if scan_method:
        context["scan_method"] = scan_method
        context["discovery_scan_method"] = scan_method

    return context


def _phase1_summary_from_scan(scan_row: Scan) -> dict:
    for phase_row in getattr(scan_row, "phases", []) or []:
        if getattr(phase_row, "phase_key", "") not in ("host_discovery", "phase1"):
            continue
        summary = getattr(phase_row, "summary", {}) or {}
        if isinstance(summary, dict):
            return summary
    return {}


def _apply_phase1_summary_hints(
    result: dict,
    db: Session,
    user_id: str,
    scan_id: Optional[str],
) -> None:
    if not scan_id:
        return
    scan_row = (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.created_by == user_id)
        .first()
    )
    if not scan_row:
        return
    phase1_summary = _phase1_summary_from_scan(scan_row)
    if not phase1_summary:
        return

    summary = result.setdefault("summary", {})
    for key in ("total_hosts", "active_hosts", "inactive_hosts"):
        if phase1_summary.get(key) is not None:
            summary[key] = phase1_summary[key]

    discovery_scan_method = _normalize_scan_method(
        phase1_summary.get("discovery_scan_method")
        or phase1_summary.get("scan_type")
    )
    if discovery_scan_method:
        summary["discovery_scan_method"] = discovery_scan_method
        metadata = result.setdefault("metadata", {})
        metadata.setdefault("scan_method", discovery_scan_method)
        metadata.setdefault("discovery_scan_method", discovery_scan_method)


def finish_progress(scan_id: str):
    """Mark a scan as finished."""
    with _progress_lock:
        if scan_id in _scan_progress:
            _scan_progress[scan_id]["status"] = "complete"
            _scan_progress[scan_id]["elapsed_time"] = time.time() - _scan_progress[scan_id]["start_time"]


# ──────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _api_instance
    create_tables()
    # ensure_scan_schema()
    _api_instance = HostDiscoveryAPI(silent=False)
    log.info("HostDiscoveryAPI initialised")
    yield
    log.info("Shutting down")


app = FastAPI(
    title       = "Ccure Audit - Pro Edition",
    description = "CDAC-style network scanner.",
    version     = "1.0.0",
    lifespan    = lifespan,
)

# -- CORS Configuration --------------------------------------------------------
_default_origins = [
    "http://localhost:3000",
    "http://localhost:8080",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:5173",
]
_configured_origins = os.getenv("CORS_ALLOW_ORIGINS", "")
allow_origins = [
    origin.strip()
    for origin in (_configured_origins.split(",") if _configured_origins else _default_origins)
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

def _get_api() -> HostDiscoveryAPI:
    if _api_instance is None:
        raise HTTPException(status_code=503, detail="API not initialised yet.")
    return _api_instance


# -- Authentication routes -----------------------------------------------------
app.include_router(auth_router)

# -- Scan history routes -------------------------------------------------------
app.include_router(scans_router)


# -- Request models for TRADITIONAL scans (unchanged) --------------------------

class SingleHostRequest(BaseModel):
    target:    str = Field(..., example="192.168.1.1")
    scan_type: str = Field("adaptive", example="adaptive")

class RangeRequest(BaseModel):
    target:    str = Field(..., example="192.168.1.1-50")
    scan_type: str = Field("adaptive", example="adaptive")

class SubnetRequest(BaseModel):
    target:    str = Field(..., example="192.168.1.0/24")
    scan_type: str = Field("adaptive", example="adaptive")

class SubnetsRequest(BaseModel):
    target:        str = Field(..., example="10.0.0.0/16")
    subnet_prefix: int = Field(24, ge=1, le=30)
    scan_type:     str = Field("adaptive", example="adaptive")


# -- NEW REQUEST MODELS for PHASE-SELECTIVE scans ------------------------------

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


class CredentialedScanRequest(BaseModel):
    ip:          str            = Field(..., example="192.168.1.10")
    username:    str            = Field(..., example="root")
    password:    Optional[str]  = Field(None)
    key_path:    Optional[str]  = Field(None)
    port:        int            = Field(22, ge=1, le=65535)
    auth_method: str            = Field("password")
    sections:    Optional[List[str]] = Field(None)
    os_type:     str            = Field("auto", description="'linux' | 'windows' | 'auto'")

    @field_validator("key_path")
    @classmethod
    def validate_key_path(cls, v):
        if v is None:
            return v
        p = Path(v).resolve()
        
        # Only allow paths within a designated key directory
        # Defaults to the system user's home directory if SCAN_KEY_DIR is not set.
        allowed_str = os.getenv("SCAN_KEY_DIR")
        allowed_base = Path(allowed_str).resolve() if allowed_str else Path.home().resolve()
        
        if not str(p).startswith(str(allowed_base)):
            raise ValueError(f"key_path must be within the allowed directory ({allowed_base})")
            
        if not p.exists():
            raise ValueError("key_path does not exist")
        if not p.is_file():
            raise ValueError("key_path must be a file, not a directory")
            
        return str(p)


class PhasesRequest(BaseModel):
    """Convenience endpoint — run any combination of phases in one call."""
    targets:    List[str] = Field(..., example=["192.168.1.0/24"])
    phases:     str       = Field("1", example="1+2",
                                 description="'1' | '1+2' | '1+2+3+4'")
    scan_type:  str       = Field("adaptive", example="adaptive")
    intensity:  str       = Field("normal",   example="normal")


# -- HEALTH & INFO ENDPOINTS ---------------------------------------------------

@app.get("/", tags=["Health"])
async def root():
    return _get_api().get_system_info()


@app.get("/scan/progress/{scan_id}", tags=["Progress"])
async def get_scan_progress(
    scan_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get real-time progress for an ongoing scan.
    Returns:
      - total_ips: total IPs being scanned
      - discovered: IPs discovered so far
      - active: active IPs discovered so far
      - status: "running" or "complete"
      - elapsed_time: seconds elapsed
      - percentage: progress percentage (0-100)
    """
    with _progress_lock:
        if scan_id not in _scan_progress:
            return {"status": "not_found", "message": "Scan not found or completed"}

        progress = _scan_progress[scan_id].copy()
        total = progress.get("total_ips", 0)
        discovered = progress.get("discovered", 0)

        # Calculate percentage
        percentage = (discovered / total * 100) if total > 0 else 0
        progress["percentage"] = round(percentage, 1)

        return progress




@app.post("/scan/host", tags=["Traditional Scans"])
async def scan_host(req: SingleHostRequest, current_user: User = Depends(get_current_user)):
    result = await _get_api().scan_single_host(req.target, req.scan_type)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Scan failed"))
    return result


@app.post("/scan/range", tags=["Traditional Scans"])
async def scan_range(req: RangeRequest, current_user: User = Depends(get_current_user)):
    result = await _get_api().scan_ip_range(req.target, req.scan_type)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Scan failed"))
    return result


@app.post("/scan/subnet", tags=["Traditional Scans"])
async def scan_subnet(req: SubnetRequest, current_user: User = Depends(get_current_user)):
    result = await _get_api().scan_subnet(req.target, req.scan_type)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Scan failed"))
    return result


@app.post("/scan/subnets", tags=["Traditional Scans"])
async def scan_subnets(req: SubnetsRequest, current_user: User = Depends(get_current_user)):
    result = await _get_api().scan_subnets_of_subnet(
        req.target, req.subnet_prefix, req.scan_type
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Scan failed"))
    return result


# -- PHASE-SELECTIVE ENDPOINTS -------------------------------------------------

@app.post("/scan/host-discovery", tags=["Phase-Selective Scans"])
@limiter.limit("5/minute")
async def scan_host_discovery(
    request: Request,
    req:  HostDiscoveryRequest,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """
    Host Discovery: Phase 1.

    Always runs regardless of pipeline_mode.

    DB behaviour by pipeline_mode:
      basic    → scan is created AND immediately marked `status="complete"`.
      asset    → scan is created with `status="running"` (Asset Discovery will close it).
      advanced → scan is created with `status="running"` (Advanced Scan will close it).
    """
    mode = resolve_pipeline_mode(req.pipeline_mode)
    orch = _get_api()._orch

    # Resolve and validate discovery_intensity (asset pipeline only)
    raw_intensity = (req.discovery_intensity or "normal").strip().lower()
    discovery_intensity = raw_intensity if raw_intensity in ("light", "normal", "deep") else "normal"

    result = await orch.run_host_discovery_only(
        req.targets, req.scan_type, mode,
        discovery_intensity=discovery_intensity,
        rate_limit=req.rate_limit,
        max_concurrency=req.max_concurrency,
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Host Discovery failed"))

    result.setdefault("metadata", {}).update(
        _resolve_report_context(
            db,
            str(user.id),
            requested_targets=req.targets,
            requested_scan_type=req.scan_type,
            hosts=result.get("data", []),
        )
    )

    # ── Persist to DB ──────────────────────────────────────────────────────────
    target_str   = ", ".join(req.targets)
    terminal     = get_terminal_phase(mode)      # 1, 2, or 4 (mapped to 3 in update_scan_phase)
    host_discovery_final = (terminal == 1)               # True only for "basic"

    report_paths = {}
    if host_discovery_final:
        raw_paths = orch.generate_phase_report(result, "host_discovery")
        report_paths = {
            k: v for k, v in raw_paths.items()
            if v and os.path.isfile(v)
        }

    scan = create_scan(
        db               = db,
        user_id          = str(user.id),
        target           = target_str,
        targets          = req.targets,
        scan_type        = req.scan_type,
        pipeline_mode    = mode,                    # stored for history display
        phase1_data      = {
            "data": result["data"],
            "summary": result["summary"],
            "metadata": result.get("metadata", {}),
        },
        is_final         = host_discovery_final,            # marks complete immediately for "basic"
        report_json_path = report_paths.get("json_pdf"),
        report_xml_path  = report_paths.get("xml_pdf"),
    )

    if report_paths:
        result["reports"] = report_paths

    result["scan_id"]              = str(scan.id)
    result["pipeline_mode"]        = mode
    result["terminal_phase"]       = terminal
    if mode == "asset":
        result["discovery_intensity"] = discovery_intensity
    log.info(
        "Host Discovery complete — scan_id=%s pipeline=%s intensity=%s is_final=%s",
        scan.id, mode, discovery_intensity if mode == "asset" else "n/a", host_discovery_final,
    )
    return result


@app.post("/scan/asset-discovery", tags=["Phase-Selective Scans"])
@limiter.limit("5/minute")
async def scan_asset_discovery(
    request: Request,
    req:  AssetDiscoveryRequest,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """
    Asset Discovery: Port Scanning.

    Only valid for `pipeline_mode` = "asset" or "advanced".
    Calling Asset Discovery with `pipeline_mode` = "basic" is rejected (400).

    DB behaviour:
      asset    → is_final=True  → scan marked `status="complete"`.
      advanced → is_final=False → scan stays `status="running"` until Advanced Scan.
    """
    mode = resolve_pipeline_mode(req.pipeline_mode)

    # Guard: Asset Discovery must be part of the declared pipeline
    if not is_phase_in_pipeline(mode, 2):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Asset Discovery is not part of the '{mode}' pipeline "
                f"(phases: {PIPELINE_PHASES[mode]}). "
                "Did you select the wrong scan template?"
            ),
        )

    orch     = _get_api()._orch
    terminal = get_terminal_phase(mode)
    is_final = (terminal == 2)                   # True for "asset", False for "advanced"

    try:
        result = await orch.run_asset_discovery_only(req.hosts, req.intensity, pipeline_mode=mode)
        if not result.get("success"):
            raise HTTPException(status_code=400, detail=result.get("error", "Asset Discovery failed"))

        result.setdefault("metadata", {}).update(
            _resolve_report_context(
                db,
                str(user.id),
                scan_id=req.scan_id,
                hosts=req.hosts,
            )
        )
        _apply_phase1_summary_hints(result, db, str(user.id), req.scan_id)

        report_paths = {}
        if is_final:
            raw_paths = orch.generate_phase_report(result, "asset_discovery")
            report_paths = {
                k: v for k, v in raw_paths.items()
                if v and os.path.isfile(v)
            }

        updated = None
        if req.scan_id:
            updated = update_scan_phase(
                db               = db,
                scan_id          = req.scan_id,
                user_id          = str(user.id),
                phase            = 2,
                phase_data       = {
                    "data": result["data"],
                    "summary": result["summary"],
                    "metadata": result.get("metadata", {}),
                },
                is_final         = is_final,
                pipeline_mode    = mode,
                report_json_path = report_paths.get("json_pdf"),
                report_xml_path  = report_paths.get("xml_pdf"),
            )
            if not updated:
                raise HTTPException(status_code=404, detail="Scan not found.")
            result["scan_id"] = str(req.scan_id)

        if report_paths:
            result["reports"] = report_paths

        result["pipeline_mode"]  = mode
        result["terminal_phase"] = terminal
        log.info(
            "Asset Discovery complete — scan_id=%s pipeline=%s is_final=%s",
            req.scan_id, mode, is_final,
        )
        return result

    except HTTPException:
        if req.scan_id:
            mark_scan_failed(db, req.scan_id, str(user.id), "Asset Discovery failed.")
        raise
    except Exception as exc:
        if req.scan_id:
            mark_scan_failed(db, req.scan_id, str(user.id), str(exc))
        log.exception("Asset Discovery error — user=%s scan_id=%s", user.id, req.scan_id)
        raise HTTPException(status_code=500, detail="Asset Discovery scan failed.")


@app.post("/scan/advanced-scan", tags=["Phase-Selective Scans"])
@limiter.limit("5/minute")
async def scan_advanced_scan(
    request: Request,
    req:  AdvancedScanRequest,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """
    Advanced Scan: Vulnerability Audit + Risk Scoring.

    Only valid for `pipeline_mode` = "advanced".
    Calling Advanced Scan with "basic" or "asset" is rejected (400).

    Always marks the scan `status="complete"` and generates PDF reports.
    """
    mode = resolve_pipeline_mode(req.pipeline_mode)

    if not is_phase_in_pipeline(mode, 3):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Advanced Scan is not part of the '{mode}' pipeline "
                f"(phases: {PIPELINE_PHASES[mode]}). "
                "Use the 'Advanced Scan' template to run vulnerability audits."
            ),
        )

    orch = _get_api()._orch

    try:
        import asyncio
        result = await asyncio.to_thread(orch.run_advanced_scan_only, req.hosts)
        if not result.get("success"):
            raise HTTPException(status_code=400, detail=result.get("error", "Advanced Scan failed"))

        result.setdefault("metadata", {}).update(
            _resolve_report_context(
                db,
                str(user.id),
                scan_id=req.scan_id,
                hosts=req.hosts,
            )
        )
        _apply_phase1_summary_hints(result, db, str(user.id), req.scan_id)

        report_paths = orch.generate_phase_report(result, "phase_selective_scan")
        report_paths = {
            k: v for k, v in report_paths.items()
            if v and os.path.isfile(v)
        }

        if req.scan_id:
            updated = update_scan_phase(
                db               = db,
                scan_id          = req.scan_id,
                user_id          = str(user.id),
                phase            = 3,
                phase_data       = {
                    "data": result["data"],
                    "summary": result["summary"],
                    "metadata": result.get("metadata", {}),
                },
                is_final         = True,          # Advanced Scan always closes the scan
                pipeline_mode    = mode,
                report_json_path = report_paths.get("json_pdf"),
                report_xml_path  = report_paths.get("xml_pdf"),
            )
            if not updated:
                raise HTTPException(status_code=404, detail="Scan not found.")
            result["scan_id"] = req.scan_id

        if report_paths:
            result["reports"] = report_paths

        result["pipeline_mode"]  = mode
        result["terminal_phase"] = get_terminal_phase(mode)
        log.info(
            "Advanced Scan complete — scan_id=%s pipeline=%s (scan closed)",
            req.scan_id, mode,
        )
        return result

    except HTTPException:
        if req.scan_id:
            mark_scan_failed(db, req.scan_id, str(user.id), "Advanced Scan failed.")
        raise
    except Exception as exc:
        if req.scan_id:
            mark_scan_failed(db, req.scan_id, str(user.id), str(exc))
        log.exception("Advanced Scan error — user=%s scan_id=%s", user.id, req.scan_id)
        raise HTTPException(status_code=500, detail="Advanced Scan failed.")


def _detect_os(ssh) -> str:
    """
    Robust OS auto-detection via SSH.

    Runs up to 5 lightweight probes in priority order — each designed for a
    different SSH default shell (cmd.exe, PowerShell, bash/sh).  Stops as
    soon as a confident match is found.

    Returns 'windows' or 'linux'.
    """

    # ── Probe 1: cmd.exe native — ver always prints "Microsoft Windows" ──────
    # Works even when cmd.exe is the SSH default shell.
    r = ssh.run("ver", timeout=4)
    out = r.stdout.strip()
    log.debug("[OS-detect] ver → %s", out[:80])
    if r.success and "microsoft windows" in out.lower():
        return "windows"

    # ── Probe 2: cmd /c ver — same as above but explicit cmd ─────────────────
    r = ssh.run("cmd /c ver", timeout=4)
    out = r.stdout.strip()
    log.debug("[OS-detect] cmd /c ver → %s", out[:80])
    if r.success and "microsoft windows" in out.lower():
        return "windows"

    # ── Probe 3: PowerShell $env:OS — Windows_NT on all Windows machines ─────
    # Works when PowerShell is the default shell.
    r = ssh.run("$env:OS", timeout=4)
    out = r.stdout.strip()
    log.debug("[OS-detect] $env:OS → %s", out[:80])
    if r.success and "windows" in out.lower():
        return "windows"

    # ── Probe 4: uname exact match — only real Linux/macOS returns this ───────
    r = ssh.run("uname -s", timeout=4)
    out = r.stdout.strip().upper()
    log.debug("[OS-detect] uname -s → %s", out[:80])
    if r.success and out in {"LINUX", "DARWIN", "FREEBSD", "OPENBSD", "NETBSD"}:
        return "linux"
    # Git Bash on Windows returns MINGW64_NT-10.0-... / MSYS_NT-... (contains "NT")
    # If we got something with "NT" it's likely Windows under Git Bash
    if r.success and "NT" in out and "LINUX" not in out:
        return "windows"

    # ── Probe 5: PowerShell [Environment]::OSVersion — works on PS 5+ ────────
    r = ssh.run("[Environment]::OSVersion.Platform", timeout=4)
    out = r.stdout.strip()
    log.debug("[OS-detect] OSVersion.Platform → %s", out[:80])
    if r.success and "win" in out.lower():
        return "windows"

    # ── Safe fallback ─────────────────────────────────────────────────────────
    log.warning("[OS-detect] All probes inconclusive — defaulting to 'linux'")
    return "linux"


@app.post("/scan/credentialed", tags=["Credentialed Scans"])
@limiter.limit("5/minute")
async def scan_credentialed(
    request: Request,
    req:  CredentialedScanRequest,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """
    SSH Credentialed Scan (Linux targets).
    Credentials are NEVER stored — used for SSH session only, then discarded.
    """
    import time

    if not PARAMIKO_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Credentialed scanning requires paramiko. Run: pip install paramiko==3.4.0",
        )

    start_time = time.time()

    if not SSHScanner.test_connectivity(req.ip, req.port, timeout=5):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot reach {req.ip}:{req.port} — host is down or port is closed.",
        )

    try:
        with SSHScanner(
            ip        = req.ip,
            username  = req.username,
            password  = req.password if req.auth_method == "password" else None,
            key_path  = req.key_path  if req.auth_method == "key"      else None,
            port      = req.port,
            timeout   = 20,
        ) as ssh:
            # ── OS Auto-detection ───────────────────────────────────────────
            os_type = (req.os_type or "auto").strip().lower()
            if os_type == "auto":
                os_type = _detect_os(ssh)
            log.info("Credentialed scan OS detected as '%s' for %s", os_type, req.ip)

            if os_type == "windows":
                collector = WindowsCollector(ssh)
            else:
                collector = LinuxCollector(ssh)

            system_data = collector.collect_all(sections=req.sections)
            system_data["detected_os"] = os_type
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        log.exception("Credentialed scan error on %s", req.ip)
        raise HTTPException(status_code=500, detail=f"Scan error: {exc}")

    packages     = system_data.get("packages", [])
    matcher      = VulnMatcher()
    raw_findings = matcher.match_packages(packages)
    cve_list     = matcher.to_report_format(raw_findings)

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for cve in cve_list:
        sev = cve.get("severity", "Info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    scan_duration = round(time.time() - start_time, 2)

    stored_report = {
        "scan_type":              "credentialed",
        "target":                 req.ip,
        "detected_os":            system_data.get("detected_os", "linux"),
        "system_info": {
            "os_name":        system_data.get("os_name", ""),
            "os_version_id":  system_data.get("os_version_id", ""),
            "kernel_version": system_data.get("kernel_version", ""),
            "hostname":       system_data.get("hostname_fqdn", ""),
            "uptime":         system_data.get("uptime", ""),
            "cpu_model":      system_data.get("cpu_model", ""),
            "cpu_count":      system_data.get("cpu_count", ""),
            "cpu_arch":       system_data.get("cpu_arch", ""),
            "memory_summary": system_data.get("memory_summary", {}),
            "disk_usage":     system_data.get("disk_usage", []),
        },
        "packages":                packages,
        "package_count":           len(packages),
        "running_services":        system_data.get("running_services", []),
        "open_ports_credentialed": system_data.get("open_ports_credentialed", []),
        "users":                   system_data.get("users", []),
        "suid_binaries":           system_data.get("suid_binaries", []),
        "world_writable_dirs":     system_data.get("world_writable_dirs", []),
        "sudo_nopasswd":           system_data.get("sudo_nopasswd", False),
        "sudo_rules_raw":          system_data.get("sudo_rules_raw", ""),
        "cron_info_raw":           system_data.get("cron_info_raw", ""),
        "security_issues":         system_data.get("security_issues", []),
        "failed_login_count":      system_data.get("failed_login_count", 0),
        "brute_force_warning":     system_data.get("brute_force_warning", False),
        "failed_logins_recent":    system_data.get("failed_logins_recent", []),
        "network_interfaces_raw":  system_data.get("network_interfaces_raw", ""),
        "env_vars_flagged":        system_data.get("env_vars_summary", []),
        "cves":                    cve_list,
        "cve_count":               len(cve_list),
        "severity_summary":        severity_counts,
        "scan_duration":           scan_duration,
    }

    report_result = {
        "success": True,
        "data":    {"credentialed": {"report": stored_report}},
        "summary": {
            "scan_type":      "credentialed",
            "active_hosts":   1,
            "package_count":  len(packages),
            "cve_count":      len(cve_list),
            "critical_count": severity_counts["Critical"],
            "high_count":     severity_counts["High"],
            "medium_count":   severity_counts["Medium"],
            "low_count":      severity_counts["Low"],
            "info_count":     severity_counts["Info"],
            "scan_duration":  scan_duration,
        },
        "metadata": {"target": req.ip, "scan_type": "credentialed"},
    }
    report_paths = _get_api()._orch.generate_phase_report(report_result, "credentialed_scan")

    scan = create_completed_scan(
        db               = db,
        user_id          = user.id,
        target           = req.ip,
        targets          = [req.ip],
        scan_type        = "credentialed",
        phase            = 3,
        results          = {"credentialed": {"report": stored_report}},
        summary          = report_result["summary"],
        scan_duration    = scan_duration,
        report_json_path = report_paths.get("json_pdf"),
        report_xml_path  = report_paths.get("xml_pdf"),
    )

    return {
        "success":  True,
        "scan_id":  scan.id,
        "username": req.username,
        **stored_report,
    }


@app.post("/scan/phases", tags=["Phase-Selective Scans"])
@limiter.limit("5/minute")
async def scan_phases(request: Request, req: PhasesRequest, current_user: User = Depends(get_current_user)):
    """Convenience endpoint — run any combination of phases in one call."""
    orch   = _get_api()._orch
    result = await orch.run_phases(req.targets, req.phases, req.scan_type, req.intensity)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Scan failed"))
    return result


# -- REPORTS DOWNLOAD ----------------------------------------------------------

_REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")


def _load_scan_report_paths(db: Session, scan: Scan) -> dict:
    """Generate report PDFs from stored scan phase payloads when no file path exists."""
    if not scan.phases:
        return {}

    payloads = build_legacy_scan_results(db, str(scan.id))

    # Prefer the most complete phase available.
    for key in ("credentialed", "phase3", "phase2", "phase1"):
        if key in payloads and isinstance(payloads[key], dict):
            payload = payloads[key]
            break
    else:
        return {}

    if not payload.get("data"):
        return {}

    payload_data = payload.get("data", [])
    payload_meta = payload.get("metadata", {}) if isinstance(payload.get("metadata"), dict) else {}
    context_meta = _resolve_report_context(
        db,
        str(scan.created_by),
        scan_id=scan.id,
        hosts=payload_data if isinstance(payload_data, list) else [],
    )

    result = {
        "success": True,
        "data":    payload_data,
        "summary": payload.get("summary", {}),
        "metadata": {"scan_id": scan.id, **payload_meta, **context_meta},
    }
    _apply_phase1_summary_hints(result, db, str(scan.created_by), scan.id)

    report_paths = ScanReportGenerator(output_dir=_REPORTS_DIR).generate(result, key)
    report_paths = {k: v for k, v in report_paths.items() if v and os.path.isfile(v)}
    if report_paths:
        if report_paths.get("json_pdf"):
            scan.report_json_path = report_paths["json_pdf"]
        if report_paths.get("xml_pdf"):
            scan.report_xml_path = report_paths["xml_pdf"]
        db.commit()
        db.refresh(scan)

    return report_paths


@app.get("/reports/download/{scan_id}", tags=["Reports"])
def download_report(
    scan_id: str,
    fmt:     str            = "JSON",
    token:   Optional[str]  = Query(None),
    db:      Session        = Depends(get_db),
    user:    User           = Depends(get_current_user_flexible),
):
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.created_by == user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    fmt_upper = fmt.upper()
    if fmt_upper not in ("JSON", "XML"):
        raise HTTPException(status_code=400, detail="fmt must be 'JSON' or 'XML'.")

    pdf_path = scan.report_json_path if fmt_upper == "JSON" else scan.report_xml_path
    if not pdf_path or not os.path.isfile(os.path.abspath(pdf_path)):
        report_paths = _load_scan_report_paths(db, scan)
        pdf_path = report_paths.get("json_pdf" if fmt_upper == "JSON" else "xml_pdf")

    if not pdf_path:
        raise HTTPException(
            status_code=404,
            detail=f"No {fmt_upper} PDF report is attached to this scan.",
        )

    pdf_path = os.path.abspath(pdf_path)
    reports_root = os.path.abspath(_REPORTS_DIR)
    if not os.path.isfile(pdf_path):
        raise HTTPException(status_code=404, detail="Report file not found on disk.")
    if os.path.commonpath([reports_root, pdf_path]) != reports_root:
        raise HTTPException(status_code=400, detail="Stored report path is invalid.")

    return FileResponse(
        path       = pdf_path,
        media_type = "application/pdf",
        filename   = os.path.basename(pdf_path),
    )


# -- DOCUMENTATION -------------------------------------------------------------

@app.get("/api/pipeline-modes", tags=["Documentation"])
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


@app.get("/api/workflow-example", tags=["Documentation"])
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
