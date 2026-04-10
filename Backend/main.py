"""
main.py
-----------------
FastAPI entry point for Ccure Audit Pro Edition v2.

UPDATED WITH: Phase-selective endpoints for frontend-driven orchestration (Option 1).

Run::

    pip install fastapi uvicorn reportlab
    uvicorn main:app --reload

ENDPOINT GROUPS:

1. HEALTH & INFO
   GET   /                         -> health + system info

2. TRADITIONAL SCANS (Backward Compatible)
   POST  /scan/host                -> single host (all 4 phases)
   POST  /scan/range               -> IP range (discovery only)
   POST  /scan/subnet              -> CIDR subnet (discovery only)
   POST  /scan/subnets             -> sub-networks of a parent CIDR (discovery only)

3. NEW: PHASE-SELECTIVE SCANS (Frontend Orchestration)
   POST  /scan/phase1              -> Phase 1 only (discovery)
   POST  /scan/phase2              -> Phase 2 only (port scan)
   POST  /scan/phase3              -> Phase 3+4 (vulnerability + risk)
   POST  /scan/phases              -> Flexible phase combination
"""

import glob
import logging
import os
from contextlib import asynccontextmanager
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.host_discovery_api import HostDiscoveryAPI
from auth.router import router as auth_router
from auth.models import create_tables, User, get_db
from auth.dependencies import get_current_user
from scans.router import router as scans_router
from scans.models import Scan
from scans.db_helpers import create_scan, create_completed_scan, update_scan_phase
from engines.credentialed.ssh_scanner     import SSHScanner, PARAMIKO_AVAILABLE
from engines.credentialed.linux_collector import LinuxCollector
from engines.credentialed.vuln_matcher    import VulnMatcher
# -- Logging -------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s - %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ccure.api")

# -- Application state ---------------------------------------------------------
_api_instance: Optional[HostDiscoveryAPI] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _api_instance
    create_tables()                          # ← create users table if not exists
    _api_instance = HostDiscoveryAPI(silent=False)
    log.info("HostDiscoveryAPI initialised")
    yield
    log.info("Shutting down")


app = FastAPI(
    title       = "Ccure Audit - Pro Edition (Phase-Selective)",
    description = "CDAC-style network scanner with phase-selective scanning for frontend orchestration.",
    version     = "2.1.0",
    lifespan    = lifespan,
)

# -- CORS Configuration --------------------------------------------------------
# IMPORTANT: Update these for your frontend URL
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",      # React dev server
        "http://localhost:8080",      # Vue dev server
        "http://localhost:5173",      # Vite dev server
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:5173",
        # Add your production domain here
        # "https://yourdomain.com",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    target:    str   = Field(..., example="192.168.1.1",  description="IP, hostname, or CIDR")
    scan_type: str   = Field("adaptive", example="adaptive",
                             description="ping | arp | tcp | full | adaptive | stealth")

class RangeRequest(BaseModel):
    target:    str   = Field(..., example="192.168.1.1-50", description="IP range")
    scan_type: str   = Field("adaptive", example="adaptive")

class SubnetRequest(BaseModel):
    target:    str   = Field(..., example="192.168.1.0/24", description="CIDR notation")
    scan_type: str   = Field("adaptive", example="adaptive")

class SubnetsRequest(BaseModel):
    target:        str = Field(..., example="10.0.0.0/16",   description="Parent CIDR")
    subnet_prefix: int = Field(24,  example=24, ge=1, le=30, description="Sub-network prefix length")
    scan_type:     str = Field("adaptive", example="adaptive")


# -- NEW REQUEST MODELS for PHASE-SELECTIVE scans ------------------------------

class Phase1Request(BaseModel):
    """
    Request model for Phase 1 (Discovery only).
    
    Example::
    
        {
            "targets": ["192.168.1.0/24", "10.0.0.1-50"],
            "scan_type": "adaptive"
        }
    """
    targets:    List[str] = Field(..., 
                                  example=["192.168.1.0/24", "192.168.1.10"],
                                  description="List of IPs, ranges, or subnets")
    scan_type:  str       = Field("adaptive", example="adaptive",
                                  description="ping | arp | tcp | full | adaptive | stealth")


class Phase2Request(BaseModel):
    """
    Request model for Phase 2 (Port Scanning only).
    
    This takes output from Phase 1 and runs port scanning on those hosts.
    
    Example::
    
        {
            "hosts": [
                {
                    "ip": "192.168.1.10",
                    "is_active": true,
                    "mac": "aa:bb:cc:dd:ee:ff",
                    ...
                },
                ...
            ],
            "intensity": "normal",
            "scan_id": 1
        }
    """
    hosts:      List[dict] = Field(...,
                                   description="Host data from Phase 1 output")
    intensity:  str        = Field("normal", example="normal",
                                  description="light | normal | deep")
    scan_id:    Optional[int] = Field(None, description="Scan DB id from Phase 1 (optional)")


class Phase3Request(BaseModel):
    """
    Request model for Phase 3 (Vulnerability + Risk Scoring).
    
    This takes output from Phase 2 and runs vulnerability scanning.
    
    Example::
    
        {
            "hosts": [
                {
                    "ip": "192.168.1.10",
                    "is_active": true,
                    "open_ports": [
                        {"port": 22, "service": "ssh"},
                        {"port": 80, "service": "http"}
                    ],
                    ...
                },
                ...
            ],
            "scan_id": 1
        }
    """
    hosts:   List[dict] = Field(...,
                             description="Host data from Phase 2 output")
    scan_id: Optional[int] = Field(None, description="Scan DB id from Phase 1 (optional)")


class CredentialedScanRequest(BaseModel):
    ip:          str            = Field(...,  example="192.168.1.10",  description="Target IP or hostname")
    username:    str            = Field(...,  example="root",           description="SSH username")
    password:    Optional[str]  = Field(None, example="mysecretpass",  description="SSH password (discarded after use)")
    key_path:    Optional[str]  = Field(None, description="Path to SSH private key")
    port:        int            = Field(22,   ge=1, le=65535,          description="SSH port")
    auth_method: str            = Field("password", description="'password' or 'key'")
    sections:    Optional[List[str]] = Field(None, description="Data categories to collect. None = all")
    

class PhasesRequest(BaseModel):
    """
    Request model for flexible phase selection.
    
    Allows running any combination of phases in sequence.
    
    Examples::
    
        {"targets": ["192.168.1.0/24"], "phases": "1"}           # Discovery only
        {"targets": ["192.168.1.0/24"], "phases": "1+2"}         # Discovery + Ports
        {"targets": ["192.168.1.0/24"], "phases": "1+2+3+4"}     # Full scan
    """
    targets:    List[str] = Field(...,
                                  example=["192.168.1.0/24"],
                                  description="List of IPs, ranges, or subnets")
    phases:     str       = Field("1", example="1+2",
                                 description="'1' | '1+2' | '1+2+3+4' | etc.")
    scan_type:  str       = Field("adaptive", example="adaptive",
                                 description="ping | arp | tcp | full | adaptive | stealth")
    intensity:  str       = Field("normal", example="normal",
                                 description="light | normal | deep (for phases 2+)")


# -- HEALTH & INFO ENDPOINTS ---------------------------------------------------

@app.get("/", tags=["Health"])
async def root():
    """
    Health check + system capabilities.
    
    Returns information about the scanner, supported scan types, intensities, etc.
    """
    return _get_api().get_system_info()


# -- TRADITIONAL SCAN ENDPOINTS (Backward Compatible) --------------------------

@app.post("/scan/host", tags=["Traditional Scans"])
async def scan_host(req: SingleHostRequest, current_user: User = Depends(get_current_user)):
    """
    Scan a single host with ALL 4 phases.
    
    ⚠️  Note: This runs the full pipeline. For selective scanning, use phase-specific endpoints.
    
    Example request::
    
        POST /scan/host
        {
            "target": "192.168.1.10",
            "scan_type": "adaptive"
        }
    """
    result = await _get_api().scan_single_host(req.target, req.scan_type)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Scan failed"))
    return result


@app.post("/scan/range", tags=["Traditional Scans"])
async def scan_range(req: RangeRequest, current_user: User = Depends(get_current_user)):
    """
    Scan an IP range (e.g., 192.168.1.1-50).
    
    Runs Phase 1 (discovery) only.
    
    Example request::
    
        POST /scan/range
        {
            "target": "192.168.1.1-50",
            "scan_type": "adaptive"
        }
    """
    result = await _get_api().scan_ip_range(req.target, req.scan_type)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Scan failed"))
    return result


@app.post("/scan/subnet", tags=["Traditional Scans"])
async def scan_subnet(req: SubnetRequest, current_user: User = Depends(get_current_user)):
    """
    Scan all hosts in a CIDR subnet.
    
    Runs Phase 1 (discovery) only.
    
    Example request::
    
        POST /scan/subnet
        {
            "target": "192.168.1.0/24",
            "scan_type": "adaptive"
        }
    """
    result = await _get_api().scan_subnet(req.target, req.scan_type)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Scan failed"))
    return result


@app.post("/scan/subnets", tags=["Traditional Scans"])
async def scan_subnets(req: SubnetsRequest, current_user: User = Depends(get_current_user)):
    """
    Scan sub-networks within a parent CIDR, grouped by subnet.
    
    Example request::
    
        POST /scan/subnets
        {
            "target": "10.0.0.0/16",
            "subnet_prefix": 24,
            "scan_type": "adaptive"
        }
    """
    result = await _get_api().scan_subnets_of_subnet(
        req.target, req.subnet_prefix, req.scan_type
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Scan failed"))
    return result


# -- NEW PHASE-SELECTIVE ENDPOINTS (Frontend Orchestration) --------------------

@app.post("/scan/phase1", tags=["Phase-Selective Scans"])
async def scan_phase1(
    req:  Phase1Request,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """Phase 1: host discovery. Saves result to DB and returns scan_id."""
    orch   = _get_api()._orch
    result = await orch.run_phase1_only(req.targets, req.scan_type)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Scan failed"))

    # ── Persist to DB ──────────────────────────────────────────────────────
    target_str = ", ".join(req.targets)
    scan = create_scan(
        db        = db,
        user_id   = user.id,
        target    = target_str,
        scan_type = req.scan_type,
        phase1_data = {"data": result["data"], "summary": result["summary"]},
    )
    result["scan_id"] = scan.id          # ← frontend stores this
    return result


@app.post("/scan/phase2", tags=["Phase-Selective Scans"])
async def scan_phase2(
    req:  Phase2Request,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """Phase 2: port scan. Updates DB scan record if scan_id provided."""
    orch   = _get_api()._orch
    result = orch.run_phase2_only(req.hosts, req.intensity)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Scan failed"))

    # ── Update DB ──────────────────────────────────────────────────────────
    if req.scan_id:
        update_scan_phase(
            db         = db,
            scan_id    = req.scan_id,
            user_id    = user.id,
            phase      = 2,
            phase_data = {"data": result["data"], "summary": result["summary"]},
            is_final   = False,
        )
        result["scan_id"] = req.scan_id
    return result


@app.post("/scan/phase3", tags=["Phase-Selective Scans"])
async def scan_phase3(
    req:  Phase3Request,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """Phase 3+4: vulnerability audit. Marks scan complete in DB."""
    orch   = _get_api()._orch
    result = orch.run_phase3_only(req.hosts)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Scan failed"))

    # ── Update DB — mark complete ──────────────────────────────────────────
    if req.scan_id:
        update_scan_phase(
            db         = db,
            scan_id    = req.scan_id,
            user_id    = user.id,
            phase      = 3,
            phase_data = {"data": result["data"], "summary": result["summary"]},
            is_final   = True,
        )
        result["scan_id"] = req.scan_id
    return result

@app.post("/scan/credentialed", tags=["Credentialed Scans"])
async def scan_credentialed(
    req:  CredentialedScanRequest,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """
    🔐 Credentialed SSH Scan (Linux targets).
    Logs into target via SSH, collects full system info, matches packages to CVEs.
    Credentials are NEVER stored — used for SSH session only, then discarded (Option A).
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
            timeout   = 15,
        ) as ssh:
            collector   = LinuxCollector(ssh)
            system_data = collector.collect_all(sections=req.sections)
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

    scan = create_completed_scan(
        db            = db,
        user_id       = user.id,
        target        = req.ip,
        scan_type     = "credentialed",
        phase         = 3,
        results       = {"credentialed": {"report": stored_report}},
        summary       = {
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
        scan_duration = scan_duration,
    )

    return {
        "success":  True,
        "scan_id":  scan.id,
        "username": req.username,
        **stored_report,
    }


@app.post("/scan/phases", tags=["Phase-Selective Scans"])
async def scan_phases(req: PhasesRequest, current_user: User = Depends(get_current_user)):
    """
    🚀 FLEXIBLE PHASE SELECTION: Run any combination of phases.
    
    This is a convenience endpoint that orchestrates multiple phases in sequence.
    
    **Phases parameter**:
    - "1" → Phase 1 only (discovery)
    - "1+2" → Phase 1 + 2 (discovery + ports)
    - "1+2+3+4" → Full scan (all phases, same as /scan/host)
    - "2" → Will run phase 1 first (prerequisite)
    
    Example request (Discovery only)::
    
        POST /scan/phases
        {
            "targets": ["192.168.1.0/24"],
            "phases": "1",
            "scan_type": "adaptive"
        }
    
    Example request (Discovery + Port scan)::
    
        POST /scan/phases
        {
            "targets": ["192.168.1.0/24"],
            "phases": "1+2",
            "scan_type": "adaptive",
            "intensity": "normal"
        }
    
    Example request (Full scan)::
    
        POST /scan/phases
        {
            "targets": ["192.168.1.0/24"],
            "phases": "1+2+3+4",
            "scan_type": "adaptive",
            "intensity": "deep"
        }
    
    Response structure is same as individual phase endpoints.
    """
    orch = _get_api()._orch
    result = await orch.run_phases(req.targets, req.phases, req.scan_type, req.intensity)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Scan failed"))
    return result


# -- REPORTS DOWNLOAD ENDPOINT ------------------------------------------------

# Resolve the reports directory relative to this file so it works regardless
# of where uvicorn is launched from.
_REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")


@app.get("/reports/download/{scan_id}", tags=["Reports"])
def download_report(
    scan_id: int,
    fmt: str = "JSON",          # "JSON" or "XML"
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """
    Download the PDF report for a completed scan.

    - **scan_id**: the scan DB id returned by /scan/phase1 (stored in frontend as `scanId`)
    - **fmt**: `JSON` (default) — tabular report, or `XML` — raw XML data report

    The endpoint verifies that the scan belongs to the requesting user,
    then serves the most recently generated matching PDF from `reports/`.
    """
    # Ownership check — 404 hides existence from other users
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    fmt_upper = fmt.upper()
    if fmt_upper not in ("JSON", "XML"):
        raise HTTPException(status_code=400, detail="fmt must be 'JSON' or 'XML'.")

    # Find the most recently modified PDF that matches the format suffix
    pattern = os.path.join(_REPORTS_DIR, f"*_{fmt_upper}.pdf")
    matches = sorted(
        glob.glob(pattern),
        key=os.path.getmtime,
        reverse=True,
    )

    if not matches:
        raise HTTPException(
            status_code=404,
            detail=f"No {fmt_upper} PDF report found yet. Complete a scan first.",
        )

    pdf_path = matches[0]
    filename = os.path.basename(pdf_path)
    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=filename,
    )


# -- DOCUMENTATION ENDPOINT ---------------------------------------------------

@app.get("/api/workflow-example", tags=["Documentation"])
async def workflow_example():
    """
    Example workflow for phase-selective scanning.
    
    This shows how a frontend should orchestrate the phases for optimal UX.
    """
    return {
        "workflow": "Frontend-Driven Phase Orchestration",
        "steps": [
            {
                "step": 1,
                "endpoint": "POST /scan/phase1",
                "purpose": "Discover all active hosts in subnet",
                "payload": {
                    "targets": ["192.168.1.0/24"],
                    "scan_type": "adaptive"
                },
                "time": "~30-45 seconds for /24",
                "output": "List of 254 hosts (active + inactive)",
            },
            {
                "step": 2,
                "endpoint": "POST /scan/phase2",
                "purpose": "User selects 5 hosts and requests port scan",
                "payload": {
                    "hosts": "<!-- 5 hosts from step 1 output -->",
                    "intensity": "normal"
                },
                "time": "~5-15 seconds",
                "output": "Port info on 5 hosts",
            },
            {
                "step": 3,
                "endpoint": "POST /scan/phase3",
                "purpose": "User clicks 'Deep Audit' on critical host",
                "payload": {
                    "hosts": "<!-- 1 host from step 2 output -->"
                },
                "time": "~30-60 seconds",
                "output": "Full vulnerability report + risk scores",
            },
        ],
        "total_time": "~75-120 seconds",
        "note": "Compare to naive approach: running full scan on all 254 hosts = 20+ hours",
        "benefit": "User gets progressive results, controls scope, much faster",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
