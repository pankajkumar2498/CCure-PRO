"""
routers/credentialed.py
─────────────────────────────────────────────────────────────────────────────
SSH credentialed scan endpoint.

Endpoints
─────────
  POST /scan/credentialed → SSH-based system inspection + CVE matching
"""

import logging
import os
import time
from pathlib import Path
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr, field_validator
from sqlalchemy.orm import Session

from db.base import get_db
from db.models import User
from auth.rbac import require_role
from scans.db_helpers import create_completed_scan
from scan_helpers import get_api, limiter, log

from engines.credentialed.ssh_scanner       import SSHScanner, PARAMIKO_AVAILABLE
from engines.credentialed.linux_collector   import LinuxCollector
from engines.credentialed.windows_collector import WindowsCollector
from engines.credentialed.vuln_matcher      import VulnMatcher

router = APIRouter(tags=["Credentialed Scans"])


# ── Request model ─────────────────────────────────────────────────────────────

class CredentialedScanRequest(BaseModel):
    ip:          str                 = Field(..., example="192.168.1.10")
    username:    str                 = Field(..., example="root")
    password:    Optional[SecretStr] = Field(None)
    key_path:    Optional[str]       = Field(None)
    port:        int                 = Field(22, ge=1, le=65535)
    auth_method: str                 = Field("password")
    sections:    Optional[List[str]] = Field(None)
    os_type:     str                 = Field("auto", description="'linux' | 'windows' | 'auto'")

    model_config = {
        # Never include password in JSON serialisation or __repr__
        "json_schema_extra": {"examples": [{"ip": "192.168.1.10", "username": "root", "auth_method": "password"}]},
    }

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


# ── OS detection ──────────────────────────────────────────────────────────────

def _detect_os(ssh) -> str:
    """
    Robust OS auto-detection via SSH.

    Runs up to 5 lightweight probes in priority order — each designed for a
    different SSH default shell (cmd.exe, PowerShell, bash/sh).  Stops as
    soon as a confident match is found.

    Returns 'windows' or 'linux'.
    """

    # ── Probe 1: cmd.exe native — ver always prints "Microsoft Windows" ──────
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


# ── Endpoint ──────────────────────────────────────────────────────────────────

from core.tasks import run_credentialed_scan_task

@router.post("/scan/credentialed")
@limiter.limit("5/minute")
async def scan_credentialed(
    request: Request,
    req:  CredentialedScanRequest,
    user: User    = Depends(require_role(["superadmin", "org_admin"])),
):
    """
    SSH Credentialed Scan (Trigger Background Task).
    """
    if not PARAMIKO_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Credentialed scanning requires paramiko. Run: pip install paramiko==3.4.0",
        )

    # Note: test_connectivity is fast, so we keep it in the API for immediate feedback
    if not SSHScanner.test_connectivity(req.ip, req.port, timeout=5):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot reach {req.ip}:{req.port} — host is down or port is closed.",
        )

    task = run_credentialed_scan_task.delay(
        user_id     = str(user.id),
        ip          = req.ip,
        username    = req.username,
        password    = req.password.get_secret_value() if req.auth_method == "password" and req.password else None,
        key_path    = req.key_path  if req.auth_method == "key"      else None,
        port        = req.port,
        auth_method = req.auth_method,
        sections    = req.sections,
        os_type_req = req.os_type,
    )

    log.info("Credentialed scan triggered — target=%s task_id=%s", req.ip, task.id)

    try:
        # Credentialed scans are very slow (15-60s)
        result = task.get(timeout=120)
        if not result.get("success"):
            raise HTTPException(status_code=400, detail=result.get("error", "Credentialed scan failed"))

        from scans.db_helpers import read_scan_full
        from db.base import SessionLocal
        db = SessionLocal()
        try:
            full_data = read_scan_full(db, result["scan_id"], str(user.id))
            # The frontend expects the 'stored_report' fields at the top level
            # Extract credentialed results from the phase3 results
            from scans.legacy_json_builder import build_legacy_scan_results
            legacy = build_legacy_scan_results(db, result["scan_id"])
            report_data = legacy.get("credentialed", {}).get("report", {})
            
            return {
                "success": True,
                "scan_id": result["scan_id"],
                **report_data
            }
        finally:
            db.close()
    except Exception as exc:
        log.error("Credentialed Scan wait failed: %s", exc)
        raise HTTPException(status_code=500, detail="Credentialed scan timed out or failed in background.")
