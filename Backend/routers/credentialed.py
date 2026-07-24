"""
routers/credentialed.py
─────────────────────────────────────────────────────────────────────────────
SSH credentialed scan endpoint.

Endpoints
─────────
  POST /scan/credentialed → SSH-based system inspection + CVE matching
"""

import os
from pathlib import Path
from typing import List, Optional

from auth.rbac import require_permission
from db.base import SessionLocal
from db.models import ComplianceCredential, User
from engines.credentialed.ssh_scanner import PARAMIKO_AVAILABLE, SSHScanner
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, SecretStr, field_validator
from scan_helpers import limiter, log
from scans.db_helpers import create_scan

router = APIRouter(tags=["Credentialed Scans"])


# ── Request model ─────────────────────────────────────────────────────────────


class CredentialedScanRequest(BaseModel):
    ip: str = Field(..., examples=["10.180.6.140"])
    username: str | None = Field(None, examples=["root"])
    password: SecretStr | None = Field(None)
    key_path: str | None = Field(None)
    port: int = Field(22, ge=1, le=65535)
    auth_method: str = Field("password")
    sections: list[str] | None = Field(None)
    os_type: str = Field("auto", description="'linux' | 'windows' | 'auto'")
    credential_id: str | None = Field(None)

    model_config = {
        # Never include password in JSON serialisation or __repr__
        "json_schema_extra": {
            "examples": [
                {"ip": "10.180.6.140", "username": "root", "auth_method": "password"}
            ]
        },
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
        allowed_base = (
            Path(allowed_str).resolve() if allowed_str else Path.home().resolve()
        )

        if not str(p).startswith(str(allowed_base)):
            raise ValueError(
                f"key_path must be within the allowed directory ({allowed_base})"
            )

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
    req: CredentialedScanRequest,
    org_id: str | None = Query(None),
    user: User = Depends(require_permission("scans", "execute")),
):
    """
    SSH Credentialed Scan (Trigger Background Task).
    """
    if not PARAMIKO_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Credentialed scanning requires paramiko. Run: pip install paramiko==3.4.0",
        )

    # Validate based on credential input type
    target_port = req.port
    if not req.credential_id:
        if not req.username:
            raise HTTPException(
                status_code=400,
                detail="Username is required when not using stored credentials.",
            )
        if req.auth_method == "password" and not req.password:
            raise HTTPException(
                status_code=400,
                detail="Password is required for password authentication.",
            )
        if req.auth_method == "key" and not req.key_path:
            raise HTTPException(
                status_code=400, detail="Key path is required for key authentication."
            )
    else:
        # Verify stored credential exists and fetch its port
        db = SessionLocal()
        try:
            role_name = (getattr(getattr(user, "role", None), "name", "") or "").lower()
            target_org_id = (
                org_id if (role_name == "superadmin" and org_id) else str(user.org_id)
            )
            cred = (
                db.query(ComplianceCredential)
                .filter(
                    ComplianceCredential.id == req.credential_id,
                    ComplianceCredential.tenant_id == target_org_id,
                )
                .first()
            )
            if not cred:
                raise HTTPException(
                    status_code=404,
                    detail="Stored credential not found or access denied.",
                )
            target_port = cred.port
        finally:
            db.close()

    # Note: test_connectivity is fast, so we keep it in the API for immediate feedback
    if not SSHScanner.test_connectivity(req.ip, target_port, timeout=5):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot reach {req.ip}:{target_port} — host is down or port is closed.",
        )

    db = SessionLocal()
    try:
        role_name = (getattr(getattr(user, "role", None), "name", "") or "").lower()
        target_org_id = (
            org_id if (role_name == "superadmin" and org_id) else str(user.org_id)
        )
        scan = create_scan(
            db=db,
            user_id=str(user.id),
            target=req.ip,
            targets=[req.ip],
            scan_type="credentialed",
            pipeline_mode="vulnerability_audit",
            org_id=target_org_id,
        )
        scan_id = str(scan.id)
        scan_no = scan.scan_no
    finally:
        db.close()

    task = run_credentialed_scan_task.delay(
        user_id=str(user.id),
        ip=req.ip,
        username=req.username,
        password=(
            req.password.get_secret_value()
            if req.auth_method == "password" and req.password
            else None
        ),
        key_path=req.key_path if req.auth_method == "key" else None,
        port=target_port,
        auth_method=req.auth_method,
        sections=req.sections,
        os_type_req=req.os_type,
        scan_id=scan_id,
        credential_id=req.credential_id,
    )

    log.info(
        "Credentialed scan queued — target=%s scan_id=%s task_id=%s",
        req.ip,
        scan_id,
        task.id,
    )

    return {
        "success": True,
        "scan_id": scan_id,
        "scan_no": scan_no,
        "status": "running",
    }
