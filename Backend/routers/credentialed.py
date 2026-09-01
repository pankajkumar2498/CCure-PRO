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
from engines.credentialed.ssh_scanner import PARAMIKO_AVAILABLE
from engines.credentialed.transport_resolver import TRANSPORT_SSH, resolve_endpoint
from orchestrator.scan_orchestrator import ScanOrchestrator
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from scan_helpers import limiter, log
from scans.db_helpers import create_scan

router = APIRouter(tags=["Credentialed Scans"])


def _enforce_credentialed_scan_scope(
    hosts: list[str], user: User, org_id: str | None
) -> None:
    """
    Deny hosts outside the organisation's authorised scan scope.

    Mirrors the check scan_helpers.validate_scan_targets applies to network
    scans. It lives here rather than there because this route expands its own
    targets and never calls that helper.
    """
    from core.scan_scope import ScanScopeError, enforce_org_scan_scope
    from db.models import Organization

    role_name = (getattr(getattr(user, "role", None), "name", "") or "").lower()
    target_org_id = (
        org_id if (role_name == "superadmin" and org_id) else str(user.org_id)
    )

    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.id == target_org_id).first()
        try:
            enforce_org_scan_scope(hosts, org)
        except ScanScopeError as exc:
            raise HTTPException(status_code=403, detail=exc.message) from exc
    finally:
        db.close()


# ── Request model ─────────────────────────────────────────────────────────────


class CredentialedScanRequest(BaseModel):
    # `ip` remains the single-target field every existing client sends.
    # `targets` accepts several, including ranges and CIDRs, so one audit can
    # cover a set of hosts under one scan record instead of one scan each.
    ip: str | None = Field(None, examples=["10.180.6.140"])
    targets: list[str] | None = Field(
        None, examples=[["10.180.6.140", "10.180.6.150-160"]]
    )
    username: str | None = Field(None, examples=["root"])
    password: SecretStr | None = Field(None)
    key_path: str | None = Field(None)
    #: ``None`` means "whatever this credential says", not 22. The default used
    #: to be 22, which is indistinguishable from an operator asking for 22 — so
    #: a stored credential's port had to overwrite it unconditionally and there
    #: was no way to run one credential against a host whose listener had moved.
    port: int | None = Field(None, ge=1, le=65535)
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

    @model_validator(mode="after")
    def require_a_target(self):
        if not self.ip and not (self.targets and any(t.strip() for t in self.targets)):
            raise ValueError("Provide 'ip' or a non-empty 'targets' list.")
        return self

    def requested_targets(self) -> list[str]:
        """Raw target expressions, de-duplicated, order preserved."""
        raw = list(self.targets or [])
        if self.ip:
            raw.insert(0, self.ip)
        seen: list[str] = []
        for item in raw:
            token = (item or "").strip()
            if token and token not in seen:
                seen.append(token)
        return seen

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

from core.tasks import MAX_CREDENTIALED_TARGETS, run_credentialed_scan_task


@router.post("/scan/credentialed")
@limiter.limit("5/minute")
async def scan_credentialed(
    request: Request,
    response: Response,
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
    target_transport = TRANSPORT_SSH
    credential_use_tls = None
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
            # An explicit port on the request wins. Previously the stored
            # credential's port overwrote it unconditionally, so the field was
            # dead whenever a credential was named and an operator could not
            # point one credential at a host whose listener had moved.
            target_port = req.port or cred.port
            target_transport = cred.transport or TRANSPORT_SSH
            credential_use_tls = (cred.options or {}).get("use_tls")
        finally:
            db.close()

    # Expand ranges and CIDRs into the hosts that will actually be authenticated
    # to. Doing it here rather than in the worker means an unusable target set
    # is rejected while the operator is still looking at the form.
    hosts = ScanOrchestrator._expand_targets(req.requested_targets())
    if not hosts:
        raise HTTPException(
            status_code=400,
            detail="No valid targets to scan. Check the address, range, or CIDR.",
        )

    # A credentialed audit authenticates to each host, so an out-of-scope
    # target here is worse than an out-of-scope port scan: it would present
    # this organisation's stored credentials to a machine it does not own.
    _enforce_credentialed_scan_scope(hosts, user, org_id)
    if len(hosts) > MAX_CREDENTIALED_TARGETS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"{len(hosts)} hosts requested — a credentialed audit authenticates "
                f"to each one in turn and is limited to {MAX_CREDENTIALED_TARGETS} "
                f"per scan. Narrow the range or split it across scans."
            ),
        )

    # test_connectivity is fast, so it stays in the API for immediate feedback.
    # With one target an unreachable host means the scan has nothing to do, so
    # it is rejected outright — the behaviour operators already rely on. With
    # several, one dead host must not block the rest; those are recorded as
    # failed hosts in the report instead.
    if len(hosts) == 1:
        # Resolved rather than probed on one fixed port. A bare
        # ``test_connectivity`` on the credential's stated port rejected the
        # scan here — before the worker, which now resolves the endpoint, ever
        # ran — so a host whose listener had moved could not be scanned at all
        # however good the resolution downstream was. This probes the same
        # candidates the worker will, and only refuses when none answers.
        preflight = resolve_endpoint(
            ip=hosts[0],
            transport=target_transport,
            stated_port=target_port,
            use_tls=credential_use_tls,
            include_fallbacks=True,
            timeout=5,
        )
        if not preflight.resolved:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Cannot reach {hosts[0]} — host is down or no "
                    f"{target_transport.upper()} port is open. "
                    f"{preflight.reason}"
                ),
            )

    target_str = ", ".join(hosts)

    db = SessionLocal()
    try:
        role_name = (getattr(getattr(user, "role", None), "name", "") or "").lower()
        target_org_id = (
            org_id if (role_name == "superadmin" and org_id) else str(user.org_id)
        )
        scan = create_scan(
            db=db,
            user_id=str(user.id),
            target=target_str,
            targets=hosts,
            scan_type="credentialed",
            # This audit runs no discovery and no port scan. Recording it as a
            # vulnerability_audit claimed three phases that never executed.
            pipeline_mode="credentialed",
            org_id=target_org_id,
        )
        scan_id = str(scan.id)
        scan_no = scan.scan_no
    finally:
        db.close()

    task = run_credentialed_scan_task.delay(
        user_id=str(user.id),
        targets=hosts,
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
        "Credentialed scan queued — hosts=%d target=%s scan_id=%s task_id=%s",
        len(hosts),
        target_str,
        scan_id,
        task.id,
    )

    return {
        "success": True,
        "scan_id": scan_id,
        "scan_no": scan_no,
        "status": "running",
        "targets": hosts,
        "hosts_queued": len(hosts),
    }
