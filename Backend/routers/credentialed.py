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
from pathlib import Path
from typing import List, Optional

from ccure_platform.api import (
    CurrentUser,
    require_authorized,
    resolve_active_organisation,
)
from db.base import SessionLocal
from core import credential_vault
from engines.credentialed.ssh_scanner import PARAMIKO_AVAILABLE
from engines.credentialed.transport_resolver import TRANSPORT_SSH, resolve_endpoint
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from core.celery_app import registered_task
from core.rate_limiter import limiter
from core.task_names import RUN_CREDENTIALED_SCAN
from scans.scan_creation import (
    MAX_CREDENTIALED_TARGETS,
    create_credentialed_scan,
    expand_targets,
)

#: The API's logger, as scan_helpers names it, so these records are unchanged.
log = logging.getLogger("ccure.api")

router = APIRouter(tags=["Credentialed Scans"])


def _enforce_credentialed_scan_scope(
    hosts: list[str], user: CurrentUser, org_id: str | None
) -> None:
    """
    Deny hosts outside the organisation's authorised scan scope.

    Mirrors the check scan_helpers.validate_scan_targets applies to network
    scans. It lives here rather than there because this route expands its own
    targets and never calls that helper.
    """
    from core.scan_scope import ScanScopeError, enforce_org_scan_scope, org_scan_scope

    target_org_id = resolve_active_organisation(user, org_id)

    db = SessionLocal()
    try:
        try:
            enforce_org_scan_scope(hosts, org_scan_scope(db, target_org_id))
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
    #: Let the engine establish which authentication service the host offers,
    #: rather than making the operator know. ``None`` means "decide", and the
    #: decision is: discover whenever no ``port`` was stated. The UI sends no
    #: port by default, so this is the normal path -- the operator supplies a
    #: credential and the scanner works out whether to speak WinRM, SMB or SSH
    #: and on which port. Setting a port pins it, which is the escape hatch for
    #: a listener on a port nothing would guess.
    discover_transport: bool | None = Field(None)
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

    policy_id: str | None = Field(
        None,
        description=(
            "Reusable scan policy to run this audit under (GAP-12). The "
            "policy decides which benchmarks, profile, check families, "
            "severity floor and sections are assessed. Where it names a "
            "setting it wins over the same parameter in this request, and the "
            "response lists what it overrode."
        ),
    )

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


# ── Endpoint ──────────────────────────────────────────────────────────────────


@router.post("/scan/credentialed")
@limiter.limit("5/minute")
async def scan_credentialed(
    request: Request,
    response: Response,
    req: CredentialedScanRequest,
    org_id: str | None = Query(None),
    user: CurrentUser = Depends(require_authorized("audit.scan.run")),
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
            target_org_id = resolve_active_organisation(user, org_id)
            # Through the credential vault, which owns the table (G2).
            try:
                cred = credential_vault.get_for_org(
                    db, target_org_id, req.credential_id
                )
            except credential_vault.CredentialNotFound:
                raise HTTPException(
                    status_code=404,
                    detail="Stored credential not found or access denied.",
                ) from None
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
    hosts = expand_targets(req.requested_targets())
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
        target_org_id = resolve_active_organisation(user, org_id)
        created = create_credentialed_scan(
            db,
            user_id=str(user.id),
            hosts=hosts,
            org_id=target_org_id,
            policy_id=req.policy_id,
            sections=req.sections,
        )
    finally:
        db.close()
    scan_id = created.scan_id
    scan_no = created.scan_no
    eff_sections = created.sections
    policy_summary = created.policy

    task = registered_task(RUN_CREDENTIALED_SCAN).delay(
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
        # Decided here rather than in the worker, because by the time the
        # worker sees `port` it has already fallen back to the stored
        # credential's -- which is NOT NULL and defaults to 22, so it can no
        # longer tell "the operator asked for 22" from "nobody said anything".
        # That distinction is exactly what this feature turns on.
        discover_transport=(
            req.discover_transport
            if req.discover_transport is not None
            else req.port is None
        ),
        auth_method=req.auth_method,
        # The policy's section list where it names one, the request's
        # otherwise. The worker reads the rest of the configuration back from
        # the scan's own snapshot rather than from these arguments -- a
        # password already travels here and nothing else should join it.
        sections=eff_sections,
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
        # Reported at acceptance, not only in the report: an audit that
        # assessed something other than what was asked for must say so now.
        "policy": policy_summary,
    }
