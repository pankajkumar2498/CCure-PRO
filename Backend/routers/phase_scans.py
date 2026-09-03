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

from typing import List, Optional

from auth.rbac import require_permission
from core.quota import check_scan_quota, get_quota_status
from core.tasks import (
    run_asset_discovery_task,
    run_host_discovery_task,
    run_traditional_scan_task,
    run_vulnerability_audit_task,
)
from db.base import get_db
from db.models import Scan, User
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, field_validator
from scan_helpers import (
    VALID_PIPELINE_MODES,
    is_phase_in_pipeline,
    limiter,
    log,
    resolve_pipeline_mode,
    validate_scan_targets,
)
from scans.db_helpers import (
    create_scan,
)
from scans.policy_binding import (
    reapply_policy_snapshot as _reapply_policy_snapshot,
    resolve_scan_policy as _resolve_scan_policy,
)
from sqlalchemy.orm import Session

router = APIRouter(tags=["Phase-Selective Scans"])


# ── Helpers ───────────────────────────────────────────────────────────────────


def _is_superadmin(user: User) -> bool:
    return (
        getattr(getattr(user, "role", None), "name", "") or ""
    ).lower() == "superadmin"


def _resolve_org(user: User, requested_org: str | None) -> str:
    if _is_superadmin(user) and requested_org:
        return requested_org
    return str(user.org_id)


def _org_row(db: Session, org_id: str):
    """
    Load the Organization that a scan's authorisation scope is read from.

    Returns None if the row is missing, which core.scan_scope treats as "no
    scope configured" — the same as a NULL scope, so a dangling org_id cannot
    become a way to scan without a scope under REQUIRE_SCAN_SCOPE.
    """
    from db.models import Organization

    return db.query(Organization).filter(Organization.id == org_id).first()


# ── Quota status endpoint ─────────────────────────────────────────────────────


@router.get("/scan/quota")
def get_scan_quota(
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("scans", "read")),
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


def _validate_pipeline_mode(value: str | None) -> str | None:
    """
    Reject an unknown pipeline_mode instead of silently running something else.

    The resolver downstream falls back to 'basic' for anything it does not
    recognise, which meant a typo returned HTTP 200, created a scan row holding
    the bogus value verbatim, and surfaced it in Scan History as the scan's
    type. A caller that asks for a pipeline that does not exist should be told.
    """
    if value is None:
        return value
    token = str(value).strip().lower()
    if not token:
        return None
    if token not in VALID_PIPELINE_MODES:
        allowed = ", ".join(sorted(VALID_PIPELINE_MODES))
        raise ValueError(
            f"Unknown pipeline_mode '{value}'. Expected one of: {allowed}."
        )
    return token


def _validate_intensity(value: str | None) -> str | None:
    """Reject an unknown intensity rather than quietly substituting 'normal'."""
    if value is None:
        return value
    token = str(value).strip().lower()
    if not token:
        return None
    allowed = ("light", "normal", "deep", "custom")
    if token not in allowed:
        raise ValueError(
            f"Unknown intensity '{value}'. Expected one of: {', '.join(allowed)}."
        )
    return token


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

    targets: list[str] = Field(..., examples=[["10.180.6.0/24"]])
    scan_type: str = Field("adaptive", examples=["adaptive"])
    pipeline_mode: str | None = Field(
        "basic", examples=["basic"], description="basic | asset | vulnerability_audit"
    )
    phases: list[int] | None = Field(
        None, examples=[[1, 2]], description="Phase list from frontend (informational)"
    )
    discovery_intensity: str | None = Field(
        "normal",
        examples=["normal"],
        description="light | normal | deep (asset pipeline only)",
    )
    port_scan_intensity: str | None = Field(
        "normal",
        examples=["normal"],
        description="light | normal | deep — intensity for Phase 2 port scan (asset pipeline only)",
    )
    os_detection: bool = Field(
        True,
        description="Enable Nmap -O OS fingerprinting in Phase 2 (passed through auto-chained task)",
    )
    execution_mode: str | None = Field(
        "automatic", description="automatic | interactive"
    )
    rate_limit: float | None = Field(
        None, description="Optional rate limit for probes per second (PPS)."
    )
    max_concurrency: int | None = Field(
        None, description="Max concurrent threads (e.g. TCP connect probes)."
    )
    wait: bool = Field(
        False,
        description="If true, wait for task completion (up to 300s) before returning.",
    )
    custom_ports: str | None = Field(
        None, description="Custom ports/ranges to scan (e.g. '22,80,443')"
    )
    exclude_ports: str | None = Field(
        None, description="Ports/ranges to exclude from scan (e.g. '2375,6443')"
    )
    options: dict | None = Field(
        None,
        description="Additional scan configurations including SNMP credentials for topology mapping",
    )
    passive_first: bool | None = Field(
        None, description="Bypass active scan on hosts already resolved passively"
    )
    exclude_ot_from_nmap: bool | None = Field(
        None, description="Exclude OT ports from Nmap scanning"
    )
    exclude_ips: str | None = Field(
        None, description="IPs/subnets to exclude from this scan"
    )
    policy_id: str | None = Field(
        None,
        description=(
            "Reusable scan policy to run this scan under (GAP-12). Where the "
            "policy names a setting it wins over the same parameter in this "
            "request, and the response lists what it overrode. Omitting it "
            "preserves the pre-policy behaviour exactly."
        ),
    )

    _check_mode = field_validator("pipeline_mode")(_validate_pipeline_mode)
    _check_intensity = field_validator("discovery_intensity", "port_scan_intensity")(
        _validate_intensity
    )


class AssetDiscoveryRequest(BaseModel):
    """
    Asset Discovery — Phase 2.

    Must include the same `pipeline_mode` used in the Host Discovery request so the
    backend can decide whether this is the terminal phase (asset) or not (vulnerability_audit).
    """

    hosts: list[dict] = Field(..., description="Host dicts from Host Discovery")
    intensity: str = Field("normal", examples=["normal"])
    scan_id: str | None = Field(None)
    pipeline_mode: str | None = Field(
        "asset", examples=["asset"], description="basic | asset | vulnerability_audit"
    )
    os_detection: bool = Field(
        True, description="Enable Nmap -O OS fingerprinting during port scan"
    )
    phases: list[int] | None = Field(
        None, description="Phase list from frontend (informational)"
    )
    custom_ports: str | None = Field(
        None, description="Custom ports/ranges to scan (e.g. '22,80,443')"
    )
    exclude_ports: str | None = Field(
        None, description="Ports/ranges to exclude from scan (e.g. '2375,6443')"
    )
    exclude_ot_from_nmap: bool | None = Field(
        None, description="Exclude OT ports from Nmap scanning"
    )
    exclude_ips: str | None = Field(
        None, description="IPs/subnets to exclude from this scan"
    )
    passive_first: bool | None = Field(
        None, description="Bypass active scan on hosts already resolved passively"
    )

    _check_mode = field_validator("pipeline_mode")(_validate_pipeline_mode)
    _check_intensity = field_validator("intensity")(_validate_intensity)


class VulnerabilityAuditRequest(BaseModel):
    """
    Vulnerability Audit — Phase 3.

    Only reached when pipeline_mode is "vulnerability_audit". Always marks the scan complete.
    """

    hosts: list[dict] = Field(..., description="Host dicts from Asset Discovery")
    scan_id: str | None = Field(None)
    pipeline_mode: str | None = Field(
        "vulnerability_audit",
        examples=["vulnerability_audit"],
        description="basic | asset | vulnerability_audit",
    )
    vulnerability_profile: str | None = Field(
        "recommended",
        examples=["recommended"],
        description="recommended | conservative | deep",
    )
    phases: list[int] | None = Field(
        None, description="Phase list from frontend (informational)"
    )
    exclude_ot_from_nmap: bool | None = Field(
        None, description="Exclude OT ports from Nmap scanning"
    )
    exclude_ips: str | None = Field(
        None, description="IPs/subnets to exclude from this scan"
    )

    _check_mode = field_validator("pipeline_mode")(_validate_pipeline_mode)


class PhasesRequest(BaseModel):
    """Convenience endpoint — run any combination of phases in one call."""

    targets: list[str] = Field(..., examples=[["10.180.6.0/24"]])
    phases: str = Field("1", examples=["1+2"], description="'1' | '1+2' | '1+2+3+4'")
    scan_type: str = Field("adaptive", examples=["adaptive"])
    intensity: str = Field("normal", examples=["normal"])
    passive_first: bool | None = Field(None)
    exclude_ot_from_nmap: bool | None = Field(None)
    exclude_ips: str | None = Field(None)

    _check_intensity = field_validator("intensity")(_validate_intensity)


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("/scan/host-discovery")
@limiter.limit("5/minute")
async def scan_host_discovery(
    request: Request,
    response: Response,
    req: HostDiscoveryRequest,
    org_id: str | None = Query(None),
    user: User = Depends(require_permission("scans", "execute")),
    db: Session = Depends(get_db),
):
    """
    Host Discovery: Phase 1 (Trigger and Return Immediately).

    Quota enforcement runs BEFORE the scan row is created, so rejected
    requests never produce orphaned DB rows.
    """
    # Normalise intensities
    raw_disc_intensity = (req.discovery_intensity or "normal").strip().lower()
    discovery_intensity = (
        raw_disc_intensity
        if raw_disc_intensity in ("light", "normal", "deep")
        else "normal"
    )
    raw_port_intensity = (req.port_scan_intensity or "normal").strip().lower()
    port_scan_intensity = (
        raw_port_intensity
        if raw_port_intensity in ("light", "normal", "deep")
        else "normal"
    )

    resolved_org = _resolve_org(user, org_id)

    # ── Target gate — reject unusable input before it costs quota, and
    #    unauthorised targets before anything touches the network ─────────────
    targets = validate_scan_targets(req.targets, org=_org_row(db, resolved_org))

    # ── Quota gate — raises HTTP 400/429 if over limit ────────────────────────
    check_scan_quota(
        db, org_id=resolved_org, targets=targets, custom_ports=req.custom_ports
    )

    scan = create_scan(
        db=db,
        user_id=str(user.id),
        target=", ".join(targets),
        targets=targets,
        scan_type=req.scan_type,
        pipeline_mode=req.pipeline_mode,
        org_id=resolved_org,
    )
    # -- Policy gate (GAP-12) ------------------------------------------------
    # Resolved *after* the scan row exists so the snapshot lands in the same
    # commit as the row it describes, and *before* dispatch so the worker can
    # never read a scan whose configuration has not been settled.
    #
    # A policy that cannot be used raises rather than falling back. The scan
    # row is deleted first: a queued scan that never dispatched is a ghost in
    # Scan History, and the quota it consumed has not been spent.
    effective, policy_overrides = _resolve_scan_policy(
        db,
        scan=scan,
        policy_id=req.policy_id,
        org_id=resolved_org,
        scan_kind="network",
        has_credential=bool((req.options or {}).get("credentials")),
        request_options={
            "custom_ports": req.custom_ports,
            "exclude_ports": req.exclude_ports,
            "discovery_intensity": discovery_intensity,
            "port_scan_intensity": port_scan_intensity,
            "os_detection": req.os_detection,
            "exclude_ips": req.exclude_ips,
        },
    )

    # The policy is authoritative for every setting it names. Reading them back
    # from the resolved configuration -- rather than from `req` -- is what makes
    # the recorded snapshot and the arguments the task receives the same thing.
    eff_custom_ports = effective.custom_ports
    eff_exclude_ports = effective.exclude_ports
    eff_discovery = effective.discovery_intensity or discovery_intensity
    eff_port_intensity = effective.port_scan_intensity or port_scan_intensity
    eff_os_detection = (
        req.os_detection if effective.os_detection is None else effective.os_detection
    )
    eff_exclude_ips = (
        ",".join(effective.excluded_targets)
        if effective.excluded_targets
        else req.exclude_ips
    )

    scan.options = {
        **(scan.options or {}),
        "execution_mode": req.execution_mode or "automatic",
        **({"custom_ports": eff_custom_ports} if eff_custom_ports else {}),
        **({"exclude_ports": eff_exclude_ports} if eff_exclude_ports else {}),
        **(
            {"passive_first": req.passive_first}
            if req.passive_first is not None
            else {}
        ),
        **(
            {"exclude_ot_from_nmap": req.exclude_ot_from_nmap}
            if req.exclude_ot_from_nmap is not None
            else {}
        ),
        **({"exclude_ips": eff_exclude_ips} if eff_exclude_ips else {}),
        **(req.options or {}),
    }
    # Re-applied because the dict literal above rebuilds `options` wholesale and
    # would otherwise drop the snapshot written into it a moment ago.
    _reapply_policy_snapshot(scan, effective)
    db.commit()
    scan_id = str(scan.id)
    scan_no = scan.scan_no

    # Dispatch to Celery
    task = run_host_discovery_task.delay(
        user_id=str(user.id),
        targets=targets,
        scan_type=req.scan_type,
        pipeline_mode=req.pipeline_mode,
        discovery_intensity=eff_discovery,
        scan_id=scan_id,
        rate_limit=req.rate_limit,
        max_concurrency=req.max_concurrency,
        os_detection=eff_os_detection,
        port_scan_intensity=eff_port_intensity,
        custom_ports=eff_custom_ports,
        exclude_ports=eff_exclude_ports,
        passive_first=req.passive_first,
        exclude_ot_from_nmap=req.exclude_ot_from_nmap,
        exclude_ips=eff_exclude_ips,
    )

    # Store the task ID so it can be revoked if needed
    scan.current_task_id = task.id
    db.commit()

    log.info(
        "Host Discovery triggered — task_id=%s, scan_id=%s, wait=%s",
        task.id,
        scan_id,
        req.wait,
    )

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
                    "results": results,
                }
        except Exception as e:
            log.warning("Wait timed out or failed for scan %s: %s", scan_id, e)

    return {
        "success": True,
        "task_id": task.id,
        "scan_id": scan_id,
        "scan_no": scan_no,
        "status": "running",
        # What configuration this scan is running under, and which of the
        # caller's own parameters the policy displaced. Reported at acceptance
        # rather than only in the report: a scan that assessed something other
        # than what was asked for must say so now.
        "policy": {
            "policy_id": effective.policy_id,
            "policy_name": effective.policy_name,
            "fingerprint": effective.fingerprint(),
            "source": effective.source,
            "overrides": policy_overrides,
        },
    }


@router.post("/scan/asset-discovery")
@limiter.limit("5/minute")
async def scan_asset_discovery(
    request: Request,
    response: Response,
    req: AssetDiscoveryRequest,
    org_id: str | None = Query(None),
    user: User = Depends(require_permission("scans", "execute")),
    db: Session = Depends(get_db),
):
    """
    Asset Discovery: Phase 2 (Trigger and Return Immediately).
    """
    mode = resolve_pipeline_mode(req.pipeline_mode)
    if not is_phase_in_pipeline(mode, 2):
        raise HTTPException(
            status_code=400,
            detail=f"Asset Discovery is not part of the '{mode}' pipeline.",
        )

    # SaaS Stability: Prevent duplicate phase triggers if the backend is already chaining
    scan = db.query(Scan).filter(Scan.id == req.scan_id).first()
    if scan and scan.status == "running" and scan.current_task_id:
        log.info(
            "Phase 2 already in progress (chained) for scan %s, skipping redundant trigger.",
            req.scan_id,
        )
        return {"success": True, "task_id": scan.current_task_id, "status": "running"}

    resolved_org = _resolve_org(user, org_id)

    # ── Quota gate for custom ports (Phase 2 manually triggered) ──────────────
    if req.custom_ports:
        check_scan_quota(db, org_id=resolved_org, custom_ports=req.custom_ports)

    task = run_asset_discovery_task.delay(
        user_id=str(user.id),
        hosts=req.hosts,
        intensity=req.intensity,
        scan_id=req.scan_id,
        pipeline_mode=req.pipeline_mode,
        os_detection=req.os_detection,
        custom_ports=req.custom_ports,
        exclude_ports=req.exclude_ports,
        exclude_ot_from_nmap=req.exclude_ot_from_nmap,
        passive_first=req.passive_first,
        exclude_ips=req.exclude_ips,
    )

    # Track active task for termination
    if req.scan_id and scan:
        options = dict(scan.options or {})
        if req.custom_ports:
            options["custom_ports"] = req.custom_ports
        if req.exclude_ports:
            options["exclude_ports"] = req.exclude_ports
        if req.exclude_ot_from_nmap is not None:
            options["exclude_ot_from_nmap"] = req.exclude_ot_from_nmap
        if req.passive_first is not None:
            options["passive_first"] = req.passive_first
        if req.exclude_ips:
            options["exclude_ips"] = req.exclude_ips
        scan.current_task_id = task.id
        scan.status = "running"
        scan.options = options
        db.commit()

    return {"success": True, "task_id": task.id, "status": "running"}


@router.post("/scan/vulnerability-audit")
@limiter.limit("5/minute")
async def scan_vulnerability_audit(
    request: Request,
    response: Response,
    req: VulnerabilityAuditRequest,
    user: User = Depends(require_permission("scans", "execute")),
    db: Session = Depends(get_db),
):
    """
    Vulnerability Audit: Phase 3 (Trigger and Return Immediately).
    """
    mode = resolve_pipeline_mode(req.pipeline_mode)
    if not is_phase_in_pipeline(mode, 3):
        raise HTTPException(
            status_code=400,
            detail=f"Vulnerability Audit is not part of the '{mode}' pipeline.",
        )

    # SaaS Stability: Prevent duplicate phase triggers if the backend is already chaining
    scan = db.query(Scan).filter(Scan.id == req.scan_id).first()
    if scan and scan.status == "running" and scan.current_task_id:
        log.info(
            "Phase 3 already in progress (chained) for scan %s, skipping redundant trigger.",
            req.scan_id,
        )
        return {"success": True, "task_id": scan.current_task_id, "status": "running"}

    task = run_vulnerability_audit_task.delay(
        user_id=str(user.id),
        hosts=req.hosts,
        scan_id=req.scan_id,
        pipeline_mode=req.pipeline_mode,
        exclude_ot_from_nmap=req.exclude_ot_from_nmap,
        exclude_ips=req.exclude_ips,
    )

    # Track active task for termination
    if req.scan_id and scan:
        options = dict(scan.options or {})
        if req.exclude_ot_from_nmap is not None:
            options["exclude_ot_from_nmap"] = req.exclude_ot_from_nmap
        if req.exclude_ips:
            options["exclude_ips"] = req.exclude_ips
        scan.current_task_id = task.id
        scan.status = "running"
        scan.options = options
        db.commit()

    return {"success": True, "task_id": task.id, "status": "running"}


@router.post("/scan/phases")
@limiter.limit("5/minute")
async def scan_phases(
    request: Request,
    response: Response,
    req: PhasesRequest,
    current_user: User = Depends(require_permission("scans", "execute")),
    db: Session = Depends(get_db),
):
    """Convenience endpoint — run any combination of phases in one call (Background)."""
    targets = validate_scan_targets(
        req.targets, org=_org_row(db, str(current_user.org_id))
    )
    task = run_traditional_scan_task.delay(
        user_id=str(current_user.id),
        targets=targets,
        phases=req.phases,
        scan_type=req.scan_type,
        intensity=req.intensity,
        passive_first=req.passive_first,
        exclude_ot_from_nmap=req.exclude_ot_from_nmap,
        exclude_ips=req.exclude_ips,
    )
    return {
        "success": True,
        "detail": "Combined phase scan initiated in background.",
        "task_id": task.id,
        "status": "running",
    }
