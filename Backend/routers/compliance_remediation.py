"""
routers/compliance_remediation.py
─────────────────────────────────────────────────────────────────────────────
Compliance remediation: the credentials it connects with, applying a fix
(directly, or through the maker-checker queue) and rolling one back.

Part of the compliance router, split out of ``routers/compliance.py`` (G6,
C8 of docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md) and moved
unchanged; that module mounts the parts' sections in the order the API has
always listed them.
"""

from ccure_platform.api import (
    CurrentUser,
    log_audit_event,
    require_authorized,
    resolve_active_organisation,
)
from core import credential_vault
from core.rate_limiter import limiter
from core.security_crypto import encrypt_credential
from datetime import datetime, timezone
from db.base import gen_compliance_remediation_request_id, get_db
from db.models.compliance import (
    ComplianceControl,
    ComplianceFinding,
    ComplianceFindingHistory,
    ComplianceRemediation,
    ComplianceRemediationRequest,
    ComplianceRule,
    ComplianceTenantFramework,
)
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field, SecretStr
from routers.compliance_common import _asset_of, _may_bypass_maker_checker
from sqlalchemy.orm import Session

# Served as ``routers.compliance``: its routes' limiter keys, logger, gateway
# policy entries and model names are that module's, as they were before the
# split (see routers/compliance.py).
__name__ = "routers.compliance"  # noqa: A001


credentials = router = APIRouter()


class CredentialCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    username: str = Field(..., min_length=1, max_length=150)
    auth_method: str = Field("password", pattern="^(password|key)$")
    password: SecretStr | None = None
    key_content: SecretStr | None = None
    port: int = Field(22, ge=1, le=65535)


class CredentialResponse(BaseModel):
    id: str
    name: str
    username: str
    auth_method: str
    port: int
    created_at: datetime

    class Config:
        from_attributes = True


# ─────────────────────────────────────────────────────────────────────────────
# 4.5. Credentials Manager
# ─────────────────────────────────────────────────────────────────────────────


# These three routes predate /credentials. No screen calls them since F3, but
# their request and response shapes, status codes and messages are kept. Their
# rules are not their own any more: they are adapters over core.credential_vault,
# the service /credentials uses. They used to authorise on audit.compliance.read
# and .manage_integrations — under which a viewer could list every credential's
# username, and a custom role could delete one without audit.credential.delete —
# and applied no type rules, rate limit or canonical audit action.
@router.post(
    "/credentials",
    status_code=status.HTTP_201_CREATED,
    response_model=CredentialResponse,
)
@limiter.limit("20/minute")
def create_credential(
    request: Request,
    response: Response,
    payload: CredentialCreate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.credential.manage")),
):
    """Register new SSH or Password credentials for target assets."""
    try:
        return credential_vault.create(
            db,
            actor=user,
            org_id=resolve_active_organisation(user),
            name=payload.name,
            username=payload.username,
            auth_method=payload.auth_method,
            password=(
                payload.password.get_secret_value()
                if payload.password is not None
                else None
            ),
            private_key=(
                payload.key_content.get_secret_value()
                if payload.key_content is not None
                else None
            ),
            port=payload.port,
            request=request,
        )
    except credential_vault.DuplicateCredentialName:
        raise HTTPException(
            status_code=400, detail="A credential with this name already exists"
        ) from None
    except credential_vault.MissingSecret as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                "Password is required for password authentication"
                if exc.field == "password"
                else "Private key content is required for key authentication"
            ),
        ) from None
    except credential_vault.CredentialRuleViolation as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None


@router.get("/credentials", response_model=list[CredentialResponse])
@limiter.limit("60/minute")
def list_credentials(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.credential.read")),
):
    """List registered target credentials (excluding passwords/private keys)."""
    return credential_vault.list_for_org(db, resolve_active_organisation(user))


@router.delete("/credentials/{id}", status_code=status.HTTP_200_OK)
@limiter.limit("20/minute")
def delete_credential(
    request: Request,
    response: Response,
    id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.credential.delete")),
):
    """Delete a registered credential."""
    try:
        credential_vault.delete(
            db,
            actor=user,
            org_id=resolve_active_organisation(user),
            credential_id=id,
            request=request,
        )
    except credential_vault.CredentialNotFound:
        raise HTTPException(status_code=404, detail="Credential not found") from None
    return {"message": "Credential deleted successfully"}


execution = router = APIRouter()


class JITCredentials(BaseModel):
    username: str = Field(..., min_length=1, max_length=150)
    auth_method: str = Field("password", pattern="^(password|key)$")
    password: SecretStr | None = None
    key_content: SecretStr | None = None
    port: int = Field(22, ge=1, le=65535)


class RemediationRequest(BaseModel):
    action: str = Field(..., pattern="^(apply_script)$")
    credential_id: str | None = None
    jit_credentials: JITCredentials | None = None
    emergency_bypass: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# 5. Remediation Execution (Maker-Checker validation)
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/findings/{id}/remediate")
# Changes configuration on a live host. The blast radius of a loop here is
# somebody else's production machine, not this API's CPU.
@limiter.limit("10/minute")
def apply_remediation(
    request: Request,
    response: Response,
    id: str,
    payload: RemediationRequest,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.remediate")),
):
    """Trigger a remediation task for a failed finding."""
    finding = (
        db.query(ComplianceFinding)
        .filter(ComplianceFinding.id == id, ComplianceFinding.tenant_id == user.org_id)
        .first()
    )

    if not finding or finding.status != "fail":
        raise HTTPException(status_code=400, detail="No failing finding matching ID")

    # Verify associated framework is active and installed
    ctrl = db.query(ComplianceControl).filter_by(id=finding.control_id).first()
    if ctrl:
        tf = (
            db.query(ComplianceTenantFramework)
            .filter_by(
                tenant_id=user.org_id, framework_id=ctrl.framework_id, is_enabled=True
            )
            .first()
        )
        if not tf:
            raise HTTPException(
                status_code=400,
                detail="Cannot trigger remediations for disabled or uninstalled frameworks.",
            )

    # Fetch remediation script
    remediation = (
        db.query(ComplianceRemediation)
        .filter(ComplianceRemediation.rule_id == finding.rule_id)
        .first()
    )

    if not remediation or not remediation.fix_command:
        raise HTTPException(
            status_code=400, detail="No automated fix script registered for this rule"
        )

    # Validate credential input
    enc_password = None
    enc_key_content = None
    username = None
    port = 22
    auth_method = None
    cred_id = None

    if payload.credential_id:
        # Through the credential vault, which owns the table (G2).
        try:
            cred = credential_vault.get_for_org(db, user.org_id, payload.credential_id)
        except credential_vault.CredentialNotFound:
            raise HTTPException(
                status_code=404, detail="Stored credential not found"
            ) from None
        cred_id = cred.id
        username = cred.username
        enc_password = cred.encrypted_password
        enc_key_content = cred.encrypted_key_content
        port = cred.port
        auth_method = cred.auth_method
    elif payload.jit_credentials:
        jit = payload.jit_credentials
        username = jit.username
        port = jit.port
        auth_method = jit.auth_method
        if jit.auth_method == "password":
            if not jit.password:
                raise HTTPException(
                    status_code=400, detail="Password required for JIT password auth"
                )
            enc_password = encrypt_credential(jit.password.get_secret_value())
        elif jit.auth_method == "key":
            if not jit.key_content:
                raise HTTPException(
                    status_code=400, detail="Key content required for JIT key auth"
                )
            enc_key_content = encrypt_credential(jit.key_content.get_secret_value())
    else:
        raise HTTPException(
            status_code=400,
            detail="Must provide stored credential_id or jit_credentials",
        )

    # Maker-Checker flow check
    if payload.emergency_bypass:
        if not _may_bypass_maker_checker(db, user):
            raise HTTPException(
                status_code=403,
                detail="Emergency bypass is restricted to administrators and compliance officers.",
            )

        finding.status = "pending_reverify"
        db.commit()

        log_audit_event(
            db,
            user,
            "emergency_bypass_remediation",
            "finding",
            finding.id,
            changes={
                "reason": "Bypassed Maker-Checker queue",
                "asset_id": finding.asset_id or "Global",
            },
        )

        from core.compliance_tasks import run_reremediation_task

        run_reremediation_task.delay(
            finding.id,
            remediation.id,
            user.id,
            remediation_request_id=None,
            jit_enc_password=enc_password,
            jit_enc_key_content=enc_key_content,
            jit_username=username,
            jit_port=port,
            jit_auth_method=auth_method,
            stored_cred_id=cred_id,
        )

        return {"message": "Emergency bypass remediation dispatched directly."}

    # Normal Maker-Checker Flow: create pending request ticket
    req_id = gen_compliance_remediation_request_id(user.org_id)
    new_request = ComplianceRemediationRequest(
        id=req_id,
        tenant_id=user.org_id,
        finding_id=finding.id,
        remediation_id=remediation.id,
        credential_id=cred_id,
        requested_by=user.id,
        status="pending_approval",
        emergency_bypass=False,
        username=username,
        encrypted_password=enc_password,
        encrypted_key_content=enc_key_content,
        port=port,
        auth_method=auth_method,
        created_at=datetime.now(timezone.utc),
    )
    db.add(new_request)

    finding.status = "pending_reverify"
    log_audit_event(
        db, user, "request_remediation", "remediation_request", req_id, status="success"
    )
    db.commit()

    return {
        "message": "Remediation request submitted to the approvals queue.",
        "request_id": req_id,
    }


queue = router = APIRouter()


class RemediationApprovalPayload(BaseModel):
    status: str = Field(..., pattern="^(approved|rejected)$")


class RollbackRequest(BaseModel):
    credential_id: str | None = None
    jit_credentials: JITCredentials | None = None
    emergency_bypass: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# 5.5. Maker-Checker Remediation Queue
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/remediations/requests")
def list_remediation_requests(
    status: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.read")),
):
    """Retrieve remediation execution requests filterable by status."""
    # Filter only remediation requests belonging to active/enabled frameworks for this tenant
    enabled_fw_subquery = (
        db.query(ComplianceTenantFramework.framework_id)
        .filter(
            ComplianceTenantFramework.tenant_id == user.org_id,
            ComplianceTenantFramework.is_enabled == True,
        )
        .subquery()
    )

    q = (
        db.query(ComplianceRemediationRequest)
        .join(
            ComplianceFinding,
            ComplianceFinding.id == ComplianceRemediationRequest.finding_id,
        )
        .join(ComplianceControl, ComplianceControl.id == ComplianceFinding.control_id)
        .filter(
            ComplianceRemediationRequest.tenant_id == user.org_id,
            ComplianceControl.framework_id.in_(enabled_fw_subquery),
        )
    )

    if status and status != "all":
        q = q.filter(ComplianceRemediationRequest.status == status)
    requests = q.order_by(ComplianceRemediationRequest.created_at.desc()).all()

    results = []
    for req in requests:
        finding = db.query(ComplianceFinding).filter_by(id=req.finding_id).first()
        remediation = (
            db.query(ComplianceRemediation).filter_by(id=req.remediation_id).first()
        )
        asset_ip = "Unknown"
        if finding and finding.asset_id:
            asset = _asset_of(db, finding.asset_id)
            if asset:
                asset_ip = asset.ip_address

        is_rb = req.id.startswith("crrq_rollback_")
        rule = (
            db.query(ComplianceRule).filter_by(id=finding.rule_id).first()
            if (finding and finding.rule_id)
            else None
        )
        display_command = "N/A"
        if is_rb:
            from core.compliance_tasks import ROLLBACK_COMMANDS

            display_command = (
                ROLLBACK_COMMANDS.get(rule.rule_family_code) if rule else "N/A"
            )
        else:
            display_command = remediation.fix_command if remediation else "N/A"

        results.append(
            {
                "id": req.id,
                "finding_id": req.finding_id,
                "control_id": finding.control_id if finding else "Unknown",
                "control_title": (
                    (
                        db.query(ComplianceControl)
                        .filter_by(id=finding.control_id)
                        .first()
                        .title
                    )
                    if finding
                    else "Unknown"
                ),
                "remediation_id": req.remediation_id,
                "fix_command": display_command,
                "asset_ip": asset_ip,
                "status": req.status,
                "emergency_bypass": req.emergency_bypass,
                "created_at": req.created_at.isoformat(),
                "requested_by": req.requested_by,
                "approved_by": req.approved_by,
                "execution_log": req.execution_log,
            }
        )
    return {"data": results}


@router.post("/remediations/requests/{id}/approve")
def approve_remediation_request(
    id: str,
    payload: RemediationApprovalPayload,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(
        require_authorized("audit.compliance.approve_exception")
    ),
):
    """Approve or reject a pending remediation request (Checker approval)."""
    req = (
        db.query(ComplianceRemediationRequest)
        .filter_by(id=id, tenant_id=user.org_id)
        .with_for_update()
        .first()
    )

    if not req:
        raise HTTPException(status_code=404, detail="Remediation request not found")

    finding = db.query(ComplianceFinding).filter_by(id=req.finding_id).first()
    if finding:
        ctrl = db.query(ComplianceControl).filter_by(id=finding.control_id).first()
        if ctrl:
            tf = (
                db.query(ComplianceTenantFramework)
                .filter_by(
                    tenant_id=user.org_id,
                    framework_id=ctrl.framework_id,
                    is_enabled=True,
                )
                .first()
            )
            if not tf:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot approve remediation requests for disabled or uninstalled frameworks.",
                )

    if not req:
        raise HTTPException(status_code=404, detail="Remediation request not found")

    if req.status != "pending_approval":
        raise HTTPException(
            status_code=400,
            detail=f"Request already processed. Current status: {req.status}",
        )

    # Enforce Maker-Checker: request creator cannot self-approve
    if payload.status == "approved" and req.requested_by == user.id:
        raise HTTPException(
            status_code=400,
            detail="Zero-trust security violation: Request creator cannot self-approve remediation requests.",
        )

    req.reviewed_at = datetime.now(timezone.utc)
    req.approved_by = user.id

    if payload.status == "rejected":
        req.status = "rejected"
        req.username = None
        req.encrypted_password = None
        req.encrypted_key_content = None
        req.port = None
        req.auth_method = None
        db.commit()

        finding = db.query(ComplianceFinding).filter_by(id=req.finding_id).first()
        if finding:
            finding.status = "fail"
            history = ComplianceFindingHistory(
                id=f"cfh_{user.org_id}_{datetime.now().strftime('%M%S%f')}",
                finding_id=finding.id,
                status="fail",
                changed_by=user.id,
                source="remediation",
                note="Remediation execution request rejected by checker.",
            )
            db.add(history)
            db.commit()

        log_audit_event(
            db, user, "reject_remediation", "remediation_request", id, status="success"
        )
        return {"message": "Remediation request rejected."}

    req.status = "approved"

    # The approval is the auditable act, so it and its audit event share one
    # transaction. `is_rb` is derived from the request id, which is already
    # known here, so classifying the action does not need the commit to have
    # happened first.
    is_rb = req.id.startswith("crrq_rollback_")
    action_label = "approve_rollback" if is_rb else "approve_remediation"
    log_audit_event(db, user, action_label, "remediation_request", id, status="success")
    db.commit()

    # Dispatched only after the commit: the worker reads this row, and handing
    # it a request that is still uncommitted is a race it cannot win. Keeping
    # the dispatch outside the transaction also releases the audit chain-head
    # lock before this call blocks on the broker.
    from core.compliance_tasks import run_reremediation_task

    run_reremediation_task.delay(
        req.finding_id,
        req.remediation_id,
        user.id,
        remediation_request_id=req.id,
        is_rollback=is_rb,
    )

    msg_label = (
        "Rollback approved and queued for execution."
        if is_rb
        else "Remediation approved and queued for execution."
    )
    return {"message": msg_label}


@router.post("/remediations/requests/{id}/cancel")
def cancel_remediation_request(
    id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.remediate")),
):
    """Cancel a pending remediation request created by the current user."""
    req = (
        db.query(ComplianceRemediationRequest)
        .filter_by(id=id, tenant_id=user.org_id)
        .with_for_update()
        .first()
    )

    if not req:
        raise HTTPException(status_code=404, detail="Remediation request not found")

    if req.status != "pending_approval":
        raise HTTPException(
            status_code=400,
            detail=f"Request already processed. Current status: {req.status}",
        )

    # Only the creator of the request can cancel it
    if req.requested_by != user.id:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Only the creator of the request can cancel it.",
        )

    req.reviewed_at = datetime.now(timezone.utc)
    req.approved_by = user.id
    req.status = "rejected"
    req.username = None
    req.encrypted_password = None
    req.encrypted_key_content = None
    req.port = None
    req.auth_method = None
    log_audit_event(
        db, user, "cancel_remediation", "remediation_request", id, status="success"
    )
    db.commit()

    finding = db.query(ComplianceFinding).filter_by(id=req.finding_id).first()
    if finding:
        finding.status = "fail"
        history = ComplianceFindingHistory(
            id=f"cfh_{user.org_id}_{datetime.now().strftime('%M%S%f')}",
            finding_id=finding.id,
            status="fail",
            changed_by=user.id,
            source="remediation",
            note="Remediation execution request cancelled by creator.",
        )
        db.add(history)
        db.commit()

    return {"message": "Remediation request cancelled."}


@router.post("/remediations/requests/{id}/rollback")
def rollback_remediation_request(
    id: str,
    payload: RollbackRequest,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.remediate")),
):
    """Submit a rollback command request for an already executed remediation request."""
    # 1. Fetch original request to verify it was executed
    orig_req = (
        db.query(ComplianceRemediationRequest)
        .filter_by(id=id, tenant_id=user.org_id)
        .with_for_update()
        .first()
    )

    if not orig_req:
        raise HTTPException(
            status_code=404, detail="Original remediation request not found"
        )

    if orig_req.status != "executed":
        raise HTTPException(
            status_code=400,
            detail=f"Only successfully executed requests can be rolled back. Current status: {orig_req.status}",
        )

    # 2. Verify finding & rule
    finding = db.query(ComplianceFinding).filter_by(id=orig_req.finding_id).first()
    if not finding:
        raise HTTPException(
            status_code=404, detail="Associated compliance finding not found"
        )

    ctrl = db.query(ComplianceControl).filter_by(id=finding.control_id).first()
    if ctrl:
        tf = (
            db.query(ComplianceTenantFramework)
            .filter_by(
                tenant_id=user.org_id, framework_id=ctrl.framework_id, is_enabled=True
            )
            .first()
        )
        if not tf:
            raise HTTPException(
                status_code=400,
                detail="Cannot request rollback for disabled or uninstalled frameworks.",
            )

    rule = db.query(ComplianceRule).filter_by(id=finding.rule_id).first()
    if not rule:
        raise HTTPException(
            status_code=404, detail="Associated compliance rule not found"
        )

    from core.compliance_tasks import ROLLBACK_COMMANDS

    if rule.rule_family_code not in ROLLBACK_COMMANDS:
        raise HTTPException(
            status_code=400,
            detail=f"No automated rollback script registered for rule family code: {rule.rule_family_code}",
        )

    # 3. Validate credentials input
    enc_password = None
    enc_key_content = None
    username = None
    port = 22
    auth_method = None
    cred_id = None

    if payload.credential_id:
        # Through the credential vault, which owns the table (G2).
        try:
            cred = credential_vault.get_for_org(db, user.org_id, payload.credential_id)
        except credential_vault.CredentialNotFound:
            raise HTTPException(
                status_code=404, detail="Stored credential not found"
            ) from None
        cred_id = cred.id
        username = cred.username
        enc_password = cred.encrypted_password
        enc_key_content = cred.encrypted_key_content
        port = cred.port
        auth_method = cred.auth_method
    elif payload.jit_credentials:
        jit = payload.jit_credentials
        username = jit.username
        port = jit.port
        auth_method = jit.auth_method
        if jit.auth_method == "password":
            if not jit.password:
                raise HTTPException(
                    status_code=400, detail="Password required for JIT password auth"
                )
            enc_password = encrypt_credential(jit.password.get_secret_value())
        elif jit.auth_method == "key":
            if not jit.key_content:
                raise HTTPException(
                    status_code=400, detail="Key content required for JIT key auth"
                )
            enc_key_content = encrypt_credential(jit.key_content.get_secret_value())
    else:
        raise HTTPException(
            status_code=400,
            detail="Must provide stored credential_id or jit_credentials",
        )

    # 4. Check if a pending/active rollback request already exists to prevent duplicate actions
    rollback_req_id = id.replace("crrq_", "crrq_rollback_", 1)
    existing_rb = (
        db.query(ComplianceRemediationRequest)
        .filter_by(id=rollback_req_id, tenant_id=user.org_id)
        .first()
    )
    if existing_rb and existing_rb.status in ("pending_approval", "approved"):
        raise HTTPException(
            status_code=400,
            detail="A rollback request is already active or pending approval for this ticket.",
        )

    # 5. Create new rollback request for historical integrity
    new_req = ComplianceRemediationRequest(
        id=rollback_req_id,
        tenant_id=user.org_id,
        finding_id=orig_req.finding_id,
        remediation_id=orig_req.remediation_id,
        credential_id=cred_id,
        requested_by=user.id,
        username=username,
        encrypted_password=enc_password,
        encrypted_key_content=enc_key_content,
        port=port,
        auth_method=auth_method,
        status="pending_approval",
    )

    # 6. Maker-Checker Bypass logic for administrators
    is_bypass = False
    if payload.emergency_bypass:
        if not _may_bypass_maker_checker(db, user):
            raise HTTPException(
                status_code=403,
                detail="Emergency bypass rollback is restricted to administrators and compliance officers.",
            )
        is_bypass = True
        new_req.status = "approved"
        new_req.approved_by = user.id
        new_req.reviewed_at = datetime.now(timezone.utc)
        new_req.emergency_bypass = True

    db.add(new_req)

    # One audit call rather than two, because both branches record the same
    # act — the rollback request being created — and differ only in whether it
    # bypassed approval. `is_bypass` is decided above, so the classification is
    # available before the commit and both action names are preserved.
    #
    # An emergency bypass skips the approvals queue, so this event is the only
    # record that it happened.
    log_audit_event(
        db,
        user,
        "emergency_bypass_rollback" if is_bypass else "request_rollback",
        "remediation_request",
        new_req.id,
        status="success",
    )
    db.commit()

    if is_bypass:
        # After the commit: the worker reads this row.
        from core.compliance_tasks import run_reremediation_task

        run_reremediation_task.delay(
            new_req.finding_id,
            new_req.remediation_id,
            user.id,
            remediation_request_id=new_req.id,
            is_rollback=True,
        )
        return {
            "message": "Emergency bypass rollback dispatched directly.",
            "request_id": new_req.id,
        }
    return {
        "message": "Rollback request submitted to approvals queue.",
        "request_id": new_req.id,
    }
