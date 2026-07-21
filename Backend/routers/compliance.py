"""
routers/compliance.py
Base routers for the CCure Audit PRO Policy Compliance Engine.
"""

import logging
from typing import Optional, List
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status, BackgroundTasks
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy import or_, and_
from sqlalchemy.orm import Session

from auth.rbac import require_permission
from db.base import (
    get_db,
    gen_compliance_credential_id,
    gen_compliance_remediation_request_id,
)
from db.models import User, Asset
from db.models.compliance import (
    ComplianceFramework,
    ComplianceTenantFramework,
    ComplianceControl,
    ComplianceRule,
    ComplianceRuleControl,
    CompliancePolicy,
    CompliancePolicyRule,
    ComplianceScanRun,
    ComplianceFinding,
    ComplianceFindingHistory,
    ComplianceException,
    ComplianceScore,
    ComplianceRemediation,
    ComplianceCredential,
    ComplianceRemediationRequest,
)
from core.security_crypto import encrypt_credential
from core.audit import log_audit_event

log = logging.getLogger("ccure.compliance")
router = APIRouter(prefix="/compliance", tags=["Compliance"])


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic Schemas
# ─────────────────────────────────────────────────────────────────────────────


class ExceptionRequest(BaseModel):
    reason: str = Field(..., min_length=10, max_length=1000)
    compensating_control: Optional[str] = None
    expires_at: datetime


class ExceptionApproval(BaseModel):
    status: str = Field(..., pattern="^(approved|rejected)$")


class PolicyCreate(BaseModel):
    framework_id: str
    name: str = Field(..., min_length=3, max_length=255)
    target_platform: str = Field(
        ..., pattern="^(windows|linux|network_device|cloud|database|any)$"
    )
    rule_ids: List[str]
    tags: Optional[List[str]] = None


class ScanTrigger(BaseModel):
    framework_id: str
    policy_id: str
    asset_ids: Optional[List[str]] = None
    asset_tags: Optional[List[str]] = None


class AttestationRequest(BaseModel):
    status: str = Field(..., pattern="^(pass|fail|not_applicable)$")
    note: Optional[str] = None
    evidence_file_ids: Optional[List[str]] = None


class JITCredentials(BaseModel):
    username: str = Field(..., min_length=1, max_length=150)
    auth_method: str = Field("password", pattern="^(password|key)$")
    password: Optional[SecretStr] = None
    key_content: Optional[SecretStr] = None
    port: int = Field(22, ge=1, le=65535)


class RemediationRequest(BaseModel):
    action: str = Field(..., pattern="^(apply_script)$")
    credential_id: Optional[str] = None
    jit_credentials: Optional[JITCredentials] = None
    emergency_bypass: bool = False


class RollbackRequest(BaseModel):
    credential_id: Optional[str] = None
    jit_credentials: Optional[JITCredentials] = None
    emergency_bypass: bool = False


class CredentialCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    username: str = Field(..., min_length=1, max_length=150)
    auth_method: str = Field("password", pattern="^(password|key)$")
    password: Optional[SecretStr] = None
    key_content: Optional[SecretStr] = None
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


class RemediationApprovalPayload(BaseModel):
    status: str = Field(..., pattern="^(approved|rejected)$")


# ─────────────────────────────────────────────────────────────────────────────
# Helper Methods
# ─────────────────────────────────────────────────────────────────────────────


def _is_admin(user: User) -> bool:
    role_name = (getattr(getattr(user, "role", None), "name", "") or "").lower()
    return role_name in ("admin", "superadmin", "compliance_officer")


# ─────────────────────────────────────────────────────────────────────────────
# 1. Framework Marketplace & Installation
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/marketplace")
def get_marketplace_frameworks(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "read")),
):
    """List all global frameworks and see which ones are installed on the tenant org."""
    frameworks = (
        db.query(ComplianceFramework)
        .filter(
            or_(
                ComplianceFramework.tenant_id == None,
                ComplianceFramework.tenant_id == user.org_id,
            )
        )
        .all()
    )

    installed = (
        db.query(ComplianceTenantFramework)
        .filter(
            ComplianceTenantFramework.tenant_id == user.org_id,
            ComplianceTenantFramework.is_enabled == True,
        )
        .all()
    )
    installed_ids = {inst.framework_id for inst in installed}

    results = []
    for fw in frameworks:
        controls_count = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == fw.id)
            .count()
        )
        results.append(
            {
                "framework_id": fw.id,
                "code": fw.code,
                "name": fw.name,
                "version": fw.version,
                "is_installed": fw.id in installed_ids,
                "controls_count": controls_count,
            }
        )

    return {"data": results}


@router.post("/marketplace/{framework_id}/install", status_code=status.HTTP_201_CREATED)
def install_marketplace_framework(
    framework_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "manage_frameworks")),
):
    """Install/enable a framework for the organization."""
    # Check framework exists
    fw = (
        db.query(ComplianceFramework)
        .filter(
            ComplianceFramework.id == framework_id,
            or_(
                ComplianceFramework.tenant_id == None,
                ComplianceFramework.tenant_id == user.org_id,
            ),
        )
        .first()
    )

    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")

    # Check if already installed
    existing = (
        db.query(ComplianceTenantFramework)
        .filter(
            ComplianceTenantFramework.tenant_id == user.org_id,
            ComplianceTenantFramework.framework_id == framework_id,
        )
        .first()
    )

    if existing:
        if existing.is_enabled:
            return {"message": "Framework already installed"}
        existing.is_enabled = True
        existing.enabled_by = user.id
        existing.enabled_at = datetime.now(timezone.utc)
    else:
        inst_id = f"ctf_{user.org_id}_{framework_id}"
        new_inst = ComplianceTenantFramework(
            id=inst_id,
            tenant_id=user.org_id,
            framework_id=framework_id,
            is_enabled=True,
            enabled_by=user.id,
            enabled_at=datetime.now(timezone.utc),
        )
        db.add(new_inst)

    # Automatically bootstrap default policy baseline containing all controls and rules
    policy_id = f"cpl_{user.org_id}_{fw.code.lower()}_default"
    family_code = (
        f"POL-{user.org_id.upper().replace('.', '_')}-{fw.code.upper()}-DEFAULT"
    )

    default_policy = (
        db.query(CompliancePolicy)
        .filter(
            or_(
                CompliancePolicy.id == policy_id,
                and_(
                    CompliancePolicy.tenant_id == user.org_id,
                    CompliancePolicy.framework_id == framework_id,
                ),
                and_(
                    CompliancePolicy.tenant_id == user.org_id,
                    CompliancePolicy.policy_family_code == family_code,
                    CompliancePolicy.version_number == 1,
                ),
            )
        )
        .first()
    )
    if not default_policy:
        default_policy = CompliancePolicy(
            id=policy_id,
            framework_id=framework_id,
            tenant_id=user.org_id,
            policy_family_code=family_code,
            version_number=1,
            name=f"{fw.name} Default Policy Baseline",
            target_platform="any",
            status="active",
            is_active=True,
            created_by=user.id,
            created_at=datetime.now(timezone.utc),
        )
        db.add(default_policy)
        db.flush()

    # Query and link all rules for this framework if not already linked
    rules_linked = (
        db.query(CompliancePolicyRule)
        .filter(CompliancePolicyRule.policy_id == default_policy.id)
        .count()
    )
    if rules_linked == 0:
        rules = (
            db.query(ComplianceRule)
            .join(
                ComplianceRuleControl,
                ComplianceRuleControl.rule_id == ComplianceRule.id,
            )
            .join(
                ComplianceControl,
                ComplianceControl.id == ComplianceRuleControl.control_id,
            )
            .filter(ComplianceControl.framework_id == framework_id)
            .all()
        )

        if rules:
            for r in rules:
                link = CompliancePolicyRule(policy_id=default_policy.id, rule_id=r.id)
                db.add(link)

    db.commit()
    log_audit_event(db, user, "install_framework", "framework", framework_id, "success")
    return {"message": f"Successfully installed framework {fw.name}"}


@router.post("/marketplace/{framework_id}/uninstall", status_code=status.HTTP_200_OK)
def uninstall_marketplace_framework(
    framework_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "manage_frameworks")),
):
    """Uninstall/disable a framework for the organization."""
    existing = (
        db.query(ComplianceTenantFramework)
        .filter(
            ComplianceTenantFramework.tenant_id == user.org_id,
            ComplianceTenantFramework.framework_id == framework_id,
        )
        .first()
    )

    if not existing:
        raise HTTPException(
            status_code=404, detail="Framework installation record not found"
        )

    existing.is_enabled = False
    db.commit()
    log_audit_event(
        db, user, "uninstall_framework", "framework", framework_id, "success"
    )
    return {"message": "Framework uninstalled successfully"}


# ─────────────────────────────────────────────────────────────────────────────
# 2. Policy Baselines
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/policies")
def list_policies(
    framework_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "read")),
):
    """Retrieve compliance policies for the tenant organization."""
    # Filter only policies belonging to active/enabled frameworks for this tenant
    enabled_fw_subquery = (
        db.query(ComplianceTenantFramework.framework_id)
        .filter(
            ComplianceTenantFramework.tenant_id == user.org_id,
            ComplianceTenantFramework.is_enabled == True,
        )
        .scalar_subquery()
    )

    q = db.query(CompliancePolicy).filter(
        or_(
            CompliancePolicy.tenant_id == None,
            CompliancePolicy.tenant_id == user.org_id,
        ),
        CompliancePolicy.is_active == True,
        CompliancePolicy.framework_id.in_(enabled_fw_subquery),
    )
    if framework_id:
        q = q.filter(CompliancePolicy.framework_id == framework_id)

    policies = q.all()
    result = []
    for p in policies:
        rules_count = (
            db.query(CompliancePolicyRule)
            .filter(CompliancePolicyRule.policy_id == p.id)
            .count()
        )
        result.append(
            {
                "id": p.id,
                "name": p.name,
                "framework_id": p.framework_id,
                "policy_family_code": p.policy_family_code,
                "version_number": p.version_number,
                "target_platform": p.target_platform,
                "status": p.status,
                "rules_count": rules_count,
                "created_at": p.created_at.isoformat(),
            }
        )
    return {"data": result}


@router.get("/policies/{id}/rules")
def get_policy_rules(
    id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "read")),
):
    """Retrieve all rules linked to a policy baseline, enriched with control metadata."""
    policy = (
        db.query(CompliancePolicy)
        .filter(
            CompliancePolicy.id == id,
            or_(
                CompliancePolicy.tenant_id == None,
                CompliancePolicy.tenant_id == user.org_id,
            ),
        )
        .first()
    )
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    policy_rules = (
        db.query(CompliancePolicyRule)
        .filter(CompliancePolicyRule.policy_id == id)
        .all()
    )
    rule_ids = [pr.rule_id for pr in policy_rules]
    rules = db.query(ComplianceRule).filter(ComplianceRule.id.in_(rule_ids)).all()

    result = []
    for r in rules:
        mapping = (
            db.query(ComplianceRuleControl)
            .filter(ComplianceRuleControl.rule_id == r.id)
            .first()
        )
        control = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.id == mapping.control_id)
            .first()
            if mapping
            else None
        )

        result.append(
            {
                "id": r.id,
                "rule_name": r.rule_family_code,
                "check_type": r.check_type,
                "evidence_source": r.evidence_source,
                "check_definition": r.check_definition,
                "severity": r.severity.upper(),
                "control_id": control.id if control else None,
                "control_number": control.control_number if control else None,
                "control_title": control.title if control else "Manual Control",
                "recommendation_text": (
                    r.remediation.recommendation_text
                    if r.remediation
                    else "No recommendation available."
                ),
            }
        )
    return {"data": result}


class RuleUpdatePayload(BaseModel):
    check_definition: dict
    severity: str
    severity_weight: int


@router.put("/rules/{id}")
def update_compliance_rule(
    id: str,
    payload: RuleUpdatePayload,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "manage_rules")),
):
    """Update a compliance rule's verification parameters and severity levels."""
    rule = db.query(ComplianceRule).filter(ComplianceRule.id == id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    rule.check_definition = payload.check_definition
    rule.severity = payload.severity.lower()
    rule.severity_weight = payload.severity_weight
    db.commit()
    return {"message": "Rule updated successfully"}


@router.post("/policies", status_code=status.HTTP_201_CREATED)
def create_policy_baseline(
    payload: PolicyCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "manage_rules")),
):
    """Create version 1 of a new policy baseline."""
    # Verify associated framework is active and installed
    tf = (
        db.query(ComplianceTenantFramework)
        .filter_by(
            tenant_id=user.org_id, framework_id=payload.framework_id, is_enabled=True
        )
        .first()
    )
    if not tf:
        raise HTTPException(
            status_code=400, detail="Associated framework must be installed and active."
        )
    # Verify rules exist
    rules = (
        db.query(ComplianceRule).filter(ComplianceRule.id.in_(payload.rule_ids)).all()
    )
    if len(rules) != len(payload.rule_ids):
        raise HTTPException(
            status_code=400, detail="One or more selected rules do not exist"
        )

    policy_family = f"POL-{user.org_id.upper().replace('.', '_')}-{payload.name.replace(' ', '-').upper()[:15]}"
    policy_id = f"cpl_{user.org_id}_{policy_family.lower()}_v1"

    new_policy = CompliancePolicy(
        id=policy_id,
        framework_id=payload.framework_id,
        tenant_id=user.org_id,
        policy_family_code=policy_family,
        version_number=1,
        name=payload.name,
        target_platform=payload.target_platform,
        status="active",
        is_active=True,
        tags=payload.tags or [],
        created_by=user.id,
        created_at=datetime.now(timezone.utc),
    )
    db.add(new_policy)

    # Link rules
    for r in rules:
        link = CompliancePolicyRule(policy_id=policy_id, rule_id=r.id)
        db.add(link)

    db.commit()
    log_audit_event(db, user, "create_policy", "policy", policy_id, "success")
    return {"message": "Policy baseline created successfully", "policy_id": policy_id}


# ─────────────────────────────────────────────────────────────────────────────
# 3. Trigger Scans
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/scans", status_code=status.HTTP_202_ACCEPTED)
def trigger_compliance_scan(
    payload: ScanTrigger,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "scan")),
):
    """Dispatches a compliance scanning run task."""
    # Verify associated framework is installed and active
    tf = (
        db.query(ComplianceTenantFramework)
        .filter_by(
            tenant_id=user.org_id, framework_id=payload.framework_id, is_enabled=True
        )
        .first()
    )
    if not tf:
        raise HTTPException(
            status_code=400,
            detail="Cannot trigger scans for disabled or uninstalled frameworks.",
        )

    # Validate framework and policy baselines
    policy = (
        db.query(CompliancePolicy)
        .filter(
            CompliancePolicy.id == payload.policy_id,
            or_(
                CompliancePolicy.tenant_id == None,
                CompliancePolicy.tenant_id == user.org_id,
            ),
        )
        .first()
    )

    if not policy:
        raise HTTPException(status_code=404, detail="Policy baseline not found")

    # Add random UUID suffix to prevent primary key collisions when triggered concurrently
    import uuid

    rand_suffix = uuid.uuid4().hex[:4]
    run_id = f"csr_{user.org_id[:4]}_{datetime.now().strftime('%d%b%y_%H%M%S')}_{rand_suffix}"

    new_run = ComplianceScanRun(
        id=run_id,
        tenant_id=user.org_id,
        framework_id=payload.framework_id,
        policy_id=payload.policy_id,
        initiated_by=user.id,
        scope={
            "asset_ids": payload.asset_ids or [],
            "asset_tags": payload.asset_tags or [],
        },
        status="queued",
        started_at=datetime.now(timezone.utc),
    )
    db.add(new_run)
    db.commit()

    # Route scan evaluation task directly through local BackgroundTasks for immediate updates
    from core.compliance_tasks import run_scan_task

    background_tasks.add_task(run_scan_task, run_id, user.org_id)

    log_audit_event(db, user, "trigger_scan", "scan_run", run_id, "success")
    return {"message": "Scan run triggered successfully", "scan_run_id": run_id}


# ─────────────────────────────────────────────────────────────────────────────
# 4. Findings & Attestations
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/findings")
def list_findings(
    status: Optional[str] = Query(None),
    limit: int = Query(10000, ge=1, le=50000),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "read")),
):
    """List compliance findings for the organization with control and rule details."""
    # Filter only findings belonging to active/enabled frameworks for this tenant
    enabled_fws = (
        db.query(ComplianceTenantFramework.framework_id)
        .filter(
            ComplianceTenantFramework.tenant_id == user.org_id,
            ComplianceTenantFramework.is_enabled == True,
        )
        .all()
    )
    enabled_fw_ids = [r[0] for r in enabled_fws]

    # Resolve latest scan runs per enabled framework
    latest_run_ids = []
    for fw_id in enabled_fw_ids:
        latest = (
            db.query(ComplianceScanRun)
            .filter(
                ComplianceScanRun.tenant_id == user.org_id,
                ComplianceScanRun.framework_id == fw_id,
                ComplianceScanRun.status == "completed",
            )
            .order_by(ComplianceScanRun.finished_at.desc())
            .first()
        )
        if latest:
            latest_run_ids.append(latest.id)

    q = (
        db.query(ComplianceFinding, ComplianceControl, ComplianceRule, Asset)
        .outerjoin(
            ComplianceControl, ComplianceControl.id == ComplianceFinding.control_id
        )
        .outerjoin(ComplianceRule, ComplianceRule.id == ComplianceFinding.rule_id)
        .outerjoin(Asset, Asset.id == ComplianceFinding.asset_id)
        .filter(
            ComplianceFinding.tenant_id == user.org_id,
            ComplianceControl.framework_id.in_(enabled_fw_ids),
            or_(
                ComplianceFinding.scan_run_id.in_(latest_run_ids),
                ComplianceFinding.source == "manual_attestation",
            ),
        )
    )

    if status:
        q = q.filter(ComplianceFinding.status == status)

    findings = q.order_by(ComplianceFinding.last_seen.desc()).limit(limit).all()
    result = []
    for f, control, rule, asset in findings:
        asset_info = {"ip": None, "hostname": None, "reboot_pending": False}
        if asset:
            asset_info = {
                "ip": asset.ip_address,
                "hostname": asset.hostname,
                "reboot_pending": (asset.custom_attributes or {}).get(
                    "reboot_pending", False
                ),
            }
        elif f.asset_id:
            asset_info = {
                "ip": "Unknown",
                "hostname": "Unknown",
                "reboot_pending": False,
            }

        # Resolve remediation details
        recommendation = "No recommendation available."
        fix_command = None
        if rule and rule.remediation:
            recommendation = rule.remediation.recommendation_text
            fix_command = rule.remediation.fix_command

        result.append(
            {
                "id": f.id,
                "control_id": f.control_id,
                "control_title": control.title if control else "Unknown Control",
                "rule_id": f.rule_id,
                "rule_name": rule.rule_family_code if rule else "Manual Check",
                "severity": (rule.severity.upper() if rule else "MEDIUM"),
                "check_definition": rule.check_definition if rule else None,
                "asset_id": f.asset_id,
                "asset_ip": asset_info["ip"],
                "asset_hostname": asset_info["hostname"],
                "asset_reboot_pending": asset_info["reboot_pending"],
                "source": f.source,
                "status": f.status,
                "evidence": f.evidence,
                "last_seen": f.last_seen.isoformat(),
                "recommendation_text": recommendation,
                "fix_command": fix_command,
            }
        )
    return {"data": result}


@router.post("/controls/{control_id}/attest")
def attest_manual_control(
    control_id: str,
    payload: AttestationRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "attest")),
):
    """Submit manual audit evidence and notes for process controls."""
    ctrl = (
        db.query(ComplianceControl).filter(ComplianceControl.id == control_id).first()
    )
    if not ctrl:
        raise HTTPException(status_code=404, detail="Control not found")

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
            detail="Cannot attest controls for disabled or uninstalled frameworks.",
        )

    finding_id = f"cfnd_{user.org_id}_manual_{control_id}"

    finding = (
        db.query(ComplianceFinding).filter(ComplianceFinding.id == finding_id).first()
    )
    now = datetime.now(timezone.utc)

    if not finding:
        finding = ComplianceFinding(
            id=finding_id,
            tenant_id=user.org_id,
            control_id=control_id,
            source="manual_attestation",
            status=payload.status,
            evidence={"note": payload.note or ""},
            evidence_file_ids=payload.evidence_file_ids or [],
            attested_by=user.id,
            first_seen=now,
            last_seen=now,
        )
        db.add(finding)
    else:
        finding.status = payload.status
        finding.evidence = {"note": payload.note or ""}
        finding.evidence_file_ids = payload.evidence_file_ids or []
        finding.attested_by = user.id
        finding.last_seen = now

    # Log history trail
    history = ComplianceFindingHistory(
        id=f"cfh_{user.org_id}_{datetime.now().strftime('%M%S%f')}",
        finding_id=finding_id,
        status=payload.status,
        changed_by=user.id,
        source="manual_attestation",
        note=payload.note or "Manual attestation updated",
    )
    db.add(history)
    db.commit()

    log_audit_event(db, user, "attest_control", "finding", finding_id, "success")
    return {"message": "Attestation recorded successfully"}


# ─────────────────────────────────────────────────────────────────────────────
# 4.5. Credentials Manager
# ─────────────────────────────────────────────────────────────────────────────


@router.post(
    "/credentials",
    status_code=status.HTTP_201_CREATED,
    response_model=CredentialResponse,
)
def create_credential(
    payload: CredentialCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "manage_integrations")),
):
    """Register new SSH or Password credentials for target assets."""
    # Ensure name uniqueness per tenant
    existing = (
        db.query(ComplianceCredential)
        .filter_by(name=payload.name, tenant_id=user.org_id)
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=400, detail="A credential with this name already exists"
        )

    # Basic validations based on auth_method
    encrypted_password = None
    encrypted_key_content = None

    if payload.auth_method == "password":
        if not payload.password:
            raise HTTPException(
                status_code=400,
                detail="Password is required for password authentication",
            )
        encrypted_password = encrypt_credential(payload.password.get_secret_value())
    elif payload.auth_method == "key":
        if not payload.key_content:
            raise HTTPException(
                status_code=400,
                detail="Private key content is required for key authentication",
            )
        encrypted_key_content = encrypt_credential(
            payload.key_content.get_secret_value()
        )

    cred_id = gen_compliance_credential_id(user.org_id)
    new_cred = ComplianceCredential(
        id=cred_id,
        tenant_id=user.org_id,
        name=payload.name,
        username=payload.username,
        encrypted_password=encrypted_password,
        encrypted_key_content=encrypted_key_content,
        port=payload.port,
        auth_method=payload.auth_method,
    )
    db.add(new_cred)
    db.commit()
    db.refresh(new_cred)
    log_audit_event(db, user, "create_credential", "credential", cred_id, "success")
    return new_cred


@router.get("/credentials", response_model=List[CredentialResponse])
def list_credentials(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "read")),
):
    """List registered target credentials (excluding passwords/private keys)."""
    creds = db.query(ComplianceCredential).filter_by(tenant_id=user.org_id).all()
    return creds


@router.delete("/credentials/{id}", status_code=status.HTTP_200_OK)
def delete_credential(
    id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "manage_integrations")),
):
    """Delete a registered credential."""
    cred = (
        db.query(ComplianceCredential).filter_by(id=id, tenant_id=user.org_id).first()
    )
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    db.delete(cred)
    db.commit()
    log_audit_event(db, user, "delete_credential", "credential", id, "success")
    return {"message": "Credential deleted successfully"}


# ─────────────────────────────────────────────────────────────────────────────
# 5. Remediation Execution (Maker-Checker validation)
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/findings/{id}/remediate")
def apply_remediation(
    id: str,
    payload: RemediationRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "remediate")),
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
        cred = (
            db.query(ComplianceCredential)
            .filter_by(id=payload.credential_id, tenant_id=user.org_id)
            .first()
        )
        if not cred:
            raise HTTPException(status_code=404, detail="Stored credential not found")
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
        if not _is_admin(user):
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
            f"Bypassed Maker-Checker queue. Asset: {finding.asset_id or 'Global'}",
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
    db.commit()

    log_audit_event(
        db, user, "request_remediation", "remediation_request", req_id, "success"
    )
    return {
        "message": "Remediation request submitted to the approvals queue.",
        "request_id": req_id,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 5.5. Maker-Checker Remediation Queue
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/remediations/requests")
def list_remediation_requests(
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "read")),
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
            asset = db.query(Asset).filter_by(id=finding.asset_id).first()
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
    user: User = Depends(require_permission("compliance", "approve_exception")),
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
            db, user, "reject_remediation", "remediation_request", id, "success"
        )
        return {"message": "Remediation request rejected."}

    req.status = "approved"
    db.commit()

    from core.compliance_tasks import run_reremediation_task

    is_rb = req.id.startswith("crrq_rollback_")
    run_reremediation_task.delay(
        req.finding_id,
        req.remediation_id,
        user.id,
        remediation_request_id=req.id,
        is_rollback=is_rb,
    )

    action_label = "approve_rollback" if is_rb else "approve_remediation"
    msg_label = (
        "Rollback approved and queued for execution."
        if is_rb
        else "Remediation approved and queued for execution."
    )
    log_audit_event(db, user, action_label, "remediation_request", id, "success")
    return {"message": msg_label}


@router.post("/remediations/requests/{id}/cancel")
def cancel_remediation_request(
    id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "remediate")),
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

    log_audit_event(
        db, user, "cancel_remediation", "remediation_request", id, "success"
    )
    return {"message": "Remediation request cancelled."}


@router.post("/remediations/requests/{id}/rollback")
def rollback_remediation_request(
    id: str,
    payload: RollbackRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "remediate")),
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
        cred = (
            db.query(ComplianceCredential)
            .filter_by(id=payload.credential_id, tenant_id=user.org_id)
            .first()
        )
        if not cred:
            raise HTTPException(status_code=404, detail="Stored credential not found")
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
        if not _is_admin(user):
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
    db.commit()

    if is_bypass:
        from core.compliance_tasks import run_reremediation_task

        run_reremediation_task.delay(
            new_req.finding_id,
            new_req.remediation_id,
            user.id,
            remediation_request_id=new_req.id,
            is_rollback=True,
        )
        log_audit_event(
            db,
            user,
            "emergency_bypass_rollback",
            "remediation_request",
            new_req.id,
            "success",
        )
        return {
            "message": "Emergency bypass rollback dispatched directly.",
            "request_id": new_req.id,
        }
    else:
        log_audit_event(
            db, user, "request_rollback", "remediation_request", new_req.id, "success"
        )
        return {
            "message": "Rollback request submitted to approvals queue.",
            "request_id": new_req.id,
        }


# ─────────────────────────────────────────────────────────────────────────────
# 6. Exception Waivers & Approvals
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/findings/{id}/exception", status_code=status.HTTP_201_CREATED)
def request_exception_waiver(
    id: str,
    payload: ExceptionRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "attest")),
):
    """Request a temporary waiver exception for a failing control."""
    finding = (
        db.query(ComplianceFinding)
        .filter(ComplianceFinding.id == id, ComplianceFinding.tenant_id == user.org_id)
        .first()
    )

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

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
                detail="Cannot request exceptions for disabled or uninstalled frameworks.",
            )

    exc_id = f"cex_{user.org_id}_{datetime.now().strftime('%M%S%f')}"
    new_exception = ComplianceException(
        id=exc_id,
        tenant_id=user.org_id,
        control_id=finding.control_id,
        finding_id=finding.id,
        reason=payload.reason,
        compensating_control=payload.compensating_control,
        requested_by=user.id,
        status="pending",
        expires_at=payload.expires_at,
    )
    db.add(new_exception)
    db.commit()

    log_audit_event(db, user, "request_waiver", "exception", exc_id, "success")
    return {"message": "Exception request submitted", "exception_id": exc_id}


@router.patch("/exceptions/{id}")
def approve_exception_waiver(
    id: str,
    payload: ExceptionApproval,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "approve_exception")),
):
    """Approve or reject a pending waiver request (Compliance Officer only)."""
    exc = (
        db.query(ComplianceException)
        .filter(
            ComplianceException.id == id, ComplianceException.tenant_id == user.org_id
        )
        .first()
    )

    if not exc or exc.status != "pending":
        raise HTTPException(status_code=400, detail="No pending waiver matching ID")

    exc.status = payload.status
    exc.approved_by = user.id

    if payload.status == "approved":
        # Transition finding status
        finding = (
            db.query(ComplianceFinding)
            .filter(ComplianceFinding.id == exc.finding_id)
            .first()
        )
        if finding:
            finding.status = "exception"
            # Append timeline log
            history = ComplianceFindingHistory(
                id=f"cfh_{user.org_id}_{datetime.now().strftime('%M%S%f')}",
                finding_id=finding.id,
                status="exception",
                changed_by=user.id,
                source="exception_granted",
                note=f"Approved exception waiver: {exc.reason[:100]}",
            )
            db.add(history)

    db.commit()
    log_audit_event(db, user, "approve_waiver", "exception", id, "success")
    return {"message": f"Waiver request {payload.status} successfully"}


# ─────────────────────────────────────────────────────────────────────────────
# 7. Dashboard Summaries
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/summary")
def get_dashboard_summary(
    framework_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "read")),
):
    """Retrieve compliance summary statistics and quadrant metrics."""
    # Filter scores by enabled frameworks
    enabled_fw_subquery = (
        db.query(ComplianceTenantFramework.framework_id)
        .filter(
            ComplianceTenantFramework.tenant_id == user.org_id,
            ComplianceTenantFramework.is_enabled == True,
        )
        .scalar_subquery()
    )

    scores = (
        db.query(ComplianceScore)
        .filter(
            ComplianceScore.tenant_id == user.org_id,
            ComplianceScore.asset_id == None,  # Org-level summaries
            ComplianceScore.theme
            == None,  # Exclude quadrant scores from overall framework averages
            ComplianceScore.framework_id.in_(enabled_fw_subquery),
        )
        .all()
    )

    # Default mockup if no scores are populated yet
    if not scores:
        return {
            "score_pct": 0.00,
            "weighted_score_pct": 0.00,
            "quadrant_scores": {"ORG": 0.0, "PPL": 0.0, "PHY": 0.0, "TECH": 0.0},
            "kpis": {"total": 93, "passed": 0, "failed": 0, "exceptions": 0},
        }

    # Aggregate average score percentage across enabled frameworks
    avg_score = sum(float(s.score_pct) for s in scores) / len(scores)
    avg_weighted = sum(float(s.weighted_score_pct) for s in scores) / len(scores)

    # Resolve quadrant scores (ORG, PPL, PHY, TECH)
    quadrants = {"ORG": 0.0, "PPL": 0.0, "PHY": 0.0, "TECH": 0.0}
    for q_code in quadrants.keys():
        q_scores = (
            db.query(ComplianceScore)
            .filter(
                ComplianceScore.tenant_id == user.org_id,
                ComplianceScore.asset_id == None,
                ComplianceScore.theme == q_code,
                ComplianceScore.framework_id.in_(enabled_fw_subquery),
            )
            .all()
        )
        if q_scores:
            quadrants[q_code] = sum(float(s.score_pct) for s in q_scores) / len(
                q_scores
            )

    # Compute sum totals
    total = sum(s.total_controls for s in scores)
    passed = sum(s.pass_count for s in scores)
    failed = sum(s.fail_count for s in scores)

    # Filter exceptions to only count active ones linked to enabled frameworks
    exceptions = (
        db.query(ComplianceException)
        .join(ComplianceControl, ComplianceControl.id == ComplianceException.control_id)
        .join(
            ComplianceTenantFramework,
            and_(
                ComplianceTenantFramework.framework_id
                == ComplianceControl.framework_id,
                ComplianceTenantFramework.tenant_id == user.org_id,
                ComplianceTenantFramework.is_enabled == True,
            ),
        )
        .filter(
            ComplianceException.tenant_id == user.org_id,
            ComplianceException.status == "approved",
        )
        .count()
    )

    return {
        "score_pct": round(avg_score, 2),
        "weighted_score_pct": round(avg_weighted, 2),
        "quadrant_scores": quadrants,
        "kpis": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "exceptions": exceptions,
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# 8. Report Exporting (SoA & Executive PDFs / DOCX)
# ─────────────────────────────────────────────────────────────────────────────

import io
from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

try:
    import docx
    from docx import Document
except ImportError:
    docx = None
    Document = None


def _generate_soa_docx(controls: list, findings_map: dict) -> io.BytesIO:
    """Generates the Word Statement of Applicability document using python-docx."""
    doc = Document()
    doc.add_heading("CCure Audit PRO — Statement of Applicability (SoA)", level=1)
    doc.add_paragraph("ISO/IEC 27001:2022 Controls Compliance Ledger Catalog.")

    table = doc.add_table(rows=1, cols=5)
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = "Control ID"
    hdr_cells[1].text = "Name"
    hdr_cells[2].text = "Category"
    hdr_cells[3].text = "Scan Mode"
    hdr_cells[4].text = "Verdict Status"

    for c in controls:
        row_cells = table.add_row().cells
        row_cells[0].text = str(c.control_number or c.id)
        row_cells[1].text = str(c.title)
        row_cells[2].text = str(c.theme)
        row_cells[3].text = str(c.scannability)

        f = findings_map.get(c.id)
        row_cells[4].text = str(f.status).upper() if f else "PENDING"

    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer


def _generate_soa_pdf(controls: list, findings_map: dict) -> io.BytesIO:
    """Generates the Statement of Applicability document using ReportLab."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        fontSize=18,
        textColor=colors.HexColor("#003366"),
    )
    cell_style = ParagraphStyle("CellStyle", parent=styles["Normal"], fontSize=8)

    story = [
        Paragraph("Statement of Applicability (SoA) Report", title_style),
        Paragraph("ISO 27001:2022 Security Controls Ledger", styles["Normal"]),
        Spacer(1, 10 * mm),
    ]

    table_data = [
        [
            Paragraph("<b>Control ID</b>", cell_style),
            Paragraph("<b>Name</b>", cell_style),
            Paragraph("<b>Category</b>", cell_style),
            Paragraph("<b>Scan Mode</b>", cell_style),
            Paragraph("<b>Verdict</b>", cell_style),
        ]
    ]

    for c in controls:
        f = findings_map.get(c.id)
        status_text = f.status.upper() if f else "PENDING"
        table_data.append(
            [
                Paragraph(c.control_number or c.id, cell_style),
                Paragraph(
                    c.title[:45] + "..." if len(c.title) > 45 else c.title, cell_style
                ),
                Paragraph(c.theme, cell_style),
                Paragraph(c.scannability, cell_style),
                Paragraph(
                    (
                        f"<font color='green'>{status_text}</font>"
                        if status_text == "PASS"
                        else f"<font color='red'>{status_text}</font>"
                    ),
                    cell_style,
                ),
            ]
        )

    tbl = Table(table_data, colWidths=[20 * mm, 75 * mm, 25 * mm, 30 * mm, 30 * mm])
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#003366")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(tbl)

    doc.build(story)
    buffer.seek(0)
    return buffer


@router.get("/reports/soa")
def download_statement_of_applicability(
    fmt: str = "pdf",
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "read")),
):
    """Generates and downloads the organization Statement of Applicability."""
    # Filter controls to only active frameworks
    controls = (
        db.query(ComplianceControl)
        .join(
            ComplianceTenantFramework,
            and_(
                ComplianceTenantFramework.framework_id
                == ComplianceControl.framework_id,
                ComplianceTenantFramework.tenant_id == user.org_id,
                ComplianceTenantFramework.is_enabled == True,
            ),
        )
        .order_by(ComplianceControl.control_number)
        .all()
    )
    control_ids = [c.id for c in controls]

    # Resolve latest scan runs per enabled framework
    enabled_fws = (
        db.query(ComplianceTenantFramework.framework_id)
        .filter(
            ComplianceTenantFramework.tenant_id == user.org_id,
            ComplianceTenantFramework.is_enabled == True,
        )
        .all()
    )
    enabled_fw_ids = [r[0] for r in enabled_fws]

    latest_run_ids = []
    for fw_id in enabled_fw_ids:
        latest = (
            db.query(ComplianceScanRun)
            .filter(
                ComplianceScanRun.tenant_id == user.org_id,
                ComplianceScanRun.framework_id == fw_id,
                ComplianceScanRun.status == "completed",
            )
            .order_by(ComplianceScanRun.finished_at.desc())
            .first()
        )
        if latest:
            latest_run_ids.append(latest.id)

    findings = (
        db.query(ComplianceFinding)
        .filter(
            ComplianceFinding.tenant_id == user.org_id,
            ComplianceFinding.control_id.in_(control_ids),
            or_(
                ComplianceFinding.scan_run_id.in_(latest_run_ids),
                ComplianceFinding.source == "manual_attestation",
            ),
        )
        .all()
    )
    findings_map = {f.control_id: f for f in findings}

    if fmt.lower() == "docx" and Document is not None:
        buffer = _generate_soa_docx(controls, findings_map)
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"soa_{user.org_id}.docx"
    else:
        buffer = _generate_soa_pdf(controls, findings_map)
        media = "application/pdf"
        filename = f"soa_{user.org_id}.pdf"

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/executive")
def download_executive_compliance_report(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "read")),
):
    """Generates the executive management compliance posture report PDF."""
    # Filter scores by enabled frameworks
    enabled_fw_subquery = (
        db.query(ComplianceTenantFramework.framework_id)
        .filter(
            ComplianceTenantFramework.tenant_id == user.org_id,
            ComplianceTenantFramework.is_enabled == True,
        )
        .subquery()
    )

    scores = (
        db.query(ComplianceScore)
        .filter(
            ComplianceScore.tenant_id == user.org_id,
            ComplianceScore.asset_id == None,
            ComplianceScore.theme == None,
            ComplianceScore.framework_id.in_(enabled_fw_subquery),
        )
        .all()
    )

    avg_score = (
        round(sum(float(s.score_pct) for s in scores) / len(scores), 2)
        if scores
        else 0.0
    )
    avg_weighted = (
        round(sum(float(s.weighted_score_pct) for s in scores) / len(scores), 2)
        if scores
        else 0.0
    )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ExecutiveTitle",
        parent=styles["Title"],
        fontSize=22,
        textColor=colors.HexColor("#003366"),
        spaceAfter=15,
    )
    metric_style = ParagraphStyle(
        "MetricLabel",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#4A5568"),
    )
    value_style = ParagraphStyle(
        "MetricValue",
        parent=styles["Normal"],
        fontSize=28,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#22C55E"),
    )

    story = [
        Paragraph("Executive Compliance Assessment Report", title_style),
        Paragraph(
            f"Organization ID: {user.org_id} | Date: {datetime.now().strftime('%d %b %Y')}",
            styles["Normal"],
        ),
        Spacer(1, 10 * mm),
        Paragraph("<b>1. Compliance Posture Headline Scores</b>", styles["Heading2"]),
        Spacer(1, 4 * mm),
    ]

    metrics_table = Table(
        [
            [
                Paragraph("Standard Assessment Score", metric_style),
                Paragraph("Risk-Weighted Score", metric_style),
            ],
            [
                Paragraph(f"{avg_score}%", value_style),
                Paragraph(f"{avg_weighted}%", value_style),
            ],
        ],
        colWidths=[90 * mm, 90 * mm],
    )
    metrics_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    story.append(metrics_table)
    story.append(Spacer(1, 10 * mm))

    # Add exceptions overview filtered to enabled frameworks
    exceptions_count = (
        db.query(ComplianceException)
        .join(ComplianceControl, ComplianceControl.id == ComplianceException.control_id)
        .join(
            ComplianceTenantFramework,
            and_(
                ComplianceTenantFramework.framework_id
                == ComplianceControl.framework_id,
                ComplianceTenantFramework.tenant_id == user.org_id,
                ComplianceTenantFramework.is_enabled == True,
            ),
        )
        .filter(
            ComplianceException.tenant_id == user.org_id,
            ComplianceException.status == "approved",
        )
        .count()
    )

    story.append(Paragraph("<b>2. Active Exception Waivers</b>", styles["Heading2"]))
    story.append(
        Paragraph(
            f"Currently, there are {exceptions_count} active exception waivers approved by the compliance officer.",
            styles["Normal"],
        )
    )

    doc.build(story)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=compliance_executive_{user.org_id[:4]}.pdf"
        },
    )


@router.get("/gap-analysis")
def get_compliance_gap_analysis(
    source_framework_id: str = "cfw_iso27001_2022",
    target_framework_id: str = "cfw_nist_csf_v2",
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "read")),
):
    """Calculates estimated compliance posture for target framework based on source framework crosswalk mappings."""
    target_fw = (
        db.query(ComplianceFramework)
        .filter(ComplianceFramework.id == target_framework_id)
        .first()
    )
    source_fw = (
        db.query(ComplianceFramework)
        .filter(ComplianceFramework.id == source_framework_id)
        .first()
    )

    if not target_fw or not source_fw:
        raise HTTPException(status_code=404, detail="Framework not found")

    target_controls = (
        db.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == target_framework_id)
        .all()
    )
    source_findings = (
        db.query(ComplianceFinding)
        .filter(ComplianceFinding.tenant_id == user.org_id)
        .all()
    )
    source_findings_map = {f.control_id: f.status for f in source_findings}

    total_target = len(target_controls)
    estimated_pass = 0
    estimated_fail = 0
    pending_manual = 0
    mapped_count = 0

    control_breakdown = []
    for ctrl in target_controls:
        status_eval = "pending_manual"
        mapped_iso = ctrl.crosswalk or []

        if mapped_iso:
            mapped_count += 1
            has_pass = False
            has_fail = False
            for iso_num in mapped_iso:
                iso_ctrl_id = f"cct_{source_fw.code.lower()}_{iso_num.lower().replace('a.', '').replace('.', '_')}"
                found_status = source_findings_map.get(iso_ctrl_id)
                if found_status in ("pass", "exception"):
                    has_pass = True
                elif found_status in ("fail", "pending_reverify"):
                    has_fail = True

            if has_pass:
                status_eval = "pass"
                estimated_pass += 1
            elif has_fail:
                status_eval = "fail"
                estimated_fail += 1
            else:
                pending_manual += 1
        else:
            pending_manual += 1

        control_breakdown.append(
            {
                "control_id": ctrl.id,
                "control_number": ctrl.control_number,
                "theme": ctrl.theme,
                "title": ctrl.title,
                "crosswalk": mapped_iso,
                "estimated_status": status_eval,
            }
        )

    estimated_pct = (
        round((estimated_pass / total_target) * 100, 2) if total_target > 0 else 0.0
    )

    return {
        "source_framework": {
            "id": source_fw.id,
            "name": source_fw.name,
            "code": source_fw.code,
        },
        "target_framework": {
            "id": target_fw.id,
            "name": target_fw.name,
            "code": target_fw.code,
        },
        "summary": {
            "total_target_controls": total_target,
            "mapped_controls": mapped_count,
            "estimated_pass": estimated_pass,
            "estimated_fail": estimated_fail,
            "pending_manual": pending_manual,
            "estimated_score_pct": estimated_pct,
        },
        "controls": control_breakdown,
    }


@router.get("/reports/nist_csf")
def download_nist_csf_report(
    fmt: str = "pdf",
    functions: Optional[str] = Query(
        None, description="Comma-separated list of functions: GV,ID,PR,DE,RS,RC"
    ),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("compliance", "read")),
):
    """Generates and downloads the NIST CSF v2.0 Compliance Assessment Report."""
    fw_id = "cfw_nist_csf_v2"
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if functions:
        fn_list = [f.strip().upper() for f in functions.split(",") if f.strip()]
        if fn_list:
            query = query.filter(ComplianceControl.theme.in_(fn_list))

    controls = query.order_by(
        ComplianceControl.theme, ComplianceControl.control_number
    ).all()
    control_ids = [c.id for c in controls]

    findings = (
        db.query(ComplianceFinding)
        .filter(
            ComplianceFinding.tenant_id == user.org_id,
            ComplianceFinding.control_id.in_(control_ids),
        )
        .all()
    )
    findings_map = {f.control_id: f for f in findings}

    if fmt.lower() == "docx" and Document is not None:
        buffer = _generate_soa_docx(controls, findings_map)
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"nist_csf_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_soa_pdf(controls, findings_map)
        media = "application/pdf"
        filename = f"nist_csf_report_{user.org_id[:4]}.pdf"

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
