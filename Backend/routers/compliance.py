"""
routers/compliance.py
Base routers for the CCure Audit PRO Policy Compliance Engine.
"""

import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field, SecretStr, model_validator
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from ccure_platform.api import CurrentUser, has_permission, require_permission
from core import compliance_frameworks, nist_csf
from ccure_platform.api import log_audit_event
from core.security_crypto import encrypt_credential
from core.upload_guard import (
    MalwareDetected,
    MalwareScanUnavailable,
    UploadTooLarge,
    UploadTypeRejected,
    assert_content_matches,
    content_disposition,
    read_capped_async,
    sanitize_filename,
    scan_for_malware,
)
from db.base import (
    SessionLocal,
    gen_compliance_credential_id,
    gen_compliance_remediation_request_id,
    get_db,
)
from db.models import Asset
from db.models.compliance import (
    ComplianceControl,
    ComplianceCredential,
    ComplianceEvidenceFile,
    ComplianceException,
    ComplianceFinding,
    ComplianceFindingHistory,
    ComplianceFramework,
    CompliancePolicy,
    CompliancePolicyRule,
    ComplianceRemediation,
    ComplianceRemediationRequest,
    ComplianceRule,
    ComplianceRuleControl,
    ComplianceScanRun,
    ComplianceScanSchedule,
    ComplianceScore,
    ComplianceTenantFramework,
)
from scan_helpers import limiter

log = logging.getLogger("ccure.compliance")
router = APIRouter(prefix="/compliance", tags=["Compliance"])


def _audit_refusal(
    user: CurrentUser,
    action: str,
    resource_type: str,
    resource_id: str,
    status: str,
) -> None:
    """
    Audit an outcome whose handler is about to raise.

    ``log_audit_event`` adds and flushes but deliberately leaves the commit to
    the caller, and ``get_db`` closes its session without committing. So an
    event written on the request's session and followed by ``raise
    HTTPException`` is discarded when the transaction unwinds — and a refusal
    that leaves no trace is precisely the event an audit trail exists to hold.

    A separate session, committed immediately, is the same remedy
    ``auth/email_domain_guard.py`` uses for the identical situation. Failure to
    audit is logged and swallowed: it must not convert a clean 400 or 503 into
    a 500 that hides why the request was refused.
    """
    audit_db = SessionLocal()
    try:
        log_audit_event(
            audit_db, user, action, resource_type, resource_id, status=status
        )
        audit_db.commit()
    except Exception as exc:  # pragma: no cover - auditing must not mask the refusal
        audit_db.rollback()
        log.warning(
            "Could not audit %s refusal (%s): %s",
            action,
            status,
            exc.__class__.__name__,
        )
    finally:
        audit_db.close()


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic Schemas
# ─────────────────────────────────────────────────────────────────────────────


class ExceptionRequest(BaseModel):
    reason: str = Field(..., min_length=10, max_length=1000)
    compensating_control: str | None = None
    expires_at: datetime


class ExceptionApproval(BaseModel):
    status: str = Field(..., pattern="^(approved|rejected)$")


class PolicyCreate(BaseModel):
    framework_id: str
    name: str = Field(..., min_length=3, max_length=255)
    target_platform: str = Field(
        ..., pattern="^(windows|linux|network_device|cloud|database|any)$"
    )
    rule_ids: list[str]
    tags: list[str] | None = None


class ScanTrigger(BaseModel):
    framework_id: str
    policy_id: str
    asset_ids: list[str] | None = None
    asset_tags: list[str] | None = None


class AttestationRequest(BaseModel):
    status: str = Field(..., pattern="^(pass|fail|not_applicable)$")
    note: str | None = None
    evidence_file_ids: list[str] | None = None
    # ISO/IEC 27001:2022 clause 6.1.3(d) requires the SoA to justify both the
    # inclusion of every applicable control and the exclusion of every
    # inapplicable one. `not_applicable` without a reason is not an exclusion
    # an auditor can accept.
    justification: str | None = Field(None, max_length=2000)
    owner: str | None = None
    next_review_at: datetime | None = None

    # A model validator, not a field validator: Pydantic v2 does not run a
    # field validator when the field is absent from the payload, which is
    # exactly the case this rule exists to reject — an exclusion submitted with
    # no justification key at all.
    @model_validator(mode="after")
    def _require_justification_for_exclusion(self):
        if self.status == "not_applicable" and not (self.justification or "").strip():
            raise ValueError(
                "A justification is required when a control is excluded as not "
                "applicable (ISO/IEC 27001:2022 clause 6.1.3 d)."
            )
        return self


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


class RollbackRequest(BaseModel):
    credential_id: str | None = None
    jit_credentials: JITCredentials | None = None
    emergency_bypass: bool = False


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


class RemediationApprovalPayload(BaseModel):
    status: str = Field(..., pattern="^(approved|rejected)$")


class ScheduleCreate(BaseModel):
    framework_id: str
    policy_id: str
    frequency: str = Field(..., pattern="^(daily|weekly|monthly|quarterly|continuous)$")
    asset_ids: list[str] | None = None
    asset_tags: list[str] | None = None
    notify_on: str = Field("always", pattern="^(always|on_failure_only|on_score_drop)$")
    notify_channels: list[str] | None = None
    first_run_at: datetime | None = None


class ScheduleUpdate(BaseModel):
    is_active: bool | None = None
    frequency: str | None = Field(
        None, pattern="^(daily|weekly|monthly|quarterly|continuous)$"
    )
    notify_on: str | None = Field(
        None, pattern="^(always|on_failure_only|on_score_drop)$"
    )
    notify_channels: list[str] | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Helper Methods
# ─────────────────────────────────────────────────────────────────────────────


def require_active_framework(framework_id: str) -> None:
    """Refuses a framework this installation has parked.

    Eleven of the thirteen seeded catalogues are parked while ISO 27001 and
    NIST CSF are being finished (see `core.compliance_frameworks`). The
    per-tenant `is_enabled` flag already gates the register, scans, findings,
    attestation, evidence, schedules and the dashboard — but every one of the
    thirteen report endpoints checked nothing at all, so
    `/compliance/reports/nis2` would render a full PDF for a framework the
    workspace does not list and no tenant has installed. This is the guard
    those endpoints were missing.

    A parked framework answers 403 rather than 404: the catalogue exists, its
    controls are seeded and its crosswalks are live, and telling the caller it
    does not exist would be false.
    """
    if compliance_frameworks.is_active(framework_id):
        return

    if compliance_frameworks.is_known(framework_id):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Framework {framework_id} is not enabled on this installation. "
                "Active frameworks: "
                + ", ".join(compliance_frameworks.active_framework_ids())
                + "."
            ),
        )

    raise HTTPException(status_code=404, detail=f"Unknown framework {framework_id}")


# The emergency bypass skips the maker-checker queue, i.e. the account performs the
# approval decision itself. That is exactly what `audit.compliance.approve_exception`
# grants (organisation scope, the organisation's own queue): no broader bypass
# permission exists or was added (RBAC-7; docs/architecture/RBAC_ADMINISTRATION.md).
def _may_bypass_maker_checker(db: Session, user: CurrentUser) -> bool:
    return has_permission(db, user, "audit.compliance.approve_exception")


def _latest_run_id(db: Session, org_id: str, framework_id: str) -> str | None:
    """Most recent completed scan run for this tenant and framework."""
    row = (
        db.query(ComplianceScanRun.id)
        .filter(
            ComplianceScanRun.tenant_id == org_id,
            ComplianceScanRun.framework_id == framework_id,
            ComplianceScanRun.status == "completed",
        )
        .order_by(ComplianceScanRun.finished_at.desc().nullslast())
        .first()
    )
    return row[0] if row else None


# Theme families whose published order is not the alphabetical one.
_THEME_ORDER: tuple = tuple(nist_csf.FUNCTION_ORDER) + ("ORG", "PPL", "PHY", "TECH")


def _ordered_themes(themes) -> list:
    """Theme codes in a stable, framework-meaningful order.

    `quadrant_scores` is a JSON object and the dashboard renders it in key
    order, so the order the backend builds it in is what the user sees. Both
    branches of `/summary` used to build it from a `set` or from a `DISTINCT`
    with no `ORDER BY`, which meant the NIST CSF "Core Functions Breakdown"
    panel came out in whatever order Postgres returned — and could differ
    between two loads of the same page.

    Families whose published order is not alphabetical are listed in
    `_THEME_ORDER` and emitted in it — CSF's GV, ID, PR, DE, RS, RC and ISO's
    ORG, PPL, PHY, TECH (Annex A clauses 5 to 8). Everything else sorts
    alphabetically, which is at least deterministic.
    """
    unique = {t for t in themes if t}
    known = [t for t in _THEME_ORDER if t in unique]
    rest = sorted(unique - set(known))
    return known + rest


#: ISO/IEC 27001's management-system clauses; never rows of a Statement of
#: Applicability (see `download_statement_of_applicability`).
SOA_EXCLUDED_THEME = "ISMS"


def control_sort_key(control_number: str) -> tuple:
    """Orders control numbers numerically rather than lexicographically.

    `ORDER BY control_number` is a string sort, so an ISO Statement of
    Applicability came out as A.5.1, A.5.10, A.5.11 … A.5.2 — immediately
    visible to an auditor and wrong in every framework whose controls are
    numbered with dots. Splitting on the separators and comparing the numeric
    segments as integers restores A.5.1 < A.5.2 < A.5.10.

    NIST CSF 2.0 is handled separately because its order is *not* derivable
    from the identifier. Sorting `GV.OC-01` as text gives the Functions in the
    order DE, GV, ID, PR, RC, RS and the Govern Categories as OC, OV, PO, RM,
    RR, SC — where NIST publishes GV, ID, PR, DE, RS, RC and OC, RM, RR, PO,
    OV, SC. Both orders carry meaning to an assessor, and neither is
    alphabetical, so `core.nist_csf` holds the published sequence and this
    consults it first. It returns keys of the same `(int, int, str)` shape as
    the generic path below, so the two compose in one sorted list.

    Non-numeric segments in other frameworks sort as text after any numeric
    segment at the same position, which keeps them grouped and stable.

    ISO/IEC 27001 Annex A (``A.5.1``) sorts after the standard's clauses
    (``4.1`` … ``10.2``). Stripping the ``A.`` alone would give clause 5.1 and
    control A.5.1 the same key and interleave the two; the leading group keeps
    Annex A together, and a list holding only Annex A controls sorts exactly as
    it did before.
    """
    if not control_number:
        return ()

    csf_key = nist_csf.sort_key(control_number)
    if csf_key is not None:
        return csf_key

    text = str(control_number).strip()
    annex_a = text.startswith("A.")
    cleaned = text.lstrip("A.").strip()
    parts = re.split(r"[.\-_]", cleaned)
    key: list = []
    for part in parts:
        if part.isdigit():
            key.append((0, int(part), ""))
        else:
            key.append((1, 0, part.lower()))
    return ((1, 0, ""),) + tuple(key) if annex_a else tuple(key)


class RolledFinding:
    """A control's single verdict, standing in for the findings behind it.

    Report generators read `.status` off whatever the finding map holds. They
    used to hold an arbitrary one of the control's findings — with twelve rules
    on ISO A.8.20 that meant eleven verdicts were discarded and whichever row
    the database returned last decided what the report said. This carries the
    rolled-up verdict instead while keeping the attribute surface the
    generators already use, and additionally exposes the reviewer's own inputs,
    which a Statement of Applicability has to print.
    """

    __slots__ = (
        "attested_by",
        "contributing",
        "evidence",
        "justification",
        "owner",
        "reviewed_at",
        "rule_id",
        "source",
        "status",
    )

    def __init__(self, status: str, findings: list):
        self.status = status
        self.contributing = findings
        attested = next((f for f in findings if f.source == "manual_attestation"), None)
        representative = attested or (findings[0] if findings else None)
        self.rule_id = next((f.rule_id for f in findings if f.rule_id), None)
        self.evidence = getattr(representative, "evidence", {}) or {}
        self.source = getattr(representative, "source", "auto_scan")
        self.justification = getattr(attested, "justification", None)
        self.owner = getattr(attested, "owner", None)
        self.attested_by = getattr(attested, "attested_by", None)
        self.reviewed_at = getattr(attested, "reviewed_at", None)


def rolled_up_control_findings(db: Session, org_id: str, control_ids: list) -> dict:
    """`{control_id: RolledFinding}` for every control that has any finding."""
    from core.compliance_tasks import roll_up_statuses

    if not control_ids:
        return {}

    grouped: dict = {}
    rows = (
        db.query(ComplianceFinding)
        .filter(
            ComplianceFinding.tenant_id == org_id,
            ComplianceFinding.control_id.in_(control_ids),
        )
        .all()
    )
    for f in rows:
        grouped.setdefault(f.control_id, []).append(f)

    out: dict = {}
    for control_id, findings in grouped.items():
        verdict = roll_up_statuses([(f.status, f.source) for f in findings])
        if verdict is not None:
            out[control_id] = RolledFinding(verdict, findings)
    return out


def rolled_up_control_status(db: Session, org_id: str, control_ids: list) -> dict:
    """One verdict per control, using the engine's own precedence rules.

    Every consumer that summarises findings by control — the dashboard, the
    SoA, the gap analysis — used to build `{f.control_id: f for f in findings}`
    and let the last row of an unordered query decide. They all call this now,
    so a control reports the same verdict wherever it is displayed.
    """
    from core.compliance_tasks import roll_up_statuses

    if not control_ids:
        return {}

    rows = (
        db.query(
            ComplianceFinding.control_id,
            ComplianceFinding.status,
            ComplianceFinding.source,
        )
        .filter(
            ComplianceFinding.tenant_id == org_id,
            ComplianceFinding.control_id.in_(control_ids),
        )
        .all()
    )

    grouped: dict = {}
    for control_id, finding_status, source in rows:
        grouped.setdefault(control_id, []).append((finding_status, source))

    return {
        control_id: roll_up_statuses(entries)
        for control_id, entries in grouped.items()
        if roll_up_statuses(entries) is not None
    }


# ─────────────────────────────────────────────────────────────────────────────
# 1. Framework Marketplace & Installation
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/marketplace")
def get_marketplace_frameworks(
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "read")),
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

    # Parked catalogues are not offered. They stay seeded — ISO's and NIST's
    # crosswalks resolve into them and `main.py`'s bootstrap treats a missing
    # one as damage to repair — but the marketplace is the one place a tenant
    # admin could turn a parked framework back on, so it lists only the active
    # ones. `active_framework_ids()` fixes the display order too; the query
    # above has no ORDER BY, so the card grid was in whatever order Postgres
    # returned.
    active_ids = list(compliance_frameworks.active_framework_ids())
    by_id = {fw.id: fw for fw in frameworks}

    # Loaded benchmarks are active but can never appear in a hardcoded tuple —
    # they arrive by `scripts/benchmarks/load_benchmark.py`, after this module
    # was written. They are discovered from what is actually in the catalogue
    # and appended in a stable order, so the shipped catalogues keep their
    # curated position and a benchmark does not silently fail to be listed
    # while scoring and producing findings behind the scenes.
    active_ids += sorted(
        fw.id
        for fw in frameworks
        if compliance_frameworks.is_benchmark_framework(fw.id)
        and fw.id not in active_ids
    )

    results = []
    for framework_id in active_ids:
        fw = by_id.get(framework_id)
        if not fw:
            continue
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

    return {
        "data": results,
        # The frontend builds its framework selectors from this rather than
        # from a hardcoded list of thirteen ids, so enabling a framework later
        # is a backend change alone.
        "active_framework_ids": list(active_ids),
        "parked_framework_ids": list(compliance_frameworks.parked_framework_ids()),
    }


@router.post("/marketplace/{framework_id}/install", status_code=status.HTTP_201_CREATED)
def install_marketplace_framework(
    framework_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "manage_frameworks")),
):
    """Install/enable a framework for the organization."""
    # A parked framework cannot be installed, or a tenant admin could bring one
    # back through the marketplace and then scan against a catalogue that is
    # not finished. Refused before the existence check so the answer is the
    # same whether or not the row happens to be seeded.
    require_active_framework(framework_id)

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

    # Link every active rule that covers a control of this framework, adding
    # any that are missing. The previous `if rules_linked == 0` guard meant the
    # baseline was populated exactly once: a framework that later gained rules
    # — as ISO 27001 just did for its twelve genuinely scannable controls —
    # never picked them up in an organisation that had already installed it.
    already_linked = {
        row[0]
        for row in db.query(CompliancePolicyRule.rule_id)
        .filter(CompliancePolicyRule.policy_id == default_policy.id)
        .all()
    }

    framework_rules = (
        db.query(ComplianceRule)
        .join(
            ComplianceRuleControl,
            ComplianceRuleControl.rule_id == ComplianceRule.id,
        )
        .join(
            ComplianceControl,
            ComplianceControl.id == ComplianceRuleControl.control_id,
        )
        .filter(
            ComplianceControl.framework_id == framework_id,
            ComplianceRule.status == "active",
        )
        .distinct()
        .all()
    )

    for r in framework_rules:
        if r.id not in already_linked:
            db.add(CompliancePolicyRule(policy_id=default_policy.id, rule_id=r.id))
            already_linked.add(r.id)

    log_audit_event(
        db, user, "install_framework", "framework", framework_id, status="success"
    )
    db.commit()
    return {"message": f"Successfully installed framework {fw.name}"}


@router.post("/marketplace/{framework_id}/uninstall", status_code=status.HTTP_200_OK)
def uninstall_marketplace_framework(
    framework_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "manage_frameworks")),
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
    log_audit_event(
        db, user, "uninstall_framework", "framework", framework_id, status="success"
    )
    db.commit()
    return {"message": "Framework uninstalled successfully"}


# ─────────────────────────────────────────────────────────────────────────────
# 2. Policy Baselines
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/policies")
def list_policies(
    framework_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "read")),
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
    user: CurrentUser = Depends(require_permission("compliance", "read")),
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
    request: Request,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "manage_rules")),
):
    """
    Update a compliance rule's verification parameters and severity levels.

    **Superadmin only, despite the `compliance:manage_rules` dependency.**

    `compliance_rules` has no `tenant_id`: it is a single global catalogue that
    every tenant on the installation is scored against. `manage_rules` is held
    by `org_admin` as well as `superadmin`, so before this check an
    administrator of one tenant could rewrite `check_definition`, `severity` or
    `severity_weight` on any of the catalogue's rules and silently change the
    compliance posture reported to every other tenant — weakening a control so
    their own org passes, or skewing everyone's score through the weights.

    That is a cross-tenant integrity flaw rather than a data leak, which is why
    it survived the org-scoping review: there is no `org_id` to filter on. The
    fix is to gate the writer, not the query.

    The role is checked here rather than by swapping the dependency so that
    `manage_rules` keeps working for the tenant-scoped compliance routes that
    legitimately use it.
    """
    if not has_permission(db, user, "audit.compliance.manage_shared_rules"):
        raise HTTPException(
            status_code=403,
            detail=(
                "Compliance rules are a shared catalogue used by every "
                "organisation on this installation; only a superadmin may "
                "change them."
            ),
        )

    rule = db.query(ComplianceRule).filter(ComplianceRule.id == id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    # Capture the previous definition before overwriting it. The model treats
    # rules as versioned and immutable (`rule_family_code` + `version_number`,
    # `superseded_by_rule_id`), so an in-place edit rewrites the basis on which
    # every historical finding for this rule was raised. Recording the old
    # values keeps that change reconstructible instead of invisible.
    before = {
        "check_definition": rule.check_definition,
        "severity": rule.severity,
        "severity_weight": rule.severity_weight,
    }

    rule.check_definition = payload.check_definition
    rule.severity = payload.severity.lower()
    rule.severity_weight = payload.severity_weight

    log_audit_event(
        db,
        user,
        "compliance.rule_updated",
        "compliance_rule",
        str(rule.id),
        {
            "rule_family_code": rule.rule_family_code,
            "version_number": rule.version_number,
            "status": rule.status,
            "before": before,
            "after": {
                "check_definition": rule.check_definition,
                "severity": rule.severity,
                "severity_weight": rule.severity_weight,
            },
        },
        request,
    )
    db.commit()
    return {"message": "Rule updated successfully"}


@router.post("/policies", status_code=status.HTTP_201_CREATED)
def create_policy_baseline(
    payload: PolicyCreate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "manage_rules")),
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

    # Every rule must map to a control *in this policy's framework*, or it
    # contributes nothing and the scan silently skips it. 495 rules in the
    # shipped catalogue have no control mapping at all; before this check a
    # policy built from one of them produced a foreign-key violation mid-scan,
    # which the finding writer then handled by rolling back the whole session
    # and discarding every finding the run had produced.
    unmapped = [
        r.id
        for r in rules
        if not db.query(ComplianceRuleControl.rule_id)
        .join(
            ComplianceControl,
            ComplianceControl.id == ComplianceRuleControl.control_id,
        )
        .filter(
            ComplianceRuleControl.rule_id == r.id,
            ComplianceControl.framework_id == payload.framework_id,
        )
        .first()
    ]
    if unmapped:
        raise HTTPException(
            status_code=400,
            detail=(
                "These rules are not mapped to any control in the selected "
                "framework and would never be evaluated: " + ", ".join(unmapped)
            ),
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

    log_audit_event(db, user, "create_policy", "policy", policy_id, status="success")
    db.commit()
    return {"message": "Policy baseline created successfully", "policy_id": policy_id}


# ─────────────────────────────────────────────────────────────────────────────
# 3. Trigger Scans
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/scans", status_code=status.HTTP_202_ACCEPTED)
# Dispatches a scanning run. Same class as the other scan-dispatch routes,
# which have carried 5/minute all along.
@limiter.limit("5/minute")
def trigger_compliance_scan(
    request: Request,
    response: Response,
    payload: ScanTrigger,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "scan")),
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

    rand_suffix = uuid.uuid4().hex[:4]
    run_id = f"csr_{user.org_id[:4]}_{datetime.now().strftime('%d%b%y_%H%M%S')}_{rand_suffix}"

    now = datetime.now(timezone.utc)
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
        # `created_at` is when the operator asked; `started_at` is set by the
        # worker when it picks the run up. Stamping started_at here made every
        # queued run look like it had already begun, which is also why a run
        # that died before starting had no usable timestamp at all.
        created_at=now,
    )
    db.add(new_run)
    log_audit_event(db, user, "trigger_scan", "scan_run", run_id, status="success")
    db.commit()

    # Dispatch to the Celery `compliance` queue. This used to go through
    # FastAPI's BackgroundTasks, which runs the evaluation inside the API
    # process: a scan over a large estate occupied an API worker for its whole
    # duration, had no retry, no visibility, and was lost outright if the
    # container restarted mid-run. The queue and a worker consuming it already
    # existed.
    #
    # If the broker is unreachable, fall back to in-process execution rather
    # than refusing the scan — a single-container deployment with no worker is
    # a supported way to run this product, and failing closed here would make
    # compliance scanning unavailable rather than merely slower.
    from core.compliance_tasks import run_scan_task

    dispatch = "celery"
    try:
        run_scan_task.delay(run_id, user.org_id)
    except Exception as exc:  # broker down, not configured, etc.
        log.warning(
            "Could not queue compliance scan %s (%s); running in-process.",
            run_id,
            exc,
        )
        background_tasks.add_task(run_scan_task, run_id, user.org_id)
        dispatch = "in_process"

    return {
        "message": "Scan run triggered successfully",
        "scan_run_id": run_id,
        "dispatch": dispatch,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 4. Findings & Attestations
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/findings")
def list_findings(
    framework_id: str | None = Query(None),
    status: str | None = Query(None),
    saq_profile: str | None = Query(None),
    cde_scope: str | None = Query(None),
    cde_scope_only: bool | None = Query(False),
    impact_level: str | None = Query(None),
    zero_trust_only: bool | None = Query(False),
    sdf_scope: str | None = Query(None),
    privacy_role: str | None = Query(None),
    purdue_level: str | None = Query(None),
    component_type: str | None = Query(None),
    sl_level: str | None = Query(None),
    bes_impact_level: str | None = Query(None),
    standard_number: str | None = Query(None),
    nis2_entity_type: str | None = Query(None),
    nis2_sector: str | None = Query(None),
    nis2_member_state: str | None = Query(None),
    limit: int = Query(10000, ge=1, le=50000),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "read")),
):
    """List compliance findings for the organization with control and rule details."""
    if framework_id and framework_id != "all":
        require_active_framework(framework_id)

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

    # One row per *check*, not one row per control.
    #
    # The distinct key used to be (asset_id, control_id), which collapsed every
    # rule mapped to a control down to whichever finding was seen last. A.8.20
    # carries twelve rules, so eleven failures per host were invisible in the
    # UI — un-remediable, un-waivable, un-exportable — while still counting
    # against the score. Adding rule_id keeps the original intent (one row per
    # check rather than one per historical scan run) and surfaces all of them.
    subq = (
        db.query(ComplianceFinding.id)
        .filter(ComplianceFinding.tenant_id == user.org_id)
        .distinct(
            ComplianceFinding.asset_id,
            ComplianceFinding.control_id,
            ComplianceFinding.rule_id,
        )
        .order_by(
            ComplianceFinding.asset_id,
            ComplianceFinding.control_id,
            ComplianceFinding.rule_id,
            ComplianceFinding.last_seen.desc(),
        )
        .subquery()
    )

    q = (
        db.query(ComplianceFinding, ComplianceControl, ComplianceRule, Asset)
        .outerjoin(
            ComplianceControl, ComplianceControl.id == ComplianceFinding.control_id
        )
        .outerjoin(ComplianceRule, ComplianceRule.id == ComplianceFinding.rule_id)
        .outerjoin(Asset, Asset.id == ComplianceFinding.asset_id)
        .filter(
            ComplianceFinding.id.in_(subq),
            ComplianceControl.framework_id.in_(enabled_fw_ids),
        )
    )

    if framework_id and framework_id != "all":
        q = q.filter(ComplianceControl.framework_id == framework_id)

    if status:
        q = q.filter(ComplianceFinding.status == status)

    if saq_profile and saq_profile != "all":
        q = q.filter(ComplianceControl.saq_profiles.contains([saq_profile]))

    if impact_level and impact_level != "all":
        q = q.filter(ComplianceControl.saq_profiles.contains([impact_level.upper()]))

    if zero_trust_only:
        q = q.filter(ComplianceControl.tags.contains(["zero_trust"]))

    if sdf_scope and sdf_scope != "all":
        q = q.filter(ComplianceControl.sdf_scope == sdf_scope)

    if privacy_role and privacy_role != "all":
        q = q.filter(ComplianceControl.privacy_role.in_([privacy_role, "both"]))

    if purdue_level and purdue_level != "all":
        q = q.filter(ComplianceControl.tags.contains([purdue_level.upper()]))

    if component_type and component_type != "all":
        q = q.filter(ComplianceControl.tags.contains([component_type.upper()]))

    if sl_level and sl_level != "all":
        q = q.filter(ComplianceControl.tags.contains([sl_level.upper()]))

    if bes_impact_level and bes_impact_level != "all":
        q = q.filter(ComplianceControl.tags.contains([bes_impact_level.capitalize()]))

    if standard_number and standard_number != "all":
        q = q.filter(ComplianceControl.tags.contains([standard_number.upper()]))

    if nis2_entity_type and nis2_entity_type != "all":
        q = q.filter(ComplianceControl.tags.contains([nis2_entity_type.capitalize()]))

    if nis2_sector and nis2_sector != "all":
        q = q.filter(ComplianceControl.tags.contains([nis2_sector.capitalize()]))

    if cde_scope:
        q = q.filter(ComplianceFinding.cde_scope == cde_scope)
    elif cde_scope_only:
        q = q.filter(ComplianceFinding.cde_scope.isnot(None))

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
                "control_number": control.control_number if control else None,
                "control_title": control.title if control else "Unknown Control",
                "control_description": control.description if control else None,
                "control_tags": control.tags if control else [],
                "framework_id": control.framework_id if control else None,
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
                # The engine writes a plain-English reason into the evidence
                # payload whenever a control could not be assessed ("No
                # 'offline_configuration' evidence has been collected for this
                # asset"). It was never surfaced, so `manual_review` reached the
                # operator with no explanation of what to do about it.
                "status_reason": (
                    f.evidence.get("message") if isinstance(f.evidence, dict) else None
                ),
                "justification": f.justification,
                "evidence_file_ids": f.evidence_file_ids or [],
                "next_review_at": (
                    f.next_review_at.isoformat() if f.next_review_at else None
                ),
                "control_evidence_checklist": (
                    control.evidence_checklist if control else []
                ),
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
    user: CurrentUser = Depends(require_permission("compliance", "attest")),
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

    # The *same* id the scan derives for this control's org-level placeholder.
    # These used to be two different ids, so attesting a control produced a
    # second org-level row rather than updating the placeholder, and the two
    # then competed in the score rollup — where `manual_review` outranked
    # `pass`, so the attestation was silently discarded. For ISO, where 63 of
    # 93 controls are attestation-only, that made most of the framework
    # impossible to comply with.
    from core.compliance_tasks import org_finding_id_for

    finding_id = org_finding_id_for(user.org_id, control_id)

    finding = (
        db.query(ComplianceFinding).filter(ComplianceFinding.id == finding_id).first()
    )
    now = datetime.now(timezone.utc)

    # Evidence files must belong to this tenant and this control. Without the
    # check a caller could attach another organisation's evidence to their own
    # attestation by guessing an id.
    file_ids = list(payload.evidence_file_ids or [])
    if file_ids:
        owned = {
            row[0]
            for row in db.query(ComplianceEvidenceFile.id)
            .filter(
                ComplianceEvidenceFile.id.in_(file_ids),
                ComplianceEvidenceFile.tenant_id == user.org_id,
                ComplianceEvidenceFile.control_id == control_id,
            )
            .all()
        }
        unknown = [fid for fid in file_ids if fid not in owned]
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Evidence files not found for this control: " + ", ".join(unknown)
                ),
            )

    evidence_payload = {
        "note": payload.note or "",
        "justification": payload.justification or "",
        "attested_at": now.isoformat(),
        "attested_by": user.id,
    }

    if not finding:
        finding = ComplianceFinding(
            id=finding_id,
            tenant_id=user.org_id,
            control_id=control_id,
            source="manual_attestation",
            status=payload.status,
            evidence=evidence_payload,
            evidence_file_ids=file_ids,
            justification=payload.justification,
            owner=payload.owner or user.id,
            next_review_at=payload.next_review_at,
            attested_by=user.id,
            reviewed_at=now,
            first_seen=now,
            last_seen=now,
        )
        db.add(finding)
    else:
        finding.source = "manual_attestation"
        finding.status = payload.status
        finding.evidence = evidence_payload
        finding.evidence_file_ids = file_ids
        finding.justification = payload.justification
        finding.owner = payload.owner or finding.owner or user.id
        finding.next_review_at = payload.next_review_at or finding.next_review_at
        finding.attested_by = user.id
        finding.reviewed_at = now
        finding.last_seen = now

    # Bind the uploaded files to the finding they now support.
    if file_ids:
        db.query(ComplianceEvidenceFile).filter(
            ComplianceEvidenceFile.id.in_(file_ids),
            ComplianceEvidenceFile.tenant_id == user.org_id,
        ).update({"finding_id": finding_id}, synchronize_session=False)

    # Log history trail
    history = ComplianceFindingHistory(
        id=f"cfh_{uuid.uuid4().hex[:24]}",
        finding_id=finding_id,
        status=payload.status,
        changed_by=user.id,
        source="manual_attestation",
        note=payload.note or "Manual attestation updated",
    )
    db.add(history)
    db.commit()

    # Recalculate cached framework score immediately upon attestation update.
    # The run id is carried over from the score row rather than nulled: passing
    # None used to overwrite `scan_run_id` with NULL, so an attestation erased
    # the score's link to the scan that produced the rest of it.
    from core.compliance_tasks import _calculate_compliance_score

    _calculate_compliance_score(
        db,
        user.org_id,
        ctrl.framework_id,
        None,
        _latest_run_id(db, user.org_id, ctrl.framework_id),
    )
    log_audit_event(db, user, "attest_control", "finding", finding_id, status="success")
    db.commit()

    return {"message": "Attestation recorded successfully", "finding_id": finding_id}


# ─────────────────────────────────────────────────────────────────────────────
# 4.2. Control Register
#
# The workspace could only reach a control through a *finding*, and only a
# finding whose status happened to be `manual_review`. A control that had never
# been scanned was therefore unreachable — for ISO 27001 that meant the
# reviewer could not see, let alone attest, most of Annex A, and the
# applicability decision that clause 6.1.3 is built around had no route through
# the product at all.
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/frameworks/{framework_id}/controls")
def list_framework_controls(
    framework_id: str,
    status: str | None = Query(None),
    theme: str | None = Query(None),
    scannability: str | None = Query(None),
    search: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "read")),
):
    """Every control of a framework with its current rolled-up verdict."""
    require_active_framework(framework_id)

    tf = (
        db.query(ComplianceTenantFramework)
        .filter_by(tenant_id=user.org_id, framework_id=framework_id, is_enabled=True)
        .first()
    )
    if not tf:
        raise HTTPException(
            status_code=404, detail="Framework is not installed for this organization."
        )

    query = db.query(ComplianceControl).filter(
        ComplianceControl.framework_id == framework_id
    )
    if theme and theme != "all":
        query = query.filter(ComplianceControl.theme == theme)
    if scannability and scannability != "all":
        query = query.filter(ComplianceControl.scannability == scannability)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                ComplianceControl.title.ilike(pattern),
                ComplianceControl.control_number.ilike(pattern),
                ComplianceControl.description.ilike(pattern),
            )
        )

    controls = query.all()
    control_ids = [c.id for c in controls]
    verdicts = rolled_up_control_status(db, user.org_id, control_ids)

    # The org-level attestation row carries the reviewer's own inputs —
    # justification, owner, review date, attached evidence — which the rolled-up
    # verdict deliberately does not.
    attestations = {
        f.control_id: f
        for f in db.query(ComplianceFinding)
        .filter(
            ComplianceFinding.tenant_id == user.org_id,
            ComplianceFinding.control_id.in_(control_ids),
            ComplianceFinding.asset_id.is_(None),
        )
        .all()
    }

    evidence_counts = dict(
        db.query(
            ComplianceEvidenceFile.control_id, func.count(ComplianceEvidenceFile.id)
        )
        .filter(
            ComplianceEvidenceFile.tenant_id == user.org_id,
            ComplianceEvidenceFile.control_id.in_(control_ids),
        )
        .group_by(ComplianceEvidenceFile.control_id)
        .all()
    )

    rows = []
    for c in controls:
        verdict = verdicts.get(c.id) or "not_assessed"
        if status and status != "all" and verdict != status:
            continue
        att = attestations.get(c.id)
        rows.append(
            {
                "control_id": c.id,
                "control_number": c.control_number,
                "title": c.title,
                "description": c.description,
                "theme": c.theme,
                # NIST CSF's hierarchy is Function ▸ Category ▸ Subcategory, and
                # `theme` alone carries only the two-letter Function code. The
                # register printed a bare "GV" against every Govern row, which
                # tells a reviewer neither which Function nor which Category
                # they are attesting within. Derived from the identifier rather
                # than stored, so it is correct for any framework whose controls
                # are CSF Subcategories and null everywhere else.
                "function": nist_csf.function_name_for(c.control_number),
                "category": (
                    c.control_number.partition("-")[0]
                    if nist_csf.is_csf_subcategory(c.control_number)
                    else None
                ),
                "category_name": nist_csf.category_name_for(c.control_number),
                "scannability": c.scannability,
                "scan_module_hint": c.scan_module_hint,
                "evidence_checklist": c.evidence_checklist or [],
                "crosswalk": c.crosswalk or [],
                "tags": c.tags or [],
                "status": verdict,
                "justification": att.justification if att else None,
                "owner": att.owner if att else None,
                "attested_by": att.attested_by if att else None,
                "reviewed_at": (
                    att.reviewed_at.isoformat() if att and att.reviewed_at else None
                ),
                "next_review_at": (
                    att.next_review_at.isoformat()
                    if att and att.next_review_at
                    else None
                ),
                "evidence_file_count": evidence_counts.get(c.id, 0),
            }
        )

    rows.sort(key=lambda r: control_sort_key(r["control_number"]))

    # Readiness, not a single percentage. "62% compliant" cannot distinguish a
    # framework nobody has looked at from one that was assessed and failed, and
    # for a certification workflow the actionable number is how many controls
    # still need a human.
    tally: dict = {}
    for r in rows:
        tally[r["status"]] = tally.get(r["status"], 0) + 1

    return {
        "framework_id": framework_id,
        "total": len(rows),
        "summary": {
            "passed": tally.get("pass", 0),
            "failed": tally.get("fail", 0),
            "not_applicable": tally.get("not_applicable", 0),
            "exception": tally.get("exception", 0),
            "awaiting_review": tally.get("manual_review", 0),
            "not_assessed": tally.get("not_assessed", 0),
        },
        "data": rows,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 4.3. Attestation Evidence Files
# ─────────────────────────────────────────────────────────────────────────────

# Deliberately conservative. Evidence is policy documents, screenshots, signed
# records and exported reports; nothing here needs to be executable, and an
# archive would let a caller smuggle content past the type check.
_ALLOWED_EVIDENCE_TYPES = {
    "application/pdf": ".pdf",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "text/plain": ".txt",
    "text/csv": ".csv",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
}
_MAX_EVIDENCE_BYTES = 25 * 1024 * 1024

# A per-tenant ceiling, because the per-file cap alone bounds nothing: an
# account holding `compliance:attest` could upload 25 MB in a loop until the
# API host's disk filled. Evidence is policy documents and screenshots, so 2 GB
# is far above any real workspace and still a bound. Raise it deliberately for
# a tenant that legitimately needs more.
_MAX_EVIDENCE_BYTES_PER_TENANT = int(
    os.environ.get("COMPLIANCE_EVIDENCE_TENANT_QUOTA_BYTES", 2 * 1024 * 1024 * 1024)
)


def _lock_tenant_evidence_quota(db: Session, tenant_id: str) -> None:
    """
    Take a transaction-scoped advisory lock covering one tenant's quota check.

    Postgres only. SQLite — which `config.py` falls back to when DATABASE_URL is
    unset — serialises writers at the database level anyway, so there is nothing
    to add there and nothing to fail over. Any other backend gets no lock and
    the pre-existing race; that is stated here rather than hidden, because a
    silent no-op is how a concurrency guard stops guarding.
    """
    if db.bind is None or db.bind.dialect.name != "postgresql":
        return
    from sqlalchemy import text

    # hashtext() gives a stable 32-bit key; the constant namespaces this lock
    # so it cannot collide with an advisory lock taken elsewhere.
    db.execute(
        text("SELECT pg_advisory_xact_lock(:ns, hashtext(:tenant))"),
        {"ns": 0x0E71DE17, "tenant": str(tenant_id)},
    )


def _evidence_root() -> str:
    """Base directory for stored evidence, configurable per deployment."""
    import os

    return os.environ.get(
        "COMPLIANCE_EVIDENCE_DIR", os.path.join("/app", "data", "compliance_evidence")
    )


@router.post("/controls/{control_id}/evidence", status_code=status.HTTP_201_CREATED)
@limiter.limit("20/minute")
async def upload_control_evidence(
    request: Request,
    response: Response,
    control_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "attest")),
):
    """Attach an audit evidence document to a control."""
    import hashlib

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
            detail="Cannot attach evidence for a disabled or uninstalled framework.",
        )

    content_type = (file.content_type or "").split(";")[0].strip().lower()
    if content_type not in _ALLOWED_EVIDENCE_TYPES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{content_type or 'unknown'}' is not an accepted evidence type. "
                "Upload a PDF, image, text, CSV, Word or Excel document."
            ),
        )

    # Read with a cap rather than trusting a declared length: the size is only
    # known once the bytes are in hand, and an unbounded read is how an upload
    # endpoint becomes a memory exhaustion primitive.
    try:
        payload = await read_capped_async(file, _MAX_EVIDENCE_BYTES)
    except UploadTooLarge:
        raise HTTPException(
            status_code=413,
            detail=f"Evidence files are limited to {_MAX_EVIDENCE_BYTES // (1024 * 1024)} MB.",
        )
    if not payload:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")

    # The content type above is the one the *client* declared in the multipart
    # part header. Nothing derived it from the bytes, so `malware.exe` renamed
    # to `malware.pdf` arrives declared `application/pdf` and satisfied the
    # whitelist. Confirm the payload's own signature agrees before storing it.
    try:
        assert_content_matches(payload, content_type)
    except UploadTypeRejected as exc:
        raise HTTPException(status_code=400, detail=exc.message)

    # Evidence is handed back to other people in the tenant, which makes this a
    # file-sharing surface whether or not it was designed as one. No-ops unless
    # CLAMAV_HOST is configured; see core/upload_guard.py for the fail-open
    # rationale and how to make it fail closed.
    try:
        av_verdict = scan_for_malware(payload, context=f"evidence upload by {user.id}")
    except MalwareDetected as exc:
        _audit_refusal(
            user, "upload_evidence", "evidence", control_id, "blocked_malware"
        )
        raise HTTPException(
            status_code=400,
            detail=f"The uploaded file was rejected by malware scanning: {exc.signature}",
        )
    except MalwareScanUnavailable as exc:
        # 503, not 400: the file is not accused of anything — the scanner this
        # deployment requires could not answer, so the upload is refused rather
        # than stored unscanned. Distinct status so a client can retry.
        _audit_refusal(
            user, "upload_evidence", "evidence", control_id, "scanner_unavailable"
        )
        raise HTTPException(
            status_code=503,
            detail=(
                "Evidence cannot be accepted right now: malware scanning is "
                f"unavailable ({exc}). Try again shortly."
            ),
        )

    # A per-file cap bounds one request; it does not bound a loop of them.
    #
    # Serialise the check per tenant before summing. SUM-then-compare-then-write
    # is read-modify-write across three statements: two concurrent uploads each
    # read the same total, each conclude they fit, and the quota is exceeded by
    # whatever the second one carried. A transaction-scoped advisory lock keyed
    # on the tenant makes the read and the write one critical section; Postgres
    # releases it at COMMIT or ROLLBACK, so no unlock path can be missed.
    #
    # Evidence upload is a low-frequency operation, so serialising a tenant's
    # concurrent uploads costs nothing measurable.
    _lock_tenant_evidence_quota(db, user.org_id)

    used = (
        db.query(func.coalesce(func.sum(ComplianceEvidenceFile.size_bytes), 0))
        .filter(ComplianceEvidenceFile.tenant_id == user.org_id)
        .scalar()
        or 0
    )
    if used + len(payload) > _MAX_EVIDENCE_BYTES_PER_TENANT:
        raise HTTPException(
            status_code=413,
            detail=(
                "This workspace has reached its evidence storage quota of "
                f"{_MAX_EVIDENCE_BYTES_PER_TENANT // (1024 * 1024)} MB. "
                "Remove superseded evidence or ask an administrator to raise it."
            ),
        )

    file_id = f"cef_{uuid.uuid4().hex[:24]}"
    digest = hashlib.sha256(payload).hexdigest()

    # The stored name is derived entirely from the generated id and the
    # extension implied by the accepted content type — never from the
    # user-supplied filename, which is attacker-controlled and would otherwise
    # let `../` escape the tenant directory.
    extension = _ALLOWED_EVIDENCE_TYPES[content_type]
    tenant_dir = os.path.join(_evidence_root(), user.org_id)
    os.makedirs(tenant_dir, exist_ok=True)
    storage_path = os.path.join(tenant_dir, f"{file_id}{extension}")
    # Nothing above this line has touched the disk. Every rejection — wrong
    # type, wrong content, malware detected, scanner unavailable, over quota —
    # returns before the first byte is written, so a refused upload is never
    # briefly present in storage. Scan-then-persist, never persist-then-scan.
    with open(storage_path, "wb") as fh:
        fh.write(payload)

    try:
        record = ComplianceEvidenceFile(
            id=file_id,
            tenant_id=user.org_id,
            control_id=control_id,
            # A display name only — the storage path above is UUID-derived and
            # never touches this. `os.path.basename()` alone was not enough: the
            # API runs on Linux, where `\` is not a separator, and it strips
            # neither quotes nor control characters, both of which reach a
            # response header on download.
            filename=sanitize_filename(file.filename, fallback=f"evidence{extension}"),
            content_type=content_type,
            size_bytes=len(payload),
            sha256=digest,
            storage_path=storage_path,
            uploaded_by=user.id,
            uploaded_at=datetime.now(timezone.utc),
        )
        db.add(record)
        db.commit()
    except Exception:
        # The bytes are on disk and the row that points at them does not exist.
        # An orphan here is worse than it looks: it is unreachable through the
        # API, and the quota sums `size_bytes` over *rows*, so it consumes disk
        # that nothing accounts for and nothing will ever reclaim.
        db.rollback()
        try:
            os.unlink(storage_path)
        except OSError:
            log.warning(
                "Orphaned evidence file left on disk after a failed commit: %s",
                storage_path,
            )
        raise

    # Committed explicitly. The commit above persisted the evidence row and
    # ended that transaction, so this event begins a new one that nothing else
    # would ever close — the handler returns straight after, and `get_db`
    # closes without committing, discarding it.
    log_audit_event(db, user, "upload_evidence", "evidence", file_id, status="success")
    db.commit()

    if av_verdict != "clean":
        # An auditor reading this trail needs to know the difference between
        # "scanned and clean" and "never scanned".
        log.info(
            "Evidence %s stored with malware scan verdict: %s", file_id, av_verdict
        )
    return {
        "id": file_id,
        "filename": record.filename,
        "content_type": content_type,
        "size_bytes": record.size_bytes,
        "sha256": digest,
        "malware_scan": av_verdict,
        "uploaded_at": record.uploaded_at.isoformat(),
    }


@router.get("/controls/{control_id}/evidence")
def list_control_evidence(
    control_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "read")),
):
    """List the evidence documents attached to a control."""
    files = (
        db.query(ComplianceEvidenceFile)
        .filter(
            ComplianceEvidenceFile.tenant_id == user.org_id,
            ComplianceEvidenceFile.control_id == control_id,
        )
        .order_by(ComplianceEvidenceFile.uploaded_at.desc())
        .all()
    )
    return {
        "data": [
            {
                "id": f.id,
                "filename": f.filename,
                "content_type": f.content_type,
                "size_bytes": f.size_bytes,
                "sha256": f.sha256,
                "uploaded_by": f.uploaded_by,
                "uploaded_at": f.uploaded_at.isoformat(),
            }
            for f in files
        ]
    }


@router.get("/evidence/{file_id}/download")
def download_control_evidence(
    file_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "read")),
):
    """Download one evidence document."""
    import os

    record = (
        db.query(ComplianceEvidenceFile)
        .filter(
            ComplianceEvidenceFile.id == file_id,
            ComplianceEvidenceFile.tenant_id == user.org_id,
        )
        .first()
    )
    if not record or not os.path.exists(record.storage_path):
        raise HTTPException(status_code=404, detail="Evidence file not found")

    # FileResponse streams from disk rather than reading the whole file into
    # memory first. One 25 MB read is survivable; a dozen concurrent auditors
    # downloading evidence at once is what made this worth changing.
    #
    # The Content-Disposition is built by upload_guard, not by f-string. The
    # filename is user-supplied, and interpolating it into a quoted-string
    # header let a `"` in the name reshape the header.
    return FileResponse(
        path=record.storage_path,
        media_type=record.content_type,
        headers={
            "Content-Disposition": content_disposition(record.filename),
            "X-Evidence-SHA256": record.sha256,
        },
    )


@router.delete("/evidence/{file_id}", status_code=status.HTTP_200_OK)
def delete_control_evidence(
    file_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "attest")),
):
    """Remove an evidence document."""
    import os

    record = (
        db.query(ComplianceEvidenceFile)
        .filter(
            ComplianceEvidenceFile.id == file_id,
            ComplianceEvidenceFile.tenant_id == user.org_id,
        )
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="Evidence file not found")

    try:
        if os.path.exists(record.storage_path):
            os.remove(record.storage_path)
    except OSError:
        log.warning("Could not remove evidence file from disk: %s", record.storage_path)

    db.delete(record)
    log_audit_event(db, user, "delete_evidence", "evidence", file_id, status="success")
    db.commit()
    return {"message": "Evidence file removed"}


# ─────────────────────────────────────────────────────────────────────────────
# 4.4. Scan Run Status & History
#
# There was no way to ask how a scan was going. The workspace polled a blind
# thirty-second timer and then stopped, so a run that ended `failed` was
# indistinguishable from one still in progress, and nothing ever surfaced the
# reason.
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/scans")
def list_scan_runs(
    framework_id: str | None = Query(None),
    limit: int = Query(25, ge=1, le=200),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "read")),
):
    """Compliance scan history, most recent first."""
    if framework_id and framework_id != "all":
        require_active_framework(framework_id)

    query = db.query(ComplianceScanRun).filter(
        ComplianceScanRun.tenant_id == user.org_id
    )
    if framework_id and framework_id != "all":
        query = query.filter(ComplianceScanRun.framework_id == framework_id)
    else:
        # Historical runs for a framework that has since been parked would
        # otherwise still be listed, and each row carries a framework name and
        # a score the workspace can no longer open. Scoped to the frameworks
        # this installation offers, like every other listing here.
        # Excluded by what is parked rather than included by what is active:
        # the active set is a fixed tuple, and a loaded benchmark is active
        # without being in it. Filtering by the parked list admits both.
        query = query.filter(
            ~ComplianceScanRun.framework_id.in_(
                compliance_frameworks.parked_framework_ids()
            )
        )

    runs = query.order_by(ComplianceScanRun.created_at.desc()).limit(limit).all()
    return {"data": [_serialize_run(db, r) for r in runs]}


@router.get("/scans/{run_id}")
def get_scan_run(
    run_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "read")),
):
    """Status of one compliance scan run."""
    run = (
        db.query(ComplianceScanRun)
        .filter(
            ComplianceScanRun.id == run_id,
            ComplianceScanRun.tenant_id == user.org_id,
        )
        .first()
    )
    if not run:
        raise HTTPException(status_code=404, detail="Scan run not found")
    # A run belonging to a framework this installation has parked is history
    # the workspace can no longer act on; the same guard the rest of the module
    # applies.
    require_active_framework(run.framework_id)
    return _serialize_run(db, run)


def _serialize_run(db: Session, run: ComplianceScanRun) -> dict:
    findings = (
        db.query(ComplianceFinding.status, func.count(ComplianceFinding.id))
        .filter(ComplianceFinding.scan_run_id == run.id)
        .group_by(ComplianceFinding.status)
        .all()
    )
    return {
        "id": run.id,
        "framework_id": run.framework_id,
        "policy_id": run.policy_id,
        "schedule_id": run.schedule_id,
        "status": run.status,
        "initiated_by": run.initiated_by,
        "scope": run.scope,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "error_message": run.error_message,
        "finding_counts": {status: count for status, count in findings},
    }


# ─────────────────────────────────────────────────────────────────────────────
# 4.6. Scan Schedules
#
# `compliance_scan_schedules` has existed since the first compliance migration,
# Celery beat has polled it every sixty seconds, and `manage_schedules` has been
# a granted permission — with no endpoint that could create a row. Continuous
# assessment was unreachable end to end.
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/schedules", status_code=status.HTTP_201_CREATED)
def create_scan_schedule(
    payload: ScheduleCreate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "manage_schedules")),
):
    """Create a recurring compliance scan."""
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

    schedule_id = f"csh_{uuid.uuid4().hex[:24]}"
    schedule = ComplianceScanSchedule(
        id=schedule_id,
        tenant_id=user.org_id,
        framework_id=payload.framework_id,
        policy_id=payload.policy_id,
        scope={
            "asset_ids": payload.asset_ids or [],
            "asset_tags": payload.asset_tags or [],
        },
        frequency=payload.frequency,
        notify_on=payload.notify_on,
        notify_channels=payload.notify_channels or [],
        is_active=True,
        # Due immediately on the next beat tick unless the caller says
        # otherwise, so a new schedule visibly does something.
        next_run_at=payload.first_run_at or datetime.now(timezone.utc),
    )
    db.add(schedule)
    log_audit_event(
        db, user, "create_schedule", "schedule", schedule_id, status="success"
    )
    db.commit()
    return {"message": "Schedule created", "schedule_id": schedule_id}


@router.get("/schedules")
def list_scan_schedules(
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "read")),
):
    """List this organization's compliance scan schedules."""
    # A schedule survives its framework being parked. `run_scheduled_scans`
    # now skips it, so listing it would offer an edit button on something that
    # will never fire.
    rows = (
        db.query(ComplianceScanSchedule)
        .filter(
            ComplianceScanSchedule.tenant_id == user.org_id,
            # See the scan-run listing above: parked-exclusion rather than
            # active-inclusion, so a loaded benchmark's schedules are visible.
            ~ComplianceScanSchedule.framework_id.in_(
                compliance_frameworks.parked_framework_ids()
            ),
        )
        .all()
    )
    return {
        "data": [
            {
                "id": s.id,
                "framework_id": s.framework_id,
                "policy_id": s.policy_id,
                "scope": s.scope,
                "frequency": s.frequency,
                "notify_on": s.notify_on,
                "notify_channels": s.notify_channels,
                "is_active": s.is_active,
                "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
                "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
            }
            for s in rows
        ]
    }


@router.patch("/schedules/{schedule_id}")
def update_scan_schedule(
    schedule_id: str,
    payload: ScheduleUpdate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "manage_schedules")),
):
    """Pause, resume or re-time a compliance scan schedule."""
    schedule = (
        db.query(ComplianceScanSchedule)
        .filter(
            ComplianceScanSchedule.id == schedule_id,
            ComplianceScanSchedule.tenant_id == user.org_id,
        )
        .first()
    )
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    if payload.is_active is not None:
        schedule.is_active = payload.is_active
    if payload.frequency is not None:
        schedule.frequency = payload.frequency
    if payload.notify_on is not None:
        schedule.notify_on = payload.notify_on
    if payload.notify_channels is not None:
        schedule.notify_channels = payload.notify_channels

    log_audit_event(
        db, user, "update_schedule", "schedule", schedule_id, status="success"
    )
    db.commit()
    return {"message": "Schedule updated"}


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_200_OK)
def delete_scan_schedule(
    schedule_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "manage_schedules")),
):
    """Remove a compliance scan schedule."""
    schedule = (
        db.query(ComplianceScanSchedule)
        .filter(
            ComplianceScanSchedule.id == schedule_id,
            ComplianceScanSchedule.tenant_id == user.org_id,
        )
        .first()
    )
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    db.delete(schedule)
    log_audit_event(
        db, user, "delete_schedule", "schedule", schedule_id, status="success"
    )
    db.commit()
    return {"message": "Schedule removed"}


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
    user: CurrentUser = Depends(
        require_permission("compliance", "manage_integrations")
    ),
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
    log_audit_event(
        db, user, "create_credential", "credential", cred_id, status="success"
    )
    db.commit()
    db.refresh(new_cred)
    return new_cred


@router.get("/credentials", response_model=list[CredentialResponse])
def list_credentials(
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "read")),
):
    """List registered target credentials (excluding passwords/private keys)."""
    creds = db.query(ComplianceCredential).filter_by(tenant_id=user.org_id).all()
    return creds


@router.delete("/credentials/{id}", status_code=status.HTTP_200_OK)
def delete_credential(
    id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(
        require_permission("compliance", "manage_integrations")
    ),
):
    """Delete a registered credential."""
    cred = (
        db.query(ComplianceCredential).filter_by(id=id, tenant_id=user.org_id).first()
    )
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    db.delete(cred)
    log_audit_event(db, user, "delete_credential", "credential", id, status="success")
    db.commit()
    return {"message": "Credential deleted successfully"}


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
    user: CurrentUser = Depends(require_permission("compliance", "remediate")),
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


# ─────────────────────────────────────────────────────────────────────────────
# 5.5. Maker-Checker Remediation Queue
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/remediations/requests")
def list_remediation_requests(
    status: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "read")),
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
    user: CurrentUser = Depends(require_permission("compliance", "approve_exception")),
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
    user: CurrentUser = Depends(require_permission("compliance", "remediate")),
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
    user: CurrentUser = Depends(require_permission("compliance", "remediate")),
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


# ─────────────────────────────────────────────────────────────────────────────
# 6. Exception Waivers & Approvals
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/findings/{id}/exception", status_code=status.HTTP_201_CREATED)
def request_exception_waiver(
    id: str,
    payload: ExceptionRequest,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "attest")),
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
    log_audit_event(db, user, "request_waiver", "exception", exc_id, status="success")
    db.commit()

    return {"message": "Exception request submitted", "exception_id": exc_id}


@router.patch("/exceptions/{id}")
def approve_exception_waiver(
    id: str,
    payload: ExceptionApproval,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "approve_exception")),
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

    log_audit_event(db, user, "approve_waiver", "exception", id, status="success")
    db.commit()
    return {"message": f"Waiver request {payload.status} successfully"}


# ─────────────────────────────────────────────────────────────────────────────
# 7. Dashboard Summaries
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/summary")
def get_dashboard_summary(
    framework_id: str | None = Query(None),
    saq_profile: str | None = Query(None),
    cde_scope: str | None = Query(None),
    cde_scope_only: bool | None = Query(False),
    impact_level: str | None = Query(None),
    zero_trust_only: bool | None = Query(False),
    sdf_scope: str | None = Query(None),
    privacy_role: str | None = Query(None),
    purdue_level: str | None = Query(None),
    component_type: str | None = Query(None),
    sl_level: str | None = Query(None),
    bes_impact_level: str | None = Query(None),
    standard_number: str | None = Query(None),
    nis2_entity_type: str | None = Query(None),
    nis2_sector: str | None = Query(None),
    nis2_member_state: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "read")),
):
    """Retrieve compliance summary statistics and quadrant metrics."""
    # An explicit framework must be one this installation offers. Left
    # unguarded, `?framework_id=cfw_nis2` returned a scored dashboard for a
    # parked catalogue. `None` and "all" fall through to the tenant's enabled
    # set below, which is already the active pair.
    if framework_id and framework_id != "all":
        require_active_framework(framework_id)

    # Filter scores by enabled frameworks
    enabled_fw_subquery = (
        db.query(ComplianceTenantFramework.framework_id)
        .filter(
            ComplianceTenantFramework.tenant_id == user.org_id,
            ComplianceTenantFramework.is_enabled == True,
        )
        .scalar_subquery()
    )

    # Apply framework_id query parameter filter dynamically
    if framework_id and framework_id != "all":
        target_fws = [framework_id]
    else:
        # Resolve all enabled frameworks
        enabled_fws_list = (
            db.query(ComplianceTenantFramework.framework_id)
            .filter(
                ComplianceTenantFramework.tenant_id == user.org_id,
                ComplianceTenantFramework.is_enabled == True,
            )
            .all()
        )
        target_fws = [r[0] for r in enabled_fws_list]

    if (
        (saq_profile and saq_profile != "all")
        or cde_scope
        or cde_scope_only
        or (impact_level and impact_level != "all")
        or zero_trust_only
        or (sdf_scope and sdf_scope != "all")
        or (privacy_role and privacy_role != "all")
        or (purdue_level and purdue_level != "all")
        or (component_type and component_type != "all")
        or (sl_level and sl_level != "all")
        or (bes_impact_level and bes_impact_level != "all")
        or (standard_number and standard_number != "all")
        or (nis2_entity_type and nis2_entity_type != "all")
        or (nis2_sector and nis2_sector != "all")
        or (nis2_member_state and nis2_member_state != "all")
    ):
        # Dynamically calculate overall scores and quadrant scores based on the filters
        control_query = db.query(ComplianceControl).filter(
            ComplianceControl.framework_id.in_(target_fws)
        )
        if saq_profile and saq_profile != "all":
            control_query = control_query.filter(
                ComplianceControl.saq_profiles.contains([saq_profile])
            )
        if impact_level and impact_level != "all":
            control_query = control_query.filter(
                ComplianceControl.saq_profiles.contains([impact_level.upper()])
            )
        if zero_trust_only:
            control_query = control_query.filter(
                ComplianceControl.tags.contains(["zero_trust"])
            )
        # Apply DPDP SDF scope filter on controls
        if sdf_scope and sdf_scope != "all":
            control_query = control_query.filter(
                ComplianceControl.sdf_scope == sdf_scope
            )
        # Apply GDPR privacy role filter on controls
        if privacy_role and privacy_role != "all":
            control_query = control_query.filter(
                ComplianceControl.privacy_role.in_([privacy_role, "both"])
            )
        if purdue_level and purdue_level != "all":
            control_query = control_query.filter(
                ComplianceControl.tags.contains([purdue_level.upper()])
            )
        if component_type and component_type != "all":
            control_query = control_query.filter(
                ComplianceControl.tags.contains([component_type.upper()])
            )
        if sl_level and sl_level != "all":
            control_query = control_query.filter(
                ComplianceControl.tags.contains([sl_level.upper()])
            )
        if bes_impact_level and bes_impact_level != "all":
            control_query = control_query.filter(
                ComplianceControl.tags.contains([bes_impact_level.capitalize()])
            )
        if standard_number and standard_number != "all":
            control_query = control_query.filter(
                ComplianceControl.tags.contains([standard_number.upper()])
            )
        if nis2_entity_type and nis2_entity_type != "all":
            control_query = control_query.filter(
                ComplianceControl.tags.contains([nis2_entity_type.capitalize()])
            )
        if nis2_sector and nis2_sector != "all":
            control_query = control_query.filter(
                ComplianceControl.tags.contains([nis2_sector.capitalize()])
            )

        controls = control_query.all()
        if not controls:
            return {
                "score_pct": 0.0,
                "weighted_score_pct": 0.0,
                "quadrant_scores": {},
                "kpis": {"total": 0, "passed": 0, "failed": 0, "exceptions": 0},
            }

        control_ids = [c.id for c in controls]

        # One rolled-up verdict per control, through the shared precedence
        # table — the previous last-wins dict let whichever finding the
        # database returned last decide the control, so a filtered dashboard
        # could disagree with the unfiltered one about the same control.
        from core.compliance_tasks import roll_up_statuses

        finding_query = db.query(ComplianceFinding).filter(
            ComplianceFinding.tenant_id == user.org_id,
            ComplianceFinding.control_id.in_(control_ids),
        )

        if cde_scope:
            finding_query = finding_query.filter(
                ComplianceFinding.cde_scope == cde_scope
            )
        elif cde_scope_only:
            finding_query = finding_query.filter(
                ComplianceFinding.cde_scope.isnot(None)
            )

        grouped: dict = {}
        for f in finding_query.all():
            grouped.setdefault(f.control_id, []).append((f.status, f.source))
        verdicts = {cid: roll_up_statuses(entries) for cid, entries in grouped.items()}

        def _verdicts_for(subset):
            return [verdicts.get(c.id) for c in subset]

        def _score(subset):
            vs = _verdicts_for(subset)
            p = sum(1 for v in vs if v in ("pass", "exception"))
            applicable_n = sum(1 for v in vs if v != "not_applicable")
            return (round((p / applicable_n) * 100, 2) if applicable_n else 0.0), p

        total = len(controls)
        all_verdicts = _verdicts_for(controls)
        score_pct, passed = _score(controls)
        failed = sum(1 for v in all_verdicts if v in ("fail", "pending_reverify"))
        exceptions = sum(1 for v in all_verdicts if v == "exception")
        assessed = sum(
            1 for v in all_verdicts if v is not None and v != "manual_review"
        )

        quadrants = {}
        for theme in _ordered_themes({c.theme for c in controls if c.theme}):
            quadrants[theme] = _score([c for c in controls if c.theme == theme])[0]

        return {
            "score_pct": score_pct,
            # Reported as equal to the unweighted score and labelled as such.
            # This branch has no per-rule severity in hand, and returning the
            # unweighted number under the name "weighted" silently claimed a
            # risk weighting that had not been applied.
            "weighted_score_pct": score_pct,
            "weighted_available": False,
            "quadrant_scores": quadrants,
            "kpis": {
                "total": total,
                "passed": passed,
                "failed": failed,
                "exceptions": exceptions,
                # Coverage and conformity are different questions and a single
                # percentage cannot answer both: an unscanned framework and a
                # badly-failing one both read as a low score.
                "assessed": assessed,
                "not_assessed": total - assessed,
            },
        }

    # Apply framework_id query parameter filter dynamically
    if framework_id and framework_id != "all":
        target_fws = [framework_id]
    else:
        target_fws = enabled_fw_subquery

    # Resolve default themes directly from ComplianceControl catalog for target frameworks
    ctrl_themes_rows = (
        db.query(ComplianceControl.theme)
        .filter(ComplianceControl.framework_id.in_(target_fws))
        .distinct()
        .all()
    )
    default_themes = _ordered_themes([t[0] for t in ctrl_themes_rows if t[0]])
    if not default_themes:
        default_themes = ["ORG", "PPL", "PHY", "TECH"]

    total_controls_count = (
        db.query(func.count(ComplianceControl.id))
        .filter(ComplianceControl.framework_id.in_(target_fws))
        .scalar()
        or 0
    )

    scores = (
        db.query(ComplianceScore)
        .filter(
            ComplianceScore.tenant_id == user.org_id,
            ComplianceScore.asset_id == None,  # Org-level summaries
            ComplianceScore.theme
            == None,  # Exclude quadrant scores from overall framework averages
            ComplianceScore.framework_id.in_(target_fws),
        )
        .all()
    )

    # Default baseline if no scores are populated yet for target framework.
    # Every control is *unassessed*, not failed — the KPI keys have to say so,
    # or a newly installed framework is indistinguishable from one that was
    # scanned and failed outright.
    if not scores:
        return {
            "score_pct": 0.00,
            "weighted_score_pct": 0.00,
            "weighted_available": False,
            "quadrant_scores": {t: 0.0 for t in default_themes},
            "kpis": {
                "total": total_controls_count,
                "passed": 0,
                "failed": 0,
                "exceptions": 0,
                "not_applicable": 0,
                "assessed": 0,
                "not_assessed": total_controls_count,
            },
        }

    # Aggregate average score percentage across enabled frameworks
    avg_score = sum(float(s.score_pct) for s in scores) / len(scores)
    avg_weighted = sum(float(s.weighted_score_pct) for s in scores) / len(scores)

    # Resolve dynamic theme scores across enabled tenant frameworks
    active_themes = (
        db.query(ComplianceScore.theme)
        .filter(
            ComplianceScore.tenant_id == user.org_id,
            ComplianceScore.asset_id == None,
            ComplianceScore.theme != None,
            ComplianceScore.framework_id.in_(target_fws),
        )
        .distinct()
        .all()
    )
    theme_codes = _ordered_themes([t[0] for t in active_themes if t[0]])
    if not theme_codes:
        theme_codes = _ordered_themes(default_themes)

    quadrants = {q_code: 0.0 for q_code in theme_codes}
    for q_code in theme_codes:
        q_scores = (
            db.query(ComplianceScore)
            .filter(
                ComplianceScore.tenant_id == user.org_id,
                ComplianceScore.asset_id == None,
                ComplianceScore.theme == q_code,
                ComplianceScore.framework_id.in_(target_fws),
            )
            .all()
        )
        if q_scores:
            quadrants[q_code] = round(
                sum(float(s.score_pct) for s in q_scores) / len(q_scores), 2
            )

    # Compute sum totals
    total = sum(s.total_controls for s in scores)
    passed = sum(s.pass_count for s in scores)
    failed = sum(s.fail_count for s in scores)
    # `pending_count` is controls that reached no verdict plus those awaiting a
    # human. Reporting it is not cosmetic: on a freshly installed framework
    # total/passed/failed reads 106/0/0 at 0%, which is indistinguishable from
    # a framework that was assessed and failed everything. NIST CSF makes that
    # acute — 79 of its 106 Subcategories are attestation-only, so an untouched
    # installation is *expected* to sit at 0% until a reviewer works through
    # them, and the dashboard has to be able to say so. The filtered branch
    # above already returns these two keys; this one did not, so the same
    # framework reported a different KPI shape depending on whether a filter
    # happened to be applied.
    pending = sum(s.pending_count or 0 for s in scores)
    not_applicable = sum(s.na_count or 0 for s in scores)

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
            ComplianceControl.framework_id.in_(target_fws),
        )
        .count()
    )

    return {
        "score_pct": round(avg_score, 2),
        "weighted_score_pct": round(avg_weighted, 2),
        "weighted_available": True,
        "quadrant_scores": quadrants,
        "kpis": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "exceptions": exceptions,
            "not_applicable": not_applicable,
            "assessed": max(total - pending, 0),
            "not_assessed": pending,
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# 8. Report Exporting (SoA & Executive PDFs / DOCX)
# ─────────────────────────────────────────────────────────────────────────────

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

try:
    import docx
    from docx import Document
except ImportError:
    docx = None
    Document = None


def _verdict_of(findings_map: dict, control_id: str) -> str:
    """Reads a control's verdict from either a status map or a finding map.

    Twelve report endpoints built `{f.control_id: f for f in findings}` and let
    the last row of an unordered query decide the control. They now pass the
    rolled-up status map from `rolled_up_control_status`, but the accessor
    tolerates the old shape so a caller that has not been converted still
    renders rather than raising.
    """
    value = findings_map.get(control_id)
    if value is None:
        return "PENDING"
    if isinstance(value, str):
        return value.upper()
    return str(getattr(value, "status", "PENDING")).upper()


# ─────────────────────────────────────────────────────────────────────────────
# Statement of Applicability
#
# ISO/IEC 27001:2022 clause 6.1.3(d) requires the SoA to state, for every
# control: whether it is applicable, the justification for including it, whether
# it is implemented, and the justification for excluding it if it is not. The
# previous export carried none of the four — it was a five-column control status
# table (id, name, category, scan mode, verdict) labelled "SoA", which is not an
# artefact a certification body can accept. It also had no organisation name, no
# generation date and no approver.
# ─────────────────────────────────────────────────────────────────────────────

# How a rolled-up verdict maps onto the two columns an SoA actually asks for.
# `not_applicable` is the only status that makes a control excluded; everything
# else means the organisation has decided the control applies, and the question
# is then whether it is implemented yet.
_SOA_APPLICABILITY = {
    "not_applicable": ("No", "Excluded"),
    "pass": ("Yes", "Implemented"),
    "exception": ("Yes", "Implemented (compensating control)"),
    "fail": ("Yes", "Not implemented"),
    "pending_reverify": ("Yes", "Remediation in progress"),
    "remediation_applied": ("Yes", "Remediation applied, awaiting verification"),
    "manual_review": ("Yes", "Awaiting review"),
}


def _soa_row(control, rolled) -> dict:
    """Builds the SoA columns for one control."""
    verdict = getattr(rolled, "status", None) or "not_assessed"
    applicable, implementation = _SOA_APPLICABILITY.get(
        verdict, ("Yes", "Not assessed")
    )

    justification = getattr(rolled, "justification", None)
    if not justification:
        if verdict == "not_applicable":
            # An exclusion with no recorded reason is a finding in its own
            # right, and saying so in the document is more useful than leaving
            # the cell blank for the auditor to discover.
            justification = (
                "NOT RECORDED — an exclusion requires a documented justification."
            )
        else:
            # For an included control the standard's own requirement is a
            # reason for inclusion; the control's objective is that reason
            # unless the organisation has written a more specific one.
            justification = control.description or control.title

    return {
        "number": control.control_number or control.id,
        "title": control.title or "",
        "theme": control.theme or "",
        "applicable": applicable,
        "justification": justification,
        "implementation": implementation,
        "verdict": verdict.replace("_", " ").upper(),
        "owner": getattr(rolled, "owner", None) or "",
        "reviewed_at": (
            getattr(rolled, "reviewed_at", None).strftime("%d %b %Y")
            if getattr(rolled, "reviewed_at", None)
            else ""
        ),
    }


def _generate_soa_detailed_pdf(
    controls: list, findings_map: dict, meta: dict
) -> io.BytesIO:
    """Renders a certification-grade Statement of Applicability as PDF."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=14 * mm,
        title=f"Statement of Applicability — {meta['framework_name']}",
        author="CCure Audit PRO",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "SoATitle",
        parent=styles["Title"],
        fontSize=17,
        textColor=colors.HexColor("#003366"),
        spaceAfter=4,
    )
    meta_style = ParagraphStyle("SoAMeta", parent=styles["Normal"], fontSize=9)
    cell = ParagraphStyle("SoACell", parent=styles["Normal"], fontSize=7, leading=9)
    head = ParagraphStyle(
        "SoAHead",
        parent=styles["Normal"],
        fontSize=7,
        leading=9,
        textColor=colors.white,
    )

    rows = [_soa_row(c, findings_map.get(c.id)) for c in controls]
    counts: dict = {}
    for r in rows:
        counts[r["applicable"]] = counts.get(r["applicable"], 0) + 1
    implemented = sum(1 for r in rows if r["implementation"].startswith("Implemented"))

    story = [
        Paragraph("Statement of Applicability", title_style),
        Paragraph(
            f"{meta['framework_name']} ({meta['framework_version']})",
            styles["Heading3"],
        ),
        Spacer(1, 3 * mm),
        Paragraph(f"<b>Organization:</b> {meta['organization']}", meta_style),
        Paragraph(
            f"<b>Generated:</b> {meta['generated_at'].strftime('%d %b %Y %H:%M UTC')}"
            f" &nbsp;&nbsp; <b>By:</b> {meta['generated_by']}",
            meta_style,
        ),
        Paragraph(
            f"<b>Controls:</b> {len(rows)} total &nbsp;|&nbsp; "
            f"{counts.get('Yes', 0)} applicable &nbsp;|&nbsp; "
            f"{counts.get('No', 0)} excluded &nbsp;|&nbsp; "
            f"{implemented} implemented",
            meta_style,
        ),
        Paragraph(
            f"<b>Source scan run:</b> {meta.get('last_run_id') or 'None — no completed scan'}",
            meta_style,
        ),
        Spacer(1, 5 * mm),
    ]

    table_data = [
        [
            Paragraph("<b>Ref</b>", head),
            Paragraph("<b>Control</b>", head),
            Paragraph("<b>Applicable</b>", head),
            Paragraph("<b>Justification</b>", head),
            Paragraph("<b>Implementation status</b>", head),
            Paragraph("<b>Owner</b>", head),
            Paragraph("<b>Reviewed</b>", head),
        ]
    ]
    evidence_counts = meta.get("evidence_counts") or {}
    for control, r in zip(controls, rows):
        n_files = evidence_counts.get(control.id, 0)
        impl = r["implementation"]
        if n_files:
            impl = f"{impl}<br/><font size='6' color='#4A5568'>{n_files} evidence file(s)</font>"
        table_data.append(
            [
                Paragraph(r["number"], cell),
                Paragraph(r["title"], cell),
                Paragraph(r["applicable"], cell),
                Paragraph(r["justification"], cell),
                Paragraph(impl, cell),
                Paragraph(r["owner"], cell),
                Paragraph(r["reviewed_at"], cell),
            ]
        )

    tbl = Table(
        table_data,
        colWidths=[18 * mm, 62 * mm, 20 * mm, 92 * mm, 44 * mm, 190 / 5 * mm, 20 * mm],
        repeatRows=1,
    )
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#003366")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E0")),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#F7FAFC")],
                ),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story.append(tbl)

    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("<b>Approval</b>", styles["Heading3"]))
    story.append(
        Paragraph(
            "This Statement of Applicability was reviewed and approved by:",
            meta_style,
        )
    )
    story.append(Spacer(1, 4 * mm))
    approval = Table(
        [
            [
                Paragraph("Name", cell),
                Paragraph("Role", cell),
                Paragraph("Signature", cell),
                Paragraph("Date", cell),
            ],
            [
                Paragraph("", cell),
                Paragraph("", cell),
                Paragraph("", cell),
                Paragraph("", cell),
            ],
        ],
        colWidths=[65 * mm, 65 * mm, 75 * mm, 40 * mm],
        rowHeights=[7 * mm, 16 * mm],
    )
    approval.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E0")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(approval)

    doc.build(story)
    buffer.seek(0)
    return buffer


def _generate_soa_detailed_docx(
    controls: list, findings_map: dict, meta: dict
) -> io.BytesIO:
    """Renders a certification-grade Statement of Applicability as a Word document."""
    try:
        from docx import Document as _Document
        from docx.enum.section import WD_ORIENT
        from docx.oxml import parse_xml
        from docx.oxml.ns import nsdecls
        from docx.shared import Pt, RGBColor
    except ImportError:
        return io.BytesIO(b"python-docx is not installed.")

    doc = _Document()
    section = doc.sections[0]
    section.orientation = WD_ORIENT.LANDSCAPE
    section.page_width, section.page_height = section.page_height, section.page_width

    heading = doc.add_paragraph()
    run = heading.add_run("Statement of Applicability")
    run.font.size = Pt(18)
    run.font.bold = True
    run.font.color.rgb = RGBColor(0, 51, 102)

    sub = doc.add_paragraph()
    sub_run = sub.add_run(f"{meta['framework_name']} ({meta['framework_version']})")
    sub_run.font.size = Pt(11)
    sub_run.font.italic = True

    rows = [_soa_row(c, findings_map.get(c.id)) for c in controls]
    applicable = sum(1 for r in rows if r["applicable"] == "Yes")
    excluded = len(rows) - applicable
    implemented = sum(1 for r in rows if r["implementation"].startswith("Implemented"))

    for line in (
        f"Organization: {meta['organization']}",
        f"Generated: {meta['generated_at'].strftime('%d %b %Y %H:%M UTC')} by {meta['generated_by']}",
        f"Controls: {len(rows)} total | {applicable} applicable | {excluded} excluded | {implemented} implemented",
        f"Source scan run: {meta.get('last_run_id') or 'None — no completed scan'}",
    ):
        p = doc.add_paragraph()
        p.add_run(line).font.size = Pt(9)

    table = doc.add_table(rows=1, cols=7)
    table.style = "Table Grid"
    headers = [
        "Ref",
        "Control",
        "Applicable",
        "Justification",
        "Implementation status",
        "Owner",
        "Reviewed",
    ]
    for idx, name in enumerate(headers):
        cell = table.rows[0].cells[idx]
        cell.text = name
        cell._tc.get_or_add_tcPr().append(
            parse_xml(f'<w:shd {nsdecls("w")} w:fill="003366"/>')
        )
        for para in cell.paragraphs:
            for r in para.runs:
                r.font.bold = True
                r.font.size = Pt(8)
                r.font.color.rgb = RGBColor(255, 255, 255)

    for r in rows:
        cells = table.add_row().cells
        for idx, key in enumerate(
            (
                "number",
                "title",
                "applicable",
                "justification",
                "implementation",
                "owner",
                "reviewed_at",
            )
        ):
            cells[idx].text = str(r[key])
            for para in cells[idx].paragraphs:
                for run_ in para.runs:
                    run_.font.size = Pt(7)

    doc.add_paragraph()
    approval_heading = doc.add_paragraph()
    approval_heading.add_run("Approval").font.bold = True
    doc.add_paragraph("This Statement of Applicability was reviewed and approved by:")
    approval = doc.add_table(rows=2, cols=4)
    approval.style = "Table Grid"
    for idx, label in enumerate(("Name", "Role", "Signature", "Date")):
        approval.rows[0].cells[idx].text = label

    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer


def _generate_soa_docx(
    controls: list,
    findings_map: dict,
    title: str = "CCure Audit PRO — Statement of Applicability (SoA)",
    subtitle: str = "Controls Compliance Ledger Catalog",
) -> io.BytesIO:
    """Generates the Word Statement of Applicability document using python-docx."""
    try:
        from docx import Document
        from docx.oxml import parse_xml
        from docx.oxml.ns import nsdecls
        from docx.shared import Inches, Pt, RGBColor
    except ImportError:
        return io.BytesIO(b"python-docx is not installed.")

    doc = Document()
    p_title = doc.add_paragraph()
    run_t = p_title.add_run(title)
    run_t.font.size = Pt(18)
    run_t.font.bold = True
    run_t.font.color.rgb = RGBColor(15, 23, 42)

    p_sub = doc.add_paragraph()
    run_sub = p_sub.add_run(subtitle)
    run_sub.font.italic = True

    table = doc.add_table(rows=1, cols=5)
    table.style = "Table Grid"
    hdr_cells = table.rows[0].cells
    hdr_names = ["Control ID", "Name", "Category", "Scan Mode", "Verdict Status"]
    for i, name in enumerate(hdr_names):
        shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="0F172A"/>')
        hdr_cells[i]._tc.get_or_add_tcPr().append(shd)
        hdr_cells[i].text = name
        for p in hdr_cells[i].paragraphs:
            for run in p.runs:
                run.font.bold = True
                run.font.color.rgb = RGBColor(255, 255, 255)

    for c in controls:
        row_cells = table.add_row().cells
        row_cells[0].text = str(c.control_number or c.id)
        row_cells[1].text = str(c.title or "")
        row_cells[2].text = str(c.theme or "N/A")
        row_cells[3].text = str(c.scannability or "manual").upper()

        row_cells[4].text = _verdict_of(findings_map, c.id)

    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer


def _generate_soa_pdf(
    controls: list,
    findings_map: dict,
    title: str = "Statement of Applicability (SoA) Report",
    subtitle: str = "Security Controls Ledger",
) -> io.BytesIO:
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
        Paragraph(title, title_style),
        Paragraph(subtitle, styles["Normal"]),
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
        status_text = _verdict_of(findings_map, c.id)
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
@limiter.limit("10/minute")
def download_statement_of_applicability(
    request: Request,
    fmt: str = "pdf",
    framework_id: str = Query("cfw_iso27001_2022"),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "export_report")),
):
    """Statement of Applicability for one framework.

    A Statement of Applicability is an ISO/IEC 27001 artefact covering one
    standard's control set. This used to emit the controls of *every* installed
    framework, so an organisation with all twelve installed received an
    800-row multi-standard dump labelled "ISO 27001 SoA". It is now scoped to a
    single framework, defaulting to ISO 27001:2022.
    """
    require_active_framework(framework_id)

    fw = (
        db.query(ComplianceFramework)
        .filter(ComplianceFramework.id == framework_id)
        .first()
    )
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")

    tf = (
        db.query(ComplianceTenantFramework)
        .filter_by(tenant_id=user.org_id, framework_id=framework_id, is_enabled=True)
        .first()
    )
    if not tf:
        raise HTTPException(
            status_code=400,
            detail="Framework is not installed for this organization.",
        )

    # ISO/IEC 27001's management-system clauses (4–10) are in the catalogue as
    # attestation controls but not in the SoA: clause 6.1.3(d) makes the SoA a
    # statement about Annex A controls, and clauses 4–10 are mandatory — there
    # is no applicability to state.
    controls = (
        db.query(ComplianceControl)
        .filter(
            ComplianceControl.framework_id == framework_id,
            ComplianceControl.theme != SOA_EXCLUDED_THEME,
        )
        .all()
    )
    # Numeric ordering. `ORDER BY control_number` is a string sort, so the SoA
    # came out A.5.1, A.5.10, A.5.11 … A.5.2 — the first thing an auditor
    # notices.
    controls.sort(key=lambda c: control_sort_key(c.control_number))
    control_ids = [c.id for c in controls]

    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    org = getattr(user, "organization", None)
    org_name = getattr(org, "name", None) or user.org_id

    evidence_counts = dict(
        db.query(
            ComplianceEvidenceFile.control_id, func.count(ComplianceEvidenceFile.id)
        )
        .filter(
            ComplianceEvidenceFile.tenant_id == user.org_id,
            ComplianceEvidenceFile.control_id.in_(control_ids),
        )
        .group_by(ComplianceEvidenceFile.control_id)
        .all()
    )

    meta = {
        "framework_name": fw.name,
        "framework_version": fw.version,
        "organization": org_name,
        "generated_at": datetime.now(timezone.utc),
        "generated_by": getattr(user, "email", None) or user.id,
        "last_run_id": _latest_run_id(db, user.org_id, framework_id),
        "evidence_counts": evidence_counts,
    }

    slug = fw.code.lower()
    if fmt.lower() == "docx":
        # Say so rather than quietly handing back a PDF. python-docx was not a
        # declared dependency, so every DOCX request in this module fell
        # through to the PDF branch — the caller asked for one format and
        # received another with no indication why.
        if Document is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    "DOCX export is unavailable because python-docx is not "
                    "installed on this deployment. Request fmt=pdf instead."
                ),
            )
        buffer = _generate_soa_detailed_docx(controls, findings_map, meta)
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"soa_{slug}_{user.org_id}.docx"
    else:
        buffer = _generate_soa_detailed_pdf(controls, findings_map, meta)
        media = "application/pdf"
        filename = f"soa_{slug}_{user.org_id}.pdf"

    log_audit_event(db, user, "export_soa", "framework", framework_id, status="success")
    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/executive")
# Report generation renders a PDF or DOCX synchronously inside the request,
# so each call holds a threadpool worker for as long as the render takes.
# Thirteen of these endpoints existed and none carried a limit, which made
# a loop over any one of them a CPU and memory exhaustion path that needs no
# special privilege beyond compliance:export_report.
@limiter.limit("10/minute")
def download_executive_compliance_report(
    request: Request,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "export_report")),
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
    user: CurrentUser = Depends(require_permission("compliance", "read")),
):
    """Calculates estimated compliance posture for target framework based on source framework crosswalk mappings."""
    require_active_framework(source_framework_id)
    require_active_framework(target_framework_id)

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
    source_controls = (
        db.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == source_framework_id)
        .all()
    )

    def normalize(val: str) -> str:
        return (
            val.lower()
            .replace("a.", "")
            .replace(".", "")
            .replace("-", "")
            .replace(" ", "")
            .replace("_", "")
        )

    source_num_to_id = {normalize(c.control_number): c.id for c in source_controls}

    # Rolled up through the shared precedence table and scoped to the source
    # framework. This used to read every finding the tenant had, across all
    # frameworks, into a last-wins dict.
    source_findings_map = rolled_up_control_status(
        db, user.org_id, [c.id for c in source_controls]
    )

    total_target = len(target_controls)
    estimated_pass = 0
    estimated_fail = 0
    pending_manual = 0
    mapped_count = 0

    control_breakdown = []
    for ctrl in target_controls:
        status_eval = "pending_manual"
        mapped_ref = ctrl.crosswalk or []

        if mapped_ref:
            mapped_count += 1
            has_pass = False
            has_fail = False
            for cross_num in mapped_ref:
                clean_cross_num = (
                    cross_num.split(":", 1)[1] if ":" in cross_num else cross_num
                )
                norm_num = normalize(clean_cross_num)
                source_ctrl_id = source_num_to_id.get(norm_num)
                if not source_ctrl_id:
                    clean_raw = (
                        clean_cross_num.lower()
                        .replace("a.", "")
                        .replace(".", "_")
                        .replace("-", "_")
                    )
                    source_ctrl_id = f"cct_{source_fw.code.lower()}_{clean_raw}"

                found_status = source_findings_map.get(source_ctrl_id)
                if found_status in ("pass", "exception"):
                    has_pass = True
                elif found_status in ("fail", "pending_reverify"):
                    has_fail = True

            # Fail wins. A target control that crosswalks to three source
            # controls, one passing and two failing, is not "covered" — the
            # previous order checked has_pass first and rounded the gap
            # analysis up, which is the one direction a gap analysis must never
            # round.
            if has_fail:
                status_eval = "fail"
                estimated_fail += 1
            elif has_pass:
                status_eval = "pass"
                estimated_pass += 1
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
                "crosswalk": mapped_ref,
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


# ─────────────────────────────────────────────────────────────────────────────
# NIST CSF 2.0 Organizational Profile
#
# The CSF report used the generic Statement of Applicability generator, which
# is an ISO artefact: five columns headed "Control ID / Name / Category / Scan
# Mode / Verdict", with `Category` printing the raw Function code. Nothing in
# it named a Function, nothing grouped by Category, and there was no per-
# Function score — so the one thing every CSF reader looks for, which Function
# is weakest, could not be read off it. NIST calls this artefact a Current
# Profile, and it is organised Function ▸ Category ▸ Subcategory.
# ─────────────────────────────────────────────────────────────────────────────

# Verdict -> (label, hex colour). `not_assessed` and `manual_review` are kept
# apart on purpose: "nobody has looked at this" and "a human still has to sign
# it off" are different states, and collapsing them is what lets an unscanned
# framework read as a failing one.
_CSF_VERDICT_DISPLAY = {
    "pass": ("Compliant", "#16A34A"),
    "exception": ("Compliant (exception)", "#0891B2"),
    "fail": ("Non-compliant", "#DC2626"),
    "pending_reverify": ("Non-compliant (re-verify)", "#EA580C"),
    "remediation_applied": ("Partially compliant", "#CA8A04"),
    "manual_review": ("Awaiting review", "#7C3AED"),
    "not_applicable": ("Not applicable", "#64748B"),
    "not_assessed": ("Not assessed", "#94A3B8"),
}


def _csf_verdict(findings_map: dict, control_id: str) -> str:
    value = findings_map.get(control_id)
    if value is None:
        return "not_assessed"
    if isinstance(value, str):
        return value
    return str(getattr(value, "status", "not_assessed"))


def _csf_group(controls: list, findings_map: dict) -> list:
    """`[(function_code, function_name, score, [(category, name, [rows])])]`.

    Ordered by `core.nist_csf`, which is NIST's published order rather than the
    alphabetical one.
    """
    by_function: dict = {}
    for c in controls:
        number = c.control_number or ""
        category = (
            number.partition("-")[0] if nist_csf.is_csf_subcategory(number) else "—"
        )
        function = c.theme or (category.split(".")[0] if "." in category else "—")
        by_function.setdefault(function, {}).setdefault(category, []).append(c)

    def _score(subset: list) -> tuple:
        verdicts = [_csf_verdict(findings_map, c.id) for c in subset]
        applicable = [v for v in verdicts if v != "not_applicable"]
        passed = sum(1 for v in applicable if v in ("pass", "exception"))
        assessed = sum(
            1 for v in applicable if v not in ("not_assessed", "manual_review")
        )
        pct = round(passed / len(applicable) * 100, 1) if applicable else 0.0
        return pct, passed, len(applicable), assessed

    out: list = []
    for function in nist_csf.FUNCTION_ORDER:
        if function not in by_function:
            continue
        categories = by_function[function]
        ordered_categories = [
            (code, nist_csf.CATEGORY_ORDER[code][1], categories[code])
            for code in nist_csf.CATEGORY_ORDER
            if code in categories
        ]
        # Anything that is not a recognised Category still has to appear;
        # dropping rows out of an audit artefact is worse than an odd heading.
        ordered_categories += [
            (code, code, rows)
            for code, rows in categories.items()
            if code not in nist_csf.CATEGORY_ORDER
        ]
        flat = [c for _, _, rows in ordered_categories for c in rows]
        for _, _, rows in ordered_categories:
            rows.sort(key=lambda c: control_sort_key(c.control_number))
        out.append(
            (
                function,
                nist_csf.FUNCTION_NAMES.get(function, function),
                _score(flat),
                ordered_categories,
            )
        )

    for function, categories in by_function.items():
        if function in nist_csf.FUNCTION_ORDER:
            continue
        ordered_categories = [(code, code, rows) for code, rows in categories.items()]
        flat = [c for _, _, rows in ordered_categories for c in rows]
        out.append((function, function, _score(flat), ordered_categories))

    return out


def _generate_nist_csf_pdf(
    controls: list, findings_map: dict, meta: dict
) -> io.BytesIO:
    """NIST CSF 2.0 Current Profile, grouped Function ▸ Category ▸ Subcategory."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title="NIST CSF 2.0 Current Profile",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CSFTitle",
        parent=styles["Heading1"],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0A2E5C"),
    )
    sub_style = ParagraphStyle(
        "CSFSub",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=9.5,
        textColor=colors.HexColor("#475569"),
    )
    fn_style = ParagraphStyle(
        "CSFFunction",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0A2E5C"),
    )
    cat_style = ParagraphStyle(
        "CSFCategory",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9.5,
        textColor=colors.HexColor("#1E293B"),
    )
    cell = ParagraphStyle("CSFCell", parent=styles["Normal"], fontSize=7.5, leading=9.5)
    hdr = ParagraphStyle(
        "CSFHdr",
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9.5,
        textColor=colors.white,
    )
    kpi = ParagraphStyle(
        "CSFKpi",
        fontSize=8,
        leading=11,
        alignment=1,
        textColor=colors.HexColor("#334155"),
    )

    grouped = _csf_group(controls, findings_map)

    story: list = [
        Paragraph("NIST Cybersecurity Framework 2.0 — Current Profile", title_style),
        Paragraph(
            f"{meta.get('organization', 'Organisation')} · "
            f"Generated {meta.get('generated_at', '')}"
            + (f" · Scope: {meta['scope']}" if meta.get("scope") else ""),
            sub_style,
        ),
        Spacer(1, 4 * mm),
        Paragraph(
            "Scores are computed over applicable Subcategories only. A Subcategory "
            "marked Not applicable is excluded from its Function's denominator; one "
            "that is Not assessed or Awaiting review remains in the denominator and "
            "counts against the score, because coverage is part of the posture.",
            sub_style,
        ),
        Spacer(1, 5 * mm),
    ]

    # Function summary — the headline a CSF reader is looking for.
    summary_rows = [
        [
            Paragraph("Function", hdr),
            Paragraph("Categories", hdr),
            Paragraph("Subcategories", hdr),
            Paragraph("Applicable", hdr),
            Paragraph("Assessed", hdr),
            Paragraph("Compliant", hdr),
            Paragraph("Score", hdr),
        ]
    ]
    for code, name, (pct, passed, applicable, assessed), categories in grouped:
        subcount = sum(len(rows) for _, _, rows in categories)
        summary_rows.append(
            [
                Paragraph(f"<b>{code}</b> {name}", cell),
                Paragraph(str(len(categories)), cell),
                Paragraph(str(subcount), cell),
                Paragraph(str(applicable), cell),
                Paragraph(str(assessed), cell),
                Paragraph(str(passed), cell),
                Paragraph(f"<b>{pct}%</b>", cell),
            ]
        )
    summary = Table(
        summary_rows,
        colWidths=[95 * mm, 22 * mm, 26 * mm, 22 * mm, 21 * mm, 22 * mm, 20 * mm],
        repeatRows=1,
    )
    summary.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0A2E5C")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#F8FAFC")],
                ),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(summary)

    total = len(controls)
    all_verdicts = [_csf_verdict(findings_map, c.id) for c in controls]
    applicable_all = [v for v in all_verdicts if v != "not_applicable"]
    passed_all = sum(1 for v in applicable_all if v in ("pass", "exception"))
    overall = (
        round(passed_all / len(applicable_all) * 100, 1) if applicable_all else 0.0
    )
    story.append(Spacer(1, 4 * mm))
    story.append(
        Table(
            [
                [
                    Paragraph(
                        f"SUBCATEGORIES<br/><font size=13><b>{total}</b></font>", kpi
                    ),
                    Paragraph(
                        "COMPLIANT<br/>"
                        f"<font size=13 color='#16A34A'><b>{passed_all}</b></font>",
                        kpi,
                    ),
                    Paragraph(
                        "NON-COMPLIANT<br/><font size=13 color='#DC2626'><b>"
                        f"{sum(1 for v in all_verdicts if v in ('fail', 'pending_reverify'))}"
                        "</b></font>",
                        kpi,
                    ),
                    Paragraph(
                        "AWAITING REVIEW<br/><font size=13 color='#7C3AED'><b>"
                        f"{sum(1 for v in all_verdicts if v == 'manual_review')}"
                        "</b></font>",
                        kpi,
                    ),
                    Paragraph(
                        "NOT ASSESSED<br/><font size=13 color='#94A3B8'><b>"
                        f"{sum(1 for v in all_verdicts if v == 'not_assessed')}"
                        "</b></font>",
                        kpi,
                    ),
                    Paragraph(
                        "NOT APPLICABLE<br/><font size=13 color='#64748B'><b>"
                        f"{sum(1 for v in all_verdicts if v == 'not_applicable')}"
                        "</b></font>",
                        kpi,
                    ),
                    Paragraph(
                        f"OVERALL<br/><font size=13 color='#0A2E5C'><b>{overall}%</b></font>",
                        kpi,
                    ),
                ]
            ],
            colWidths=[38 * mm] * 6 + [38 * mm],
            style=TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                    ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#CBD5E1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E2E8F0")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            ),
        )
    )

    for code, name, (pct, passed, applicable, assessed), categories in grouped:
        story.append(Spacer(1, 7 * mm))
        story.append(
            Paragraph(
                f"{code} — {name} &nbsp;·&nbsp; {pct}% "
                f"({passed}/{applicable} applicable Subcategories compliant)",
                fn_style,
            )
        )
        for cat_code, cat_name, rows in categories:
            story.append(Spacer(1, 2 * mm))
            story.append(Paragraph(f"{cat_code} · {cat_name}", cat_style))
            data = [
                [
                    Paragraph("Subcategory", hdr),
                    Paragraph("Outcome", hdr),
                    Paragraph("Assessment", hdr),
                    Paragraph("Status", hdr),
                    Paragraph("Owner / Reviewed", hdr),
                ]
            ]
            for c in rows:
                verdict = _csf_verdict(findings_map, c.id)
                label, colour = _CSF_VERDICT_DISPLAY.get(
                    verdict, (verdict.replace("_", " ").title(), "#334155")
                )
                rolled = findings_map.get(c.id)
                owner = getattr(rolled, "owner", None) or ""
                reviewed = getattr(rolled, "reviewed_at", None)
                data.append(
                    [
                        Paragraph(f"<b>{c.control_number}</b>", cell),
                        Paragraph(c.title or "", cell),
                        Paragraph(
                            (
                                "Automated"
                                if (c.scannability or "manual") == "auto"
                                else "Attestation"
                            ),
                            cell,
                        ),
                        Paragraph(
                            f"<font color='{colour}'><b>{label}</b></font>", cell
                        ),
                        Paragraph(
                            f"{owner}<br/>{reviewed.strftime('%d %b %Y') if reviewed else ''}",
                            cell,
                        ),
                    ]
                )
            tbl = Table(
                data,
                colWidths=[22 * mm, 128 * mm, 24 * mm, 40 * mm, 34 * mm],
                repeatRows=1,
            )
            tbl.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#F8FAFC")],
                        ),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]
                )
            )
            story.append(tbl)

    doc.build(story)
    buffer.seek(0)
    return buffer


def _generate_nist_csf_docx(
    controls: list, findings_map: dict, meta: dict
) -> io.BytesIO:
    """The same Current Profile as a Word document."""
    try:
        from docx import Document as _Document
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.shared import Pt, RGBColor
    except ImportError:
        return io.BytesIO(b"python-docx is not installed.")

    document = _Document()
    heading = document.add_paragraph()
    run = heading.add_run("NIST Cybersecurity Framework 2.0 — Current Profile")
    run.font.size = Pt(18)
    run.font.bold = True
    run.font.color.rgb = RGBColor(10, 46, 92)

    meta_p = document.add_paragraph()
    meta_run = meta_p.add_run(
        f"{meta.get('organization', 'Organisation')} · "
        f"Generated {meta.get('generated_at', '')}"
        + (f" · Scope: {meta['scope']}" if meta.get("scope") else "")
    )
    meta_run.font.italic = True
    meta_p.alignment = WD_ALIGN_PARAGRAPH.LEFT

    grouped = _csf_group(controls, findings_map)

    document.add_paragraph("Function summary").runs[0].bold = True
    summary = document.add_table(rows=1, cols=5)
    summary.style = "Table Grid"
    for i, name in enumerate(
        ["Function", "Subcategories", "Applicable", "Compliant", "Score"]
    ):
        summary.rows[0].cells[i].text = name
        for p in summary.rows[0].cells[i].paragraphs:
            for r in p.runs:
                r.font.bold = True
    for code, name, (pct, passed, applicable, _assessed), categories in grouped:
        cells = summary.add_row().cells
        cells[0].text = f"{code} — {name}"
        cells[1].text = str(sum(len(rows) for _, _, rows in categories))
        cells[2].text = str(applicable)
        cells[3].text = str(passed)
        cells[4].text = f"{pct}%"

    for code, name, (pct, passed, applicable, _assessed), categories in grouped:
        document.add_paragraph()
        fn_p = document.add_paragraph()
        fn_run = fn_p.add_run(
            f"{code} — {name} · {pct}% ({passed}/{applicable} applicable compliant)"
        )
        fn_run.font.size = Pt(13)
        fn_run.font.bold = True
        fn_run.font.color.rgb = RGBColor(10, 46, 92)

        for cat_code, cat_name, rows in categories:
            cat_p = document.add_paragraph()
            cat_run = cat_p.add_run(f"{cat_code} · {cat_name}")
            cat_run.font.bold = True

            table = document.add_table(rows=1, cols=4)
            table.style = "Table Grid"
            for i, name_ in enumerate(
                ["Subcategory", "Outcome", "Assessment", "Status"]
            ):
                table.rows[0].cells[i].text = name_
                for p in table.rows[0].cells[i].paragraphs:
                    for r in p.runs:
                        r.font.bold = True
            for c in rows:
                verdict = _csf_verdict(findings_map, c.id)
                label = _CSF_VERDICT_DISPLAY.get(
                    verdict, (verdict.replace("_", " ").title(), "")
                )[0]
                cells = table.add_row().cells
                cells[0].text = str(c.control_number or "")
                cells[1].text = str(c.title or "")
                cells[2].text = (
                    "Automated"
                    if (c.scannability or "manual") == "auto"
                    else "Attestation"
                )
                cells[3].text = label

    buffer = io.BytesIO()
    document.save(buffer)
    buffer.seek(0)
    return buffer


@router.get("/reports/nist_csf")
@limiter.limit("10/minute")
def download_nist_csf_report(
    request: Request,
    fmt: str = "pdf",
    functions: str | None = Query(
        None, description="Comma-separated list of functions: GV,ID,PR,DE,RS,RC"
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "export_report")),
):
    """Generates and downloads the NIST CSF v2.0 Current Profile report."""
    fw_id = nist_csf.FRAMEWORK_ID
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    scope_label = None
    if functions:
        fn_list = [f.strip().upper() for f in functions.split(",") if f.strip()]
        unknown = [f for f in fn_list if f not in nist_csf.FUNCTION_ORDER]
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Unknown CSF Function(s): {', '.join(unknown)}. "
                    f"Valid values are {', '.join(nist_csf.FUNCTION_ORDER)}."
                ),
            )
        if fn_list:
            query = query.filter(ComplianceControl.theme.in_(fn_list))
            # Report the Functions in NIST's order regardless of how the caller
            # listed them, so "RC,GV" is not printed back as a scope of
            # "Recover, Govern".
            scope_label = ", ".join(
                f"{f} {nist_csf.FUNCTION_NAMES[f]}"
                for f in nist_csf.FUNCTION_ORDER
                if f in fn_list
            )

    # Ordered in Python, not SQL: `ORDER BY theme, control_number` is a string
    # sort and CSF's order is not alphabetical in either column.
    controls = sorted(query.all(), key=lambda c: control_sort_key(c.control_number))
    control_ids = [c.id for c in controls]

    # One rolled-up verdict per Subcategory (see RolledFinding). A separate,
    # unused `ComplianceFinding` query used to run here as well and its result
    # was discarded.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    org = getattr(user, "organization", None)
    meta = {
        "organization": getattr(org, "name", None) or user.org_id,
        "generated_at": datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC"),
        "scope": scope_label,
    }

    if fmt.lower() == "docx" and Document is not None:
        buffer = _generate_nist_csf_docx(controls, findings_map, meta)
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"nist_csf_current_profile_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_nist_csf_pdf(controls, findings_map, meta)
        media = "application/pdf"
        filename = f"nist_csf_current_profile_{user.org_id[:4]}.pdf"

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/cis_v8_1")
@limiter.limit("10/minute")
def download_cis_v8_1_report(
    request: Request,
    fmt: str = "pdf",
    ig: str | None = Query(
        None, description="Implementation Group filter: ig1, ig2, ig3"
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "export_report")),
):
    """Generates and downloads the CIS Controls v8.1 Compliance Assessment Report."""
    fw_id = "cfw_cis_v8_1"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if ig:
        ig_val = ig.strip().lower()
        query = query.filter(ComplianceControl.tags.contains([ig_val]))

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
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    report_title = "CIS Critical Security Controls v8.1 Executive Report"
    report_sub = f"CIS Controls v8.1 Assessment Ledger (Tenant: {user.org_id[:8]})"

    if fmt.lower() == "docx" and Document is not None:
        buffer = _generate_soa_docx(
            controls, findings_map, title=report_title, subtitle=report_sub
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"cis_v8_1_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_soa_pdf(
            controls, findings_map, title=report_title, subtitle=report_sub
        )
        media = "application/pdf"
        filename = f"cis_v8_1_report_{user.org_id[:4]}.pdf"

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/soc2_type2")
@limiter.limit("10/minute")
def download_soc2_type2_report(
    request: Request,
    fmt: str = "pdf",
    tsc: str | None = Query(
        None, description="Trust Services Criteria filter: cc, a, pi, c, p"
    ),
    audit_period_days: int = Query(
        90, ge=30, le=365, description="SOC 2 Type II Observation Period in Days"
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "export_report")),
):
    """Generates and downloads the SOC 2 Type II (AICPA Trust Services Criteria) Compliance Audit Report."""
    fw_id = "cfw_soc2_type2"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if tsc:
        tsc_code = f"SOC2_{tsc.strip().upper()}"
        query = query.filter(ComplianceControl.theme == tsc_code)

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
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    # Time-Series Historical Deviation check for SOC 2 Type II observation window
    window_start = datetime.now(timezone.utc) - timedelta(days=audit_period_days)
    history_deviations = (
        db.query(ComplianceFindingHistory.finding_id)
        .join(
            ComplianceFinding,
            ComplianceFinding.id == ComplianceFindingHistory.finding_id,
        )
        .filter(
            ComplianceFinding.tenant_id == user.org_id,
            ComplianceFinding.control_id.in_(control_ids),
            ComplianceFindingHistory.changed_at >= window_start,
            ComplianceFindingHistory.status == "fail",
        )
        .distinct()
        .all()
    )
    deviation_finding_ids = {h[0] for h in history_deviations}

    # Annotate findings map with historical deviations if any occurred during the window
    for f in findings:
        if f.id in deviation_finding_ids and f.status == "pass":
            ev = dict(f.evidence or {})
            ev["historical_deviation"] = (
                f"Failed at least once within the past {audit_period_days}-day observation period."
            )
            f.evidence = ev

    report_title = "SOC 2 Type II Audit Readiness & Trust Services Ledger"
    report_sub = f"AICPA Trust Services Criteria Assessment (Tenant: {user.org_id[:8]} | Observation Window: {audit_period_days} Days)"

    if fmt.lower() == "docx" and Document is not None:
        buffer = _generate_soa_docx(
            controls, findings_map, title=report_title, subtitle=report_sub
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"soc2_type2_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_soa_pdf(
            controls, findings_map, title=report_title, subtitle=report_sub
        )
        media = "application/pdf"
        filename = f"soc2_type2_report_{user.org_id[:4]}.pdf"

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/cert_in_2022")
@limiter.limit("10/minute")
def download_cert_in_2022_report(
    request: Request,
    fmt: str = "pdf",
    theme: str | None = Query(
        None,
        description="CERT-In theme filter: CERT_IR, CERT_LOG, CERT_AM, CERT_VM, CERT_AC, CERT_DP",
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "export_report")),
):
    """Generates and downloads the CERT-In Cyber Security Directions 2022 & CCMP Compliance Report."""
    fw_id = "cfw_cert_in_2022"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if theme:
        query = query.filter(ComplianceControl.theme == theme.strip().upper())

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
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    report_title = "CERT-In Directions 2022 & CCMP Security Compliance Audit Report"
    report_sub = f"Indian Cyber Security Directions & Cyber Crisis Management Plan Ledger (Tenant: {user.org_id[:8]})"

    if fmt.lower() == "docx" and Document is not None:
        buffer = _generate_soa_docx(
            controls, findings_map, title=report_title, subtitle=report_sub
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"cert_in_2022_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_soa_pdf(
            controls, findings_map, title=report_title, subtitle=report_sub
        )
        media = "application/pdf"
        filename = f"cert_in_2022_report_{user.org_id[:4]}.pdf"

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _generate_pci_dss_docx(
    controls: list,
    findings_map: dict,
    title: str = "PCI-DSS v4.0 Compliance Assessment Report",
    subtitle: str = "Payment Card Industry Data Security Standard Assessment Ledger",
) -> io.BytesIO:
    """Generates the Word PCI-DSS report using python-docx."""
    try:
        from docx import Document
        from docx.oxml import parse_xml
        from docx.oxml.ns import nsdecls
        from docx.shared import Inches, Pt, RGBColor
    except ImportError:
        return io.BytesIO(b"python-docx is not installed.")

    doc = Document()
    p_title = doc.add_paragraph()
    run_t = p_title.add_run(title)
    run_t.font.size = Pt(18)
    run_t.font.bold = True
    run_t.font.color.rgb = RGBColor(30, 64, 175)

    p_sub = doc.add_paragraph()
    run_sub = p_sub.add_run(subtitle)
    run_sub.font.italic = True

    table = doc.add_table(rows=1, cols=6)
    table.style = "Table Grid"
    hdr_cells = table.rows[0].cells
    hdr_names = [
        "Control ID",
        "Name",
        "SAQ Profile Relevance",
        "March 31, 2025 Mandatory",
        "CDE Scope Tagging",
        "Verdict Status",
    ]
    for i, name in enumerate(hdr_names):
        shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="1E40AF"/>')
        hdr_cells[i]._tc.get_or_add_tcPr().append(shd)
        hdr_cells[i].text = name
        for p in hdr_cells[i].paragraphs:
            for run in p.runs:
                run.font.bold = True
                run.font.color.rgb = RGBColor(255, 255, 255)

    for c in controls:
        row_cells = table.add_row().cells
        row_cells[0].text = str(c.control_number or c.id)
        row_cells[1].text = str(c.title)

        saq_str = ", ".join(c.saq_profiles) if c.saq_profiles else "All"
        row_cells[2].text = saq_str

        is_mand = (
            "Yes"
            if (
                c.tags
                and "v4_2025_mandatory" in c.tags
                or getattr(c, "v4_2025_mandatory", False)
            )
            else "No"
        )
        row_cells[3].text = is_mand

        is_cde = "Yes" if (c.tags and "cde" in [t.lower() for t in c.tags]) else "No"
        row_cells[4].text = is_cde

        f = findings_map.get(c.id)
        row_cells[5].text = str(f.status).upper() if f else "PENDING"

    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer


def _generate_pci_dss_pdf(
    controls: list,
    findings_map: dict,
    title: str = "PCI-DSS v4.0 Compliance Assessment Report",
    subtitle: str = "Payment Card Industry Data Security Standard Assessment Ledger",
) -> io.BytesIO:
    """Generates the PCI-DSS PDF document using ReportLab."""
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
        fontSize=16,
        textColor=colors.HexColor("#003366"),
    )
    cell_style = ParagraphStyle("CellStyle", parent=styles["Normal"], fontSize=8)

    story = [
        Paragraph(title, title_style),
        Paragraph(subtitle, styles["Normal"]),
        Spacer(1, 10 * mm),
    ]

    table_data = [
        [
            Paragraph("<b>Control ID</b>", cell_style),
            Paragraph("<b>Name</b>", cell_style),
            Paragraph("<b>SAQ Profile Relevance</b>", cell_style),
            Paragraph("<b>March 31, 2025 Mandatory</b>", cell_style),
            Paragraph("<b>CDE Scope Tagging</b>", cell_style),
            Paragraph("<b>Verdict</b>", cell_style),
        ]
    ]

    for c in controls:
        status_text = _verdict_of(findings_map, c.id)

        saq_str = ", ".join(c.saq_profiles) if c.saq_profiles else "All"
        is_mand = (
            "Yes"
            if (
                c.tags
                and "v4_2025_mandatory" in c.tags
                or getattr(c, "v4_2025_mandatory", False)
            )
            else "No"
        )
        is_cde = "Yes" if (c.tags and "cde" in [t.lower() for t in c.tags]) else "No"

        table_data.append(
            [
                Paragraph(c.control_number or c.id, cell_style),
                Paragraph(
                    c.title[:35] + "..." if len(c.title) > 35 else c.title, cell_style
                ),
                Paragraph(saq_str, cell_style),
                Paragraph(is_mand, cell_style),
                Paragraph(is_cde, cell_style),
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

    tbl = Table(
        table_data, colWidths=[15 * mm, 50 * mm, 35 * mm, 25 * mm, 25 * mm, 30 * mm]
    )
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


@router.get("/reports/pci_dss_v4")
@limiter.limit("10/minute")
def download_pci_dss_v4_report(
    request: Request,
    fmt: str = "pdf",
    saq_profile: str | None = Query(
        None,
        description="Filter by SAQ profile: saq_a, saq_a_ep, saq_b_ip, saq_c, saq_d_merchant, saq_d_service_provider",
    ),
    cde_scope_only: bool = Query(
        False, description="Filter only by CDE scope tagged controls/findings"
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "export_report")),
):
    """Generates and downloads the PCI-DSS v4.0 Compliance Assessment Report."""
    fw_id = "cfw_pci_dss_v4"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if saq_profile:
        query = query.filter(ComplianceControl.saq_profiles.contains([saq_profile]))

    if cde_scope_only:
        query = query.filter(ComplianceControl.tags.contains(["cde"]))

    controls = query.order_by(
        ComplianceControl.theme, ComplianceControl.control_number
    ).all()
    control_ids = [c.id for c in controls]

    finding_query = db.query(ComplianceFinding).filter(
        ComplianceFinding.tenant_id == user.org_id,
        ComplianceFinding.control_id.in_(control_ids),
    )

    if cde_scope_only:
        finding_query = finding_query.filter(ComplianceFinding.cde_scope.isnot(None))

    findings = finding_query.all()
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    report_title = "PCI-DSS v4.0 Compliance Audit Assessment Report"
    report_sub = f"PCI-DSS v4.0 Assessment Ledger (Tenant: {user.org_id[:8]}"
    if saq_profile:
        report_sub += f" | SAQ Profile: {saq_profile.upper()}"
    if cde_scope_only:
        report_sub += " | CDE Scope Only"
    report_sub += ")"

    if fmt.lower() == "docx" and Document is not None:
        buffer = _generate_pci_dss_docx(
            controls, findings_map, title=report_title, subtitle=report_sub
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"pci_dss_v4_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_pci_dss_pdf(
            controls, findings_map, title=report_title, subtitle=report_sub
        )
        media = "application/pdf"
        filename = f"pci_dss_v4_report_{user.org_id[:4]}.pdf"

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _generate_privacy_docx(
    controls: list,
    findings_map: dict,
    title: str,
    subtitle: str,
    scope_label: str = "",
) -> io.BytesIO:
    """Generates Word report for privacy frameworks (DPDP / GDPR)."""
    try:
        from docx import Document
        from docx.oxml import parse_xml
        from docx.oxml.ns import nsdecls
        from docx.shared import Inches, Pt, RGBColor
    except ImportError:
        return io.BytesIO(b"python-docx is not installed.")

    doc = Document()
    p_title = doc.add_paragraph()
    run_t = p_title.add_run(title)
    run_t.font.size = Pt(18)
    run_t.font.bold = True
    run_t.font.color.rgb = RGBColor(29, 78, 216)

    p_sub = doc.add_paragraph()
    run_sub = p_sub.add_run(subtitle)
    run_sub.font.italic = True
    if scope_label:
        doc.add_paragraph(f"Scope Filter: {scope_label}")

    table = doc.add_table(rows=1, cols=5)
    table.style = "Table Grid"
    hdr_cells = table.rows[0].cells
    hdr_names = [
        "Control Number",
        "Title",
        "Theme / Principle",
        "Scannability",
        "Verdict",
    ]
    for i, name in enumerate(hdr_names):
        shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="1D4ED8"/>')
        hdr_cells[i]._tc.get_or_add_tcPr().append(shd)
        hdr_cells[i].text = name
        for p in hdr_cells[i].paragraphs:
            for run in p.runs:
                run.font.bold = True
                run.font.color.rgb = RGBColor(255, 255, 255)

    for c in controls:
        row_cells = table.add_row().cells
        row_cells[0].text = str(c.control_number or c.id)
        row_cells[1].text = str(c.title)
        row_cells[2].text = str(c.theme)
        row_cells[3].text = str(c.scannability).upper()
        row_cells[4].text = _verdict_of(findings_map, c.id)

    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer


def _generate_privacy_pdf(
    controls: list,
    findings_map: dict,
    title: str,
    subtitle: str,
    primary_color: str = "#003366",
    scope_label: str = "",
) -> io.BytesIO:
    """Generates PDF document for privacy frameworks with custom brand color palette."""
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
        fontSize=16,
        textColor=colors.HexColor(primary_color),
    )
    cell_style = ParagraphStyle("CellStyle", parent=styles["Normal"], fontSize=8)

    story = [
        Paragraph(title, title_style),
        Paragraph(subtitle, styles["Normal"]),
    ]
    if scope_label:
        story.append(Paragraph(f"<b>Scope Filter:</b> {scope_label}", styles["Normal"]))
    story.append(Spacer(1, 10 * mm))

    table_data = [
        [
            Paragraph("<b>Control ID</b>", cell_style),
            Paragraph("<b>Title</b>", cell_style),
            Paragraph("<b>Theme</b>", cell_style),
            Paragraph("<b>Scannability</b>", cell_style),
            Paragraph("<b>Verdict</b>", cell_style),
        ]
    ]

    for c in controls:
        status_text = _verdict_of(findings_map, c.id)
        table_data.append(
            [
                Paragraph(str(c.control_number or c.id), cell_style),
                Paragraph(str(c.title), cell_style),
                Paragraph(str(c.theme), cell_style),
                Paragraph(str(c.scannability).upper(), cell_style),
                Paragraph(f"<b>{status_text}</b>", cell_style),
            ]
        )

    t = Table(table_data, colWidths=[25 * mm, 75 * mm, 30 * mm, 25 * mm, 25 * mm])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(primary_color)),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(t)

    doc.build(story)
    buffer.seek(0)
    return buffer


@router.get("/reports/dpdp_2023")
@limiter.limit("10/minute")
def download_dpdp_2023_report(
    request: Request,
    fmt: str = "pdf",
    sdf_scope: str | None = Query(
        None, description="Filter by SDF scope: sdf_mandatory, general_fiduciary"
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "export_report")),
):
    """Generates and downloads the DPDP Act 2023 Compliance Assessment Report."""
    fw_id = "cfw_dpdp_2023"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if sdf_scope and sdf_scope != "all":
        query = query.filter(ComplianceControl.sdf_scope == sdf_scope)

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
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    report_title = "DPDP Act 2023 Digital Personal Data Protection Audit Report"
    report_sub = (
        f"Data Protection Board of India Compliance Ledger (Tenant: {user.org_id[:8]})"
    )
    scope_label = f"SDF Scope: {sdf_scope.upper()}" if sdf_scope else "All Controls"

    if fmt.lower() == "docx" and Document is not None:
        buffer = _generate_privacy_docx(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"dpdp_2023_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_privacy_pdf(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            primary_color="#d97706",
            scope_label=scope_label,
        )
        media = "application/pdf"
        filename = f"dpdp_2023_report_{user.org_id[:4]}.pdf"

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/gdpr")
@limiter.limit("10/minute")
def download_gdpr_report(
    request: Request,
    fmt: str = "pdf",
    privacy_role: str | None = Query(
        None, description="Filter by Privacy Role: controller, processor, both"
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "export_report")),
):
    """Generates and downloads the EU GDPR Compliance Assessment Report."""
    fw_id = "cfw_gdpr"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if privacy_role and privacy_role != "all":
        query = query.filter(ComplianceControl.privacy_role.in_([privacy_role, "both"]))

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
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    report_title = "EU GDPR 2016/679 Compliance Assessment Audit Report"
    report_sub = (
        f"European Data Protection Board Assessment Ledger (Tenant: {user.org_id[:8]})"
    )
    scope_label = (
        f"Privacy Role: {privacy_role.upper()}" if privacy_role else "All Roles"
    )

    if fmt.lower() == "docx" and Document is not None:
        buffer = _generate_privacy_docx(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"gdpr_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_privacy_pdf(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            primary_color="#1d4ed8",
            scope_label=scope_label,
        )
        media = "application/pdf"
        filename = f"gdpr_report_{user.org_id[:4]}.pdf"

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _generate_nist_800_53_docx(
    controls, findings_map, title, subtitle, scope_label=None
):
    try:
        from docx import Document
        from docx.oxml import parse_xml
        from docx.oxml.ns import nsdecls
        from docx.shared import Inches, Pt, RGBColor
    except ImportError:
        return io.BytesIO(b"python-docx is not installed.")

    doc = Document()
    p_title = doc.add_paragraph()
    run_t = p_title.add_run(title)
    run_t.font.size = Pt(18)
    run_t.font.bold = True
    run_t.font.color.rgb = RGBColor(10, 46, 92)  # Federal Navy Blue

    p_sub = doc.add_paragraph()
    run_sub = p_sub.add_run(subtitle)
    run_sub.font.italic = True
    if scope_label:
        doc.add_paragraph(f"Scope / Baseline: {scope_label}")

    table = doc.add_table(rows=1, cols=6)
    table.style = "Table Grid"
    hdr_cells = table.rows[0].cells
    hdr_names = [
        "Control Number",
        "Title",
        "Family",
        "FedRAMP Baseline",
        "Zero Trust",
        "Verdict",
    ]
    for i, name in enumerate(hdr_names):
        shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="0A2E5C"/>')
        hdr_cells[i]._tc.get_or_add_tcPr().append(shd)
        hdr_cells[i].text = name
        for p in hdr_cells[i].paragraphs:
            for run in p.runs:
                run.font.bold = True
                run.font.color.rgb = RGBColor(255, 255, 255)

    for c in controls:
        f = findings_map.get(c.id)
        verdict = f.status.upper() if f else "UNTESTED"
        baselines = ", ".join(c.saq_profiles) if c.saq_profiles else "N/A"
        zta = "Yes" if "zero_trust" in (c.tags or []) else "No"

        row_cells = table.add_row().cells
        row_cells[0].text = c.control_number
        row_cells[1].text = c.title
        row_cells[2].text = c.theme or "N/A"
        row_cells[3].text = baselines
        row_cells[4].text = zta
        row_cells[5].text = verdict

    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer


def _generate_nist_800_53_pdf(
    controls, findings_map, title, subtitle, scope_label=None
):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
    )
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle(
        "NISTTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0A2E5C"),
    )
    sub_style = ParagraphStyle(
        "NISTSub",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#4b5563"),
    )
    hdr_style = ParagraphStyle(
        "NISTHeader",
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=10,
        textColor=colors.white,
    )
    badge_style = ParagraphStyle(
        "BadgeText",
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9,
        alignment=1,
        textColor=colors.white,
    )
    kpi_style = ParagraphStyle(
        "KPIStyle",
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        alignment=1,
        textColor=colors.HexColor("#334155"),
    )

    story.append(Paragraph(title, title_style))
    story.append(Paragraph(subtitle, sub_style))
    if scope_label:
        story.append(
            Paragraph(f"<b>Filter Baseline:</b> {scope_label}", styles["Normal"])
        )
    story.append(Spacer(1, 10))

    # Executive Headline Summary Box
    total_c = len(controls)
    passed_c = sum(
        1
        for c in controls
        if findings_map.get(c.id) and findings_map.get(c.id).status == "pass"
    )
    failed_c = sum(
        1
        for c in controls
        if findings_map.get(c.id) and findings_map.get(c.id).status == "fail"
    )
    untested_c = total_c - (passed_c + failed_c)
    score_pct = round((passed_c / total_c * 100), 1) if total_c > 0 else 0.0

    kpi_table = Table(
        [
            [
                Paragraph(
                    f"TOTAL CONTROLS<br/><font size=13 color='#0F172A'><b>{total_c}</b></font>",
                    kpi_style,
                ),
                Paragraph(
                    f"PASSED<br/><font size=13 color='#16A34A'><b>{passed_c}</b></font>",
                    kpi_style,
                ),
                Paragraph(
                    f"FAILED<br/><font size=13 color='#DC2626'><b>{failed_c}</b></font>",
                    kpi_style,
                ),
                Paragraph(
                    f"UNTESTED<br/><font size=13 color='#475569'><b>{untested_c}</b></font>",
                    kpi_style,
                ),
                Paragraph(
                    f"POSTURE SCORE<br/><font size=13 color='#0A2E5C'><b>{score_pct}%</b></font>",
                    kpi_style,
                ),
            ]
        ],
        colWidths=[100, 100, 100, 100, 110],
    )
    kpi_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.append(kpi_table)
    story.append(Spacer(1, 12))

    table_data = [
        [
            Paragraph("Control ID", hdr_style),
            Paragraph("Title", hdr_style),
            Paragraph("Family", hdr_style),
            Paragraph("FedRAMP Baseline", hdr_style),
            Paragraph("Zero Trust", hdr_style),
            Paragraph("Verdict", hdr_style),
        ]
    ]
    for c in controls:
        f = findings_map.get(c.id)
        verdict = f.status.upper() if f else "UNTESTED"
        verdict_color = (
            colors.HexColor("#16a34a")
            if verdict == "PASS"
            else (
                colors.HexColor("#dc2626")
                if verdict == "FAIL"
                else colors.HexColor("#6b7280")
            )
        )

        b_str = ", ".join(c.saq_profiles) if c.saq_profiles else "LOW"
        b_bg = (
            "#EF4444"
            if "HIGH" in b_str
            else "#F59E0B" if "MODERATE" in b_str else "#22C55E"
        )
        b_cell = Table(
            [[Paragraph(b_str, badge_style)]], colWidths=[70], rowHeights=[16]
        )
        b_cell.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(b_bg)),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )

        v_cell = Table(
            [[Paragraph(verdict, badge_style)]], colWidths=[72], rowHeights=[16]
        )
        v_cell.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), verdict_color),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )

        zta = "Yes" if "zero_trust" in (c.tags or []) else "No"

        table_data.append(
            [
                Paragraph(f"<b>{c.control_number}</b>", styles["Normal"]),
                Paragraph(c.title, styles["Normal"]),
                Paragraph(c.theme or "N/A", styles["Normal"]),
                b_cell,
                Paragraph(zta, styles["Normal"]),
                v_cell,
            ]
        )

    t = Table(table_data, colWidths=[65, 165, 75, 75, 55, 75])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0A2E5C")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, 0), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("TOPPADDING", (0, 0), (-1, 0), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    story.append(t)
    doc.build(story)
    buffer.seek(0)
    return buffer


@router.get("/reports/nist_800_53_r5")
@limiter.limit("10/minute")
def download_nist_800_53_r5_report(
    request: Request,
    fmt: str = "pdf",
    impact_level: str | None = Query(None, description="LOW | MODERATE | HIGH"),
    control_family: str | None = Query(None, description="SP53_AC | SP53_AU | etc"),
    zero_trust_only: bool = Query(False),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "export_report")),
):
    """Generates and downloads the NIST SP 800-53 Rev. 5 Federal Information Security Assessment Report."""
    fw_id = "cfw_nist_800_53_r5"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if impact_level and impact_level != "all":
        query = query.filter(
            ComplianceControl.saq_profiles.contains([impact_level.upper()])
        )

    if control_family and control_family != "all":
        query = query.filter(ComplianceControl.theme == control_family.upper())

    if zero_trust_only:
        query = query.filter(ComplianceControl.tags.contains(["zero_trust"]))

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
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    report_title = "NIST SP 800-53 Rev. 5 Federal Security Assessment Report"
    report_sub = (
        f"U.S. Federal & Defense Accreditation Ledger (Tenant: {user.org_id[:8]})"
    )
    scope_label = (
        f"FedRAMP Impact Level: {impact_level.upper()}"
        if impact_level and impact_level != "all"
        else "All Impact Baselines"
    )
    if zero_trust_only:
        scope_label += " (Zero Trust Architecture Only)"

    if fmt.lower() == "docx" and Document is not None:
        buffer = _generate_nist_800_53_docx(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"nist_800_53_r5_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_nist_800_53_pdf(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
        )
        media = "application/pdf"
        filename = f"nist_800_53_r5_report_{user.org_id[:4]}.pdf"

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ─────────────────────────────────────────────────────────────────────────────
# IEC 62443 Executive Audit Report Generators
# ─────────────────────────────────────────────────────────────────────────────


def _generate_iec_62443_pdf(
    controls,
    findings_map,
    title="IEC 62443 Industrial Cybersecurity Audit Report",
    subtitle="IACS System Security & Security Level Readiness Ledger",
    scope_label="All Security Levels (SL1–SL4)",
):
    from io import BytesIO

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle(
        "IECTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#F43F5E"),
        alignment=0,
    )
    sub_style = ParagraphStyle(
        "IECSub",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#6B7280"),
    )
    hdr_style = ParagraphStyle(
        "IECHdr",
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=10,
        textColor=colors.white,
    )
    badge_style = ParagraphStyle(
        "IECBadge",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9,
        textColor=colors.white,
        alignment=1,
    )
    kpi_style = ParagraphStyle(
        "IECKPIStyle",
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        alignment=1,
        textColor=colors.HexColor("#334155"),
    )

    story.append(Paragraph(title, title_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(subtitle, sub_style))
    if scope_label:
        story.append(Spacer(1, 4))
        story.append(
            Paragraph(f"<b>Scope Baseline:</b> {scope_label}", styles["Normal"])
        )
    story.append(Spacer(1, 10))

    # Executive Headline Summary Box
    total_c = len(controls)
    passed_c = sum(
        1
        for c in controls
        if findings_map.get(c.id) and findings_map.get(c.id).status == "pass"
    )
    failed_c = sum(
        1
        for c in controls
        if findings_map.get(c.id) and findings_map.get(c.id).status == "fail"
    )
    untested_c = total_c - (passed_c + failed_c)
    score_pct = round((passed_c / total_c * 100), 1) if total_c > 0 else 0.0

    kpi_table = Table(
        [
            [
                Paragraph(
                    f"TOTAL CONTROLS<br/><font size=13 color='#0F172A'><b>{total_c}</b></font>",
                    kpi_style,
                ),
                Paragraph(
                    f"PASSED<br/><font size=13 color='#16A34A'><b>{passed_c}</b></font>",
                    kpi_style,
                ),
                Paragraph(
                    f"FAILED<br/><font size=13 color='#DC2626'><b>{failed_c}</b></font>",
                    kpi_style,
                ),
                Paragraph(
                    f"UNTESTED<br/><font size=13 color='#475569'><b>{untested_c}</b></font>",
                    kpi_style,
                ),
                Paragraph(
                    f"READY SCORE<br/><font size=13 color='#F43F5E'><b>{score_pct}%</b></font>",
                    kpi_style,
                ),
            ]
        ],
        colWidths=[100, 100, 100, 100, 140],
    )
    kpi_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF1F2")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#FECDD3")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#FFE4E6")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.append(kpi_table)
    story.append(Spacer(1, 12))

    table_data = [
        [
            Paragraph("Requirement ID", hdr_style),
            Paragraph("Control Title", hdr_style),
            Paragraph("Theme", hdr_style),
            Paragraph("Purdue Level", hdr_style),
            Paragraph("Target SL", hdr_style),
            Paragraph("Verdict", hdr_style),
        ]
    ]
    for c in controls:
        f = findings_map.get(c.id)
        verdict = f.status.upper() if f else "UNTESTED"
        verdict_color = (
            colors.HexColor("#16A34A")
            if verdict == "PASS"
            else (
                colors.HexColor("#DC2626")
                if verdict == "FAIL"
                else colors.HexColor("#6B7280")
            )
        )

        tags = c.tags or []
        sl_str = next((t for t in tags if t.startswith("SL")), "SL1-SL4")
        purdue_levels_set = {"L0", "L1", "L2", "L3", "L3.5", "L4", "L5"}
        purdue_str = ", ".join([t for t in tags if t in purdue_levels_set]) or "L1-L3.5"

        v_cell = Table(
            [[Paragraph(verdict, badge_style)]], colWidths=[72], rowHeights=[16]
        )
        v_cell.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), verdict_color),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )

        table_data.append(
            [
                Paragraph(f"<b>{c.control_number}</b>", styles["Normal"]),
                Paragraph(c.title, styles["Normal"]),
                Paragraph(c.theme or "N/A", styles["Normal"]),
                Paragraph(purdue_str, styles["Normal"]),
                Paragraph(sl_str, styles["Normal"]),
                v_cell,
            ]
        )

    t = Table(table_data, colWidths=[80, 175, 70, 75, 60, 75])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F43F5E")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, 0), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("TOPPADDING", (0, 0), (-1, 0), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    story.append(t)
    doc.build(story)
    buffer.seek(0)
    return buffer


def _generate_iec_62443_docx(
    controls,
    findings_map,
    title="IEC 62443 Industrial Cybersecurity Audit Report",
    subtitle="IACS System Security & Security Level Readiness Ledger",
    scope_label="All Security Levels (SL1–SL4)",
):
    from io import BytesIO

    try:
        from docx import Document
        from docx.shared import Inches, Pt, RGBColor
    except ImportError:
        return BytesIO(b"python-docx is not installed.")

    doc = Document()
    doc.add_heading(title, level=0)
    p_sub = doc.add_paragraph(subtitle)
    if scope_label:
        p_scope = doc.add_paragraph(f"Scope Baseline: {scope_label}")

    table = doc.add_table(rows=1, cols=6)
    table.style = "Table Grid"
    hdr_cells = table.rows[0].cells
    hdr_titles = [
        "Requirement ID",
        "Control Title",
        "Theme",
        "Purdue Level",
        "Target SL",
        "Verdict",
    ]
    for i, t in enumerate(hdr_titles):
        hdr_cells[i].text = t

    for c in controls:
        f = findings_map.get(c.id)
        verdict = f.status.upper() if f else "UNTESTED"
        tags = c.tags or []
        sl_str = next((t for t in tags if t.startswith("SL")), "SL1-SL4")
        purdue_levels_set = {"L0", "L1", "L2", "L3", "L3.5", "L4", "L5"}
        purdue_str = ", ".join([t for t in tags if t in purdue_levels_set]) or "L1-L3.5"

        row_cells = table.add_row().cells
        row_cells[0].text = c.control_number
        row_cells[1].text = c.title
        row_cells[2].text = c.theme or "N/A"
        row_cells[3].text = purdue_str
        row_cells[4].text = sl_str
        row_cells[5].text = verdict

    buffer = BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer


@router.get("/reports/iec_62443")
@limiter.limit("10/minute")
def download_iec_62443_report(
    request: Request,
    fmt: str = Query("pdf", description="pdf | docx"),
    purdue_level: str | None = Query(None, description="L0 | L1 | L2 | L3 | L3.5"),
    component_type: str | None = Query(None, description="NDD | EDR | HDR | SW"),
    sl_level: str | None = Query(None, description="SL1 | SL2 | SL3 | SL4"),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "export_report")),
):
    """Generates and downloads the IEC 62443 Industrial Cybersecurity Assessment Report."""
    fw_id = "cfw_iec_62443"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if purdue_level and purdue_level != "all":
        query = query.filter(ComplianceControl.tags.contains([purdue_level.upper()]))

    if component_type and component_type != "all":
        query = query.filter(ComplianceControl.tags.contains([component_type.upper()]))

    if sl_level and sl_level != "all":
        query = query.filter(ComplianceControl.tags.contains([sl_level.upper()]))

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
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    report_title = "IEC 62443 Industrial Cybersecurity Audit Report"
    report_sub = f"OT/ICS System Security Ledger (Tenant: {user.org_id[:8]})"
    scope_parts = []
    if purdue_level and purdue_level != "all":
        scope_parts.append(f"Purdue Level: {purdue_level.upper()}")
    if component_type and component_type != "all":
        scope_parts.append(f"Component: {component_type.upper()}")
    if sl_level and sl_level != "all":
        scope_parts.append(f"Target SL: {sl_level.upper()}")
    scope_label = (
        ", ".join(scope_parts) if scope_parts else "All OT Assets & Security Levels"
    )

    if fmt.lower() == "docx":
        buffer = _generate_iec_62443_docx(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"iec_62443_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_iec_62443_pdf(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
        )
        media = "application/pdf"
        filename = f"iec_62443_report_{user.org_id[:4]}.pdf"

    from fastapi.responses import StreamingResponse

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _generate_nist_800_82_pdf(
    controls,
    findings_map,
    title="NIST SP 800-82 Rev. 3 OT Security Assessment Report",
    subtitle="Operational Technology (OT) Security Control Ledger & Purdue Alignment",
    scope_label="All OT Assets & Purdue Levels (L0–L5)",
):
    from io import BytesIO

    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError:
        return BytesIO(b"ReportLab is not installed.")

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    story = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "NIST82Title",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#2563EB"),
        alignment=0,
    )
    sub_style = ParagraphStyle(
        "NIST82Sub",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#6B7280"),
    )
    badge_style = ParagraphStyle(
        "NIST82Badge",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.white,
        alignment=1,
    )

    story.append(Paragraph(title, title_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(subtitle, sub_style))
    if scope_label:
        story.append(Spacer(1, 4))
        story.append(
            Paragraph(f"<b>Scope Baseline:</b> {scope_label}", styles["Normal"])
        )
    story.append(Spacer(1, 14))

    table_data = [
        [
            "Control ID",
            "Control Title",
            "Theme",
            "Purdue Level",
            "Components",
            "Verdict",
        ]
    ]
    purdue_levels_set = {"L0", "L1", "L2", "L3", "L3.5", "L4", "L5"}
    for c in controls:
        f = findings_map.get(c.id)
        verdict = f.status.upper() if f else "UNTESTED"
        verdict_color = (
            colors.HexColor("#16A34A")
            if verdict == "PASS"
            else (
                colors.HexColor("#DC2626")
                if verdict == "FAIL"
                else colors.HexColor("#6B7280")
            )
        )

        tags = c.tags or []
        purdue_str = ", ".join([t for t in tags if t in purdue_levels_set]) or "L0-L5"
        comp_types = {
            "PLC",
            "RTU",
            "SCADA",
            "DCS",
            "SIS",
            "HMI",
            "HISTORIAN",
            "IED",
            "NDD",
            "EDR",
            "HDR",
            "SW",
        }
        comp_str = ", ".join([t for t in tags if t in comp_types]) or "N/A"

        v_cell = Table(
            [[Paragraph(verdict, badge_style)]], colWidths=[55], rowHeights=[14]
        )
        v_cell.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), verdict_color),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )

        table_data.append(
            [
                Paragraph(f"<b>{c.control_number}</b>", styles["Normal"]),
                Paragraph(c.title, styles["Normal"]),
                Paragraph(c.theme or "N/A", styles["Normal"]),
                Paragraph(purdue_str, styles["Normal"]),
                Paragraph(comp_str, styles["Normal"]),
                v_cell,
            ]
        )

    t = Table(table_data, colWidths=[80, 180, 75, 75, 70, 60])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2563EB")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, 0), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("TOPPADDING", (0, 0), (-1, 0), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    story.append(t)
    doc.build(story)
    buffer.seek(0)
    return buffer


def _generate_nist_800_82_docx(
    controls,
    findings_map,
    title="NIST SP 800-82 Rev. 3 OT Security Assessment Report",
    subtitle="Operational Technology (OT) Security Control Ledger & Purdue Alignment",
    scope_label="All OT Assets & Purdue Levels (L0–L5)",
):
    from io import BytesIO

    try:
        from docx import Document
    except ImportError:
        return BytesIO(b"python-docx is not installed.")

    doc = Document()
    doc.add_heading(title, level=0)
    doc.add_paragraph(subtitle)
    if scope_label:
        doc.add_paragraph(f"Scope Baseline: {scope_label}")

    table = doc.add_table(rows=1, cols=6)
    table.style = "Table Grid"
    hdr_cells = table.rows[0].cells
    hdr_titles = [
        "Control ID",
        "Control Title",
        "Theme",
        "Purdue Level",
        "Components",
        "Verdict",
    ]
    for i, t in enumerate(hdr_titles):
        hdr_cells[i].text = t

    purdue_levels_set = {"L0", "L1", "L2", "L3", "L3.5", "L4", "L5"}
    comp_types = {
        "PLC",
        "RTU",
        "SCADA",
        "DCS",
        "SIS",
        "HMI",
        "HISTORIAN",
        "IED",
        "NDD",
        "EDR",
        "HDR",
        "SW",
    }
    for c in controls:
        f = findings_map.get(c.id)
        verdict = f.status.upper() if f else "UNTESTED"
        tags = c.tags or []
        purdue_str = ", ".join([t for t in tags if t in purdue_levels_set]) or "L0-L5"
        comp_str = ", ".join([t for t in tags if t in comp_types]) or "N/A"

        row_cells = table.add_row().cells
        row_cells[0].text = c.control_number
        row_cells[1].text = c.title
        row_cells[2].text = c.theme or "N/A"
        row_cells[3].text = purdue_str
        row_cells[4].text = comp_str
        row_cells[5].text = verdict

    buffer = BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer


@router.get("/reports/nist_800_82")
@limiter.limit("10/minute")
def download_nist_800_82_report(
    request: Request,
    fmt: str = Query("pdf", description="pdf | docx"),
    purdue_level: str | None = Query(
        None, description="L0 | L1 | L2 | L3 | L3.5 | L4 | L5"
    ),
    component_type: str | None = Query(
        None, description="PLC | RTU | SCADA | DCS | SIS | HMI | HISTORIAN | IED"
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "export_report")),
):
    """Generates and downloads the NIST SP 800-82 Rev. 3 OT Security Assessment Report."""
    fw_id = "cfw_nist_800_82_r3"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if purdue_level and purdue_level != "all":
        query = query.filter(ComplianceControl.tags.contains([purdue_level.upper()]))

    if component_type and component_type != "all":
        query = query.filter(ComplianceControl.tags.contains([component_type.upper()]))

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
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    report_title = "NIST SP 800-82 Rev. 3 OT Security Assessment Report"
    report_sub = (
        f"Operational Technology Security Control Ledger (Tenant: {user.org_id[:8]})"
    )
    scope_parts = []
    if purdue_level and purdue_level != "all":
        scope_parts.append(f"Purdue Level: {purdue_level.upper()}")
    if component_type and component_type != "all":
        scope_parts.append(f"Component: {component_type.upper()}")
    scope_label = (
        ", ".join(scope_parts) if scope_parts else "All OT Assets & Purdue Levels"
    )

    if fmt.lower() == "docx":
        buffer = _generate_nist_800_82_docx(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"nist_800_82_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_nist_800_82_pdf(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
        )
        media = "application/pdf"
        filename = f"nist_800_82_report_{user.org_id[:4]}.pdf"

    from fastapi.responses import StreamingResponse

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ─────────────────────────────────────────────────────────────────────────────
# NERC CIP Executive Audit Report Generators & Routes
# ─────────────────────────────────────────────────────────────────────────────


def _generate_nerc_cip_pdf(
    controls,
    findings_map,
    title="NERC CIP Critical Infrastructure Protection Audit Report",
    subtitle="North American Electric Reliability Corporation Compliance Assessment Ledger",
    scope_label="All BES Cyber Systems & Impact Baselines",
    regional_entity="WECC / NERC Regional Compliance Entity",
):
    from io import BytesIO

    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError:
        return BytesIO(b"ReportLab is not installed.")

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    story = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "NERCTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0284C7"),
        alignment=0,
    )
    sub_style = ParagraphStyle(
        "NERCSub",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
    )
    badge_style = ParagraphStyle(
        "NERCBadge",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.white,
        alignment=1,
    )

    story.append(Paragraph(title, title_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(subtitle, sub_style))
    story.append(Spacer(1, 4))
    story.append(
        Paragraph(
            f"<b>Regulatory Entity:</b> {regional_entity} | <b>Scope Filter:</b> {scope_label}",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 14))

    table_data = [
        [
            "Control ID",
            "Control Title",
            "Standard / Theme",
            "BES Impact",
            "Purdue / Assets",
            "Verdict",
        ]
    ]

    impact_colors = {
        "HIGH": colors.HexColor("#DC2626"),
        "MEDIUM": colors.HexColor("#EA580C"),
        "LOW": colors.HexColor("#CA8A04"),
    }

    purdue_set = {"L0", "L1", "L2", "L3", "L3.5", "L4", "L5"}
    impact_set = {"High", "Medium", "Low"}

    for c in controls:
        f = findings_map.get(c.id)
        verdict = f.status.upper() if f else "UNTESTED"
        verdict_color = (
            colors.HexColor("#16A34A")
            if verdict == "PASS"
            else (
                colors.HexColor("#DC2626")
                if verdict == "FAIL"
                else colors.HexColor("#6B7280")
            )
        )

        tags = c.tags or []
        purdue_str = ", ".join([t for t in tags if t in purdue_set]) or "L0-L5"
        impacts = [t.upper() for t in tags if t in impact_set]
        impact_str = ", ".join(impacts) if impacts else "ALL"
        top_impact = impacts[0] if impacts else "MEDIUM"
        imp_color = impact_colors.get(top_impact, colors.HexColor("#0284C7"))

        v_cell = Table(
            [[Paragraph(verdict, badge_style)]], colWidths=[55], rowHeights=[14]
        )
        v_cell.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), verdict_color),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )

        imp_cell = Table(
            [[Paragraph(impact_str, badge_style)]], colWidths=[65], rowHeights=[14]
        )
        imp_cell.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), imp_color),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )

        table_data.append(
            [
                Paragraph(f"<b>{c.control_number}</b>", styles["Normal"]),
                Paragraph(c.title, styles["Normal"]),
                Paragraph(c.theme or "N/A", styles["Normal"]),
                imp_cell,
                Paragraph(purdue_str, styles["Normal"]),
                v_cell,
            ]
        )

    t = Table(table_data, colWidths=[75, 175, 75, 70, 70, 60])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0284C7")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, 0), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("TOPPADDING", (0, 0), (-1, 0), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    story.append(t)
    doc.build(story)
    buffer.seek(0)
    return buffer


def _generate_nerc_cip_docx(
    controls,
    findings_map,
    title="NERC CIP Critical Infrastructure Protection Audit Report",
    subtitle="North American Electric Reliability Corporation Compliance Assessment Ledger",
    scope_label="All BES Cyber Systems & Impact Baselines",
    regional_entity="WECC / NERC Regional Compliance Entity",
):
    from io import BytesIO

    try:
        from docx import Document
    except ImportError:
        return BytesIO(b"python-docx is not installed.")

    doc = Document()
    doc.add_heading(title, level=0)
    doc.add_paragraph(subtitle)
    doc.add_paragraph(
        f"Regulatory Entity: {regional_entity} | Scope Filter: {scope_label}"
    )

    table = doc.add_table(rows=1, cols=6)
    table.style = "Table Grid"
    hdr_cells = table.rows[0].cells
    hdr_titles = [
        "Control ID",
        "Control Title",
        "Theme",
        "BES Impact",
        "Purdue Level",
        "Verdict",
    ]
    for i, t in enumerate(hdr_titles):
        hdr_cells[i].text = t

    purdue_set = {"L0", "L1", "L2", "L3", "L3.5", "L4", "L5"}
    impact_set = {"High", "Medium", "Low"}

    for c in controls:
        tags = c.tags or []
        purdue_str = ", ".join([t for t in tags if t in purdue_set]) or "L0-L5"
        impact_str = ", ".join([t.upper() for t in tags if t in impact_set]) or "ALL"

        row_cells = table.add_row().cells
        row_cells[0].text = c.control_number
        row_cells[1].text = c.title
        row_cells[2].text = c.theme or "N/A"
        row_cells[3].text = impact_str
        row_cells[4].text = purdue_str
        # The verdict column was declared in the header and never filled, and
        # the function never returned its buffer at all — it built a document
        # and dropped it. Nothing caught this because no route reached the
        # generator: the workspace offered NERC CIP in its report menu and
        # `/compliance/reports/nerc_cip` was not registered.
        row_cells[5].text = _verdict_of(findings_map, c.id)

    buffer = BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer


def _generate_nis2_pdf(
    controls,
    findings_map,
    title="EU NIS 2 Directive Compliance Audit Report",
    subtitle="European Union Directive (EU) 2022/2555 Cybersecurity Risk Management Audit",
    scope_label="All Essential & Important Entities",
    entity_type_label="Essential Entity",
    member_state_label="All EU (ENISA Coordinated)",
):
    from io import BytesIO

    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError:
        return BytesIO(b"ReportLab is not installed.")

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "NIS2Title",
        parent=styles["Heading1"],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#1E3A8A"),
    )
    sub_style = ParagraphStyle(
        "NIS2Sub",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#4B5563"),
    )
    section_style = ParagraphStyle(
        "NIS2Section",
        parent=styles["Heading2"],
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#1E3A8A"),
    )
    badge_style = ParagraphStyle(
        "NIS2Badge",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.white,
        alignment=1,
    )

    total_c = len(controls)
    passes = sum(
        1
        for c in controls
        if findings_map.get(c.id) and findings_map.get(c.id).status.lower() == "pass"
    )
    fails = sum(
        1
        for c in controls
        if findings_map.get(c.id) and findings_map.get(c.id).status.lower() == "fail"
    )
    untested = total_c - (passes + fails)
    score_pct = round((passes / total_c * 100), 1) if total_c > 0 else 0.0
    fine_ceiling = (
        "EUR 10,000,000 or 2% Turnover"
        if "Essential" in entity_type_label
        else "EUR 7,000,000 or 1.4% Turnover"
    )

    story = [
        Paragraph(f"<b>{title}</b>", title_style),
        Spacer(1, 4),
        Paragraph(subtitle, sub_style),
        Spacer(1, 4),
        Paragraph(
            f"<b>Entity Scope:</b> {entity_type_label} | <b>Competent Authority:</b> {member_state_label} | <b>Sector Scope:</b> {scope_label}",
            sub_style,
        ),
        Paragraph(
            f"<b>Statutory Penalty Ceiling:</b> {fine_ceiling} | <b>Compliance Rate:</b> {score_pct}%",
            sub_style,
        ),
        Spacer(1, 10),
        Paragraph("<b>1. Executive Summary Statistics</b>", section_style),
        Spacer(1, 4),
    ]

    exec_stats_data = [
        ["Total Assessed Controls", "Pass", "Fail", "Untested", "Compliance Score"],
        [str(total_c), str(passes), str(fails), str(untested), f"{score_pct}%"],
    ]
    t_stats = Table(exec_stats_data, colWidths=[120, 80, 80, 80, 180])
    t_stats.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A8A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ]
        )
    )
    story.append(t_stats)
    story.append(Spacer(1, 10))

    story.append(
        Paragraph(
            "<b>2. Article 23 CSIRT Mandatory Incident SLA Timeline</b>", section_style
        )
    )
    story.append(Spacer(1, 4))
    sla_data = [
        ["Phase", "Mandated SLA Timeline", "Scope & Description"],
        [
            "Early Warning",
            "≤ 24 Hours",
            "Notify CSIRT/Competent Authority of significant incident or cyber threat",
        ],
        [
            "Incident Notification",
            "≤ 72 Hours",
            "Submit initial assessment, severity indicator, and IoC indicators",
        ],
        [
            "Final Report",
            "≤ 1 Month",
            "Provide complete root-cause analysis, mitigation, and cross-border impact",
        ],
    ]
    t_sla = Table(sla_data, colWidths=[120, 130, 290])
    t_sla.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ]
        )
    )
    story.append(t_sla)
    story.append(Spacer(1, 10))

    story.append(
        Paragraph(
            "<b>3. Article 20 Management Board Governance Attestation</b>",
            section_style,
        )
    )
    story.append(Spacer(1, 4))
    story.append(
        Paragraph(
            '<i>"Under Article 20 of EU NIS 2 Directive (EU 2022/2555), members of the executive management body '
            "have personally reviewed the cybersecurity risk management posture, completed mandatory training, "
            'and accept personal liability for compliance oversight."</i>',
            sub_style,
        )
    )
    story.append(Spacer(1, 10))

    story.append(
        Paragraph(
            "<b>4. Article 21 Detailed Control Evaluation Matrix</b>", section_style
        )
    )
    story.append(Spacer(1, 4))

    table_data = [
        [
            "Control Number",
            "Control Title",
            "Article 21 Domain",
            "Scannability",
            "Verdict",
        ]
    ]

    for c in controls:
        f = findings_map.get(c.id)
        verdict = f.status.upper() if f else "UNTESTED"
        verdict_color = (
            colors.HexColor("#16A34A")
            if verdict == "PASS"
            else (
                colors.HexColor("#DC2626")
                if verdict == "FAIL"
                else colors.HexColor("#6B7280")
            )
        )

        v_cell = Table(
            [[Paragraph(verdict, badge_style)]], colWidths=[65], rowHeights=[14]
        )
        v_cell.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), verdict_color),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )

        table_data.append(
            [
                Paragraph(f"<b>{c.control_number}</b>", styles["Normal"]),
                Paragraph(c.title, styles["Normal"]),
                Paragraph(c.theme or "N/A", styles["Normal"]),
                Paragraph(
                    c.scannability.upper() if c.scannability else "AUTO",
                    styles["Normal"],
                ),
                v_cell,
            ]
        )

    t = Table(table_data, colWidths=[90, 210, 105, 70, 65])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A8A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, 0), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("TOPPADDING", (0, 0), (-1, 0), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    story.append(t)
    doc.build(story)
    buffer.seek(0)
    return buffer


def _generate_nis2_docx(
    controls,
    findings_map,
    title="EU NIS 2 Directive Compliance Audit Report",
    subtitle="European Union Directive (EU) 2022/2555 Cybersecurity Risk Management Audit",
    scope_label="All Essential & Important Entities",
    entity_type_label="Essential Entity",
    member_state_label="All EU (ENISA Coordinated)",
):
    from io import BytesIO

    try:
        from docx import Document
    except ImportError:
        return BytesIO(b"python-docx is not installed.")

    doc = Document()
    doc.add_heading(title, level=0)
    doc.add_paragraph(subtitle)
    doc.add_paragraph(
        f"Entity Classification: {entity_type_label} | Competent Authority: {member_state_label} | Sector Scope: {scope_label}"
    )

    doc.add_heading("1. Article 23 CSIRT SLA Timeline", level=1)
    doc.add_paragraph(
        "Early Warning: ≤ 24h | Incident Notification: ≤ 72h | Final Report: ≤ 1 Month"
    )

    doc.add_heading("2. Article 20 Board Attestation", level=1)
    doc.add_paragraph(
        "Executive management bodies accept personal accountability and confirm mandatory cybersecurity training under Article 20."
    )

    doc.add_heading("3. Control Evaluation Matrix", level=1)
    table = doc.add_table(rows=1, cols=5)
    table.style = "Table Grid"
    hdr_cells = table.rows[0].cells
    hdr_titles = [
        "Control ID",
        "Control Title",
        "Article 21 Domain",
        "Scannability",
        "Verdict",
    ]
    for i, t in enumerate(hdr_titles):
        hdr_cells[i].text = t

    for c in controls:
        f = findings_map.get(c.id)
        verdict = f.status.upper() if f else "UNTESTED"

        row_cells = table.add_row().cells
        row_cells[0].text = c.control_number
        row_cells[1].text = c.title
        row_cells[2].text = c.theme or "N/A"
        row_cells[3].text = c.scannability.upper() if c.scannability else "AUTO"
        row_cells[4].text = verdict

    buffer = BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer


@router.get("/reports/nerc_cip")
@limiter.limit("10/minute")
def download_nerc_cip_report(
    request: Request,
    fmt: str = Query("pdf", description="pdf | docx"),
    bes_impact_level: str | None = Query(None, description="High | Medium | Low"),
    standard_number: str | None = Query(None, description="CIP-002 … CIP-014"),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "export_report")),
):
    """NERC CIP Critical Infrastructure Protection audit report.

    Both generators below have existed since the framework was added and no
    route ever reached them, while the workspace's report menu offered "NERC
    CIP Critical Infrastructure" as an option — so selecting it returned 404.
    """
    fw_id = "cfw_nerc_cip"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if bes_impact_level and bes_impact_level != "all":
        query = query.filter(
            ComplianceControl.tags.contains([bes_impact_level.capitalize()])
        )
    if standard_number and standard_number != "all":
        query = query.filter(ComplianceControl.tags.contains([standard_number.upper()]))

    controls = query.all()
    controls.sort(key=lambda c: control_sort_key(c.control_number))
    control_ids = [c.id for c in controls]
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    scope_parts = []
    if bes_impact_level and bes_impact_level != "all":
        scope_parts.append(f"BES Impact: {bes_impact_level.capitalize()}")
    if standard_number and standard_number != "all":
        scope_parts.append(f"Standard: {standard_number.upper()}")
    scope_label = (
        ", ".join(scope_parts)
        if scope_parts
        else "All BES Cyber Systems & Impact Baselines"
    )

    if fmt.lower() == "docx":
        buffer = _generate_nerc_cip_docx(
            controls, findings_map, scope_label=scope_label
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"nerc_cip_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_nerc_cip_pdf(controls, findings_map, scope_label=scope_label)
        media = "application/pdf"
        filename = f"nerc_cip_report_{user.org_id[:4]}.pdf"

    log_audit_event(db, user, "export_report", "framework", fw_id, status="success")
    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/nis2")
@limiter.limit("10/minute")
def download_nis2_report(
    request: Request,
    fmt: str = Query("pdf", description="pdf | docx"),
    nis2_entity_type: str | None = Query(
        "essential", description="essential | important"
    ),
    nis2_sector: str | None = Query(None, description="all | 18 sectors"),
    nis2_member_state: str | None = Query(
        None, description="all | DE | FR | IT | NL | BE | ES | SE | PL | IE"
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("compliance", "export_report")),
):
    """Generates and downloads the EU NIS 2 Directive Regulatory Audit Report."""
    fw_id = "cfw_nis2"
    require_active_framework(fw_id)
    query = db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw_id)

    if nis2_entity_type and nis2_entity_type != "all":
        query = query.filter(
            ComplianceControl.tags.contains([nis2_entity_type.capitalize()])
        )

    if nis2_sector and nis2_sector != "all":
        query = query.filter(
            ComplianceControl.tags.contains([nis2_sector.capitalize()])
        )

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
    # One rolled-up verdict per control (see RolledFinding): the previous
    # dict comprehension let the last row of an unordered query decide.
    findings_map = rolled_up_control_findings(db, user.org_id, control_ids)

    report_title = "EU NIS 2 Directive Regulatory Compliance Audit Report"
    report_sub = f"European Union Directive (EU) 2022/2555 Security Assessment Ledger (Tenant: {user.org_id[:8]})"

    entity_label = (
        "Essential Entity (Art. 3.1)"
        if nis2_entity_type and nis2_entity_type.lower() == "essential"
        else "Important Entity (Art. 3.2)"
    )

    scope_label = (
        nis2_sector.upper()
        if nis2_sector and nis2_sector != "all"
        else "All 18 Critical Sectors"
    )

    member_state_labels = {
        "DE": "Germany — BSI (Bundesamt für Sicherheit in der Informationstechnik)",
        "FR": "France — ANSSI (Agence nationale de la sécurité des SI)",
        "IT": "Italy — ACN (Agenzia per la Cybersicurezza Nazionale)",
        "NL": "Netherlands — NCSC-NL",
        "BE": "Belgium — CCB (Centre for Cybersecurity Belgium)",
        "ES": "Spain — INCIBE / CCN-CERT",
        "SE": "Sweden — MSB",
        "PL": "Poland — NASK / CERT Polska",
        "IE": "Ireland — NCSC-IE",
    }
    member_label = (
        member_state_labels.get(nis2_member_state.upper(), "All EU (ENISA Coordinated)")
        if nis2_member_state
        else "All EU (ENISA Coordinated)"
    )

    if fmt.lower() == "docx":
        buffer = _generate_nis2_docx(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
            entity_type_label=entity_label,
            member_state_label=member_label,
        )
        media = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        filename = f"nis2_report_{user.org_id[:4]}.docx"
    else:
        buffer = _generate_nis2_pdf(
            controls,
            findings_map,
            title=report_title,
            subtitle=report_sub,
            scope_label=scope_label,
            entity_type_label=entity_label,
            member_state_label=member_label,
        )
        media = "application/pdf"
        filename = f"nis2_report_{user.org_id[:4]}.pdf"

    from fastapi.responses import StreamingResponse

    return StreamingResponse(
        buffer,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
