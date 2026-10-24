"""
routers/compliance_catalogue.py
─────────────────────────────────────────────────────────────────────────────
The compliance catalogue's API: the framework marketplace, policy
baselines and their rules, and the control register.

Part of the compliance router, split out of ``routers/compliance.py`` (G6,
C8 of docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md) and moved
unchanged; that module mounts the parts' sections in the order the API has
always listed them.
"""

from ccure_platform.api import (
    CurrentUser,
    has_permission,
    log_audit_event,
    require_authorized,
)
from core import compliance_frameworks, nist_csf
from datetime import datetime, timezone
from db.base import get_db
from db.models.compliance import (
    ComplianceControl,
    ComplianceEvidenceFile,
    ComplianceFinding,
    ComplianceFramework,
    CompliancePolicy,
    CompliancePolicyRule,
    ComplianceRule,
    ComplianceRuleControl,
    ComplianceTenantFramework,
)
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from routers.compliance_common import (
    control_sort_key,
    require_active_framework,
    rolled_up_control_status,
)
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

# Served as ``routers.compliance``: its routes' limiter keys, logger, gateway
# policy entries and model names are that module's, as they were before the
# split (see routers/compliance.py).
__name__ = "routers.compliance"  # noqa: A001


marketplace = router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# 1. Framework Marketplace & Installation
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/marketplace")
def get_marketplace_frameworks(
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.read")),
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
    user: CurrentUser = Depends(
        require_authorized("audit.compliance.manage_frameworks")
    ),
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
    user: CurrentUser = Depends(
        require_authorized("audit.compliance.manage_frameworks")
    ),
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


baselines = router = APIRouter()


class PolicyCreate(BaseModel):
    framework_id: str
    name: str = Field(..., min_length=3, max_length=255)
    target_platform: str = Field(
        ..., pattern="^(windows|linux|network_device|cloud|database|any)$"
    )
    rule_ids: list[str]
    tags: list[str] | None = None


# ─────────────────────────────────────────────────────────────────────────────
# 2. Policy Baselines
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/policies")
def list_policies(
    framework_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_authorized("audit.compliance.read")),
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
    user: CurrentUser = Depends(require_authorized("audit.compliance.read")),
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
    user: CurrentUser = Depends(require_authorized("audit.compliance.manage_rules")),
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
    user: CurrentUser = Depends(require_authorized("audit.compliance.manage_rules")),
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


register = router = APIRouter()


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
    user: CurrentUser = Depends(require_authorized("audit.compliance.read")),
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
