"""
routers/compliance_assessment.py
─────────────────────────────────────────────────────────────────────────────
The compliance assessment's API: starting a scan, its findings, its runs
and the dashboard summary.

Part of the compliance router, split out of ``routers/compliance.py`` (G6,
C8 of docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md) and moved
unchanged; that module mounts the parts' sections in the order the API has
always listed them.
"""

import uuid
from ccure_platform.api import CurrentUser, log_audit_event, require_authorized
from core import compliance_frameworks
from core.rate_limiter import limiter
from datetime import datetime, timezone
from db.base import get_db
from db.models.compliance import (
    ComplianceControl,
    ComplianceException,
    ComplianceFinding,
    CompliancePolicy,
    ComplianceScanRun,
    ComplianceScore,
    ComplianceTenantFramework,
)
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from pydantic import BaseModel
from routers.compliance_common import (
    _findings_with_assets,
    _ordered_themes,
    log,
    require_active_framework,
)
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

# Served as ``routers.compliance``: its routes' limiter keys, logger, gateway
# policy entries and model names are that module's, as they were before the
# split (see routers/compliance.py).
__name__ = "routers.compliance"  # noqa: A001


scans = router = APIRouter()


class ScanTrigger(BaseModel):
    framework_id: str
    policy_id: str
    asset_ids: list[str] | None = None
    asset_tags: list[str] | None = None


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
    user: CurrentUser = Depends(require_authorized("audit.compliance.scan")),
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


findings = router = APIRouter()


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
    user: CurrentUser = Depends(require_authorized("audit.compliance.read")),
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

    q = _findings_with_assets(db).filter(
        ComplianceFinding.id.in_(subq),
        ComplianceControl.framework_id.in_(enabled_fw_ids),
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


runs = router = APIRouter()


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
    user: CurrentUser = Depends(require_authorized("audit.compliance.read")),
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
    user: CurrentUser = Depends(require_authorized("audit.compliance.read")),
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


summary = router = APIRouter()


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
    user: CurrentUser = Depends(require_authorized("audit.compliance.read")),
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
