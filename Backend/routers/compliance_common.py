"""
routers/compliance_common.py
─────────────────────────────────────────────────────────────────────────────
What the compliance router's parts share: the refusal audit, the framework
gate, the maker-checker bypass rule, control ordering and the verdict
roll-up.

Part of the compliance router, split out of ``routers/compliance.py`` (G6,
C8 of docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md) and moved
unchanged; that module mounts the parts' sections in the order the API has
always listed them.
"""

import logging
import re
from ccure_platform.api import CurrentUser, has_permission, log_audit_event
from core import compliance_frameworks, nist_csf
from db.base import SessionLocal
from db.models import Asset
from db.models.compliance import (
    ComplianceControl,
    ComplianceFinding,
    ComplianceRule,
    ComplianceScanRun,
)
from fastapi import HTTPException
from sqlalchemy.orm import Session

# Served as ``routers.compliance``: its routes' limiter keys, logger, gateway
# policy entries and model names are that module's, as they were before the
# split (see routers/compliance.py).
__name__ = "routers.compliance"  # noqa: A001


log = logging.getLogger("ccure.compliance")


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
# Compliance's reads of the asset record
#
# The findings list and the remediation queue label a compliance finding with
# its asset. They read the asset model, as the router always did, here in one
# place; G4 recorded that these reads belong behind the asset registry's read
# API (docs/architecture/MODULAR_REFACTORING_LOG.md §7).
# ─────────────────────────────────────────────────────────────────────────────


def _findings_with_assets(db: Session):
    """Compliance findings with their control, rule and asset, outer-joined."""
    return (
        db.query(ComplianceFinding, ComplianceControl, ComplianceRule, Asset)
        .outerjoin(
            ComplianceControl, ComplianceControl.id == ComplianceFinding.control_id
        )
        .outerjoin(ComplianceRule, ComplianceRule.id == ComplianceFinding.rule_id)
        .outerjoin(Asset, Asset.id == ComplianceFinding.asset_id)
    )


def _asset_of(db: Session, asset_id: str):
    """The asset a compliance finding names, or None."""
    return db.query(Asset).filter_by(id=asset_id).first()
