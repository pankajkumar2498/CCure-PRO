"""
routers/findings.py
─────────────────────────────────────────────────────────────────────────────
Vulnerability / Findings Browser REST API.

Field notes (verified against db/models/findings.py):
  VulnerabilityDefinition is the shared CVE catalogue: cvss_v2/v3/v4_score,
          cvss_vector, cvss_version, severity, cwe_ids, references, description,
          title, published_at, source.
  AssetVulnerability is the per-host finding and carries what the scan measured
          against *this* asset: severity, cvss_score, cvss_vector, cvss_version,
          confidence, qod, detection_method, detected_version, attack_surface,
          in_kev, kev_due_date, epss_score, epss_percentile, has_exploit,
          evidence, plus status and lifecycle timestamps.

Severity is read from the finding, never the catalogue. The catalogue row is
shared by every host that ever matched the CVE, whereas the finding was scored
against the version detected on this one. Severity is stored lower case
(``scans.cvss.CANONICAL_SEVERITIES``) and Title-cased on the way out, because
the frontend keys its badge classes on "Critical"/"High"/...
"""

import logging
from typing import Any, Optional

from auth.rbac import require_permission
from engines.credentialed.vuln_matcher import compare_distro_versions
from core.audit import log_audit_event
from core.vuln_intel import compute_priority
from db.base import get_db, utcnow
from db.models import User
from db.models.assets import Asset
from db.models.findings import AssetVulnerability, VulnerabilityDefinition
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from scans.cvss import canonical_severity, display_severity, severity_from_score
from sqlalchemy import String, case, func, or_
from sqlalchemy import and_ as sa_and
from sqlalchemy.orm import Session, joinedload

log = logging.getLogger("ccure.findings")
router = APIRouter(prefix="/findings", tags=["Findings"])


def _is_superadmin(user: User) -> bool:
    return (
        getattr(getattr(user, "role", None), "name", "") or ""
    ).lower() == "superadmin"


def _resolve_org(user: User, requested_org: str | None) -> str:
    if _is_superadmin(user) and requested_org:
        return requested_org
    return str(user.org_id)


def _priority_label_sql():
    """
    The priority ladder expressed in SQL, mirroring ``compute_priority``.

    It has to exist in both forms: the label is shown per row (Python) and
    filtered on across the whole result set (here). Keeping the thresholds
    identical is what stops the count in the header disagreeing with the rows
    underneath it.
    """
    cvss = func.coalesce(AssetVulnerability.cvss_score, 0)
    epss = func.coalesce(AssetVulnerability.epss_score, 0)
    return case(
        (AssetVulnerability.in_kev.is_(True), "P0"),
        (epss >= 0.70, "P1"),
        (sa_and(AssetVulnerability.has_exploit.is_(True), cvss >= 7.0), "P1"),
        (cvss >= 9.0, "P2"),
        (cvss >= 7.0, "P3"),
        (epss >= 0.30, "P3"),
        else_="P4",
    )


def _finding_port(finding: AssetVulnerability) -> str | None:
    """Port label for a finding, or None when it is a host-level finding."""
    service = getattr(finding, "service", None)
    if service is None or service.port is None:
        return None
    return f"{service.port}/{service.protocol or 'tcp'}"


# ── List Findings ─────────────────────────────────────────────────────────────


@router.get("")
@router.get("/")
def list_findings(
    severity: str | None = Query(None),
    status: str | None = Query(None),
    priority: str | None = Query(None),
    in_kev: bool | None = Query(None),
    search: str | None = Query(None),
    asset_id: str | None = Query(None),
    scan_id: str | None = Query(None),
    sort_by: str = Query("priority"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("findings", "read")),
):
    org = _resolve_org(user, org_id)

    q = (
        db.query(AssetVulnerability, VulnerabilityDefinition, Asset)
        .join(
            VulnerabilityDefinition,
            AssetVulnerability.vuln_id == VulnerabilityDefinition.id,
        )
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .options(joinedload(AssetVulnerability.service))
        .filter(Asset.org_id == org)
    )

    # Severity lives on the finding, not the catalogue: a finding is scored
    # against the version detected on *this* host, and the catalogue row is
    # shared by every host that ever matched the CVE. Comparison is folded to
    # lower case on both sides — the previous `.title()` matched only the
    # handful of Title-cased catalogue rows and hid 42 of 51 Critical+High
    # findings behind the Vulnerability Browser's default filter.
    if severity:
        sev_list = [canonical_severity(s) for s in severity.split(",") if s.strip()]
        if sev_list:
            q = q.filter(func.lower(AssetVulnerability.severity).in_(sev_list))

    if status:
        q = q.filter(
            AssetVulnerability.status.in_([s.strip() for s in status.split(",")])
        )
    else:
        q = q.filter(AssetVulnerability.status == "open")

    if in_kev is not None:
        q = q.filter(AssetVulnerability.in_kev.is_(bool(in_kev)))

    if asset_id:
        q = q.filter(AssetVulnerability.asset_id == asset_id)

    if scan_id:
        # Match a scan whether it is the one that first raised the finding or
        # the most recent to re-observe it, so selecting a historical scan no
        # longer returns nothing once a re-scan has moved `scan_id` forward.
        q = q.filter(
            or_(
                AssetVulnerability.scan_id == scan_id,
                AssetVulnerability.first_scan_id == scan_id,
            )
        )

    if search:
        q = q.filter(
            or_(
                VulnerabilityDefinition.id.ilike(f"%{search}%"),
                VulnerabilityDefinition.title.ilike(f"%{search}%"),
                func.cast(Asset.ip_address, String).ilike(f"%{search}%"),
                AssetVulnerability.detected_version.ilike(f"%{search}%"),
            )
        )

    # Priority is expressed in SQL rather than computed per row after slicing.
    # Filtering after `.limit()` returned a page shorter than its own page size
    # while `total` still reported the unfiltered count, so the UI paginated
    # over rows that were never going to appear.
    if priority:
        allowed = [p.strip().upper() for p in priority.split(",") if p.strip()]
        if allowed:
            q = q.filter(_priority_label_sql().in_(allowed))

    total = q.count()

    if sort_by == "cvss":
        q = q.order_by(AssetVulnerability.cvss_score.desc().nullslast())
    elif sort_by == "first_found":
        q = q.order_by(AssetVulnerability.first_found_at.desc())
    else:
        # "priority" — KEV first, then exploit probability, then severity.
        q = q.order_by(
            AssetVulnerability.in_kev.desc(),
            AssetVulnerability.epss_score.desc().nullslast(),
            AssetVulnerability.cvss_score.desc().nullslast(),
        )

    rows = q.offset(skip).limit(limit).all()

    result = []
    for finding, vuln, asset in rows:
        cvss = float(finding.cvss_score or 0)
        epss = float(finding.epss_score or 0)
        ps, pl = compute_priority(
            cvss_score=cvss,
            epss_score=epss,
            in_kev=bool(finding.in_kev),
            has_exploit=bool(finding.has_exploit),
        )

        result.append(
            {
                "id": finding.id,
                "vuln_id": vuln.id,
                "title": vuln.title,
                "severity": display_severity(finding.severity),
                "cvss_score": cvss,
                # Retained under its historical name for the existing frontend.
                "cvss_v3_score": cvss,
                "cvss_version": finding.cvss_version,
                "cvss_vector": finding.cvss_vector,
                "confidence": finding.confidence,
                "qod": finding.qod,
                "detection_method": finding.detection_method,
                "detected_version": finding.detected_version,
                "attack_surface": finding.attack_surface,
                "epss_score": epss,
                "epss_percentile": float(finding.epss_percentile or 0),
                "in_kev": bool(finding.in_kev),
                "kev_due_date": (
                    finding.kev_due_date.isoformat() if finding.kev_due_date else None
                ),
                "has_exploit": bool(finding.has_exploit),
                # Which corpora reported it, and how strong the evidence is.
                # "An exploit exists" spans an unreproduced proof of concept
                # and a module observed hitting honeypots; triage needs to see
                # which, and a bare boolean cannot say.
                "exploit_sources": list(finding.exploit_sources or []),
                "verified_exploit": bool(finding.verified_exploit),
                "canary_confirmed": bool(finding.canary_confirmed),
                "ransomware_linked": bool(finding.ransomware_linked),
                # The vendor's own advisory. For OT products its wording is
                # frequently the only remediation instruction in existence.
                "vendor_advisory_id": finding.vendor_advisory_id,
                "vendor_advisory_url": finding.vendor_advisory_url,
                "vendor_remediation": finding.vendor_remediation,
                "priority_score": ps,
                "priority_label": pl,
                "cwe_ids": vuln.cwe_ids or [],
                "status": finding.status,
                "asset": {
                    "id": asset.id,
                    "ip_address": str(asset.ip_address),
                    "hostname": asset.hostname,
                    "risk_score": asset.risk_score,
                },
                "port": _finding_port(finding),
                "first_found_at": (
                    finding.first_found_at.isoformat()
                    if finding.first_found_at
                    else None
                ),
                "last_found_at": (
                    finding.last_found_at.isoformat() if finding.last_found_at else None
                ),
                "fixed_at": finding.fixed_at.isoformat() if finding.fixed_at else None,
            }
        )

    return {"total": total, "skip": skip, "limit": limit, "findings": result}


# ── Grouped Findings ──────────────────────────────────────────────────────────


def _highest_version(values: Any) -> str | None:
    """
    The newest version among a group's fix targets, or None if none published.

    Compared with the distribution-aware comparator rather than as text or as
    naive tuples: these strings carry epochs and distribution releases
    (``1:3.5.5-4.el9_8``), and the whole point of the value is that upgrading
    to it clears every finding in the group. Picking the wrong one advises an
    upgrade that leaves some of them open.
    """
    best: str | None = None
    for value in values or []:
        candidate = str(value or "").strip()
        if not candidate:
            continue
        if best is None:
            best = candidate
            continue
        order = compare_distro_versions(candidate, best)
        # An unorderable pair leaves the incumbent in place rather than
        # swapping on a comparison that returned nothing.
        if order is not None and order > 0:
            best = candidate
    return best


@router.get("/grouped/by-component")
def list_findings_grouped(
    severity: str | None = Query(None),
    status: str | None = Query(None),
    asset_id: str | None = Query(None),
    scan_id: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("findings", "read")),
):
    """
    Findings rolled up to the component that would be remediated.

    One outdated application produces one row per CVE published against it. A
    single Chrome install twelve major versions behind contributed 1,736 rows to
    the vulnerability list — accurate, and unreadable. An operator upgrades
    Chrome once; this returns that as one row carrying the CVE count, the worst
    severity, and whether any of them are known-exploited.

    The per-CVE detail remains available from the ungrouped endpoint, filtered
    by the same asset and component.
    """
    org = _resolve_org(user, org_id)

    worst = func.max(AssetVulnerability.cvss_score)
    q = (
        db.query(
            AssetVulnerability.asset_id.label("asset_id"),
            Asset.ip_address.label("ip_address"),
            Asset.hostname.label("hostname"),
            func.coalesce(AssetVulnerability.component, "Unattributed").label(
                "component"
            ),
            func.max(AssetVulnerability.component_version).label("component_version"),
            # Every distinct fix target in the group, resolved to the single
            # highest one below. SQL max() cannot do it: these are version
            # strings, and text ordering puts "99.0.1" above "140.0.7339.185",
            # so the row would advise downgrading.
            func.array_agg(
                func.distinct(AssetVulnerability.component_fixed_version)
            ).label("fixed_versions"),
            func.count(AssetVulnerability.id).label("finding_count"),
            worst.label("max_cvss"),
            func.bool_or(AssetVulnerability.in_kev).label("in_kev"),
            func.max(AssetVulnerability.last_found_at).label("last_found_at"),
            func.min(AssetVulnerability.first_found_at).label("first_found_at"),
            func.count(func.nullif(AssetVulnerability.in_kev, False)).label(
                "kev_count"
            ),
            # Exploitation evidence rolled up with the findings it belongs to.
            # A component row that says "1,736 findings" ranks the same as any
            # other until it also says three of them have working exploits and
            # one has been seen against a honeypot.
            func.count(func.nullif(AssetVulnerability.has_exploit, False)).label(
                "exploit_count"
            ),
            func.bool_or(AssetVulnerability.verified_exploit).label("verified_exploit"),
            func.bool_or(AssetVulnerability.canary_confirmed).label("canary_confirmed"),
            func.bool_or(AssetVulnerability.ransomware_linked).label(
                "ransomware_linked"
            ),
        )
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(Asset.org_id == org)
        .group_by(
            AssetVulnerability.asset_id,
            Asset.ip_address,
            Asset.hostname,
            func.coalesce(AssetVulnerability.component, "Unattributed"),
        )
    )

    if severity:
        sev_list = [canonical_severity(s) for s in severity.split(",") if s.strip()]
        if sev_list:
            q = q.filter(func.lower(AssetVulnerability.severity).in_(sev_list))
    if status:
        q = q.filter(
            AssetVulnerability.status.in_([s.strip() for s in status.split(",")])
        )
    else:
        q = q.filter(AssetVulnerability.status == "open")
    if asset_id:
        q = q.filter(AssetVulnerability.asset_id == asset_id)
    if scan_id:
        q = q.filter(
            or_(
                AssetVulnerability.scan_id == scan_id,
                AssetVulnerability.first_scan_id == scan_id,
            )
        )

    total = q.count()
    rows = (
        q.order_by(
            func.bool_or(AssetVulnerability.in_kev).desc(),
            worst.desc().nullslast(),
            func.count(AssetVulnerability.id).desc(),
        )
        .offset(skip)
        .limit(limit)
        .all()
    )

    groups = []
    for r in rows:
        score = float(r.max_cvss or 0)
        target = _highest_version(r.fixed_versions)
        groups.append(
            {
                "component": r.component,
                "component_version": r.component_version,
                # The one upgrade that clears the whole group. Upgrading Chrome
                # to the newest required version also clears everything fixed
                # in the versions before it, so the group needs the highest
                # boundary any of its findings asks for — not the first seen.
                "fixed_version": target,
                "remediation": (
                    f"Upgrade {r.component} to {target} or later — "
                    f"resolves {r.finding_count} finding"
                    f"{'s' if r.finding_count != 1 else ''}"
                    if target and r.component
                    else None
                ),
                "asset": {
                    "id": r.asset_id,
                    "ip_address": str(r.ip_address) if r.ip_address else None,
                    "hostname": r.hostname,
                },
                "finding_count": r.finding_count,
                "kev_count": r.kev_count,
                "in_kev": bool(r.in_kev),
                "exploit_count": r.exploit_count,
                "verified_exploit": bool(r.verified_exploit),
                "canary_confirmed": bool(r.canary_confirmed),
                "ransomware_linked": bool(r.ransomware_linked),
                "max_cvss": score,
                "severity": display_severity(severity_from_score(score or None)),
                "first_found_at": (
                    r.first_found_at.isoformat() if r.first_found_at else None
                ),
                "last_found_at": (
                    r.last_found_at.isoformat() if r.last_found_at else None
                ),
            }
        )

    return {"total": total, "skip": skip, "limit": limit, "groups": groups}


# ── Finding Detail ────────────────────────────────────────────────────────────


@router.get("/{finding_id}")
def get_finding(
    finding_id: str,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("findings", "read")),
):
    org = _resolve_org(user, org_id)

    row = (
        db.query(AssetVulnerability, VulnerabilityDefinition, Asset)
        .join(
            VulnerabilityDefinition,
            AssetVulnerability.vuln_id == VulnerabilityDefinition.id,
        )
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(AssetVulnerability.id == finding_id, Asset.org_id == org)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding, vuln, asset = row

    # Enrich vulnerability definition details if they are missing in the postgres/main database
    if not vuln.description or not vuln.cvss_vector:
        try:
            from core.cve_database import get_cve_database

            cve_db = get_cve_database()
            if cve_db.db_available:
                details = cve_db.get_cve_details(vuln.id)
                if details:
                    vuln.description = details.get("description") or vuln.description
                    if not vuln.cvss_vector:
                        vuln.cvss_vector = details.get("cvss_vector") or details.get(
                            "cvss_v3_vector"
                        )

                    if details.get("cwe_ids"):
                        vuln.cwe_ids = details.get("cwe_ids")

                    if details.get("references"):
                        raw_refs = details.get("references")
                        clean_refs = []
                        for ref in raw_refs:
                            if isinstance(ref, str):
                                clean_refs.append(ref)
                            elif isinstance(ref, dict) and ref.get("url"):
                                clean_refs.append(ref["url"])
                        vuln.references = clean_refs

                    if details.get("published") and not vuln.published_at:
                        from datetime import date, datetime

                        pub = details.get("published")
                        if isinstance(pub, str):
                            try:
                                vuln.published_at = datetime.fromisoformat(pub).date()
                            except ValueError:
                                pass
                        elif isinstance(pub, (datetime, date)):
                            vuln.published_at = pub
                    db.commit()
        except Exception as e:
            log.warning("Failed to enrich vulnerability details for %s: %s", vuln.id, e)
            db.rollback()

    # What the scan itself recorded is authoritative — it was measured against
    # this host at scan time. The live CVE database is consulted only to fill
    # gaps for findings written before these columns existed.
    is_kev = bool(finding.in_kev)
    epss_score = float(finding.epss_score or 0.0)
    has_exploit = bool(finding.has_exploit)

    if not (is_kev or epss_score or has_exploit):
        try:
            from core.cve_database import get_cve_database

            cve_db = get_cve_database()
            if cve_db.db_available:
                details = cve_db.get_cve_details(vuln.id)
                if details:
                    epss_score = float(details.get("epss_score") or 0.0)
                    is_kev = bool(details.get("in_kev") or is_kev)
                    has_exploit = bool(details.get("has_exploit") or has_exploit)
        except Exception as e:
            log.warning(
                "Failed to lookup real-time CVE intelligence details for %s: %s",
                vuln.id,
                e,
            )

    ps, pl = compute_priority(
        cvss_score=float(finding.cvss_score or 0),
        epss_score=epss_score,
        in_kev=is_kev,
        has_exploit=has_exploit,
    )

    return {
        "id": finding.id,
        "status": finding.status,
        "severity": display_severity(finding.severity),
        "cvss_score": float(finding.cvss_score or 0),
        "cvss_version": finding.cvss_version,
        "cvss_vector": finding.cvss_vector,
        "confidence": finding.confidence,
        "qod": finding.qod,
        "detection_method": finding.detection_method,
        "detected_version": finding.detected_version,
        "attack_surface": finding.attack_surface,
        "port": _finding_port(finding),
        "in_kev": is_kev,
        "kev_due_date": (
            finding.kev_due_date.isoformat() if finding.kev_due_date else None
        ),
        "epss_score": epss_score,
        "epss_percentile": float(finding.epss_percentile or 0),
        "has_exploit": has_exploit,
        "priority_score": ps,
        "priority_label": pl,
        # The probe output the finding was actually raised on.
        "evidence": finding.evidence,
        "proof": finding.proof,
        "plugin_output": finding.plugin_output,
        "remediation_notes": finding.remediation_notes,
        "accepted_risk_reason": finding.accepted_risk_reason,
        "accepted_by": finding.accepted_by,
        "first_found_at": (
            finding.first_found_at.isoformat() if finding.first_found_at else None
        ),
        "last_found_at": (
            finding.last_found_at.isoformat() if finding.last_found_at else None
        ),
        "fixed_at": finding.fixed_at.isoformat() if finding.fixed_at else None,
        "vulnerability": {
            "id": vuln.id,
            "title": vuln.title,
            "description": vuln.description,
            "severity": display_severity(vuln.severity),
            "cvss_version": vuln.cvss_version,
            "cvss_v3_score": float(vuln.cvss_v3_score or 0),
            "cvss_v3_vector": vuln.cvss_vector,  # field is cvss_vector not cvss_v3_vector
            "cvss_v2_score": (
                float(vuln.cvss_v2_score or 0) if vuln.cvss_v2_score else None
            ),
            "epss_score": epss_score,
            "in_kev": is_kev,
            "has_exploit": has_exploit,
            "priority_score": ps,
            "priority_label": pl,
            "cwe_ids": vuln.cwe_ids or [],
            "references": vuln.references or [],
            "published_at": str(vuln.published_at) if vuln.published_at else None,
        },
        "asset": {
            "id": asset.id,
            "ip_address": str(asset.ip_address),
            "hostname": asset.hostname,
            "os_name": asset.os_name,
            "risk_score": asset.risk_score,
            "risk_level": asset.risk_level,
        },
    }


# ── Update Finding Status ─────────────────────────────────────────────────────


class StatusUpdate(BaseModel):
    status: str
    accepted_risk_reason: str | None = None
    remediation_notes: str | None = None


@router.patch("/{finding_id}/status")
def update_finding_status(
    finding_id: str,
    body: StatusUpdate,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("findings", "update")),
):
    org = _resolve_org(user, org_id)

    row = (
        db.query(AssetVulnerability, Asset)
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(AssetVulnerability.id == finding_id, Asset.org_id == org)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding, _ = row
    allowed = {"open", "accepted", "fixed"}
    if body.status not in allowed:
        raise HTTPException(status_code=400, detail=f"Status must be one of: {allowed}")

    finding.status = body.status

    if body.status == "accepted":
        finding.accepted_by = str(user.id)
        finding.accepted_risk_reason = body.accepted_risk_reason

    if body.status == "fixed":
        # **`fixed_at` is deliberately not written here.** (GAP-14.)
        #
        # That column is the evidence timeline GAP-13 reconstructs a baseline
        # from — "was this finding open at time T" is answered by
        # `first_found_at <= T and (fixed_at is null or fixed_at > T)`. It is
        # written by the two scan sweeps, from an assessment that actually
        # looked at the host.
        #
        # This endpoint previously stamped it from a user's click, which put
        # an unverified assertion into that timeline: every later comparison,
        # every report built on one, and every remediation figure downstream
        # then treated a person's opinion as an observation. A finding marked
        # fixed by hand that was never actually fixed would read as fixed for
        # ever, because no scan writes `fixed_at` for a finding it still sees.
        #
        # What a person *can* say is "I have applied the fix", which is a
        # claim that it is ready to be checked rather than a claim that it
        # works. That is `pending_verification`, and the finding stays there
        # until a scan agrees — at which point
        # `core.remediation.verification` sets `verified_fixed`, and only
        # then, and only if the scan assessed the relevant check.
        try:
            from core.remediation import STATE_VERIFIED_FIXED, claim_fixed

            if finding.remediation_state != STATE_VERIFIED_FIXED:
                claim_fixed(
                    db,
                    finding,
                    actor_id=str(user.id),
                    note=body.remediation_notes,
                )
        except Exception:  # noqa: BLE001
            # The triage status is the caller's own and must still be
            # recorded; a workflow bookkeeping failure is not a reason to
            # refuse it. Logged with its traceback so it is fixable.
            log.warning(
                "Could not move finding %s to pending verification",
                finding_id,
                exc_info=True,
            )

    if body.remediation_notes:
        finding.remediation_notes = body.remediation_notes

    log_audit_event(
        db=db,
        user=user,
        action=f"finding_{body.status}",
        resource_type="finding",
        resource_id=finding_id,
        status="success",
    )
    db.commit()

    # After status change, refresh vuln_counts and possibly risk_score for the asset
    try:
        asset_id = finding.asset_id
        sev_rows = (
            db.query(
                AssetVulnerability.severity,
                func.count(AssetVulnerability.id).label("cnt"),
            )
            .filter(
                AssetVulnerability.asset_id == asset_id,
                AssetVulnerability.status == "open",
            )
            .group_by(AssetVulnerability.severity)
            .all()
        )
        sev_map = (
            {canonical_severity(r.severity): r.cnt for r in sev_rows}
            if sev_rows
            else {}
        )
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if asset:
            asset.vuln_counts = {
                "critical": sev_map.get("critical", 0),
                "high": sev_map.get("high", 0),
                "medium": sev_map.get("medium", 0),
                "low": sev_map.get("low", 0),
            }

            # Recompute a simple aggregate risk score from counts (same logic as credentialed sync)
            computed = min(
                100,
                (asset.vuln_counts.get("critical", 0) * 25)
                + (asset.vuln_counts.get("high", 0) * 15)
                + (asset.vuln_counts.get("medium", 0) * 8)
                + (asset.vuln_counts.get("low", 0) * 3),
            )
            # Assigned unconditionally. Guarding this with `computed >=
            # risk_score` meant risk could only ever ratchet upwards: an asset
            # whose findings were all fixed or accepted kept its old score and
            # stayed "Critical" on the dashboard while its own vuln_counts read
            # zero — the two numbers came from the same rows and disagreed.
            asset.risk_score = int(computed)
            if computed >= 90:
                asset.risk_level = "Critical"
            elif computed >= 70:
                asset.risk_level = "High"
            elif computed >= 40:
                asset.risk_level = "Medium"
            elif computed > 0:
                asset.risk_level = "Low"
            else:
                asset.risk_level = "Info"
            db.commit()
    except Exception:
        db.rollback()

    return {
        "success": True,
        "id": finding_id,
        "status": body.status,
        "remediation_state": finding.remediation_state,
        # Said out loud rather than implied. A caller who set "fixed" needs to
        # know the product has recorded a claim awaiting confirmation, not a
        # confirmed fix — otherwise the distinction exists only in the
        # database and never reaches anybody.
        "verified": finding.remediation_state == "verified_fixed",
        **(
            {
                "note": (
                    "Recorded as pending verification. A finding is reported "
                    "as verified fixed only after a subsequent scan assesses "
                    "the relevant check and finds it gone."
                )
            }
            if body.status == "fixed" and finding.remediation_state != "verified_fixed"
            else {}
        ),
    }


# ── Update Remediation Notes ──────────────────────────────────────────────────


class NotesUpdate(BaseModel):
    remediation_notes: str


@router.patch("/{finding_id}/notes")
def update_finding_notes(
    finding_id: str,
    body: NotesUpdate,
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("findings", "update")),
):
    org = _resolve_org(user, org_id)
    row = (
        db.query(AssetVulnerability, Asset)
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(AssetVulnerability.id == finding_id, Asset.org_id == org)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding, _ = row
    finding.remediation_notes = body.remediation_notes.strip()
    db.commit()
    return {"success": True, "id": finding_id}
