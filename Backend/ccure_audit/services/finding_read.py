"""
FindingReadService — the findings an assessment reported, with their
remediation record.

Phase 5 step 5.5. The finding-read half of ``reporting/exports.py`` (GAP-15),
moved here **verbatim** so the export and the future integration adapter read
findings through one implementation:

* :func:`finding_query`, :func:`owner_names`, :func:`definition_titles` — the
  tenant-scoped base query and the two batched lookups;
* :func:`finding_pairs` — the query-building part of the export's
  ``finding_export_rows`` (scope ``scan`` or ``asset``, and the filters),
  unchanged, including its early empty answer;
* :func:`finding_context_map` — the ``(host, identifier)`` bridge the findings
  CSV joins its GAP-14 remediation columns through, unchanged.

The export keeps building its rows exactly as before from what these return.
Log records keep the ``ccure.reporting.exports`` logger name.

:class:`FindingReadService` adds frozen views for the integration adapter; the
export does not use them.
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy.orm import Session

# The rendering helpers and the host lookups the moved code calls, under the
# names it has always used. ``_text``/``_iso`` are the assessment-read copies
# the 5.4 tests pin to the export's own.
from ccure_audit.services.assessment_read import _iso, _text
from ccure_audit.services.assessment_read import (
    asset_ids_for_hosts as _asset_ids_for_hosts,
)
from ccure_audit.services.assessment_read import scan_host_audits as _scan_host_audits
from ccure_audit.services.views import view

log = logging.getLogger("ccure.reporting.exports")


def finding_query(db: Session, org_id: str):
    from db.models.assets import Asset
    from db.models.findings import AssetVulnerability

    return (
        db.query(AssetVulnerability, Asset)
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(AssetVulnerability.org_id == org_id)
    )


def owner_names(db: Session, owner_ids: Iterable[str]) -> Dict[str, str]:
    """
    Owner ids to display names, in one query.

    An email address is the only identifier a person reliably recognises, so it
    is what the export carries — and it is already what the remediation API
    returns, so the spreadsheet and the queue name the same person the same way.
    """
    wanted = sorted({str(o) for o in owner_ids if o})
    if not wanted:
        return {}
    try:
        from ccure_platform import api as platform_api

        return platform_api.user_display_names(db, wanted)
    except Exception as exc:
        log.debug("Could not resolve remediation owner names for an export: %s", exc)
        return {}


def finding_pairs(
    db: Session,
    scan: Any,
    *,
    asset_id: Optional[str] = None,
    severity: Optional[Sequence[str]] = None,
    status: Optional[Sequence[str]] = None,
    remediation_state: Optional[Sequence[str]] = None,
    overdue_only: bool = False,
    scope: str = "scan",
) -> List[Tuple[Any, Any]]:
    """
    ``(finding, asset)`` pairs for an export of *scan*, tenant-scoped.

    ``scope`` is ``"scan"`` (the findings this scan reported) or ``"asset"``
    (every finding currently held against the assets this scan touched). The
    body is the export's own query, moved unchanged.
    """
    from db.models.findings import AssetVulnerability

    org_id = str(getattr(scan, "org_id", "") or "")
    scan_id = str(getattr(scan, "id", "") or "")

    query = finding_query(db, org_id)
    if scope == "scan":
        query = query.filter(AssetVulnerability.scan_id == scan_id)
    else:
        asset_ids = sorted(
            set(
                _asset_ids_for_hosts(
                    db, org_id, [a.host for a in _scan_host_audits(db, scan)]
                ).values()
            )
        )
        scan_assets = [
            row[0]
            for row in db.query(AssetVulnerability.asset_id)
            .filter(AssetVulnerability.scan_id == scan_id)
            .distinct()
            .all()
        ]
        asset_ids = sorted(set(asset_ids) | {str(a) for a in scan_assets if a})
        if not asset_ids:
            return []
        query = query.filter(AssetVulnerability.asset_id.in_(asset_ids))

    if asset_id:
        query = query.filter(AssetVulnerability.asset_id == str(asset_id))
    if severity:
        wanted = [str(s).strip().lower() for s in severity if s]
        if wanted:
            query = query.filter(AssetVulnerability.severity.in_(wanted))
    if status:
        wanted = [str(s).strip().lower() for s in status if s]
        if wanted:
            query = query.filter(AssetVulnerability.status.in_(wanted))
    if remediation_state:
        wanted = [str(s).strip().lower() for s in remediation_state if s]
        if wanted:
            query = query.filter(AssetVulnerability.remediation_state.in_(wanted))
    if overdue_only:
        query = query.filter(
            AssetVulnerability.sla_due_at.isnot(None),
            AssetVulnerability.sla_due_at < datetime.now(timezone.utc),
        )

    # Streamed rather than materialised: a credentialed audit of one Windows
    # host produces well over a hundred findings and an estate produces
    # thousands, and holding every ORM object would be the memory explosion the
    # brief names.
    pairs = list(query.yield_per(1000))
    return pairs


def definition_titles(db: Session, vuln_ids: Iterable[str]) -> Dict[str, str]:
    """Catalogue titles for the findings being exported, in one query."""
    wanted = sorted({str(v) for v in vuln_ids if v})
    if not wanted:
        return {}
    try:
        from db.models.findings import VulnerabilityDefinition

        titles: Dict[str, str] = {}
        for start in range(0, len(wanted), 900):
            chunk = wanted[start : start + 900]
            for def_id, title in (
                db.query(VulnerabilityDefinition.id, VulnerabilityDefinition.title)
                .filter(VulnerabilityDefinition.id.in_(chunk))
                .all()
            ):
                titles[str(def_id)] = str(title or "")
        return titles
    except Exception as exc:
        log.debug("Could not resolve definition titles for an export: %s", exc)
        return {}


def finding_context_map(
    db: Session, scan: Any
) -> Dict[Tuple[str, str], Dict[str, str]]:
    """
    Remediation context for the findings CSV, keyed by ``(host, identifier)``.

    The findings CSV is generated from the *scan payload* rather than from the
    database — that is what makes it a point-in-time record of what the scan
    reported, and it is deliberately not being changed into a database dump.
    The GAP-14 record lives in the database, so this is the bridge: one query,
    a dictionary, and ``csv_generator`` looks each finding up by identity.

    Both halves of the key are normalised, because the payload spells a host as
    it probed it and an identifier in whichever case the source used.

    **Each record is registered under its title as well as its identifier**,
    and that is not belt and braces — it is the only key a configuration
    finding has. ``StandardizedFinding.plugin_id`` falls back to the title when
    the payload carries no ``plugin_id``/``id``/``rule_id`` key, and the
    credentialed pipeline emits configuration findings with the minted
    ``CCURE-CFG-…`` identifier in ``cve_id`` rather than in any of those three.
    ``cve_ids`` is then empty, because ``CCURE-CFG-…`` is correctly rejected as
    a CVE. So a CVE finding joins on its CVE and a configuration finding joins
    on its title, which the database holds because the catalogue row was minted
    from the same result.

    A title shared by two findings on one host is registered under neither:
    showing one finding's owner and due date against its sibling would be
    worse than showing none, and the identifier key still resolves both.
    """
    from core.remediation.sla import sla_state
    from db.models.findings import AssetVulnerability

    org_id = str(getattr(scan, "org_id", "") or "")
    scan_id = str(getattr(scan, "id", "") or "")
    if not org_id or not scan_id:
        return {}

    pairs = list(
        finding_query(db, org_id)
        .filter(AssetVulnerability.scan_id == scan_id)
        .yield_per(1000)
    )
    owners = owner_names(db, [f.remediation_owner for f, _a in pairs])
    titles = definition_titles(db, [f.vuln_id for f, _a in pairs])

    out: Dict[Tuple[str, str], Dict[str, str]] = {}
    ambiguous_titles: set = set()

    for finding, asset in pairs:
        state = sla_state(finding)
        payload = {
            "remediation_state": _text(finding.remediation_state),
            "remediation_owner": _text(
                owners.get(str(finding.remediation_owner or ""), "")
            ),
            "sla_due_at": _iso(finding.sla_due_at),
            "sla_state": _text(state),
            "overdue": _text(state == "overdue"),
            "verified_at": _iso(finding.verified_at),
            "verified_scan_id": _text(finding.verified_scan_id),
            "accepted_at": _iso(finding.accepted_at),
            "exception_expires_at": _iso(finding.exception_expires_at),
        }
        host = str(getattr(asset, "ip_address", "") or "").strip().lower()
        if not host:
            continue

        identifier = str(finding.vuln_id or "").strip().upper()
        if identifier:
            out[(host, identifier)] = payload

        title_key = (host, str(titles.get(str(finding.vuln_id), "")).strip().upper())
        if not title_key[1] or title_key[1] == identifier:
            continue
        if title_key in out:
            ambiguous_titles.add(title_key)
        else:
            out[title_key] = payload

    for key in ambiguous_titles:
        out.pop(key, None)

    return out


# ─────────────────────────────────────────────────────────────────────────────
# Views, for the integration adapter
#
# Typed values, not the export's rendered cells: a number stays a Decimal, a
# date a date, a timestamp an aware datetime, and "no value" stays None. The
# same base query, the same catalogue titles and the same ``sla_state`` the
# export uses, so the two cannot disagree about a finding.
# ─────────────────────────────────────────────────────────────────────────────


def _aware(value: Any) -> Optional[datetime]:
    """Stored timestamps are aware; a naive one predates that rule and is UTC,
    exactly as the export's ``_iso`` treats it."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


@view
class FindingView:
    finding_id: str
    scan_id: str
    first_scan_id: Optional[str]
    asset_id: str
    ip_address: Optional[str]
    hostname: Optional[str]
    mac_address: Optional[str]
    definition_id: str
    #: ``cve`` | ``config_check`` | ``plugin_check`` | ``privilege_check``.
    definition_type: str
    title: str
    severity: Optional[str]
    cvss_score: Optional[Decimal]
    cvss_vector: Optional[str]
    cvss_version: Optional[str]
    status: str
    source_family: str
    detection_method: Optional[str]
    confidence: Optional[str]
    qod: Optional[int]
    detected_version: Optional[str]
    in_kev: bool
    kev_due_date: Optional[date]
    epss_score: Optional[Decimal]
    epss_percentile: Optional[Decimal]
    has_exploit: bool
    verified_exploit: bool
    canary_confirmed: bool
    ransomware_linked: bool
    exploit_sources: Tuple[str, ...]
    evidence: Optional[str]
    vendor_remediation: Optional[str]
    first_found_at: datetime
    last_found_at: datetime
    fixed_at: Optional[datetime]
    remediation_state: str
    remediation_owner_id: Optional[str]
    assigned_at: Optional[datetime]
    sla_due_at: Optional[datetime]
    sla_basis: Optional[str]
    #: Computed against the current time, as the export does.
    sla_state: str
    verified_at: Optional[datetime]
    verified_scan_id: Optional[str]
    reopened_at: Optional[datetime]
    reopened_count: int
    accepted_at: Optional[datetime]
    accepted_by_id: Optional[str]
    exception_expires_at: Optional[datetime]
    accepted_risk_reason: Optional[str]


@view
class FindingPageView:
    scan_id: str
    items: Tuple[FindingView, ...]
    #: The last ``finding_id`` of this page, to pass as ``after``; ``None`` when
    #: there are no more.
    next_after: Optional[str]


def _opt(value: Any) -> Optional[str]:
    return None if value is None else str(value)


def _finding_view(finding: Any, asset: Any, title: str, state: str) -> FindingView:
    from core.checks.definitions import definition_type_for_id

    return FindingView(
        finding_id=str(finding.id),
        scan_id=str(finding.scan_id),
        first_scan_id=_opt(finding.first_scan_id),
        asset_id=str(finding.asset_id),
        ip_address=_opt(getattr(asset, "ip_address", None)),
        hostname=_opt(getattr(asset, "hostname", None)),
        mac_address=_opt(getattr(asset, "mac_address", None)),
        definition_id=str(finding.vuln_id),
        definition_type=str(definition_type_for_id(str(finding.vuln_id or ""))),
        title=title,
        severity=_opt(finding.severity),
        cvss_score=finding.cvss_score,
        cvss_vector=_opt(finding.cvss_vector),
        cvss_version=_opt(finding.cvss_version),
        status=str(finding.status),
        source_family=str(finding.source_family),
        detection_method=_opt(finding.detection_method),
        confidence=_opt(finding.confidence),
        qod=finding.qod,
        detected_version=_opt(finding.detected_version),
        in_kev=bool(finding.in_kev),
        kev_due_date=finding.kev_due_date,
        epss_score=finding.epss_score,
        epss_percentile=finding.epss_percentile,
        has_exploit=bool(finding.has_exploit),
        verified_exploit=bool(finding.verified_exploit),
        canary_confirmed=bool(finding.canary_confirmed),
        ransomware_linked=bool(finding.ransomware_linked),
        exploit_sources=tuple(str(s) for s in (finding.exploit_sources or ()) if s),
        evidence=_opt(finding.evidence),
        vendor_remediation=_opt(finding.vendor_remediation),
        first_found_at=_aware(finding.first_found_at),
        last_found_at=_aware(finding.last_found_at),
        fixed_at=_aware(finding.fixed_at),
        remediation_state=str(finding.remediation_state or "open"),
        remediation_owner_id=_opt(finding.remediation_owner),
        assigned_at=_aware(finding.assigned_at),
        sla_due_at=_aware(finding.sla_due_at),
        sla_basis=_opt(finding.sla_basis),
        sla_state=state,
        verified_at=_aware(finding.verified_at),
        verified_scan_id=_opt(finding.verified_scan_id),
        reopened_at=_aware(finding.reopened_at),
        reopened_count=int(finding.reopened_count or 0),
        accepted_at=_aware(finding.accepted_at),
        accepted_by_id=_opt(finding.accepted_by),
        exception_expires_at=_aware(finding.exception_expires_at),
        accepted_risk_reason=_opt(finding.accepted_risk_reason),
    )


class FindingReadService:
    """Read the findings one assessment reported, for one tenant, as views."""

    #: Upper bound on a page, whatever the caller asks for.
    MAX_PAGE = 1000

    def __init__(self, db: Session) -> None:
        self._db = db

    def findings(
        self,
        *,
        org_id: str,
        scan_id: str,
        after: Optional[str] = None,
        limit: int = 500,
    ) -> FindingPageView:
        """
        The findings this scan reported (the export's ``scope="scan"``), in
        ``finding_id`` order, ``limit`` at a time. Cursor paging by id, so a
        page never skips or repeats a finding however the data is paged.
        """
        from core.remediation.sla import sla_state
        from db.models.findings import AssetVulnerability
        from db.models.scans import Scan

        if not org_id:
            raise ValueError("org_id is required: an assessment belongs to one tenant")
        if limit < 1:
            raise ValueError("limit must be at least 1")
        limit = min(limit, self.MAX_PAGE)
        scan = (
            self._db.query(Scan.id)
            .filter(Scan.id == scan_id, Scan.org_id == org_id)
            .first()
        )
        if scan is None:
            # Another tenant's scan is indistinguishable from a missing one.
            raise LookupError(f"no assessment {scan_id!r} for this tenant")

        query = (
            finding_query(self._db, org_id)
            .filter(AssetVulnerability.scan_id == scan_id)
            .order_by(AssetVulnerability.id)
        )
        if after is not None:
            query = query.filter(AssetVulnerability.id > after)
        pairs = query.limit(limit + 1).all()
        more = len(pairs) > limit
        pairs = pairs[:limit]

        titles = definition_titles(self._db, [f.vuln_id for f, _a in pairs])
        items = tuple(
            _finding_view(f, a, titles.get(str(f.vuln_id), ""), sla_state(f))
            for f, a in pairs
        )
        return FindingPageView(
            scan_id=scan_id,
            items=items,
            next_after=items[-1].finding_id if more and items else None,
        )
