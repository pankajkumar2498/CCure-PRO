"""
AssessmentReadService — what one assessment established, read from what it stored.

Phase 5 step 5.4. The read half of ``reporting/exports.py`` (GAP-15), moved
here **verbatim** so the export and the future integration adapter read a scan
through one implementation. The export keeps every public function and renders
exactly what it rendered before; it now calls these instead of carrying them.

What moved, unchanged in behaviour:

* the configuration-verdict walker — :func:`collect_host_audits`,
  :func:`dedupe_host_audits`, :func:`scan_host_audits` and :class:`HostAudit` —
  which finds every ``config_audit`` record across the three payload shapes a
  scan can store and never attributes one host's verdicts to another;
* :func:`control_map_for_checks` and :class:`ControlRef` — the check → control
  mapping through the tenant's enabled-and-active frameworks;
* :func:`asset_ids_for_hosts`, :func:`organisation_name` and
  :func:`policy_framework_ids` — the three lookups the export made inline.

Log records keep the ``ccure.reporting.exports`` logger name they were written
under, so existing log filters still match.

:class:`AssessmentReadService` adds the typed, frozen views the integration
adapter will consume. The export does not use the views: it keeps rendering
from the records above, so its output is byte-identical by construction.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from sqlalchemy.orm import Session

from ccure_audit.services.views import view

log = logging.getLogger("ccure.reporting.exports")


# ─────────────────────────────────────────────────────────────────────────────
# Text rendering used by the walker
#
# A deliberate copy of ``reporting.exports._text``: the walker derives a host
# and a deduplication key with it, so the two must agree exactly for the export
# to stay byte-identical. The service may not import the renderer (that would
# be a cycle), and the renderer's copy is not moved because every row cell
# depends on it. tests/audit_boundary asserts the two agree.
# ─────────────────────────────────────────────────────────────────────────────


def _text(value: Any) -> str:
    """Render a value for a cell, with ``None`` as an empty cell."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, datetime):
        return _iso(value)
    if isinstance(value, (list, tuple)):
        return "; ".join(_text(v) for v in value if v is not None and v != "")
    return str(value)


def _iso(value: Any) -> str:
    """ISO-8601 in UTC, or ``""``. Identical to ``reporting.exports._iso``."""
    if value is None or value == "":
        return ""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


# ─────────────────────────────────────────────────────────────────────────────
# Control and framework mapping
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ControlRef:
    """One framework control a check answers for."""

    framework_id: str
    framework_name: str
    control_id: str
    control_title: str
    profiles: Tuple[str, ...] = ()

    def profile_label(self) -> str:
        # Empty means the control is in scope whatever profile was selected,
        # which is what every pre-Phase-4 control is. "All" says that; an empty
        # cell would read as "nobody recorded a profile".
        return ", ".join(self.profiles) if self.profiles else "All"


# ─────────────────────────────────────────────────────────────────────────────
# Reading the scan's stored configuration verdicts
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class HostAudit:
    """One host's configuration-audit record, as the scan stored it."""

    host: str
    summary: Mapping[str, Any] = field(default_factory=dict)

    @property
    def assessed(self) -> bool:
        return bool(self.summary.get("assessed"))

    @property
    def results(self) -> List[Mapping[str, Any]]:
        return [
            r for r in (self.summary.get("results") or []) if isinstance(r, Mapping)
        ]


def collect_host_audits(
    payload: Any, host_hint: str = "", depth: int = 0
) -> List[HostAudit]:
    """
    Every ``config_audit`` record in a stored scan payload, with its host.

    Walked rather than read from a fixed path, and that is a deliberate choice
    rather than laziness. The same record reaches three different shapes: the
    vulnerability-audit pipeline nests it under
    ``_phase_data[i].credentialed_report``, the standalone credentialed scan
    puts the whole report in ``options["credentialed_report"]``, and a
    multi-host credentialed run carries a list of reports beside a single
    ``report``. A fixed path would export one of those and silently return
    nothing for the other two — an empty sheet that reads as a clean host.

    The host is taken from the record's own container, so a walk can never
    attribute one machine's verdicts to another.
    """
    found: List[HostAudit] = []
    if depth > 8:
        return found

    if isinstance(payload, Mapping):
        host = (
            _text(payload.get("target"))
            or _text(payload.get("ip_address"))
            or _text(payload.get("ip"))
            or host_hint
        )
        audit = payload.get("config_audit")
        if isinstance(audit, Mapping):
            found.append(HostAudit(host=host, summary=audit))
        for key, value in payload.items():
            if key == "config_audit":
                continue
            found.extend(collect_host_audits(value, host, depth + 1))
    elif isinstance(payload, list):
        for item in payload:
            found.extend(collect_host_audits(item, host_hint, depth + 1))

    return found


def dedupe_host_audits(audits: Sequence[HostAudit]) -> List[HostAudit]:
    """
    One record per (host, fingerprint of what it holds).

    A multi-host credentialed scan stores the first host's report twice — once
    as ``report`` for the consumers that predate multi-host support and once
    inside ``reports`` — so a plain walk returns it twice and the export would
    double every one of that host's verdicts. Counted rows are the whole point
    of the reconciliation requirement, so this is not cosmetic.
    """
    seen: set = set()
    out: List[HostAudit] = []
    for audit in audits:
        key = (
            audit.host,
            bool(audit.summary.get("assessed")),
            len(audit.results),
            _text(audit.summary.get("policy_fingerprint")),
            tuple(sorted(str(r.get("check_id") or "") for r in audit.results))[:50],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(audit)
    return out


def scan_host_audits(db: Session, scan: Any) -> List[HostAudit]:
    """Every configuration-audit record this scan produced, across its phases."""
    audits: List[HostAudit] = []

    for phase in getattr(scan, "phases", None) or []:
        audits.extend(collect_host_audits(getattr(phase, "summary", None)))

    options = getattr(scan, "options", None) or {}
    if isinstance(options, Mapping):
        report = options.get("credentialed_report")
        if report is not None:
            audits.extend(collect_host_audits(report))

    return dedupe_host_audits(audits)


def control_map_for_checks(
    db: Session,
    *,
    org_id: str,
    check_ids: Sequence[str],
    framework_ids: Optional[Sequence[str]] = None,
) -> Dict[str, List[ControlRef]]:
    """
    Which framework controls each check answers for.

    Four queries in total regardless of how many checks are passed, because
    this runs over a benchmark that can carry 955 rules and one query per check
    would be exactly the N+1 the brief names.

    The framework set is the same intersection ``compliance_sync`` writes
    through — installed by this tenant **and** active in this installation —
    optionally narrowed further by the scan's own GAP-12 framework selection.
    An export must not name a framework the tenant never installed, and it must
    not name one the scan's policy excluded, because in both cases the rest of
    that framework was never assessed.
    """
    from core.compliance_frameworks import is_active as is_active_framework
    from db.models.compliance import (
        ComplianceControl,
        ComplianceFramework,
        ComplianceRuleControl,
        ComplianceTenantFramework,
    )

    wanted_checks = [str(c) for c in check_ids if c]
    if not wanted_checks:
        return {}

    enabled = [
        row[0]
        for row in db.query(ComplianceTenantFramework.framework_id)
        .filter(
            ComplianceTenantFramework.tenant_id == org_id,
            ComplianceTenantFramework.is_enabled.is_(True),
        )
        .all()
        if is_active_framework(row[0])
    ]
    if framework_ids:
        narrowed = {str(f) for f in framework_ids if f}
        enabled = [f for f in enabled if f in narrowed]
    if not enabled:
        return {}

    framework_names = {
        fid: name
        for fid, name in db.query(ComplianceFramework.id, ComplianceFramework.name)
        .filter(ComplianceFramework.id.in_(enabled))
        .all()
    }

    mapping: Dict[str, List[ControlRef]] = {}
    # Chunked because `IN` with several thousand parameters is refused by some
    # drivers and is slow on all of them. 900 keeps well inside PostgreSQL's
    # bind-parameter ceiling with room for the other predicates.
    for start in range(0, len(wanted_checks), 900):
        chunk = wanted_checks[start : start + 900]
        rows = (
            db.query(
                ComplianceRuleControl.rule_id,
                ComplianceControl.id,
                ComplianceControl.title,
                ComplianceControl.framework_id,
                ComplianceControl.profiles,
            )
            .join(
                ComplianceControl,
                ComplianceControl.id == ComplianceRuleControl.control_id,
            )
            .filter(
                ComplianceRuleControl.rule_id.in_(chunk),
                ComplianceControl.framework_id.in_(enabled),
            )
            .all()
        )
        for rule_id, control_id, title, framework_id, profiles in rows:
            profile_tuple: Tuple[str, ...] = ()
            if isinstance(profiles, (list, tuple)):
                profile_tuple = tuple(str(p) for p in profiles if p)
            mapping.setdefault(str(rule_id), []).append(
                ControlRef(
                    framework_id=str(framework_id or ""),
                    framework_name=str(framework_names.get(framework_id) or ""),
                    control_id=str(control_id or ""),
                    control_title=str(title or ""),
                    profiles=profile_tuple,
                )
            )

    return mapping


def asset_ids_for_hosts(
    db: Session, org_id: str, hosts: Iterable[str]
) -> Dict[str, str]:
    """Map each host address to its asset id in one query."""
    wanted = sorted({str(h) for h in hosts if h})
    if not wanted or not org_id:
        return {}
    try:
        from db.models.assets import Asset

        rows = (
            db.query(Asset.ip_address, Asset.id)
            .filter(Asset.org_id == org_id, Asset.ip_address.in_(wanted))
            .all()
        )
        return {str(ip): str(asset_id) for ip, asset_id in rows}
    except Exception as exc:
        log.debug("Could not resolve asset ids for an export: %s", exc)
        return {}


def organisation_name(db: Session, scan: Any) -> str:
    """The scan organisation's display name, or ``""``. Never raises."""
    org_name = ""
    try:
        from db.models import Organization

        org = (
            db.query(Organization)
            .filter(Organization.id == getattr(scan, "org_id", None))
            .first()
        )
        org_name = str(getattr(org, "name", "") or "")
    except Exception as exc:  # an export must not fail over a display name
        log.debug("Could not resolve the organisation name for an export: %s", exc)
    return org_name


def policy_framework_ids(scan: Any) -> Optional[List[str]]:
    """
    The scan's own GAP-12 framework selection, read from its policy snapshot.

    ``None`` when the scan recorded no snapshot or it cannot be read; a list
    (possibly empty, meaning "no restriction") when it did. Never raises.
    """
    policy_frameworks: Optional[List[str]] = None

    # The scan's own framework selection, read from the snapshot. A scan
    # narrowed to one benchmark must not export rows naming the controls of a
    # framework it never assessed.
    try:
        from core.scan_policy import read_policy_snapshot

        effective = read_policy_snapshot(scan)
        if effective is not None:
            policy_frameworks = [str(f) for f in (effective.framework_ids or ()) if f]
    except Exception as exc:
        log.debug("Could not read the policy snapshot for an export: %s", exc)
    return policy_frameworks


# ─────────────────────────────────────────────────────────────────────────────
# Views, for the integration adapter
#
# Built from the same records the export renders, so the two cannot disagree
# about what a scan established. Text fields go through the same ``_text`` the
# export applies to each cell, which keeps every view value a plain string.
# ─────────────────────────────────────────────────────────────────────────────


@view
class ControlRefView:
    framework_id: str
    framework_name: str
    #: Audit's internal control row id (``cct_…``) — what the export prints.
    control_id: str
    control_title: str
    profiles: Tuple[str, ...]
    #: How the framework publishes the control: code + version + number (e.g.
    #: ``ISO27001_2022`` / ``2022`` / ``A.8.9``). This is what other modules
    #: identify a control by; the internal ``control_id`` is opaque to them.
    framework_code: str
    framework_version: str
    control_number: str


@view
class CheckVerdictView:
    """One check's stored result on one host, exactly as the engine recorded it."""

    check_id: str
    title: str
    #: The result's own target. The export falls back to it when the host
    #: record carries no host, and a consumer must do the same.
    target: str
    #: The stored ``CheckOutcome`` value, lower-cased; ``""`` when the record
    #: carries none. Never translated here: the export labels it, the adapter
    #: maps it, and neither guesses.
    outcome: str
    severity: str
    check_type: str
    domain: str
    description: str
    expected: str
    observed: str
    #: Every distinct raw reading, in order — the export's Evidence cell, split.
    evidence_lines: Tuple[str, ...]
    error: str
    remediation: str
    references: str
    not_applicable_reason: str
    controls: Tuple[ControlRefView, ...]


@view
class HostVerdictsView:
    host: str
    asset_id: Optional[str]
    platform: str
    #: False when the configuration audit did not run on this host; ``reason``
    #: then carries the engine's own explanation and ``results`` is empty.
    assessed: bool
    reason: str
    results: Tuple[CheckVerdictView, ...]


@view
class AssessmentVerdictsView:
    scan_id: str
    org_id: str
    #: The scan's GAP-12 framework selection; ``None`` when none was recorded.
    policy_framework_ids: Optional[Tuple[str, ...]]
    hosts: Tuple[HostVerdictsView, ...]


#: A control whose published identifiers could not be read. Empty rather than
#: guessed: the adapter refuses an empty identifier by name.
_UNPUBLISHED: Tuple[str, str, str] = ("", "", "")


def _check_verdict(
    result: Mapping[str, Any],
    refs: Sequence[ControlRef],
    published: Mapping[str, Tuple[str, str, str]],
) -> CheckVerdictView:
    metadata = result.get("metadata") or {}
    evidence = result.get("evidence") or []
    first = evidence[0] if evidence and isinstance(evidence[0], Mapping) else {}
    lines: List[str] = []
    for item in evidence:
        if not isinstance(item, Mapping):
            continue
        raw = _text(item.get("raw")).strip()
        if raw and raw not in lines:
            lines.append(raw)
    return CheckVerdictView(
        check_id=_text(result.get("check_id")),
        title=_text(result.get("title")),
        target=_text(result.get("target")),
        outcome=str(result.get("outcome") or "").strip().lower(),
        severity=_text(result.get("severity")),
        check_type=_text(metadata.get("check_type")),
        domain=_text(metadata.get("domain")),
        description=_text(first.get("description")),
        expected=_text(first.get("expected")),
        observed=_text(first.get("observed")),
        evidence_lines=tuple(lines),
        error=_text(result.get("error")),
        remediation=_text(result.get("remediation")),
        references=_text(result.get("references")),
        not_applicable_reason=_text(metadata.get("not_applicable_reason")),
        controls=tuple(
            ControlRefView(
                framework_id=r.framework_id,
                framework_name=r.framework_name,
                control_id=r.control_id,
                control_title=r.control_title,
                profiles=tuple(r.profiles),
                framework_code=published.get(r.control_id, _UNPUBLISHED)[0],
                framework_version=published.get(r.control_id, _UNPUBLISHED)[1],
                control_number=published.get(r.control_id, _UNPUBLISHED)[2],
            )
            for r in refs
        ),
    )


class AssessmentReadService:
    """Read one assessment's stored verdicts for one tenant, as views."""

    def __init__(self, db: Session) -> None:
        self._db = db

    def _scan(self, org_id: str, scan_id: str) -> Any:
        from db.models.scans import Scan

        if not org_id:
            raise ValueError("org_id is required: an assessment belongs to one tenant")
        scan = (
            self._db.query(Scan)
            .filter(Scan.id == scan_id, Scan.org_id == org_id)
            .first()
        )
        if scan is None:
            # Another tenant's scan is indistinguishable from a missing one.
            raise LookupError(f"no assessment {scan_id!r} for this tenant")
        return scan

    def _published_identifiers(
        self, control_ids: Iterable[str]
    ) -> Dict[str, Tuple[str, str, str]]:
        """
        ``control row id → (framework code, framework version, control number)``,
        in one query. The export's ``ControlRef`` carries only the internal ids;
        the view adds the published ones without touching the export's path.
        """
        from db.models.compliance import ComplianceControl, ComplianceFramework

        wanted = sorted({c for c in control_ids if c})
        if not wanted:
            return {}
        rows = (
            self._db.query(
                ComplianceControl.id,
                ComplianceFramework.code,
                ComplianceFramework.version,
                ComplianceControl.control_number,
            )
            .join(
                ComplianceFramework,
                ComplianceFramework.id == ComplianceControl.framework_id,
            )
            .filter(ComplianceControl.id.in_(wanted))
            .all()
        )
        return {
            str(cid): (str(code or ""), str(version or ""), str(number or ""))
            for cid, code, version, number in rows
        }

    def verdicts(self, *, org_id: str, scan_id: str) -> AssessmentVerdictsView:
        """
        Every configuration verdict the assessment stored, per host, with the
        framework controls each check answers for — through the same walker,
        policy narrowing and control map the export uses, unfiltered.
        """
        scan = self._scan(org_id, scan_id)
        frameworks = policy_framework_ids(scan)
        audits = scan_host_audits(self._db, scan)
        check_ids = sorted(
            {
                str(r.get("check_id") or "")
                for a in audits
                for r in a.results
                if r.get("check_id")
            }
        )
        controls = control_map_for_checks(
            self._db,
            org_id=org_id,
            check_ids=check_ids,
            framework_ids=frameworks or None,
        )
        assets = asset_ids_for_hosts(self._db, org_id, [a.host for a in audits])
        published = self._published_identifiers(
            {ref.control_id for refs in controls.values() for ref in refs}
        )
        hosts = tuple(
            HostVerdictsView(
                host=a.host,
                asset_id=assets.get(a.host),
                platform=_text(a.summary.get("platform")),
                assessed=a.assessed,
                reason=_text(a.summary.get("reason")) if not a.assessed else "",
                results=(
                    tuple(
                        _check_verdict(
                            r,
                            controls.get(str(r.get("check_id") or "")) or [],
                            published,
                        )
                        for r in a.results
                    )
                    if a.assessed
                    else ()
                ),
            )
            for a in audits
        )
        return AssessmentVerdictsView(
            scan_id=str(scan.id),
            org_id=org_id,
            policy_framework_ids=tuple(frameworks) if frameworks is not None else None,
            hosts=hosts,
        )
