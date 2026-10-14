"""
reporting/exports.py
─────────────────────────────────────────────────────────────────────────────
Assessment results as tabular rows, for the CSV, XLSX and JSON exporters.

    scan ──> phase payloads / asset_vulnerabilities / GAP-13 comparison
              ──> Row lists ──> csv_generator | xlsx_generator | JSON

This module produces **rows**, never files. The format layer decides how a row
is written; this layer decides what a row *is*, so the XLSX, the CSV and the
JSON cannot disagree about the same scan — which is the failure a second
exporter always produces eventually.

Three things it deliberately does not do
────────────────────────────────────────
* **Evaluate anything.** Every verdict here was reached by the Phase 3 engine
  during the scan and stored. Recomputing one at export time would report a
  result the scan never produced.
* **Compare anything.** ``comparison_export_rows`` renders a
  :class:`core.findings.ScanComparison` the caller already obtained from
  GAP-13. There is no second classification here, and a finding can therefore
  never be exported as fixed by a scan that did not assess it.
* **Authorise anything.** The caller passes a scan it has already fetched
  through its own tenant-scoped lookup. Every query below re-filters on
  ``org_id`` anyway, because a cross-tenant row in an export is the worst
  defect available in this file.

Why the verdicts come from the scan payload and not ``compliance_findings``
──────────────────────────────────────────────────────────────────────────
``compliance_findings.status`` has no ``error`` member and must not gain one —
it is a compliance verdict vocabulary, and ERROR is a scan-time condition.
``compliance_sync`` therefore maps ERROR onto ``manual_review`` with the reason
in the evidence payload, which is right for a compliance register and wrong for
an export whose stated requirement is that the states stay distinct.

The authoritative per-check record is what the engine returned:
``config_audit.results`` on the credentialed report, one entry per check, each
carrying its own :class:`core.checks.contract.CheckOutcome`. That is what this
module reads, and it is why a control that errored exports as ERROR rather than
as something a reader would take for a human review decision.

The control and framework mapping is then layered on from
``compliance_rules`` → ``compliance_rule_controls`` → ``compliance_controls``,
using the same enabled-and-active intersection ``compliance_sync`` applies, so
the export cannot name a framework the tenant never installed.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from sqlalchemy.orm import Session

# The read half of this module lives in the Audit assessment-read service
# (Phase 5.4). Imported under the names this module has always used, so the
# rendering code below is unchanged and ``reporting.exports.ControlRef`` /
# ``control_map_for_checks`` still resolve for existing callers.
from ccure_audit.services.assessment_read import (  # noqa: F401
    ControlRef,
    HostAudit as _HostAudit,
    asset_ids_for_hosts as _asset_ids_for_hosts,
    collect_host_audits as _collect_host_audits,
    control_map_for_checks,
    dedupe_host_audits as _dedupe_host_audits,
    organisation_name,
    policy_framework_ids,
    scan_host_audits as _scan_host_audits,
)

# The finding-read half lives in the Audit finding-read service (Phase 5.5),
# imported under the names this module has always used.
from ccure_audit.services.finding_read import (  # noqa: F401
    definition_titles as _definition_titles,
    finding_context_map,
    finding_pairs,
    owner_names as _owner_names,
)

log = logging.getLogger("ccure.reporting.exports")

__all__ = [
    "COMPARISON_COLUMNS",
    "CONFIG_VERDICT_COLUMNS",
    "FINDING_EXPORT_COLUMNS",
    "SCAN_CONTEXT_COLUMNS",
    "VERDICT_LABELS",
    "VERDICT_NOT_ASSESSED",
    "ControlRef",
    "comparison_export_rows",
    "compliance_verdict_rows",
    "control_map_for_checks",
    "export_payload",
    "finding_context_map",
    "finding_export_rows",
    "scan_context",
    "scan_context_rows",
    "workbook_sheets",
]


# ─────────────────────────────────────────────────────────────────────────────
# Verdict vocabulary
# ─────────────────────────────────────────────────────────────────────────────

#: How a stored ``CheckOutcome`` is spelled in an export.
#:
#: Upper case, and each one distinct. The requirement this satisfies is that a
#: control which was not assessed, could not be assessed, or does not apply is
#: never rendered as passed or failed — so there is no ``""`` in this table and
#: no two outcomes share a label. An outcome this build does not recognise is
#: passed through in upper case rather than blanked, because a value nobody
#: defined is still a fact about the stored record.
VERDICT_LABELS: Dict[str, str] = {
    "pass": "PASS",
    "fail": "FAIL",
    "not_applicable": "NOT_APPLICABLE",
    "manual_review": "MANUAL_REVIEW",
    "error": "ERROR",
}

#: The sixth state, and the only one that is not a stored outcome. It means the
#: check was in scope for the host and the scan produced no verdict for it —
#: the configuration audit did not run at all. It exists so an export of such a
#: scan says so out loud, rather than shipping an empty sheet that a reader
#: takes for a clean host.
VERDICT_NOT_ASSESSED = "NOT_ASSESSED"


def _verdict_label(outcome: Any) -> str:
    text = str(outcome or "").strip().lower()
    if not text:
        return VERDICT_NOT_ASSESSED
    return VERDICT_LABELS.get(text, text.upper())


# ─────────────────────────────────────────────────────────────────────────────
# Column surfaces
#
# These lists are the export's contract. The coverage measurement reads them,
# so a column removed here loses its coverage credit rather than quietly
# continuing to be claimed.
# ─────────────────────────────────────────────────────────────────────────────

CONFIG_VERDICT_COLUMNS: Tuple[str, ...] = (
    "Scan ID",
    "Scan Number",
    "Scan Completed",
    "Organization",
    "Asset ID",
    "Host",
    "Platform",
    "Framework ID",
    "Framework Name",
    "Control ID",
    "Control Title",
    "Profile",
    "Check ID",
    "Check Type",
    "Check Domain",
    "Title",
    "Description",
    "Verdict",
    "Severity",
    "Expected",
    "Observed",
    "Evidence",
    "Applicability",
    "Error",
    "Remediation",
    "References",
    "Policy Name",
    "Policy Version",
    "Configuration ID",
)

FINDING_EXPORT_COLUMNS: Tuple[str, ...] = (
    "Finding ID",
    "Scan ID",
    "Asset ID",
    "Host",
    "Hostname",
    "Identifier",
    "Definition Type",
    "Title",
    "Severity",
    "CVSS Score",
    "Status",
    "Source",
    "In CISA KEV",
    "KEV Due Date",
    "EPSS Probability",
    "Evidence",
    "First Found",
    "Last Found",
    "Fixed At",
    "Remediation State",
    "Remediation Owner",
    "Assigned At",
    "SLA Due",
    "SLA Basis",
    "SLA State",
    "Overdue",
    "Verified At",
    "Verified By Scan",
    "Reopened At",
    "Reopened Count",
    "Risk Accepted At",
    "Risk Acceptance Expires",
    "Risk Acceptance Reason",
    "Remediation Notes",
    "Policy Name",
    "Configuration ID",
    # Appended, after the policy columns, for the reason every addition to an
    # export in this product is appended: a consumer reading by index keeps
    # working.
    #
    # "In CISA KEV" above is catalogue membership with a federal deadline
    # behind it. This is whether any public exploit exists at all, which on
    # this installation is true of 27,640 CVEs CISA does not list - so it is
    # not a duplicate of the column three places to its left.
    #
    # There is deliberately **no Priority column here**, and that asymmetry
    # with the scan findings CSV is on purpose. Priority is not stored on
    # `asset_vulnerabilities`; the findings API derives it in a SQL CASE at
    # read time. Emitting it here would mean a second derivation, and the one
    # rule this whole field is governed by is that the report carries the
    # backend's value rather than computing its own.
    "Exploit Availability",
    "Vendor Remediation",
)

COMPARISON_COLUMNS: Tuple[str, ...] = (
    "Current Scan ID",
    "Baseline Scan ID",
    "Finding ID",
    "Identifier",
    "Asset ID",
    "Change",
    "Severity",
    "Title",
    "Source",
    "First Found",
    "Last Found",
    "Fixed At",
    "Evidence",
)

SCAN_CONTEXT_COLUMNS: Tuple[str, ...] = ("Field", "Value")


# ─────────────────────────────────────────────────────────────────────────────
# Small helpers
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
    """
    An ISO-8601 timestamp in UTC, or an empty cell.

    Naive datetimes are stamped UTC rather than left ambiguous: every timestamp
    this product stores is timezone-aware UTC, and a naive one reaching here is
    a row that predates that rule. Rendering it without a zone beside aware
    siblings would put two clocks in one column.
    """
    if value is None or value == "":
        return ""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


# ─────────────────────────────────────────────────────────────────────────────
# Scan context
# ─────────────────────────────────────────────────────────────────────────────


def scan_context(db: Session, scan: Any) -> Dict[str, Any]:
    """
    The scan's own identity and the immutable GAP-12 policy snapshot.

    Read from ``scans.options["scan_policy"]`` — the snapshot the dispatching
    side wrote and the worker executed from — and **never** from the policy row
    it names. The policy may since have been edited, versioned or archived, and
    none of that changes what this scan assessed. That is the whole reason the
    snapshot exists, and an export that resolved the live row instead would
    misreport every scan whose policy has moved on.
    """
    from core.findings.comparison import policy_context
    from core.checks.plugin_outcomes import coverage_summary

    org_name = organisation_name(db, scan)

    policy = policy_context(scan)
    policy = _scoped_policy(policy, _text(getattr(scan, "pipeline_mode", "")))

    return {
        "scan_id": str(getattr(scan, "id", "") or ""),
        "scan_no": _text(getattr(scan, "scan_no", "")),
        "scan_type": _text(getattr(scan, "scan_type", "")),
        "pipeline_mode": _text(getattr(scan, "pipeline_mode", "")),
        "status": _text(getattr(scan, "status", "")),
        "target": _text(getattr(scan, "target_str", "")),
        "started_at": _iso(getattr(scan, "started_at", None)),
        "completed_at": _iso(getattr(scan, "completed_at", None)),
        "org_id": str(getattr(scan, "org_id", "") or ""),
        "org_name": org_name,
        "policy": policy,
        # None for a scan that never recorded its candidate searches; [] for
        # one where every search ran to completion. See core.candidate_enumeration.
        "candidate_searches_truncated": _truncated_searches(db, scan),
        "network_plugin_coverage": coverage_summary(_scan_hosts(db, scan)),
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }


def _truncated_searches(db: Session, scan: Any) -> List[str] | None:
    from core.candidate_enumeration import describe, truncated_searches

    hosts = _scan_hosts(db, scan)
    if not any("candidate_enumeration" in h for h in hosts):
        return None
    return [describe(entry) for entry in truncated_searches(hosts)]


#: Policy settings that only a vulnerability or configuration assessment reads.
_CHECK_SETTINGS = (
    "Benchmarks",
    "Benchmark profile",
    "Platform scope",
    "Check families",
    "Assessment sections",
    "Built-in checks",
    "Severity threshold",
    "Check exclusions",
    "Tag exclusions",
    "Intrusive probes",
    "Credential required",
)
_NO_CHECKS = "Not applicable — this scan type runs no checks"


def _scoped_policy(policy: Mapping[str, Any], pipeline_mode: str) -> Dict[str, Any]:
    """
    The policy snapshot with settings this scan type never used marked so.

    A Basic Network Scan's export said "Benchmarks: Every framework installed
    for this organisation" and "Built-in checks: Included" — true of the
    snapshot's defaults and false of a scan that ran no checks at all.
    """
    scoped = dict(policy or {})
    summary = scoped.get("summary")
    if not isinstance(summary, Mapping) or pipeline_mode not in ("basic", "asset"):
        return scoped
    summary = dict(summary)
    for key in _CHECK_SETTINGS:
        if key in summary:
            summary[key] = _NO_CHECKS
    if pipeline_mode == "basic":
        for key in ("Port selection", "Port exclusions"):
            if key in summary:
                summary[key] = "Not applicable — host discovery scans no ports"
    scoped["summary"] = summary
    return scoped


def scan_context_rows(context: Mapping[str, Any]) -> List[List[str]]:
    """The scan context as a two-column sheet a person can read."""
    policy = context.get("policy") or {}
    rows: List[List[str]] = [
        ["Scan ID", _text(context.get("scan_id"))],
        ["Scan Number", _text(context.get("scan_no"))],
        ["Scan Type", _text(context.get("scan_type"))],
        ["Pipeline", _text(context.get("pipeline_mode"))],
        ["Status", _text(context.get("status"))],
        ["Target", _text(context.get("target"))],
        ["Started", _text(context.get("started_at"))],
        ["Completed", _text(context.get("completed_at"))],
        ["Organization ID", _text(context.get("org_id"))],
        ["Organization", _text(context.get("org_name"))],
        ["Exported At", _text(context.get("exported_at"))],
    ]
    truncated = context.get("candidate_searches_truncated")
    coverage = context.get("network_plugin_coverage") or {}
    if coverage.get("recorded"):
        rows.append(
            [
                "Network plugin coverage",
                (
                    "Complete"
                    if coverage.get("complete")
                    else "Incomplete; absence of findings does not establish a clean assessment"
                ),
            ]
        )
        for outcome in coverage.get("incomplete", []):
            rows.append(
                [
                    f"{outcome.get('host')} / {outcome.get('plugin')}",
                    f"{outcome.get('status')}: {outcome.get('detail', '')}",
                ]
            )
    if truncated is not None:
        rows.append(
            [
                "Candidate Searches Truncated",
                (
                    "; ".join(truncated)
                    if truncated
                    else "None — every candidate search ran to completion"
                ),
            ]
        )
    if policy.get("recorded"):
        rows.extend(
            [
                ["Policy Name", _text(policy.get("policy_name"))],
                ["Policy Version", _text(policy.get("version_number"))],
                ["Policy Source", _text(policy.get("source"))],
                ["Configuration ID", _text(policy.get("fingerprint"))],
            ]
        )
        # One row per setting. The whole mapping used to be written into one
        # cell as a Python dict repr — "{'Policy': 'None (scan …" — which no
        # reader or spreadsheet formula can use.
        summary = policy.get("summary")
        if isinstance(summary, Mapping):
            rows.extend(
                [f"Policy: {key}", _text(value)] for key, value in summary.items()
            )
        elif summary:
            rows.append(["Policy Summary", _text(summary)])
    else:
        # Said in words rather than left blank. A scan that predates GAP-12 has
        # no recorded configuration, and an empty Configuration ID cell would
        # read as an export that failed to fill it in.
        rows.append(
            [
                "Policy",
                "No scan policy was recorded for this scan; it predates the "
                "scan policy engine or ran before a snapshot could be written.",
            ]
        )
    return rows


def _policy_columns(context: Mapping[str, Any]) -> Tuple[str, str, str]:
    policy = context.get("policy") or {}
    if not policy.get("recorded"):
        return ("", "", "")
    return (
        _text(policy.get("policy_name")),
        _text(policy.get("version_number")),
        _text(policy.get("fingerprint")),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Compliance / benchmark verdict rows
# ─────────────────────────────────────────────────────────────────────────────


def compliance_verdict_rows(
    db: Session,
    scan: Any,
    *,
    context: Optional[Mapping[str, Any]] = None,
    asset_id: Optional[str] = None,
    host: Optional[str] = None,
    framework_id: Optional[str] = None,
    profile: Optional[str] = None,
    severity: Optional[Sequence[str]] = None,
    verdict: Optional[Sequence[str]] = None,
) -> List[List[str]]:
    """
    One row per (check, control) verdict this scan actually produced.

    A check that maps to no installed framework control still gets a row, with
    empty framework and control cells. Dropping it would silently lose every
    built-in check and every benchmark rule the tenant has not crosswalked —
    and those are assessment results the scan really produced. The reconciliation
    requirement is that no row disappears; a row with an empty mapping column is
    not a missing row.

    A check that maps to *several* controls gets one row per control, which is
    what makes the sheet usable as a compliance register. The count of distinct
    checks is therefore not the row count, and the summary sheet states both.
    """
    context = dict(context or scan_context(db, scan))
    org_id = str(getattr(scan, "org_id", "") or "")
    policy = context.get("policy") or {}
    # The scan's own framework selection, read from the snapshot. A scan
    # narrowed to one benchmark must not export rows naming the controls of a
    # framework it never assessed.
    policy_frameworks = policy_framework_ids(scan)

    if framework_id:
        wanted = [str(framework_id)]
        policy_frameworks = (
            [f for f in policy_frameworks if f in wanted]
            if policy_frameworks
            else wanted
        )

    audits = _scan_host_audits(db, scan)
    if host:
        audits = [a for a in audits if a.host == host]

    check_ids = sorted(
        {
            str(r.get("check_id") or "")
            for a in audits
            for r in a.results
            if r.get("check_id")
        }
    )
    controls = control_map_for_checks(
        db,
        org_id=org_id,
        check_ids=check_ids,
        framework_ids=policy_frameworks or None,
    )

    hosts_to_assets = _asset_ids_for_hosts(db, org_id, [a.host for a in audits])
    if asset_id:
        audits = [a for a in audits if hosts_to_assets.get(a.host) == str(asset_id)]

    wanted_severity = {str(s).strip().lower() for s in (severity or []) if s}
    wanted_verdict = {str(v).strip().upper() for v in (verdict or []) if v}
    policy_name, policy_version, configuration_id = _policy_columns(context)

    rows: List[List[str]] = []
    for audit in audits:
        platform = _text(audit.summary.get("platform"))
        asset = hosts_to_assets.get(audit.host, "")

        if not audit.assessed:
            # The audit did not run on this host. One explicit row carrying the
            # engine's own reason, so the export states it rather than being
            # silent — an empty sheet reads as a clean host.
            row_verdict = VERDICT_NOT_ASSESSED
            if wanted_verdict and row_verdict not in wanted_verdict:
                continue
            if wanted_severity:
                continue
            rows.append(
                _verdict_row(
                    context=context,
                    asset_id=asset,
                    host=audit.host,
                    platform=platform,
                    control=None,
                    result={},
                    verdict_label=row_verdict,
                    applicability=_text(audit.summary.get("reason")),
                    policy=(policy_name, policy_version, configuration_id),
                )
            )
            continue

        for result in audit.results:
            label = _verdict_label(result.get("outcome"))
            if wanted_verdict and label not in wanted_verdict:
                continue
            if (
                wanted_severity
                and str(result.get("severity") or "").strip().lower()
                not in wanted_severity
            ):
                continue

            refs = controls.get(str(result.get("check_id") or "")) or [None]
            for ref in refs:
                if profile and ref is not None and ref.profiles:
                    if str(profile) not in ref.profiles:
                        continue
                rows.append(
                    _verdict_row(
                        context=context,
                        asset_id=asset,
                        host=audit.host or _text(result.get("target")),
                        platform=platform,
                        control=ref,
                        result=result,
                        verdict_label=label,
                        applicability=_text(
                            (result.get("metadata") or {}).get("not_applicable_reason")
                        ),
                        policy=(policy_name, policy_version, configuration_id),
                    )
                )

    return rows


def _verdict_row(
    *,
    context: Mapping[str, Any],
    asset_id: str,
    host: str,
    platform: str,
    control: Optional[ControlRef],
    result: Mapping[str, Any],
    verdict_label: str,
    applicability: str,
    policy: Tuple[str, str, str],
) -> List[str]:
    metadata = result.get("metadata") or {}
    evidence = result.get("evidence") or []
    first = evidence[0] if evidence and isinstance(evidence[0], Mapping) else {}

    # Every distinct raw reading, joined. A rule with seven registry objects
    # that all found nothing printed the same sentence seven times in the PDF
    # before this was collapsed there; the same applies in a cell.
    raw_lines: List[str] = []
    for item in evidence:
        if not isinstance(item, Mapping):
            continue
        raw = _text(item.get("raw")).strip()
        if raw and raw not in raw_lines:
            raw_lines.append(raw)

    return [
        _text(context.get("scan_id")),
        _text(context.get("scan_no")),
        _text(context.get("completed_at")),
        _text(context.get("org_name")) or _text(context.get("org_id")),
        _text(asset_id),
        _text(host),
        _text(platform),
        _text(control.framework_id) if control else "",
        _text(control.framework_name) if control else "",
        _text(control.control_id) if control else "",
        _text(control.control_title) if control else "",
        control.profile_label() if control else "",
        _text(result.get("check_id")),
        _text(metadata.get("check_type")),
        _text(metadata.get("domain")),
        _text(result.get("title")),
        _text(first.get("description")),
        verdict_label,
        _text(result.get("severity")),
        _text(first.get("expected")),
        _text(first.get("observed")),
        "\n".join(raw_lines),
        applicability,
        _text(result.get("error")),
        _text(result.get("remediation")),
        _text(result.get("references")),
        policy[0],
        policy[1],
        policy[2],
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Findings, with the GAP-14 remediation record
# ─────────────────────────────────────────────────────────────────────────────


def finding_export_rows(
    db: Session,
    scan: Any,
    *,
    context: Optional[Mapping[str, Any]] = None,
    asset_id: Optional[str] = None,
    severity: Optional[Sequence[str]] = None,
    status: Optional[Sequence[str]] = None,
    remediation_state: Optional[Sequence[str]] = None,
    overdue_only: bool = False,
    scope: str = "scan",
) -> List[List[str]]:
    """
    One row per finding, carrying its GAP-14 remediation and SLA record.

    ``scope`` is ``"scan"`` — the findings this scan reported — or ``"asset"``,
    every finding currently held against the assets this scan touched. The
    second is what a remediation owner wants (a scan that fixed nothing still
    has an overdue list) and the first is what an auditor wants (what did *this*
    assessment say). They are different questions and the export names which
    one it answered rather than picking one silently.

    The SLA state is computed here rather than stored, because "overdue" is a
    function of the current time and a materialised copy would be stale the
    moment it was written. ``sla_due_at`` itself *is* materialised — that is the
    indexed predicate — and this only compares it against now.
    """
    from core.remediation.sla import sla_state

    context = dict(context or scan_context(db, scan))

    pairs = finding_pairs(
        db,
        scan,
        asset_id=asset_id,
        severity=severity,
        status=status,
        remediation_state=remediation_state,
        overdue_only=overdue_only,
        scope=scope,
    )

    owners = _owner_names(db, [f.remediation_owner for f, _asset in pairs])
    definitions = _definition_titles(db, [f.vuln_id for f, _asset in pairs])
    policy_name, _policy_version, configuration_id = _policy_columns(context)

    rows: List[List[str]] = []
    for finding, asset in pairs:
        state = sla_state(finding)
        rows.append(
            [
                _text(finding.id),
                _text(finding.scan_id),
                _text(finding.asset_id),
                _text(getattr(asset, "ip_address", "")),
                _text(getattr(asset, "hostname", "")),
                _text(finding.vuln_id),
                _definition_type(finding.vuln_id),
                _text(definitions.get(str(finding.vuln_id), "")),
                _text(finding.severity),
                _text(finding.cvss_score),
                _text(finding.status),
                _text(finding.source_family),
                _text(bool(finding.in_kev)),
                _iso(finding.kev_due_date),
                _text(finding.epss_score),
                _text(finding.evidence),
                _iso(finding.first_found_at),
                _iso(finding.last_found_at),
                _iso(finding.fixed_at),
                _text(finding.remediation_state),
                _text(owners.get(str(finding.remediation_owner or ""), "")),
                _iso(finding.assigned_at),
                _iso(finding.sla_due_at),
                _text(finding.sla_basis),
                _text(state),
                _text(state == "overdue"),
                _iso(finding.verified_at),
                _text(finding.verified_scan_id),
                _iso(finding.reopened_at),
                _text(finding.reopened_count),
                _iso(finding.accepted_at),
                _iso(finding.exception_expires_at),
                _text(finding.accepted_risk_reason),
                _text(finding.remediation_notes),
                policy_name,
                configuration_id,
                # Three-valued, like everywhere else this field is rendered.
                # The column is NOT NULL on the table with a server default of
                # false, so a row written before the exploit feeds were wired
                # carries `false` meaning "never looked" - but that is the
                # column's own history and not something this export can
                # correct. What it can do is not add a second layer of
                # guessing on top: the stored value is printed as stored.
                _text(bool(finding.has_exploit)),
                _text(finding.vendor_remediation),
            ]
        )
    return rows


def _definition_type(vuln_id: Any) -> str:
    try:
        from core.checks.definitions import definition_type_for_id

        return _text(definition_type_for_id(str(vuln_id or "")))
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# Scan comparison
# ─────────────────────────────────────────────────────────────────────────────


def comparison_export_rows(comparison: Any) -> List[List[str]]:
    """
    A GAP-13 comparison as rows. No classification happens here.

    Every ``classification`` value is the one GAP-13 assigned, upper-cased for
    the sheet, so a finding can never be exported as FIXED by a scan that did
    not assess it — that refusal lives in ``core/findings/comparison.py`` and
    is not repeated, weakened or second-guessed here.
    """
    if comparison is None:
        return []
    rows: List[List[str]] = []
    for delta in getattr(comparison, "findings", None) or []:
        rows.append(
            [
                _text(getattr(comparison, "current_scan_id", "")),
                _text(getattr(comparison, "baseline_scan_id", "")),
                _text(getattr(delta, "finding_id", "")),
                _text(getattr(delta, "vuln_id", "")),
                _text(getattr(delta, "asset_id", "")),
                str(getattr(delta, "classification", "") or "").upper(),
                _text(getattr(delta, "severity", "")),
                _text(getattr(delta, "title", "")),
                _text(getattr(delta, "source_family", "")),
                _iso(getattr(delta, "first_found_at", None)),
                _iso(getattr(delta, "last_found_at", None)),
                _iso(getattr(delta, "fixed_at", None)),
                _text(getattr(delta, "evidence", "")),
            ]
        )
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# The whole thing, as one structure
# ─────────────────────────────────────────────────────────────────────────────


def _scan_hosts(db: Session, scan: Any) -> List[Dict[str, Any]]:
    """
    The scan's host records, from the most complete phase it stored.

    Every phase row keeps its hosts in ``summary._phase_data``; a later phase
    carries everything an earlier one found plus its own results, so the
    highest phase with hosts is the scan's inventory.
    """
    from db.models.scans import ScanPhase

    phases = (
        db.query(ScanPhase)
        .filter(ScanPhase.scan_id == str(getattr(scan, "id", "") or ""))
        .order_by(ScanPhase.phase_order.desc())
        .all()
    )
    for phase in phases:
        data = (
            (phase.summary or {}).get("_phase_data")
            if isinstance(phase.summary, dict)
            else None
        )
        if isinstance(data, list) and data:
            return [h for h in data if isinstance(h, dict)]
    return []


def host_export_rows(db: Session, scan: Any) -> List[List[str]]:
    """
    One row per host the scan recorded — the same row the host CSV writes.

    A Basic Network Scan or Asset Discovery workbook used to carry a summary
    and three empty sheets: the hosts, MAC addresses, operating systems and
    open services the scan had just discovered appeared nowhere in it.
    """
    from reporting.csv_generator import _host_inventory_row

    ports_scanned = (_text(getattr(scan, "pipeline_mode", "")) or "basic") != "basic"
    # Cells are made safe by the writers (xlsx_generator.sanitize_cell), as
    # for every other dataset here.
    return [_host_inventory_row(host, ports_scanned) for host in _scan_hosts(db, scan)]


def export_payload(
    db: Session,
    scan: Any,
    *,
    comparison: Any = None,
    datasets: Sequence[str] = ("hosts", "compliance", "findings", "comparison"),
    **filters: Any,
) -> Dict[str, Any]:
    """
    Every requested dataset for one scan, as headers plus rows.

    This is the single assembly point. The XLSX writer turns it into
    worksheets, the CSV writer takes one dataset from it, and the JSON response
    returns it as it stands — so the three cannot disagree about a scan, which
    is what makes the reconciliation requirement satisfiable at all rather than
    a matter of keeping three code paths in step by hand.
    """
    context = scan_context(db, scan)
    payload: Dict[str, Any] = {"scan": context, "datasets": {}}

    if "hosts" in datasets:
        from reporting.csv_generator import HOST_INVENTORY_HEADERS

        rows = host_export_rows(db, scan)
        payload["datasets"]["hosts"] = {
            "columns": list(HOST_INVENTORY_HEADERS),
            "rows": rows,
            "row_count": len(rows),
        }

    if "compliance" in datasets:
        rows = compliance_verdict_rows(
            db,
            scan,
            context=context,
            **_pick(
                filters,
                (
                    "asset_id",
                    "host",
                    "framework_id",
                    "profile",
                    "severity",
                    "verdict",
                ),
            ),
        )
        payload["datasets"]["compliance"] = {
            "columns": list(CONFIG_VERDICT_COLUMNS),
            "rows": rows,
            "row_count": len(rows),
            "verdict_counts": _verdict_counts(rows),
        }

    if "findings" in datasets:
        rows = finding_export_rows(
            db,
            scan,
            context=context,
            **_pick(
                filters,
                (
                    "asset_id",
                    "severity",
                    "status",
                    "remediation_state",
                    "overdue_only",
                    "scope",
                ),
            ),
        )
        payload["datasets"]["findings"] = {
            "columns": list(FINDING_EXPORT_COLUMNS),
            "rows": rows,
            "row_count": len(rows),
        }

    if "comparison" in datasets:
        rows = comparison_export_rows(comparison)
        payload["datasets"]["comparison"] = {
            "columns": list(COMPARISON_COLUMNS),
            "rows": rows,
            "row_count": len(rows),
            "comparable": bool(getattr(comparison, "comparable", False)),
            "reason": _text(getattr(comparison, "reason", "")),
            "counts": dict(getattr(comparison, "counts", {}) or {}),
            "summary": (
                comparison.summary_line() if hasattr(comparison, "summary_line") else ""
            ),
        }

    return payload


def _pick(filters: Mapping[str, Any], keys: Sequence[str]) -> Dict[str, Any]:
    return {k: filters[k] for k in keys if k in filters and filters[k] is not None}


def _verdict_counts(rows: Sequence[Sequence[str]]) -> Dict[str, int]:
    """
    How many rows carry each verdict.

    The reconciliation requirement is that these agree with the database and
    the PDF, so the number is produced from the exported rows themselves rather
    than recounted from the source — a count taken from anywhere else can agree
    with the source and still disagree with the file that was delivered.
    """
    index = CONFIG_VERDICT_COLUMNS.index("Verdict")
    counts: Dict[str, int] = {}
    for row in rows:
        if len(row) > index:
            key = str(row[index])
            counts[key] = counts.get(key, 0) + 1
    return counts


def workbook_sheets(
    payload: Mapping[str, Any]
) -> List[Tuple[str, Sequence[str], List[List[str]]]]:
    """
    An :func:`export_payload` turned into ``(sheet, header, rows)`` triples.

    The summary comes first because it is the sheet a workbook opens on, and it
    carries the row count of every other sheet plus the scan's policy snapshot.
    A reader who opens a compliance sheet showing 8 rows needs to be able to see
    whether that is the whole assessment or the residue of a filter, and a count
    beside a Configuration ID is what answers it.

    Only the datasets the caller asked for appear. An absent sheet means the
    export did not include that dataset; an empty one means it was included and
    matched nothing. Those are different facts and the workbook keeps them
    apart.
    """
    context = payload.get("scan") or {}
    datasets = payload.get("datasets") or {}

    summary_rows = scan_context_rows(context)
    summary_rows.append(["", ""])
    summary_rows.append(["Dataset", "Rows exported"])
    for key in ("hosts", "compliance", "findings", "comparison"):
        data = datasets.get(key)
        if data is not None:
            summary_rows.append([key.capitalize(), str(data.get("row_count", 0))])

    compliance = datasets.get("compliance")
    if compliance is not None:
        counts = compliance.get("verdict_counts") or {}
        if counts:
            summary_rows.append(["", ""])
            summary_rows.append(["Verdict", "Count"])
            for verdict in sorted(counts):
                summary_rows.append([verdict, str(counts[verdict])])

    comparison = datasets.get("comparison")
    if comparison is not None:
        summary_rows.append(["", ""])
        summary_rows.append(
            [
                "Comparison",
                comparison.get("summary")
                or comparison.get("reason")
                or "no comparison was requested",
            ]
        )

    # Timestamps are ISO-8601 in UTC as text, and the workbook says so rather
    # than leaving a reader to guess. openpyxl cannot store a timezone on a
    # datetime cell - Excel has no concept of one - so writing these as real
    # date cells would strip the zone and render a UTC instant in the reader's
    # own locale, which is the two-clocks defect the report helpers already
    # avoid elsewhere.
    summary_rows.append(["", ""])
    summary_rows.append(
        [
            "Timestamps",
            "ISO-8601, UTC. Text cells, because Excel cannot carry a time zone.",
        ]
    )

    sheets: List[Tuple[str, Sequence[str], List[List[str]]]] = [
        ("Summary", SCAN_CONTEXT_COLUMNS, summary_rows)
    ]
    hosts = datasets.get("hosts")
    if hosts is not None:
        sheets.append(("Hosts", hosts.get("columns") or [], hosts.get("rows") or []))
    if compliance is not None:
        sheets.append(
            (
                "Compliance Verdicts",
                CONFIG_VERDICT_COLUMNS,
                compliance.get("rows") or [],
            )
        )
    findings = datasets.get("findings")
    if findings is not None:
        sheets.append(("Findings", FINDING_EXPORT_COLUMNS, findings.get("rows") or []))
    if comparison is not None:
        sheets.append(
            ("Scan Comparison", COMPARISON_COLUMNS, comparison.get("rows") or [])
        )
    return sheets
