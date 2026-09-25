"""
core/config_audit/findings.py
─────────────────────────────────────────────────────────────────────────────
Where a configuration check result joins the paths this product already has.

There are two of them and a check result reaches both, which is the point of
the whole phase:

* **The finding model** — ``StandardizedFinding`` → the normalizer → risk →
  the executive and technical PDFs. A failing hardening control is a security
  finding, and it belongs in the same list, ranked by the same severity, as
  the CVEs found on the same host. This is why Phase 0 widened
  ``vulnerability_definitions`` to admit ``config_check`` rows and widened
  ``vuln_id`` to 120 characters: without that, the only home for a CIS control
  was a second findings table, and a second findings table brings a second
  risk model and a second report generator behind it.

* **The compliance model** — ``compliance_findings.status``. The four
  non-error outcomes are spelled identically to that column's CHECK
  constraint, so the verdict stores with no translation table.

Only a FAIL becomes a finding. A PASS is a compliance verdict, not a
vulnerability; NOT_APPLICABLE, MANUAL_REVIEW and ERROR are not verdicts at
all. ``CheckResult.is_finding`` already encodes exactly that and is used here
rather than re-deriving it, so the two cannot drift apart.

ERROR does not reach ``compliance_findings``
────────────────────────────────────────────
``compliance_findings.status`` has no ``error`` member and must not gain one —
it would be a claim about a host that nothing established. An errored check
maps to ``manual_review`` with the reason recorded in the evidence payload,
which is the same treatment the compliance engine already gives a host it
could not collect from. The reason travels with it: "not assessed" with no
explanation is what an operator cannot act on.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional

from core.checks.contract import CheckOutcome, CheckResult
from core.checks.definitions import (
    DEFINITION_TYPE_CONFIG_CHECK,
    DEFINITION_TYPE_PRIVILEGE_CHECK,
    definition_id_for_check,
)
from core.config_audit.spec import ConfigCheck
from core.checks.finding_normalizer import (
    Confidence,
    DetectionMethod,
    Remediation,
    RemediationConfidence,
    StandardizedFinding,
)
from core.checks.finding_normalizer import normalize_severity as display_severity

log = logging.getLogger("ccure.config_audit.findings")

__all__ = [
    "CONFIG_PLUGIN_FAMILY",
    "PRIVILEGE_PLUGIN_FAMILY",
    "catalogue_row",
    "compliance_verdict",
    "config_definition_id",
    "finding_from_result",
    "findings_from_results",
]

#: Groups configuration findings in the report's plugin-family breakdown, so a
#: reader can see at a glance how much of a host's risk is hardening rather
#: than missing patches.
CONFIG_PLUGIN_FAMILY = "Configuration Audit"

#: Privilege findings group separately in the report's family breakdown. A
#: writable service binary and a missing password-length policy are both
#: "configuration" in the loose sense, and a reader triaging a host needs them
#: in different piles: one is a deviation from a baseline, the other is a path
#: to SYSTEM.
PRIVILEGE_PLUGIN_FAMILY = "Local Privilege"

#: How an errored or unassessable check is recorded as a compliance verdict.
#: Deliberately the same value the compliance engine already writes for a host
#: it could not collect evidence from.
_UNASSESSED_STATUS = "manual_review"


def config_definition_id(
    check_id: str, finding_type: str = DEFINITION_TYPE_CONFIG_CHECK
) -> str:
    """
    Mint the catalogue identifier, falling back to the raw check id if the
    check is named in a way the minter refuses.

    ``finding_type`` decides the segment: ``CCURE-CFG-…`` for a hardening
    control, ``CCURE-PRV-…`` for a local privilege condition. A reader triaging
    findings needs to tell "this host deviates from a baseline" from "this host
    has a path to SYSTEM", and the identifier is the first place that shows.

    The fallback logs loudly rather than raising: one badly named rule must not
    abort the persistence of every other finding on the host. It cannot produce
    a collision, because ``definition_id_for_check`` only refuses ids that are
    empty, over-long, or already CVE-shaped — and each of those is visible in
    the log line.
    """
    try:
        return definition_id_for_check(check_id, finding_type)
    except ValueError as exc:
        log.error(
            "Check %r could not be given a catalogue identifier (%s); the "
            "finding will be filed under the raw check id.",
            check_id,
            exc,
        )
        return str(check_id)


def finding_from_result(
    result: CheckResult,
    *,
    check: Optional[ConfigCheck] = None,
    hostname: str = "",
) -> Optional[StandardizedFinding]:
    """
    Render a failing check as a security finding, or None for anything that is
    not a FAIL.

    Returning None rather than a suppressed finding is deliberate: a caller
    that has to remember to filter will one day forget, and a passing control
    rendered as a finding is the most visible kind of wrong a scanner can be.
    """
    if not result.is_finding:
        return None

    evidence_lines: List[str] = []
    for item in result.evidence:
        parts = [item.description]
        if item.expected is not None:
            parts.append(f"Expected: {item.expected}")
        if item.observed is not None:
            parts.append(f"Observed: {item.observed}")
        evidence_lines.append("\n".join(parts))
        if item.raw:
            evidence_lines.append(item.raw)

    remediation = None
    if result.remediation:
        remediation = Remediation(
            summary=result.remediation,
            confidence=RemediationConfidence.CONFIGURATION_GUIDANCE,
        )

    description = ""
    rationale = ""
    if check is not None:
        description = check.description
        rationale = check.rationale
    narrative = "\n\n".join(p for p in (description, rationale) if p)

    finding_type = str(
        result.metadata.get("finding_type")
        or (check.finding_type if check is not None else DEFINITION_TYPE_CONFIG_CHECK)
    )
    return StandardizedFinding(
        plugin_id=config_definition_id(result.check_id, finding_type),
        plugin_name=result.title or result.check_id,
        plugin_family=(
            PRIVILEGE_PLUGIN_FAMILY
            if finding_type == DEFINITION_TYPE_PRIVILEGE_CHECK
            else CONFIG_PLUGIN_FAMILY
        ),
        host=result.target,
        hostname=hostname,
        # A configuration control is a property of the host, not of a listening
        # service, so it carries no port. Inventing one would place the finding
        # against a service that has nothing to do with it.
        port=None,
        severity=display_severity(result.severity),
        severity_source="rule",
        synopsis=result.title or result.check_id,
        description=narrative or result.title,
        evidence="\n\n".join(line for line in evidence_lines if line),
        evidence_available=bool(result.evidence),
        detection_method=DetectionMethod.CONFIG_CHECK,
        confidence=Confidence.CONFIRMED,
        remediation=remediation,
        references=list(result.references),
        # A misconfiguration is exploitable through whatever reaches the host;
        # the CVSS notion of attack surface does not apply, and claiming
        # "remote" would overstate it. "local" understates it equally, so the
        # applicability note carries the truth instead of the field.
        attack_surface="local",
        applicability_note=(
            "Configuration control assessed on the host itself; exposure "
            "depends on who can reach the affected component."
        ),
        cve_ids=list(result.cve_ids),
    )


def findings_from_results(
    results: Iterable[CheckResult],
    *,
    checks_by_id: Optional[Dict[str, ConfigCheck]] = None,
    hostname: str = "",
) -> List[StandardizedFinding]:
    lookup = checks_by_id or {}
    findings: List[StandardizedFinding] = []
    for result in results:
        finding = finding_from_result(
            result, check=lookup.get(result.check_id), hostname=hostname
        )
        if finding is not None:
            findings.append(finding)
    return findings


def compliance_verdict(result: CheckResult) -> Dict[str, Any]:
    """
    Render a check result as the ``(status, evidence)`` pair
    ``_save_finding`` writes to ``compliance_findings``.

    The status is taken from the outcome's own value for the four that the
    column already accepts, and mapped to ``manual_review`` for ERROR. The
    mapping is one-directional on purpose: a stored ``manual_review`` does not
    say whether a check errored or was always manual, so the evidence payload
    carries ``outcome`` verbatim and a reader can tell.
    """
    status = (
        _UNASSESSED_STATUS
        if result.outcome is CheckOutcome.ERROR
        else result.outcome.value
    )
    evidence: Dict[str, Any] = {
        "check_id": result.check_id,
        "outcome": result.outcome.value,
        "assessed": result.outcome.is_assessed,
        "severity": result.severity,
        "detection_method": result.detection_method,
        "qod": result.qod,
        "observations": [item.as_dict() for item in result.evidence],
    }
    if result.error:
        evidence["message"] = result.error
        evidence["not_assessed_reason"] = result.error
    elif result.outcome is CheckOutcome.NOT_APPLICABLE:
        evidence["message"] = result.metadata.get(
            "not_applicable_reason", "This check does not apply to this host."
        )
    if result.remediation:
        evidence["remediation"] = result.remediation
    if result.references:
        evidence["references"] = list(result.references)
    if result.metadata:
        evidence["check_metadata"] = dict(result.metadata)
    return {"status": status, "evidence": evidence}


def catalogue_row(check: ConfigCheck) -> Dict[str, Any]:
    """
    The ``vulnerability_definitions`` row this check's findings point at.

    ``cve_id`` is None and ``definition_type`` is ``config_check``, which is
    what ``ck_vuln_def_cve_id_matches_type`` requires. Filing a check as a
    ``cve`` row would give it KEV lookups, EPSS scores, CVSS bands and an NVD
    link that resolves to nothing.
    """
    return {
        "id": config_definition_id(check.check_id, check.finding_type),
        "definition_type": check.finding_type,
        "cve_id": None,
        "title": check.title,
        "description": "\n\n".join(
            part for part in (check.description, check.rationale) if part
        )
        or check.title,
        "severity": check.severity,
        "references": list(check.references),
    }
