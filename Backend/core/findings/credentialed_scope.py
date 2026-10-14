"""
What a credentialed audit of one host actually assessed.

A finding the audit did not report has gone away only if the audit looked for
it. Two questions decide that, and both sweeps — the standalone credentialed
scan's and the vulnerability-audit pipeline's — ask them here so they cannot
answer differently:

* Package CVEs: the matcher runs over the whole installed inventory, so an
  absent CVE is gone — but only when an inventory was collected and the feed
  lookup succeeded. A collector that returned nothing, or a lookup that failed
  (``package_coverage.lookup_failures``), assessed no package at all.
* Configuration and privilege findings: only checks that reached a PASS or
  FAIL verdict establish anything; an errored, inapplicable or uncollected
  check is not a check that passed.
"""

from __future__ import annotations

from typing import Any, Mapping

#: Identifiers only an authenticated session produces: configuration and
#: privilege checks, and the credentialed audit's own not-assessed markers.
CREDENTIALED_ID_PREFIXES = ("CCURE-CFG-", "CCURE-PRV-", "MISC-CREDENTIALED-")
CREDENTIALED_DETECTIONS = frozenset({"credentialed", "credentialed_package"})


def assessed_check_ids(config_summary: Any) -> set:
    """
    Catalogue ids of the configuration checks this scan reached a *verdict* on.

    Only PASS and FAIL count. A check that errored, was not applicable or could
    not be collected established nothing about the host, and a finding it did
    not report is not a finding that went away.

    This is what stops a sweep turning an unreachable session into a page of
    remediated controls: 126 Windows STIG findings on one measured host are
    absent from `cve_list` when the audit passes *and* when the audit never
    ran, and only this set tells the two apart.
    """
    ids: set = set()
    if not isinstance(config_summary, dict) or not config_summary.get("assessed"):
        return ids
    from core.config_audit.findings import config_definition_id

    for result in config_summary.get("results") or []:
        if not isinstance(result, dict):
            continue
        if str(result.get("outcome") or "").strip().lower() not in ("pass", "fail"):
            continue
        check_id = str(result.get("check_id") or "").strip()
        if not check_id:
            continue
        finding_type = str(
            (result.get("metadata") or {}).get("finding_type") or "config_check"
        )
        ids.add(config_definition_id(check_id, finding_type))
    return ids


def packages_assessed(report: Mapping[str, Any] | None) -> bool:
    """True when the audit collected an inventory and matched it without failure."""
    if not isinstance(report, Mapping):
        return False
    collected = (
        bool(report.get("packages")) or int(report.get("package_count") or 0) > 0
    )
    coverage = report.get("package_coverage") or {}
    failed = (
        bool(coverage.get("lookup_failures"))
        if isinstance(coverage, Mapping)
        else False
    )
    return collected and not failed and report.get("inventory_complete") is not False


def is_credentialed_finding(finding: Mapping[str, Any]) -> bool:
    """Whether a finding in a scan payload came from an authenticated session."""
    if str(finding.get("finding_origin") or "").lower() == "credentialed":
        return True
    if str(finding.get("detection_method") or "").lower() in CREDENTIALED_DETECTIONS:
        return True
    identifier = str(
        finding.get("cve_id") or finding.get("cve") or finding.get("id") or ""
    ).upper()
    return identifier.startswith(CREDENTIALED_ID_PREFIXES)
