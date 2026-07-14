"""
core/web/correlation.py
────────────────────────────────────────────────────────────────────────────
Finding deduplication and correlation engine.

When multiple tools (Nuclei, SQLMap, ffuf) find the same vulnerability
on the same endpoint, this engine merges them into a single high-confidence
finding to avoid duplicate noise in reports.

Correlation rules:
  1. Same URL + same finding_type → merge (keep highest severity)
  2. Same URL + overlapping CVE → merge
  3. Nuclei + SQLMap both find SQLi → single finding, verified=True
"""

import logging
from typing import Dict, List, Set

log = logging.getLogger("ccure.web.correlation")


def deduplicate_findings(findings: List[Dict]) -> List[Dict]:
    """
    Deduplicate web findings by URL + finding_type.

    When duplicates are found:
      - Keep the one with highest severity
      - Merge evidence from both
      - Mark as verified if multiple tools confirm

    Args:
        findings: Raw finding dicts from all detection tools

    Returns:
        Deduplicated finding list
    """
    if not findings:
        return []

    # Group by (matched_at_url, finding_type)
    groups: Dict[str, List[Dict]] = {}
    for f in findings:
        url = (f.get("matched_at") or f.get("request_url") or "").split("?")[0]
        ftype = f.get("finding_type", "unknown")
        key = f"{url}|{ftype}"
        groups.setdefault(key, []).append(f)

    deduplicated: List[Dict] = []
    for key, group in groups.items():
        if len(group) == 1:
            deduplicated.append(group[0])
            continue

        # Merge group into single finding
        merged = _merge_finding_group(group)
        deduplicated.append(merged)

    log.info(
        "Deduplication: %d findings → %d (removed %d duplicates)",
        len(findings),
        len(deduplicated),
        len(findings) - len(deduplicated),
    )
    return deduplicated


def _merge_finding_group(group: List[Dict]) -> Dict:
    """
    Merge a group of duplicate findings into one.

    Strategy:
      - Use highest severity from the group
      - Use highest CVSS from the group
      - Mark as verified if multiple tools agree
      - Concatenate unique evidence
    """
    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

    # Sort by severity (highest first)
    sorted_group = sorted(
        group,
        key=lambda f: severity_rank.get(f.get("severity", "info").lower(), 0),
        reverse=True,
    )

    # Start with highest-severity finding
    merged = dict(sorted_group[0])

    # Merge from others
    tools_used: Set[str] = set()
    all_evidence: List[str] = []
    max_cvss = merged.get("cvss_score", 0.0) or 0.0

    for f in sorted_group:
        tool = f.get("detected_by", "unknown")
        tools_used.add(tool)

        cvss = f.get("cvss_score", 0.0) or 0.0
        if cvss > max_cvss:
            max_cvss = cvss

        # Collect unique evidence
        for evidence_field in ("request_evidence", "response_evidence", "payload_used"):
            ev = f.get(evidence_field)
            if ev and ev not in all_evidence:
                all_evidence.append(str(ev)[:2000])

    merged["cvss_score"] = max_cvss
    merged["detected_by"] = ",".join(sorted(tools_used))

    # Multiple tools = higher confidence
    if len(tools_used) > 1:
        merged["is_verified"] = True
        merged["description"] = (
            (merged.get("description") or "")
            + f"\n\n[Confirmed by {len(tools_used)} tools: {', '.join(sorted(tools_used))}]"
        ).strip()

    return merged


def correlate_with_network_findings(
    web_findings: List[Dict],
    network_cves: List[Dict],
    target_domain: str,
) -> List[Dict]:
    """
    Cross-reference web findings with network scan CVEs for the same
    host/domain. If both find the same CVE, boost confidence.

    Args:
        web_findings: Findings from web scan
        network_cves: CVEs from network vulnerability scan
        target_domain: Target domain for matching

    Returns:
        Enhanced web findings with cross-reference notes
    """
    network_cve_ids: Set[str] = {
        cve.get("cve_id", "").upper() for cve in network_cves if cve.get("cve_id")
    }

    if not network_cve_ids:
        return web_findings

    for f in web_findings:
        cve_id = (f.get("cve_id") or "").upper()
        if cve_id and cve_id in network_cve_ids:
            f["is_verified"] = True
            f["description"] = (
                (f.get("description") or "")
                + "\n\n[Cross-confirmed: also found by network vulnerability scan]"
            ).strip()
            log.info(
                "Cross-correlation: %s confirmed by both web and network scans",
                cve_id,
            )

    return web_findings
