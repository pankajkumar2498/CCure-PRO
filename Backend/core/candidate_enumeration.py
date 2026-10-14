"""
Which unauthenticated CVE candidate searches stopped at their row cap.

A candidate search returns at most ``CPE_MATCH_ROW_CAP`` (2,000) or
``NAME_MATCH_ROW_CAP`` (200) rows, ranked by KEV, EPSS and CVSS. When it hits
the cap the remaining candidates are never evaluated. That used to be a single
WARNING in the worker log and a per-record flag nothing read; on 10.180.6.45
(13 Oct 2026) the kernel search stopped at 2,000 of ~14,000 CVEs and the report
said nothing. ``engines.vulnerability.plugins.cve_engine`` now records each
truncated search on the host; this module rolls those records up for the scan
summary and phrases them once for every report.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from core.vuln_intel import parse_cpe_identities

_SOURCES = {"cpe_exact": "exact product identity", "name_match": "name match"}


def truncated_searches(hosts: Iterable[Mapping[str, Any]]) -> list[dict]:
    """Every truncated search across ``hosts``, each tagged with its host."""
    out: list[dict] = []
    for host in hosts or []:
        record = host.get("candidate_enumeration") or {}
        for entry in record.get("truncated") or []:
            out.append(
                {**entry, "host": host.get("ip_address") or host.get("ip") or ""}
            )
    return out


def searches_run(hosts: Iterable[Mapping[str, Any]]) -> int | None:
    """Searches recorded across ``hosts``; None when no host recorded any."""
    counts = [
        int((host.get("candidate_enumeration") or {}).get("searches") or 0)
        for host in hosts or []
        if "candidate_enumeration" in host
    ]
    return sum(counts) if counts else None


def _search_label(search: str) -> str:
    identities = parse_cpe_identities([search])
    if identities:
        vendor, product = identities[0]
        return f"{vendor}:{product}"
    return search


def describe(entry: Mapping[str, Any]) -> str:
    """One truncated search, in words."""
    port = entry.get("port")
    where = (
        f"port {port}/{entry.get('protocol') or 'tcp'}"
        if port not in (None, "")
        else "operating system"
    )
    cap = entry.get("cap")
    stopped = f"stopped at {int(cap):,} candidates" if cap else "stopped at its cap"
    source = _SOURCES.get(str(entry.get("source") or ""), "search")
    host = entry.get("host") or ""
    prefix = f"{host} " if host else ""
    return (
        f"{prefix}{where}: '{_search_label(str(entry.get('search') or ''))}' "
        f"({source}) {stopped}; lower-ranked candidates were not evaluated"
    )
