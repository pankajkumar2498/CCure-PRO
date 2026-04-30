"""
Matches installed package versions against the vulnerability-intelligence DB.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from core.vuln_intel import (
    build_sql_or_clauses,
    get_vuln_engine,
    merge_alias_fields,
    normalize_package_names,
)

log = logging.getLogger("ccure.vuln_matcher")

BEST_CVSS_LATERAL = """
LEFT JOIN LATERAL (
    SELECT version, base_score, severity, vector
    FROM cvss
    WHERE cvss.cve_id = c.cve_id
    ORDER BY
        CASE version
            WHEN '4.0' THEN 4
            WHEN '3.1' THEN 3
            WHEN '3.0' THEN 2
            WHEN '2.0' THEN 1
            ELSE 0
        END DESC,
        base_score DESC NULLS LAST
    LIMIT 1
) best_cvss ON TRUE
"""


@dataclass
class CredentialedCVE:
    cve_id: str
    severity: str
    cvss_score: float
    description: str
    package_name: str
    installed_ver: str
    fixed_ver: str = ""
    source: str = "vuln_intel"
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    in_kev: bool = False
    kev_due_date: str = ""
    has_exploit: bool = False
    exploit_sources: List[str] = None
    priority_score: float = 0.0
    priority_level: str = "P4"
    matched_by: str = ""
    cpe_uri: str = ""
    cvss_version: str = ""
    cvss_vector: str = ""

    def __post_init__(self):
        if self.exploit_sources is None:
            self.exploit_sources = []


class VulnMatcher:
    """
    Matches installed packages against the normalized vuln-intel database.
    """

    def __init__(self):
        self.engine = get_vuln_engine()

    def match_packages(self, packages: List[Dict[str, str]]) -> List[CredentialedCVE]:
        findings: List[CredentialedCVE] = []
        best_by_cve: Dict[str, CredentialedCVE] = {}

        try:
            with self.engine.connect() as conn:
                for pkg in packages:
                    name = (pkg.get("name") or "").strip()
                    version = (pkg.get("version") or "").strip()
                    if not name:
                        continue

                    for finding in self._match_package(conn, name, version):
                        current = best_by_cve.get(finding.cve_id)
                        if current is None or finding.priority_score > current.priority_score:
                            best_by_cve[finding.cve_id] = finding
        except SQLAlchemyError as exc:
            log.warning("Vulnerability-intel query failed: %s", exc)

        findings = list(best_by_cve.values())
        findings.sort(key=lambda item: (item.priority_score, item.cvss_score), reverse=True)
        return findings

    def _match_package(self, conn, package_name: str, installed_version: str) -> List[CredentialedCVE]:
        matches: List[CredentialedCVE] = []
        candidates = normalize_package_names(package_name)
        if not candidates:
            return matches

        matches.extend(self._match_cpe_records(conn, package_name, installed_version, candidates))
        matches.extend(self._match_osv_records(conn, package_name, installed_version, candidates))
        return matches

    def _match_cpe_records(
        self,
        conn,
        package_name: str,
        installed_version: str,
        candidates: List[str],
    ) -> List[CredentialedCVE]:
        where_sql, params = build_sql_or_clauses(
            column_expressions=("LOWER(p.product)", "LOWER(p.vendor)", "LOWER(p.cpe_uri)"),
            values=candidates,
            param_prefix="pkg",
        )
        query = text(
            f"""
            SELECT
                c.cve_id,
                c.description,
                best_cvss.version AS cvss_version,
                best_cvss.base_score AS cvss_score,
                best_cvss.severity AS cvss_severity,
                best_cvss.vector AS cvss_vector,
                epss.epss_score,
                epss.percentile AS epss_percentile,
                (kev.cve_id IS NOT NULL) AS in_kev,
                kev.due_date AS kev_due_date,
                COALESCE(exploits.has_exploit, FALSE) AS has_exploit,
                exploits.exploit_sources,
                p.cpe_uri,
                p.vendor,
                p.product,
                p.version_start_including,
                p.version_start_excluding,
                p.version_end_including,
                p.version_end_excluding
            FROM cpe p
            JOIN cve c ON c.cve_id = p.cve_id
            {BEST_CVSS_LATERAL}
            LEFT JOIN epss ON epss.cve_id = c.cve_id
            LEFT JOIN kev ON kev.cve_id = c.cve_id
            LEFT JOIN exploits ON exploits.cve_id = c.cve_id
            WHERE {where_sql}
            ORDER BY
                (kev.cve_id IS NOT NULL) DESC,
                COALESCE(epss.epss_score, 0) DESC,
                COALESCE(best_cvss.base_score, 0) DESC
            LIMIT 200
            """
        )
        rows = conn.execute(query, params).mappings().all()
        findings: List[CredentialedCVE] = []
        for row in rows:
            if not self._package_matches_cpe_row(package_name, row):
                continue
            if installed_version and not self._installed_version_matches(installed_version, row):
                continue
            record = merge_alias_fields(
                {
                    "cve_id": row.get("cve_id"),
                    "description": row.get("description"),
                    "cvss_score": row.get("cvss_score") or 0.0,
                    "severity": row.get("cvss_severity"),
                    "epss_score": row.get("epss_score") or 0.0,
                    "epss_percentile": row.get("epss_percentile") or 0.0,
                    "in_kev": bool(row.get("in_kev")),
                    "kev_due_date": row.get("kev_due_date"),
                    "has_exploit": bool(row.get("has_exploit")),
                    "exploit_sources": list(row.get("exploit_sources") or []),
                    "cvss_version": row.get("cvss_version"),
                    "cvss_vector": row.get("cvss_vector"),
                }
            )
            findings.append(
                CredentialedCVE(
                    cve_id=record["cve_id"],
                    severity=record["severity"],
                    cvss_score=record["cvss_score"],
                    description=record["description"],
                    package_name=package_name,
                    installed_ver=installed_version,
                    fixed_ver=self._row_fixed_version(row),
                    source="cpe_match",
                    epss_score=float(record.get("epss_score", 0.0) or 0.0),
                    epss_percentile=float(record.get("epss_percentile", 0.0) or 0.0),
                    in_kev=bool(record.get("in_kev")),
                    kev_due_date=str(record.get("kev_due_date") or ""),
                    has_exploit=bool(record.get("has_exploit")),
                    exploit_sources=list(record.get("exploit_sources") or []),
                    priority_score=float(record.get("priority_score", 0.0) or 0.0),
                    priority_level=record.get("priority_level", "P4"),
                    matched_by="cpe",
                    cpe_uri=row.get("cpe_uri") or "",
                    cvss_version=str(record.get("cvss_version") or ""),
                    cvss_vector=str(record.get("cvss_vector") or ""),
                )
            )
        return findings

    def _match_osv_records(
        self,
        conn,
        package_name: str,
        installed_version: str,
        candidates: List[str],
    ) -> List[CredentialedCVE]:
        where_sql, params = build_sql_or_clauses(
            column_expressions=("LOWER(aff.package_name)",),
            values=candidates,
            param_prefix="osv_pkg",
        )
        query = text(
            f"""
            SELECT
                oa.cve_id,
                c.description,
                best_cvss.version AS cvss_version,
                best_cvss.base_score AS cvss_score,
                best_cvss.severity AS cvss_severity,
                best_cvss.vector AS cvss_vector,
                epss.epss_score,
                epss.percentile AS epss_percentile,
                (kev.cve_id IS NOT NULL) AS in_kev,
                kev.due_date AS kev_due_date,
                COALESCE(exploits.has_exploit, FALSE) AS has_exploit,
                exploits.exploit_sources,
                aff.ecosystem,
                aff.package_name,
                ranges.introduced,
                ranges.fixed
            FROM osv_affected aff
            JOIN osv_aliases oa ON oa.osv_id = aff.osv_id AND oa.cve_id IS NOT NULL
            JOIN cve c ON c.cve_id = oa.cve_id
            {BEST_CVSS_LATERAL}
            LEFT JOIN epss ON epss.cve_id = c.cve_id
            LEFT JOIN kev ON kev.cve_id = c.cve_id
            LEFT JOIN exploits ON exploits.cve_id = c.cve_id
            LEFT JOIN osv_ranges ranges ON ranges.osv_id = aff.osv_id
            WHERE {where_sql}
            ORDER BY
                (kev.cve_id IS NOT NULL) DESC,
                COALESCE(epss.epss_score, 0) DESC,
                COALESCE(best_cvss.base_score, 0) DESC
            LIMIT 200
            """
        )
        rows = conn.execute(query, params).mappings().all()
        findings: List[CredentialedCVE] = []
        for row in rows:
            if installed_version and not self._installed_version_matches_osv(installed_version, row):
                continue
            record = merge_alias_fields(
                {
                    "cve_id": row.get("cve_id"),
                    "description": row.get("description"),
                    "cvss_score": row.get("cvss_score") or 0.0,
                    "severity": row.get("cvss_severity"),
                    "epss_score": row.get("epss_score") or 0.0,
                    "epss_percentile": row.get("epss_percentile") or 0.0,
                    "in_kev": bool(row.get("in_kev")),
                    "kev_due_date": row.get("kev_due_date"),
                    "has_exploit": bool(row.get("has_exploit")),
                    "exploit_sources": list(row.get("exploit_sources") or []),
                    "cvss_version": row.get("cvss_version"),
                    "cvss_vector": row.get("cvss_vector"),
                }
            )
            findings.append(
                CredentialedCVE(
                    cve_id=record["cve_id"],
                    severity=record["severity"],
                    cvss_score=record["cvss_score"],
                    description=record["description"],
                    package_name=package_name,
                    installed_ver=installed_version,
                    fixed_ver=str(row.get("fixed") or ""),
                    source="osv_match",
                    epss_score=float(record.get("epss_score", 0.0) or 0.0),
                    epss_percentile=float(record.get("epss_percentile", 0.0) or 0.0),
                    in_kev=bool(record.get("in_kev")),
                    kev_due_date=str(record.get("kev_due_date") or ""),
                    has_exploit=bool(record.get("has_exploit")),
                    exploit_sources=list(record.get("exploit_sources") or []),
                    priority_score=float(record.get("priority_score", 0.0) or 0.0),
                    priority_level=record.get("priority_level", "P4"),
                    matched_by=f"osv:{row.get('ecosystem') or 'unknown'}",
                    cvss_version=str(record.get("cvss_version") or ""),
                    cvss_vector=str(record.get("cvss_vector") or ""),
                )
            )
        return findings

    def _package_matches_cpe_row(self, package_name: str, row: Dict[str, Any]) -> bool:
        candidates = normalize_package_names(package_name)
        haystacks = [
            str(row.get("product") or "").lower(),
            str(row.get("vendor") or "").lower(),
            str(row.get("cpe_uri") or "").lower(),
        ]
        return any(candidate and any(candidate in hay for hay in haystacks) for candidate in candidates)

    def _installed_version_matches(self, installed_version: str, row: Dict[str, Any]) -> bool:
        exact_version = _extract_cpe_exact_version(str(row.get("cpe_uri") or ""))
        min_incl = row.get("version_start_including")
        min_excl = row.get("version_start_excluding")
        max_incl = row.get("version_end_including")
        max_excl = row.get("version_end_excluding")

        if exact_version and exact_version not in {"*", "-"}:
            if _version_eq(installed_version, exact_version):
                return True

        if min_incl and not _version_gte(installed_version, str(min_incl)):
            return False
        if min_excl and not _version_gt(installed_version, str(min_excl)):
            return False
        if max_incl and not _version_lte(installed_version, str(max_incl)):
            return False
        if max_excl and not _version_lt(installed_version, str(max_excl)):
            return False

        if any([min_incl, min_excl, max_incl, max_excl]):
            return True
        if exact_version and exact_version not in {"*", "-"}:
            return _version_eq(installed_version, exact_version)
        return False

    def _installed_version_matches_osv(self, installed_version: str, row: Dict[str, Any]) -> bool:
        introduced = str(row.get("introduced") or "").strip()
        fixed = str(row.get("fixed") or "").strip()

        if introduced and introduced not in {"0", "*"} and not _version_gte(installed_version, introduced):
            return False
        if fixed and fixed not in {"*", "-"} and not _version_lt(installed_version, fixed):
            return False
        return True

    def _row_fixed_version(self, row: Dict[str, Any]) -> str:
        for key in ("version_end_excluding", "version_end_including"):
            value = row.get(key)
            if value:
                return str(value)
        return ""

    def to_report_format(self, findings: List[CredentialedCVE]) -> List[Dict[str, Any]]:
        return [
            {
                "cve_id": f.cve_id,
                "cve": f.cve_id,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "cvss": f.cvss_score,
                "description": f.description,
                "desc": f.description,
                "package": f.package_name,
                "installed_ver": f.installed_ver,
                "fixed_ver": f.fixed_ver,
                "source": f.source,
                "matched_by": f.matched_by,
                "epss_score": f.epss_score,
                "epss_percentile": f.epss_percentile,
                "in_kev": f.in_kev,
                "kev_due_date": f.kev_due_date,
                "has_exploit": f.has_exploit,
                "exploit_sources": f.exploit_sources,
                "priority_score": f.priority_score,
                "priority_level": f.priority_level,
                "cpe_uri": f.cpe_uri,
                "cvss_version": f.cvss_version,
                "cvss_vector": f.cvss_vector,
            }
            for f in findings
        ]


def _extract_cpe_exact_version(cpe_uri: str) -> str:
    parts = cpe_uri.split(":")
    if len(parts) > 5:
        return parts[5].strip()
    return ""


def _parse_version(ver: str) -> Tuple[int, ...]:
    if ":" in ver:
        ver = ver.split(":", 1)[1]
    ver = re.sub(r"(ubuntu|debian|el\d+|deb\d+|~).*$", "", ver, flags=re.IGNORECASE)
    parts = re.split(r"[.\-~+_]", ver)
    nums: List[int] = []
    for part in parts:
        if not part:
            continue
        if part.isdigit():
            nums.append(int(part))
            continue
        match = re.match(r"(\d+)([a-z]?)", part, re.IGNORECASE)
        if match:
            if match.group(1):
                nums.append(int(match.group(1)))
            if match.group(2):
                nums.append(ord(match.group(2).lower()) - ord("a") + 1)
    return tuple(nums) if nums else (0,)


def _version_lt(ver_a: str, ver_b: str) -> bool:
    a = _parse_version(ver_a)
    b = _parse_version(ver_b)
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    return a < b


def _version_lte(ver_a: str, ver_b: str) -> bool:
    return _version_lt(ver_a, ver_b) or _version_eq(ver_a, ver_b)


def _version_gt(ver_a: str, ver_b: str) -> bool:
    return not _version_lte(ver_a, ver_b)


def _version_gte(ver_a: str, ver_b: str) -> bool:
    return not _version_lt(ver_a, ver_b)


def _version_eq(ver_a: str, ver_b: str) -> bool:
    return _parse_version(ver_a) == _parse_version(ver_b)
