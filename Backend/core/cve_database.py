"""
Query wrapper for vulnerability intelligence with PostgreSQL primary and
legacy SQLite fallback.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.vuln_intel import (
    as_list,
    build_sql_or_clauses,
    can_connect_vuln_db,
    extract_search_terms,
    get_vuln_engine,
    merge_alias_fields,
    title_case_severity,
)
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)

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


class CVEDatabase:
    """
    Query interface for vulnerability intelligence.
    """

    def __init__(self, db_path: str | None = None):
        if db_path is None:
            # Check db/cves.db first, then fall back to cves.db at the backend root
            db_path = Path(__file__).parent.parent / "db" / "cves.db"
            if not db_path.exists():
                db_path = Path(__file__).parent.parent / "cves.db"

        self.db_path = Path(db_path)
        self.sqlite_available = self.db_path.exists()
        self.postgres_available = can_connect_vuln_db()
        self.db_available = self.postgres_available or self.sqlite_available
        self.backend = (
            "postgresql"
            if self.postgres_available
            else ("sqlite" if self.sqlite_available else "fallback")
        )

        if self.backend == "postgresql":
            logger.info("CVE Database: using PostgreSQL vulnerability-intel database")
        elif self.backend == "sqlite":
            logger.warning(
                "CVE Database: PostgreSQL unavailable, falling back to SQLite at %s",
                self.db_path,
            )
        else:
            logger.warning(
                "CVE Database: no database available, using hardcoded fallback hints"
            )

    def search_cves_for_service(
        self, service_name: str, version: str = ""
    ) -> list[dict]:
        if self.backend == "postgresql":
            return self._search_postgres(service_name, version)
        if self.backend == "sqlite":
            return self._search_sqlite(service_name, version)
        return self._fallback_search(service_name, version)

    def get_cve_details(self, cve_id: str) -> dict | None:
        if self.backend == "postgresql":
            return self._get_postgres_details(cve_id)
        if self.backend == "sqlite":
            return self._get_sqlite_details(cve_id)
        return None

    def get_cves_by_severity(self, severity: str) -> list[dict]:
        if self.backend == "postgresql":
            return self._get_postgres_by_severity(severity)
        if self.backend == "sqlite":
            return self._get_sqlite_by_severity(severity)
        return []

    def _search_postgres(self, service_name: str, version: str = "") -> list[dict]:
        terms = extract_search_terms(f"{service_name} {version}")
        if not terms:
            return self._fallback_search(service_name, version)

        where_sql, params = build_sql_or_clauses(
            column_expressions=(
                "LOWER(cpe.product)",
                "LOWER(cpe.vendor)",
            ),
            values=terms,
            param_prefix="term",
        )
        params["ts_query"] = " ".join(terms)
        query = text(
            f"""
            SELECT
                c.cve_id,
                c.description,
                c.published_date,
                c.last_modified,
                best_cvss.version AS cvss_version,
                best_cvss.base_score AS cvss_score,
                best_cvss.severity AS cvss_severity,
                best_cvss.vector AS cvss_vector,
                epss.epss_score,
                epss.percentile AS epss_percentile,
                (kev.cve_id IS NOT NULL) AS in_kev,
                kev.due_date AS kev_due_date,
                kev.vendor_project AS kev_vendor_project,
                kev.product AS kev_product,
                kev.vuln_name AS kev_vuln_name,
                COALESCE(exploits.has_exploit, FALSE) AS has_exploit,
                exploits.exploit_sources
            FROM cve c
            {BEST_CVSS_LATERAL}
            LEFT JOIN epss ON epss.cve_id = c.cve_id
            LEFT JOIN kev ON kev.cve_id = c.cve_id
            LEFT JOIN exploits ON exploits.cve_id = c.cve_id
            LEFT JOIN cpe ON cpe.cve_id = c.cve_id
            WHERE ({where_sql})
               OR c.description_tsv @@ websearch_to_tsquery('english', :ts_query)
            GROUP BY
                c.cve_id, c.description, c.published_date, c.last_modified,
                best_cvss.version, best_cvss.base_score, best_cvss.severity, best_cvss.vector,
                epss.epss_score, epss.percentile,
                kev.cve_id, kev.due_date, kev.vendor_project, kev.product, kev.vuln_name,
                exploits.has_exploit, exploits.exploit_sources
            ORDER BY
                (kev.cve_id IS NOT NULL) DESC,
                COALESCE(epss.epss_score, 0) DESC,
                COALESCE(best_cvss.base_score, 0) DESC,
                c.published_date DESC
            LIMIT 20
            """
        )

        try:
            with get_vuln_engine().connect() as conn:
                rows = conn.execute(query, params).mappings().all()
            return [self._format_postgres_row(row) for row in rows]
        except SQLAlchemyError as exc:
            logger.error("PostgreSQL CVE search failed for %s: %s", service_name, exc)
            if self.sqlite_available:
                return self._search_sqlite(service_name, version)
            return self._fallback_search(service_name, version)

    def _get_postgres_details(self, cve_id: str) -> dict | None:
        query = text(
            f"""
            SELECT
                c.cve_id,
                c.description,
                c.published_date,
                c.last_modified,
                c.raw_json,
                best_cvss.version AS cvss_version,
                best_cvss.base_score AS cvss_score,
                best_cvss.severity AS cvss_severity,
                best_cvss.vector AS cvss_vector,
                epss.epss_score,
                epss.percentile AS epss_percentile,
                (kev.cve_id IS NOT NULL) AS in_kev,
                kev.due_date AS kev_due_date,
                kev.vendor_project AS kev_vendor_project,
                kev.product AS kev_product,
                kev.vuln_name AS kev_vuln_name,
                COALESCE(exploits.has_exploit, FALSE) AS has_exploit,
                exploits.exploit_sources,
                COALESCE(array_agg(DISTINCT cwe.cwe_id) FILTER (WHERE cwe.cwe_id IS NOT NULL), '{{}}') AS cwe_ids,
                COALESCE(jsonb_agg(DISTINCT jsonb_build_object(
                    'url', refs.url,
                    'source', refs.source,
                    'tags', refs.tags
                )) FILTER (WHERE refs.url IS NOT NULL), '[]'::jsonb) AS references,
                COALESCE(jsonb_agg(DISTINCT jsonb_build_object(
                    'cpe_uri', cpe.cpe_uri,
                    'vendor', cpe.vendor,
                    'product', cpe.product,
                    'version_start_including', cpe.version_start_including,
                    'version_start_excluding', cpe.version_start_excluding,
                    'version_end_including', cpe.version_end_including,
                    'version_end_excluding', cpe.version_end_excluding
                )) FILTER (WHERE cpe.cpe_uri IS NOT NULL), '[]'::jsonb) AS affected
            FROM cve c
            {BEST_CVSS_LATERAL}
            LEFT JOIN epss ON epss.cve_id = c.cve_id
            LEFT JOIN kev ON kev.cve_id = c.cve_id
            LEFT JOIN exploits ON exploits.cve_id = c.cve_id
            LEFT JOIN cwe ON cwe.cve_id = c.cve_id
            LEFT JOIN cve_references refs ON refs.cve_id = c.cve_id
            LEFT JOIN cpe ON cpe.cve_id = c.cve_id
            WHERE c.cve_id = :cve_id
            GROUP BY
                c.cve_id, c.description, c.published_date, c.last_modified, c.raw_json,
                best_cvss.version, best_cvss.base_score, best_cvss.severity, best_cvss.vector,
                epss.epss_score, epss.percentile,
                kev.cve_id, kev.due_date, kev.vendor_project, kev.product, kev.vuln_name,
                exploits.has_exploit, exploits.exploit_sources
            """
        )
        try:
            with get_vuln_engine().connect() as conn:
                row = conn.execute(query, {"cve_id": cve_id}).mappings().first()
            if not row:
                return None
            record = self._format_postgres_row(row)
            record["references"] = as_list(row.get("references"))
            record["affected"] = as_list(row.get("affected"))
            record["cwe_ids"] = as_list(row.get("cwe_ids"))
            record["raw_json"] = row.get("raw_json")
            return record
        except SQLAlchemyError as exc:
            logger.error("PostgreSQL CVE detail lookup failed for %s: %s", cve_id, exc)
            if self.sqlite_available:
                return self._get_sqlite_details(cve_id)
            return None

    def _get_postgres_by_severity(self, severity: str) -> list[dict]:
        query = text(
            f"""
            SELECT
                c.cve_id,
                c.description,
                c.published_date,
                c.last_modified,
                best_cvss.version AS cvss_version,
                best_cvss.base_score AS cvss_score,
                best_cvss.severity AS cvss_severity,
                best_cvss.vector AS cvss_vector,
                epss.epss_score,
                epss.percentile AS epss_percentile,
                (kev.cve_id IS NOT NULL) AS in_kev,
                kev.due_date AS kev_due_date,
                kev.vendor_project AS kev_vendor_project,
                kev.product AS kev_product,
                kev.vuln_name AS kev_vuln_name,
                COALESCE(exploits.has_exploit, FALSE) AS has_exploit,
                exploits.exploit_sources
            FROM cve c
            {BEST_CVSS_LATERAL}
            LEFT JOIN epss ON epss.cve_id = c.cve_id
            LEFT JOIN kev ON kev.cve_id = c.cve_id
            LEFT JOIN exploits ON exploits.cve_id = c.cve_id
            WHERE UPPER(COALESCE(best_cvss.severity, 'NONE')) = :severity
            ORDER BY
                (kev.cve_id IS NOT NULL) DESC,
                COALESCE(epss.epss_score, 0) DESC,
                COALESCE(best_cvss.base_score, 0) DESC
            LIMIT 200
            """
        )
        try:
            with get_vuln_engine().connect() as conn:
                rows = (
                    conn.execute(query, {"severity": severity.upper()}).mappings().all()
                )
            return [self._format_postgres_row(row) for row in rows]
        except SQLAlchemyError as exc:
            logger.error("PostgreSQL severity lookup failed for %s: %s", severity, exc)
            if self.sqlite_available:
                return self._get_sqlite_by_severity(severity)
            return []

    def _format_postgres_row(self, row: dict[str, Any]) -> dict[str, Any]:
        record = {
            "cve_id": row.get("cve_id"),
            "description": row.get("description") or "",
            "cvss_score": float(row.get("cvss_score") or 0.0),
            "severity": title_case_severity(
                row.get("cvss_severity"), row.get("cvss_score")
            ),
            "cvss_version": row.get("cvss_version"),
            "cvss_vector": row.get("cvss_vector"),
            "published": row.get("published_date"),
            "updated_at": row.get("last_modified"),
            "epss_score": float(row.get("epss_score") or 0.0),
            "epss_percentile": float(row.get("epss_percentile") or 0.0),
            "in_kev": bool(row.get("in_kev")),
            "kev_due_date": row.get("kev_due_date"),
            "kev_vendor_project": row.get("kev_vendor_project"),
            "kev_product": row.get("kev_product"),
            "kev_vuln_name": row.get("kev_vuln_name"),
            "has_exploit": bool(row.get("has_exploit")),
            "exploit_sources": as_list(row.get("exploit_sources")),
        }
        return merge_alias_fields(record)

    def _search_sqlite(self, service_name: str, version: str = "") -> list[dict]:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            search_term = f"%{service_name}%"
            query = """
                SELECT cve_id, description, cvss_score, severity
                FROM cves
                WHERE affected_software LIKE ? OR description LIKE ?
                ORDER BY cvss_score DESC
                LIMIT 20
            """
            cursor.execute(query, (search_term, search_term))
            rows = cursor.fetchall()
            conn.close()
            return [
                merge_alias_fields(
                    {
                        "cve_id": row[0],
                        "description": row[1],
                        "cvss_score": row[2] or 0.0,
                        "severity": row[3],
                    }
                )
                for row in rows
            ]
        except sqlite3.Error as exc:
            logger.error("SQLite CVE search failed for %s: %s", service_name, exc)
            return self._fallback_search(service_name, version)

    def _get_sqlite_details(self, cve_id: str) -> dict | None:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
            row = cursor.fetchone()
            conn.close()
            if not row:
                return None
            return merge_alias_fields(
                {
                    "cve_id": row[0],
                    "description": row[1],
                    "cvss_score": row[2],
                    "severity": row[3],
                    "affected": json.loads(row[4]) if row[4] else [],
                    "references": json.loads(row[5]) if row[5] else [],
                    "published": row[6],
                    "updated_at": row[7],
                }
            )
        except (sqlite3.Error, json.JSONDecodeError) as exc:
            logger.error("SQLite CVE detail lookup failed for %s: %s", cve_id, exc)
            return None

    def _get_sqlite_by_severity(self, severity: str) -> list[dict]:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT cve_id, description, cvss_score, severity
                FROM cves
                WHERE severity = ?
                ORDER BY cvss_score DESC
                """,
                (severity,),
            )
            rows = cursor.fetchall()
            conn.close()
            return [
                merge_alias_fields(
                    {
                        "cve_id": row[0],
                        "description": row[1],
                        "cvss_score": row[2],
                        "severity": row[3],
                    }
                )
                for row in rows
            ]
        except sqlite3.Error as exc:
            logger.error("SQLite severity lookup failed for %s: %s", severity, exc)
            return []

    def _fallback_search(self, service_name: str, version: str) -> list[dict]:
        from core.constants import CVE_HINTS

        service_name_lower = service_name.lower()
        cves: list[dict] = []
        for key, hints in CVE_HINTS.items():
            if service_name_lower in key.lower() or key.lower() in service_name_lower:
                cves.extend(hints)
        normalized = [merge_alias_fields(item) for item in cves]
        normalized.sort(key=lambda item: item.get("cvss_score", 0.0), reverse=True)
        return normalized[:20]


_cve_db: CVEDatabase | None = None


def get_cve_database() -> CVEDatabase:
    global _cve_db
    if _cve_db is None:
        _cve_db = CVEDatabase()
    return _cve_db
