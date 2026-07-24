"""
Shared helpers for the separate vulnerability-intelligence database.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from datetime import date, datetime
from decimal import Decimal
from functools import lru_cache
from typing import Any, Dict, List, Tuple

from config import AppConfig
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)

CVSS_VERSION_ORDER = {
    "4.0": 4,
    "3.1": 3,
    "3.0": 2,
    "2.0": 1,
}

SERVICE_ALIASES = {
    "openssh": ["openssh", "ssh"],
    "dropbear": ["dropbear", "ssh"],
    "apache": ["apache", "httpd"],
    "nginx": ["nginx"],
    "iis": ["iis", "microsoft-iis"],
    "redis": ["redis"],
    "mongodb": ["mongodb", "mongo"],
    "mysql": ["mysql"],
    "postgresql": ["postgresql", "postgres"],
    "tomcat": ["tomcat", "apache tomcat"],
    "php": ["php"],
    "openssl": ["openssl"],
    "ftp": ["ftp", "vsftpd", "proftpd"],
    "smb": ["smb", "samba", "microsoft-ds"],
    "rdp": ["rdp", "remote desktop"],
    "mssql": ["mssql", "sql server", "microsoft sql server"],
}


def title_case_severity(severity: Any, cvss_score: Any = 0.0) -> str:
    text = str(severity or "").strip().upper()
    if text in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}:
        return "Info" if text == "NONE" else text.title()
    try:
        score = float(cvss_score or 0.0)
    except (TypeError, ValueError):
        score = 0.0
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


def compute_priority(
    cvss_score: Any = 0.0,
    epss_score: Any = 0.0,
    in_kev: bool = False,
    has_exploit: bool = False,
) -> tuple[float, str]:
    try:
        cvss = float(cvss_score or 0.0)
    except (TypeError, ValueError):
        cvss = 0.0
    try:
        epss = float(epss_score or 0.0)
    except (TypeError, ValueError):
        epss = 0.0

    if in_kev:
        return 100.0, "P0"

    score = (epss * 40.0) + (cvss * 4.0) + (15.0 if has_exploit else 0.0)
    if epss >= 0.70 or (has_exploit and cvss >= 7.0):
        return round(score, 2), "P1"
    if cvss >= 9.0:
        return round(score, 2), "P2"
    if cvss >= 7.0 or epss >= 0.30:
        return round(score, 2), "P3"
    return round(score, 2), "P4"


def rank_cvss_version(version: str) -> int:
    return CVSS_VERSION_ORDER.get(str(version or "").strip(), 0)


def extract_search_terms(raw_text: str, include_aliases: bool = True) -> list[str]:
    text = (raw_text or "").strip().lower()
    if not text:
        return []

    terms: list[str] = []
    for canonical, aliases in SERVICE_ALIASES.items():
        matched_aliases = [
            alias
            for alias in aliases
            if re.search(rf"(^|[^a-z0-9]){re.escape(alias)}([^a-z0-9]|$)", text)
        ]
        if matched_aliases:
            terms.extend(matched_aliases)
            if re.search(rf"(^|[^a-z0-9]){re.escape(canonical)}([^a-z0-9]|$)", text):
                terms.append(canonical)

    for token in re.findall(r"[a-z][a-z0-9+._-]{1,}", text):
        if token.isdigit():
            continue
        if re.fullmatch(r"\d+([._-]\d+)+", token):
            continue
        terms.append(token)

    unique_terms: list[str] = []
    seen = set()
    for term in terms:
        normalized = term.strip().lower()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        unique_terms.append(normalized)

    return unique_terms[:10]


def normalize_package_names(name: str) -> list[str]:
    raw = (name or "").strip().lower()
    if not raw:
        return []

    candidates = {raw}
    candidates.add(raw.replace("_", "-"))
    candidates.add(raw.replace("-", "_"))
    candidates.add(raw.replace(" ", "-"))
    candidates.add(raw.replace(" ", "_"))
    candidates.add(raw.split(":")[0])
    candidates.add(re.sub(r"[^a-z0-9.+_-]+", "-", raw).strip("-"))

    no_vendor_prefix = re.sub(r"^(python3-|python-|lib|perl-|php-)", "", raw)
    if no_vendor_prefix:
        candidates.add(no_vendor_prefix)

    compact = re.sub(r"[^a-z0-9]+", "", raw)
    if compact:
        candidates.add(compact)

    return [item for item in candidates if item]


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _json_safe(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    return value


@lru_cache(maxsize=1)
def get_vuln_engine() -> Engine:
    return create_engine(
        AppConfig.VULN_DB_URL,
        pool_pre_ping=True,
        pool_recycle=3600,
        pool_size=5,
        max_overflow=5,
        echo=False,
        connect_args={"connect_timeout": 2},
    )


def can_connect_vuln_db() -> bool:
    try:
        with get_vuln_engine().connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        return True
    except SQLAlchemyError as exc:
        logger.warning("Vulnerability-intel database unavailable: %s", exc)
        return False


def merge_alias_fields(record: dict[str, Any]) -> dict[str, Any]:
    record = _json_safe(record)
    cve_id = record.get("cve_id") or record.get("cve")
    description = record.get("description") or record.get("desc") or ""
    cvss_score = record.get("cvss_score", record.get("cvss", 0.0))
    severity = title_case_severity(record.get("severity"), cvss_score)
    out = dict(record)
    out["cve_id"] = cve_id
    out["cve"] = cve_id
    out["description"] = description
    out["desc"] = description
    out["cvss_score"] = float(cvss_score or 0.0)
    out["cvss"] = float(cvss_score or 0.0)
    out["severity"] = severity
    priority_score, priority_level = compute_priority(
        cvss_score=out.get("cvss_score", 0.0),
        epss_score=out.get("epss_score", 0.0),
        in_kev=bool(out.get("in_kev")),
        has_exploit=bool(out.get("has_exploit")),
    )
    out.setdefault("priority_score", priority_score)
    out.setdefault("priority_level", priority_level)
    return out


def build_sql_or_clauses(
    column_expressions: Sequence[str],
    values: Sequence[str],
    param_prefix: str,
    use_exact: bool = False,
) -> tuple[str, dict[str, str]]:
    """
    Build SQL OR clauses for searching multiple values across columns.

    Parameters
    ----------
    column_expressions : Column expressions to search (e.g., "LOWER(p.product)")
    values : Values to search for
    param_prefix : Prefix for parameter names
    use_exact : If True, use exact match (=) instead of LIKE wildcards (%)
               Use this when indexes exist on the columns for better performance

    Returns
    -------
    Tuple of (WHERE clause string, parameter dict)
    """
    clauses: list[str] = []
    params: dict[str, str] = {}
    idx = 0
    for value in values:
        for expr in column_expressions:
            param_name = f"{param_prefix}_{idx}"
            if use_exact:
                # Exact match - uses indexes efficiently
                clauses.append(f"{expr} = :{param_name}")
                params[param_name] = value
            else:
                # LIKE match - slower but more flexible (handles partial matches)
                clauses.append(f"{expr} LIKE :{param_name}")
                params[param_name] = f"%{value}%"
            idx += 1
    return (" OR ".join(clauses)) or "FALSE", params
