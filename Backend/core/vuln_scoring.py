"""
core/vuln_scoring.py
─────────────────────────────────────────────────────────────────────────────
How a vulnerability record is normalised and prioritised: severity casing,
the KEV/EPSS/exploit/CVSS priority, and the aliased fields every finding
carries. Pure functions over plain values — no database, no configuration, no
I/O — so anything may use them without loading the vulnerability-intelligence
database layer.

They lived in ``core/vuln_intel.py`` beside the queries against the
``vuln_intel`` database, so ``core/risk.py``, which needs two of them to merge
duplicate findings, loaded SQLAlchemy and the database configuration — and
through ``core.risk`` so did the discovery engine, which only wants OS
fingerprinting. They moved here unchanged in B3
(docs/architecture/MODULAR_REFACTORING_LOG.md §6); ``core.vuln_intel``
re-exports them, so ``core.vuln_intel.compute_priority`` is this very function
and every existing caller is unaffected.

The priority ladder is still the vulnerability-intelligence capability's own
(routers/findings.py mirrors it in SQL), which is why this module is classified
with it rather than with the scan kernel.
"""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
import re
from collections.abc import Sequence
from typing import Any


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


# The version matcher's query helpers, pure (G3): moved from core.vuln_intel,
# which re-exports them, so the matcher loads no database layer.


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
