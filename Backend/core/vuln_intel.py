"""
Shared helpers for the separate vulnerability-intelligence database.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from functools import lru_cache
from typing import Any, Dict, List, Tuple

from config import AppConfig
from db.fork_safety import release_pool_after_fork
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)

# Pure normalisation and priority, moved to core/vuln_scoring.py in B3 so that
# using them no longer loads this module's database layer. Re-exported: the
# names here are those same functions, for every existing caller.
from core.vuln_scoring import (  # noqa: E402,F401
    _json_safe,
    build_sql_or_clauses,
    compute_priority,
    merge_alias_fields,
    normalize_package_names,
    title_case_severity,
)

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


def parse_cpe_identities(cpes: Any) -> list[tuple[str, str]]:
    """
    Extract ``(vendor, product)`` pairs from scanner-assigned CPE strings.

    Both formats in circulation are handled — CPE 2.2 (``cpe:/a:vendor:product``),
    which is what Nmap emits, and CPE 2.3 (``cpe:2.3:a:vendor:product:...``).
    Anything that does not parse is skipped rather than guessed at: a bad
    identity would silently select the wrong product's CVEs.
    """
    identities: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw in as_list(cpes):
        text_value = str(raw or "").strip().lower()
        if not text_value.startswith("cpe:"):
            continue
        parts = text_value.split(":")
        if len(parts) > 2 and parts[1] == "2.3":
            vendor, product = (parts[3], parts[4]) if len(parts) > 4 else ("", "")
        else:
            # cpe:/a:vendor:product[:version]
            vendor, product = (parts[2], parts[3]) if len(parts) > 3 else ("", "")
        vendor, product = vendor.strip(), product.strip()
        if not vendor or not product or product in ("*", "-"):
            continue
        if (vendor, product) not in seen:
            seen.add((vendor, product))
            identities.append((vendor, product))
    return identities


def build_cpe_identity_clauses(
    identities: list[tuple[str, str]],
) -> tuple[str, dict[str, str]]:
    """
    WHERE clause selecting rows by exact CPE **product**.

    Equality rather than ``LIKE '%…%'``: these come from the scanner's own
    identification, so there is nothing to guess, and equality uses the index
    on the column.

    Vendor is deliberately not part of the key. The two sides disagree on it
    often enough to matter — Nmap still identifies nginx as ``igor_sysoev``
    while NVD reassigned it to ``f5`` — and requiring both to agree would drop
    every nginx CVE on the floor. Product names come from the same CPE
    dictionary on both sides and are stable across those vendor reassignments.
    """
    clauses: list[str] = []
    params: dict[str, str] = {}
    for index, (_vendor, product) in enumerate(identities):
        param = f"cpe_p_{index}"
        if param in params:
            continue
        clauses.append(f"LOWER(cpe.product) = :{param}")
        params[param] = product
    return (" OR ".join(clauses)) or "FALSE", params


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


@lru_cache(maxsize=1)
def get_vuln_engine() -> Engine:
    # The worker's parent process connects this engine at import (core/utils.py
    # probes it), so without the fork guard every Celery child shares one
    # socket to vuln_intel — see db/fork_safety.py.
    return release_pool_after_fork(
        create_engine(
            AppConfig.VULN_DB_URL,
            pool_pre_ping=True,
            pool_recycle=3600,
            pool_size=5,
            max_overflow=5,
            echo=False,
            connect_args={"connect_timeout": 2},
        )
    )


def can_connect_vuln_db() -> bool:
    try:
        with get_vuln_engine().connect() as conn:
            conn.exec_driver_sql("SELECT 1 FROM cve LIMIT 1")
        return True
    except SQLAlchemyError as exc:
        logger.debug("Vulnerability-intel database or 'cve' table unavailable: %s", exc)
        return False


def get_feed_freshness() -> dict[str, Any]:
    """
    Report how current the vulnerability feed is.

    A vulnerability report is only as good as the feed behind it: a scan run
    against a feed that is weeks old cannot know about anything published
    since, and "no findings" then means far less than it appears. The report
    therefore states the feed date rather than leaving the reader to assume it
    is current.

    Returns ``{"last_modified": date|None, "cve_count": int|None}``. Values are
    None when the feed cannot be queried, so the report says "not recorded"
    instead of implying freshness it cannot demonstrate.
    """
    blank: dict[str, Any] = {"last_modified": None, "cve_count": None}
    try:
        with get_vuln_engine().connect() as conn:
            row = conn.execute(
                text("SELECT max(last_modified), count(*) FROM cve")
            ).first()
    except SQLAlchemyError as exc:
        logger.debug("Vulnerability feed freshness unavailable: %s", exc)
        return blank

    if not row:
        return blank
    return {"last_modified": row[0], "cve_count": row[1]}


def csaf_advisories_for(cve_ids: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Vendor and ICS advisories covering these CVEs, keyed by CVE.

    Enrichment only, and joined on the CVE alone — which is why it is safe.
    Nothing here decides whether a host is affected; that verdict was already
    reached by the engine that raised the finding. This attaches what the
    vendor published about the same CVE: the advisory reference and, more
    usefully, the vendor's own remediation wording.

    That wording is the part NVD cannot supply. NVD yields a version boundary
    inferred from a CPE range; Siemens writes "Update to V2606 or later
    version". For OT products the vendor advisory is frequently the only place
    a remediation is stated at all.

    Deliberately not attempted here: deciding that an *unfound* CVE applies
    because a CSAF product name resembles something installed. CSAF product
    trees express versions in the `vers:` range syntax over nested branches,
    and matching an installed package against that is how confident false
    positives are made.
    """
    wanted = [str(c).strip().upper() for c in (cve_ids or []) if str(c or "").strip()]
    if not wanted:
        return {}

    engine = get_vuln_engine()
    if engine is None:
        return {}

    out: Dict[str, List[Dict[str, Any]]] = {}
    try:
        with engine.connect() as conn:
            rows = (
                conn.execute(
                    text(
                        """
                    SELECT c.cve_id,
                           a.id       AS advisory_id,
                           a.provider,
                           a.title,
                           a.url,
                           (
                               SELECT string_agg(DISTINCT f.remediation, ' | ')
                               FROM csaf_affected f
                               WHERE f.advisory_id = a.id
                                 AND f.cve_id = c.cve_id
                                 AND f.remediation IS NOT NULL
                           ) AS remediation
                    FROM csaf_advisory_cve c
                    JOIN csaf_advisory a ON a.id = c.advisory_id
                    WHERE c.cve_id = ANY(:cves)
                    ORDER BY a.updated DESC NULLS LAST
                    """
                    ),
                    {"cves": wanted},
                )
                .mappings()
                .all()
            )
    except SQLAlchemyError as exc:
        # Enrichment is additive: a findings report without vendor advisories
        # is still correct, so a failure here must not fail the scan.
        logger.warning("CSAF advisory lookup failed: %s", exc)
        return {}

    for row in rows:
        out.setdefault(row["cve_id"], []).append(
            {
                "advisory_id": row["advisory_id"],
                "provider": row["provider"],
                "title": row["title"],
                "url": row["url"],
                "remediation": row["remediation"],
            }
        )
    return out


def exploit_intel_for(cve_ids: Sequence[str]) -> Dict[str, Dict[str, Any]]:
    """
    Exploitation evidence for these CVEs, keyed by CVE.

    One lookup rather than three query sites, so the credentialed matcher, the
    network syncer and the backfill all report the same thing about the same
    CVE. Divergence between those paths is how a finding came to say different
    things depending on which engine raised it.

    Returns, per CVE: which corpora reported an exploit, whether one was
    reproduced, whether it has been seen against a honeypot, and whether it is
    used in ransomware. `has_exploit` on its own cannot separate a weaponised
    Metasploit module from an unreproduced proof of concept, and triage turns
    on exactly that difference.
    """
    wanted = [str(c).strip().upper() for c in (cve_ids or []) if str(c or "").strip()]
    if not wanted:
        return {}

    engine = get_vuln_engine()
    if engine is None:
        return {}

    out: Dict[str, Dict[str, Any]] = {}
    try:
        with engine.connect() as conn:
            rows = (
                conn.execute(
                    text(
                        """
                    SELECT e.cve_id,
                           e.exploit_sources,
                           e.verified_exploit,
                           COALESCE(v.canary_confirmed, FALSE) AS canary_confirmed,
                           -- VulnCheck records this as free text ("Known",
                           -- "Unknown"), so only an explicit "known" counts.
                           (lower(COALESCE(v.ransomware, '')) = 'known')
                               AS ransomware_linked
                    FROM exploits e
                    LEFT JOIN vulncheck_kev v ON v.cve_id = e.cve_id
                    WHERE e.cve_id = ANY(:cves) AND e.has_exploit
                    """
                    ),
                    {"cves": wanted},
                )
                .mappings()
                .all()
            )
    except SQLAlchemyError as exc:
        # Additive: a finding without exploit provenance is still a correct
        # finding, so this must never fail a scan.
        logger.warning("Exploit intel lookup failed: %s", exc)
        return {}

    for row in rows:
        out[row["cve_id"]] = {
            "exploit_sources": list(row["exploit_sources"] or []),
            "verified_exploit": bool(row["verified_exploit"]),
            "canary_confirmed": bool(row["canary_confirmed"]),
            "ransomware_linked": bool(row["ransomware_linked"]),
        }
    return out
