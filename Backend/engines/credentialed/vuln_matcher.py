"""
engines/credentialed/vuln_matcher.py
--------------------------------------
Matches installed package versions against a CVE knowledge base.

This is significantly more accurate than banner-based matching because
we have the exact package name and version from the package manager
rather than guessing from a service banner.

Usage::

    from engines.credentialed.vuln_matcher import VulnMatcher

    matcher = VulnMatcher()
    findings = matcher.match_packages(packages_list)
    # findings: List[CredentialedCVE]
"""

import logging
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from pathlib import Path

log = logging.getLogger("ccure.vuln_matcher")

@dataclass
class CredentialedCVE:
    """A CVE finding from package-version matching."""
    cve_id:          str
    severity:        str
    cvss_score:      float
    description:     str
    package_name:    str
    installed_ver:   str
    fixed_ver:       str = ""
    source:          str = "package_version_match"

def _extract_nvd_constraints(affected_raw: str, pkg_name: str) -> List[Dict[str, Any]]:
    constraints = []
    if not affected_raw:
        return constraints
    try:
        affected = json.loads(affected_raw)
    except Exception:
        return constraints
        
    for conf in affected:
        for node in conf.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                cpe = match.get("criteria", "").lower()
                parts = cpe.split(":")
                product = parts[4] if len(parts) > 4 else ""
                
                if pkg_name not in product and product not in pkg_name:
                    continue
                    
                exact_ver = parts[5] if len(parts) > 5 and parts[5] not in ("*", "-") else None
                min_v = match.get("versionStartIncluding") or match.get("versionStartExcluding")
                max_v = match.get("versionEndIncluding") or match.get("versionEndExcluding")
                
                if exact_ver or min_v or max_v:
                    constraints.append({
                        "min_ver": min_v,
                        "max_ver": max_v,
                        "exact_ver": exact_ver
                    })
    return constraints

class VulnMatcher:
    """
    Matches a list of installed packages against a local CVE database via SQLAlchemy.
    """

    def __init__(self):
        db_path = Path(__file__).parent.parent.parent / "cves.db"
        self.engine = create_engine(f"sqlite:///{db_path}")

    def match_packages(
        self,
        packages: List[Dict[str, str]],
    ) -> List[CredentialedCVE]:
        findings: List[CredentialedCVE] = []
        seen_cves: set = set()

        try:
            with self.engine.connect() as conn:
                for pkg in packages:
                    name    = pkg.get("name", "").lower().strip()
                    version = pkg.get("version", "").strip()

                    if not name or not version:
                        continue

                    query = text("""
                        SELECT cve_id, description, cvss_score, severity, affected_software
                        FROM cves
                        WHERE affected_software LIKE :name OR description LIKE :name
                        LIMIT 50
                    """)
                    results = conn.execute(query, {"name": f"%{name}%"}).fetchall()

                    for row in results:
                        cve_id, desc, cvss, severity, affected_raw = row
                        
                        if cve_id in seen_cves:
                            continue

                        constraints = _extract_nvd_constraints(affected_raw, name)
                        
                        if not constraints:
                            continue

                        for c in constraints:
                            cve_dict = {
                                "cve_id": cve_id,
                                "severity": severity,
                                "cvss": cvss,
                                "description": desc,
                                "min_ver": c["min_ver"],
                                "max_ver": c["max_ver"],
                                "fixed_ver": c["max_ver"] or "",
                            }
                            finding = None
                            if c["exact_ver"]:
                                if _version_gte(version, c["exact_ver"]) and _version_lt(version, c["exact_ver"] + ".99"):
                                    finding = self._check_match(name, version, cve_dict)
                            else:
                                finding = self._check_match(name, version, cve_dict)
                                
                            if finding:
                                findings.append(finding)
                                seen_cves.add(cve_id)
                                break

        except OperationalError as e:
            log.warning(f"CVE database query failed: {e}. Ensure you ran download_nvd.py.")

        findings.sort(key=lambda c: c.cvss_score, reverse=True)
        return findings

    def _check_match(
        self,
        pkg_name:  str,
        installed: str,
        cve:       Dict[str, Any],
    ) -> Optional[CredentialedCVE]:
        """Return a CredentialedCVE if installed version is in vulnerable range."""
        min_ver  = cve.get("min_ver")
        max_ver  = cve.get("max_ver")

        if min_ver and not _version_gte(installed, min_ver):
            return None

        if max_ver and not _version_lt(installed, max_ver):
            return None

        return CredentialedCVE(
            cve_id        = cve["cve_id"],
            severity      = cve.get("severity", "Unknown"),
            cvss_score    = float(cve.get("cvss", 0.0)),
            description   = cve.get("description", ""),
            package_name  = pkg_name,
            installed_ver = installed,
            fixed_ver     = cve.get("fixed_ver", ""),
        )

    def to_report_format(self, findings: List[CredentialedCVE]) -> List[Dict[str, Any]]:
        return [
            {
                "cve_id":       f.cve_id,
                "severity":     f.severity,
                "cvss_score":   f.cvss_score,
                "description":  f.description,
                "package":      f.package_name,
                "installed_ver": f.installed_ver,
                "fixed_ver":    f.fixed_ver,
                "source":       f.source,
            }
            for f in findings
        ]



# ---------------------------------------------------------------------------
# Version comparison helpers
# ---------------------------------------------------------------------------

def _parse_version(ver: str) -> Tuple[int, ...]:
    """
    Extract numeric components from a version string.

    Examples
    --------
    "1.1.1f"       → (1, 1, 1, 6)      # letters → ord offset
    "7.4p1"        → (7, 4, 1)
    "2.4.51"       → (2, 4, 51)
    "2.35-0ubuntu" → (2, 35)
    """
    # Strip Debian epoch prefix (e.g. "1:7.6p1" → "7.6p1")
    if ":" in ver:
        ver = ver.split(":", 1)[1]
    # Strip distro suffix noise (ubuntu, debian, el9, etc.)
    ver = re.sub(r"(ubuntu|debian|el\d|deb\d|~).*$", "", ver, flags=re.IGNORECASE)

    # Normalise: split on non-numeric separators
    parts = re.split(r"[.\-~+]", ver)
    nums: List[int] = []
    for part in parts:
        if part.isdigit():
            nums.append(int(part))
        else:
            # e.g. "1f" → extract leading digits + letter offset
            m = re.match(r"(\d+)([a-z]?)", part, re.IGNORECASE)
            if m:
                if m.group(1):
                    nums.append(int(m.group(1)))
                if m.group(2):
                    nums.append(ord(m.group(2).lower()) - ord("a") + 1)
    return tuple(nums) if nums else (0,)


def _version_lt(ver_a: str, ver_b: str) -> bool:
    """Return True if ver_a < ver_b."""
    a = _parse_version(ver_a)
    b = _parse_version(ver_b)
    # Pad shorter tuple with zeros
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    return a < b


def _version_gte(ver_a: str, ver_b: str) -> bool:
    """Return True if ver_a >= ver_b."""
    return not _version_lt(ver_a, ver_b)
