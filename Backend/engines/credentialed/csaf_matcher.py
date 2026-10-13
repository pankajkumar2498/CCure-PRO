"""
engines/credentialed/csaf_matcher.py
─────────────────────────────────────────────────────────────────────────────
Match installed software against vendor CSAF advisories.

Why this exists
───────────────
OT software is largely invisible to NVD. TIA Portal, WinCC, SIMATIC ProSave
and their siblings either have no CPE at all or have one nobody publishes
against, so the CPE path — which carries every other finding this product
makes — sees nothing. The vendor publishes the advisory instead, and for these
products it is frequently the only structured source there is.

Why the matching is this strict
───────────────────────────────
The obvious approach is token containment, the same rule the Microsoft
application matcher uses. Measured against the real host it produced **1,901
matches from 191 packages**, and inspection showed most were wrong:

    Google Cloud SDK                    ->  TIA Portal Cloud V16
    SIMATIC WinCC Runtime Advanced V17  ->  SIMATIC WinCC 7.2

The failure is structural. Stripping vendor and product-family noise from an
OT name removes exactly the words that distinguish products — "Runtime",
"Advanced", "Professional" — leaving a single generic token like ``wincc`` or
``cloud`` that matches half the catalogue. Containment works for
"Google Chrome" and does not work here.

Two conditions are therefore required, and both were derived from measurement
rather than taste:

1. **Normalised whole-name equality.** Not containment, not overlap. Vendor
   prefix, parentheticals, version tokens and update suffixes are removed from
   both sides and the remainder must be identical.

2. **Release-line agreement.** A product name matching is not enough: an
   advisory for "SIMATIC ProSave V18" carrying ``vers:all/*`` means every
   version *of the V18 line*, not of ProSave. Without this, an installed V19
   inherits V18's and V20's advisories. This is the same failure as the
   Windows servicing-line bug — the product matched, the version line did not
   — and on this host the rule correctly withheld advisories for WinCC Runtime
   Advanced V11 through V16 from an installed V17.

What is deliberately not asserted
─────────────────────────────────
A constraint this module cannot compare — ``<V19_Update_4``, "All versions
prior to the latest build" — produces **no finding**. Those are counted and
reported as unassessed rather than guessed at, because an ordering invented
between "V17.0 UPD6" and "V19_Update_4" would compare cleanly and mean
nothing.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Iterable

from core.vuln_intel import get_vuln_engine
from engines.credentialed.vuln_matcher import (
    compare_distro_versions,
    version_too_coarse,
)
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

log = logging.getLogger("ccure.credentialed.csaf")

_PARENTHETICAL = re.compile(r"\(.*?\)")
_VERSION_TOKEN = re.compile(r"\bv?\d+(\.\d+)*\b", re.IGNORECASE)
_UPDATE_TOKEN = re.compile(r"\b(upd|update|sp|service pack)\s*\d*\b", re.IGNORECASE)
_VENDOR_PREFIX = re.compile(r"^\s*siemens\s+", re.IGNORECASE)
_RELEASE_LINE = re.compile(r"\bV?(\d+(?:\.\d+)?)\b", re.IGNORECASE)

#: A constraint this module can order against an installed version: an
#: optional `vers:<scheme>/` prefix, an operator, and a purely numeric dotted
#: version. Anything with words in it ("V19_Update_4") is not comparable.
_COMPARABLE = re.compile(
    r"^(?:vers:[a-z]+/)?(?P<op>[<>]=?)\s*v?(?P<version>\d+(?:\.\d+)*)\s*$",
    re.IGNORECASE,
)

#: Every version of this product line is affected, so no comparison is needed —
#: presence of the line is the finding.
_ALL_AFFECTED = {"vers:all/*", "vers:all/<*", "*"}


def normalize_product(name: str) -> str:
    """Reduce a product name to its identity, dropping vendor and version noise."""
    text_value = _VENDOR_PREFIX.sub("", str(name or ""))
    text_value = _PARENTHETICAL.sub(" ", text_value)
    # Siemens writes "Product: <constraint>" in some names; the tail is the
    # constraint, not part of the identity.
    text_value = re.sub(r":.*$", " ", text_value)
    text_value = _VERSION_TOKEN.sub(" ", text_value)
    text_value = _UPDATE_TOKEN.sub(" ", text_value)
    text_value = re.sub(r"[^A-Za-z0-9]+", " ", text_value)
    return " ".join(text_value.lower().split())


def release_line(value: str) -> str | None:
    """The major release line — ``19`` from "SIMATIC ProSave V19.0"."""
    match = _RELEASE_LINE.search(str(value or ""))
    if not match:
        return None
    return match.group(1).split(".")[0]


def _installed_is_affected(installed: str, constraint: str) -> bool | None:
    """
    Whether an installed version falls inside a CSAF constraint.

    ``None`` means the constraint could not be ordered against the installed
    version — the caller records that as unassessed and raises nothing.
    """
    text_value = str(constraint or "").strip()
    if text_value.lower() in _ALL_AFFECTED:
        return True

    match = _COMPARABLE.match(text_value)
    if not match:
        return None

    order = compare_distro_versions(installed, match.group("version"))
    if order is None:
        return None

    op = match.group("op")
    if op == "<":
        return order < 0
    if op == "<=":
        return order <= 0
    if op == ">":
        return order > 0
    return order >= 0


class CsafProductMatcher:
    """Matches installed packages against vendor CSAF advisories."""

    def __init__(self) -> None:
        self.engine = get_vuln_engine()
        self._considered = 0
        self._name_matched = 0
        self._line_matched = 0
        self._uncomparable = 0

    def coverage(self) -> dict:
        return {
            "csaf_packages_considered": self._considered,
            "csaf_products_matched": self._name_matched,
            "csaf_release_line_agreed": self._line_matched,
            "csaf_constraints_uncomparable": self._uncomparable,
        }

    def match(self, packages: Iterable[dict]) -> list[dict]:
        rows = self._load_catalogue()
        if not rows:
            return []

        by_name: dict[str, list[dict]] = {}
        for row in rows:
            key = normalize_product(row["product_name"])
            if key:
                by_name.setdefault(key, []).append(row)

        findings: list[dict] = []
        emitted: set[tuple] = set()

        for pkg in packages or []:
            name = str(pkg.get("name") or "").strip()
            version = str(pkg.get("version") or "").strip()
            if not name:
                continue
            self._considered += 1

            candidates = by_name.get(normalize_product(name))
            if not candidates:
                continue
            self._name_matched += 1

            # The display name carries the line when DisplayVersion does not
            # ("SIMATIC ProSave V19.0" against a version of "19.00.0000").
            installed_line = release_line(version) or release_line(name)
            if not installed_line:
                continue

            for row in candidates:
                if release_line(row["product_name"]) != installed_line:
                    continue
                self._line_matched += 1

                verdict = _installed_is_affected(version, row["version_constraint"])
                if verdict is None:
                    self._uncomparable += 1
                    continue
                if not verdict:
                    continue

                cve_id = row["cve_id"]
                key = (cve_id, name)
                if key in emitted:
                    continue
                emitted.add(key)

                # "V19" against "< 19.0.2" is in range only if the update level
                # the version does not state is below 2.
                comparable = _COMPARABLE.match(
                    str(row["version_constraint"] or "").strip()
                )
                coarse = bool(comparable) and version_too_coarse(
                    version, comparable.group("version")
                )

                findings.append(
                    {
                        "cve_id": cve_id,
                        "severity": _severity(row["cvss_score"]),
                        "cvss_score": float(row["cvss_score"] or 0.0),
                        "description": (
                            f"{row['product_name']} is affected by {cve_id} "
                            f"({row['advisory_id']}). Installed: {version or 'unknown'}; "
                            f"advisory constraint: {row['version_constraint']}."
                        ),
                        "package_name": name,
                        "installed_ver": version,
                        "installed_version_precision": "coarse" if coarse else "",
                        "fixed_ver": _fixed_from_constraint(row["version_constraint"]),
                        "source": "csaf",
                        "matched_by": f"csaf:{row['provider']}",
                        "vendor_advisories": [
                            {
                                "advisory_id": row["advisory_id"],
                                "provider": row["provider"],
                                "title": row["title"],
                                "url": row["url"],
                                "remediation": row["remediation"],
                            }
                        ],
                        "vendor_remediation": (
                            f"{str(row['provider']).upper()} {row['advisory_id']}: "
                            f"{row['remediation']}"
                            if row["remediation"]
                            else None
                        ),
                    }
                )

        if findings or self._name_matched:
            log.info(
                "CSAF matching: %d package(s) considered, %d matched a product, "
                "%d agreed on release line, %d finding(s); %d constraint(s) not "
                "comparable and therefore not asserted",
                self._considered,
                self._name_matched,
                self._line_matched,
                len(findings),
                self._uncomparable,
            )
        return findings

    def _load_catalogue(self) -> list[dict]:
        if self.engine is None:
            return []
        try:
            with self.engine.connect() as conn:
                return [
                    dict(r)
                    for r in conn.execute(
                        text(
                            """
                            SELECT f.product_name,
                                   f.version_constraint,
                                   f.remediation,
                                   c.cve_id,
                                   c.cvss_score,
                                   a.id       AS advisory_id,
                                   a.provider,
                                   a.title,
                                   a.url
                            FROM csaf_affected f
                            JOIN csaf_advisory_cve c
                              ON c.advisory_id = f.advisory_id
                             AND c.cve_id = f.cve_id
                            JOIN csaf_advisory a ON a.id = f.advisory_id
                            WHERE f.category = 'product_version_range'
                              AND f.version_constraint IS NOT NULL
                              AND f.product_name <> ''
                              AND f.status = 'known_affected'
                            """
                        )
                    ).mappings()
                ]
        except SQLAlchemyError as exc:
            log.warning("CSAF catalogue unavailable: %s", exc)
            return []


def _fixed_from_constraint(constraint: str) -> str:
    """The version that resolves the finding, when the constraint names one."""
    match = _COMPARABLE.match(str(constraint or "").strip())
    if match and match.group("op").startswith("<"):
        return match.group("version")
    return ""


def _severity(score: Any) -> str:
    try:
        value = float(score or 0.0)
    except (TypeError, ValueError):
        value = 0.0
    if value >= 9.0:
        return "Critical"
    if value >= 7.0:
        return "High"
    if value >= 4.0:
        return "Medium"
    if value > 0.0:
        return "Low"
    return "Info"
