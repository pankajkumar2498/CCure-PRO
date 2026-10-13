"""
Matches installed package versions against the vulnerability-intelligence DB.
"""

from __future__ import annotations

import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from core.checks.platform_scope import configuration_platforms, declared_platforms
from engines.credentialed.package_identity import (
    candidate_products,
    curated_identity,
    is_companion_package,
    is_component_package,
    normalize_vendor,
    resolve_identities,
    version_space_contains,
)
from core.vuln_intel import (
    build_sql_or_clauses,
    get_vuln_engine,
    merge_alias_fields,
    normalize_package_names,
)
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

log = logging.getLogger("ccure.vuln_matcher")

# Performance tuning constants
BATCH_QUERY_THRESHOLD = 50  # Use batch query when packages >= this
PARALLEL_WORKERS = 4  # Parallel threads for package matching
QUERY_TIMEOUT = 30  # Query timeout in seconds
#: Rows fetched per resolved CPE identity. Applied per product, not across
#: the whole result, so a large product cannot displace a small one.
#:
#: Sized against the real dictionary rather than guessed: once per-build
#: pins that cannot match the installed version are filtered out in SQL,
#: the largest product observed (google:chrome) contributes ~5,600 rows.
#: This sits well above that, so the cap is a safety valve rather than a
#: silent filter — and reaching it is logged with the product named.
PER_IDENTITY_ROW_CAP = 25000
#: Ceiling on the OSV advisory rows one host's inventory may pull back. It was
#: ``LIMIT 5000`` and nothing noticed reaching it: an Ubuntu 24.04 desktop
#: (2,699 packages) matches 17,676 rows, so 12,676 were dropped without a word
#: — whichever ranked lowest by KEV, EPSS and CVSS. This sits an order of
#: magnitude above that, and reaching it is recorded as an incomplete lookup
#: in the result, not merely logged.
OSV_ROW_CAP = 200_000

#: A binary package built for one kernel ABI: linux-image-6.8.0-146-generic,
#: linux-headers-6.8.0-58, linux-modules-extra-6.8.0-142-generic,
#: linux-hwe-6.8-headers-6.8.0-58. Meta packages (linux-image-generic) and
#: kernel-independent ones (linux-firmware, linux-libc-dev) carry no ABI.
_KERNEL_ABI_PACKAGE = re.compile(
    r"^linux-[a-z0-9.-]*?-(\d+\.\d+\.\d+-\d+)(?:-[a-z0-9]+)*$"
)
_KERNEL_ABI = re.compile(r"^(\d+\.\d+\.\d+-\d+)")


def kernel_abi(release: str) -> str:
    """``6.8.0-146`` from ``uname -r``'s ``6.8.0-146-generic``; "" if unknown."""
    match = _KERNEL_ABI.match(str(release or "").strip())
    return match.group(1) if match else ""


def package_kernel_abi(name: str) -> str:
    """The kernel ABI a binary package was built for, or "" if it has none."""
    match = _KERNEL_ABI_PACKAGE.match(str(name or "").strip().lower())
    return match.group(1) if match else ""


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
    exploit_sources: list[str] = None
    priority_score: float = 0.0
    priority_level: str = "P4"
    matched_by: str = ""
    cpe_uri: str = ""
    cvss_version: str = ""
    cvss_vector: str = ""
    #: The CPE configuration this finding matched, in the shape the report
    #: normalizer reads. Without it the remediation resolver has no product
    #: or fixed version to work from, so credentialed findings could not be
    #: grouped by upgrade and their remediation text could not name one.
    affected_software: list = None
    #: The platforms this record applies to — "android", "macos", … — read
    #: from the CNA's description, NVD's "running on" configuration nodes or
    #: the CPE's target_sw. Empty means no restriction could be established,
    #: never "applies nowhere". The normalizer rules a finding out when the
    #: host runs a platform outside this list (core.checks.platform_scope).
    affected_platforms: list = None
    #: "coarse" when the installed version names less than the matched bound
    #: needs — "V19" against a fix in 19.0.2 — so the match is a possibility,
    #: not a confirmation (``version_too_coarse``). Empty otherwise.
    installed_version_precision: str = ""

    def __post_init__(self):
        if self.exploit_sources is None:
            self.exploit_sources = []
        if self.affected_software is None:
            self.affected_software = []
        if self.affected_platforms is None:
            self.affected_platforms = []


class VulnMatcher:
    """
    Matches installed packages against the normalized vuln-intel database.

    Optimizations applied:
    1. Batch queries - single query for all packages instead of N queries
    2. Parallel processing - concurrent package matching with ThreadPoolExecutor
    3. Query optimization - reduced JOIN overhead via batch operations
    """

    def __init__(self):
        self.engine = get_vuln_engine()
        self._package_vendors: dict[str, str] = {}
        #: OSV ecosystems applicable to the host being matched. Empty means the
        #: host's release could not be established, and OSV matching is skipped
        #: rather than run against every distribution in the database.
        self._osv_ecosystems: list[str] = []
        #: How much of the installed inventory this matcher could actually
        #: evaluate. Reported alongside the findings so "0 vulnerabilities" can
        #: be told apart from "nothing was assessable".
        self._packages_seen: int = 0
        self._packages_cpe_resolved: int = 0
        #: Toolchain fragments — SDK headers, vs_* MSIs, IntelliSense metadata.
        #: Counted separately so they neither inflate the coverage gap nor
        #: disappear from the report without a trace.
        self._packages_components: int = 0
        #: Advisory rows matched by package name that carry no version range at
        #: all. They establish nothing about the installed version, so they are
        #: counted here instead of being reported as findings.
        self._osv_rows_without_range: int = 0
        #: Feed lookups that failed. A failed query returns no rows, which is
        #: byte-identical to an inventory with nothing to report, so the failure
        #: travels with the result instead of staying in the worker log.
        self._lookup_failures: list[str] = []
        #: Packages built for a kernel other than the running one, by ABI.
        self._inactive_kernel_packages: dict[str, str] = {}
        self._running_kernel: str = ""

    @property
    def lookup_failures(self) -> list[str]:
        return list(self._lookup_failures)

    def _lookup_failed(self, stage: str, exc: Exception) -> None:
        log.warning("%s failed: %s", stage, exc)
        detail = str(getattr(exc, "orig", None) or exc).strip().splitlines()
        self._lookup_failures.append(
            f"{stage}: {detail[0][:200] if detail else type(exc).__name__}"
        )

    def coverage(self) -> dict:
        """
        What share of the installed inventory was assessable, and by what.

        A credentialed audit that evaluated 13 of 192 packages has not audited
        the host; it has audited 7% of it. Without this the result is
        indistinguishable from a clean bill of health.

        Toolchain components are excluded from the denominator, and that is a
        correction rather than a flattering adjustment. On a real Windows host,
        150 of 191 packages resolved to no CPE identity, which reads as a
        150-package blind spot — but most were SDK headers, ``vs_*`` resource
        MSIs and IntelliSense metadata, none of which NVD publishes a CPE for
        because none can be independently vulnerable. Leaving them in
        overstates the gap as badly as counting them as assessed would
        overstate the coverage. Both counts are reported so the exclusion is
        visible rather than assumed.
        """
        assessable = (
            self._packages_seen if self._osv_ecosystems else self._packages_cpe_resolved
        )
        real = max(self._packages_seen - self._packages_components, 0)
        real_assessable = real if self._osv_ecosystems else self._packages_cpe_resolved
        inactive = len(self._inactive_kernel_packages)
        if self._osv_ecosystems:
            # Collected, deliberately not assessed: see match_packages.
            assessable = max(assessable - inactive, 0)
            real_assessable = max(real_assessable - inactive, 0)
        if self._lookup_failures:
            # Collected is not assessed: nothing here was checked against the
            # feed it failed to reach.
            assessable = real_assessable = 0
        return {
            "packages_collected": self._packages_seen,
            "packages_assessable": assessable,
            "packages_cpe_resolved": self._packages_cpe_resolved,
            "packages_toolchain_components": self._packages_components,
            "packages_assessable_software": real,
            "osv_advisories_without_range": self._osv_rows_without_range,
            "lookup_failures": list(self._lookup_failures),
            "running_kernel": self._running_kernel or None,
            "packages_inactive_kernel": inactive,
            "inactive_kernels": sorted(set(self._inactive_kernel_packages.values())),
            "advisory_source": (
                self._osv_ecosystems[0] if self._osv_ecosystems else None
            ),
            "coverage_pct": (
                round(100.0 * assessable / self._packages_seen, 1)
                if self._packages_seen
                else 0.0
            ),
            # Coverage over software an audit could genuinely report on.
            "coverage_pct_software": (
                round(100.0 * real_assessable / real, 1) if real else 0.0
            ),
        }

    def match_packages(
        self,
        packages: list[dict[str, str]],
        os_id: str = "",
        os_version_id: str = "",
        running_kernel: str = "",
    ) -> list[CredentialedCVE]:
        """
        Match installed packages against the vulnerability database.

        ``os_id`` / ``os_version_id`` come from the host's own ``/etc/os-release``
        (``ID`` and ``VERSION_ID``). They scope OSV matching to the advisories
        published for that exact release — without them a 24.04 host was matched
        against 14.04, Debian and Mageia advisories whose fixed versions mean
        nothing here.

        ``running_kernel`` is ``uname -r``. A package built for another kernel
        ABI is left out of matching and counted in ``coverage()`` instead: on
        10.180.6.45 (13 Oct 2026, running 6.8.0-146) 3,391 kernel CVEs were
        reported against linux-headers-6.8.0-58 — header files of a kernel
        whose image was no longer installed — and the running kernel's own
        unfixed CVEs were filed under 6.8.0-142, which sorts first. Kernel
        advisories describe the kernel that runs; a kernel that is installed
        but not running is named as not assessed, never as clean. With no
        running kernel recorded, every package is matched as before.
        """
        if not packages:
            return []

        self._osv_ecosystems = osv_ecosystems_for(os_id, os_version_id)
        if self._osv_ecosystems:
            log.info("OSV matching scoped to %s", ", ".join(self._osv_ecosystems))
        elif os_id:
            # A distribution was identified but has no ecosystem mapping, so its
            # advisories cannot be reached. Worth flagging: distro-packaged
            # software on this host will be under-reported.
            log.warning(
                "No OSV ecosystem mapping for distribution %r %r — advisory "
                "matching is disabled for this host and distro-packaged "
                "software will be under-reported.",
                os_id,
                os_version_id,
            )
        else:
            # No /etc/os-release at all, which is the normal case for Windows.
            # Its software is not distribution-packaged, so OSV has nothing to
            # say about it and the CPE path is the right one.
            log.info(
                "No distribution release reported (version=%r); OSV advisory "
                "matching does not apply. Matching against CPE only.",
                os_version_id,
            )

        # Extract unique package names
        package_data = {}
        # Publisher per package: the vendor half of a CPE identity, and the
        # signal that decides whether a product-name match can be trusted.
        self._package_vendors = {}
        # Source package per binary, where the collector read it (dpkg), and
        # the source's own version, which is what an advisory's range is in.
        self._package_sources = {}
        self._package_source_versions = {}
        for pkg in packages:
            name = (pkg.get("name") or "").strip()
            version = (pkg.get("version") or "").strip()
            if name and name not in package_data:
                package_data[name] = version
                self._package_vendors[name] = (
                    pkg.get("vendor") or pkg.get("publisher") or ""
                ).strip()
                source = (pkg.get("source") or "").strip().lower()
                if source:
                    self._package_sources[name] = source
                    source_version = (pkg.get("source_version") or "").strip()
                    if source_version:
                        self._package_source_versions[name] = source_version

        if not package_data:
            return []
        # The inventory's size, whether or not a lookup succeeds. It used to be
        # set only after the first feed query, so a failed query reported
        # "0 packages collected" for a host that had 2,699.
        self._packages_seen = len(package_data)

        self._running_kernel = kernel_abi(running_kernel)
        self._inactive_kernel_packages = {}
        if self._running_kernel:
            for name in list(package_data):
                abi = package_kernel_abi(name)
                source = self._package_sources.get(name, "linux")
                if abi and abi != self._running_kernel and source.startswith("linux"):
                    self._inactive_kernel_packages[name] = abi
                    del package_data[name]
            if self._inactive_kernel_packages:
                log.info(
                    "Not assessing %d package(s) built for kernel(s) %s; "
                    "running kernel is %s",
                    len(self._inactive_kernel_packages),
                    ", ".join(sorted(set(self._inactive_kernel_packages.values()))),
                    self._running_kernel,
                )

        log.info(f"Matching {len(package_data)} unique packages against vuln database")
        start_time = time.time()

        # One path, whatever the package count. The batch path resolves every
        # package to a CPE identity in a single query and matches on it; the
        # per-package path matched loose name fragments against product OR
        # vendor, so which code ran — and therefore which findings appeared —
        # depended on how many packages the host happened to have installed.
        # It also issued N queries where this issues two.
        findings = self._match_packages_batch(package_data)
        self._attach_platform_scope(findings)

        elapsed = time.time() - start_time
        log.info(
            f"Package matching completed in {elapsed:.2f}s - found {len(findings)} CVEs"
        )

        return findings

    def _match_packages_batch(
        self, package_data: dict[str, str]
    ) -> list[CredentialedCVE]:
        """
        Batch query optimization - single query for all packages.

        Fetches all potential matches in one query, then filters in Python.
        This reduces N database round-trips to 1-2 queries.
        """
        findings: list[CredentialedCVE] = []
        best_by_cve: dict[str, CredentialedCVE] = {}

        try:
            with self.engine.connect() as conn:
                # Get all unique package names for batch query
                package_names = list(package_data.keys())

                # Build batch query for CPE records
                cpe_findings = self._batch_query_cpe(conn, package_names, package_data)

                # Build batch query for OSV records
                osv_findings = self._batch_query_osv(conn, package_names, package_data)

                # Merge findings, keeping highest priority per CVE
                all_findings = cpe_findings + osv_findings
                for finding in all_findings:
                    current = best_by_cve.get(finding.cve_id)
                    if (
                        current is None
                        or finding.priority_score > current.priority_score
                    ):
                        best_by_cve[finding.cve_id] = finding

        except SQLAlchemyError as exc:
            self._lookup_failed("Batch vulnerability query", exc)

        findings = list(best_by_cve.values())
        findings.sort(
            key=lambda item: (item.priority_score, item.cvss_score), reverse=True
        )
        return findings

    def _attach_platform_scope(self, findings: list[CredentialedCVE]) -> None:
        """
        Record which platforms each CPE-matched finding's record applies to.

        The ``cpe`` table is NVD's configuration flattened to its vulnerable
        entries, so "chrome AND running on iphone_os" arrives as plain
        "chrome". On a Windows host that reported 413 Chrome CVEs published
        for Android, Mac, iOS, Linux and ChromeOS. The configuration is read
        back from the CVE record here, once, for the findings that survived
        version matching — not in the main query, where it would be fetched
        for every one of Chrome's ~5,600 candidate rows.

        This only records the scope. Ruling a finding out is the normalizer's
        decision, so the candidate is still counted and named in the report's
        suppressed-candidates appendix rather than vanishing here.
        """
        scoped = [f for f in findings if f.matched_by == "cpe" and f.affected_software]
        if not scoped:
            return
        configurations: dict[str, Any] = {}
        try:
            with self.engine.connect() as conn:
                rows = (
                    conn.execute(
                        text(
                            "SELECT cve_id, raw_json->'configurations' AS configurations "
                            "FROM cve WHERE cve_id = ANY(:ids)"
                        ),
                        {"ids": sorted({f.cve_id for f in scoped})},
                    )
                    .mappings()
                    .all()
                )
            configurations = {r["cve_id"]: r["configurations"] for r in rows}
        except SQLAlchemyError as exc:
            # The description is still read below; only the configuration half
            # of the scope is lost, and losing it restricts nothing.
            log.warning("Could not read CVE configurations for platform scope: %s", exc)

        for finding in scoped:
            matched = finding.affected_software[0]
            installed = finding.installed_ver

            def version_matches(match: dict, installed: str = installed) -> bool:
                if not installed:
                    return True
                return self._installed_version_matches(
                    installed,
                    {
                        "cpe_uri": match.get("criteria") or "",
                        "version_start_including": match.get("versionStartIncluding"),
                        "version_start_excluding": match.get("versionStartExcluding"),
                        "version_end_including": match.get("versionEndIncluding"),
                        "version_end_excluding": match.get("versionEndExcluding"),
                    },
                )

            configured = configuration_platforms(
                configurations.get(finding.cve_id),
                str(matched.get("vendor") or ""),
                str(matched.get("product") or ""),
                version_matches,
            )
            finding.affected_platforms = list(
                declared_platforms(finding.description, configured, [finding.cpe_uri])
            )

    @staticmethod
    def _row_cpe_config(row) -> dict:
        """The matched CPE row as a configuration the report normalizer reads."""
        return {
            "cpe_uri": row.get("cpe_uri") or "",
            "vendor": row.get("vendor") or "",
            "product": row.get("product") or "",
            "version_start_including": row.get("version_start_including"),
            "version_start_excluding": row.get("version_start_excluding"),
            "version_end_including": row.get("version_end_including"),
            "version_end_excluding": row.get("version_end_excluding"),
        }

    def _resolve_package_identities(
        self, conn, package_data: dict[str, str]
    ) -> dict[str, list[tuple[str, str]]]:
        """
        Map installed package names to the CPE identities they resolve to.

        Candidates are proposed from the package's display name and publisher,
        then validated against the CPE dictionary in one query — a name only
        counts if NVD actually publishes under it. Packages that resolve to
        nothing are logged, because an unmatched package is a coverage gap in
        the audit and the operator should be able to see how large it is.
        """
        packages = [
            {"name": name, "vendor": self._package_vendors.get(name, "")}
            for name in package_data
        ]
        # Companion packages are excluded here as well as components. They are
        # already skipped by resolve_identities — an installer is not the
        # product it installs — so counting them as assessable-but-unresolved
        # charged the coverage figure for software the matcher deliberately
        # never looks at. Leaving them in was why this number disagreed with
        # the same measurement taken offline: 93 here against 76 there.
        self._packages_components = sum(
            1
            for pkg in packages
            if is_component_package(pkg["name"]) or is_companion_package(pkg["name"])
        )
        candidates: set[str] = set()
        for pkg in packages:
            candidates.update(
                candidate_products(
                    pkg["name"], normalize_vendor(pkg.get("vendor") or "")
                )
            )
        # Curated identities name a product NVD publishes under punctuation the
        # tokeniser cannot reproduce, so they must be queried for explicitly or
        # the dictionary lookup below will never confirm them.
        for pkg in packages:
            stated = curated_identity(pkg["name"])
            if stated is not None:
                candidates.add(stated[1])
        if not candidates:
            return {}

        rows = conn.execute(
            text(
                "SELECT DISTINCT LOWER(vendor) AS vendor, LOWER(product) AS product "
                "FROM cpe WHERE LOWER(product) = ANY(:candidates)"
            ),
            {"candidates": sorted(candidates)},
        ).fetchall()

        known: dict[str, list[tuple[str, str]]] = {}
        for vendor_name, product_name in rows:
            known.setdefault(product_name, []).append((vendor_name, product_name))

        resolved = resolve_identities(packages, known)
        resolved = self._drop_mismatched_version_spaces(conn, resolved, package_data)
        unresolved = [p["name"] for p in packages if p["name"] not in resolved]
        # "not assessed" is only true where OSV cannot cover the package either.
        # OSV is matched on the package name and needs no CPE identity, so on a
        # host with a scoped distribution the unresolved packages are still
        # assessed against that distribution's advisories — saying otherwise
        # understated the tool's own coverage. Where there is no OSV scope
        # (Windows, or a distribution with no ecosystem mapping) the CPE path is
        # the only one available and unresolved really does mean unassessed,
        # which is worth stating plainly.
        self._packages_cpe_resolved = len(resolved)
        if self._osv_ecosystems:
            log.info(
                "Package identity resolution: %d/%d packages mapped to a CPE "
                "product; the remaining %d are assessed against %s advisories "
                "by package name",
                len(resolved),
                len(packages),
                len(unresolved),
                self._osv_ecosystems[0],
            )
        else:
            log.warning(
                "Package identity resolution: %d/%d packages mapped to a CPE "
                "product; %d NOT ASSESSED — no distribution advisory source "
                "applies to this host, so software without a CPE identity is "
                "not evaluated at all",
                len(resolved),
                len(packages),
                len(unresolved),
            )
        if unresolved:
            log.debug("Unmatched packages: %s", ", ".join(sorted(unresolved)[:40]))
        return resolved

    def _drop_mismatched_version_spaces(
        self,
        conn,
        resolved: dict[str, list[tuple[str, str]]],
        package_data: dict[str, str],
    ) -> dict[str, list[tuple[str, str]]]:
        """
        Discard identities numbered in a different version space to the package.

        A name can resolve correctly and still be uncomparable: an installer
        carries the installer's version, not the product's, and some CPEs are
        numbered by year. Both compare cleanly against a release number and
        both produce nonsense, so the published versions for the product are
        used to check that the two sides are counting the same thing.
        """
        if not resolved:
            return resolved

        pairs = sorted({ident for idents in resolved.values() for ident in idents})
        params: dict[str, str] = {}
        clauses = []
        for index, (vendor_name, product_name) in enumerate(pairs):
            params[f"v_{index}"] = vendor_name
            params[f"p_{index}"] = product_name
            clauses.append(
                f"(LOWER(vendor) = :v_{index} AND LOWER(product) = :p_{index})"
            )

        rows = conn.execute(
            text(
                "SELECT LOWER(vendor) AS vendor, LOWER(product) AS product, "
                "version_start_including, version_start_excluding, "
                "version_end_including, version_end_excluding "
                f"FROM cpe WHERE {' OR '.join(clauses)}"
            ),
            params,
        ).fetchall()

        published: dict[tuple[str, str], list[str]] = {}
        for row in rows:
            key = (row[0], row[1])
            bucket = published.setdefault(key, [])
            for value in row[2:]:
                if value:
                    bucket.append(str(value))

        kept: dict[str, list[tuple[str, str]]] = {}
        for pkg_name, identities in resolved.items():
            installed = package_data.get(pkg_name, "")
            usable = [
                ident
                for ident in identities
                if version_space_contains(installed, published.get(ident, []))
            ]
            if usable:
                kept[pkg_name] = usable
            else:
                log.info(
                    "Package %r (version %r) resolves to %s but is numbered in a "
                    "different version space; no finding asserted",
                    pkg_name,
                    installed,
                    identities,
                )
        return kept

    def _batch_query_cpe(
        self, conn, package_names: list[str], package_data: dict[str, str]
    ) -> list[CredentialedCVE]:
        """Execute batch query for CPE records."""
        findings: list[CredentialedCVE] = []

        # Resolve each installed package to the CPE identity NVD publishes it
        # under, and query on that. Matching loose name fragments against
        # product OR vendor was wrong in both directions: "Google Chrome" hit
        # nothing (Chrome's CVEs never surfaced), while a vendor hit attached
        # every CVE that vendor had ever published to one unrelated package.
        identities_by_package = self._resolve_package_identities(conn, package_data)
        if not identities_by_package:
            log.info("No installed package resolved to a known CPE identity")
            return findings

        # Installed versions per identity — several packages can resolve to the
        # same product.
        versions_by_identity: dict[tuple[str, str], set[str]] = {}
        for pkg_name, idents in identities_by_package.items():
            installed = (package_data.get(pkg_name) or "").strip()
            for ident in idents:
                versions_by_identity.setdefault(ident, set())
                if installed:
                    versions_by_identity[ident].add(installed)

        pairs = sorted(versions_by_identity)
        name_params = {}
        clauses = []
        for index, (vendor_name, product_name) in enumerate(pairs):
            name_params[f"v_{index}"] = vendor_name
            name_params[f"p_{index}"] = product_name

            # A CPE row with no version bounds pins one exact release, so it can
            # only apply when the installed version *is* that release. Filtering
            # those out in SQL is what keeps the row count workable: of Chrome's
            # ~35,000 rows, ~30,000 are per-build pins that could never match
            # the one build installed here. Fetching them all and discarding
            # them in Python is what forced a row cap, and the cap then dropped
            # whole products.
            versions = sorted(versions_by_identity[(vendor_name, product_name)])
            pin_clauses = []
            for v_index, version in enumerate(versions):
                key = f"ver_{index}_{v_index}"
                name_params[key] = version
                pin_clauses.append(f"split_part(p.cpe_uri, ':', 6) = :{key}")
            pin_sql = f" OR {' OR '.join(pin_clauses)}" if pin_clauses else ""

            clauses.append(
                f"(LOWER(p.vendor) = :v_{index} AND LOWER(p.product) = :p_{index}"
                f" AND (p.version_start_including IS NOT NULL"
                f" OR p.version_start_excluding IS NOT NULL"
                f" OR p.version_end_including IS NOT NULL"
                f" OR p.version_end_excluding IS NOT NULL{pin_sql}))"
            )
        identity_clause = " OR ".join(clauses)

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
            WHERE {identity_clause}
        """
        )

        # Rows are allocated per identity rather than across the whole result.
        # A single global cap let the largest product crowd out every other one:
        # Chrome alone has ~35,000 CPE rows against a 5,000-row limit, and
        # ordering by exploitation likelihood put those first — so eight real
        # Siemens findings on a live host were silently truncated away by a
        # browser that happened to be installed alongside.
        query = text(
            f"""
            SELECT * FROM (
                SELECT ranked.*, ROW_NUMBER() OVER (
                    PARTITION BY ranked.vendor, ranked.product
                    ORDER BY ranked.in_kev DESC,
                             COALESCE(ranked.epss_score, 0) DESC,
                             COALESCE(ranked.cvss_score, 0) DESC
                ) AS identity_rank
                FROM ({query.text}) ranked
            ) capped
            WHERE capped.identity_rank <= {PER_IDENTITY_ROW_CAP}
        """
        )

        try:
            rows = conn.execute(query, name_params).mappings().all()
            at_cap = {
                (r.get("vendor"), r.get("product"))
                for r in rows
                if r.get("identity_rank") == PER_IDENTITY_ROW_CAP
            }
            if at_cap:
                log.warning(
                    "CPE row cap (%d) reached for %s — some published "
                    "configurations were not evaluated for these products",
                    PER_IDENTITY_ROW_CAP,
                    ", ".join(f"{v}:{p}" for v, p in sorted(at_cap)),
                )

            # Filter results in Python - match against installed versions
            for row in rows:
                product = str(row.get("product") or "").lower()
                vendor = str(row.get("vendor") or "").lower()

                # Attribute the row to the packages that resolved to exactly
                # this identity — not to anything whose name happens to share a
                # substring with it.
                for pkg_name, installed_ver in package_data.items():
                    if (vendor, product) in identities_by_package.get(pkg_name, ()):
                        # Version check
                        if installed_ver and not self._installed_version_matches(
                            installed_ver, row
                        ):
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
                                "exploit_sources": list(
                                    row.get("exploit_sources") or []
                                ),
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
                                package_name=pkg_name,
                                installed_ver=installed_ver,
                                fixed_ver=self._row_fixed_version(row),
                                source="cpe_match",
                                epss_score=float(record.get("epss_score", 0.0) or 0.0),
                                epss_percentile=float(
                                    record.get("epss_percentile", 0.0) or 0.0
                                ),
                                in_kev=bool(record.get("in_kev")),
                                kev_due_date=str(record.get("kev_due_date") or ""),
                                has_exploit=bool(record.get("has_exploit")),
                                exploit_sources=list(
                                    record.get("exploit_sources") or []
                                ),
                                priority_score=float(
                                    record.get("priority_score", 0.0) or 0.0
                                ),
                                priority_level=record.get("priority_level", "P4"),
                                matched_by="cpe",
                                cpe_uri=row.get("cpe_uri") or "",
                                affected_software=[self._row_cpe_config(row)],
                                cvss_version=str(record.get("cvss_version") or ""),
                                cvss_vector=str(record.get("cvss_vector") or ""),
                                installed_version_precision=(
                                    "coarse"
                                    if self._coarse_against(installed_ver, row)
                                    else ""
                                ),
                            )
                        )
                        break  # Only match first compatible package

        except SQLAlchemyError as exc:
            self._lookup_failed("Batch CPE query", exc)

        return findings

    def _osv_names_for(self, pkg_name: str) -> list[str]:
        """
        The OSV package names an installed package can be matched under.

        Distribution advisories name the *source* package. Where the collector
        read it, that is the only name used: guessing it from the binary name
        by stripping ``python3-``/``lib`` is right for libwine (source wine)
        and wrong for python3-git (GitPython, source python-git), which drew
        Git's advisories — 48 findings on one Ubuntu desktop, two of them
        Critical. The heuristics remain for packages with no recorded source.
        """
        source = getattr(self, "_package_sources", {}).get(pkg_name)
        if source:
            return [source]
        return normalize_package_names(pkg_name)

    def _osv_version_for(self, pkg_name: str, installed_ver: str) -> str:
        """
        The version an OSV range is compared against for this package.

        A distribution advisory's ranges are in its *source* package's version
        space, and a binary's version need not be: telnet 0.17+2.5-3ubuntu4.2
        is built from inetutils 2:2.5-3ubuntu4.2, so against the fix
        2:2.5-3ubuntu4.1 the binary's version — no epoch — compared older and
        the host was reported vulnerable to a flaw it is patched for. Measured
        on one Ubuntu 24.04 desktop (13 Oct 2026): 53 such findings, most of
        them aspnetcore-runtime-8.0 read against dotnet8's 8.0.131-8.0.31
        numbering. Where the collector read the source version, it is the one
        compared, and the one reported beside the fixed version.
        """
        if pkg_name in getattr(self, "_package_sources", {}):
            return (
                getattr(self, "_package_source_versions", {}).get(pkg_name)
                or installed_ver
            )
        return installed_ver

    def _batch_query_osv(
        self, conn, package_names: list[str], package_data: dict[str, str]
    ) -> list[CredentialedCVE]:
        """Execute batch query for OSV records."""
        findings: list[CredentialedCVE] = []

        normalized_names = set()
        for pkg_name in package_names:
            normalized_names.update(self._osv_names_for(pkg_name))

        name_params = {
            f"osv_{i}": name.lower() for i, name in enumerate(normalized_names)
        }
        name_placeholders = ", ".join([f":osv_{i}" for i in range(len(name_params))])

        if not name_params:
            return findings

        # No release, no OSV matching. An advisory names the version a
        # distribution fixed a flaw in *for one release*; applied to a different
        # release its fixed version is meaningless, which is how a 24.04 host
        # came to be assessed against 14.04 and Debian advisories.
        if not self._osv_ecosystems:
            return findings

        eco_params = {f"osv_eco_{i}": eco for i, eco in enumerate(self._osv_ecosystems)}
        eco_placeholders = ", ".join([f":osv_eco_{i}" for i in range(len(eco_params))])

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
            LEFT JOIN osv_ranges ranges
                   ON ranges.osv_id = aff.osv_id
                  -- Only this package's ranges, in this release. Joining on
                  -- osv_id alone paired an installed package with another
                  -- package's fixed version from the same advisory, and an
                  -- Ubuntu 24.04 package with 25.10's fix. Rows written before
                  -- osv_ranges gained these columns carry NULL and still match,
                  -- so a partially re-synced database degrades to the old
                  -- behaviour rather than losing the range entirely.
                  AND (ranges.package_name IS NULL
                       OR lower(ranges.package_name) = lower(aff.package_name))
                  AND (ranges.ecosystem IS NULL
                       OR ranges.ecosystem = aff.ecosystem)
            WHERE LOWER(aff.package_name) IN ({name_placeholders})
              AND aff.ecosystem LIKE ANY (ARRAY[{eco_placeholders}])
            -- The trailing keys make the order total. Without them a CVE that
            -- two source packages share (xorg-server and xwayland) went to
            -- whichever row PostgreSQL returned first, so two scans of an
            -- unchanged host could file it under different packages — and
            -- the package is part of a finding's identity.
            ORDER BY
                (kev.cve_id IS NOT NULL) DESC,
                COALESCE(epss.epss_score, 0) DESC,
                COALESCE(best_cvss.base_score, 0) DESC,
                oa.cve_id,
                LOWER(aff.package_name),
                aff.ecosystem,
                ranges.introduced NULLS FIRST,
                ranges.fixed NULLS FIRST
            LIMIT {OSV_ROW_CAP + 1}
        """
        )

        try:
            rows = conn.execute(query, {**name_params, **eco_params}).mappings().all()
            if len(rows) > OSV_ROW_CAP:
                rows = rows[:OSV_ROW_CAP]
                self._lookup_failures.append(
                    f"Batch OSV query: more than {OSV_ROW_CAP:,} advisory rows "
                    f"matched this inventory; the remainder were not assessed"
                )
                log.warning("OSV advisory rows reached the cap of %d", OSV_ROW_CAP)

            # The installed packages each advisory name can reach, in inventory
            # order. Scanning every package for every row was rows × packages:
            # once the row limit was lifted an Ubuntu desktop took 42 s here.
            packages_by_osv_name: dict[str, list[str]] = {}
            for pkg_name in package_data:
                for cand in dict.fromkeys(self._osv_names_for(pkg_name)):
                    if cand:
                        packages_by_osv_name.setdefault(cand, []).append(pkg_name)

            for row in rows:
                osv_pkg_name = str(row.get("package_name") or "").lower()

                for pkg_name in packages_by_osv_name.get(osv_pkg_name, ()):
                    binary_ver = package_data[pkg_name]
                    installed_ver = self._osv_version_for(pkg_name, binary_ver)
                    if installed_ver and not self._installed_version_matches_osv(
                        installed_ver, row
                    ):
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
                            package_name=pkg_name,
                            installed_ver=installed_ver,
                            fixed_ver=str(row.get("fixed") or ""),
                            source="osv_match",
                            epss_score=float(record.get("epss_score", 0.0) or 0.0),
                            epss_percentile=float(
                                record.get("epss_percentile", 0.0) or 0.0
                            ),
                            in_kev=bool(record.get("in_kev")),
                            kev_due_date=str(record.get("kev_due_date") or ""),
                            has_exploit=bool(record.get("has_exploit")),
                            exploit_sources=list(record.get("exploit_sources") or []),
                            priority_score=float(
                                record.get("priority_score", 0.0) or 0.0
                            ),
                            priority_level=record.get("priority_level", "P4"),
                            matched_by=f"osv:{row.get('ecosystem') or 'unknown'}",
                            cvss_version=str(record.get("cvss_version") or ""),
                            cvss_vector=str(record.get("cvss_vector") or ""),
                        )
                    )
                    break

        except SQLAlchemyError as exc:
            self._lookup_failed("Batch OSV query", exc)

        return findings

    def _match_packages_parallel(
        self, package_data: dict[str, str]
    ) -> list[CredentialedCVE]:
        """
        Parallel processing for smaller package sets.

        Uses ThreadPoolExecutor to query multiple packages concurrently.
        """
        findings: list[CredentialedCVE] = []
        best_by_cve: dict[str, CredentialedCVE] = {}

        try:
            with self.engine.connect() as conn:
                # Split into chunks for parallel processing
                items = list(package_data.items())

                with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as pool:
                    future_to_pkg = {
                        pool.submit(self._match_package, conn, name, ver): (name, ver)
                        for name, ver in items
                    }

                    for future in as_completed(future_to_pkg):
                        try:
                            for finding in future.result():
                                current = best_by_cve.get(finding.cve_id)
                                if (
                                    current is None
                                    or finding.priority_score > current.priority_score
                                ):
                                    best_by_cve[finding.cve_id] = finding
                        except Exception as exc:
                            pkg_name = future_to_pkg[future][0]
                            log.warning(f"Package '{pkg_name}' matching failed: {exc}")

        except SQLAlchemyError as exc:
            log.warning("Parallel vulnerability query failed: %s", exc)

        findings = list(best_by_cve.values())
        findings.sort(
            key=lambda item: (item.priority_score, item.cvss_score), reverse=True
        )
        return findings

    def _match_package(
        self, conn, package_name: str, installed_version: str
    ) -> list[CredentialedCVE]:
        matches: list[CredentialedCVE] = []
        candidates = normalize_package_names(package_name)
        if not candidates:
            return matches

        matches.extend(
            self._match_cpe_records(conn, package_name, installed_version, candidates)
        )
        matches.extend(
            self._match_osv_records(conn, package_name, installed_version, candidates)
        )
        return matches

    def _match_cpe_records(
        self,
        conn,
        package_name: str,
        installed_version: str,
        candidates: list[str],
    ) -> list[CredentialedCVE]:
        where_sql, params = build_sql_or_clauses(
            column_expressions=(
                "LOWER(p.product)",
                "LOWER(p.vendor)",
                "LOWER(p.cpe_uri)",
            ),
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
        findings: list[CredentialedCVE] = []
        for row in rows:
            if not self._package_matches_cpe_row(package_name, row):
                continue
            if installed_version and not self._installed_version_matches(
                installed_version, row
            ):
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
                    affected_software=[self._row_cpe_config(row)],
                    cvss_version=str(record.get("cvss_version") or ""),
                    cvss_vector=str(record.get("cvss_vector") or ""),
                    installed_version_precision=(
                        "coarse" if self._coarse_against(installed_version, row) else ""
                    ),
                )
            )
        return findings

    def _match_osv_records(
        self,
        conn,
        package_name: str,
        installed_version: str,
        candidates: list[str],
    ) -> list[CredentialedCVE]:
        where_sql, params = build_sql_or_clauses(
            column_expressions=("LOWER(aff.package_name)",),
            values=candidates,
            param_prefix="osv_pkg",
        )

        # Scope to the host's own release, exactly as the batch path does.
        #
        # This filter was missing here, and this path is the one taken by every
        # host with fewer than BATCH_QUERY_THRESHOLD packages — a container, an
        # appliance, a minimal VM. Those hosts were matched against every
        # distribution in the database at once, which is the precise failure
        # osv_ecosystems_for exists to prevent: a Debian package name matching
        # an Ubuntu advisory whose fixed version refers to a different build.
        # Returning nothing when the release is unknown matches the batch
        # path's behaviour, where no scope means no OSV matching rather than
        # unscoped matching.
        if not self._osv_ecosystems:
            return []
        eco_params = {f"osv_eco_{i}": eco for i, eco in enumerate(self._osv_ecosystems)}
        eco_placeholders = ", ".join(f":osv_eco_{i}" for i in range(len(eco_params)))
        params.update(eco_params)
        where_sql = (
            f"({where_sql}) AND aff.ecosystem LIKE ANY (ARRAY[{eco_placeholders}])"
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
            LEFT JOIN osv_ranges ranges
                   ON ranges.osv_id = aff.osv_id
                  -- Only this package's ranges, in this release. Joining on
                  -- osv_id alone paired an installed package with another
                  -- package's fixed version from the same advisory, and an
                  -- Ubuntu 24.04 package with 25.10's fix. Rows written before
                  -- osv_ranges gained these columns carry NULL and still match,
                  -- so a partially re-synced database degrades to the old
                  -- behaviour rather than losing the range entirely.
                  AND (ranges.package_name IS NULL
                       OR lower(ranges.package_name) = lower(aff.package_name))
                  AND (ranges.ecosystem IS NULL
                       OR ranges.ecosystem = aff.ecosystem)
            WHERE {where_sql}
            ORDER BY
                (kev.cve_id IS NOT NULL) DESC,
                COALESCE(epss.epss_score, 0) DESC,
                COALESCE(best_cvss.base_score, 0) DESC
            LIMIT 200
            """
        )
        rows = conn.execute(query, params).mappings().all()
        findings: list[CredentialedCVE] = []
        for row in rows:
            if installed_version and not self._installed_version_matches_osv(
                installed_version, row
            ):
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

    def _package_matches_cpe_row(self, package_name: str, row: dict[str, Any]) -> bool:
        candidates = normalize_package_names(package_name)
        haystacks = [
            str(row.get("product") or "").lower(),
            str(row.get("vendor") or "").lower(),
            str(row.get("cpe_uri") or "").lower(),
        ]
        return any(
            candidate and any(candidate in hay for hay in haystacks)
            for candidate in candidates
        )

    def _installed_version_matches(
        self, installed_version: str, row: dict[str, Any]
    ) -> bool:
        # A distribution's package version is not an upstream version, and the
        # CPE ranges published against a product describe upstream releases
        # only. Comparing the two produces confident nonsense.
        #
        # Ubuntu 24.04 ships Firefox as a snap and leaves a transition stub deb
        # versioned "1:1snap1-0ubuntu5". Reduced to a comparable number that is
        # "1", which sits below every fixed version ever published, so every
        # Firefox CVE back to 2008 matched — CVE-2008-0016 was reported as a
        # Confirmed Critical on a current release. The same reduction put
        # "9.6p1-3ubuntu13.18" below "9.8" and "2:8.2.4-1ubuntu2" below "8.2.5".
        #
        # For these packages the distribution's own advisory is the only
        # authority, and that is what the OSV path consults. Declining to answer
        # here loses nothing that was ever correct.
        if is_distro_package_version(installed_version):
            return False

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

    def _installed_version_matches_osv(
        self, installed_version: str, row: dict[str, Any]
    ) -> bool:
        """
        Whether the installed version falls inside an OSV advisory's range.

        Distribution ordering is used here, not the upstream-CPE ordering.
        An advisory's boundaries are the distribution's own package versions —
        ``0:2.34-274.el9_8``, ``2.9.13-6ubuntu1.3`` — and comparing them with a
        function that strips everything from ``el9`` or ``ubuntu`` onward makes
        a backported fix indistinguishable from the version it fixes.
        """
        introduced = str(row.get("introduced") or "").strip()
        fixed = str(row.get("fixed") or "").strip()

        # No range stored at all — not "introduced 0, no fix", which is how a
        # distribution says "affected, no fix released", but no boundary of any
        # kind. That asserts nothing about this version. It was read as
        # affected, and a withdrawn advisory whose ranges were gone
        # (UBUNTU-CVE-2024-3094) became a Critical, Confirmed xz backdoor on a
        # host running the safe rollback build.
        if not introduced and not fixed:
            self._osv_rows_without_range += 1
            return False

        if introduced and introduced not in {"0", "*"}:
            order = compare_distro_versions(installed_version, introduced)
            # An unreadable boundary asserts nothing, so it does not exclude.
            if order is not None and order < 0:
                return False
        if fixed and fixed not in {"*", "-"}:
            order = compare_distro_versions(installed_version, fixed)
            # Unreadable here must not claim the finding: without an ordering
            # there is no evidence the host is below the fixed release.
            if order is None or order >= 0:
                return False
        return True

    @staticmethod
    def _coarse_against(installed: str, row: dict[str, Any]) -> bool:
        """Whether any bound of this CPE row is finer than the installed version."""
        if not installed:
            return False
        return any(
            version_too_coarse(installed, str(row.get(key)))
            for key in (
                "version_start_including",
                "version_start_excluding",
                "version_end_including",
                "version_end_excluding",
            )
            if row.get(key)
        )

    def _row_fixed_version(self, row: dict[str, Any]) -> str:
        # Only an exclusive upper bound names a fixed release. An inclusive one
        # names the *last vulnerable* release: "Nmap through 7.99" was reported
        # as "fixed in 7.99" and the report advised upgrading to it. The bound
        # still travels in affected_software, where the normalizer words it as
        # "a release later than 7.99".
        value = row.get("version_end_excluding")
        return str(value) if value else ""

    def to_report_format(self, findings: list[CredentialedCVE]) -> list[dict[str, Any]]:
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
                "affected_software": f.affected_software,
                "affected_platforms": f.affected_platforms,
                "installed_version_precision": f.installed_version_precision,
            }
            for f in findings
        ]


def _extract_cpe_exact_version(cpe_uri: str) -> str:
    parts = cpe_uri.split(":")
    if len(parts) > 5:
        return parts[5].strip()
    return ""


#: A dotted numeric run — the version itself, wherever it sits in the string.
#: Real inventories wrap versions in prose: Windows DisplayVersion values like
#: "ad 9.0.14" (AnyDesk), "v2.1", "Release 4.3".
_VERSION_RUN = re.compile(r"\d+(?:\.\d+)*")


#: Markers that identify a version string as a *distribution* package version
#: rather than an upstream release: a Debian epoch, a Debian/Ubuntu/RPM revision
#: suffix, a backport or snap-transition marker.
#:
#: Such a version orders correctly only against other versions from the same
#: distribution, using that distribution's own advisories. It carries no usable
#: ordering against an upstream CPE range, because the distribution backports
#: fixes without changing the upstream component of the version.
_DISTRO_VERSION_MARKERS = re.compile(
    r"""
      ^\d+:                 # Debian epoch, e.g. "1:1snap1-0ubuntu5"
    | -\d*ubuntu            # Ubuntu revision,  e.g. "-0ubuntu5"
    | ubuntu\d              # Ubuntu revision without a dash
    | [-+]\d*build\d        # Ubuntu no-change rebuild, e.g. "1.80.2-1build2",
                            # "16+257build1.1"
    | \+~cs                 # Debian component-source rev, e.g. "6.1.13+~cs7.0.5-3"
    | [-+~]deb\d            # Debian revision,  e.g. "+deb12u1"
    | -\d+\+deb             # Debian revision
    | \.el\d                # RHEL / CentOS,    e.g. ".el8_9"
    | \.fc\d                # Fedora
    | \+dfsg                # Debian repackaged source
    | ~bpo                  # Debian backport
    | snap\d                # Ubuntu snap transition stub
    | \+esm                 # Ubuntu Expanded Security Maintenance
    """,
    re.IGNORECASE | re.VERBOSE,
)


def osv_ecosystems_for(os_id: str, os_version_id: str) -> list[str]:
    """
    The OSV ecosystems whose advisories apply to this host.

    OSV records are scoped to an exact distribution release: an advisory in
    ``Ubuntu:24.04:LTS`` states the version Canonical fixed the flaw in *for
    24.04*, which is the only version that can be compared against a package
    installed from that release.

    Matching without this filter is what produced the false positives. A host
    running Ubuntu 24.04 was matched against ``Ubuntu:14.04:LTS``,
    ``Debian:11``, ``Mageia:9`` and ``Chainguard`` advisories, whose fixed
    versions have no relationship to anything installed on it. The database
    holds 189,789 ``Ubuntu:24.04:LTS`` records — the correct ones — and none of
    them were being preferred.

    Returns an empty list when the release cannot be established, which the
    caller treats as "no OSV matching", because a match against the wrong
    release is worse than no match at all.

    The returned values are **SQL LIKE patterns**, not literals. Most
    distributions name an ecosystem exactly (``Rocky Linux:9``) and their
    pattern contains no wildcard, so it behaves as equality. Red Hat does not:
    it splits a release across repository modules —
    ``Red Hat:enterprise_linux:9::appstream``, ``::baseos``, ``::crb`` and more
    — and SUSE names products rather than versions
    (``SUSE:Linux Enterprise Server 15 SP5``). No fixed string can cover those,
    and the earlier ``Red Hat:9`` / ``SUSE:15.5`` forms matched nothing at all:
    RHEL-family and SUSE hosts were assessed against zero advisories while
    67,266 applicable ones sat in the database.
    """
    distro = str(os_id or "").strip().lower()
    release = str(os_version_id or "").strip()
    if not distro or not release:
        return []

    major = release.split(".")[0]
    minor = release.split(".")[1] if "." in release else ""

    if distro == "ubuntu":
        # Ubuntu Pro carries the same advisories for ESM-covered packages.
        return [
            f"Ubuntu:{release}:LTS",
            f"Ubuntu:Pro:{release}:LTS",
            f"Ubuntu:{release}",
        ]
    if distro == "debian":
        return [f"Debian:{major}"]
    if distro in ("rhel", "redhat", "centos", "centos-stream", "oracle", "ol"):
        # Every repository module of this release, and nothing from another.
        return [f"Red Hat:enterprise_linux:{major}::%"]
    if distro == "rocky":
        return [f"Rocky Linux:{major}"]
    if distro in ("almalinux", "alma"):
        return [f"AlmaLinux:{major}"]
    if distro == "alpine":
        parts = release.split(".")
        return [f"Alpine:v{'.'.join(parts[:2])}"]
    if distro in ("opensuse", "opensuse-leap", "opensuse-tumbleweed"):
        return [f"openSUSE:Leap {release}%"]
    if distro in ("sles", "sled", "suse"):
        # SLES 15.5 is published as "…Enterprise Server 15 SP5", so the
        # release's two halves have to be rebuilt into SUSE's own wording.
        return [f"SUSE:%{major} SP{minor}%"] if minor else [f"SUSE:%{major}%"]
    return []


def is_distro_package_version(version: str) -> bool:
    """
    Whether a version string came from a distribution's package manager.

    Used to stop distro versions being compared against upstream CPE ranges —
    see ``VulnMatcher._installed_version_matches`` for what that produced.
    """
    text = str(version or "").strip()
    if not text:
        return False
    return bool(_DISTRO_VERSION_MARKERS.search(text))


def version_too_coarse(installed: str, bound: str) -> bool:
    """
    Whether an installed version names too little to be compared with a bound.

    A registry entry that reads "V19" names a release line, not the update
    installed on it: against "fixed in 19.0.2" it could be 19.0.0 or 19.0.3,
    and reading it as 19.0.0 reported TIA Portal as Confirmed vulnerable to
    CVE-2023-46280 on 10.180.6.30 (12 Oct 2026) without knowing its update
    level. True when the installed version has fewer components than the bound,
    agrees with it on every one it has, and the bound's remaining components
    are not all zero ("V3.0" against 3.0.0 is decidable; against 3.0.6 it is
    not).
    """
    have = _parse_version(installed)
    edge = _parse_version(bound)
    if not have or not edge or len(have) >= len(edge):
        return False
    return edge[: len(have)] == have and any(edge[len(have) :])


def _parse_version(ver: str) -> tuple[int, ...]:
    """
    Reduce a package version string to a comparable tuple.

    Returns an **empty tuple** when no version can be read. That distinction
    matters: the previous implementation split on separators and silently
    discarded any component that would not parse, so AnyDesk's Windows
    DisplayVersion "ad 9.0.14" became ``(0, 14)`` — a perfectly comparable
    value that is wrong. Every "affected before 5.5.3" record then matched a
    9.x install, and a live audit reported three Critical false positives on a
    fully patched product. Producing nothing is recoverable; producing a wrong
    number that compares cleanly is not.
    """
    if not ver:
        return ()
    text = str(ver)
    if ":" in text:
        # Debian epoch — "1:2.3.4" is version 2.3.4.
        text = text.split(":", 1)[1]
    text = re.sub(r"(ubuntu|debian|el\d+|deb\d+|~).*$", "", text, flags=re.IGNORECASE)

    match = _VERSION_RUN.search(text)
    if not match:
        return ()
    parts = tuple(int(p) for p in match.group(0).split("."))

    # A trailing patch letter ("1.0.2k") orders after the plain release.
    tail = text[match.end() : match.end() + 1]
    if tail and tail.isalpha():
        parts = parts + (ord(tail.lower()) - ord("a") + 1,)
    return parts


# ── Distribution version comparison ──────────────────────────────────────────
#
# `_parse_version` above deliberately discards distribution suffixes, because
# its job is to compare a package against an *upstream* CPE range where
# "2.34-274.el9_8" and "2.34" are the same upstream release.
#
# On the OSV path that is exactly wrong, and it was silently costing findings.
# A distribution almost never fixes a CVE by taking a new upstream version; it
# backports the patch and increments the release. Rocky's fix for glibc is
# 2.34-274.el9_8 against an installed 2.34-266.el9_8 — same upstream version,
# eight releases apart. Stripping at "el9" reduced both to (2, 34), the
# comparison found them equal, and "installed < fixed" came out false, so no
# finding was asserted. Measured on a Rocky 9.8 container: glibc, openssl,
# expat, glib2 and systemd were all genuinely behind their published fixes and
# all five were reported as clean.
#
# The same regex strips "ubuntu" and "debian", so this was never a RHEL-only
# problem — it silently suppressed every Debian- and Ubuntu-family finding
# whose fix was a backport, which is most of them.
#
# What follows is rpm's `rpmvercmp` ordering, which dpkg agrees with on
# everything these feeds contain: compare epoch first, then walk both strings
# as alternating runs of digits and letters, with '~' sorting before anything.

_VERSION_SEGMENT = re.compile(r"(\d+|[a-zA-Z]+|~)")


def _split_evr(version: str) -> tuple[int, str]:
    """``"1:3.5.5-4.el9_8"`` → ``(1, "3.5.5-4.el9_8")``. Absent epoch is 0."""
    text = str(version or "").strip()
    if ":" in text:
        head, _, tail = text.partition(":")
        if head.isdigit():
            return int(head), tail
    return 0, text


def _compare_segments(a: str, b: str) -> int:
    """rpmvercmp ordering of two version strings (epoch already removed)."""
    seg_a = _VERSION_SEGMENT.findall(a)
    seg_b = _VERSION_SEGMENT.findall(b)

    for part_a, part_b in zip(seg_a, seg_b):
        if part_a == "~" or part_b == "~":
            # A tilde sorts before everything, so "1.0~rc1" precedes "1.0".
            if part_a == part_b:
                continue
            return -1 if part_a == "~" else 1

        a_num, b_num = part_a.isdigit(), part_b.isdigit()
        if a_num and b_num:
            left, right = int(part_a), int(part_b)
            if left != right:
                return -1 if left < right else 1
        elif a_num != b_num:
            # A numeric segment always outranks an alphabetic one, which is
            # what makes "1.0" newer than "1.0alpha".
            return 1 if a_num else -1
        elif part_a != part_b:
            return -1 if part_a < part_b else 1

    if len(seg_a) == len(seg_b):
        return 0
    # The longer version is newer unless its next segment is a tilde.
    longer, sign = (seg_a, 1) if len(seg_a) > len(seg_b) else (seg_b, -1)
    return -sign if longer[min(len(seg_a), len(seg_b))] == "~" else sign


def compare_distro_versions(ver_a: str, ver_b: str) -> int | None:
    """
    Order two distribution package versions: -1, 0, 1, or None if unreadable.

    None means the strings carried nothing comparable, and the callers treat
    that as "no ordering can be asserted" rather than guessing a direction.
    """
    if not str(ver_a or "").strip() or not str(ver_b or "").strip():
        return None
    epoch_a, rest_a = _split_evr(ver_a)
    epoch_b, rest_b = _split_evr(ver_b)
    if epoch_a != epoch_b:
        return -1 if epoch_a < epoch_b else 1
    if not _VERSION_SEGMENT.search(rest_a) or not _VERSION_SEGMENT.search(rest_b):
        return None
    return _compare_segments(rest_a, rest_b)


def _comparable(ver_a: str, ver_b: str) -> tuple[tuple, tuple] | None:
    """Both versions as equal-length tuples, or None when either is unreadable."""
    a, b = _parse_version(ver_a), _parse_version(ver_b)
    if not a or not b:
        return None
    length = max(len(a), len(b))
    return a + (0,) * (length - len(a)), b + (0,) * (length - len(b))


def _version_lt(ver_a: str, ver_b: str) -> bool:
    pair = _comparable(ver_a, ver_b)
    if pair is None:
        # Unreadable version: no ordering can be asserted, in either direction.
        # Returning False here means an unparseable version never satisfies a
        # "below the fixed release" test, so the finding is not claimed.
        return False
    return pair[0] < pair[1]


def _version_lte(ver_a: str, ver_b: str) -> bool:
    pair = _comparable(ver_a, ver_b)
    if pair is None:
        return False
    return pair[0] <= pair[1]


def _version_gt(ver_a: str, ver_b: str) -> bool:
    pair = _comparable(ver_a, ver_b)
    if pair is None:
        return False
    return pair[0] > pair[1]


def _version_gte(ver_a: str, ver_b: str) -> bool:
    pair = _comparable(ver_a, ver_b)
    if pair is None:
        return False
    return pair[0] >= pair[1]


def _version_eq(ver_a: str, ver_b: str) -> bool:
    pair = _comparable(ver_a, ver_b)
    if pair is None:
        return False
    return pair[0] == pair[1]
