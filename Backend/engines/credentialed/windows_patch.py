"""
engines/credentialed/windows_patch.py
─────────────────────────────────────────────────────────────────────────────
Assess a Windows host's operating system against Microsoft's published fixes.

The gap this closes
───────────────────
Package matching resolves what the uninstall registry lists. Windows itself is
not in that registry, so on a real host the operating system — the largest and
most attacked piece of software present — was never assessed at all. The audit
reported 13 of 192 applications evaluated and said nothing about the OS.

Microsoft publishes, per CVE and per product, the build number that carries
the fix. A Windows host reports its own build. Comparing them answers the
question directly, without inferring anything from software names.

Why build numbers and not installed KBs
───────────────────────────────────────
The obvious approach — check whether the fixing KB appears in ``Get-HotFix`` —
does not work on modern Windows, and fails toward false positives. Cumulative
updates supersede one another, so a fully patched host has never installed the
individual KB that first fixed a given CVE. Measured on the target host,
``Get-HotFix`` returned **4 entries** for a machine carrying hundreds of fixes.
Reporting the other hundreds as missing would be wrong every time.

Build numbers advance monotonically through cumulative updates, so
``host_build >= fixed_build`` settles it in one comparison however the host
got there.

A patched verdict must be earned
────────────────────────────────
If the host's build line is not in the feed — a release too new to have
shipped a patch, an SKU Microsoft does not publish under, a build string that
could not be parsed — this module reports the OS as **not assessed**. It never
reports "no missing patches", because the two are indistinguishable to a
reader and only one of them is a statement about the host's security.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from core.vuln_intel import get_vuln_engine
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

log = logging.getLogger("ccure.credentialed.winpatch")

#: A full Windows build: major.minor.build.revision — 10.0.26200.8973.
_FULL_BUILD = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

#: Architecture words as they appear in Microsoft product names.
_ARCH_TOKENS = {
    "x64": "x64-based",
    "arm64": "ARM64-based",
    "x86": "32-bit",
}


def normalize_arch(raw: Any) -> str:
    """``Win32_OperatingSystem.OSArchitecture`` → ``x64`` / ``arm64`` / ``x86``."""
    text_value = str(raw or "").strip().lower()
    if "arm" in text_value:
        return "arm64"
    if "32" in text_value or "x86" in text_value:
        return "x86"
    return "x64"


def host_build(os_info: dict[str, Any]) -> str | None:
    """
    The host's full build string, or None when it cannot be established.

    ``Win32_OperatingSystem.Version`` stops at the build (``10.0.26200``) and
    omits the revision, which is the part that moves with every monthly update.
    The revision lives in the registry as ``UBR``, and without it every host
    looks like the day-zero release of its Windows version — which would report
    every patch since launch as missing.
    """
    version = str(os_info.get("version") or os_info.get("Version") or "").strip()
    ubr = str(os_info.get("ubr") or os_info.get("UBR") or "").strip()

    if _FULL_BUILD.match(version):
        return version
    if version and ubr.isdigit() and re.match(r"^\d+\.\d+\.\d+$", version):
        return f"{version}.{ubr}"

    log.info(
        "Windows build not determinable (version=%r ubr=%r) — OS will be "
        "reported as not assessed rather than as patched",
        version,
        ubr,
    )
    return None


def _build_tuple(build: str) -> tuple[int, ...]:
    return tuple(int(part) for part in build.split("."))


@dataclass
class WindowsPatchResult:
    """Findings plus an explicit statement of whether the OS was assessable."""

    assessed: bool
    findings: list[dict]
    product_ids: list[str]
    product_names: list[str]
    build: str | None
    reason: str = ""

    def coverage(self) -> dict:
        return {
            "os_assessed": self.assessed,
            "os_build": self.build,
            "os_products": self.product_names,
            "os_missing_patches": len(self.findings),
            "os_coverage_note": self.reason
            or (
                f"Operating system assessed against Microsoft published fixes "
                f"for {', '.join(self.product_names)}"
                if self.assessed
                else "Operating system not assessed"
            ),
        }


class WindowsPatchMatcher:
    """Compares a Windows host's build against Microsoft's published fixes."""

    def __init__(self) -> None:
        self.engine = get_vuln_engine()

    # ── Product resolution ───────────────────────────────────────────────────

    def resolve_products(
        self, conn, build: str, arch: str, caption: str = ""
    ) -> list[tuple[str, str]]:
        """
        The Microsoft products whose fixes apply to this host.

        The build-line mapping is read out of the feed rather than hardcoded:
        every fix for "Windows 11 Version 25H2 for x64-based Systems" carries a
        build beginning ``10.0.26200``, so the feed states which product a
        host's build belongs to, and a release published next year maps itself
        as soon as its first patch ships.

        Two filters narrow what that returns, because a build prefix alone is
        not an identity. Build ``10.0.26200`` resolves to four products —
        Windows 11 25H2 in two architectures, and Windows Server 2025 in two
        installation types. Matching a Windows 11 workstation against Windows
        Server would report server-role vulnerabilities on a machine that has
        no server roles, so the edition is taken from the OS caption and the
        architecture from ``OSArchitecture``.
        """
        prefix = ".".join(build.split(".")[:3])
        rows = (
            conn.execute(
                text(
                    """
                SELECT DISTINCT product_id, product_name
                FROM msrc_product_build
                WHERE build_prefix = :prefix
                """
                ),
                {"prefix": prefix},
            )
            .mappings()
            .all()
        )

        if not rows:
            return []

        wanted = _ARCH_TOKENS.get(arch, "x64-based")
        others = {token for key, token in _ARCH_TOKENS.items() if key != arch}
        host_is_server = "server" in (caption or "").lower()

        selected: list[tuple[str, str]] = []
        for row in rows:
            name = row["product_name"] or ""
            lowered = name.lower()

            # A client host and a server host share build lines but not
            # vulnerabilities; the products must not be crossed.
            if ("windows server" in lowered) != host_is_server:
                continue

            if wanted.lower() in lowered:
                selected.append((row["product_id"], name))
            elif not any(other.lower() in lowered for other in others):
                # Products that name no architecture — "Windows Server 2022" —
                # apply to whatever architecture the host runs.
                selected.append((row["product_id"], name))

        # Every product on this build line was filtered out. Reporting nothing
        # here would silently drop the OS; the caller renders that as
        # "not assessed" rather than as a clean result.
        return selected

    # ── Matching ─────────────────────────────────────────────────────────────

    def match(self, os_info: dict[str, Any]) -> WindowsPatchResult:
        build = host_build(os_info)
        arch = normalize_arch(
            os_info.get("architecture") or os_info.get("OSArchitecture")
        )
        caption = str(
            os_info.get("caption")
            or os_info.get("os_name")
            or os_info.get("Caption")
            or ""
        )

        if build is None:
            return WindowsPatchResult(
                assessed=False,
                findings=[],
                product_ids=[],
                product_names=[],
                build=None,
                reason=(
                    "Operating system not assessed — the host's build revision "
                    "could not be read, so no comparison against Microsoft's "
                    "published fixes was possible"
                ),
            )

        if self.engine is None:
            return WindowsPatchResult(
                assessed=False,
                findings=[],
                product_ids=[],
                product_names=[],
                build=build,
                reason="Operating system not assessed — vulnerability database unavailable",
            )

        try:
            with self.engine.connect() as conn:
                products = self.resolve_products(conn, build, arch, caption)
                if not products:
                    return WindowsPatchResult(
                        assessed=False,
                        findings=[],
                        product_ids=[],
                        product_names=[],
                        build=build,
                        reason=(
                            f"Operating system not assessed — build {build} does "
                            f"not correspond to any product in the Microsoft feed. "
                            f"This is expected for a release that has not yet had "
                            f"a security update published."
                        ),
                    )

                findings = self._missing_patches(conn, [p[0] for p in products], build)
        except SQLAlchemyError as exc:
            log.warning("Windows patch matching failed: %s", exc)
            return WindowsPatchResult(
                assessed=False,
                findings=[],
                product_ids=[],
                product_names=[],
                build=build,
                reason=f"Operating system not assessed — query failed: {exc}",
            )

        names = [p[1] for p in products]
        log.info(
            "Windows OS assessed: build %s -> %s; %d missing patch(es)",
            build,
            ", ".join(names),
            len(findings),
        )
        return WindowsPatchResult(
            assessed=True,
            findings=findings,
            product_ids=[p[0] for p in products],
            product_names=names,
            build=build,
        )

    def _missing_patches(self, conn, product_ids: list[str], build: str) -> list[dict]:
        """
        CVEs whose earliest fix for this product is newer than the host's build.

        The comparison is against the *earliest* fix, not any fix. A CVE can be
        remediated more than once for the same product — a later cumulative
        update re-ships an earlier fix — and a host past the first of those is
        patched. Comparing against every remediation instead would report such
        a CVE as missing on a host that carries it.

        Build strings are compared as integer arrays. Comparing them as text
        orders ``10.0.26200.999`` above ``10.0.26200.8973``, which would report
        a patched host as vulnerable and an unpatched one as clean.

        The comparison is confined to the host's own servicing line, and that
        confinement is load-bearing. Microsoft lists a single product against
        more than one line — "Windows 11 Version 25H2" carries fixes numbered
        both ``10.0.26100.x`` and ``10.0.26200.x``. Taking the earliest fix
        across both lines picks a ``26100`` build, which a host on ``26200``
        numerically exceeds, so every genuine ``26200`` vulnerability is
        silently dismissed as already patched. Measured on the target host,
        that suppressed all but 19 of 734 findings. A fix published for one
        line says nothing about a host on another.
        """
        prefix = ".".join(build.split(".")[:3])
        rows = (
            conn.execute(
                text(
                    """
                WITH host AS (
                    SELECT string_to_array(:build, '.')::int[] AS build
                ),
                earliest AS (
                    SELECT r.cve_id,
                           min(string_to_array(r.fixed_build, '.')::int[]) AS first_fix
                    FROM msrc_remediation r
                    WHERE r.product_id = ANY(:products)
                      AND r.fixed_build LIKE :prefix || '.%'
                    GROUP BY r.cve_id, r.product_id
                )
                SELECT e.cve_id,
                       array_to_string(e.first_fix, '.') AS fixed_build,
                       (
                           SELECT string_agg(DISTINCT r2.kb_id, ', ')
                           FROM msrc_remediation r2
                           WHERE r2.cve_id = e.cve_id
                             AND r2.product_id = ANY(:products)
                             AND string_to_array(r2.fixed_build, '.')::int[] = e.first_fix
                             AND r2.kb_id IS NOT NULL
                       ) AS kb_ids,
                       c.description,
                       best_cvss.base_score,
                       best_cvss.severity,
                       best_cvss.version AS cvss_version,
                       best_cvss.vector  AS cvss_vector,
                       kev.cve_id IS NOT NULL AS in_kev,
                       epss.epss_score,
                       epss.percentile
                FROM earliest e
                CROSS JOIN host h
                LEFT JOIN cve c ON c.cve_id = e.cve_id
                LEFT JOIN LATERAL (
                    SELECT version, base_score, severity, vector
                    FROM cvss
                    WHERE cvss.cve_id = e.cve_id
                    ORDER BY CASE version
                        WHEN '4.0' THEN 4 WHEN '3.1' THEN 3
                        WHEN '3.0' THEN 2 WHEN '2.0' THEN 1 ELSE 0 END DESC,
                        base_score DESC NULLS LAST
                    LIMIT 1
                ) best_cvss ON TRUE
                LEFT JOIN kev  ON kev.cve_id  = e.cve_id
                LEFT JOIN epss ON epss.cve_id = e.cve_id
                WHERE e.first_fix > h.build
                ORDER BY best_cvss.base_score DESC NULLS LAST, e.cve_id
                """
                ),
                {"build": build, "products": product_ids, "prefix": prefix},
            )
            .mappings()
            .all()
        )

        findings: list[dict] = []
        seen: set[str] = set()
        for row in rows:
            # `earliest` groups per product as well as per CVE, so a CVE
            # affecting several matched products arrives once per product.
            if row["cve_id"] in seen:
                continue
            seen.add(row["cve_id"])
            kbs = row["kb_ids"] or ""
            findings.append(
                {
                    "cve_id": row["cve_id"],
                    "severity": _severity(row["severity"], row["base_score"]),
                    "cvss_score": float(row["base_score"] or 0.0),
                    "cvss_version": row["cvss_version"] or "",
                    "cvss_vector": row["cvss_vector"] or "",
                    "description": row["description"] or "",
                    "package_name": "Microsoft Windows (operating system)",
                    "installed_ver": build,
                    "fixed_ver": row["fixed_build"],
                    "source": "msrc",
                    "matched_by": "msrc:build",
                    "in_kev": bool(row["in_kev"]),
                    "epss_score": float(row["epss_score"] or 0.0),
                    "epss_percentile": float(row["percentile"] or 0.0),
                    "kb_ids": [kb.strip() for kb in kbs.split(",") if kb.strip()],
                    "remediation": (
                        f"Install {'KB' + ', KB'.join(kb.strip() for kb in kbs.split(',') if kb.strip())} "
                        f"or any later cumulative update (build {row['fixed_build']} or newer)"
                        if kbs
                        else f"Update to build {row['fixed_build']} or newer"
                    ),
                }
            )
        return findings


#: Words that carry no distinguishing power when deciding whether an installed
#: package and a Microsoft product name describe the same software.
_NAME_NOISE = {
    "microsoft",
    "for",
    "and",
    "on",
    "the",
    "edition",
    "based",
    "systems",
    "system",
    "x64",
    "x86",
    "arm64",
    "bit",
    "32",
    "64",
    "version",
    "server",
    "service",
    "pack",
    "sp1",
    "sp2",
    "sp3",
    "gdr",
    "cu",
    "chromium",
}


def _name_tokens(value: str) -> set[str]:
    return {
        token
        for token in re.split(r"[^a-z0-9]+", (value or "").lower())
        if token and token not in _NAME_NOISE and not token.isdigit()
    }


class MicrosoftApplicationMatcher:
    """
    Assess installed Microsoft applications against the same MSRC feed.

    Windows is not the only thing the CPE path cannot reach. Microsoft numbers
    its applications in build space while NVD publishes them in marketing
    versions, so ``version_space_contains`` correctly refuses to compare them
    and the software goes unassessed. Observed on the target host:

        Microsoft Edge 151.0.4129.72 resolves to ('microsoft', 'edge')
        but is numbered in a different version space; no finding asserted

    That identity was right and the refusal was right — the comparison really
    would have been meaningless. But MSRC publishes Edge in exactly the build
    space the host reports, and knows 385 CVEs fixed in ``151.0.4129.59``.
    The data to assess it was there; only the route to it was missing.

    Resolution runs on the build line, the same way the OS does, and is then
    confirmed by name. Either signal alone is unsafe: a build prefix can
    collide across unrelated products, and a name can match a product family
    numbered differently from the installed copy. Requiring both means a
    version comparison only happens between two things that agree on what
    software they are *and* on how it is numbered.
    """

    def __init__(self) -> None:
        self.engine = get_vuln_engine()

    def match(self, packages: list[dict[str, Any]]) -> tuple[list[dict], dict]:
        """Return ``(findings, coverage)`` for the Microsoft software installed."""
        candidates: list[tuple[str, str, str]] = []
        for pkg in packages or []:
            name = str(pkg.get("name") or "").strip()
            version = str(pkg.get("version") or "").strip()
            if not name or not version:
                continue
            parts = version.split(".")
            if len(parts) < 3 or not all(p.isdigit() for p in parts[:3]):
                continue
            candidates.append((name, version, ".".join(parts[:3])))

        if not candidates or self.engine is None:
            return [], {"apps_considered": len(candidates), "apps_assessed": 0}

        findings: list[dict] = []
        assessed: set[str] = set()
        products_matched: set[str] = set()
        reported: set[tuple] = set()

        try:
            with self.engine.connect() as conn:
                for name, version, prefix in candidates:
                    rows = (
                        conn.execute(
                            text(
                                """
                            SELECT DISTINCT product_id, product_name
                            FROM msrc_product_build
                            WHERE build_prefix = :prefix
                            """
                            ),
                            {"prefix": prefix},
                        )
                        .mappings()
                        .all()
                    )
                    if not rows:
                        continue

                    pkg_tokens = _name_tokens(name)
                    matched = []
                    for row in rows:
                        product_tokens = _name_tokens(row["product_name"] or "")
                        # Containment, not overlap: every distinguishing word
                        # in the product name must appear in the package name.
                        # "Windows SDK" {sdk} is contained in "Windows SDK
                        # Desktop Headers x64" {sdk, desktop, headers}, while
                        # "Windows 11 Version 24H2" {24h2} is not — which is
                        # what keeps SDK components off the operating system's
                        # CVEs despite sharing its build line. Overlap alone
                        # would have accepted any single word in common.
                        if product_tokens and product_tokens <= pkg_tokens:
                            matched.append((row["product_id"], row["product_name"]))
                    if not matched:
                        # The build line exists but belongs to different
                        # software. A coincidental numeric match is not an
                        # identity, and treating it as one would attach another
                        # product's CVEs to this package.
                        continue

                    product_ids = [m[0] for m in matched]
                    missing = self._missing_for_product(
                        conn, product_ids, version, prefix
                    )
                    assessed.add(name)
                    products_matched.update(m[1] for m in matched)
                    for row in missing:
                        # One MSRC product routinely ships as many installed
                        # packages — the Windows SDK alone accounts for thirty
                        # sub-components on the target host. Reporting its CVEs
                        # once per component would multiply a single missing
                        # update into thirty findings that all resolve together.
                        key = (row["cve_id"], tuple(sorted(product_ids)))
                        if key in reported:
                            continue
                        reported.add(key)
                        row["package_name"] = name
                        row["installed_ver"] = version
                        findings.append(row)
        except SQLAlchemyError as exc:
            log.warning("Microsoft application matching failed: %s", exc)
            return [], {"apps_considered": len(candidates), "apps_assessed": 0}

        log.info(
            "Microsoft application assessment: %d of %d versioned packages "
            "matched %d MSRC product(s); %d missing update(s)",
            len(assessed),
            len(candidates),
            len(products_matched),
            len(findings),
        )
        # Both counts are reported because they answer different questions and
        # the first alone overstates the second. Thirty Windows SDK components
        # are thirty assessed packages but one assessed product, and a coverage
        # figure built from package count would read as far broader than the
        # software actually evaluated.
        return findings, {
            "apps_considered": len(candidates),
            "apps_assessed": len(assessed),
            "products_assessed": len(products_matched),
            "products_assessed_names": sorted(products_matched),
        }

    def _missing_for_product(
        self, conn, product_ids: list[str], version: str, prefix: str
    ) -> list[dict]:
        rows = (
            conn.execute(
                text(
                    """
                WITH installed AS (
                    SELECT string_to_array(:version, '.')::int[] AS v
                ),
                earliest AS (
                    SELECT r.cve_id,
                           min(string_to_array(r.fixed_build, '.')::int[]) AS first_fix
                    FROM msrc_remediation r
                    WHERE r.product_id = ANY(:products)
                      AND r.fixed_build LIKE :prefix || '.%'
                    GROUP BY r.cve_id, r.product_id
                )
                SELECT DISTINCT e.cve_id,
                       array_to_string(e.first_fix, '.') AS fixed_build,
                       c.description,
                       best_cvss.base_score,
                       best_cvss.severity,
                       best_cvss.version AS cvss_version,
                       best_cvss.vector  AS cvss_vector,
                       kev.cve_id IS NOT NULL AS in_kev
                FROM earliest e
                CROSS JOIN installed i
                LEFT JOIN cve c ON c.cve_id = e.cve_id
                LEFT JOIN LATERAL (
                    SELECT version, base_score, severity, vector
                    FROM cvss WHERE cvss.cve_id = e.cve_id
                    ORDER BY CASE version
                        WHEN '4.0' THEN 4 WHEN '3.1' THEN 3
                        WHEN '3.0' THEN 2 WHEN '2.0' THEN 1 ELSE 0 END DESC,
                        base_score DESC NULLS LAST
                    LIMIT 1
                ) best_cvss ON TRUE
                LEFT JOIN kev ON kev.cve_id = e.cve_id
                WHERE e.first_fix > i.v
                ORDER BY best_cvss.base_score DESC NULLS LAST, e.cve_id
                """
                ),
                {"version": version, "products": product_ids, "prefix": prefix},
            )
            .mappings()
            .all()
        )

        seen: set[str] = set()
        out: list[dict] = []
        for row in rows:
            if row["cve_id"] in seen:
                continue
            seen.add(row["cve_id"])
            out.append(
                {
                    "cve_id": row["cve_id"],
                    "severity": _severity(row["severity"], row["base_score"]),
                    "cvss_score": float(row["base_score"] or 0.0),
                    "cvss_version": row["cvss_version"] or "",
                    "cvss_vector": row["cvss_vector"] or "",
                    "description": row["description"] or "",
                    "fixed_ver": row["fixed_build"],
                    "source": "msrc",
                    "matched_by": "msrc:app_build",
                    "in_kev": bool(row["in_kev"]),
                    "epss_score": 0.0,
                    "epss_percentile": 0.0,
                    "kb_ids": [],
                    "remediation": f"Update to {row['fixed_build']} or newer",
                }
            )
        return out


def _severity(raw: Any, score: Any) -> str:
    text_value = str(raw or "").strip().title()
    if text_value in {"Critical", "High", "Medium", "Low"}:
        return text_value
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
