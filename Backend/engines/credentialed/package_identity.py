"""
engines/credentialed/package_identity.py
─────────────────────────────────────────────────────────────────────────────
Resolve an installed package to the CPE identity NVD publishes it under.

A credentialed audit collects what the host calls its software — a Windows
``DisplayName`` like "Google Chrome" or "Visual Studio Community 2022", a
Linux package name like "openssl". NVD indexes vulnerabilities by CPE
``(vendor, product)``: ``google:chrome``, ``microsoft:visual_studio``. Nothing
matches until those two naming schemes are reconciled, and the reconciliation
is where both failure modes live:

  * Too strict and real vulnerabilities are missed. Matching "Google Chrome"
    against product names found nothing, so Chrome's CVEs never surfaced on a
    host running it.
  * Too loose and CVEs are attached to the wrong software. Matching on any
    single token resolved "Microsoft .NET Framework" to ``golang:net`` and
    "Microsoft ASP.NET Core" to ``centra:asp`` — unrelated products whose
    version ranges would then be compared against .NET's version numbers.

So a candidate is only accepted when it exists in the CPE dictionary, and the
publisher is used to corroborate the vendor. Where the publisher does not
corroborate (Windows registers WinSCP under "Martin Prikryl", not "winscp"), a
product-only match is accepted only when the whole package name resolves to it
and the name is distinctive — never from a fragment.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, Iterable, List, Sequence, Tuple

log = logging.getLogger("ccure.credentialed.identity")

Identity = Tuple[str, str]  # (vendor, product)

#: Company-form words. "Google LLC" and "Siemens AG" are the vendors google and
#: siemens; the legal suffix is noise for matching purposes.
_LEGAL_SUFFIXES = {
    "llc",
    "inc",
    "corporation",
    "corp",
    "gmbh",
    "ltd",
    "limited",
    "sro",
    "ag",
    "co",
    "kg",
    "company",
    "project",
    "foundation",
    "team",
    "group",
    "holdings",
    "sa",
    "bv",
    "oy",
    "ab",
    "plc",
    "technologies",
    "technology",
    "systems",
    "software",
    "solutions",
    "labs",
    "developers",
    "community",
}

#: Packaging and edition words that are not part of the product identity.
_EDITION_WORDS = {
    "community",
    "professional",
    "enterprise",
    "standard",
    "express",
    "ultimate",
    "home",
    "pro",
    "edition",
    "runtime",
    "setup",
    "installer",
    "update",
    "build",
    "tools",
    "viewer",
    "help",
    "client",
    "redistributable",
    "x64",
    "x86",
    "amd64",
    "win32",
    "win64",
    "bit",
    "64",
    "32",
}

#: Product names too generic to accept without the publisher corroborating the
#: vendor. Every one of these was observed resolving to the wrong vendor's
#: product against a real Windows inventory.
_AMBIGUOUS_PRODUCTS = {
    "net",
    "asp",
    "cloud",
    "java",
    "sdk",
    "core",
    "server",
    "client",
    "database",
    "studio",
    "portal",
    "framework",
    "runtime",
    "platform",
    "agent",
    "service",
    "manager",
    "tools",
    "driver",
    "api",
    "app",
    "base",
    "common",
    "system",
    "update",
    "security",
    "desktop",
    "office",
    "media",
}

#: Below this length a product name matched without vendor corroboration is
#: treated as too weak to rely on.
_MIN_UNCORROBORATED_LENGTH = 5

#: Words marking a package as a companion to a product rather than the product
#: itself — an installer, updater or helper. These carry their own version
#: ("MySQL Installer" is at 1.6.12 while MySQL Server is at 8.x), so mapping
#: them to the product's CPE compares two unrelated numbering schemes and
#: reports the product's CVEs against software that is not the product.
_COMPANION_MARKERS = {
    "installer",
    "setup",
    "updater",
    "uninstaller",
    "helper",
    "launcher",
    "bootstrapper",
    "prerequisites",
    "redistributable",
    "shortcut",
}


def is_companion_package(name: str) -> bool:
    """True when the package installs or maintains a product rather than being it."""
    tokens = {t for t in re.split(r"[^a-z0-9]+", (name or "").lower()) if t}
    return bool(tokens & _COMPANION_MARKERS)


_VERSION_TOKEN = re.compile(r"\bv?\d+(?:\.\d+)*\w*\b")
_PARENTHETICAL = re.compile(r"\(.*?\)")


def normalize_vendor(publisher: str) -> str:
    """ "Google LLC" → "google"; "Siemens AG" → "siemens"; "" → ""."""
    tokens = [t for t in re.split(r"[^a-z0-9]+", (publisher or "").lower()) if t]
    # Single letters are the debris of punctuated company forms — "JetBrains
    # s.r.o." splits to s, r, o — and no CPE vendor is one character long.
    tokens = [t for t in tokens if t not in _LEGAL_SUFFIXES and len(t) > 1]
    return "_".join(tokens)


def candidate_products(name: str, vendor: str = "") -> List[str]:
    """
    Plausible CPE product names for a package display name, strongest first.

    The vendor's own tokens are dropped from the product ("Google Chrome" under
    vendor google is the product "chrome"), version and architecture noise is
    removed, and edition words are stripped in a second variant so both
    ``visual_studio_community`` and ``visual_studio`` get a chance to match.
    """
    text = _PARENTHETICAL.sub(" ", (name or "").lower())
    text = _VERSION_TOKEN.sub(" ", text)
    tokens = [t for t in re.split(r"[^a-z0-9+]+", text) if t]
    if not tokens:
        return []

    vendor_tokens = set(vendor.split("_")) if vendor else set()
    core = [t for t in tokens if t not in vendor_tokens] or tokens

    ordered: List[str] = []

    def add(parts: Sequence[str]) -> None:
        if not parts:
            return
        candidate = "_".join(parts)
        if candidate and candidate not in ordered:
            ordered.append(candidate)

    add(core)
    add(tokens)
    add([t for t in core if t not in _EDITION_WORDS])
    add([t for t in tokens if t not in _EDITION_WORDS])
    return ordered


def _is_acceptable_uncorroborated(product: str, candidates: Sequence[str]) -> bool:
    """
    Whether a product match may be trusted without the publisher agreeing.

    It must be what the *whole* package name resolves to — never a fragment of
    it — and must not be a word generic enough to belong to many vendors.
    """
    if product in _AMBIGUOUS_PRODUCTS:
        return False
    if len(product) < _MIN_UNCORROBORATED_LENGTH:
        return False
    # candidates[0] is the full name with vendor tokens removed; candidates[1]
    # is the full name as written. Anything else is a narrowed variant.
    return product in set(candidates[:2])


def _leading_number(version: str) -> int | None:
    match = re.search(r"\d+", str(version or ""))
    return int(match.group(0)) if match else None


def version_space_contains(installed: str, published_versions: Sequence[str]) -> bool:
    """
    Whether an installed version plausibly belongs to a product's version space.

    Resolving a name to a CPE product is not enough: the two sides must also be
    counting the same thing. Observed against a real host — "MySQL Installer"
    version 1.6.12 resolved to ``oracle:mysql`` and matched server CVEs fixed in
    5.6, because 1.6.12 is genuinely lower; and "Visual Studio Build Tools"
    18.7.4 matched a CPE whose versions are years (2012). The numbers compare
    cleanly and the comparison is meaningless.

    The published versions for the product describe the space it is numbered
    in. An installed major outside that range says the two are numbered
    differently, and no ordering between them can be asserted.
    """
    installed_major = _leading_number(installed)
    if installed_major is None:
        return False

    majors = sorted(
        m for m in (_leading_number(v) for v in published_versions) if m is not None
    )
    if not majors:
        # Nothing published to compare against — the range check cannot rule
        # the mapping out, so it does not.
        return True

    # The full published range, not a trimmed percentile. This check exists to
    # catch a *different numbering scheme* — a release number against
    # year-based versions, a build number against marketing versions — not to
    # judge whether a version is plausibly current. Trimming the range to the
    # 5th–95th percentile also rejected software that is merely old, which is
    # exactly what an audit is supposed to find. Companion packages, the other
    # thing the trimmed range caught, are excluded by name before they reach
    # this point.
    return majors[0] <= installed_major <= majors[-1]


def resolve_identities(
    packages: Iterable[dict],
    known_identities: Dict[str, List[Identity]],
) -> Dict[str, List[Identity]]:
    """
    Map each package name to the CPE identities it resolves to.

    ``known_identities`` maps a candidate product name to the ``(vendor,
    product)`` pairs that exist in the CPE dictionary for it — supplied by the
    caller, which is the only component that talks to the database.

    A package resolves to nothing when no candidate exists in the dictionary,
    or when the only matches are uncorroborated and too weak to trust. That is
    a reported coverage gap, not a silent one: the caller logs it.
    """
    resolved: Dict[str, List[Identity]] = {}

    for pkg in packages:
        name = (pkg.get("name") or "").strip()
        if not name or name in resolved:
            continue
        if is_companion_package(name):
            # "MySQL Installer" is not MySQL. Its version is the installer's,
            # so any comparison against the product's ranges is meaningless —
            # and it read as a very old install, matching every server CVE.
            log.debug("Skipping companion package %r", name)
            continue
        vendor = normalize_vendor(pkg.get("vendor") or pkg.get("publisher") or "")
        candidates = candidate_products(name, vendor)

        corroborated: List[Identity] = []
        uncorroborated: List[Identity] = []
        for candidate in candidates:
            for identity in known_identities.get(candidate, ()):
                if vendor and identity[0] == vendor:
                    if identity not in corroborated:
                        corroborated.append(identity)
                elif _is_acceptable_uncorroborated(identity[1], candidates):
                    if identity not in uncorroborated:
                        uncorroborated.append(identity)

        # The publisher agreeing with the CPE vendor is the strongest signal
        # available, so when it is present nothing weaker is mixed in.
        identities = corroborated or uncorroborated
        if identities:
            resolved[name] = identities

    return resolved
