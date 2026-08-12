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


#: Tokens marking a package as a piece of a product's developer tooling rather
#: than software that can be independently vulnerable.
_COMPONENT_MARKERS = {
    "sdk",
    "headers",
    "libs",
    "symbols",
    "intellisense",
    "winrt",
    "targeting",
    "documentation",
    "samples",
    "metadata",
    "contracts",
    "resources",
    "fonts",
    "certification",
}

#: Visual Studio ships its internals as individually registered MSIs named
#: vs_something. They are not products and NVD publishes no CPE for them.
_COMPONENT_PREFIXES = (
    "vs_",
    "icecap_",
    "sqlsysclrtypes",
    "dotnet_",
    "vcpp_",
    "winappdeploy",
    "intellitraceprofiler",
)

#: An installed Windows update, not software. ``Get-HotFix`` output is folded
#: into the package list as pseudo-packages so the inventory records it, but a
#: KB is a patch: it has no CPE, its "version" is the date it was installed,
#: and it can never resolve to anything. Four of them sat in the assessable
#: denominator of a real host, permanently unresolvable, making coverage look
#: worse than it was. The MSRC matcher assesses the patch level properly.
_KB_PACKAGE = re.compile(r"^kb\d{6,}$", re.IGNORECASE)

#: The Visual C++ runtime, which Windows registers as several MSIs per
#: architecture and edition — "Minimum Runtime", "Additional Runtime", "Debug
#: Runtime". NVD publishes no per-redistributable CPE, and they are patched as
#: part of the redistributable package rather than individually. Ten of these
#: were sitting in the denominator on one host.
_VCPP_RUNTIME = re.compile(
    r"visual\s+c\+\+.*\b(runtime|redistributable)\b", re.IGNORECASE
)

#: Pieces of a .NET installation that ship and version with the runtime:
#: the host, the FX resolver, targeting packs. They are not separately
#: patchable, and their DisplayVersion is the MSI's own number
#: ("72.72.55158" for .NET 9.0.18), so mapping them to microsoft:.net would
#: compare two unrelated numbering schemes. The runtime itself is resolved by
#: the curated rules below and is what actually gets patched.
_DOTNET_SUBCOMPONENT = re.compile(
    r"^microsoft\s+\.net\s+(host|targeting\s+pack)|"
    r"^microsoft\s+\.net\s+host\s+fx\s+resolver|"
    r"cumulative\s+intellisense\s+pack",
    re.IGNORECASE,
)


def is_component_package(name: str) -> bool:
    """
    True when the package is a fragment of a toolchain, not assessable software.

    This exists to keep the coverage figure honest in the direction people
    rarely check. A real Windows host reported 150 packages that resolved to no
    CPE identity, which reads as a 150-package blind spot — but the overwhelming
    majority were "Windows SDK Desktop Headers x64", "vs_filehandler_amd64",
    "WinRT Intellisense IoT - en-us" and their siblings. NVD publishes no CPE
    for any of them because none is independently vulnerable: they are header
    files, resource MSIs and IntelliSense metadata that move with the toolchain
    that owns them.

    Counting them as unassessed overstates the gap exactly as badly as counting
    them as assessed would overstate the coverage. Both mislead; the coverage
    number is only worth reporting if its denominator is software an audit
    could genuinely have findings about.
    """
    lowered = (name or "").strip().lower()
    if not lowered:
        return False
    if lowered.startswith(_COMPONENT_PREFIXES):
        return True
    if _KB_PACKAGE.match(lowered):
        return True
    if _VCPP_RUNTIME.search(lowered):
        return True
    if _DOTNET_SUBCOMPONENT.search(lowered):
        return True
    if any(pattern.search(name or "") for pattern in _SUBCOMPONENT_PATTERNS):
        return True
    tokens = {t for t in re.split(r"[^a-z0-9]+", lowered) if t}
    return bool(tokens & _COMPONENT_MARKERS)


#: Products whose CPE name cannot be produced from their display name by
#: tokenising, because NVD publishes them with punctuation the tokeniser has
#: no way to reintroduce.
#:
#: ".NET" is the case that matters most. NVD's products are ``.net``,
#: ``.net_framework`` and ``asp.net_core`` — with a literal leading dot.
#: Splitting "Microsoft .NET Framework 4.7.2" on non-alphanumerics yields
#: ``net_framework``, which misses ``.net_framework`` by one character, so the
#: entire .NET family (338 CVEs across four products) resolved to nothing on
#: every Windows host. No amount of token juggling recovers a character that
#: tokenising removed; the mapping has to be stated.
#:
#: Each entry is matched against the whole display name, case-insensitively.
#: Ordering matters — the first match wins, so more specific patterns lead.
_CURATED_RULES: List[Tuple[re.Pattern, Identity]] = [
    (re.compile(r"^microsoft\s+asp\.net\s+core", re.I), ("microsoft", "asp.net_core")),
    (
        re.compile(r"^microsoft\s+\.net\s+framework", re.I),
        ("microsoft", ".net_framework"),
    ),
    (re.compile(r"^microsoft\s+\.net\s+core", re.I), ("microsoft", ".net_core")),
    # "Windows Desktop Runtime" and ".NET Runtime" are both the .NET runtime,
    # which NVD publishes simply as "microsoft:.net".
    (
        re.compile(r"^microsoft\s+(windows\s+desktop|\.net)\s+runtime", re.I),
        ("microsoft", ".net"),
    ),
    # NVD files VirtualBox under vm_virtualbox, not virtualbox.
    (
        re.compile(r"^oracle\s+vm\s+virtualbox|^virtualbox\b", re.I),
        ("oracle", "vm_virtualbox"),
    ),
    (
        re.compile(r"wincc\s+runtime\s+advanced", re.I),
        ("siemens", "wincc_runtime_advanced"),
    ),
    (
        re.compile(r"wincc\s+runtime\s+professional", re.I),
        ("siemens", "simatic_wincc_runtime_professional"),
    ),
    # Siemens OT software, which a general-purpose scanner rarely covers and
    # which is the reason this tool is pointed at these hosts at all.
    #
    # Only products NVD actually publishes under are listed. It is tempting to
    # map the SIMATIC HMI packages installed alongside TIA — "SIMATIC HMI
    # Symbol Library", "SIMATIC HMI Touch Input" — onto the simatic_hmi_*
    # CPEs, and it would raise the coverage number. It would also be wrong:
    # those CPEs are *panel firmware* (KTP700, Comfort Panels), not the
    # desktop libraries the engineering station installs. Matching a
    # workstation library against panel firmware advisories would report
    # hardware vulnerabilities on a machine that is not that hardware.
    (
        re.compile(r"totally\s+integrated\s+automation\s+portal", re.I),
        ("siemens", "totally_integrated_automation_portal"),
    ),
    (
        re.compile(r"\bSTEP\s*7\b|\bSIMATIC\s+STEP\s*7", re.I),
        ("siemens", "simatic_step_7"),
    ),
    (
        re.compile(r"^HP\s+PC\s+Hardware\s+Diagnostics", re.I),
        ("hp", "pc_hardware_diagnostics"),
    ),
]

#: Sub-components that ship inside a product this file already resolves, and
#: that NVD publishes no CPE of their own for.
#:
#: TIA Portal installs "SIMATIC HMI Symbol Library", "SIMATIC Device Drivers
#: WoW", "SIMATIC Event Database" and similar as separately registered MSIs.
#: None has a CPE, none is patched on its own — they move when TIA Portal is
#: updated, and TIA Portal *is* assessed by the curated rules above. Counting
#: them as unassessed software charged the coverage figure for six entries
#: that could never resolve no matter how much mapping work was done.
#:
#: The same applies to the Visual Studio and Windows SDK tooling: development
#: headers, interop assemblies and diagnostic packs are artefacts of an
#: install, not products an advisory is ever published against.
#:
#: This is a denominator correction, not a detection change — nothing that
#: could have produced a finding stops producing one. Software that genuinely
#: has no CPE but *is* standalone (UltraViewer, the OPC UA Local Discovery
#: Server) is deliberately left counted as unassessed, because it really is.
_SUBCOMPONENT_PATTERNS = (
    re.compile(
        r"^SIMATIC\s+(HMI\s+(Symbol\s+Library|Touch\s+Input)|"
        r"Device\s+Drivers|Event\s+Database)",
        re.I,
    ),
    re.compile(r"^SIMATIC\s+S7-PCT", re.I),
    re.compile(r"^TIA\s+Portal\s+(Project\s+Server|Help\s+Viewer)", re.I),
    re.compile(r"^Entity\s+Framework\b.*\bfor\s+Visual\s+Studio", re.I),
    re.compile(r"^MSI\s+Development\s+Tools", re.I),
    re.compile(r"Diagnostic\s+Pack\s+for\s+Visual\s+Studio", re.I),
    re.compile(r"^Microsoft\s+Primary\s+Interoperability\s+Assemblies", re.I),
    re.compile(r"^Universal\s+CRT\b", re.I),
    re.compile(r"^Windows\s+Software\s+Development\s+Kit", re.I),
)


def curated_identity(name: str) -> Identity | None:
    """The stated CPE identity for a display name, when one is known."""
    text = (name or "").strip()
    if not text:
        return None
    for pattern, identity in _CURATED_RULES:
        if pattern.search(text):
            return identity
    return None


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
        if is_component_package(name):
            # A toolchain fragment is not independently vulnerable, which is
            # why the coverage figure already excludes it from the denominator.
            # It has to be excluded from resolution for the same reason, or the
            # two disagree: "Microsoft .NET Framework 4.7.2 Targeting Pack" was
            # counted as non-assessable and still resolved to
            # microsoft:.net_framework through the curated rule below, so the
            # runtime's CVEs were reported against build-time reference
            # assemblies. Its DisplayVersion is the MSI's own number, so the
            # comparison behind those findings was between two unrelated
            # numbering schemes.
            log.debug("Skipping component package %r", name)
            continue

        # A stated identity outranks anything the heuristics can derive, since
        # it exists precisely for the names they cannot reach.
        stated = curated_identity(name)
        if stated is not None:
            resolved[name] = [stated]
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
