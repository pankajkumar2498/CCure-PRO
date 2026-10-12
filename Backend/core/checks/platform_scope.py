"""
core/checks/platform_scope.py
─────────────────────────────────────────────────────────────────────────────
Which platforms a vulnerability record applies to, and which one a host runs.

A CVE published against a cross-platform product is very often about one
platform's build of it. The record says so in one of three places, and a
matcher that reads only the product and the version range reads none of them:

  * **The CNA's own description.** Google writes "Use after free in X in
    Google Chrome on Android prior to 144.0.7559.59"; Mozilla writes "This bug
    only affects Firefox on Windows". The vendor is the authority on which of
    its builds carries the flaw.
  * **NVD's configuration.** "chrome AND running on iphone_os" is an AND node
    whose second half is a non-vulnerable platform CPE. Flattening the
    configuration to its vulnerable CPEs — which is what the ``cpe`` table
    holds — throws the platform away.
  * **The CPE's ``target_sw`` field**, e.g. ``chrome:*:…:android:*:*``.

Measured on scan #9 (10.180.6.30, Windows 11, 12 Oct 2026): 413 of the 1,736
Google Chrome findings were published for Android, Mac, iOS, Linux or
ChromeOS, CVE-2025-14174 — a Mac-only ANGLE flaw — among them, listed in the
report's "known exploited, immediate action" table for a Windows host.

The description is consulted first, and deliberately ahead of the
configuration. NVD applies a generic desktop template to Chromium records:
CVE-2026-0906 reads "Google Chrome on Android" while its configuration says
"running on linux_kernel or windows". Where the two disagree, the vendor's
statement about its own product wins.

**Absence of evidence is never evidence of absence.** Every function here
answers "no restriction" (an empty tuple, or an empty family) when it meets a
platform it does not recognise, a configuration it cannot read, or a host OS
it cannot place — so nothing is ruled out on a guess. A finding is suppressed
only when the record names its platforms *and* the host positively runs a
different one.

Pure functions only: no database, no I/O, so the credentialed matcher and the
finding normalizer can both use them.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, Iterable, Iterator, Optional, Sequence, Tuple

#: Display names, for the suppression reason a reader sees in the report.
PLATFORM_LABELS: Dict[str, str] = {
    "windows": "Windows",
    "linux": "Linux",
    "macos": "macOS",
    "ios": "iOS",
    "android": "Android",
    "chromeos": "ChromeOS",
    "fuchsia": "Fuchsia",
    "freebsd": "FreeBSD",
    "solaris": "Solaris",
}

#: Tokens that identify a family in a host's OS string. Families that run on a
#: Linux kernel are listed first: an Android or ChromeOS fingerprint often
#: names the kernel too, and it is the more specific family that is meant.
#: There is deliberately no bare "ios" token — it would place every Cisco IOS
#: device in Apple's family.
_HOST_OS_TOKENS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("android", ("android",)),
    ("chromeos", ("chromeos", "chrome os", "chromium os")),
    ("ios", ("iphone os", "iphone_os", "ipados")),
    ("windows", ("windows",)),
    ("macos", ("mac os", "macos", "os x", "darwin")),
    ("freebsd", ("freebsd",)),
    ("solaris", ("solaris", "sunos")),
    (
        "linux",
        (
            "linux",
            "ubuntu",
            "debian",
            "red hat",
            "redhat",
            "centos",
            "rocky",
            "almalinux",
            "fedora",
            "suse",
            "alpine",
        ),
    ),
)

#: How a CNA names a platform in prose. "Desktop" is Chromium's word for every
#: build that is not mobile, so it restricts to all of them.
_PROSE_PLATFORMS: Dict[str, Tuple[str, ...]] = {
    "android": ("android",),
    "ios": ("ios",),
    "ipados": ("ios",),
    "mac": ("macos",),
    "macos": ("macos",),
    "mac os": ("macos",),
    "mac os x": ("macos",),
    "os x": ("macos",),
    "osx": ("macos",),
    "windows": ("windows",),
    "linux": ("linux",),
    "chromeos": ("chromeos",),
    "chrome os": ("chromeos",),
    "lacros": ("chromeos",),
    "fuchsia": ("fuchsia",),
    "desktop": ("windows", "macos", "linux", "chromeos"),
}

_LIST = r"([A-Za-z][A-Za-z ,/]{0,80}?)"
#: "in Google Chrome on Android prior to 144.0.7559.59", "on Linux, ChromeOS
#: prior to …", "on Mac,Windows prior to …". Chromium's CNA writes every
#: platform-specific record this way.
_PRIOR_TO = re.compile(r"\bon\s+" + _LIST + r"\s+prior\s+to\b", re.IGNORECASE)
#: "This bug only affects Firefox on Windows. Other operating systems are
#: unaffected." / "This vulnerability only affects Firefox for Android."
_ONLY_AFFECTS = re.compile(
    r"\bonly\s+affect(?:s|ed)\b[^.]{0,80}?\b(?:on|for)\s+" + _LIST + r"\s*(?:\.|;|$)",
    re.IGNORECASE,
)
_SEPARATORS = re.compile(r"\s*(?:,|/|\band\b|\bor\b)\s*", re.IGNORECASE)


def host_platform(host_os: str) -> str:
    """
    The platform family a host's OS string names, or "" when it cannot be told.

    Ambiguity answers "": a string naming two unrelated families ("Windows
    Subsystem for Linux") places the host in neither, because guessing would
    let a record be ruled out against the wrong one.
    """
    text = str(host_os or "").lower()
    if not text.strip():
        return ""
    found = [
        family
        for family, tokens in _HOST_OS_TOKENS
        if any(token in text for token in tokens)
    ]
    # Android and ChromeOS fingerprints routinely name the kernel as well.
    if "linux" in found and ("android" in found or "chromeos" in found):
        found.remove("linux")
    return found[0] if len(found) == 1 else ""


def _families_in_list(phrase: str) -> Tuple[str, ...]:
    """Families a CNA's platform list names; () if any item is not a platform."""
    families: list[str] = []
    for item in _SEPARATORS.split(phrase.strip()):
        item = re.sub(r"\s+", " ", item.strip().lower())
        if not item:
            continue
        mapped = _PROSE_PLATFORMS.get(item)
        if mapped is None:
            # "on a crafted page prior to" is not a platform statement. One
            # unrecognised word voids the whole list rather than shortening it.
            return ()
        for family in mapped:
            if family not in families:
                families.append(family)
    return tuple(families)


def platforms_named_in(description: Any) -> Tuple[str, ...]:
    """
    The platforms a record's own description restricts it to, or ().

    Only the two fixed phrasings above are read, and only when every item in
    the list is a platform name; a description that merely mentions an
    operating system restricts nothing.
    """
    text = str(description or "")
    for pattern in (_PRIOR_TO, _ONLY_AFFECTS):
        match = pattern.search(text)
        if match:
            families = _families_in_list(match.group(1))
            if families:
                return families
    return ()


def _cpe_fields(criteria: Any) -> list[str]:
    parts = str(criteria or "").split(":")
    return parts if len(parts) >= 5 and parts[0] == "cpe" else []


def cpe_target_platform(criteria: Any) -> str:
    """The family a CPE 2.3 ``target_sw`` field pins, or "" for none/unknown."""
    parts = _cpe_fields(criteria)
    if len(parts) <= 10:
        return ""
    target = parts[10].strip().lower()
    if target in ("", "*", "-"):
        return ""
    if "android" in target:
        return "android"
    if target in ("iphone_os", "ipados", "ios"):
        return "ios"
    if target.startswith("mac") or target in ("os_x", "osx"):
        return "macos"
    if target.startswith("windows"):
        return "windows"
    if target in ("chrome_os", "chromeos"):
        return "chromeos"
    if "linux" in target:
        return "linux"
    return ""


def platform_of_os_cpe(criteria: Any) -> str:
    """The family an NVD "running on" platform CPE names, or "" when unknown."""
    parts = _cpe_fields(criteria)
    if not parts:
        return ""
    vendor, product = parts[3].lower(), parts[4].lower()
    if vendor == "google" and product == "android":
        return "android"
    if vendor == "google" and product in ("chrome_os", "chromeos"):
        return "chromeos"
    if vendor == "apple" and product in ("iphone_os", "ipados"):
        return "ios"
    if vendor == "apple" and product in ("macos", "mac_os_x", "mac_os"):
        return "macos"
    if vendor == "microsoft" and product.startswith("windows"):
        return "windows"
    if vendor == "linux" or "linux" in product:
        return "linux"
    return ""


def _iter_matches(node: Any, depth: int = 0) -> Iterator[Dict[str, Any]]:
    if depth > 8 or not isinstance(node, dict):
        return
    for match in node.get("cpeMatch") or node.get("cpe_match") or []:
        if isinstance(match, dict):
            yield match
    for child in node.get("children") or []:
        yield from _iter_matches(child, depth + 1)


def _names_product(match: Dict[str, Any], vendor: str, product: str) -> bool:
    parts = _cpe_fields(match.get("criteria") or match.get("cpe23Uri"))
    return bool(parts) and (parts[3].lower(), parts[4].lower()) == (
        vendor.lower(),
        product.lower(),
    )


def configuration_platforms(
    configurations: Any,
    vendor: str,
    product: str,
    version_matches: Callable[[Dict[str, Any]], bool],
) -> Tuple[str, ...]:
    """
    The platforms on which NVD's configurations make this product vulnerable.

    Only configurations holding a vulnerable entry for this product *at the
    installed version* (``version_matches``) are considered. Each of those
    applies on the platforms of its "running on" node, or on the platform its
    product entry's ``target_sw`` pins.

    Returns () — no restriction — when any applicable configuration names no
    platform, names one this module does not recognise, or uses a negated
    node; and when there is nothing to read at all.
    """
    if not isinstance(configurations, list):
        return ()
    families: set[str] = set()
    applicable = False
    for config in configurations:
        if not isinstance(config, dict):
            continue
        nodes = [n for n in (config.get("nodes") or []) if isinstance(n, dict)]
        hits = [
            match
            for node in nodes
            for match in _iter_matches(node)
            if match.get("vulnerable") is not False
            and _names_product(match, vendor, product)
            and version_matches(match)
        ]
        if not hits:
            continue
        applicable = True
        if any(node.get("negate") for node in nodes):
            return ()
        operator = str(config.get("operator") or "OR").upper()
        running_on = [
            match
            for node in nodes
            for match in _iter_matches(node)
            if match.get("vulnerable") is False
        ]
        if operator == "AND" and running_on:
            named = {platform_of_os_cpe(m.get("criteria")) for m in running_on}
        else:
            named = {cpe_target_platform(m.get("criteria")) for m in hits}
        if "" in named:
            return ()
        families |= named
    return tuple(sorted(families)) if applicable else ()


def declared_platforms(
    description: Any,
    configured: Optional[Sequence[str]] = None,
    cpe_uris: Iterable[Any] = (),
) -> Tuple[str, ...]:
    """
    The platforms a record applies to, from the strongest source that says.

    The CNA's description first, then the platforms the matcher read off NVD's
    configuration, then the ``target_sw`` of the CPE entries matched — and
    only if every one of those is pinned.
    """
    named = platforms_named_in(description)
    if named:
        return named
    if configured:
        return tuple(f for f in configured if f in PLATFORM_LABELS)
    targets = {cpe_target_platform(uri) for uri in cpe_uris}
    if targets and "" not in targets:
        return tuple(sorted(targets))
    return ()


def scope_excludes_host(scope: Sequence[str], host_os: str) -> str:
    """
    The host's family when a declared scope rules this host out, else "".

    Both halves must be known: a record that names no platform applies
    everywhere, and a host whose platform cannot be placed is not ruled out.
    """
    if not scope:
        return ""
    family = host_platform(host_os)
    if not family or family in scope:
        return ""
    return family


def describe_scope(scope: Sequence[str]) -> str:
    """'Android', 'Linux and ChromeOS', 'Android, Linux and ChromeOS'."""
    labels = [PLATFORM_LABELS.get(f, f) for f in scope]
    if len(labels) <= 1:
        return "".join(labels)
    return f"{', '.join(labels[:-1])} and {labels[-1]}"
