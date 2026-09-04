"""
core/checks/definitions.py
─────────────────────────────────────────────────────────────────────────────
Identifiers for findings that are not CVEs.

Why this exists
───────────────
``asset_vulnerabilities.vuln_id`` is a NOT NULL foreign key into
``vulnerability_definitions``, whose primary key was sized and named for CVE
identifiers. Every finding this product could record therefore had to *be* a
CVE, and the capabilities that produce findings with no CVE at all — a CIS
control, a STIG rule, a weak service ACL, an unquoted service path, a database
account with no password policy, a switch still running Telnet — had nowhere
to write. The alternative every scanner reaches for at that point is its own
findings table, and at that moment the product has two finding models, two
risk models, two remediation workflows and two report generators.

So the catalogue stays one catalogue, and this module owns the one thing that
has to be true for that to work: a non-CVE definition must be impossible to
mistake for a CVE, in the database and on a page.

The identifier scheme
─────────────────────
    CVE-2024-4577                       a real CVE, untouched
    CCURE-CFG-CIS-WIN2022-2-3-1-1       a configuration control
    CCURE-CHK-SMB-SIGNING-DISABLED      an active check with no CVE
    CCURE-PRV-WIN-UNQUOTED-SVC-PATH     a local privilege condition

``CCURE-`` is a deliberate vendor prefix. A reader who sees it in a report
knows immediately that the identifier is ours and that searching NVD for it
will return nothing, which is the failure mode of every scanner that invents
bare numeric plugin ids and renders them in the same column as CVEs.

Nothing here mints an identifier that could collide with a CVE: the
``CVE-`` prefix is rejected outright rather than escaped, because a definition
that *is* a CVE should be filed under its real identifier and reach the
catalogue through the feed, not through a check.
"""

from __future__ import annotations

import re
from typing import Final

__all__ = [
    "DEFINITION_ID_MAX_LENGTH",
    "DEFINITION_TYPES",
    "DEFINITION_TYPE_CONFIG_CHECK",
    "DEFINITION_TYPE_CVE",
    "DEFINITION_TYPE_PLUGIN_CHECK",
    "DEFINITION_TYPE_PRIVILEGE_CHECK",
    "CCURE_DEFINITION_PREFIX",
    "definition_id_for_check",
    "definition_type_for_id",
    "is_ccure_definition_id",
    "is_cve_id",
]

#: Mirrors ``vulnerability_definitions.id`` / ``asset_vulnerabilities.vuln_id``
#: as widened by migration ``e1f2a3b4c5d6``. Kept here as the single number the
#: minting function truncates against, so widening the column again is one
#: edit in two places rather than a hunt.
DEFINITION_ID_MAX_LENGTH: Final[int] = 120

CCURE_DEFINITION_PREFIX: Final[str] = "CCURE"

#: ``vulnerability_definitions.definition_type``. Every row the vulnerability
#: feeds write is ``cve``; the rest are produced by checks.
DEFINITION_TYPE_CVE: Final[str] = "cve"
#: A configuration control — CIS, STIG, a vendor hardening guide, an internal
#: benchmark. Judged against an expected state, not against a version.
DEFINITION_TYPE_CONFIG_CHECK: Final[str] = "config_check"
#: An active check that proved a weakness with no CVE assigned to it —
#: anonymous FTP, SMB signing disabled, a default credential accepted.
DEFINITION_TYPE_PLUGIN_CHECK: Final[str] = "plugin_check"
#: A local privilege-escalation condition — a writable service binary, an
#: unquoted service path, a world-writable file on PATH.
DEFINITION_TYPE_PRIVILEGE_CHECK: Final[str] = "privilege_check"

DEFINITION_TYPES: Final[tuple[str, ...]] = (
    DEFINITION_TYPE_CVE,
    DEFINITION_TYPE_CONFIG_CHECK,
    DEFINITION_TYPE_PLUGIN_CHECK,
    DEFINITION_TYPE_PRIVILEGE_CHECK,
)

#: The short segment that appears in the identifier for each non-CVE type.
_TYPE_SEGMENT: Final[dict[str, str]] = {
    DEFINITION_TYPE_CONFIG_CHECK: "CFG",
    DEFINITION_TYPE_PLUGIN_CHECK: "CHK",
    DEFINITION_TYPE_PRIVILEGE_CHECK: "PRV",
}
_SEGMENT_TYPE: Final[dict[str, str]] = {v: k for k, v in _TYPE_SEGMENT.items()}

_CVE_RE: Final[re.Pattern[str]] = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_SLUG_STRIP: Final[re.Pattern[str]] = re.compile(r"[^A-Z0-9]+")


def is_cve_id(value: str | None) -> bool:
    """True for a well-formed CVE identifier and nothing else."""
    return bool(_CVE_RE.match(str(value or "").strip()))


def is_ccure_definition_id(value: str | None) -> bool:
    """True for an identifier this module minted."""
    return str(value or "").strip().upper().startswith(f"{CCURE_DEFINITION_PREFIX}-")


def definition_type_for_id(value: str | None) -> str:
    """
    Recover the definition type from an identifier.

    Falls back to ``cve`` only for something that really parses as a CVE.
    Anything else unrecognised comes back as ``plugin_check`` rather than
    ``cve``: mislabelling an in-house identifier as a CVE would put it in front
    of a customer as a published vulnerability, which is the worse direction to
    be wrong in.
    """
    text = str(value or "").strip().upper()
    if is_cve_id(text):
        return DEFINITION_TYPE_CVE
    if is_ccure_definition_id(text):
        parts = text.split("-")
        if len(parts) >= 2 and parts[1] in _SEGMENT_TYPE:
            return _SEGMENT_TYPE[parts[1]]
    return DEFINITION_TYPE_PLUGIN_CHECK


def definition_id_for_check(
    check_id: str, definition_type: str = DEFINITION_TYPE_CONFIG_CHECK
) -> str:
    """
    Mint the catalogue identifier for a check.

    ``check_id`` is the check's own stable name — "cis_win2022_2.3.1.1",
    "smb_signing_disabled". It is upper-cased and reduced to ``A-Z0-9-`` so the
    identifier is safe in a URL path, a filename and a CSV cell without
    quoting, and so two spellings of one check ("2.3.1.1" and "2_3_1_1") can
    never produce two catalogue rows for the same control.

    Raises rather than escaping when handed something that already looks like a
    CVE — see the module docstring.
    """
    raw = str(check_id or "").strip()
    if not raw:
        raise ValueError("definition_id_for_check: check_id is required")
    if is_cve_id(raw):
        raise ValueError(
            f"definition_id_for_check: {raw!r} is a CVE identifier. A finding "
            "for a published CVE belongs in the catalogue under its own "
            "identifier, written by the vulnerability feeds — not minted here."
        )
    if definition_type not in _TYPE_SEGMENT:
        raise ValueError(
            f"definition_id_for_check: definition_type {definition_type!r} is "
            f"not one of {tuple(_TYPE_SEGMENT)}"
        )

    slug = _SLUG_STRIP.sub("-", raw.upper()).strip("-")
    if not slug:
        raise ValueError(
            f"definition_id_for_check: {check_id!r} reduces to an empty slug"
        )

    minted = f"{CCURE_DEFINITION_PREFIX}-{_TYPE_SEGMENT[definition_type]}-{slug}"
    if len(minted) > DEFINITION_ID_MAX_LENGTH:
        # Truncating the tail would silently merge two long sibling controls
        # onto one catalogue row — exactly the collision the slug rules above
        # exist to prevent — so this refuses instead. A check id that long is a
        # naming problem to fix at the source.
        raise ValueError(
            f"definition_id_for_check: {minted!r} is {len(minted)} characters, "
            f"over the {DEFINITION_ID_MAX_LENGTH}-character column limit. "
            "Shorten the check id rather than letting two controls collide on "
            "a truncated identifier."
        )
    return minted
