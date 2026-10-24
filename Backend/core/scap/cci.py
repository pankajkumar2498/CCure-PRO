"""
core/scap/cci.py
─────────────────────────────────────────────────────────────────────────────
CCI identifiers, and the crosswalk from them to NIST SP 800-53.

What a CCI is and why it is the interesting identifier
──────────────────────────────────────────────────────
A STIG rule carries a Control Correlation Identifier — ``CCI-000366`` — and
that CCI is what ties the technical requirement to a control in NIST SP
800-53. It is the join every compliance programme built on STIGs actually
uses: an auditor asks "show me AC-17", not "show me RHEL-09-255040". Losing
the CCI reduces a STIG result to a list of host settings with no standard
behind it.

**No mapping is written here.** The CCI-to-800-53 correspondence is DISA's,
published as ``U_CCI_List.xml``, and inventing even one entry would put a false
compliance claim into a customer's report — the position this programme has
taken since Phase 4 and the reason no CIS content ships. This module reads the
published list when an operator supplies it, and carries the raw CCIs through
when they do not, so a STIG result is never *less* traceable than the content
it came from.

Enhancements collapse to their base control, deliberately
─────────────────────────────────────────────────────────
DISA maps CCIs to controls at enhancement granularity — ``AC-17 (1)``. The
seeded NIST SP 800-53 Rev. 5 catalogue here holds the 252 **base** controls, so
a crosswalk naming ``AC-17 (1)`` resolves to nothing at all, silently, in gap
analysis and in cross-framework inheritance. That is precisely the defect
CLAUDE.md records against thirteen ISO crosswalks. The base control is
therefore what the crosswalk names, and the enhancement is kept in the
control's tags where it is visible without being load-bearing.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, Iterable, List, Mapping, Sequence, Set, Tuple
from xml.etree import ElementTree as ET

from core.scap.oval import local_name

log = logging.getLogger("ccure.scap.cci")

__all__ = [
    "CCI_PATTERN",
    "NIST_FRAMEWORK_CODE",
    "base_control",
    "crosswalk_entries",
    "parse_cci_list",
]

#: The framework code the crosswalk targets, matching the seeded catalogue's
#: ``code``. Crosswalk entries are ``CODE:control_number`` — see
#: the compliance gap analysis (``routers/compliance_reports.py``), which
#: splits on the colon and normalises what follows.
NIST_FRAMEWORK_CODE = "NIST_800_53_R5"

CCI_PATTERN = re.compile(r"CCI-\d{6}", re.IGNORECASE)

#: ``AC-17 (1)``, ``AC-17(1)``, ``ac-17.1`` → ``AC-17``.
_ENHANCEMENT = re.compile(r"^\s*([A-Za-z]{2})\s*-\s*(\d+)")

#: A control reference inside prose. The lookbehind is load-bearing: NIST CSF
#: identifiers are ``PR.DS-01``, and without it ``DS-1`` is extracted from one
#: and emitted as an 800-53 control that does not exist. That is precisely the
#: dangling-crosswalk defect CLAUDE.md records against thirteen ISO entries —
#: it resolves to nothing, silently, in gap analysis and rule inheritance.
_CONTROL_IN_TEXT = re.compile(r"(?<![A-Za-z0-9.])([A-Za-z]{2}-\d+)(?:\s*\(\d+\))?")


def base_control(reference: str) -> str:
    """
    The base 800-53 control a reference names, or ``""`` if it names none.

    ``"AC-17 (1)"`` → ``"AC-17"``. An empty answer is returned rather than the
    input, because a crosswalk entry that resolves to nothing is worse than an
    absent one: it looks like coverage in every count that reads the field.
    """
    match = _ENHANCEMENT.match(str(reference or ""))
    if not match:
        return ""
    return f"{match.group(1).upper()}-{int(match.group(2))}"


def parse_cci_list(source: str | bytes) -> Dict[str, Tuple[str, ...]]:
    """
    Read DISA's ``U_CCI_List.xml`` into ``CCI id → base 800-53 controls``.

    The document nests ``<cci_item id="CCI-000366">`` with one or more
    ``<references><reference … index="AC-17 (1)"/></references>``. Several
    revisions of 800-53 appear in the same file; entries are taken from every
    reference and collapsed to base controls, so a list that stops publishing
    Rev. 4 does not empty the mapping.

    An unreadable document raises rather than returning an empty mapping. An
    empty mapping would present as "this content has no CCIs", which is a
    statement about the content rather than about the file that failed to load.
    """
    text = source.decode("utf-8", "replace") if isinstance(source, bytes) else source
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"the CCI list is not well-formed XML: {exc}") from exc

    mapping: Dict[str, Set[str]] = {}
    for node in root.iter():
        if local_name(node.tag) != "cci_item":
            continue
        cci_id = (node.get("id") or "").strip().upper()
        if not CCI_PATTERN.fullmatch(cci_id):
            continue
        controls: Set[str] = set()
        for child in node.iter():
            if local_name(child.tag) != "reference":
                continue
            index = child.get("index") or child.get("title") or ""
            control = base_control(index)
            if control:
                controls.add(control)
        if controls:
            mapping[cci_id] = controls

    if not mapping:
        raise ValueError(
            "the CCI list parsed but named no controls; it is not the "
            "U_CCI_List.xml this reader expects"
        )
    return {cci: tuple(sorted(controls)) for cci, controls in mapping.items()}


def crosswalk_entries(
    idents: Iterable[Tuple[str, str]],
    references: Iterable[Tuple[str, str]] = (),
    *,
    cci_index: Mapping[str, Sequence[str]] | None = None,
    nist_controls: Iterable[str] | None = None,
) -> Tuple[str, ...]:
    """
    Crosswalk entries for one rule, from its idents and references.

    Two independent sources, both used:

    - **CCIs** resolved through *cci_index*, which is DISA's published mapping
      and is present only when an operator supplied the list.
    - **NIST references the content itself carries.** SSG rules cite 800-53
      controls directly alongside their CCIs, so a useful crosswalk exists even
      with no CCI list — which is the common case, and the reason this does not
      simply return nothing without one.

    *nist_controls* is the control numbers the NIST SP 800-53 catalogue holds,
    and every entry is checked against it. It is the compliance catalogue's
    (``core.compliance_seeds.nist_800_53_control_numbers``) and the caller
    supplies it: the converter reads no compliance data (G4). None or empty
    checks nothing, as an unreadable seed did before.
    """
    index = {k.upper(): tuple(v) for k, v in (cci_index or {}).items()}
    controls: Set[str] = set()

    pairs = list(references)

    for _system, value in idents:
        token = str(value or "").strip().upper()
        if CCI_PATTERN.fullmatch(token):
            controls.update(index.get(token, ()))
    for href, text in pairs:
        token = str(text or "").strip().upper()
        if CCI_PATTERN.fullmatch(token):
            controls.update(index.get(token, ()))

    for href, text in pairs:
        # Only a reference that is *about* 800-53 is read as one, and the href
        # is what says so. Without this a rule's CIS reference — "3.4", "5.1" —
        # or its ISO one would be pattern-matched into an 800-53 control its
        # author never claimed, and SSG rules carry a dozen such references
        # each.
        source = f"{href} {text}".lower()
        if "800-53" not in source and "nist" not in source:
            continue
        for token in _CONTROL_IN_TEXT.findall(str(text)):
            control = base_control(token)
            if control:
                controls.add(control)

    # Every entry is checked against the catalogue it names. An entry that
    # resolves to nothing is worse than an absent one.
    catalogue = set(nist_controls or ())
    if catalogue:
        controls &= catalogue
    return tuple(f"{NIST_FRAMEWORK_CODE}:{control}" for control in sorted(controls))
