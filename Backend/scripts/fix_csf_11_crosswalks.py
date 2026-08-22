"""
Script: fix_csf_11_crosswalks.py
Purpose: Rewrite NIST CSF **1.1** Subcategory references in every
         `*_controls_seed.json` into their CSF **2.0** equivalents, and
         normalise the framework prefix to `NIST_CSF_V2:`.
Usage:   python -m scripts.fix_csf_11_crosswalks [--check]

Why this exists
───────────────
Ten of the other seeded frameworks crosswalk to NIST CSF. Of their 693
references, 102 named Subcategories that CSF 2.0 does not have — `PR.AC-*`,
`PR.PT-*`, `PR.IP-*`, `ID.SC-*`, `DE.CM-04`, `DE.CM-08`, `RS.RP-01` and the
rest are CSF **1.1** identifiers. CSF 2.0 renamed or re-homed all of them:
identity and access moved from `PR.AC` to `PR.AA`, supply chain moved from
`ID.SC` into the new Govern function as `GV.SC`, protective technology split
across `PR.PS` and `PR.IR`.

The references were not merely cosmetic. `seed_real_rules.py` resolves a NIS2
crosswalk of the form `GV.PO-01` to `cct_nist_csf_v2_gv_po_01` and inherits
that control's rules; a reference to `PR.AC-01` resolves to a control id that
does not exist, silently inherits nothing, and the NIS2 control falls back to
an attestation placeholder. `/compliance/gap-analysis` reads the same field, so
a tenant asking "we are PCI-compliant, where does that leave us against NIST
CSF" got a coverage figure computed over crosswalks that could never match.
Forty of PCI-DSS's 62 CSF references were dangling, and 24 of NIS 2's 44.

Two identifiers were never CSF at all and are judgement calls rather than
translations; they are listed separately in `MANUAL_TARGETS` with the control
that carries them.

`--check` exits non-zero if any dangling reference remains, which is what the
integration test uses.
"""

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.nist_csf_catalogue import SUBCATEGORIES  # noqa: E402
from core.compliance_seeds import all_seed_paths

# CSF 1.1 Subcategory -> CSF 2.0 Subcategory, following NIST's own 1.1-to-2.0
# mapping published alongside CSF 2.0.
CSF_11_TO_20: dict[str, str] = {
    # Identity Management and Access Control: PR.AC -> PR.AA / PR.IR
    "PR.AC-01": "PR.AA-01",
    "PR.AC-02": "PR.AA-06",
    "PR.AC-03": "PR.AA-05",
    "PR.AC-04": "PR.AA-05",
    "PR.AC-05": "PR.IR-01",
    "PR.AC-06": "PR.AA-02",
    "PR.AC-07": "PR.AA-03",
    # Protective Technology: PR.PT -> PR.PS / PR.IR
    "PR.PT-01": "PR.PS-04",
    "PR.PT-02": "PR.PS-01",
    "PR.PT-03": "PR.PS-01",
    "PR.PT-04": "PR.IR-01",
    "PR.PT-05": "PR.IR-03",
    # Information Protection Processes and Procedures: PR.IP -> several
    "PR.IP-01": "PR.PS-01",
    "PR.IP-02": "PR.PS-06",
    "PR.IP-03": "ID.RA-07",
    "PR.IP-04": "PR.DS-11",
    "PR.IP-06": "ID.AM-08",
    "PR.IP-09": "ID.IM-04",
    # Data Security items that moved out of PR.DS
    "PR.DS-03": "ID.AM-08",
    "PR.DS-06": "ID.RA-09",
    # Supply Chain Risk Management: ID.SC -> GV.SC (new Govern function)
    "ID.SC-01": "GV.SC-01",
    "ID.SC-02": "GV.SC-04",
    "ID.SC-03": "GV.SC-05",
    "ID.SC-04": "GV.SC-07",
    "ID.SC-05": "GV.SC-08",
    # Business Environment: ID.BE -> GV.OC / PR.IR
    "ID.BE-05": "PR.IR-03",
    # Detection
    "DE.AE-01": "ID.AM-03",
    "DE.AE-05": "DE.AE-08",
    "DE.CM-04": "DE.CM-09",
    "DE.CM-08": "ID.RA-01",
    "DE.DP-01": "GV.RR-02",
    # Response
    "RS.RP-01": "RS.MA-01",
    "RS.AN-01": "RS.MA-02",
    "RS.AN-05": "ID.RA-08",
    "RS.CO-05": "RS.CO-03",
}

# Identifiers that were never CSF Subcategories in any version. The target is
# chosen from what the carrying control is actually about, keyed by
# `(seed file stem, control id, bad reference)` so the decision is auditable.
MANUAL_TARGETS: dict[tuple[str, str, str], str] = {
    # A DPIA is an impact assessment; CSF 2.0 has no privacy-specific outcome.
    ("dpdp_2023", "DPDP_6_3", "GV.RA-01"): "ID.RA-04",
    ("gdpr", "GDPR_6_3", "GV.RA-01"): "ID.RA-04",
    # Vendor interactive remote access is an access-permission outcome.
    ("nerc_cip", "CIP-005-R3", "ID.SD-04"): "PR.AA-05",
    # This NIS2 control is the 72-hour notification to authorities, which is
    # the reporting outcome rather than 1.1's "investigate the alert".
    ("nis2", "inc_03", "RS.AN-01"): "RS.CO-02",
}

_CSF_REF = re.compile(r"^(?:GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{1,2}$")
_CANONICAL_PREFIX = "NIST_CSF_V2"


def _split(ref: str) -> tuple[str | None, str]:
    """`"NIST_CSF:PR.AC-01"` -> `("NIST_CSF", "PR.AC-01")`."""
    if ":" in ref:
        prefix, _, tail = ref.partition(":")
        return prefix.strip(), tail.strip()
    return None, ref.strip()


def _normalise_number(number: str) -> str:
    """CSF numbers are zero-padded to two digits (`PR.AA-1` -> `PR.AA-01`)."""
    head, sep, tail = number.rpartition("-")
    if sep and tail.isdigit():
        return f"{head}-{int(tail):02d}"
    return number


def rewrite_reference(stem: str, control_id: str, ref: str) -> tuple[str, bool]:
    """Returns `(new_reference, changed)` for one crosswalk entry."""
    prefix, number = _split(ref)
    number = _normalise_number(number)
    if not _CSF_REF.match(number):
        return ref, False  # not a CSF reference at all

    target = MANUAL_TARGETS.get((stem, control_id, number))
    if target is None:
        target = CSF_11_TO_20.get(number, number)

    new_ref = f"{_CANONICAL_PREFIX}:{target}"
    return new_ref, new_ref != ref


def process(path: str, apply_changes: bool) -> tuple[int, list]:
    """Rewrites one seed file. Returns `(changed_count, remaining_dangling)`.

    Substitution is textual rather than a `json.load`/`json.dump` round trip.
    These files are hand-formatted — several pack a control onto a handful of
    lines — and re-serialising them reflows every line in the file, so a
    twelve-reference correction arrived as an 1,800-line diff with the real
    change buried inside it. The regex below only ever touches the quoted
    reference itself.
    """
    stem = os.path.basename(path).replace("_controls_seed.json", "")
    with open(path, "r", encoding="utf-8") as fh:
        original = fh.read()

    doc = json.loads(original)

    # Which control carries a given reference string, so `MANUAL_TARGETS` can be
    # keyed by control. A reference that appears under two controls with
    # different manual targets would be ambiguous; none currently is, and the
    # loop below asserts that by preferring an exact (control, ref) hit.
    owners: dict[str, list] = {}
    for ctrl in doc.get("controls", []):
        for ref in ctrl.get("crosswalk") or []:
            owners.setdefault(ref, []).append(str(ctrl["id"]))

    changed = 0
    dangling: list = []
    replacements: dict[str, str] = {}

    for ref, control_ids in owners.items():
        targets = {rewrite_reference(stem, cid, ref)[0] for cid in control_ids}
        if len(targets) > 1:
            # Ambiguous only if a MANUAL_TARGETS entry disagrees with the
            # general map for the same reference string in one file. Fall back
            # to per-control handling by leaving the shared string alone and
            # reporting it, rather than silently picking one.
            dangling.append((stem, ",".join(control_ids), ref, "ambiguous"))
            continue
        new_ref = targets.pop()
        if new_ref != ref:
            replacements[ref] = new_ref
        _, number = _split(new_ref)
        if _CSF_REF.match(number) and number not in SUBCATEGORIES:
            dangling.append((stem, control_ids[0], ref, number))

    updated = original
    for old, new in replacements.items():
        pattern = re.compile(r'"' + re.escape(old) + r'"')
        updated, n = pattern.subn(f'"{new}"', updated)
        changed += n

    # Several 1.1 identifiers collapse onto one 2.0 Subcategory — PR.AC-03 and
    # PR.AC-04 both become PR.AA-05 — so a control that referenced both now
    # carries it twice. Drop the duplicates, and only rewrite the file when the
    # de-duplication actually changes something.
    if changed:
        doc = json.loads(updated)
        deduped = False
        for ctrl in doc.get("controls", []):
            refs = ctrl.get("crosswalk") or []
            seen: list = []
            for ref in refs:
                if ref not in seen:
                    seen.append(ref)
            if seen != refs:
                ctrl["crosswalk"] = seen
                deduped = True
        if deduped:
            updated = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"

    if apply_changes and changed:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(updated)

    return changed, dangling


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Migrate NIST CSF 1.1 crosswalk references to CSF 2.0."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Report without writing; exit non-zero if anything would change.",
    )
    args = parser.parse_args()

    total_changed = 0
    all_dangling: list = []

    for path in all_seed_paths():
        # The CSF catalogue itself crosswalks *to* ISO, not to itself.
        if path.endswith("nist_csf_v2_controls_seed.json"):
            continue
        changed, dangling = process(path, apply_changes=not args.check)
        all_dangling.extend(dangling)
        total_changed += changed
        if changed:
            print(f"  {os.path.basename(path):<40} {changed:>3} references rewritten")

    if all_dangling:
        print("\nERROR: references that are not CSF 2.0 Subcategories remain:")
        for stem, cid, original, resolved in all_dangling:
            print(f"  {stem}:{cid}  {original} -> {resolved}")
        return 1

    if args.check:
        if total_changed:
            print(
                f"\nERROR: {total_changed} CSF 1.1 references still present. "
                "Run `python -m scripts.fix_csf_11_crosswalks`."
            )
            return 1
        print("All NIST CSF crosswalk references are CSF 2.0 Subcategories.")
        return 0

    print(f"\nRewrote {total_changed} NIST CSF crosswalk references to CSF 2.0.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
