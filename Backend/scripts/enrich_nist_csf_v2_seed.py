"""
Script: enrich_nist_csf_v2_seed.py
Purpose: Render `core/nist_csf_catalogue.py` into
         `nist_csf_v2_controls_seed.json`.
Usage:   python -m scripts.enrich_nist_csf_v2_seed [--check]

Why this exists
───────────────
The shipped catalogue had 106 rows and the right total, which is precisely what
made its defects invisible. Measured against NIST.CSWP.29 (CSF 2.0, February
2024):

  * **RS.AN-08 was missing.** ISO A.5.27 crosswalks to it, so that reference
    dangled, and Respond carried 12 Subcategories where the standard defines 13.
  * **RC.RP-07 does not exist.** RC.RP has exactly six Subcategories in CSF 2.0.
    The invented seventh carried ID.IM-03's content, which is why Recover showed
    9 against the standard's 8. The two errors cancelled in the total of 106 and
    neither was visible from a count.
  * **Eight outcome statements described a different Subcategory**, several of
    them CSF 1.1 text: ID.AM-04 is "inventories of services provided by
    suppliers", not 1.1's "external information systems are catalogued";
    ID.AM-07 is *data* inventories, not asset inventories; RS.MA-04 is
    escalation, not plan testing; RS.MA-05 is the recovery-initiation criteria,
    not regulatory reporting; PR.PS-03 is hardware life cycle, not secure
    development. A reviewer attesting against those was attesting to the wrong
    outcome, and the attestation is the *only* evidence for 79 of the 106.
  * **Nothing carried a description.** `seed_compliance.py` falls back to the
    title, so all 106 stored their own title back as the control objective.
  * **Seventeen Subcategories carried the wrong `scannability`.** Twelve claimed
    `auto` against modules that do not exist (`sast_dast_scan`,
    `ha_failover_check`, `app_locker_scan`, `ir_triage_matrix`, …) and could
    only ever report unassessed; five claimed `manual` while inheriting
    automated rules through a crosswalk that had no business carrying them —
    ID.AM-07, "inventories of data are maintained", was being answered by
    A.8.8's critical-vulnerability count.

Generation removes that whole class of drift: `scannability` and
`scan_module_hint` are *derived* from `AUTOMATED_ISO_CONTROLS`, so the catalogue
cannot advertise automation the rule engine has no way to deliver, and the
control order is `CATEGORY_ORDER`, which is NIST's published order rather than
the alphabetical one a plain `ORDER BY` produces.

`--check` exits non-zero if the JSON on disk differs from what the core module
would render, which is what `tests/test_nist_csf_v2_framework_integration.py`
uses to keep the two in step.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.nist_csf_catalogue import (  # noqa: E402
    AUTOMATED_ISO_CONTROLS,
    CATEGORY_ORDER,
    FUNCTION_NAMES,
    FUNCTION_ORDER,
    SUBCATEGORIES,
)

FRAMEWORK = {
    "id": "cfw_nist_csf_v2",
    "code": "NIST_CSF_V2",
    "name": "NIST Cybersecurity Framework (CSF) v2.0",
    "version": "2.0",
    "description": (
        "NIST CSF 2.0 organises cybersecurity outcomes into 6 Functions "
        "(Govern, Identify, Protect, Detect, Respond, Recover), 22 Categories "
        "and 106 Subcategories, crosswalked here to ISO/IEC 27001:2022 Annex A."
    ),
    "author": "National Institute of Standards and Technology (NIST)",
}

# `scan_module_hint` is a String(100) column, so the derived hint is capped.
_HINT_LIMIT = 100


def subcategory_sort_key(sub_id: str) -> tuple:
    """Function, then Category, then Subcategory number — in NIST's order.

    Alphabetical ordering is wrong twice over here: it opens a CSF report on
    Detect rather than Govern, and it runs Govern as OC, OV, PO, RM, RR, SC
    rather than the published OC, RM, RR, PO, OV, SC.
    """
    category, _, number = sub_id.partition("-")
    function = category.split(".")[0]
    return (
        FUNCTION_ORDER.index(function) if function in FUNCTION_ORDER else 99,
        list(CATEGORY_ORDER).index(category) if category in CATEGORY_ORDER else 99,
        int(number) if number.isdigit() else 0,
    )


def _derive_automation(crosswalk: list) -> tuple[str, str | None]:
    """`(scannability, scan_module_hint)` from the ISO controls a rule reaches.

    A Subcategory is `auto` exactly when its crosswalk reaches an ISO control
    carrying a rule wired to a real evidence-adapter key. Anything else is
    attestation work, and saying otherwise puts coverage on the dashboard that
    the engine cannot produce.
    """
    reached = [c for c in crosswalk if c in AUTOMATED_ISO_CONTROLS]
    if not reached:
        return "manual", None

    hints: list[str] = []
    for iso in reached:
        hint = AUTOMATED_ISO_CONTROLS[iso]
        if hint not in hints:
            hints.append(hint)

    joined = " / ".join(hints)
    while len(joined) > _HINT_LIMIT and len(hints) > 1:
        hints.pop()
        joined = " / ".join(hints)
    return "auto", joined[:_HINT_LIMIT]


def render() -> dict:
    """The full seed document, built from the core module."""
    controls = []
    for sub_id in sorted(SUBCATEGORIES, key=subcategory_sort_key):
        entry = SUBCATEGORIES[sub_id]
        category = sub_id.partition("-")[0]
        function = category.split(".")[0]
        scannability, hint = _derive_automation(entry["crosswalk"])

        controls.append(
            {
                "id": sub_id,
                "theme": function,
                "function": FUNCTION_NAMES[function],
                "category": category,
                "category_name": CATEGORY_ORDER[category][1],
                "title": entry["title"],
                "description": entry["description"],
                "scannability": scannability,
                "scan_module_hint": hint,
                "crosswalk": list(entry["crosswalk"]),
                "evidence_checklist": list(entry["checklist"]),
                # Function and Category codes are carried as tags so the
                # dashboard's tag filters can slice the framework by its own
                # hierarchy without a schema change.
                "tags": [function, category],
            }
        )

    return {"framework": dict(FRAMEWORK), "controls": controls}


def _validate(doc: dict) -> list:
    """Structural guards that must hold before anything is written."""
    problems = []
    controls = doc["controls"]

    if len(controls) != 106:
        problems.append(f"expected 106 Subcategories, rendered {len(controls)}")

    expected_per_function = {"GV": 31, "ID": 21, "PR": 22, "DE": 11, "RS": 13, "RC": 8}
    actual: dict = {}
    for c in controls:
        actual[c["theme"]] = actual.get(c["theme"], 0) + 1
    if actual != expected_per_function:
        problems.append(
            f"Function distribution is {actual}, CSF 2.0 defines {expected_per_function}"
        )

    seen = set()
    for c in controls:
        if c["id"] in seen:
            problems.append(f"duplicate Subcategory {c['id']}")
        seen.add(c["id"])
        if len(c["title"]) > 255:
            problems.append(f"{c['id']} title exceeds the 255-char column")
        if c["description"].strip() == c["title"].strip():
            problems.append(f"{c['id']} description is just its title")
        if len(c["evidence_checklist"]) < 3:
            problems.append(f"{c['id']} evidence checklist is too thin")
        if not c["crosswalk"]:
            problems.append(f"{c['id']} has no crosswalk")
        if c["scannability"] == "auto" and not c["scan_module_hint"]:
            problems.append(f"{c['id']} claims auto with no module")
        if c["scannability"] != "auto" and c["scan_module_hint"]:
            problems.append(f"{c['id']} names a module but is not auto")

    return problems


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate the NIST CSF 2.0 controls seed from the core module."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the seed on disk differs from the rendered catalogue.",
    )
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base_dir, "nist_csf_v2_controls_seed.json")

    doc = render()
    problems = _validate(doc)
    if problems:
        for p in problems:
            print(f"ERROR: {p}")
        return 1

    rendered = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"

    if args.check:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                on_disk = fh.read()
        except FileNotFoundError:
            print(f"ERROR: {path} does not exist")
            return 1
        if on_disk != rendered:
            print(
                "ERROR: nist_csf_v2_controls_seed.json is out of date. "
                "Run `python -m scripts.enrich_nist_csf_v2_seed`."
            )
            return 1
        print("nist_csf_v2_controls_seed.json is up to date.")
        return 0

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(rendered)

    auto = sum(1 for c in doc["controls"] if c["scannability"] == "auto")
    print(f"Rendered {len(doc['controls'])} NIST CSF 2.0 Subcategories to {path}")
    for fn in FUNCTION_ORDER:
        n = sum(1 for c in doc["controls"] if c["theme"] == fn)
        cats = len({c["category"] for c in doc["controls"] if c["theme"] == fn})
        print(
            f"  {fn} {FUNCTION_NAMES[fn]:<9} {cats:>2} Categories  {n:>3} Subcategories"
        )
    print(f"  automated: {auto}   attestation: {len(doc['controls']) - auto}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
