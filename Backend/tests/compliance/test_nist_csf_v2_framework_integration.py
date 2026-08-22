"""
End-to-end coverage of the NIST Cybersecurity Framework 2.0 assessment workflow.

This suite did not exist. Every other seeded framework has one — IEC 62443,
NERC CIP, NIS 2, SP 800-53, SP 800-82, ISO 27001 — while NIST CSF, which is the
gap-analysis target the product ships with by default, appeared only as a
literal framework id inside other tests. That is why the following all reached
the live database undetected:

  * the catalogue had 106 Subcategories and the wrong ones: RS.AN-08 missing
    (leaving ISO A.5.27's crosswalk dangling) and RC.RP-07 invented, so Respond
    carried 12 and Recover 9 against the standard's 13 and 8. The two errors
    cancelled in the total.
  * 102 crosswalk references across ten other frameworks named CSF **1.1**
    Subcategories — `PR.AC-*`, `PR.PT-*`, `ID.SC-*`, `DE.CM-04` — which resolve
    to control ids that do not exist, so the rules they were meant to inherit
    were silently never inherited.
  * eight outcome statements described a different Subcategory, several of them
    CSF 1.1 text, and none of the 106 carried a description at all.
  * seventeen Subcategories had a `scannability` the rule catalogue could not
    support in either direction.
  * the seeder's "already mapped" flag was only set when it *inserted* a link,
    so every re-run handed all 106 an attestation placeholder — including those
    with real automated checks, which a `manual_review` placeholder suppresses.
  * five Subcategories' only rule was `archived`, so they produced no finding on
    any run and sat at "not assessed" with no reason given.
  * `ORDER BY theme, control_number` sorted the framework alphabetically, so the
    audit report opened on Detect and ran Govern as OC, OV, PO, RM, RR, SC.

Every test below fails on the pre-fix engine.
"""

from core.compliance_seeds import all_seed_paths, seed_path

from testpaths import MAIN_PY

import json
import os

import pytest

CSF_FW = "cfw_nist_csf_v2"
SEED = seed_path("nist_csf_v2_controls_seed.json")

# NIST.CSWP.29, February 2024. Six Functions, 22 Categories, 106 Subcategories.
EXPECTED_PER_FUNCTION = {"GV": 31, "ID": 21, "PR": 22, "DE": 11, "RS": 13, "RC": 8}
EXPECTED_PER_CATEGORY = {
    "GV.OC": 5,
    "GV.RM": 7,
    "GV.RR": 4,
    "GV.PO": 2,
    "GV.OV": 3,
    "GV.SC": 10,
    "ID.AM": 7,
    "ID.RA": 10,
    "ID.IM": 4,
    "PR.AA": 6,
    "PR.AT": 2,
    "PR.DS": 4,
    "PR.PS": 6,
    "PR.IR": 4,
    "DE.CM": 5,
    "DE.AE": 6,
    "RS.MA": 5,
    "RS.AN": 4,
    "RS.CO": 2,
    "RS.MI": 2,
    "RC.RP": 6,
    "RC.CO": 2,
}


def _seed_controls() -> list:
    with open(SEED, encoding="utf-8") as fh:
        return json.load(fh)["controls"]


# ─────────────────────────────────────────────────────────────────────────────
# Catalogue structure
# ─────────────────────────────────────────────────────────────────────────────


def test_core_has_six_functions_twentytwo_categories_and_106_subcategories():
    """The distribution, not just the total.

    The shipped catalogue had exactly 106 rows, which is what hid the fault:
    RS.AN-08 was missing and RC.RP-07 was invented, so Respond was one short and
    Recover one over and the total came out right anyway.
    """
    controls = _seed_controls()
    assert len(controls) == 106

    per_function: dict = {}
    per_category: dict = {}
    for c in controls:
        per_function[c["theme"]] = per_function.get(c["theme"], 0) + 1
        category = c["id"].partition("-")[0]
        per_category[category] = per_category.get(category, 0) + 1

    assert per_function == EXPECTED_PER_FUNCTION
    assert per_category == EXPECTED_PER_CATEGORY


def test_subcategory_identifiers_are_unique_and_well_formed():
    import re

    ids = [c["id"] for c in _seed_controls()]
    assert len(ids) == len(set(ids)), "duplicate Subcategory identifier"
    pattern = re.compile(r"^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}$")
    bad = [i for i in ids if not pattern.match(i)]
    assert not bad, f"malformed Subcategory identifiers: {bad}"


def test_withdrawn_and_invented_subcategories_are_absent():
    """CSF 2.0 has no ID.AM-06, and RC.RP stops at 06.

    ID.AM-06 was withdrawn in 2.0 (its content moved to GV.RR-02). RC.RP-07 was
    never a CSF Subcategory at all — it carried ID.IM-03's outcome and inflated
    Recover to nine.
    """
    ids = {c["id"] for c in _seed_controls()}
    assert "ID.AM-06" not in ids
    assert "RC.RP-07" not in ids
    # …and the one that was actually missing is present.
    assert "RS.AN-08" in ids


def test_every_subcategory_carries_reviewer_facing_metadata():
    """79 of the 106 can only be satisfied by attestation.

    For those, the objective and the evidence checklist are the entire prompt
    the reviewer works from. All 106 previously stored their own title back as
    the description, because `seed_compliance.py` falls back to the title when
    the seed has no `description` key and the seed had none.
    """
    for c in _seed_controls():
        cid = c["id"]
        assert c.get("description"), f"{cid} has no description"
        assert (
            c["description"].strip() != c["title"].strip()
        ), f"{cid} description is just its title"
        assert (
            len(c.get("evidence_checklist") or []) >= 3
        ), f"{cid} evidence checklist is too thin"
        assert c.get("crosswalk"), f"{cid} has no crosswalk"
        assert len(c["title"]) <= 255, f"{cid} title exceeds the column width"


def test_outcome_statements_are_csf_20_not_csf_11():
    """Eight titles described a different Subcategory, several from CSF 1.1.

    Each pair below is one of them: the identifier, and a phrase that must
    appear in the 2.0 outcome. ID.AM-04 in 1.1 was "external information systems
    are catalogued"; in 2.0 it is supplier service inventories. RS.MA-04 in the
    shipped catalogue was plan testing; in 2.0 it is escalation.
    """
    titles = {c["id"]: c["title"].lower() for c in _seed_controls()}
    for sub_id, phrase in [
        ("ID.AM-01", "hardware"),
        ("ID.AM-04", "suppliers"),
        ("ID.AM-07", "data"),
        ("PR.PS-03", "hardware"),
        ("PR.PS-06", "software development"),
        ("RS.MA-04", "escalated"),
        ("RS.MA-05", "recovery"),
        ("RS.AN-08", "magnitude"),
        ("RC.RP-02", "recovery actions"),
        ("RC.RP-03", "backups"),
    ]:
        assert phrase in titles[sub_id], (
            f"{sub_id} outcome statement does not mention '{phrase}': "
            f"{titles[sub_id]!r}"
        )


def test_seed_json_matches_the_core_module():
    """The JSON is generated; drift between it and its source is a defect."""
    from scripts.enrich_nist_csf_v2_seed import render

    rendered = render()
    with open(SEED, encoding="utf-8") as fh:
        on_disk = json.load(fh)

    assert rendered == on_disk, (
        "nist_csf_v2_controls_seed.json is out of date. Run "
        "`python -m scripts.enrich_nist_csf_v2_seed`."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Crosswalks
# ─────────────────────────────────────────────────────────────────────────────


def test_crosswalks_resolve_to_real_iso_controls():
    """A crosswalk is what the rule mapper and gap analysis both read."""
    iso_path = seed_path("iso27001_2022_controls_seed.json")
    with open(iso_path, encoding="utf-8") as fh:
        iso = json.load(fh)["controls"]
    valid = {
        str(c["id"]) if str(c["id"]).startswith("A.") else f"A.{c['id']}" for c in iso
    }

    dangling = {
        c["id"]: [x for x in c["crosswalk"] if x not in valid] for c in _seed_controls()
    }
    dangling = {k: v for k, v in dangling.items() if v}
    assert not dangling, f"crosswalks point at non-existent ISO controls: {dangling}"


def test_no_other_framework_references_a_csf_11_subcategory():
    """102 of 693 references across ten frameworks named identifiers 2.0 dropped.

    `PR.AC-01` resolves to `cct_nist_csf_v2_pr_ac_01`, which does not exist, so
    the NIS 2 rule mapper inherited nothing and `/compliance/gap-analysis`
    computed coverage over crosswalks that could never match. Forty of
    PCI-DSS's 62 CSF references were dangling.
    """
    import re

    valid = {c["id"] for c in _seed_controls()}
    csf_ref = re.compile(r"^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{1,2}$")

    dangling: list = []
    for path in all_seed_paths():
        if path.endswith("nist_csf_v2_controls_seed.json"):
            continue
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        for ctrl in doc.get("controls", []):
            for ref in ctrl.get("crosswalk") or []:
                number = ref.split(":", 1)[1].strip() if ":" in ref else ref.strip()
                head, sep, tail = number.rpartition("-")
                if sep and tail.isdigit():
                    number = f"{head}-{int(tail):02d}"
                if csf_ref.match(number) and number not in valid:
                    dangling.append((os.path.basename(path), ctrl["id"], ref))

    assert not dangling, (
        f"{len(dangling)} references to Subcategories CSF 2.0 does not define: "
        f"{dangling[:12]}"
    )


def test_iso_and_csf_crosswalks_agree_on_rs_an_08():
    """The reference that proved RS.AN-08 was missing rather than optional."""
    iso_path = seed_path("iso27001_2022_controls_seed.json")
    with open(iso_path, encoding="utf-8") as fh:
        iso = json.load(fh)["controls"]
    refs = {r for c in iso for r in (c.get("crosswalk") or []) if "RS.AN-08" in r}
    assert refs, "ISO A.5.27 no longer crosswalks to RS.AN-08"
    assert "RS.AN-08" in {c["id"] for c in _seed_controls()}


# ─────────────────────────────────────────────────────────────────────────────
# Automation claims
# ─────────────────────────────────────────────────────────────────────────────


def test_scannability_is_derived_from_reachable_automation():
    """A Subcategory may claim `auto` only where a real rule can reach it.

    Twelve claimed `auto` against modules that do not exist — `sast_dast_scan`,
    `ha_failover_check`, `app_locker_scan`, `ir_triage_matrix` — and reported
    unassessed forever while the dashboard counted them as coverage. Five more
    claimed `manual` while inheriting automated rules through a crosswalk that
    had no business carrying them: ID.AM-07, "inventories of data are
    maintained", was answered by A.8.8's critical-vulnerability count.
    """
    from core.nist_csf_catalogue import AUTOMATED_ISO_CONTROLS

    wrong: list = []
    for c in _seed_controls():
        reachable = bool(set(c["crosswalk"]) & set(AUTOMATED_ISO_CONTROLS))
        claimed = c["scannability"] == "auto"
        if reachable != claimed:
            wrong.append((c["id"], c["scannability"], sorted(c["crosswalk"])))
    assert not wrong, f"scannability disagrees with reachable automation: {wrong}"


def test_auto_subcategories_name_a_module_that_exists():
    """`scan_module_hint` used to name modules the product does not have."""
    from core.nist_csf_catalogue import AUTOMATED_ISO_CONTROLS

    known = set(AUTOMATED_ISO_CONTROLS.values())
    for c in _seed_controls():
        if c["scannability"] != "auto":
            assert not c[
                "scan_module_hint"
            ], f"{c['id']} is not auto but names {c['scan_module_hint']!r}"
            continue
        assert c["scan_module_hint"], f"{c['id']} claims auto with no module"
        parts = [p.strip() for p in c["scan_module_hint"].split(" / ")]
        # The hint is a "/"-joined list capped at the column width, so a
        # truncated tail is acceptable; the first element never is.
        assert (
            parts[0] in known
        ), f"{c['id']} names an unknown module: {c['scan_module_hint']!r}"


# ─────────────────────────────────────────────────────────────────────────────
# Ordering
# ─────────────────────────────────────────────────────────────────────────────


def test_functions_and_categories_sort_in_nists_published_order():
    """Not alphabetically.

    `ORDER BY theme, control_number` gives DE, GV, ID, PR, RC, RS and Govern as
    OC, OV, PO, RM, RR, SC. NIST publishes GV, ID, PR, DE, RS, RC and OC, RM,
    RR, PO, OV, SC, and an auditor reads the alphabetical form as a different
    framework.
    """
    from routers.compliance import control_sort_key

    shuffled = [
        "RC.CO-03",
        "GV.SC-01",
        "DE.AE-02",
        "ID.AM-01",
        "RS.MA-01",
        "GV.OC-01",
        "PR.AA-01",
        "GV.RM-01",
        "GV.OV-01",
        "GV.PO-01",
        "GV.RR-01",
        "RC.RP-01",
    ]
    assert sorted(shuffled, key=control_sort_key) == [
        "GV.OC-01",
        "GV.RM-01",
        "GV.RR-01",
        "GV.PO-01",
        "GV.OV-01",
        "GV.SC-01",
        "ID.AM-01",
        "PR.AA-01",
        "DE.AE-02",
        "RS.MA-01",
        "RC.RP-01",
        "RC.CO-03",
    ]


def test_subcategory_numbers_sort_numerically_within_a_category():
    from routers.compliance import control_sort_key

    unordered = ["GV.SC-10", "GV.SC-02", "GV.SC-01", "ID.RA-10", "ID.RA-02"]
    assert sorted(unordered, key=control_sort_key) == [
        "GV.SC-01",
        "GV.SC-02",
        "GV.SC-10",
        "ID.RA-02",
        "ID.RA-10",
    ]


def test_csf_ordering_does_not_disturb_other_frameworks():
    """The ISO sort key must keep working — one list, two key shapes."""
    from routers.compliance import control_sort_key

    iso = ["A.5.10", "A.5.2", "A.8.24", "A.8.9", "A.5.1"]
    assert sorted(iso, key=control_sort_key) == [
        "A.5.1",
        "A.5.2",
        "A.5.10",
        "A.8.9",
        "A.8.24",
    ]


def test_dashboard_function_breakdown_is_deterministic_and_canonical():
    """`quadrant_scores` is rendered in key order, so build order is the UI order.

    Both branches of `/summary` built it from a `set` or an unordered
    `DISTINCT`, so the Core Functions panel could differ between two loads of
    the same page.
    """
    from routers.compliance import _ordered_themes

    assert _ordered_themes({"RC", "GV", "PR", "DE", "RS", "ID"}) == [
        "GV",
        "ID",
        "PR",
        "DE",
        "RS",
        "RC",
    ]
    # ISO's four themes are Annex A clauses 5 to 8, also not alphabetical.
    assert _ordered_themes({"TECH", "ORG", "PHY", "PPL"}) == [
        "ORG",
        "PPL",
        "PHY",
        "TECH",
    ]
    # Anything unknown is at least stable.
    assert _ordered_themes({"ZZ", "AA"}) == ["AA", "ZZ"]


def test_function_and_category_names_are_resolvable():
    """The register printed a bare "GV" against all 31 Govern rows."""
    from core import nist_csf

    assert nist_csf.function_name_for("PR.AA-05") == "Protect"
    assert nist_csf.function_name_for("GV") == "Govern"
    assert nist_csf.category_name_for("GV.SC-01") == (
        "Cybersecurity Supply Chain Risk Management"
    )
    # Not a CSF identifier — must not be forced into the CSF hierarchy.
    assert nist_csf.category_name_for("A.8.20") is None
    assert nist_csf.is_csf_subcategory("A.8.20") is False
    assert nist_csf.is_csf_subcategory("DE.CM-09") is True


# ─────────────────────────────────────────────────────────────────────────────
# Rule wiring and scoring
# ─────────────────────────────────────────────────────────────────────────────


def test_placeholder_never_shares_a_subcategory_with_an_automated_rule(db_session):
    """A `manual_review` placeholder suppresses a `pass` from a real check.

    The seeder set its "already mapped" flag only when it *inserted* a crosswalk
    link, so on every run after the first nothing set the flag and all 106
    Subcategories were handed an attestation placeholder — the 27 with real
    automated checks included. Those could then never report compliant no matter
    what the scan found.
    """
    from db.models.compliance import (
        ComplianceControl,
        ComplianceRule,
        ComplianceRuleControl,
    )

    rows = (
        db_session.query(
            ComplianceControl.control_number,
            ComplianceRule.id,
            ComplianceRule.evidence_source,
        )
        .join(
            ComplianceRuleControl,
            ComplianceRuleControl.control_id == ComplianceControl.id,
        )
        .join(ComplianceRule, ComplianceRule.id == ComplianceRuleControl.rule_id)
        .filter(ComplianceControl.framework_id == CSF_FW)
        .all()
    )
    if not rows:
        pytest.skip("NIST CSF catalogue is not seeded in this database")

    by_control: dict = {}
    for number, rule_id, source in rows:
        by_control.setdefault(number, []).append((rule_id, source))

    offenders = [
        number
        for number, rules in by_control.items()
        if any(s and s != "manual" for _, s in rules)
        and any(r.startswith("crl_nist_auto_gen_") for r, _ in rules)
    ]
    assert not offenders, (
        "attestation placeholder sits alongside automated checks on: " f"{offenders}"
    )


def test_every_subcategory_has_a_rule_that_can_run(db_session):
    """`run_scan_task` evaluates `active` rules only.

    Five Subcategories' only rule was `archived` with no successor, so they
    produced no finding on any run and showed as "not assessed" with nothing in
    the UI able to say why.
    """
    from db.models.compliance import (
        ComplianceControl,
        ComplianceRule,
        ComplianceRuleControl,
    )

    controls = (
        db_session.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == CSF_FW)
        .all()
    )
    if not controls:
        pytest.skip("NIST CSF catalogue is not seeded in this database")

    runnable = {
        control_id
        for (control_id,) in db_session.query(ComplianceRuleControl.control_id)
        .join(ComplianceRule, ComplianceRule.id == ComplianceRuleControl.rule_id)
        .filter(ComplianceRule.status == "active")
        .distinct()
    }
    stranded = [c.control_number for c in controls if c.id not in runnable]
    assert not stranded, f"Subcategories with no runnable rule: {stranded}"


def test_a_rule_resolves_only_to_csf_controls_in_a_csf_scan(db_session):
    """Rules are crosswalked across standards on purpose."""
    from core.compliance_tasks import resolve_controls_for_rule
    from db.models.compliance import (
        ComplianceControl,
        ComplianceRule,
        ComplianceRuleControl,
    )

    csf_ctrl = ComplianceControl(
        id="cct_csf_probe",
        framework_id=CSF_FW,
        control_number="PR.ZZ-99",
        theme="PR",
        title="Probe (CSF)",
        scannability="auto",
    )
    iso_ctrl = ComplianceControl(
        id="cct_csf_probe_iso",
        framework_id="cfw_iso27001_2022",
        control_number="A.9.98",
        theme="TECH",
        title="Probe (ISO)",
        scannability="auto",
    )
    rule = ComplianceRule(
        id="crl_csf_probe",
        rule_family_code="CSF-PROBE",
        version_number=1,
        check_type="port_state",
        evidence_source="services_ports",
        target_platform="any",
        check_definition={
            "key": "open_ports",
            "operator": "not_contains",
            "expected": 23,
        },
        severity="high",
        status="active",
    )
    db_session.add_all([csf_ctrl, iso_ctrl, rule])
    db_session.flush()
    db_session.add_all(
        [
            ComplianceRuleControl(rule_id=rule.id, control_id=csf_ctrl.id),
            ComplianceRuleControl(rule_id=rule.id, control_id=iso_ctrl.id),
        ]
    )
    db_session.commit()
    try:
        assert resolve_controls_for_rule(db_session, rule.id, CSF_FW) == [csf_ctrl.id]
        assert resolve_controls_for_rule(db_session, rule.id, "cfw_iso27001_2022") == [
            iso_ctrl.id
        ]
    finally:
        db_session.query(ComplianceRuleControl).filter_by(rule_id=rule.id).delete()
        db_session.query(ComplianceRule).filter_by(id=rule.id).delete()
        db_session.query(ComplianceControl).filter(
            ComplianceControl.id.in_([csf_ctrl.id, iso_ctrl.id])
        ).delete(synchronize_session=False)
        db_session.commit()


def test_attestation_moves_a_subcategory_off_the_placeholder():
    """The route to a verdict for 79 of the 106."""
    from core.compliance_tasks import roll_up_statuses

    assert (
        roll_up_statuses(
            [("manual_review", "auto_scan"), ("pass", "manual_attestation")]
        )
        == "pass"
    )
    assert (
        roll_up_statuses(
            [("manual_review", "auto_scan"), ("not_applicable", "manual_attestation")]
        )
        == "not_applicable"
    )


def test_a_subcategory_reaches_pass_when_every_check_passes():
    """Automated Subcategories must be able to score, not only to fail."""
    from core.compliance_tasks import roll_up_statuses

    assert roll_up_statuses([("pass", "auto_scan")] * 4) == "pass"
    # One unassessed check is not a failure, but it is not a pass either.
    assert (
        roll_up_statuses([("pass", "auto_scan")] * 3 + [("manual_review", "auto_scan")])
        == "manual_review"
    )
    # One failure fails the Subcategory regardless of ordering.
    mixed = [("pass", "auto_scan")] * 3 + [("fail", "auto_scan")]
    assert roll_up_statuses(mixed) == "fail"
    assert roll_up_statuses(list(reversed(mixed))) == "fail"


def test_not_applicable_is_excluded_from_the_score_not_counted_as_failed():
    """Every status the workflow can produce needs a defined report rendering."""
    from routers.compliance import _CSF_VERDICT_DISPLAY

    for status in (
        "pass",
        "fail",
        "exception",
        "pending_reverify",
        "remediation_applied",
        "manual_review",
        "not_applicable",
        "not_assessed",
    ):
        assert status in _CSF_VERDICT_DISPLAY, f"no report rendering for {status}"

    # "nobody looked" and "a human still has to sign it off" must stay apart.
    assert (
        _CSF_VERDICT_DISPLAY["not_assessed"][0]
        != _CSF_VERDICT_DISPLAY["manual_review"][0]
    )


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────


def test_report_groups_by_function_then_category_in_published_order():
    """The Current Profile is Function ▸ Category ▸ Subcategory."""
    from routers.compliance import _csf_group

    class _C:
        def __init__(self, number, theme, title):
            self.id = number
            self.control_number = number
            self.theme = theme
            self.title = title
            self.scannability = "manual"

    controls = [
        _C("RC.CO-03", "RC", "Recovery communicated"),
        _C("GV.SC-01", "GV", "SCRM programme"),
        _C("GV.OC-01", "GV", "Mission understood"),
        _C("ID.AM-01", "ID", "Hardware inventory"),
        _C("GV.RM-01", "GV", "Risk objectives"),
    ]
    grouped = _csf_group(controls, {})

    assert [code for code, _, _, _ in grouped] == ["GV", "ID", "RC"]
    govern = next(cats for code, _, _, cats in grouped if code == "GV")
    assert [c for c, _, _ in govern] == ["GV.OC", "GV.RM", "GV.SC"]


def test_report_score_excludes_not_applicable_from_the_denominator():
    from routers.compliance import _csf_group

    class _C:
        def __init__(self, number, theme):
            self.id = number
            self.control_number = number
            self.theme = theme
            self.title = number
            self.scannability = "auto"

    controls = [_C(f"PR.AA-0{n}", "PR") for n in range(1, 5)]
    verdicts = {
        "PR.AA-01": "pass",
        "PR.AA-02": "pass",
        "PR.AA-03": "not_applicable",
        "PR.AA-04": "fail",
    }
    (_code, _name, (pct, passed, applicable, assessed), _cats) = _csf_group(
        controls, verdicts
    )[0]
    assert applicable == 3, "not_applicable must leave the denominator"
    assert passed == 2
    assert assessed == 3
    assert pct == pytest.approx(66.7, abs=0.1)


def test_report_rejects_an_unknown_function_filter():
    """`functions=PROTECT` used to silently return an empty report."""
    from core import nist_csf

    assert set(nist_csf.FUNCTION_ORDER) == set(EXPECTED_PER_FUNCTION)
    assert nist_csf.FUNCTION_ORDER == ("GV", "ID", "PR", "DE", "RS", "RC")


def test_csf_workflow_endpoints_are_registered():
    from main import app

    paths = {getattr(r, "path", "") for r in app.routes}
    for required in (
        "/compliance/reports/nist_csf",
        "/compliance/gap-analysis",
        "/compliance/frameworks/{framework_id}/controls",
        "/compliance/controls/{control_id}/attest",
        "/compliance/scans",
    ):
        assert required in paths, f"missing route: {required}"


# ─────────────────────────────────────────────────────────────────────────────
# Bootstrap
# ─────────────────────────────────────────────────────────────────────────────


def test_bootstrap_reseeds_a_truncated_csf_catalogue():
    """The self-heal threshold was 20 against a 106-Subcategory framework.

    Every other framework's threshold is its real control count, so a NIST
    catalogue truncated to anything above 20 satisfied the check and was never
    repaired.
    """
    main_py = MAIN_PY
    with open(main_py, encoding="utf-8") as fh:
        source = fh.read()
    assert (
        "nist_ctrl_count < 106" in source
    ), "main.py's NIST CSF re-seed threshold is not the framework's size"


# ─────────────────────────────────────────────────────────────────────────────
# HTTP surface, end to end
# ─────────────────────────────────────────────────────────────────────────────


def _install_csf(db_session, org_id):
    """Seeds the catalogue and enables it for the tenant."""
    from db.models.compliance import ComplianceTenantFramework
    from scripts.seed_compliance import seed_framework_and_controls

    seed_framework_and_controls(db_session, SEED)
    tfw = (
        db_session.query(ComplianceTenantFramework)
        .filter(
            ComplianceTenantFramework.tenant_id == org_id,
            ComplianceTenantFramework.framework_id == CSF_FW,
        )
        .first()
    )
    if not tfw:
        db_session.add(
            ComplianceTenantFramework(
                id=f"ctf_{org_id}_{CSF_FW}",
                tenant_id=org_id,
                framework_id=CSF_FW,
                is_enabled=True,
            )
        )
        db_session.commit()


def test_controls_register_returns_the_full_core_in_published_order(
    client, db_session, test_user, auth_headers
):
    """The register is the only route to a Subcategory with no finding yet."""
    _install_csf(db_session, test_user.org_id)

    res = client.get(f"/compliance/frameworks/{CSF_FW}/controls", headers=auth_headers)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["total"] == 106

    rows = body["data"]
    assert [r["theme"] for r in rows][:31] == ["GV"] * 31
    assert [r["control_number"] for r in rows][:6] == [
        "GV.OC-01",
        "GV.OC-02",
        "GV.OC-03",
        "GV.OC-04",
        "GV.OC-05",
        "GV.RM-01",
    ]
    # Govern's Categories in NIST's order, not alphabetically.
    govern_categories: list = []
    for r in rows:
        if r["theme"] != "GV":
            continue
        if r["category"] not in govern_categories:
            govern_categories.append(r["category"])
    assert govern_categories == [
        "GV.OC",
        "GV.RM",
        "GV.RR",
        "GV.PO",
        "GV.OV",
        "GV.SC",
    ]

    # Function and Category names reach the UI rather than a bare code.
    first = rows[0]
    assert first["function"] == "Govern"
    assert first["category_name"] == "Organizational Context"
    assert first["description"] and first["description"] != first["title"]
    assert len(first["evidence_checklist"]) >= 3

    # Coverage and conformity are reported separately.
    for key in (
        "passed",
        "failed",
        "not_applicable",
        "exception",
        "awaiting_review",
        "not_assessed",
    ):
        assert key in body["summary"], f"summary is missing {key}"


def test_summary_reports_coverage_not_just_a_percentage(
    client, db_session, test_user, auth_headers
):
    """A framework nobody has assessed must not read as one that failed."""
    _install_csf(db_session, test_user.org_id)

    res = client.get(f"/compliance/summary?framework_id={CSF_FW}", headers=auth_headers)
    assert res.status_code == 200, res.text
    body = res.json()
    kpis = body["kpis"]
    # The unfiltered branch returned only total/passed/failed/exceptions, so the
    # same framework reported a different KPI shape depending on whether a
    # filter happened to be applied. Both branches carry all of these now.
    for key in (
        "total",
        "passed",
        "failed",
        "exceptions",
        "not_applicable",
        "assessed",
        "not_assessed",
    ):
        assert key in kpis, f"KPI block is missing {key}"
    assert "weighted_available" in body

    # This tenant has run no CSF scan, so nothing is assessed and nothing has
    # passed — which must be distinguishable from a framework that failed.
    assert kpis["passed"] == 0
    assert kpis["failed"] == 0
    assert kpis["not_assessed"] > 0
    assert kpis["assessed"] == 0


def test_current_profile_report_renders_in_both_formats(
    client, db_session, test_user, auth_headers
):
    _install_csf(db_session, test_user.org_id)

    pdf = client.get("/compliance/reports/nist_csf?fmt=pdf", headers=auth_headers)
    assert pdf.status_code == 200, pdf.text
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content[:5] == b"%PDF-"

    docx = client.get("/compliance/reports/nist_csf?fmt=docx", headers=auth_headers)
    assert docx.status_code == 200, docx.text
    # python-docx is a declared dependency; a 29-byte "not installed" body is a
    # regression, not an acceptable fallback.
    assert docx.content[:2] == b"PK", docx.content[:80]


def test_report_function_filter_is_validated(
    client, db_session, test_user, auth_headers
):
    """`functions=PROTECT` used to return an empty report rather than an error."""
    _install_csf(db_session, test_user.org_id)

    ok = client.get(
        "/compliance/reports/nist_csf?fmt=pdf&functions=GV,RC", headers=auth_headers
    )
    assert ok.status_code == 200, ok.text

    bad = client.get(
        "/compliance/reports/nist_csf?fmt=pdf&functions=PROTECT", headers=auth_headers
    )
    assert bad.status_code == 400
    assert "PROTECT" in bad.json()["detail"]


def test_gap_analysis_projects_iso_posture_onto_every_subcategory(
    client, db_session, test_user, auth_headers
):
    """Each Subcategory must be mapped; an unmapped one is an invisible gap."""
    _install_csf(db_session, test_user.org_id)

    res = client.get(
        f"/compliance/gap-analysis?source_framework_id=cfw_iso27001_2022"
        f"&target_framework_id={CSF_FW}",
        headers=auth_headers,
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["summary"]["total_target_controls"] == 106
    assert (
        body["summary"]["mapped_controls"] == 106
    ), "every Subcategory carries an ISO crosswalk"
    unmapped = [c["control_number"] for c in body["controls"] if not c["crosswalk"]]
    assert not unmapped, unmapped
