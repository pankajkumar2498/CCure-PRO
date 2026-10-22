"""
End-to-end coverage of the ISO/IEC 27001:2022 assessment workflow.

This suite did not exist. Every other seeded framework — CIS, SOC 2, CERT-In,
PCI-DSS, DPDP, GDPR — had a dedicated integration test; ISO 27001, the product's
default and flagship framework, appeared only as a `source_framework_id` string
in two gap-analysis assertions. That is why five separate defects that made the
ISO assessment produce meaningful verdicts for exactly one of its 93 controls
all reached the live database undetected:

  * rules resolved to an arbitrary control, half the time in another framework
  * every control marked `auto` was wired to an evidence source with no adapter
  * an attestation could not move the score past the scan's own placeholder
  * a control's verdict was decided by whichever finding the database returned
    last
  * `not_applicable` — the SoA's central decision — had no route through the UI

Each test below fails on the pre-fix engine.
"""

from core.compliance_seeds import all_seed_paths, seed_path


import json
from datetime import datetime, timezone

import pytest

ISO_FW = "cfw_iso27001_2022"
SEED = seed_path("iso27001_2022_controls_seed.json")


# ─────────────────────────────────────────────────────────────────────────────
# Catalogue
# ─────────────────────────────────────────────────────────────────────────────


def _seed_controls() -> list:
    with open(SEED, encoding="utf-8") as fh:
        return json.load(fh)["controls"]


def _annex_a() -> list:
    return [c for c in _seed_controls() if c["theme"] != "ISMS"]


#: ISO/IEC 27001:2022's management-system clauses, in the standard's order.
MANAGEMENT_CLAUSES = [
    "4.1",
    "4.2",
    "4.3",
    "4.4",
    "5.1",
    "5.2",
    "5.3",
    "6.1.1",
    "6.1.2",
    "6.1.3",
    "6.2",
    "6.3",
    "7.1",
    "7.2",
    "7.3",
    "7.4",
    "7.5",
    "8.1",
    "8.2",
    "8.3",
    "9.1",
    "9.2",
    "9.3",
    "10.1",
    "10.2",
]


def test_annex_a_is_complete_and_correctly_themed():
    """93 controls, split 37 / 8 / 14 / 34 across the four Annex A themes."""
    controls = _annex_a()
    assert len(controls) == 93

    by_theme: dict = {}
    for c in controls:
        by_theme[c["theme"]] = by_theme.get(c["theme"], 0) + 1
    assert by_theme == {"ORG": 37, "PPL": 8, "PHY": 14, "TECH": 34}


def test_the_management_clauses_are_present_and_attestation_only():
    """
    Clauses 4–10, so a Policy Pro baseline naming one is not UNKNOWN_CONTROL.

    Each is published under its own number — ``5.1``, never ``A.5.1``, which
    is a different requirement — and carries an id that cannot collide with
    Annex A's row. Nothing automates them, and no crosswalk has been reviewed,
    so none is claimed.
    """
    clauses = [c for c in _seed_controls() if c["theme"] == "ISMS"]
    assert [c["control_number"] for c in clauses] == MANAGEMENT_CLAUSES
    for c in clauses:
        num = c["control_number"]
        assert c["id"] == f"clause_{num}"
        assert c["scannability"] == "manual" and not c.get("scan_module_hint")
        assert not c.get("crosswalk"), f"{num} claims a crosswalk nobody reviewed"
        assert c["description"].strip() != c["title"].strip()
        assert c.get("evidence_checklist"), f"{num} has no evidence checklist"
    assert (
        len({c["title"] for c in clauses}) == len(clauses) - 2
    )  # 8.2/8.3 repeat 6.1.2/6.1.3


def test_the_seeder_publishes_each_control_under_its_own_number():
    from scripts.seed_compliance import _control_number

    iso = "cfw_iso27001_2022"
    assert _control_number(iso, {"id": "5.1"}) == "A.5.1"
    assert _control_number(iso, {"id": "clause_5.1", "control_number": "5.1"}) == "5.1"
    # A catalogue outside the allow-list keeps its stored id until verified.
    assert (
        _control_number("cfw_nis2", {"id": "gov_01", "control_number": "NIS2-Art20-01"})
        == "gov_01"
    )


def test_every_control_carries_auditor_facing_metadata():
    """Descriptions, evidence checklists and crosswalks on all 93 Annex A controls.

    ISO shipped with 0 crosswalks, 0 evidence checklists and 82 of 93
    descriptions that were the control's own title repeated back. For a
    framework where 63 controls are attestation-only, the evidence checklist is
    the entire prompt the reviewer works from.
    """
    for c in _annex_a():
        cid = c["id"]
        assert c.get("description"), f"{cid} has no description"
        assert (
            c["description"].strip() != c["title"].strip()
        ), f"{cid} description is just its title"
        assert c.get("evidence_checklist"), f"{cid} has no evidence checklist"
        assert len(c["evidence_checklist"]) >= 2, f"{cid} checklist is too thin"
        assert c.get("crosswalk"), f"{cid} has no crosswalk"


def test_scannability_only_claims_automation_that_exists():
    """Any control claiming automation must have a rule reading a real key.

    All fourteen `auto` controls were once covered only by a generated
    placeholder pointing at `auto_scan`, an evidence source with no adapter, so
    the catalogue advertised automation the engine could not deliver.

    `semi_auto` is included deliberately. This test inspected `auto` alone,
    which is how eighteen controls sat at `semi_auto` with no automated rule at
    all — A.5.9, A.5.15, A.5.16, A.5.17, A.5.23, A.8.3, A.8.4, A.8.6, A.8.10,
    A.8.11, A.8.12, A.8.19, A.8.22, A.8.23, A.8.31 and three others, every one
    of them covered only by a manual attestation placeholder. `semi_auto` is
    still a claim of partial automation, and the register, the coverage figures
    and the SoA's scan-mode column all read it as one.
    """
    # Imported by bare module name, which is how pytest itself names it: the
    # grouping directories carry no __init__.py, so there is no `tests`
    # package to qualify through, and `tests/` is on sys.path via conftest.
    from test_compliance_rule_wiring import _adapter_keys, _seeded_rules

    auto_ids = {
        f"cct_iso27001_2022_{c['id'].replace('.', '_')}"
        for c in _seed_controls()
        if c["scannability"] in ("auto", "semi_auto")
    }

    covered = set()
    for rule in _seeded_rules():
        source = rule.get("evidence_source")
        if source == "manual":
            continue
        key = (rule.get("check_definition") or {}).get("key")
        if not key or key not in _adapter_keys(source):
            continue
        normalized = str(rule["control_id"]).replace(".", "_").replace("-", "_")
        covered.add(normalized)

    uncovered = auto_ids - covered
    assert not uncovered, (
        "controls are marked scannability=auto but have no rule capable of "
        f"producing a verdict: {sorted(uncovered)}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Engine
# ─────────────────────────────────────────────────────────────────────────────


def test_rule_resolves_only_to_controls_of_the_named_framework(db_session):
    """A rule crosswalked across frameworks must not leak into another one.

    `_save_finding` used to resolve a rule to its control with `.first()` — no
    ordering, no framework filter. Measured on the shipped catalogue, 57 of the
    114 rules in the ISO default policy resolved to a control belonging to a
    different standard, so an ISO scan wrote half its findings onto DPDP, GDPR
    and IEC 62443 controls and ISO scored as unassessed.
    """
    from core.compliance_tasks import resolve_controls_for_rule
    from db.models.compliance import (
        ComplianceControl,
        ComplianceFramework,
        ComplianceRule,
        ComplianceRuleControl,
    )

    other_fw = ComplianceFramework(
        id="cfw_iso_leak_probe", code="LEAKPROBE", name="Leak Probe", version="1"
    )
    iso_ctrl = ComplianceControl(
        id="cct_iso_leak_probe_iso",
        framework_id=ISO_FW,
        control_number="A.9.99",
        theme="TECH",
        title="Probe control (ISO)",
        scannability="auto",
    )
    other_ctrl = ComplianceControl(
        id="cct_iso_leak_probe_other",
        framework_id="cfw_iso_leak_probe",
        control_number="X.1",
        theme="TECH",
        title="Probe control (other framework)",
        scannability="auto",
    )
    rule = ComplianceRule(
        id="crl_iso_leak_probe",
        rule_family_code="ISO-LEAK-PROBE",
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
    db_session.add_all([other_fw, iso_ctrl, other_ctrl, rule])
    db_session.flush()
    db_session.add_all(
        [
            ComplianceRuleControl(rule_id=rule.id, control_id=iso_ctrl.id),
            ComplianceRuleControl(rule_id=rule.id, control_id=other_ctrl.id),
        ]
    )
    db_session.commit()

    try:
        iso_hits = resolve_controls_for_rule(db_session, rule.id, ISO_FW)
        other_hits = resolve_controls_for_rule(
            db_session, rule.id, "cfw_iso_leak_probe"
        )

        assert iso_hits == [iso_ctrl.id]
        assert other_hits == [other_ctrl.id]
        # Deterministic: same answer on a second call.
        assert resolve_controls_for_rule(db_session, rule.id, ISO_FW) == iso_hits
    finally:
        db_session.query(ComplianceRuleControl).filter_by(rule_id=rule.id).delete()
        db_session.query(ComplianceRule).filter_by(id=rule.id).delete()
        db_session.query(ComplianceControl).filter(
            ComplianceControl.id.in_([iso_ctrl.id, other_ctrl.id])
        ).delete(synchronize_session=False)
        db_session.query(ComplianceFramework).filter_by(id=other_fw.id).delete()
        db_session.commit()


def test_control_verdict_is_worst_of_its_checks_not_the_last_one():
    """A.8.20 carries twelve rules; one failure must fail the control.

    Scoring built `{f.control_id: f for f in findings}` — an unordered dict
    comprehension in which the last row won — so a host with SSH closed and SMB
    wide open could score `pass` on a control covering both.
    """
    from core.compliance_tasks import roll_up_statuses

    mixed = [("pass", "auto_scan")] * 11 + [("fail", "auto_scan")]
    assert roll_up_statuses(mixed) == "fail"
    assert roll_up_statuses(list(reversed(mixed))) == "fail"

    assert roll_up_statuses([("pass", "auto_scan")] * 12) == "pass"
    assert roll_up_statuses([]) is None


def test_attestation_outranks_the_engines_own_placeholder():
    """A reviewed control is more authoritative than an unreviewed one.

    The rollup put `manual_review` above `pass`, and the scan's placeholder and
    the attestation lived at different ids, so attesting a governance control
    never moved the score. That disabled 63 of ISO's 93 controls.
    """
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
    # A human recording a failure is still a failure.
    assert (
        roll_up_statuses([("pass", "auto_scan"), ("fail", "manual_attestation")])
        == "fail"
    )


def test_org_level_finding_id_is_shared_by_scan_and_attestation():
    """One row per (tenant, control), so an attestation updates the placeholder."""
    from core.compliance_tasks import org_finding_id_for

    a = org_finding_id_for("org_x", "cct_iso27001_2022_5_1")
    b = org_finding_id_for("org_x", "cct_iso27001_2022_5_1")
    c = org_finding_id_for("org_x", "cct_iso27001_2022_5_2")
    assert a == b
    assert a != c
    assert len(a) < 250


def test_finding_ids_do_not_collide_on_similar_controls():
    """Ids used to be built from the last eight characters of each component."""
    from core.compliance_tasks import finding_id_for

    ids = {
        finding_id_for("org_default", "asset_1", f"cct_iso27001_2022_8_{n}", "crl_x")
        for n in range(1, 35)
    }
    assert len(ids) == 34


def test_unassessed_is_not_reported_as_failed():
    """A missing evidence key must not evaluate to a failure."""
    from core.compliance_evidence import ComplianceEvidenceProvider

    payload = ComplianceEvidenceProvider._fetch_and_translate(
        None, "asset", "auto_scan"
    )
    assert payload["_evidence_available"] is False
    assert "_reason" in payload


def test_credential_dependent_rules_are_gated_on_credentials():
    """`credential_validation` belongs on the prerequisite gate.

    It was missing, so on a host the scanner could not authenticate to, the
    A.8.2 rule evaluated to a *failure* — reporting a control as breached when
    the only fact established was that there were no credentials for that host.
    """
    from core.compliance_tasks import CREDENTIALED_EVIDENCE_SOURCES

    assert "credential_validation" in CREDENTIALED_EVIDENCE_SOURCES
    assert "offline_configuration" in CREDENTIALED_EVIDENCE_SOURCES
    assert "malware_scan" in CREDENTIALED_EVIDENCE_SOURCES
    assert "vulnerability_audit" in CREDENTIALED_EVIDENCE_SOURCES


def test_password_policy_is_collected_not_assumed():
    """No hard-coded password policy may reach the evidence layer.

    `attrs["password_policy"]` was a literal {complexity: True,
    history_length: 24, min_length: 14} written for every host, so any rule
    reading it passed unconditionally everywhere — fabricated evidence behind
    an auditor-facing verdict.
    """
    # The hub's code, split into scans/tasks/ by G1; core/tasks.py is a facade.
    from testpaths import BACKEND_ROOT

    source = "".join(
        path.read_text(encoding="utf-8")
        for path in sorted((BACKEND_ROOT / "scans" / "tasks").glob("*.py"))
    )
    assert '"history_length": 24' not in source
    assert '"min_length": 14' not in source

    from engines.credentialed.linux_collector import _parse_linux_password_policy
    from engines.credentialed.windows_collector import _parse_net_accounts

    # Nothing collected means nothing claimed.
    assert _parse_net_accounts("") == {}
    assert _parse_linux_password_policy("") == {}

    parsed = _parse_net_accounts(
        "Minimum password age (days):     1\n"
        "Maximum password age (days):     90\n"
        "Minimum password length:         14\n"
        "Length of password history:      24\n"
        "Lockout threshold:               5\n"
    )
    assert parsed["min_length"] == 14
    assert parsed["lockout_threshold"] == 5


# ─────────────────────────────────────────────────────────────────────────────
# Ordering and reporting
# ─────────────────────────────────────────────────────────────────────────────


def test_control_numbers_sort_numerically():
    """A.5.2 before A.5.10.

    `ORDER BY control_number` is a string sort, so the Statement of
    Applicability came out A.5.1, A.5.10, A.5.11 … A.5.2.
    """
    from routers.compliance import control_sort_key

    unordered = ["A.5.10", "A.5.2", "A.8.24", "A.8.9", "A.5.1", "A.7.14", "A.7.2"]
    assert sorted(unordered, key=control_sort_key) == [
        "A.5.1",
        "A.5.2",
        "A.5.10",
        "A.7.2",
        "A.7.14",
        "A.8.9",
        "A.8.24",
    ]
    # The management-system clauses come first and never interleave with Annex
    # A: clause 5.1 and control A.5.1 are different requirements.
    mixed = ["A.5.1", "10.1", "5.1", "A.8.9", "6.1.3", "4.1", "9.2"]
    assert sorted(mixed, key=control_sort_key) == [
        "4.1",
        "5.1",
        "6.1.3",
        "9.2",
        "10.1",
        "A.5.1",
        "A.8.9",
    ]


def test_the_soa_lists_annex_a_only():
    """Clause 6.1.3(d): the SoA states applicability for Annex A controls.

    Clauses 4–10 are mandatory; there is no applicability to state for them,
    and an SoA row claiming one would invite an exclusion the standard forbids.
    """
    import inspect

    from routers import compliance

    assert compliance.SOA_EXCLUDED_THEME == "ISMS"
    source = inspect.getsource(compliance.download_statement_of_applicability)
    assert "ComplianceControl.theme != SOA_EXCLUDED_THEME" in source


def test_soa_maps_every_verdict_to_applicability_and_implementation():
    """Clause 6.1.3(d) needs applicability and implementation status per control."""
    from routers.compliance import _SOA_APPLICABILITY, _soa_row

    class _Ctrl:
        control_number = "A.5.23"
        title = "Information security for use of cloud services"
        description = "Cloud services are acquired and managed securely."
        theme = "ORG"
        id = "cct_iso27001_2022_5_23"

    class _Rolled:
        def __init__(self, status, justification=None):
            self.status = status
            self.justification = justification
            self.owner = None
            self.reviewed_at = None

    excluded = _soa_row(_Ctrl(), _Rolled("not_applicable", "No cloud services in use."))
    assert excluded["applicable"] == "No"
    assert excluded["implementation"] == "Excluded"
    assert excluded["justification"] == "No cloud services in use."

    # An exclusion with no reason must say so rather than leave a blank cell.
    silent = _soa_row(_Ctrl(), _Rolled("not_applicable"))
    assert "NOT RECORDED" in silent["justification"]

    implemented = _soa_row(_Ctrl(), _Rolled("pass"))
    assert implemented["applicable"] == "Yes"
    assert implemented["implementation"] == "Implemented"

    # Never assessed still counts as applicable — the organisation has not
    # excluded it, it simply has not looked yet.
    unknown = _soa_row(_Ctrl(), None)
    assert unknown["applicable"] == "Yes"
    assert unknown["implementation"] == "Not assessed"

    assert set(_SOA_APPLICABILITY) >= {
        "pass",
        "fail",
        "not_applicable",
        "exception",
        "manual_review",
    }


def test_gap_analysis_does_not_round_up():
    """One passing crosswalk source must not outrank two failing ones."""
    import inspect

    from routers import compliance

    source = inspect.getsource(compliance.get_compliance_gap_analysis)
    fail_at = source.index("if has_fail:")
    pass_at = source.index("elif has_pass:")
    assert fail_at < pass_at, "gap analysis must check has_fail before has_pass"


# ─────────────────────────────────────────────────────────────────────────────
# API surface
# ─────────────────────────────────────────────────────────────────────────────


def test_iso_workflow_endpoints_are_registered():
    """The routes the ISO workflow needs must exist.

    `/compliance/reports/nerc_cip` was offered by the workspace's report menu
    and never registered; the controls register, evidence upload and scan
    status endpoints did not exist at all.
    """
    from main import app

    paths = {getattr(r, "path", "") for r in app.routes}
    for required in (
        "/compliance/frameworks/{framework_id}/controls",
        "/compliance/controls/{control_id}/evidence",
        "/compliance/evidence/{file_id}/download",
        "/compliance/scans",
        "/compliance/scans/{run_id}",
        "/compliance/schedules",
        "/compliance/schedules/{schedule_id}",
        "/compliance/reports/soa",
        "/compliance/reports/nerc_cip",
    ):
        assert required in paths, f"missing route: {required}"


def test_attestation_requires_a_reason_for_exclusion():
    """`not_applicable` without justification is not an auditable exclusion."""
    from pydantic import ValidationError
    from routers.compliance import AttestationRequest

    with pytest.raises(ValidationError):
        AttestationRequest(status="not_applicable", note="n/a")

    ok = AttestationRequest(
        status="not_applicable",
        justification="The organisation operates no cloud services.",
    )
    assert ok.justification

    # A pass needs no exclusion reason.
    assert AttestationRequest(status="pass").status == "pass"


def test_scan_run_records_when_it_was_requested():
    """`created_at` must exist on the model.

    `run_scheduled_scans` passed this keyword to the constructor and the column
    did not exist, so every scheduled compliance scan raised TypeError, was
    swallowed by a bare `except`, and reported success=False. No scheduled scan
    had ever run.
    """
    from db.models.compliance import ComplianceScanRun

    run = ComplianceScanRun(
        id="csr_probe",
        tenant_id="org_x",
        framework_id=ISO_FW,
        scope={},
        status="queued",
        created_at=datetime.now(timezone.utc),
    )
    assert run.created_at is not None
    assert hasattr(run, "error_message")


def test_scheduled_scan_task_actually_runs(db_session):
    """Call `run_scheduled_scans` for real, with no schedules due.

    This is the guard that was missing. The task carried *two* independent
    breaks, each hidden behind the other and both swallowed by a bare `except`:
    an `ImportError` for `gen_compliance_scan_run_id`, which `db.base` did not
    define, and then a `created_at` keyword the model had no column for.
    Asserting on the model or on the endpoint could not see either — only
    invoking the task can, which is why it ran broken on beat every sixty
    seconds for as long as the feature has existed.
    """
    from core.compliance_tasks import run_scheduled_scans

    result = run_scheduled_scans()
    assert result["success"] is True, f"task still fails: {result.get('error')}"
    assert "triggered_count" in result


def test_scan_run_id_generator_exists_and_is_unique():
    """The id generator the scheduled-scan task imports must exist."""
    from db.base import gen_compliance_scan_run_id

    ids = {gen_compliance_scan_run_id("org_default") for _ in range(200)}
    assert len(ids) == 200
    assert all(i.startswith("csr_") for i in ids)
    assert all(len(i) <= 100 for i in ids)


def test_findings_are_listed_per_check_not_per_control():
    """The distinct key must include rule_id.

    `DISTINCT ON (asset_id, control_id)` returned one row per control, so with
    twelve rules on A.8.20 eleven failures per host were invisible in the UI
    while still counting against the score.
    """
    import inspect

    from routers import compliance

    source = inspect.getsource(compliance.list_findings)
    distinct_block = source[source.index(".distinct(") : source.index(".order_by(")]
    assert "ComplianceFinding.rule_id" in distinct_block


# ─────────────────────────────────────────────────────────────────────────────
# Catalogue and wiring integrity
# ─────────────────────────────────────────────────────────────────────────────


def test_a_module_hint_is_only_set_where_something_runs():
    """A named scan module is a promise that a check executes.

    A.8.19 advertised "Software inventory" and A.8.22 "Network Topology" while
    both were attestation-only, which reads on screen as automation that is
    merely unfinished rather than automation that does not exist.
    """
    offenders = [
        (c["id"], c["scannability"], c.get("scan_module_hint"))
        for c in _seed_controls()
        if c.get("scan_module_hint") and c["scannability"] != "auto"
    ]
    assert not offenders, f"non-auto controls naming a scan module: {offenders}"

    missing = [
        c["id"]
        for c in _seed_controls()
        if c["scannability"] == "auto" and not c.get("scan_module_hint")
    ]
    assert not missing, f"auto controls with no module named: {missing}"


def test_every_crosswalk_resolves_to_a_real_control():
    """A crosswalk drives gap analysis and cross-framework rule inheritance.

    Thirteen references named control ids their target catalogue does not use:
    `GDPR:5-1` against an id of `GDPR_5_1`, `DPDP_2023:1-1` against `DPDP_1_1`,
    `CERT_IN_2022:IR-1` against `cert_in_ir_1`, `IEC_62443:SR 5.1` against
    `SR-5.1`. Each one silently resolved to nothing.
    """

    catalogues: dict = {}
    for path in all_seed_paths():
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        ids = {str(c["id"]) for c in doc["controls"]}
        ids |= {
            str(c["control_number"]) for c in doc["controls"] if c.get("control_number")
        }
        catalogues[doc["framework"]["code"]] = ids

    dangling = []
    for control in _seed_controls():
        for ref in control.get("crosswalk") or []:
            framework, _, target = ref.partition(":")
            known = catalogues.get(framework)
            if known is None:
                dangling.append((control["id"], ref, "unknown framework"))
                continue
            if not ({target, target.lstrip("A."), f"A.{target}"} & known):
                dangling.append((control["id"], ref, "no such control"))

    assert not dangling, f"crosswalks that resolve to nothing: {dangling}"


def test_every_control_has_a_rule_that_can_actually_run(db_session):
    """`run_scan_task` evaluates `active` rules only.

    24 of the 93 had a single rule and it was `archived` with no successor, so
    they produced no finding on any run and showed as "not assessed" with
    nothing in the UI able to say why — A.5.1 Policies, A.5.2 Roles, A.5.24 and
    A.5.26 incident management, A.5.29 continuity, A.5.35 and A.5.36 review and
    compliance among them. They stayed attestable, but they never reached the
    reviewer's findings queue and the SoA printed them as unassessed.
    """
    from db.models.compliance import (
        ComplianceControl,
        ComplianceRule,
        ComplianceRuleControl,
    )

    controls = (
        db_session.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == ISO_FW)
        .all()
    )
    if not controls:
        pytest.skip("ISO 27001 catalogue is not seeded in this database")

    runnable = {
        control_id
        for (control_id,) in db_session.query(ComplianceRuleControl.control_id)
        .join(ComplianceRule, ComplianceRule.id == ComplianceRuleControl.rule_id)
        .filter(ComplianceRule.status == "active")
        .distinct()
    }
    stranded = sorted(c.control_number for c in controls if c.id not in runnable)
    assert not stranded, f"controls with no runnable rule: {stranded}"


def test_placeholder_never_shares_a_control_with_an_automated_rule(db_session):
    """A `manual_review` placeholder outranks `pass` and suppresses it.

    A.8.13 and A.8.18 landed in that state the moment they were wired to real
    checks: the dynamic generator skips *creating* a placeholder for a mapped
    control but cannot remove one an earlier run left behind, so their
    automated checks could all pass and the control still reported as awaiting
    review.
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
            ComplianceRule.status,
        )
        .join(
            ComplianceRuleControl,
            ComplianceRuleControl.control_id == ComplianceControl.id,
        )
        .join(ComplianceRule, ComplianceRule.id == ComplianceRuleControl.rule_id)
        .filter(ComplianceControl.framework_id == ISO_FW)
        .all()
    )
    if not rows:
        pytest.skip("ISO 27001 catalogue is not seeded in this database")

    by_control: dict = {}
    for number, rule_id, source, status in rows:
        if status == "active":
            by_control.setdefault(number, []).append((rule_id, source))

    offenders = sorted(
        number
        for number, rules in by_control.items()
        if any(s and s != "manual" for _, s in rules)
        and any(r.startswith("crl_auto_gen_") for r, _ in rules)
    )
    assert (
        not offenders
    ), f"attestation placeholder sits alongside automated checks on: {offenders}"
