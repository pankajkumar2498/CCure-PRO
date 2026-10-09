"""
The PolicyPro library → PolicyBaseline reference converter, and Audit's
coverage answer to it (``scripts/integration``).

The fixture is a three-reference excerpt in the library's own column layout —
one management-system clause and two Annex A controls, each with its Policy
Clause row and one of the twelve derived row types that must not reach a
baseline. The full library is not in the repository, so it is not read here.

What is pinned: only Policy Clause rows become requirements; control ids are
carried in the spelling Audit's catalogue stores; applicability comes from the
organisation's SoA or from an explicit, labelled demonstration and never from a
default; a HIPAA library is refused with the reason; and a converted baseline
flows through Audit's mapping service to a coverage answer.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timezone

import pytest

from ccure_contracts.common.v1.vocabulary import Applicability, BaselineMappingState
from scripts.integration import policypro_library_to_baseline as conv
from scripts.integration.baseline_coverage_report import coverage_for, summary

WHEN = datetime(2026, 9, 1, tzinfo=timezone.utc)

COLUMNS = [
    "row_id",
    "iso_area",
    "iso_reference",
    "policy_id",
    "policy_name",
    "clause_id",
    "clause_type",
    "control_theme",
    "control_title",
    "requirement_type",
    "detailed_policy_requirement",
    "procedure_or_operational_detail",
    "policypro_template_fields",
    "questionnaire_prompt",
    "answer_type",
    "trigger_logic",
    "audit_evidence",
    "statement_of_applicability_fields",
    "risk_treatment_linkage",
    "primary_owner",
    "review_frequency",
    "ccure_module_mapping",
    "validation_source",
    "validation_status",
    "implementation_notes",
]


def _row(
    area,
    ref,
    clause_id,
    clause_type,
    title,
    requirement,
    fields="system | timeout_value",
):
    return {
        "row_id": f"ISO27001-CSV-{clause_id}",
        "iso_area": area,
        "iso_reference": ref,
        "policy_id": "ISO27001-X",
        "policy_name": "ISO 27001 X",
        "clause_id": clause_id,
        "clause_type": clause_type,
        "control_theme": "X",
        "control_title": title,
        "requirement_type": "x",
        "detailed_policy_requirement": requirement,
        "procedure_or_operational_detail": "x",
        "policypro_template_fields": fields,
        "questionnaire_prompt": "x",
        "answer_type": "x",
        "trigger_logic": "x",
        "audit_evidence": "x",
        "statement_of_applicability_fields": "x",
        "risk_treatment_linkage": "x",
        "primary_owner": "x",
        "review_frequency": "x",
        "ccure_module_mapping": "PolicyPro; Audit; Rank",
        "validation_source": "x",
        "validation_status": "x",
        "implementation_notes": "x",
    }


ISMS, ANNEX = conv.ISMS_AREA, conv.ANNEX_AREA
LIBRARY = [
    _row(
        ISMS,
        "4.1",
        "ISO27001-ISMS.4.1",
        "Policy Clause",
        "Context",
        "Determine issues.",
    ),
    _row(
        ISMS,
        "4.1",
        "ISO27001-ISMS.4.1.TASK",
        "Implementation Task",
        "Context",
        "Implement: Context",
    ),
    _row(
        ANNEX,
        "A.5.1",
        "ISO27001-ORG.A.5.1",
        "Policy Clause",
        "Policies",
        "Define policies.",
    ),
    _row(
        ANNEX,
        "A.5.1",
        "ISO27001-ORG.A.5.1.SOP",
        "Detailed SOP Step",
        "Policies",
        "SOP: Policies",
    ),
    _row(
        ANNEX,
        "A.8.9",
        "ISO27001-TECH.A.8.9",
        "Policy Clause",
        "Configuration management",
        "Manage secure configuration.",
        fields="system | baseline | drift",
    ),
    _row(
        ANNEX,
        "A.8.9",
        "ISO27001-TECH.A.8.9.TEST",
        "Control Test Case",
        "Configuration management",
        "Test",
    ),
]


def _csv(rows, columns=COLUMNS) -> str:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=columns)
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()


def _rows(rows=LIBRARY):
    return conv._read_rows(io.StringIO(_csv(rows)))


def _soa(lines) -> dict:
    text = "annex_control_id,applicable_yes_no,justification_for_inclusion,justification_for_exclusion\n"
    text += "".join(",".join(line) + "\n" for line in lines)
    return conv.read_soa(io.StringIO(text))


def _build(rows=None, soa=None, demo=False):
    return conv.build_baseline(
        rows if rows is not None else _rows(),
        soa=soa,
        demo_all_applicable=demo,
        tenant="org_policypro_test",
        baseline_id="acme-isms",
        baseline_version=3,
        policy_id="pp-isms",
        policy_version="2.1",
        policy_title="ACME ISMS Policy",
        approved_at=WHEN,
        effective_from=WHEN,
        produced_at=WHEN,
    )


def test_one_requirement_per_reference_from_its_policy_clause_row():
    message, report = _build(demo=True)
    controls = message.data.controls
    assert [c.requirement_id for c in controls] == [
        "ISO27001-ISMS.4.1",
        "ISO27001-ORG.A.5.1",
        "ISO27001-TECH.A.8.9",
    ]
    assert [c.control.control_id for c in controls] == ["4.1", "A.5.1", "A.8.9"]
    assert {
        (c.control.framework.code, c.control.framework.version) for c in controls
    } == {("ISO27001_2022", "2022")}
    assert controls[2].requirement_text == "Manage secure configuration."
    assert all(c.parameters == [] for c in controls)
    assert (report.references, report.isms_clauses, report.annex_controls) == (3, 1, 2)
    # Candidate parameter names are reported for the vocabulary conversation,
    # never sent as parameters.
    assert report.candidate_parameters["4.1"] == ["timeout_value"]


def test_a_demonstration_says_so_and_is_idempotent():
    first, _ = _build(demo=True)
    again, _ = _build(demo=True)
    assert first.data.policy.title.startswith("DEMONSTRATION ONLY")
    assert first.source.module.value == "policy_pro"
    assert first.message_id == again.message_id  # stable across retries


@pytest.mark.parametrize("soa, demo", [(None, False), ({}, True)])
def test_applicability_is_never_a_default(soa, demo):
    with pytest.raises(conv.ConversionError, match="applicability is a decision"):
        _build(soa=soa, demo=demo)


def test_the_soa_decides_annex_a_applicability():
    soa = _soa(
        [("A.5.1", "yes", "Needed", ""), ("A.8.9", "No", "", "No IT systems in scope")]
    )
    message, report = _build(soa=soa)
    by_ref = {c.control.control_id: c for c in message.data.controls}
    assert by_ref["A.8.9"].applicability is Applicability.NOT_APPLICABLE
    assert by_ref["A.8.9"].applicability_justification == "No IT systems in scope"
    assert by_ref["A.5.1"].applicability is Applicability.APPLICABLE
    # Clauses 4–10 are mandatory for conformity: applicable without asking.
    assert by_ref["4.1"].applicability is Applicability.APPLICABLE
    assert report.not_applicable == 1
    assert not message.data.policy.title.startswith("DEMONSTRATION")


@pytest.mark.parametrize(
    "lines, match",
    [
        ([("A.5.1", "yes", "", "")], "A.8.9 .* has no SoA decision"),
        ([("A.5.1", "maybe", "", ""), ("A.8.9", "yes", "", "")], "must be yes or no"),
        (
            [("A.5.1", "yes", "", ""), ("A.8.9", "no", "", "")],
            "justification_for_exclusion",
        ),
        ([("A.5.1", "yes", "", ""), ("A.5.1", "no", "", "x")], "answered twice"),
        (
            [
                ("A.5.1", "yes", "", ""),
                ("A.8.9", "yes", "", ""),
                ("4.1", "no", "", "x"),
            ],
            "mandatory",
        ),
        (
            [
                ("A.5.1", "yes", "", ""),
                ("A.8.9", "yes", "", ""),
                ("A.9.9", "yes", "", ""),
            ],
            "does not have",
        ),
    ],
)
def test_an_soa_that_cannot_be_honoured_is_refused(lines, match):
    with pytest.raises(conv.ConversionError, match=match):
        _build(soa=_soa(lines))


def test_a_hipaa_library_is_refused_with_the_reason():
    rows = conv._read_rows(
        io.StringIO(
            "row_id,policy_id,clause_id,hipaa_reference\nr,p,c,45 CFR 164.312\n"
        )
    )
    with pytest.raises(
        conv.ConversionError, match="HIPAA library: its identifiers are PolicyPro's own"
    ):
        _build(rows=rows, demo=True)


def test_an_unrecognised_file_is_refused():
    rows = conv._read_rows(io.StringIO("a,b\n1,2\n"))
    with pytest.raises(conv.ConversionError, match="not a PolicyPro ISO 27001 library"):
        _build(rows=rows, demo=True)


def test_two_policy_clause_rows_for_one_reference_are_refused():
    rows = _rows(
        LIBRARY
        + [_row(ANNEX, "A.8.9", "ISO27001-TECH.A.8.9-B", "Policy Clause", "C", "Dup")]
    )
    with pytest.raises(conv.ConversionError, match="two Policy Clause rows"):
        _build(rows=rows, demo=True)


def test_the_command_line_writes_json_and_refuses_with_exit_2(tmp_path, capsys):
    library = tmp_path / "library.csv"
    library.write_text(_csv(LIBRARY), encoding="utf-8")
    assert (
        conv.main(
            ["--library", str(library), "--demo-all-applicable", "--tenant", "org_x"]
        )
        == 0
    )
    out = json.loads(capsys.readouterr().out)
    assert out["contract"] == "ccure.audit.policy_baseline"
    assert len(out["data"]["controls"]) == 3

    assert conv.main(["--library", str(library), "--tenant", "org_x"]) == 2
    assert "refused:" in capsys.readouterr().err


def test_a_converted_baseline_gets_a_coverage_answer(db_session):
    from db.models import Organization

    org_id = f"org_pp_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Organization(id=org_id, name=f"PP {org_id}", slug=org_id.replace("_", "-"))
    )
    db_session.flush()
    try:
        message, _ = _build(demo=True)
        coverage = coverage_for(db_session, message, org_id=org_id, now=WHEN)
        data = coverage.data
        assert data.activation == "pending_review"
        assert data.summary.controls_total == 3 == len(data.controls)
        by_ref = {c.control.control_id: c for c in data.controls}
        # A management-system clause is in Audit's ISO catalogue (since
        # 28 Sep 2026) as an attestation control: answered, never unknown and
        # never automated.
        assert by_ref["4.1"].mapping_state is BaselineMappingState.ATTESTATION_REQUIRED
        assert [c.requirement_id for c in data.controls] == [
            c.requirement_id for c in message.data.controls
        ]
        assert "ATTESTATION_REQUIRED" in summary(coverage)
        assert not db_session.new and not db_session.dirty and not db_session.deleted
    finally:
        db_session.rollback()
