"""
Integration contracts — Phase 4 of the modular-platform programme.

``ccure_contracts`` defines what Policy Pro, Audit, Rank and IR will exchange.
It is a reviewed draft, not yet wired to anything, so these tests guard the
*definitions*:

* the committed JSON Schemas are exactly what the models generate;
* every committed example is valid, and every digest in one is real;
* every field names the module that owns it;
* the semantic rules hold — unknown is never zero, PASS is earned, a
  baseline cannot carry an executable check, IR cannot verify a fix;
* the package imports only the standard library and Pydantic, and nothing in
  the application imports it yet.

Design document: docs/architecture/contracts/PHASE4_INTEGRATION_CONTRACTS.md.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import sys

import pytest
from pydantic import ValidationError

from ccure_contracts.common.v1.fields import AVAILABILITIES, OWNERS
from ccure_contracts.common.v1.vocabulary import AssessmentState
from ccure_contracts.registry import CONTRACTS, PACKAGE_ROOT, SCHEMA_LOCK
from scripts.architecture.import_graph import collect_edges
from scripts.contracts.generate_schemas import render

EXAMPLES = [(spec, path) for spec in CONTRACTS for path in spec.example_paths()]


def _example(area: str, name: str) -> dict:
    return json.loads((PACKAGE_ROOT / area / "v1" / "examples" / name).read_text())


def _spec(name: str):
    return next(s for s in CONTRACTS if s.name == name)


def _canonical_digest(obj: dict, drop: str | None = None) -> str:
    data = {k: v for k, v in obj.items() if k != drop}
    text = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ── Schemas and examples ──────────────────────────────────────────────────────


@pytest.mark.parametrize("spec", CONTRACTS, ids=lambda s: s.name)
def test_committed_schema_is_what_the_model_generates(spec):
    assert spec.schema_path.exists(), f"missing {spec.schema_path}"
    assert spec.schema_path.read_text(encoding="utf-8") == render(spec), (
        f"{spec.schema_path.name} has drifted from its model. Regenerate:\n"
        "  python -m scripts.contracts.generate_schemas"
    )


@pytest.mark.parametrize(
    "spec, path", EXAMPLES, ids=[f"{s.name}:{p.name}" for s, p in EXAMPLES]
)
def test_every_example_is_valid(spec, path):
    spec.model.model_validate_json(path.read_text(encoding="utf-8"))


def test_every_message_contract_has_an_example():
    enveloped = [s for s in CONTRACTS if "contract" in s.model.model_fields]
    without = [
        s.name for s in enveloped if not s.examples and not s.name.endswith("Page")
    ]
    assert not without, f"message contracts without an example: {without}"


def test_published_contracts_are_pinned():
    """A published schema may change only with a new schema_version."""
    lock = json.loads(SCHEMA_LOCK.read_text()) if SCHEMA_LOCK.exists() else {}
    for spec in CONTRACTS:
        assert spec.status in ("draft", "published")
        if spec.status == "published":
            digest = hashlib.sha256(render(spec).encode()).hexdigest()
            assert lock.get(spec.name) == digest, (
                f"{spec.name} is published and its schema changed. Publish a new "
                "schema_version rather than editing a published one."
            )


def test_digests_in_the_examples_are_real():
    baseline = _example("policy_baseline", "policy_baseline.request.json")
    coverage = _example("policy_baseline", "baseline_coverage.response.json")
    assert coverage["data"]["baseline"]["content_sha256"] == _canonical_digest(
        baseline["data"]
    )
    for area, name in (
        ("compliance_gap", "compliance_gap_report.json"),
        ("assessment_result", "assessment_result.json"),
    ):
        data = _example(area, name)["data"]
        assert data["content_sha256"] == _canonical_digest(data, drop="content_sha256")
    evidence = _example("incident_evidence", "incident_evidence.request.json")
    receipt = _example("incident_evidence", "incident_evidence_receipt.response.json")
    assert receipt["data"]["content_sha256"] == _canonical_digest(evidence["data"])


# ── Ownership and availability ────────────────────────────────────────────────


def _objects(schema: dict):
    yield "root", schema
    for name, definition in schema.get("$defs", {}).items():
        yield name, definition


@pytest.mark.parametrize("spec", CONTRACTS, ids=lambda s: s.name)
def test_every_field_names_its_owner(spec):
    schema = json.loads(spec.schema_path.read_text())
    missing = []
    for obj_name, obj in _objects(schema):
        for prop, body in obj.get("properties", {}).items():
            if body.get("x-ccure-owner") not in OWNERS:
                missing.append(f"{obj_name}.{prop}")
            if body.get("x-ccure-availability") not in AVAILABILITIES:
                missing.append(f"{obj_name}.{prop} (availability)")
    assert not missing, f"fields without a valid owner/availability: {missing}"


@pytest.mark.parametrize("spec", CONTRACTS, ids=lambda s: s.name)
def test_a_field_audit_cannot_populate_is_never_a_bare_required_value(spec):
    """
    A not_implemented field is either optional, or a measured value that says
    why it is absent. A required plain field would force Audit to invent one.
    """
    schema = json.loads(spec.schema_path.read_text())
    bad = []
    for obj_name, obj in _objects(schema):
        required = set(obj.get("required", []))
        for prop, body in obj.get("properties", {}).items():
            if body.get("x-ccure-availability") != "not_implemented":
                continue
            refs = [b.get("$ref", "") for b in body.get("allOf", [])]
            is_measured = any(r.endswith("/CcureMeasuredValueV1") for r in refs)
            if prop in required and not is_measured:
                bad.append(f"{obj_name}.{prop}")
    assert not bad, f"required not_implemented fields: {bad}"


def test_the_assessment_states_are_exactly_the_six():
    assert {s.value for s in AssessmentState} == {
        "PASS",
        "FAIL",
        "NOT_ASSESSED",
        "NOT_APPLICABLE",
        "MANUAL_REVIEW",
        "ERROR",
    }


# ── Semantic rules ────────────────────────────────────────────────────────────


def test_unknown_is_not_zero_for_a_measured_value():
    from ccure_contracts.common.v1.envelope import CcureMeasuredValueV1

    with pytest.raises(ValidationError, match="unknown is not zero"):
        CcureMeasuredValueV1(status="not_implemented", value=0, reason="n/a")
    with pytest.raises(ValidationError, match="must say why"):
        CcureMeasuredValueV1(status="not_collected")
    with pytest.raises(ValidationError, match="must carry a value"):
        CcureMeasuredValueV1(status="available")


def test_an_unassessed_asset_cannot_report_zero_findings():
    result = _example("assessment_result", "assessment_result.json")
    unassessed = next(
        a for a in result["data"]["assets"] if a["coverage"] == "NOT_ASSESSED"
    )
    assert unassessed["finding_counts"] is None
    broken = copy.deepcopy(result)
    target = next(
        a for a in broken["data"]["assets"] if a["coverage"] == "NOT_ASSESSED"
    )
    target["finding_counts"] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "none": 0,
        "unscored": 0,
    }
    with pytest.raises(ValidationError, match="not zero"):
        _spec("AssessmentResult").model.model_validate(broken)


def test_pass_requires_every_in_scope_asset_to_have_passed():
    report = _example("compliance_gap", "compliance_gap_report.json")
    broken = copy.deepcopy(report)
    control = next(
        c for c in broken["data"]["controls"] if c["requirement_id"] == "REQ-CFG-01"
    )
    assert control["asset_counts"]["NOT_ASSESSED"] > 0
    control["state"] = "PASS"
    control.pop("state_reason", None)
    with pytest.raises(ValidationError, match="PASS requires"):
        _spec("ComplianceGapReport").model.model_validate(broken)


def test_a_gap_report_accounts_for_every_control():
    report = _example("compliance_gap", "compliance_gap_report.json")
    broken = copy.deepcopy(report)
    broken["data"]["controls"] = [
        c for c in broken["data"]["controls"] if c["state"] == "FAIL"
    ]
    with pytest.raises(ValidationError, match="summary does not match"):
        _spec("ComplianceGapReport").model.model_validate(broken)


@pytest.mark.parametrize("smuggled", ["check_definition", "command", "oval_definition"])
def test_a_policy_baseline_cannot_carry_an_executable_check(smuggled):
    baseline = _example("policy_baseline", "policy_baseline.request.json")
    broken = copy.deepcopy(baseline)
    broken["data"]["controls"][0][smuggled] = {"cmd": "reg query HKLM\\..."}
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        _spec("PolicyBaseline").model.model_validate(broken)


def test_ir_cannot_verify_a_fix():
    evidence = _example("incident_evidence", "incident_evidence.request.json")
    broken = copy.deepcopy(evidence)
    broken["data"]["remediation_claims"][0]["claim"] = "verified_fixed"
    with pytest.raises(ValidationError):
        _spec("IncidentEvidence").model.model_validate(broken)

    receipt = _example("incident_evidence", "incident_evidence_receipt.response.json")
    broken = copy.deepcopy(receipt)
    broken["data"]["claims"][0]["remediation_state_after"] = "verified_fixed"
    with pytest.raises(ValidationError, match="never make a finding verified_fixed"):
        _spec("IncidentEvidenceReceipt").model.model_validate(broken)


def test_timestamps_must_carry_a_timezone():
    baseline = _example("policy_baseline", "policy_baseline.request.json")
    broken = copy.deepcopy(baseline)
    broken["produced_at"] = "2026-09-25T09:12:04"
    with pytest.raises(ValidationError, match="timezone"):
        _spec("PolicyBaseline").model.model_validate(broken)


def test_a_verified_fix_names_the_assessment_that_verified_it():
    page = _example("assessment_result", "assessment_findings_page.json")
    broken = copy.deepcopy(page)
    broken["items"][0]["remediation"]["state"] = "verified_fixed"
    with pytest.raises(ValidationError, match="must name the assessment"):
        _spec("AssessmentFindingsPage").model.model_validate(broken)


def test_a_message_names_the_contract_it_conforms_to():
    coverage = _example("policy_baseline", "baseline_coverage.response.json")
    with pytest.raises(ValidationError):
        _spec("PolicyBaseline").model.model_validate(coverage)


# ── Independence ──────────────────────────────────────────────────────────────

_ALLOWED_THIRD_PARTY = {"pydantic", "pydantic_core"}


def test_contracts_import_only_the_standard_library_and_pydantic():
    offenders = []
    for path in PACKAGE_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                top = name.split(".")[0]
                if top == "ccure_contracts" or top in _ALLOWED_THIRD_PARTY:
                    continue
                if top in sys.stdlib_module_names or top == "__future__":
                    continue
                offenders.append(f"{path.relative_to(PACKAGE_ROOT)}: {name}")
    assert not offenders, f"ccure_contracts may import no module's code: {offenders}"


def test_contract_classes_carry_the_ccure_prefix():
    """FastAPI names OpenAPI schemas after the class; a bare name would collide."""
    for spec in CONTRACTS:
        schema = json.loads(spec.schema_path.read_text())
        for name, definition in schema.get("$defs", {}).items():
            if "properties" in definition:
                assert name.startswith("Ccure") and name.endswith("V1"), name
        assert spec.model.__name__.startswith("Ccure")


def test_nothing_in_the_application_imports_the_contracts_yet():
    """
    Phase 4 is definitions only: no route, task or service may use a contract
    until the design is reviewed. Delete this test in the phase that builds the
    Audit integration adapter (plan Phase 7).
    """
    _, edges = collect_edges()
    users = sorted(
        {
            e.src
            for e in edges
            if e.dst.startswith("ccure_contracts")
            and not e.src.startswith("ccure_contracts")
        }
    )
    assert not users, f"application modules importing ccure_contracts: {users}"


def test_a_correction_is_a_new_result_that_says_why():
    """Q9: an AssessmentResult is corrected by superseding it, never by editing it."""
    result = _example("assessment_result", "assessment_result.json")
    model = _spec("AssessmentResult").model

    correction = copy.deepcopy(result)
    correction["data"]["result_id"] = "ar_scn_defa_c522b539_26sep26_k2mq_c1"
    correction["data"]["supersedes_result_id"] = result["data"]["result_id"]
    correction["data"][
        "correction_reason"
    ] = "Coverage was miscounted by an Audit defect."
    model.model_validate(correction)

    without_reason = copy.deepcopy(correction)
    del without_reason["data"]["correction_reason"]
    with pytest.raises(ValidationError, match="correction must say why"):
        model.model_validate(without_reason)

    itself = copy.deepcopy(correction)
    itself["data"]["supersedes_result_id"] = itself["data"]["result_id"]
    with pytest.raises(ValidationError, match="cannot supersede itself"):
        model.model_validate(itself)


def test_a_received_baseline_starts_pending_review():
    """Q1: nothing governs an assessment until an Audit administrator activates it."""
    coverage = _example("policy_baseline", "baseline_coverage.response.json")
    assert coverage["data"]["activation"] == "pending_review"
