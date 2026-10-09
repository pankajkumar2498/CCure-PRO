"""
tests/compliance/test_benchmark_compliance.py
─────────────────────────────────────────────────────────────────────────────
A configuration verdict becoming a compliance finding.

This is the link Phase 3 built and left unconnected. Everything below is about
what reaches ``compliance_findings.status`` and what deliberately does not.

The outcome matrix is the point:

    PASS            -> "pass"
    FAIL            -> "fail"
    NOT_APPLICABLE  -> "not_applicable"
    MANUAL_REVIEW   -> "manual_review"
    ERROR           -> "manual_review", with the reason recorded

The last row is the one that matters. ``compliance_findings.status`` has no
``error`` member and must not gain one — it would be a claim about a host that
nothing established. So an errored check is *not assessed*, and the reason
travels with it so an operator can see why rather than only that.

Nothing in this file lets an unreadable check become a pass or a fail. Several
tests exist purely to hold that line from different directions, because it is
the property a customer's audit report depends on.
"""

import uuid

import pytest

from core.benchmarks.loader import load_pack_into_db, rule_row_id
from core.benchmarks.pack import BenchmarkControl, BenchmarkPack, BenchmarkProfile
from core.checks.contract import CheckOutcome, CheckResult, Evidence
from core.compliance_sync import sync_config_audit_findings
from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation
from db.models.assets import Asset
from db.models.compliance import (
    ComplianceControl,
    ComplianceFinding,
    ComplianceFramework,
    ComplianceRule,
    ComplianceTenantFramework,
)
from db.models.rbac import Organization

PACK_CODE = "SYNC_TEST"


def _check(control_id: str) -> ConfigCheck:
    return ConfigCheck(
        check_id=control_id,
        title="A benchmark recommendation",
        check_type="registry",
        platforms=("windows",),
        collect={"path": r"HKLM\SOFTWARE\X", "value": "V"},
        expect=Expectation("equals", 1),
        absent=AbsencePolicy.MANUAL_REVIEW,
        remediation="Set it to 1.",
    )


def _pack() -> BenchmarkPack:
    return BenchmarkPack(
        code=PACK_CODE,
        name="Sync Test Benchmark",
        version="1.0.0",
        platform="windows",
        publisher="Test Publisher",
        licence="Test licence",
        profiles=(BenchmarkProfile("L1"),),
        controls=(
            BenchmarkControl(
                control_id="1.1",
                title="A benchmark recommendation",
                assessment="automated",
                severity="high",
                profiles=("L1",),
                remediation="Set it to 1.",
                check=_check("1.1"),
            ),
        ),
    )


@pytest.fixture
def benchmark_env(db_session):
    """An org with the benchmark installed, plus an asset to hang findings off."""
    pack = _pack()
    load_pack_into_db(db_session, pack, commit=False)

    org_id = f"org_sync_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Organization(
            id=org_id,
            name=f"Sync {org_id}",
            slug=org_id.replace("_", "-"),
            max_assets=10,
            max_users=10,
            is_active=True,
            settings={},
        )
    )
    db_session.flush()
    db_session.add(
        ComplianceTenantFramework(
            id=f"ctf_{org_id}",
            tenant_id=org_id,
            framework_id=pack.framework_id,
            is_enabled=True,
        )
    )
    asset_id = f"ast_{org_id}_10_0_0_5"
    db_session.add(
        Asset(id=asset_id, org_id=org_id, ip_address="10.0.0.5", hostname="sync-host")
    )
    db_session.flush()

    yield {
        "pack": pack,
        "org_id": org_id,
        "asset_id": asset_id,
        "rule_id": rule_row_id(pack, "1.1"),
    }

    db_session.query(ComplianceFinding).filter(
        ComplianceFinding.tenant_id == org_id
    ).delete()
    db_session.query(ComplianceFramework).filter(
        ComplianceFramework.id == pack.framework_id
    ).delete()
    db_session.query(ComplianceRule).filter(
        ComplianceRule.id.like(f"rule_{PACK_CODE.lower()}%")
    ).delete(synchronize_session=False)
    db_session.query(Asset).filter(Asset.org_id == org_id).delete()
    db_session.query(Organization).filter(Organization.id == org_id).delete()
    db_session.commit()


def a_result(env, outcome, *, with_evidence=True, error=None) -> CheckResult:
    evidence = (
        [
            Evidence(
                collector="windows_registry",
                description="A benchmark recommendation",
                expected="equals 1",
                observed="0",
                raw="CCURE::VALUE::0",
            )
        ]
        if with_evidence
        else []
    )
    kwargs = dict(
        check_id=env["rule_id"],
        outcome=outcome,
        title="A benchmark recommendation",
        severity="high",
        target="10.0.0.5",
        evidence=evidence,
        remediation="Set it to 1.",
    )
    if outcome is CheckOutcome.ERROR:
        kwargs["error"] = error or "the command exited 5"
    return CheckResult(**kwargs)


def _sync(db_session, env, results):
    summary = sync_config_audit_findings(
        db_session, org_id=env["org_id"], asset_id=env["asset_id"], results=results
    )
    db_session.flush()
    return summary


def _findings(db_session, env):
    return (
        db_session.query(ComplianceFinding)
        .filter(ComplianceFinding.tenant_id == env["org_id"])
        .all()
    )


class TestTheOutcomeMatrix:
    @pytest.mark.parametrize(
        "outcome,status",
        [
            (CheckOutcome.PASS, "pass"),
            (CheckOutcome.FAIL, "fail"),
            (CheckOutcome.NOT_APPLICABLE, "not_applicable"),
            (CheckOutcome.MANUAL_REVIEW, "manual_review"),
        ],
    )
    def test_each_verdict_reaches_the_finding(
        self, db_session, benchmark_env, outcome, status
    ):
        _sync(db_session, benchmark_env, [a_result(benchmark_env, outcome)])
        rows = _findings(db_session, benchmark_env)
        assert len(rows) == 1
        assert rows[0].status == status

    def test_an_error_is_not_assessed_and_says_why(self, db_session, benchmark_env):
        """
        The column has no `error` member and must not gain one. `manual_review`
        with the reason recorded is the honest storage.
        """
        _sync(
            db_session,
            benchmark_env,
            [a_result(benchmark_env, CheckOutcome.ERROR, error="Access is denied")],
        )
        row = _findings(db_session, benchmark_env)[0]
        assert row.status == "manual_review"
        assert row.evidence["outcome"] == "error"
        assert row.evidence["assessed"] is False
        assert "Access is denied" in row.evidence["not_assessed_reason"]

    def test_an_error_is_distinguishable_from_a_genuine_manual_review(
        self, db_session, benchmark_env
    ):
        """
        Both store as `manual_review`. Only the payload separates "nobody could
        check this" from "this always needed a person".
        """
        _sync(db_session, benchmark_env, [a_result(benchmark_env, CheckOutcome.ERROR)])
        errored = _findings(db_session, benchmark_env)[0].evidence["outcome"]
        _sync(
            db_session,
            benchmark_env,
            [a_result(benchmark_env, CheckOutcome.MANUAL_REVIEW)],
        )
        manual = _findings(db_session, benchmark_env)[0].evidence["outcome"]
        assert errored == "error"
        assert manual == "manual_review"

    def test_no_outcome_ever_produces_a_status_the_column_rejects(
        self, db_session, benchmark_env
    ):
        allowed = {
            "pass",
            "fail",
            "not_applicable",
            "manual_review",
            "exception",
            "remediation_applied",
            "pending_reverify",
        }
        for outcome in CheckOutcome:
            _sync(db_session, benchmark_env, [a_result(benchmark_env, outcome)])
            assert _findings(db_session, benchmark_env)[0].status in allowed


class TestUnavailableEvidenceNeverBecomesAVerdict:
    def test_an_unreadable_check_is_not_a_pass(self, db_session, benchmark_env):
        _sync(db_session, benchmark_env, [a_result(benchmark_env, CheckOutcome.ERROR)])
        assert _findings(db_session, benchmark_env)[0].status != "pass"

    def test_an_unreadable_check_is_not_a_fail(self, db_session, benchmark_env):
        """
        The direction that reaches a customer as a false positive — a control
        reported breached on a host nobody could read.
        """
        _sync(db_session, benchmark_env, [a_result(benchmark_env, CheckOutcome.ERROR)])
        assert _findings(db_session, benchmark_env)[0].status != "fail"

    def test_a_failure_whose_evidence_was_lost_degrades_to_not_assessed(
        self, db_session, benchmark_env
    ):
        """
        A stored row that lost its evidence cannot support a finding anybody
        could defend, so it reports as unassessed rather than as a bare
        accusation.
        """
        stored = {
            "check_id": benchmark_env["rule_id"],
            "outcome": "fail",
            "title": "A benchmark recommendation",
            "severity": "high",
            "evidence": [],
        }
        _sync(db_session, benchmark_env, [stored])
        row = _findings(db_session, benchmark_env)[0]
        assert row.status == "manual_review"
        assert "no evidence" in row.evidence["not_assessed_reason"]

    def test_an_unknown_outcome_is_skipped_rather_than_guessed(
        self, db_session, benchmark_env
    ):
        summary = _sync(
            db_session,
            benchmark_env,
            [{"check_id": benchmark_env["rule_id"], "outcome": "probably_fine"}],
        )
        assert summary.findings_written == 0
        assert summary.unmapped_results == 1
        assert _findings(db_session, benchmark_env) == []


class TestEvidenceIsCarriedThrough:
    def test_expected_and_observed_reach_the_finding(self, db_session, benchmark_env):
        """
        "Why did CCURE mark this FAIL?" has to be answerable from the stored
        row alone.
        """
        _sync(db_session, benchmark_env, [a_result(benchmark_env, CheckOutcome.FAIL)])
        observation = _findings(db_session, benchmark_env)[0].evidence["observations"][
            0
        ]
        assert observation["expected"] == "equals 1"
        assert observation["observed"] == "0"
        assert observation["collector"] == "windows_registry"
        assert observation["collected_at"]

    def test_the_remediation_travels_with_the_verdict(self, db_session, benchmark_env):
        _sync(db_session, benchmark_env, [a_result(benchmark_env, CheckOutcome.FAIL)])
        assert (
            _findings(db_session, benchmark_env)[0].evidence["remediation"]
            == "Set it to 1."
        )

    def test_the_severity_reaches_the_finding_for_risk(self, db_session, benchmark_env):
        _sync(db_session, benchmark_env, [a_result(benchmark_env, CheckOutcome.FAIL)])
        assert _findings(db_session, benchmark_env)[0].evidence["severity"] == "high"

    def test_the_finding_names_its_rule(self, db_session, benchmark_env):
        _sync(db_session, benchmark_env, [a_result(benchmark_env, CheckOutcome.FAIL)])
        assert (
            _findings(db_session, benchmark_env)[0].rule_id == benchmark_env["rule_id"]
        )


class TestGating:
    def test_a_result_matching_no_rule_is_not_invented_a_control(
        self, db_session, benchmark_env
    ):
        """
        A built-in check has no benchmark control to answer for. It is still a
        security finding; attaching it to an arbitrary control would put a
        verdict on a framework nobody mapped it to.
        """
        orphan = a_result(benchmark_env, CheckOutcome.FAIL)
        orphan.check_id = "ccure.win.uac.enabled"
        summary = _sync(db_session, benchmark_env, [orphan])
        assert summary.unmapped_results == 1
        assert summary.findings_written == 0

    def test_a_tenant_without_the_framework_installed_gets_no_findings(
        self, db_session, benchmark_env
    ):
        db_session.query(ComplianceTenantFramework).filter(
            ComplianceTenantFramework.tenant_id == benchmark_env["org_id"]
        ).update({"is_enabled": False})
        db_session.flush()
        summary = _sync(
            db_session, benchmark_env, [a_result(benchmark_env, CheckOutcome.FAIL)]
        )
        assert summary.findings_written == 0
        assert _findings(db_session, benchmark_env) == []

    def test_a_parked_framework_gets_no_findings(
        self, db_session, benchmark_env, monkeypatch
    ):
        """
        Writing findings for a parked catalogue would put a score on a
        framework the workspace cannot open.
        """
        from core import compliance_frameworks

        monkeypatch.setattr(
            compliance_frameworks, "is_active", lambda framework_id: False
        )
        summary = _sync(
            db_session, benchmark_env, [a_result(benchmark_env, CheckOutcome.FAIL)]
        )
        assert summary.findings_written == 0

    def test_an_empty_result_set_writes_nothing(self, db_session, benchmark_env):
        assert _sync(db_session, benchmark_env, []).findings_written == 0


class TestConvergence:
    def test_rescanning_updates_the_finding_rather_than_adding_one(
        self, db_session, benchmark_env
    ):
        """
        One row per (asset, control, rule). A second scan is the same control
        re-answered, not a second control.
        """
        _sync(db_session, benchmark_env, [a_result(benchmark_env, CheckOutcome.FAIL)])
        _sync(db_session, benchmark_env, [a_result(benchmark_env, CheckOutcome.PASS)])
        rows = _findings(db_session, benchmark_env)
        assert len(rows) == 1
        assert rows[0].status == "pass"

    def test_both_dict_and_object_results_are_accepted(self, db_session, benchmark_env):
        """
        The scan path stores the dict form on the asset and hands it back; the
        engine produces objects. Neither caller should have to remember which.
        """
        as_object = a_result(benchmark_env, CheckOutcome.FAIL)
        assert _sync(db_session, benchmark_env, [as_object]).findings_written == 1
        assert (
            _sync(db_session, benchmark_env, [as_object.as_dict()]).findings_written
            == 1
        )
