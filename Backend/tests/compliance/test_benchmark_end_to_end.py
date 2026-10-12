"""
tests/compliance/test_benchmark_end_to_end.py
─────────────────────────────────────────────────────────────────────────────
The whole Phase 4 chain, and the guards on the content that ships.

    pack file → framework/controls/rules → selection → engine → collector
        → evidence → verdict → compliance finding → security finding → risk
        → remediation

Run against the packs that actually ship, through the real collectors, with
only the transport stubbed. Everything between the JSON on disk and the row in
``compliance_findings`` is the production path.

The content guards matter as much as the chain. The shipped packs are CCURE's
own baseline and must never be mistaken for CIS Benchmarks — the tests below
pin the publisher, the licence and the explicit disclaimer, because a pack that
drifts into claiming CIS provenance is a false compliance claim in a customer's
audit report, which is the failure this whole phase was shaped to avoid.
"""

import json
import uuid
from dataclasses import dataclass

import pytest

from core.benchmarks import load_pack, load_pack_into_db
from core.benchmarks.selection import benchmark_checks_for_org
from core.checks.contract import CheckOutcome
from core.compliance_seeds import seed_path
from core.config_audit import CollectionContext, ConfigAuditEngine
from core.compliance_sync import sync_config_audit_findings
from core.config_audit.findings import findings_from_results
from db.models.assets import Asset
from db.models.compliance import (
    ComplianceControl,
    ComplianceFinding,
    ComplianceFramework,
    ComplianceRule,
    ComplianceTenantFramework,
)
from db.models.rbac import Organization
from scans.finding_normalizer import RemediationConfidence
from testpaths import BACKEND_ROOT

BENCHMARK_DIR = BACKEND_ROOT / "data" / "benchmarks"
WINDOWS_PACK = BENCHMARK_DIR / "ccure_windows_baseline.benchmark.json"
LINUX_PACK = BENCHMARK_DIR / "ccure_linux_baseline.benchmark.json"


@dataclass
class FakeResult:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    success: bool = True


class FakeExecutor:
    """
    UAC reads back non-compliant, the firewall service reads back compliant,
    everything else cannot be read at all.

    That mixture is deliberate: it produces a FAIL, a PASS and a set of
    unreadable checks in one run, which is what lets a single scan assert that
    the third group does not become either of the first two.
    """

    def connect(self):
        pass

    def disconnect(self):
        pass

    def run(self, command, timeout=None):
        if "PSVersionTable" in command:
            return FakeResult(stdout="5")
        if "EnableLUA" in command:
            return FakeResult(stdout="CCURE::VALUE::0")
        if "MpsSvc" in command:
            return FakeResult(stdout="CCURE::VALUE::Running")
        return FakeResult(stderr="not stubbed", exit_code=1, success=False)


@pytest.fixture
def installed_benchmark(db_session):
    pack = load_pack(WINDOWS_PACK)
    load_pack_into_db(db_session, pack, commit=False)

    org_id = f"org_e2e_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Organization(
            id=org_id,
            name=f"E2E {org_id}",
            slug=org_id.replace("_", "-"),
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
    asset_id = f"ast_{org_id}_10_0_0_7"
    db_session.add(
        Asset(id=asset_id, org_id=org_id, ip_address="10.0.0.7", hostname="e2e-host")
    )
    db_session.flush()

    yield {"pack": pack, "org_id": org_id, "asset_id": asset_id}

    db_session.query(ComplianceFinding).filter(
        ComplianceFinding.tenant_id == org_id
    ).delete()
    db_session.query(ComplianceFramework).filter(
        ComplianceFramework.id == pack.framework_id
    ).delete()
    db_session.query(ComplianceRule).filter(
        ComplianceRule.id.like("rule_ccure_windows_baseline%")
    ).delete(synchronize_session=False)
    db_session.query(Asset).filter(Asset.org_id == org_id).delete()
    db_session.query(Organization).filter(Organization.id == org_id).delete()
    db_session.commit()


def run_chain(db_session, env):
    checks = benchmark_checks_for_org(db_session, env["org_id"])
    context = CollectionContext(
        target="10.0.0.7",
        platform="windows",
        executor=FakeExecutor(),
        asset_id=env["asset_id"],
        org_id=env["org_id"],
    )
    report = ConfigAuditEngine().run(checks, context)
    summary = sync_config_audit_findings(
        db_session,
        org_id=env["org_id"],
        asset_id=env["asset_id"],
        results=report.results,
    )
    db_session.flush()
    return checks, report, summary


class TestTheWholeChain:
    def test_benchmark_content_reaches_the_engine(
        self, db_session, installed_benchmark
    ):
        checks, _report, _summary = run_chain(db_session, installed_benchmark)
        assert len(checks) == 10, [c.check_id for c in checks]
        # The check id *is* the rule id, which is what lets the sync find the
        # rule again without a second mapping table.
        assert all(c.check_id.startswith("rule_ccure_windows_baseline") for c in checks)

    def test_the_engine_produces_a_mixture_of_real_outcomes(
        self, db_session, installed_benchmark
    ):
        _checks, report, _summary = run_chain(db_session, installed_benchmark)
        counts = report.counts
        assert counts["pass"] == 1
        assert counts["fail"] == 1
        assert counts["error"] == 8
        # Verdicts only: the eight unreadable checks are excluded from both
        # halves of the fraction rather than counted as failures.
        assert report.compliance_score() == 50.0

    def test_verdicts_land_in_compliance_findings(
        self, db_session, installed_benchmark
    ):
        _checks, _report, summary = run_chain(db_session, installed_benchmark)
        assert summary.findings_written == 10
        assert summary.controls_covered == 10
        assert summary.by_status == {"pass": 1, "fail": 1, "manual_review": 8}

    def test_every_finding_is_attached_to_its_benchmark_control(
        self, db_session, installed_benchmark
    ):
        run_chain(db_session, installed_benchmark)
        rows = (
            db_session.query(ComplianceFinding, ComplianceControl)
            .join(
                ComplianceControl,
                ComplianceControl.id == ComplianceFinding.control_id,
            )
            .filter(ComplianceFinding.tenant_id == installed_benchmark["org_id"])
            .all()
        )
        assert len(rows) == 10
        assert all(
            c.framework_id == installed_benchmark["pack"].framework_id for _f, c in rows
        )

    def test_the_failure_can_be_defended_from_the_stored_row_alone(
        self, db_session, installed_benchmark
    ):
        """
        "Why did CCURE mark this FAIL?" answered without re-running anything.
        """
        run_chain(db_session, installed_benchmark)
        failure = (
            db_session.query(ComplianceFinding)
            .filter(
                ComplianceFinding.tenant_id == installed_benchmark["org_id"],
                ComplianceFinding.status == "fail",
            )
            .one()
        )
        observation = failure.evidence["observations"][0]
        assert observation["expected"] == "EnableLUA = 1"
        assert observation["observed"] == "0"
        assert observation["collector"] == "windows_registry"
        assert observation["collected_at"]
        assert failure.evidence["remediation"]

    def test_the_failure_also_becomes_a_security_finding(
        self, db_session, installed_benchmark
    ):
        """
        Same failing control, two destinations: a compliance verdict and an
        ordinary finding ranked beside the CVEs on the same host.
        """
        _checks, report, _summary = run_chain(db_session, installed_benchmark)
        findings = findings_from_results(report.results)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.plugin_id.startswith("CCURE-CFG-")
        assert finding.severity == "High"
        assert finding.host == "10.0.0.7"

    def test_the_security_finding_carries_actionable_remediation(
        self, db_session, installed_benchmark
    ):
        _checks, report, _summary = run_chain(db_session, installed_benchmark)
        remediation = findings_from_results(report.results)[0].remediation
        assert remediation is not None
        assert remediation.confidence is RemediationConfidence.CONFIGURATION_GUIDANCE
        assert remediation.is_actionable
        assert "EnableLUA" in remediation.summary

    def test_severity_flows_into_the_risk_path(self, db_session, installed_benchmark):
        """
        The rule's severity becomes the finding's, in the canonical vocabulary
        the risk model already ranks on — no separate benchmark risk scale.
        """
        from scans.cvss import SEVERITY_RANK

        _checks, report, _summary = run_chain(db_session, installed_benchmark)
        finding = findings_from_results(report.results)[0]
        assert SEVERITY_RANK[finding.severity] == SEVERITY_RANK["High"]

    def test_passing_and_unreadable_controls_produce_no_security_finding(
        self, db_session, installed_benchmark
    ):
        """
        A pass is a compliance verdict, not a vulnerability, and an unreadable
        check is not a verdict at all.
        """
        _checks, report, _summary = run_chain(db_session, installed_benchmark)
        assert len(findings_from_results(report.results)) == 1


class TestTheHonestDirections:
    def test_eight_unreadable_checks_became_neither_pass_nor_fail(
        self, db_session, installed_benchmark
    ):
        run_chain(db_session, installed_benchmark)
        statuses = [
            f.status
            for f in db_session.query(ComplianceFinding)
            .filter(ComplianceFinding.tenant_id == installed_benchmark["org_id"])
            .all()
        ]
        assert statuses.count("manual_review") == 8
        assert statuses.count("pass") == 1
        assert statuses.count("fail") == 1

    def test_a_host_that_answers_nothing_scores_nothing(
        self, db_session, installed_benchmark
    ):
        """
        None, not 0% and not 100%. Both numbers are assertions nobody
        established about a host the scanner could not read.
        """

        class Unreachable(FakeExecutor):
            def run(self, command, timeout=None):
                if "PSVersionTable" in command:
                    return FakeResult(stdout="5")
                return FakeResult(stderr="denied", exit_code=5, success=False)

        checks = benchmark_checks_for_org(db_session, installed_benchmark["org_id"])
        report = ConfigAuditEngine().run(
            checks,
            CollectionContext(
                target="10.0.0.7", platform="windows", executor=Unreachable()
            ),
        )
        assert report.compliance_score() is None
        assert report.counts["fail"] == 0
        assert report.counts["pass"] == 0

    def test_a_windows_benchmark_is_not_dispatched_at_a_linux_host(
        self, db_session, installed_benchmark
    ):
        checks = benchmark_checks_for_org(db_session, installed_benchmark["org_id"])
        report = ConfigAuditEngine().run(
            checks,
            CollectionContext(
                target="10.0.0.7", platform="linux", executor=FakeExecutor()
            ),
        )
        assert report.counts["not_applicable"] == len(checks)
        assert report.counts["fail"] == 0


class TestProfileScoping:
    def test_selection_can_narrow_to_a_profile(self, db_session, installed_benchmark):
        every = benchmark_checks_for_org(db_session, installed_benchmark["org_id"])
        level_one = benchmark_checks_for_org(
            db_session, installed_benchmark["org_id"], profile="L1"
        )
        level_two = benchmark_checks_for_org(
            db_session, installed_benchmark["org_id"], profile="L2"
        )
        assert len(every) == 10
        assert len(level_one) == 8
        assert len(level_two) == 2
        assert {c.check_id for c in level_two} <= {c.check_id for c in every}

    def test_an_unknown_profile_selects_only_unscoped_controls(
        self, db_session, installed_benchmark
    ):
        """
        Controls naming no profile stay in scope; ones naming a real profile
        drop out. Under-selecting is the safe direction — it under-reports
        coverage rather than assessing against a profile nobody chose.
        """
        assert (
            benchmark_checks_for_org(
                db_session, installed_benchmark["org_id"], profile="L9"
            )
            == []
        )


class TestPhase3StillBehavesAsItDid:
    def test_builtin_checks_run_alongside_benchmark_checks(
        self, db_session, installed_benchmark
    ):
        """
        Phase 4 adds content; it does not replace the built-in pack. A
        regression here would silently drop twenty checks from every scan.
        """
        from core.tasks import _run_configuration_audit

        extra = benchmark_checks_for_org(db_session, installed_benchmark["org_id"])
        summary, _findings = _run_configuration_audit(
            executor=FakeExecutor(),
            ip="10.0.0.7",
            os_type="windows",
            system_data={},
            extra_checks=extra,
        )
        from core.config_audit.builtin import builtin_checks

        expected_builtin = len(
            [c for c in builtin_checks() if c.applies_to_platform("windows")]
        )
        assert summary["benchmark_checks"] == 10
        # Derived rather than hardcoded: Phase 5 added privilege checks to the
        # built-in pack and this assertion was a magic 20 that silently became
        # wrong. What matters is that the benchmark content is *added to* the
        # built-ins, not that either count is a particular number.
        assert summary["checks_run"] == expected_builtin + 10

    def test_a_scan_with_no_benchmark_installed_still_runs_the_builtins(self):
        from core.tasks import _run_configuration_audit

        summary, _findings = _run_configuration_audit(
            executor=FakeExecutor(), ip="10.0.0.7", os_type="windows", system_data={}
        )
        from core.config_audit.builtin import builtin_checks

        expected_builtin = len(
            [c for c in builtin_checks() if c.applies_to_platform("windows")]
        )
        assert summary["benchmark_checks"] == 0
        assert summary["checks_run"] == expected_builtin


class TestTheShippedPacksAreWhatTheyClaim:
    @pytest.mark.parametrize("path", [WINDOWS_PACK, LINUX_PACK])
    def test_each_pack_parses(self, path):
        pack = load_pack(path)
        assert pack.controls
        assert pack.profiles

    @pytest.mark.parametrize("path", [WINDOWS_PACK, LINUX_PACK])
    def test_no_shipped_pack_claims_to_be_a_cis_benchmark(self, path):
        """
        The single most important property of the content that ships. A pack
        drifting into claiming CIS provenance is a false compliance claim.
        """
        pack = load_pack(path)
        assert pack.publisher == "CCURE Audit PRO"
        assert "not a CIS Benchmark" in pack.licence
        assert not pack.code.startswith("CIS_")
        assert "CIS" not in pack.name

    @pytest.mark.parametrize("path", [WINDOWS_PACK, LINUX_PACK])
    def test_every_crosswalk_resolves_to_a_real_cis_safeguard(self, path):
        """
        CLAUDE.md records thirteen ISO crosswalks that named ids the target
        catalogue does not use; each resolved to nothing in gap analysis and in
        cross-framework inheritance, silently.
        """
        with open(seed_path("cis_v8_1_controls_seed.json"), encoding="utf-8") as fh:
            known = {str(c["id"]) for c in json.load(fh)["controls"]}
        dangling = []
        for control in load_pack(path).controls:
            for target in control.crosswalk:
                code, _, safeguard = target.partition(":")
                if code == "CIS_V8_1" and safeguard not in known:
                    dangling.append(f"{control.control_id} -> {target}")
        assert not dangling, dangling

    @pytest.mark.parametrize("path", [WINDOWS_PACK, LINUX_PACK])
    def test_every_automated_control_has_remediation_and_a_rationale(self, path):
        missing = [
            c.control_id
            for c in load_pack(path).controls
            if c.is_automated and (not c.remediation or not c.rationale)
        ]
        assert not missing, missing

    @pytest.mark.parametrize("path", [WINDOWS_PACK, LINUX_PACK])
    def test_unimplemented_controls_say_why(self, path):
        for control in load_pack(path).controls:
            if control.assessment == "unimplemented":
                assert control.unimplemented_reason

    def test_the_committed_packs_match_their_generator(self):
        """
        The packs are generated from the built-in rules. Editing the JSON by
        hand would let the two disagree, and the JSON is what loads.
        """
        import subprocess
        import sys

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.benchmarks.build_baseline_packs",
                "--check",
            ],
            cwd=str(BACKEND_ROOT),
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr


class TestOperatingSystemTargeting:
    """
    ``platforms`` distinguishes Windows from Linux and no further. Benchmark
    content needs more: a CIS Ubuntu 22.04 benchmark and a CIS RHEL 9 benchmark
    are both ``linux``, and running one against the other's host checks paths
    and package names that distribution does not use — then reads their absence
    as a verdict. Confident, wrong findings.
    """

    def _pack(self, **applies_to):
        from core.benchmarks.pack import parse_pack

        return parse_pack(
            {
                "benchmark": {
                    "code": "OS_TARGET_TEST",
                    "name": "OS Target Test",
                    "version": "1.0.0",
                    "platform": "linux",
                    "publisher": "Test",
                    "licence": "Test",
                    "profiles": [{"id": "L1"}],
                    "applies_to": applies_to,
                },
                "controls": [
                    {
                        "control_id": "1.1",
                        "title": "A distribution-specific recommendation",
                        "assessment": "automated",
                        "severity": "medium",
                        "check": {
                            "check_type": "file",
                            "collect": {"path": "/etc/example"},
                            "operator": "equals",
                            "expected": "1",
                            "absent": "fail",
                            "platforms": ["linux"],
                        },
                    }
                ],
            }
        )

    def _run(self, pack, os_name, os_version_id):
        checks = [c.check for c in pack.controls if c.check]
        return ConfigAuditEngine().run(
            checks,
            CollectionContext(
                target="10.0.0.8",
                platform="linux",
                os_name=os_name,
                os_version_id=os_version_id,
                executor=FakeExecutor(),
            ),
        )

    def test_a_pack_declares_its_operating_system_once(self):
        pack = self._pack(os_name_contains=["ubuntu"])
        assert pack.controls[0].check.os_match == {"os_name_contains": ["ubuntu"]}

    def test_the_wrong_distribution_is_not_applicable_not_a_finding(self):
        report = self._run(
            self._pack(os_name_contains=["ubuntu"]), "Rocky Linux 9.8", "9.8"
        )
        assert report.counts["not_applicable"] == 1
        assert report.counts["fail"] == 0
        assert report.counts["pass"] == 0

    def test_the_right_distribution_is_assessed(self):
        report = self._run(
            self._pack(os_name_contains=["ubuntu"]), "Ubuntu 22.04.4 LTS", "22.04"
        )
        assert report.counts["not_applicable"] == 0
        # The stub cannot read the file, so it errors — the point is that the
        # check was dispatched rather than skipped.
        assert report.counts["error"] == 1

    def test_version_targeting_separates_two_releases(self):
        pack = self._pack(os_name_contains=["ubuntu"], os_version_prefix=["22.04"])
        assert (
            self._run(pack, "Ubuntu 22.04.4 LTS", "22.04").counts["not_applicable"] == 0
        )
        assert (
            self._run(pack, "Ubuntu 24.04.1 LTS", "24.04").counts["not_applicable"] == 1
        )

    def test_an_unidentified_os_is_an_error_not_a_skip(self):
        """
        "We could not tell what this host runs" is not "this host is not what
        the benchmark is for". Only the second is a reason for a control to
        leave the score; the first is a fingerprinting gap and must show as one.
        """
        report = self._run(self._pack(os_name_contains=["ubuntu"]), "", "")
        assert report.counts["error"] == 1
        assert report.counts["not_applicable"] == 0
        assert "not identified" in report.results[0].error

    def test_a_pack_with_no_os_constraint_runs_everywhere(self):
        """Every Phase 3 built-in is in this category and must stay so."""
        pack = self._pack()
        assert pack.controls[0].check.os_match == {}
        assert self._run(pack, "Rocky Linux 9.8", "9.8").counts["not_applicable"] == 0

    def test_an_unsupported_targeting_key_is_refused(self):
        """
        A key nothing reads would look like targeting while constraining
        nothing — a benchmark that appears scoped and is not.
        """
        from core.benchmarks.pack import PackError

        with pytest.raises(PackError, match="unsupported"):
            self._pack(os_familly=["linux"])


class TestBenchmarkResolutionIsDefensive:
    """
    Resolving benchmark content must not be able to fail a scan whose findings
    are already collected.

    Regression: the first version of this resolved `scan_row.org_id`
    unconditionally at the top of `_apply_credentialed_enrichment`, which
    crashed five existing tests that hand the function a stand-in scan row —
    and would have crashed a real scan for any row without an organisation.
    The findings are the customer's deliverable; losing them to a
    compliance-content lookup is the wrong trade.
    """

    def test_a_scan_row_without_an_organisation_does_not_crash_enrichment(
        self, db_session
    ):
        from core import tasks

        # The same stand-in shape `tests/credentialed/test_credentialed_end_to_end`
        # supplies: an id and options, and deliberately no org_id. Returning
        # None (an ordinary unauthenticated audit) rather than raising is the
        # assertion.
        class _ScanRow:
            id = "scn_no_org"
            options = {}

        assert tasks._apply_credentialed_enrichment(db_session, _ScanRow(), []) is None

    def test_resolution_happens_after_the_no_credentials_early_return(self):
        """
        A scan with no credentials configured returns long before the host
        loop and must not pay for a query whose result it never uses.
        """
        import inspect

        from core import tasks

        source = inspect.getsource(tasks._apply_credentialed_enrichment)
        plan_at = source.index("plan = _credentialed_plan_for_scan")
        # Anchored on the call, not on its argument list. GAP-12 made this a
        # multi-line call — it now passes the scan's effective policy — and an
        # anchor that spelled out the arguments broke on a change that did not
        # touch the ordering this test exists to pin.
        resolve_at = source.index("benchmark_checks_for_org(")
        assert plan_at < resolve_at

        # The policy snapshot is read on the same path and must be behind the
        # same early return, for the same reason: a scan with no credentials
        # pays for neither.
        policy_at = source.index("read_policy_snapshot(scan_row)")
        assert plan_at < policy_at
