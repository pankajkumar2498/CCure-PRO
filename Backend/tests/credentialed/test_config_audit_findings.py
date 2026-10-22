"""
tests/credentialed/test_config_audit_findings.py
─────────────────────────────────────────────────────────────────────────────
Where a configuration check result joins the paths this product already has:
the finding model, and the compliance verdict.

The thing being defended here is that there is exactly one of each. Phase 0
widened ``vulnerability_definitions`` to admit ``config_check`` rows precisely
so a CIS control would not need a findings table of its own — and a findings
table of its own is what brings a second risk model and a second report
generator behind it.

The end-to-end class at the bottom drives ``audit_credentialed_host`` with a
stub transport, which is the only place the wiring is actually visible: that a
configuration failure lands in ``cve_list`` beside the CVEs, that the summary
reaches the stored report, and that a configuration audit which does not run
says so rather than leaving a silent zero.
"""

from dataclasses import dataclass
from unittest.mock import patch

import pytest

from core.checks.contract import CheckOutcome, CheckResult, Evidence
from core.config_audit import AbsencePolicy, ConfigCheck, Expectation
from core.config_audit.findings import (
    CONFIG_PLUGIN_FAMILY,
    catalogue_row,
    compliance_verdict,
    finding_from_result,
    findings_from_results,
)
from scans.finding_normalizer import (
    Confidence,
    DetectionMethod,
    RemediationConfidence,
)


def a_check(**overrides) -> ConfigCheck:
    params = dict(
        check_id="ccure.win.uac.enabled",
        title="User Account Control is enabled",
        check_type="registry",
        platforms=("windows",),
        severity="high",
        collect={"path": r"HKLM\SOFTWARE\X", "value": "EnableLUA"},
        expect=Expectation("equals", 1),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="UAC mediates elevation.",
        rationale="Without it, any admin process runs fully elevated.",
        remediation="Set EnableLUA to 1.",
        references=("https://example.invalid/uac",),
    )
    params.update(overrides)
    return ConfigCheck(**params)


def a_result(outcome=CheckOutcome.FAIL, **overrides) -> CheckResult:
    params = dict(
        check_id="ccure.win.uac.enabled",
        outcome=outcome,
        title="User Account Control is enabled",
        severity="high",
        target="10.0.0.1",
        evidence=[
            Evidence(
                collector="windows_registry",
                description="User Account Control is enabled",
                expected="EnableLUA = 1",
                observed="0",
                raw="CCURE::VALUE::0",
            )
        ],
        remediation="Set EnableLUA to 1.",
        references=["https://example.invalid/uac"],
    )
    params.update(overrides)
    if params["outcome"] is CheckOutcome.ERROR:
        params.setdefault("error", "could not read the value")
    return CheckResult(**params)


class TestOnlyAFailureBecomesAFinding:
    def test_a_failure_produces_a_standardized_finding(self):
        finding = finding_from_result(a_result(), check=a_check())
        assert finding is not None
        assert finding.plugin_family == CONFIG_PLUGIN_FAMILY
        assert finding.host == "10.0.0.1"
        assert finding.severity == "High"

    @pytest.mark.parametrize(
        "outcome",
        [
            CheckOutcome.PASS,
            CheckOutcome.NOT_APPLICABLE,
            CheckOutcome.MANUAL_REVIEW,
            CheckOutcome.ERROR,
        ],
    )
    def test_nothing_else_does(self, outcome):
        """
        A pass is a compliance verdict, not a vulnerability. The other three
        are not verdicts at all. Returning None rather than a suppressed
        finding means a caller cannot forget to filter.
        """
        assert finding_from_result(a_result(outcome=outcome)) is None

    def test_the_batch_helper_filters_the_same_way(self):
        results = [a_result(), a_result(outcome=CheckOutcome.PASS, check_id="b")]
        assert len(findings_from_results(results)) == 1


class TestTheFindingCarriesWhatATriagerNeeds:
    def test_the_identifier_is_a_minted_ccure_id_not_a_cve(self):
        """
        The vendor prefix tells a reader the identifier is ours and that NVD
        has never heard of it.
        """
        finding = finding_from_result(a_result(), check=a_check())
        assert finding.plugin_id.startswith("CCURE-CFG-")
        assert not finding.cve_ids

    def test_the_evidence_states_expected_beside_observed(self):
        finding = finding_from_result(a_result(), check=a_check())
        assert "Expected: EnableLUA = 1" in finding.evidence
        assert "Observed: 0" in finding.evidence
        assert finding.evidence_available

    def test_detection_is_config_check_at_confirmed_confidence(self):
        finding = finding_from_result(a_result(), check=a_check())
        assert finding.detection_method is DetectionMethod.CONFIG_CHECK
        assert finding.confidence is Confidence.CONFIRMED

    def test_remediation_is_marked_as_configuration_guidance(self):
        """
        Not NONE_PUBLISHED, which the report renders as "no published fix —
        compensating controls only". That is true of an unpatched CVE and
        false of a hardening control, where the fix is known and available now.
        """
        finding = finding_from_result(a_result(), check=a_check())
        assert (
            finding.remediation.confidence
            is RemediationConfidence.CONFIGURATION_GUIDANCE
        )
        assert finding.remediation.is_actionable

    def test_a_configuration_finding_carries_no_port(self):
        """
        A host-level control is not a property of a listening service.
        Inventing a port would file it against a service it has nothing to do
        with.
        """
        assert finding_from_result(a_result(), check=a_check()).port is None

    def test_the_description_carries_the_rules_own_narrative(self):
        finding = finding_from_result(a_result(), check=a_check())
        assert "mediates elevation" in finding.description
        assert "fully elevated" in finding.description

    def test_evidence_is_redacted_on_the_way_through(self):
        """
        Collected configuration is exactly where credentials turn up — a
        connection string, an unattended-install answer file — and this object
        reaches the database and the report.
        """
        result = a_result(
            evidence=[
                Evidence(
                    collector="windows_file",
                    description="An answer file",
                    expected="absent",
                    observed="present",
                    raw="password=SuperSecret123",
                )
            ]
        )
        assert "SuperSecret123" not in finding_from_result(result).evidence


class TestTheComplianceVerdict:
    @pytest.mark.parametrize(
        "outcome,status",
        [
            (CheckOutcome.PASS, "pass"),
            (CheckOutcome.FAIL, "fail"),
            (CheckOutcome.NOT_APPLICABLE, "not_applicable"),
            (CheckOutcome.MANUAL_REVIEW, "manual_review"),
        ],
    )
    def test_the_four_storable_outcomes_need_no_translation(self, outcome, status):
        """
        ``CheckOutcome`` spells these exactly as ``compliance_findings.status``
        does, so no mapping table stands between the two — and a mapping table
        is how two vocabularies for one idea begin.
        """
        assert compliance_verdict(a_result(outcome=outcome))["status"] == status

    def test_an_error_is_stored_as_manual_review_with_its_reason(self):
        """
        The status column has no ``error`` member and must not gain one: it
        would be a claim about a host that nothing established.
        """
        verdict = compliance_verdict(a_result(outcome=CheckOutcome.ERROR))
        assert verdict["status"] == "manual_review"
        assert verdict["evidence"]["outcome"] == "error"
        assert verdict["evidence"]["assessed"] is False
        assert verdict["evidence"]["not_assessed_reason"]

    def test_an_error_and_a_genuine_manual_review_stay_distinguishable(self):
        """
        Both store as ``manual_review``. The evidence payload is what lets a
        reader tell "nobody could check this" from "this always needed a
        person".
        """
        errored = compliance_verdict(a_result(outcome=CheckOutcome.ERROR))
        manual = compliance_verdict(a_result(outcome=CheckOutcome.MANUAL_REVIEW))
        assert errored["status"] == manual["status"] == "manual_review"
        assert errored["evidence"]["outcome"] != manual["evidence"]["outcome"]

    def test_the_verdict_carries_the_observations(self):
        verdict = compliance_verdict(a_result())
        observation = verdict["evidence"]["observations"][0]
        assert observation["expected"] == "EnableLUA = 1"
        assert observation["observed"] == "0"

    def test_a_status_the_column_would_reject_is_never_produced(self):
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
            assert compliance_verdict(a_result(outcome=outcome))["status"] in allowed


class TestTheCatalogueRow:
    def test_a_check_is_filed_as_config_check_with_no_cve_id(self):
        """
        ``ck_vuln_def_cve_id_matches_type`` requires this. Filing a check as a
        ``cve`` row would give it KEV lookups, EPSS scores, CVSS bands and an
        NVD link that resolves to nothing.
        """
        row = catalogue_row(a_check())
        assert row["definition_type"] == "config_check"
        assert row["cve_id"] is None
        assert row["id"].startswith("CCURE-CFG-")

    def test_two_spellings_of_one_check_id_produce_one_row(self):
        a = catalogue_row(a_check(check_id="cis.win.2.3.1.1"))
        b = catalogue_row(a_check(check_id="cis_win_2_3_1_1"))
        assert a["id"] == b["id"]

    def test_an_unmintable_id_degrades_to_the_raw_id_rather_than_raising(self):
        """
        One badly named rule must not abort the persistence of every other
        finding on the host.
        """
        row = catalogue_row(a_check(check_id="x" * 200))
        assert row["id"] == "x" * 200


# ─────────────────────────────────────────────────────────────────────────────
# End to end, through the real credentialed audit
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class FakeResult:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    success: bool = True


class TestConfigurationAuditRunsInsideTheCredentialedScan:
    """
    Drives ``_run_configuration_audit`` — the function
    ``audit_credentialed_host`` calls on the session the collectors just used.
    """

    class _Executor:
        def __init__(self, table):
            self.table = table

        def connect(self):
            pass

        def disconnect(self):
            pass

        def run(self, command, timeout=None):
            if "PSVersionTable" in command:
                return FakeResult(stdout="5")
            for needle, response in self.table.items():
                if needle in command:
                    return response
            return FakeResult(stderr="no stub", exit_code=1, success=False)

    def _run(self, table, system_data=None):
        from scans.tasks.credentialed import _run_configuration_audit

        return _run_configuration_audit(
            executor=self._Executor(table),
            ip="10.0.0.1",
            os_type="windows",
            system_data=system_data or {},
        )

    def test_a_misconfigured_host_produces_findings_shaped_like_the_others(self):
        summary, findings = self._run(
            {"EnableLUA": FakeResult(stdout="CCURE::VALUE::0")}
        )
        assert summary["assessed"] is True
        uac = [f for f in findings if "UAC" in f["cve_id"]]
        assert uac, [f["cve_id"] for f in findings]
        finding = uac[0]
        # The keys the report and risk paths read off every other finding.
        for key in (
            "cve_id",
            "severity",
            "description",
            "detection_method",
            "remediation",
        ):
            assert key in finding
        assert finding["detection_method"] == "config_check"
        assert finding["definition_type"] == "config_check"
        assert finding["expected_state"] and finding["observed_state"]

    def test_a_compliant_setting_produces_no_finding_for_that_check(self):
        _, findings = self._run({"EnableLUA": FakeResult(stdout="CCURE::VALUE::1")})
        assert not [f for f in findings if "UAC" in f["cve_id"]]

    def test_an_unreachable_host_produces_errors_rather_than_findings(self):
        """
        Every check reports ERROR, so nothing becomes a finding — and the
        score is None rather than 0% or 100%.
        """
        summary, findings = self._run({})
        assert findings == []
        assert summary["counts"]["error"] > 0
        assert summary["counts"]["pass"] == 0
        assert summary["counts"]["fail"] == 0
        assert summary["score_pct"] is None

    def test_the_summary_counts_verdicts_separately_from_checks_run(self):
        summary, _ = self._run({"EnableLUA": FakeResult(stdout="CCURE::VALUE::1")})
        assert summary["checks_run"] > summary["checks_assessed"]

    def test_the_platform_selects_the_rule_set(self):
        from scans.tasks.credentialed import _run_configuration_audit

        summary, _ = _run_configuration_audit(
            executor=self._Executor({}),
            ip="10.0.0.1",
            os_type="linux",
            system_data={},
        )
        assert summary["platform"] == "linux"
        # No Windows registry rule may be dispatched at a Linux host.
        assert all("win" not in r["check_id"] for r in summary["results"]), [
            r["check_id"] for r in summary["results"]
        ]

    def test_collected_inventory_is_reused_rather_than_re_read(self):
        """
        The credentialed collection already enumerated software and sockets. A
        rule set with many package checks must not repeat that read per rule.
        """
        summary, _ = self._run(
            {},
            system_data={
                "installed_software": [{"name": "7-Zip", "version": "23.01"}],
                "open_ports": [{"port": "3389"}],
                "password_policy": {"min_length": 14, "history_length": 24},
            },
        )
        by_id = {r["check_id"]: r for r in summary["results"]}
        # Answered from password_policy, with no session needed.
        assert by_id["ccure.win.password.minimum_length"]["outcome"] == "pass"
        assert by_id["ccure.win.password.history"]["outcome"] == "pass"

    def test_an_engine_failure_propagates_so_the_caller_can_record_it(self):
        """
        This function does not swallow. Its caller catches and records the
        omission — asserted for real in
        :class:`TestTheWholeCredentialedAuditEndToEnd` below, because
        swallowing here would leave the caller with an empty result that looks
        exactly like a clean host.
        """
        from scans.tasks.credentialed import _run_configuration_audit

        with patch(
            "core.config_audit.ConfigAuditEngine.run",
            side_effect=RuntimeError("engine exploded"),
        ):
            with pytest.raises(RuntimeError):
                _run_configuration_audit(
                    executor=self._Executor({}),
                    ip="10.0.0.1",
                    os_type="windows",
                    system_data={},
                )


class TestTheWholeCredentialedAuditEndToEnd:
    """
    ``audit_credentialed_host`` itself, with the transport and the collector
    stubbed and everything between them real.

    This is the only place the wiring is visible end to end: that configuration
    failures reach ``cve_list`` beside the CVE findings rather than a list of
    their own, that they are counted in the severity summary the report reads,
    that the per-check detail reaches the stored report, and that an audit
    which could not run says so.
    """

    def _audit(self, *, config_raises=False, system_data=None):
        from scans.tasks import credentialed as tasks  # reads the patched name

        collected = (
            system_data
            if system_data is not None
            else {
                "packages": [{"name": "openssl", "version": "3.0.7"}],
                "os_id": "rocky",
                "os_version_id": "9",
            }
        )

        class StubConnection:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def run(self, command, timeout=None):
                return FakeResult(stdout="")

        class StubCollector:
            def __init__(self, _ssh):
                pass

            def collect_all(self, sections=None, on_section_complete=None):
                return dict(collected)

        class StubMatcher:
            def match_packages(self, *_args, **_kwargs):
                return []

            def coverage(self):
                return {}

            def to_report_format(self, _findings):
                return []

        config_patch = (
            patch.object(
                tasks,
                "_run_configuration_audit",
                side_effect=RuntimeError("engine exploded"),
            )
            if config_raises
            else patch.object(
                tasks,
                "_run_configuration_audit",
                return_value=(
                    {
                        "assessed": True,
                        "platform": "linux",
                        "checks_run": 10,
                        "checks_assessed": 2,
                        "score_pct": 50.0,
                        "counts": {"pass": 1, "fail": 1, "error": 8},
                        "results": [],
                    },
                    [
                        {
                            "cve_id": "CCURE-CFG-CCURE-LINUX-SHADOW-PERMISSIONS",
                            "severity": "Critical",
                            "title": "/etc/shadow is not readable by unprivileged users",
                            "description": "…",
                            "detection_method": "config_check",
                            "package": "",
                        }
                    ],
                ),
            )
        )

        # The CVE-enrichment paths are stubbed as well, not because this test
        # cares about them but because they open connections to the `vuln_intel`
        # database. A test about configuration-audit wiring has no business
        # doing that: it makes the test depend on a feed database being present
        # and populated, and it consumes connections from a pool the rest of
        # the suite is sharing.
        with patch(
            "engines.credentialed.ssh_scanner.SSHScanner", return_value=StubConnection()
        ), patch(
            "engines.credentialed.linux_collector.LinuxCollector", StubCollector
        ), patch(
            "engines.credentialed.vuln_matcher.VulnMatcher", StubMatcher
        ), patch(
            "engines.credentialed.os_detection.detect_os", return_value="linux"
        ), patch(
            "core.vuln_intel.csaf_advisories_for", return_value={}
        ), patch(
            "core.vuln_intel.exploit_intel_for", return_value={}
        ), patch(
            "engines.credentialed.csaf_matcher.CsafProductMatcher"
        ) as csaf, config_patch:
            csaf.return_value.match.return_value = []
            csaf.return_value.coverage.return_value = {}
            return tasks.audit_credentialed_host(
                ip="10.0.0.1", username="u", password="p", port=22
            )

    def test_a_configuration_failure_is_in_the_same_finding_list_as_the_cves(self):
        report, _system_data, _os = self._audit()
        ids = [f.get("cve_id") for f in report["cves"]]
        assert "CCURE-CFG-CCURE-LINUX-SHADOW-PERMISSIONS" in ids

    def test_it_is_counted_in_the_severity_summary_the_report_reads(self):
        report, _system_data, _os = self._audit()
        assert report["severity_summary"]["Critical"] >= 1

    def test_the_per_check_summary_reaches_the_stored_report(self):
        report, system_data, _os = self._audit()
        assert report["config_audit"]["assessed"] is True
        assert report["config_audit"]["score_pct"] == 50.0
        assert system_data["config_audit"]["checks_run"] == 10

    def test_an_audit_that_could_not_run_is_recorded_as_a_gap(self):
        """
        The defect this guards: a configuration audit that crashed leaves no
        failing checks, which is byte-identical to a host that passed every
        one. The scan says so instead — the same treatment the OS and
        inventory branches already give an unassessed dimension.
        """
        report, _system_data, _os = self._audit(config_raises=True)
        ids = [f.get("cve_id") for f in report["cves"]]
        assert "MISC-CREDENTIALED-CONFIG-NOT-ASSESSED" in ids
        gap = next(
            f
            for f in report["cves"]
            if f.get("cve_id") == "MISC-CREDENTIALED-CONFIG-NOT-ASSESSED"
        )
        assert "engine exploded" in gap["description"]
        assert report["config_audit"]["assessed"] is False

    def test_a_successful_audit_records_no_gap(self):
        report, _system_data, _os = self._audit()
        ids = [f.get("cve_id") for f in report["cves"]]
        assert "MISC-CREDENTIALED-CONFIG-NOT-ASSESSED" not in ids


class TestTheCredentialedSyncFilesACheckAsACheck:
    """
    ``cve_list`` carries configuration and privilege findings beside package
    CVEs, and ``_sync_credentialed_vulnerabilities`` is the single writer that
    turns all of them into catalogue rows. It used to assume every entry was a
    CVE: it wrote the identifier into ``cve_id`` and let ``definition_type``
    take its ``'cve'`` default.

    ``vulnerability_definitions.cve_id`` is ``varchar(30)`` and a minted
    identifier is longer — ``CCURE-CFG-CCURE-LINUX-AUDITD-RUNNING`` is 37 — so
    the insert raised ``StringDataRightTruncation``. The catalogue write is
    inside the finding sync, so **one over-long check identifier discarded
    every finding in the scan**, the package CVEs included. Measured on a real
    Ubuntu 24.04 host: the audit collected for 615 seconds and then reported
    the scan as failed.

    These drive the real function against a real session, because the previous
    guard for this class of defect read the source instead of calling it — and
    a line that exists is not a line that runs.
    """

    @staticmethod
    def _fixture(db_session):
        import uuid

        from db.models.assets import Asset
        from db.models.rbac import Organization
        from db.models.scans import Scan
        from scans.db_helpers import utcnow

        org_id = f"org_{uuid.uuid4().hex[:8]}"
        db_session.add(
            Organization(
                id=org_id,
                name="P",
                slug=f"p-{uuid.uuid4().hex[:8]}",
                is_active=True,
                settings={},
            )
        )
        db_session.commit()
        asset = Asset(
            id=f"ast_{org_id}_10_0_0_9",
            org_id=org_id,
            ip_address="10.0.0.9",
            last_seen_at=utcnow(),
        )
        db_session.add(asset)
        scan_id = f"scn_{uuid.uuid4().hex[:8]}"
        db_session.add(
            Scan(
                id=scan_id,
                org_id=org_id,
                target_str="10.0.0.9",
                scan_type="credentialed",
                pipeline_mode="credentialed",
            )
        )
        db_session.commit()
        return org_id, asset, scan_id

    #: 37 characters — seven more than ``cve_id`` can hold.
    LONG_CHECK_ID = "CCURE-CFG-CCURE-LINUX-AUDITD-RUNNING"

    def test_an_over_long_check_identifier_does_not_abort_the_sync(self, db_session):
        from scans.tasks.credentialed_sync import _sync_credentialed_vulnerabilities
        from db.models.findings import AssetVulnerability

        org_id, asset, scan_id = self._fixture(db_session)
        assert len(self.LONG_CHECK_ID) > 30, "the id must exceed cve_id's width"

        _sync_credentialed_vulnerabilities(
            db_session,
            asset,
            org_id,
            scan_id,
            [
                {
                    "cve_id": self.LONG_CHECK_ID,
                    "definition_type": "config_check",
                    "title": "The audit daemon is running",
                    "severity": "Medium",
                    "evidence": "Expected: running\nObserved: inactive",
                    "expected_state": "running",
                    "observed_state": "inactive",
                },
                {
                    "cve_id": "CVE-2024-6387",
                    "title": "regreSSHion",
                    "severity": "High",
                    "cvss_score": 8.1,
                    "package": "openssh-server",
                },
            ],
        )
        db_session.commit()

        # The package CVE survives. Before the fix the check's insert raised
        # first and took this with it.
        written = {
            r.vuln_id
            for r in db_session.query(AssetVulnerability)
            .filter(AssetVulnerability.scan_id == scan_id)
            .all()
        }
        assert self.LONG_CHECK_ID in written
        assert "CVE-2024-6387" in written

    def test_a_check_row_carries_no_cve_id_and_a_cve_row_still_does(self, db_session):
        from scans.tasks.credentialed_sync import _sync_credentialed_vulnerabilities
        from db.models.findings import VulnerabilityDefinition

        org_id, asset, scan_id = self._fixture(db_session)
        _sync_credentialed_vulnerabilities(
            db_session,
            asset,
            org_id,
            scan_id,
            [
                {
                    "cve_id": self.LONG_CHECK_ID,
                    "definition_type": "config_check",
                    "title": "The audit daemon is running",
                    "severity": "Medium",
                    "evidence": "Expected: running\nObserved: inactive",
                },
                {
                    "cve_id": "CVE-2024-6387",
                    "title": "regreSSHion",
                    "severity": "High",
                    "cvss_score": 8.1,
                },
            ],
        )
        db_session.commit()

        check = (
            db_session.query(VulnerabilityDefinition)
            .filter(VulnerabilityDefinition.id == self.LONG_CHECK_ID)
            .one()
        )
        # NULL here is what keeps a configuration weakness out of the KEV,
        # EPSS and CVSS joins, all of which run through cve_id.
        assert check.cve_id is None
        assert check.definition_type == "config_check"

        cve = (
            db_session.query(VulnerabilityDefinition)
            .filter(VulnerabilityDefinition.id == "CVE-2024-6387")
            .one()
        )
        assert cve.cve_id == "CVE-2024-6387"
        assert cve.definition_type == "cve"

    def test_a_check_finding_is_not_described_as_a_package_query(self, db_session):
        """
        The evidence block was written for package matching. On a check it read
        "Package: unknown", "Fixed in: no fixed version published" and an NVD
        link for an identifier NVD has never heard of.
        """
        from scans.tasks.credentialed_sync import _sync_credentialed_vulnerabilities
        from db.models.findings import AssetVulnerability

        org_id, asset, scan_id = self._fixture(db_session)
        _sync_credentialed_vulnerabilities(
            db_session,
            asset,
            org_id,
            scan_id,
            [
                {
                    "cve_id": self.LONG_CHECK_ID,
                    "definition_type": "config_check",
                    "title": "The audit daemon is running",
                    "severity": "Medium",
                    "evidence": "Expected: running\nObserved: inactive",
                }
            ],
        )
        db_session.commit()

        row = (
            db_session.query(AssetVulnerability)
            .filter(AssetVulnerability.vuln_id == self.LONG_CHECK_ID)
            .one()
        )
        assert "nvd.nist.gov" not in (row.evidence or "")
        assert "authenticated package query" not in (row.evidence or "")
        assert "Observed: inactive" in (row.evidence or "")
