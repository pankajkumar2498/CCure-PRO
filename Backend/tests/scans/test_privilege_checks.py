"""
tests/scans/test_privilege_checks.py
─────────────────────────────────────────────────────────────────────────────
Local privilege-escalation and host-exposure checks (GAP-08, Phase 5).

Two things are proven for every check, because the brief asks for both and
because one without the other is worthless:

**Detection logic** — offenders present produce a FAIL, offenders absent produce
a PASS, and neither is reachable from a probe that could not run.

**The evidence path** — the FAIL names *which* service, *which* binary, *which*
sudo rule. A privilege finding that says "a service has a weak ACL" without
naming it cannot be acted on, and on a host with two hundred services it is
indistinguishable from noise.

The state matrix these checks must never violate
────────────────────────────────────────────────
    offenders found            -> FAIL, with the offenders as evidence
    probe ran, none found      -> PASS   (AbsencePolicy.PASS)
    probe could not run        -> ERROR  (never PASS, never FAIL)
    required tool absent (97)  -> ERROR  (nothing was established)
    wrong platform             -> NOT_APPLICABLE
    unknown probe name         -> ERROR  (a product gap, not a host property)

The third and fourth rows are the point of the whole engine. A host the scanner
could not read must not acquire a clean bill of health, and "find is not
installed" establishes nothing about that host's SUID binaries.

Every ``gap08_area`` is named in this file. ``scripts/measure_privilege_coverage``
reads these sources to decide which areas are *proven* rather than merely
implemented, so an area with a check and no test here counts for nothing.
"""

from dataclasses import dataclass

import pytest

from core.checks.contract import CheckOutcome
from core.checks.definitions import DEFINITION_TYPE_PRIVILEGE_CHECK
from core.config_audit import CollectionContext, ConfigAuditEngine
from core.config_audit.builtin import PRIVILEGE_CHECKS
from core.config_audit.builtin.privilege_linux import LINUX_PRIVILEGE_CHECKS
from core.config_audit.builtin.privilege_windows import WINDOWS_PRIVILEGE_CHECKS
from core.config_audit.collection import CollectionStatus
from core.config_audit.collectors.privilege_linux import (
    EXPECTED_SUID,
    LINUX_PROBES,
    LinuxPrivilegeCollector,
)
from core.config_audit.collectors.privilege_windows import (
    WINDOWS_PROBES,
    WindowsPrivilegeCollector,
)
from core.config_audit.findings import (
    PRIVILEGE_PLUGIN_FAMILY,
    findings_from_results,
)
from core.config_audit.spec import AbsencePolicy, ConfigCheck
from scans.finding_normalizer import Confidence, DetectionMethod

#: Every capability area this phase claims, named so the coverage script can
#: see them. Keeping the list here rather than deriving it means a check that
#: loses its test also loses its coverage credit.
COVERED_AREAS = (
    "win.unquoted_service_path",
    "win.service_permissions",
    "win.service_binary_permissions",
    "win.always_install_elevated",
    "win.scheduled_task_permissions",
    "win.writable_path",
    "win.unattend_files",
    "win.cached_logons",
    "win.lsa_protection",
    "win.powershell_logging",
    "linux.suid_binaries",
    "linux.sgid_binaries",
    "linux.world_writable_dirs",
    "linux.world_writable_files",
    "linux.sudo_nopasswd",
    "linux.writable_path",
    "linux.unowned_files",
    "linux.ungrouped_files",
    "linux.sensitive_file_modes",
    "linux.root_path_integrity",
    "linux.file_capabilities",
    "linux.writable_systemd_units",
)


@dataclass
class FakeResult:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    success: bool = True


class Stub:
    """A transport that returns one canned answer to the probe command."""

    def __init__(self, response=None, raises=None):
        self.response = response or FakeResult()
        self.raises = raises
        self.commands = []

    def connect(self):
        pass

    def disconnect(self):
        pass

    def run(self, command, timeout=None):
        self.commands.append(command)
        if self.raises:
            raise self.raises
        if "PSVersionTable" in command:
            return FakeResult(stdout="5")
        return self.response


def ctx(platform, response=None, raises=None, executor="stub"):
    return CollectionContext(
        target="10.0.0.4",
        platform=platform,
        executor=None if executor is None else Stub(response, raises),
    )


def run(check: ConfigCheck, platform: str, response=None, raises=None, executor="stub"):
    return ConfigAuditEngine().run_check(
        check, ctx(platform, response, raises, executor)
    )


def by_area(area: str) -> ConfigCheck:
    for check in PRIVILEGE_CHECKS:
        if check.metadata.get("gap08_area") == area:
            return check
    raise AssertionError(f"no privilege check covers {area}")


def platform_of(check: ConfigCheck) -> str:
    return check.platforms[0]


CLEAN = FakeResult(stdout="CCURE::ABSENT::no offending items found")


# ─────────────────────────────────────────────────────────────────────────────
# Every check, from every direction
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("area", COVERED_AREAS)
class TestEveryCoveredArea:
    """
    The full matrix, applied to all twenty-two areas.

    Parameterised rather than written out so that adding a check without
    thinking about its failure modes is not possible: a new area added to
    ``COVERED_AREAS`` immediately owes six passing assertions.
    """

    def test_a_clean_host_passes(self, area):
        check = by_area(area)
        result = run(check, platform_of(check), CLEAN)
        assert result.outcome is CheckOutcome.PASS, result.error

    def test_offenders_produce_a_failure_naming_them(self, area):
        check = by_area(area)
        result = run(
            check,
            platform_of(check),
            FakeResult(stdout="CCURE::VALUE::offender-one\noffender-two"),
        )
        assert result.outcome is CheckOutcome.FAIL
        # The evidence path: a finding that cannot name what to fix is noise.
        observed = result.evidence[0].observed
        assert "offender-one" in observed
        assert "offender-two" in observed

    def test_a_probe_that_could_not_run_is_an_error(self, area):
        check = by_area(area)
        result = run(
            check,
            platform_of(check),
            FakeResult(stderr="Access is denied.", exit_code=5, success=False),
        )
        assert result.outcome is CheckOutcome.ERROR
        assert not result.is_verdict

    def test_output_with_no_sentinel_is_an_error_not_a_clean_host(self, area):
        check = by_area(area)
        result = run(check, platform_of(check), FakeResult(stdout="unexpected"))
        assert result.outcome is CheckOutcome.ERROR

    def test_no_session_is_an_error(self, area):
        check = by_area(area)
        result = run(check, platform_of(check), executor=None)
        assert result.outcome is CheckOutcome.ERROR
        assert "authenticated session" in result.error

    def test_the_other_platform_is_not_applicable(self, area):
        check = by_area(area)
        other = "linux" if platform_of(check) == "windows" else "windows"
        result = run(check, other, CLEAN)
        assert result.outcome is CheckOutcome.NOT_APPLICABLE
        assert result.outcome is not CheckOutcome.FAIL


class TestNothingReachesPassExceptAnEstablishedAbsence:
    """
    The direction that matters. A host the scanner could not read must not
    acquire a clean bill of health.
    """

    @pytest.mark.parametrize("area", COVERED_AREAS)
    def test_a_failed_probe_never_passes(self, area):
        check = by_area(area)
        for response in (
            FakeResult(stderr="denied", exit_code=1, success=False),
            FakeResult(stdout="", exit_code=0, success=True),
            FakeResult(stdout="garbage output"),
        ):
            result = run(check, platform_of(check), response)
            assert result.outcome is not CheckOutcome.PASS, (area, response)

    def test_a_transport_exception_never_passes(self):
        check = by_area("linux.suid_binaries")
        result = run(check, "linux", raises=ConnectionResetError("connection dropped"))
        assert result.outcome is CheckOutcome.ERROR

    def test_a_missing_tool_is_unavailable_not_a_clean_host(self):
        """
        Exit 97 is Phase 3's reserved "the tool I needed is not installed"
        sentinel. A host with no `find` has established nothing about its SUID
        binaries, and reporting that as "none found" is the exact inversion this
        engine exists to prevent.
        """
        state = LinuxPrivilegeCollector().collect(
            by_area("linux.suid_binaries"),
            ctx("linux", FakeResult(exit_code=97, success=False)),
        )
        assert state.status is CollectionStatus.UNAVAILABLE
        assert "not installed" in state.detail

    def test_a_sentinel_claiming_offenders_with_none_is_unavailable(self):
        """
        The probe said there was a value and produced nothing. That is a defect
        in the probe, not a clean host, and must not read as one.
        """
        state = LinuxPrivilegeCollector().collect(
            by_area("linux.suid_binaries"),
            ctx("linux", FakeResult(stdout="CCURE::VALUE::")),
        )
        assert state.status is CollectionStatus.UNAVAILABLE


# ─────────────────────────────────────────────────────────────────────────────
# The collectors themselves
# ─────────────────────────────────────────────────────────────────────────────


class TestProbeResolution:
    def test_an_unknown_probe_is_a_product_gap_not_a_host_property(self):
        """
        "This build has no such probe" must never render as NOT_APPLICABLE or
        PASS — the same reading the engine gives an unimplemented check type.
        """
        for collector, platform in (
            (WindowsPrivilegeCollector(), "windows"),
            (LinuxPrivilegeCollector(), "linux"),
        ):
            check = ConfigCheck(
                check_id="t",
                title="t",
                check_type="privilege",
                platforms=(platform,),
                collect={"probe": "does_not_exist"},
                expect=by_area("linux.suid_binaries").expect,
                absent=AbsencePolicy.PASS,
            )
            state = collector.collect(check, ctx(platform, CLEAN))
            assert state.status is CollectionStatus.UNAVAILABLE
            assert "no " in state.detail and "probe" in state.detail

    def test_a_rule_with_no_probe_parameter_is_refused(self):
        check = ConfigCheck(
            check_id="t",
            title="t",
            check_type="privilege",
            platforms=("linux",),
            collect={"unrelated": "x"},
            expect=by_area("linux.suid_binaries").expect,
            absent=AbsencePolicy.PASS,
        )
        state = LinuxPrivilegeCollector().collect(check, ctx("linux", CLEAN))
        assert state.status is CollectionStatus.UNAVAILABLE
        assert "required parameter" in state.detail

    def test_offenders_are_returned_as_a_list_not_a_blob(self):
        """
        A list so the evidence renders one offender per entry. A single blob
        makes a twelve-service finding unreadable in a report cell.
        """
        state = LinuxPrivilegeCollector().collect(
            by_area("linux.suid_binaries"),
            ctx("linux", FakeResult(stdout="CCURE::VALUE::/a/one\n/b/two")),
        )
        assert state.status is CollectionStatus.COLLECTED
        assert state.value == ["/a/one", "/b/two"]

    def test_every_probe_name_a_check_uses_actually_exists(self):
        """
        A rule naming a probe the collector does not have would report ERROR on
        every host — registered, dispatched and permanently useless.
        """
        for check in WINDOWS_PRIVILEGE_CHECKS:
            assert check.collect["probe"] in WINDOWS_PROBES, check.check_id
        for check in LINUX_PRIVILEGE_CHECKS:
            assert check.collect["probe"] in LINUX_PROBES, check.check_id

    def test_probes_carry_a_longer_timeout_than_the_engine_default(self):
        """
        These walk every service and stat every binary. Timing out mid-probe
        and reporting a clean host is the failure this guards.
        """
        assert WindowsPrivilegeCollector().default_timeout >= 120
        assert LinuxPrivilegeCollector().default_timeout >= 120


class TestProbeConstruction:
    def test_every_probe_terminates_with_a_sentinel_on_both_paths(self):
        for name, body in {**WINDOWS_PROBES, **LINUX_PROBES}.items():
            assert "CCURE::ABSENT::" in body, name
            assert "CCURE::VALUE::" in body, name

    def test_the_suid_allowlist_covers_the_common_distribution_binaries(self):
        """
        A legitimate binary missing from the list is a false positive, and a
        check that cries wolf trains the reader to ignore it.
        """
        for expected in ("sudo", "passwd", "su", "mount", "umount", "pkexec"):
            assert expected in EXPECTED_SUID

    def test_the_capability_probe_reports_only_privilege_granting_caps(self):
        """
        cap_net_bind_service on a web server is normal. Reporting it is the
        noise that teaches a reader to skip the finding.
        """
        body = LINUX_PROBES["file_capabilities"]
        assert "cap_setuid" in body
        assert "cap_sys_admin" in body
        assert "cap_net_bind_service" not in body

    def test_always_install_elevated_requires_both_hives(self):
        """
        Either alone does nothing. Reporting one as a finding is simply wrong.
        """
        body = WINDOWS_PROBES["always_install_elevated"]
        assert "HKLM" in body and "HKCU" in body
        assert "-and" in body

    def test_the_unquoted_path_probe_excludes_the_unexploitable(self):
        """
        An unquoted path with no space cannot be hijacked, and one under
        %SystemRoot% sits in an admin-only directory. Reporting either is noise.
        """
        body = WINDOWS_PROBES["unquoted_service_path"]
        assert "notmatch ' '" in body
        assert "SystemRoot" in body

    def test_the_service_acl_probe_ignores_virtual_service_accounts(self):
        r"""
        Regression, found by real-target validation.

        The first version reported seven services on a stock Windows 11
        workstation, because NT SERVICE\TrustedInstaller
        (S-1-5-80-956008885-...) holds full control over service configuration —
        which is simply how Windows servicing works — and because each service's
        own virtual account holds ChangeConfig over itself.

        Both are machine-managed identities nobody can authenticate as. Seven
        false positives on a clean host is the failure that teaches a reader to
        skip the check, which is worse than not having it.
        """
        body = WINDOWS_PROBES["service_permissions"]
        assert "S-1-5-80-*" in body

    def test_the_service_acl_probe_ignores_trusted_principals_and_read_rights(self):
        """
        SERVICE_START alone is not privilege escalation, and flagging SYSTEM
        for being able to change a service teaches the reader to ignore it.
        """
        body = WINDOWS_PROBES["service_permissions"]
        assert "S-1-5-32-544" in body  # Administrators, trusted
        assert "S-1-5-18" in body  # SYSTEM, trusted
        assert "0x0002" in body  # CHANGE_CONFIG is what is looked for

    def test_the_account_file_probe_does_not_duplicate_the_phase3_checks(self):
        """
        `ccure.linux.passwd.permissions` and `.shadow.permissions` already
        assert those two files' modes. Repeating them here would report one
        condition twice and make the remediation look twice as large.
        """
        body = LINUX_PROBES["sensitive_file_modes"]
        # Ownership of all four is checked...
        assert "/etc/passwd /etc/shadow /etc/group /etc/gshadow" in body
        # ...but modes only for the two Phase 3 does not look at.
        mode_section = body.split("Modes of")[-1] if "Modes of" in body else body
        assert "for f in /etc/group /etc/gshadow" in body


# ─────────────────────────────────────────────────────────────────────────────
# Finding integration
# ─────────────────────────────────────────────────────────────────────────────


class TestPrivilegeFindings:
    def _failure(self, area: str):
        check = by_area(area)
        result = run(
            check,
            platform_of(check),
            FakeResult(stdout="CCURE::VALUE::svc-one :: C:\\bad.exe"),
        )
        assert result.outcome is CheckOutcome.FAIL
        return check, findings_from_results(
            [result], checks_by_id={check.check_id: check}
        )

    def test_a_failure_mints_a_privilege_identifier_not_a_config_one(self):
        _check, findings = self._failure("win.service_permissions")
        assert len(findings) == 1
        assert findings[0].plugin_id.startswith("CCURE-PRV-")

    def test_it_is_never_filed_as_a_cve(self):
        """
        A privilege condition is not a published vulnerability. Filing it as a
        CVE row inherits KEV lookups, EPSS scores and an NVD link that resolves
        to nothing.
        """
        _check, findings = self._failure("win.service_permissions")
        assert findings[0].cve_ids == []

    def test_privilege_findings_group_separately_from_hardening(self):
        """
        "Deviates from a baseline" and "has a path to SYSTEM" are different
        piles to a triager.
        """
        _check, findings = self._failure("linux.sudo_nopasswd")
        assert findings[0].plugin_family == PRIVILEGE_PLUGIN_FAMILY

    def test_the_offenders_reach_the_finding_evidence(self):
        _check, findings = self._failure("win.service_permissions")
        assert "svc-one" in findings[0].evidence
        assert findings[0].evidence_available

    def test_the_finding_carries_actionable_remediation(self):
        from scans.finding_normalizer import RemediationConfidence

        _check, findings = self._failure("linux.sudo_nopasswd")
        remediation = findings[0].remediation
        assert remediation is not None
        assert remediation.confidence is RemediationConfidence.CONFIGURATION_GUIDANCE
        assert remediation.is_actionable

    def test_detection_is_config_check_at_confirmed_confidence(self):
        _check, findings = self._failure("linux.sudo_nopasswd")
        assert findings[0].detection_method is DetectionMethod.CONFIG_CHECK
        assert findings[0].confidence is Confidence.CONFIRMED

    def test_a_pass_produces_no_finding(self):
        check = by_area("win.service_permissions")
        result = run(check, "windows", CLEAN)
        assert findings_from_results([result]) == []

    def test_an_error_produces_no_finding(self):
        check = by_area("win.service_permissions")
        result = run(
            check, "windows", FakeResult(stderr="x", exit_code=1, success=False)
        )
        assert findings_from_results([result]) == []

    def test_the_catalogue_row_is_a_privilege_row(self):
        from core.config_audit.findings import catalogue_row

        row = catalogue_row(by_area("linux.writable_path"))
        assert row["definition_type"] == DEFINITION_TYPE_PRIVILEGE_CHECK
        assert row["cve_id"] is None


class TestSeverityIsEvidenceBased:
    def test_severity_reaches_the_finding_in_the_canonical_vocabulary(self):
        from scans.cvss import SEVERITY_RANK

        check = by_area("win.service_permissions")
        result = run(check, "windows", FakeResult(stdout="CCURE::VALUE::svc"))
        finding = findings_from_results([result])[0]
        assert finding.severity in SEVERITY_RANK
        assert SEVERITY_RANK[finding.severity] == SEVERITY_RANK["Critical"]

    def test_direct_paths_to_system_are_rated_critical(self):
        """
        These need no further condition: rewrite the service config, overwrite
        the binary, or install any MSI, and you are SYSTEM.
        """
        for area in (
            "win.service_permissions",
            "win.service_binary_permissions",
            "win.always_install_elevated",
            "linux.writable_path",
            "linux.writable_systemd_units",
        ):
            assert by_area(area).severity == "critical", area

    def test_the_unquoted_path_is_high_not_critical(self):
        """
        It is only exploitable if the attacker can *also* write to one of the
        truncated directories — a separate condition this check does not
        establish. Rating it Critical would put it above conditions that need
        nothing further.
        """
        assert by_area("win.unquoted_service_path").severity == "high"

    def test_logging_gaps_are_low_and_are_still_reported(self):
        """
        Not an escalation path, which is why it is Low; it is the reason one
        leaves no trace, which is why it is not simply omitted.
        """
        assert by_area("win.powershell_logging").severity == "low"

    def test_no_privilege_check_is_unscored(self):
        for check in PRIVILEGE_CHECKS:
            assert check.severity in (
                "critical",
                "high",
                "medium",
                "low",
            ), check.check_id


# ─────────────────────────────────────────────────────────────────────────────
# Shape of the check set
# ─────────────────────────────────────────────────────────────────────────────


class TestTheCheckSet:
    def test_every_privilege_check_declares_the_privilege_finding_type(self):
        for check in PRIVILEGE_CHECKS:
            assert check.finding_type == DEFINITION_TYPE_PRIVILEGE_CHECK

    def test_every_privilege_check_treats_absence_as_compliant(self):
        """
        Unlike the Phase 3 registry rules, where an absent value means "at a
        platform default that varies by build". Here the probe *searched* and
        found nothing, which is a real result.
        """
        for check in PRIVILEGE_CHECKS:
            assert check.absent is AbsencePolicy.PASS, check.check_id

    def test_every_privilege_check_needs_credentials(self):
        for check in PRIVILEGE_CHECKS:
            assert check.requires_credentials, check.check_id

    def test_no_privilege_check_is_intrusive(self):
        """
        These run on every credentialed scan, including against OT hosts.
        Nothing here may disrupt a target.
        """
        assert not [c.check_id for c in PRIVILEGE_CHECKS if c.intrusive]

    def test_every_check_has_a_rationale_and_a_remediation(self):
        missing = [
            c.check_id
            for c in PRIVILEGE_CHECKS
            if not c.rationale.strip() or not c.remediation.strip()
        ]
        assert not missing, missing

    def test_every_check_is_tagged_with_its_coverage_area(self):
        untagged = [
            c.check_id for c in PRIVILEGE_CHECKS if not c.metadata.get("gap08_area")
        ]
        assert not untagged, untagged

    def test_the_covered_areas_match_the_implemented_checks(self):
        """
        Keeps this file's list honest against the checks that exist, so the
        coverage script cannot credit an area whose test was deleted.
        """
        implemented = {c.metadata["gap08_area"] for c in PRIVILEGE_CHECKS}
        assert implemented == set(COVERED_AREAS)

    def test_all_areas_appear_in_the_measurement_scope(self):
        from scripts.measure_privilege_coverage import SCOPE

        scope = {area for area, _p, _d in SCOPE}
        assert set(COVERED_AREAS) <= scope

    def test_the_measurement_denominator_includes_unimplemented_areas(self):
        """
        A denominator containing only what was built measures the list, not the
        capability — and can never go down.
        """
        from scripts.measure_privilege_coverage import SCOPE

        scope = {area for area, _p, _d in SCOPE}
        assert scope - set(
            COVERED_AREAS
        ), "every scope area is implemented; the denominator is a tautology"

    def test_check_ids_are_unique_across_the_whole_builtin_pack(self):
        from core.config_audit.builtin import BUILTIN_CHECKS

        ids = [c.check_id for c in BUILTIN_CHECKS]
        assert len(ids) == len(set(ids))

    def test_privilege_checks_use_the_local_privilege_domain(self):
        for check in PRIVILEGE_CHECKS:
            assert check.domain == "local_privilege", check.check_id


class TestPrivilegeChecksInTheRealScanPath:
    """
    ``_run_configuration_audit`` is what a credentialed scan actually calls.
    Everything above tests the engine directly; this tests the path a customer's
    scan takes.
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
            return FakeResult(stderr="not stubbed", exit_code=1, success=False)

    def _audit(self, table, os_type="windows"):
        from core.tasks import _run_configuration_audit

        return _run_configuration_audit(
            executor=self._Executor(table),
            ip="10.0.0.4",
            os_type=os_type,
            system_data={},
        )

    def test_privilege_checks_run_alongside_the_hardening_checks(self):
        """
        Asserted by *family* rather than by a total.

        This used to assert ``checks_run == 20`` — 10 Phase 3 hardening plus 10
        Phase 5 privilege. A hardcoded total breaks on every content phase that
        adds a built-in (Phase 8's middleware rules took it to 56), and it is
        the weaker assertion anyway: a total of 20 is equally satisfied by 20
        hardening checks and no privilege ones, which is the regression this
        test exists to catch.
        """
        summary, _findings = self._audit({})
        ran = [r["check_id"] for r in summary["results"]]
        assert [c for c in ran if c.startswith("ccure.priv.")], ran
        assert [c for c in ran if c.startswith("ccure.win.")], ran
        assert summary["checks_run"] == len(ran)

    def test_a_privilege_failure_mints_a_prv_identifier_in_the_scan_path(self):
        """
        Regression. The scan path minted the identifier without consulting the
        check's declared finding type, so every privilege finding would have
        been filed as CCURE-CFG- — the right finding in the wrong pile, and
        invisible to anyone filtering for privilege conditions.
        """
        summary, findings = self._audit(
            {"AlwaysInstallElevated": FakeResult(stdout="CCURE::VALUE::both hives set")}
        )
        privilege = [f for f in findings if f["cve_id"].startswith("CCURE-PRV-")]
        assert privilege, [f["cve_id"] for f in findings]
        assert privilege[0]["definition_type"] == "privilege_check"

    def test_the_offenders_reach_the_scan_finding(self):
        _summary, findings = self._audit(
            {"AlwaysInstallElevated": FakeResult(stdout="CCURE::VALUE::both hives set")}
        )
        privilege = [f for f in findings if f["cve_id"].startswith("CCURE-PRV-")][0]
        assert "both hives set" in privilege["observed_state"]
        assert privilege["remediation"]

    def test_an_unreachable_host_produces_no_privilege_findings(self):
        """
        Every probe errors, so nothing becomes a finding — and nothing becomes
        a pass either.
        """
        summary, findings = self._audit({})
        assert [f for f in findings if f["cve_id"].startswith("CCURE-PRV-")] == []
        assert summary["counts"]["error"] > 0
        assert summary["counts"]["pass"] == 0
        assert summary["counts"]["fail"] == 0

    def test_linux_privilege_checks_run_on_a_linux_host(self):
        """By family, for the reason given on the Windows test above."""
        summary, _findings = self._audit({}, os_type="linux")
        ran = [r["check_id"] for r in summary["results"]]
        assert [c for c in ran if c.startswith("ccure.priv.linux.")], ran
        assert [c for c in ran if c.startswith("ccure.linux.")], ran
        # And nothing targeted at the other platform leaked in.
        assert not [c for c in ran if c.startswith("ccure.win.")], ran
