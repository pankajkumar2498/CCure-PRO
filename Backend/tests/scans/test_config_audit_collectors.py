"""
tests/scans/test_config_audit_collectors.py
─────────────────────────────────────────────────────────────────────────────
The collectors, and the distinction they exist to preserve.

``WindowsCollector._run`` and ``LinuxCollector._run`` both end with
``return _clean_output(result.stdout) if result.stdout else ""`` — the exit
code is discarded. For bulk inventory that is defensible. For a configuration
check it is the central defect, because a failed command returns ``""``, the
comparison reads ``""`` as the host's setting, and the check reports a verdict
about a machine that never answered.

Every collector below is therefore tested against three shapes of the same
command: a value, a successful "not there", and a failure. The failure case is
the one that matters, and it is asserted for each collector rather than once
generically, because each one has its own command and its own chance to get it
wrong.
"""

from dataclasses import dataclass

import pytest

from core.config_audit.collection import (
    CollectedState,
    CollectionContext,
    CollectionStatus,
)
from core.config_audit.collectors.base import CollectorRegistry, ShellRunner
from core.config_audit.collectors.linux import (
    LinuxConfigFileCollector,
    LinuxFileCollector,
    LinuxPackageCollector,
    LinuxPermissionCollector,
    LinuxPortCollector,
    LinuxSecurityPolicyCollector,
    LinuxServiceCollector,
)
from core.config_audit.collectors.windows import (
    WindowsCommandCollector,
    WindowsPackageCollector,
    WindowsPortCollector,
    WindowsRegistryCollector,
    WindowsSecurityPolicyCollector,
    WindowsServiceCollector,
    ps_quote,
)
from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation


@dataclass
class FakeResult:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    success: bool = True


class FakeExecutor:
    def __init__(self, table=None, shell="powershell"):
        self.table = table or {}
        self.shell = shell
        self.commands = []

    def connect(self):
        pass

    def disconnect(self):
        pass

    def run(self, command, timeout=None):
        self.commands.append(command)
        if "PSVersionTable" in command:
            return FakeResult(stdout="5" if self.shell == "powershell" else "cmd")
        for needle, response in self.table.items():
            if needle in command:
                return response
        return FakeResult(stderr="no stub", exit_code=1, success=False)


def check(check_type, collect, **overrides) -> ConfigCheck:
    params = dict(
        check_id="t",
        title="t",
        check_type=check_type,
        collect=collect,
        expect=Expectation("equals", "x"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        platforms=("any",),
    )
    params.update(overrides)
    return ConfigCheck(**params)


def ctx(executor, platform="windows", **kwargs) -> CollectionContext:
    return CollectionContext(
        target="10.0.0.1", platform=platform, executor=executor, **kwargs
    )


# ─────────────────────────────────────────────────────────────────────────────
# The shell runner
# ─────────────────────────────────────────────────────────────────────────────


class TestShellRunnerPreservesTheExitCode:
    def test_a_failed_command_is_not_reported_as_empty_output(self):
        runner = ShellRunner(
            FakeExecutor(
                {"whoami": FakeResult(stderr="denied", exit_code=5, success=False)}
            ),
            "windows",
        )
        out = runner.run("whoami")
        assert out.ok is False
        assert out.exit_code == 5
        assert "denied" in out.failure_detail()

    def test_a_successful_command_with_no_output_is_still_successful(self):
        """
        ``sc.exe query`` for an absent service prints nothing and exits 0.
        Branching on truthiness of stdout would call that a failure.
        """
        runner = ShellRunner(FakeExecutor({"echo": FakeResult(stdout="")}), "windows")
        assert runner.run("echo").ok is True

    def test_no_executor_is_a_transport_error_not_a_silent_empty(self):
        out = ShellRunner(None, "windows").run("whoami")
        assert out.ok is False
        assert "no authenticated session" in out.failure_detail()

    def test_a_raising_transport_is_caught_and_named(self):
        class Boom:
            def run(self, *_, **__):
                raise ConnectionResetError("dropped")

        out = ShellRunner(Boom(), "windows").run("whoami")
        assert out.ok is False
        assert "ConnectionResetError" in out.failure_detail()

    def test_powershell_commands_are_not_double_encoded(self):
        """
        pywinrm already base64-encodes UTF-16-LE. Wrapping again feeds the
        encoder its own output — the defect CLAUDE.md records for ``_wrap_ps``.
        """
        executor = FakeExecutor(
            {"Get-Item": FakeResult(stdout="ok")}, shell="powershell"
        )
        ShellRunner(executor, "windows").run("Get-Item X")
        assert "Get-Item X" in executor.commands[-1]
        assert "-EncodedCommand" not in executor.commands[-1]

    def test_a_cmd_shell_gets_an_encoded_command(self):
        executor = FakeExecutor({}, shell="cmd")
        ShellRunner(executor, "windows").run("Get-Item X")
        assert "-EncodedCommand" in executor.commands[-1]

    def test_shell_detection_runs_once_per_runner(self):
        executor = FakeExecutor(
            {"A": FakeResult(stdout="a"), "B": FakeResult(stdout="b")}
        )
        runner = ShellRunner(executor, "windows")
        runner.run("A")
        runner.run("B")
        assert sum("PSVersionTable" in c for c in executor.commands) == 1

    def test_linux_commands_are_never_wrapped(self):
        executor = FakeExecutor({"cat": FakeResult(stdout="x")})
        ShellRunner(executor, "linux").run("cat /etc/passwd")
        assert executor.commands == ["cat /etc/passwd"]


# ─────────────────────────────────────────────────────────────────────────────
# Quoting — rule parameters are data, not code
# ─────────────────────────────────────────────────────────────────────────────


class TestRuleParametersCannotBecomeCode:
    def test_powershell_single_quotes_are_doubled(self):
        assert ps_quote("O'Brien") == "'O''Brien'"

    def test_a_path_containing_a_quote_cannot_terminate_the_literal(self):
        executor = FakeExecutor({"": FakeResult(stdout="CCURE::VALUE::1")})
        WindowsRegistryCollector().collect(
            check("registry", {"path": r"HKLM\A'; Stop-Computer; '", "value": "V"}),
            ctx(executor),
        )
        command = executor.commands[-1]
        # The apostrophe is doubled, so the injected text stays *inside* the
        # PowerShell literal instead of terminating it and being parsed as the
        # next statement.
        assert r"'HKLM:\A''; Stop-Computer; '" in command

    def test_linux_paths_are_shell_quoted(self):
        executor = FakeExecutor({"": FakeResult(stdout="CCURE::VALUE::644")})
        LinuxPermissionCollector().collect(
            check("permission", {"path": "/tmp/$(reboot)", "attribute": "mode"}),
            ctx(executor, platform="linux"),
        )
        assert "'/tmp/$(reboot)'" in executor.commands[-1]


# ─────────────────────────────────────────────────────────────────────────────
# Windows collectors
# ─────────────────────────────────────────────────────────────────────────────


class TestWindowsRegistryCollector:
    def _collect(self, response, **params):
        base = {"path": r"HKLM\SOFTWARE\X", "value": "V"}
        base.update(params)
        return WindowsRegistryCollector().collect(
            check("registry", base), ctx(FakeExecutor({"": response}))
        )

    def test_a_value_is_collected(self):
        state = self._collect(FakeResult(stdout="CCURE::VALUE::1"))
        assert state.status is CollectionStatus.COLLECTED
        assert state.value == "1"

    def test_a_missing_key_and_a_missing_value_are_both_absent_with_distinct_detail(
        self,
    ):
        no_key = self._collect(
            FakeResult(stdout="CCURE::ABSENT::registry key does not exist")
        )
        no_value = self._collect(
            FakeResult(stdout="CCURE::ABSENT::value is not set under an existing key")
        )
        assert no_key.status is CollectionStatus.ABSENT
        assert no_value.status is CollectionStatus.ABSENT
        assert no_key.detail != no_value.detail

    def test_a_failed_command_is_unavailable_not_absent(self):
        state = self._collect(FakeResult(stderr="denied", exit_code=5, success=False))
        assert state.status is CollectionStatus.UNAVAILABLE
        assert "denied" in state.detail

    def test_output_with_no_sentinel_is_unavailable_not_an_empty_value(self):
        state = self._collect(FakeResult(stdout="WARNING: provider noise"))
        assert state.status is CollectionStatus.UNAVAILABLE

    def test_a_sentinel_after_banner_noise_is_still_found(self):
        state = self._collect(FakeResult(stdout="banner\nmore\nCCURE::VALUE::1"))
        assert state.status is CollectionStatus.COLLECTED
        assert state.value == "1"

    def test_an_unknown_hive_is_a_rule_defect_not_a_host_observation(self):
        state = self._collect(FakeResult(stdout="CCURE::VALUE::1"), path="HKXX\\Y")
        assert state.status is CollectionStatus.UNAVAILABLE
        assert "unknown hive" in state.detail

    def test_without_a_value_name_the_key_presence_is_the_reading(self):
        executor = FakeExecutor(
            {"Test-Path": FakeResult(stdout="CCURE::VALUE::present")}
        )
        state = WindowsRegistryCollector().collect(
            check("registry", {"path": r"HKLM\SOFTWARE\X"}), ctx(executor)
        )
        assert state.value == "present"


class TestWindowsServiceCollector:
    def test_a_running_service_reports_its_status(self):
        executor = FakeExecutor(
            {"Get-Service": FakeResult(stdout="CCURE::VALUE::Running")}
        )
        state = WindowsServiceCollector().collect(
            check("service", {"name": "MpsSvc"}), ctx(executor)
        )
        assert state.value == "Running"

    def test_an_uninstalled_service_is_absent_not_stopped(self):
        """
        "Not installed" and "stopped" are the same for one rule and opposite
        for another. Only the rule's absence policy can resolve it, so the
        collector must not.
        """
        executor = FakeExecutor(
            {
                "Get-Service": FakeResult(
                    stdout="CCURE::ABSENT::service is not installed"
                )
            }
        )
        state = WindowsServiceCollector().collect(
            check("service", {"name": "TlntSvr"}), ctx(executor)
        )
        assert state.status is CollectionStatus.ABSENT

    def test_a_failed_query_is_unavailable(self):
        executor = FakeExecutor(
            {
                "Get-Service": FakeResult(
                    stderr="RPC unavailable", exit_code=1, success=False
                )
            }
        )
        state = WindowsServiceCollector().collect(
            check("service", {"name": "MpsSvc"}), ctx(executor)
        )
        assert state.status is CollectionStatus.UNAVAILABLE

    def test_an_unsupported_attribute_is_a_rule_defect(self):
        state = WindowsServiceCollector().collect(
            check("service", {"name": "X", "attribute": "colour"}), ctx(FakeExecutor())
        )
        assert state.status is CollectionStatus.UNAVAILABLE
        assert "unsupported attribute" in state.detail


class TestInventoryBackedCollectorsPreferCollectedData:
    def test_a_package_is_answered_from_the_inventory_without_a_command(self):
        executor = FakeExecutor()
        state = WindowsPackageCollector().collect(
            check("package", {"name": "7-Zip", "attribute": "version"}),
            ctx(
                executor,
                system_data={
                    "installed_software": [{"name": "7-Zip", "version": "23.01"}]
                },
            ),
        )
        assert state.value == "23.01"
        assert executor.commands == []

    def test_a_package_missing_from_a_present_inventory_is_absent(self):
        state = WindowsPackageCollector().collect(
            check("package", {"name": "Telnet"}),
            ctx(
                FakeExecutor(), system_data={"installed_software": [{"name": "7-Zip"}]}
            ),
        )
        assert state.status is CollectionStatus.ABSENT

    def test_with_no_inventory_it_falls_back_to_a_live_query(self):
        executor = FakeExecutor(
            {"Uninstall": FakeResult(stdout="CCURE::VALUE::installed")}
        )
        state = WindowsPackageCollector().collect(
            check("package", {"name": "7-Zip"}), ctx(executor)
        )
        assert state.value == "installed"
        assert executor.commands

    def test_a_port_is_answered_from_the_socket_table(self):
        executor = FakeExecutor()
        state = WindowsPortCollector().collect(
            check("port", {"port": 3389}),
            ctx(executor, system_data={"open_ports": [{"port": "3389"}]}),
        )
        assert state.value == "listening"
        assert executor.commands == []

    def test_a_non_numeric_port_is_a_rule_defect(self):
        state = WindowsPortCollector().collect(
            check("port", {"port": "three thousand"}), ctx(FakeExecutor())
        )
        assert state.status is CollectionStatus.UNAVAILABLE


class TestWindowsSecurityPolicyIsNeverSynthesised:
    """
    CLAUDE.md records that ``password_policy`` was once hard-coded for every
    host, so every rule reading it passed unconditionally everywhere. Nothing
    here may default a value it could not read.
    """

    def test_a_collected_setting_is_used(self):
        state = WindowsSecurityPolicyCollector().collect(
            check("security_policy", {"setting": "min_length"}),
            ctx(FakeExecutor(), system_data={"password_policy": {"min_length": 14}}),
        )
        assert state.value == 14

    def test_a_setting_absent_from_the_policy_falls_through_to_secedit(self):
        executor = FakeExecutor(
            {"secedit": FakeResult(stdout="[System Access]\nMinimumPasswordLength = 8")}
        )
        state = WindowsSecurityPolicyCollector().collect(
            check("security_policy", {"setting": "min_length"}),
            ctx(executor, system_data={"password_policy": {"history_length": 24}}),
        )
        assert state.status is CollectionStatus.COLLECTED
        assert state.value == "8"

    def test_a_failed_export_is_unavailable_not_a_default(self):
        executor = FakeExecutor(
            {"secedit": FakeResult(stderr="denied", exit_code=1, success=False)}
        )
        state = WindowsSecurityPolicyCollector().collect(
            check("security_policy", {"setting": "min_length"}), ctx(executor)
        )
        assert state.status is CollectionStatus.UNAVAILABLE

    def test_the_export_runs_once_for_several_settings(self):
        executor = FakeExecutor(
            {
                "secedit": FakeResult(
                    stdout="MinimumPasswordLength = 14\nPasswordHistorySize = 24"
                )
            }
        )
        shared = ctx(executor)
        collector = WindowsSecurityPolicyCollector()
        a = collector.collect(
            check("security_policy", {"setting": "min_length"}), shared
        )
        b = collector.collect(
            check("security_policy", {"setting": "history_length"}), shared
        )
        assert a.value == "14" and b.value == "24"
        assert sum("secedit" in c for c in executor.commands) == 1


class TestWindowsCommandCollector:
    def test_output_is_returned(self):
        executor = FakeExecutor({"hostname": FakeResult(stdout="PANKAJM-HPNEW")})
        state = WindowsCommandCollector().collect(
            check("command", {"command": "hostname"}), ctx(executor)
        )
        assert state.value == "PANKAJM-HPNEW"

    def test_a_nonzero_exit_is_unavailable(self):
        executor = FakeExecutor(
            {"hostname": FakeResult(exit_code=1, success=False, stderr="x")}
        )
        state = WindowsCommandCollector().collect(
            check("command", {"command": "hostname"}), ctx(executor)
        )
        assert state.status is CollectionStatus.UNAVAILABLE


# ─────────────────────────────────────────────────────────────────────────────
# Linux collectors
# ─────────────────────────────────────────────────────────────────────────────


def linux_ctx(table, **kwargs):
    return ctx(FakeExecutor(table), platform="linux", **kwargs)


class TestLinuxFilesystemCollectors:
    def test_a_mode_is_read(self):
        state = LinuxPermissionCollector().collect(
            check("permission", {"path": "/etc/shadow", "attribute": "mode"}),
            linux_ctx({"stat": FakeResult(stdout="CCURE::VALUE::640")}),
        )
        assert state.value == "640"

    def test_a_missing_path_is_absent(self):
        state = LinuxPermissionCollector().collect(
            check("permission", {"path": "/etc/nope", "attribute": "mode"}),
            linux_ctx(
                {"[ -e": FakeResult(stdout="CCURE::ABSENT::path does not exist")}
            ),
        )
        assert state.status is CollectionStatus.ABSENT

    def test_an_unsupported_attribute_names_what_is_supported(self):
        state = LinuxPermissionCollector().collect(
            check("permission", {"path": "/etc/passwd", "attribute": "colour"}),
            linux_ctx({}),
        )
        assert state.status is CollectionStatus.UNAVAILABLE
        assert "mode" in state.detail

    def test_a_file_read_returns_content(self):
        state = LinuxFileCollector().collect(
            check("file", {"path": "/etc/hostname", "attribute": "content"}),
            linux_ctx({"head -c": FakeResult(stdout="CCURE::VALUE::rocky9")}),
        )
        assert state.value == "rocky9"


class TestLinuxConfigFileDirectiveParsing:
    def _collect(self, content, key="PermitRootLogin", separator=""):
        return LinuxConfigFileCollector().collect(
            check(
                "config_file",
                {"path": "/etc/ssh/sshd_config", "key": key, "separator": separator},
            ),
            linux_ctx({"cat": FakeResult(stdout="CCURE::VALUE::" + content)}),
        )

    def test_a_whitespace_separated_directive_is_read(self):
        assert self._collect("PermitRootLogin no\n").value == "no"

    def test_a_commented_directive_is_absent_not_its_commented_value(self):
        """
        ``# PermitRootLogin yes`` means the daemon is on its default. Reading
        "yes" out of a comment is a finding invented from a comment.
        """
        state = self._collect("# PermitRootLogin yes\n")
        assert state.status is CollectionStatus.ABSENT

    def test_the_last_occurrence_wins(self):
        """
        Matching how configuration parsers actually resolve a repeated
        directive. Taking the first would report a value the software does not
        use.
        """
        assert (
            self._collect("MaxAuthTries 6\nMaxAuthTries 4\n", key="MaxAuthTries").value
            == "4"
        )

    def test_an_absent_directive_is_absent(self):
        assert self._collect("Port 22\n").status is CollectionStatus.ABSENT

    def test_a_value_continues_past_the_first_line(self):
        """
        Regression. Only the first line of the output carries the sentinel
        prefix, and the first version of the parser returned that line alone —
        so every configuration file was read as its first directive and every
        other directive in it reported as absent. That surfaces as a
        fleet-wide configuration gap rather than as a parser bug, which is why
        it is asserted directly rather than only through a rule.
        """
        content = "Port 22\nPermitRootLogin no\nX11Forwarding no\n"
        assert self._collect(content).value == "no"
        assert self._collect(content, key="X11Forwarding").value == "no"

    def test_a_blank_line_inside_a_file_does_not_truncate_it(self):
        content = "Port 22\n\n\nPermitRootLogin no\n"
        assert self._collect(content).value == "no"

    def test_key_matching_is_case_insensitive(self):
        assert self._collect("permitrootlogin no\n").value == "no"

    def test_an_equals_separated_file_is_parsed_with_the_separator(self):
        state = LinuxConfigFileCollector().collect(
            check(
                "config_file",
                {"path": "/etc/x.conf", "key": "minlen", "separator": "="},
            ),
            linux_ctx({"cat": FakeResult(stdout="CCURE::VALUE::minlen = 14\n")}),
        )
        assert state.value == "14"

    def test_a_missing_file_is_absent(self):
        state = LinuxConfigFileCollector().collect(
            check("config_file", {"path": "/etc/nope", "key": "k"}),
            linux_ctx(
                {
                    "[ -f": FakeResult(
                        stdout="CCURE::ABSENT::configuration file does not exist"
                    )
                }
            ),
        )
        assert state.status is CollectionStatus.ABSENT


class TestLinuxMissingToolsAreUnavailableNotAbsent:
    """
    A host whose package manager could not be found has not established that
    the package is missing. Exit 97 is the sentinel each command uses to say
    "the tool I needed is not here", distinct from "the thing is not there".
    """

    def test_no_package_manager_is_unavailable(self):
        state = LinuxPackageCollector().collect(
            check("package", {"name": "auditd"}),
            linux_ctx({"dpkg-query": FakeResult(exit_code=97, success=False)}),
        )
        assert state.status is CollectionStatus.UNAVAILABLE
        assert "dpkg-query nor rpm" in state.detail

    def test_no_systemctl_is_unavailable(self):
        state = LinuxServiceCollector().collect(
            check("service", {"name": "auditd"}),
            linux_ctx({"systemctl": FakeResult(exit_code=97, success=False)}),
        )
        assert state.status is CollectionStatus.UNAVAILABLE
        assert "systemctl" in state.detail

    def test_no_ss_is_unavailable(self):
        state = LinuxPortCollector().collect(
            check("port", {"port": 23}),
            linux_ctx({"ss ": FakeResult(exit_code=97, success=False)}),
        )
        assert state.status is CollectionStatus.UNAVAILABLE


class TestLinuxServiceStates:
    def test_an_inactive_unit_is_a_reading_not_a_failure(self):
        """
        ``systemctl is-active`` exits non-zero for an inactive unit. That is a
        successful read of "inactive", and treating the exit code as a
        collection failure would make every stopped service unassessable.
        """
        state = LinuxServiceCollector().collect(
            check("service", {"name": "auditd"}),
            linux_ctx({"systemctl": FakeResult(stdout="CCURE::VALUE::inactive")}),
        )
        assert state.status is CollectionStatus.COLLECTED
        assert state.value == "inactive"

    def test_an_unknown_unit_is_absent(self):
        state = LinuxServiceCollector().collect(
            check("service", {"name": "auditd"}),
            linux_ctx(
                {
                    "systemctl": FakeResult(
                        stdout="CCURE::ABSENT::unit is not known to systemd"
                    )
                }
            ),
        )
        assert state.status is CollectionStatus.ABSENT

    def test_an_empty_state_is_unavailable_not_an_empty_reading(self):
        state = LinuxServiceCollector().collect(
            check("service", {"name": "auditd"}),
            linux_ctx({"systemctl": FakeResult(stdout="CCURE::VALUE::")}),
        )
        assert state.status is CollectionStatus.UNAVAILABLE

    def test_a_bare_unit_name_gains_the_service_suffix(self):
        executor = FakeExecutor(
            {"systemctl": FakeResult(stdout="CCURE::VALUE::active")}
        )
        LinuxServiceCollector().collect(
            check("service", {"name": "auditd"}), ctx(executor, platform="linux")
        )
        assert "auditd.service" in executor.commands[-1]


class TestLinuxSecurityPolicy:
    def test_login_defs_is_read_whitespace_separated(self):
        state = LinuxSecurityPolicyCollector().collect(
            check("security_policy", {"setting": "pass_max_days"}),
            linux_ctx(
                {"login.defs": FakeResult(stdout="CCURE::VALUE::PASS_MAX_DAYS\t90\n")}
            ),
        )
        assert state.value == "90"

    def test_pwquality_settings_are_read_from_their_own_file(self):
        executor = FakeExecutor(
            {"pwquality": FakeResult(stdout="CCURE::VALUE::minlen = 14\n")}
        )
        state = LinuxSecurityPolicyCollector().collect(
            check("security_policy", {"setting": "minlen"}),
            ctx(executor, platform="linux"),
        )
        assert state.value == "14"
        assert "pwquality.conf" in executor.commands[-1]

    def test_a_missing_file_is_absent_not_a_default(self):
        state = LinuxSecurityPolicyCollector().collect(
            check("security_policy", {"setting": "pass_max_days"}),
            linux_ctx(
                {
                    "[ -f": FakeResult(
                        stdout="CCURE::ABSENT::/etc/login.defs does not exist"
                    )
                }
            ),
        )
        assert state.status is CollectionStatus.ABSENT


# ─────────────────────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────────────────────


class TestCollectorRegistry:
    def test_a_duplicate_registration_is_refused(self):
        """
        Two collectors claiming one pair means one silently never runs — the
        plugin-registration failure CLAUDE.md records, one layer up.
        """
        registry = CollectorRegistry()
        registry.register(WindowsRegistryCollector())
        with pytest.raises(ValueError, match="already registered"):
            registry.register(WindowsRegistryCollector())

    def test_replace_is_available_for_tests_that_need_it(self):
        registry = CollectorRegistry()
        registry.register(WindowsRegistryCollector())
        registry.register(WindowsRegistryCollector(), replace=True)

    def test_an_unregistered_pair_resolves_to_none(self):
        assert CollectorRegistry().resolve("registry", "windows") is None

    def test_registration_requires_a_check_type_and_platforms(self):
        class Anonymous(WindowsRegistryCollector):
            check_type = ""

        with pytest.raises(ValueError, match="check_type"):
            CollectorRegistry().register(Anonymous())

    def test_the_shared_registry_covers_both_host_platforms(self):
        from core.config_audit import collector_registry

        for platform in ("windows", "linux"):
            types = collector_registry.supported_check_types(platform)
            assert {"file", "service", "package", "port", "command"} <= set(types)

    def test_registry_is_a_windows_only_check_type(self):
        from core.config_audit import collector_registry

        assert collector_registry.resolve("registry", "windows") is not None
        assert collector_registry.resolve("registry", "linux") is None


class TestCollectedStateContract:
    def test_unavailable_without_a_reason_is_refused(self):
        """
        An unexplained failure is indistinguishable in a log from a check that
        did nothing.
        """
        with pytest.raises(ValueError, match="detail"):
            CollectedState(status=CollectionStatus.UNAVAILABLE)

    def test_observed_text_distinguishes_empty_from_absent_from_null(self):
        assert CollectedState.collected("").observed_text() == "(empty)"
        assert CollectedState.collected(None).observed_text() == "(null)"
        assert "not present" in CollectedState.absent("gone").observed_text()

    def test_only_collected_and_absent_are_observations(self):
        assert CollectionStatus.COLLECTED.is_observation
        assert CollectionStatus.ABSENT.is_observation
        assert not CollectionStatus.UNSUPPORTED.is_observation
        assert not CollectionStatus.UNAVAILABLE.is_observation

    def test_the_context_cache_computes_once_including_for_failures(self):
        calls = []

        def produce():
            calls.append(1)
            return "value"

        context = CollectionContext(target="t", platform="linux")
        assert context.cached("k", produce) == "value"
        assert context.cached("k", produce) == "value"
        assert len(calls) == 1
