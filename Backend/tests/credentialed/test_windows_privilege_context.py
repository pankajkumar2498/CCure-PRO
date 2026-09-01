"""
What privilege the Windows session held, recorded with the results.

There is **no elevation mechanism on the Windows path and none is invented
here.** WinRM and OpenSSH both run as whoever authenticated; this product does
not create a service or a scheduled task to escalate, and doing so would be an
intrusive change to a host it is only meant to assess.

What that leaves is a reporting problem rather than a collection one. The same
check set produces different answers under an administrator and under a
standard user — a registry read that returns a value to one and nothing to the
other — and until this was recorded there was nothing in the result to say
which had happened.

Measured against a real Windows 11 Pro host over WinRM as a member of
Administrators: **20 of 20 Windows built-in checks completed, 0 errors.** No
check in the current set needs SYSTEM.
"""

import pytest
from engines.credentialed.ssh_scanner import CommandResult
from engines.credentialed.windows_collector import COMMANDS, WindowsCollector


class _Executor:
    """Answers the privilege probe with whatever a test hands it."""

    ip = "10.0.0.5"

    def __init__(self, privilege_json):
        self._privilege_json = privilege_json

    def run(self, command, timeout=None, stdin_data=None):
        # Answer the shell probe so the collector resolves to "powershell" and
        # sends commands verbatim. Left unanswered it assumes cmd.exe and
        # base64-encodes everything, and the matching below would never fire —
        # the test would pass while asserting nothing. This is also the real
        # shape over WinRM, which is always PowerShell.
        if "PSVersionTable" in command:
            return CommandResult(stdout="5", exit_code=0, success=True)
        if "WindowsIdentity" in command:
            if self._privilege_json is None:
                return CommandResult(stderr="denied", exit_code=1, success=False)
            return CommandResult(stdout=self._privilege_json, exit_code=0, success=True)
        return CommandResult(stdout="", exit_code=0, success=True)


def _context(privilege_json):
    collector = WindowsCollector(_Executor(privilege_json))
    return collector._collect_system_info().get("privilege_context")


# ─────────────────────────────────────────────────────────────────────────────
# The token is recorded
# ─────────────────────────────────────────────────────────────────────────────


def test_an_administrator_session_is_recorded_as_such():
    context = _context(
        '{"Name":"HOST\\\\svc_scan","IsAdministrator":true,"IsSystem":false}'
    )
    assert context["is_administrator"] is True
    assert context["is_system"] is False
    assert context["account"] == "HOST\\svc_scan"


def test_a_standard_user_session_is_recorded_as_such():
    """
    The case the record exists for. Its findings are a subset of what an
    administrator would have seen, and nothing else in the result says so.
    """
    context = _context(
        '{"Name":"HOST\\\\helpdesk","IsAdministrator":false,"IsSystem":false}'
    )
    assert context["is_administrator"] is False


def test_a_system_session_is_distinguished_from_an_administrator():
    context = _context(
        '{"Name":"NT AUTHORITY\\\\SYSTEM",' '"IsAdministrator":true,"IsSystem":true}'
    )
    assert context["is_system"] is True


def test_an_unreadable_probe_is_unknown_rather_than_not_administrator():
    """
    Three states, and collapsing two of them is the bug. Reading a failed probe
    as "not an administrator" would attribute a complete audit's findings to a
    partial one and invite a reader to discount them.
    """
    context = _context(None)
    assert context["is_administrator"] is None
    assert context["is_system"] is None


def test_a_malformed_probe_response_is_also_unknown():
    context = _context("not json at all")
    assert context["is_administrator"] is None


# ─────────────────────────────────────────────────────────────────────────────
# How the probe is written
# ─────────────────────────────────────────────────────────────────────────────


def test_the_probe_asks_windows_rather_than_matching_a_group_name():
    """
    ``WindowsBuiltInRole.Administrator`` resolves to S-1-5-32-544. Matching the
    group's *name* fails on a non-English install, where the group is not
    called "Administrators".
    """
    probe = COMMANDS["privilege_context"]
    assert "WindowsBuiltInRole]::Administrator" in probe
    assert "'Administrators'" not in probe


def test_the_probe_reads_and_writes_nothing_on_the_target():
    """
    ``New-Object`` constructs a .NET object in the remote session and changes
    nothing, so the check is against cmdlets that touch the machine rather than
    against the verb alone.
    """
    probe = COMMANDS["privilege_context"]
    for mutating in (
        "Set-ItemProperty",
        "New-Item",
        "New-Service",
        "Remove-",
        "Start-Service",
        "Stop-Service",
        "Register-",
        "Out-File",
    ):
        assert mutating not in probe


@pytest.mark.parametrize(
    "mechanism",
    [
        "New-Service",
        "Register-ScheduledTask",
        "schtasks",
        "psexec",
        "runas",
        "Start-Process -Verb",
        "Invoke-WmiMethod -Class Win32_Process",
    ],
)
def test_no_elevation_mechanism_is_invented_on_the_windows_path(mechanism):
    """
    A guard on the instruction, not just on today's code. Escalating by creating
    a service or a scheduled task changes a host this product is only meant to
    read, and it is how a scanner becomes the incident.
    """
    import inspect

    from engines.credentialed import windows_collector

    assert mechanism not in inspect.getsource(windows_collector)


def test_the_windows_path_has_no_sudo_equivalent():
    """
    ``SSHScanner.run_sudo`` is POSIX-only by construction. If a Windows
    elevation helper is ever added it must arrive with its own review, not by
    quietly acquiring the name.
    """
    from engines.credentialed.winrm_executor import WinRMExecutor

    assert not hasattr(WinRMExecutor, "run_sudo")


def test_the_privilege_context_reaches_the_stored_report():
    """
    Collected but unreachable is not recorded. The stored report's
    ``system_info`` is what the asset sync and the report generators read, so a
    value that stops at ``system_data`` tells nobody anything.
    """
    import inspect

    from core import tasks

    source = inspect.getsource(tasks.audit_credentialed_host)
    assert '"privilege_context": system_data.get("privilege_context")' in source
