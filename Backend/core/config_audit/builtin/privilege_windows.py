"""
core/config_audit/builtin/privilege_windows.py
─────────────────────────────────────────────────────────────────────────────
Windows local privilege-escalation and host-exposure checks (GAP-08).

Every check has the same shape: a probe enumerates offending items, the rule
asserts there are none, and the offenders become the evidence. So a clean host
produces an ABSENT reading — which ``AbsencePolicy.PASS`` turns into a pass —
and a breached one produces a FAIL naming exactly what to fix.

That shape is why ``absent`` is ``PASS`` here and ``MANUAL_REVIEW`` on most of
the Phase 3 Windows rules. A registry value that is missing tells you nothing,
because the platform default varies by build. A *search* that returned nothing
is a real result: the probe ran, and there were no offenders.

Severity is evidence-based, not uniform
───────────────────────────────────────
These are rated by what an attacker gains, and three of them are Critical
because they are a direct, unconditional path to SYSTEM:

* **A weak service ACL** lets a non-administrator rewrite the service's binary
  path. That is SYSTEM on the next start, with no other condition needed.
* **A writable service binary** is the same thing by a different route.
* **AlwaysInstallElevated** set in both hives means any MSI the user can write
  runs as SYSTEM.

The unquoted service path is High rather than Critical deliberately: it is only
exploitable if the attacker can *also* write to one of the truncated
directories, which is a separate condition this check does not establish. Rating
it Critical would put it above conditions that need nothing further.
"""

from __future__ import annotations

from typing import List

from core.checks.definitions import DEFINITION_TYPE_PRIVILEGE_CHECK
from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

__all__ = ["WINDOWS_PRIVILEGE_CHECKS", "windows_privilege_checks"]

_MS_DOCS = "https://learn.microsoft.com/windows/security/"


def _check(
    *,
    slug: str,
    probe: str,
    area: str,
    title: str,
    severity: str,
    description: str,
    rationale: str,
    remediation: str,
    references: tuple = (),
) -> ConfigCheck:
    return ConfigCheck(
        check_id=f"ccure.priv.win.{slug}",
        title=title,
        check_type="privilege",
        platforms=("windows",),
        domain="local_privilege",
        severity=severity,
        collect={"probe": probe},
        # No offenders is the compliant state. `is_empty` covers the case where
        # the probe returns an empty list rather than an absence, so the two
        # paths to "clean" agree.
        expect=Expectation("is_empty", description="no offending items"),
        absent=AbsencePolicy.PASS,
        finding_type=DEFINITION_TYPE_PRIVILEGE_CHECK,
        description=description,
        rationale=rationale,
        remediation=remediation,
        references=references or (_MS_DOCS,),
        metadata={"gap08_area": area},
    )


WINDOWS_PRIVILEGE_CHECKS: List[ConfigCheck] = [
    _check(
        slug="service.acl",
        probe="service_permissions",
        area="win.service_permissions",
        title="No service grants configuration rights to a non-administrator",
        severity="critical",
        description=(
            "Every service's security descriptor is read and checked for an "
            "access-control entry granting a non-administrative principal the "
            "right to change the service's configuration."
        ),
        rationale=(
            "A principal that can change a service's configuration can point "
            "its binary path at anything and restart it. That is SYSTEM on the "
            "next start, with no further condition — the shortest path from an "
            "ordinary account to full control of the host."
        ),
        remediation=(
            "Remove CHANGE_CONFIG, WRITE_DAC, WRITE_OWNER and ALL_ACCESS from "
            "non-administrative principals on the named services: "
            "sc.exe sdset <service> <SDDL>. Only Administrators and SYSTEM "
            "should hold them."
        ),
    ),
    _check(
        slug="service.binary.acl",
        probe="service_binary_permissions",
        area="win.service_binary_permissions",
        title="No service executable is writable by a non-administrator",
        severity="critical",
        description=(
            "The executable behind each service is resolved and its ACL "
            "inspected for write access granted to Everyone, Users, "
            "Authenticated Users or Guests."
        ),
        rationale=(
            "Overwriting the binary a service runs replaces what SYSTEM "
            "executes at the next start. It needs no other weakness and "
            "survives a reboot."
        ),
        remediation=(
            "Remove write, modify and full-control entries for non-"
            "administrative principals from the named executables, and from "
            "the directories containing them."
        ),
    ),
    _check(
        slug="always.install.elevated",
        probe="always_install_elevated",
        area="win.always_install_elevated",
        title="AlwaysInstallElevated is not enabled",
        severity="critical",
        description=(
            "Checks whether AlwaysInstallElevated is set to 1 in **both** "
            "HKLM and HKCU. Either alone has no effect and is not reported."
        ),
        rationale=(
            "With both set, any Windows Installer package runs with SYSTEM "
            "privileges regardless of who launches it. An unprivileged user "
            "who can write an MSI has full control of the host."
        ),
        remediation=(
            "Set AlwaysInstallElevated to 0, or remove it, under "
            "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer in both HKLM "
            "and HKCU."
        ),
    ),
    _check(
        slug="service.unquoted.path",
        probe="unquoted_service_path",
        area="win.unquoted_service_path",
        title="No service has an exploitable unquoted image path",
        severity="high",
        description=(
            "Services whose image path is unquoted, contains a space, and "
            "resolves outside %SystemRoot%. Unquoted paths without a space, "
            "and those under %SystemRoot%, are not reported — neither is "
            "hijackable."
        ),
        rationale=(
            "Windows resolves an unquoted path by trying each space-delimited "
            "prefix in turn, so C:\\Program Files\\App\\svc.exe will run "
            "C:\\Program.exe first if it exists. Where an unprivileged user "
            "can write to one of those directories, the service runs their "
            "binary as SYSTEM."
        ),
        remediation=(
            "Quote the image path: "
            'sc.exe config <service> binPath= "\\"C:\\Path With Spaces\\svc.exe\\"". '
            "Also confirm no non-administrator can write to the truncated "
            "directories."
        ),
    ),
    _check(
        slug="task.binary.acl",
        probe="scheduled_task_permissions",
        area="win.scheduled_task_permissions",
        title="No scheduled-task executable is writable by a non-administrator",
        severity="high",
        description=(
            "Each scheduled task's action executable is resolved and its ACL "
            "checked for write access granted to non-administrative "
            "principals."
        ),
        rationale=(
            "A task running as SYSTEM or an administrator executes whatever is "
            "at that path when it next fires. Overwriting it is code execution "
            "in that context, on the task's own schedule."
        ),
        remediation=(
            "Remove write access for non-administrative principals from the "
            "named executables, or repoint the task at a protected location."
        ),
    ),
    _check(
        slug="writable.path",
        probe="writable_path",
        area="win.writable_path",
        title="No directory on the system PATH is writable by a non-administrator",
        severity="high",
        description=(
            "Every directory on the machine PATH is checked for write access "
            "granted to Everyone, Users, Authenticated Users or Guests."
        ),
        rationale=(
            "Anything that resolves a command by name searches PATH in order. "
            "A writable directory early on it lets an unprivileged user place "
            "a binary that a privileged process then executes."
        ),
        remediation=(
            "Remove write access for non-administrative principals, or remove "
            "the directory from the machine PATH."
        ),
    ),
    _check(
        slug="unattend.files",
        probe="unattend_files",
        area="win.unattend_files",
        title="No unattended-install answer file remains on disk",
        severity="high",
        description=(
            "Looks for Unattend.xml, unattend.xml and sysprep.inf in the "
            "locations Windows setup leaves them."
        ),
        rationale=(
            "These files routinely contain a local administrator password, in "
            "plain text or reversible base64, and are readable by any local "
            "user. They are one of the first things an attacker with a shell "
            "reads."
        ),
        remediation=(
            "Delete the named files. If the credential they contain is still "
            "in use anywhere, rotate it — assume it is known."
        ),
    ),
    _check(
        slug="cached.logons",
        probe="cached_logons",
        area="win.cached_logons",
        title="Cached logon count is limited",
        severity="medium",
        description=("Reads CachedLogonsCount and reports a value above 4."),
        rationale=(
            "Cached domain credentials can be extracted offline by anyone who "
            "obtains the machine or SYSTEM on it. Each cached logon is another "
            "account whose credential is recoverable from this host."
        ),
        remediation=(
            "Set CachedLogonsCount to 4 or fewer under Winlogon, or 0 where "
            "the host is always able to reach a domain controller."
        ),
    ),
    _check(
        slug="lsa.protection",
        probe="lsa_protection",
        area="win.lsa_protection",
        title="LSA runs as a protected process (RunAsPPL)",
        severity="medium",
        description="Reads RunAsPPL under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa.",
        rationale=(
            "Without LSA protection, credential material held in LSASS can be "
            "read by any process running as SYSTEM — which is exactly what the "
            "privilege-escalation conditions above grant."
        ),
        remediation=(
            "Set RunAsPPL to 1 and reboot. Confirm no driver or security agent "
            "in use requires unprotected access to LSASS first."
        ),
    ),
    _check(
        slug="powershell.logging",
        probe="powershell_logging",
        area="win.powershell_logging",
        title="PowerShell script-block logging is enabled",
        severity="low",
        description=("Reads EnableScriptBlockLogging under the PowerShell policy key."),
        rationale=(
            "This is not itself an escalation path, which is why it is Low. "
            "It is the reason one leaves no trace: without script-block "
            "logging there is no record of what was run, and an investigation "
            "into any of the conditions above has nothing to reconstruct."
        ),
        remediation=(
            "Enable 'Turn on PowerShell Script Block Logging' by policy, and "
            "forward the resulting events off the host."
        ),
    ),
]


def windows_privilege_checks() -> List[ConfigCheck]:
    return list(WINDOWS_PRIVILEGE_CHECKS)
