"""
core/config_audit/collectors/privilege_windows.py
─────────────────────────────────────────────────────────────────────────────
Windows local privilege-escalation and host-exposure enumeration.

Every probe answers the same shape of question — **which items are offending**
— and returns one offender per line, or nothing at all when the host is clean.
The rule then asserts the list is empty. A compliant host therefore produces an
ABSENT reading (the rule's policy turns that into PASS) and a breached one
produces the offenders as the evidence a triager acts on.

Why these are typed probes and not ``command`` rules
────────────────────────────────────────────────────
Phase 3 records the reason: "a benchmark expressed entirely as shell one-liners
cannot be inspected, cached or reasoned about, and each one is a fresh
opportunity for a non-zero exit to be read as a value". Service-ACL parsing is
not a one-liner, and a rule author should not be pasting one. The commands live
here, are unit-tested against captured output, and a rule names a probe.

What "offending" means, and why each probe is conservative
──────────────────────────────────────────────────────────
Every probe below reports only what it can *establish*. Where Windows makes a
condition ambiguous the probe reports nothing rather than guessing — an empty
result reads as "clean" and a false positive here sends someone to reconfigure
a service that was fine. Specifically:

* **Unquoted service paths** are only reported when the path is genuinely
  exploitable: unquoted, containing a space, and outside ``%SystemRoot%``. An
  unquoted path with no space cannot be hijacked, and reporting it is noise
  that trains a reader to ignore the finding.
* **Weak service ACLs** are only those granting a *non-administrative*
  principal a right that lets them change what the service runs
  (``CHANGE_CONFIG``, ``WRITE_DAC``, ``WRITE_OWNER``, ``ALL_ACCESS``).
  ``SERVICE_START`` alone is not privilege escalation.
* **AlwaysInstallElevated** requires **both** HKLM and HKCU to be set. Either
  alone does nothing, and reporting one of them as a finding is wrong.

`icacls` and `sc.exe sdshow` exit non-zero for reasons that are not the
question being asked (a service that vanished between enumeration and query),
so each probe swallows the per-item failure and continues; a probe that could
not run *at all* still reports UNAVAILABLE through the sentinel contract.
"""

from __future__ import annotations

import logging
from typing import Dict

from core.config_audit.collection import CollectedState, CollectionContext
from core.config_audit.collectors.base import Collector
from core.config_audit.collectors.windows import _ABSENT, _VALUE, _runner, ps_quote
from core.config_audit.spec import ConfigCheck

log = logging.getLogger("ccure.config_audit.privilege.windows")

__all__ = ["WindowsPrivilegeCollector", "WINDOWS_PROBES"]


#: Rights that let a non-administrator change what a service executes. Anything
#: outside this set — starting or stopping a service, reading its config — is
#: not privilege escalation and must not be reported as one.
_DANGEROUS_SERVICE_RIGHTS = (
    "'ChangeConfig','WriteDac','WriteOwner','AllAccess','GenericWrite','GenericAll'"
)

#: Principals whose write access to a service or binary is expected. A finding
#: that flags SYSTEM for being able to modify a service teaches the reader to
#: ignore the check.
_TRUSTED_SIDS = (
    "'S-1-5-32-544'"  # BUILTIN\Administrators
    ",'S-1-5-18'"  # LOCAL SYSTEM
    ",'S-1-5-19'"  # LOCAL SERVICE
    ",'S-1-5-20'"  # NETWORK SERVICE
    ",'S-1-3-0'"  # CREATOR OWNER
    ",'S-1-5-32-549'"  # Server Operators
)

#: Identities whose write access to a filesystem path is the finding.
_UNTRUSTED_IDENTITIES = (
    "'Everyone','BUILTIN\\Users','NT AUTHORITY\\Authenticated Users',"
    "'BUILTIN\\Guests','NT AUTHORITY\\INTERACTIVE','Users','Authenticated Users'"
)

_WRITE_RIGHTS = "'Write','Modify','FullControl','TakeOwnership','ChangePermissions'"


def _emit(body: str) -> str:
    """
    Wrap a probe body so it always terminates with a sentinel.

    ``$found`` is the list the body fills. Empty means clean, and the ABSENT
    sentinel says so explicitly rather than leaving the collector to read empty
    output — which is the reading that turns a failed command into a clean host.
    """
    return (
        "$ErrorActionPreference='SilentlyContinue'; $found=@(); "
        + body
        + "; if ($found.Count -eq 0) { Write-Output "
        + f"'{_ABSENT}no offending items found' "
        + "} else { Write-Output ("
        + f"'{_VALUE}' + ($found -join \"`n\")) }}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# The probe catalogue
# ─────────────────────────────────────────────────────────────────────────────

#: Unquoted service image paths that are genuinely hijackable.
_UNQUOTED_SERVICE_PATH = _emit(
    "Get-CimInstance Win32_Service | ForEach-Object { "
    "  $p = $_.PathName; "
    "  if ([string]::IsNullOrWhiteSpace($p)) { return }; "
    "  $t = $p.Trim(); "
    # Already quoted -> not hijackable.
    "  if ($t.StartsWith('\"')) { return }; "
    # No space in the executable portion -> nothing to hijack.
    "  $exe = $t; $sp = $t.IndexOf('.exe'); "
    "  if ($sp -ge 0) { $exe = $t.Substring(0, $sp + 4) }; "
    "  if ($exe -notmatch ' ') { return }; "
    # Under %SystemRoot% the directories are already admin-only.
    "  if ($exe -like ($env:SystemRoot + '*')) { return }; "
    "  $found += ($_.Name + ' :: ' + $exe) "
    "}"
)

#: Services whose security descriptor grants a non-admin the right to change
#: what the service runs.
_SERVICE_PERMISSIONS = _emit(
    f"$trusted = @({_TRUSTED_SIDS}); "
    f"$danger = @({_DANGEROUS_SERVICE_RIGHTS}); "
    "Get-Service | ForEach-Object { "
    "  $name = $_.Name; "
    "  $sddl = (& sc.exe sdshow $name 2>$null | Where-Object { $_ -match 'D:' }); "
    "  if (-not $sddl) { return }; "
    "  try { $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor("
    "    ($sddl -join '')) } catch { return }; "
    "  foreach ($ace in $sd.DiscretionaryAcl) { "
    "    $sid = $ace.SecurityIdentifier.Value; "
    "    if ($trusted -contains $sid) { continue }; "
    # Virtual service accounts, S-1-5-80-*.
    #
    # Found by real-target validation, which reported seven services on a
    # normal Windows 11 workstation because NT SERVICE\TrustedInstaller
    # (S-1-5-80-956008885-...) holds full control over service configuration —
    # which is how Windows servicing works — and because each service's own
    # virtual account holds ChangeConfig over itself.
    #
    # Both are machine-managed identities that no user can authenticate as, and
    # an attacker who can already act as a service account has that service's
    # privileges regardless. Reporting them is the noise that teaches a reader
    # to skip the finding, which is worse than not having the check.
    "    if ($sid -like 'S-1-5-80-*') { continue }; "
    "    $mask = $ace.AccessMask; "
    # SERVICE_CHANGE_CONFIG 0x0002, WRITE_DAC 0x40000, WRITE_OWNER 0x80000,
    # GENERIC_WRITE 0x40000000, GENERIC_ALL 0x10000000
    "    if (($mask -band 0x0002) -or ($mask -band 0x40000) -or "
    "        ($mask -band 0x80000) -or ($mask -band 0x40000000) -or "
    "        ($mask -band 0x10000000)) { "
    "      $who = $sid; "
    "      try { $who = (New-Object System.Security.Principal.SecurityIdentifier("
    "        $sid)).Translate([System.Security.Principal.NTAccount]).Value } catch {}; "
    "      $found += ($name + ' :: ' + $who + ' :: mask 0x' + "
    "        $mask.ToString('X')); break "
    "    } "
    "  } "
    "}"
)

#: Service executables a non-administrator can overwrite.
_SERVICE_BINARY_PERMISSIONS = _emit(
    f"$bad = @({_UNTRUSTED_IDENTITIES}); $rights = @({_WRITE_RIGHTS}); "
    "Get-CimInstance Win32_Service | ForEach-Object { "
    "  $name = $_.Name; $p = $_.PathName; "
    "  if ([string]::IsNullOrWhiteSpace($p)) { return }; "
    "  $t = $p.Trim().Trim('\"'); $sp = $t.IndexOf('.exe'); "
    "  if ($sp -ge 0) { $t = $t.Substring(0, $sp + 4) }; "
    "  if (-not (Test-Path -LiteralPath $t)) { return }; "
    "  try { $acl = Get-Acl -LiteralPath $t } catch { return }; "
    "  foreach ($ace in $acl.Access) { "
    "    if ($ace.AccessControlType -ne 'Allow') { continue }; "
    "    $who = $ace.IdentityReference.Value; "
    "    if ($bad -notcontains $who -and "
    "        $bad -notcontains ($who -replace '^.*\\\\','')) { continue }; "
    "    $r = $ace.FileSystemRights.ToString(); "
    "    foreach ($need in $rights) { if ($r -like ('*' + $need + '*')) { "
    "      $found += ($name + ' :: ' + $t + ' :: ' + $who + ' :: ' + $r); break } } "
    "  } "
    "}"
)

#: Both halves of AlwaysInstallElevated. Either alone does nothing.
_ALWAYS_INSTALL_ELEVATED = _emit(
    "$k='SOFTWARE\\Policies\\Microsoft\\Windows\\Installer'; "
    "$hklm = (Get-ItemProperty -Path ('HKLM:\\' + $k) "
    "  -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)"
    ".AlwaysInstallElevated; "
    "$hkcu = (Get-ItemProperty -Path ('HKCU:\\' + $k) "
    "  -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)"
    ".AlwaysInstallElevated; "
    "if ($hklm -eq 1 -and $hkcu -eq 1) { "
    "  $found += 'AlwaysInstallElevated is 1 in BOTH HKLM and HKCU — any MSI "
    "runs as SYSTEM' "
    "}"
)

#: Scheduled-task executables a non-administrator can overwrite.
_SCHEDULED_TASK_PERMISSIONS = _emit(
    f"$bad = @({_UNTRUSTED_IDENTITIES}); $rights = @({_WRITE_RIGHTS}); "
    "Get-ScheduledTask | ForEach-Object { "
    "  $tn = $_.TaskName; "
    "  foreach ($action in $_.Actions) { "
    "    $exe = $action.Execute; "
    "    if ([string]::IsNullOrWhiteSpace($exe)) { continue }; "
    "    $exe = [Environment]::ExpandEnvironmentVariables($exe.Trim().Trim('\"')); "
    "    if (-not (Test-Path -LiteralPath $exe)) { continue }; "
    "    try { $acl = Get-Acl -LiteralPath $exe } catch { continue }; "
    "    foreach ($ace in $acl.Access) { "
    "      if ($ace.AccessControlType -ne 'Allow') { continue }; "
    "      $who = $ace.IdentityReference.Value; "
    "      if ($bad -notcontains $who -and "
    "          $bad -notcontains ($who -replace '^.*\\\\','')) { continue }; "
    "      $r = $ace.FileSystemRights.ToString(); "
    "      foreach ($need in $rights) { if ($r -like ('*' + $need + '*')) { "
    "        $found += ($tn + ' :: ' + $exe + ' :: ' + $who); break } } "
    "    } "
    "  } "
    "}"
)

#: Directories on the machine PATH a non-administrator can write to. A binary
#: dropped there is executed by anything that resolves a name through PATH.
_WRITABLE_PATH = _emit(
    f"$bad = @({_UNTRUSTED_IDENTITIES}); $rights = @({_WRITE_RIGHTS}); "
    "$machinePath = [Environment]::GetEnvironmentVariable('Path','Machine'); "
    "foreach ($dir in ($machinePath -split ';')) { "
    "  if ([string]::IsNullOrWhiteSpace($dir)) { continue }; "
    "  $d = [Environment]::ExpandEnvironmentVariables($dir.Trim().Trim('\"')); "
    "  if (-not (Test-Path -LiteralPath $d -PathType Container)) { continue }; "
    "  try { $acl = Get-Acl -LiteralPath $d } catch { continue }; "
    "  foreach ($ace in $acl.Access) { "
    "    if ($ace.AccessControlType -ne 'Allow') { continue }; "
    "    $who = $ace.IdentityReference.Value; "
    "    if ($bad -notcontains $who -and "
    "        $bad -notcontains ($who -replace '^.*\\\\','')) { continue }; "
    "    $r = $ace.FileSystemRights.ToString(); "
    "    foreach ($need in $rights) { if ($r -like ('*' + $need + '*')) { "
    "      $found += ($d + ' :: ' + $who + ' :: ' + $r); break } } "
    "  } "
    "}"
)

#: Unattended-install answer files left on disk. They routinely contain a
#: local administrator password in plain text or base64.
_UNATTEND_FILES = _emit(
    "$paths = @("
    "  ($env:SystemRoot + '\\Panther\\Unattend.xml'),"
    "  ($env:SystemRoot + '\\Panther\\Unattended.xml'),"
    "  ($env:SystemRoot + '\\Panther\\Unattend\\Unattend.xml'),"
    "  ($env:SystemRoot + '\\System32\\Sysprep\\unattend.xml'),"
    "  ($env:SystemRoot + '\\System32\\Sysprep\\Panther\\unattend.xml'),"
    "  ($env:SystemDrive + '\\unattend.xml'),"
    "  ($env:SystemDrive + '\\sysprep.inf')"
    "); "
    "foreach ($p in $paths) { if (Test-Path -LiteralPath $p) { $found += $p } }"
)

#: How many logons Windows caches. Cached credentials are recoverable offline
#: by anyone who obtains the machine.
_CACHED_LOGONS = _emit(
    "$v = (Get-ItemProperty -Path "
    "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' "
    "-Name CachedLogonsCount -ErrorAction SilentlyContinue).CachedLogonsCount; "
    "if ($null -ne $v -and [int]$v -gt 4) { "
    "  $found += ('CachedLogonsCount = ' + $v + ' (more than 4 logons cached)') }"
)

#: LSA run as a protected process. Without it, credential material in LSASS is
#: readable by any process running as SYSTEM.
_LSA_PROTECTION = _emit(
    "$v = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
    "-Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL; "
    "if ($null -eq $v -or [int]$v -eq 0) { "
    "  $found += 'RunAsPPL is not enabled — LSASS is not a protected process' }"
)

#: PowerShell script-block logging. Its absence is not privilege escalation; it
#: is the reason an escalation leaves no trace, which is why it is Low rather
#: than being left out.
_POWERSHELL_LOGGING = _emit(
    "$v = (Get-ItemProperty -Path ('HKLM:\\SOFTWARE\\Policies\\Microsoft\\"
    "Windows\\PowerShell\\ScriptBlockLogging') "
    "-Name EnableScriptBlockLogging -ErrorAction SilentlyContinue)"
    ".EnableScriptBlockLogging; "
    "if ($null -eq $v -or [int]$v -eq 0) { "
    "  $found += 'PowerShell script-block logging is not enabled' }"
)

WINDOWS_PROBES: Dict[str, str] = {
    "unquoted_service_path": _UNQUOTED_SERVICE_PATH,
    "service_permissions": _SERVICE_PERMISSIONS,
    "service_binary_permissions": _SERVICE_BINARY_PERMISSIONS,
    "always_install_elevated": _ALWAYS_INSTALL_ELEVATED,
    "scheduled_task_permissions": _SCHEDULED_TASK_PERMISSIONS,
    "writable_path": _WRITABLE_PATH,
    "unattend_files": _UNATTEND_FILES,
    "cached_logons": _CACHED_LOGONS,
    "lsa_protection": _LSA_PROTECTION,
    "powershell_logging": _POWERSHELL_LOGGING,
}


class WindowsPrivilegeCollector(Collector):
    """Enumerates local privilege-escalation conditions on a Windows host."""

    check_type = "privilege"
    platforms = ("windows",)
    name = "windows_privilege"

    #: These walk every service and stat every service binary. On a host with
    #: 200 services that is slower than a registry read, so the default is
    #: raised above the engine's 45s rather than left to time out mid-probe and
    #: report a clean host.
    default_timeout = 180

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "probe")
        if failure:
            return failure
        probe = str(params["probe"]).strip().lower()
        command = WINDOWS_PROBES.get(probe)
        if command is None:
            # A rule naming a probe this build does not have is a product gap,
            # not a property of the host — the same reading the engine gives an
            # unimplemented check type.
            return CollectedState.unavailable(
                f"no Windows privilege probe named {probe!r}; available: "
                f"{', '.join(sorted(WINDOWS_PROBES))}",
                collector=self.name,
            )

        runner = _runner(ctx)
        if not runner.available:
            return CollectedState.unavailable(
                "no authenticated session to the Windows target",
                collector=self.name,
            )

        timeout = max(int(ctx.timeout or 0), self.default_timeout)
        out = runner.run(command, timeout=timeout)
        if not out.ok:
            return CollectedState.unavailable(
                out.failure_detail(), raw=out.stderr or out.stdout, collector=self.name
            )

        from core.config_audit.collectors.windows import _parse_sentinel

        value, absent_reason = _parse_sentinel(out.stdout)
        if absent_reason is not None:
            return CollectedState.absent(
                absent_reason, raw=out.text, collector=self.name
            )
        if value is None:
            return CollectedState.unavailable(
                "probe produced no recognisable result marker",
                raw=out.text,
                collector=self.name,
            )
        offenders = [line.strip() for line in value.splitlines() if line.strip()]
        # Returned as a list so the rule's `is_empty` sees a list and the
        # evidence renders one offender per entry rather than one blob.
        return CollectedState.collected(offenders, raw=out.text, collector=self.name)


def register_windows_privilege_collector(registry) -> None:
    registry.register(WindowsPrivilegeCollector())
