"""
core/config_audit/collectors/windows.py
─────────────────────────────────────────────────────────────────────────────
Windows configuration collectors.

Every command below prints one of three sentinels rather than relying on empty
output to mean anything:

    CCURE::VALUE::<text>   a reading
    CCURE::ABSENT::<why>   ran fine, the item is not there
    (non-zero exit)        could not be read

That is the whole reason these are separate from ``WindowsCollector``'s
commands, which return bare text and cannot express the middle case. "The
registry value does not exist" and "the registry value is an empty string"
routinely mean opposite things for a hardening rule, and a collector that
returns ``""`` for both has already lost the distinction before the engine
sees it.

Commands are written to exit 0 for all three normal outcomes and to leave the
error path to PowerShell itself, so a non-zero exit unambiguously means the
read failed rather than the setting being off.

Reuse over re-collection
────────────────────────
``package``, ``port`` and ``security_policy`` answer from ``system_data`` when
a credentialed collection already gathered it — the same session's inventory of
191 packages should not be re-read once per package rule. They fall back to a
live query when it is absent. Both paths record which one produced the value,
because a reviewer challenging a finding needs to know whether it was read now
or read during collection.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable, Mapping, Optional

from core.config_audit.collection import CollectedState, CollectionContext
from core.config_audit.collectors.base import Collector, ShellRunner
from core.config_audit.spec import ConfigCheck

log = logging.getLogger("ccure.config_audit.windows")

__all__ = [
    "WindowsCommandCollector",
    "WindowsConfigFileCollector",
    "WindowsDirectoryCollector",
    "WindowsFileCollector",
    "WindowsPackageCollector",
    "WindowsPermissionCollector",
    "WindowsPortCollector",
    "WindowsProcessCollector",
    "WindowsRegistryCollector",
    "WindowsSecurityPolicyCollector",
    "WindowsServiceCollector",
    "register_windows_collectors",
]

_VALUE = "CCURE::VALUE::"
_ABSENT = "CCURE::ABSENT::"

#: Registry hive prefixes a rule may name, mapped to the PowerShell drive.
#: A rule naming an unknown hive is a rule defect and reports as unavailable
#: rather than being silently rewritten to HKLM.
_HIVES = {
    "HKLM": "HKLM:",
    "HKEY_LOCAL_MACHINE": "HKLM:",
    "HKCU": "HKCU:",
    "HKEY_CURRENT_USER": "HKCU:",
    "HKCR": "HKCR:",
    "HKEY_CLASSES_ROOT": "HKCR:",
    "HKU": "HKU:",
    "HKEY_USERS": "HKU:",
}


def ps_quote(value: Any) -> str:
    """
    Render *value* as a PowerShell single-quoted literal.

    Single quotes are doubled, which is PowerShell's own escape and the only
    one that holds inside a single-quoted string. Rule parameters reach these
    commands verbatim, and a path containing an apostrophe must not be able to
    terminate the literal and have the remainder parsed as code.
    """
    return "'" + str(value).replace("'", "''") + "'"


def _parse_sentinel(text: str) -> tuple[Optional[str], Optional[str]]:
    """
    Pull a sentinel out of command output.

    Returns ``(value, absent_reason)`` with exactly one of the two set, or
    ``(None, None)`` when the output carries no sentinel at all — which means
    the command did not run the way the collector expected and must not be read
    as a value.

    Two properties, and the second was a real defect before it was tested:

    * **Lines before the marker are skipped.** A profile banner or a provider
      warning routinely precedes the answer, so taking line one would read the
      banner as the host's setting.

    * **A value continues to the end of the output, not to the end of its
      line.** Only the first line carries the prefix, and ``file`` content and
      every ``config_file`` read are multi-line. Stopping at the newline
      returned the first directive of ``sshd_config`` and reported every other
      one as absent — a fleet-wide configuration gap that was really a parser
      bug. An absence reason is genuinely one line and is still read as one.
    """
    lines = (text or "").splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(_VALUE):
            head = line[line.index(_VALUE) + len(_VALUE) :]
            # Trailing newlines are an artefact of how the shell echoed the
            # value, not part of it. Interior blank lines are preserved.
            return "\n".join([head, *lines[index + 1 :]]).rstrip("\r\n"), None
        if stripped.startswith(_ABSENT):
            return None, stripped[len(_ABSENT) :] or "not present"
    return None, None


def _runner(ctx: CollectionContext) -> ShellRunner:
    key = "__shell_runner__"
    if key not in ctx.cache:
        ctx.cache[key] = ShellRunner(
            ctx.executor, ctx.platform, default_timeout=ctx.timeout
        )
    return ctx.cache[key]


class _WindowsCollector(Collector):
    """Shared plumbing: run a sentinel command and interpret its three outcomes."""

    platforms = ("windows",)

    def _sentinel_command(
        self,
        ctx: CollectionContext,
        command: str,
        *,
        timeout: Optional[int] = None,
    ) -> CollectedState:
        runner = _runner(ctx)
        if not runner.available:
            return CollectedState.unavailable(
                "no authenticated session to the Windows target",
                collector=self.name,
            )
        out = runner.run(command, timeout=timeout)
        if not out.ok:
            return CollectedState.unavailable(
                out.failure_detail(), raw=out.stderr or out.stdout, collector=self.name
            )
        value, absent_reason = _parse_sentinel(out.stdout)
        if absent_reason is not None:
            return CollectedState.absent(
                absent_reason, raw=out.text, collector=self.name
            )
        if value is None:
            # The command succeeded but printed nothing this collector can
            # read. Treating that as an empty value would put "" into the
            # comparison as though it were the host's setting.
            return CollectedState.unavailable(
                "command produced no recognisable result marker",
                raw=out.text,
                collector=self.name,
            )
        return CollectedState.collected(value, raw=out.text, collector=self.name)


# ─────────────────────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────────────────────


class WindowsRegistryCollector(_WindowsCollector):
    """
    Reads one registry value.

    Distinguishes a missing key from a missing value beneath a key that does
    exist. Both are ABSENT, with different detail, because a rule author
    debugging a surprising result needs to know which of the two happened —
    a missing key usually means the feature was never installed, a missing
    value that it is at its default.
    """

    check_type = "registry"
    name = "windows_registry"

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "path")
        if failure:
            return failure
        path = str(params["path"]).strip()
        value_name = params.get("value")

        hive, _, remainder = path.replace("/", "\\").partition("\\")
        drive = _HIVES.get(hive.upper().rstrip(":"))
        if not drive:
            return CollectedState.unavailable(
                f"registry path names an unknown hive {hive!r}; expected one "
                f"of {sorted(set(_HIVES))}",
                collector=self.name,
            )
        ps_path = f"{drive}\\{remainder}" if remainder else drive

        if not value_name:
            # Presence of the key itself is the reading.
            command = (
                f"$ErrorActionPreference='SilentlyContinue'; "
                f"if (Test-Path -LiteralPath {ps_quote(ps_path)}) "
                f"{{ Write-Output '{_VALUE}present' }} "
                f"else {{ Write-Output '{_ABSENT}registry key does not exist' }}"
            )
            return self._sentinel_command(ctx, command)

        command = (
            f"$ErrorActionPreference='SilentlyContinue'; "
            f"$p = {ps_quote(ps_path)}; $n = {ps_quote(value_name)}; "
            f"if (-not (Test-Path -LiteralPath $p)) "
            f"{{ Write-Output '{_ABSENT}registry key does not exist' }} "
            f"else {{ "
            f"$item = Get-ItemProperty -LiteralPath $p -ErrorAction SilentlyContinue; "
            f"if ($null -eq $item -or -not ($item.PSObject.Properties.Name -contains $n)) "
            f"{{ Write-Output '{_ABSENT}value is not set under an existing key' }} "
            f"else {{ Write-Output ('{_VALUE}' + [string]$item.$n) }} }}"
        )
        return self._sentinel_command(ctx, command)


# ─────────────────────────────────────────────────────────────────────────────
# Filesystem
# ─────────────────────────────────────────────────────────────────────────────


class WindowsFileCollector(_WindowsCollector):
    """
    Reads a file's existence, or one attribute of it.

    ``attribute`` selects what is compared: ``exists`` (default), ``content``,
    ``line_count``, ``size``. Content is capped — a rule that matches against a
    multi-megabyte log would otherwise pull it across the transport and into
    an evidence record.
    """

    check_type = "file"
    name = "windows_file"
    _MAX_CONTENT_BYTES = 64 * 1024

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "path")
        if failure:
            return failure
        path = ps_quote(params["path"])
        attribute = str(params.get("attribute", "exists")).strip().lower()
        cap = int(params.get("max_bytes", self._MAX_CONTENT_BYTES))

        if attribute == "exists":
            body = f"Write-Output '{_VALUE}present'"
        elif attribute == "content":
            body = (
                f"$raw = Get-Content -LiteralPath $p -Raw -ErrorAction Stop; "
                f"if ($raw.Length -gt {cap}) {{ $raw = $raw.Substring(0, {cap}) }}; "
                f"Write-Output ('{_VALUE}' + $raw)"
            )
        elif attribute == "line_count":
            body = (
                f"$n = (Get-Content -LiteralPath $p -ErrorAction Stop | "
                f"Measure-Object -Line).Lines; Write-Output ('{_VALUE}' + $n)"
            )
        elif attribute == "size":
            body = (
                f"$len = (Get-Item -LiteralPath $p -ErrorAction Stop).Length; "
                f"Write-Output ('{_VALUE}' + $len)"
            )
        else:
            return CollectedState.unavailable(
                f"file check requests unsupported attribute {attribute!r}",
                collector=self.name,
            )

        command = (
            f"$ErrorActionPreference='Stop'; $p = {path}; "
            f"if (-not (Test-Path -LiteralPath $p -PathType Leaf)) "
            f"{{ Write-Output '{_ABSENT}file does not exist' }} "
            f"else {{ {body} }}"
        )
        return self._sentinel_command(ctx, command)


class WindowsDirectoryCollector(_WindowsCollector):
    """Existence, or the number of entries, of a directory."""

    check_type = "directory"
    name = "windows_directory"

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "path")
        if failure:
            return failure
        attribute = str(params.get("attribute", "exists")).strip().lower()
        if attribute == "exists":
            body = f"Write-Output '{_VALUE}present'"
        elif attribute == "entry_count":
            body = (
                f"$n = @(Get-ChildItem -LiteralPath $p -Force -ErrorAction Stop).Count; "
                f"Write-Output ('{_VALUE}' + $n)"
            )
        else:
            return CollectedState.unavailable(
                f"directory check requests unsupported attribute {attribute!r}",
                collector=self.name,
            )
        command = (
            f"$ErrorActionPreference='Stop'; $p = {ps_quote(params['path'])}; "
            f"if (-not (Test-Path -LiteralPath $p -PathType Container)) "
            f"{{ Write-Output '{_ABSENT}directory does not exist' }} "
            f"else {{ {body} }}"
        )
        return self._sentinel_command(ctx, command)


class WindowsPermissionCollector(_WindowsCollector):
    """
    Reads the ACL of a filesystem path.

    ``attribute`` is ``owner`` or ``access`` (default). ``access`` renders one
    ``identity=rights`` pair per entry, semicolon separated and sorted, so a
    rule can test membership with ``contains`` and so that two hosts with the
    same ACL in a different order produce the same evidence text.
    """

    check_type = "permission"
    name = "windows_permission"

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "path")
        if failure:
            return failure
        attribute = str(params.get("attribute", "access")).strip().lower()
        if attribute == "owner":
            body = f"Write-Output ('{_VALUE}' + $acl.Owner)"
        elif attribute == "access":
            body = (
                "$pairs = $acl.Access | ForEach-Object { "
                "$_.IdentityReference.ToString() + '=' + "
                "$_.FileSystemRights.ToString() } | Sort-Object; "
                f"Write-Output ('{_VALUE}' + ($pairs -join '; '))"
            )
        else:
            return CollectedState.unavailable(
                f"permission check requests unsupported attribute {attribute!r}",
                collector=self.name,
            )
        command = (
            f"$ErrorActionPreference='Stop'; $p = {ps_quote(params['path'])}; "
            f"if (-not (Test-Path -LiteralPath $p)) "
            f"{{ Write-Output '{_ABSENT}path does not exist' }} "
            f"else {{ $acl = Get-Acl -LiteralPath $p; {body} }}"
        )
        return self._sentinel_command(ctx, command)


# ─────────────────────────────────────────────────────────────────────────────
# Services, processes
# ─────────────────────────────────────────────────────────────────────────────


class WindowsServiceCollector(_WindowsCollector):
    """
    Reads a service's running state or start mode.

    A service that is not installed is ABSENT, not "stopped". A hardening rule
    saying "the Telnet service must not be running" is satisfied by a host that
    never had it; one saying "the Windows Firewall service must be running" is
    breached by the same absence. Only the rule's ``absent`` policy can tell
    those apart, so the collector must not resolve it here.
    """

    check_type = "service"
    name = "windows_service"

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "name")
        if failure:
            return failure
        attribute = str(params.get("attribute", "status")).strip().lower()
        if attribute == "status":
            body = f"Write-Output ('{_VALUE}' + $svc.Status.ToString())"
        elif attribute == "start_mode":
            body = (
                "$cim = Get-CimInstance -ClassName Win32_Service -Filter "
                '("Name=\'" + $n.Replace("\'","\'\'") + "\'") '
                "-ErrorAction SilentlyContinue; "
                "if ($null -eq $cim) { Write-Output "
                f"'{_ABSENT}service has no Win32_Service record' }} "
                f"else {{ Write-Output ('{_VALUE}' + $cim.StartMode) }}"
            )
        else:
            return CollectedState.unavailable(
                f"service check requests unsupported attribute {attribute!r}",
                collector=self.name,
            )
        command = (
            f"$ErrorActionPreference='SilentlyContinue'; $n = {ps_quote(params['name'])}; "
            f"$svc = Get-Service -Name $n -ErrorAction SilentlyContinue; "
            f"if ($null -eq $svc) "
            f"{{ Write-Output '{_ABSENT}service is not installed' }} "
            f"else {{ {body} }}"
        )
        return self._sentinel_command(ctx, command)


class WindowsProcessCollector(_WindowsCollector):
    """Whether a named process is running, and how many instances."""

    check_type = "process"
    name = "windows_process"

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "name")
        if failure:
            return failure
        attribute = str(params.get("attribute", "running")).strip().lower()
        if attribute not in ("running", "instance_count"):
            return CollectedState.unavailable(
                f"process check requests unsupported attribute {attribute!r}",
                collector=self.name,
            )
        emit = (
            f"Write-Output ('{_VALUE}' + $procs.Count)"
            if attribute == "instance_count"
            else f"Write-Output '{_VALUE}running'"
        )
        command = (
            f"$ErrorActionPreference='SilentlyContinue'; "
            f"$procs = @(Get-Process -Name {ps_quote(params['name'])} "
            f"-ErrorAction SilentlyContinue); "
            f"if ($procs.Count -eq 0) "
            f"{{ Write-Output '{_ABSENT}no such process is running' }} "
            f"else {{ {emit} }}"
        )
        return self._sentinel_command(ctx, command)


# ─────────────────────────────────────────────────────────────────────────────
# Inventory-backed collectors
# ─────────────────────────────────────────────────────────────────────────────


def _iter_records(source: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(source, list):
        for entry in source:
            if isinstance(entry, Mapping):
                yield entry


class WindowsPackageCollector(_WindowsCollector):
    """
    Whether a package is installed, and at what version.

    Answers from the credentialed collection's software inventory when one is
    present. That inventory is the expensive read — 191 entries on the
    validation host — and a benchmark with fifty package rules would otherwise
    perform it fifty times.
    """

    check_type = "package"
    name = "windows_package"

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "name")
        if failure:
            return failure
        wanted = str(params["name"]).strip().lower()
        attribute = str(params.get("attribute", "installed")).strip().lower()
        if attribute not in ("installed", "version"):
            return CollectedState.unavailable(
                f"package check requests unsupported attribute {attribute!r}",
                collector=self.name,
            )

        inventory = (ctx.system_data or {}).get("installed_software")
        if isinstance(inventory, list) and inventory:
            for record in _iter_records(inventory):
                name = str(record.get("name") or record.get("Name") or "").strip()
                if name.lower() == wanted or wanted in name.lower():
                    version = str(
                        record.get("version") or record.get("Version") or ""
                    ).strip()
                    value = version if attribute == "version" else "installed"
                    if attribute == "version" and not version:
                        return CollectedState.absent(
                            "package is installed but records no version",
                            raw=name,
                            collector=self.name,
                        )
                    return CollectedState.collected(
                        value, raw=f"{name} {version}".strip(), collector=self.name
                    )
            return CollectedState.absent(
                "not present in the collected software inventory",
                collector=self.name,
            )

        # No inventory in hand — read the uninstall keys directly.
        command = (
            f"$ErrorActionPreference='SilentlyContinue'; "
            f"$want = {ps_quote(params['name'])}; "
            f"$paths = @('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
            f"'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); "
            f"$hit = Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | "
            f"Where-Object {{ $_.DisplayName -and $_.DisplayName -like ('*' + $want + '*') }} | "
            f"Select-Object -First 1; "
            f"if ($null -eq $hit) "
            f"{{ Write-Output '{_ABSENT}package is not installed' }} "
            + (
                f"else {{ if ([string]::IsNullOrEmpty($hit.DisplayVersion)) "
                f"{{ Write-Output '{_ABSENT}installed but records no version' }} "
                f"else {{ Write-Output ('{_VALUE}' + $hit.DisplayVersion) }} }}"
                if attribute == "version"
                else f"else {{ Write-Output '{_VALUE}installed' }}"
            )
        )
        return self._sentinel_command(ctx, command)


class WindowsPortCollector(_WindowsCollector):
    """
    Whether a TCP port is listening.

    Prefers the credentialed collection's socket table for the same reason as
    packages: it is one read that answers every port rule.
    """

    check_type = "port"
    name = "windows_port"

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "port")
        if failure:
            return failure
        try:
            port = int(str(params["port"]).strip())
        except (TypeError, ValueError):
            return CollectedState.unavailable(
                f"port check names a non-numeric port {params['port']!r}",
                collector=self.name,
            )

        table = (ctx.system_data or {}).get("open_ports")
        if isinstance(table, list) and table:
            for record in _iter_records(table):
                try:
                    entry_port = int(
                        str(record.get("port") or record.get("Port") or "").strip()
                    )
                except (TypeError, ValueError):
                    continue
                if entry_port == port:
                    return CollectedState.collected(
                        "listening",
                        raw=str(record)[:300],
                        collector=self.name,
                    )
            return CollectedState.absent(
                "port is not in the collected listening-socket table",
                collector=self.name,
            )

        command = (
            f"$ErrorActionPreference='SilentlyContinue'; "
            f"$c = @(Get-NetTCPConnection -State Listen -LocalPort {port} "
            f"-ErrorAction SilentlyContinue); "
            f"if ($c.Count -eq 0) "
            f"{{ Write-Output '{_ABSENT}no process is listening on this port' }} "
            f"else {{ Write-Output '{_VALUE}listening' }}"
        )
        return self._sentinel_command(ctx, command)


class WindowsSecurityPolicyCollector(_WindowsCollector):
    """
    Reads one local security-policy setting.

    Answers from the credentialed collection's ``password_policy`` where the
    named setting is one of the seven it already parses, and otherwise runs
    ``secedit`` and reads the exported INI.

    CLAUDE.md records that this data was once *synthesised* — a hard-coded
    ``{complexity: True, history_length: 24, min_length: 14}`` written for
    every host, which made every rule reading it pass unconditionally
    everywhere. A setting this collector cannot read is ABSENT or UNAVAILABLE;
    it is never defaulted.
    """

    check_type = "security_policy"
    name = "windows_security_policy"

    #: secedit's INI names for the settings ``password_policy`` already holds,
    #: so a rule can be written against either spelling.
    _POLICY_ALIASES = {
        "min_length": "MinimumPasswordLength",
        "minimum_password_length": "MinimumPasswordLength",
        "history_length": "PasswordHistorySize",
        "password_history_size": "PasswordHistorySize",
        "max_age": "MaximumPasswordAge",
        "maximum_password_age": "MaximumPasswordAge",
        "min_age": "MinimumPasswordAge",
        "lockout_threshold": "LockoutBadCount",
        "lockout_duration": "LockoutDuration",
        "complexity": "PasswordComplexity",
        "password_complexity": "PasswordComplexity",
    }

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "setting")
        if failure:
            return failure
        setting = str(params["setting"]).strip()
        canonical = self._POLICY_ALIASES.get(setting.lower(), setting)

        collected = (ctx.system_data or {}).get("password_policy")
        if isinstance(collected, Mapping) and collected:
            for candidate in (setting, setting.lower(), canonical):
                if candidate in collected:
                    value = collected[candidate]
                    if value is None:
                        break
                    return CollectedState.collected(
                        value,
                        raw=f"password_policy[{candidate}]={value}",
                        collector=f"{self.name}:collected",
                    )

        # Export the local policy once per run — a benchmark with twenty
        # policy rules must not run secedit twenty times — and read the
        # requested setting out of the memoised INI.
        exported = ctx.cached("__secedit__", lambda: self._run_secedit(ctx))
        if isinstance(exported, CollectedState):
            # The export itself failed. Its own detail is the useful one.
            return exported
        if not isinstance(exported, dict):
            return CollectedState.unavailable(
                "security policy could not be exported from the target",
                collector=self.name,
            )

        for candidate in (canonical, setting):
            if candidate in exported:
                return CollectedState.collected(
                    exported[candidate],
                    raw=f"{candidate} = {exported[candidate]}",
                    collector=f"{self.name}:secedit",
                )
        return CollectedState.absent(
            f"{canonical!r} is not present in the exported security policy",
            collector=f"{self.name}:secedit",
        )

    def _run_secedit(self, ctx: CollectionContext) -> Any:
        runner = _runner(ctx)
        if not runner.available:
            return CollectedState.unavailable(
                "no authenticated session to the Windows target",
                collector=self.name,
            )
        command = (
            "$ErrorActionPreference='SilentlyContinue'; "
            "$f = Join-Path $env:TEMP ('ccure_sec_' + [guid]::NewGuid().ToString() + '.inf'); "
            "secedit /export /areas SECURITYPOLICY /cfg $f | Out-Null; "
            "if (Test-Path -LiteralPath $f) { Get-Content -LiteralPath $f; "
            "Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue } "
            "else { Write-Output 'CCURE::SECEDIT_FAILED' }"
        )
        out = runner.run(command, timeout=ctx.timeout)
        if not out.ok or "CCURE::SECEDIT_FAILED" in out.stdout:
            return CollectedState.unavailable(
                f"secedit export failed: {out.failure_detail()}",
                raw=out.stderr or out.stdout,
                collector=self.name,
            )
        return _parse_ini(out.stdout)


def _parse_ini(text: str) -> dict[str, str]:
    """Flatten an INI export to ``{key: value}``, last section wins."""
    values: dict[str, str] = {}
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith((";", "#", "[")):
            continue
        key, sep, value = stripped.partition("=")
        if sep:
            values[key.strip()] = value.strip()
    return values


# ─────────────────────────────────────────────────────────────────────────────
# Generic text-configuration and command collectors
# ─────────────────────────────────────────────────────────────────────────────


class WindowsConfigFileCollector(_WindowsCollector):
    """
    Reads one directive out of a text configuration file.

    ``separator`` defaults to ``=``; ``comment`` to ``#``. The last occurrence
    wins, matching how nearly every configuration parser resolves a repeated
    directive — taking the first would report a value the software itself does
    not use.
    """

    check_type = "config_file"
    name = "windows_config_file"

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "path", "key")
        if failure:
            return failure
        command = (
            f"$ErrorActionPreference='Stop'; $p = {ps_quote(params['path'])}; "
            f"if (-not (Test-Path -LiteralPath $p -PathType Leaf)) "
            f"{{ Write-Output '{_ABSENT}configuration file does not exist' }} "
            f"else {{ Write-Output ('{_VALUE}' + "
            f'((Get-Content -LiteralPath $p -Raw) -replace "`r`n", "`n")) }}'
        )
        state = self._sentinel_command(ctx, command)
        if state.status.name != "COLLECTED":
            return state
        return _directive_from_text(
            str(state.value),
            key=str(params["key"]),
            separator=str(params.get("separator", "=")),
            comment=str(params.get("comment", "#")),
            collector=self.name,
            raw=state.raw,
        )


def _directive_from_text(
    text: str,
    *,
    key: str,
    separator: str,
    comment: str,
    collector: str,
    raw: Optional[str] = None,
) -> CollectedState:
    """
    Extract ``key`` from configuration text.

    A directive present but commented out is ABSENT, not a reading of its
    commented value: ``# PermitRootLogin yes`` is the software running on its
    default, and reporting "yes" there would be a finding invented out of a
    comment.
    """
    found: Optional[str] = None
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped or (comment and stripped.startswith(comment)):
            continue
        if separator:
            name, sep, value = stripped.partition(separator)
            if not sep:
                continue
        else:  # whitespace-separated, as in sshd_config
            parts = stripped.split(None, 1)
            if len(parts) != 2:
                continue
            name, value = parts[0], parts[1]
        if name.strip().lower() == key.strip().lower():
            found = value.strip()
    if found is None:
        return CollectedState.absent(
            f"directive {key!r} is not set (absent or commented out)",
            raw=raw,
            collector=collector,
        )
    return CollectedState.collected(found, raw=raw, collector=collector)


class WindowsCommandCollector(_WindowsCollector):
    """
    Runs a rule-supplied command and returns its output.

    The escape hatch for settings no typed collector reaches. Deliberately
    last: a benchmark expressed entirely as shell one-liners cannot be
    inspected, cached or reasoned about, and each one is a fresh opportunity
    for a non-zero exit to be read as a value.
    """

    check_type = "command"
    name = "windows_command"

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "command")
        if failure:
            return failure
        runner = _runner(ctx)
        if not runner.available:
            return CollectedState.unavailable(
                "no authenticated session to the Windows target",
                collector=self.name,
            )
        out = runner.run(str(params["command"]), timeout=ctx.timeout)
        if not out.ok:
            return CollectedState.unavailable(
                out.failure_detail(), raw=out.stderr or out.stdout, collector=self.name
            )
        text = out.text
        if not text and params.get("empty_is_absent", True):
            return CollectedState.absent(
                "command succeeded and produced no output",
                collector=self.name,
            )
        return CollectedState.collected(text, raw=out.text, collector=self.name)


def register_windows_collectors(registry: Any) -> None:
    for collector in (
        WindowsRegistryCollector(),
        WindowsFileCollector(),
        WindowsDirectoryCollector(),
        WindowsPermissionCollector(),
        WindowsServiceCollector(),
        WindowsProcessCollector(),
        WindowsPackageCollector(),
        WindowsPortCollector(),
        WindowsSecurityPolicyCollector(),
        WindowsConfigFileCollector(),
        WindowsCommandCollector(),
    ):
        registry.register(collector)
