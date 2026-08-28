"""
core/config_audit/collectors/linux.py
─────────────────────────────────────────────────────────────────────────────
Linux configuration collectors.

Same three-outcome contract as the Windows set: a ``CCURE::VALUE::`` line, a
``CCURE::ABSENT::`` line, or a non-zero exit meaning the read failed. The
commands are written so the *shell* exits 0 for all three normal outcomes,
because on this platform the temptation to conflate them is stronger — ``grep``
exits 1 when it matches nothing, which is a perfectly successful read of "the
directive is not there", and reading that exit code as a failure would make
every absent-directive rule unassessable.

Every parameter that reaches a command goes through ``shlex.quote``. Rule
parameters are data, and a path like ``/tmp/$(reboot)`` must reach ``test -f``
as a filename rather than as a command substitution — the rules are
administrator-editable, so this is an injection boundary inside the product,
not merely defensive style.
"""

from __future__ import annotations

import logging
import shlex
from typing import Any, Iterable, Mapping, Optional

from core.config_audit.collection import CollectedState, CollectionContext
from core.config_audit.collectors.base import Collector, ShellRunner
from core.config_audit.collectors.windows import _directive_from_text, _parse_sentinel
from core.config_audit.spec import ConfigCheck

log = logging.getLogger("ccure.config_audit.linux")

__all__ = [
    "LinuxCommandCollector",
    "LinuxConfigFileCollector",
    "LinuxDirectoryCollector",
    "LinuxFileCollector",
    "LinuxPackageCollector",
    "LinuxPermissionCollector",
    "LinuxPortCollector",
    "LinuxProcessCollector",
    "LinuxSecurityPolicyCollector",
    "LinuxServiceCollector",
    "register_linux_collectors",
]

_VALUE = "CCURE::VALUE::"
_ABSENT = "CCURE::ABSENT::"


def _emit_value(expression: str) -> str:
    """Shell fragment printing a VALUE sentinel followed by *expression*."""
    return f"printf '%s' '{_VALUE}'; {expression}"


def _emit_absent(reason: str) -> str:
    return f"printf '%s\\n' {shlex.quote(_ABSENT + reason)}"


def _runner(ctx: CollectionContext) -> ShellRunner:
    key = "__shell_runner__"
    if key not in ctx.cache:
        ctx.cache[key] = ShellRunner(
            ctx.executor, ctx.platform, default_timeout=ctx.timeout
        )
    return ctx.cache[key]


class _LinuxCollector(Collector):
    platforms = ("linux",)

    def _sentinel_command(
        self, ctx: CollectionContext, command: str, *, timeout: Optional[int] = None
    ) -> CollectedState:
        runner = _runner(ctx)
        if not runner.available:
            return CollectedState.unavailable(
                "no authenticated session to the Linux target", collector=self.name
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
            return CollectedState.unavailable(
                "command produced no recognisable result marker",
                raw=out.text,
                collector=self.name,
            )
        return CollectedState.collected(value, raw=out.text, collector=self.name)


# ─────────────────────────────────────────────────────────────────────────────
# Filesystem
# ─────────────────────────────────────────────────────────────────────────────


class LinuxFileCollector(_LinuxCollector):
    """Existence, content, line count or size of a file."""

    check_type = "file"
    name = "linux_file"
    _MAX_CONTENT_BYTES = 64 * 1024

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "path")
        if failure:
            return failure
        path = shlex.quote(str(params["path"]))
        attribute = str(params.get("attribute", "exists")).strip().lower()
        cap = int(params.get("max_bytes", self._MAX_CONTENT_BYTES))

        if attribute == "exists":
            body = f"printf '%s\\n' '{_VALUE}present'"
        elif attribute == "content":
            body = _emit_value(f"head -c {cap} -- {path}")
        elif attribute == "line_count":
            body = _emit_value(f"wc -l < {path} | tr -d ' '")
        elif attribute == "size":
            body = _emit_value(f"stat -c '%s' -- {path}")
        else:
            return CollectedState.unavailable(
                f"file check requests unsupported attribute {attribute!r}",
                collector=self.name,
            )
        command = f"if [ -f {path} ]; then {body}; else {_emit_absent('file does not exist')}; fi"
        return self._sentinel_command(ctx, command)


class LinuxDirectoryCollector(_LinuxCollector):
    """Existence, or entry count, of a directory."""

    check_type = "directory"
    name = "linux_directory"

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "path")
        if failure:
            return failure
        path = shlex.quote(str(params["path"]))
        attribute = str(params.get("attribute", "exists")).strip().lower()
        if attribute == "exists":
            body = f"printf '%s\\n' '{_VALUE}present'"
        elif attribute == "entry_count":
            body = _emit_value(f"ls -A -- {path} | wc -l | tr -d ' '")
        else:
            return CollectedState.unavailable(
                f"directory check requests unsupported attribute {attribute!r}",
                collector=self.name,
            )
        command = (
            f"if [ -d {path} ]; then {body}; "
            f"else {_emit_absent('directory does not exist')}; fi"
        )
        return self._sentinel_command(ctx, command)


class LinuxPermissionCollector(_LinuxCollector):
    """
    Reads mode, owner or group of a path.

    ``mode`` is returned as the octal ``stat`` prints — ``644``, not
    ``-rw-r--r--`` — so a rule can compare numerically. ``stat`` omits a
    leading zero on modes below 0100, which a rule expecting a fixed width
    would trip over; the value is left as the tool reports it rather than
    padded here, and the built-in rules compare with ``in`` against the
    spellings that actually occur.
    """

    check_type = "permission"
    name = "linux_permission"

    _ATTRIBUTES = {
        "mode": "%a",
        "owner": "%U",
        "group": "%G",
        "owner_uid": "%u",
        "group_gid": "%g",
    }

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "path")
        if failure:
            return failure
        attribute = str(params.get("attribute", "mode")).strip().lower()
        fmt = self._ATTRIBUTES.get(attribute)
        if not fmt:
            return CollectedState.unavailable(
                f"permission check requests unsupported attribute {attribute!r}; "
                f"expected one of {sorted(self._ATTRIBUTES)}",
                collector=self.name,
            )
        path = shlex.quote(str(params["path"]))
        command = (
            f"if [ -e {path} ]; then {_emit_value(f'stat -c {shlex.quote(fmt)} -- {path}')}; "
            f"else {_emit_absent('path does not exist')}; fi"
        )
        return self._sentinel_command(ctx, command)


# ─────────────────────────────────────────────────────────────────────────────
# Services, processes
# ─────────────────────────────────────────────────────────────────────────────


class LinuxServiceCollector(_LinuxCollector):
    """
    Reads a systemd unit's active state or enablement.

    ``systemctl is-active`` exits non-zero for an inactive unit, which is a
    successful read of "inactive" and not a collection failure — so its exit
    code is deliberately swallowed and only its stdout is used. A unit that
    systemd does not know about at all is ABSENT.

    A host with no systemd reports UNAVAILABLE rather than ABSENT: nothing was
    established about the service, only about the init system.
    """

    check_type = "service"
    name = "linux_service"

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "name")
        if failure:
            return failure
        attribute = str(params.get("attribute", "status")).strip().lower()
        if attribute not in ("status", "start_mode"):
            return CollectedState.unavailable(
                f"service check requests unsupported attribute {attribute!r}",
                collector=self.name,
            )
        unit = str(params["name"])
        if not unit.endswith(".service") and "." not in unit:
            unit = f"{unit}.service"
        quoted = shlex.quote(unit)
        query = "is-active" if attribute == "status" else "is-enabled"
        command = (
            "if ! command -v systemctl >/dev/null 2>&1; then exit 97; fi; "
            f"if ! systemctl list-unit-files --no-legend --no-pager {quoted} 2>/dev/null "
            f"| grep -q . && ! systemctl list-units --all --no-legend --no-pager {quoted} "
            f"2>/dev/null | grep -q .; then {_emit_absent('unit is not known to systemd')}; "
            f"else printf '%s' '{_VALUE}'; systemctl {query} {quoted} 2>/dev/null || true; fi"
        )
        runner = _runner(ctx)
        if not runner.available:
            return CollectedState.unavailable(
                "no authenticated session to the Linux target", collector=self.name
            )
        out = runner.run(command, timeout=ctx.timeout)
        if out.exit_code == 97:
            return CollectedState.unavailable(
                "systemctl is not present on this host, so unit state could "
                "not be read",
                collector=self.name,
            )
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
            return CollectedState.unavailable(
                "command produced no recognisable result marker",
                raw=out.text,
                collector=self.name,
            )
        # `systemctl is-active` on a known-but-dead unit prints "inactive";
        # printing nothing at all means the query itself did not answer.
        if not value.strip():
            return CollectedState.unavailable(
                f"systemctl {query} returned no state for {unit}",
                raw=out.text,
                collector=self.name,
            )
        return CollectedState.collected(
            value.strip(), raw=out.text, collector=self.name
        )


class LinuxProcessCollector(_LinuxCollector):
    """Whether a named process is running, and how many instances."""

    check_type = "process"
    name = "linux_process"

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
        name = shlex.quote(str(params["name"]))
        emit = (
            _emit_value("printf '%s' \"$n\"")
            if attribute == "instance_count"
            else f"printf '%s\\n' '{_VALUE}running'"
        )
        command = (
            "if ! command -v pgrep >/dev/null 2>&1; then exit 97; fi; "
            f"n=$(pgrep -c -x {name} 2>/dev/null || printf '0'); "
            f"if [ \"$n\" -eq 0 ]; then {_emit_absent('no such process is running')}; "
            f"else {emit}; fi"
        )
        runner = _runner(ctx)
        if not runner.available:
            return CollectedState.unavailable(
                "no authenticated session to the Linux target", collector=self.name
            )
        out = runner.run(command, timeout=ctx.timeout)
        if out.exit_code == 97:
            return CollectedState.unavailable(
                "pgrep is not present on this host, so process state could not "
                "be read",
                collector=self.name,
            )
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
            return CollectedState.unavailable(
                "command produced no recognisable result marker",
                raw=out.text,
                collector=self.name,
            )
        return CollectedState.collected(value, raw=out.text, collector=self.name)


# ─────────────────────────────────────────────────────────────────────────────
# Inventory-backed collectors
# ─────────────────────────────────────────────────────────────────────────────


def _iter_records(source: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(source, list):
        for entry in source:
            if isinstance(entry, Mapping):
                yield entry


class LinuxPackageCollector(_LinuxCollector):
    """
    Whether a package is installed, and at what version.

    Prefers the credentialed collection's package inventory. Falls back to
    ``dpkg-query`` then ``rpm``, and reports UNAVAILABLE — not ABSENT — where
    neither package manager is present: a host whose package manager could not
    be found has not established that the package is missing.
    """

    check_type = "package"
    name = "linux_package"

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

        inventory = (ctx.system_data or {}).get("installed_packages") or (
            ctx.system_data or {}
        ).get("installed_software")
        if isinstance(inventory, list) and inventory:
            for record in _iter_records(inventory):
                name = str(record.get("name") or record.get("Name") or "").strip()
                if name.lower() == wanted:
                    version = str(
                        record.get("version") or record.get("Version") or ""
                    ).strip()
                    if attribute == "version":
                        if not version:
                            return CollectedState.absent(
                                "package is installed but records no version",
                                raw=name,
                                collector=self.name,
                            )
                        return CollectedState.collected(
                            version, raw=f"{name} {version}", collector=self.name
                        )
                    return CollectedState.collected(
                        "installed",
                        raw=f"{name} {version}".strip(),
                        collector=self.name,
                    )
            return CollectedState.absent(
                "not present in the collected package inventory",
                collector=self.name,
            )

        pkg = shlex.quote(str(params["name"]))
        # Built as locals rather than inline: a backslash inside an f-string
        # expression is a syntax error on the Python this runs on (3.11), and
        # the shell fragments below need embedded double quotes.
        absent_branch = _emit_absent("package is not installed")
        value_branch = _emit_value('printf %s "$v"')
        command = (
            "if command -v dpkg-query >/dev/null 2>&1; then "
            f"v=$(dpkg-query -W -f='${{Version}}' {pkg} 2>/dev/null || true); "
            f"s=$(dpkg-query -W -f='${{Status}}' {pkg} 2>/dev/null || true); "
            'case "$s" in *"install ok installed"*) ;; *) v="" ;; esac; '
            "elif command -v rpm >/dev/null 2>&1; then "
            f"v=$(rpm -q --qf '%{{VERSION}}-%{{RELEASE}}' {pkg} 2>/dev/null || true); "
            'case "$v" in *"not installed"*) v="" ;; esac; '
            "else exit 97; fi; "
            'if [ -z "$v" ]; then ' + absent_branch + "; "
            "else " + value_branch + "; fi"
        )
        runner = _runner(ctx)
        if not runner.available:
            return CollectedState.unavailable(
                "no authenticated session to the Linux target", collector=self.name
            )
        out = runner.run(command, timeout=ctx.timeout)
        if out.exit_code == 97:
            return CollectedState.unavailable(
                "neither dpkg-query nor rpm is present, so package state could "
                "not be read",
                collector=self.name,
            )
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
            return CollectedState.unavailable(
                "command produced no recognisable result marker",
                raw=out.text,
                collector=self.name,
            )
        return CollectedState.collected(
            value if attribute == "version" else "installed",
            raw=out.text,
            collector=self.name,
        )


class LinuxPortCollector(_LinuxCollector):
    """Whether a TCP port is listening, from the socket table or ``ss``."""

    check_type = "port"
    name = "linux_port"

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
                        "listening", raw=str(record)[:300], collector=self.name
                    )
            return CollectedState.absent(
                "port is not in the collected listening-socket table",
                collector=self.name,
            )

        command = (
            "if ! command -v ss >/dev/null 2>&1; then exit 97; fi; "
            f"if ss -H -lnt 'sport = :{port}' 2>/dev/null | grep -q .; then "
            f"printf '%s\\n' '{_VALUE}listening'; "
            f"else {_emit_absent('no process is listening on this port')}; fi"
        )
        runner = _runner(ctx)
        if not runner.available:
            return CollectedState.unavailable(
                "no authenticated session to the Linux target", collector=self.name
            )
        out = runner.run(command, timeout=ctx.timeout)
        if out.exit_code == 97:
            return CollectedState.unavailable(
                "ss is not present on this host, so listening sockets could "
                "not be read",
                collector=self.name,
            )
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
            return CollectedState.unavailable(
                "command produced no recognisable result marker",
                raw=out.text,
                collector=self.name,
            )
        return CollectedState.collected(value, raw=out.text, collector=self.name)


class LinuxSecurityPolicyCollector(_LinuxCollector):
    """
    Reads one password or account policy setting.

    Answers from the credentialed collection's ``password_policy`` where it
    holds the setting, and otherwise reads ``/etc/login.defs`` — the same file
    ``LinuxCollector`` parses, so the two agree by construction.

    ``pwquality`` settings are read from ``/etc/security/pwquality.conf``. A
    setting present in neither file is ABSENT, which for most of them means the
    system default is in force; the rule decides whether that is acceptable,
    because the defaults differ by distribution and this collector must not
    pretend to know which one it is looking at.
    """

    check_type = "security_policy"
    name = "linux_security_policy"

    _LOGIN_DEFS = {
        "max_age": "PASS_MAX_DAYS",
        "pass_max_days": "PASS_MAX_DAYS",
        "min_age": "PASS_MIN_DAYS",
        "pass_min_days": "PASS_MIN_DAYS",
        "warn_age": "PASS_WARN_AGE",
        "pass_warn_age": "PASS_WARN_AGE",
        "min_length": "PASS_MIN_LEN",
        "pass_min_len": "PASS_MIN_LEN",
        "encrypt_method": "ENCRYPT_METHOD",
        "umask": "UMASK",
    }
    _PWQUALITY = {
        "minlen": "minlen",
        "dcredit": "dcredit",
        "ucredit": "ucredit",
        "lcredit": "lcredit",
        "ocredit": "ocredit",
        "minclass": "minclass",
        "maxrepeat": "maxrepeat",
    }

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "setting")
        if failure:
            return failure
        setting = str(params["setting"]).strip()
        lowered = setting.lower()

        collected = (ctx.system_data or {}).get("password_policy")
        if isinstance(collected, Mapping) and collected:
            for candidate in (setting, lowered):
                if candidate in collected and collected[candidate] is not None:
                    return CollectedState.collected(
                        collected[candidate],
                        raw=f"password_policy[{candidate}]={collected[candidate]}",
                        collector=f"{self.name}:collected",
                    )

        if lowered in self._PWQUALITY:
            return self._read_directive(
                ctx,
                path="/etc/security/pwquality.conf",
                key=self._PWQUALITY[lowered],
                separator="=",
            )
        key = self._LOGIN_DEFS.get(lowered, setting.upper())
        return self._read_directive(ctx, path="/etc/login.defs", key=key, separator="")

    def _read_directive(
        self, ctx: CollectionContext, *, path: str, key: str, separator: str
    ) -> CollectedState:
        quoted = shlex.quote(path)
        command = (
            f"if [ -f {quoted} ]; then {_emit_value(f'cat -- {quoted}')}; "
            f"else {_emit_absent(f'{path} does not exist')}; fi"
        )
        state = self._sentinel_command(ctx, command)
        if state.status.name != "COLLECTED":
            return state
        return _directive_from_text(
            str(state.value),
            key=key,
            separator=separator,
            comment="#",
            collector=self.name,
            raw=state.raw,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Generic text-configuration and command collectors
# ─────────────────────────────────────────────────────────────────────────────


class LinuxConfigFileCollector(_LinuxCollector):
    """
    Reads one directive out of a text configuration file.

    ``separator`` defaults to ``=``. Pass an empty string for whitespace-
    separated formats such as ``sshd_config`` and ``login.defs``.
    """

    check_type = "config_file"
    name = "linux_config_file"

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "path", "key")
        if failure:
            return failure
        quoted = shlex.quote(str(params["path"]))
        command = (
            f"if [ -f {quoted} ]; then {_emit_value(f'cat -- {quoted}')}; "
            f"else {_emit_absent('configuration file does not exist')}; fi"
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


class LinuxCommandCollector(_LinuxCollector):
    """Runs a rule-supplied command and returns its output."""

    check_type = "command"
    name = "linux_command"

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "command")
        if failure:
            return failure
        runner = _runner(ctx)
        if not runner.available:
            return CollectedState.unavailable(
                "no authenticated session to the Linux target", collector=self.name
            )
        out = runner.run(str(params["command"]), timeout=ctx.timeout)
        if not out.ok:
            return CollectedState.unavailable(
                out.failure_detail(), raw=out.stderr or out.stdout, collector=self.name
            )
        text = out.text
        if not text and params.get("empty_is_absent", True):
            return CollectedState.absent(
                "command succeeded and produced no output", collector=self.name
            )
        return CollectedState.collected(text, raw=out.text, collector=self.name)


def register_linux_collectors(registry: Any) -> None:
    for collector in (
        LinuxFileCollector(),
        LinuxDirectoryCollector(),
        LinuxPermissionCollector(),
        LinuxServiceCollector(),
        LinuxProcessCollector(),
        LinuxPackageCollector(),
        LinuxPortCollector(),
        LinuxSecurityPolicyCollector(),
        LinuxConfigFileCollector(),
        LinuxCommandCollector(),
    ):
        registry.register(collector)
