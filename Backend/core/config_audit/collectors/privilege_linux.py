"""
core/config_audit/collectors/privilege_linux.py
─────────────────────────────────────────────────────────────────────────────
Linux local privilege-escalation and host-exposure enumeration.

Same contract as the Windows probes: one offender per line, nothing at all when
the host is clean, and a non-zero exit meaning the probe could not run.

Four of these replace prose
───────────────────────────
``LinuxCollector._collect_security_audit`` already gathers SUID binaries,
world-writable directories and sudo rules — and turns them into sentences in
``security_issues``:

    "NOPASSWD sudo rule detected — any command runs without password"
    "37 SUID binaries found — review for privilege escalation risk"

A sentence in a PDF has no severity, no risk score, no remediation, no
lifecycle, no deduplication and cannot be exported or triaged. The probes below
produce the same observations as findings. The collector keeps emitting its
prose — the report's posture section reads it and nothing here should change
what an existing report says — but the *finding* is now the authoritative form.

Allow-listing, and why a bare count is not a check
──────────────────────────────────────────────────
"37 SUID binaries" is not a finding: a stock distribution ships around thirty
and the number says nothing. What matters is a SUID bit on something that
should not carry one. ``_EXPECTED_SUID`` is the set a normal system has, so the
probe reports the *difference* — which on a clean host is empty, and on a
tampered one names the binary.

The list is conservative in the direction that under-reports: a legitimate
binary missing from it produces a false positive, which is the failure that
trains a reader to ignore the check, so anything commonly shipped is included.

Exit 97 is the reserved "the tool I needed is not installed" sentinel from
Phase 3. A host with no ``find`` establishes nothing about its SUID binaries,
and reporting that as "none found" would be the exact inversion this engine
exists to prevent.
"""

from __future__ import annotations

import logging
import shlex
from typing import Dict

from core.config_audit.collection import CollectedState, CollectionContext
from core.config_audit.collectors.base import Collector
from core.config_audit.collectors.linux import _runner
from core.config_audit.collectors.windows import _parse_sentinel
from core.config_audit.spec import ConfigCheck

log = logging.getLogger("ccure.config_audit.privilege.linux")

__all__ = ["LinuxPrivilegeCollector", "LINUX_PROBES", "EXPECTED_SUID"]

_VALUE = "CCURE::VALUE::"
_ABSENT = "CCURE::ABSENT::"

#: SUID/SGID binaries a stock distribution ships. Reporting these would be
#: noise; reporting a SUID bit on anything *else* is the finding.
#:
#: Deliberately generous. A legitimate binary missing from this list becomes a
#: false positive, and a check that cries wolf is worse than one that misses —
#: the reader stops looking. Entries are basenames, matched exactly.
EXPECTED_SUID = (
    "at",
    "chage",
    "chfn",
    "chsh",
    "crontab",
    "expiry",
    "fusermount",
    "fusermount3",
    "gpasswd",
    "mount",
    "mount.nfs",
    "newgidmap",
    "newgrp",
    "newuidmap",
    "ntfs-3g",
    "pam_timestamp_check",
    "passwd",
    "pkexec",
    "polkit-agent-helper-1",
    "ping",
    "ping6",
    "su",
    "sudo",
    "sudoedit",
    "umount",
    "unix_chkpwd",
    "write",
    "ssh-agent",
    "dbus-daemon-launch-helper",
    "utempter",
    "staprun",
    "cockpit-session",
    "grub2-set-bootflag",
    # Legitimately SUID on Debian and Ubuntu, for host-based authentication.
    # Reported on a stock container during real-target validation.
    "ssh-keysign",
    "vmware-user-suid-wrapper",
    "Xorg.wrap",
    "snap-confine",
)


def _emit(body: str) -> str:
    """
    Wrap a probe so it always terminates with a sentinel.

    ``$found`` accumulates offenders, newline-separated. Empty means clean and
    says so, rather than leaving the collector to read empty output — the
    reading that turns a failed command into a healthy host.
    """
    return (
        "found=''; "
        + body
        + "; if [ -z \"$found\" ]; then printf '%s\\n' "
        + f"'{_ABSENT}no offending items found'; "
        + f"else printf '%s' '{_VALUE}'; printf '%s\\n' \"$found\"; fi"
    )


_SUID_LIST = " ".join(shlex.quote(name) for name in EXPECTED_SUID)

#: SUID binaries outside the expected set.
_SUID_BINARIES = _emit(
    "if ! command -v find >/dev/null 2>&1; then exit 97; fi; "
    f"expected=' {' '.join(EXPECTED_SUID)} '; "
    "hits=$(timeout 60 find / -xdev -perm -4000 -type f "
    "  -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -200); "
    "for f in $hits; do "
    '  b=$(basename "$f"); '
    '  case "$expected" in *" $b "*) continue ;; esac; '
    '  found="$found$f\n"; '
    "done"
)

#: SGID binaries outside the expected set.
_SGID_BINARIES = _emit(
    "if ! command -v find >/dev/null 2>&1; then exit 97; fi; "
    f"expected=' {' '.join(EXPECTED_SUID)} '; "
    "hits=$(timeout 60 find / -xdev -perm -2000 -type f "
    "  -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -200); "
    "for f in $hits; do "
    '  b=$(basename "$f"); '
    '  case "$expected" in *" $b "*) continue ;; esac; '
    '  found="$found$f\n"; '
    "done"
)

#: World-writable directories missing the sticky bit. With the sticky bit a
#: user can only remove their own files; without it anyone can replace anyone's.
_WORLD_WRITABLE_DIRS = _emit(
    "if ! command -v find >/dev/null 2>&1; then exit 97; fi; "
    "hits=$(timeout 60 find / -xdev -type d -perm -0002 ! -perm -1000 "
    "  -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -100); "
    'for d in $hits; do found="$found$d\n"; done'
)

#: World-writable regular files outside the pseudo-filesystems.
_WORLD_WRITABLE_FILES = _emit(
    "if ! command -v find >/dev/null 2>&1; then exit 97; fi; "
    "hits=$(timeout 60 find / -xdev -type f -perm -0002 "
    "  -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -100); "
    'for f in $hits; do found="$found$f\n"; done'
)

#: sudo rules granting command execution with no password.
#:
#: Parsed from the files rather than from `sudo -l`, which reports only the
#: invoking user's rules — and the scanner's account is rarely the one whose
#: NOPASSWD rule matters.
_SUDO_NOPASSWD = _emit(
    "for f in /etc/sudoers $(ls /etc/sudoers.d/* 2>/dev/null); do "
    '  [ -r "$f" ] || continue; '
    "  while IFS= read -r line; do "
    '    case "$line" in \\#*) continue ;; esac; '
    '    case "$line" in *NOPASSWD*) found="$found$f: $line\n" ;; esac; '
    '  done < "$f"; '
    "done"
)

#: Directories on root's PATH that a non-root user can write to.
_WRITABLE_PATH = _emit(
    "p=$(sudo -n printenv PATH 2>/dev/null || printenv PATH 2>/dev/null || "
    "  echo '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'); "
    "IFS=':'; for d in $p; do "
    '  [ -n "$d" ] || continue; '
    '  [ -d "$d" ] || continue; '
    '  if [ -w "$d" ] && [ "$(id -u)" != \'0\' ]; then '
    '    found="$found$d (writable by $(id -un))\n"; continue; fi; '
    # `stat` does NOT dereference by default, and /bin, /sbin and /lib are
    # symlinks into /usr on every modern distribution. A symlink's own mode is
    # always 777, so without -L this reported /bin and /sbin as world-writable
    # on every host — found by real-target validation.
    "  perm=$(stat -L -c '%a' \"$d\" 2>/dev/null); "
    '  case "$perm" in *2|*3|*6|*7) found="$found$d (mode $perm)\n" ;; esac; '
    "done; unset IFS"
)

#: Relative or empty entries on root's PATH. An empty entry means "the current
#: directory", so a binary dropped anywhere root happens to cd into is executed.
_ROOT_PATH_INTEGRITY = _emit(
    "p=$(sudo -n printenv PATH 2>/dev/null || printenv PATH 2>/dev/null); "
    "[ -n \"$p\" ] || p='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin'; "
    'case "$p" in ::*|*::*|*:) found="${found}PATH contains an empty entry '
    '(the current directory): $p\n" ;; esac; '
    "IFS=':'; for d in $p; do "
    '  [ -n "$d" ] || continue; '
    '  case "$d" in /*) ;; *) found="$found relative PATH entry: $d\n" ;; esac; '
    "done; unset IFS"
)

#: Files owned by a uid with no passwd entry — usually left by a removed
#: account, and adopted by whoever is next assigned that uid.
_UNOWNED_FILES = _emit(
    "if ! command -v find >/dev/null 2>&1; then exit 97; fi; "
    "hits=$(timeout 60 find / -xdev -nouser "
    "  -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -50); "
    'for f in $hits; do found="$found$f\n"; done'
)

#: Files owned by a gid with no group entry.
_UNGROUPED_FILES = _emit(
    "if ! command -v find >/dev/null 2>&1; then exit 97; fi; "
    "hits=$(timeout 60 find / -xdev -nogroup "
    "  -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -50); "
    'for f in $hits; do found="$found$f\n"; done'
)

#: The account-database files that decide who may become whom.
#:
#: Deliberately scoped around what the Phase 3 built-ins already assert.
#: ``ccure.linux.passwd.permissions`` and ``ccure.linux.shadow.permissions``
#: already check the *modes* of those two files, so repeating them here would
#: produce two findings for one root cause — inflating a host's finding count
#: and making the remediation look twice as large as it is.
#:
#: What is genuinely uncovered, and is what this probe reports: **ownership**
#: of all four files, and the **modes** of ``/etc/group`` and ``/etc/gshadow``,
#: which nothing else looks at.
_SENSITIVE_FILE_MODES = _emit(
    # Ownership of all four — not covered anywhere else. A root-owned mode 644
    # and a user-owned mode 644 are very different things.
    "for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do "
    '  [ -e "$f" ] || continue; '
    "  o=$(stat -L -c '%U' \"$f\" 2>/dev/null) || continue; "
    "  if [ \"$o\" != 'root' ]; then "
    '    found="$found$f owned by $o (expected root)\n"; fi; '
    "done; "
    # Modes of the two files the Phase 3 built-ins do not look at.
    "for f in /etc/group /etc/gshadow; do "
    '  [ -e "$f" ] || continue; '
    "  m=$(stat -L -c '%a' \"$f\" 2>/dev/null) || continue; "
    '  case "$m" in *[2367]) '
    '    found="$found$f is group- or world-writable (mode $m)\n" ;; esac; '
    "  if [ \"$f\" = '/etc/gshadow' ]; then "
    '    case "$m" in *[4567]) '
    '      found="$found$f is world-readable (mode $m)\n" ;; esac; fi; '
    "done"
)

#: File capabilities granting privilege without a SUID bit.
#:
#: ``setcap`` is the modern replacement for SUID and is invisible to every
#: SUID check — a binary with ``cap_setuid+ep`` is a root shell and carries no
#: SUID bit at all. Only the capabilities that actually grant privilege are
#: reported; ``cap_net_bind_service`` on a web server is normal and reporting
#: it would be the noise that teaches a reader to skip the finding.
#: The capabilities that actually confer privilege. ``cap_net_bind_service`` on
#: a web server is normal and is deliberately absent — reporting it is the noise
#: that teaches a reader to skip the finding.
_DANGEROUS_CAPS = (
    "cap_setuid|cap_setgid|cap_sys_admin|cap_dac_override|"
    "cap_dac_read_search|cap_sys_ptrace|cap_sys_module|cap_chown|"
    "cap_fowner|cap_sys_rawio"
)

_FILE_CAPABILITIES = _emit(
    "if ! command -v getcap >/dev/null 2>&1; then exit 97; fi; "
    # Filtered inside the command substitution rather than in a `while` loop:
    # a loop on the right of a pipe runs in a subshell, so anything it assigns
    # to `found` is discarded when the subshell exits — the assignment appears
    # to work and the probe reports a clean host.
    f"hits=$(timeout 60 getcap -r / 2>/dev/null | grep -E '{_DANGEROUS_CAPS}' "
    "  | head -100); "
    # grep exits 1 when nothing matches, which inside $( ) is a successful read
    # of "no capabilities of interest" — the same reading Phase 3 gives it.
    'if [ -n "$hits" ]; then found="$hits"; fi'
)


#: systemd unit files a non-root user can rewrite.
#:
#: A writable unit is root at the next ``daemon-reload`` or reboot: the
#: ``ExecStart=`` line is simply replaced. It is one of the most common real
#: findings on a Linux estate and is invisible to every SUID, capability and
#: sudo check.
_WRITABLE_SYSTEMD_UNITS = _emit(
    "if ! command -v find >/dev/null 2>&1; then exit 97; fi; "
    "dirs=''; "
    "for d in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system "
    "         /run/systemd/system; do "
    '  [ -d "$d" ] && dirs="$dirs $d"; '
    "done; "
    '[ -n "$dirs" ] || dirs=/etc/systemd/system; '
    "hits=$(timeout 60 find $dirs -type f -name '*.service' "
    # The parentheses must reach `find` as literal characters, so the
    # backslashes are escaped for Python as well as for the shell. Written
    # `\\(` they are an invalid escape sequence — currently a DeprecationWarning
    # and an error in a future Python.
    "  \\( -perm -0002 -o -perm -0020 \\) 2>/dev/null | head -100); "
    'if [ -n "$hits" ]; then found="$hits"; fi'
)


LINUX_PROBES: Dict[str, str] = {
    "suid_binaries": _SUID_BINARIES,
    "sgid_binaries": _SGID_BINARIES,
    "world_writable_dirs": _WORLD_WRITABLE_DIRS,
    "world_writable_files": _WORLD_WRITABLE_FILES,
    "sudo_nopasswd": _SUDO_NOPASSWD,
    "writable_path": _WRITABLE_PATH,
    "root_path_integrity": _ROOT_PATH_INTEGRITY,
    "unowned_files": _UNOWNED_FILES,
    "ungrouped_files": _UNGROUPED_FILES,
    "sensitive_file_modes": _SENSITIVE_FILE_MODES,
    "file_capabilities": _FILE_CAPABILITIES,
    "writable_systemd_units": _WRITABLE_SYSTEMD_UNITS,
}


class LinuxPrivilegeCollector(Collector):
    """Enumerates local privilege-escalation conditions on a Linux host."""

    check_type = "privilege"
    platforms = ("linux",)
    name = "linux_privilege"

    #: Several probes walk the whole filesystem. They carry their own
    #: ``timeout 60`` so a slow mount cannot hang the session, and this is the
    #: transport-level ceiling above it.
    default_timeout = 180

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "probe")
        if failure:
            return failure
        probe = str(params["probe"]).strip().lower()
        command = LINUX_PROBES.get(probe)
        if command is None:
            return CollectedState.unavailable(
                f"no Linux privilege probe named {probe!r}; available: "
                f"{', '.join(sorted(LINUX_PROBES))}",
                collector=self.name,
            )

        runner = _runner(ctx)
        if not runner.available:
            return CollectedState.unavailable(
                "no authenticated session to the Linux target", collector=self.name
            )

        timeout = max(int(ctx.timeout or 0), self.default_timeout)
        out = runner.run(command, timeout=timeout)
        if out.exit_code == 97:
            return CollectedState.unavailable(
                "a tool this probe needs is not installed on the host, so "
                "nothing was established about it",
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
                "probe produced no recognisable result marker",
                raw=out.text,
                collector=self.name,
            )
        offenders = [line.strip() for line in value.splitlines() if line.strip()]
        if not offenders:
            # The sentinel said there was a value and the value is empty. That
            # is a probe defect, not a clean host, and must not read as one.
            return CollectedState.unavailable(
                "probe reported offenders and produced none",
                raw=out.text,
                collector=self.name,
            )
        return CollectedState.collected(offenders, raw=out.text, collector=self.name)


def register_linux_privilege_collector(registry) -> None:
    registry.register(LinuxPrivilegeCollector())
