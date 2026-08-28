"""
core/config_audit/builtin/privilege_linux.py
─────────────────────────────────────────────────────────────────────────────
Linux local privilege-escalation and host-exposure checks (GAP-08).

Four of these replace prose. ``LinuxCollector._collect_security_audit`` already
gathered SUID binaries, world-writable directories and sudo rules and turned
them into sentences in ``security_issues``:

    "NOPASSWD sudo rule detected — any command runs without password"
    "37 SUID binaries found — review for privilege escalation risk"

A sentence in a PDF has no severity, no risk score, no remediation, no
lifecycle, no deduplication, and cannot be exported, filtered or triaged. The
checks below produce the same observations as findings that do.

Note the second sentence in particular: a count is not a check. A stock
distribution ships around thirty SUID binaries, so "37" says nothing at all.
What matters is the SUID bit on something that should not carry one, which is
why the probe reports the *difference* from the expected set rather than a
total.

The collector keeps emitting its prose — the report's posture section reads it,
and nothing here should change what an existing report says. The finding is now
the authoritative form.
"""

from __future__ import annotations

from typing import List

from core.checks.definitions import DEFINITION_TYPE_PRIVILEGE_CHECK
from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

__all__ = ["LINUX_PRIVILEGE_CHECKS", "linux_privilege_checks"]


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
) -> ConfigCheck:
    return ConfigCheck(
        check_id=f"ccure.priv.linux.{slug}",
        title=title,
        check_type="privilege",
        platforms=("linux",),
        domain="local_privilege",
        severity=severity,
        collect={"probe": probe},
        expect=Expectation("is_empty", description="no offending items"),
        absent=AbsencePolicy.PASS,
        finding_type=DEFINITION_TYPE_PRIVILEGE_CHECK,
        description=description,
        rationale=rationale,
        remediation=remediation,
        metadata={"gap08_area": area},
    )


LINUX_PRIVILEGE_CHECKS: List[ConfigCheck] = [
    _check(
        slug="writable.path",
        probe="writable_path",
        area="linux.writable_path",
        title="No directory on root's PATH is writable by a non-root user",
        severity="critical",
        description=(
            "Each directory on root's PATH is checked for group- or "
            "world-writability, and for direct writability by the scanning "
            "account."
        ),
        rationale=(
            "Anything root runs by name resolves through PATH. A writable "
            "directory on it lets an unprivileged user place a binary that "
            "root then executes — an unconditional path to root that needs no "
            "other weakness."
        ),
        remediation=(
            "chmod go-w on the named directories, or remove them from root's "
            "PATH. A directory that must be writable does not belong on it."
        ),
    ),
    _check(
        slug="sudo.nopasswd",
        probe="sudo_nopasswd",
        area="linux.sudo_nopasswd",
        title="No sudo rule grants command execution without a password",
        severity="high",
        description=(
            "Parses /etc/sudoers and /etc/sudoers.d for rules carrying "
            "NOPASSWD, and reports the file and the rule."
        ),
        rationale=(
            "A NOPASSWD rule means anyone who obtains that account's shell — "
            "through a stolen key, a hijacked session, or a web shell — "
            "escalates with no credential at all. The password prompt is the "
            "last control between a compromised session and root."
        ),
        remediation=(
            "Remove NOPASSWD, or narrow it to the specific commands that need "
            "it. Where it exists for automation, prefer a dedicated account "
            "with a tightly scoped command list."
        ),
    ),
    _check(
        slug="suid.unexpected",
        probe="suid_binaries",
        area="linux.suid_binaries",
        title="No unexpected binary carries the SUID bit",
        severity="high",
        description=(
            "Every SUID binary on local filesystems is compared against the "
            "set a stock distribution ships. Only the difference is reported — "
            "a count of SUID binaries is not a finding."
        ),
        rationale=(
            "A SUID binary runs as its owner, usually root, whoever starts it. "
            "One outside the expected set is either a deliberate backdoor or a "
            "packaging mistake, and in both cases is a candidate for direct "
            "escalation."
        ),
        remediation=(
            "chmod u-s on the named binaries unless the SUID bit is required "
            "and understood. If it is required, record why."
        ),
    ),
    _check(
        slug="worldwritable.dirs",
        probe="world_writable_dirs",
        area="linux.world_writable_dirs",
        title="No world-writable directory is missing the sticky bit",
        severity="high",
        description=(
            "World-writable directories without the sticky bit. Directories "
            "that have it — /tmp and friends — are not reported."
        ),
        rationale=(
            "With the sticky bit a user may only delete their own files. "
            "Without it, any user can replace any other user's file in that "
            "directory, including one a privileged process later reads or "
            "executes."
        ),
        remediation=(
            "chmod +t on the named directories, or remove world-write where it "
            "is not needed."
        ),
    ),
    _check(
        slug="root.path.integrity",
        probe="root_path_integrity",
        area="linux.root_path_integrity",
        title="Root's PATH contains no relative or empty entry",
        severity="high",
        description=(
            "Checks root's PATH for empty entries — a leading, trailing or "
            "doubled colon — and for entries that are not absolute."
        ),
        rationale=(
            "An empty PATH entry means the current directory. A privileged "
            "process that changes into a directory an unprivileged user "
            "controls will then execute a binary from it by name."
        ),
        remediation=(
            "Remove empty and relative entries from root's PATH in the shell "
            "profile or the service unit that sets it."
        ),
    ),
    _check(
        slug="systemd.unit.writable",
        probe="writable_systemd_units",
        area="linux.writable_systemd_units",
        title="No systemd unit file is writable by a non-root user",
        severity="critical",
        description=(
            "Service unit files under the systemd unit directories are checked "
            "for group- or world-writability."
        ),
        rationale=(
            "A writable unit file is root at the next daemon-reload or reboot: "
            "the ExecStart line is simply replaced. It is one of the most "
            "common real findings on a Linux estate and is invisible to every "
            "SUID, capability and sudo check."
        ),
        remediation=(
            "chmod go-w on the named unit files and confirm they are owned by "
            "root. Unit files should be 0644 root:root."
        ),
    ),
    _check(
        slug="sgid.unexpected",
        probe="sgid_binaries",
        area="linux.sgid_binaries",
        title="No unexpected binary carries the SGID bit",
        severity="medium",
        description=(
            "SGID binaries compared against the expected set, reporting only "
            "the difference."
        ),
        rationale=(
            "An SGID binary runs with its group's privileges. It is rated "
            "below SUID because group privilege is usually a smaller prize "
            "than root — but a group such as shadow or disk is not."
        ),
        remediation="chmod g-s on the named binaries unless the bit is required.",
    ),
    _check(
        slug="worldwritable.files",
        probe="world_writable_files",
        area="linux.world_writable_files",
        title="No world-writable regular file outside pseudo-filesystems",
        severity="medium",
        description="World-writable regular files on local filesystems.",
        rationale=(
            "Any user can rewrite the contents. Where the file is a script, a "
            "configuration file or a library that something privileged reads, "
            "that is code execution in the reader's context."
        ),
        remediation="chmod o-w on the named files.",
    ),
    _check(
        slug="account.files.ownership",
        probe="sensitive_file_modes",
        area="linux.sensitive_file_modes",
        title="Account database files are root-owned and correctly permissioned",
        severity="critical",
        description=(
            "Ownership of /etc/passwd, /etc/shadow, /etc/group and "
            "/etc/gshadow, plus the modes of /etc/group and /etc/gshadow. The "
            "modes of passwd and shadow are asserted separately by the "
            "built-in file-permission checks and are not repeated here."
        ),
        rationale=(
            "These four files decide who may become whom. A non-root owner can "
            "rewrite them at will; a world-readable gshadow exposes group "
            "password hashes to offline cracking."
        ),
        remediation=(
            "chown root:root on all four. chmod 0644 /etc/group and "
            "chmod 0640 /etc/gshadow (0000 on distributions that expect it)."
        ),
    ),
    _check(
        slug="file.capabilities",
        probe="file_capabilities",
        area="linux.file_capabilities",
        title="No binary carries a privilege-granting file capability",
        severity="high",
        description=(
            "Every file capability on local filesystems, filtered to the ones "
            "that confer privilege — cap_setuid, cap_sys_admin, "
            "cap_dac_override and their neighbours. cap_net_bind_service is "
            "normal on a web server and is not reported."
        ),
        rationale=(
            "File capabilities are the modern replacement for the SUID bit and "
            "are invisible to every SUID check: a binary with cap_setuid+ep is "
            "a root shell and carries no SUID bit at all. A host can therefore "
            "pass every SUID check and still hand out root."
        ),
        remediation=(
            "setcap -r on the named binaries unless the capability is required "
            "and understood. Where it is required, prefer the narrowest "
            "capability that works."
        ),
    ),
    _check(
        slug="unowned.files",
        probe="unowned_files",
        area="linux.unowned_files",
        title="No file is owned by a user that does not exist",
        severity="low",
        description="Files whose owning uid has no entry in the password database.",
        rationale=(
            "Usually the residue of a removed account. The risk is delayed "
            "rather than immediate: the next account assigned that uid "
            "silently inherits ownership of every one of these files."
        ),
        remediation=(
            "Reassign the named files to a valid owner, or remove them if the "
            "account they belonged to is gone for good."
        ),
    ),
    _check(
        slug="ungrouped.files",
        probe="ungrouped_files",
        area="linux.ungrouped_files",
        title="No file is owned by a group that does not exist",
        severity="low",
        description="Files whose owning gid has no entry in the group database.",
        rationale=(
            "As with unowned files, the next group assigned that gid inherits "
            "access to all of them."
        ),
        remediation="Reassign the named files to a valid group, or remove them.",
    ),
]


def linux_privilege_checks() -> List[ConfigCheck]:
    return list(LINUX_PRIVILEGE_CHECKS)
