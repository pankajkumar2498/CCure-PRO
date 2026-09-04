"""
core/config_audit/builtin/linux_host.py
─────────────────────────────────────────────────────────────────────────────
A small set of genuine Linux host hardening checks.

As with the Windows set, these exist to exercise the engine against real hosts
rather than to be a benchmark.

The absence policies differ from Windows in a way worth noticing
────────────────────────────────────────────────────────────────
On Windows, absence usually means "at the platform default", so most rules
defer. On Linux the answer depends on *what* is absent:

* A missing **file** that every system has (``/etc/passwd``, ``/etc/shadow``)
  is a real finding — FAIL.
* A missing **directive** inside a configuration file means the daemon is
  running on its compiled-in default, and those defaults differ between
  OpenSSH versions and between distributions. Deferring is the honest answer,
  and it is why the ``sshd_config`` rules below are MANUAL_REVIEW rather than
  assuming the upstream default.
* A missing **service or listener** settles the question — a telnet daemon
  that is not listening is not accepting clear-text passwords — so PASS.

``sshd_config`` is whitespace-separated, not ``key=value``, so those rules
pass ``separator: ""``. Getting that wrong yields "directive not set" for
every one of them, which reads as a fleet-wide configuration gap rather than a
parser bug — a failure that looks like data.
"""

from __future__ import annotations

from typing import List

from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

__all__ = ["LINUX_HOST_CHECKS", "linux_host_checks"]

_SSHD = "/etc/ssh/sshd_config"


LINUX_HOST_CHECKS: List[ConfigCheck] = [
    ConfigCheck(
        check_id="ccure.linux.ssh.permit_root_login",
        title="SSH does not permit password-based root login",
        check_type="config_file",
        platforms=("linux",),
        severity="high",
        collect={"path": _SSHD, "key": "PermitRootLogin", "separator": ""},
        expect=Expectation(
            "in",
            ["no", "prohibit-password", "without-password", "forced-commands-only"],
            description="no, prohibit-password or forced-commands-only",
        ),
        # OpenSSH has defaulted to prohibit-password since 7.0, but the
        # effective value on a given host also depends on distribution patches
        # and on Include'd fragments this check does not follow.
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="Whether the SSH daemon accepts a direct root login with a password.",
        rationale=(
            "Direct root login removes the accountability of a named account "
            "and gives a single guessed password full control of the host."
        ),
        remediation=(
            "Set 'PermitRootLogin prohibit-password' (or 'no') in "
            "/etc/ssh/sshd_config and reload sshd."
        ),
        tags=("linux", "remote_access"),
    ),
    ConfigCheck(
        check_id="ccure.linux.ssh.password_authentication",
        title="SSH password authentication is disabled",
        check_type="config_file",
        platforms=("linux",),
        severity="medium",
        collect={"path": _SSHD, "key": "PasswordAuthentication", "separator": ""},
        expect=Expectation("is_false", description="no"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="Whether the SSH daemon accepts passwords as well as keys.",
        rationale=(
            "Key authentication is not guessable; leaving passwords enabled "
            "keeps the host exposed to spraying regardless of key hygiene."
        ),
        remediation=(
            "Set 'PasswordAuthentication no' once key access is confirmed "
            "working for every account that needs it."
        ),
        tags=("linux", "remote_access"),
    ),
    ConfigCheck(
        check_id="ccure.linux.ssh.max_auth_tries",
        title="SSH limits authentication attempts per connection",
        check_type="config_file",
        platforms=("linux",),
        severity="low",
        collect={"path": _SSHD, "key": "MaxAuthTries", "separator": ""},
        expect=Expectation("lte", 4, description="at most 4"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="Failed attempts allowed within a single SSH connection.",
        rationale=(
            "A high limit lets one connection carry many guesses, which costs "
            "an attacker far less than opening a connection per attempt."
        ),
        remediation="Set 'MaxAuthTries 4' in /etc/ssh/sshd_config.",
        tags=("linux", "remote_access"),
    ),
    ConfigCheck(
        check_id="ccure.linux.passwd.permissions",
        title="/etc/passwd is not group- or world-writable",
        check_type="permission",
        platforms=("linux",),
        severity="high",
        collect={"path": "/etc/passwd", "attribute": "mode"},
        expect=Expectation(
            "in", ["644", "0644", "444", "0444"], description="0644 or stricter"
        ),
        # Every Linux system has /etc/passwd. Its absence is not a pass.
        absent=AbsencePolicy.FAIL,
        description="Filesystem mode of the local account database.",
        rationale=(
            "A writable /etc/passwd allows an unprivileged user to add an "
            "account, or to blank the password field of an existing one."
        ),
        remediation="chmod 0644 /etc/passwd && chown root:root /etc/passwd",
        tags=("linux", "filesystem"),
    ),
    ConfigCheck(
        check_id="ccure.linux.shadow.permissions",
        title="/etc/shadow is not readable by unprivileged users",
        check_type="permission",
        platforms=("linux",),
        severity="critical",
        collect={"path": "/etc/shadow", "attribute": "mode"},
        expect=Expectation(
            "in",
            ["0", "000", "400", "0400", "600", "0600", "640", "0640"],
            description="0640 or stricter",
        ),
        absent=AbsencePolicy.FAIL,
        description="Filesystem mode of the local password hash store.",
        rationale=(
            "A readable /etc/shadow hands every local user the hashes to crack "
            "offline, at their own pace and without triggering any lockout."
        ),
        remediation="chmod 0640 /etc/shadow && chown root:shadow /etc/shadow",
        tags=("linux", "filesystem"),
    ),
    ConfigCheck(
        check_id="ccure.linux.auditd.running",
        title="The audit daemon is running",
        check_type="service",
        platforms=("linux",),
        severity="medium",
        collect={"name": "auditd", "attribute": "status"},
        expect=Expectation("equals", "active"),
        # A host with no auditd unit is a host with no kernel audit trail.
        absent=AbsencePolicy.FAIL,
        description="auditd records kernel audit events to disk.",
        rationale=(
            "Without it there is no local record of privilege use or of "
            "changes to the files these other rules check, so an incident "
            "cannot be reconstructed afterwards."
        ),
        remediation="Install and enable auditd, then define an audit ruleset.",
        tags=("linux", "logging"),
    ),
    ConfigCheck(
        check_id="ccure.linux.telnet.port_closed",
        title="No telnet daemon is listening",
        check_type="port",
        platforms=("linux",),
        severity="high",
        collect={"port": 23},
        expect=Expectation("not_equals", "listening"),
        # Nothing listening on 23 settles it — there is no telnet service to
        # carry a clear-text password.
        absent=AbsencePolicy.PASS,
        description="TCP 23, the telnet service port.",
        rationale=(
            "Telnet transmits credentials and session content in clear text on "
            "a network where anyone on the path can read them."
        ),
        remediation="Remove the telnet server package and use SSH.",
        tags=("linux", "protocol"),
    ),
    ConfigCheck(
        check_id="ccure.linux.password.max_age",
        title="Password maximum age is set",
        check_type="security_policy",
        platforms=("linux",),
        severity="low",
        collect={"setting": "pass_max_days"},
        expect=Expectation("lte", 365, description="at most 365 days"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="PASS_MAX_DAYS from /etc/login.defs.",
        rationale=(
            "An unbounded password lifetime means a credential compromised "
            "years ago is still valid today."
        ),
        remediation="Set PASS_MAX_DAYS in /etc/login.defs and apply with chage.",
        tags=("linux", "identity"),
    ),
    ConfigCheck(
        check_id="ccure.linux.password.min_length",
        title="Password quality enforces a minimum length",
        check_type="security_policy",
        platforms=("linux",),
        severity="medium",
        collect={"setting": "minlen"},
        expect=Expectation("gte", 14, description="at least 14 characters"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="minlen from /etc/security/pwquality.conf.",
        rationale=(
            "Length is the property that most directly resists offline "
            "cracking of a recovered hash."
        ),
        remediation="Set 'minlen = 14' in /etc/security/pwquality.conf.",
        tags=("linux", "identity"),
    ),
    ConfigCheck(
        check_id="ccure.linux.cron.permissions",
        title="/etc/crontab is not writable by unprivileged users",
        check_type="permission",
        platforms=("linux",),
        severity="medium",
        collect={"path": "/etc/crontab", "attribute": "mode"},
        expect=Expectation(
            "in", ["600", "0600", "644", "0644"], description="0644 or stricter"
        ),
        # A host with no /etc/crontab is not misconfigured — some minimal
        # images and containers legitimately ship without cron at all.
        absent=AbsencePolicy.NOT_APPLICABLE,
        description="Filesystem mode of the system crontab.",
        rationale=(
            "A writable system crontab is a direct path to code execution as "
            "root at the next scheduled run."
        ),
        remediation="chmod 0644 /etc/crontab && chown root:root /etc/crontab",
        tags=("linux", "filesystem"),
    ),
]


def linux_host_checks() -> List[ConfigCheck]:
    return list(LINUX_HOST_CHECKS)
