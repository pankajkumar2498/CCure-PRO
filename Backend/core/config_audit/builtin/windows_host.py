"""
core/config_audit/builtin/windows_host.py
─────────────────────────────────────────────────────────────────────────────
A small set of genuine Windows host hardening checks.

These are here to prove the engine end to end against a real machine, not to
be a benchmark. CIS and STIG content arrives in Phases 4 and 5 as rule data;
nothing in this file is a prerequisite for that, and none of it should grow
into a benchmark by accretion.

Two things worth reading before adding one
──────────────────────────────────────────
**Most of these declare ``absent = MANUAL_REVIEW``, and that is not
timidity.** A Windows security setting is very often *absent from the registry
when it is at its default*, and the default differs by build and by SKU. A
rule that reports "SMB1 value not present" as a PASS is asserting a default it
has not read; one that reports it as a FAIL invents a finding on a host that
may well be configured correctly. MANUAL_REVIEW says what is true — the
setting was not explicitly configured and a person has to decide whether the
platform default is acceptable here. Where absence genuinely settles the
question (a service that is not installed cannot be running) the policy is
PASS, and that is stated at each rule.

**Severity is the rule's, not the finding's.** These are ratings of the
control, chosen against what an attacker gains, and they flow through
``normalize_severity`` into the same severity column as CVSS-derived ratings.
Nothing here fabricates a CVSS score to go with them.
"""

from __future__ import annotations

from typing import List

from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

__all__ = ["WINDOWS_HOST_CHECKS", "windows_host_checks"]


_LANMAN = r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
_LSA = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
_POLICIES = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
_TERMINAL = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"


WINDOWS_HOST_CHECKS: List[ConfigCheck] = [
    ConfigCheck(
        check_id="ccure.win.uac.enabled",
        title="User Account Control is enabled",
        check_type="registry",
        platforms=("windows",),
        severity="high",
        collect={"path": _POLICIES, "value": "EnableLUA"},
        expect=Expectation("equals", 1, description="EnableLUA = 1"),
        # EnableLUA is written on every supported Windows build. Its absence
        # means the read did not find a key that should be there, which is a
        # question about the host rather than an answer about UAC.
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "User Account Control mediates elevation to administrative rights. "
            "With it off, any process started by a member of the local "
            "Administrators group runs fully elevated with no prompt and no "
            "split token."
        ),
        rationale=(
            "Disabling UAC removes the boundary that stops a single "
            "user-context compromise becoming immediate administrative "
            "control of the machine."
        ),
        remediation=(
            "Set EnableLUA to 1 under HKLM\\SOFTWARE\\Microsoft\\Windows\\"
            "CurrentVersion\\Policies\\System and restart the host."
        ),
        references=(
            "https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/",
        ),
        tags=("windows", "privilege"),
    ),
    ConfigCheck(
        check_id="ccure.win.rdp.nla_required",
        title="RDP requires Network Level Authentication",
        check_type="registry",
        platforms=("windows",),
        severity="high",
        collect={"path": _TERMINAL, "value": "UserAuthentication"},
        expect=Expectation("equals", 1, description="UserAuthentication = 1"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Network Level Authentication makes the client authenticate before "
            "a Remote Desktop session is created."
        ),
        rationale=(
            "Without NLA the server allocates a session and renders a logon "
            "screen to an unauthenticated caller, which both widens the "
            "pre-authentication attack surface and makes RDP usable for "
            "resource exhaustion."
        ),
        remediation=(
            "Enable 'Require user authentication for remote connections by "
            "using Network Level Authentication', or set UserAuthentication "
            "to 1 on the RDP-Tcp listener."
        ),
        tags=("windows", "remote_access"),
    ),
    ConfigCheck(
        check_id="ccure.win.smbv1.server_disabled",
        title="SMBv1 server is disabled",
        check_type="registry",
        platforms=("windows",),
        severity="high",
        collect={"path": _LANMAN, "value": "SMB1"},
        expect=Expectation("equals", 0, description="SMB1 = 0"),
        # Absent means "not explicitly configured", and the effective default
        # has changed across builds — removed entirely on current client SKUs,
        # present and enabled on older ones. Neither PASS nor FAIL can be
        # asserted from the absence alone.
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "The SMB version 1 server protocol, superseded since 2006 and the "
            "transport used by EternalBlue and WannaCry."
        ),
        rationale=(
            "SMBv1 has no protocol-level integrity protection and cannot "
            "negotiate the mitigations later dialects carry."
        ),
        remediation=(
            "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol, "
            "or set SMB1 to 0 under the LanmanServer parameters key."
        ),
        tags=("windows", "protocol"),
    ),
    ConfigCheck(
        check_id="ccure.win.lsa.restrict_anonymous_sam",
        title="Anonymous enumeration of SAM accounts is restricted",
        check_type="registry",
        platforms=("windows",),
        severity="medium",
        collect={"path": _LSA, "value": "RestrictAnonymousSAM"},
        expect=Expectation("equals", 1, description="RestrictAnonymousSAM = 1"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Controls whether an unauthenticated session may enumerate local "
            "account names."
        ),
        rationale=(
            "An account list is the input to password spraying; withholding it "
            "removes the step that makes spraying efficient."
        ),
        remediation=(
            "Set RestrictAnonymousSAM to 1 under HKLM\\SYSTEM\\"
            "CurrentControlSet\\Control\\Lsa."
        ),
        tags=("windows", "identity"),
    ),
    ConfigCheck(
        check_id="ccure.win.firewall.service_running",
        title="Windows Firewall service is running",
        check_type="service",
        platforms=("windows",),
        severity="high",
        collect={"name": "MpsSvc", "attribute": "status"},
        expect=Expectation("equals", "Running"),
        # MpsSvc is present on every supported Windows install. If it is not
        # installed, host filtering is not merely off — it has been removed.
        absent=AbsencePolicy.FAIL,
        description="The Windows Defender Firewall service enforces host packet filtering.",
        rationale=(
            "With the service stopped, every profile's rules are inert and the "
            "host accepts whatever the network offers it."
        ),
        remediation="Start-Service MpsSvc and set its start type to Automatic.",
        tags=("windows", "network"),
    ),
    ConfigCheck(
        check_id="ccure.win.telnet.server_absent",
        title="Telnet server is not installed",
        check_type="service",
        platforms=("windows",),
        severity="high",
        collect={"name": "TlntSvr", "attribute": "status"},
        expect=Expectation("not_equals", "Running"),
        # A service that is not installed cannot be running. Absence settles
        # the question here, so it is a genuine PASS rather than a deferral.
        absent=AbsencePolicy.PASS,
        description="The Telnet server service, which carries credentials in clear text.",
        rationale=(
            "Telnet authenticates over an unencrypted channel; anyone able to "
            "observe the path recovers the password."
        ),
        remediation=(
            "Uninstall the Telnet Server feature and use SSH or WinRM over "
            "HTTPS instead."
        ),
        tags=("windows", "protocol"),
    ),
    ConfigCheck(
        check_id="ccure.win.remote_registry.not_running",
        title="Remote Registry service is not running",
        check_type="service",
        platforms=("windows",),
        severity="medium",
        collect={"name": "RemoteRegistry", "attribute": "status"},
        expect=Expectation("not_equals", "Running"),
        absent=AbsencePolicy.PASS,
        description=(
            "The Remote Registry service allows the registry to be read and "
            "written across the network."
        ),
        rationale=(
            "It is rarely required on a workstation and gives an authenticated "
            "attacker a broad configuration read, and often a write."
        ),
        remediation=(
            "Stop the RemoteRegistry service and set its start type to "
            "Disabled where remote management does not depend on it."
        ),
        tags=("windows", "remote_access"),
    ),
    ConfigCheck(
        check_id="ccure.win.password.minimum_length",
        title="Minimum password length is at least 14 characters",
        check_type="security_policy",
        platforms=("windows",),
        severity="medium",
        collect={"setting": "min_length"},
        expect=Expectation("gte", 14, description="at least 14 characters"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="The local security policy's minimum password length.",
        rationale=(
            "Length is the property that most directly resists offline "
            "cracking of a recovered hash."
        ),
        remediation=(
            "Set Minimum password length to 14 or more in the local security "
            "policy, or through the domain password policy where the host is "
            "joined."
        ),
        tags=("windows", "identity"),
    ),
    ConfigCheck(
        check_id="ccure.win.password.history",
        title="Password history retains at least 24 passwords",
        check_type="security_policy",
        platforms=("windows",),
        severity="low",
        collect={"setting": "history_length"},
        expect=Expectation("gte", 24),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="How many previous passwords the system refuses to accept again.",
        rationale=(
            "Without history a forced change can be satisfied by re-setting "
            "the password that was just compromised."
        ),
        remediation="Set 'Enforce password history' to 24 or more.",
        tags=("windows", "identity"),
    ),
    ConfigCheck(
        check_id="ccure.win.lockout.threshold",
        title="Account lockout threshold is set and workable",
        check_type="security_policy",
        platforms=("windows",),
        severity="medium",
        collect={"setting": "lockout_threshold"},
        # A threshold of 0 means no lockout at all; a very low one is a
        # self-inflicted denial of service. Both ends are wrong, which is what
        # `between` expresses and what two separate rules would obscure.
        expect=Expectation(
            "between", [1, 10], description="between 1 and 10 failed attempts"
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="Failed sign-in attempts before the account is locked.",
        rationale=(
            "A per-account lockout is the control that answers credential "
            "stuffing from many source addresses, which no per-address rate "
            "limit can."
        ),
        remediation=(
            "Set 'Account lockout threshold' to a value between 1 and 10, with "
            "a lockout duration long enough to make automated guessing "
            "impractical."
        ),
        tags=("windows", "identity"),
    ),
]


def windows_host_checks() -> List[ConfigCheck]:
    return list(WINDOWS_HOST_CHECKS)
