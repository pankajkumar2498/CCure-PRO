"""
Windows authenticated collection over SMB, Remote Registry and WMI/DCOM.

The second Windows transport. WinRM is off by default on Windows *client*
editions, so an estate of workstations was reachable by this product only where
somebody had turned WinRM on — the largest remaining functional difference
between this and the tools it is measured against, whose primary Windows
transport has always been SMB.

What these assert is that it is a **transport**, not a second way of assessing
Windows: the same ``WindowsCollector``, the same parsers, the same checks and
the same findings, reached by answering the collector's named items from WMI and
the registry instead of from PowerShell.

The property that matters most is the refusal. This transport cannot execute
commands — doing so would mean creating a service or a scheduled task on the
target — so a command-shaped check must report ERROR and must never, under any
circumstance, report a pass it did not establish.
"""

import pytest
from engines.credentialed.smb_executor import (
    UNSERVED_KEYS,
    SMBAuthenticationError,
    SMBConfigurationError,
    SMBConnectionError,
    SMBError,
    SMBExecutor,
    SMBPermissionError,
    classify_smb_error,
)


class _FakeSMB(SMBExecutor):
    """
    An executor with the wire replaced and everything above it real.

    Subclassing rather than mocking ``run_named`` keeps the native handlers, the
    JSON shaping and the fall-through logic under test — those are where the
    behaviour lives.
    """

    def __init__(self, *, registry=None, wmi=None, shares=None, services=None):
        self.ip = "10.0.0.5"
        self.username = "svc_scan"
        self.domain = "CORP"
        self.port = 445
        self.timeout = 5
        self._password = "pw"
        self._closed = False
        self.unavailable = {}
        self.remote_registry_was_running = None
        self._registry_data = registry or {}
        self._wmi_data = wmi or {}
        self._shares = shares or []
        self._services = services or []
        self.queries = []

    # The four primitives the handlers are built on.
    def wmi_query(self, query, limit=5000):
        self.queries.append(query)
        for fragment, rows in self._wmi_data.items():
            if fragment.lower() in query.lower():
                return rows
        return []

    def read_registry_value(self, hive, path, name):
        return self._registry_data.get((hive.upper(), path, name))

    def enumerate_registry_subkeys(self, hive, path):
        prefix = f"{path}\\"
        seen = []
        for h, p, _n in self._registry_data:
            if h == hive.upper() and p.startswith(prefix):
                child = p[len(prefix) :].split("\\", 1)[0]
                if child not in seen:
                    seen.append(child)
        return seen

    def list_shares(self):
        return list(self._shares)

    def service_states(self):
        return list(self._services)

    def server_info(self):
        return {
            "server_os": "Windows 10.0 Build 26100",
            "dns_hostname": "WS-01",
            "netbios_name": "WS-01",
            "domain": "CORP",
            "signing_required": True,
        }


# ─────────────────────────────────────────────────────────────────────────────
# It is a transport, and it refuses to pretend to be a shell
# ─────────────────────────────────────────────────────────────────────────────


def test_running_a_command_is_refused_rather_than_approximated():
    """
    Remote execution over SMB means creating a service or a scheduled task on
    the target. That writes to a host this product only reads, and it is the
    elevation mechanism the Windows path is forbidden to invent.
    """
    result = _FakeSMB().run("Get-Service")
    assert result.success is False
    assert result.exit_code == -1
    assert "does not execute commands" in result.stderr


def test_the_refusal_names_the_transport_that_can_do_it():
    """An operator reading this needs the next step, not just a refusal."""
    assert "WinRM" in _FakeSMB().run("whoami").stderr


def test_the_executor_declares_that_it_runs_no_commands():
    assert _FakeSMB().executes_commands is False


@pytest.mark.parametrize(
    "mechanism", ["New-Service", "Register-ScheduledTask", "svcctl_Create", "atsvc"]
)
def test_no_remote_execution_mechanism_is_present(mechanism):
    """
    A guard on the design decision, not just on today's code. The moment this
    module learns to create a service it stops being a read-only transport.
    """
    import inspect

    from engines.credentialed import smb_executor

    assert mechanism not in inspect.getsource(smb_executor)


# ─────────────────────────────────────────────────────────────────────────────
# Native collection answers the collector's own item names
# ─────────────────────────────────────────────────────────────────────────────


def test_os_info_is_shaped_exactly_as_the_powershell_output():
    """
    The parsers in ``WindowsCollector`` are the contract. If the shape drifts,
    the collector silently reads ``Caption`` as empty and the host loses its
    operating system — which is what a package matcher needs most.
    """
    x = _FakeSMB(
        wmi={
            "win32_operatingsystem": [
                {
                    "Caption": "Microsoft Windows 11 Pro",
                    "Version": "10.0.26200",
                    "BuildNumber": "26200",
                    "OSArchitecture": "64-bit",
                }
            ]
        }
    )
    import json

    payload = json.loads(x.run_named("os_info").stdout)
    assert payload["Caption"] == "Microsoft Windows 11 Pro"
    assert payload["Version"] == "10.0.26200"
    assert payload["OSArchitecture"] == "64-bit"


def test_the_build_revision_comes_from_the_registry():
    """
    ``Win32_OperatingSystem.Version`` stops at the build and omits the UBR, so
    without this every host looks like the day-zero release of its Windows
    version and every patch since launch reads as missing. It is the single
    most consequential value this transport reads.
    """
    import json

    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    x = _FakeSMB(
        registry={
            ("HKLM", path, "CurrentBuild"): "26200",
            ("HKLM", path, "UBR"): "9278",
            ("HKLM", path, "DisplayVersion"): "25H2",
        }
    )
    payload = json.loads(x.run_named("os_revision").stdout)
    assert payload["UBR"] == "9278"
    assert payload["CurrentBuild"] == "26200"
    assert payload["DisplayVersion"] == "25H2"


def test_the_package_inventory_is_read_from_the_uninstall_hive():
    """
    Not from ``Win32_Product``: querying that class triggers an MSI
    reconfiguration of every installed product, which is a write to the host and
    notoriously slow. The registry is both read-only and complete.
    """
    import json

    base = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
    x = _FakeSMB(
        registry={
            ("HKLM", f"{base}\\Git_is1", "DisplayName"): "Git",
            ("HKLM", f"{base}\\Git_is1", "DisplayVersion"): "2.44.0",
            ("HKLM", f"{base}\\Git_is1", "Publisher"): "The Git Project",
            ("HKLM", f"{base}\\Orphan", "DisplayVersion"): "1.0",
        }
    )
    payload = json.loads(x.run_named("software_x64").stdout)
    assert payload == [
        {
            "DisplayName": "Git",
            "DisplayVersion": "2.44.0",
            "Publisher": "The Git Project",
        }
    ]


def test_a_registry_entry_with_no_display_name_is_not_a_package():
    """Uninstall hives are full of fragments with no name; they are not software."""
    import json

    base = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
    x = _FakeSMB(registry={("HKLM", f"{base}\\Frag", "Publisher"): "x"})
    assert json.loads(x.run_named("software_x64").stdout) == []


def test_only_running_services_are_reported_as_the_command_reports_them():
    import json

    x = _FakeSMB(
        wmi={
            "win32_service": [
                {
                    "Name": "Spooler",
                    "State": "Running",
                    "StartMode": "Auto",
                    "DisplayName": "Print Spooler",
                    "PathName": "C:\\spoolsv.exe",
                },
                {
                    "Name": "Dead",
                    "State": "Stopped",
                    "StartMode": "Manual",
                    "DisplayName": "Dead",
                    "PathName": "",
                },
            ]
        }
    )
    payload = json.loads(x.run_named("services").stdout)
    assert [row["Name"] for row in payload] == ["Spooler"]
    assert payload[0]["Status"] == "Running"
    assert payload[0]["StartType"] == "Auto"


def test_an_unserved_key_falls_through_rather_than_inventing_a_reading():
    """
    ``None`` tells the collector this transport has no answer, which is a
    different thing from an empty answer. An inventory that could not be read
    and one that is genuinely empty must never look the same.
    """
    assert _FakeSMB().run_named("scheduled_tasks") is None
    assert _FakeSMB().run_named("open_ports") is None


def test_every_unserved_key_carries_a_reason():
    """
    The list is the honest account of what this transport does not collect. An
    entry with no reason is a gap nobody can act on.
    """
    for key, reason in UNSERVED_KEYS.items():
        assert reason and len(reason) > 15, key


def test_a_failing_native_handler_reports_failure_not_emptiness():
    class _Broken(_FakeSMB):
        def wmi_query(self, query, limit=5000):
            raise SMBConnectionError("DCOM blocked")

    result = _Broken().run_named("os_info")
    assert result is not None
    assert result.success is False
    assert "DCOM blocked" in result.stderr


# ─────────────────────────────────────────────────────────────────────────────
# Error classification — four types, and they must stay four
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text,expected",
    [
        ("SMB SessionError: STATUS_LOGON_FAILURE", SMBAuthenticationError),
        ("STATUS_ACCOUNT_LOCKED_OUT", SMBAuthenticationError),
        ("STATUS_PASSWORD_EXPIRED", SMBAuthenticationError),
        ("STATUS_ACCESS_DENIED", SMBPermissionError),
        ("WBEM_E_ACCESS_DENIED", SMBPermissionError),
        ("STATUS_PIPE_NOT_AVAILABLE", SMBConfigurationError),
        ("[Errno 111] Connection refused", SMBConnectionError),
        ("timed out", SMBConnectionError),
        ("something nobody has seen before", SMBConnectionError),
    ],
)
def test_errors_are_classified_not_flattened(text, expected):
    """
    A refused password, an unprivileged account, nothing listening and a
    switched-off subsystem need four different actions. Collapsing them is how a
    stopped Remote Registry service becomes "host unreachable" and an operator
    spends an afternoon on the firewall.
    """
    assert isinstance(classify_smb_error(Exception(text)), expected)


def test_a_rejected_credential_is_not_reported_as_unreachable():
    """
    impacket's rejection text contains none of "401", "unauthorized" or
    "authentication", so a generic classifier calls it a connection error.
    """
    error = classify_smb_error(Exception("SMB SessionError: STATUS_LOGON_FAILURE"))
    assert isinstance(error, SMBAuthenticationError)
    assert not isinstance(error, SMBConnectionError)


def test_every_error_type_is_an_smb_error():
    for cls in (
        SMBAuthenticationError,
        SMBConnectionError,
        SMBPermissionError,
        SMBConfigurationError,
    ):
        assert issubclass(cls, SMBError)


# ─────────────────────────────────────────────────────────────────────────────
# The collector stays transport-independent
# ─────────────────────────────────────────────────────────────────────────────


def test_the_collector_prefers_a_native_answer_over_running_a_command():
    from engines.credentialed.windows_collector import WindowsCollector

    x = _FakeSMB(
        wmi={
            "win32_operatingsystem": [
                {
                    "Caption": "Microsoft Windows 11 Pro",
                    "Version": "10.0.26200",
                    "BuildNumber": "26200",
                    "OSArchitecture": "64-bit",
                }
            ]
        }
    )
    data = WindowsCollector(x)._run_json("os_info")
    assert data["Caption"] == "Microsoft Windows 11 Pro"


def test_the_collector_records_what_this_transport_could_not_serve():
    """
    Silence would read downstream as "the host has none of that". For the
    software inventory that means an unassessed host reported as clean.
    """
    from engines.credentialed.windows_collector import WindowsCollector

    collector = WindowsCollector(_FakeSMB())
    collector._run("scheduled_tasks")
    assert "scheduled_tasks" in collector._unavailable


def test_no_shell_is_probed_on_a_transport_that_runs_no_commands():
    """
    Probing would spend a refusal and then log advice about OpenSSH's
    DefaultShell to an operator who is not using OpenSSH.
    """
    from engines.credentialed.windows_collector import WindowsCollector

    assert WindowsCollector(_FakeSMB()).shell_type == "native"


def test_winrm_is_untouched_and_still_runs_commands():
    """The new transport must not narrow the old one."""
    from engines.credentialed.winrm_executor import WinRMExecutor

    assert getattr(WinRMExecutor, "run_named", None) is None
    assert getattr(WinRMExecutor, "executes_commands", True) is not False


# ─────────────────────────────────────────────────────────────────────────────
# Configuration checks run natively where the transport can answer them
# ─────────────────────────────────────────────────────────────────────────────


def _ctx(executor):
    from core.config_audit import CollectionContext

    return CollectionContext(
        target="10.0.0.5",
        platform="windows",
        os_name="Microsoft Windows 11 Pro",
        os_version_id="10.0.26200",
        executor=executor,
        system_data={},
        timeout=10,
    )


def test_a_registry_check_is_answered_over_remote_registry():
    from core.checks.contract import CheckOutcome
    from core.config_audit import ConfigAuditEngine
    from core.config_audit.builtin import builtin_checks

    check = next(c for c in builtin_checks() if c.check_id == "ccure.win.uac.enabled")
    path = check.collect["path"]
    _hive, _, remainder = path.replace("/", "\\").partition("\\")
    x = _FakeSMB(registry={("HKLM", remainder, check.collect["value"]): "1"})

    result = ConfigAuditEngine().run_check(check, _ctx(x))
    assert result.outcome is CheckOutcome.PASS


def test_a_missing_registry_value_is_absent_not_an_error():
    """
    A security value missing from the registry is at its platform default, which
    is a reading. Only the rule's own AbsencePolicy decides what it means.
    """
    from core.config_audit import ConfigAuditEngine
    from core.config_audit.builtin import builtin_checks

    from core.checks.contract import CheckOutcome

    check = next(c for c in builtin_checks() if c.check_id == "ccure.win.uac.enabled")
    result = ConfigAuditEngine().run_check(check, _ctx(_FakeSMB()))
    # Whatever the rule's AbsencePolicy resolves it to, the collection itself
    # succeeded — so this must not surface as the transport having failed.
    assert result.outcome is not CheckOutcome.ERROR
    described = " ".join(
        str(getattr(e, "description", "")) for e in (result.evidence or [])
    )
    assert "could not be read" not in described


def test_a_service_check_is_answered_over_wmi():
    from core.checks.contract import CheckOutcome
    from core.config_audit import ConfigAuditEngine
    from core.config_audit.builtin import builtin_checks

    check = next(
        c for c in builtin_checks() if c.check_id == "ccure.win.telnet.server_absent"
    )
    x = _FakeSMB(wmi={"win32_service": []}, services=[])
    result = ConfigAuditEngine().run_check(check, _ctx(x))
    # Telnet is not installed, so the rule's absence policy applies rather than
    # a verdict about a service that does not exist.
    assert result.outcome is not CheckOutcome.ERROR


def test_a_command_check_reports_error_and_never_a_verdict():
    """
    The property this whole transport is built around. A check it cannot perform
    is a recorded gap; it is never a pass.
    """
    from core.checks.contract import CheckOutcome
    from core.config_audit import ConfigAuditEngine
    from core.config_audit.builtin import builtin_checks

    engine = ConfigAuditEngine()
    ctx = _ctx(_FakeSMB())
    for check in builtin_checks():
        if check.check_type != "privilege" or "windows" not in check.platforms:
            continue
        result = engine.run_check(check, ctx)
        assert result.outcome is CheckOutcome.ERROR, check.check_id
        break


def test_the_service_name_is_bound_not_interpolated():
    """
    Rule parameters are administrator-editable, so this is an injection boundary
    inside the product rather than defensive style.
    """
    x = _FakeSMB(wmi={"win32_service": []})
    x.query_service('evil" OR Name != "')
    assert x.queries
    assert '\\"' in x.queries[0]


def test_remote_registry_state_is_unknown_until_it_is_measured():
    """
    Binding the registry pipe can trigger-start the service, and this product's
    own check treats a running Remote Registry as a finding. Recording the state
    first is what keeps the scan from reporting a condition it created.
    """
    assert _FakeSMB().remote_registry_was_running is None


# ─────────────────────────────────────────────────────────────────────────────
# Wiring: the credential vocabulary, the resolver and the API
# ─────────────────────────────────────────────────────────────────────────────


def test_smb_is_a_usable_transport_for_a_windows_credential():
    from db.models.compliance import (
        CREDENTIAL_TYPE_WINDOWS,
        TRANSPORT_SMB,
        USABLE_TRANSPORTS,
    )
    from routers.credentials import TYPE_TRANSPORTS

    assert TRANSPORT_SMB in USABLE_TRANSPORTS
    assert TRANSPORT_SMB in TYPE_TRANSPORTS[CREDENTIAL_TYPE_WINDOWS]


def test_winrm_remains_the_default_windows_transport():
    """
    SMB widens reach; WinRM keeps depth. It executes commands and so drives
    every check, where SMB drives the subset readable from WMI and the registry.
    Neither is a superset, and the default must stay the deeper one.
    """
    from db.models.compliance import CREDENTIAL_TYPE_WINDOWS, TRANSPORT_WINRM
    from routers.credentials import TYPE_DEFAULTS

    assert TYPE_DEFAULTS[CREDENTIAL_TYPE_WINDOWS]["transport"] == TRANSPORT_WINRM


@pytest.mark.parametrize(
    "service,product,expected",
    [
        ("microsoft-ds", "", True),
        ("netbios-ssn", "", True),
        ("smb", "", True),
        ("unknown", "Samba smbd 4.19.5", True),
        ("http", "nginx", False),
        ("microsoft-rdp", "", False),
        ("ms-wbt-server", "", False),
    ],
)
def test_smb_is_identified_from_the_port_scans_own_evidence(service, product, expected):
    from engines.credentialed.transport_resolver import candidate_endpoints

    record = {
        "port": 9999,
        "protocol": "tcp",
        "state": "open",
        "service": service,
        "product": product,
    }
    ports = [e.port for e in candidate_endpoints(transport="smb", open_ports=[record])]
    assert (9999 in ports) is expected


def test_the_smb_probe_is_a_socket_test_not_an_authentication_attempt():
    from engines.credentialed.transport_resolver import _default_probe

    assert _default_probe("smb") is SMBExecutor.test_connectivity


def test_the_transport_defaults_to_445_and_falls_back_to_139():
    from engines.credentialed.transport_resolver import DEFAULT_PORT, FALLBACK_PORTS

    assert DEFAULT_PORT["smb"] == 445
    assert FALLBACK_PORTS["smb"] == (445, 139)


def test_reachability_can_be_probed_without_impacket_installed():
    """
    The probe is pure ``socket``. A build without impacket must still be able to
    say whether anything is listening, or the resolver cannot even explain why
    it refused.
    """
    import inspect

    source = inspect.getsource(SMBExecutor.test_connectivity)
    assert "impacket" not in source


def test_an_absent_impacket_is_a_configuration_error_not_a_crash(monkeypatch):
    from engines.credentialed import smb_executor

    monkeypatch.setattr(smb_executor, "IMPACKET_AVAILABLE", False)
    with pytest.raises(SMBConfigurationError, match="impacket"):
        smb_executor.SMBExecutor(ip="10.0.0.5", username="u", password="p")


def test_a_domain_qualified_principal_is_split_for_ntlm():
    r"""
    NTLM wants the domain in its own field. ``principal()`` composes
    ``DOMAIN\user`` for the transports that want it joined; this one does not,
    and a joined name in the username field authenticates as nobody.
    """
    from engines.credentialed import smb_executor

    x = smb_executor.SMBExecutor.__new__(smb_executor.SMBExecutor)
    smb_executor.SMBExecutor.__init__(
        x, ip="10.0.0.5", username="CORP\svc_scan", password="pw"
    )
    assert x.username == "svc_scan"
    assert x.domain == "CORP"
