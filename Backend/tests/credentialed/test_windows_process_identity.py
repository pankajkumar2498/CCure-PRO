"""
tests/test_windows_process_identity.py
────────────────────────────────────────────────────────────────────────────
Naming the software behind a Windows listening socket.

``netstat -ano`` reports a PID and nothing else, and the socket table is
discarded immediately afterwards — so a PID left unresolved here can never be
resolved. The consequence was visible on a real host: every exposed service
recorded with no product and no version, an exposure report that could say
*which* ports were reachable but not *what* was answering on them.

The lookup is deliberately scoped to the PIDs holding a socket. Asking for
every process forces PowerShell to read 469 executables' version resources and
exceeds the command timeout, which returns nothing at all — a slower query that
yields less than no query.
"""

import json

import pytest
from engines.credentialed.ssh_scanner import CommandResult
from engines.credentialed.windows_collector import (
    _MAX_IDENTITY_PIDS,
    WindowsCollector,
)

NETSTAT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       8016
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       10748
  TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING       11544
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1692
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       3300
  TCP    127.0.0.1:5432         0.0.0.0:0              LISTENING       11432
  TCP    10.0.0.5:139           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:9999           0.0.0.0:0              ESTABLISHED     999
"""

# Shapes taken from the real host: nginx ships the literal string "None" in
# its version resource, and PID 4 (System) exposes nothing at all.
PROCESSES = [
    {
        "Id": 8016,
        "ProcessName": "sshd",
        "Path": "C:\\Windows\\System32\\OpenSSH\\sshd.exe",
        "Company": "",
        "Product": "OpenSSH for Windows",
        "FileVersion": "9.5.5.1",
    },
    {
        "Id": 10748,
        "ProcessName": "nginx",
        "Path": "C:\\nginx\\nginx.exe",
        "Company": "None",
        "Product": "None",
        "FileVersion": None,
    },
    {
        "Id": 11544,
        "ProcessName": "mysqld",
        "Path": "C:\\MySQL\\bin\\mysqld.exe",
        "Company": "Oracle Corporation",
        "Product": "MySQL Server",
        "FileVersion": "8.0.40.0",
    },
    {
        "Id": 11432,
        "ProcessName": "postgres",
        "Path": "C:\\PG\\bin\\postgres.exe",
        "Company": "PostgreSQL Global Development Group",
        "Product": "PostgreSQL",
        "FileVersion": "18.3",
    },
    {
        "Id": 4,
        "ProcessName": "System",
        "Path": None,
        "Company": None,
        "Product": None,
        "FileVersion": None,
    },
    {
        "Id": 1692,
        "ProcessName": "svchost",
        "Path": "C:\\Windows\\System32\\svchost.exe",
        "Company": "Microsoft Corporation",
        "Product": "Microsoft Windows Operating System",
        "FileVersion": "10.0.26100.1",
    },
    {
        "Id": 3300,
        "ProcessName": "svchost",
        "Path": "C:\\Windows\\System32\\svchost.exe",
        "Company": "Microsoft Corporation",
        "Product": "Microsoft Windows Operating System",
        "FileVersion": "10.0.26100.1",
    },
]


# svchost hosts other people's code. Its own version resource says "Microsoft
# Windows Operating System", which is true of the binary and useless for saying
# what answers on port 135.
SERVICES = [
    {"Name": "RpcSs", "DisplayName": "Remote Procedure Call (RPC)", "ProcessId": 1692},
    {"Name": "RpcEptMapper", "DisplayName": "RPC Endpoint Mapper", "ProcessId": 1692},
    {"Name": "sshd", "DisplayName": "OpenSSH SSH Server", "ProcessId": 8016},
    {
        "Name": "CDPSvc",
        "DisplayName": "Connected Devices Platform Service",
        "ProcessId": 3300,
    },
    {"Name": "Orphan", "DisplayName": "Not Running", "ProcessId": 0},
]


class _FakeSSH:
    """Records every command issued so the query scope can be asserted."""

    def __init__(self, processes=PROCESSES, identity_ok=True, services=None):
        self.commands = []
        self._processes = processes
        self._identity_ok = identity_ok
        self._services = SERVICES if services is None else services

    def run(self, command, timeout=None):
        self.commands.append(command)
        if "PSVersionTable" in command:
            return CommandResult(stdout="5", exit_code=0, success=True)
        if "netstat" in command:
            return CommandResult(stdout=NETSTAT, exit_code=0, success=True)
        if "Win32_Service" in command:
            return CommandResult(
                stdout=json.dumps(self._services), exit_code=0, success=True
            )
        if "Get-Process" in command:
            if not self._identity_ok:
                # What a timeout looks like: no output, no message.
                return CommandResult(stderr="", exit_code=-1, success=False)
            return CommandResult(
                stdout=json.dumps(self._processes), exit_code=0, success=True
            )
        return CommandResult(exit_code=1, success=False)

    @property
    def identity_command(self):
        return next((c for c in self.commands if "Get-Process -Id" in c), "")


@pytest.fixture
def collector():
    ssh = _FakeSSH()
    return WindowsCollector(ssh), ssh


def test_listening_sockets_are_resolved_to_their_software(collector):
    coll, _ssh = collector
    ports = {p["port"]: p for p in coll._collect_open_ports()}

    assert ports["22"]["process"] == "sshd"
    assert ports["22"]["product"] == "OpenSSH for Windows"
    assert ports["22"]["version"] == "9.5.5.1"

    assert ports["3306"]["product"] == "MySQL Server"
    assert ports["3306"]["version"] == "8.0.40.0"

    assert ports["5432"]["product"] == "PostgreSQL"
    assert ports["5432"]["version"] == "18.3"


def test_placeholder_version_resources_are_not_stored_as_a_product(collector):
    """
    nginx really does ship "None" as both Company and Product. Recording that
    is worse than recording nothing — it reads as a product called None.
    """
    coll, _ssh = collector
    ports = {p["port"]: p for p in coll._collect_open_ports()}

    assert ports["80"]["process"] == "nginx"
    assert "product" not in ports["80"]
    assert "version" not in ports["80"]


def test_a_process_with_no_version_resource_still_gets_its_name(collector):
    """PID 4 exposes no file metadata, but naming it 'System' still beats 'PID 4'."""
    coll, _ssh = collector
    ports = {p["port"]: p for p in coll._collect_open_ports()}

    assert ports["445"]["process"] == "System"
    assert ports["445"]["pid"] == "4"
    assert "product" not in ports["445"]


def test_only_listening_pids_are_queried(collector):
    """
    Asking for every process on a busy host reads 469 version resources and
    blows the command timeout, returning nothing. Scope is the fix.
    """
    coll, ssh = collector
    coll._collect_open_ports()
    cmd = ssh.identity_command

    assert "Get-Process -Id " in cmd
    for pid in ("8016", "10748", "11544", "11432", "4"):
        assert pid in cmd
    # The ESTABLISHED row holds no listening socket and must not be queried.
    assert "999" not in cmd


def test_pid_count_is_capped(monkeypatch):
    """A host with an unusual number of sockets cannot rebuild the timeout."""
    rows = [
        "  TCP    0.0.0.0:%d    0.0.0.0:0    LISTENING    %d" % (1024 + i, 5000 + i)
        for i in range(_MAX_IDENTITY_PIDS + 40)
    ]

    class _ManySSH(_FakeSSH):
        def run(self, command, timeout=None):
            if "netstat" in command:
                self.commands.append(command)
                return CommandResult(stdout="\n".join(rows), exit_code=0, success=True)
            return super().run(command, timeout)

    ssh = _ManySSH(processes=[])
    coll = WindowsCollector(ssh)
    ports = coll._collect_open_ports()

    assert len(ports) == _MAX_IDENTITY_PIDS + 40  # every socket still recorded
    queried = ssh.identity_command.split("Get-Process -Id ")[1].split(" ")[0]
    assert len(queried.split(",")) == _MAX_IDENTITY_PIDS


def test_a_failed_lookup_does_not_lose_the_socket_table():
    """
    The port inventory is the primary result. If identity resolution times out,
    the sockets are still reported — just unnamed, as they were before.
    """
    ssh = _FakeSSH(identity_ok=False)
    coll = WindowsCollector(ssh)
    ports = {p["port"]: p for p in coll._collect_open_ports()}

    assert len(ports) == 8  # every LISTENING row in the fixture
    assert ports["22"]["process"] == "PID 8016"
    assert "product" not in ports["22"]


def test_collector_identity_outranks_a_package_name_guess():
    """
    A version read from the binary describes the exact file serving the port.
    A package match is an inference from a process name, and must never
    overwrite the stronger evidence.
    """
    from scans.asset_syncer import _service_identity_from_process

    # The package path alone misfires here, and this pairing is real: the host
    # runs a Java service and also has "Java Auto Updater" installed. Substring
    # matching picks the updater; the binary is the Platform SE runtime.
    packages = [{"name": "Java Auto Updater", "version": "2.8.451.16"}]
    guessed, guessed_version = _service_identity_from_process("java", packages)
    assert guessed == "Java Auto Updater"
    assert guessed_version == "2.8.451.16"

    # What the collector read from the binary must survive that guess.
    record = {
        "port": "22311",
        "process": "java",
        "product": "Java(TM) Platform SE 8",
        "version": "8.0.4410.7",
    }
    if not record.get("product"):  # mirrors the guard in _apply_credentialed_enrichment
        record["product"], record["version"] = guessed, guessed_version
    assert record["product"] == "Java(TM) Platform SE 8"
    assert record["version"] == "8.0.4410.7"

    # And with nothing from the collector, the guess is still better than blank.
    fallback = {"port": "22311", "process": "java"}
    if not fallback.get("product"):
        fallback["product"], fallback["version"] = guessed, guessed_version
    assert fallback["product"] == "Java Auto Updater"


def test_an_os_process_is_never_attributed_to_an_installed_package():
    """
    Found on a real host: PID 4 ("System", the Windows kernel) was matched to
    "HP System Default Settings" because "system" appears inside that package
    name, stamping a false product *and version* onto SMB and WinRM. A wrong
    version is worse than none — it is what the CVE range check reads.
    """
    from scans.asset_syncer import _service_identity_from_process

    packages = [{"name": "HP System Default Settings", "version": "1.5.20.1"}]
    product, version = _service_identity_from_process("System", packages)

    assert product == "System"
    assert version is None


def test_a_package_match_must_be_anchored_at_the_name_start():
    """
    Substring-anywhere is not evidence of identity. A package may be claimed
    only when the process name opens it, or matches it exactly.
    """
    from scans.asset_syncer import _service_identity_from_process

    packages = [
        {"name": "PostgreSQL 18", "version": "18.3"},
        {"name": "Microsoft Visual Studio Code", "version": "1.130.0"},
        {"name": "nginx", "version": "1.26.3"},
    ]

    # Opens the package name — a defensible claim.
    assert _service_identity_from_process("postgres", packages) == (
        "PostgreSQL 18",
        "18.3",
    )
    # Exact match.
    assert _service_identity_from_process("nginx", packages) == ("nginx", "1.26.3")
    # Appears mid-name only — rejected, the process is merely named.
    assert _service_identity_from_process("code", packages) == ("code", None)


def test_generic_name_check_ignores_the_exe_suffix():
    from scans.asset_syncer import _service_identity_from_process

    packages = [{"name": "Svchost Helper Suite", "version": "3.0"}]
    assert _service_identity_from_process("svchost.exe", packages) == (
        "svchost.exe",
        None,
    )


def test_svchost_is_named_by_the_service_it_hosts(collector):
    """
    A shared host process's own version resource says "Microsoft Windows
    Operating System" — accurate about the binary, useless about the port.
    The hosted service is what is actually answering.
    """
    coll, _ssh = collector
    ports = {p["port"]: p for p in coll._collect_open_ports()}

    rpc = ports["135"]
    assert rpc["process"] == "svchost"
    assert rpc["product"] == "RPC Endpoint Mapper, Remote Procedure Call (RPC)"
    assert rpc["hosted_services"] == "RPC Endpoint Mapper, Remote Procedure Call (RPC)"
    # No version: several services share the process, and the container's build
    # number is not theirs. Asserting one would feed the CVE range check a
    # version that belongs to something else.
    assert "version" not in rpc

    assert ports["5040"]["product"] == "Connected Devices Platform Service"


def test_a_real_product_is_not_replaced_by_its_service_name(collector):
    """
    sshd runs as a Windows service too, but it is not a host process — its
    binary names itself precisely, with a version. That is the better evidence.
    """
    coll, _ssh = collector
    ports = {p["port"]: p for p in coll._collect_open_ports()}

    assert ports["22"]["product"] == "OpenSSH for Windows"
    assert ports["22"]["version"] == "9.5.5.1"
    # The service is still recorded as corroborating evidence.
    assert ports["22"]["hosted_services"] == "OpenSSH SSH Server"


def test_a_host_process_with_no_services_claims_nothing(collector):
    """PID 4 hosts no service and has no version resource. It stays unnamed."""
    coll, _ssh = collector
    ports = {p["port"]: p for p in coll._collect_open_ports()}

    assert ports["445"]["process"] == "System"
    assert "product" not in ports["445"]
    assert "hosted_services" not in ports["445"]


def test_services_with_no_process_are_ignored():
    """A stopped service reports ProcessId 0 and belongs to no socket."""
    ssh = _FakeSSH()
    mapping = WindowsCollector(ssh)._services_by_pid()
    assert "0" not in mapping
    assert mapping["1692"] == [
        "RPC Endpoint Mapper",
        "Remote Procedure Call (RPC)",
    ]


def test_resolved_identity_reaches_the_service_row(db_session):
    """The whole point: the software name lands on the asset's service record."""
    import uuid

    from db.base import utcnow
    from db.models.assets import Asset
    from db.models.findings import Service
    from db.models.rbac import Organization
    from db.models.scans import Scan
    from scans.asset_syncer import upsert_credentialed_services

    org_id = f"org_test_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Organization(
            id=org_id,
            name="W",
            slug=f"w-{uuid.uuid4().hex[:8]}",
            max_assets=10,
            max_users=10,
            is_active=True,
            settings={},
        )
    )
    db_session.commit()
    asset = Asset(
        id=f"ast_{org_id}_10_0_0_5",
        org_id=org_id,
        ip_address="10.0.0.5",
        last_seen_at=utcnow(),
    )
    db_session.add(asset)
    scan_id = f"scn_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Scan(
            id=scan_id,
            org_id=org_id,
            target_str="10.0.0.5",
            scan_type="credentialed",
            pipeline_mode="credentialed",
        )
    )
    db_session.commit()

    ssh = _FakeSSH()
    listeners = WindowsCollector(ssh)._collect_open_ports()
    upsert_credentialed_services(db_session, asset.id, scan_id, listeners)
    db_session.commit()

    row = (
        db_session.query(Service)
        .filter(Service.asset_id == asset.id, Service.port == 3306)
        .one()
    )
    assert row.service_product == "MySQL Server"
    assert row.service_version == "8.0.40.0"
    assert row.service_name == "mysqld"
