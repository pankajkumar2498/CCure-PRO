r"""
engines/credentialed/windows_collector.py
------------------------------------------
Collects system information from a Windows host via SSH (OpenSSH Server)
using PowerShell commands. Requires Windows OpenSSH Server to be installed
and PowerShell to be the default shell (or cmd.exe fallback).

Enable on target: Add-WindowsCapability -Online -Name OpenSSH.Server
Set shell:        New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" `
                    -Name DefaultShell `
                    -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
"""

import base64
import ipaddress
import json
import logging
import re
from typing import Any, Callable, Dict, List, Optional

from core.mac import collector_mac
from engines.credentialed.ssh_scanner import BaseExecutor

log = logging.getLogger("ccure.windows_collector")

# Regex to strip ANSI/VT100 escape codes from terminal output
_ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-9;]*[A-Za-z]|\][^\x07]*\x07|[^\[\]])")


#: Values a Windows version resource uses to mean "nothing here". They arrive
#: as real strings, not nulls — nginx ships binaries whose Company and Product
#: are both the literal text "None" — and recording that as a product name is
#: worse than recording no product at all.
_PLACEHOLDER_VALUES = {"", "none", "null", "n/a", "unknown", "not available"}


def _clean_value(value: Any) -> str:
    """Text from PowerShell, with its placeholder strings treated as absent."""
    text = str(value if value is not None else "").strip()
    return "" if text.lower() in _PLACEHOLDER_VALUES else text


#: Resolve specific PIDs to the software running under them.
#:
#: Scoped to the PIDs holding a socket rather than every process on the box.
#: Selecting Company/Product/FileVersion forces PowerShell to read each
#: executable's version resource, which on a busy workstation (469 processes)
#: takes longer than the command timeout and returns nothing at all — the
#: listening set is a few dozen, and completes comfortably.
_PROCESS_IDENTITY_CMD = (
    "Get-Process -Id {pids} -ErrorAction SilentlyContinue | "
    "Select-Object Id,ProcessName,Path,Company,Product,FileVersion | "
    "ConvertTo-Json -Compress"
)

#: Ceiling on PIDs per query, so a host with an unusual number of listening
#: sockets cannot rebuild the timeout problem this scoping exists to avoid.
_MAX_IDENTITY_PIDS = 250

#: Which Windows services are running inside which process.
#:
#: Generic host processes run other people's code. ``svchost.exe`` on port 135
#: has a perfectly accurate version resource that reads "Microsoft Windows
#: Operating System" — true of the binary, useless for saying what is answering
#: on the port. The service table is the only thing that can name it.
_SERVICE_PID_CMD = (
    "Get-CimInstance Win32_Service -Filter 'ProcessId > 0' | "
    "Select-Object Name,DisplayName,ProcessId | ConvertTo-Json -Compress"
)

#: Processes that host other code rather than being the thing itself. For these
#: the hosted Windows service names identify the listener; the binary's own
#: version resource does not.
_HOST_PROCESSES = {"svchost", "dllhost", "taskhostw", "rundll32", "system", "services"}


# `net accounts` labels, matched case-insensitively against the start of each
# line. Deliberately label-based rather than positional: an earlier positional
# version keyed off the order of the numeric lines, and a single missing or
# extra line shifted every value — silently reporting one policy setting's
# number as another's. In a compliance product a silently wrong value is worse
# than no value, so an unrecognised layout yields nothing and the engine reports
# the control as not assessed.
_NET_ACCOUNTS_LABELS = (
    ("max_age_days", "maximum password age"),
    ("min_age_days", "minimum password age"),
    ("min_length", "minimum password length"),
    ("history_length", "length of password history"),
    ("lockout_threshold", "lockout threshold"),
    ("lockout_duration_minutes", "lockout duration"),
)


def _parse_net_accounts(raw: str) -> dict:
    """Extracts the local password policy from `net accounts` output.

    Returns only the keys it could actually read. A key that is absent means
    "not collected", which the compliance engine renders as not assessed —
    inventing a value here is what the previous hard-coded password policy did
    on every host in the estate.

    Non-English Windows installs localise these labels and will parse to an
    empty dict. That is the intended outcome: the control is then reported as
    unassessed rather than assessed from a guess.
    """
    if not raw:
        return {}

    policy: dict = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        label, _, tail = line.partition(":")
        label = label.strip().lower()
        tail = tail.strip()
        if not tail:
            continue

        for key, prefix in _NET_ACCOUNTS_LABELS:
            if not label.startswith(prefix):
                continue
            token = tail.split()[0]
            if token.isdigit():
                policy[key] = int(token)
            else:
                # "Never" / "Unlimited" — the setting exists but imposes no
                # limit, which for an age or a threshold means "not enforced".
                policy[key] = 0
            break

    if "min_length" in policy:
        # `net accounts` has no complexity line. A non-zero minimum length is
        # the closest observable proxy, and it is reported as exactly that
        # rather than as a guarantee that complexity rules are enabled.
        policy["complexity"] = policy["min_length"] > 0

    return policy


def _clean_output(raw: str) -> str:
    """Strip BOM, ANSI escape sequences, and leading non-printable garbage."""
    # Remove UTF-8 BOM
    raw = raw.lstrip("\ufeff")
    # Strip ANSI colour/cursor codes
    raw = _ANSI_ESCAPE.sub("", raw)
    # Strip Windows \r
    raw = raw.replace("\r", "")
    return raw.strip()


# PowerShell commands — output as plain text or JSON
def _subnet_from_windows_interfaces(raw: Any, target_ip: str) -> str:
    if not raw or not target_ip:
        return ""
    try:
        target = ipaddress.ip_address(target_ip)
    except ValueError:
        return ""

    interfaces = (
        raw if isinstance(raw, list) else [raw] if isinstance(raw, dict) else []
    )
    for iface in interfaces:
        ip_addr = _first_value(iface.get("IPAddress") or iface.get("IPv4Address"))
        prefix = _first_value(iface.get("PrefixLength"))
        if not ip_addr or prefix is None:
            continue
        try:
            network = ipaddress.ip_network(f"{ip_addr}/{prefix}", strict=False)
        except ValueError:
            continue
        if target in network:
            return str(network)
    return ""


def _first_value(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


#: This function lived here and in the other collector, character for
#: character. ``core.mac.collector_mac`` is that same body, moved once; the
#: alias keeps both call sites below unchanged.
_normalize_mac = collector_mac


def _mac_from_windows_interfaces(raw: Any, target_ip: str) -> str:
    interfaces = (
        raw if isinstance(raw, list) else [raw] if isinstance(raw, dict) else []
    )
    fallback = ""
    for iface in interfaces:
        mac = _normalize_mac(iface.get("MacAddress"))
        if not mac:
            continue
        if not fallback:
            fallback = mac
        ip_addr = _first_value(iface.get("IPAddress") or iface.get("IPv4Address"))
        if target_ip and ip_addr == target_ip:
            return mac
    return fallback


COMMANDS: dict[str, str] = {
    # OS info
    "os_info": "(Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture | ConvertTo-Json)",
    # The update revision (UBR) and the marketing release ("25H2").
    #
    # Win32_OperatingSystem.Version stops at the build — 10.0.26200 — and omits
    # the revision, which is the only part that moves when a monthly cumulative
    # update is installed. Matching the OS against Microsoft's published fixes
    # compares build numbers, so without the UBR every host looks like the
    # day-zero release of its Windows version and every patch since launch
    # reads as missing.
    "os_revision": (
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' "
        "| Select-Object CurrentBuild, UBR, DisplayVersion, ProductName | ConvertTo-Json)"
    ),
    "hostname": "hostname",
    "uptime": "((Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime).ToString('dd\\.hh\\:mm\\:ss')",
    # Hardware & Identity
    "computer_system": "(Get-CimInstance Win32_ComputerSystem | Select-Object Name, DNSHostName, Domain, PartOfDomain, Manufacturer, Model | ConvertTo-Json)",
    "bios": "(Get-CimInstance Win32_BIOS | Select-Object SerialNumber, SMBIOSBIOSVersion | ConvertTo-Json)",
    "cpu": "(Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors | ConvertTo-Json)",
    "memory": "(Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory | ConvertTo-Json)",
    "disk": "(Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free | ConvertTo-Json)",
    # Installed software (registry-based — most complete source)
    "software_x64": "(Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' | Where-Object {$_.DisplayName} | Select-Object DisplayName, DisplayVersion, Publisher | ConvertTo-Json)",
    "software_x86": "(Get-ItemProperty 'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' | Where-Object {$_.DisplayName} | Select-Object DisplayName, DisplayVersion, Publisher | ConvertTo-Json)",
    # Windows Updates / Hotfixes
    "hotfixes": "(Get-HotFix | Select-Object HotFixID, Description, InstalledOn | ConvertTo-Json)",
    # Services
    "services": "(Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, StartType | ConvertTo-Json)",
    # Network
    "open_ports": "netstat -ano | findstr LISTENING",
    "network_iface": (
        "Get-NetIPConfiguration | ForEach-Object { "
        "$ipv4=$_.IPv4Address | Select-Object -First 1; "
        "[PSCustomObject]@{ "
        "InterfaceAlias=$_.InterfaceAlias; "
        "InterfaceIndex=$_.InterfaceIndex; "
        "IPAddress=$ipv4.IPAddress; "
        "PrefixLength=$ipv4.PrefixLength; "
        "MacAddress=$_.NetAdapter.MacAddress; "
        "InterfaceDescription=$_.NetAdapter.InterfaceDescription "
        "} } | ConvertTo-Json"
    ),
    "network_config": "(Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv6Address, IPv4DefaultGateway, DNSServer | ConvertTo-Json)",
    # Users
    "local_users": "(Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet | ConvertTo-Json)",
    "local_admins": "(Get-LocalGroupMember -Group Administrators | Select-Object Name, ObjectClass | ConvertTo-Json)",
    # Security
    "firewall": "(Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | ConvertTo-Json)",
    "shares": "(Get-SmbShare | Select-Object Name, Path, Description | ConvertTo-Json)",
    "audit_policy": "auditpol /get /category:* 2>&1",
    # `net accounts` is the one password-policy source available without RSAT
    # or a domain query, and it reports the effective local policy. Output is
    # locale-dependent label text, so the parser matches on the numeric tail of
    # each line rather than the label. Compliance controls that read password
    # policy used to be answered from a hard-coded constant; this collects it.
    "password_policy": "net accounts",
    # NOTE: Get-ItemProperty | ConvertTo-Json serialises the full RegistryKey
    # PSObject (including .NET provider metadata). Use Get-ItemPropertyValue to
    # get just the DWORD, then build a clean PSCustomObject.
    "rdp_status": (
        "$_fDeny = Get-ItemPropertyValue "
        "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
        "-Name fDenyTSConnections -ErrorAction SilentlyContinue; "
        "[PSCustomObject]@{ fDenyTSConnections = if ($_fDeny -ne $null) { [int]$_fDeny } else { 1 } } "
        "| ConvertTo-Json -Compress"
    ),
    # Scheduled tasks (suspicious ones — not system-signed)
    "scheduled_tasks": "(Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled' -and $_.Author -notmatch 'Microsoft'} | Select-Object TaskName, TaskPath, State | ConvertTo-Json)",
    # Event log — failed logins
    "failed_logins": "(Get-WinEvent -LogName Security -FilterHashtable @{Id=4625} -MaxEvents 20 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | ConvertTo-Json)",
    # Safe Protocol Hardening Queries
    "smbv1_status": (
        "$_smb1 = Get-ItemPropertyValue 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name SMB1 -ErrorAction SilentlyContinue; "
        "$_feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue; "
        "[PSCustomObject]@{ "
        "  SMB1 = if ($_smb1 -ne $null) { [int]$_smb1 } else { 0 }; "
        "  FeatureEnabled = if ($_feat -ne $null -and $_feat.State -eq 'Enabled') { $true } else { $false } "
        "} | ConvertTo-Json -Compress"
    ),
    "netbios_status": (
        "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' | "
        "Select-Object SettingID, NetbiosOptions | ConvertTo-Json"
    ),
    "tls_status": (
        "$protocols = @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1'); "
        "$res = @(); "
        "foreach ($proto in $protocols) { "
        "  foreach ($type in @('Client', 'Server')) { "
        '    $val = Get-ItemPropertyValue "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$proto\\$type" -Name Enabled -ErrorAction SilentlyContinue; '
        "    $res += [PSCustomObject]@{ Protocol = $proto; Type = $type; Enabled = if ($val -ne $null) { [int]$val } else { 1 } } "
        "  } "
        "}; "
        "$res | ConvertTo-Json"
    ),
    "rdp_nla_status": (
        "$_nla = Get-ItemPropertyValue 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue; "
        "[PSCustomObject]@{ UserAuthentication = if ($_nla -ne $null) { [int]$_nla } else { 0 } } | ConvertTo-Json -Compress"
    ),
    "telnet_status": (
        "$_svc = Get-Service -Name TlntSvr -ErrorAction SilentlyContinue; "
        "$_feat = Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction SilentlyContinue; "
        "[PSCustomObject]@{ "
        "  ServiceRunning = if ($_svc -ne $null -and $_svc.Status -eq 'Running') { $true } else { $false }; "
        "  FeatureEnabled = if ($_feat -ne $null -and $_feat.State -eq 'Enabled') { $true } else { $false } "
        "} | ConvertTo-Json -Compress"
    ),
}


class WindowsCollector:
    """
    Runs PowerShell commands over an open executor connection and parses the
    output into structured dicts ready for JSON serialisation.

    **Transport-agnostic.** The parameter is a ``BaseExecutor``, so this drives
    either ``SSHScanner`` (OpenSSH on Windows) or ``WinRMExecutor`` (native
    WinRM, added in Phase 2) without knowing which. Every command below is
    plain PowerShell and every parser reads its output — none of it depends on
    how the bytes arrived, which is why native Windows support needed a new
    transport rather than a second collector.

    ``_detect_shell`` works over both: WinRM answers ``$PSVersionTable`` with a
    version number, so it reports "powershell" and ``_wrap_ps`` correctly
    leaves commands alone — pywinrm does its own UTF-16-LE base64 encoding, and
    wrapping twice would send the encoder its own output.
    """

    # Path to PowerShell executable — used when the default shell is cmd.exe
    _PS_EXE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

    def __init__(self, ssh: BaseExecutor):
        self._ssh = ssh
        self.shell_type = self._detect_shell()
        if self.shell_type == "cmd":
            log.warning(
                "Windows target default SSH shell is 'cmd'. "
                "Commands will be wrapped in explicit powershell.exe calls. "
                "To avoid this overhead, set the default shell: "
                "New-ItemProperty -Path 'HKLM:\\SOFTWARE\\OpenSSH' -Name DefaultShell "
                "-Value 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -PropertyType String -Force"
            )
        else:
            log.info("Windows SSH shell detected as PowerShell.")

    def _detect_shell(self) -> str:
        """Returns 'powershell' or 'cmd'."""
        result = self._ssh.run("$PSVersionTable.PSVersion.Major", timeout=8)
        cleaned = _clean_output(result.stdout)
        return "powershell" if (result.success and cleaned.isdigit()) else "cmd"

    def _wrap_ps(self, cmd: str) -> str:
        """
        When the default shell is cmd.exe, encode the PowerShell command as
        UTF-16-LE base64 and pass it via -EncodedCommand.

        This avoids ALL quoting/escaping ambiguities that arise when cmd.exe
        passes the command string to powershell.exe — the only safe method
        for complex commands with braces, dollar signs, and inner quotes.
        """
        if self.shell_type == "powershell":
            return cmd
        encoded = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")
        return (
            f"{self._PS_EXE} -NoProfile -NonInteractive -ExecutionPolicy Bypass"
            f" -EncodedCommand {encoded}"
        )

    def collect_all(
        self,
        sections: list[str] | None = None,
        on_section_complete: Callable | None = None,
    ) -> dict[str, Any]:
        """
        Run all collectors concurrently and return a merged dict.

        All section collectors are independent — they run concurrently via
        a ThreadPoolExecutor. If one section fails the others are unaffected.
        Results are merged in the same structure as the sequential version so
        the caller (credentialed engine / report layer) is unchanged.
        """
        run_all = sections is None

        tasks: list[tuple] = []
        if run_all or "system_info" in sections:
            tasks.append(("system_info", self._collect_system_info))
        if run_all or "packages" in sections:
            tasks.append(("packages", self._collect_software))
        if run_all or "services" in sections:
            tasks.append(("services", self._collect_services))
        if run_all or "ports" in sections:
            tasks.append(("ports", self._collect_open_ports))
        if run_all or "users" in sections:
            tasks.append(("users", self._collect_users))
            tasks.append(("local_groups", self._collect_local_groups))
        if run_all or "security" in sections:
            tasks.append(("security", self._collect_security))
        if run_all or "network" in sections:
            tasks.append(("network", self._collect_network))
        if run_all or "history" in sections:
            tasks.append(("history", self._collect_login_history))

        result: dict[str, Any] = {}

        from concurrent.futures import ThreadPoolExecutor, as_completed

        with ThreadPoolExecutor(max_workers=len(tasks) or 1) as pool:
            future_map = {pool.submit(fn): name for name, fn in tasks}
            for future in as_completed(future_map):
                name = future_map[future]
                try:
                    data = future.result()
                    if on_section_complete:
                        on_section_complete(name)
                    # Flat-merge sections that return dicts
                    if name in ("system_info", "security", "network", "history"):
                        result.update(data)
                    elif name == "packages":
                        result["packages"] = data
                    elif name == "services":
                        result["running_services"] = data
                    elif name == "ports":
                        result["open_ports_credentialed"] = data
                    elif name == "users":
                        result["users"] = data
                    elif name == "local_groups":
                        result["local_groups"] = data
                except Exception as exc:
                    # See the Linux collector: a swallowed section failure reads
                    # downstream as "nothing found", which for the software
                    # inventory means an unassessed host is reported as clean.
                    log.warning("Windows section '%s' collection failed: %s", name, exc)
                    result.setdefault("collection_errors", {})[name] = str(exc)

        result["sections_requested"] = [name for name, _fn in tasks]
        return result

    def _collect_system_info(self) -> dict[str, Any]:
        data: dict[str, Any] = {}

        os_raw = self._run_json("os_info")
        data["os_name"] = os_raw.get("Caption", "Windows")
        data["os_version_id"] = os_raw.get("Version", "")
        data["os_build"] = os_raw.get("BuildNumber", "")
        data["kernel_version"] = os_raw.get("Version", "")
        data["cpu_arch"] = os_raw.get("OSArchitecture", "")
        data["os_family"] = "Windows"
        data["os_confidence"] = 100

        # Build revision — see the "os_revision" command for why this matters.
        # os_version_id is upgraded from 10.0.26200 to 10.0.26200.8973 so the
        # patch matcher receives a build it can compare; the unrevised value is
        # kept as os_version_base for anything that was reading the old shape.
        revision_raw = self._run_json("os_revision")
        if isinstance(revision_raw, list):
            revision_raw = revision_raw[0] if revision_raw else {}
        if isinstance(revision_raw, dict):
            ubr = str(revision_raw.get("UBR") or "").strip()
            data["os_ubr"] = ubr
            data["os_release"] = (revision_raw.get("DisplayVersion") or "").strip()
            base = str(data.get("os_version_id") or "").strip()
            data["os_version_base"] = base
            if ubr.isdigit() and re.match(r"^\d+\.\d+\.\d+$", base):
                data["os_version_id"] = f"{base}.{ubr}"
                data["kernel_version"] = data["os_version_id"]
        else:
            data["os_ubr"] = ""
            data["os_release"] = ""
            data["os_version_base"] = str(data.get("os_version_id") or "")

        computer_raw = self._run_json("computer_system")
        if isinstance(computer_raw, list):
            computer_raw = computer_raw[0] if computer_raw else {}
        if isinstance(computer_raw, dict):
            dns_host = (
                computer_raw.get("DNSHostName") or computer_raw.get("Name") or ""
            ).strip()
            domain = (computer_raw.get("Domain") or "").strip()
            data["hostname_short"] = dns_host
            data["domain"] = domain
            data["manufacturer"] = (computer_raw.get("Manufacturer") or "").strip()
            data["hardware_model"] = (computer_raw.get("Model") or "").strip()
            if dns_host and domain and domain.upper() != "WORKGROUP":
                data["hostname_fqdn"] = f"{dns_host}.{domain}"
                data["fqdn"] = data["hostname_fqdn"]
            else:
                data["hostname_fqdn"] = dns_host or self._run("hostname")
        else:
            data["hostname_fqdn"] = self._run("hostname")
        data["uptime"] = self._run("uptime")

        bios_raw = self._run_json("bios")
        if isinstance(bios_raw, list):
            bios_raw = bios_raw[0] if bios_raw else {}
        if isinstance(bios_raw, dict):
            data["serial_number"] = (bios_raw.get("SerialNumber") or "").strip()
            data["bios_version"] = (bios_raw.get("SMBIOSBIOSVersion") or "").strip()
        else:
            data["serial_number"] = ""
            data["bios_version"] = ""

        cpu_raw = self._run_json("cpu")
        if isinstance(cpu_raw, list):
            cpu_raw = cpu_raw[0] if cpu_raw else {}
        data["cpu_model"] = cpu_raw.get("Name", "")
        data["cpu_count"] = str(cpu_raw.get("NumberOfLogicalProcessors", ""))

        mem_raw = self._run_json("memory")
        if mem_raw:
            total_kb = mem_raw.get("TotalVisibleMemorySize", 0)
            free_kb = mem_raw.get("FreePhysicalMemory", 0)
            data["memory_summary"] = {
                "total": f"{total_kb // 1024} MB",
                "free": f"{free_kb  // 1024} MB",
                "used": f"{(total_kb - free_kb) // 1024} MB",
                "available": f"{free_kb  // 1024} MB",
            }

        disk_raw = self._run_json("disk")
        if isinstance(disk_raw, list):
            data["disk_usage"] = [
                {
                    "filesystem": d.get("Name", ""),
                    "used": f"{(d.get('Used') or 0) // (1024**3)} GB",
                    "available": f"{(d.get('Free') or 0) // (1024**3)} GB",
                }
                for d in disk_raw
                if d.get("Name")
            ]

        return data

    def _collect_software(self) -> list[dict[str, str]]:
        """Combine 64-bit and 32-bit registry keys for installed software."""
        packages = []
        seen = set()
        for key in ("software_x64", "software_x86"):
            items = self._run_json(key)
            if not isinstance(items, list):
                items = [items] if isinstance(items, dict) else []
            for item in items:
                name = (item.get("DisplayName") or "").strip()
                ver = (item.get("DisplayVersion") or "").strip()
                if name and name not in seen:
                    packages.append(
                        {
                            "name": name,
                            "version": ver,
                            # The registry query already asks for Publisher and
                            # this discarded it. It is the vendor half of a CPE
                            # identity: "Google Chrome" alone does not resolve
                            # to cpe:2.3:a:google:chrome, but publisher "Google
                            # LLC" plus product "chrome" does.
                            "vendor": (item.get("Publisher") or "").strip(),
                            "arch": "",
                            "manager": "windows_registry",
                        }
                    )
                    seen.add(name)

        # Also collect Windows hotfixes as pseudo-packages
        hotfixes = self._run_json("hotfixes")
        if isinstance(hotfixes, list):
            for hf in hotfixes:
                kb = hf.get("HotFixID", "")
                if kb and kb not in seen:
                    packages.append(
                        {
                            "name": kb,
                            "version": str(hf.get("InstalledOn", "")),
                            "arch": "",
                            "manager": "windows_update",
                        }
                    )
                    seen.add(kb)

        return packages

    def _collect_services(self) -> list[dict[str, str]]:
        items = self._run_json("services")
        if not isinstance(items, list):
            items = [items] if isinstance(items, dict) else []
        return [
            {
                "name": i.get("Name", ""),
                "description": i.get("DisplayName", ""),
                "start_type": str(i.get("StartType", "")),
            }
            for i in items
            if i.get("Name")
        ]

    def _process_identity_map(self, pids: set[str]) -> dict[str, dict[str, str]]:
        """
        PID → the software running under it, for the PIDs holding a socket.

        This is the only point at which the two halves can be joined. netstat
        reports a PID and the socket table is discarded straight afterwards, so
        anything not resolved here is unresolvable later: the service record,
        the asset's inventory and the report all end up naming a port with no
        idea what is answering on it.

        The binary's own version resource is preferred over a guess from the
        installed-software list, because it describes the exact file serving
        the port — ``mysqld`` resolves to "MySQL Server 8.0.40.0" whether or not
        MySQL registered an uninstall entry.
        """
        wanted = sorted({p for p in pids if p and p.isdigit()}, key=int)
        if not wanted:
            return {}
        if len(wanted) > _MAX_IDENTITY_PIDS:
            log.debug(
                "Resolving identity for the first %d of %d listening PIDs",
                _MAX_IDENTITY_PIDS,
                len(wanted),
            )
            wanted = wanted[:_MAX_IDENTITY_PIDS]

        raw = self._run_command(
            _PROCESS_IDENTITY_CMD.format(pids=",".join(wanted)),
            timeout=90,
            label="listening_processes",
        )
        entries = self._decode_json(raw, "listening_processes")
        if isinstance(entries, dict):
            entries = [entries]
        if not isinstance(entries, list):
            entries = []

        services = self._services_by_pid()

        mapping: dict[str, dict[str, str]] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            pid = _clean_value(entry.get("Id"))
            name = _clean_value(entry.get("ProcessName"))
            if not pid or not name:
                continue

            record: dict[str, str] = {"process": name}
            # Product names the software; Company is the fallback for binaries
            # that ship a vendor but no product string.
            product = _clean_value(entry.get("Product")) or _clean_value(
                entry.get("Company")
            )
            version = _clean_value(entry.get("FileVersion"))
            path = _clean_value(entry.get("Path"))

            hosted = services.get(pid) or []
            if hosted:
                record["hosted_services"] = ", ".join(hosted)[:512]

            if name.lower() in _HOST_PROCESSES and hosted:
                # The binary is a container. Its version resource describes the
                # container ("Microsoft Windows Operating System"), not what is
                # answering on the port, so the hosted service names take over.
                # No version is asserted: several services can share one process
                # and the host binary's build number is not theirs.
                record["product"] = ", ".join(hosted)[:255]
                version = ""
            elif product:
                record["product"] = product[:255]

            if version:
                record["version"] = version[:200]
            if path:
                record["process_path"] = path[:512]
            mapping[pid] = record
        return mapping

    def _services_by_pid(self) -> dict[str, list[str]]:
        """
        PID → the Windows services running inside it.

        Only meaningful for host processes, but cheap enough to fetch once and
        attach everywhere: it is also the evidence that a socket on a shared
        ``svchost`` belongs to RPC rather than to Windows in general.
        """
        try:
            raw = self._run_command(
                _SERVICE_PID_CMD, timeout=60, label="services_by_pid"
            )
            entries = self._decode_json(raw, "services_by_pid")
        except Exception as exc:  # noqa: BLE001 — identity degrades, nothing breaks
            log.debug("Could not map services to PIDs: %s", exc)
            return {}

        if isinstance(entries, dict):
            entries = [entries]
        if not isinstance(entries, list):
            return {}

        mapping: dict[str, list[str]] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            pid = _clean_value(entry.get("ProcessId"))
            label = _clean_value(entry.get("DisplayName")) or _clean_value(
                entry.get("Name")
            )
            if pid and pid != "0" and label:
                mapping.setdefault(pid, []).append(label)
        return {pid: sorted(names) for pid, names in mapping.items()}

    def _collect_open_ports(self) -> list[dict[str, str]]:
        raw = self._run("open_ports")

        ports = []
        for line in raw.splitlines():
            # Format: TCP    0.0.0.0:445    0.0.0.0:0    LISTENING    4
            parts = line.split()
            if len(parts) >= 4 and "LISTENING" in parts:
                local = parts[1]
                ports.append(
                    {
                        "state": "LISTEN",
                        "local_addr": local,
                        "port": local.rsplit(":", 1)[-1] if ":" in local else "",
                        "pid": parts[-1],
                        # Retained for protected processes the lookup cannot
                        # read, so the record still says which PID holds the
                        # socket even when the software cannot be named.
                        "process": f"PID {parts[-1]}",
                    }
                )

        # Resolved after parsing, because only now is the PID set known — and
        # querying just those is what keeps the lookup inside its timeout.
        try:
            processes = self._process_identity_map({p["pid"] for p in ports})
        except Exception as exc:  # noqa: BLE001 — the socket table is still useful
            log.debug("Could not resolve listening process identities: %s", exc)
            processes = {}

        for record in ports:
            record.update(processes.get(record["pid"], {}))
        return ports

    def _collect_users(self) -> list[dict[str, str]]:
        users_raw = self._run_json("local_users")
        admins_raw = self._run_json("local_admins")
        admin_names = set()
        if isinstance(admins_raw, list):
            for a in admins_raw:
                name = a.get("Name", "")
                if "\\" in name:
                    name = name.split("\\")[-1]
                admin_names.add(name)

        if not isinstance(users_raw, list):
            users_raw = [users_raw] if isinstance(users_raw, dict) else []
        return [
            {
                "username": u.get("Name", ""),
                "enabled": str(u.get("Enabled", "")),
                "is_admin": u.get("Name", "") in admin_names,
                "last_logon": str(u.get("LastLogon", "")),
                "pwd_required": str(u.get("PasswordRequired", "")),
            }
            for u in users_raw
            if u.get("Name")
        ]

    def _collect_security(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        issues = []

        fw_raw = self._run_json("firewall")
        if isinstance(fw_raw, list):
            data["firewall_profiles"] = fw_raw
            for p in fw_raw:
                if not p.get("Enabled"):
                    issues.append(f"Firewall profile '{p.get('Name')}' is DISABLED")

        shares_raw = self._run_json("shares")
        if isinstance(shares_raw, list):
            data["smb_shares"] = shares_raw
            admin_shares = {"ADMIN$", "C$", "IPC$"}
            extra_shares = [
                s["Name"] for s in shares_raw if s.get("Name") not in admin_shares
            ]
            if extra_shares:
                issues.append(
                    f"Non-default SMB shares found: {', '.join(extra_shares)}"
                )

        rdp_raw = self._run_json("rdp_status")
        rdp_enabled = rdp_raw.get("fDenyTSConnections", 1) == 0 if rdp_raw else False
        data["rdp_enabled"] = rdp_enabled
        if rdp_enabled:
            issues.append(
                "RDP is enabled — ensure NLA is enforced and access is restricted"
            )

        tasks_raw = self._run_json("scheduled_tasks")
        if isinstance(tasks_raw, list):
            data["suspicious_scheduled_tasks"] = tasks_raw

        pwd_policy = _parse_net_accounts(self._run("password_policy"))
        if pwd_policy:
            data["password_policy"] = pwd_policy

        # Safe Protocol Hardening Checks
        smb1_raw = self._run_json("smbv1_status")
        smbv1_disabled = not (
            smb1_raw.get("SMB1", 0) == 1 or smb1_raw.get("FeatureEnabled", False)
        )
        data["smbv1_disabled"] = smbv1_disabled
        if not smbv1_disabled:
            issues.append("Legacy SMBv1 protocol is enabled")

        netbios_raw = self._run_json("netbios_status")
        netbios_list = (
            netbios_raw
            if isinstance(netbios_raw, list)
            else [netbios_raw] if isinstance(netbios_raw, dict) else []
        )
        netbios_disabled = True
        if netbios_list:
            for adapter in netbios_list:
                # NetbiosOptions: 0 = DHCP/Default, 1 = Enabled, 2 = Disabled
                if adapter.get("NetbiosOptions") != 2:
                    netbios_disabled = False
                    break
        else:
            netbios_disabled = False
        data["netbios_disabled"] = netbios_disabled
        if not netbios_disabled:
            issues.append(
                "NetBIOS over TCP/IP is enabled on one or more network adapters"
            )

        tls_raw = self._run_json("tls_status")
        tls_list = (
            tls_raw
            if isinstance(tls_raw, list)
            else [tls_raw] if isinstance(tls_raw, dict) else []
        )
        legacy_tls_disabled = True
        for proto in tls_list:
            if proto.get("Enabled", 1) == 1:
                legacy_tls_disabled = False
                issues.append(
                    f"Legacy SChannel protocol {proto.get('Protocol')} ({proto.get('Type')}) is enabled"
                )
        data["legacy_tls_disabled"] = legacy_tls_disabled

        nla_raw = self._run_json("rdp_nla_status")
        rdp_nla_enforced = nla_raw.get("UserAuthentication", 0) == 1
        data["rdp_nla_enforced"] = rdp_nla_enforced
        if not rdp_nla_enforced and rdp_enabled:
            issues.append(
                "RDP is enabled but Network Level Authentication (NLA) is not enforced"
            )

        telnet_raw = self._run_json("telnet_status")
        telnet_disabled = not (
            telnet_raw.get("ServiceRunning", False)
            or telnet_raw.get("FeatureEnabled", False)
        )
        data["telnet_disabled"] = telnet_disabled
        if not telnet_disabled:
            issues.append("Telnet client or server is enabled/running")

        data["security_issues"] = issues
        return data

    def _collect_network(self) -> dict[str, Any]:
        iface_raw = self._run_json("network_iface")
        return {
            "network_interfaces_raw": json.dumps(iface_raw) if iface_raw else "",
            "subnet": _subnet_from_windows_interfaces(iface_raw, self._ssh.ip),
            "mac_address": _mac_from_windows_interfaces(iface_raw, self._ssh.ip),
            "arp_table_raw": "",
            "env_vars_summary": [],
        }

    def _collect_login_history(self) -> dict[str, Any]:
        failed_raw = self._run_json("failed_logins")
        failed_list = failed_raw if isinstance(failed_raw, list) else []
        return {
            "login_history_raw": "",
            "failed_logins_recent": [
                str(f.get("TimeCreated", "")) for f in failed_list[:20]
            ],
            "failed_login_count": len(failed_list),
            "brute_force_warning": len(failed_list) >= 10,
        }

    def _collect_local_groups(self) -> list[dict[str, Any]]:
        admins_raw = self._run_json("local_admins")
        admin_names = []
        if isinstance(admins_raw, list):
            for a in admins_raw:
                name = a.get("Name", "")
                if name:
                    if "\\" in name:
                        name = name.split("\\")[-1]
                    admin_names.append(name)
        elif isinstance(admins_raw, dict):
            name = admins_raw.get("Name", "")
            if name:
                if "\\" in name:
                    name = name.split("\\")[-1]
                admin_names.append(name)

        return [{"name": "Administrators", "members": admin_names}]

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _run(self, key: str, timeout: int = 45) -> str:
        """Execute a named command and return cleaned stdout."""
        cmd = COMMANDS.get(key, "")
        if not cmd:
            return ""
        final_cmd = self._wrap_ps(cmd)
        result = self._ssh.run(final_cmd, timeout=timeout)
        if result.stderr:
            log.debug("stderr for '%s': %s", key, result.stderr[:200])
        return _clean_output(result.stdout) if result.stdout else ""

    def _run_command(self, cmd: str, timeout: int = 45, label: str = "") -> str:
        """
        Execute a PowerShell command built at runtime.

        The counterpart to :meth:`_run` for commands whose text depends on what
        an earlier collector found — the process lookup can only be written
        once the socket table has named its PIDs.
        """
        if not cmd:
            return ""
        result = self._ssh.run(self._wrap_ps(cmd), timeout=timeout)
        if result.stderr:
            log.debug("stderr for '%s': %s", label or "ad-hoc", result.stderr[:200])
        return _clean_output(result.stdout) if result.stdout else ""

    def _run_json(self, key: str) -> Any:
        """Run a named command and parse its output as JSON."""
        return self._decode_json(self._run(key), key)

    def _decode_json(self, raw: str, label: str) -> Any:
        """
        Parse command output as JSON.

        Uses JSONDecoder.raw_decode() which:
          - Skips any leading noise/banner text before the first '[' or '{'
          - Stops parsing at the end of the first complete JSON value
          - Ignores any trailing garbage (e.g. provider metadata, blank lines)
        """
        if not raw:
            return {}

        # Fast-path: direct parse
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass

        # Slow-path: scan for the first '[' or '{' and use raw_decode so that
        # trailing non-JSON content is ignored.
        decoder = json.JSONDecoder()
        for i, ch in enumerate(raw):
            if ch in "[{":
                try:
                    obj, _ = decoder.raw_decode(raw, i)
                    return obj
                except json.JSONDecodeError:
                    continue  # try next occurrence

        log.warning("Failed to parse JSON for command '%s' | raw=%.300s", label, raw)
        return {}
