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

from engines.credentialed.ssh_scanner import SSHScanner

log = logging.getLogger("ccure.windows_collector")

# Regex to strip ANSI/VT100 escape codes from terminal output
_ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-9;]*[A-Za-z]|\][^\x07]*\x07|[^\[\]])")


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


def _normalize_mac(value: str) -> str:
    text = str(value or "").strip().lower().replace("-", ":")
    if not text or text in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
        return ""
    if re.fullmatch(r"[0-9a-f]{12}", text):
        text = ":".join(text[i : i + 2] for i in range(0, 12, 2))
    return text if re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", text) else ""


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
    Runs PowerShell commands over an open SSHScanner connection and parses
    the output into structured dicts ready for JSON serialisation.
    Works regardless of whether the SSH default shell is PowerShell or cmd.
    """

    # Path to PowerShell executable — used when the default shell is cmd.exe
    _PS_EXE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

    def __init__(self, ssh: SSHScanner):
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
                    log.warning("Windows section '%s' collection failed: %s", name, exc)

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

    def _collect_open_ports(self) -> list[dict[str, str]]:
        raw = self._run("open_ports")
        ports = []
        for line in raw.splitlines():
            # Format: TCP    0.0.0.0:445    0.0.0.0:0    LISTENING    4
            parts = line.split()
            if len(parts) >= 4 and "LISTENING" in parts:
                local = parts[1]
                port = local.rsplit(":", 1)[-1] if ":" in local else ""
                pid = parts[-1]
                ports.append(
                    {
                        "state": "LISTEN",
                        "local_addr": local,
                        "port": port,
                        "process": f"PID {pid}",
                    }
                )
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

    def _run_json(self, key: str) -> Any:
        """
        Run a named command and parse its output as JSON.

        Uses JSONDecoder.raw_decode() which:
          - Skips any leading noise/banner text before the first '[' or '{'
          - Stops parsing at the end of the first complete JSON value
          - Ignores any trailing garbage (e.g. provider metadata, blank lines)
        """
        raw = self._run(key)
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

        log.warning("Failed to parse JSON for command '%s' | raw=%.300s", key, raw)
        return {}
