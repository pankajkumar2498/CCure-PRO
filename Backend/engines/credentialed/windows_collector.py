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

import json
import logging
import re
from typing import Any, Dict, List, Optional

from engines.credentialed.ssh_scanner import SSHScanner

log = logging.getLogger("ccure.windows_collector")

# PowerShell commands — output as plain text or JSON
COMMANDS: Dict[str, str] = {
    # OS info
    "os_info":       "(Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture | ConvertTo-Json)",
    "hostname":      "hostname",
    "uptime":        "((Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime).ToString('dd\\.hh\\:mm\\:ss')",

    # Hardware
    "cpu":           "(Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors | ConvertTo-Json)",
    "memory":        "(Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory | ConvertTo-Json)",
    "disk":          "(Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free | ConvertTo-Json)",

    # Installed software (registry-based — most complete source)
    "software_x64":  "(Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' | Where-Object {$_.DisplayName} | Select-Object DisplayName, DisplayVersion, Publisher | ConvertTo-Json)",
    "software_x86":  "(Get-ItemProperty 'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' | Where-Object {$_.DisplayName} | Select-Object DisplayName, DisplayVersion, Publisher | ConvertTo-Json)",

    # Windows Updates / Hotfixes
    "hotfixes":      "(Get-HotFix | Select-Object HotFixID, Description, InstalledOn | ConvertTo-Json)",

    # Services
    "services":      "(Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, StartType | ConvertTo-Json)",

    # Network
    "open_ports":    "netstat -ano | findstr LISTENING",
    "network_iface": "(Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, PrefixLength, AddressFamily | ConvertTo-Json)",

    # Users
    "local_users":   "(Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet | ConvertTo-Json)",
    "local_admins":  "(Get-LocalGroupMember -Group Administrators | Select-Object Name, ObjectClass | ConvertTo-Json)",

    # Security
    "firewall":      "(Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | ConvertTo-Json)",
    "shares":        "(Get-SmbShare | Select-Object Name, Path, Description | ConvertTo-Json)",
    "audit_policy":  "auditpol /get /category:* 2>&1",
    "rdp_status":    "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue | ConvertTo-Json)",

    # Scheduled tasks (suspicious ones — not system-signed)
    "scheduled_tasks": "(Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled' -and $_.Author -notmatch 'Microsoft'} | Select-Object TaskName, TaskPath, State | ConvertTo-Json)",

    # Event log — failed logins
    "failed_logins": "(Get-WinEvent -LogName Security -FilterHashtable @{Id=4625} -MaxEvents 20 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | ConvertTo-Json)",
}


class WindowsCollector:
    """
    Runs PowerShell commands over an open SSHScanner connection and parses
    the output into structured dicts ready for JSON serialisation.
    """

    def __init__(self, ssh: SSHScanner):
        self._ssh = ssh
        self.shell_type = self._detect_shell()
        if self.shell_type == "cmd":
            log.warning(
                "Windows target default SSH shell is 'cmd'. "
                "PowerShell is required for JSON commands to work. "
                "Please run: New-ItemProperty -Path 'HKLM:\\SOFTWARE\\OpenSSH' -Name DefaultShell -Value 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -PropertyType String -Force"
            )

    def _detect_shell(self) -> str:
        """Returns 'powershell' or 'cmd'."""
        result = self._ssh.run("$PSVersionTable.PSVersion.Major", timeout=5)
        return "powershell" if result.success and result.stdout.strip().isdigit() else "cmd"

    def collect_all(self, sections: Optional[List[str]] = None) -> Dict[str, Any]:
        run_all = sections is None
        result: Dict[str, Any] = {}

        if run_all or "system_info" in sections:
            result.update(self._collect_system_info())
        if run_all or "packages" in sections:
            result["packages"] = self._collect_software()
        if run_all or "services" in sections:
            result["running_services"] = self._collect_services()
        if run_all or "ports" in sections:
            result["open_ports_credentialed"] = self._collect_open_ports()
        if run_all or "users" in sections:
            result["users"] = self._collect_users()
        if run_all or "security" in sections:
            result.update(self._collect_security())
        if run_all or "network" in sections:
            result.update(self._collect_network())
        if run_all or "history" in sections:
            result.update(self._collect_login_history())

        return result

    def _collect_system_info(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {}

        os_raw = self._run_json("os_info")
        data["os_name"]       = os_raw.get("Caption", "Windows")
        data["os_version_id"] = os_raw.get("Version", "")
        data["os_build"]      = os_raw.get("BuildNumber", "")
        data["cpu_arch"]      = os_raw.get("OSArchitecture", "")

        data["hostname_fqdn"] = self._run("hostname")
        data["uptime"]        = self._run("uptime")

        cpu_raw = self._run_json("cpu")
        if isinstance(cpu_raw, list):
            cpu_raw = cpu_raw[0] if cpu_raw else {}
        data["cpu_model"] = cpu_raw.get("Name", "")
        data["cpu_count"] = str(cpu_raw.get("NumberOfLogicalProcessors", ""))

        mem_raw = self._run_json("memory")
        if mem_raw:
            total_kb = mem_raw.get("TotalVisibleMemorySize", 0)
            free_kb  = mem_raw.get("FreePhysicalMemory", 0)
            data["memory_summary"] = {
                "total":     f"{total_kb // 1024} MB",
                "free":      f"{free_kb  // 1024} MB",
                "used":      f"{(total_kb - free_kb) // 1024} MB",
                "available": f"{free_kb  // 1024} MB",
            }

        disk_raw = self._run_json("disk")
        if isinstance(disk_raw, list):
            data["disk_usage"] = [
                {
                    "filesystem": d.get("Name", ""),
                    "used":       f"{(d.get('Used') or 0) // (1024**3)} GB",
                    "available":  f"{(d.get('Free') or 0) // (1024**3)} GB",
                }
                for d in disk_raw if d.get("Name")
            ]

        return data

    def _collect_software(self) -> List[Dict[str, str]]:
        """Combine 64-bit and 32-bit registry keys for installed software."""
        packages = []
        seen = set()
        for key in ("software_x64", "software_x86"):
            items = self._run_json(key)
            if not isinstance(items, list):
                items = [items] if isinstance(items, dict) else []
            for item in items:
                name = (item.get("DisplayName") or "").strip()
                ver  = (item.get("DisplayVersion") or "").strip()
                if name and name not in seen:
                    packages.append({
                        "name":    name,
                        "version": ver,
                        "arch":    "",
                        "manager": "windows_registry",
                    })
                    seen.add(name)

        # Also collect Windows hotfixes as pseudo-packages
        hotfixes = self._run_json("hotfixes")
        if isinstance(hotfixes, list):
            for hf in hotfixes:
                kb = hf.get("HotFixID", "")
                if kb and kb not in seen:
                    packages.append({
                        "name":    kb,
                        "version": str(hf.get("InstalledOn", "")),
                        "arch":    "",
                        "manager": "windows_update",
                    })
                    seen.add(kb)

        return packages

    def _collect_services(self) -> List[Dict[str, str]]:
        items = self._run_json("services")
        if not isinstance(items, list):
            items = [items] if isinstance(items, dict) else []
        return [
            {
                "name":        i.get("Name", ""),
                "description": i.get("DisplayName", ""),
                "start_type":  str(i.get("StartType", "")),
            }
            for i in items if i.get("Name")
        ]

    def _collect_open_ports(self) -> List[Dict[str, str]]:
        raw = self._run("open_ports")
        ports = []
        for line in raw.splitlines():
            # Format: TCP    0.0.0.0:445    0.0.0.0:0    LISTENING    4
            parts = line.split()
            if len(parts) >= 4 and "LISTENING" in parts:
                local = parts[1]
                port  = local.rsplit(":", 1)[-1] if ":" in local else ""
                pid   = parts[-1]
                ports.append({
                    "state":      "LISTEN",
                    "local_addr": local,
                    "port":       port,
                    "process":    f"PID {pid}",
                })
        return ports

    def _collect_users(self) -> List[Dict[str, str]]:
        users_raw  = self._run_json("local_users")
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
                "username":  u.get("Name", ""),
                "enabled":   str(u.get("Enabled", "")),
                "is_admin":  u.get("Name", "") in admin_names,
                "last_logon": str(u.get("LastLogon", "")),
                "pwd_required": str(u.get("PasswordRequired", "")),
            }
            for u in users_raw if u.get("Name")
        ]

    def _collect_security(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
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
            extra_shares = [s["Name"] for s in shares_raw if s.get("Name") not in admin_shares]
            if extra_shares:
                issues.append(f"Non-default SMB shares found: {', '.join(extra_shares)}")

        rdp_raw = self._run_json("rdp_status")
        rdp_enabled = rdp_raw.get("fDenyTSConnections", 1) == 0 if rdp_raw else False
        data["rdp_enabled"] = rdp_enabled
        if rdp_enabled:
            issues.append("RDP is enabled — ensure NLA is enforced and access is restricted")

        tasks_raw = self._run_json("scheduled_tasks")
        if isinstance(tasks_raw, list):
            data["suspicious_scheduled_tasks"] = tasks_raw

        data["security_issues"] = issues
        return data

    def _collect_network(self) -> Dict[str, Any]:
        iface_raw = self._run_json("network_iface")
        return {
            "network_interfaces_raw": json.dumps(iface_raw) if iface_raw else "",
            "arp_table_raw":          "",
            "env_vars_summary":       [],
        }

    def _collect_login_history(self) -> Dict[str, Any]:
        failed_raw = self._run_json("failed_logins")
        failed_list = failed_raw if isinstance(failed_raw, list) else []
        return {
            "login_history_raw":     "",
            "failed_logins_recent":  [str(f.get("TimeCreated", "")) for f in failed_list[:20]],
            "failed_login_count":    len(failed_list),
            "brute_force_warning":   len(failed_list) >= 10,
        }

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _run(self, key: str) -> str:
        cmd = COMMANDS.get(key, "")
        if not cmd:
            return ""
        result = self._ssh.run(cmd, timeout=30)
        return result.stdout or ""

    def _run_json(self, key: str) -> Any:
        raw = self._run(key)
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            log.debug("Failed to parse JSON for command '%s': %s", key, raw[:100])
            return {}
