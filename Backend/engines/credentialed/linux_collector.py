"""
engines/credentialed/linux_collector.py
----------------------------------------
Collects full system information from a Linux host over SSH.

Each collector method is independent — if one command fails the others
still run.  Returns a flat dict that gets merged into the final report.

Usage (called by the endpoint, not directly)::

    from engines.credentialed.linux_collector import LinuxCollector
    from engines.credentialed.ssh_scanner import SSHScanner

    with SSHScanner(ip, username, password=pw) as ssh:
        collector = LinuxCollector(ssh)
        data = collector.collect_all()
"""

import logging
import re
from typing import Any, Dict, List, Optional

from engines.credentialed.ssh_scanner import SSHScanner, CommandResult

log = logging.getLogger("ccure.linux_collector")

# ---------------------------------------------------------------------------
# All commands executed on the remote host
# ---------------------------------------------------------------------------
# Performance optimization: reduced timeouts for slow commands
# - SUID/world-writable scans reduced from 25s to 10s timeout
# - Head limits reduced to prevent large output transfers
# ---------------------------------------------------------------------------
COMMANDS: Dict[str, str] = {
    "os_release":      "cat /etc/os-release 2>/dev/null",
    "kernel":          "uname -r 2>/dev/null",
    "uname_full":      "uname -a 2>/dev/null",
    "hostname":        "hostname -f 2>/dev/null || hostname 2>/dev/null",
    "uptime":          "uptime -p 2>/dev/null || uptime 2>/dev/null",
    "packages_deb":    "dpkg -l 2>/dev/null",
    "packages_rpm":    "rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\\n' 2>/dev/null",
    "running_svcs":    "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null",
    "open_ports":      "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
    "users":           "cat /etc/passwd 2>/dev/null",
    "sudo_rules":      "sudo -ln 2>/dev/null || sudo -l 2>/dev/null",
    "cron_jobs":       "crontab -l 2>/dev/null; ls /etc/cron* 2>/dev/null",
    # Optimized: reduced timeout from 25s to 10s, reduced head from 100 to 50
    "suid_files":      "timeout 10 find / -perm -4000 -type f 2>/dev/null | head -50",
    # Optimized: reduced timeout from 25s to 10s, reduced head from 50 to 25
    "world_writable":  "timeout 10 find / -perm -0002 -type d -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' 2>/dev/null | head -25",
    "cpu":             "lscpu 2>/dev/null",
    "memory":          "free -h 2>/dev/null",
    "disk":            "df -h 2>/dev/null",
    "network_iface":   "ip addr show 2>/dev/null || ifconfig 2>/dev/null",
    "arp_table":       "arp -n 2>/dev/null || ip neigh 2>/dev/null",
    "login_history":   "last -n 20 2>/dev/null",
    "failed_logins":   "lastb -n 20 2>/dev/null || journalctl _COMM=sshd -n 30 --no-pager 2>/dev/null",
    "env_vars":        "env 2>/dev/null",
}


class LinuxCollector:
    """
    Runs all COMMANDS via an open SSHScanner and parses the output into
    structured dicts ready for JSON serialisation and CVE matching.
    """

    def __init__(self, ssh: SSHScanner):
        self._ssh = ssh

    # ── Entry point ────────────────────────────────────────────────────────

    def collect_all(self, sections: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run all collectors concurrently and return a merged dict.

        Parameters
        ----------
        sections : Optional list of section names to collect.
                   If None, all sections are collected.
                   Valid names: system_info, packages, services, ports,
                                users, security, network, history.

        All section collectors are independent — they run concurrently via
        a ThreadPoolExecutor to reduce wall-clock time. If one fails the
        others are unaffected.
        """
        run_all = sections is None

        # Build list of (section_name, callable) pairs to run
        tasks: List[tuple] = []
        if run_all or "system_info" in sections:
            tasks.append(("system_info", self._collect_system_info))
        if run_all or "packages" in sections:
            tasks.append(("packages", self._collect_packages))
        if run_all or "services" in sections:
            tasks.append(("services", self._collect_services))
        if run_all or "ports" in sections:
            tasks.append(("ports", self._collect_open_ports))
        if run_all or "users" in sections:
            tasks.append(("users", self._collect_users))
        if run_all or "security" in sections:
            tasks.append(("security", self._collect_security_audit))
        if run_all or "network" in sections:
            tasks.append(("network", self._collect_network))
        if run_all or "history" in sections:
            tasks.append(("history", self._collect_login_history))

        result: Dict[str, Any] = {}

        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=len(tasks) or 1) as pool:
            future_map = {pool.submit(fn): name for name, fn in tasks}
            from concurrent.futures import as_completed
            for future in as_completed(future_map):
                name = future_map[future]
                try:
                    data = future.result()
                    # system_info and security return flat dicts; merge them
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
                except Exception as exc:
                    log.warning("Section '%s' collection failed: %s", name, exc)

        return result


    # ── System info ────────────────────────────────────────────────────────

    def _collect_system_info(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {}

        # OS details
        os_raw = self._run("os_release")
        os_info = _parse_key_value(os_raw, sep="=")
        data["os_name"]       = _unquote(os_info.get("PRETTY_NAME", ""))
        data["os_id"]         = _unquote(os_info.get("ID", ""))
        data["os_version_id"] = _unquote(os_info.get("VERSION_ID", ""))
        data["os_id_like"]    = _unquote(os_info.get("ID_LIKE", ""))

        # Kernel
        data["kernel_version"] = self._run("kernel")
        data["uname_full"]     = self._run("uname_full")

        # Hostname
        data["hostname_fqdn"] = self._run("hostname")

        # Uptime
        data["uptime"] = self._run("uptime")

        # CPU
        cpu_raw = self._run("cpu")
        cpu_info = _parse_key_value(cpu_raw, sep=":")
        data["cpu_model"]   = cpu_info.get("Model name", "").strip()
        data["cpu_count"]   = cpu_info.get("CPU(s)", "").strip()
        data["cpu_arch"]    = cpu_info.get("Architecture", "").strip()

        # Memory
        mem_raw = self._run("memory")
        data["memory_raw"] = mem_raw
        data["memory_summary"] = _parse_free_output(mem_raw)

        # Disk
        data["disk_usage"] = _parse_df_output(self._run("disk"))

        return data

    # ── Packages ───────────────────────────────────────────────────────────

    def _collect_packages(self) -> List[Dict[str, str]]:
        packages: List[Dict[str, str]] = []

        # Try Debian/Ubuntu first
        deb_raw = self._run("packages_deb")
        if deb_raw:
            packages = _parse_dpkg_output(deb_raw)

        # Fall back to RPM
        if not packages:
            rpm_raw = self._run("packages_rpm")
            if rpm_raw:
                packages = _parse_rpm_output(rpm_raw)

        return packages

    # ── Services ───────────────────────────────────────────────────────────

    def _collect_services(self) -> List[Dict[str, str]]:
        raw = self._run("running_svcs")
        if not raw:
            return []
        services = []
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1] == "loaded" and "running" in line:
                services.append({
                    "name":        parts[0],
                    "load_state":  parts[1],
                    "active_state": parts[2],
                    "sub_state":   parts[3],
                    "description": " ".join(parts[4:]) if len(parts) > 4 else "",
                })
            elif parts:
                # Fallback: just capture the service unit name
                services.append({"name": parts[0], "description": " ".join(parts[1:])})
        return services

    # ── Open ports (socket table) ──────────────────────────────────────────

    def _collect_open_ports(self) -> List[Dict[str, str]]:
        raw = self._run("open_ports")
        return _parse_ss_output(raw)

    # ── Users ──────────────────────────────────────────────────────────────

    def _collect_users(self) -> List[Dict[str, str]]:
        raw = self._run("users")
        users = []
        for line in raw.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            uid = int(parts[2]) if parts[2].isdigit() else -1
            users.append({
                "username":    parts[0],
                "uid":         parts[2],
                "gid":         parts[3],
                "description": parts[4],
                "home":        parts[5],
                "shell":       parts[6],
                "is_system":   uid < 1000 and uid != 0,
                "is_root":     uid == 0,
            })
        return users

    # ── Security audit ─────────────────────────────────────────────────────

    def _collect_security_audit(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {}

        # SUID binaries
        suid_raw = self._run("suid_files")
        data["suid_binaries"] = [
            line.strip() for line in suid_raw.splitlines() if line.strip()
        ]

        # World-writable directories
        ww_raw = self._run("world_writable")
        data["world_writable_dirs"] = [
            line.strip() for line in ww_raw.splitlines() if line.strip()
        ]

        # Sudo rules
        sudo_raw = self._run("sudo_rules")
        data["sudo_rules_raw"] = sudo_raw
        data["sudo_nopasswd"] = "NOPASSWD" in sudo_raw

        # Cron jobs
        cron_raw = self._run("cron_jobs")
        data["cron_info_raw"] = cron_raw

        # Security issue summary
        issues = []
        if data["sudo_nopasswd"]:
            issues.append("NOPASSWD sudo rule detected — any command runs without password")
        if len(data["suid_binaries"]) > 15:
            issues.append(f"{len(data['suid_binaries'])} SUID binaries found — review for privilege escalation risk")
        if data["world_writable_dirs"]:
            issues.append(f"{len(data['world_writable_dirs'])} world-writable directories found")

        data["security_issues"] = issues
        return data

    # ── Network ────────────────────────────────────────────────────────────

    def _collect_network(self) -> Dict[str, Any]:
        return {
            "network_interfaces_raw": self._run("network_iface"),
            "arp_table_raw":          self._run("arp_table"),
            "env_vars_summary":       _extract_sensitive_env(self._run("env_vars")),
        }

    # ── Login history ──────────────────────────────────────────────────────

    def _collect_login_history(self) -> Dict[str, Any]:
        login_raw       = self._run("login_history")
        failed_raw      = self._run("failed_logins")
        failed_lines    = [l for l in failed_raw.splitlines() if l.strip() and not l.startswith("btmp")]

        return {
            "login_history_raw":    login_raw,
            "failed_logins_recent": failed_lines[:20],
            "failed_login_count":   len(failed_lines),
            "brute_force_warning":  len(failed_lines) > 50,
        }

    # ── Internal helpers ───────────────────────────────────────────────────

    def _run(self, command_key: str) -> str:
        """Run a named command and return stdout; return '' on failure."""
        cmd = COMMANDS.get(command_key)
        if not cmd:
            return ""
        result = self._ssh.run(cmd, timeout=30)
        if not result.success and result.stderr:
            log.debug("Command '%s' stderr on %s: %s", command_key, self._ssh.ip, result.stderr[:200])
        return result.stdout or ""


# ---------------------------------------------------------------------------
# Parsing utilities
# ---------------------------------------------------------------------------

def _parse_key_value(text: str, sep: str = "=") -> Dict[str, str]:
    """Parse a file of KEY=value lines into a dict."""
    out = {}
    for line in text.splitlines():
        if sep in line:
            k, _, v = line.partition(sep)
            out[k.strip()] = v.strip()
    return out


def _unquote(s: str) -> str:
    """Strip surrounding quotes from a value."""
    return s.strip("\"'")


def _parse_dpkg_output(raw: str) -> List[Dict[str, str]]:
    """Parse `dpkg -l` output into a list of {name, version, arch, description}."""
    packages = []
    for line in raw.splitlines():
        if not line.startswith("ii"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            packages.append({
                "name":        parts[1].split(":")[0],   # strip arch suffix
                "version":     parts[2],
                "arch":        parts[3] if len(parts) > 3 else "",
                "description": " ".join(parts[4:]) if len(parts) > 4 else "",
                "manager":     "dpkg",
            })
    return packages


def _parse_rpm_output(raw: str) -> List[Dict[str, str]]:
    """Parse `rpm -qa` output (name version-release per line)."""
    packages = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            packages.append({
                "name":    parts[0],
                "version": parts[1],
                "arch":    "",
                "manager": "rpm",
            })
        elif parts:
            packages.append({"name": parts[0], "version": "", "arch": "", "manager": "rpm"})
    return packages


def _parse_ss_output(raw: str) -> List[Dict[str, str]]:
    """Parse `ss -tlnp` output into port records."""
    ports = []
    for line in raw.splitlines():
        # Skip header and non-LISTEN lines
        if "LISTEN" not in line and "State" not in line:
            continue
        if "State" in line:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        local_addr = parts[3] if len(parts) > 3 else ""
        # Extract port from "0.0.0.0:22" or ":::22" or "*:22"
        port_str = local_addr.rsplit(":", 1)[-1] if ":" in local_addr else ""
        process  = parts[-1] if len(parts) > 4 else ""
        ports.append({
            "state":       parts[0],
            "local_addr":  local_addr,
            "port":        port_str,
            "process":     process,
        })
    return ports


def _parse_free_output(raw: str) -> Dict[str, str]:
    """Parse `free -h` into {total, used, free, available}."""
    for line in raw.splitlines():
        if line.lower().startswith("mem"):
            parts = line.split()
            if len(parts) >= 4:
                return {
                    "total":     parts[1],
                    "used":      parts[2],
                    "free":      parts[3],
                    "available": parts[6] if len(parts) > 6 else "",
                }
    return {}


def _parse_df_output(raw: str) -> List[Dict[str, str]]:
    """Parse `df -h` into list of filesystem records."""
    entries = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0] == "Filesystem":
            continue
        entries.append({
            "filesystem": parts[0],
            "size":       parts[1],
            "used":       parts[2],
            "available":  parts[3],
            "use_pct":    parts[4],
            "mounted_on": parts[5],
        })
    return entries


def _extract_sensitive_env(raw: str) -> List[str]:
    """Return env vars that might reveal credentials or sensitive config."""
    sensitive_patterns = re.compile(
        r"(password|passwd|secret|token|api_key|aws|database_url|db_url|private)",
        re.IGNORECASE,
    )
    flagged = []
    for line in raw.splitlines():
        if sensitive_patterns.search(line):
            # Mask the value portion
            key = line.split("=", 1)[0]
            flagged.append(f"{key}=***REDACTED***")
    return flagged
