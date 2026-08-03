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

import ipaddress
import json
import logging
import re
from typing import Any, Callable, Dict, List, Optional

from engines.credentialed.ssh_scanner import SSHScanner

log = logging.getLogger("ccure.linux_collector")

# ---------------------------------------------------------------------------
# All commands executed on the remote host
# ---------------------------------------------------------------------------
# Performance optimization: reduced timeouts for slow commands
# - SUID/world-writable scans reduced from 25s to 10s timeout
# - Head limits reduced to prevent large output transfers
# ---------------------------------------------------------------------------
COMMANDS: dict[str, str] = {
    "os_release": "cat /etc/os-release 2>/dev/null",
    "kernel": "uname -r 2>/dev/null",
    "uname_full": "uname -a 2>/dev/null",
    "hostname_short": "hostname -s 2>/dev/null || hostname 2>/dev/null",
    "hostname_fqdn": "hostname -f 2>/dev/null || hostname 2>/dev/null",
    "domain": "dnsdomainname 2>/dev/null || domainname 2>/dev/null",
    "dmi_vendor": "cat /sys/class/dmi/id/sys_vendor 2>/dev/null",
    "dmi_product": "cat /sys/class/dmi/id/product_name 2>/dev/null",
    "dmi_serial": 'ser=$(sudo -n dmidecode -s system-serial-number 2>/dev/null || cat /sys/class/dmi/id/product_serial 2>/dev/null); case "$ser" in ""|[Nn]one|[Tt]o\\ [Bb]e\\ [Ff]illed*|[Dd]efault*|[Nn]ot\\ [Ss]pecified) cat /etc/machine-id 2>/dev/null;; *) echo "$ser";; esac',
    "uptime": "uptime -p 2>/dev/null || uptime 2>/dev/null",
    "packages_deb": "dpkg -l 2>/dev/null",
    "packages_rpm": "rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\\n' 2>/dev/null",
    "running_svcs": "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null",
    "open_ports": "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
    "users": "cat /etc/passwd 2>/dev/null",
    "sudo_rules": "sudo -ln 2>/dev/null || sudo -l 2>/dev/null",
    "cron_jobs": "crontab -l 2>/dev/null; ls /etc/cron* 2>/dev/null",
    # Optimized: reduced timeout from 25s to 10s, reduced head from 100 to 50
    "suid_files": "timeout 10 find / -perm -4000 -type f 2>/dev/null | head -50",
    # Optimized: reduced timeout from 25s to 10s, reduced head from 50 to 25
    "world_writable": "timeout 10 find / -perm -0002 -type d -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' 2>/dev/null | head -25",
    "cpu": "lscpu 2>/dev/null",
    "memory": "free -h 2>/dev/null",
    "disk": "df -h 2>/dev/null",
    "network_iface": "ip -j addr show 2>/dev/null || ip addr show 2>/dev/null || ifconfig 2>/dev/null",
    "network_route": "ip -j route show default 2>/dev/null || ip route show default 2>/dev/null",
    "arp_table": "arp -n 2>/dev/null || ip neigh 2>/dev/null",
    "login_history": "last -n 20 2>/dev/null",
    "failed_logins": "lastb -n 20 2>/dev/null || journalctl _COMM=sshd -n 30 --no-pager 2>/dev/null",
    "env_vars": "env 2>/dev/null",
    "bios_version": "cat /sys/class/dmi/id/bios_version 2>/dev/null",
    "local_groups": "cat /etc/group 2>/dev/null",
    # Safe Protocol Hardening Queries
    "samba_config": "cat /etc/samba/smb.conf 2>/dev/null",
    "nmbd_status": "systemctl is-active nmbd 2>/dev/null || systemctl is-active nmb 2>/dev/null",
    "openssl_config": "cat /etc/ssl/openssl.cnf /etc/pki/tls/openssl.cnf 2>/dev/null",
    "telnet_status": "systemctl is-active telnet.socket 2>/dev/null || systemctl is-active telnetd 2>/dev/null || which telnetd 2>/dev/null",
}


class LinuxCollector:
    """
    Runs all COMMANDS via an open SSHScanner and parses the output into
    structured dicts ready for JSON serialisation and CVE matching.
    """

    def __init__(self, ssh: SSHScanner):
        self._ssh = ssh

    # ── Entry point ────────────────────────────────────────────────────────

    def collect_all(
        self,
        sections: list[str] | None = None,
        on_section_complete: Callable | None = None,
    ) -> dict[str, Any]:
        """
        Run all collectors concurrently and return a merged dict.

        Parameters
        ----------
        sections : Optional list of section names to collect.
        on_section_complete : Optional callback(section_name) called as each finish.
        """
        run_all = sections is None

        tasks: list[tuple] = []
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
            tasks.append(("local_groups", self._collect_local_groups))
        if run_all or "security" in sections:
            tasks.append(("security", self._collect_security_audit))
        if run_all or "network" in sections:
            tasks.append(("network", self._collect_network))
        if run_all or "history" in sections:
            tasks.append(("history", self._collect_login_history))

        result: dict[str, Any] = {}

        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=len(tasks) or 1) as pool:
            future_map = {pool.submit(fn): name for name, fn in tasks}
            from concurrent.futures import as_completed

            for future in as_completed(future_map):
                name = future_map[future]
                try:
                    data = future.result()
                    if on_section_complete:
                        on_section_complete(name)

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
                    # Recorded, not just logged. A section that failed silently
                    # is indistinguishable from a section that found nothing —
                    # and for the package inventory those two readings are
                    # "could not assess this host" versus "this host is clean".
                    log.warning("Section '%s' collection failed: %s", name, exc)
                    result.setdefault("collection_errors", {})[name] = str(exc)

        result["sections_requested"] = [name for name, _fn in tasks]
        return result

    # ── System info ────────────────────────────────────────────────────────

    def _collect_system_info(self) -> dict[str, Any]:
        data: dict[str, Any] = {}

        # OS details
        os_raw = self._run("os_release")
        os_info = _parse_key_value(os_raw, sep="=")
        data["os_name"] = _unquote(os_info.get("PRETTY_NAME", ""))
        data["os_id"] = _unquote(os_info.get("ID", ""))
        data["os_version_id"] = _unquote(os_info.get("VERSION_ID", ""))
        data["os_id_like"] = _unquote(os_info.get("ID_LIKE", ""))

        # Kernel
        data["kernel_version"] = self._run("kernel")
        data["uname_full"] = self._run("uname_full")

        # Hostname
        hostname_fqdn = self._run("hostname_fqdn").strip()
        hostname_short = self._run("hostname_short").strip()
        data["hostname_fqdn"] = hostname_fqdn
        data["hostname_short"] = hostname_short

        domain = self._run("domain").strip()
        if domain.lower() in ("(none)", "none", ""):
            # Fallback: parse resolv.conf for search/domain options
            res = self._ssh.run(
                "grep -E '^(search|domain)' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | head -n 1"
            )
            resolv_domain = res.stdout.strip() if res.success and res.stdout else ""
            if resolv_domain:
                domain = resolv_domain
            else:
                domain = ""

        data["domain"] = domain

        if "." in hostname_fqdn:
            data["fqdn"] = hostname_fqdn
        elif hostname_short and domain:
            data["fqdn"] = f"{hostname_short}.{domain}"
        else:
            data["fqdn"] = hostname_fqdn

        data["manufacturer"] = self._run("dmi_vendor")
        data["hardware_model"] = self._run("dmi_product")
        data["os_family"] = "Linux"
        data["os_confidence"] = 100

        # Uptime
        data["uptime"] = self._run("uptime")

        # BIOS/Serial Number
        data["serial_number"] = self._run("dmi_serial")
        data["bios_version"] = self._run("bios_version")

        # CPU
        cpu_raw = self._run("cpu")
        cpu_info = _parse_key_value(cpu_raw, sep=":")
        data["cpu_model"] = cpu_info.get("Model name", "").strip()
        data["cpu_count"] = cpu_info.get("CPU(s)", "").strip()
        data["cpu_arch"] = cpu_info.get("Architecture", "").strip()

        # Memory
        mem_raw = self._run("memory")
        data["memory_raw"] = mem_raw
        data["memory_summary"] = _parse_free_output(mem_raw)

        # Disk
        data["disk_usage"] = _parse_df_output(self._run("disk"))

        return data

    # ── Packages ───────────────────────────────────────────────────────────

    def _collect_packages(self) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []

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

    def _collect_services(self) -> list[dict[str, str]]:
        raw = self._run("running_svcs")
        if not raw:
            return []
        services = []
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1] == "loaded" and "running" in line:
                services.append(
                    {
                        "name": parts[0],
                        "load_state": parts[1],
                        "active_state": parts[2],
                        "sub_state": parts[3],
                        "description": " ".join(parts[4:]) if len(parts) > 4 else "",
                    }
                )
            elif parts:
                # Fallback: just capture the service unit name
                services.append({"name": parts[0], "description": " ".join(parts[1:])})
        return services

    # ── Open ports (socket table) ──────────────────────────────────────────

    def _collect_open_ports(self) -> list[dict[str, str]]:
        raw = self._run("open_ports")
        return _parse_ss_output(raw)

    # ── Users ──────────────────────────────────────────────────────────────

    def _collect_users(self) -> list[dict[str, str]]:
        raw = self._run("users")
        users = []
        for line in raw.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            uid = int(parts[2]) if parts[2].isdigit() else -1
            users.append(
                {
                    "username": parts[0],
                    "uid": parts[2],
                    "gid": parts[3],
                    "description": parts[4],
                    "home": parts[5],
                    "shell": parts[6],
                    "is_system": uid < 1000 and uid != 0,
                    "is_root": uid == 0,
                }
            )
        return users

    # ── Local groups ───────────────────────────────────────────────────────

    def _collect_local_groups(self) -> list[dict[str, Any]]:
        raw = self._run("local_groups")
        groups = []
        for line in raw.splitlines():
            parts = line.strip().split(":")
            if len(parts) < 3:
                continue
            name = parts[0]
            gid = parts[2]
            members_str = parts[3] if len(parts) > 3 else ""
            members = [m.strip() for m in members_str.split(",") if m.strip()]
            groups.append({"name": name, "gid": gid, "members": members})
        return groups

    # ── Security audit ─────────────────────────────────────────────────────

    def _collect_security_audit(self) -> dict[str, Any]:
        data: dict[str, Any] = {}

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
            issues.append(
                "NOPASSWD sudo rule detected — any command runs without password"
            )
        if len(data["suid_binaries"]) > 15:
            issues.append(
                f"{len(data['suid_binaries'])} SUID binaries found — review for privilege escalation risk"
            )
        if data["world_writable_dirs"]:
            issues.append(
                f"{len(data['world_writable_dirs'])} world-writable directories found"
            )

        # Safe Protocol Hardening Checks
        # 1. SMBv1 status
        samba_raw = self._run("samba_config").strip()
        smbv1_disabled = True
        if samba_raw:
            # Parse server min protocol (handle comments, spacing, and case-insensitivity)
            smb_min_proto_match = re.search(
                r"^\s*server\s+min\s+protocol\s*=\s*(\w+)",
                samba_raw,
                re.IGNORECASE | re.MULTILINE,
            )
            if smb_min_proto_match:
                min_proto = smb_min_proto_match.group(1).upper()
                if min_proto in ("CORE", "LANMAN1", "LANMAN2", "NT1"):
                    smbv1_disabled = False
        else:
            # Samba config does not exist/uninstalled -> Secure default
            smbv1_disabled = True

        data["smbv1_disabled"] = smbv1_disabled
        if not smbv1_disabled:
            issues.append("Legacy SMBv1 protocol is allowed in Samba configuration")

        # 2. NetBIOS status (nmbd service)
        nmbd_raw = self._run("nmbd_status").strip().lower()
        netbios_disabled = True
        if "active" in nmbd_raw:
            netbios_disabled = False
        data["netbios_disabled"] = netbios_disabled
        if not netbios_disabled:
            issues.append("NetBIOS daemon (nmbd) is active and running")

        # 3. Legacy TLS status
        openssl_raw = self._run("openssl_config").strip()
        legacy_tls_disabled = True
        if openssl_raw:
            min_proto_match = re.search(
                r"MinProtocol\s*=\s*(\S+)", openssl_raw, re.IGNORECASE
            )
            if min_proto_match:
                min_proto = min_proto_match.group(1).lower()
                if "tls1.2" in min_proto or "tls1.3" in min_proto:
                    legacy_tls_disabled = True
                else:
                    legacy_tls_disabled = False
        data["legacy_tls_disabled"] = legacy_tls_disabled

        # 4. Telnet status
        telnet_raw = self._run("telnet_status").strip().lower()
        telnet_disabled = True
        if "active" in telnet_raw or "telnetd" in telnet_raw:
            telnet_disabled = False
        data["telnet_disabled"] = telnet_disabled
        if not telnet_disabled:
            issues.append("Telnet service/daemon is running or installed")

        # 5. RDP NLA is a Windows-only configuration, default to True on Linux
        data["rdp_nla_enforced"] = True

        data["security_issues"] = issues
        return data

    # ── Network ────────────────────────────────────────────────────────────

    def _collect_network(self) -> dict[str, Any]:
        iface_raw = self._run("network_iface")
        subnet = _subnet_from_linux_interfaces(iface_raw, self._ssh.ip)
        primary_mac = _mac_from_linux_interfaces(iface_raw, self._ssh.ip)
        return {
            "network_interfaces_raw": iface_raw,
            "subnet": subnet,
            "mac_address": primary_mac,
            "arp_table_raw": self._run("arp_table"),
            "env_vars_summary": _extract_sensitive_env(self._run("env_vars")),
        }

    # ── Login history ──────────────────────────────────────────────────────

    def _collect_login_history(self) -> dict[str, Any]:
        login_raw = self._run("login_history")
        failed_raw = self._run("failed_logins")
        failed_lines = [
            l for l in failed_raw.splitlines() if l.strip() and not l.startswith("btmp")
        ]

        return {
            "login_history_raw": login_raw,
            "failed_logins_recent": failed_lines[:20],
            "failed_login_count": len(failed_lines),
            "brute_force_warning": len(failed_lines) > 50,
        }

    # ── Internal helpers ───────────────────────────────────────────────────

    def _run(self, command_key: str) -> str:
        """Run a named command and return stdout; return '' on failure."""
        cmd = COMMANDS.get(command_key)
        if not cmd:
            return ""

        # If the command uses sudo and we have password credentials, try injecting the sudo password
        if "sudo" in cmd and getattr(self._ssh, "_password", None):
            import re

            passwd = self._ssh._password
            escaped_passwd = passwd.replace("'", "'\\''")
            injected_cmd = re.sub(
                r"\bsudo\s+(?:-n\s+)?", f"echo '{escaped_passwd}' | sudo -S ", cmd
            )
            log.info(
                "Executing sudo command '%s' with password injection on %s",
                command_key,
                self._ssh.ip,
            )
            result = self._ssh.run(injected_cmd, timeout=30)
            log.info(
                "Injected command '%s' exit_code=%d, success=%s, stdout_len=%d, stderr='%s'",
                command_key,
                result.exit_code,
                result.success,
                len(result.stdout),
                result.stderr,
            )
            if result.success and result.stdout.strip():
                return result.stdout

        result = self._ssh.run(cmd, timeout=30)
        if not result.success and result.stderr:
            log.debug(
                "Command '%s' stderr on %s: %s",
                command_key,
                self._ssh.ip,
                result.stderr[:200],
            )
        return result.stdout or ""


# ---------------------------------------------------------------------------
# Parsing utilities
# ---------------------------------------------------------------------------


def _parse_key_value(text: str, sep: str = "=") -> dict[str, str]:
    """Parse a file of KEY=value lines into a dict."""
    out = {}
    for line in text.splitlines():
        if sep in line:
            k, _, v = line.partition(sep)
            out[k.strip()] = v.strip()
    return out


def _subnet_from_linux_interfaces(raw: str, target_ip: str) -> str:
    if not raw or not target_ip:
        return ""
    try:
        target = ipaddress.ip_address(target_ip)
    except ValueError:
        return ""

    try:
        interfaces = json.loads(raw)
        if isinstance(interfaces, list):
            for iface in interfaces:
                for addr in iface.get("addr_info") or []:
                    if addr.get("family") != "inet":
                        continue
                    local = addr.get("local")
                    prefixlen = addr.get("prefixlen")
                    if not local or prefixlen is None:
                        continue
                    try:
                        network = ipaddress.ip_network(
                            f"{local}/{prefixlen}", strict=False
                        )
                    except ValueError:
                        continue
                    if target in network:
                        return str(network)
    except (TypeError, json.JSONDecodeError):
        pass

    for match in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", raw):
        local, prefixlen = match.groups()
        try:
            network = ipaddress.ip_network(f"{local}/{prefixlen}", strict=False)
        except ValueError:
            continue
        if target in network:
            return str(network)
    return ""


def _normalize_mac(value: str) -> str:
    text = str(value or "").strip().lower().replace("-", ":")
    if not text or text in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
        return ""
    if re.fullmatch(r"[0-9a-f]{12}", text):
        text = ":".join(text[i : i + 2] for i in range(0, 12, 2))
    return text if re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", text) else ""


def _mac_from_linux_interfaces(raw: str, target_ip: str) -> str:
    if not raw:
        return ""
    try:
        target = ipaddress.ip_address(target_ip) if target_ip else None
    except ValueError:
        target = None

    try:
        interfaces = json.loads(raw)
        if isinstance(interfaces, list):
            fallback = ""
            for iface in interfaces:
                mac = _normalize_mac(iface.get("address"))
                if not mac:
                    continue
                if iface.get("ifname") != "lo" and not fallback:
                    fallback = mac
                for addr in iface.get("addr_info") or []:
                    if (
                        addr.get("family") == "inet"
                        and target
                        and addr.get("local") == str(target)
                    ):
                        return mac
            if fallback:
                return fallback
    except (TypeError, json.JSONDecodeError):
        pass

    blocks = re.split(r"\n(?=\d+:\s+)", raw)
    fallback = ""
    for block in blocks:
        mac_match = re.search(
            r"(?:link/(?:ether|loopback)|ether|HWaddr)\s+([0-9a-fA-F:.-]{12,17})",
            block,
        )
        if not mac_match:
            continue
        mac = _normalize_mac(mac_match.group(1))
        if not mac:
            continue
        if " lo:" not in block and not fallback:
            fallback = mac
        if target and re.search(rf"inet\s+{re.escape(str(target))}/", block):
            return mac
    return fallback


def _unquote(s: str) -> str:
    """Strip surrounding quotes from a value."""
    return s.strip("\"'")


def _parse_dpkg_output(raw: str) -> list[dict[str, str]]:
    """Parse `dpkg -l` output into a list of {name, version, arch, description}."""
    packages = []
    for line in raw.splitlines():
        if not line.startswith("ii"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            packages.append(
                {
                    "name": parts[1].split(":")[0],  # strip arch suffix
                    "version": parts[2],
                    "arch": parts[3] if len(parts) > 3 else "",
                    "description": " ".join(parts[4:]) if len(parts) > 4 else "",
                    "manager": "dpkg",
                }
            )
    return packages


def _parse_rpm_output(raw: str) -> list[dict[str, str]]:
    """Parse `rpm -qa` output (name version-release per line)."""
    packages = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            packages.append(
                {
                    "name": parts[0],
                    "version": parts[1],
                    "arch": "",
                    "manager": "rpm",
                }
            )
        elif parts:
            packages.append(
                {"name": parts[0], "version": "", "arch": "", "manager": "rpm"}
            )
    return packages


def _parse_ss_output(raw: str) -> list[dict[str, str]]:
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
        process = parts[-1] if len(parts) > 4 else ""
        ports.append(
            {
                "state": parts[0],
                "local_addr": local_addr,
                "port": port_str,
                "process": process,
            }
        )
    return ports


def _parse_free_output(raw: str) -> dict[str, str]:
    """Parse `free -h` into {total, used, free, available}."""
    for line in raw.splitlines():
        if line.lower().startswith("mem"):
            parts = line.split()
            if len(parts) >= 4:
                return {
                    "total": parts[1],
                    "used": parts[2],
                    "free": parts[3],
                    "available": parts[6] if len(parts) > 6 else "",
                }
    return {}


def _parse_df_output(raw: str) -> list[dict[str, str]]:
    """Parse `df -h` into list of filesystem records."""
    entries = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0] == "Filesystem":
            continue
        entries.append(
            {
                "filesystem": parts[0],
                "size": parts[1],
                "used": parts[2],
                "available": parts[3],
                "use_pct": parts[4],
                "mounted_on": parts[5],
            }
        )
    return entries


def _extract_sensitive_env(raw: str) -> list[str]:
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
