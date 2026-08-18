"""
core/utils.py
-------------
Cross-cutting utilities: privilege detection, input validation,
CVE lookup, version extraction, token-bucket rate limiter.
No engines are imported here.
"""

import ctypes
import ipaddress
import logging
import os
import platform
import re
import socket
import time
import uuid
from typing import Dict, List, Optional

log = logging.getLogger("ccure.utils")

from core.constants import CVE_DB, CVE_HINTS, VER_PATTERNS

# =============================================================================
# Privilege Manager
# =============================================================================


class PrivilegeManager:
    @staticmethod
    def get_platform() -> str:
        s = platform.system().lower()
        return {"windows": "windows", "linux": "linux", "darwin": "macos"}.get(
            s, "unknown"
        )

    @staticmethod
    def is_admin() -> bool:
        try:
            if PrivilegeManager.get_platform() == "windows":
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            return os.geteuid() == 0
        except Exception as exc:
            log.debug("Privilege check failed: %s", exc)
            return False

    @staticmethod
    def info() -> dict:
        admin = PrivilegeManager.is_admin()
        return {
            "platform": PrivilegeManager.get_platform(),
            "has_privileges": admin,
            "privilege_level": "Administrator/Root" if admin else "Limited",
        }


# =============================================================================
# Input Validator
# =============================================================================


class InputValidator:
    # The leading character is deliberately excluded from the dash class.
    #
    # The previous pattern, ^[\w.\-:/\[\]]+$, accepted "-oN", "-sS", "-iL/etc/
    # passwd" and "--iflist": every scanner this product drives is executed as
    # an argv list, and a value beginning with "-" lands in that list as an
    # *option* rather than a target. is_safe() is the primitive whose name
    # asserts a value is safe to pass onward, so it must not approve a string
    # that changes the command being run.
    #
    # No exploit path went through it today — resolve_target() also requires the
    # value to parse as an IP, CIDR, range or resolvable hostname, and none of
    # those start with a dash, so these were rejected a step later with HTTP
    # 422. That is one layer, in a different function, on every current caller.
    # This is the layer that belongs here.
    _SAFE_RE = re.compile(r"^[\w.:/\[\]][\w.\-:/\[\]]*$")
    MAX_HOSTS = 4096

    @staticmethod
    def is_safe(value: str) -> bool:
        return bool(InputValidator._SAFE_RE.match(value.strip()))

    @staticmethod
    def resolve_hostname(host: str) -> str | None:
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None

    @staticmethod
    def validate_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_cidr(cidr: str) -> dict:
        if "/" not in cidr:
            return {"valid": False, "error": "Missing '/' in CIDR."}
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.num_addresses > InputValidator.MAX_HOSTS:
                return {
                    "valid": False,
                    "error": f"Network too large ({net.num_addresses} hosts). Max {InputValidator.MAX_HOSTS}.",
                }
            return {"valid": True, "network": net}
        except ValueError as e:
            return {"valid": False, "error": f"Invalid CIDR: {e}"}

    @staticmethod
    def validate_range(ip_range: str) -> dict:
        parts = ip_range.split("-")
        if len(parts) == 2:
            try:
                start_ip = ipaddress.ip_address(parts[0])
                if "." in parts[1]:
                    end_ip = ipaddress.ip_address(parts[1])
                else:
                    base = str(start_ip).rsplit(".", 1)[0]
                    end_ip = ipaddress.ip_address(f"{base}.{parts[1]}")
                if int(end_ip) < int(start_ip):
                    return {"valid": False, "error": "Start IP > End IP."}
                if int(end_ip) - int(start_ip) > InputValidator.MAX_HOSTS:
                    return {
                        "valid": False,
                        "error": f"Range too large. Max {InputValidator.MAX_HOSTS}.",
                    }
                return {"valid": True}
            except ValueError as e:
                return {"valid": False, "error": str(e)}
        return {"valid": False, "error": "Range must contain exactly one dash."}

    @staticmethod
    def resolve_target(target: str) -> dict:
        target = target.strip()
        if not InputValidator.is_safe(target):
            return {"error": f"Invalid or unsafe target: '{target}'"}
        if "/" in target:
            res = InputValidator.validate_cidr(target)
            if res["valid"]:
                return {"resolved": target, "original": target, "type": "cidr"}
            return {"error": res["error"]}
        if "-" in target:
            if InputValidator.validate_ip(target.split("-")[0]):
                res = InputValidator.validate_range(target)
                if res["valid"]:
                    return {"resolved": target, "original": target, "type": "range"}
                return {"error": res["error"]}
        if InputValidator.validate_ip(target):
            return {"resolved": target, "original": target, "type": "ip"}
        resolved = InputValidator.resolve_hostname(target)
        if resolved:
            return {
                "resolved": resolved,
                "original": target,
                "type": "hostname",
                "resolved_ip": resolved,
            }
        return {"error": f"Cannot resolve hostname: '{target}'"}

    @staticmethod
    def expand_ip_range(target: str) -> list[str]:
        try:
            parts = target.split("-")
            start = ipaddress.ip_address(parts[0])
            if "." in parts[1]:
                end = ipaddress.ip_address(parts[1])
            else:
                base = str(start).rsplit(".", 1)[0]
                end = ipaddress.ip_address(f"{base}.{parts[1]}")
            if int(end) < int(start):
                return []
            return [
                str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)
            ]
        except Exception as exc:
            log.debug("Failed to expand IP range '%s': %s", target, exc)
            return []

    @staticmethod
    def expand_target(target: str) -> list[str]:
        """Expand any target string (CIDR / range / single IP) to a flat list of IPs."""
        res = InputValidator.resolve_target(target)
        if "error" in res:
            return []
        t = res["type"]
        if t == "cidr":
            return [
                str(ip) for ip in ipaddress.ip_network(target, strict=False).hosts()
            ]
        if t == "range":
            return InputValidator.expand_ip_range(target)
        return [res["resolved"]]

    @staticmethod
    def parse_custom_ports(ports_str: str) -> list[int]:
        if not ports_str or not ports_str.strip():
            raise ValueError("Port input cannot be empty.")

        seen_ports = set()
        ports_list = []
        tokens = [t.strip() for t in ports_str.split(",")]

        for token in tokens:
            if not token:
                raise ValueError(
                    "Malformed input: empty token in port list (check for consecutive or trailing commas)."
                )

            # Strip internal spaces for range tolerance (e.g. "80 - 83" → "80-83")
            token = token.replace(" ", "")

            # Check if it's a range
            if "-" in token:
                range_match = re.match(r"^(\d+)-(\d+)$", token)
                if not range_match:
                    raise ValueError(
                        f"Malformed port range: '{token}'. Use format 'start-end' (e.g. 80-90)."
                    )
                start_p, end_p = int(range_match.group(1)), int(range_match.group(2))
                if not (1 <= start_p <= 65535) or not (1 <= end_p <= 65535):
                    raise ValueError(
                        f"Port numbers in range '{token}' must be between 1 and 65535."
                    )
                if start_p > end_p:
                    raise ValueError(
                        f"Invalid range '{token}': start port {start_p} is greater than end port {end_p}."
                    )

                for p in range(start_p, end_p + 1):
                    if p in seen_ports:
                        raise ValueError(
                            f"Duplicate port detected: {p} is specified more than once."
                        )
                    seen_ports.add(p)
                    ports_list.append(p)
            else:
                if not token.isdigit():
                    raise ValueError(
                        f"Malformed port: '{token}'. Must be a number between 1 and 65535."
                    )
                p = int(token)
                if not (1 <= p <= 65535):
                    raise ValueError(f"Port '{token}' must be between 1 and 65535.")
                if p in seen_ports:
                    raise ValueError(
                        f"Duplicate port detected: {p} is specified more than once."
                    )
                seen_ports.add(p)
                ports_list.append(p)

        return sorted(ports_list)

    @staticmethod
    def parse_exclude_ports(ports_str: str) -> list[int]:
        """
        Parse an exclude-ports string into a sorted list of unique port numbers.

        Accepts the same formats as parse_custom_ports:
          - Single ports:   "22,443"
          - Ranges:         "80-90"
          - Mixed:          "22,80-90,443"
          - Space-tolerant: "80 - 90"

        Returns an empty list for empty/None input (exclude is optional).

        Raises:
            ValueError: On malformed tokens, out-of-range ports, or duplicates.
        """
        if not ports_str or not ports_str.strip():
            return []

        seen_ports = set()
        ports_list = []
        tokens = [t.strip() for t in ports_str.split(",")]

        for token in tokens:
            if not token:
                raise ValueError(
                    "Malformed input: empty token in exclude list (check for consecutive or trailing commas)."
                )

            # Strip internal spaces for range tolerance
            token = token.replace(" ", "")

            if "-" in token:
                range_match = re.match(r"^(\d+)-(\d+)$", token)
                if not range_match:
                    raise ValueError(
                        f"Malformed port range: '{token}'. Use format 'start-end' (e.g. 80-90)."
                    )
                start_p, end_p = int(range_match.group(1)), int(range_match.group(2))
                if not (1 <= start_p <= 65535) or not (1 <= end_p <= 65535):
                    raise ValueError(
                        f"Port numbers in range '{token}' must be between 1 and 65535."
                    )
                if start_p > end_p:
                    raise ValueError(
                        f"Invalid range '{token}': start port {start_p} is greater than end port {end_p}."
                    )

                for p in range(start_p, end_p + 1):
                    if p in seen_ports:
                        raise ValueError(
                            f"Duplicate port detected: {p} is specified more than once."
                        )
                    seen_ports.add(p)
                    ports_list.append(p)
            else:
                if not token.isdigit():
                    raise ValueError(
                        f"Malformed port: '{token}'. Must be a number between 1 and 65535."
                    )
                p = int(token)
                if not (1 <= p <= 65535):
                    raise ValueError(f"Port '{token}' must be between 1 and 65535.")
                if p in seen_ports:
                    raise ValueError(
                        f"Duplicate port detected: {p} is specified more than once."
                    )
                seen_ports.add(p)
                ports_list.append(p)

        return sorted(ports_list)


# =============================================================================
# Token-Bucket Rate Limiter  (prevents IDS triggers)
# =============================================================================

import threading


class TokenBucket:
    def __init__(self, rate: float = 100.0, capacity: float = 200.0):
        self.rate = rate  # tokens per second
        self.capacity = capacity
        self.tokens = capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, n: float = 1.0):
        with self._lock:
            now = time.monotonic()
            self.tokens = min(
                self.capacity, self.tokens + (now - self._last) * self.rate
            )
            self._last = now
            if self.tokens >= n:
                self.tokens -= n
                sleep_time = 0
            else:
                sleep_time = (n - self.tokens) / self.rate
                self.tokens = 0

        if sleep_time > 0:
            time.sleep(sleep_time)


from functools import lru_cache


@lru_cache(maxsize=1024)
def lookup_cve(
    banner: str, version: str = "", cpes: tuple[str, ...] = ()
) -> list[dict]:
    """
    Candidate CVEs for an observed service.

    ``version`` is the version the scanner actually fingerprinted for this
    service. It is passed through to the database layer and returned on each
    record so the report can compare it against the CVE's published vulnerable
    range. Without it every match is unverifiable and the report can only ever
    say "potential".

    ``cpes`` are the scanner's own CPE identifiers for the service. When
    present the database selects candidates by exact vendor/product instead of
    matching substrings of the banner, which is both far more precise and the
    difference between a candidate set that fits under the row cap and one that
    gets truncated by it.

    Cached with LRU to avoid redundant DB hits for common services (e.g. many
    ports running the same web server) — hence the tuple parameter, which is
    hashable where a list would not be.
    """
    if not banner and not cpes:
        return []

    banner_lc = (banner or "").lower()
    found: list[dict] = []

    # Try database first if available
    if CVE_DB and CVE_DB.db_available:
        try:
            db_results = CVE_DB.search_cves_for_service(banner, version, cpes)
            if db_results:
                found.extend(db_results)
        except Exception as e:
            log.debug("CVE DB search error for '%s': %s", banner, e)

    # Fallback to the hardcoded hint table only when the database is
    # unavailable. These hints carry no CPE data, so findings derived from them
    # cannot be version-verified and are reported at low confidence.
    if not found:
        for key, hints in CVE_HINTS.items():
            if key in banner_lc:
                for hint in hints:
                    entry = dict(hint)
                    entry.setdefault("detection_source", "hint_table")
                    found.append(entry)

    return found


# =============================================================================
# Version Extraction
# =============================================================================


def extract_version(banner: str, service: str = "") -> str:
    for pat in VER_PATTERNS:
        m = pat.search(banner)
        if m:
            return m.group(1)
    return ""


# =============================================================================
# Local Host Helpers
# =============================================================================


def get_local_ips() -> set:
    local = {"127.0.0.1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            addr = info[4][0]
            try:
                ipaddress.IPv4Address(addr)
                local.add(addr)
            except ValueError:
                pass
    except Exception as exc:
        log.debug("Failed to get local IPs: %s", exc)
    return local


def get_local_mac() -> str:
    """
    Return the primary network interface MAC address for this machine.

    Strategy:
    1. psutil.net_if_addrs()  — resolve the gateway-facing interface and get its MAC
    2. uuid.getnode()         — cross-platform fallback (48-bit int, MSB first)
    """
    # Attempt 1: psutil — accurate, works on multi-NIC Windows/Linux/macOS
    try:
        import socket

        import psutil

        AF_LINK = (
            psutil.AF_LINK
        )  # = 17 on Linux, 18 on macOS, -1000 on Windows (still works)

        # Find which interface carries the default route
        gw_iface = None
        gateways = psutil.net_if_stats()
        # Use the first UP, non-loopback interface that has a gateway
        # by trying to open a UDP socket to 8.8.8.8 to find the source IP
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
        except Exception as exc:
            log.debug("UDP socket connection to find local IP failed: %s", exc)
            local_ip = None

        if local_ip:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address == local_ip:
                        gw_iface = iface
                        break
                if gw_iface:
                    break

        if gw_iface:
            for addr in psutil.net_if_addrs().get(gw_iface, []):
                if addr.family == AF_LINK and addr.address:
                    mac = addr.address.upper().replace("-", ":")
                    if mac and mac != "00:00:00:00:00:00":
                        return mac
    except Exception as exc:
        log.debug("psutil MAC address resolution failed: %s", exc)

    # Attempt 2: uuid.getnode() — reliable cross-platform fallback
    try:
        n = uuid.getnode()
        if (n >> 40) & 1:
            # Multicast bit set = locally administered / random address
            return "N/A"
        # getnode() returns a 48-bit big-endian integer — extract MSB first
        return ":".join(f"{(n >> (8 * i)) & 0xFF:02X}" for i in reversed(range(6)))
    except Exception as exc:
        log.debug("uuid.getnode MAC resolution failed: %s", exc)
        return "N/A"


#  after a successful PING/TCP response, try an ARP cache lookup as a best-effort fallback. This works when the target is on the same subnet:

import re
import subprocess


def get_mac_from_arp_cache(ip: str) -> str:
    """
    Try to read MAC from the OS ARP cache after a successful ping/TCP.
    Works only if target is on the same subnet.
    Returns 'N/A' if not found or cross-subnet.
    """
    try:
        system = platform.system().lower()

        if system == "windows":
            out = subprocess.check_output(
                ["arp", "-a", ip], timeout=3, stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            match = re.search(
                r"(\b" + re.escape(ip) + r"\b)\s+([\da-fA-F:-]{11,17})", out
            )
        else:
            # 1. Primary path for Linux: Parse /proc/net/arp directly (no subprocess/tools needed)
            if os.path.exists("/proc/net/arp"):
                try:
                    with open(
                        "/proc/net/arp", "r", encoding="utf-8", errors="ignore"
                    ) as f:
                        for line in f:
                            parts = line.split()
                            if len(parts) >= 4 and parts[0] == ip:
                                raw_mac = parts[3]
                                if raw_mac and raw_mac != "00:00:00:00:00:00":
                                    mac = re.sub(r"[^a-fA-F0-9]", "", raw_mac)
                                    if len(mac) == 12:
                                        return ":".join(
                                            mac[i : i + 2].upper()
                                            for i in range(0, 12, 2)
                                        )
                except Exception as proc_exc:
                    log.debug("Failed to read /proc/net/arp: %s", proc_exc)

            # 2. Secondary path: 'ip neigh show <ip>' (standard on modern Linux)
            try:
                out = subprocess.check_output(
                    ["ip", "neigh", "show", ip], timeout=3, stderr=subprocess.DEVNULL
                ).decode(errors="ignore")
                match = re.search(r"([\da-fA-F]{2}[:\-]){5}[\da-fA-F]{2}", out)
                if match:
                    raw_mac = match.group(0)
                    mac = re.sub(r"[^a-fA-F0-9]", "", raw_mac)
                    if len(mac) == 12:
                        return ":".join(mac[i : i + 2].upper() for i in range(0, 12, 2))
            except Exception as ip_exc:
                log.debug("Failed to run 'ip neigh show': %s", ip_exc)

            # 3. Tertiary path: arp -n <ip> (requires net-tools)
            out = subprocess.check_output(
                ["arp", "-n", ip], timeout=3, stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            match = re.search(r"([\da-fA-F]{2}[:\-]){5}[\da-fA-F]{2}", out)

        if match:
            raw_mac = match.group(0) if system != "windows" else match.group(2)
            mac = re.sub(r"[^a-fA-F0-9]", "", raw_mac)
            if len(mac) == 12:
                return ":".join(mac[i : i + 2].upper() for i in range(0, 12, 2))

    except Exception as exc:
        log.debug("Failed to read MAC from ARP cache for %s: %s", ip, exc)

    return "N/A"


def normalize_mac(mac: str) -> str | None:
    """
    Standardize a MAC address into uppercase colon-separated format (AA:BB:CC:DD:EE:FF).
    Returns None if the format is invalid or has incorrect length.
    """
    if not mac:
        return None

    # Strip common separators
    temp = mac.strip().replace(":", "").replace("-", "").replace(".", "")
    # Check that it consists of exactly 12 hexadecimal characters
    if len(temp) != 12 or not all(c in "0123456789abcdefABCDEF" for c in temp):
        return None

    return ":".join(temp[i : i + 2].upper() for i in range(0, 12, 2))
