"""
core/utils.py
-------------
Cross-cutting utilities: privilege detection, input validation,
CVE lookup, version extraction, token-bucket rate limiter.
No engines are imported here.
"""

import ctypes
import ipaddress
import os
import platform
import re
import socket
import time
import uuid
from typing import Dict, List, Optional

from core.constants import CVE_HINTS, VER_PATTERNS, CVE_DB


# =============================================================================
# Privilege Manager
# =============================================================================

class PrivilegeManager:
    @staticmethod
    def get_platform() -> str:
        s = platform.system().lower()
        return {"windows": "windows", "linux": "linux", "darwin": "macos"}.get(s, "unknown")

    @staticmethod
    def is_admin() -> bool:
        try:
            if PrivilegeManager.get_platform() == "windows":
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            return os.geteuid() == 0
        except Exception:
            return False

    @staticmethod
    def info() -> Dict:
        admin = PrivilegeManager.is_admin()
        return {
            "platform":        PrivilegeManager.get_platform(),
            "has_privileges":  admin,
            "privilege_level": "Administrator/Root" if admin else "Limited",
        }


# =============================================================================
# Input Validator
# =============================================================================

class InputValidator:
    _SAFE_RE  = re.compile(r'^[\w.\-:/\[\]]+$')
    MAX_HOSTS = 4096

    @staticmethod
    def is_safe(value: str) -> bool:
        return bool(InputValidator._SAFE_RE.match(value.strip()))

    @staticmethod
    def resolve_hostname(host: str) -> Optional[str]:
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
    def validate_cidr(cidr: str) -> Dict:
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
    def validate_range(ip_range: str) -> Dict:
        parts = ip_range.split("-")
        if len(parts) == 2:
            try:
                start_ip = ipaddress.ip_address(parts[0])
                if "." in parts[1]:
                    end_ip = ipaddress.ip_address(parts[1])
                else:
                    base   = str(start_ip).rsplit(".", 1)[0]
                    end_ip = ipaddress.ip_address(f"{base}.{parts[1]}")
                if int(end_ip) < int(start_ip):
                    return {"valid": False, "error": "Start IP > End IP."}
                if int(end_ip) - int(start_ip) > InputValidator.MAX_HOSTS:
                    return {"valid": False, "error": f"Range too large. Max {InputValidator.MAX_HOSTS}."}
                return {"valid": True}
            except ValueError as e:
                return {"valid": False, "error": str(e)}
        return {"valid": False, "error": "Range must contain exactly one dash."}

    @staticmethod
    def resolve_target(target: str) -> Dict:
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
                "resolved": resolved, "original": target,
                "type": "hostname", "resolved_ip": resolved,
            }
        return {"error": f"Cannot resolve hostname: '{target}'"}

    @staticmethod
    def expand_ip_range(target: str) -> List[str]:
        try:
            parts = target.split("-")
            start = ipaddress.ip_address(parts[0])
            if "." in parts[1]:
                end = ipaddress.ip_address(parts[1])
            else:
                base = str(start).rsplit(".", 1)[0]
                end  = ipaddress.ip_address(f"{base}.{parts[1]}")
            if int(end) < int(start):
                return []
            return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
        except Exception:
            return []

    @staticmethod
    def expand_target(target: str) -> List[str]:
        """Expand any target string (CIDR / range / single IP) to a flat list of IPs."""
        res = InputValidator.resolve_target(target)
        if "error" in res:
            return []
        t = res["type"]
        if t == "cidr":
            return [str(ip) for ip in ipaddress.ip_network(target, strict=False).hosts()]
        if t == "range":
            return InputValidator.expand_ip_range(target)
        return [res["resolved"]]


# =============================================================================
# Token-Bucket Rate Limiter  (prevents IDS triggers)
# =============================================================================

import threading

class TokenBucket:
    def __init__(self, rate: float = 100.0, capacity: float = 200.0):
        self.rate     = rate        # tokens per second
        self.capacity = capacity
        self.tokens   = capacity
        self._last    = time.monotonic()
        self._lock    = threading.Lock()

    def consume(self, n: float = 1.0):
        with self._lock:
            now          = time.monotonic()
            self.tokens  = min(self.capacity, self.tokens + (now - self._last) * self.rate)
            self._last   = now
            if self.tokens >= n:
                self.tokens -= n
                sleep_time = 0
            else:
                sleep_time  = (n - self.tokens) / self.rate
                self.tokens = 0
        
        if sleep_time > 0:
            time.sleep(sleep_time)


# =============================================================================
# CVE Lookup
# =============================================================================

def lookup_cve(banner: str) -> List[Dict]:
    """
    Match a banner / service string against CVE database.
    Falls back to hardcoded hints if database is unavailable.
    """
    banner_lc = banner.lower()
    found: List[Dict] = []
    
    # Try database first if available
    if CVE_DB and CVE_DB.db_available:
        db_results = CVE_DB.search_cves_for_service(banner, "")
        if db_results:
            found.extend(db_results)
    
    # Fallback to hardcoded hints if no database results
    if not found:
        for key, hints in CVE_HINTS.items():
            if key in banner_lc:
                found.extend(hints)
    
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
    except Exception:
        pass
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

        AF_LINK = psutil.AF_LINK  # = 17 on Linux, 18 on macOS, -1000 on Windows (still works)

        # Find which interface carries the default route
        gw_iface = None
        gateways = psutil.net_if_stats()
        # Use the first UP, non-loopback interface that has a gateway
        # by trying to open a UDP socket to 8.8.8.8 to find the source IP
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
        except Exception:
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
    except Exception:
        pass

    # Attempt 2: uuid.getnode() — reliable cross-platform fallback
    try:
        n = uuid.getnode()
        if (n >> 40) & 1:
            # Multicast bit set = locally administered / random address
            return "N/A"
        # getnode() returns a 48-bit big-endian integer — extract MSB first
        return ":".join(f"{(n >> (8 * i)) & 0xFF:02X}" for i in reversed(range(6)))
    except Exception:
        return "N/A"




#  after a successful PING/TCP response, try an ARP cache lookup as a best-effort fallback. This works when the target is on the same subnet:

import subprocess
import re
import platform

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
                ["arp", "-a", ip], timeout=3,
                stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            match = re.search(
                r'(\b' + re.escape(ip) + r'\b)\s+([\da-fA-F:-]{11,17})',
                out
            )
        else:
            out = subprocess.check_output(
                ["arp", "-n", ip], timeout=3,
                stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            match = re.search(
                r'([\da-fA-F]{2}[:\-]){5}[\da-fA-F]{2}',
                out
            )

        if match:
            raw_mac = match.group(0) if system != "windows" else match.group(2)
            mac = re.sub(r'[^a-fA-F0-9]', '', raw_mac)
            return ':'.join(mac[i:i+2].upper() for i in range(0, 12, 2))

    except Exception:
        pass

    return "N/A"
