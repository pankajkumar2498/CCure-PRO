"""
core/discovery/techniques/arp_cache.py
────────────────────────────────────────────────────────────────────────────
ARP Cache Lookup Technique

Best-effort fallback when raw sockets (Scapy ARP) are unavailable.
Reads the OS ARP cache to find MAC addresses of hosts that have already
responded to ICMP or TCP probes.

Used by: DiscoveryEngine as a post-probe enrichment.
"""

import logging
import platform
import re
import subprocess
from typing import Dict, List

log = logging.getLogger("ccure.discovery.arp_cache")


def probe(
    ips: List[str],
    results: Dict[str, Dict],
) -> None:
    """
    Check the OS ARP cache for each IP and update the result if found.
    """
    for ip in ips:
        mac = get_mac_from_arp_cache(ip)
        if mac and mac != "N/A":
            results[ip]["mac"] = mac
            # Also update mac_address alias for frontend/sync consistency
            results[ip]["mac_address"] = mac

            # If we just found the MAC, try to get vendor
            from core.oui_lookup import classify_mac

            if results[ip].get("device_category", "unknown") == "unknown":
                results[ip]["device_category"] = classify_mac(mac)


def get_mac_from_arp_cache(ip: str) -> str:
    """
    Try to read MAC from the OS ARP cache.
    Works only if target is on the same subnet.
    """
    import os

    try:
        system = platform.system().lower()

        if system == "windows":
            # Command: arp -a 10.180.5.122
            # Output:
            # Interface: 10.180.5.10 --- 0xb
            #   Internet Address      Physical Address      Type
            #   10.180.5.122          00-0c-29-8e-4a-5b     dynamic
            out = subprocess.check_output(
                ["arp", "-a", ip], timeout=2, stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            # Look for the IP followed by a MAC pattern
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
                    ["ip", "neigh", "show", ip], timeout=2, stderr=subprocess.DEVNULL
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
                ["arp", "-n", ip], timeout=2, stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            # Look for 6 pairs of hex digits
            match = re.search(r"([\da-fA-F]{2}[:\-]){5}[\da-fA-F]{2}", out)

        if match:
            raw_mac = match.group(0) if system != "windows" else match.group(2)
            # Standardize to AA:BB:CC...
            mac = re.sub(r"[^a-fA-F0-9]", "", raw_mac)
            if len(mac) == 12:
                return ":".join(mac[i : i + 2].upper() for i in range(0, 12, 2))

    except Exception as exc:
        log.debug("Failed to read MAC from ARP cache for %s: %s", ip, exc)
        pass

    return "N/A"
