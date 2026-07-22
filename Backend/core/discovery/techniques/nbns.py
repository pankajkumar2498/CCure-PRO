"""
core/discovery/techniques/nbns.py — NetBIOS Name Service (UDP 137)

Sends a NBSTAT (node status) request to each IP and parses the name table.
Returns: computer name, workgroup, MAC address (if not already captured by ARP).

Only useful on Windows hosts and Samba servers — skip on Linux/macOS.
Runs only in the AGGRESSIVE profile (Phase 3 pipeline).
"""

import logging
import socket
import struct
from typing import Dict, List, Tuple, Optional

log = logging.getLogger("ccure.discovery.nbns")

# Standard NetBIOS Node Status request payload
_NBSTAT_PAYLOAD = (
    b"\xa2\x48\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41"
    b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
    b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
)


def probe(
    ips: List[str],
    results: Dict[str, Dict],
    timeout: float = 1.0,
) -> None:
    """
    Query NetBIOS node status (UDP 137) for each active IP.
    Extracts computer name AND MAC address from the payload.
    """
    for ip in ips:
        if ip not in results:
            continue

        names, mac = _query(ip, timeout)
        if names:
            results[ip]["netbios_names"] = names
            for entry in names:
                if not (entry["flags"] & 0x8000):  # workstation/server name
                    results[ip].setdefault("netbios_computer", entry["name"])
                    if (
                        not results[ip].get("hostname")
                        or results[ip]["hostname"] == "Unknown"
                    ):
                        results[ip]["hostname"] = entry["name"]
                    break

        if mac and (results[ip].get("mac", "N/A") == "N/A"):
            results[ip]["mac"] = mac


def _query(ip: str, timeout: float) -> Tuple[List[Dict], Optional[str]]:
    """Send NBSTAT and return (parsed names, mac_string)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_NBSTAT_PAYLOAD, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
    except Exception:
        return [], None

    if len(data) < 57:
        return [], None

    num_names = data[56]
    names: List[Dict] = []
    for i in range(num_names):
        offset = 57 + i * 18
        if offset + 18 > len(data):
            break
        raw = data[offset : offset + 15]
        flags = struct.unpack(">H", data[offset + 16 : offset + 18])[0]
        name = raw.decode("ascii", errors="ignore").strip()
        if name:
            names.append({"name": name, "flags": flags})

    # Extract MAC (last 6 bytes after the name table)
    mac = None
    mac_offset = 57 + num_names * 18
    if mac_offset + 6 <= len(data):
        mac_bytes = data[mac_offset : mac_offset + 6]
        if any(b != 0 for b in mac_bytes):
            mac = ":".join(f"{b:02x}" for b in mac_bytes)

    return names, mac
