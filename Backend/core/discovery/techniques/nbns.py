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
from typing import Dict, List

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

    Side effects:
        results[ip]["netbios_names"] → list of {name, flags} dicts
        results[ip]["mac"]           → real MAC if ARP didn't capture it
    """
    for ip in ips:
        if ip not in results:
            continue
        names = _query(ip, timeout)
        if names:
            results[ip]["netbios_names"] = names
            # Extract computer name (flag bit 12 = 0 → workstation/server name)
            for entry in names:
                if not (entry["flags"] & 0x8000):  # not a group name
                    results[ip].setdefault("netbios_computer", entry["name"])
                    break


def _query(ip: str, timeout: float) -> List[Dict]:
    """Send NBSTAT and return parsed name table, or [] on failure."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_NBSTAT_PAYLOAD, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
    except Exception:
        return []

    if len(data) < 57:
        return []

    num_names = data[56]
    names: List[Dict] = []
    for i in range(num_names):
        offset = 57 + i * 18
        if offset + 18 > len(data):
            break
        raw = data[offset:offset + 15]
        flags = struct.unpack(">H", data[offset + 16:offset + 18])[0]
        name  = raw.decode("ascii", errors="ignore").strip()
        if name:
            names.append({"name": name, "flags": flags})
    return names
