"""
engines/discovery/enum_probe.py
---------------------------------
GAP-09: Deep Enumeration Probes (pure stdlib, no Nmap)

Three independent probers run per active host discovered in Phase 1:

  1. PTR Reverse DNS  -- stdlib socket.gethostbyaddr() wired to host's IP
  2. mDNS Service Discovery -- unicast DNS-SD queries to port 5353 reveal
       advertised service types (_http._tcp, _ssh._tcp, _smb._tcp, etc.)
  3. NetBIOS NBSTAT (enhanced) -- raw UDP 137, full name table decode:
       computer name, workgroup/domain, MAC, logged-on username

All functions are synchronous and designed to be called from an asyncio
run_in_executor() block (as done in _enrich_host).

Interface
---------
    ptr_lookup(ip)        -> Optional[str]           hostname or None
    mdns_services(ip)     -> Dict                    {"hostname": ..., "services": [...]}
    nbstat_full(ip)       -> Dict                    {"computer_name", "workgroup", "mac", "names"}
"""

import logging
import socket
import struct
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("ccure.enum_probe")

# ---------------------------------------------------------------------------
# 1. PTR Reverse DNS
# ---------------------------------------------------------------------------

def ptr_lookup(ip: str, timeout: float = 2.0) -> Optional[str]:
    """
    Resolve the PTR record for *ip* via the system DNS resolver.

    Uses socket.gethostbyaddr() which queries the configured resolver
    (respects /etc/resolv.conf on Linux, Windows DNS cache on Windows).

    Returns the canonical hostname string, or None on failure.
    """
    socket.setdefaulttimeout(timeout)
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        if hostname and hostname != ip:
            return hostname
    except (socket.herror, socket.gaierror, OSError):
        pass
    finally:
        socket.setdefaulttimeout(None)
    return None


# ---------------------------------------------------------------------------
# 2. mDNS Service Discovery (unicast DNS-SD to target:5353)
# ---------------------------------------------------------------------------

# Service types to probe via unicast mDNS
_MDNS_SERVICES = [
    "_services._dns-sd._udp.local",   # global service discovery
    "_http._tcp.local",
    "_https._tcp.local",
    "_ssh._tcp.local",
    "_ftp._tcp.local",
    "_smb._tcp.local",
    "_afpovertcp._tcp.local",          # Apple Filing Protocol
    "_rfb._tcp.local",                 # VNC
    "_printer._tcp.local",
    "_ipp._tcp.local",                 # Internet Printing Protocol
    "_pdl-datastream._tcp.local",      # JetDirect / raw print
    "_nfs._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",                # AirPlay audio
]

_MDNS_PORT  = 5353
_MDNS_TID   = 0x0000  # mDNS transactions are always 0
_QTYPE_PTR  = 12
_QTYPE_ANY  = 255
_QCLASS_IN  = 1


def _build_mdns_query(name: str, qtype: int = _QTYPE_PTR) -> bytes:
    """Build a minimal DNS query packet for an mDNS name."""
    labels = b""
    for part in name.rstrip(".").split("."):
        enc = part.encode("utf-8")
        labels += bytes([len(enc)]) + enc
    labels += b"\x00"

    return (
        struct.pack("!HHHHH",
                    _MDNS_TID,  # Transaction ID (0 for mDNS)
                    0x0000,     # Flags: standard query
                    1,          # QDCOUNT
                    0, 0)       # ANCOUNT, NSCOUNT (0)
        + struct.pack("!H", 0)  # ARCOUNT
        + labels
        + struct.pack("!HH", qtype, _QCLASS_IN)
    )


def _parse_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    """
    Parse a DNS-encoded name starting at *offset* in *data*.
    Follows pointer compression (RFC 1035 §4.1.4).
    Returns (name_string, new_offset).
    """
    labels: List[str] = []
    visited = set()
    orig_offset = offset

    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)

        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:  # Pointer compression
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            sub, _ = _parse_dns_name(data, ptr)
            labels.append(sub)
            offset += 2
            break
        else:
            offset += 1
            labels.append(data[offset: offset + length].decode("utf-8", errors="replace"))
            offset += length

    return ".".join(labels), offset


def _parse_dns_answers(data: bytes) -> List[Dict]:
    """
    Parse the answers/additional sections of a DNS response.
    Returns a list of { "name", "type", "rdata" } dicts.
    """
    if len(data) < 12:
        return []

    an_count = struct.unpack_from("!H", data, 6)[0]
    offset   = 12   # skip header

    # Skip questions
    q_count = struct.unpack_from("!H", data, 4)[0]
    for _ in range(q_count):
        _, offset = _parse_dns_name(data, offset)
        offset += 4  # QTYPE + QCLASS

    records = []
    for _ in range(an_count):
        if offset >= len(data):
            break
        name, offset = _parse_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype  = struct.unpack_from("!H", data, offset)[0]
        rdlen  = struct.unpack_from("!H", data, offset + 8)[0]
        offset += 10
        rdata  = data[offset: offset + rdlen]
        offset += rdlen

        rdata_str = ""
        if rtype in (12, 16):   # PTR, TXT
            try:
                rdata_str, _ = _parse_dns_name(rdata, 0)
            except Exception:
                rdata_str = rdata.decode("utf-8", errors="replace")
        elif rtype == 33:        # SRV
            if len(rdata) > 6:
                target, _ = _parse_dns_name(rdata, 6)
                rdata_str = target
        else:
            rdata_str = rdata.hex()

        records.append({"name": name, "type": rtype, "rdata": rdata_str})

    return records


def mdns_services(ip: str, timeout: float = 1.5) -> Dict:
    """
    Query a host's port 5353 (unicast mDNS) for advertised services.

    Sends queries for the _services._dns-sd names and several well-known
    service types. Replies contain PTR records naming specific service
    instances the host is advertising.

    Returns::
        {
          "hostname":  str | None,
          "services":  ["_http._tcp.local", ...],
          "instances": ["MacBook Air._ssh._tcp.local", ...],
        }
    """
    out: Dict = {"hostname": None, "services": [], "instances": []}

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        for svc in _MDNS_SERVICES:
            query = _build_mdns_query(svc, _QTYPE_PTR)
            try:
                s.sendto(query, (ip, _MDNS_PORT))
                try:
                    data, _ = s.recvfrom(2048)
                    records  = _parse_dns_answers(data)
                    for rec in records:
                        rdata = rec["rdata"]
                        if rec["type"] == 12:   # PTR
                            # Strip trailing dot
                            svc_name = rdata.rstrip(".")
                            if "._tcp.local" in svc_name or "._udp.local" in svc_name:
                                # Remove instance part to get service type
                                parts = svc_name.split(".", 1)
                                if len(parts) > 1 and "._" in parts[1]:
                                    svc_type = parts[1]
                                    if svc_type not in out["services"]:
                                        out["services"].append(svc_type)
                                    out["instances"].append(svc_name[:48])
                            elif ".local" in svc_name:
                                out["hostname"] = svc_name
                except socket.timeout:
                    pass
                except Exception:
                    pass
            except Exception:
                pass

    return out


# ---------------------------------------------------------------------------
# 3. NetBIOS NBSTAT — Enhanced (full name table + MAC + workgroup)
# ---------------------------------------------------------------------------

# NetBIOS name type codes (least significant byte of flags)
_NB_TYPE = {
    0x00: "workstation",
    0x03: "messenger",
    0x06: "server",
    0x1B: "domain_master_browser",
    0x1C: "domain_controller",
    0x1D: "master_browser",
    0x1E: "browser_elections",
    0x20: "file_server",
    0x21: "ras_client",
}

_NBSTAT_REQUEST = (
    b"\xa2\x48"       # Transaction ID
    b"\x00\x00"       # Flags: query, non-recursive
    b"\x00\x01"       # QDCOUNT = 1
    b"\x00\x00"       # ANCOUNT = 0
    b"\x00\x00"       # NSCOUNT = 0
    b"\x00\x00"       # ARCOUNT = 0
    # QNAME: * encoded as 32-char NetBIOS level-2 name "CKAAA...AAA"
    b"\x20"
    b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    b"\x00"
    b"\x00\x21"       # QTYPE  = NBSTAT (0x21)
    b"\x00\x01"       # QCLASS = IN
)


def nbstat_full(ip: str, timeout: float = 2.0) -> Dict:
    """
    Send a NetBIOS NBSTAT request to *ip*:137 and decode the full response.

    RFC 1002 §4.2.18 defines the NBSTAT response format.

    Returns::
        {
          "computer_name": str,     # primary workstation name (type 0x00)
          "workgroup":     str,     # domain/workgroup name (type 0x1C or 0x00 group)
          "mac":           str,     # "AA:BB:CC:DD:EE:FF" from adapter status
          "names":         [        # all decoded NB names
            {"name": str, "type_code": int, "type": str, "flags": int, "group": bool}
          ]
        }
    """
    result: Dict = {
        "computer_name": "",
        "workgroup": "",
        "mac": "",
        "names": [],
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(_NBSTAT_REQUEST, (ip, 137))
            data, _ = s.recvfrom(1024)
    except Exception as exc:
        log.debug("nbstat_full(%s) error: %s", ip, exc)
        return result

    # Minimum response: 57 bytes (12 DNS header + 44 question + 1 name count)
    if len(data) < 57:
        return result

    num_names = data[56]
    names: List[Dict] = []

    for i in range(num_names):
        offset = 57 + i * 18
        if offset + 18 > len(data):
            break

        raw_name   = data[offset: offset + 15]
        type_code  = data[offset + 15]          # 16th byte = NB suffix
        flags      = struct.unpack_from(">H", data, offset + 16)[0]
        is_group   = bool(flags & 0x8000)       # bit 15 = GROUP name
        name       = raw_name.decode("ascii", errors="ignore").rstrip()

        type_label = _NB_TYPE.get(type_code, f"0x{type_code:02X}")
        entry = {
            "name":      name,
            "type_code": type_code,
            "type":      type_label,
            "flags":     flags,
            "group":     is_group,
        }
        names.append(entry)

        # Primary computer name: type 0x00, not a group
        if type_code == 0x00 and not is_group and not result["computer_name"]:
            result["computer_name"] = name

        # Workgroup/domain: type 0x00 group OR type 0x1C
        if (type_code == 0x00 and is_group) or type_code == 0x1C:
            if not result["workgroup"]:
                result["workgroup"] = name

    result["names"] = names

    # MAC: follows the name table at offset 57 + num_names*18 + 57-byte stats
    mac_offset = 57 + num_names * 18 + 57
    if mac_offset + 6 <= len(data):
        mac_bytes = data[mac_offset: mac_offset + 6]
        result["mac"] = ":".join(f"{b:02X}" for b in mac_bytes)

    return result
