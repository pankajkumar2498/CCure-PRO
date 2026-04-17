"""
core/discovery/enrichment.py
────────────────────────────────────────────────────────────────────────────
Post-Discovery Host Enrichment (AGGRESSIVE Profile Only)

Runs after the main probe phase on confirmed-active hosts to gather
additional intelligence: reverse DNS, mDNS service names, NetBIOS computer
name, SNMP device classification, and TCP-options OS fingerprinting.

Design rules:
  ✅ Only called by DiscoveryEngine when profile.enrichment=True (AGGRESSIVE)
  ✅ Each probe is independently try/catch — one failure doesn't block others
  ✅ All probes are gate-checked (skip if open_ports insufficient, etc.)
  ✅ Scapy is used for SNMP and mDNS — no dependency on net-snmp binaries
  ❌ Never called from PortEngine or VulnerabilityEngine
  ❌ Never touches the results of Phase 2 or Phase 3

Called from:
  core/discovery/engine.py → _enrich_active() → asyncio.to_thread(enrich_host, ...)
"""

import logging
import socket
import struct
from typing import Dict, List, Optional

from core.constants import SCAPY_AVAILABLE

log = logging.getLogger("ccure.discovery.enrichment")

# SNMP OIDs for device classification
_SNMP_OIDS = {
    "ip_forwarding": "1.3.6.1.2.1.4.1.0",     # 1=router, 2=host
    "bridge_mib":    "1.3.6.1.2.1.17.1.1.0",  # present → switch
    "sys_obj_id":    "1.3.6.1.2.1.1.2.0",      # enterprise OID
}

# Try to import Scapy SNMP extensions (optional — may not be present)
_SNMP_AVAILABLE = False
if SCAPY_AVAILABLE:
    try:
        from scapy.all import SNMP, SNMPget, SNMPvarbind, ASN1_OID
        _SNMP_AVAILABLE = True
    except ImportError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def enrich_host(ip: str, result: Dict) -> None:
    """
    Run all enrichment probes for one active host.

    Each probe is guarded by its own try/except so a single failure
    (e.g. SNMP timeout) doesn't prevent the others from running.

    Args:
        ip:     Target IP address string.
        result: Host result dict from DiscoveryEngine — mutated in place.
    """
    for fn in (_ptr_lookup, _mdns_query, _netbios_query, _snmp_classify, _os_probe_full):
        try:
            fn(ip, result)
        except Exception as exc:
            log.debug("enrich_host(%s) %s error: %s", ip, fn.__name__, exc)


# ─────────────────────────────────────────────────────────────────────────────
# Individual probe functions
# ─────────────────────────────────────────────────────────────────────────────

def _ptr_lookup(ip: str, result: Dict) -> None:
    """
    Reverse DNS PTR lookup via the OS resolver.
    Faster and more reliable than Scapy DNS queries for standard PTR records.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            result.setdefault("ptr_hostname", hostname)
            if not result.get("hostname") or result["hostname"] in ("Unknown", ""):
                result["hostname"] = hostname
    except (socket.herror, socket.gaierror):
        pass


def _mdns_query(ip: str, result: Dict) -> None:
    """
    Send a unicast mDNS PTR query to the target to resolve its .local hostname.
    Uses Scapy for raw DNS packet construction (not multicast join).
    Falls back to socket-based query when Scapy unavailable.
    """
    if not SCAPY_AVAILABLE:
        return
    try:
        from scapy.all import sr1, IP, UDP, DNS, DNSQR
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa."
        pkt = IP(dst=ip) / UDP(dport=5353) / DNS(
            rd=0, qd=DNSQR(qname=rev, qtype="PTR")
        )
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp and resp.haslayer(DNS) and resp[DNS].ancount > 0:
            name = resp[DNS].an.rrname
            if isinstance(name, bytes):
                name = name.decode("utf-8", errors="replace")
            name = name.rstrip(".")
            if name:
                result["mdns_name"] = name
    except Exception as exc:
        log.debug("_mdns_query(%s) error: %s", ip, exc)


def _netbios_query(ip: str, result: Dict) -> None:
    """
    NetBIOS Node Status (UDP 137) — returns computer name, workgroup, MAC.
    Uses raw socket (no Scapy needed — this is a plain UDP exchange).
    """
    _NBSTAT = (
        b"\xa2\x48\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.sendto(_NBSTAT, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
    except Exception:
        return

    if len(data) < 57:
        return

    num_names = data[56]
    names: List[Dict] = []
    computer_name = ""
    workgroup = ""

    for i in range(num_names):
        offset = 57 + i * 18
        if offset + 18 > len(data):
            break
        raw  = data[offset:offset + 15]
        name_type = data[offset + 15] if offset + 15 < len(data) else 0
        flags = struct.unpack(">H", data[offset + 16:offset + 18])[0]
        name  = raw.decode("ascii", errors="ignore").strip()
        if name:
            names.append({"name": name, "flags": flags, "type": name_type})
            # Computer name: type 0x00, not a group (bit 15 clear)
            if name_type == 0x00 and not (flags & 0x8000) and not computer_name:
                computer_name = name
            # Workgroup: type 0x00, group (bit 15 set)
            if name_type == 0x00 and (flags & 0x8000) and not workgroup:
                workgroup = name

    if names:
        result["netbios_names"]    = names
        result["netbios_computer"] = computer_name
        result["netbios_workgroup"] = workgroup
        if computer_name and (not result.get("hostname") or result["hostname"] in ("Unknown", "")):
            result["hostname"] = computer_name

    # MAC from NetBIOS response (last 6 bytes starting at offset 57 + num_names*18)
    mac_offset = 57 + num_names * 18
    if mac_offset + 6 <= len(data):
        mac_bytes = data[mac_offset:mac_offset + 6]
        if any(b != 0 for b in mac_bytes):
            mac_str = ":".join(f"{b:02x}" for b in mac_bytes)
            if result.get("mac", "N/A") == "N/A":
                result["mac"] = mac_str


def _snmp_classify(ip: str, result: Dict) -> None:
    """
    Query SNMP OIDs via Scapy to classify device as 'router', 'switch', or None.
    Skips gracefully when Scapy SNMP is unavailable.
    """
    if not _SNMP_AVAILABLE:
        return
    try:
        from scapy.all import sr1, IP, UDP
        for name, oid in _SNMP_OIDS.items():
            pkt = IP(dst=ip) / UDP(dport=161) / SNMP(
                community=b"public",
                PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))]),
            )
            resp = sr1(pkt, timeout=2, verbose=0)
            if resp is None or not resp.haslayer(SNMP):
                continue
            val = str(resp[SNMP].PDU.varbindlist[0].value)
            if name == "ip_forwarding" and val.strip() == "1":
                result["snmp_device_type"] = "router"
                if result.get("device_category", "unknown") == "unknown":
                    result["device_category"] = "router"
                return
            if name == "bridge_mib":
                result["snmp_device_type"] = "switch"
                if result.get("device_category", "unknown") == "unknown":
                    result["device_category"] = "switch"
                return
    except Exception as exc:
        log.debug("_snmp_classify(%s) error: %s", ip, exc)


def _os_probe_full(ip: str, result: Dict) -> None:
    """
    Send a crafted SYN with a full TCP option set to extract MSS/WScale/SAckOK
    from the SYN-ACK. Refines OS fingerprint beyond the TTL-only initial guess.

    Gate: Only runs if the host has confirmed-open ports.
    Skip: If OS confidence is already High (Nmap detected).
    """
    if not SCAPY_AVAILABLE:
        return
    if result.get("os_confidence") == "High":
        return  # Already have a high-confidence fingerprint

    # Gate: skip if no open ports (all timeouts guaranteed)
    open_ports = [p for p, state in result.get("port_states", {}).items() if state == "open"]
    if not open_ports:
        return

    try:
        from scapy.all import sr, IP, TCP
        from core.risk import fingerprint_os
        pkt = IP(dst=ip) / TCP(
            dport=80, flags="S",
            options=[
                ("MSS",       1460),
                ("NOP",       None),
                ("WScale",    6),
                ("NOP",       None),
                ("NOP",       None),
                ("SAckOK",    b""),
                ("Timestamp", (0, 0)),
                ("EOL",       None),
            ],
        )
        ans, _ = sr(pkt, timeout=2, verbose=0)
        for _, rcv in ans:
            if not rcv.haslayer(TCP):
                continue
            opts = dict(rcv[TCP].options) if rcv[TCP].options else {}
            ts   = opts.get("Timestamp")
            tcp_fp = {
                "ttl":     rcv[IP].ttl,
                "window":  rcv[TCP].window,
                "mss":     opts.get("MSS"),
                "wscale":  opts.get("WScale"),
                "sack_ok": "SAckOK" in opts,
                "ts_val":  ts[0] if isinstance(ts, (tuple, list)) else None,
                "df_bit":  bool(rcv[IP].flags & 0x02),
            }
            guess, conf = fingerprint_os(tcp_fp["ttl"], tcp_fp["window"], tcp_fp)
            result["tcp_fingerprint"] = tcp_fp
            if conf in ("High", "Medium") or result.get("os_confidence", "Low") == "Low":
                result["os_guess"]      = guess
                result["os_confidence"] = conf
    except Exception as exc:
        log.debug("_os_probe_full(%s) error: %s", ip, exc)
