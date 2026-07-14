"""
core/discovery/techniques/udp_probe.py — Scapy UDP Service Discovery
"""

import logging
from typing import Dict, List
from core.constants import SCAPY_AVAILABLE

log = logging.getLogger("ccure.discovery.udp_probe")

# ICMP type-3 codes that mean "filtered" (policy/admin block — not "closed")
_FILTERED_CODES = {1, 2, 9, 10, 13}


def probe(
    ips: List[str],
    ports: List[int],
    results: Dict[str, Dict],
    timeout: float = 2.0,
) -> None:
    """
    Send UDP probes to common service ports and parse ICMP-Unreachable responses.

    Used as a last-resort LAN discovery technique for hosts that block both
    ARP and ICMP: DHCP servers, SNMP agents, NTP servers, IKE gateways.

    Scapy sr() is required to receive ICMP Unreachable replies at the
    raw-socket level — the standard Python socket API cannot do this.

    State semantics:
      UDP reply          → "open"         → host marked active
      ICMP type-3 code-3 → "closed"       → host exists (not marked active alone)
      ICMP type-3 other  → "filtered"     → port/host policy-blocked
      No reply           → "open|filtered"→ ambiguous (service or firewall)
    """
    if not SCAPY_AVAILABLE or not ips or not ports:
        return
    try:
        from scapy.all import sr, IP, UDP

        pkts = [IP(dst=ip) / UDP(dport=port) for ip in ips for port in ports]
        if not pkts:
            return
        ans, unans = sr(pkts, timeout=timeout, verbose=0, multi=True)

        for snd, rcv in ans:
            if not (snd.haslayer(IP) and snd.haslayer(UDP)):
                continue
            ip = snd[IP].dst
            port = snd[UDP].dport
            if ip not in results:
                continue

            from scapy.all import ICMP

            if rcv.haslayer(ICMP) and rcv[ICMP].type == 3:
                code = rcv[ICMP].code
                state = (
                    "closed"
                    if code == 3
                    else (("filtered" if code in _FILTERED_CODES else "filtered"))
                )
                results[ip]["port_states"][port] = state
                # RST from ICMP still confirms host existence
                if code == 3 and not results[ip]["is_active"]:
                    results[ip].update(is_active=True, method="ICMP-Unreach")
                    results[ip]["confirmations"].append(f"ICMP3:{port}")
            elif rcv.haslayer(UDP):
                results[ip]["port_states"][port] = "open"
                if not results[ip]["is_active"]:
                    results[ip].update(is_active=True, method="UDP")
                    results[ip]["confirmations"].append(f"UDP:{port}")

        for snd in unans:
            if snd.haslayer(IP) and snd.haslayer(UDP):
                ip = snd[IP].dst
                port = snd[UDP].dport
                if ip in results:
                    results[ip]["port_states"].setdefault(port, "open|filtered")

    except Exception as exc:
        log.debug("udp_probe.probe error: %s", exc)
