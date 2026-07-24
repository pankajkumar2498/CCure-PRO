"""
core/discovery/techniques/tcp_syn.py — Scapy TCP SYN Probe
Requires root. Detects open/closed/filtered states per port.
"""

import logging
from typing import Dict, List

from core.constants import SCAPY_AVAILABLE
from core.risk import fingerprint_os

log = logging.getLogger("ccure.discovery.tcp_syn")

_ICMP3_FILTERED = {1, 2, 9, 10, 13}


def probe(
    ips: list[str],
    ports: list[int],
    results: dict[str, dict],
    timeout: float = 1.5,
) -> None:
    """
    Send TCP SYN to each IP:port and decode SYN-ACK / RST / ICMP responses.

    SYN-ACK → port open   → host confirmed active, TCP fingerprint captured
    RST     → port closed  → host confirmed active (RST proves existence)
    ICMP-3  → filtered     → port state recorded as 'filtered'
    Timeout → filtered     → port state recorded as 'filtered'

    Used by: BALANCED (corporate fallback) + AGGRESSIVE (all zones).
    """
    if not SCAPY_AVAILABLE or not ips or not ports:
        return
    try:
        from scapy.all import ICMP, IP, TCP, sr

        pkts = IP(dst=ips) / TCP(dport=ports, flags="S")
        ans, unans = sr(pkts, timeout=timeout, verbose=0, multi=True)

        for snd, rcv in ans:
            if not rcv.haslayer(IP):
                continue
            ip = rcv[IP].src
            if ip not in results:
                continue

            if rcv.haslayer(TCP):
                flags = rcv[TCP].flags
                sport = rcv[TCP].sport

                if flags & 0x12:  # SYN-ACK → open
                    results[ip]["port_states"][sport] = "open"
                    if not results[ip]["is_active"]:
                        ttl = rcv[IP].ttl
                        win = rcv[TCP].window
                        opts = dict(rcv[TCP].options) if rcv[TCP].options else {}
                        tcp_fp = {
                            "mss": opts.get("MSS"),
                            "wscale": opts.get("WScale"),
                            "sack_ok": "SAckOK" in opts,
                            "window": win,
                            "df_bit": bool(rcv[IP].flags & 0x02),
                        }
                        guess, conf = fingerprint_os(ttl, win, tcp_fp)
                        results[ip].update(
                            is_active=True,
                            method="TCP SYN",
                            os_guess=guess,
                            os_confidence=conf,
                            tcp_fingerprint=tcp_fp,
                        )
                        results[ip]["confirmations"].append(f"SYN-ACK:{sport}")

                elif flags & 0x04:  # RST → closed (host exists)
                    results[ip]["port_states"][sport] = "closed"
                    if not results[ip]["is_active"]:
                        results[ip].update(is_active=True, method="TCP RST")
                        results[ip]["confirmations"].append(f"RST:{sport}")

            elif rcv.haslayer(ICMP) and rcv[ICMP].type == 3:
                orig_port = snd[TCP].dport if snd.haslayer(TCP) else None
                if orig_port:
                    results[ip]["port_states"][orig_port] = "filtered"

        for snd in unans:
            if snd.haslayer(IP) and snd.haslayer(TCP):
                ip = snd[IP].dst
                port = snd[TCP].dport
                if ip in results:
                    results[ip]["port_states"].setdefault(port, "filtered")

    except Exception as exc:
        log.debug("tcp_syn.probe error: %s", exc)
