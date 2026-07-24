"""
core/discovery/techniques/icmp.py — ICMP Echo Discovery
"""

import logging
from typing import Dict, List, Optional

from core.constants import SCAPY_AVAILABLE
from core.risk import fingerprint_os

log = logging.getLogger("ccure.discovery.icmp")


def probe(
    ips: list[str],
    results: dict[str, dict],
    timeout: float = 1.5,
) -> None:
    """
    Send ICMP Echo Request to each IP and capture TTL for OS fingerprinting.

    Unlike ARP, ICMP traverses routers — it works for corporate VPN hosts and
    any target reachable at L3. However, many host firewalls (Windows Defender,
    iptables DROP) silently discard ICMP, so TCP fallbacks are essential.

    Side effects:
        Updates results[ip]:
          - is_active    → True (if ICMP reply received)
          - method       → "ICMP"
          - os_guess     → inferred from TTL (64→Linux, 128→Windows, 255→Cisco)
          - os_confidence→ "Low" (TTL alone is weak signal)
          - confirmations → appended "ICMP"
          - elapsed_ms   → round-trip time
    """
    if not SCAPY_AVAILABLE or not ips:
        return
    try:
        from scapy.all import ICMP, IP, sr

        ans, _ = sr(
            IP(dst=ips) / ICMP(type="echo-request"),
            timeout=timeout,
            verbose=0,
            multi=True,
        )
        for snd, rcv in ans:
            if not rcv.haslayer(IP):
                continue
            ip = rcv[IP].src
            if ip not in results:
                continue
            ttl = rcv[IP].ttl
            if results[ip].get("os_guess", "Unknown") == "Unknown":
                guess, conf = fingerprint_os(ttl, None)
                results[ip].update(
                    is_active=True,
                    method="ICMP",
                    os_guess=guess,
                    os_confidence=conf,
                )
                elapsed = _latency_ms(snd, rcv)
                if elapsed is not None and results[ip].get("elapsed_ms") is None:
                    results[ip]["elapsed_ms"] = elapsed
            if not results[ip]["is_active"]:
                results[ip]["is_active"] = True
                results[ip]["method"] = "ICMP"
            if "ICMP" not in results[ip]["confirmations"]:
                results[ip]["confirmations"].append("ICMP")
    except Exception as exc:
        log.debug("icmp.probe error: %s", exc)


def _latency_ms(sent, received) -> float | None:
    try:
        t_s = getattr(sent, "sent_time", None) or getattr(sent, "time", None)
        t_r = getattr(received, "time", None)
        if t_s and t_r:
            e = (float(t_r) - float(t_s)) * 1000
            return e if e >= 0 else None
    except Exception as exc:
        log.debug("Failed to calculate ICMP latency: %s", exc)
    return None
