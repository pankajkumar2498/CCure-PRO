"""
core/discovery/techniques/arp.py
────────────────────────────────────────────────────────────────────────────
ARP Discovery Technique (Layer-2 Broadcast)

Scapy only. Requires root + network interface in the same broadcast domain.
Gives the MOST reliable host discovery on LAN and provides the real MAC
address (needed for OUI/vendor lookup), bypassing all host firewalls.

Failure modes:
  - Target on different VLAN/subnet → use ICMP instead
  - VPN endpoint (routed private IP) → use ICMP instead
  - AP client isolation → ARP still works (AP reflects to wired)
  - ARP proxy / proxy-ARP → marks host active, MAC = proxy's MAC

Used by: FAST, BALANCED, AGGRESSIVE profiles (LAN zone only).
"""

import logging
import time
from typing import Dict, List, Optional

from core.constants import SCAPY_AVAILABLE

log = logging.getLogger("ccure.discovery.arp")


def probe(
    ips: List[str],
    results: Dict[str, Dict],
    timeout: float = 2.0,
) -> None:
    """
    Send ARP broadcast to all IPs in the batch and mark responding hosts active.

    Args:
        ips:     List of target IP strings (must be on same L2 segment).
        results: Shared results dict (ip → result dict) — mutated in place.
        timeout: Scapy srp() timeout in seconds.

    Side effects:
        Updates results[ip] for each responding host:
          - is_active   → True
          - mac         → real MAC address from ARP reply
          - method      → "ARP"
          - device_category → OUI-based classification
          - confirmations → appended "ARP"
          - elapsed_ms  → round-trip time
    """
    if not SCAPY_AVAILABLE:
        log.debug("arp.probe: Scapy unavailable, skipping")
        return
    if not ips:
        return

    try:
        from scapy.all import srp, Ether, ARP
        from core.oui_lookup import classify_mac

        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ips),
            timeout=timeout,
            verbose=0,
        )
        for snd, rcv in ans:
            ip = rcv.psrc
            if ip not in results:
                continue
            mac = rcv.hwsrc
            elapsed = _latency_ms(snd, rcv)

            results[ip]["mac"] = mac

            if not results[ip]["is_active"]:
                results[ip].update(
                    is_active=True,
                    method="ARP",
                    device_category=classify_mac(mac),
                )
                if elapsed is not None:
                    results[ip]["elapsed_ms"] = elapsed
                results[ip]["confirmations"].append("ARP")
            else:
                # Already active (ICMP/TCP hit first) — update OUI only
                if results[ip].get("device_category", "unknown") in ("unknown", ""):
                    results[ip]["device_category"] = classify_mac(mac)
                if "ARP" not in results[ip]["confirmations"]:
                    results[ip]["confirmations"].append("ARP")

    except Exception as exc:
        log.debug("arp.probe error: %s", exc)


def _latency_ms(sent, received) -> Optional[float]:
    """Extract round-trip latency from Scapy packets."""
    try:
        t_send = getattr(sent, "sent_time", None) or getattr(sent, "time", None)
        t_recv = getattr(received, "time", None)
        if t_send and t_recv:
            elapsed = (float(t_recv) - float(t_send)) * 1000
            if elapsed >= 0:
                return elapsed
    except Exception:
        pass
    return None
