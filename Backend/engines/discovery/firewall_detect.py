"""
engines/discovery/firewall_detect.py
--------------------------------------
GAP-10: Firewall / Filter Detection (pure Scapy, no Nmap)

Three complementary techniques:

  1. ACK Probe
     Sends TCP packets with only the ACK flag set to a probed port.
     A stateful firewall drops the packet (filtered).
     An unfiltered host (or stateless firewall) returns TCP RST.
     Mirrors Nmap's -sA (ACK scan) which maps firewall rules.

  2. ICMP Unreachable Classification
     Analyses ICMP type-3 responses to classify filter disposition:
       Code 0  = net-unreachable    → routing issue (no firewall)
       Code 1  = host-unreachable   → host down / routing black hole
       Code 3  = port-unreachable   → host is up, port closed (not filtered)
       Code 9  = net-admin-prohibited  → firewall (policy-based reject)
       Code 10 = host-admin-prohibited → firewall (host-level reject)
       Code 13 = comm-admin-prohibited → firewall (ACL / admin policy)

  3. RST Rate-Limit Detection
     Sends N SYNs rapidly to N different closed ports.
     If the RST reply ratio drops below 80%, the target is likely
     throttling RST packets (common on Windows / Cisco IOS).
     Nmap adjusts its retransmit timings when it detects this.

All functions require raw socket privileges (root or CAP_NET_RAW).
Falls back to empty/None results when Scapy is unavailable.

Interface
---------
    ack_probe(ip, ports, has_privileges, timeout) -> Dict[int, str]
        port -> "unfiltered" | "filtered" | "open|filtered" | "error"

    icmp_classify(icmp_type, icmp_code) -> str
        human-readable filter disposition string

    rst_rate_limit_check(ip, probe_ports, has_privileges) -> Dict
        {"throttled": bool, "sent": int, "received": int, "ratio": float}

    detect_firewall(ip, open_ports, has_privileges) -> Dict
        {"ack_results": ..., "rst_throttled": bool, "firewall_confidence": str}
        Firewall confidence: "High" | "Medium" | "Low" | "None"
"""

import logging
import random
from typing import Dict, List, Optional

log = logging.getLogger("ccure.firewall_detect")

# ---------------------------------------------------------------------------
# Scapy import — graceful fallback when not available / no privileges
# ---------------------------------------------------------------------------

try:
    from scapy.all import (
        IP, TCP, ICMP, UDP,
        sr, sr1, send,
        conf as scapy_conf,
    )
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ---------------------------------------------------------------------------
# 1. ACK Probe
# ---------------------------------------------------------------------------

# Ports to ACK-probe when the caller doesn't specify particular ones
_DEFAULT_ACK_PORTS = [80, 443, 22, 25, 53, 110, 139, 445]

_ICMP_FILTER_CODES = {9, 10, 13}   # admin-prohibited variants → firewall
_ICMP_UNREACH_CODES = {0, 1, 3}    # routing / host issues → no firewall


def ack_probe(
    ip: str,
    ports: Optional[List[int]] = None,
    has_privileges: bool = True,
    timeout: float = 2.0,
) -> Dict[int, str]:
    """
    Send TCP ACK packets to each port in *ports* and classify the result.

    Returns a dict mapping port → state string:
        "unfiltered"   — RST received; firewall is not blocking this port
        "filtered"     — No response; stateful firewall dropped the packet
        "open|filtered"— ICMP unreachable (admin-prohibited → firewall)
        "error"        — Privilege/send error
    """
    if not has_privileges or not SCAPY_AVAILABLE:
        return {}

    if ports is None:
        ports = _DEFAULT_ACK_PORTS

    states: Dict[int, str] = {}

    try:
        pkts = [
            IP(dst=ip) / TCP(dport=port, flags="A", seq=random.randint(1, 2**31))
            for port in ports
        ]
        answered, unanswered = sr(pkts, timeout=timeout, verbose=0)

        # Ports that received no response → filtered
        answered_ports = set()
        for snd, rcv in answered:
            port = snd[TCP].dport
            answered_ports.add(port)

            if rcv.haslayer(TCP):
                fl = rcv[TCP].flags
                if fl & 0x04:   # RST
                    states[port] = "unfiltered"
                elif fl & 0x12:  # SYN-ACK (unlikely but possible)
                    states[port] = "open"
                else:
                    states[port] = "open|filtered"

            elif rcv.haslayer(ICMP):
                icmp_type = rcv[ICMP].type
                icmp_code = rcv[ICMP].code
                if icmp_type == 3 and icmp_code in _ICMP_FILTER_CODES:
                    states[port] = "filtered"    # admin prohibited
                elif icmp_type == 3 and icmp_code in _ICMP_UNREACH_CODES:
                    states[port] = "open|filtered"
                else:
                    states[port] = "open|filtered"
            else:
                states[port] = "open|filtered"

        for pkt in unanswered:
            port = pkt[TCP].dport
            if port not in states:
                states[port] = "filtered"

    except Exception as exc:
        log.debug("ack_probe(%s) error: %s", ip, exc)
        for port in (ports or []):
            states.setdefault(port, "error")

    return states


# ---------------------------------------------------------------------------
# 2. ICMP Unreachable Classification
# ---------------------------------------------------------------------------

_ICMP_TYPE3_LABELS: Dict[int, str] = {
    0:  "net-unreachable (routing, no firewall)",
    1:  "host-unreachable (target down or black-hole)",
    2:  "protocol-unreachable",
    3:  "port-unreachable (host up, port closed, not filtered)",
    4:  "fragmentation-needed (PMTU issue)",
    5:  "source-route-failed",
    6:  "destination-network-unknown",
    7:  "destination-host-unknown",
    9:  "network-admin-prohibited (firewall/ACL)",
    10: "host-admin-prohibited (host-level firewall)",
    13: "communication-admin-prohibited (policy firewall)",
}


def icmp_classify(icmp_type: int, icmp_code: int) -> str:
    """
    Classify an ICMP response for firewall mapping.

    Returns a human-readable string describing the filter disposition.
    Type 3 (Destination Unreachable) codes 9, 10, 13 indicate a firewall.
    """
    if icmp_type != 3:
        return f"icmp-type-{icmp_type} (not a destination unreachable)"
    return _ICMP_TYPE3_LABELS.get(icmp_code, f"code-{icmp_code} (unclassified)")


def icmp_is_firewall(icmp_type: int, icmp_code: int) -> bool:
    """Return True if the ICMP response indicates a policy firewall."""
    return icmp_type == 3 and icmp_code in _ICMP_FILTER_CODES


# ---------------------------------------------------------------------------
# 3. RST Rate-Limit Detection
# ---------------------------------------------------------------------------

_DEFAULT_RST_PORTS = list(range(40000, 40020))   # 20 unlikely-open ports


def rst_rate_limit_check(
    ip: str,
    probe_ports: Optional[List[int]] = None,
    has_privileges: bool = True,
    timeout: float = 3.0,
    threshold: float = 0.8,
) -> Dict:
    """
    Detect TCP RST throttling by sending N SYNs and counting RST replies.

    A ratio < *threshold* means some RSTs were dropped, which indicates
    the target or an intermediate device is rate-limiting RST responses.
    Windows and Cisco IOS devices commonly do this.

    Returns::
        {
          "throttled": bool,
          "sent": int,
          "received": int,
          "ratio": float,
          "note": str
        }
    """
    if not has_privileges or not SCAPY_AVAILABLE:
        return {"throttled": False, "sent": 0, "received": 0, "ratio": 1.0,
                "note": "privileges unavailable"}

    ports = probe_ports or _DEFAULT_RST_PORTS
    n     = len(ports)

    try:
        pkts = [
            IP(dst=ip) / TCP(
                dport=port,
                flags="S",
                seq=random.randint(1, 2**31),
                window=1024,
            )
            for port in ports
        ]
        answered, _ = sr(pkts, timeout=timeout, verbose=0)

        rst_count = sum(
            1 for _, rcv in answered
            if rcv.haslayer(TCP) and rcv[TCP].flags & 0x04
        )

        ratio     = rst_count / n if n else 1.0
        throttled = ratio < threshold
        note = (
            f"RST throttling detected ({rst_count}/{n} RSTs received)"
            if throttled else
            f"Normal RST rate ({rst_count}/{n})"
        )

        return {
            "throttled": throttled,
            "sent":      n,
            "received":  rst_count,
            "ratio":     round(ratio, 3),
            "note":      note,
        }

    except Exception as exc:
        log.debug("rst_rate_limit_check(%s) error: %s", ip, exc)
        return {"throttled": False, "sent": 0, "received": 0, "ratio": 1.0,
                "note": str(exc)}


# ---------------------------------------------------------------------------
# 4. Master firewall detection — combines all three signals
# ---------------------------------------------------------------------------

def detect_firewall(
    ip: str,
    open_ports: Optional[List[int]] = None,
    has_privileges: bool = True,
) -> Dict:
    """
    Run all three firewall detection techniques and synthesise a verdict.

    Returns::
        {
          "ack_results":         {port: state, ...},
          "rst_throttled":       bool,
          "rst_detail":          {...},
          "filtered_count":      int,
          "unfiltered_count":    int,
          "firewall_confidence": "High" | "Medium" | "Low" | "None",
          "firewall_likely":     bool,
          "signals":             ["rst_throttled", "all_ports_filtered", ...]
        }
    """
    if not has_privileges or not SCAPY_AVAILABLE:
        return {
            "ack_results": {}, "rst_throttled": False, "rst_detail": {},
            "filtered_count": 0, "unfiltered_count": 0,
            "firewall_confidence": "None", "firewall_likely": False,
            "signals": [],
        }

    # ACK probe — try provided open ports + a handful of common ports
    probe_ports = list(set((open_ports or []) + _DEFAULT_ACK_PORTS))[:16]
    ack         = ack_probe(ip, probe_ports, has_privileges)

    # RST rate-limit check
    rst_detail  = rst_rate_limit_check(ip, has_privileges=has_privileges)

    filtered   = sum(1 for v in ack.values() if v == "filtered")
    unfiltered = sum(1 for v in ack.values() if v == "unfiltered")
    total      = len(ack) or 1

    signals: List[str] = []

    if rst_detail.get("throttled"):
        signals.append("rst_throttled")
    if filtered / total > 0.8:
        signals.append("all_ports_filtered")
    elif filtered / total > 0.5:
        signals.append("majority_ports_filtered")
    if filtered > 0 and unfiltered > 0:
        signals.append("mixed_filter_pattern")

    # Determine confidence
    n_signals = len(signals)
    if n_signals >= 2:
        confidence = "High"
    elif n_signals == 1:
        confidence = "Medium"
    elif filtered > 0:
        confidence = "Low"
    else:
        confidence = "None"

    return {
        "ack_results":         ack,
        "rst_throttled":       rst_detail.get("throttled", False),
        "rst_detail":          rst_detail,
        "filtered_count":      filtered,
        "unfiltered_count":    unfiltered,
        "firewall_confidence": confidence,
        "firewall_likely":     confidence in ("High", "Medium"),
        "signals":             signals,
    }
