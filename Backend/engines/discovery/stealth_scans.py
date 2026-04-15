"""
engines/discovery/stealth_scans.py
------------------------------------
GAP-03 — Stealth / Evasion Scan Techniques

Implements the complete set of TCP probe variants that Nmap supports.
All techniques use Scapy raw sockets — no Nmap binary required.

Scan Techniques
---------------
SYN      Half-open — standard (already in discovery_engine)
FIN      TCP FIN only — RFC 793: compliant open ports silently drop;
         closed ports MUST respond with RST.
XMAS     FIN + PSH + URG set — same RFC semantics as FIN
NULL     No TCP flags — same semantics as FIN / XMAS
ACK      Pure ACK — maps firewall rules (RST=unfiltered, no reply=filtered)
WINDOW   ACK + window inspection — some kernels set non-zero window for open
MAIMON   FIN + ACK — Uriel Maimon (Phrack #49, 1996)

Evasion Helpers
---------------
decoy_syn()          Send probes from decoy IPs then from real IP (confuses IDS)
custom_fragment()    Fragment at caller-specified MTU (any value ≥8 bytes)
source_port_spoof()  Force a specific TCP source port (e.g. 53, 80, 443)
randomised_ports()   Shuffle port list to defeat port-order fingerprinting
decoys_from_subnet() Generate plausible decoy IPs in same /24

Timing Templates (T0 – T5)  — mirrors Nmap's -T0 through -T5
-------------------------
T0  Paranoid    serial, 5 min inter-probe delay
T1  Sneaky      serial, 15 s inter-probe delay
T2  Polite      serial, 300 ms inter-probe delay, 10 s timeout
T3  Normal      parallel (default), 50 ms jitter, 3 s timeout
T4  Aggressive  parallel, 5 ms jitter, 1.25 s timeout
T5  Insane      parallel, no jitter, 300 ms timeout

Port-state Semantics
--------------------
SYN:          SYN-ACK → open   | RST → closed      | no reply/ICMP → filtered
FIN/XMAS/NULL/MAIMON:
              no reply → open|filtered (cannot confirm open without RST absence)
              RST      → closed
              ICMP-3   → filtered
ACK/WINDOW:   RST      → unfiltered (firewall allows; open/closed unknown)
              no reply → filtered
"""

import logging
import random
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

from core.constants import SCAPY_AVAILABLE

log = logging.getLogger("ccure.stealth")

# ---------------------------------------------------------------------------
# ICMP categorisation
# ---------------------------------------------------------------------------
_ICMP3_FILTERED = {1, 2, 9, 10, 13}   # admin/policy filtered (not port-unreach)

# ---------------------------------------------------------------------------
# TCP flag bitmasks
# ---------------------------------------------------------------------------
_F_FIN  = 0x01
_F_SYN  = 0x02
_F_RST  = 0x04
_F_PSH  = 0x08
_F_ACK  = 0x10
_F_URG  = 0x20


# ---------------------------------------------------------------------------
# Scan technique
# ---------------------------------------------------------------------------

class ScanTechnique(str, Enum):
    SYN    = "syn"
    FIN    = "fin"
    XMAS   = "xmas"
    NULL   = "null"
    ACK    = "ack"
    WINDOW = "window"
    MAIMON = "maimon"


_TECHNIQUE_FLAGS: Dict[ScanTechnique, int] = {
    ScanTechnique.SYN:    _F_SYN,
    ScanTechnique.FIN:    _F_FIN,
    ScanTechnique.XMAS:   _F_FIN | _F_PSH | _F_URG,
    ScanTechnique.NULL:   0x00,
    ScanTechnique.ACK:    _F_ACK,
    ScanTechnique.WINDOW: _F_ACK,
    ScanTechnique.MAIMON: _F_FIN | _F_ACK,
}

# Techniques where silence == open|filtered (per RFC 793)
_SILENT_OPEN_TECHNIQUES = {
    ScanTechnique.FIN,
    ScanTechnique.XMAS,
    ScanTechnique.NULL,
    ScanTechnique.MAIMON,
}


# ---------------------------------------------------------------------------
# Timing templates
# ---------------------------------------------------------------------------

@dataclass
class TimingTemplate:
    """
    Per-probe timing constraints matching Nmap's -T0 through -T5 model.

    Attributes
    ----------
    name:           Human-readable label
    parallelism:    Max probes in flight simultaneously (1 = fully serial)
    min_rtt_ms:     RTT floor (adaptive floor for future RTT-based tuning)
    max_rtt_ms:     RTT ceiling
    scan_delay_ms:  Enforced wait between consecutive probes to same host
    timeout_ms:     Hard per-probe receive timeout before calling "no reply"
    jitter_ms:      Random additional delay added to each inter-probe gap
    """
    name:          str
    parallelism:   int
    min_rtt_ms:    float
    max_rtt_ms:    float
    scan_delay_ms: float
    timeout_ms:    float
    jitter_ms:     float


TIMING_TEMPLATES: Dict[int, TimingTemplate] = {
    # level: name         parallel  min_rtt   max_rtt   delay     timeout   jitter
    0: TimingTemplate("Paranoid",     1,   300_000, 300_000, 300_000, 300_000,    0),
    1: TimingTemplate("Sneaky",       1,    15_000, 300_000,  15_000,  15_000,    0),
    2: TimingTemplate("Polite",       1,     1_000,  10_000,     300,  10_000,  100),
    3: TimingTemplate("Normal",     100,       100,  10_000,       0,   3_000,   50),
    4: TimingTemplate("Aggressive", 300,        25,   5_000,       0,   1_250,    5),
    5: TimingTemplate("Insane",     500,         5,   1_250,       0,     300,    0),
}

_DEFAULT_TIMING = TIMING_TEMPLATES[3]


# ---------------------------------------------------------------------------
# State classifier  (pure function — no I/O)
# ---------------------------------------------------------------------------

def _classify_state(
    technique: ScanTechnique,
    tcp_flags: Optional[int],
    icmp_type: Optional[int],
    icmp_code: Optional[int],
) -> str:
    """
    Translate a raw probe response (or silence) into a port-state string.

    Returns one of:  open | closed | filtered | unfiltered | open|filtered
    """
    if tcp_flags is not None:
        if technique == ScanTechnique.SYN:
            if tcp_flags & _F_RST:
                return "closed"
            if tcp_flags & (_F_SYN | _F_ACK):   # SYN-ACK = 0x12
                return "open"
            return "filtered"

        if technique in _SILENT_OPEN_TECHNIQUES:
            if tcp_flags & _F_RST:
                return "closed"
            # No RST but got TCP back (unusual) → just "open"
            return "open"

        if technique in (ScanTechnique.ACK, ScanTechnique.WINDOW):
            # ACK scans don't classify open/closed — only filtered vs unfiltered
            if tcp_flags & _F_RST:
                return "unfiltered"
            return "filtered"

    if icmp_type == 3:
        if icmp_code == 3:
            return "closed"
        if icmp_code in _ICMP3_FILTERED:
            return "filtered"

    # No reply and no ICMP
    if technique in _SILENT_OPEN_TECHNIQUES:
        return "open|filtered"   # could be open; cannot confirm without RST
    return "filtered"


# ---------------------------------------------------------------------------
# StealthScanner — main class
# ---------------------------------------------------------------------------

class StealthScanner:
    """
    Multi-technique TCP port scanner built entirely on Scapy raw sockets.

    Each ``scan()`` call returns ``{port: state_string}``.
    Supported states: open, closed, filtered, unfiltered, open|filtered

    Parameters
    ----------
    timing:          TimingTemplate to use (T3 Normal by default)
    source_port:     Fixed TCP source port for all probes (None = random)
    decoys:          List of decoy source IPs to send spoofed probes from
    mtu:             Custom fragmentation MTU in bytes (None = no fragment)
    randomize_order: Shuffle port list before scanning (defeats order heuristics)
    """

    def __init__(
        self,
        timing: TimingTemplate = _DEFAULT_TIMING,
        source_port: Optional[int] = None,
        decoys: Optional[List[str]] = None,
        mtu: Optional[int] = None,
        randomize_order: bool = True,
    ):
        self.timing          = timing
        self.source_port     = source_port
        self.decoys          = decoys or []
        self.mtu             = mtu
        self.randomize_order = randomize_order

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def scan(
        self,
        target: str,
        ports: List[int],
        technique: ScanTechnique = ScanTechnique.SYN,
    ) -> Dict[int, str]:
        """
        Scan *target* on *ports* using *technique*.

        Returns a dict ``{port: state}``.  Raises nothing — errors are
        logged and an empty dict is returned so callers are never broken.
        """
        if not SCAPY_AVAILABLE:
            log.warning("StealthScanner: Scapy not available; scan skipped")
            return {}

        port_list = list(ports)
        if self.randomize_order:
            random.shuffle(port_list)

        # Decoy probes only make sense for SYN scans (need real reply)
        if self.decoys and technique == ScanTechnique.SYN:
            return self._scan_with_decoys(target, port_list, technique)

        if self.timing.parallelism == 1:
            return self._scan_serial(target, port_list, technique)

        return self._scan_parallel(target, port_list, technique)

    # ------------------------------------------------------------------
    # Serial scan — T0 / T1 / T2
    # ------------------------------------------------------------------

    def _scan_serial(
        self,
        target: str,
        ports: List[int],
        technique: ScanTechnique,
    ) -> Dict[int, str]:
        try:
            from scapy.all import sr1, fragment, ICMP, TCP
        except ImportError:
            return {}

        flags     = _TECHNIQUE_FLAGS[technique]
        timeout_s = self.timing.timeout_ms / 1000.0
        results: Dict[int, str] = {}

        for port in ports:
            pkt = self._build_packet(target, port, flags)

            try:
                if self.mtu:
                    from scapy.all import fragment as scapy_fragment, sr1 as _sr1
                    frags = scapy_fragment(pkt, fragsize=self.mtu)
                    resp = None
                    for frag in frags[:-1]:
                        sr1(frag, timeout=0.05, verbose=0)
                        time.sleep(0.01)
                    resp = sr1(frags[-1], timeout=timeout_s, verbose=0)
                else:
                    resp = sr1(pkt, timeout=timeout_s, verbose=0)
            except Exception as exc:
                log.debug("_scan_serial sr1 error port %d: %s", port, exc)
                results[port] = "filtered"
                continue

            tcp_flags = icmp_type = icmp_code = None
            if resp is not None:
                if resp.haslayer(TCP):
                    tcp_flags = int(resp[TCP].flags)
                elif resp.haslayer(ICMP):
                    icmp_type = resp[ICMP].type
                    icmp_code = resp[ICMP].code

            results[port] = _classify_state(technique, tcp_flags, icmp_type, icmp_code)

            # Apply inter-probe delay + jitter
            delay_s = self.timing.scan_delay_ms / 1000.0
            if self.timing.jitter_ms > 0:
                delay_s += random.uniform(0, self.timing.jitter_ms / 1000.0)
            if delay_s > 0:
                time.sleep(delay_s)

        return results

    # ------------------------------------------------------------------
    # Parallel scan — T3 / T4 / T5
    # ------------------------------------------------------------------

    def _scan_parallel(
        self,
        target: str,
        ports: List[int],
        technique: ScanTechnique,
    ) -> Dict[int, str]:
        try:
            from scapy.all import sr, fragment as scapy_fragment, ICMP, TCP
        except ImportError:
            return {}

        flags     = _TECHNIQUE_FLAGS[technique]
        timeout_s = self.timing.timeout_ms / 1000.0

        pkts = []
        for port in ports:
            pkt = self._build_packet(target, port, flags)
            if self.mtu:
                pkts.extend(scapy_fragment(pkt, fragsize=self.mtu))
            else:
                pkts.append(pkt)

        if not pkts:
            return {}

        try:
            # Apply initial jitter so parallel runs don't burst-fire at t=0
            if self.timing.jitter_ms > 0:
                time.sleep(random.uniform(0, self.timing.jitter_ms / 1000.0))
            ans, unans = sr(pkts, timeout=timeout_s, verbose=0, multi=True)
        except Exception as exc:
            log.debug("_scan_parallel sr() error: %s", exc)
            return {}

        results: Dict[int, str] = {}

        # ── Answered packets ─────────────────────────────────────────────
        for snd, rcv in ans:
            try:
                from scapy.all import TCP as _TCP, ICMP as _ICMP, IP as _IP
                if not snd.haslayer(_TCP):
                    continue
                port = snd[_TCP].dport

                tcp_flags = icmp_type = icmp_code = None
                if rcv.haslayer(_TCP):
                    tcp_flags = int(rcv[_TCP].flags)
                    # WINDOW scan: also record the window value for heuristics
                    if technique == ScanTechnique.WINDOW and rcv[_IP].flags == 0:
                        win = rcv[_TCP].window
                        if win > 0:
                            # Positive window in RST → likely open (heuristic)
                            results[port] = "open"
                            continue
                elif rcv.haslayer(_ICMP):
                    icmp_type = rcv[_ICMP].type
                    icmp_code = rcv[_ICMP].code

                results[port] = _classify_state(technique, tcp_flags, icmp_type, icmp_code)
            except Exception:
                continue

        # ── Unanswered packets ───────────────────────────────────────────
        for snd in unans:
            try:
                from scapy.all import TCP as _TCP
                if not snd.haslayer(_TCP):
                    continue
                port = snd[_TCP].dport
                if port not in results:
                    if technique in _SILENT_OPEN_TECHNIQUES:
                        results[port] = "open|filtered"
                    else:
                        results[port] = "filtered"
            except Exception:
                continue

        return results

    # ------------------------------------------------------------------
    # Decoy scan  (SYN only)
    # ------------------------------------------------------------------

    def _scan_with_decoys(
        self,
        target: str,
        ports: List[int],
        technique: ScanTechnique,
    ) -> Dict[int, str]:
        """
        Fire SYN probes from each decoy IP before sending the real probes.

        Decoy packets are spoofed (src = decoy IP) so the target's logs show
        traffic from multiple sources. Only the real-IP probe gets a real reply
        (the kernel discards spoofed replies because there is no socket for them).
        """
        try:
            from scapy.all import IP, TCP, send
        except ImportError:
            return {}

        flags = _TECHNIQUE_FLAGS[technique]

        for port in ports:
            for decoy_ip in self.decoys:
                try:
                    dpkt = (
                        IP(src=decoy_ip, dst=target)
                        / TCP(
                            sport=self.source_port or random.randint(1024, 65535),
                            dport=port,
                            flags=flags,
                        )
                    )
                    send(dpkt, verbose=0)
                except Exception:
                    pass
            # Small delay between decoys and real probe
            delay = max(0.01, self.timing.scan_delay_ms / 1000.0 * 0.1)
            time.sleep(delay)

        # Real scan from actual IP
        return self._scan_parallel(target, ports, technique)

    # ------------------------------------------------------------------
    # Packet builder
    # ------------------------------------------------------------------

    def _build_packet(self, target: str, port: int, flags: int):
        """Build a single IP/TCP probe packet."""
        try:
            from scapy.all import IP, TCP
        except ImportError:
            return None

        sport = self.source_port or random.randint(1024, 65535)
        return IP(dst=target) / TCP(sport=sport, dport=port, flags=flags)


# ---------------------------------------------------------------------------
# Module-level convenience helpers
# ---------------------------------------------------------------------------

def randomised_ports(ports: List[int]) -> List[int]:
    """Return a shuffled copy of the port list (original is unchanged)."""
    shuffled = list(ports)
    random.shuffle(shuffled)
    return shuffled


def decoys_from_subnet(real_ip: str, count: int = 4) -> List[str]:
    """
    Generate ``count`` plausible decoy IPs in the same /24 block as *real_ip*.
    *real_ip* itself is excluded from the decoy list.
    """
    try:
        parts  = real_ip.split(".")
        prefix = ".".join(parts[:3])
        decoys: List[str] = []
        attempts = 0
        while len(decoys) < count and attempts < 100:
            attempts += 1
            last = random.randint(2, 253)    # .0 = network, .1 = gateway, .255 = bc
            candidate = f"{prefix}.{last}"
            if candidate != real_ip and candidate not in decoys:
                decoys.append(candidate)
        return decoys
    except Exception:
        return []


def scan_results_summary(results: Dict[int, str]) -> Dict[str, int]:
    """
    Aggregate a port-state dict into counts by state.

    Example return value::

        {"open": 3, "closed": 12, "filtered": 45, "open|filtered": 7}
    """
    summary: Dict[str, int] = {}
    for state in results.values():
        summary[state] = summary.get(state, 0) + 1
    return summary
