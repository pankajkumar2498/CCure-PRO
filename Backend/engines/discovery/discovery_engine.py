"""
engines/discovery/discovery_engine.py
--------------------------------------
Phase 1 - Host Discovery

Supports all scan modes:
  * ARP      - L2 broadcast (needs root + scapy)
  * PING     - ICMP echo + timestamp (needs root + scapy)
  * TCP      - async TCP connect (works unprivileged)
  * FULL     - ARP + ICMP + TCP SYN + UDP (needs root + scapy)
  * ADAPTIVE - LAN->ARP, WAN->SYN, fallback->TCP connect
  * STEALTH  - fragmented packets, low TTL

Returns a list of dicts:
  {ip, is_active, mac, method, elapsed_ms, os_guess, os_confidence,
   confirmations, port_states, device_category, tcp_fingerprint,
   snmp_device_type, mdns_name, netbios_names, os_fingerprint_full}

Priority-1 improvements
------------------------
A. TCP RST / filtered-state detection  (_scapy_syn)
B. UDP ICMP-Unreachable detection      (_scapy_udp)
C. OUI -> Device Category mapping      (classify_mac via ARP)

Priority-2 improvements
------------------------
D. Expanded OS fingerprint + TCP options (_os_probe_full)
E. SNMP device classification            (_snmp_classify)
F. mDNS hostname resolution              (_mdns_query)
G. NetBIOS node status                   (_netbios_query)

Priority-3 improvements
------------------------
H. Multi-probe OS fingerprinting engine  (OSFingerprintEngine via _enrich_host)
I. Service probe database                (service_probe_engine.py / service_probes.json)
J. Adaptive timing engine                (AdaptiveTimer — drives all Scapy timeouts)
"""

import asyncio
import ipaddress
import logging
import socket
import ssl
import struct
import time
from typing import Dict, List, Optional

from core.constants import SCAPY_AVAILABLE
from core.models import DiscoveryScanType
from core.oui_lookup import classify_mac
from engines.discovery.enum_probe import ptr_lookup, mdns_services, nbstat_full   # GAP-09
from engines.discovery.firewall_detect import detect_firewall                     # GAP-10
from core.risk import fingerprint_os
from core.timing import AdaptiveTimer
from engines.discovery.stealth_scans import (
    StealthScanner, ScanTechnique, TIMING_TEMPLATES,
    randomised_ports, decoys_from_subnet,
)
from engines.discovery.l2_sniffer import sniff_l2_infrastructure

log = logging.getLogger("ccure.discovery")

# Scapy symbols injected at runtime if available
_SNMP_AVAILABLE = False
if SCAPY_AVAILABLE:
    from scapy.all import (
        srp, sr, sr1, Ether, ARP, IP, ICMP, TCP, UDP, DNS, DNSQR, fragment,
    )
    try:
        from scapy.all import SNMP, SNMPget, SNMPvarbind, ASN1_OID
        _SNMP_AVAILABLE = True
    except ImportError:
        pass

# ICMP type-3 codes that mean a port/host is *filtered* (admin/policy block)
_ICMP3_FILTERED_CODES = {1, 2, 9, 10, 13}

# SNMP OIDs used for device classification (Priority 2-E)
_SNMP_DEVICE_OIDS = {
    "ip_forwarding": "1.3.6.1.2.1.4.1.0",    # 1 = router, 2 = host
    "sys_obj_id":    "1.3.6.1.2.1.1.2.0",    # enterprise OID
    "bridge_mib":    "1.3.6.1.2.1.17.1.1.0", # Bridge-MIB → switch
}


# =============================================================================
# Internal helpers
# =============================================================================

def _blank_result(ip: str) -> Dict:
    return {
        "ip":                 ip,
        "is_active":          False,
        "mac":                "N/A",
        "method":             "N/A",
        "elapsed_ms":         None,
        "os_guess":           "Unknown",
        "os_confidence":      "Low",
        "confirmations":      [],
        # Priority-1
        "port_states":        {},     # {port: "open"|"closed"|"filtered"|"open|filtered"}
        "device_category":    "unknown",
        # Priority-2
        "tcp_fingerprint":    {},     # raw TCP option values from _os_probe_full
        "snmp_device_type":   None,   # "router" / "switch" / None
        "mdns_name":          None,   # mDNS PTR hostname
        "netbios_names":      [],     # [{name, flags}, ...]
        # Priority-3
        "os_fingerprint_full": {},   # multi-probe OS engine result
    }


# =============================================================================
# Discovery Engine
# =============================================================================

class DiscoveryEngine:
    """
    Run Phase 1 host discovery against a list of IPs.

    Usage::

        engine = DiscoveryEngine(has_privileges=False)
        results = engine.run(ip_list, scan_type=DiscoveryScanType.ADAPTIVE)
        # results -> List[dict] one entry per IP
    """

    def __init__(
        self,
        has_privileges:  bool = False,
        stealth_mode:    bool = False,
        timing_level:    int  = 3,
        scan_technique:  str  = "syn",
        decoy_count:     int  = 0,
        source_port:     Optional[int] = None,
        fragment_mtu:    Optional[int] = None,
        randomize_ports: bool = False,
    ):
        self.has_privileges  = has_privileges
        self.stealth_mode    = stealth_mode
        self.randomize_ports = randomize_ports or stealth_mode  # stealth implies randomize
        # GAP-03: Timing template — T0 (Paranoid) … T5 (Insane)
        self.timing = TIMING_TEMPLATES.get(timing_level, TIMING_TEMPLATES[3])
        # GAP-03: Scan technique for stealth host discovery
        try:
            self.scan_technique = ScanTechnique(scan_technique)
        except ValueError:
            self.scan_technique = ScanTechnique.SYN
        # GAP-03: Decoy / source-port / MTU evasion options
        self.decoy_count  = decoy_count
        self.source_port  = source_port
        self.fragment_mtu = fragment_mtu
        # Priority 3-J: adaptive timing per-scan instance
        self.timer = AdaptiveTimer()
        # Priority 3-H: multi-probe OS fingerprint engine (lazy import to
        # avoid loading Scapy at import time when it may not be needed)
        self._fp_engine = None

    def _get_fp_engine(self):
        """Lazy-load OSFingerprintEngine so Scapy isn't required at import."""
        if self._fp_engine is None:
            from engines.discovery.os_fingerprint import OSFingerprintEngine
            self._fp_engine = OSFingerprintEngine()
        return self._fp_engine

    @staticmethod
    def _capture_latency_ms(sent_pkt, recv_pkt) -> Optional[float]:
        """
        Best-effort latency extraction from Scapy packets.
        Returns None when timing info is unavailable.
        """
        try:
            send_time = getattr(sent_pkt, "sent_time", None) or getattr(sent_pkt, "time", None)
            recv_time = getattr(recv_pkt, "time", None)
            if send_time is None or recv_time is None:
                return None
            elapsed = (float(recv_time) - float(send_time)) * 1000.0
            if elapsed >= 0:
                return elapsed
        except Exception:
            return None
        return None

    @staticmethod
    def _set_elapsed_if_missing(
        results: Dict,
        ip: str,
        *,
        sent_pkt=None,
        recv_pkt=None,
        fallback_ms: Optional[float] = None,
    ) -> None:
        host = results.get(ip)
        if not host or host.get("elapsed_ms") is not None:
            return
        elapsed = DiscoveryEngine._capture_latency_ms(sent_pkt, recv_pkt)
        if elapsed is None:
            elapsed = fallback_ms
        if elapsed is not None:
            host["elapsed_ms"] = elapsed
            # Priority 3-J: feed RTT sample into adaptive timer
            self.timer.record_rtt(elapsed)

    # ------------------------------------------------------------------
    # Public entry
    # ------------------------------------------------------------------
    async def run(
        self,
        ip_list:   List[str],
        scan_type: DiscoveryScanType = DiscoveryScanType.ADAPTIVE,
    ) -> List[Dict]:
        results: Dict[str, Dict] = {ip: _blank_result(ip) for ip in ip_list}

        BATCH = 50
        for i in range(0, len(ip_list), BATCH):
            batch = ip_list[i:i + BATCH]
            await self._phase1(batch, scan_type, results)

        # Priority 2: enrich every active host concurrently
        if self.has_privileges and SCAPY_AVAILABLE:
            active = [ip for ip, r in results.items() if r["is_active"]]
            if active:
                await asyncio.gather(*[self._enrich_host(ip, results[ip]) for ip in active])

        return list(results.values())

    # ------------------------------------------------------------------
    # Phase 1 dispatch
    # ------------------------------------------------------------------
    async def _phase1(self, batch: List[str], st: DiscoveryScanType, results: Dict):
        if st == DiscoveryScanType.ADAPTIVE:
            await self._run_adaptive(batch, results)
            return

        can_raw = self.has_privileges and SCAPY_AVAILABLE
        if can_raw and st != DiscoveryScanType.TCP:
            self._scapy_layered(batch, st, results)

        if st in (DiscoveryScanType.TCP, DiscoveryScanType.FULL):
            await self._async_tcp(batch, [22, 80, 443], results)

        # ── TCP fallback for PING and STEALTH ────────────────────────────
        # ICMP and fragmented packets are almost always blocked by host firewalls
        # (Windows Defender, iptables DROP rules). Without a fallback, any host
        # that blocks ICMP appears permanently Inactive even though TCP ports are
        # wide open. Fix: after the raw-packet attempt, retry any still-inactive
        # host via TCP connect on the most common ports.
        if st in (DiscoveryScanType.PING, DiscoveryScanType.STEALTH):
            still_down = [ip for ip in batch if not results[ip]["is_active"]]
            if still_down:
                await self._async_tcp(
                    still_down,
                    [22, 80, 443, 445, 3389, 8080, 135, 139, 3306, 8443],
                    results,
                    is_retry=True,
                )

    async def _run_adaptive(self, batch: List[str], results: Dict):
        lan = [ip for ip in batch if ipaddress.ip_address(ip).is_private]
        wan = [ip for ip in batch if not ipaddress.ip_address(ip).is_private]

        if not self.has_privileges or not SCAPY_AVAILABLE:
            await self._async_tcp(batch, [22, 80, 443], results)
        else:
            if lan:
                self._scapy_arp(lan, results)
                # Parse CDP/LLDP/STP for enhanced switch detection
                self._enrich_via_l2_sniffer(results)
                # ICMP for LAN OS fingerprinting (gets TTL)
                self._scapy_icmp_probe(lan, results)
                # Priority 1-B: UDP scan for common LAN services
                self._scapy_udp(lan, [53, 67, 123, 161, 500, 1900], results)
            if wan:
                # Priority 1-A: SYN scan with RST/filtered detection
                self._scapy_syn(wan, [22, 80, 443], results)

        # Retry unreachable hosts with wider port list
        blocked = [ip for ip in batch if not results[ip]["is_active"]]
        if blocked:
            await self._async_tcp(
                blocked,
                [21, 23, 53, 111, 135, 139, 443, 445, 3389, 8080, 8443],
                results,
                is_retry=True,
            )

    # ------------------------------------------------------------------
    # Scapy methods
    # ------------------------------------------------------------------
    def _scapy_arp(self, ips: List[str], results: Dict):
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ips),
                timeout=0.5, verbose=0,
            )
            for snd, rcv in ans:
                ip = rcv.psrc
                self._set_elapsed_if_missing(results, ip, sent_pkt=snd, recv_pkt=rcv)
                if ip in results and not results[ip]["is_active"]:
                    mac = rcv.hwsrc
                    # Priority 1-C: classify device type from OUI
                    device_cat = classify_mac(mac)
                    results[ip].update(
                        is_active=True,
                        mac=mac,
                        method="ARP",
                        device_category=device_cat,
                    )
                    results[ip]["confirmations"].append("ARP")
        except Exception as exc:
            log.debug("_scapy_arp error: %s", exc)

    def _enrich_via_l2_sniffer(self, results: Dict):
        """Passively sniffs for CDP, LLDP, STP and updates matching MACs."""
        try:
            # Only wait 3 seconds max to not stall the primary discovery pipeline
            l2_devices = sniff_l2_infrastructure(timeout=3.0)
            
            # Map discovered properties back to any IP sharing that MAC
            for l2_dev in l2_devices:
                mac_target = l2_dev["mac"].lower()
                for ip, host in results.items():
                    if host.get("mac", "").lower() == mac_target:
                        cat = l2_dev.get("device_category")
                        if cat and cat != "unknown":
                            host["device_category"] = cat
                        if l2_dev.get("hostname"):
                            host["hostname"] = l2_dev["hostname"]
                        
                        # Store extracted protocols in confirmations or a new field
                        if l2_dev.get("protocols"):
                            for proto in l2_dev["protocols"]:
                                host["confirmations"].append(f"L2:{proto}")
        except Exception as exc:
            log.debug("_enrich_via_l2_sniffer error: %s", exc)

    def _scapy_syn(self, ips: List[str], ports: List[int], results: Dict):
        """
        Priority 1-A: TCP SYN scan with RST / filtered-state detection.

        GAP-03: When stealth_mode is True, delegates to _scapy_stealth_scan()
        which uses the configured scan technique (FIN/XMAS/NULL/ACK/MAIMON)
        and applies timing-template delays, decoy probes, and randomized
        port ordering.  When stealth_mode is False, uses the fast batch sr()
        path for performance.

        Outcomes per response (SYN path)
        ---------------------------------
        SYN-ACK (flags & 0x12)  -> port open   -> host marked active
        RST     (flags & 0x04)  -> port closed  -> proves host exists
        ICMP type 3             -> port filtered
        No reply (unans)        -> port filtered (stealth firewall)
        """
        # GAP-03: Stealth mode → use full evasion technique instead of raw SYN
        if self.stealth_mode and self.has_privileges and SCAPY_AVAILABLE:
            self._scapy_stealth_scan(ips, ports, results)
            return

        try:
            port_list = randomised_ports(ports) if self.randomize_ports else ports
            pkts = IP(dst=ips) / TCP(dport=port_list, flags="S")
            # GAP-03: Custom MTU fragmentation when configured
            if self.fragment_mtu:
                pkts = fragment(pkts, fragsize=self.fragment_mtu)
            elif self.stealth_mode:
                pkts = fragment(pkts)   # default Scapy fragment size (~576 B)
            # Priority 3-J: use adaptive timeout
            ans, unans = sr(pkts, timeout=self.timer.timeout, verbose=0, multi=True)

            for snd, rcv in ans:
                if not rcv.haslayer(IP):
                    continue
                ip  = rcv[IP].src
                if ip not in results:
                    continue
                self._set_elapsed_if_missing(results, ip, sent_pkt=snd, recv_pkt=rcv)

                # ── TCP response ────────────────────────────────────────────
                if rcv.haslayer(TCP):
                    flags = rcv[TCP].flags
                    sport = rcv[TCP].sport
                    if flags & 0x12:  # SYN-ACK → open
                        results[ip]["port_states"][sport] = "open"
                        if not results[ip]["is_active"]:
                            ttl  = rcv[IP].ttl
                            win  = rcv[TCP].window
                            # Priority 2-D: extract TCP options for richer fingerprint
                            opts_raw = dict(rcv[TCP].options) if rcv[TCP].options else {}
                            tcp_opts = {
                                "mss":     opts_raw.get("MSS"),
                                "wscale":  opts_raw.get("WScale"),
                                "sack_ok": "SAckOK" in opts_raw,
                                "ts_val":  (opts_raw.get("Timestamp") or (None,))[0],
                                "df_bit":  bool(rcv[IP].flags & 0x02),
                                "window":  win,
                            }
                            guess, conf = fingerprint_os(ttl, win, tcp_opts)
                            results[ip].update(
                                is_active=True, method="TCP SYN",
                                os_guess=guess, os_confidence=conf,
                                tcp_fingerprint=tcp_opts,
                            )
                            results[ip]["confirmations"].append(f"SYN-ACK:{sport}")
                    elif flags & 0x04:  # RST → closed (NOT filtered)
                        results[ip]["port_states"][sport] = "closed"
                        # A RST proves the host exists; mark active if not known
                        if not results[ip]["is_active"]:
                            results[ip].update(
                                is_active=True, method="TCP RST",
                            )
                            results[ip]["confirmations"].append(f"RST:{sport}")

                # ── ICMP type 3 → port/host filtered ────────────────────────
                elif rcv.haslayer(ICMP) and rcv[ICMP].type == 3:
                    orig_port = None
                    if rcv.haslayer(TCP):
                        orig_port = rcv[TCP].dport
                    elif snd.haslayer(TCP):
                        orig_port = snd[TCP].dport
                    if orig_port is not None:
                        results[ip]["port_states"][orig_port] = "filtered"

            # ── Unanswered packets → filtered (stealth drop) ─────────────
            for snd in unans:
                if not snd.haslayer(IP) or not snd.haslayer(TCP):
                    continue
                ip   = snd[IP].dst
                port = snd[TCP].dport
                if ip in results:
                    results[ip]["port_states"].setdefault(port, "filtered")

        except Exception as exc:
            log.debug("_scapy_syn error: %s", exc)

    def _scapy_stealth_scan(self, ips: List[str], ports: List[int], results: Dict):
        """
        GAP-03: Full evasion scan using StealthScanner.

        Uses self.scan_technique (FIN/XMAS/NULL/ACK/WINDOW/MAIMON/SYN)
        with timing-template delays, optional decoy probes,
        optional source-port spoofing, and randomized port ordering.

        State mapping for host-liveness:
          open | closed | unfiltered → host confirmed active
          open|filtered              → host likely active (record tentatively)
          filtered                   → no evidence of host
        """
        try:
            decoys = (
                decoys_from_subnet(ips[0], self.decoy_count)
                if self.decoy_count and ips
                else []
            )
            scanner = StealthScanner(
                timing=self.timing,
                source_port=self.source_port,
                decoys=decoys,
                mtu=self.fragment_mtu,
                randomize_order=True,
            )

            technique = self.scan_technique
            method_label = f"{technique.value.upper()} Stealth"

            # Probe a small port set per IP for liveness check
            probe_ports = list(ports[:10]) if len(ports) > 10 else list(ports)

            for ip in ips:
                if ip not in results:
                    continue
                try:
                    port_states = scanner.scan(ip, probe_ports, technique)
                except Exception as exc:
                    log.debug("_scapy_stealth_scan scan(%s): %s", ip, exc)
                    continue

                for port, state in port_states.items():
                    results[ip]["port_states"][port] = state

                    # Any non-filtered state is evidence the host exists
                    if state in ("open", "closed", "unfiltered"):
                        if not results[ip]["is_active"]:
                            results[ip].update(
                                is_active=True,
                                method=method_label,
                            )
                        results[ip]["confirmations"].append(
                            f"{technique.value.upper()}:{port}:{state}"
                        )

                    elif state == "open|filtered":
                        # Likely active but not confirmed — record tentatively
                        if not results[ip]["is_active"]:
                            results[ip]["confirmations"].append(
                                f"{technique.value.upper()}:{port}:open|filtered"
                            )

        except Exception as exc:
            log.debug("_scapy_stealth_scan error: %s", exc)

    def _scapy_udp(self, ips: List[str], ports: List[int], results: Dict):
        """
        Priority 1-B: UDP scan with ICMP-Unreachable decoding.

        Uses Scapy sr() so ICMP error messages generated by the target's
        kernel are matched back to the originating UDP probe.

        Outcomes per response
        ---------------------
        ICMP type 3, code 3          -> port closed
        ICMP type 3, code 1/2/9/10/13-> port filtered
        UDP reply                    -> port open (service responded)
        No reply                     -> "open|filtered"  (ambiguous)
        """
        try:
            pkts = [
                IP(dst=ip) / UDP(dport=port)
                for ip in ips
                for port in ports
            ]
            if not pkts:
                return
            # Priority 3-J: UDP needs longer timeout for ICMP-unreachable replies
            udp_timeout = max(self.timer.timeout, 2.0)
            ans, unans = sr(pkts, timeout=udp_timeout, verbose=0, multi=True)

            for snd, rcv in ans:
                if not snd.haslayer(IP) or not snd.haslayer(UDP):
                    continue
                ip   = snd[IP].dst
                port = snd[UDP].dport
                if ip not in results:
                    continue
                self._set_elapsed_if_missing(results, ip, sent_pkt=snd, recv_pkt=rcv)

                if rcv.haslayer(ICMP) and rcv[ICMP].type == 3:
                    code = rcv[ICMP].code
                    if code == 3:  # Port Unreachable -> closed
                        results[ip]["port_states"][port] = "closed"
                    elif code in _ICMP3_FILTERED_CODES:
                        results[ip]["port_states"][port] = "filtered"
                    # other ICMP-3 codes: leave as-is

                elif rcv.haslayer(UDP):  # Real UDP reply -> open
                    results[ip]["port_states"][port] = "open"
                    if not results[ip]["is_active"]:
                        results[ip].update(
                            is_active=True,
                            method="UDP",
                        )
                        results[ip]["confirmations"].append(f"UDP:{port}")

            # Unanswered UDP probes -> open|filtered (no ICMP back, firewall may be dropping)
            for snd in unans:
                if not snd.haslayer(IP) or not snd.haslayer(UDP):
                    continue
                ip   = snd[IP].dst
                port = snd[UDP].dport
                if ip in results:
                    results[ip]["port_states"].setdefault(port, "open|filtered")

        except Exception as exc:
            log.debug("_scapy_udp error: %s", exc)

    # ------------------------------------------------------------------
    # Priority 2-D: Full TCP options OS probe
    # ------------------------------------------------------------------
    @staticmethod
    def _os_probe_full(ip: str) -> Dict:
        """
        Send a crafted SYN with a full TCP option set to read the server's
        MSS, WScale, SAckOK, Timestamp, and DF-bit from its SYN-ACK.

        Returns a dict suitable for passing to fingerprint_os(tcp_opts=...).
        Returns {} when the host does not respond or Scapy is unavailable.
        """
        if not SCAPY_AVAILABLE:
            return {}
        try:
            pkt = IP(dst=ip) / TCP(
                dport=80, flags="S",
                options=[
                    ("MSS",       1460),
                    ("NOP",       None),
                    ("WScale",    6),
                    ("NOP",       None),
                    ("NOP",       None),
                    ("SAckOK",    ""),
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
                return {
                    "ttl":     rcv[IP].ttl,
                    "window":  rcv[TCP].window,
                    "mss":     opts.get("MSS"),
                    "wscale":  opts.get("WScale"),
                    "sack_ok": "SAckOK" in opts,
                    "ts_val":  ts[0] if isinstance(ts, (tuple, list)) else None,
                    "df_bit":  bool(rcv[IP].flags & 0x02),
                    "ihl":     rcv[IP].ihl,
                }
        except Exception as exc:
            log.debug("_os_probe_full(%s) error: %s", ip, exc)
        return {}

    # ------------------------------------------------------------------
    # Priority 2-E: SNMP device classification
    # ------------------------------------------------------------------
    @staticmethod
    def _snmp_classify(ip: str, community: str = "public") -> Optional[str]:
        """
        Query three SNMP OIDs to classify the device as 'router', 'switch',
        or None (no SNMP or unrecognised).

        Uses Scapy SNMP so it works without net-snmp binaries.
        Returns None when SNMP is unavailable or unreachable.
        """
        if not _SNMP_AVAILABLE:
            return None
        for name, oid in _SNMP_DEVICE_OIDS.items():
            try:
                pkt = IP(dst=ip) / UDP(dport=161) / SNMP(
                    community=community,
                    PDU=SNMPget(
                        varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))]
                    ),
                )
                resp = sr1(pkt, timeout=2, verbose=0)
                if resp is None or not resp.haslayer(SNMP):
                    continue
                val = str(resp[SNMP].PDU.varbindlist[0].value)
                if name == "ip_forwarding" and val.strip() == "1":
                    return "router"
                if name == "bridge_mib":
                    return "switch"
                # sys_obj_id: could map to known enterprise OIDs later
            except Exception as exc:
                log.debug("_snmp_classify(%s) OID %s error: %s", ip, name, exc)
        return None

    # ------------------------------------------------------------------
    # Priority 2-F: mDNS hostname resolution
    # ------------------------------------------------------------------
    @staticmethod
    def _mdns_query(ip: str) -> Optional[str]:
        """
        Send a unicast mDNS PTR query directly to the target IP to resolve
        its .local hostname without joining the multicast group.

        Returns the first PTR name found, or None.
        """
        if not SCAPY_AVAILABLE:
            return None
        try:
            # Reverse DNS label for PTR: e.g. 192.168.1.5 -> 5.1.168.192.in-addr.arpa
            rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa."
            pkt = IP(dst=ip) / UDP(dport=5353) / DNS(
                rd=0, qd=DNSQR(qname=rev, qtype="PTR"),
            )
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp and resp.haslayer(DNS) and resp[DNS].ancount > 0:
                name = resp[DNS].an.rrname
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                return name.rstrip(".")
        except Exception as exc:
            log.debug("_mdns_query(%s) error: %s", ip, exc)
        return None

    # ------------------------------------------------------------------
    # Priority 2-G: NetBIOS node status
    # ------------------------------------------------------------------
    @staticmethod
    def _netbios_query(ip: str) -> List[Dict]:
        """
        Send a raw NetBIOS node-status request (UDP 137) and parse the
        name table from the response.

        Returns a list of {name, flags} dicts, or [] on failure.
        """
        # Standard NetBIOS node-status payload
        _NB_PAYLOAD = (
            b"\xa2\x48\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41"
            b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
            b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            sock.sendto(_NB_PAYLOAD, (ip, 137))
            data, _ = sock.recvfrom(1024)
            sock.close()

            if len(data) < 57:
                return []

            num_names = data[56]
            names: List[Dict] = []
            for i in range(num_names):
                offset = 57 + i * 18
                if offset + 18 > len(data):
                    break
                raw_name = data[offset:offset + 15]
                flags    = struct.unpack(">H", data[offset + 16:offset + 18])[0]
                name     = raw_name.decode("ascii", errors="ignore").strip()
                if name:
                    names.append({"name": name, "flags": flags})
            return names
        except Exception as exc:
            log.debug("_netbios_query(%s) error: %s", ip, exc)
            return []

    # ------------------------------------------------------------------
    # Priority 2 orchestrator: enrich a single active host
    # ------------------------------------------------------------------
    async def _enrich_host(self, ip: str, result: Dict) -> None:
        """
        Run all Priority-2 enrichment probes for one active host.
        Executes in an asyncio thread-pool so blocking Scapy calls
        don't stall the event loop.
        """
        loop = asyncio.get_event_loop()

        # D: Full TCP options fingerprint — refines OS guess
        def _do_os_probe():
            tcp_fp = self._os_probe_full(ip)
            if tcp_fp and result.get("os_confidence", "Low") != "High":
                ttl  = tcp_fp.get("ttl") or 64
                win  = tcp_fp.get("window")
                g, c = fingerprint_os(ttl, win, tcp_fp)
                result["tcp_fingerprint"]  = tcp_fp
                result["os_guess"]         = g
                result["os_confidence"]    = c

        # E: SNMP device type — may override OUI category
        def _do_snmp():
            dev = self._snmp_classify(ip)
            if dev:
                result["snmp_device_type"] = dev
                # Let SNMP trump OUI for device_category when more specific
                if result.get("device_category") == "unknown":
                    result["device_category"] = dev

        # F: PTR reverse DNS (GAP-09)
        def _do_ptr():
            hostname = ptr_lookup(ip)
            if hostname:
                result.setdefault("ptr_hostname", hostname)
                # Upgrade hostname if it was unknown
                if not result.get("hostname") or result["hostname"] == "Unknown":
                    result["hostname"] = hostname

        # G: mDNS service discovery — unicast DNS-SD (GAP-09)
        def _do_mdns_services():
            # Legacy mDNS PTR query still useful on some platforms
            legacy_name = self._mdns_query(ip)
            if legacy_name:
                result["mdns_name"] = legacy_name
            # Full service discovery
            svc_data = mdns_services(ip)
            if svc_data.get("hostname") or svc_data.get("services"):
                result["mdns_services"] = svc_data.get("services", [])
                if svc_data.get("hostname") and not result.get("mdns_name"):
                    result["mdns_name"] = svc_data["hostname"]

        # H: NetBIOS NBSTAT — enhanced full name table (GAP-09)
        def _do_netbios():
            # Enhanced: full name table with computer name, workgroup, MAC
            nb = nbstat_full(ip)
            if nb.get("names"):
                result["netbios_names"]    = nb["names"]
                result["netbios_computer"] = nb.get("computer_name", "")
                result["netbios_workgroup"]= nb.get("workgroup", "")
                # Use NetBIOS MAC if ARP didn't capture it
                if nb.get("mac") and not result.get("mac"):
                    result["mac"] = nb["mac"]
                # Use NetBIOS hostname as hostname if not already resolved
                if nb.get("computer_name") and (
                    not result.get("hostname") or result["hostname"] == "Unknown"
                ):
                    result["hostname"] = nb["computer_name"]

        # I: Firewall / filter detection — ACK probe + RST rate-limit (GAP-10)
        def _do_firewall_detect():
            if not self.has_privileges or not SCAPY_AVAILABLE:
                return
            open_ports = [
                int(p) for p in result.get("port_states", {})
                if result["port_states"][p] == "open"
            ]
            fw = detect_firewall(ip, open_ports, has_privileges=True)
            if fw.get("firewall_confidence") != "None":
                result["firewall_info"] = fw
                # Surface a simple flag on the host for the UI
                result["firewall_likely"]      = fw["firewall_likely"]
                result["firewall_confidence"]  = fw["firewall_confidence"]

        # J: Multi-probe OS fingerprint engine (Priority 3-H)
        def _do_full_os_fingerprint():
            if not SCAPY_AVAILABLE:
                return
            open_ports = [
                p for p, state in result.get("port_states", {}).items()
                if state == "open"
            ]
            open_port   = open_ports[0]  if open_ports  else 80
            closed_port = 33333

            fp = self._get_fp_engine().probe(ip, open_port=open_port, closed_port=closed_port)
            result["os_fingerprint_full"] = fp

            _CONF_RANK = {"High": 3, "Medium": 2, "Low": 1}
            current_rank = _CONF_RANK.get(result.get("os_confidence", "Low"), 1)
            new_rank     = _CONF_RANK.get(fp.get("confidence", "Low"), 1)
            if new_rank > current_rank and fp.get("os", "Unknown") != "Unknown":
                result["os_guess"]      = fp["os"]
                result["os_confidence"] = fp["confidence"]

        for fn in (
            _do_os_probe, _do_snmp,
            _do_ptr, _do_mdns_services, _do_netbios,   # GAP-09
            _do_firewall_detect,                        # GAP-10
            _do_full_os_fingerprint,
        ):
            try:
                await loop.run_in_executor(None, fn)
            except Exception as exc:
                log.debug("_enrich_host(%s) %s error: %s", ip, fn.__name__, exc)

    def _scapy_icmp_probe(self, ips: List[str], results: Dict):
        """Send ICMP echo probes to capture TTL for OS fingerprinting."""
        try:
            pkts = IP(dst=ips) / ICMP(type="echo-request")
            ans, _ = sr(pkts, timeout=1, verbose=0, multi=True)
            for snd, rcv in ans:
                if not rcv.haslayer(IP):
                    continue
                ip = rcv[IP].src
                if ip not in results:
                    continue
                self._set_elapsed_if_missing(results, ip, sent_pkt=snd, recv_pkt=rcv)
                ttl = rcv[IP].ttl
                # Only update OS if not already set by ARP (which doesn't get TTL)
                if results[ip]["os_guess"] == "Unknown":
                    guess, conf = fingerprint_os(ttl, None)  # no TCP window from ICMP
                    results[ip].update(
                        is_active=True, method="ICMP",
                        os_guess=guess, os_confidence=conf,
                    )
                    results[ip]["confirmations"].append("ICMP")
        except Exception as exc:
            log.debug("_scapy_icmp_probe error: %s", exc)

    def _scapy_layered(self, batch: List[str], st: DiscoveryScanType, results: Dict):
        if st in (DiscoveryScanType.ARP, DiscoveryScanType.FULL):
            self._scapy_arp(batch, results)
        if st in (DiscoveryScanType.PING, DiscoveryScanType.FULL, DiscoveryScanType.STEALTH):
            try:
                pkts = [IP(dst=batch) / ICMP(type="echo-request")]
                if st == DiscoveryScanType.FULL:
                    pkts += [IP(dst=batch) / ICMP(type=13)]             # Timestamp
                    pkts += [IP(dst=batch) / TCP(dport=[22, 80, 443], flags="S")]
                    # UDP DNS probe handled separately for ICMP-unreachable decoding
                if self.stealth_mode:
                    pkts = [fragment(p) for p in pkts]
                ans, _ = sr(pkts, timeout=1, verbose=0, multi=True)
                for snd, rcv in ans:
                    if not rcv.haslayer(IP):
                        continue
                    ip = rcv[IP].src
                    if ip not in results:
                        continue
                    self._set_elapsed_if_missing(results, ip, sent_pkt=snd, recv_pkt=rcv)
                    ttl  = rcv[IP].ttl
                    win  = rcv[TCP].window if rcv.haslayer(TCP) else None
                    g, c = fingerprint_os(ttl, win)
                    if results[ip]["os_guess"] == "Unknown":
                        results[ip]["os_guess"]      = g
                        results[ip]["os_confidence"] = c
                    method = (
                        "ICMP"      if rcv.haslayer(ICMP) else
                        "TCP Probe" if rcv.haslayer(TCP)  else "UDP Probe"
                    )
                    results[ip]["is_active"] = True
                    results[ip]["method"]    = method
                    if method not in results[ip]["confirmations"]:
                        results[ip]["confirmations"].append(method)
            except Exception as exc:
                log.debug("_scapy_layered ICMP/TCP error: %s", exc)

        # Priority 1-B: run proper UDP scan for FULL mode
        if st == DiscoveryScanType.FULL:
            self._scapy_udp(batch, [53, 67, 123, 161, 500, 1900], results)

    # ------------------------------------------------------------------
    # Async TCP connect (works without root)
    # ------------------------------------------------------------------
    async def _async_tcp(
        self,
        ips:      List[str],
        ports:    List[int],
        results:  Dict,
        is_retry: bool = False,
    ):
        # Priority 3-J: use adaptive timeout, floor at 0.8 s for first pass
        timeout = self.timer.timeout if is_retry else max(self.timer.timeout, 0.8)
        sem     = asyncio.Semaphore(50)

        async def probe(ip: str, port: int):
            async with sem:
                try:
                    t0 = time.time()
                    use_tls = port in (443, 8443, 465, 993, 995)
                    if use_tls:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode    = ssl.CERT_NONE
                        conn = asyncio.open_connection(ip, port, ssl=ctx)
                    else:
                        conn = asyncio.open_connection(ip, port)
                    _, writer = await asyncio.wait_for(conn, timeout=timeout)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    elapsed = (time.time() - t0) * 1000
                    # Priority 3-J: record RTT for adaptive timing
                    self.timer.record_rtt(elapsed)
                    if not results[ip]["is_active"]:
                        results[ip].update(
                            is_active=True,
                            method=f"TCP Connect{'(retry)' if is_retry else ''}",
                            elapsed_ms=elapsed,
                        )
                        results[ip]["confirmations"].append(f"TCP:{port}")
                except Exception:
                    pass

        tasks = [probe(ip, port) for ip in ips for port in ports]
        await asyncio.gather(*tasks)
