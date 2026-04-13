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
  {ip, is_active, mac, method, elapsed_ms, os_guess, os_confidence, confirmations}
"""

import asyncio
import ipaddress
import socket
import ssl
import time
from typing import Dict, List, Optional

from core.constants import SCAPY_AVAILABLE
from core.models import DiscoveryScanType
from core.risk import fingerprint_os

# Scapy symbols injected at runtime if available
if SCAPY_AVAILABLE:
    from scapy.all import (
        srp, sr, Ether, ARP, IP, ICMP, TCP, UDP, DNS, DNSQR, fragment,
    )


# =============================================================================
# Internal helpers
# =============================================================================

def _blank_result(ip: str) -> Dict:
    return {
        "ip":           ip,
        "is_active":    False,
        "mac":          "N/A",
        "method":       "N/A",
        "elapsed_ms":   None,
        "os_guess":     "Unknown",
        "os_confidence":"Low",
        "confirmations": [],
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

    def __init__(self, has_privileges: bool = False, stealth_mode: bool = False):
        self.has_privileges = has_privileges
        self.stealth_mode   = stealth_mode

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
                # Use ICMP for LAN OS fingerprinting (gets TTL for OS detection)
                self._scapy_icmp_probe(lan, results)
            if wan:
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
                    results[ip].update(
                        is_active=True, mac=rcv.hwsrc,
                        method="ARP",
                    )
                    results[ip]["confirmations"].append("ARP")
        except Exception:
            pass

    def _scapy_syn(self, ips: List[str], ports: List[int], results: Dict):
        try:
            pkts = IP(dst=ips) / TCP(dport=ports, flags="S")
            if self.stealth_mode:
                pkts = fragment(pkts)
            ans, _ = sr(pkts, timeout=1, verbose=0, multi=True)
            for snd, rcv in ans:
                if not rcv.haslayer(IP):
                    continue
                ip = rcv[IP].src
                self._set_elapsed_if_missing(results, ip, sent_pkt=snd, recv_pkt=rcv)
                if ip not in results or results[ip]["is_active"]:
                    continue
                ttl = rcv[IP].ttl
                win = rcv[TCP].window if rcv.haslayer(TCP) else None
                guess, conf = fingerprint_os(ttl, win)
                results[ip].update(
                    is_active=True, method="TCP SYN",
                    os_guess=guess, os_confidence=conf,
                )
        except Exception:
            pass

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
        except Exception:
            pass

    def _scapy_layered(self, batch: List[str], st: DiscoveryScanType, results: Dict):
        if st in (DiscoveryScanType.ARP, DiscoveryScanType.FULL):
            self._scapy_arp(batch, results)
        if st in (DiscoveryScanType.PING, DiscoveryScanType.FULL, DiscoveryScanType.STEALTH):
            try:
                pkts = [IP(dst=batch) / ICMP(type="echo-request")]
                if st == DiscoveryScanType.FULL:
                    pkts += [IP(dst=batch) / ICMP(type=13)]           # Timestamp
                    pkts += [IP(dst=batch) / TCP(dport=[22, 80, 443], flags="S")]
                    pkts += [IP(dst=batch) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="a.root-servers.net"))]
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
            except Exception:
                pass

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
        timeout = 1.5 if is_retry else 0.8
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
