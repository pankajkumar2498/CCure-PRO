"""
core/discovery/engine.py
────────────────────────────────────────────────────────────────────────────
Host Discovery Engine — Scapy Only

This is the SINGLE host discovery engine used by ALL scan modules.
It accepts a DiscoveryProfile that controls which techniques to run,
making it independently configurable per pipeline stage without changing logic.

Architecture contract:
  ✅ Scapy ONLY in this engine (ARP, ICMP, TCP SYN, UDP)
  ✅ All three modules (Basic, Asset, Advanced) use THIS engine with
     different profiles (FAST, BALANCED, AGGRESSIVE)
  ❌ No Nmap calls here — Nmap lives in core/nmap/wrapper.py (Phase 2+3)
  ❌ No port scanning here — Phase 2 concern

Usage::

    from core.discovery.engine import DiscoveryEngine
    from core.discovery.profiles import FAST, BALANCED, AGGRESSIVE

    # Basic Scan (Phase 1 only)
    engine = DiscoveryEngine(profile=FAST, has_privileges=True)
    hosts  = await engine.run(["192.168.1.0/24"])

    # Asset Discovery (Phase 1 of a 1+2 pipeline)
    engine = DiscoveryEngine(profile=BALANCED, has_privileges=True)
    hosts  = await engine.run(["192.168.1.0/24"])

    # Advanced Scan (Phase 1 of a 1+2+3 pipeline)
    engine = DiscoveryEngine(profile=AGGRESSIVE, has_privileges=True)
    hosts  = await engine.run(["192.168.1.0/24"])

Returns::

    List[DiscoveryResult] — one entry per IP probed.
    Only the ip/is_active/mac/method/confirmations fields are populated here.
    Hostname/vendor/OS fields are filled by the orchestrator after this engine
    returns (from Nmap in Phase 2+3 or the enrichment module in AGGRESSIVE mode).
"""

import asyncio
import ipaddress
import logging
import time
from typing import Dict, List, Optional

from core.constants import SCAPY_AVAILABLE
from core.discovery.profiles import DiscoveryProfile, BALANCED, Technique
from core.discovery.techniques import arp, icmp, tcp_syn, tcp_conn, udp_probe, nbns

log = logging.getLogger("ccure.discovery.engine")


# ─────────────────────────────────────────────────────────────────────────────
# Result Model
# ─────────────────────────────────────────────────────────────────────────────

def _blank_result(ip: str) -> Dict:
    """Return an empty host result dict for one IP."""
    return {
        "ip":                 ip,
        "ip_address":         ip,   # alias used by HostResult / orchestrator
        "is_active":          False,
        "mac":                "N/A",
        "method":             "N/A",
        "elapsed_ms":         None,
        "confirmations":      [],
        # These are enriched in later phases / enrichment step:
        "os_guess":           "Unknown",
        "os_confidence":      "Low",
        "port_states":        {},
        "device_category":    "unknown",
        "tcp_fingerprint":    {},
        "snmp_device_type":   None,
        "mdns_name":          None,
        "netbios_names":      [],
        "os_fingerprint_full": {},
    }


# ─────────────────────────────────────────────────────────────────────────────
# Batch sizing (matches existing production logic)
# ─────────────────────────────────────────────────────────────────────────────

def _batch_size(total: int) -> int:
    if total <= 20:   return total
    if total <= 100:  return 50
    if total <= 254:  return 128
    if total <= 510:  return 256
    if total <= 1024: return 512
    return 1024


# ─────────────────────────────────────────────────────────────────────────────
# LAN / WAN zone detection (reused from existing production code)
# ─────────────────────────────────────────────────────────────────────────────

def _local_subnets() -> List[ipaddress.IPv4Network]:
    """Return directly-attached interface subnets via psutil."""
    subnets: List[ipaddress.IPv4Network] = []
    try:
        import psutil
        for _, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family != 2 or not addr.netmask:
                    continue
                try:
                    subnets.append(ipaddress.IPv4Network(
                        f"{addr.address}/{addr.netmask}", strict=False
                    ))
                except ValueError:
                    pass
    except Exception:
        pass
    return subnets


def _is_lan(ip: str, subnets: List[ipaddress.IPv4Network]) -> bool:
    if subnets:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in subnets)
    return ipaddress.ip_address(ip).is_private


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return (
            not addr.is_private and not addr.is_loopback
            and not addr.is_link_local and not addr.is_multicast
            and not addr.is_reserved and not addr.is_unspecified
        )
    except ValueError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Discovery Engine
# ─────────────────────────────────────────────────────────────────────────────

class DiscoveryEngine:
    """
    Profile-driven host discovery engine.

    ALL scan modules (Basic, Asset Discovery, Advanced Scan) use this class
    with different DiscoveryProfile instances. This is the SINGLE discovery
    engine in the codebase — there is no separate 'fast scanner' or
    'advanced discovery module'.

    Each technique is a separate module in core/discovery/techniques/:
      arp.py       — Scapy ARP broadcast (L2, LAN only)
      icmp.py      — Scapy ICMP echo (L3, all zones)
      tcp_syn.py   — Scapy TCP SYN (L3, needs root)
      tcp_conn.py  — asyncio TCP connect (no root)
      udp_probe.py — Scapy UDP probes (DNS/SNMP/NTP/DHCP/IKE)
      nbns.py      — NetBIOS Name Service (UDP 137, LAN)
    """

    def __init__(
        self,
        profile:        DiscoveryProfile = BALANCED,
        has_privileges: bool = False,
        stealth_mode:   bool = False,
        rate_limit:     Optional[float] = None,
        concurrency_override: Optional[int] = None,
    ):
        self.profile       = profile
        self.has_priv      = has_privileges
        self.stealth_mode  = stealth_mode
        self.rate_limit    = rate_limit
        self.concurrency_override = concurrency_override
        self._local_nets   = []   # populated in run()

        can_raw = has_privileges and SCAPY_AVAILABLE
        if not can_raw and any(
            t in (Technique.ARP, Technique.ICMP, Technique.TCP_SYN, Technique.UDP_PROBE)
            for t in profile.techniques
        ):
            log.warning(
                "Profile '%s' requests raw-socket techniques but "
                "privileges=%s / scapy_available=%s. "
                "Raw techniques will be skipped; TCP connect will cover fallback.",
                profile.name, has_privileges, SCAPY_AVAILABLE,
            )

    # ── Public entry ──────────────────────────────────────────────────────────

    async def run(self, ip_list: List[str]) -> List[Dict]:
        """
        Discover all IPs in ip_list using the configured profile.

        Args:
            ip_list: Flat list of IP address strings to probe.

        Returns:
            List[dict] — one entry per IP, enriched with discovery data.
            Active hosts have is_active=True; inactive hosts have is_active=False.
        """
        if not ip_list:
            return []

        results: Dict[str, Dict] = {ip: _blank_result(ip) for ip in ip_list}
        self._local_nets = _local_subnets()

        # ── Stealth mode: randomize probe order ────────────────────────────
        import random
        scan_order = list(ip_list)
        if self.stealth_mode:
            random.shuffle(scan_order)
            log.debug("Stealth: shuffled %d targets", len(scan_order))

        batch_sz = _batch_size(len(scan_order))
        log.info(
            "DiscoveryEngine [%s]: %d IPs, batch=%d, priv=%s",
            self.profile.name, len(scan_order), batch_sz, self.has_priv,
        )

        # ── Process in batches ─────────────────────────────────────────────
        for i in range(0, len(scan_order), batch_sz):
            batch = scan_order[i:i + batch_sz]
            await self._probe_batch(batch, results)

            # ── Hostile-env auto-escalation ───────────────────────────────
            if (
                i == 0                             # only after first batch
                and self.profile.stealth_auto
                and not self.stealth_mode
                and self._hostile_network(results, len(batch))
            ):
                log.warning(
                    "Hostile network detected after first batch. "
                    "Auto-escalating to stealth mode for remaining batches."
                )
                self.stealth_mode = True

        # ── Post-scan enrichment (AGGRESSIVE profile only) ─────────────────
        if self.profile.enrichment and self.has_priv and SCAPY_AVAILABLE:
            active_ips = [ip for ip, r in results.items() if r["is_active"]]
            if active_ips:
                await self._enrich_active(active_ips, results)

        return list(results.values())

    # ── Batch probe dispatch ──────────────────────────────────────────────────

    async def _probe_batch(self, batch: List[str], results: Dict):
        """Run all configured techniques on a batch of IPs."""
        profile    = self.profile
        can_raw    = self.has_priv and SCAPY_AVAILABLE
        techniques = profile.techniques
        timeout    = profile.timeout

        # Zone split for routing-aware probing
        if profile.separate_lan_wan:
            lan      = [ip for ip in batch if _is_lan(ip, self._local_nets)]
            corporate = [ip for ip in batch
                         if not _is_lan(ip, self._local_nets) and not _is_public(ip)]
            internet  = [ip for ip in batch if _is_public(ip)]
        else:
            lan = batch
            corporate = []
            internet  = []

        # ── ARP — LAN zone only ────────────────────────────────────────────
        if Technique.ARP in techniques and can_raw and lan:
            await asyncio.to_thread(arp.probe, lan, results, timeout=timeout)

        # ── ICMP ──────────────────────────────────────────────────────────
        if Technique.ICMP in techniques and can_raw:
            # LAN: fallback for non-ARP-responding hosts + TTL for ARP-confirmed
            if lan:
                lan_icmp_targets = [
                    ip for ip in lan
                    if not results[ip]["is_active"]
                    or results[ip].get("os_guess", "Unknown") == "Unknown"
                ]
                if lan_icmp_targets:
                    await asyncio.to_thread(
                        icmp.probe, lan_icmp_targets, results, timeout=timeout
                    )
            # Corporate: primary probe (ICMP often allowed internally)
            if corporate:
                await asyncio.to_thread(icmp.probe, corporate, results, timeout=timeout)

        # ── TCP SYN — Scapy raw (needs root) ──────────────────────────────
        if Technique.TCP_SYN in techniques and can_raw:
            # Corporate fallback: hosts that didn't respond to ICMP
            if corporate:
                corp_still_down = [ip for ip in corporate if not results[ip]["is_active"]]
                if corp_still_down:
                    await asyncio.to_thread(
                        tcp_syn.probe,
                        corp_still_down,
                        [22, 135, 139, 445, 3389, 8080, 5985],
                        results,
                        timeout=timeout,
                    )
            # Internet: web ports only (mimic legitimate traffic)
            if internet:
                await asyncio.to_thread(
                    tcp_syn.probe,
                    internet,
                    [80, 443, 22, 8080, 8443],
                    results,
                    timeout=timeout,
                )

        # ── UDP probes — LAN multicast services ────────────────────────────
        if Technique.UDP_PROBE in techniques and can_raw:
            # LAN: hosts still inactive after ARP + ICMP
            if lan:
                lan_udp_targets = [ip for ip in lan if not results[ip]["is_active"]]
                if lan_udp_targets:
                    await asyncio.to_thread(
                        udp_probe.probe,
                        lan_udp_targets,
                        [53, 67, 123, 161, 500, 1900],
                        results,
                        timeout=max(timeout, 2.0),
                    )

        # ── NetBIOS — LAN Microsoft hosts ─────────────────────────────────
        if Technique.NBNS in techniques and lan:
            lan_netbios = [ip for ip in lan if results[ip]["is_active"]]
            if lan_netbios:
                await asyncio.to_thread(nbns.probe, lan_netbios, results)

        # ── TCP connect — final fallback for everything still inactive ─────
        if Technique.TCP_CONN in techniques:
            inactive = [ip for ip in batch if not results[ip]["is_active"]]
            if inactive:
                # Port list: prefer lower-signature ports (web first)
                ports = [80, 443, 22, 8080, 8443, 135, 139, 445, 3389, 21, 111]
                await tcp_conn.probe(
                    inactive, ports, results,
                    timeout=timeout,
                    concurrency=self.concurrency_override or self.rate_limit or self.profile.concurrency,
                    retries=self.profile.retries,
                )

    # ── Post-scan enrichment (AGGRESSIVE profile) ─────────────────────────────

    async def _enrich_active(self, ips: List[str], results: Dict):
        """
        Enrich active hosts with SNMP/mDNS/NetBIOS/PTR/OS fingerprint.
        Only runs when profile.enrichment=True (AGGRESSIVE profile).
        Executes all per-host enrichment in parallel using asyncio.gather.
        """
        from core.discovery.enrichment import enrich_host
        await asyncio.gather(*[
            asyncio.to_thread(enrich_host, ip, results[ip])
            for ip in ips
        ])

    # ── Hostile environment detection ─────────────────────────────────────────

    @staticmethod
    def _hostile_network(results: Dict, batch_size: int) -> bool:
        """
        Heuristic: return True when >85% of probed IPs were silently dropped
        and at least one host replied (meaning Scapy works, not a config issue).
        """
        if batch_size < 5:
            return False
        any_active = any(r["is_active"] for r in results.values())
        if not any_active:
            return False  # Could be config/privilege issue
        silent_drops = sum(
            1 for r in results.values()
            if not r["is_active"] and not r.get("port_states")
        )
        return (silent_drops / len(results)) >= 0.85
