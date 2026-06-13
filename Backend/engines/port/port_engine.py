"""
engines/port/port_engine.py  (REFACTORED)
────────────────────────────────────────────────────────────────────────────
Phase 2 — Asset Discovery / Port Scanning

ARCHITECTURE CHANGE (vs. original):
  OLD: Custom async TCP connect + Scapy UDP for all port scanning
  NEW: Nmap as PRIMARY scanner + async TCP connect as FALLBACK

WHY:
  - Nmap -sS scans 1,000 ports in ~0.5 s vs. 6–10 s for asyncio TCP connect
  - Nmap -sV has 4,500 service probes covering every protocol
  - Nmap -O uses 2,600+ OS signatures (far superior to our TTL heuristics)
  - Nmap handles UDP open/filtered/closed correctly via raw ICMP
  - Service+version from Nmap feeds the plugin engine with accurate input

FALLBACK:
  When nmap is not installed or not privileged, falls back to the
  existing async TCP connect + Scapy UDP implementation (unchanged logic
  from the original port_engine.py).

STRICT RULE:
  All Nmap calls go through core.nmap.wrapper.NmapScanner.
  No direct calls to nmap.PortScanner() or subprocess(['nmap', ...])
  anywhere in this file.

Output format: UNCHANGED — callers (orchestrator, frontend) receive the
same host dict structure with open_ports, udp_services, cves fields.
The only difference is that service/version/banner data is now richer.
"""

import asyncio
import logging
import platform
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

from core.constants import PORT_DB, SCAN_PORTS_QUICK, SCAN_PORTS_FULL, SCAPY_AVAILABLE
from core.models import PortResult, ScanIntensity
from core.nmap.wrapper import NmapScanner, NMAP_AVAILABLE, NmapScanResult
from core.utils import lookup_cve, extract_version

log = logging.getLogger("ccure.port")


class PortEngine:
    """
    Phase 2 port scanning engine.

    Behaviour depends on nmap availability:
      nmap present  → NmapScanner.scan_ports() + detect_services() per host
      nmap absent   → falls back to async TCP connect + Scapy UDP (original impl)

    Both paths produce identical output structure so the orchestrator,
    vulnerability engine, and frontend are unaffected.
    """

    def __init__(
        self,
        intensity: ScanIntensity = ScanIntensity.NORMAL,
        nmap_scanner: Optional[NmapScanner] = None,
        os_detection: bool = False,
        custom_ports: Optional[List[int]] = None,
    ):
        self.intensity = intensity
        self.os_detection = os_detection
        self.custom_ports = custom_ports
        # Use injected scanner (testable) or default singleton
        # On Windows, sudo doesn't work — disable it. On Linux/Mac, enable it for SYN scan.
        use_sudo = platform.system() != "Windows" and nmap_scanner is None
        self._nmap = nmap_scanner or NmapScanner(sudo=use_sudo, timeout_sec=600)

    # ── Public entry ──────────────────────────────────────────────────────────

    async def run(self, hosts: List[Dict], scan_id: Optional[str] = None) -> List[Dict]:
        """
        Scan all active hosts for open ports and services.

        Args:
            hosts: List of host dicts from Phase 1 (DiscoveryEngine).
                   Only hosts with is_active=True are scanned.
            scan_id: Optional UUID to publish real-time progress.

        Returns:
            Same list, each active host enriched with:
              open_ports   → List[PortResult dicts]
              udp_services → List[UDP service dicts]
              cves         → Initial CVE list from banner matching
              os_guess     → Nmap OS detection (if available)
        """
        active = [h for h in hosts if h.get("is_active")]
        if not active:
            return hosts

        if NMAP_AVAILABLE:
            await self._scan_with_nmap(active, scan_id=scan_id)
        else:
            log.warning(
                "nmap not available — falling back to async TCP connect. "
                "Install nmap for faster, more accurate port scanning."
            )
            await self._scan_fallback(active, scan_id=scan_id)

        # After port scanning, perform a lightweight SNMP check on active hosts
        await self._lightweight_snmp_check(active)

        return hosts


    async def _scan_with_nmap(self, hosts: List[Dict], scan_id: Optional[str] = None) -> None:
        """
        Use NmapScanner for port scanning.

        LIGHT / NORMAL — single combined pass (fastest):
          nmap -sS -sV --version-light <ports> --open -T4 --min-parallelism 64
          All hosts scanned in one Nmap invocation; service data already
          attached — no second per-host pass needed.

        DEEP — two-pass:
          Pass 1: full port discovery (-p- all 65 535 ports)
          Pass 2: service detect on open ports only (8 concurrent workers)

        When os_detection=True (set via constructor), passes with_os=True to
        NmapScanner for active OS fingerprinting (-O flag).  This brings Phase 2
        OS classification in line with Phase 3 (Vulnerability Audit) and prevents
        asymmetric OS detection across scan types.
        """
        intensity_map = {
            ScanIntensity.LIGHT:  "basic",
            ScanIntensity.NORMAL: "normal",
            ScanIntensity.DEEP:   "deep",
        }
        nmap_intensity = intensity_map.get(self.intensity, "normal")
        ips = [self._ip(h) for h in hosts if self._ip(h)]

        loop = asyncio.get_event_loop()
        log.info("Nmap port scan: %d hosts, intensity=%s, os_detection=%s",
                 len(ips), nmap_intensity, self.os_detection)
        t0 = time.time()

        from core.redis_client import publish_progress

        if self.custom_ports or self.intensity != ScanIntensity.DEEP:
            # ──────────────────────────────────────────────────────────
            # LIGHT / NORMAL / Custom Ports: single batch call — port states + service info
            # in one Nmap invocation.  Saves the entire _enrich_services() loop
            # (≈65 separate Nmap processes at 4 workers = the ~400 s bottleneck).
            # ──────────────────────────────────────────────────────────
            include_svc = (self.intensity == ScanIntensity.NORMAL) or bool(self.custom_ports)
            if scan_id:
                await publish_progress(scan_id, 2, {
                    "total_hosts": len(ips),
                    "status": "running"
                })

            nmap_results: Dict[str, NmapScanResult] = await loop.run_in_executor(
                None,
                lambda: self._nmap.scan_hosts(
                    ips,
                    intensity=nmap_intensity,
                    with_services=include_svc,
                    with_os=self.os_detection,
                    ports=self.custom_ports,
                ),
            )
            log.info(
                "Nmap port scan done in %.1fs (combined pass, services=%s)",
                time.time() - t0, include_svc,
            )
            # Apply results directly — service info already present
            for host in hosts:
                ip = self._ip(host)
                if not ip or ip not in nmap_results:
                    continue
                self._apply_nmap_ports(
                    host, nmap_results[ip], service_detection=include_svc
                )
            
            if scan_id:
                await publish_progress(scan_id, 2, {
                    "scanned_hosts": len(ips),
                    "total_hosts": len(ips),
                    "status": "running"
                })
        else:
            # ──────────────────────────────────────────────────────────
            # DEEP: two-pass — full port sweep then targeted service detect
            # ──────────────────────────────────────────────────────────
            if scan_id:
                await publish_progress(scan_id, 2, {
                    "phase_detail": "port_sweep",
                    "total_hosts": len(ips),
                    "status": "running"
                })

            nmap_results: Dict[str, NmapScanResult] = await loop.run_in_executor(
                None,
                lambda: self._nmap.scan_hosts(ips, intensity="deep", with_os=self.os_detection),
            )
            log.info(
                "Nmap DEEP port scan done in %.1fs (pass 1/2)",
                time.time() - t0,
            )
            await self._enrich_services(hosts, nmap_results, loop, scan_id=scan_id)

    async def _enrich_services(
        self,
        hosts: List[Dict],
        initial_results: Dict[str, NmapScanResult],
        loop: asyncio.AbstractEventLoop,
        scan_id: Optional[str] = None
    ) -> None:
        """
        Run targeted service/version detection per host on its open ports.
        Only called for DEEP intensity; LIGHT/NORMAL use the combined single
        pass instead.

        Max workers raised to 8 (was 4) — service probes on a small known-open
        port list per host are lightweight; 8 concurrent Nmap processes are
        safe on all supported Windows Npcap versions as of 1.79.
        """
        t0 = time.time()
        n_workers = max(1, min(len(hosts), 8))  # was 4
        from core.redis_client import publish_progress

        if scan_id:
            asyncio.create_task(publish_progress(scan_id, 2, {
                "phase_detail": "service_detection",
                "scanned_hosts": 0,
                "total_hosts": len(hosts),
                "status": "running"
            }))

        completed = 0
        def _enrich_one(host: Dict) -> None:
            nonlocal completed
            ip = self._ip(host)
            if not ip:
                return
            initial = initial_results.get(ip)
            open_port_nums = (
                [p.port for p in initial.open_ports] if initial else None
            )
            if not open_port_nums:
                if initial:
                    self._apply_nmap_ports(host, initial, service_detection=False)
                return
            svc_result = self._nmap.detect_services(ip, ports=open_port_nums)
            self._apply_nmap_ports(host, svc_result, service_detection=True)
            completed += 1
            if scan_id:
                asyncio.run_coroutine_threadsafe(publish_progress(scan_id, 2, {
                    "phase_detail": "service_detection",
                    "scanned_hosts": completed,
                    "total_hosts": len(hosts),
                    "status": "running"
                }), loop)

        with ThreadPoolExecutor(max_workers=n_workers, thread_name_prefix="svc-enrich") as pool:
            tasks = [
                loop.run_in_executor(pool, _enrich_one, host)
                for host in hosts
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, Exception):
                    log.debug("Service enrichment error: %s", res)

        if scan_id:
            asyncio.create_task(publish_progress(scan_id, 2, {
                "phase_detail": "service_detection",
                "scanned_hosts": len(hosts),
                "total_hosts": len(hosts),
                "status": "complete"
            }))

        log.info("DEEP service enrichment done in %.1fs (pass 2/2)", time.time() - t0)

    def _apply_nmap_ports(
        self,
        host: Dict,
        nmap_result: NmapScanResult,
        service_detection: bool = True,
    ) -> None:
        """
        Convert NmapScanResult ports into the standard PortResult dict format
        and merge into the host dict.
        """
        if nmap_result.state in ("nmap_unavailable", "error", "timeout"):
            ip = self._ip(host)
            log.warning(
                "Nmap scan %s for %s: %s",
                nmap_result.state, ip, nmap_result.error_message or "Unknown error"
            )
            return

        ip = self._ip(host)
        existing_ports = {p["port"] for p in host.get("open_ports", [])}

        # ── Parallelize CVE Lookups for all open ports ────────────────────────
        # This avoids the sequential bottleneck when a host has many ports.
        from concurrent.futures import ThreadPoolExecutor
        
        open_ports = nmap_result.open_ports
        results_map = {}
        
        if open_ports:
            def _lookup_task(port_obj):
                banner = port_obj.banner or port_obj.scripts.get("banner", "")
                query_str = banner or port_obj.service.lower()
                return port_obj.port, lookup_cve(query_str)

            with ThreadPoolExecutor(max_workers=min(len(open_ports), 20)) as pool:
                for p_num, cves in pool.map(_lookup_task, open_ports):
                    results_map[p_num] = cves

        for nmap_port in open_ports:
            if nmap_port.port in existing_ports:
                continue

            meta = PORT_DB.get(nmap_port.port, {
                "service": nmap_port.service or "unknown",
                "risk":    "Info",
                "note":    "",
            })

            # Version string: prefer Nmap's richer version over our regex
            version_str = (
                nmap_port.full_version
                or extract_version(nmap_port.banner, nmap_port.service)
            )
            banner = nmap_port.banner or nmap_port.scripts.get("banner", "")
            
            # Use pre-fetched CVEs from our parallel pool
            cves = results_map.get(nmap_port.port, [])

            pr = PortResult(
                port    = nmap_port.port,
                service = nmap_port.service or meta.get("service", "unknown"),
                state   = nmap_port.state,
                banner  = banner[:500] if banner else "",
                version = version_str[:200] if version_str else "",
                product = nmap_port.product[:255] if nmap_port.product else "",
                risk    = meta.get("risk", "Info"),
                cves    = cves,
            )
            host.setdefault("open_ports", []).append(pr.to_dict())
            host.setdefault("cves", []).extend(cves)
            existing_ports.add(nmap_port.port)

        # Apply OS detection if available
        best_os = nmap_result.best_os
        if best_os and best_os.accuracy >= 75:
            host["os_guess"]       = best_os.name
            host["os_confidence"]  = (
                "High"   if best_os.accuracy >= 90 else
                "Medium" if best_os.accuracy >= 75 else "Low"
            )
            if best_os.cpe:
                host.setdefault("os_cpe", best_os.cpe)

    async def _lightweight_snmp_check(self, hosts: List[Dict]) -> None:
        """
        Check if port 161 (SNMP) is open on active hosts, and perform a lightweight
        community query to get classification parameters.
        """
        from core.discovery.enrichment import _snmp_lightweight_probe
        
        def _check_host(host: Dict):
            ip = host.get("ip_address") or host.get("ip")
            if not ip:
                return
            
            # Check if port 161 is open in open_ports
            is_161_open = False
            for p in host.get("open_ports", []):
                if p.get("port") == 161:
                    is_161_open = True
                    break
            
            # Also check if it's in port_states
            if not is_161_open:
                port_states = host.get("port_states", {})
                if port_states.get(161) == "open" or port_states.get("161") == "open":
                    is_161_open = True
                    
            if not is_161_open:
                # If Nmap didn't scan UDP, we might not know if 161 is open.
                # Only check if it's not explicitly closed to avoid useless timeouts.
                port_states = host.get("port_states", {})
                if port_states.get(161) == "closed" or port_states.get("161") == "closed":
                    return
            
            # Run the lightweight probe
            _snmp_lightweight_probe(ip, host)
            
        loop = asyncio.get_running_loop()
        await asyncio.gather(*[
            loop.run_in_executor(None, _check_host, h)
            for h in hosts
        ])

    # ── Fallback path (TCP connect) ───────────────────────────────────────────

    async def _scan_fallback(self, hosts: List[Dict], scan_id: Optional[str] = None) -> None:
        """
        Original async TCP connect + Scapy UDP implementation.
        Used when nmap is not installed.
        Identical logic to the original port_engine.py — not changed.
        """
        ports = self._port_list()
        concurrency = 500 if self.intensity != ScanIntensity.DEEP else 50
        tout = 2.0 if self.intensity == ScanIntensity.DEEP else 0.8

        hosts_map: Dict[str, Dict] = {}
        for h in hosts:
            ip = self._ip(h)
            if ip:
                hosts_map[ip] = h

        # Async TCP connect
        tcp_queue: asyncio.Queue = asyncio.Queue()
        for ip in hosts_map:
            for p in ports:
                tcp_queue.put_nowait((ip, p))

        async def tcp_worker():
            while True:
                try:
                    ip, port = tcp_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                try:
                    await self._probe_tcp_fallback(ip, port, hosts_map, tout)
                except Exception:
                    pass
                finally:
                    tcp_queue.task_done()

        workers = [asyncio.create_task(tcp_worker()) for _ in range(concurrency)]
        await asyncio.gather(*workers)

        # Scapy UDP (if available)
        if SCAPY_AVAILABLE:
            await asyncio.get_event_loop().run_in_executor(
                None, self._scan_udp_scapy, list(hosts_map.keys()), hosts_map
            )

    async def _probe_tcp_fallback(
        self, ip: str, port: int, hosts_map: Dict, timeout: float
    ) -> None:
        """Original async TCP connect logic (unchanged from previous implementation)."""
        import ssl as _ssl
        use_tls = port in {443, 8443, 465, 993, 995}
        t0 = time.time()
        try:
            if use_tls:
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                conn = asyncio.open_connection(ip, port, ssl=ctx)
            else:
                conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        except (asyncio.TimeoutError, TimeoutError):
            host = hosts_map.get(ip)
            if host:
                host["filtered_ports_count"] = host.get("filtered_ports_count", 0) + 1
            return
        except (ConnectionRefusedError, OSError):
            host = hosts_map.get(ip)
            if host:
                host["closed_ports_count"] = host.get("closed_ports_count", 0) + 1
            return
        except Exception:
            return

        # Port is open — grab banner
        banner = ""
        try:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n") if port in (80, 8080) else None
            data = await asyncio.wait_for(reader.read(4096), timeout=1.0)
            if data:
                banner = data.decode("utf-8", errors="ignore").strip()[:200]
        except Exception:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        elapsed = (time.time() - t0) * 1000
        meta = PORT_DB.get(port, {"service": "unknown", "risk": "Info", "note": ""})
        cves = lookup_cve(banner or meta["service"].lower())

        pr = PortResult(
            port=port, service=meta["service"], state="open",
            banner=banner, version=extract_version(banner, meta["service"]),
            risk=meta["risk"], cves=cves,
        )
        host = hosts_map.get(ip)
        if host is None:
            return
        existing = {p["port"] for p in host.get("open_ports", [])}
        if port not in existing:
            host.setdefault("open_ports", []).append(pr.to_dict())
            host.setdefault("cves", []).extend(cves)

    def _scan_udp_scapy(self, ips: List[str], hosts_map: Dict) -> None:
        """Original Scapy UDP scan logic (unchanged)."""
        from engines.port._udp_services import UDP_SERVICES, build_payload, add_udp_result
        try:
            from scapy.all import sr, IP, UDP, ICMP, Raw
            pkts = []
            for ip in ips:
                for port, info in UDP_SERVICES.items():
                    payload = build_payload(port, info["probe"])
                    pkt = IP(dst=ip) / UDP(dport=port)
                    if payload:
                        pkt = pkt / Raw(load=payload)
                    pkts.append(pkt)
            if not pkts:
                return
            ans, unans = sr(pkts, timeout=3.0, verbose=0, multi=True)
            for snd, rcv in ans:
                if not (snd.haslayer(IP) and snd.haslayer(UDP)):
                    continue
                ip   = snd[IP].dst
                port = snd[UDP].dport
                if ip not in hosts_map:
                    continue
                host = hosts_map[ip]
                info = UDP_SERVICES.get(port, {})
                if rcv.haslayer(ICMP) and rcv[ICMP].type == 3:
                    pass  # closed or filtered — skip
                elif rcv.haslayer(UDP):
                    raw = bytes(rcv[UDP].payload)
                    banner = raw.decode("utf-8", errors="ignore").strip()[:120]
                    add_udp_result(host, port, info, "open", banner)
            for snd in unans:
                if snd.haslayer(IP) and snd.haslayer(UDP):
                    ip   = snd[IP].dst
                    port = snd[UDP].dport
                    if ip in hosts_map:
                        add_udp_result(hosts_map[ip], port, UDP_SERVICES.get(port, {}), "open|filtered", "")
        except Exception as exc:
            log.debug("_scan_udp_scapy error: %s", exc)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _port_list(self) -> List[int]:
        if self.custom_ports:
            return self.custom_ports
        if self.intensity == ScanIntensity.LIGHT:
            return SCAN_PORTS_QUICK
        return SCAN_PORTS_FULL

    @staticmethod
    def _ip(host: Dict) -> Optional[str]:
        return host.get("ip_address") or host.get("ip")
