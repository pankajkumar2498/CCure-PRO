"""
engines/port/port_engine.py
----------------------------
Phase 2 - Port Scanning

For each active host, concurrently probes all ports in the selected port list
using asyncio TCP connect. Returns hosts enriched with open_ports + initial CVEs.

Port list by intensity:
  LIGHT  -> SCAN_PORTS_QUICK  (top-68 high-value ports)
  NORMAL -> SCAN_PORTS_FULL   (all named ports in PORT_DB)
  DEEP   -> SCAN_PORTS_FULL  (named ports, longer timeout, lower concurrency)
"""

import asyncio
import ssl
import time
from typing import Dict, List

from core.constants import PORT_DB, SCAN_PORTS_QUICK, SCAN_PORTS_FULL
from core.models import PortResult, ScanIntensity
from core.utils import lookup_cve, extract_version

_TLS_PORTS = {443, 8443, 465, 993, 995}


class PortEngine:
    def __init__(self, intensity: ScanIntensity = ScanIntensity.NORMAL):
        self.intensity = intensity

    # ------------------------------------------------------------------
    # Public entry
    # ------------------------------------------------------------------
    def run(self, hosts: List[Dict]) -> List[Dict]:
        """
        hosts: list of discovery result dicts (only is_active==True entries processed).
        Returns same list with 'open_ports' and 'cves' fields populated.
        """
        active = [h for h in hosts if h.get("is_active")]
        if not active:
            return hosts
        
        # Check if there's already a running event loop
        try:
            loop = asyncio.get_running_loop()
            # There's a running loop, we need to run in a separate thread
            import concurrent.futures
            import threading
            
            result = []
            exception = None
            
            def _run_in_thread():
                nonlocal result, exception
                try:
                    # Create a new event loop for this thread
                    new_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(new_loop)
                    try:
                        new_loop.run_until_complete(self._scan_all(active))
                    finally:
                        new_loop.close()
                except Exception as e:
                    exception = e
            
            thread = threading.Thread(target=_run_in_thread)
            thread.start()
            thread.join()
            
            if exception:
                raise exception
        except RuntimeError:
            # No running loop, use asyncio.run as normal
            asyncio.run(self._scan_all(active))
        
        return hosts

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _port_list(self) -> List[int]:
        if self.intensity == ScanIntensity.LIGHT:
            return SCAN_PORTS_QUICK
        # NORMAL and DEEP both use the full named-port list.
        # DEEP previously used all 65535 ports, but bulk-scanning 65k ports in
        # rapid succession triggers Windows Firewall and Linux iptables connection
        # tracking to START DROPPING SYN PACKETS — so you actually detect FEWER
        # open ports than in normal mode. DEEP intensity now means "probe the same
        # ports as normal, but with longer timeouts and deeper banner grabbing"
        # which is far more accurate and reliable.
        return SCAN_PORTS_FULL

    def _concurrency(self) -> int:
        # Lower concurrency on deep to reduce packet storm / firewall triggering
        if self.intensity == ScanIntensity.DEEP:
            return 30
        return 100

    def _timeout(self) -> float:
        # Longer timeout for deep mode — catches slow services (DB, SMB handshake)
        if self.intensity == ScanIntensity.DEEP:
            return 2.0
        return 0.8

    async def _scan_all(self, hosts: List[Dict]):
        ports = self._port_list()
        sem   = asyncio.Semaphore(self._concurrency())
        tout  = self._timeout()

        async def bounded(ip, port):
            async with sem:
                await self._probe_port(ip, port, hosts_map, tout)

        # Build a quick lookup by IP - handle both "ip" and "ip_address" keys
        hosts_map: Dict[str, Dict] = {}
        ip_field = None  # Detect which field name is used
        
        for h in hosts:
            if "ip_address" in h:
                ip_field = "ip_address"
                break
            elif "ip" in h:
                ip_field = "ip"
                break
        
        # If we still don't know, assume "ip_address" (from HostResult model)
        if not ip_field:
            ip_field = "ip_address"
        
        for h in hosts:
            ip = h.get(ip_field)
            if ip:
                hosts_map[ip] = h

        tasks = [bounded(ip, p) for ip in hosts_map.keys() for p in ports]
        await asyncio.gather(*tasks)

    async def _probe_port(self, ip: str, port: int, hosts_map: Dict[str, Dict],
                          timeout: float = 0.8):
        # timeout passed in from _scan_all - no longer hardcoded
        use_tls  = port in _TLS_PORTS
        try:
            t0 = time.time()
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                conn = asyncio.open_connection(ip, port, ssl=ctx)
            else:
                conn = asyncio.open_connection(ip, port)

            reader, writer = await asyncio.wait_for(conn, timeout=timeout)

            # -- Quick banner grab ----------------------------------------
            banner = ""
            try:
                if port in (80, 8080, 8000, 8888, 443, 8443):
                    writer.write(
                        b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n"
                    )
                    await writer.drain()
                data = await asyncio.wait_for(reader.read(2048), timeout=1.0)
                if data:
                    text = data.decode("utf-8", errors="ignore").strip()
                    if port == 22:
                        banner = text.split("\n")[0].strip()
                    else:
                        for line in text.split("\n"):
                            if line.lower().startswith("server:"):
                                banner = line.split(":", 1)[1].strip()
                                break
                        if not banner:
                            banner = text.split("\n")[0][:80].replace("\r", "")
            except Exception:
                pass

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            elapsed  = (time.time() - t0) * 1000
            meta     = PORT_DB.get(port, {"service": "unknown", "risk": "Info", "note": ""})
            cves     = lookup_cve(banner) if banner else lookup_cve(meta["service"].lower())

            pr = PortResult(
                port    = port,
                service = meta["service"],
                state   = "open",
                banner  = banner,
                version = extract_version(banner, meta["service"]),
                risk    = meta["risk"],
                cves    = cves,
            )

            host = hosts_map[ip]
            if host.get("elapsed_ms") is None:
                host["elapsed_ms"] = elapsed

            existing = {p["port"] for p in host.get("open_ports", [])}
            if port not in existing:
                host.setdefault("open_ports", []).append(pr.to_dict())
                host.setdefault("cves", []).extend(cves)

        except Exception:
            pass
