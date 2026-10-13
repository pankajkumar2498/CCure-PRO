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

from core.constants import (
    PORT_DB,
    SCAN_PORTS_OT,
    SCAN_PORTS_QUICK,
    SCAPY_AVAILABLE,
)
from core.models import FINGERPRINT_SOURCES, PortResult, ScanIntensity
from core.nmap.wrapper import NMAP_AVAILABLE, NmapScanner, NmapScanResult
from core.utils import extract_version
from core.checks.finding_normalizer import version_precision

log = logging.getLogger("ccure.port")

#: Fields that describe *what is running* on the port, as opposed to how the
#: port behaved. Only these are taken from the stronger observation.
_IDENTITY_FIELDS = (
    "service",
    "product",
    "version",
    "extra",
    "cpe",
    "version_precision",
    "fingerprint_source",
)


def _summarize_ports(ports: list[int], limit: int = 12) -> str:
    """Compact port list for the scan record: '22, 80, 443 … (+40 more)'."""
    if not ports:
        return "none"
    head = ", ".join(str(p) for p in ports[:limit])
    if len(ports) > limit:
        return f"{head} (+{len(ports) - limit} more)"
    return head


def _ports_spec(ports: list[int]) -> str:
    """
    The probed port set as a lossless, re-parseable spec: ``1-1024,1433,3306``.

    Distinct from :func:`_summarize_ports`, which is for humans and truncates.
    A later stage has to be able to answer "was this port actually probed?",
    and the difference between "probed and did not answer" and "never probed"
    is the difference between reporting a service as firewalled and admitting
    it was not tested.
    """
    if not ports:
        return ""
    ordered = sorted(set(ports))
    parts: list[str] = []
    start = prev = ordered[0]
    for port in ordered[1:]:
        if port == prev + 1:
            prev = port
            continue
        parts.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = port
    parts.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(parts)


def _rank(record: dict) -> int:
    try:
        return FINGERPRINT_SOURCES.index(record.get("fingerprint_source") or "")
    except ValueError:
        return 0


def _record_port(host: dict, incoming: dict) -> None:
    """
    Add a port observation to a host, keeping the best-evidenced identification.

    Ports arrive from several places — discovery enrichment, the OT and SNMP
    probes, the TCP fallback, and Nmap service detection — and they do not
    arrive in quality order. The previous rule was "first writer wins", which
    meant a discovery-time connect-and-read on port 445 or 502 permanently
    blocked the Nmap fingerprint for that port. Downstream, a service with no
    version cannot be version-checked, so every CVE against it was withheld as
    unverifiable: a silent false negative created by arrival order.

    Identification now comes from whichever observation is better evidenced;
    everything else (banner, risk metadata) fills in from either.
    """
    ports = host.setdefault("open_ports", [])
    for index, existing in enumerate(ports):
        if existing.get("port") != incoming.get("port"):
            continue
        if (existing.get("protocol") or "tcp") != (incoming.get("protocol") or "tcp"):
            continue

        winner, loser = (
            (incoming, existing)
            if _rank(incoming) > _rank(existing)
            else (existing, incoming)
        )
        merged = dict(loser)
        merged.update({k: v for k, v in winner.items() if v not in (None, "", [], {})})
        for key in _IDENTITY_FIELDS:
            merged[key] = winner.get(key) or loser.get(key) or merged.get(key)
        # A port observed open by any probe is open, whichever record wins.
        if "open" in (existing.get("state", ""), incoming.get("state", "")):
            merged["state"] = "open"
        merged["cves"] = (existing.get("cves") or []) + [
            c
            for c in (incoming.get("cves") or [])
            if c not in (existing.get("cves") or [])
        ]
        ports[index] = merged
        return

    ports.append(incoming)


def fingerprint_os_confidence(accuracy: float) -> str:
    """
    Confidence for an OS named only by an Nmap TCP/IP fingerprint.

    Nmap's ``accuracy`` scores how well the packets matched a fingerprint, not
    how likely the name is to be right, and the fingerprint database cannot
    tell close releases apart: a Windows 11 host (build 26300) was reported as
    "Microsoft Windows 10 1703" at accuracy >= 90, shown as High and stored at
    90%. A fingerprint therefore tops out at Medium. High is for a host that
    states its own identity — SNMP sysDescr, an authenticated session.
    """
    if accuracy >= 90:
        return "Medium"
    return "Low"


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
        nmap_scanner: NmapScanner | None = None,
        os_detection: bool = False,
        custom_ports: list[int] | None = None,
        exclude_ports: list[int] | None = None,
        exclude_ot_from_nmap: bool = True,
    ):
        self.intensity = intensity
        self.os_detection = os_detection
        self.custom_ports = custom_ports
        self.exclude_ports = exclude_ports
        self.exclude_ot_from_nmap = exclude_ot_from_nmap
        # Use injected scanner (testable) or default singleton
        # On Windows, sudo doesn't work — disable it. On Linux/Mac, enable it for SYN scan.
        use_sudo = platform.system() != "Windows" and nmap_scanner is None
        self._nmap = nmap_scanner or NmapScanner(sudo=use_sudo, timeout_sec=600)

    # ── Public entry ──────────────────────────────────────────────────────────

    async def run(self, hosts: list[dict], scan_id: str | None = None) -> list[dict]:
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
              os_guess     → Nmap OS detection (if available)

        This engine identifies services; it does not assess them. CVE candidate
        generation was removed from here because a port scan cannot verify what
        it matches: it produced candidates keyed on service names ("http",
        "ssh") that the vulnerability phase then generated a second time.
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

        # Run dynamic OT identity probes on open SCADA ports
        await self._ot_enrichment_check(active)

        return hosts

    async def _scan_with_nmap(
        self, hosts: list[dict], scan_id: str | None = None
    ) -> None:
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
            ScanIntensity.LIGHT: "basic",
            ScanIntensity.NORMAL: "normal",
            ScanIntensity.DEEP: "deep",
        }
        nmap_intensity = intensity_map.get(self.intensity, "normal")
        ips = [self._ip(h) for h in hosts if self._ip(h)]

        loop = asyncio.get_event_loop()
        log.info(
            "Nmap port scan: %d hosts, intensity=%s, os_detection=%s",
            len(ips),
            nmap_intensity,
            self.os_detection,
        )
        t0 = time.time()

        from core.redis_client import publish_progress

        if self.custom_ports or self.intensity != ScanIntensity.DEEP:
            # ──────────────────────────────────────────────────────────
            # LIGHT / NORMAL / Custom Ports: single batch call — port states + service info
            # in one Nmap invocation.  Saves the entire _enrich_services() loop
            # (≈65 separate Nmap processes at 4 workers = the ~400 s bottleneck).
            # ──────────────────────────────────────────────────────────
            include_svc = (self.intensity == ScanIntensity.NORMAL) or bool(
                self.custom_ports
            )
            if scan_id:
                await publish_progress(
                    scan_id, 2, {"total_hosts": len(ips), "status": "running"}
                )

            nmap_results: dict[str, NmapScanResult] = await loop.run_in_executor(
                None,
                lambda: self._nmap.scan_hosts(
                    ips,
                    intensity=nmap_intensity,
                    with_services=include_svc,
                    with_os=self.os_detection,
                    ports=self._port_list(),
                    exclude_ports=self.exclude_ports,
                    exclude_ot_from_nmap=self.exclude_ot_from_nmap,
                ),
            )
            log.info(
                "Nmap port scan done in %.1fs (combined pass, services=%s)",
                time.time() - t0,
                include_svc,
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
                await publish_progress(
                    scan_id,
                    2,
                    {
                        "scanned_hosts": len(ips),
                        "total_hosts": len(ips),
                        "status": "running",
                    },
                )
        else:
            # ──────────────────────────────────────────────────────────
            # DEEP: two-pass — full port sweep then targeted service detect
            # ──────────────────────────────────────────────────────────
            if scan_id:
                await publish_progress(
                    scan_id,
                    2,
                    {
                        "phase_detail": "port_sweep",
                        "total_hosts": len(ips),
                        "status": "running",
                    },
                )

            nmap_results: dict[str, NmapScanResult] = await loop.run_in_executor(
                None,
                lambda: self._nmap.scan_hosts(
                    ips,
                    intensity="deep",
                    with_os=self.os_detection,
                    exclude_ports=self.exclude_ports,
                    exclude_ot_from_nmap=self.exclude_ot_from_nmap,
                ),
            )
            log.info(
                "Nmap DEEP port scan done in %.1fs (pass 1/2)",
                time.time() - t0,
            )
            await self._enrich_services(hosts, nmap_results, loop, scan_id=scan_id)

    async def _enrich_services(
        self,
        hosts: list[dict],
        initial_results: dict[str, NmapScanResult],
        loop: asyncio.AbstractEventLoop,
        scan_id: str | None = None,
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
            asyncio.create_task(
                publish_progress(
                    scan_id,
                    2,
                    {
                        "phase_detail": "service_detection",
                        "scanned_hosts": 0,
                        "total_hosts": len(hosts),
                        "status": "running",
                    },
                )
            )

        completed = 0

        def _enrich_one(host: dict) -> None:
            nonlocal completed
            ip = self._ip(host)
            if not ip:
                return
            initial = initial_results.get(ip)
            open_port_nums = [p.port for p in initial.open_ports] if initial else None
            if not open_port_nums:
                if initial:
                    self._apply_nmap_ports(host, initial, service_detection=False)
                return
            svc_result = self._nmap.detect_services(ip, ports=open_port_nums)
            self._apply_nmap_ports(host, svc_result, service_detection=True)
            completed += 1
            if scan_id:
                asyncio.run_coroutine_threadsafe(
                    publish_progress(
                        scan_id,
                        2,
                        {
                            "phase_detail": "service_detection",
                            "scanned_hosts": completed,
                            "total_hosts": len(hosts),
                            "status": "running",
                        },
                    ),
                    loop,
                )

        with ThreadPoolExecutor(
            max_workers=n_workers, thread_name_prefix="svc-enrich"
        ) as pool:
            tasks = [loop.run_in_executor(pool, _enrich_one, host) for host in hosts]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, Exception):
                    log.debug("Service enrichment error: %s", res)

        if scan_id:
            asyncio.create_task(
                publish_progress(
                    scan_id,
                    2,
                    {
                        "phase_detail": "service_detection",
                        "scanned_hosts": len(hosts),
                        "total_hosts": len(hosts),
                        "status": "complete",
                    },
                )
            )

        log.info("DEEP service enrichment done in %.1fs (pass 2/2)", time.time() - t0)

    def _apply_nmap_ports(
        self,
        host: dict,
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
                nmap_result.state,
                ip,
                nmap_result.error_message or "Unknown error",
            )
            return

        ip = self._ip(host)
        open_ports = nmap_result.open_ports

        for nmap_port in open_ports:
            meta = PORT_DB.get(
                nmap_port.port,
                {
                    "service": nmap_port.service or "unknown",
                    "risk": "Info",
                    "note": "",
                },
            )

            # Nmap reports product, version and extra separately. They are kept
            # that way: concatenating them into one display string forced every
            # later version comparison to parse the version back out of prose,
            # and lost the distinction between "no version" and "version is
            # part of a sentence".
            version = nmap_port.version or ""
            if not version and nmap_port.banner:
                version = extract_version(nmap_port.banner, nmap_port.service)
            banner = nmap_port.banner or nmap_port.scripts.get("banner", "")

            if nmap_port.version:
                source = "version_detection"
            elif nmap_port.product:
                source = "service_detection"
            elif banner:
                source = "banner"
            else:
                source = "port_state"

            pr = PortResult(
                port=nmap_port.port,
                service=nmap_port.service or meta.get("service", "unknown"),
                protocol=nmap_port.protocol or "tcp",
                state=nmap_port.state,
                banner=banner[:500] if banner else "",
                version=version[:200] if version else "",
                product=nmap_port.product[:255] if nmap_port.product else "",
                extra=nmap_port.extra[:255] if nmap_port.extra else "",
                # The scanner's own CPE for this service. Carrying it means
                # downstream matching compares identifiers instead of guessing
                # which product a banner string refers to.
                cpe=list(nmap_port.cpe or []),
                version_precision=version_precision(version) if version else "unknown",
                fingerprint_source=source,
                risk=meta.get("risk", "Info"),
            )
            _record_port(host, pr.to_dict())

        # Apply OS detection if available
        best_os = nmap_result.best_os
        if best_os and best_os.accuracy >= 75:
            host["os_guess"] = best_os.name
            host["os_confidence"] = fingerprint_os_confidence(best_os.accuracy)
            host.setdefault("os_evidence", "nmap_fingerprint")
            if best_os.cpe:
                host.setdefault("os_cpe", best_os.cpe)

    async def _lightweight_snmp_check(self, hosts: list[dict]) -> None:
        """
        Check if port 161 (SNMP) is open on active hosts, and perform a lightweight
        community query to get classification parameters.
        """
        from core.discovery.enrichment import _snmp_lightweight_probe

        def _check_host(host: dict):
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
                if (
                    port_states.get(161) == "closed"
                    or port_states.get("161") == "closed"
                ):
                    return

            # Run the lightweight probe
            _snmp_lightweight_probe(ip, host)

        loop = asyncio.get_running_loop()
        await asyncio.gather(
            *[loop.run_in_executor(None, _check_host, h) for h in hosts]
        )

    async def _ot_enrichment_check(self, hosts: list[dict]) -> None:
        """
        Check if any OT ports are open on active hosts and perform deep OT identity probing.
        """
        from core.device_classifier import classify_device
        from core.discovery.enrichment import _ot_protocol_probes

        def _check_host(host: dict):
            ip = host.get("ip_address") or host.get("ip")
            if not ip:
                return

            # SCADA/OT default ports mapped in ot_probes:
            # modbus (502), s7/mms (102), ethernetip (44818), bacnet (47808), dnp3 (20000),
            # opcua (4840), iec104 (2404), ge_srtp (18245), fins (9600), melsec (5007), codesys (2455)
            ot_ports = {
                502,
                102,
                44818,
                47808,
                20000,
                4840,
                2404,
                18245,
                9600,
                5007,
                2455,
            }

            open_ports = {
                p.get("port") for p in host.get("open_ports", []) if p.get("port")
            }

            # Skip if ot_info is already present
            if host.get("ot_info"):
                return

            # If we exclude OT from Nmap, we want to probe all candidate OT ports.
            # Otherwise, we only probe if at least one OT port is open.
            if not self.exclude_ot_from_nmap and not (open_ports & ot_ports):
                return

            # Initialize registrations needed by _ot_protocol_probes
            port_states = host.setdefault("port_states", {})
            for p in open_ports:
                if p in ot_ports:
                    port_states[p] = "open"

            host.setdefault("confirmations", [])

            # Execute OT Probes
            try:
                _ot_protocol_probes(ip, host)

                # If OT info was successfully gathered, run classifier to set exact scada_ics details
                if host.get("ot_info"):
                    classify_device(host)
            except Exception as exc:
                log.debug("PortEngine OT enrichment check failed for %s: %s", ip, exc)

        loop = asyncio.get_running_loop()
        await asyncio.gather(
            *[loop.run_in_executor(None, _check_host, h) for h in hosts]
        )

    # ── Fallback path (TCP connect) ───────────────────────────────────────────

    async def _scan_fallback(
        self, hosts: list[dict], scan_id: str | None = None
    ) -> None:
        """
        Original async TCP connect + Scapy UDP implementation.
        Used when nmap is not installed.
        Identical logic to the original port_engine.py — not changed.
        """
        ports = self._port_list()
        concurrency = 500 if self.intensity != ScanIntensity.DEEP else 50
        tout = 2.0 if self.intensity == ScanIntensity.DEEP else 0.8

        hosts_map: dict[str, dict] = {}
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
        self, ip: str, port: int, hosts_map: dict, timeout: float
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
        version = extract_version(banner, meta["service"])

        pr = PortResult(
            port=port,
            service=meta["service"],
            state="open",
            banner=banner,
            version=version,
            version_precision=version_precision(version) if version else "unknown",
            fingerprint_source="banner" if banner else "connect_probe",
            risk=meta["risk"],
        )
        host = hosts_map.get(ip)
        if host is None:
            return
        _record_port(host, pr.to_dict())

    def _scan_udp_scapy(self, ips: list[str], hosts_map: dict) -> None:
        """Original Scapy UDP scan logic (unchanged)."""
        from engines.port._udp_services import (
            UDP_SERVICES,
            add_udp_result,
            build_payload,
        )

        try:
            from scapy.all import ICMP, IP, UDP, Raw, sr

            pkts = []
            exclude_set = set(self.exclude_ports) if self.exclude_ports else set()
            for ip in ips:
                for port, info in UDP_SERVICES.items():
                    if port in exclude_set:
                        continue
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
                ip = snd[IP].dst
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
                    ip = snd[IP].dst
                    port = snd[UDP].dport
                    if ip in hosts_map:
                        add_udp_result(
                            hosts_map[ip],
                            port,
                            UDP_SERVICES.get(port, {}),
                            "open|filtered",
                            "",
                        )
        except Exception as exc:
            log.debug("_scan_udp_scapy error: %s", exc)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _port_list(self) -> list[int]:
        ports = []
        if self.custom_ports:
            ports = list(self.custom_ports)
        elif self.intensity == ScanIntensity.LIGHT:
            # Union of quick IT ports and all OT ports
            ports = sorted(list(set(SCAN_PORTS_QUICK) | set(SCAN_PORTS_OT)))
        else:
            # NORMAL/Default: All system ports (1-1024) + high-value curated ports above 1024
            system_ports = list(range(1, 1025))
            high_value_ports = [p for p in PORT_DB.keys() if p > 1024]
            ports = sorted(list(set(system_ports + high_value_ports)))

        exclude_set = set(self.exclude_ports) if self.exclude_ports else set()

        # If exclude_ot_from_nmap is enabled, automatically exclude OT ports from Nmap scan
        if self.exclude_ot_from_nmap:
            ot_ports = {
                502,
                102,
                44818,
                47808,
                20000,
                4840,
                2404,
                18245,
                9600,
                5007,
                2455,
            }
            exclude_set = exclude_set | ot_ports

        if exclude_set:
            ports = [p for p in ports if p not in exclude_set]
        return ports

    def scan_configuration(self) -> dict:
        """
        The parameters this scan actually ran with.

        Coverage bounds every conclusion drawn from a scan: a service on a port
        outside the scanned range cannot produce a finding, and a report that
        cannot state the range cannot be reproduced or defended. The engine is
        the only component that knows these values, so it publishes them rather
        than leaving the report to guess — or, worse, to assume a default.
        """
        ports = self._port_list()
        if self.custom_ports:
            selection = f"{len(ports)} custom port(s): {_summarize_ports(ports)}"
        elif self.intensity == ScanIntensity.LIGHT:
            scope = (
                "Common IT ports"
                if self.exclude_ot_from_nmap
                else ("Common IT and OT ports")
            )
            selection = f"{scope} ({len(ports)} ports)"
        elif self.intensity == ScanIntensity.DEEP:
            selection = "All 65535 TCP ports"
        else:
            selection = (
                f"System ports 1-1024 plus curated high ports ({len(ports)} ports)"
            )

        if self.exclude_ports:
            selection += f"; excluded {_summarize_ports(sorted(self.exclude_ports))}"
        if self.exclude_ot_from_nmap:
            selection += "; OT protocol ports excluded from active probing"

        service_detection = (
            "Enabled (banner and probe fingerprinting)"
            if self.intensity in (ScanIntensity.NORMAL, ScanIntensity.DEEP)
            or self.custom_ports
            else "Not performed (port state only)"
        )

        return {
            "port_range": selection,
            # The same set, machine-readable, so a later phase can tell a port
            # that was probed and stayed silent from one that was never probed.
            "ports_probed_spec": _ports_spec(ports),
            "timing_template": (
                f"Nmap -T4 ({self.intensity.value} intensity)"
                if NMAP_AVAILABLE
                else "Async TCP connect fallback"
            ),
            "scanner": (
                f"Nmap {self._nmap.nmap_version}".strip()
                if NMAP_AVAILABLE and getattr(self._nmap, "nmap_version", "")
                else ("Nmap" if NMAP_AVAILABLE else "Built-in TCP connect scanner")
            ),
            "service_detection": service_detection,
            "os_detection": "Enabled" if self.os_detection else "Not performed",
        }

    @staticmethod
    def _ip(host: dict) -> str | None:
        return host.get("ip_address") or host.get("ip")
