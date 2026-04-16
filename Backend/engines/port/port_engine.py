"""
engines/port/port_engine.py
----------------------------
Phase 2 - Port Scanning

For each active host, concurrently probes all ports in the selected port list
using asyncio TCP connect + Scapy-based UDP probes for common services.
Returns hosts enriched with open_ports + udp_services + initial CVEs.

Port list by intensity:
  LIGHT  -> SCAN_PORTS_QUICK  (top-68 high-value ports)
  NORMAL -> SCAN_PORTS_FULL   (all named ports in PORT_DB)
  DEEP   -> SCAN_PORTS_FULL  (named ports, longer timeout, deeper probing)

UDP Services scanned (all intensities):
  DNS(53), DHCP(67), TFTP(69), Kerberos(88), NTP(123), NetBIOS-NS(137),
  NetBIOS-DGM(138), SNMP(161), SNMP-Trap(162), LDAP(389), IKE(500),
  Syslog(514), RIP(520), IPMI(623), UPnP(1900), mDNS(5353)

UDP state semantics
-------------------
  "open"         — target replied with a UDP datagram
  "open|filtered"— no reply AND no ICMP Unreachable (Scapy path only)
                   — or confirmed no response (socket fallback path)
  closed ports are NEVER added to udp_services (we discard ICMP port-unreach)

When Scapy is available (privileged):
  Uses sr() so ICMP Unreachable responses are matched back to their originating
  UDP probes — the only correct way to differentiate open|filtered vs closed.

When Scapy is unavailable (unprivileged):
  Falls back to async socket; records "open" on reply, "open|filtered" on
  timeout (honest — cannot detect closed via ICMP without raw sockets).
"""

import asyncio
import logging
import socket
import ssl
import time
from typing import Dict, List, Optional

from core.constants import PORT_DB, SCAN_PORTS_QUICK, SCAN_PORTS_FULL, SCAPY_AVAILABLE
from core.models import PortResult, ScanIntensity
from core.utils import lookup_cve, extract_version

log = logging.getLogger("ccure.port")

_TLS_PORTS = {443, 8443, 465, 993, 995}

# ICMP type-3 codes that mean filtered (admin/policy block — NOT "port closed")
_ICMP3_FILTERED_CODES = {1, 2, 9, 10, 13}

# ---------------------------------------------------------------------------
# Expanded UDP service table  (port -> {service, risk, probe})
# ---------------------------------------------------------------------------

_UDP_SERVICES: Dict[int, Dict] = {
    53:   {"service": "dns",         "risk": "High",   "probe": "dns"},
    67:   {"service": "dhcp",        "risk": "High",   "probe": "dhcp"},
    69:   {"service": "tftp",        "risk": "High",   "probe": "tftp"},
    88:   {"service": "kerberos",    "risk": "High",   "probe": "generic"},
    123:  {"service": "ntp",         "risk": "Medium", "probe": "ntp"},
    137:  {"service": "netbios-ns",  "risk": "High",   "probe": "netbios"},
    138:  {"service": "netbios-dgm", "risk": "Medium", "probe": "generic"},
    161:  {"service": "snmp",        "risk": "High",   "probe": "snmp"},
    162:  {"service": "snmp-trap",   "risk": "Medium", "probe": "snmp"},
    389:  {"service": "ldap",        "risk": "High",   "probe": "generic"},
    500:  {"service": "ike",         "risk": "High",   "probe": "ike"},
    514:  {"service": "syslog",      "risk": "Medium", "probe": "syslog"},
    520:  {"service": "rip",         "risk": "Medium", "probe": "generic"},
    623:  {"service": "ipmi",        "risk": "High",   "probe": "ipmi"},
    1900: {"service": "upnp",        "risk": "Medium", "probe": "upnp"},
    5353: {"service": "mdns",        "risk": "Low",    "probe": "mdns"},
}

# Protocol-specific banner grabbing probes for TCP services
# Maps port -> (probe_bytes, service_name)
# Intensity gate: ports with intensity=7 are only probed in DEEP mode
_PROTOCOL_PROBES: Dict[int, tuple] = {
    # ── Standard application services ──────────────────────────────────
    3306:  (b"\x00\x00\x00\x00",                                        "mysql"),
    5432:  (b"\x00\x00\x00\x08\x04\xd2\x16\x2f",                       "postgresql"),
    1433:  (b"\x00\x00\x00\x00",                                        "mssql"),
    27017: (b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00",       "mongodb"),
    6379:  (b"PING\r\n",                                                 "redis"),
    3389:  (b"\x03\x00\x00\x00\x04\x00\x00\x00",                       "rdp"),
    5900:  (b"",                                                         "vnc"),
    25:    (b"HELO scanner\r\n",                                         "smtp"),
    110:   (b"USER scanner\r\n",                                         "pop3"),
    143:   (b"A1 CAPABILITY\r\n",                                        "imap"),
    21:    (b"HELP\r\n",                                                 "ftp"),
    6389:  (b"\x00\x00",                                                 "sysbase"),
    1521:  (b"\x00\x00",                                                 "oracle"),
    # ── ICS / SCADA protocols (GAP-05) ─────────────────────────────────
    # Modbus TCP: Read Device Identification (FC 43, MEI type 14)
    #   MBAP header: TID=0x0001, PID=0x0000, LEN=5, UNIT=0xFF
    #   PDU:         FC=0x2B, MEI=0x0E, RD_Level=0x01, OID=0x00
    502:   (
        b"\x00\x01\x00\x00\x00\x05\xff\x2b\x0e\x01\x00",
        "modbus",
    ),
    # Siemens S7comm: TPKT + COTP Connection Request (ISO 8073)
    #   TPKT:      version=3, length=22
    #   COTP CR:   LI=17, PDU=0xE0, dst-ref=0, src-ref=1, class=0
    #   Params:    TPDU-size=512, src-TSAP=0x0100, dst-TSAP=0x0102
    102:   (
        b"\x03\x00\x00\x16"
        b"\x11\xe0\x00\x00\x00\x01\x00"
        b"\xc0\x01\x09"
        b"\xc1\x02\x01\x00"
        b"\xc2\x02\x01\x02",
        "s7comm",
    ),
    # DNP3: Link Layer Reset Remote Link frame
    #   Start bytes 0x0564, length=5, ctrl=0xC0 (DIR+PRM+FC=0),
    #   destination=0xFFFF (broadcast), source=0x0001, CRC placeholder
    20000: (
        b"\x05\x64\x05\xC0\xFF\xFF\x01\x00\x00\x00",
        "dnp3",
    ),
    # EtherNet/IP (CIP): List Identity request
    #   Command=0x0065, Length=0, Session=0, Status=0,
    #   Sender context=0, Options=0
    44818: (
        b"\x65\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00",
        "ethernet-ip",
    ),
    # BACnet/IP over TCP (BVLC + WhoIs APDU)
    47808: (
        b"\x81\x0a\x00\x0c"
        b"\x01\x20\xff\xff\x00\xff"
        b"\x10\x08",
        "bacnet",
    ),
    # OPC-UA (port 4840): Hello message
    4840:  (
        b"HEL\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00",
        "opc-ua",
    ),
    # RPC Portmapper / rpcbind (111): NULL CALL
    #   Record Marking: last frag, length=40
    #   XID, Call, RPC v2, prog=100000 (portmap), ver=2, proc=0 (NULL)
    #   Auth=AUTH_NULL, Verifier=AUTH_NULL
    111:   (
        b"\x80\x00\x00\x28"
        b"\x72\xfe\x1d\x13"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x02"
        b"\x00\x01\x86\xa0"
        b"\x00\x00\x00\x02"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00",
        "portmapper",
    ),
    # Lantronix Device Server (9999): Get setup banner
    9999:  (b"\x00",                                                     "lantronix"),
    # Fox/Niagara (1911): initiate protocol
    1911:  (b"fox a 1 -1 fox hello\n",                                  "niagara-fox"),
}


# ---------------------------------------------------------------------------
# Module-level helpers (used by both Scapy thread and socket coroutines)
# ---------------------------------------------------------------------------

def _add_udp_result(
    host: Dict,
    port: int,
    service_info: Dict,
    state: str,
    banner: str,
) -> None:
    """Append a UDP result to the host dict, deduplicating by port."""
    existing = {s.get("port") for s in host.get("udp_services", [])}
    if port not in existing:
        host.setdefault("udp_services", []).append({
            "port":    port,
            "service": service_info.get("service", "unknown"),
            "state":   state,
            "banner":  banner,
            "risk":    service_info.get("risk", "Info"),
        })


def _build_udp_payload(port: int, probe_type: str) -> bytes:
    """
    Build the correct protocol payload for a UDP probe.

    Returns ``b""`` for 'generic' probes (bare UDP with no payload is enough
    to elicit an ICMP Port-Unreachable on closed ports, which is all we need).
    """
    if probe_type == "dns":
        # Standard DNS A query for "localhost"
        return bytes([
            0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63,
            0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x00, 0x00,
            0x01, 0x00, 0x01,
        ])

    elif probe_type == "snmp":
        # SNMPv2c GetRequest — community "public", sysDescr OID 1.3.6.1.2.1.1.1.0
        return (
            b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19"
            b"\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00"
            b"\x30\x0b\x06\x07\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
        )

    elif probe_type == "ntp":
        # NTPv3 client-mode timestamp request (48 bytes)
        return bytes([0x23] + [0x00] * 47)

    elif probe_type == "dhcp":
        # Minimal DHCP DISCOVER with magic cookie
        return (
            b"\x01\x01\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x63\x82\x53\x63"
            b"\x35\x01\x01\xff"   # Option 53: DHCP Discover, End
        )

    elif probe_type == "tftp":
        # TFTP Read Request (RRQ) for a probe filename
        return b"\x00\x01ccure_probe\x00netascii\x00"

    elif probe_type == "netbios":
        # NetBIOS Name Service — Node Status Request
        return (
            b"\xa2\x48\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41"
            b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
            b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
        )

    elif probe_type == "ike":
        # IKEv1 Phase-1 Main Mode SA initiation (minimal 28-byte header)
        return (
            b"\x00" * 8 +       # Initiator SPI (8 bytes, zeroed for probe)
            b"\x00" * 8 +       # Responder SPI (zeros)
            b"\x01" +           # Next payload = SA
            b"\x10" +           # Version = 1.0
            b"\x02" +           # Exchange type = Main Mode
            b"\x00" +           # Flags
            b"\x00\x00\x00\x00" +  # Message ID
            b"\x00\x00\x00\x1c"    # Total length = 28
        )

    elif probe_type == "ipmi":
        # RMCP ASF Presence Ping (probes BMCs responding on port 623)
        return bytes([
            0x06, 0x00, 0xff, 0x06,   # RMCP header (ver/rsv/seq/class)
            0x00, 0x00, 0x11, 0xbe,   # ASF IANA enterprise number
            0x80, 0x00,               # Msg type: Presence Ping + tag=0
            0x00, 0x00,               # Reserved
        ])

    elif probe_type == "mdns":
        # mDNS PTR query for _services._dns-sd._udp.local
        return bytes([
            0x00, 0x00,  # Transaction ID: 0 (mDNS convention)
            0x00, 0x00,  # Flags: standard query
            0x00, 0x01,  # Questions: 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   # Ans/Auth/Addl: 0
            # _services._dns-sd._udp.local  PTR
            0x09, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
            0x07, 0x5f, 0x64, 0x6e, 0x73, 0x2d, 0x73, 0x64,
            0x04, 0x5f, 0x75, 0x64, 0x70,
            0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
            0x00,
            0x00, 0x0c,  # Type: PTR
            0x00, 0x01,  # Class: IN
        ])

    elif probe_type == "syslog":
        return b"<34>1 - - - - - CCure-probe\n"

    elif probe_type == "upnp":
        return (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"HOST: 239.255.255.250:1900\r\n"
            b'MAN: "ssdp:discover"\r\n'
            b"MX: 2\r\n"
            b"ST: ssdp:all\r\n\r\n"
        )

    # "generic" / unknown — empty payload is fine; we watch for ICMP back
    return b""


# ---------------------------------------------------------------------------
# Port Engine
# ---------------------------------------------------------------------------

class PortEngine:
    def __init__(self, intensity: ScanIntensity = ScanIntensity.NORMAL, version_intensity: int = 3):
        self.intensity         = intensity
        # GAP-05: version_intensity controls probe aggressiveness
        # 1 = banner-only, 3 = protocol probes (default), 7 = ICS/SCADA probes
        self.version_intensity = max(1, min(9, version_intensity))

    # ------------------------------------------------------------------
    # Public entry
    # ------------------------------------------------------------------
    async def run(self, hosts: List[Dict]) -> List[Dict]:
        """
        hosts: list of discovery result dicts (only is_active==True entries
        are processed). Returns the same list enriched with open_ports,
        udp_services, and cves fields.
        """
        active = [h for h in hosts if h.get("is_active")]
        if not active:
            return hosts
        await self._scan_all(active)
        return hosts

    # ------------------------------------------------------------------
    # Internal configuration
    # ------------------------------------------------------------------
    def _port_list(self) -> List[int]:
        if self.intensity == ScanIntensity.LIGHT:
            return SCAN_PORTS_QUICK
        # NORMAL and DEEP both use the full named-port list.
        # DEEP means "same ports, longer timeout, deeper banner grab" —
        # not 65 k ports (which triggers rate-limiting on both ends).
        return SCAN_PORTS_FULL

    def _concurrency(self) -> int:
        return 50 if self.intensity == ScanIntensity.DEEP else 500

    def _timeout(self) -> float:
        return 2.0 if self.intensity == ScanIntensity.DEEP else 0.8

    # ------------------------------------------------------------------
    # Scan orchestrator
    # ------------------------------------------------------------------
    async def _scan_all(self, hosts: List[Dict]) -> None:
        ports = self._port_list()
        concurrency = self._concurrency()
        tout = self._timeout()

        # ── Build IP → host-dict lookup (handles both key names) ────────
        hosts_map: Dict[str, Dict] = {}
        ip_field: Optional[str] = None
        for h in hosts:
            if "ip_address" in h:
                ip_field = "ip_address"
                break
            elif "ip" in h:
                ip_field = "ip"
                break
        if not ip_field:
            ip_field = "ip_address"
        for h in hosts:
            ip = h.get(ip_field)
            if ip:
                hosts_map[ip] = h

        # ── TCP port scan (async, concurrent worker pool) ────────────────
        tcp_queue = asyncio.Queue()
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
                    await self._probe_tcp(ip, port, hosts_map, tout)
                except Exception as e:
                    pass
                finally:
                    tcp_queue.task_done()

        workers = [asyncio.create_task(tcp_worker()) for _ in range(concurrency)]
        await asyncio.gather(*workers)

        # ── UDP service scan ──────────────────────────────────────────────
        if SCAPY_AVAILABLE:
            # Primary path: Scapy sr() sees ICMP Unreachable replies → correct
            # open/closed/filtered differentiation.  Runs in thread executor
            # so blocking Scapy calls don't stall the event loop.
            await self._scan_udp_scapy(list(hosts_map.keys()), hosts_map)
        else:
            # Fallback: async socket per port. Uses a similar worker pool.
            udp_queue = asyncio.Queue()
            for ip in hosts_map:
                for p in _UDP_SERVICES:
                    udp_queue.put_nowait((ip, p))

            async def udp_worker():
                while True:
                    try:
                        ip, port = udp_queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    
                    try:
                        await self._probe_udp_socket(ip, port, hosts_map, tout)
                    except Exception:
                        pass
                    finally:
                        udp_queue.task_done()

            udp_workers = [asyncio.create_task(udp_worker()) for _ in range(min(50, concurrency))]
            await asyncio.gather(*udp_workers)

    # ------------------------------------------------------------------
    # TCP probe
    # ------------------------------------------------------------------
    async def _probe_tcp(
        self,
        ip: str,
        port: int,
        hosts_map: Dict[str, Dict],
        timeout: float = 0.8,
    ) -> None:
        """TCP connect probe with GAP-04 state differentiation.

        Three outcomes:
          Port OPEN     — connection accepted; banner grabbed and recorded.
          Port CLOSED   — target sent TCP RST (ConnectionRefusedError);
                          increments closed_ports_count on the host.
          Port FILTERED — no response within timeout; firewall silently dropped;
                          increments filtered_ports_count on the host.
        """
        # GAP-05: Skip ICS probes unless version_intensity >= 7
        _ICS_PORTS = {502, 102, 20000, 44818, 47808, 4840, 1911}
        if port in _ICS_PORTS and self.version_intensity < 7:
            return

        use_tls = port in _TLS_PORTS
        t0 = time.time()

        # ── Attempt TCP connection ─────────────────────────────────────
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                conn = asyncio.open_connection(ip, port, ssl=ctx)
            else:
                conn = asyncio.open_connection(ip, port)

            reader, writer = await asyncio.wait_for(conn, timeout=timeout)

        except (asyncio.TimeoutError, TimeoutError):
            # GAP-04: Firewall silently dropped the SYN → filtered
            host = hosts_map.get(ip)
            if host is not None:
                host["filtered_ports_count"] = host.get("filtered_ports_count", 0) + 1
            return

        except ConnectionRefusedError:
            # GAP-04: TCP RST received → port is definitively closed
            host = hosts_map.get(ip)
            if host is not None:
                host["closed_ports_count"] = host.get("closed_ports_count", 0) + 1
            return

        except OSError as exc:
            # Windows WSAECONNREFUSED (10061) or ECONNREFUSED (111 on Linux)
            errno = getattr(exc, "errno", None) or getattr(exc, "winerror", None)
            if errno in (111, 10061):
                host = hosts_map.get(ip)
                if host is not None:
                    host["closed_ports_count"] = host.get("closed_ports_count", 0) + 1
            return

        except ssl.SSLError:
            # TLS port responded but handshake failed → still open
            # Fall through to record as open without banner
            pass

        except Exception:
            return

        # ── Port is OPEN — grab banner ─────────────────────────────────
        banner = ""
        try:
            if port in _PROTOCOL_PROBES and self.version_intensity >= 3:
                probe_bytes, _ = _PROTOCOL_PROBES[port][:2]
                if probe_bytes:
                    writer.write(probe_bytes)
                    await writer.drain()
            elif port in (80, 8080, 8000, 8888, 443, 8443):
                writer.write(
                    b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n"
                )
                await writer.drain()

            data = await asyncio.wait_for(reader.read(4096), timeout=1.0)
            if data:
                try:
                    banner = data.decode("utf-8", errors="ignore").strip()
                except Exception:
                    banner = data.decode("latin1", errors="ignore").strip()
                banner = self._parse_banner(port, banner, data)
        except asyncio.TimeoutError:
            banner = ""   # No banner within window, but port IS open
        except Exception:
            pass

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        elapsed = (time.time() - t0) * 1000
        meta    = PORT_DB.get(port, {"service": "unknown", "risk": "Info", "note": ""})
        cves    = lookup_cve(banner) if banner else lookup_cve(meta["service"].lower())

        pr = PortResult(
            port    = port,
            service = meta["service"],
            state   = "open",
            banner  = banner,
            version = extract_version(banner, meta["service"]),
            risk    = meta["risk"],
            cves    = cves,
        )

        host = hosts_map.get(ip)
        if host is None:
            return
        if host.get("elapsed_ms") is None:
            host["elapsed_ms"] = elapsed

        existing = {p["port"] for p in host.get("open_ports", [])}
        if port not in existing:
            host.setdefault("open_ports", []).append(pr.to_dict())
            host.setdefault("cves", []).extend(cves)

    # ------------------------------------------------------------------
    # UDP scan — Scapy batch (primary path, requires privileges)
    # ------------------------------------------------------------------
    async def _scan_udp_scapy(
        self,
        ips: List[str],
        hosts_map: Dict[str, Dict],
    ) -> None:
        """
        Batch UDP scan using Scapy's sr() which captures ICMP Unreachable
        replies at the raw-socket level.

        State logic (per probe):
          UDP datagram reply received          → "open"
          ICMP type-3 code-3 (port unreach)   → closed  (NOT added)
          ICMP type-3 other codes (filtered)   → filtered (NOT added)
          No reply within timeout              → "open|filtered"
        """
        loop = asyncio.get_event_loop()

        def _do_scan() -> None:
            try:
                from scapy.all import IP, UDP, ICMP, Raw, sr
            except ImportError:
                log.debug("_scan_udp_scapy: Scapy import failed in executor")
                return

            # Build packet list: one probe per IP × per UDP service port
            pkts = []
            for ip in ips:
                for port, info in _UDP_SERVICES.items():
                    payload = _build_udp_payload(port, info["probe"])
                    pkt = IP(dst=ip) / UDP(dport=port)
                    if payload:
                        pkt = pkt / Raw(load=payload)
                    pkts.append(pkt)

            if not pkts:
                return

            try:
                # timeout=3 s gives slow hosts time to reply or generate ICMP;
                # multi=True keeps collecting until timeout (not just first reply)
                ans, unans = sr(pkts, timeout=3.0, verbose=0, multi=True)
            except Exception as exc:
                log.debug("_scan_udp_scapy sr() error: %s", exc)
                return

            # ── Process answered probes ──────────────────────────────────
            for snd, rcv in ans:
                if not (snd.haslayer(IP) and snd.haslayer(UDP)):
                    continue
                ip   = snd[IP].dst
                port = snd[UDP].dport
                if ip not in hosts_map:
                    continue
                host         = hosts_map[ip]
                service_info = _UDP_SERVICES.get(port, {})

                if rcv.haslayer(ICMP) and rcv[ICMP].type == 3:
                    code = rcv[ICMP].code
                    if code == 3:
                        # Port Unreachable → definitely closed; skip entirely
                        pass
                    elif code in _ICMP3_FILTERED_CODES:
                        # Admin/policy filtered; skip
                        pass
                    # Any other ICMP-3 code (e.g. network unreach): also skip
                elif rcv.haslayer(UDP):
                    # A real UDP datagram came back → port is open
                    try:
                        raw_bytes = bytes(rcv[UDP].payload)
                        banner = raw_bytes.decode("utf-8", errors="ignore").strip()[:120]
                    except Exception:
                        banner = ""
                    _add_udp_result(host, port, service_info, "open", banner)

            # ── Unanswered probes → open|filtered ────────────────────────
            # No reply + no ICMP unreachable = firewall is silently dropping,
            # OR the service is up but didn't respond to our probe.
            for snd in unans:
                if not (snd.haslayer(IP) and snd.haslayer(UDP)):
                    continue
                ip   = snd[IP].dst
                port = snd[UDP].dport
                if ip not in hosts_map:
                    continue
                host         = hosts_map[ip]
                service_info = _UDP_SERVICES.get(port, {})
                _add_udp_result(host, port, service_info, "open|filtered", "")

        await loop.run_in_executor(None, _do_scan)

    # ------------------------------------------------------------------
    # UDP probe — async socket fallback (no privileges needed)
    # ------------------------------------------------------------------
    async def _probe_udp_socket(
        self,
        ip: str,
        port: int,
        hosts_map: Dict[str, Dict],
        timeout: float = 0.8,
    ) -> None:
        """
        Async socket-based UDP probe.  Uses recvfrom() so it cannot observe
        ICMP Unreachable replies — the OS absorbs them before recvfrom sees
        anything.

        State assignment:
          - UDP reply received → "open"
          - Timeout (no reply) → "open|filtered"  (honest; cannot confirm closed)
        """
        if port not in _UDP_SERVICES:
            return

        service_info = _UDP_SERVICES[port]
        try:
            t0      = time.time()
            loop    = asyncio.get_event_loop()
            sock    = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)

            payload = _build_udp_payload(port, service_info["probe"])
            try:
                await loop.sock_sendto(sock, payload or b"\x00", (ip, port))
            except Exception:
                sock.close()
                return

            # Default state when we can't detect ICMP: honest ambiguity
            state  = "open|filtered"
            banner = ""
            try:
                data, _ = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 4096),
                    timeout=timeout,
                )
                # A real datagram arrived → port is definitely open
                banner = data.decode("utf-8", errors="ignore").strip()[:100]
                state  = "open"
            except asyncio.TimeoutError:
                pass   # leave state as "open|filtered"
            except Exception:
                pass

            sock.close()

            host = hosts_map.get(ip)
            if host is None:
                return
            if host.get("elapsed_ms") is None:
                host["elapsed_ms"] = (time.time() - t0) * 1000

            _add_udp_result(host, port, service_info, state, banner)

        except Exception:
            pass

    # ------------------------------------------------------------------
    # Banner parsing
    # ------------------------------------------------------------------
    def _parse_banner(
        self,
        port: int,
        banner_text: str,
        raw_data: bytes = None,
    ) -> str:
        if not banner_text:
            return ""
        banner_text = banner_text[:200]

        if port == 22:
            lines = banner_text.split("\n")
            if lines:
                return lines[0].strip()

        elif port == 3306:
            if "mysql" in banner_text.lower():
                return banner_text.split("\x00")[0].strip()
            if raw_data and len(raw_data) > 10:
                try:
                    vs = 1
                    ve = raw_data.find(b"\x00", vs)
                    if ve > vs:
                        v = raw_data[vs:ve].decode("utf-8", errors="ignore").strip()
                        if v:
                            return f"MySQL {v}"
                except Exception:
                    pass

        elif port == 5432:
            if "postgres" in banner_text.lower():
                return banner_text.split("\n")[0].strip()
            return "PostgreSQL"

        elif port == 1433:
            if raw_data and (b"MSSQL" in raw_data or b"mssql" in raw_data.lower()):
                return "MSSQL Server"
            return banner_text.split("\n")[0].strip() if banner_text else "MSSQL"

        elif port == 27017:
            if "ok" in banner_text.lower() or "ismaster" in banner_text.lower():
                return "MongoDB"
            return banner_text.split("\n")[0].strip() if banner_text else "MongoDB"

        elif port == 6379:
            if banner_text.startswith("+"):
                return f"Redis (responded: {banner_text.split()[0][:20]})"
            elif banner_text.startswith("-"):
                return "Redis"
            return banner_text.split("\n")[0].strip() if banner_text else "Redis"

        elif port == 3389:
            if raw_data and len(raw_data) > 0:
                return "RDP/Remote Desktop"
            return "RDP"

        elif port == 5900:
            if "rfb" in banner_text.lower():
                return banner_text.split("\n")[0].strip()
            return "VNC"

        elif port in (25, 110, 143, 21):
            lines = banner_text.split("\n")
            if lines:
                return lines[0].strip()

        # ── GAP-05: ICS / SCADA banner parsing ──────────────────────────
        elif port == 502:
            return self._parse_modbus_banner(raw_data)

        elif port == 102:
            return self._parse_s7comm_banner(raw_data)

        elif port == 20000:
            return self._parse_dnp3_banner(raw_data)

        elif port == 44818:
            return self._parse_enip_banner(raw_data, banner_text)

        elif port == 4840:
            if raw_data and raw_data[:3] == b"ACK":
                return "OPC-UA Server"
            if banner_text:
                return f"OPC-UA: {banner_text[:60]}"
            return "OPC-UA"

        elif port == 111:
            if raw_data and len(raw_data) >= 8:
                return "RPC Portmapper (rpcbind)"
            return "Portmapper"

        # Generic: return first non-empty line
        if "\n" in banner_text:
            first = banner_text.split("\n")[0].strip()
            if first:
                return first

        return banner_text.strip() if banner_text else ""

    # ------------------------------------------------------------------
    # GAP-05: ICS / SCADA protocol-specific banner decoders
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_modbus_banner(raw_data: bytes) -> str:
        """
        Decode a Modbus TCP Device Identification response (FC 43, MEI 14).

        Object IDs: 0x00=VendorName, 0x01=ProductCode, 0x02=Revision
        Response layout:
          [0:2]  Transaction ID
          [2:4]  Protocol ID (0x0000)
          [4:6]  Length
          [6]    Unit ID
          [7]    Function code (0x2B)
          [8]    MEI type (0x0E)
          [9]    Read device ID code
          [10]   Conformity level
          [11]   More follows / next OID / number of objects
          [12]   Object count
          [13:]  Objects: [OID, LEN, DATA...]
        """
        if not raw_data or len(raw_data) < 14:
            return "Modbus TCP"

        # Check it's a valid Modbus response (not exception)
        if len(raw_data) > 7 and raw_data[7] == 0xAB:   # 0x2B | 0x80
            code = raw_data[8] if len(raw_data) > 8 else 0
            return f"Modbus TCP (exception code {code})"

        objects: dict = {}
        idx = 13
        try:
            obj_count = raw_data[12]
            for _ in range(obj_count):
                if idx + 2 > len(raw_data):
                    break
                oid = raw_data[idx]
                length = raw_data[idx + 1]
                idx += 2
                if idx + length > len(raw_data):
                    break
                objects[oid] = raw_data[idx: idx + length].decode("utf-8", errors="ignore")
                idx += length
        except Exception:
            pass

        vendor  = objects.get(0x00, "")
        product = objects.get(0x01, "")
        rev     = objects.get(0x02, "")

        if vendor or product:
            parts = [p for p in [vendor, product, rev] if p]
            return "Modbus/" + " ".join(parts)
        return "Modbus TCP device"

    @staticmethod
    def _parse_s7comm_banner(raw_data: bytes) -> str:
        """
        Detect S7comm COTP Connection Confirm (PDU type 0xD0).
        A CC response confirms a Siemens S7 PLC is listening.
        """
        if not raw_data or len(raw_data) < 7:
            return "S7/Siemens device"

        # TPKT: bytes 0-3, COTP starts at byte 4
        # COTP CC PDU = 0xD0
        cotp_pdu = raw_data[5] if len(raw_data) > 5 else 0
        if cotp_pdu == 0xD0:
            return "Siemens S7 PLC (COTP connection confirmed)"
        elif cotp_pdu == 0xE0:
            return "Siemens S7 (COTP CR — unexpected, may relay)"
        return "Siemens S7 / COTP device"

    @staticmethod
    def _parse_dnp3_banner(raw_data: bytes) -> str:
        """
        Minimal DNP3 link-layer frame parser.
        Valid frames start with 0x0564 (start bytes).
        """
        if not raw_data or len(raw_data) < 4:
            return "DNP3 device"

        if raw_data[0] == 0x05 and raw_data[1] == 0x64:
            ctrl = raw_data[3] if len(raw_data) > 3 else 0
            fc   = ctrl & 0x0F
            fc_names = {
                0: "Reset Remote Link",  1: "Reset User Process",
                2: "Test Link States",   3: "Send/Confirm Data",
                9: "Request Link Status",
            }
            fc_label = fc_names.get(fc, f"FC={fc}")
            return f"DNP3 ({fc_label})"
        return "DNP3 / ICS device"

    @staticmethod
    def _parse_enip_banner(raw_data: bytes, banner_text: str) -> str:
        """
        Decode EtherNet/IP (CIP) List Identity response.
        Response command = 0x0065, encapsulation header = 24 bytes.
        """
        if not raw_data or len(raw_data) < 4:
            return "EtherNet/IP device"

        cmd = int.from_bytes(raw_data[0:2], "little") if len(raw_data) >= 2 else 0
        if cmd == 0x0065:
            # Parse device type / vendor name from CPF list items if present
            try:
                # Item count at offset 26 (after 24-byte header + 2-byte count)
                if len(raw_data) > 28:
                    vendor_id = int.from_bytes(raw_data[36:38], "little")
                    device_type = int.from_bytes(raw_data[38:40], "little")
                    return f"EtherNet/IP CIP (Vendor={vendor_id:#06x}, Type={device_type:#06x})"
            except Exception:
                pass
            return "EtherNet/IP / CIP device"

        if banner_text:
            return f"EtherNet/IP: {banner_text[:60]}"
        return "EtherNet/IP device"
