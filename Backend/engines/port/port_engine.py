"""
engines/port/port_engine.py
----------------------------
Phase 2 - Port Scanning

For each active host, concurrently probes all ports in the selected port list
using asyncio TCP connect + lightweight UDP probes for common services.
Returns hosts enriched with open_ports + udp_services + initial CVEs.

Port list by intensity:
  LIGHT  -> SCAN_PORTS_QUICK  (top-68 high-value ports)
  NORMAL -> SCAN_PORTS_FULL   (all named ports in PORT_DB)
  DEEP   -> SCAN_PORTS_FULL  (named ports, longer timeout, deeper probing)

UDP Services (scanned on all intensities):
  DNS (53), DHCP (67), NTP (123), SNMP (161), Syslog (514), UPnP (1900)
"""

import asyncio
import socket
import ssl
import time
from typing import Dict, List

from core.constants import PORT_DB, SCAN_PORTS_QUICK, SCAN_PORTS_FULL
from core.models import PortResult, ScanIntensity
from core.utils import lookup_cve, extract_version

_TLS_PORTS = {443, 8443, 465, 993, 995}

# UDP ports for critical services discovered during asset discovery
_UDP_SERVICES = {
    53:    {"service": "dns",    "risk": "High",   "probe": "dns"},
    67:    {"service": "dhcp",   "risk": "High",   "probe": "dhcp"},
    123:   {"service": "ntp",    "risk": "Medium", "probe": "ntp"},
    161:   {"service": "snmp",   "risk": "High",   "probe": "snmp"},
    162:   {"service": "snmp-t", "risk": "Medium", "probe": "snmp"},
    514:   {"service": "syslog", "risk": "Medium", "probe": "syslog"},
    1900:  {"service": "upnp",   "risk": "Medium", "probe": "upnp"},
}

# Protocol-specific banner grabbing probes for common services
# Maps port -> (probe_bytes, service_name, parser_function)
_PROTOCOL_PROBES = {
    # Database servers - send protocol-specific handshake
    3306:  (b"\x00\x00\x00\x00", "mysql"),          # MySQL: minimal handshake
    5432:  (b"\x00\x00\x00\x08\x04\xd2\x16\x2f", "postgresql"),  # PostgreSQL: startup msg
    1433:  (b"\x00\x00\x00\x00", "mssql"),          # MSSQL: TDS handshake
    27017: (b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00", "mongodb"),  # MongoDB: noop
    6379:  (b"PING\r\n", "redis"),                  # Redis: PING command
    
    # Remote access/VNC
    3389:  (b"\x03\x00\x00\x00\x04\x00\x00\x00", "rdp"),         # RDP: X.224 conn req
    5900:  (b"", "vnc"),                             # VNC: server sends first
    
    # Mail services
    25:    (b"HELO scanner\r\n", "smtp"),            # SMTP: HELO command
    110:   (b"USER scanner\r\n", "pop3"),            # POP3: USER command
    143:   (b"A1 CAPABILITY\r\n", "imap"),           # IMAP: CAPABILITY command
    
    # FTP
    21:    (b"HELP\r\n", "ftp"),                     # FTP: HELP command
    
    # Lightweight protocols
    6389:  (b"\x00\x00", "sysbase"),                 # Sybase: minimal packet
    1521:  (b"\x00\x00", "oracle"),                  # Oracle: minimal packet
}


class PortEngine:
    def __init__(self, intensity: ScanIntensity = ScanIntensity.NORMAL):
        self.intensity = intensity

    # ------------------------------------------------------------------
    # Public entry
    # ------------------------------------------------------------------
    async def run(self, hosts: List[Dict]) -> List[Dict]:
        """
        hosts: list of discovery result dicts (only is_active==True entries processed).
        Returns same list with 'open_ports' and 'cves' fields populated.
        """
        active = [h for h in hosts if h.get("is_active")]
        if not active:
            return hosts
        
        # Directly await the async _scan_all coroutine
        await self._scan_all(active)
        
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

        async def bounded_tcp(ip, port):
            async with sem:
                await self._probe_port(ip, port, hosts_map, tout)

        async def bounded_udp(ip, port):
            async with sem:
                await self._probe_udp(ip, port, hosts_map, tout)

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

        # TCP port scanning tasks
        tcp_tasks = [bounded_tcp(ip, p) for ip in hosts_map.keys() for p in ports]
        
        # UDP service scanning (common ports)
        udp_tasks = [bounded_udp(ip, p) for ip in hosts_map.keys() for p in _UDP_SERVICES.keys()]
        
        # Run both TCP and UDP scans concurrently
        all_tasks = tcp_tasks + udp_tasks
        await asyncio.gather(*all_tasks)

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

            # -- Smart banner grab ----------------------------------------
            banner = ""
            try:
                # Try protocol-specific probes first
                if port in _PROTOCOL_PROBES:
                    probe_bytes, service_name = _PROTOCOL_PROBES[port][:2]
                    if probe_bytes:
                        try:
                            writer.write(probe_bytes)
                            await writer.drain()
                        except Exception:
                            pass
                
                # If no special handling, try HTTP HEAD probe for common web ports
                elif port in (80, 8080, 8000, 8888, 443, 8443):
                    writer.write(
                        b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n"
                    )
                    await writer.drain()
                
                # Read response
                data = await asyncio.wait_for(reader.read(4096), timeout=1.0)
                if data:
                    # Try to decode as text first
                    try:
                        banner = data.decode("utf-8", errors="ignore").strip()
                    except Exception:
                        # Fall back to latin1 if UTF-8 fails
                        banner = data.decode("latin1", errors="ignore").strip()
                    
                    # Service-specific banner parsing
                    banner = self._parse_banner(port, banner, data)
                    
            except asyncio.TimeoutError:
                # Service sent no data within timeout - may still be open
                banner = ""
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

    async def _probe_udp(self, ip: str, port: int, hosts_map: Dict[str, Dict],
                         timeout: float = 0.8):
        """
        Lightweight UDP probing for common services (DNS, DHCP, SNMP, NTP, Syslog, UPnP).
        Uses simple probes:
          - DNS: Standard DNS query
          - SNMP: SNMPv2 community probe
          - NTP: NTP timestamp request
          - DHCP: DHCP Discover (broadcast-style)
          - Syslog: Simple marker packet
          - UPnP: M-SEARCH request
        """
        if port not in _UDP_SERVICES:
            return
        
        service_info = _UDP_SERVICES[port]
        try:
            t0 = time.time()
            
            # Create UDP socket with sendto/recvfrom (no connection needed)
            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            
            probe_data = self._build_udp_probe(port, service_info["probe"])
            
            # Send probe
            try:
                await loop.sock_sendto(sock, probe_data, (ip, port))
            except Exception:
                sock.close()
                return
            
            # Try to receive response
            try:
                data, _ = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 4096),
                    timeout=timeout
                )
                banner = data.decode("utf-8", errors="ignore").strip()[:100]
            except asyncio.TimeoutError:
                # No response - port may still be open in UDP firewall sense
                banner = "(no response)"
            except Exception:
                banner = ""
            
            sock.close()
            
            elapsed = (time.time() - t0) * 1000
            
            # Record UDP service
            udp_result = {
                "port": port,
                "service": service_info["service"],
                "state": "open",
                "banner": banner,
                "risk": service_info["risk"],
            }
            
            host = hosts_map[ip]
            existing_udp = {s.get("port") for s in host.get("udp_services", [])}
            if port not in existing_udp:
                host.setdefault("udp_services", []).append(udp_result)
            
        except Exception:
            pass

    def _build_udp_probe(self, port: int, probe_type: str) -> bytes:
        """Build appropriate UDP probe packet for the service."""
        if probe_type == "dns":
            # Simple DNS A query for "localhost"
            return bytes([0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63,
                         0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x00, 0x00,
                         0x01, 0x00, 0x01])
        elif probe_type == "snmp":
            # SNMPv2 GetRequest with public community
            return b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19" \
                   b"\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00" \
                   b"\x30\x0b\x06\x07\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
        elif probe_type == "ntp":
            # NTP v3 client mode timestamp request
            return bytes([0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        elif probe_type == "dhcp":
            # Minimal DHCP Discover
            return b"\x01\x01\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00\x63\x82\x53\x63"
        elif probe_type == "syslog":
            # Simple syslog marker
            return b"<34>Probe\n"
        elif probe_type == "upnp":
            # UPnP M-SEARCH
            return b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n" \
                   b"MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
        
        return b"\x00"

    def _parse_banner(self, port: int, banner_text: str, raw_data: bytes = None) -> str:
        """
        Parse service-specific banners and extract meaningful information.
        Handles version extraction and protocol-specific parsing.
        """
        if not banner_text:
            return ""
        
        # Limit banner length
        banner_text = banner_text[:200]
        
        # Service-specific parsing
        if port == 22:  # SSH
            # SSH: "SSH-2.0-OpenSSH_7.4" format
            lines = banner_text.split("\n")
            if lines:
                return lines[0].strip()
        
        elif port == 3306:  # MySQL
            # MySQL sends: version string followed by null bytes
            if "mysql" in banner_text.lower():
                return banner_text.split("\x00")[0].strip()
            # Try to extract from raw bytes
            if raw_data and len(raw_data) > 10:
                try:
                    # MySQL protocol: first byte is packet length, then version follows
                    version_start = 1
                    version_end = raw_data.find(b"\x00", version_start)
                    if version_end > version_start:
                        version = raw_data[version_start:version_end].decode("utf-8", errors="ignore").strip()
                        if version:
                            return f"MySQL {version}"
                except Exception:
                    pass
        
        elif port == 5432:  # PostgreSQL
            # PostgreSQL: looks like "NOTICE:  unrecognized request code..."
            if "postgres" in banner_text.lower():
                return banner_text.split("\n")[0].strip()
            return "PostgreSQL"
        
        elif port == 1433:  # MSSQL
            # MSSQL: TDS protocol response
            if raw_data and len(raw_data) > 5:
                # Look for version info in TDS response
                if b"MSSQL" in raw_data or b"mssql" in raw_data.lower():
                    return f"MSSQL Server"
            return banner_text.split("\n")[0].strip() if banner_text else "MSSQL"
        
        elif port == 27017:  # MongoDB
            # MongoDB: BSON response or connection reply
            if "ok" in banner_text.lower() or "ismaster" in banner_text.lower():
                return "MongoDB"
            return banner_text.split("\n")[0].strip() if banner_text else "MongoDB"
        
        elif port == 6379:  # Redis
            # Redis: "+PONG\r\n" or error message
            if banner_text.startswith("+"):
                return f"Redis (responded: {banner_text.split()[0][:20]})"
            elif banner_text.startswith("-"):
                # Error response indicates Redis is there
                return "Redis"
            return banner_text.split("\n")[0].strip() if banner_text else "Redis"
        
        elif port == 3389:  # RDP
            # RDP: binary protocol response
            if raw_data and len(raw_data) > 0:
                return "RDP/Remote Desktop"
            return "RDP"
        
        elif port == 5900:  # VNC
            # VNC: "RFB 003.008\n" format
            if "rfb" in banner_text.lower():
                return banner_text.split("\n")[0].strip()
            return "VNC"
        
        elif port in (25, 110, 143):  # SMTP, POP3, IMAP
            # These services send standard SMTP/POP3/IMAP responses
            lines = banner_text.split("\n")
            if lines:
                return lines[0].strip()
        
        elif port == 21:  # FTP
            # FTP: "220 Server ready"
            lines = banner_text.split("\n")
            if lines:
                return lines[0].strip()
        
        # Generic handling: return first line if multi-line
        if "\n" in banner_text:
            first_line = banner_text.split("\n")[0].strip()
            if first_line:
                return first_line
        
        return banner_text.strip() if banner_text else ""
