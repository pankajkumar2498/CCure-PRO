"""
engines/port/_udp_services.py
────────────────────────────────────────────────────────────────────────────
UDP Service Table and Payload Builders

Extracted from the original port_engine.py to:
  1. Keep port_engine.py focused on scanning orchestration
  2. Make the UDP service list independently testable
  3. Allow udp_probe.py (discovery technique) to share the payload builders

This module is imported by:
  engines/port/port_engine.py  → fallback UDP scan path
  (optionally) core/discovery/techniques/udp_probe.py → discovery-phase UDP
"""

from typing import Dict

# ─────────────────────────────────────────────────────────────────────────────
# UDP service table: port → {service, risk, probe}
# ─────────────────────────────────────────────────────────────────────────────

UDP_SERVICES: dict[int, dict] = {
    53: {"service": "dns", "risk": "High", "probe": "dns"},
    67: {"service": "dhcp", "risk": "High", "probe": "dhcp"},
    69: {"service": "tftp", "risk": "High", "probe": "tftp"},
    88: {"service": "kerberos", "risk": "High", "probe": "generic"},
    123: {"service": "ntp", "risk": "Medium", "probe": "ntp"},
    137: {"service": "netbios-ns", "risk": "High", "probe": "netbios"},
    138: {"service": "netbios-dgm", "risk": "Medium", "probe": "generic"},
    161: {"service": "snmp", "risk": "High", "probe": "snmp"},
    162: {"service": "snmp-trap", "risk": "Medium", "probe": "snmp"},
    389: {"service": "ldap", "risk": "High", "probe": "generic"},
    500: {"service": "ike", "risk": "High", "probe": "ike"},
    514: {"service": "syslog", "risk": "Medium", "probe": "syslog"},
    520: {"service": "rip", "risk": "Medium", "probe": "generic"},
    623: {"service": "ipmi", "risk": "High", "probe": "ipmi"},
    1900: {"service": "upnp", "risk": "Medium", "probe": "upnp"},
    5353: {"service": "mdns", "risk": "Low", "probe": "mdns"},
}


def add_udp_result(
    host: dict, port: int, service_info: dict, state: str, banner: str
) -> None:
    """Append a UDP result to the host dict, deduplicating by port."""
    existing = {s.get("port") for s in host.get("udp_services", [])}
    if port not in existing:
        host.setdefault("udp_services", []).append(
            {
                "port": port,
                "service": service_info.get("service", "unknown"),
                "state": state,
                "banner": banner,
                "risk": service_info.get("risk", "Info"),
            }
        )


def build_payload(port: int, probe_type: str) -> bytes:
    """
    Return the correct protocol payload bytes for a UDP probe.
    Returns b"" for 'generic' probes — empty UDP is enough to elicit
    ICMP Port-Unreachable from closed ports.
    """
    if probe_type == "dns":
        # Standard DNS A query for "localhost"
        return bytes(
            [
                0x00,
                0x00,
                0x01,
                0x00,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x09,
                0x6C,
                0x6F,
                0x63,
                0x61,
                0x6C,
                0x68,
                0x6F,
                0x73,
                0x74,
                0x00,
                0x00,
                0x01,
                0x00,
                0x01,
            ]
        )

    if probe_type == "snmp":
        # SNMPv2c GetRequest — community "public", OID 1.3.6.1.2.1.1.1.0
        return (
            b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19"
            b"\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00"
            b"\x30\x0b\x06\x07\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
        )

    if probe_type == "ntp":
        # NTPv3 client-mode request (48 bytes)
        return bytes([0x23] + [0x00] * 47)

    if probe_type == "dhcp":
        # Minimal DHCP DISCOVER with magic cookie
        return (
            b"\x01\x01\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x63\x82\x53\x63"
            b"\x35\x01\x01\xff"
        )

    if probe_type == "tftp":
        return b"\x00\x01ccure_probe\x00netascii\x00"

    if probe_type == "netbios":
        return (
            b"\xa2\x48\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41"
            b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
            b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
        )

    if probe_type == "ike":
        # IKEv1 Phase-1 Main Mode SA initiation (28-byte header)
        return (
            b"\x00" * 8
            + b"\x00" * 8
            + b"\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x1c"
        )

    if probe_type == "ipmi":
        # RMCP ASF Presence Ping
        return bytes(
            [0x06, 0x00, 0xFF, 0x06, 0x00, 0x00, 0x11, 0xBE, 0x80, 0x00, 0x00, 0x00]
        )

    if probe_type == "mdns":
        # mDNS PTR query for _services._dns-sd._udp.local
        return bytes(
            [
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x09,
                0x5F,
                0x73,
                0x65,
                0x72,
                0x76,
                0x69,
                0x63,
                0x65,
                0x73,
                0x07,
                0x5F,
                0x64,
                0x6E,
                0x73,
                0x2D,
                0x73,
                0x64,
                0x04,
                0x5F,
                0x75,
                0x64,
                0x70,
                0x05,
                0x6C,
                0x6F,
                0x63,
                0x61,
                0x6C,
                0x00,
                0x00,
                0x0C,
                0x00,
                0x01,
            ]
        )

    if probe_type == "syslog":
        return b"<34>1 - - - - - CCure-probe\n"

    if probe_type == "upnp":
        return (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"HOST: 239.255.255.250:1900\r\n"
            b'MAN: "ssdp:discover"\r\n'
            b"MX: 2\r\n"
            b"ST: ssdp:all\r\n\r\n"
        )

    return b""  # generic / unknown
