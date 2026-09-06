"""
core/discovery/enrichment.py
────────────────────────────────────────────────────────────────────────────
Post-Discovery Host Enrichment (AGGRESSIVE Profile Only)

Runs after the main probe phase on confirmed-active hosts to gather
additional intelligence: reverse DNS, mDNS service names, NetBIOS computer
name, SNMP device classification, and TCP-options OS fingerprinting.

Design rules:
  ✅ Only called by DiscoveryEngine when profile.enrichment=True (AGGRESSIVE)
  ✅ Each probe is independently try/catch — one failure doesn't block others
  ✅ All probes are gate-checked (skip if open_ports insufficient, etc.)
  ✅ Scapy is used for SNMP and mDNS — no dependency on net-snmp binaries
  ❌ Never called from PortEngine or VulnerabilityEngine
  ❌ Never touches the results of Phase 2 or Phase 3

Called from:
  core/discovery/engine.py → _enrich_active() → asyncio.to_thread(enrich_host, ...)
"""

import logging
import re
import socket
import struct
from typing import Dict, List, Optional

from core.constants import SCAPY_AVAILABLE
from core.discovery.host_identity import forward_confirm, resolve_identity

log = logging.getLogger("ccure.discovery.enrichment")

from concurrent.futures import ThreadPoolExecutor

_OT_POOL = ThreadPoolExecutor(max_workers=128)

# SNMP OIDs for device classification
_SNMP_OIDS = {
    "ip_forwarding": "1.3.6.1.2.1.4.1.0",  # 1=router, 2=host
    "bridge_mib": "1.3.6.1.2.1.17.1.1.0",  # present → switch
    "sys_obj_id": "1.3.6.1.2.1.1.2.0",  # enterprise OID
}

# Try to import Scapy SNMP extensions (optional — may not be present)
_SNMP_AVAILABLE = False
if SCAPY_AVAILABLE:
    try:
        from scapy.all import ASN1_OID, SNMP, SNMPget, SNMPvarbind

        _SNMP_AVAILABLE = True
    except ImportError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────


def enrich_host(
    ip: str, result: dict, ot_enrichment: bool = True, register_ports: bool = True
) -> None:
    """
    Run all enrichment probes for one active host.

    Each probe is guarded by its own try/except so a single failure
    (e.g. SNMP timeout) doesn't prevent the others from running.

    Args:
        ip:             Target IP address string.
        result:         Host result dict from DiscoveryEngine — mutated in place.
        ot_enrichment:  If True, run deep security and OT protocol queries.
        register_ports: If True, allow dynamic port/service registration on the host result.
    """
    result["_register_ports"] = register_ports
    try:
        basic_probes = [_ptr_lookup, _netbios_query, _mdns_query]
        deep_probes = [
            _snmp_lightweight_probe,
            _ot_protocol_probes,
            _mdns_service_query,
            _os_probe_full,
        ]

        probes = basic_probes + (deep_probes if ot_enrichment else [])

        for fn in probes:
            try:
                fn(ip, result)
            except Exception as exc:
                log.debug("enrich_host(%s) %s error: %s", ip, fn.__name__, exc)

        # Every probe has recorded its own typed field; one place now decides
        # which of them names the host. Doing this here rather than inside the
        # probes is what stops the winner being whichever ran first.
        resolve_identity(result)
    finally:
        result.pop("_register_ports", None)


def _register_open_port(
    result: dict,
    port: int,
    service: str,
    banner: str = "",
    version: str = "",
    product: str = "",
    protocol: str = "tcp",
) -> None:
    """
    Helper to register an open port / service dynamically on the host result.

    ``protocol`` must match the transport the probe actually spoke. Several
    enrichment probes here are UDP-only (SNMP, mDNS, NetBIOS-NS); recording
    those as TCP claimed an open TCP port that is typically filtered, and that
    claim propagated all the way into the asset registry and the exported
    reports.
    """
    if not result.get("_register_ports", True):
        return

    protocol = (protocol or "tcp").lower()

    # port_states is keyed by port alone for TCP (the port engine's convention);
    # UDP entries are namespaced so a UDP hit never masks the TCP state of the
    # same port number.
    port_states = result.setdefault("port_states", {})
    if protocol == "tcp":
        port_states[port] = "open"
        port_states[str(port)] = "open"
    else:
        port_states[f"{port}/{protocol}"] = "open"

    open_ports = result.setdefault("open_ports", [])
    if not any(
        p.get("port") == port and (p.get("protocol") or "tcp").lower() == protocol
        for p in open_ports
    ):
        from core.constants import PORT_DB

        meta = PORT_DB.get(
            port,
            {
                "service": service,
                "risk": "Info",
                "note": "",
            },
        )

        # Discovery reports what it observed and nothing more. It used to look
        # up CVEs for the banner here, which made a host-discovery scan emit
        # vulnerability claims it had no version evidence for — and on a
        # discovery-only run those reached the asset registry unverified.
        # Candidate generation belongs to the vulnerability phase, which is
        # also the only stage that verifies what it produces.
        #
        # The identification recorded here is a cheap connect-and-read, so it
        # is labelled as such: the port engine's service detection outranks it
        # and replaces these fields rather than being blocked by them.
        port_dict = {
            "port": port,
            "protocol": protocol,
            "service": service or meta.get("service", "unknown"),
            "state": "open",
            "banner": banner[:500] if banner else "",
            "version": version[:200] if version else "",
            "product": product[:255] if product else "",
            "risk": meta.get("risk", "Info"),
            "fingerprint_source": "banner" if banner else "connect_probe",
            "cves": [],
        }
        open_ports.append(port_dict)


def _is_port_connectable(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Perform a fast non-blocking TCP socket connection check."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def _ot_protocol_probes(ip: str, result: dict) -> None:
    """
    Perform safe OT protocol fingerprinting on port-gating targets sequentially.
    Utilizes smart connection checks, sequences port 102, and generates audit logs.
    """
    if result.get("_ot_probed") or result.get("ot_info"):
        return

    result["_ot_probed"] = True

    from core.discovery.techniques.ot_probes import (
        probe_bacnet,
        probe_codesys,
        probe_dnp3,
        probe_ethernetip,
        probe_fins,
        probe_ge_srtp,
        probe_iec104,
        probe_melsec,
        probe_mms,
        probe_modbus,
        probe_opcua,
        probe_s7,
    )

    # Port mapping for each protocol (MMS and S7 both share port 102, so handled separately)
    port_map = {
        "modbus": (502, True),  # (port, is_tcp)
        "ethernetip": (44818, False),  # UDP
        "bacnet": (47808, False),  # UDP
        "dnp3": (20000, True),  # TCP (fallback to UDP inside probe)
        "opcua": (4840, True),
        "iec104": (2404, True),
        "ge_srtp": (18245, True),
        "fins": (9600, True),
        "melsec": (5007, True),
        "codesys": (2455, True),
    }

    port_states = result.get("port_states", {})

    # Pre-filter: determine which protocols we should actually probe
    candidate_probes = []

    # 1. Check TCP / UDP mapped probes
    for name, (port, is_tcp) in port_map.items():
        state = port_states.get(port) or port_states.get(str(port))
        if state not in ("open", "open|filtered", "filtered", None):
            continue

        # Fast TCP pre-connection check
        if is_tcp and state is None:
            if not _is_port_connectable(ip, port, timeout=1.0):
                continue

        # If UDP, or TCP connection succeeded, or port state already confirmed open, add to candidates
        if name == "modbus":
            candidate_probes.append((name, probe_modbus))
        elif name == "ethernetip":
            candidate_probes.append((name, probe_ethernetip))
        elif name == "bacnet":
            candidate_probes.append((name, probe_bacnet))
        elif name == "dnp3":
            candidate_probes.append((name, probe_dnp3))
        elif name == "opcua":
            candidate_probes.append((name, probe_opcua))
        elif name == "iec104":
            candidate_probes.append((name, probe_iec104))
        elif name == "ge_srtp":
            candidate_probes.append((name, probe_ge_srtp))
        elif name == "fins":
            candidate_probes.append((name, probe_fins))
        elif name == "melsec":
            candidate_probes.append((name, probe_melsec))
        elif name == "codesys":
            candidate_probes.append((name, probe_codesys))

    # 2. Handle Port 102 (S7 & MMS) sequencing:
    state_102 = port_states.get(102) or port_states.get("102")
    is_102_candidate = state_102 in ("open", "open|filtered", "filtered", None)
    if is_102_candidate and state_102 is None:
        is_102_candidate = _is_port_connectable(ip, 102, timeout=1.0)

    def sequenced_port_102_probe(ip_addr: str, timeout: float = 1.0) -> dict | None:
        """Sequence Siemens S7 comm first, fallback to MMS on port 102 to avoid collision."""
        s7_info = probe_s7(ip_addr, timeout)
        if s7_info:
            return s7_info
        return probe_mms(ip_addr, timeout)

    if is_102_candidate:
        candidate_probes.append(("s7_or_mms", sequenced_port_102_probe))

    if not candidate_probes:
        return

    audit_log = logging.getLogger("ccure.audit")
    port_map_reverse = {
        "modbus": 502,
        "s7_or_mms": 102,
        "ethernetip": 44818,
        "bacnet": 47808,
        "dnp3": 20000,
        "opcua": 4840,
        "iec104": 2404,
        "ge_srtp": 18245,
        "fins": 9600,
        "melsec": 5007,
        "codesys": 2455,
    }

    # Execute candidate probes sequentially
    for name, func in candidate_probes:
        port = port_map_reverse.get(name, 102)
        audit_log.info(f"[AUDIT] Initiating {name.upper()} probe on {ip}:{port}")
        try:
            info = func(ip, 1.0)
            if info:
                audit_log.info(
                    f"[AUDIT] Successfully identified {info['protocol'].upper()} device on {ip}"
                )
                result["ot_info"] = info
                result["device_category"] = "scada_ics"
                if "vendor" in info:
                    result["vendor"] = info["vendor"]
                if "model" in info:
                    # A model is a product name, not a hostname, so it ranks
                    # last in HOSTNAME_PRECEDENCE and is recorded as its own
                    # field rather than written over one. The generic labels
                    # below are protocol descriptions rather than models and
                    # must never name a host at all.
                    generic_labels = {
                        "OPC UA Server",
                        "Modbus TCP Controller",
                        "BACnet Hvac/Sensor",
                        "DNP3 Outstation",
                        "IEC 60870-5-104 Device",
                        "MMS Telecontrol",
                        "CoDeSys PLC Runtime",
                        "GE Series PLC",
                        "Omron Sysmac PLC",
                        "S7-Compatible PLC",
                    }
                    if info["model"] not in generic_labels:
                        result["ot_model"] = info["model"]

                    vendor_part = info.get("vendor", "")
                    proto_part = info.get("protocol", "").upper()
                    import re

                    norm_vendor = re.sub(r"[^a-zA-Z0-9]", "", vendor_part.lower())
                    norm_proto = re.sub(r"[^a-zA-Z0-9]", "", proto_part.lower())
                    if norm_proto in norm_vendor or norm_vendor in norm_proto:
                        result["os_guess"] = vendor_part
                    else:
                        result["os_guess"] = f"{vendor_part} {proto_part} Device"
                    result["os_family"] = "Embedded"
                    result["os_confidence"] = "High"

                proto_label = info["protocol"].upper()
                if proto_label not in result["confirmations"]:
                    result["confirmations"].append(proto_label)
                result["method"] = proto_label

                real_proto_map_reverse = {
                    "modbus": 502,
                    "s7": 102,
                    "mms": 102,
                    "ethernetip": 44818,
                    "bacnet": 47808,
                    "dnp3": 20000,
                    "opcua": 4840,
                    "iec104": 2404,
                    "ge_srtp": 18245,
                    "fins": 9600,
                    "melsec": 5007,
                    "codesys": 2455,
                }
                proto_name = info["protocol"].lower()
                port = real_proto_map_reverse.get(proto_name)
                if port:
                    _register_open_port(
                        result,
                        port=port,
                        service=proto_name.upper() if proto_name != "s7" else "s7comm",
                        banner=f"Protocol: {proto_name.upper()}, Vendor: {info.get('vendor')}, Model: {info.get('model')}",
                    )
                break
        except Exception as exc:
            log.debug("OT probe %s failed for %s: %s", name, ip, exc)


# ─────────────────────────────────────────────────────────────────────────────
# Individual probe functions
# ─────────────────────────────────────────────────────────────────────────────


def _parse_snmp_sys_descr(sys_descr: str) -> dict:
    """
    Pull hostname and OS identity out of an SNMP sysDescr string.

    A Linux agent reports the uname line, e.g.::

        Linux superusr-HP3 6.8.0-137-generic #137-Ubuntu SMP ... x86_64

    which names the host and the exact running kernel. That is direct evidence
    from the device itself and outranks an Nmap TCP/IP fingerprint guess, which
    can only ever offer a kernel *range*. Returns any of ``hostname``,
    ``os_name``, ``os_family``, ``os_version`` it can establish.
    """
    out: dict = {}
    if not sys_descr:
        return out

    text = sys_descr.strip()

    m = re.match(
        r"^Linux\s+(?P<host>[A-Za-z0-9][A-Za-z0-9._-]*)\s+(?P<kernel>\d+\.\d+\.\d+\S*)",
        text,
    )
    if m:
        out["hostname"] = m.group("host")
        kernel = m.group("kernel")
        out["os_family"] = "Linux"
        out["os_version"] = kernel
        distro = re.search(
            r"#\d+\S*[- ](Ubuntu|Debian|SUSE|Red\s?Hat|CentOS|Fedora)", text, re.I
        )
        if distro:
            out["os_name"] = (
                f"{distro.group(1).replace(' ', '')} Linux (kernel {kernel})"
            )
        else:
            out["os_name"] = f"Linux kernel {kernel}"
        return out

    if re.search(r"\bWindows\b", text, re.I):
        out["os_family"] = "Windows"
        ver = re.search(
            r"Windows(?:\s+NT)?(?:\s+Version)?\s+(?P<v>\d+(?:\.\d+)*)", text, re.I
        )
        if ver:
            out["os_version"] = ver.group("v")
            out["os_name"] = f"Microsoft Windows {ver.group('v')}"
        else:
            out["os_name"] = "Microsoft Windows"

    return out


def _snmp_lightweight_probe(ip: str, result: dict) -> None:
    """
    Query port 161 (SNMP) using community 'public' for system details to identify
    network devices early in discovery or port scanning.
    """
    if result.get("snmp_info"):
        return  # Skip duplicate probe if already queried

    # Only probe if SNMP UDP port 161 is open or likely open (not explicitly closed)
    port_states = result.get("port_states", {})
    if (
        port_states
        and port_states.get(161) not in ("open", "open|filtered", None)
        and port_states.get("161") not in ("open", "open|filtered", None)
    ):
        return

    try:
        from engines.vulnerability.plugins.snmp_probe import (
            _ENTERPRISE_VENDORS,
            _OID_BRIDGE_ADDR,
            _OID_IF_NUMBER,
            _OID_IP_FORWARD,
            _OID_SYS_DESCR,
            _OID_SYS_NAME,
            _OID_SYS_OBJ_ID,
            _extract_integer,
            _extract_oid_value,
            _extract_string,
            _snmp_get_raw,
        )

        # Query sysObjectID using community 'public'
        data = _snmp_get_raw(ip, "public", _OID_SYS_OBJ_ID, timeout=1.0)
        if not data:
            return

        sys_obj = _extract_oid_value(data)
        if not sys_obj:
            return

        snmp_info = {
            "open": True,
            "community": "public",
            "sys_descr": "",
            "sys_name": "",
            "sys_location": "",
            "sys_contact": "",
            "sys_uptime_s": None,
            "vendor": "",
            "vendor_device": "",
            "enterprise_id": None,
            "version": "SNMPv1/v2c",
            "ip_forwarding": None,
            "if_count": 0,
            "bridge_mib": False,
            "interfaces": [],
            "ip_addresses": [],
        }

        # Get sysDescr
        descr_data = _snmp_get_raw(ip, "public", _OID_SYS_DESCR, timeout=1.0)
        if descr_data:
            snmp_info["sys_descr"] = _extract_string(descr_data)

        # sysName is the device's own idea of its hostname. It is authoritative
        # in a way reverse DNS is not — a host with no PTR record still answers
        # this — so it is queried here rather than left blank.
        name_data = _snmp_get_raw(ip, "public", _OID_SYS_NAME, timeout=1.0)
        if name_data:
            snmp_info["sys_name"] = _extract_string(name_data) or ""

        # Parse sysObjectID to get enterprise ID and vendor/vendor_device
        parts = sys_obj.split(".")
        prefix = ".".join(parts[:6])
        if prefix == "1.3.6.1.4.1" and len(parts) > 6:
            try:
                enterprise = int(parts[6])
                snmp_info["enterprise_id"] = enterprise
                vendor_info = _ENTERPRISE_VENDORS.get(enterprise)
                if vendor_info:
                    snmp_info["vendor"] = vendor_info[0]
                    snmp_info["vendor_device"] = vendor_info[1]
            except ValueError:
                pass

        # Parse device-type OIDs
        fwd_data = _snmp_get_raw(ip, "public", _OID_IP_FORWARD, timeout=1.0)
        if fwd_data:
            snmp_info["ip_forwarding"] = _extract_integer(fwd_data)

        ifn_data = _snmp_get_raw(ip, "public", _OID_IF_NUMBER, timeout=1.0)
        if ifn_data:
            snmp_info["if_count"] = _extract_integer(ifn_data) or 0

        bridge_data = _snmp_get_raw(ip, "public", _OID_BRIDGE_ADDR, timeout=1.0)
        if bridge_data:
            idx = bridge_data.rfind(b"\x04")
            snmp_info["bridge_mib"] = idx != -1 and len(bridge_data) > idx + 2

        result["snmp_info"] = snmp_info

        # The agent just told us who it is and what it runs. Use that before
        # falling back to a fingerprint guess: sysName/sysDescr are first-party
        # statements from the device, and a host with no PTR record has no
        # other way to report a hostname at all.
        placeholders = ("Unknown", "N/A", "", None)
        identity = _parse_snmp_sys_descr(snmp_info.get("sys_descr", ""))

        snmp_hostname = (snmp_info.get("sys_name") or "").strip() or identity.get(
            "hostname"
        )
        if snmp_hostname:
            # sysName is the device's own statement of its identity, so it
            # outranks PTR. The ranking is host_identity's to apply; recording
            # it here as well would reintroduce a second writer.
            result["snmp_sys_name"] = snmp_hostname

        if identity.get("os_name"):
            # sysDescr outranks a fingerprint regardless of the confidence the
            # fingerprint claims. This probe runs after the Nmap port scan, so
            # os_confidence is already "High" from a TCP/IP match — gating on
            # confidence meant the device's own statement never won, and the
            # registry kept reporting "Linux 5.0 - 5.14" for a host whose agent
            # said 6.8.0-137-generic. Only an authenticated read of the host
            # itself is better evidence than this.
            if result.get("os_evidence") not in ("credentialed",):
                nmap_guess = result.get("os_guess")
                if nmap_guess not in placeholders:
                    result["os_guess_fingerprint"] = nmap_guess
                result["os_guess"] = identity["os_name"]
                result["os_confidence"] = "High"
                result["os_family"] = identity.get("os_family") or result.get(
                    "os_family"
                )
                result["os_version"] = identity.get("os_version") or result.get(
                    "os_version"
                )
                result["os_evidence"] = "snmp_sysdescr"

        _register_open_port(
            result,
            port=161,
            service="snmp",
            banner=snmp_info.get("sys_descr", "")
            or f"SNMPv1/v2c, Community: {snmp_info.get('community')}",
            protocol="udp",
        )

    except Exception as exc:
        log.debug("_snmp_lightweight_probe(%s) error: %s", ip, exc)


def _ptr_lookup(ip: str, result: dict) -> None:
    """
    Reverse DNS PTR lookup via the OS resolver, forward-confirmed.

    Note this is the *resolver*, not DNS specifically: gethostbyaddr goes
    through the platform's name service, so a hosts-file entry answers here
    too. On a machine with Docker Desktop installed, 127.0.0.1 comes back as
    "kubernetes.docker.internal" from that file and no DNS server is involved.

    It records ``ptr_hostname`` and no longer claims ``hostname``: what DNS
    calls an address is not what a machine calls itself, and
    ``host_identity.resolve_identity`` decides between the sources afterwards.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return

    if not hostname or hostname == ip:
        return

    result.setdefault("ptr_hostname", hostname)

    # Advisory, and tri-state — see forward_confirm. A False here is worth
    # seeing (the reverse zone disagrees with the forward zone) and is never
    # a reason to withhold the name.
    confirmed = forward_confirm(ip, hostname)
    if confirmed is not None:
        result["ptr_forward_confirmed"] = confirmed
        if not confirmed:
            log.debug(
                "PTR for %s (%s) is not forward-confirmed: the name resolves "
                "to a different address",
                ip,
                hostname,
            )


def _mdns_query(ip: str, result: dict) -> None:
    """
    Send a unicast mDNS PTR query to the target to resolve its .local hostname.
    Uses Scapy for raw DNS packet construction (not multicast join).
    Falls back to socket-based query when Scapy unavailable.
    """
    if not SCAPY_AVAILABLE:
        return
    try:
        from scapy.all import DNS, DNSQR, IP, UDP, sr1

        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa."
        pkt = IP(dst=ip) / UDP(dport=5353) / DNS(rd=0, qd=DNSQR(qname=rev, qtype="PTR"))
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp and resp.haslayer(DNS) and resp[DNS].ancount > 0:
            # The host's own name is the record's *data*, not its owner name.
            # ``rrname`` is the question echoed back — for this query that is
            # always the "…in-addr.arpa" string we just sent, so reading it
            # stored the query as if it were the answer. That value is not
            # merely useless: the UI falls back to ``mdns_name`` when PTR and
            # NetBIOS are both empty, and _extract_dns_identity fed it into
            # the asset's fqdn, so a reverse-lookup string was displayed and
            # persisted as a machine's identity.
            #
            # Scapy 2.7 made 'an' a PacketListField; reading an attribute off
            # the field itself still answers but raises a DeprecationWarning
            # and is slated to stop working. Older builds hand back a bare
            # packet, which is not indexable this way, so both are handled.
            answers = resp[DNS].an
            try:
                answer = answers[0]
            except (TypeError, IndexError, AttributeError):
                answer = answers
            name = getattr(answer, "rdata", None)
            if isinstance(name, bytes):
                name = name.decode("utf-8", errors="replace")
            name = (name or "").rstrip(".")
            # A responder that echoes the question rather than answering it
            # establishes no name. Storing it would reintroduce the defect
            # above through a different door.
            if name and not name.lower().endswith(".in-addr.arpa"):
                result["mdns_name"] = name
                _register_open_port(
                    result,
                    port=5353,
                    service="mdns",
                    banner=f"mDNS Name: {name}",
                    protocol="udp",
                )
    except Exception as exc:
        log.debug("_mdns_query(%s) error: %s", ip, exc)


def _mdns_service_query(ip: str, result: dict) -> None:
    """
    Send target-specific unicast mDNS queries for common service records
    (e.g., _printer, _ipp, _ssh, _workstation) to identify device types passively.
    """
    if not SCAPY_AVAILABLE:
        return
    try:
        from scapy.all import DNS, DNSQR, IP, UDP, sr1

        services = [
            "_printer._tcp.local",
            "_ipp._tcp.local",
            "_ssh._tcp.local",
            "_workstation._tcp.local",
        ]
        found = []
        for svc in services:
            pkt = (
                IP(dst=ip)
                / UDP(dport=5353)
                / DNS(rd=0, qd=DNSQR(qname=svc + ".", qtype="PTR"))
            )
            # Use 0.4s timeout per query to stay extremely lightweight and fast
            resp = sr1(pkt, timeout=0.4, verbose=0)
            if resp and resp.haslayer(DNS) and resp[DNS].ancount > 0:
                found.append(svc)
        if found:
            result["mdns_services"] = found
            _register_open_port(
                result,
                port=5353,
                service="mdns",
                banner=f"mDNS Services Discovered: {', '.join(found)}",
                protocol="udp",
            )
    except Exception as exc:
        log.debug("_mdns_service_query(%s) error: %s", ip, exc)


def _netbios_query(ip: str, result: dict) -> None:
    """
    NetBIOS Node Status (UDP 137) — returns computer name, workgroup, MAC.
    Uses raw socket (no Scapy needed — this is a plain UDP exchange).
    """
    if result.get("netbios_names"):
        return  # Skip duplicate probe if NetBIOS was already queried during discovery

    _NBSTAT = (
        b"\xa2\x48\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.sendto(_NBSTAT, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
    except Exception as exc:
        log.debug("_netbios_query(%s) socket error: %s", ip, exc)
        return

    if len(data) < 57:
        return

    num_names = data[56]
    names: list[dict] = []
    computer_name = ""
    workgroup = ""

    for i in range(num_names):
        offset = 57 + i * 18
        if offset + 18 > len(data):
            break
        raw = data[offset : offset + 15]
        name_type = data[offset + 15] if offset + 15 < len(data) else 0
        flags = struct.unpack(">H", data[offset + 16 : offset + 18])[0]
        name = raw.decode("ascii", errors="ignore").strip()
        if name:
            names.append({"name": name, "flags": flags, "type": name_type})
            # Computer name: type 0x00, not a group (bit 15 clear)
            if name_type == 0x00 and not (flags & 0x8000) and not computer_name:
                computer_name = name
            # Workgroup: type 0x00, group (bit 15 set)
            if name_type == 0x00 and (flags & 0x8000) and not workgroup:
                workgroup = name

    if names:
        result["netbios_names"] = names
        result["netbios_computer"] = computer_name
        result["netbios_workgroup"] = workgroup
        _register_open_port(
            result,
            port=137,
            service="netbios-ns",
            banner=f"NetBIOS Computer: {computer_name}, Workgroup: {workgroup}",
            protocol="udp",
        )

    # MAC from NetBIOS response (last 6 bytes starting at offset 57 + num_names*18)
    mac_offset = 57 + num_names * 18
    if mac_offset + 6 <= len(data):
        mac_bytes = data[mac_offset : mac_offset + 6]
        if any(b != 0 for b in mac_bytes):
            mac_str = ":".join(f"{b:02x}" for b in mac_bytes)
            if result.get("mac", "N/A") == "N/A":
                result["mac"] = mac_str


def _os_probe_full(ip: str, result: dict) -> None:
    """
    Send a crafted SYN with a full TCP option set to extract MSS/WScale/SAckOK
    from the SYN-ACK. Refines OS fingerprint beyond the TTL-only initial guess.

    Gate: Only runs if the host has confirmed-open ports.
    Skip: If OS confidence is already High (Nmap detected).
    """
    if not SCAPY_AVAILABLE:
        return
    if result.get("os_confidence") == "High":
        return  # Already have a high-confidence fingerprint

    # Gate: skip if no open ports (all timeouts guaranteed)
    open_ports = [
        p for p, state in result.get("port_states", {}).items() if state == "open"
    ]
    if not open_ports:
        return

    try:
        from core.risk import fingerprint_os
        from scapy.all import IP, TCP, sr

        pkt = IP(dst=ip) / TCP(
            dport=80,
            flags="S",
            options=[
                ("MSS", 1460),
                ("NOP", None),
                ("WScale", 6),
                ("NOP", None),
                ("NOP", None),
                ("SAckOK", b""),
                ("Timestamp", (0, 0)),
                ("EOL", None),
            ],
        )
        ans, _ = sr(pkt, timeout=2, verbose=0)
        for _, rcv in ans:
            if not rcv.haslayer(TCP):
                continue
            opts = dict(rcv[TCP].options) if rcv[TCP].options else {}
            ts = opts.get("Timestamp")
            tcp_fp = {
                "ttl": rcv[IP].ttl,
                "window": rcv[TCP].window,
                "mss": opts.get("MSS"),
                "wscale": opts.get("WScale"),
                "sack_ok": "SAckOK" in opts,
                "ts_val": ts[0] if isinstance(ts, (tuple, list)) else None,
                "df_bit": bool(rcv[IP].flags & 0x02),
            }
            guess, conf = fingerprint_os(tcp_fp["ttl"], tcp_fp["window"], tcp_fp)
            result["tcp_fingerprint"] = tcp_fp
            if (
                conf in ("High", "Medium")
                or result.get("os_confidence", "Low") == "Low"
            ):
                result["os_guess"] = guess
                result["os_confidence"] = conf
    except Exception as exc:
        log.debug("_os_probe_full(%s) error: %s", ip, exc)
