"""
orchestrator/host_enrichment.py
─────────────────────────────────────────────────────────────────────────────
Host enrichment that needs more than one engine, composed by the pipeline.

Two engines used to reach into their siblings for it (B8,
docs/architecture/MODULAR_REFACTORING_LOG.md §6):

* the port engine finished every run with a lightweight SNMP query and the OT
  identity probes, both discovery enrichment's, followed by the asset
  registry's device classifier;
* discovery's SNMP probe imported the network checks' SNMP client.

The orchestrator already imports all of them, so the wiring is here and the
engines import no sibling:

* :func:`snmp_system_query` is the SNMP read discovery's probe needs, built
  from the network checks' client. The orchestrator hands it to every
  discovery engine it builds and uses it after the port scan.
* :func:`enrich_after_port_scan` is what the port engine did after its scan,
  unchanged. The orchestrator runs it on the hosts it gave the engine, straight
  after the engine.

The imports stay inside the functions, where the engines had them, so importing
the orchestrator loads no more than it did before.
"""

from __future__ import annotations

import asyncio
import logging

log = logging.getLogger("ccure.orchestrator.host_enrichment")

#: SCADA/OT default ports mapped in ot_probes: modbus (502), s7/mms (102),
#: ethernetip (44818), bacnet (47808), dnp3 (20000), opcua (4840),
#: iec104 (2404), ge_srtp (18245), fins (9600), melsec (5007), codesys (2455).
OT_PORTS = frozenset(
    {502, 102, 44818, 47808, 20000, 4840, 2404, 18245, 9600, 5007, 2455}
)


def snmp_system_query(ip: str) -> dict | None:
    """
    Read an agent's system group with community 'public': the ``snmp_info``
    record discovery's SNMP probe interprets, or None if nothing answered.

    The read the probe used to make itself, moved here unchanged: sysObjectID
    first, and nothing more unless it answers with an OID.
    """
    from engines.vulnerability.plugins.snmp_probe import (
        _ENTERPRISE_VENDORS,
        _OID_BRIDGE_ADDR,
        _OID_IF_NUMBER,
        _OID_IP_FORWARD,
        _OID_SYS_DESCR,
        _OID_SYS_NAME,
        _OID_SYS_OBJ_ID,
        _extract_integer,
        _extract_mac,
        _extract_oid_value,
        _extract_string,
        _snmp_get_raw,
    )

    # Query sysObjectID using community 'public'
    data = _snmp_get_raw(ip, "public", _OID_SYS_OBJ_ID, timeout=1.0)
    if not data:
        return None

    sys_obj = _extract_oid_value(data)
    if not sys_obj:
        return None

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

    # dot1dBaseBridgeAddress is a MacAddress. Searching the datagram for an
    # OctetString tag found the community string, so every SNMP agent was
    # reported as a bridge.
    bridge_data = _snmp_get_raw(ip, "public", _OID_BRIDGE_ADDR, timeout=1.0)
    snmp_info["bridge_mib"] = bool(bridge_data and _extract_mac(bridge_data))

    return snmp_info


async def enrich_after_port_scan(
    hosts: list[dict], *, exclude_ot_from_nmap: bool
) -> None:
    """
    After the port scan, on the hosts the port engine scanned: the lightweight
    SNMP query, then the OT identity probes and device classification.

    ``exclude_ot_from_nmap`` is the value the port engine was built with: when
    nmap was kept off the OT ports, every host gets the OT probes; otherwise
    only a host with an OT port open does.
    """
    active = [h for h in hosts if h.get("is_active")]
    if not active:
        return

    # After port scanning, perform a lightweight SNMP check on active hosts
    await _lightweight_snmp_check(active)

    # Run dynamic OT identity probes on open SCADA ports
    await _ot_enrichment_check(active, exclude_ot_from_nmap)


async def _lightweight_snmp_check(hosts: list[dict]) -> None:
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
            if port_states.get(161) == "closed" or port_states.get("161") == "closed":
                return

        # Run the lightweight probe
        _snmp_lightweight_probe(ip, host, snmp_system_query)

    loop = asyncio.get_running_loop()
    await asyncio.gather(*[loop.run_in_executor(None, _check_host, h) for h in hosts])


async def _ot_enrichment_check(hosts: list[dict], exclude_ot_from_nmap: bool) -> None:
    """
    Check if any OT ports are open on active hosts and perform deep OT identity probing.
    """
    from core.device_classifier import classify_device
    from core.discovery.enrichment import _ot_protocol_probes

    def _check_host(host: dict):
        ip = host.get("ip_address") or host.get("ip")
        if not ip:
            return

        open_ports = {
            p.get("port") for p in host.get("open_ports", []) if p.get("port")
        }

        # Skip if ot_info is already present
        if host.get("ot_info"):
            return

        # If we exclude OT from Nmap, we want to probe all candidate OT ports.
        # Otherwise, we only probe if at least one OT port is open.
        if not exclude_ot_from_nmap and not (open_ports & OT_PORTS):
            return

        # Initialize registrations needed by _ot_protocol_probes
        port_states = host.setdefault("port_states", {})
        for p in open_ports:
            if p in OT_PORTS:
                port_states[p] = "open"

        host.setdefault("confirmations", [])

        # Execute OT Probes
        try:
            _ot_protocol_probes(ip, host)

            # If OT info was successfully gathered, run classifier to set exact scada_ics details
            if host.get("ot_info"):
                classify_device(host)
        except Exception as exc:
            log.debug("OT enrichment after the port scan failed for %s: %s", ip, exc)

    loop = asyncio.get_running_loop()
    await asyncio.gather(*[loop.run_in_executor(None, _check_host, h) for h in hosts])
