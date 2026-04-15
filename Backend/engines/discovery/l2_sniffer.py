"""
engines/discovery/l2_sniffer.py
---------------------------------
GAP-07: Switch-Specific Protocols (CDP, LLDP, STP)

Passively sniffs the network for Layer-2 multicast frames to discover
connected infrastructure devices (switches, routers). Since these are
un-routed protocols, this only discovers devices physically connected
or on the same broadcast domain as the scanner.
"""

import logging
import time
from typing import Dict, List

log = logging.getLogger("ccure.l2_sniffer")

try:
    from scapy.all import sniff, Ether, IP
    from scapy.contrib.cdp import CDPv2_HDR, CDPMsgDeviceID, CDPMsgPlatform, CDPMsgPortID
    from scapy.contrib.lldp import LLDPDU, LLDPDUChassisID, LLDPDUPortID, LLDPDUSystemName, LLDPDUSystemCapabilities
    SCAPY_L2_AVAILABLE = True
except ImportError:
    SCAPY_L2_AVAILABLE = False


def sniff_l2_infrastructure(timeout: float = 15.0) -> List[Dict]:
    """
    Sniffs for CDP, LLDP, and STP frames on the local interface.
    Returns a list of structured dictionaries containing discovered
    infrastructure hardware.
    """
    if not SCAPY_L2_AVAILABLE:
        log.error("Scapy L2 contributions (CDP/LLDP) not available.")
        return []

    discovered = {}

    log.info(f"Sniffing for Layer 2 infrastructure protocols (CDP/LLDP/STP) for {timeout}s...")

    def packet_callback(pkt):
        if not pkt.haslayer(Ether):
            return

        mac = pkt[Ether].src
        if mac not in discovered:
            discovered[mac] = {
                "mac": mac,
                "protocols": [],
                "hostname": None,
                "platform": None,
                "port_id": None,
                "capabilities": [],
                "device_category": "unknown",
            }

        dev = discovered[mac]

        # STP (Spanning Tree Protocol)
        if pkt[Ether].dst in ["01:80:c2:00:00:00", "01:00:0c:cc:cc:cd"]:
            if "STP" not in dev["protocols"]:
                dev["protocols"].append("STP")
                if dev["device_category"] == "unknown":
                    dev["device_category"] = "switch"  # STP strongly implies a switch

        # CDP (Cisco Discovery Protocol)
        if pkt.haslayer("CDPv2_HDR"):
            if "CDP" not in dev["protocols"]:
                dev["protocols"].append("CDP")
            
            if pkt.haslayer("CDPMsgDeviceID"):
                dev["hostname"] = pkt["CDPMsgDeviceID"].val.decode("utf-8", "ignore")
            if pkt.haslayer("CDPMsgPlatform"):
                dev["platform"] = pkt["CDPMsgPlatform"].val.decode("utf-8", "ignore")
            if pkt.haslayer("CDPMsgPortID"):
                dev["port_id"] = pkt["CDPMsgPortID"].val.decode("utf-8", "ignore")
            
            # If we know it's CDP, it's Cisco infrastructure
            if "switch" not in dev["device_category"]:
                dev["device_category"] = "network_appliance"
                
                # Try to infer device based on platform
                platform = (dev["platform"] or "").lower()
                if "catalyst" in platform or "nexus" in platform:
                    dev["device_category"] = "switch"
                elif "router" in platform or "isr" in platform:
                    dev["device_category"] = "router"

        # LLDP (Link Layer Discovery Protocol)
        if pkt.haslayer("LLDPDU"):
            if "LLDP" not in dev["protocols"]:
                dev["protocols"].append("LLDP")

            if pkt.haslayer("LLDPDUSystemName"):
                dev["hostname"] = pkt["LLDPDUSystemName"].system_name.decode("utf-8", "ignore")
            
            if pkt.haslayer("LLDPDUSystemCapabilities"):
                caps = pkt["LLDPDUSystemCapabilities"]
                
                # Check LLDP Capability Bits
                if getattr(caps, "mac_bridge_capable", 0) or getattr(caps, "mac_bridge_enabled", 0):
                    dev["capabilities"].append("Bridge")
                    dev["device_category"] = "switch"
                elif getattr(caps, "router_capable", 0) or getattr(caps, "router_enabled", 0):
                    dev["capabilities"].append("Router")
                    # Route capability could be an L3 switch or router
                    if dev["device_category"] == "unknown":
                        dev["device_category"] = "router"

    try:
        # Multicast MACs for CDP, LLDP, STP
        bpf_filter = (
            "ether dst 01:00:0c:cc:cc:cc or "  # CDP/VTP
            "ether dst 01:80:C2:00:00:0E or "  # LLDP
            "ether dst 01:80:C2:00:00:00"      # STP
        )
        sniff(filter=bpf_filter, prn=packet_callback, timeout=timeout, store=0)
    except Exception as exc:
        log.error(f"Error sniffing L2 protocols: {exc}")

    return list(discovered.values())
