"""
engines/discovery/l2_sniffer.py
---------------------------------
GAP-07: Switch-Specific Protocols (CDP, LLDP, STP)

Passively sniffs the network for Layer-2 multicast frames to discover
connected infrastructure devices (switches, routers). Since these are
un-routed protocols, this only discovers devices physically connected
or on the same broadcast domain as the scanner.

Windows-safe implementation: Uses a daemon thread + threading.Event hard-stop
to guarantee the timeout is always honoured regardless of packet traffic.
Scapy's built-in `timeout` param relies on select() waking when a packet
arrives — on a quiet network with a BPF filter, it can block indefinitely.
"""

import logging
import sys
import threading
from typing import Dict, List

log = logging.getLogger("ccure.l2_sniffer")

try:
    from scapy.all import sniff, Ether
    from scapy.contrib.cdp import (
        CDPv2_HDR,
        CDPMsgDeviceID,
        CDPMsgPlatform,
        CDPMsgPortID,
    )
    from scapy.contrib.lldp import LLDPDU, LLDPDUSystemName, LLDPDUSystemCapabilities

    SCAPY_L2_AVAILABLE = True
except ImportError:
    SCAPY_L2_AVAILABLE = False


# Multicast destination MACs for CDP/VTP, LLDP, STP
_L2_MCAST_MACS = {
    "01:00:0c:cc:cc:cc",  # CDP / VTP
    "01:80:c2:00:00:0e",  # LLDP
    "01:80:c2:00:00:00",  # STP (802.1D)
    "01:00:0c:cc:cc:cd",  # PVST+ STP (Cisco)
}

# BPF filter for non-Windows systems (where it works reliably)
_BPF_FILTER = (
    "ether dst 01:00:0c:cc:cc:cc or "
    "ether dst 01:80:C2:00:00:0E or "
    "ether dst 01:80:C2:00:00:00"
)


def sniff_l2_infrastructure(timeout: float = 3.0) -> List[Dict]:
    """
    Sniffs for CDP, LLDP, and STP frames on the local interface.

    Uses a daemon thread with a hard threading.Event stop signal so the
    timeout is always honoured — even on Windows where no CDP/LLDP traffic
    is present and Scapy's built-in timeout mechanism stalls indefinitely.

    Returns a list of structured dicts for discovered infrastructure devices.
    Always returns within `timeout` seconds (plus a small grace period).
    """
    if not SCAPY_L2_AVAILABLE:
        log.warning(
            "Scapy L2 contributions (CDP/LLDP) not available — skipping L2 sniff."
        )
        return []

    discovered: Dict[str, Dict] = {}
    stop_event = threading.Event()

    log.info(
        f"Sniffing for Layer 2 infrastructure protocols (CDP/LLDP/STP) for {timeout}s..."
    )

    def packet_callback(pkt):
        """Process captured packets — filter in Python for portability."""
        if stop_event.is_set():
            return

        if not pkt.haslayer(Ether):
            return

        # Drop irrelevant packets early (important on Windows without BPF)
        dst = pkt[Ether].dst.lower()
        if dst not in _L2_MCAST_MACS:
            return

        mac = pkt[Ether].src.lower()
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

        # ── STP (Spanning Tree Protocol) ──────────────────────────────────
        if dst in {"01:80:c2:00:00:00", "01:00:0c:cc:cc:cd"}:
            if "STP" not in dev["protocols"]:
                dev["protocols"].append("STP")
                if dev["device_category"] == "unknown":
                    dev["device_category"] = "switch"

        # ── CDP (Cisco Discovery Protocol) ────────────────────────────────
        if pkt.haslayer("CDPv2_HDR"):
            if "CDP" not in dev["protocols"]:
                dev["protocols"].append("CDP")

            if pkt.haslayer("CDPMsgDeviceID"):
                try:
                    dev["hostname"] = pkt["CDPMsgDeviceID"].val.decode(
                        "utf-8", "ignore"
                    )
                except Exception:
                    pass
            if pkt.haslayer("CDPMsgPlatform"):
                try:
                    dev["platform"] = pkt["CDPMsgPlatform"].val.decode(
                        "utf-8", "ignore"
                    )
                except Exception:
                    pass
            if pkt.haslayer("CDPMsgPortID"):
                try:
                    dev["port_id"] = pkt["CDPMsgPortID"].val.decode("utf-8", "ignore")
                except Exception:
                    pass

            if dev["device_category"] == "unknown":
                dev["device_category"] = "network_appliance"
            platform = (dev["platform"] or "").lower()
            if "catalyst" in platform or "nexus" in platform:
                dev["device_category"] = "switch"
            elif "router" in platform or "isr" in platform:
                dev["device_category"] = "router"

        # ── LLDP (Link Layer Discovery Protocol) ──────────────────────────
        if pkt.haslayer("LLDPDU"):
            if "LLDP" not in dev["protocols"]:
                dev["protocols"].append("LLDP")

            if pkt.haslayer("LLDPDUSystemName"):
                try:
                    dev["hostname"] = pkt["LLDPDUSystemName"].system_name.decode(
                        "utf-8", "ignore"
                    )
                except Exception:
                    pass

            if pkt.haslayer("LLDPDUSystemCapabilities"):
                caps = pkt["LLDPDUSystemCapabilities"]
                if getattr(caps, "mac_bridge_capable", 0) or getattr(
                    caps, "mac_bridge_enabled", 0
                ):
                    if "Bridge" not in dev["capabilities"]:
                        dev["capabilities"].append("Bridge")
                    dev["device_category"] = "switch"
                elif getattr(caps, "router_capable", 0) or getattr(
                    caps, "router_enabled", 0
                ):
                    if "Router" not in dev["capabilities"]:
                        dev["capabilities"].append("Router")
                    if dev["device_category"] == "unknown":
                        dev["device_category"] = "router"

    def _stop_sniff(pkt):
        """stop_filter callback: tells Scapy to stop when the event is set."""
        return stop_event.is_set()

    def _do_sniff():
        """Run Scapy sniff inside a daemon thread."""
        try:
            if sys.platform == "win32":
                # On Windows: skip BPF filter (npcap hangs when filter matches 0 pkts).
                # Use stop_filter + the event so Scapy checks after every packet.
                sniff(
                    prn=packet_callback,
                    stop_filter=_stop_sniff,
                    timeout=timeout + 1,  # extra grace; stop_event fires first
                    store=0,
                )
            else:
                sniff(
                    filter=_BPF_FILTER,
                    prn=packet_callback,
                    stop_filter=_stop_sniff,
                    timeout=timeout + 1,
                    store=0,
                )
        except Exception as exc:
            log.debug("L2 sniff thread error: %s", exc)

    # ── Launch sniff in a daemon thread ───────────────────────────────────
    t = threading.Thread(target=_do_sniff, daemon=True, name="l2-sniffer")
    t.start()

    # ── Hard stop: set the event after `timeout` seconds regardless ───────
    # This guarantees we always return on time even if Scapy is stuck.
    timer = threading.Timer(timeout, stop_event.set)
    timer.daemon = True
    timer.start()

    # ── Wait for the sniff thread (bounded by timeout + small grace) ──────
    t.join(timeout=timeout + 0.5)

    # Cancel timer if thread finished early (e.g. found devices quickly)
    timer.cancel()

    # Ensure stop_event is set so zombie threads self-terminate gracefully
    stop_event.set()

    found = list(discovered.values())
    log.info(f"L2 sniff complete — {len(found)} infrastructure device(s) found.")
    return found
