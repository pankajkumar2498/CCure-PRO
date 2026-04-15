"""
core/device_classifier.py
--------------------------
GAP-07: Multi-Signal Network Device Classification

Combines five independent evidence signals to classify a host as one of:

    router            IP forwarding device (SNMP + port profile + TTL)
    switch            Layer-2 bridge (SNMP Bridge MIB)
    firewall          Packet filter / UTM
    wireless_ap       IEEE 802.11 access point
    printer           Print service devices
    iot               IoT / embedded / industrial (non-server, non-PC)
    server            Application/file/DB server
    endpoint          Workstation / laptop / desktop
    voip              VoIP PBX / SIP endpoint
    storage           NAS / SAN
    network_appliance Generic managed networking device (when specific type unknown)
    unknown           Insufficient evidence

Evidence signals (in order of reliability)
-------------------------------------------
1. SNMP OID         Highest confidence — active classification via MIB walk.
2. OUI vendor       High confidence — manufacturer reveals device class.
3. Open port profile Medium confidence — port set is a strong device hint.
4. Banner keywords  Medium confidence — sysDescr / service banners.
5. TTL              Low confidence — OS / device-family hint only.

Usage
-----
    from core.device_classifier import classify_device
    category = classify_device(host_dict)   # mutates host["device_category"]
"""

import logging
from typing import Dict, List, Optional

log = logging.getLogger("ccure.device_classifier")

# ---------------------------------------------------------------------------
# Signal 1 — SNMP OID-based classification
# ---------------------------------------------------------------------------

# OID for ipForwarding (.1.3.6.1.2.1.4.1.0): 1=forwarding(router), 2=notForwarding(host)
_OID_IP_FORWARDING   = "ip_forwarding"
# OID for ifNumber (.1.3.6.1.2.1.2.1.0): number of interfaces; >2 strongly suggests router/switch
_OID_IF_NUMBER       = "if_number"
# Bridge MIB (.1.3.6.1.2.1.17.1.1.0): presence → switch
_OID_BRIDGE_MIB      = "bridge_mib"


def _classify_from_snmp(snmp_info: Dict) -> Optional[str]:
    """Return category string from SNMP probe findings, or None."""
    if not snmp_info or not snmp_info.get("open"):
        return None

    # IP forwarding → router
    if snmp_info.get("ip_forwarding") == 1:
        return "router"

    # Bridge MIB present → switch
    if snmp_info.get("bridge_mib"):
        return "switch"

    # Many interfaces + IP forwarding disabled → switch or AP
    if_count = snmp_info.get("if_count", 0)
    if if_count > 4 and snmp_info.get("ip_forwarding") == 2:
        return "switch"

    # No forwarding, few interfaces → host (server or endpoint)
    return None


# ---------------------------------------------------------------------------
# Signal 2 — OUI vendor keyword → device category
# ---------------------------------------------------------------------------

# Extended vendor keyword table (lowercase substring match)
_VENDOR_DEVICE_MAP: Dict[str, str] = {
    # Routers / firewalls
    "cisco":           "router",
    "juniper":         "router",
    "mikrotik":        "router",
    "ubiquiti":        "wireless_ap",
    "ruckus":          "wireless_ap",
    "aruba":           "wireless_ap",
    "aerohive":        "wireless_ap",
    "peplink":         "router",
    "zyxel":           "router",
    "netgear":         "router",
    "tp-link":         "router",
    "tplink":          "router",
    "d-link":          "router",
    "dlink":           "router",
    "linksys":         "router",
    "asus":            "router",
    # Firewalls / UTM
    "fortinet":        "firewall",
    "palo alto":       "firewall",
    "sonicwall":       "firewall",
    "checkpoint":      "firewall",
    "watchguard":      "firewall",
    "barracuda":       "firewall",
    "sophos":          "firewall",
    "pfSense":         "firewall",
    # Switches
    "extreme network": "switch",
    "brocade":         "switch",
    "foundry":         "switch",
    "3com":            "switch",
    "alcatel":         "switch",
    "avaya":           "switch",
    "procurve":        "switch",
    # Printers
    "brother":         "printer",
    "canon":           "printer",
    "epson":           "printer",
    "lexmark":         "printer",
    "xerox":           "printer",
    "ricoh":           "printer",
    "kyocera":         "printer",
    "konica":          "printer",
    "sharp":           "printer",
    "oki data":        "printer",
    # HP is ambiguous: could be printer or server
    "hewlett":         "printer",
    "hp ":             "printer",
    # Servers / workstations
    "dell":            "server",
    "lenovo":          "server",
    "supermicro":      "server",
    "ibm":             "server",
    "intel":           "server",
    # IoT / embedded
    "raspberry":       "iot",
    "espressif":       "iot",
    "particle":        "iot",
    "arduino":         "iot",
    "siemens":         "iot",
    "schneider":       "iot",
    "honeywell":       "iot",
    "rockwell":        "iot",
    # VoIP
    "yealink":         "voip",
    "polycom":         "voip",
    "grandstream":     "voip",
    "snom":            "voip",
    "cisco spa":       "voip",
    # Storage
    "synology":        "storage",
    "qnap":            "storage",
    "netapp":          "storage",
    "drobo":           "storage",
}


def _classify_from_vendor(vendor: Optional[str]) -> Optional[str]:
    if not vendor:
        return None
    v = vendor.lower()
    for kw, cat in _VENDOR_DEVICE_MAP.items():
        if kw in v:
            return cat
    return None


# ---------------------------------------------------------------------------
# Signal 3 — Open port profile
# ---------------------------------------------------------------------------

_PORT_PROFILE_RULES: List[Dict] = [
    # Each rule: {"ports": required_set, "any": optional_hint_set, "category": str}
    # Evaluated in order; first match wins.
    {"ports": {9100},                            "category": "printer"},   # JetDirect
    {"ports": {515},                             "category": "printer"},   # LPD
    {"ports": {631},                             "category": "printer"},   # IPP
    {"ports": {5060},                            "category": "voip"},      # SIP
    {"ports": {5061},                            "category": "voip"},      # SIP/TLS
    {"ports": {2000},                            "category": "voip"},      # Cisco SCCP
    {"ports": {62078},                           "category": "iot"},       # Apple iOS lockdown
    {"ports": {548},                             "category": "endpoint"},  # AFP = macOS
    {"ports": {1723},                            "category": "router"},    # PPTP VPN
    {"ports": {1194},                            "category": "firewall"},  # OpenVPN
    {"ports": {4500},                            "category": "firewall"},  # IKEv2 NAT-T
    {"ports": {500},                             "category": "firewall"},  # IKE/IPsec
    {"ports": {1701},                            "category": "firewall"},  # L2TP
    {"ports": {179},                             "category": "router"},    # BGP
    {"ports": {520},                             "category": "router"},    # RIP
    {"ports": {161, 69}, "any": {23, 22},        "category": "switch"},    # TFTP + SNMP + Mgmt (common for switches)
    {"ports": {161},  "any": {22},               "category": "network_appliance"},  # SNMP + SSH = managed device
    {"ports": {161},  "any": {23},               "category": "router"},    # SNMP + Telnet = old Cisco
    {"ports": {443, 22, 80}, "any": {8443},      "category": "server"},
    {"ports": {3389, 445, 139},                  "category": "endpoint"},  # Windows workstation
    {"ports": {445, 139, 88},                    "category": "server"},    # Windows DC/Server
    {"ports": {2049},                            "category": "storage"},   # NFS
    {"ports": {3260},                            "category": "storage"},   # iSCSI
    {"ports": {6000},                            "category": "endpoint"},  # X11
    {"ports": {502},                             "category": "iot"},       # Modbus
    {"ports": {102},                             "category": "iot"},       # S7comm
    {"ports": {20000},                           "category": "iot"},       # DNP3
    {"ports": {44818},                           "category": "iot"},       # EtherNet/IP
]


def _classify_from_ports(open_ports: List[int]) -> Optional[str]:
    port_set = set(open_ports)
    for rule in _PORT_PROFILE_RULES:
        required = rule.get("ports", set())
        optional = rule.get("any", set())
        if required.issubset(port_set):
            if not optional or optional & port_set:
                return rule["category"]
    return None


# ---------------------------------------------------------------------------
# Signal 4 — Banner / sysDescr keyword matching
# ---------------------------------------------------------------------------

_BANNER_KEYWORDS: Dict[str, str] = {
    "catalyst":        "switch",
    "nexus":           "switch",
    "procurve":        "switch",
    "pfsense":         "firewall",
    "cisco ios":       "router",
    "cisco":           "router",
    "junos":           "router",
    "routeros":        "router",
    "mikrotik":        "router",
    "openwrt":         "router",
    "dd-wrt":          "router",
    "fortios":         "firewall",
    "fortinet":        "firewall",
    "panos":           "firewall",
    "asa":             "firewall",
    "netscreen":       "firewall",
    "fortigate":       "firewall",
    "sonicos":         "firewall",
    "checkpoint":      "firewall",
    "ubiquiti":        "wireless_ap",
    "unifi":           "wireless_ap",
    "airos":           "wireless_ap",
    "aruba":           "switch",
    "ruckus":          "wireless_ap",
    "windows":         "endpoint",
    "linux":           "server",
    "ubuntu":          "server",
    "debian":          "server",
    "centos":          "server",
    "red hat":         "server",
    "freebsd":         "server",
    "synology":        "storage",
    "qnap":            "storage",
    "truenas":         "storage",
    "freenas":         "storage",
    "siemens":         "iot",
    "s7-":             "iot",
    "plc":             "iot",
    "scada":           "iot",
    "modbus":          "iot",
    "printer":         "printer",
    "laserjet":        "printer",
    "jetdirect":       "printer",
    "print server":    "printer",
}


def _classify_from_banners(host: Dict) -> Optional[str]:
    """Scan all banner-like fields in the host dict for device keywords."""
    # Collect text to scan
    texts = []

    snmp = host.get("snmp_info", {})
    if snmp:
        texts.append(snmp.get("sys_descr", ""))

    for port_rec in host.get("open_ports", []):
        texts.append(port_rec.get("banner", ""))
        texts.append(port_rec.get("version", ""))
        texts.append(port_rec.get("service", ""))

    texts.append(host.get("os_guess", ""))

    combined = " ".join(str(t) for t in texts if t).lower()

    for kw, cat in _BANNER_KEYWORDS.items():
        if kw in combined:
            return cat
    return None


# ---------------------------------------------------------------------------
# Signal 5 — TTL
# ---------------------------------------------------------------------------

def _classify_from_ttl(ttl: Optional[int]) -> Optional[str]:
    if ttl is None:
        return None
    if ttl >= 250:
        return "network_appliance"   # Cisco IOS = 255, common on routers
    return None


# ---------------------------------------------------------------------------
# Master classifier
# ---------------------------------------------------------------------------

def classify_device(host: Dict) -> str:
    """
    Run all five classification signals and return the winning category.

    Also writes the result back to ``host["device_category"]`` so callers
    don't need to handle the return value separately.

    Decision priority (highest first):
        1. SNMP OID result
        2. OUI vendor
        3. Port profile
        4. Banner keywords
        5. TTL
        6. Fallback → "unknown"
    """
    # Signal 1: SNMP
    category = _classify_from_snmp(host.get("snmp_info", {}))
    if category:
        _write(host, category, "snmp")
        return category

    # Signal 2: OUI vendor
    vendor = host.get("vendor") or host.get("mac_vendor")
    if not vendor:
        from core.oui_lookup import lookup_vendor
        vendor = lookup_vendor(host.get("mac", "")) or ""
    category = _classify_from_vendor(vendor)
    if category:
        _write(host, category, "oui")
        return category

    # Signal 3: Port profile
    open_ports = [p["port"] for p in host.get("open_ports", [])]
    category = _classify_from_ports(open_ports)
    if category:
        _write(host, category, "port_profile")
        return category

    # Signal 4: Banner keywords
    category = _classify_from_banners(host)
    if category:
        _write(host, category, "banner")
        return category

    # Signal 5: TTL
    ttl = host.get("tcp_fingerprint", {}).get("ttl") or _extract_ttl(host)
    category = _classify_from_ttl(ttl)
    if category:
        _write(host, category, "ttl")
        return category

    _write(host, "unknown", "none")
    return "unknown"


def _write(host: Dict, category: str, signal: str) -> None:
    host["device_category"] = category
    host["device_category_signal"] = signal
    log.debug(
        "classify_device(%s): %s ← %s",
        host.get("ip_address") or host.get("ip", "?"),
        category, signal,
    )


def _extract_ttl(host: Dict) -> Optional[int]:
    """Best-effort TTL extraction from various host dict shapes."""
    for key in ("ttl", "ip_ttl"):
        if key in host:
            return host[key]
    fp = host.get("tcp_fingerprint", {})
    return fp.get("ttl") if fp else None
