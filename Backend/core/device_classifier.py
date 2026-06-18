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
    # HP / Hewlett Packard - AMBIGUOUS (makes printers AND servers/desktops)
    # Now skipped - let Port Profile distinguish between HP printers vs HP servers
    # Old: "hewlett":         "printer",
    # Old: "hp ":             "printer",
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
    # SCADA / ICS / OT Devices
    "siemens":         "scada_ics",
    "schneider":       "scada_ics",
    "honeywell":       "scada_ics",
    "rockwell":        "scada_ics",
    "yokogawa":        "scada_ics",
    "beckhoff":        "scada_ics",
    "omron":           "scada_ics",
    "abb":             "scada_ics",
    "wago":            "scada_ics",
    "moxa":            "scada_ics",
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
    "vmware":          "virtual_machine",
    "xen":             "virtual_machine",
    "hyperv":          "virtual_machine",
    "hyper-v":         "virtual_machine",
}


def _classify_from_vendor(vendor: Optional[str]) -> Optional[str]:
    if not vendor:
        return None
    v = vendor.lower()
    for kw, cat in _VENDOR_DEVICE_MAP.items():
        if kw in v:
            return cat
    return None


_VENDOR_OS_MAP: Dict[str, str] = {
    "cisco":       "Cisco IOS",
    "juniper":     "Junos OS",
    "fortinet":    "FortiOS",
    "mikrotik":    "RouterOS",
    "vmware":      "ESXi",
    "apple":       "macOS",
    "microsoft":   "Windows",
}


def _os_from_vendor(vendor: Optional[str]) -> Optional[str]:
    if not vendor:
        return None
    v = vendor.lower()
    for kw, os_fam in _VENDOR_OS_MAP.items():
        if kw in v:
            return os_fam
    return None


def _classify_from_netbios(host: Dict) -> Optional[str]:
    names = host.get("netbios_names")
    if not names:
        return None

    types = {n.get("type") for n in names if isinstance(n, dict) and "type" in n}

    # 0x1D = Master Browser, 0x1B = Domain Master Browser, 0x1C = Domain Controller
    if {0x1D, 0x1B, 0x1C} & types:
        return "server"
    if 0x20 in types:  # Server Service
        return "server"
    if 0x00 in types:  # Workstation Service
        return "endpoint"

    return None


def _classify_from_mdns(host: Dict) -> Optional[str]:
    mdns_services = host.get("mdns_services")
    if not mdns_services:
        return None

    services_set = set(mdns_services)
    if {"_printer._tcp.local", "_ipp._tcp.local"} & services_set:
        return "printer"
    if {"_ssh._tcp.local", "_workstation._tcp.local"} & services_set:
        return "endpoint"

    return None


# ---------------------------------------------------------------------------
# Signal 4 — Open port profile
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
    {"ports": {502},                             "category": "scada_ics"}, # Modbus
    {"ports": {102},                             "category": "scada_ics"}, # S7comm
    {"ports": {20000},                           "category": "scada_ics"}, # DNP3
    {"ports": {44818},                           "category": "scada_ics"}, # EtherNet/IP
    {"ports": {47808},                           "category": "scada_ics"}, # BACnet/IP
    {"ports": {4840},                            "category": "scada_ics"}, # OPC UA
    {"ports": {2404},                            "category": "scada_ics"}, # IEC-104
    {"ports": {18245},                           "category": "scada_ics"}, # GE SRTP
    {"ports": {9600},                            "category": "scada_ics"}, # Omron FINS
    {"ports": {5007},                            "category": "scada_ics"}, # Mitsubishi MELSEC
    {"ports": {2455},                            "category": "scada_ics"}, # CoDeSys
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
    "siemens":         "scada_ics",
    "s7-":             "scada_ics",
    "plc":             "scada_ics",
    "scada":           "scada_ics",
    "modbus":          "scada_ics",
    "bacnet":          "scada_ics",
    "opc ua":          "scada_ics",
    "opcua":           "scada_ics",
    "dnp3":            "scada_ics",
    "ethernet/ip":     "scada_ics",
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
# Signal 7 — Nmap CPE mapping
# ---------------------------------------------------------------------------

def _classify_from_cpe(os_cpe: Optional[List[str]]) -> Optional[str]:
    if not os_cpe:
        return None
    for item in os_cpe:
        cpe = str(item).lower()
        if "cpe:/o:cisco:ios" in cpe or "cpe:/o:juniper:junos" in cpe or "cpe:/o:mikrotik:routeros" in cpe:
            return "router"
        if "cpe:/o:fortinet:fortios" in cpe or "cpe:/h:paloalto:" in cpe:
            return "firewall"
        if "cpe:/h:hp:procurve" in cpe:
            return "switch"
    return None


# ---------------------------------------------------------------------------
# Master classifier
# ---------------------------------------------------------------------------

def classify_device(host: Dict) -> str:
    """
    Run all evidence signals through a weighted scoring matrix and return the winning category.

    Also writes the result back to ``host["device_category"]`` and ``host["device_category_signal"]``
    so callers don't need to handle the return value separately.
    """
    # 0. Check for OT Info (Modbus/S7/CIP/etc.) first (high-confidence active query)
    ot_info = host.get("ot_info")
    if ot_info:
        category = "scada_ics"
        _write(host, category, ot_info.get("protocol", "ot_probe"))
        if "vendor" in ot_info:
            host["vendor"] = ot_info["vendor"]
        if "model" in ot_info:
            host["os_family"] = "Embedded"
            host["os_confidence"] = "High"
        return category

    # 1. Check for Credentialed override first (100% trusted local OS query)
    is_credentialed = host.get("discovery_method") == "credentialed" or "credentialed_system_info" in host.get("custom_attributes", {})
    if is_credentialed:
        os_fam = host.get("os_family") or ""
        os_n = (host.get("os_name") or "").lower()
        hostname = (host.get("hostname") or "").lower()
        
        if "windows server" in os_fam.lower() or "windows server" in os_n:
            category = "server"
        elif "windows" in os_fam.lower() or "windows" in os_n:
            category = "endpoint"
        elif "esxi" in os_fam.lower() or "esxi" in os_n:
            category = "virtual_machine"
        elif "cisco ios" in os_fam.lower() or "cisco" in os_n:
            category = "router"
        elif "junos" in os_fam.lower() or "juniper" in os_n:
            category = "router"
        elif "fortios" in os_fam.lower() or "fortinet" in os_n:
            category = "firewall"
        else:
            # Linux or other OS family
            if any(k in hostname for k in ["desktop", "laptop", "workstation", "pc-", "client"]):
                category = "endpoint"
            else:
                category = "server"
        
        _write(host, category, "credentialed")
        return category

    # Initialize weighted scoring matrix
    CATEGORIES = [
        "router", "switch", "firewall", "wireless_ap", "printer", "iot",
        "server", "endpoint", "voip", "storage", "network_appliance",
        "scada_ics", "virtual_machine"
    ]
    scores = {cat: 0 for cat in CATEGORIES}
    contributions = {cat: ("none", 0) for cat in CATEGORIES}

    def add_score(category: str, weight: int, signal: str):
        if category in scores:
            scores[category] += weight
            sig_name, sig_w = contributions[category]
            if weight > sig_w:
                contributions[category] = (signal, weight)

    # Signal A: Hostname Heuristics
    hostname = (host.get("hostname") or "").lower()
    if hostname:
        if any(k in hostname for k in ["desktop", "laptop", "workstation", "pc-", "client"]):
            add_score("endpoint", 100, "hostname")
            add_score("router", -60, "hostname")
            add_score("switch", -60, "hostname")
            add_score("firewall", -60, "hostname")
            add_score("server", -30, "hostname")
        elif any(k in hostname for k in ["server", "srv-", "srv", "web", "db-", "sql", "mail"]):
            add_score("server", 100, "hostname")
            add_score("endpoint", -50, "hostname")
            add_score("router", -50, "hostname")
        elif any(k in hostname for k in ["router", "rtr-", "rtr", "gateway", "gw-", "gw"]):
            add_score("router", 100, "hostname")
            add_score("endpoint", -60, "hostname")
            add_score("server", -60, "hostname")
        elif any(k in hostname for k in ["switch", "sw-", "sw"]):
            add_score("switch", 100, "hostname")
            add_score("endpoint", -60, "hostname")
            add_score("server", -60, "hostname")
        elif any(k in hostname for k in ["firewall", "fw-", "fw"]):
            add_score("firewall", 100, "hostname")
            add_score("endpoint", -60, "hostname")
            add_score("server", -60, "hostname")
        elif any(k in hostname for k in ["plc", "scada", "rtu", "modbus"]):
            add_score("scada_ics", 100, "hostname")
            add_score("endpoint", -50, "hostname")

    # Signal 1: SNMP
    snmp = host.get("snmp_info", {})
    if snmp and snmp.get("open"):
        sys_descr = str(snmp.get("sys_descr", "")).lower()
        is_pc_os = False
        
        # Deep sysDescr parsing (case-insensitive checks) to extract PC operating systems
        if any(k in sys_descr for k in ["ubuntu", "debian", "red hat", "centos", "gentoo", "fedora", "suse", "generic", "windows 10", "windows 11"]):
            is_pc_os = True
            add_score("endpoint", 80, "snmp")
            add_score("server", 40, "snmp")
            add_score("router", -80, "snmp")
            add_score("switch", -80, "snmp")
            add_score("firewall", -80, "snmp")
        elif any(k in sys_descr for k in ["cisco ios", "cisco catalyst", "cisco nexus", "routeros", "junos"]):
            add_score("router", 95, "snmp")
            add_score("endpoint", -80, "snmp")
            add_score("server", -80, "snmp")

        # If not a standard PC OS (or if no explicit PC OS keyword), process forwarding OIDs
        if not is_pc_os:
            if snmp.get("ip_forwarding") == 1:
                add_score("router", 90, "snmp")
                add_score("endpoint", -50, "snmp")
                add_score("server", -50, "snmp")
            if snmp.get("bridge_mib"):
                add_score("switch", 95, "snmp")
                add_score("endpoint", -50, "snmp")
            if snmp.get("if_count", 0) > 4 and snmp.get("ip_forwarding") == 2:
                add_score("switch", 75, "snmp")

    # Signal 2: mDNS services
    mdns_services = host.get("mdns_services", [])
    if mdns_services:
        services_set = set(mdns_services)
        if {"_printer._tcp.local", "_ipp._tcp.local"} & services_set:
            add_score("printer", 95, "mdns")
        if {"_ssh._tcp.local", "_workstation._tcp.local"} & services_set:
            add_score("endpoint", 80, "mdns")

    # Signal 3: NetBIOS suffix roles
    netbios_names = host.get("netbios_names", [])
    if netbios_names:
        types = {n.get("type") for n in netbios_names if isinstance(n, dict) and "type" in n}
        if {0x1D, 0x1B, 0x1C} & types:
            add_score("server", 95, "netbios")
        elif 0x20 in types:
            add_score("server", 90, "netbios")
        elif 0x00 in types:
            add_score("endpoint", 80, "netbios")

    # Signal 3.5: Nmap CPE
    os_cpe = host.get("os_cpe", [])
    if os_cpe:
        for item in os_cpe:
            cpe = str(item).lower()
            if "cpe:/o:cisco:ios" in cpe or "cpe:/o:juniper:junos" in cpe or "cpe:/o:mikrotik:routeros" in cpe:
                add_score("router", 95, "nmap_cpe")
            elif "cpe:/o:fortinet:fortios" in cpe or "cpe:/h:paloalto:" in cpe:
                add_score("firewall", 95, "nmap_cpe")
            elif "cpe:/h:hp:procurve" in cpe:
                add_score("switch", 95, "nmap_cpe")

    # Signal 4: Port Profile
    open_ports = [p["port"] for p in host.get("open_ports", [])]
    if open_ports:
        port_set = set(open_ports)
        for rule in _PORT_PROFILE_RULES:
            required = rule.get("ports", set())
            optional = rule.get("any", set())
            if required.issubset(port_set):
                if not optional or optional & port_set:
                    add_score(rule["category"], 85, "port_profile")

    # Signal 5: Banner keywords
    texts = []
    snmp_inf = host.get("snmp_info", {})
    if snmp_inf:
        texts.append(snmp_inf.get("sys_descr", ""))
    for port_rec in host.get("open_ports", []):
        texts.append(port_rec.get("banner", ""))
        texts.append(port_rec.get("version", ""))
        texts.append(port_rec.get("service", ""))
    texts.append(host.get("os_guess", ""))
    combined_text = " ".join(str(t) for t in texts if t).lower()
    
    for kw, cat in _BANNER_KEYWORDS.items():
        if kw in combined_text:
            add_score(cat, 60, "banner")

    # Signal 6: OUI Vendor
    vendor = host.get("vendor") or host.get("mac_vendor")
    if not vendor:
        from core.oui_lookup import lookup_vendor
        vendor = lookup_vendor(host.get("mac", "")) or ""
    if vendor:
        category_from_oui = _classify_from_vendor(vendor)
        if category_from_oui:
            add_score(category_from_oui, 50, "oui")

    # Signal 7: TTL
    ttl = host.get("tcp_fingerprint", {}).get("ttl") or _extract_ttl(host)
    if ttl is not None:
        category_from_ttl = _classify_from_ttl(ttl)
        if category_from_ttl:
            add_score(category_from_ttl, 30, "ttl")

    # Select category with highest score
    winner = "unknown"
    max_score = 0
    for cat, score in scores.items():
        if score > max_score:
            max_score = score
            winner = cat

    # Gating threshold: must be >= 40 to avoid weak-signal hallucinations
    if max_score < 40:
        winner = "unknown"
        winning_signal = "none"
    else:
        winning_signal = contributions[winner][0]

    _write(host, winner, winning_signal)

    # Set os_family/os_confidence overrides if needed
    if winner != "unknown":
        if not host.get("os_family") or host.get("os_family") == "Unknown":
            if winning_signal == "mdns":
                mdns_services = set(host.get("mdns_services", []))
                if {"_printer._tcp.local", "_ipp._tcp.local"} & mdns_services:
                    host["os_family"] = "Embedded"
                    host["os_confidence"] = "High"
                else:
                    v_name = (host.get("vendor") or host.get("mac_vendor") or "").lower()
                    host["os_family"] = "macOS" if "apple" in v_name else "Linux"
                    host["os_confidence"] = "Medium"
            elif winning_signal == "netbios":
                host["os_family"] = "Windows"
                types = {n.get("type") for n in host.get("netbios_names", []) if isinstance(n, dict) and "type" in n}
                if {0x1D, 0x1B, 0x1C} & types:
                    host["os_confidence"] = "High"
                else:
                    host["os_confidence"] = "Medium"
            elif winning_signal == "oui" and vendor:
                os_fam = _os_from_vendor(vendor)
                if os_fam:
                    host["os_family"] = os_fam
                    host["os_confidence"] = "Medium"

    return winner


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
