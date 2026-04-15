# CCure-Audit-PRO — Network Device Identification Analysis

> **Scope:** Full backend codebase audit — all engines, plugins, models, and constants  
> **Date:** 2026-04-15  
> **Verdict (preview):** ⚠️ **PARTIAL** — Implicit, unreliable detection only

---

## 1. Summary of Scanning Capabilities

The system implements a **4-phase pipeline**:

| Phase | Engine | What it does |
|-------|--------|-------------|
| 1 | `DiscoveryEngine` | Host liveness: ARP, ICMP, TCP SYN, TCP connect, adaptive |
| 2 | `PortEngine` | TCP port scanning + UDP service probing + banner grabbing |
| 3 | `VulnerabilityEngine` + Plugins | TLS, HTTP, SSH, SMB, SNMP, UDP, ICMP, FTP, CVE analysis |
| 4 | `calculate_risk()` | Host risk scoring (0–100) |

**Scanning methods implemented:**

| Method | Location | Notes |
|--------|----------|-------|
| ARP broadcast | `discovery_engine.py:183` | LAN only, needs root |
| ICMP echo + timestamp | `discovery_engine.py:224` | TTL captured for OS fingerprinting |
| TCP SYN | `discovery_engine.py:201` | TTL + TCP window captured |
| TCP connect (async) | `discovery_engine.py:288` | Unprivileged fallback |
| UDP probes (9 services) | `udp_scanner.py`, `port_engine.py` | DNS, DHCP, SNMP, NTP, TFTP, Kerberos, IKE, mDNS, LDAP |
| SNMP GetRequest | `snmp_probe.py` | OID 1.3.6.1.2.1.1.1.0 (sysDescr) |
| Banner grabbing | `port_engine.py:354` | SSH, HTTP, FTP, SMTP, Redis, MySQL, RDP, VNC, etc. |
| HTTP header audit | `http_analyzer.py` | Server header, security headers |
| SMB negotiate | `smb_probe.py` | SMBv1 vs SMBv2/3 detection |
| SSH algorithm probe | `ssh_probe.py` | KEX, cipher, MAC algorithm enumeration |
| OUI/MAC vendor lookup | `oui_lookup.py` + `manuf.txt` | IEEE OUI database + macvendors.com API |
| TTL + TCP window fingerprinting | `risk.py:fingerprint_os()` | Maps to OS family |
| Service-inference OS scoring | `risk.py:infer_os_from_host()` | Port-based heuristic scoring |

---

## 2. Device Detection Analysis

### 2.1 Router Detection

**Can it detect routers?** — **PARTIALLY (Implicit)**

The code does not have any explicit `device_type = "Router"` classification. However, routers can be *inferred* through several signals:

#### Evidence in code:

**a) TTL = 255 maps to Cisco/Network Appliance** (`constants.py:301`)
```python
OS_TTL_MAP = [
    (32,  "Windows 9x / Embedded"),
    (64,  "Linux / Android / macOS / FreeBSD"),
    (128, "Windows (NT/2000/XP/7/8/10/11)"),
    (200, "Solaris / AIX"),
    (255, "Cisco IOS / Network Appliance"),   # ← router/switch signature
]
```
When a host replies to ICMP/TCP SYN with TTL=255, `fingerprint_os()` returns `"Cisco IOS / Network Appliance"`. This fires in both Phase 1 (`_scapy_syn`, `_scapy_icmp_probe`) and Phase 2.

**b) TCP window = 4096 maps to Cisco IOS** (`constants.py:312`)
```python
TCP_WINDOW_OS = {
    4096:  "Cisco IOS",   # ← Cisco routers/switches
    ...
}
```

**c) Banner/text matching in `infer_os_from_host()`** (`risk.py:94`)
```python
("Cisco IOS / Network Appliance", ["cisco ios", "routeros", "junos", "fortios"], "High"),
```
If SSH or SNMP banner contains `cisco ios`, `routeros` (MikroTik), or `junos` (Juniper), the device is classified as a Network Appliance.

**d) SNMP sysDescr fetch** (`snmp_probe.py:77`)
```python
info["sys_descr"] = data[idx + 2:idx + 2 + str_len].decode("utf-8", errors="ignore")
```
The probe fetches OID `1.3.6.1.2.1.1.1.0` (sysDescr), which on real Cisco/Juniper/MikroTik devices returns strings like:
- `"Cisco IOS Software, Version 15.2..."`
- `"Junos 21.2R3..."`
- `"RouterOS 6.49.x"`

This `sys_descr` value is referenced in `infer_os_from_host()` via `snmp_info.get("sys_descr", "")`.

**e) Port fingerprinting** (`constants.py:157,161,500`)
```python
179:  {"service": "BGP",  "risk": "High", "note": "Border Gateway Protocol"},
520:  {"service": "RIP",  "risk": "High", "note": "Routing Information Protocol"},
500:  {"service": "IKE",  "risk": "Medium"},   # VPN gateway
```
Open BGP (179) or RIP (520) strongly suggests a router. These ports are scanned in NORMAL/DEEP mode.

**f) IKE/IPsec probe** (`udp_scanner.py:184`)
```python
if data and len(data) > 28:
    found.append({"port": 500, "service": "IKE",
                  "info": "IKE/IPsec VPN gateway responding..."})
```
IKE response on UDP 500 is a strong indicator of a VPN-capable router or firewall.

---

### 2.2 Switch Detection

**Can it detect switches?** — **VERY WEAKLY (Implicit)**

Switches are the hardest to detect via IP-based scanning because most switches are L2 devices that don't respond to L3 probes on their own IPs (only management IPs do).

#### What the code can infer:

**a) MAC OUI lookup** (`oui_lookup.py`, `scan_orchestrator.py:701`)
```python
vendor = lookup_vendor(mac) or "N/A"
```
If ARP reveals a MAC address with OUI belonging to Cisco, HP/Aruba, Juniper, or Dell, it indicates a switch. The `manuf.txt` (6.4MB IEEE file) is loaded to resolve vendors. However, the code **does not use the vendor string to classify the device as a switch** — it only exposes it as an informational field.

**b) SNMP sysDescr on management IP**
If a managed switch has SNMP enabled on its management VLAN IP, the `snmp_probe.py` will fetch its `sysDescr`. Strings like `"HP ProCurve J8697A..."` or `"Cisco Catalyst IOS..."` appear there — but again, **no code parses this to set `device_type = "Switch"`**.

**c) Cisco IOS TTL = 255**
Cisco Catalyst switches also run IOS and return TTL=255, so they'd be classified the same as routers (`"Cisco IOS / Network Appliance"`). The code cannot distinguish router vs. switch from TTL alone.

**d) TFTP open** (`udp_scanner.py:83`)
```python
found.append({"port": 69, "service": "TFTP", "info": "TFTP open - anonymous read possible"})
```
Many managed switches run TFTP for firmware uploads. An open TFTP server alongside SNMP and Telnet is a heuristic switch indicator — but the code does not correlate these signals.

---

### 2.3 Firewall Detection

**Can it detect firewalls?** — **PARTIALLY (Implicit)**

**a) IKE/IPsec responding** (`udp_scanner.py:213`)
```python
found.append({"port": 500, "service": "IKE",
              "info": "IKE/IPsec VPN gateway responding - check for aggressive mode / weak ciphers"})
```
Firewalls (FortiGate, Cisco ASA, pfSense) respond to IKE. This note is purely informational.

**b) FortiOS banner match** (`risk.py:94`)
```python
("Cisco IOS / Network Appliance", ["cisco ios", "routeros", "junos", "fortios"], "High"),
```
`fortios` keyword triggers "Network Appliance" classification — FortiGate firewalls would be caught here via SNMP sysDescr or SSH banner.

**c) Scoring heuristic** (`risk.py:133`)
```python
if any(term in text_blob for term in ("cisco", "routeros", "junos", "fortinet")):
    scores["Network Appliance"] += 4
```
Banner text containing `fortinet` bumps the `Network Appliance` score by 4 points.

**d) Open ports typical of firewalls** (`constants.py`)
The following ports in `PORT_DB` suggest a firewall/security appliance:
```python
500:   {"service": "IKE",    ...},   # IPsec VPN
4500:  {"service": "IPsec-NAT", ...},
1194:  {"service": "OpenVPN", ...},
1701:  {"service": "L2TP",    ...},
1723:  {"service": "PPTP",    ...},
```
If a host shows IKE + no common server ports (no HTTP/SSH/SMB) the probability of it being a firewall is high — but the code does not implement this correlation.

**e) Scapy STEALTH mode** — fragmented packets bypass stateless packet filters, indirectly exposing firewall presence through the *absence* of SYN-ACK on filtered ports.

---

## 3. Techniques Used & Code Mapping

| Technique | Implementation | File | Lines | Device Relevance |
|-----------|---------------|------|-------|-----------------|
| **TTL fingerprinting** | `fingerprint_os(ttl, win)` | `risk.py` | 17–42 | TTL=255 → Cisco IOS |
| **TCP window fingerprinting** | `TCP_WINDOW_OS` lookup | `constants.py` | 304–313 | Window=4096 → Cisco IOS |
| **ICMP timestamp probe** | `_scapy_icmp_probe()` | `discovery_engine.py` | 224–246 | OS hint via TTL |
| **Banner grabbing** | `_probe_port()` | `port_engine.py` | 162–248 | SSH/HTTP banner: vendor ID |
| **Protocol-specific banner parsing** | `_parse_banner()` | `port_engine.py` | 354–448 | SSH, FTP, SMTP versions |
| **SNMP sysDescr fetch** | `_probe_snmp()` | `snmp_probe.py` | 56–83 | Device string from MIB |
| **SNMP community scan** | 4 communities tried | `snmp_probe.py` | 60 | public/private/community/snmp |
| **IKE probe** | IKEv1 Main Mode SA | `udp_scanner.py` | 184–216 | VPN gateway / firewall |
| **DHCP server detect** | DHCPDISCOVER | `udp_scanner.py` | 57–81 | Router (DHCP server role) |
| **DNS server detect** | DNS A query | `udp_scanner.py` | 41–55 | Router / DNS appliance |
| **OUI/MAC vendor lookup** | `lookup_vendor(mac)` | `oui_lookup.py` | 179–210 | Vendor = Cisco, Juniper, etc. |
| **Service inference scoring** | `infer_os_from_host()` | `risk.py` | 45–162 | "Network Appliance" score |
| **Keyword matching** | explicit_markers list | `risk.py` | 83–98 | cisco ios, routeros, fortios, junos |
| **BGP/RIP port detection** | `PORT_DB` + port scan | `constants.py` | 157, 161 | Router (routing protocols) |
| **ARP scan** | `_scapy_arp()` | `discovery_engine.py` | 183–199 | MAC collection for OUI |
| **Telnet on port 23** | `PORT_DB` + TCP connect | `constants.py` | 102 | Network device (often Telnet-managed) |

---

## 4. Gaps and Limitations

### ❌ Gap 1: No Explicit Device Type Classification
**Critical.** Nowhere in the entire codebase is there a `device_type` field set to `"Router"`, `"Switch"`, or `"Firewall"`. The `HostResult` model (`models.py:86`) has no such field. Detection is entirely **implicit** — the user/frontend must interpret `os_guess`, `vendor`, SNMP data, and open ports manually.

### ❌ Gap 2: SNMP sysDescr is Fetched but Not Parsed for Device Type
`snmp_probe.py` correctly retrieves `sysDescr` (the definitive device identification string), but the result is stored as a raw string. No code path extracts `device_type` from it. Strings like `"Cisco IOS, Version 15.2..."` or `"FortiOS v7.2..."` are never classified.

### ❌ Gap 3: OUI Vendor is Not Used for Device Classification
`oui_lookup.py` correctly resolves MAC → vendor (e.g., `"Cisco Systems"`, `"Juniper Networks"`), and the vendor is stored in `HostResult.vendor`. However, no logic uses `vendor` to infer that a device is a switch or router.

### ❌ Gap 4: No SNMP OID Walk Beyond sysDescr
Only OID `1.3.6.1.2.1.1.1.0` (sysDescr) is queried. Critical device classification OIDs are not fetched:
- `1.3.6.1.2.1.1.2.0` — **sysObjectID** (uniquely identifies device model from vendor MIB)
- `1.3.6.1.2.1.2.1.0` — **ifNumber** (number of interfaces — large count = switch)
- `1.3.6.1.2.1.4.1.0` — **ipForwarding** (1 = routing enabled = router)

### ❌ Gap 5: No Correlation of Multi-Signal Evidence
The system collects evidence independently (TTL, ports, banner, SNMP, vendor) but never **correlates** them into a classification decision. A device with:
- TTL=255
- Open SNMP (161)
- TFTP (69)
- No HTTP/SMB
- Cisco OUI

...would not be labelled as anything other than `os_guess = "Cisco IOS / Network Appliance"`.

### ❌ Gap 6: BGP/RIP Ports Not Used as Router Signals
`PORT_DB` correctly identifies BGP (179) and RIP (520) as routing protocols. But `infer_os_from_host()` **does not check for these ports** in its scoring logic.

### ❌ Gap 7: Switch-Specific Protocols Not Probed
The code does not probe:
- **CDP** (Cisco Discovery Protocol) — multicast, reveals device role
- **LLDP** — IEEE device discovery, exposes chassis type
- **STP BPDUs** — layer-2 switch detection (requires raw socket/scapy)

### ❌ Gap 8: Cisco IOS / Network Appliance Is Too Broad
TTL=255 is assigned to `"Cisco IOS / Network Appliance"` — but this bucket includes routers, switches, firewalls, and load balancers running IOS/NX-OS/IOS-XE. There is no disambiguation.

### ❌ Gap 9: No Nmap Integration
The codebase uses Scapy for raw packets but does not invoke Nmap. Nmap's `-O` (OS detection), `-sV` (service/version), and `--script` engine (SNMP enum, Cisco-specific NSE scripts) would dramatically improve device identification accuracy.

---

## 5. Suggested Improvements

### ✅ Improvement 1: Add `device_type` to HostResult Model

```python
# core/models.py
@dataclass
class HostResult:
    ...
    device_type: str = "Unknown"  # "Router" | "Switch" | "Firewall" | "Server" | "Workstation" | "IoT"
    device_confidence: str = "Low"
```

### ✅ Improvement 2: SNMP-Based Device Classification Engine

```python
# core/device_classifier.py
SNMP_DEVICE_HINTS = {
    # Keyword in sysDescr → device type
    "cisco ios":          "Router/Switch",
    "cisco nexus":        "Switch",
    "cisco catalyst":     "Switch",
    "cisco asa":          "Firewall",
    "cisco firepower":    "Firewall",
    "junos":              "Router",
    "fortios":            "Firewall",
    "fortigate":          "Firewall",
    "routeros":           "Router",
    "pfsense":            "Firewall",
    "opnsense":           "Firewall",
    "extreme networks":   "Switch",
    "hp procurve":        "Switch",
    "aruba":              "Switch/AP",
    "ubiquiti":           "Router/AP",
    "edgeos":             "Router",
}

def classify_from_snmp(sys_descr: str) -> tuple[str, str]:
    """Returns (device_type, confidence)"""
    blob = sys_descr.lower()
    for keyword, dtype in SNMP_DEVICE_HINTS.items():
        if keyword in blob:
            return dtype, "High"
    return "Unknown", "Low"
```

### ✅ Improvement 3: Fetch sysObjectID and ipForwarding via SNMP

Extend `snmp_probe.py` to also query:
```python
OID_SYS_OBJECT_ID = b"\x2b\x06\x01\x02\x01\x01\x02\x00"  # sysObjectID
OID_IP_FORWARDING = b"\x2b\x06\x01\x02\x01\x04\x01\x00"   # ipForwarding (1=router)
OID_IF_NUMBER     = b"\x2b\x06\x01\x02\x01\x02\x01\x00"   # ifNumber
```
`ipForwarding = 1` → definitively a router. `ifNumber > 24` → likely a switch.

### ✅ Improvement 4: OUI Vendor → Device Type Heuristic

```python
# core/device_classifier.py
NETWORK_DEVICE_OUIS = {
    # Vendor string → likely device type (must have SNMP or Telnet to confirm)
    "cisco":        "Network Device",
    "juniper":      "Network Device",
    "ubiquiti":     "Network Device",
    "mikrotik":     "Network Device",
    "netgear":      "Network Device",
    "tp-link":      "Network Device",
    "aruba":        "Network Device",
    "fortinet":     "Firewall",
    "palo alto":    "Firewall",
    "check point":  "Firewall",
    "sonicwall":    "Firewall",
}

def classify_from_vendor(vendor: str) -> str:
    if not vendor:
        return "Unknown"
    v = vendor.lower()
    for key, dtype in NETWORK_DEVICE_OUIS.items():
        if key in v:
            return dtype
    return "Unknown"
```

### ✅ Improvement 5: Multi-Signal Classification Heuristic in `infer_os_from_host()`

Add a `device_type` scoring pass to `risk.py`:

```python
def classify_device_type(host: Dict) -> Tuple[str, str]:
    open_ports = {p["port"] for p in host.get("open_ports", [])}
    snmp_descr = (host.get("snmp_info") or {}).get("sys_descr", "").lower()
    vendor     = (host.get("vendor") or "").lower()
    os_guess   = (host.get("os_guess") or "").lower()
    udp_svcs   = {s["port"] for s in host.get("udp_services", [])}

    # Strong signals
    if 500 in udp_svcs and not {80, 443, 445, 3389} & open_ports:
        return "Firewall/VPN Gateway", "High"
    if 179 in open_ports:   # BGP
        return "Router", "High"
    if 520 in open_ports:   # RIP
        return "Router", "Medium"
    if "ipforwarding" in snmp_descr or "cisco ios" in snmp_descr:
        return "Router", "High"
    if "catalyst" in snmp_descr or "procurve" in snmp_descr:
        return "Switch", "High"
    if "fortios" in snmp_descr or "asa" in snmp_descr:
        return "Firewall", "High"

    # Weak signals
    if 69 in udp_svcs and 161 in udp_svcs and 23 in open_ports:
        return "Network Device", "Medium"

    return "Unknown", "Low"
```

### ✅ Improvement 6: Add Nmap OS/Service Detection (Optional but Powerful)

```python
import subprocess, json

def nmap_os_detect(ip: str) -> dict:
    """Run nmap -O -sV --osscan-guess and return parsed result."""
    cmd = ["nmap", "-O", "-sV", "--osscan-guess", "-oX", "-", ip]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    # Parse XML output ...
    return parsed_result
```

### ✅ Improvement 7: Add CDP/LLDP Passive Listening (LAN only)

```python
# Using scapy - passively sniff CDP/LLDP frames
from scapy.all import sniff, Dot3, LLC

def sniff_lldp(interface: str, timeout: int = 10):
    """Capture LLDP frames to identify network infrastructure devices."""
    pkts = sniff(iface=interface, filter="ether proto 0x88cc", timeout=timeout)
    # Parse TLVs: System Name, System Description, Capabilities (Router/Switch/Bridge)
    ...
```
LLDP **Capabilities TLV** explicitly marks a device as `Router`, `Bridge` (Switch), or `Station`.

### ✅ Improvement 8: Extend `infer_os_from_host()` for BGP/RIP Port Scoring

```python
# risk.py - add to infer_os_from_host()
if 179 in open_ports:   # BGP
    scores["Network Appliance"] += 6
if 520 in open_ports:   # RIP
    scores["Network Appliance"] += 5
if 161 in open_ports and 23 in open_ports and 69 in open_ports:
    scores["Network Appliance"] += 4  # SNMP + Telnet + TFTP = classic router
```

---

## 6. Final Verdict

```
┌─────────────────────────────────────────────────────────┐
│                    FINAL VERDICT                         │
│                                                          │
│  Device Type    │  Detection Status  │  Reliability      │
│─────────────────┼────────────────────┼───────────────────│
│  Router         │  ⚠️ PARTIAL         │  Low–Medium       │
│  Switch         │  ❌ Minimal         │  Very Low         │
│  Firewall       │  ⚠️ PARTIAL         │  Low              │
│                                                          │
│  OVERALL VERDICT:  ⚠️  PARTIAL                           │
└─────────────────────────────────────────────────────────┘
```

### Why PARTIAL and not YES:

1. **No `device_type` field exists** in the data model — detection is never made explicit.
2. **SNMP sysDescr is the best signal** and it's fetched, but never parsed to produce a device classification.
3. **OUI vendor is resolved** but never cross-referenced to produce a device classification.
4. **TTL=255 / window=4096** correctly points to Cisco/Network Appliance, but this bucket includes routers, switches, and firewalls without distinction.
5. **IKE probe** reveals VPN functionality (firewall/router), but `udp_scanner.py` only records it as a service note, not a classification.
6. **BGP (179) and RIP (520)** — definitive router indicators — are in `PORT_DB` and scanned, but the `infer_os_from_host()` scoring model does not factor them in.
7. **Switches** are effectively invisible unless they have a management IP with SNMP, and even then the sysDescr isn't parsed.

### What would push this to YES:
- Implement `classify_device_type()` heuristic using all collected signals
- Parse SNMP sysDescr with a keyword dictionary
- Use OUI vendor for device type hints
- Add BGP/RIP/IKE port signals to the scoring model
- Add `device_type` field to `HostResult`

---

*Analysis performed on commit snapshot dated 2026-04-15. All line references are based on the files as read.*
