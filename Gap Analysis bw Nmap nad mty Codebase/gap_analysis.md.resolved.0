# CCure-Audit-PRO vs Nmap — Deep Technical Gap Analysis

> **Scope:** `discovery_engine.py`, `port_engine.py`, `core/risk.py`, `core/constants.py`, `core/oui_lookup.py`, `core/utils.py`, `engines/vulnerability/` plugins (TLS, HTTP, SSH, SMB, SNMP, UDP, ICMP, FTP, CVE).
> **Verdict Summary:** **Intermediate** — well above a basic scanner, significantly below Nmap.

---

## 1. What Is Currently Implemented

### 1.1 Host Discovery (`discovery_engine.py`)

| Technique | Implementation | Notes |
|---|---|---|
| **ARP Scan** | `_scapy_arp()` — `srp(Ether/ARP, ...)` | LAN only, 0.5 s timeout, populates MAC |
| **ICMP Echo** | `_scapy_icmp_probe()` / `_scapy_layered()` | Type 0 + Type 13 (timestamp) in FULL mode |
| **TCP SYN** | `_scapy_syn()` — raw `IP/TCP(flags="S")` | Extracts TTL + TCP window from reply |
| **TCP Connect** | `_async_tcp()` — asyncio `open_connection` | No-root fallback; TLS wrap on 443/8443 |
| **DNS UDP probe** | `_scapy_layered()` FULL mode | One DNS query to root servers |
| **Packet fragmentation** | `fragment(pkt)` in STEALTH mode | Primitive IP fragmentation only |
| **Adaptive routing** | LAN → ARP+ICMP, WAN → SYN | Private-address heuristic |
| **Latency capture** | `_capture_latency_ms()` | From Scapy `sent_time`/`recv.time` |

### 1.2 Port Scanning (`port_engine.py`)

| Capability | Detail |
|---|---|
| **TCP Connect scan** | asyncio; semaphore-controlled (30–100) |
| **TLS auto-wrap** | Ports 443, 8443, 465, 993, 995 |
| **Port lists** | LIGHT (68 ports), NORMAL (~165 named ports), DEEP (same ports, longer timeout) |
| **Banner grabbing** | Per-port probes: SSH, HTTP HEAD, MySQL handshake, PostgreSQL, MSSQL TDS, MongoDB noop, Redis PING, RDP X.224, VNC RFB, SMTP HELO, POP3 USER, IMAP CAPABILITY, FTP HELP |
| **UDP probing** | DNS, DHCP, NTP, SNMP, Syslog, UPnP — raw socket `sendto/recvfrom` |
| **CVE correlation** | Banner → SQLite NVD DB → hardcoded `CVE_HINTS` fallback |

### 1.3 OS Fingerprinting (`core/risk.py` + `core/constants.py`)

| Method | Implementation |
|---|---|
| **TTL bucketing** | 5-tier map: ≤32 → Win9x, ≤64 → Linux/macOS, ≤128 → Windows NT, ≤200 → Solaris/AIX, ≤255 → Cisco/IOS |
| **TCP Window size** | 8-entry lookup table: 65535=Windows classic, 64240=Win10/11, 4096=Cisco IOS, etc. |
| **Service-level inference** | Port presence scores (RDP=+5 Windows, NFS=+5 Linux, AFP=+4 BSD) + banner text matching |
| **Explicit string markers** | Detect IIS, WinRM, Ubuntu, Debian, CentOS, Alpine, Cisco IOS, FortiOS, JunOS |

### 1.4 Supporting Infrastructure

| Component | Detail |
|---|---|
| **OUI / MAC vendor** | `oui_lookup.py` — 6.4 MB `manuf.txt` + async API fallback (macvendors.com) |
| **CVE database** | SQLite + `download_nvd.py` + 16 hardcoded hint entries |
| **Risk scoring** | Port-weight + CVSS + HTTP header issues + TLS grade → 0-100 score |
| **Vulnerability plugins** | TLS cert/cipher, HTTP headers, SSH algo probe, SMB dialect, SNMP community, UDP services, ICMP TTL, FTP anonymous, CVE matching |
| **Rate limiter** | Token-bucket (default 200 ops/s) |
| **Privilege detection** | Admin/root check → gates Scapy availability |

---

## 2. Nmap Feature Comparison

### 2.1 Side-by-Side Matrix

| Feature Category | Nmap | CCure-Audit-PRO | Gap Level |
|---|---|---|---|
| **ARP discovery** | ✅ | ✅ | None |
| **ICMP echo / timestamp** | ✅ | ✅ | None |
| **TCP SYN scan** | ✅ | ✅ (partial — no RST on close) | Minor |
| **TCP Connect scan** | ✅ | ✅ | None |
| **TCP ACK scan** | ✅ | ❌ | **Missing** |
| **TCP FIN / Xmas / Null scan** | ✅ | ❌ | **Missing** |
| **TCP Window / Maimon scan** | ✅ | ❌ | **Missing** |
| **UDP full port scan** | ✅ (65535 ports, ICMP unreachable) | ⚠️ (7 named ports only) | **Major** |
| **SCTP scan** | ✅ | ❌ | Missing |
| **IP protocol scan** | ✅ | ❌ | Missing |
| **OS fingerprinting (nmap-os-db)** | ✅ ~5500 signatures | ⚠️ TTL+window only (~13-entry table) | **Major** |
| **TCP ISN analysis** | ✅ | ❌ | **Missing** |
| **IP ID sequence analysis** | ✅ | ❌ | **Missing** |
| **TCP options fingerprinting** | ✅ (MSS, NOP, SACK, TS, WScale) | ❌ | **Missing** |
| **Up-time estimation** | ✅ (via TCP timestamp) | ❌ | Missing |
| **Service/version detection (nmap-service-probes)** | ✅ ~11,000 signatures | ⚠️ ~10 hand-crafted probes | **Major** |
| **Banner grabbing** | ✅ protocol-aware | ✅ protocol-aware (15 services) | Moderate gap |
| **NSE scripting engine** | ✅ 600+ scripts | ❌ Plugin system (9 plugins, fixed) | **Fundamental** |
| **Firewall/filter detection** | ✅ (filtered vs closed states) | ❌ | **Missing** |
| **Idle scan (zombie)** | ✅ | ❌ | Missing |
| **Timing templates (T0–T5)** | ✅ | ⚠️ Semaphore limits only | Moderate |
| **Decoy scan (-D)** | ✅ | ❌ | Missing |
| **Fragmentation evasion** | ✅ (-f, --mtu) | ⚠️ One `fragment()` call | Partial |
| **Source port spoofing** | ✅ | ❌ | Missing |
| **TTL manipulation** | ✅ | ❌ | Missing |
| **SNMP deep enumeration** | ✅ (NSE scripts) | ⚠️ Community probe only | Major |
| **SMB enumeration** | ✅ (NSE: 30+ scripts) | ⚠️ Dialect check only | Major |
| **TLS/SSL audit** | ✅ (NSE: ssl-*, sslscan) | ✅ (cert, cipher, grade) | Moderate gap |
| **HTTP enumeration** | ✅ (NSE: http-*, 100+ scripts) | ✅ (headers, security audit) | Moderate gap |
| **DNS enumeration** | ✅ (NSE: dns-*, zone-xfer) | ❌ (sends one DNS query for host discovery only) | **Missing** |
| **LDAP enumeration** | ✅ (NSE) | ❌ | Missing |
| **mDNS / Bonjour** | ✅ | ❌ | Missing |
| **NetBIOS / NBNS** | ✅ | ❌ | Missing |
| **RPC enumeration** | ✅ | ❌ | Missing |
| **Device type classification** | ✅ (router/switch/WAP/firewall/printer/IoT) | ⚠️ Score-based OS label only | **Major** |
| **MAC OUI vendor lookup** | ✅ | ✅ (manuf.txt + API) | None |
| **CVE/vuln correlation** | ✅ (NSE vuln scripts, Vulscan) | ✅ (SQLite NVD + hints) | Minor |

---

## 3. Identified Gaps — Detailed Breakdown

### GAP-01 · OS Fingerprinting Depth

**What exists:** 5-tier TTL bucketing + 8 TCP window values.
**What's missing:**
- Nmap sends **12 distinct probes** per host (T1–T7, U1, IE1–IE2, ECN, OPS probes) and matches responses against `nmap-os-db` with ~5,500 signatures.
- Key signals NOT captured: IP ID sequence (incremental/random/zero/broken), TCP ISN offset prediction, TCP option order within SYN-ACK (MSS, NOP, WScale SACK, TS), ICMP response Code/TOS/DFbit, initial congestion window size, TOS mirroring.

**Why the gap exists:**
- The current implementation only reads fields already present in Scapy's parsed reply object (`IP.ttl`, `TCP.window`).
- OS-DB lookup tables require a signature-matching engine (not just 5 buckets).
- Sending 12 probe types per host would break the current `sr(pkts, multi=True)` single-shot design.

---

### GAP-02 · UDP Scanning Coverage

**What exists:** 7 hardcoded ports (53, 67, 123, 161, 162, 514, 1900).
**What's missing:**
- Nmap probes **up to 65,535 UDP ports** with protocol-matched payloads from `nmap-service-probes`.
- ICMP Port-Unreachable responses are used to confirm **closed** UDP ports, allowing open/closed/filtered differentiation — none of this logic is present.
- Missing UDP services: TFTP (69), Kerberos (88), NetBIOS (137/138), LDAP (389), IKE (500), mDNS (5353), IPMI (623), RIP (520), bgp (179 over UDP).

**Why the gap exists:**
- UDP probing uses a plain Python socket in the current code. There is no integration with Scapy's `sr()` at UDP layer, so ICMP-unreachable responses (which come back as IP/ICMP packets, not UDP packets) are never seen by `recvfrom()`.
- No mechanism to track "no response + no ICMP unreachable = open|filtered" state.

---

### GAP-03 · Stealth / Evasion Techniques

**What exists:** `fragment(pkt)` wraps all packets in STEALTH mode.
**What's missing:**

| Nmap Technique | CCure Status |
|---|---|
| TCP FIN scan — sends FIN, open ports silently drop | ❌ Not implemented |
| TCP Xmas scan — FIN+PSH+URG set | ❌ Not implemented |
| TCP Null scan — no flags | ❌ Not implemented |
| TCP ACK scan — firewall rule mapping | ❌ Not implemented |
| TCP Window scan — ACK + window analysis | ❌ Not implemented |
| TCP Maimon scan — FIN+ACK | ❌ Not implemented |
| Idle/Zombie scan — IP ID side channel | ❌ Not implemented |
| Decoy scan (-D RND:10) | ❌ Not implemented |
| Source port manipulation (--source-port 53) | ❌ Not implemented |
| Randomized scan order | ❌ Not implemented |
| Inter-probe jitter / T0-T5 timing templates | ⚠️ Semaphore size only (no adaptive RTT) |
| Custom MTU fragmentation (--mtu 8) | ❌ Only Scapy default fragment() |

**Why the gap exists:** The `stealth_mode` flag only adds one IP-layer `fragment()` call. There is no packet-level crafting of abnormal TCP flag combinations. The async TCP pipeline cannot do raw SYN alternatives.

---

### GAP-04 · Port State Differentiation (Open/Closed/Filtered)

**What exists:** Port is either open (connection succeeds) or implicitly closed (exception).
**What's missing:**
- **Closed** = TCP RST received (Nmap uses this).
- **Filtered** = No response after retransmit, or ICMP admin-prohibited.
- Current code swallows all exceptions uniformly — a firewall dropping packets and a host sending RST look identical.

**Why:** asyncio `open_connection` raises `ConnectionRefusedError` on RST and `TimeoutError` on drop — these are caught by a single bare `except Exception: pass`, losing the distinction. Scapy-layer probes do check `rcv.haslayer(TCP)` but never inspect the flags for RST (`0x04`) vs SYN-ACK (`0x12`).

---

### GAP-05 · Service / Version Detection Depth

**What exists:** ~15 hand-written protocol probes; ~9 regex patterns for version extraction.
**What's missing:**
- Nmap ships `nmap-service-probes` with **~11,000 probe/match combinations** covering 900+ services.
- Soft-match fallback (when probe sees non-matching but parseable data).
- Version intensity levels (0–9) to control probe aggressiveness.
- RPC, DCE/MS-RPC discovery.
- Protocol-level interrogation for ICS/SCADA (Modbus, S7comm, DNP3, BACnet) — ports are in `PORT_DB` but no active protocol probes exist.

---

### GAP-06 · NSE / Scripting Engine Equivalent

**What exists:** 9 fixed vulnerability plugins (TLS, HTTP, SSH, SMB, SNMP, UDP, ICMP, FTP, CVE).
**What's missing:**
- Dynamic script loading based on detected services.
- Hundreds of service-specific checks: DNS zone transfer, LDAP anonymous bind, NetBIOS name table, NFS exports, RPC info, Heartbleed active probe, ShellShock, EternalBlue check, default credentials testing.

**Why:** The plugin list in `vulnerability_engine.py` is hardcoded `PLUGINS = [...]`. There is no auto-selection of plugins based on what ports are open.

---

### GAP-07 · Network Device Classification

**What exists:**
- `risk.py::infer_os_from_host()` assigns a score +4 to "Network Appliance" when `cisco/routeros/junos/fortinet` appears in banners.
- TTL=255 maps to "Cisco IOS / Network Appliance" in `OS_TTL_MAP`.

**What's missing:**
- No active SNMP OID walk to distinguish: **router** (IP-Forwarding MIB `.1.3.6.1.2.1.4.1.0 = 1`), **switch** (bridge MIB `.1.3.6.1.2.1.17`), **firewall** (firewallMIB), **WAP** (dot11 MIB).
- No CDP/LLDP frame capture (Layer 2 device type advertisement).
- No ICMP Router Advertisement listening.
- No NetBIOS/NBNS name table lookup (`\x01\x02__MSBROWSE__` magic packet).
- MAC OUI-based device type classification is not wired up — the OUI lookup returns a vendor name but there is no logic to map "Cisco Systems" → router/switch, "Ubiquiti" → WAP, "Brother Industries" → printer.

---

### GAP-08 · SNMP Enumeration Depth

**What exists:** `snmp_probe.py` sends one SNMPv2 `GetRequest` with community `public`; reads `sysDescr`.
**What's missing:**
- OID walk (GetBulk) — system group, interfaces, routing table, ARP cache.
- v3 auth (USM credential probing).
- Community string brute-force (public/private/community/cisco/snmpd).
- Interface enumeration (RFC 1213 ifTable → IP address of each interface).
- Device-type determination from `sysObjectID` enterprise OID.

---

### GAP-09 · DNS / mDNS / NetBIOS Enumeration

**What exists:** One DNS UDP query is sent at Layer 3 during FULL discovery to probe if port 53 is open. No analysis of the DNS response content.
**What's missing:**
- PTR reverse DNS lookups for all discovered IPs.
- mDNS (port 5353) multicast queries → hostname, service type (`_http._tcp`, `_ssh._tcp` etc.).
- NetBIOS NBNS name table enumeration (decodes computer name, workgroup, MAC).
- DNS zone transfer attempt (AXFR) if port 53 TCP is open.

---

### GAP-10 · Firewall / Filter Detection

**What exists:** None.
**What's missing:**
- Nmap sends ACK probes (no TCP state) to unfiltered ports — RST back = unfiltered, no response = filtered.
- ICMP admin-prohibited / net-prohibited classification.
- TCP RST rate-limiting detection (Nmap adjusts retransmit timing if RSTs are throttled).

---

## 4. Why These Gaps Exist — Root Causes

| Root Cause | Affected Gaps |
|---|---|
| **No fingerprint database** — OS matching uses a 5-entry lookup table instead of a signature DB | GAP-01, GAP-02 |
| **Single-shot Scapy `sr()` call** — multi-probe per host requires a stateful per-host probe scheduler | GAP-01, GAP-03 |
| **UDP uses OS raw sockets (`socket.SOCK_DGRAM`)** — ICMP Unreachable replies are IP-layer events invisible to `recvfrom()` | GAP-02 |
| **TCP state not tracked** — all errors folded into a single `except Exception: pass` | GAP-04 |
| **No probe database** — version detection is hand-coded, not data-driven | GAP-05 |
| **Static plugin registry** — plugins are imported unconditionally, not selected by open ports | GAP-06 |
| **No protocol-specific active probes** — SNMP OID walk, LDAP bind, NetBIOS frames not implemented | GAP-07, GAP-08, GAP-09 |
| **No raw-packet evasion crafting** — only `fragment()` is used; TCP flag manipulation not attempted | GAP-03, GAP-10 |
| **OUI lookup result not classified** — vendor string is stored but not mapped to device category | GAP-07 |

---

## 5. Impact Analysis

### 5.1 Accuracy

| Metric | Impact |
|---|---|
| **OS detection accuracy** | Low-Medium. TTL alone misidentifies macOS, FreeBSD, and modern Linux (all share TTL=64). A hardened Windows host with non-default TTL is undetectable. Estimated accuracy: ~50–60% vs Nmap's ~85–90% (with full probe suite). |
| **Port state accuracy** | Missing `filtered` state means hosts behind firewalls appear to have fewer open ports than they do — producing false negatives. |
| **Service version accuracy** | Covers the top ~15 common services well. Anything outside that set returns an empty version string, degrading CVE matching quality. |

### 5.2 Detection Capability

| Scenario | Current Behaviour |
|---|---|
| **Host behind ICMP-blocking firewall** | Correctly falls back to TCP connect (good). |
| **ICS/SCADA device** | Port flagged in risk DB, but no Modbus/S7 protocol probe → no device type, no version. |
| **UDP-only services (TFTP, NetBIOS)** | Missed entirely. |
| **Network switch with SNMP** | `sysDescr` captured if community is `public`; no bridge/routing MIB walked. |
| **Stealth host (all TCP filtered)** | No packet-response available → appears inactive even if sending ACK RSTs. |

### 5.3 Real-World Usability

- **Enterprise network audit:** Missing device classification, LDAP enumeration, and NetBIOS means Active Directory topology is invisible.
- **Security compliance review:** No zone-transfer test, no Heartbleed active probe, no EternalBlue-level confirmation — finding is "port 445 open" rather than "SMBv1 confirmed + MS17-010 exploitable."
- **IoT / OT environments:** No Modbus, DNP3, BACnet active protocol interrogation.

### 5.4 Network Visibility

The scanner provides **good width** (discovers most active hosts, covers ~165 TCP ports, 7 UDP services) but **limited depth** (cannot characterise device roles or confirm vulnerability exploitability).

---

## 6. Improvement Roadmap (Scapy-based, no Nmap)

### Priority 1 — High Impact, Low Effort

#### A. TCP RST / Filtered State Detection
```python
# In _scapy_syn(): check TCP flags on response
for snd, rcv in ans:
    if rcv.haslayer(TCP):
        flags = rcv[TCP].flags
        if flags & 0x12:  # SYN-ACK → open
            mark_open(rcv[IP].src, rcv[TCP].sport)
        elif flags & 0x04:  # RST → closed (NOT filtered)
            mark_closed(rcv[IP].src, rcv[TCP].sport)
    elif rcv.haslayer(ICMP):
        if rcv[ICMP].type == 3:  # Destination Unreachable → filtered
            mark_filtered(rcv[IP].src)
# unanswered pkts in `unans` → filtered (no reply at all)
for snd in unans:
    mark_filtered(snd[IP].dst)
```

#### B. UDP ICMP-Unreachable Detection (via Scapy)
```python
# Replace socket.SOCK_DGRAM path with Scapy sr() for UDP
pkts = [IP(dst=ip)/UDP(dport=port)/payload for ip, port, payload in probes]
ans, unans = sr(pkts, timeout=2, verbose=0, multi=True)
for snd, rcv in ans:
    if rcv.haslayer(ICMP) and rcv[ICMP].type == 3:
        code = rcv[ICMP].code
        # code 3 = port unreachable → CLOSED
        # code 1,2,9,10,13 → filtered
    elif rcv.haslayer(UDP):
        # Got a UDP reply → service is open and responded
```

#### C. OUI → Device Category Mapping
```python
VENDOR_DEVICE_MAP = {
    # (substring in vendor name) → device_category
    "cisco":      "network_switch_router",
    "juniper":    "network_router_firewall",
    "ubiquiti":   "wireless_access_point",
    "mikrotik":   "network_router",
    "fortinet":   "firewall",
    "palo alto":  "firewall",
    "aruba":      "wireless_access_point",
    "brother":    "printer",
    "canon":      "printer",
    "epson":      "printer",
    "hp":         "printer_or_server",
    "raspberry":  "iot_device",
    "espressif":  "iot_device",
}
def classify_from_oui(vendor: str) -> str:
    v = vendor.lower()
    for kw, cat in VENDOR_DEVICE_MAP.items():
        if kw in v:
            return cat
    return "unknown"
```

---

### Priority 2 — Medium Impact

#### D. Expanded OS Fingerprint Table + TCP Options
```python
from scapy.all import IP, TCP, sr

def os_probe_full(ip: str) -> dict:
    """Sends a crafted SYN with TCP options to read MSS, WScale, SACK, TS."""
    pkt = IP(dst=ip)/TCP(
        dport=80, flags="S",
        options=[("MSS", 1460), ("NOP", None), ("WScale", 6),
                 ("NOP", None), ("NOP", None), ("SAckOK", ""),
                 ("Timestamp", (0, 0)), ("EOL", None)]
    )
    ans, _ = sr(pkt, timeout=2, verbose=0)
    for snd, rcv in ans:
        if not rcv.haslayer(TCP):
            continue
        opts = dict(rcv[TCP].options)
        return {
            "ttl":      rcv[IP].ttl,
            "window":   rcv[TCP].window,
            "mss":      opts.get("MSS"),
            "wscale":   opts.get("WScale"),
            "sack_ok":  "SAckOK" in opts,
            "ts_val":   opts.get("Timestamp", (None,))[0],
            "df_bit":   bool(rcv[IP].flags & 0x02),
            "ihl":      rcv[IP].ihl,
        }
    return {}
```

Use `mss` + `wscale` + `sack_ok` as additional discriminators in `fingerprint_os()`.

#### E. SNMP OID Walk for Device Classification
```python
from scapy.all import IP, UDP, SNMP, SNMPget, SNMPvarbind, ASN1_OID, sr1

DEVICE_OIDS = {
    "ip_forwarding": "1.3.6.1.2.1.4.1.0",   # 1=router, 2=host
    "sys_obj_id":    "1.3.6.1.2.1.1.2.0",   # enterprise OID
    "bridge_mib":    "1.3.6.1.2.1.17.1.1.0", # bridgeBaseDotPort (switch)
}

def snmp_classify(ip: str, community: str = "public") -> str:
    for name, oid in DEVICE_OIDS.items():
        pkt = IP(dst=ip)/UDP(dport=161)/SNMP(
            community=community,
            PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))])
        )
        resp = sr1(pkt, timeout=2, verbose=0)
        if resp and resp.haslayer(SNMP):
            val = str(resp[SNMP].PDU.varbindlist[0].value)
            if name == "ip_forwarding" and val == "1":
                return "router"
            if name == "bridge_mib":
                return "switch"
    return "unknown"
```

#### F. mDNS Hostname Resolution
```python
from scapy.all import IP, UDP, DNS, DNSQR, sr1

def mdns_query(ip: str) -> dict:
    """Query mDNS for device info — reveals device name and service type."""
    pkt = IP(dst="224.0.0.251")/UDP(dport=5353)/DNS(
        rd=0, qd=DNSQR(qname="_services._dns-sd._udp.local", qtype="PTR")
    )
    # For unicast: send to host IP directly
    pkt_uni = IP(dst=ip)/UDP(dport=5353)/DNS(
        rd=0, qd=DNSQR(qname=f"{ip.replace('.', '-')}.in-addr.arpa.local", qtype="PTR")
    )
    resp = sr1(pkt_uni, timeout=1, verbose=0)
    if resp and resp.haslayer(DNS):
        return {"mdns_name": str(resp[DNS].an.rrname), "services": []}
    return {}
```

#### G. NetBIOS Name Table Lookup
```python
import socket, struct

def netbios_query(ip: str) -> dict:
    """Send NetBIOS node status request — returns computer name + workgroup."""
    payload = (
        b"\xa2\x48\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(payload, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        num_names = data[56]
        names = []
        for i in range(num_names):
            offset = 57 + i * 18
            name = data[offset:offset+15].decode("ascii", errors="ignore").strip()
            flags = struct.unpack(">H", data[offset+16:offset+18])[0]
            names.append({"name": name, "flags": flags})
        return {"netbios_names": names}
    except Exception:
        return {}
```

---

### Priority 3 — Advanced (Closes Major Gaps)

#### H. Multi-Probe OS Fingerprinting Engine
Implement a simplified version of Nmap's probe set:
1. **T1** — Standard SYN with options (MSS, WScale, SACK, TS)
2. **T2** — SYN with no options, DF bit set
3. **T3** — SYN+FIN+URG+PSH (abnormal flags)
4. **T4** — ACK with DF bit to open port
5. **U1** — UDP to closed port (triggers ICMP unreachable)
6. **IE1/IE2** — ICMP echo with custom code/TOS

Responses feed a scoring function across these dimensions:
- `ISN` sequence class (random/time-based/constant/zero)
- `DF_bit` in response
- `ICMP response TTL` vs IP TTL
- Presence and order of TCP option types

A small JSON signature database (200–500 entries) covers 80%+ of real-world OS types.

#### I. Service Probe Database (CSV/JSON driven)
Replace hand-coded probes with a data file modelled after `nmap-service-probes`:
```
Probe TCP NULL q||
match ssh m|^SSH-([\d.]+)-(.+)$| v/$2/ d/SSH protocol $1/
match http m|^HTTP/[\d.]+ \d+| d/HTTP server/
match ftp m|^220[ -](.+)$| v/$1/
...
```

#### J. Adaptive Timing Engine
```python
class AdaptiveTimer:
    def __init__(self):
        self.rtt_samples = []
    
    def record_rtt(self, ms: float):
        self.rtt_samples.append(ms)
        if len(self.rtt_samples) > 20:
            self.rtt_samples.pop(0)
    
    @property
    def timeout(self) -> float:
        if not self.rtt_samples:
            return 1.0
        avg = sum(self.rtt_samples) / len(self.rtt_samples)
        return max(0.5, min(avg * 3 / 1000, 5.0))  # 3× RTT, clamped
    
    @property
    def send_delay(self) -> float:
        """Delay between probes to avoid IDS/firewall rate-limiting."""
        return max(0.05, self.timeout / 10)
```

---

## 7. Final Verdict

### Rating: **Intermediate** (≈ 55/100 vs Nmap as 100)

```
                  CCure-Audit-PRO  |  Nmap
------------------------------------|------------------------------------
Host Discovery           ██████████ 90%  | ██████████ 100%
TCP Port Scanning        ████████░░ 75%  | ██████████ 100%
UDP Port Scanning        ██░░░░░░░░ 20%  | ██████████ 100%
OS Fingerprinting        ███░░░░░░░ 30%  | █████████░  90%
Service/Version          ████░░░░░░ 40%  | █████████░  95%
Stealth / Evasion        █░░░░░░░░░ 10%  | █████████░  90%
Device Classification    ██░░░░░░░░ 20%  | ████████░░  80%
CVE / Vuln Correlation   ██████░░░░ 65%  | ████████░░  80%
Scripting / Extensions   ██░░░░░░░░ 20%  | ██████████ 100%
Protocol Enumeration     ███░░░░░░░ 30%  | █████████░  90%
```

### Justification

**Strengths above a basic scanner:**
- ARP+ICMP+SYN+TCP-Connect multi-method adaptive discovery is solid.
- Banner grabbing covers the top 15 services with protocol-correct probes.
- OUI/MAC vendor lookup with a 6.4 MB local database is a genuine asset.
- CVE correlation via SQLite NVD + TLS/HTTP/SMB/SNMP plugins is functional.
- Rate limiter and privilege-aware graceful degradation are production-grade.

**Fundamental shortcomings vs Nmap:**
- OS detection accuracy is **critically limited** by a tiny lookup table — a 5-probe test with 200 signatures would be 3× more accurate.
- UDP coverage is effectively **near-zero** beyond 7 named ports.
- **No port-state classification** (open/closed/filtered) limits actionability.
- **No active device-classification protocol probes** (SNMP walk, LLDP, CDP, NetBIOS).
- The plugin system is **static** (9 fixed plugins), not adaptive to discovered services the way NSE is.

> **Conclusion:** CCure-Audit-PRO is a capable first-pass discovery and risk-flagging tool. Against Nmap it is in the same category as tools like `masscan` + manual banner grabbing — excellent breadth, limited depth. Implementing Priorities 1 and 2 from the roadmap above would move the rating to **Advanced (75/100)** without any architectural changes, purely by extending existing Scapy-based code paths.
