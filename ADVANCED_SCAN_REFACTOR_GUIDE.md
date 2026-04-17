# Advanced Scan Module: Unified Asset Correlation Engine

**Problem Statement:** Advanced Scan showed inconsistent data across phases:
- ✅ Phase 1 (Discovery): Vendor details correct
- ❌ Phase 2 (Port Scan): Vendor details missing
- ✅ Phase 3 (Vulnerability): OS details correct

**Root Cause:** Each phase worked in isolation, overwriting or losing data from previous phases.

---

## Architecture: Before vs. After

### ❌ BEFORE: Isolated Phase Architecture

```
Phase 1 (Discovery)           Phase 2 (Port Scan)           Phase 3 (Vulnerability)
┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
│ Input: IPs       │         │ Input: Hosts     │         │ Input: Hosts     │
│                  │         │ (from Phase 1)   │         │ (from Phase 2)   │
│ Process:         │         │                  │         │                  │
│ - ARP scan       │─────→   │ Process:         │────→   │ Process:         │
│ - Vendor lookup  │         │ - Nmap scan      │         │ - CVE matching   │
│                  │         │ - OS detection   │         │ - Risk scoring   │
│ Output:          │         │                  │         │                  │
│ - IP ✅          │         │ Output:          │         │ Output:          │
│ - Vendor ✅      │         │ - IP ✅          │         │ - IP ✅          │
│ - MAC ✅         │         │ - Ports ✅       │         │ - CVEs ✅        │
│ - MAC ✅         │         │ - Services ✅    │         │ - Risk Score ✅  │
│                  │         │ - Vendor ❌ LOST │         │ - OS ✅          │
│                  │         │ - OS 🟡 Partial  │         │ - Vendor ❌      │
└──────────────────┘         └──────────────────┘         └──────────────────┘
   Each phase returns            Independent dict           Independent dict
   its own dict structure        (vendor not copied)        (vendor still lost)
```

**Issue:** Port Scan receives host dict from Phase 1 with vendor, but when PortEngine updates the dict with Nmap results, vendor field is not preserved (or PortEngine doesn't know about it).

---

### ✅ AFTER: Unified Asset Correlation Engine

```
Phase 1 (Discovery)           Asset Registry              Phase 2 (Port Scan)
┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
│ Input: IPs       │         │ UnifiedAsset     │         │ Input: Hosts     │
│                  │         │ ┌──────────────┐ │         │ (from Phase 1)   │
│ Process:         │         │ │ IP           │ │         │                  │
│ - Discover hosts │─────→   │ │ Vendor ✅    │ │◄────┐   │ Process:         │
│ - Vendor lookup  │ register │ │ MAC ✅       │ │     │   │ - Nmap scan      │
│                  │ phase 1  │ │ Hostname ✅  │ │     │   │ - Read vendor    │
│ Output:          │         │ │ OS 🟡 Partial│ │     │   │ - Preserve ✅    │
│ - IP ✅          │         │ │ Ports []     │ │     │   │                  │
│ - Vendor ✅      │         │ │ CVEs []      │ │     │   │ Output:          │
│ - MAC ✅         │         │ │ Risk: -      │ │     │   │ - IP ✅          │
│                  │         │ │ Phase: [1]   │ │     │   │ - Ports ✅       │
│                  │         │ └──────────────┘ │     │   │ - Vendor ✅ PRESERVED
│                  │         │                  │     │   │ - Services ✅    │
│                  │         │ enrich_port      │─────┤   │ - OS 🟡 Nmap     │
│                  │         │ scan_results()   │         │                  │
│                  │         │                  │         │ Update registry  │
│                  │         │ ┌──────────────┐ │         │ with port data   │
│                  │         │ │ IP           │ │         └──────────────────┘
│                  │         │ │ Vendor ✅    │◄────────────────┐
│                  │         │ │ MAC ✅       │ │                  Phase 3
│                  │         │ │ Hostname ✅  │ │         ┌──────────────────┐
│                  │         │ │ OS 🟡 Nmap   │ │         │ Input: Hosts     │
│                  │         │ │ Ports ✅     │ │         │                  │
│                  │         │ │ CVEs []      │ │         │ Process:         │
│                  │         │ │ Risk: -      │ │         │ - CVE matching   │
│                  │         │ │ Phase: [1,2] │ │         │ - Risk scoring   │
│                  │         │ └──────────────┘ │         │ - Enrich OS      │
│                  │         │                  │◄────────│                  │
│                  │         │ enrich_vuln      │─────┐   │ Output:          │
│                  │         │ findings()       │     │   │ - IP ✅          │
│                  │         │                  │     │   │ - Vendor ✅      │
│                  │         │ ┌──────────────┐ │     │   │ - Ports ✅       │
│                  │         │ │ IP           │ │     │   │ - OS ✅          │
│                  │         │ │ Vendor ✅    │ │     │   │ - CVEs ✅        │
│                  │         │ │ MAC ✅       │◄─────┘   │ - Risk ✅        │
│                  │         │ │ Hostname ✅  │ │         │ - Vendor ✅      │
│                  │         │ │ OS ✅        │ │         └──────────────────┘
│                  │         │ │ Ports ✅     │ │
│                  │         │ │ CVEs ✅      │ │         UNIFIED ✅
│                  │         │ │ Risk: ✅     │ │         ALL DATA CONSISTENT
│                  │         │ │ Phase: [1,2,3]         
│                  │         │ └──────────────┘ │
│                  │         │ All phases      │
│                  │         │ consistently    │
│                  │         │ merged & preserved
│                  │         └──────────────────┘
```

---

## Solution: Unified Asset Model

### Data Structure

```python
UnifiedAsset {
  # ── Immutable Discovery Data ──────────────────────────────────────────
  ip_address: str              # Primary key
  hostname: str
  mac_address: str
  is_active: bool
  discovery_timestamp: str
  discovery_method: str        # ICMP, ARP, TCP, etc.
  discovery_profile: str       # FAST, BALANCED, AGGRESSIVE
  
  # ── Vendor (from Phase 1, preserved through all phases) ──────────────
  vendor: VendorInfo {
    name: str                  # "HP Inc.", "Unknown"
    mac_address: str
    confidence: ConfidenceScore {
      score: 0.95              # 0.0-1.0
      source: "mac_oui"        # MAC → OUI database lookup
      timestamp: str
      notes: str
    }
  }
  
  # ── OS Detection (multi-source, confidence-aware) ──────────────────
  os: OSInfo {
    name: str                  # "Linux 4.15-4.19", "Windows 10"
    confidence: str            # Low / Medium / High
    cpe: str                   # CPE identifier
    primary_source: str        # nmap_os / cve_inference / ttl_heuristic
    secondary_sources: List    # [cve_inference, banner_grab]
    detection_methods: List    # [nmap_fingerprinting, cve_matching]
  }
  
  # ── Ports & Services ────────────────────────────────────────────────
  open_ports: List[Dict]       # From Nmap
  services_detected: List      # Service + Version from Nmap -sV
  udp_services: List           # UDP service discovery
  
  # ── Security Findings ───────────────────────────────────────────────
  cves: List[Dict]             # CVE data with severity
  tls_info: Dict               # SSL/TLS certificate info
  http_audit: Dict             # Security headers, etc.
  ssh_info: Dict               # SSH algorithm analysis
  smb_info: Dict               # SMB protocol info
  
  # ── Risk Scoring ────────────────────────────────────────────────────
  host_risk_score: float       # 0.0-100.0
  host_risk_level: str         # Critical / High / Medium / Low / Info
  
  # ── Device Classification ───────────────────────────────────────────
  device_category: str         # printer / server / workstation / iot
  device_confidence: str
  snmp_device_type: str
  
  # ── Audit Trail ─────────────────────────────────────────────────────
  scan_phases_completed: [1, 2, 3]      # Which phases ran
  last_updated: str
  data_sources: List[str]     # ["phase1_discovery", "phase2_port_scan", "phase3_vulnerability"]
}
```

---

## Integration Flow

### Phase 1: Discovery Registration

```python
# In run_host_discovery_only()
discovery_results = await discovery.run(all_ips)
formatted = [_format_host(ip, r).to_phase1_dict() for r in discovery_results]

# ✅ NEW: Register in unified asset registry
asset_engine.register_discovery_results(
    formatted,
    discovery_method="adaptive",
    discovery_profile="AGGRESSIVE"
)

# Output: Asset registry now has IP → UnifiedAsset mapping
#   vendor ✅ populated from MAC → OUI lookup
#   os 🟡 not available yet (will be filled by Phase 2)
#   ports [] empty (will be filled by Phase 2)
```

### Phase 2: Port Scan Enrichment

```python
# In run_asset_discovery_only()
port_engine = PortEngine(intensity=intensity_enum)
await port_engine.run(active_hosts)  # Nmap scanning
self._apply_os_inference(active_hosts)

# ✅ NEW: Preserve vendor from registry + enrich
_preserve_vendor_from_registry(active_hosts)
asset_engine.enrich_port_scan_results(active_hosts)

# What happens inside _preserve_vendor_from_registry():
# for each host:
#   asset = asset_engine.get_asset(host["ip"])
#   if asset and asset.vendor.name != "Unknown":
#     host["vendor"] = asset.vendor.name  # ✅ RESTORE from Phase 1
#     host["mac_address"] = asset.vendor.mac_address

# What happens inside enrich_port_scan_results():
# - Merges open_ports from Nmap
# - Adds OS detection from Nmap -O if available
# - Preserves vendor already in the asset
# - Adds phase 2 to completed phases list
```

### Phase 3: Vulnerability Enrichment

```python
# In run_advanced_scan_only()
vuln_engine = VulnerabilityEngine(rate_limit=self.rate_limit)
vuln_engine.run(active_hosts)

# ✅ NEW: Enrich asset registry with vulnerability findings
asset_engine.enrich_vulnerability_findings(active_hosts)

# What happens inside enrich_vulnerability_findings():
# - Adds CVE data, TLS info, HTTP audit, SSH info, etc.
# - Refines OS detection (merge with Nmap + CVE inferences)
# - Adds risk score + device classification
# - Marks phases [1, 2, 3] as completed
# - Vendor data preserved from previous phases ✅
```

---

## Data Flow Diagram (Complete Advanced Scan)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ADVANCED SCAN PIPELINE                            │
└─────────────────────────────────────────────────────────────────────────────┘

   PHASE 1: DISCOVERY                     PHASE 2: PORT SCAN              PHASE 3: VULNERABILITY
   ┌─────────────────────────┐           ┌─────────────────────┐         ┌─────────────────────┐
   │                         │           │                     │         │                     │
   │ Input: 10.180.6.45      │           │ Input: Phase1 Result           │ Input: Phase2 Result
   │                         │           │                     │         │                     │
   │ Process:                │           │ Process:            │         │ Process:            │
   │ - ICMP ping             │           │ - Nmap -sS          │         │ - CVE matching      │
   │ - ARP request           │           │ - Nmap -sV          │         │ - TLS fingerprint   │
   │ - MAC lookup            │           │ - OS fingerprint    │         │ - HTTP audit        │
   │                         │           │ - Service detection │         │ - Risk scoring      │
   │ Output:                 │           │                     │         │                     │
   │ {                       │           │ Output:             │         │ Output:             │
   │   ip: 10.180.6.45 ✅    │           │ {                   │         │ {                   │
   │   hostname: ...   ✅    │           │   ip: ...  ✅       │         │   ip: ...  ✅       │
   │   mac: 2c58... ✅       │           │   ports: [ ✅       │         │   cves: [ ✅        │
   │   vendor: HP Inc ✅     │────┐      │     22, 80, 443     │         │     CVE-2021-...,   │
   │   is_active: true ✅    │    │      │   ]                 │         │     CVE-2022-...    │
   │   discovery_method: ... │    │      │   services: [ ✅    │         │   ]                 │
   │ }                       │    │      │     ssh, http, ...  │         │   vendor: HP Inc ✅ │
   │                         │    │      │   ]                 │         │   os: Linux ✅      │
   │ Register in Registry:   │    │      │   os: Linux ✅      │         │   ports: [list] ✅  │
   │ ┌─────────────────────┐ │    │      │ }                   │         │   risk_score: 78.5  │
   │ │ UnifiedAsset        │ │    │      │                     │         │   risk_level: High  │
   │ │ ─────────────────   │ │    │      │ Registry enrich:    │         │ }                   │
   │ │ ip: 10.180.6.45     │ │    ├─────→ Preserve vendor  ✅ │         │                     │
   │ │ hostname: ...       │ │    │      │ Add ports       ✅ │         │ Registry final:     │
   │ │ mac: 2c58...        │ │    │      │ Add OS          ✅ │───┐     │ ┌─────────────────┐ │
   │ │ vendor: HP Inc ✅   │ │    │      │ Mark phases: [1,2]  │   │     │ │ UnifiedAsset    │ │
   │ │ os: Unknown 🟡      │ │    │      │                     │   │     │ │ ─────────────────│ │
   │ │ ports: []           │ │    │      │ ┌─────────────────┐ │   │     │ │ ip: 10.180.6.45 │ │
   │ │ phases: [1]         │ │    │      │ │ UnifiedAsset    │ │   │     │ │ hostname: ...   │ │
   │ │ ─────────────────   │ │    │      │ │ ─────────────────│ │   │     │ │ mac: 2c58...    │ │
   │ │ [Immutable]         │ │    │      │ │ ip: 10.180.6.45 │ │   ├────→ │ │ vendor: HP Inc ✅
   │ │ [Enriched]          │ │    │      │ │ vendor: HP ✅ ✅│ │   │     │ │ os: Linux ✅    │ │
   │ └─────────────────────┘ │    │      │ │ mac: 2c58... ✅ │ │   │     │ │ ports: [22,80..│ │
   │                         │    │      │ │ hostname: ... ✅│ │   │     │ │ os: Linux ✅    │ │
   └─────────────────────────┘    │      │ │ os: Linux ✅ ✅ │ │   │     │ │ cves: [CVE-..   │ │
                                  │      │ │ ports: [22,80..│ │   │     │ │ risk_score: 78.5│
                                  │      │ │ phases: [1, 2] │ │   │     │ │ risk_level: High│
                                  │      │ │ ─────────────────│ │   │     │ │ phases: [1,2,3] │
                                  │      │ │ [CONSISTENT!] ✅│ │   │     │ │ ─────────────────│
                                  │      │ └─────────────────┘ │   │     │ │ [FULLY UNIFIED] │
                                  │      │                     │   │     │ │      ✅✅✅      │
                                  │      └─────────────────────┘   │     │ └─────────────────┘
                                  │                                 │     │                     │
                                  └─────────────────────────────────┘     └─────────────────────┘

FINAL OUTPUT: export_all() → [UnifiedAsset.to_dict()]
```

---

## Production-Grade JSON Output (Nessus-Compatible)

```json
{
  "ip_address": "10.180.6.45",
  "hostname": "atharv-desktop.blr.cdac.in",
  "mac_address": "2c:58:b9:87:0b:b3",
  "is_active": true,
  "discovery": {
    "timestamp": "2026-04-17T15:34:58.123456",
    "method": "ICMP",
    "profile": "AGGRESSIVE"
  },
  
  "vendor": {
    "name": "HP Inc.",
    "mac_address": "2c:58:b9:87:0b:b3",
    "confidence": {
      "confidence_score": 0.95,
      "source": "mac_oui",
      "timestamp": "2026-04-17T15:34:58.123456",
      "notes": "From MAC address OUI database lookup"
    },
    "fallback_used": false,
    "strategies_tried": ["mac_oui_lookup"]
  },
  
  "os": {
    "name": "Linux 4.15-4.19",
    "confidence": "High",
    "cpe": "cpe:/o:linux:linux_kernel:4.15",
    "version": "4.15-4.19",
    "primary_source": "nmap_os",
    "secondary_sources": ["cve_inference", "banner_grab"],
    "detection_methods": ["nmap_fingerprinting", "cve_matching", "service_banner"]
  },
  
  "open_ports": [
    {
      "port": 22,
      "service": "ssh",
      "state": "open",
      "banner": "OpenSSH 7.6p1 Ubuntu 4ubuntu0.7",
      "version": "OpenSSH 7.6p1 Ubuntu",
      "risk": "Medium",
      "cves": [
        {
          "id": "CVE-2021-41617",
          "severity": "Critical",
          "score": 9.1
        }
      ]
    },
    {
      "port": 443,
      "service": "https",
      "state": "open",
      "banner": "Apache/2.4.29",
      "version": "Apache 2.4.29",
      "risk": "High",
      "cves": [
        {
          "id": "CVE-2021-44228",
          "severity": "Critical",
          "score": 10.0
        }
      ]
    },
    {
      "port": 3306,
      "service": "mysql",
      "state": "open",
      "banner": "MySQL 5.7.30",
      "version": "MySQL 5.7.30",
      "risk": "High",
      "cves": []
    }
  ],
  
  "services": [
    {
      "port": 22,
      "service": "ssh",
      "product": "OpenSSH",
      "version": "7.6p1",
      "extra": "Ubuntu"
    }
  ],
  
  "udp_services": [
    {
      "port": 53,
      "service": "dns",
      "state": "open"
    }
  ],
  
  "security": {
    "cves_count": 18,
    "cves": [
      {
        "id": "CVE-2021-41617",
        "severity": "Critical",
        "score": 9.1,
        "source_port": 22,
        "description": "OpenSSH remote code execution vulnerability"
      },
      {
        "id": "CVE-2021-44228",
        "severity": "Critical",
        "score": 10.0,
        "source_port": 443,
        "description": "Apache Log4Shell vulnerability"
      }
    ],
    "tls_info": {
      "enabled": true,
      "version": "TLSv1.2",
      "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
      "cert_subject": "CN=atharv-desktop.blr.cdac.in",
      "cert_issuer": "CN=Self-Signed",
      "cert_expired": false,
      "weak_cipher": false,
      "score": "A-"
    },
    "http_audit": {
      "status_code": 200,
      "server_header": "Apache/2.4.29",
      "hsts": false,
      "x_frame": "SAMEORIGIN",
      "csp": true,
      "x_content_type": true,
      "x_xss": true,
      "issues": [
        "HSTS header not set",
        "Server version exposed"
      ]
    },
    "ssh_info": {
      "version": "OpenSSH 7.6p1",
      "algorithms": {
        "key_exchange": ["diffie-hellman-group14-sha1"],
        "encryption": ["aes256-ctr", "aes128-ctr"],
        "mac": ["hmac-sha2-256"]
      },
      "weak_algorithms": [
        "diffie-hellman-group14-sha1 (weak)"
      ]
    },
    "smb_info": {
      "enabled": false
    }
  },
  
  "risk": {
    "score": 78.5,
    "level": "High"
  },
  
  "device": {
    "category": "Server",
    "confidence": "High",
    "snmp_type": "Linux Device"
  },
  
  "metadata": {
    "phases_completed": [1, 2, 3],
    "last_updated": "2026-04-17T15:36:50.987654",
    "data_sources": [
      "phase1_discovery",
      "phase2_port_scan",
      "phase3_vulnerability"
    ]
  }
}
```

---

## Key Improvements

### 1. **Vendor Data Preservation** ✅
- Phase 1: Vendor populated from MAC → OUI lookup
- Phase 2: Vendor PRESERVED from asset registry
- Phase 3: Vendor carried through vulnerability scan
- **Result:** Consistent vendor info across ALL phases

### 2. **Multi-Source OS Detection** ✅
- Primary source tracked (Nmap, CVE inference, etc.)
- Secondary sources tracked
- Detection methods documented
- Confidence scoring implemented

### 3. **Fallback Strategies** ✅
```python
# Vendor detection fallback chain:
1. MAC → OUI database (95% confidence)
2. SNMP sysDescr (85% confidence)
3. Service banner (70% confidence)
4. TTL heuristics (50% confidence)
5. Device classification (40% confidence)
6. Default: "Unknown"
```

### 4. **Data Consistency Rules** ✅
- Immutable discovery data (never overwritten)
- Enrichment layers (merge, don't replace)
- Confidence tracking (source + score)
- Audit trail (data_sources list)

### 5. **Nessus-Compatible Export** ✅
- Production-grade JSON format
- Security info consolidated
- Risk scoring integrated
- Device classification included

---

## Usage Examples

### Export Unified Results

```python
from orchestrator.scan_orchestrator import ScanOrchestrator

orch = ScanOrchestrator()

# ... run full advanced scan phases ...

# Export unified assets
unified_hosts = orch.asset_engine.export_all()

# Returns list of UnifiedAsset.to_dict() — production-ready JSON
for host in unified_hosts:
    print(f"IP: {host['ip_address']}")
    print(f"Vendor: {host['vendor']['name']}")      # ✅ Present!
    print(f"OS: {host['os']['name']}")              # ✅ Present!
    print(f"Ports: {len(host['open_ports'])}")      # ✅ Present!
    print(f"CVEs: {len(host['security']['cves'])}") # ✅ Present!
```

### Query Specific Asset

```python
# Get unified asset for specific IP
asset = orch.asset_engine.get_asset("10.180.6.45")

if asset:
    print(f"Vendor: {asset.vendor.name}")
    print(f"Confidence: {asset.vendor.confidence.score}")
    print(f"Detection Method: {asset.vendor.confidence.source.value}")
    print(f"Completed Phases: {asset.scan_phases_completed}")
```

### Statistics

```python
stats = orch.asset_engine.get_stats()

print(f"Total assets: {stats['total_assets']}")
print(f"Active hosts: {stats['active_hosts']}")
print(f"With vendor info: {stats['with_vendor_info']}")
print(f"With OS detection: {stats['with_os_detection']}")
print(f"With vulnerabilities: {stats['with_cves']}")
```

---

## Summary

| Aspect | Before | After |
|--------|--------|-------|
| **Vendor in Phase 2** | ❌ Lost | ✅ Preserved |
| **Vendor in Phase 3** | ❌ Missing | ✅ Present |
| **OS Consistency** | 🟡 Partial | ✅ Complete |
| **Data Overwrite** | ❌ Happens | ✅ Prevented |
| **Audit Trail** | ❌ None | ✅ Full |
| **Confidence Scoring** | ❌ Not tracked | ✅ Tracked |
| **Nessus Compatibility** | ❌ No | ✅ Yes |

The Advanced Scan module now behaves like a **production-grade scanner** (Nessus/Nmap level) with unified asset correlation! 🎉
