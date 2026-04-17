# Scan Flow Analysis: Frontend → Backend → Profiles

## Executive Summary

When you initiate a scan from the frontend, it flows through the following:
1. **Frontend selects a scan card** → sets `pipelineMode`
2. **API call includes `pipeline_mode` parameter** → determines phases to execute
3. **Orchestrator maps `pipeline_mode` to discovery profile** → controls techniques used

---

## 1. FRONTEND SCAN TYPES → PIPELINE MODES

### Dashboard Scan Selection (src/pages/Dashboard.jsx)

The user selects one of three main scan templates:

| Scan Template | Frontend ID | pipelineMode | Description |
|---|---|---|---|
| **Basic Network Scan** | "basic" | `"basic"` | Identifies live hosts only |
| **Asset Discovery** | "asset" | `"asset"` | Finds live hosts + discovers open ports |
| **Advanced Scan** | "advanced" | `"advanced"` | Full pipeline: hosts + ports + vulnerabilities + risk scoring |

```javascript
// Dashboard.jsx - Scan Cards
const TEMPLATES = [
  {
    id: "basic",
    title: "Basic Network Scan",
    pipelineMode: "basic",  // ← Sets pipelineMode in context
  },
  {
    id: "asset",
    title: "Asset Discovery",
    pipelineMode: "asset",  // ← Sets pipelineMode in context
  },
  {
    id: "advanced",
    title: "Advanced Scan",
    pipelineMode: "advanced",  // ← Sets pipelineMode in context
  },
];

const handleCard = (tpl) => {
  resetScan();
  setPipelineMode(tpl.pipelineMode);  // ← Context state
  navigate(pipeline.entryRoute);        // Always goes to /scan
};
```

**Flow:**
1. User clicks a scan card → `handleCard()` called
2. `setPipelineMode()` stores the mode in ScanContext
3. Navigate to `/scan` (NewScan page)

---

## 2. FRONTEND → BACKEND: PHASE PIPELINE

### NewScan.jsx (src/pages/scan/NewScan.jsx)

When user enters target and clicks Start Scan:

```javascript
const payload = buildPhasePayload(pipelineMode || "basic", {
  targets:   target.split(",").map(t => t.trim()).filter(Boolean),
  scan_type: scanType,
});

// buildPhasePayload() creates:
// "basic"    → { phases: [1],       pipeline_mode: "basic",    targets, scan_type }
// "asset"    → { phases: [1, 2],    pipeline_mode: "asset",    targets, scan_type }
// "advanced" → { phases: [1, 2, 3, 4], pipeline_mode: "advanced", targets, scan_type }

await api.post("/scan/host-discovery", payload);
```

**Payload Structure:**

### Basic Network Scan
```json
{
  "phases": [1],
  "pipeline_mode": "basic",
  "targets": ["192.168.1.0/24"],
  "scan_type": "adaptive"
}
```

### Asset Discovery
```json
{
  "phases": [1, 2],
  "pipeline_mode": "asset",
  "targets": ["192.168.1.0/24"],
  "scan_type": "adaptive"
}
```

### Advanced Scan
```json
{
  "phases": [1, 2, 3, 4],
  "pipeline_mode": "advanced",
  "targets": ["192.168.1.0/24"],
  "scan_type": "adaptive"
}
```

---

## 3. BACKEND ENDPOINTS & PIPELINE MODE RESOLUTION

### Endpoint Flow

| Phase | Frontend Route | API Endpoint | Orchestrator Method | Terminal Phase |
|---|---|---|---|---|
| 1 | `/scan/host-discovery` | `POST /scan/host-discovery` | `run_host_discovery_only()` | Depends on mode |
| 2 | `/scan/asset-discovery` | `POST /scan/asset-discovery` | `run_asset_discovery_only()` | Depends on mode |
| 3 | `/scan/advanced-scan` | `POST /scan/advanced-scan` | `run_advanced_scan_only()` | Phase 3 only for "advanced" |

### Backend Request Models (main.py)

```python
class HostDiscoveryRequest(BaseModel):
    targets:       List[str]
    scan_type:     str = "adaptive"
    pipeline_mode: Optional[str] = "basic"      # ← CRITICAL: tells backend the full pipeline
    phases:        Optional[List[int]] = None

class AssetDiscoveryRequest(BaseModel):
    hosts:         List[dict]
    intensity:     str = "normal"
    scan_id:       Optional[int] = None
    pipeline_mode: Optional[str] = "asset"      # ← CRITICAL: tells backend which phase is terminal

class AdvancedScanRequest(BaseModel):
    hosts:         List[dict]
    scan_id:       Optional[int] = None
    pipeline_mode: Optional[str] = "advanced"   # ← CRITICAL: only "advanced" can call this
```

---

## 4. ORCHESTRATOR → DISCOVERY PROFILES MAPPING

### The Critical Function: `profile_for_pipeline()` 
**(core/discovery/profiles.py)**

```python
def profile_for_pipeline(pipeline_mode: str) -> DiscoveryProfile:
    """
    Map a pipeline_mode string (from the API) to a DiscoveryProfile.
    
    "basic"    → FAST       (Host Discovery only)
    "asset"    → BALANCED   (Host Discovery + Asset Discovery)
    "advanced" → AGGRESSIVE (Full pipeline with enrichment)
    """
    mapping = {
        "basic":    FAST,
        "asset":    BALANCED,
        "advanced": AGGRESSIVE,
    }
    return mapping.get(pipeline_mode.lower(), BALANCED)
```

### Orchestrator: run_host_discovery_only()
**(Backend/orchestrator/scan_orchestrator.py, lines 80-140)**

```python
async def run_host_discovery_only(
    self,
    targets: List[str],
    scan_type: str = "adaptive",
    pipeline_mode: str = "basic",  # ← comes from API request
) -> Dict:
    """
    Phase 1 — Host Discovery.
    
    Maps pipeline_mode → DiscoveryProfile
    """
    # Resolve profile from pipeline_mode
    if scan_type == "fast":
        profile = FAST  # Light Mode always forces FAST
    else:
        profile = profile_for_pipeline(pipeline_mode)  # ← THE KEY MAPPING
    
    # Create discovery engine with the chosen profile
    discovery = DiscoveryEngine(
        profile=profile,
        has_privileges=self.has_priv,
        stealth_mode=self.stealth_mode,
    )
    disc_results = await discovery.run(all_ips)
    
    # Return results with profile name in metadata
    return {
        "success": True,
        "data": formatted,
        "summary": {
            "discovery_profile": profile.name,  # ← "FAST", "BALANCED", or "AGGRESSIVE"
            ...
        },
        "metadata": {
            "discovery_profile": profile.name,
            ...
        }
    }
```

---

## 5. DISCOVERY PROFILES: TECHNIQUES & PARAMETERS

### FAST Profile (Basic Network Scan)
**Used by:** `pipeline_mode="basic"`

```python
FAST = DiscoveryProfile(
    name        = "FAST",
    description = "Basic Network Scan — Phase 1 only pipeline.",
    techniques  = [Technique.ARP, Technique.TCP_CONN],  # ← Simple techniques
    timeout     = 0.8,      # ← Very fast
    retries     = 0,        # ← No retries (speed first)
    concurrency = 256,      # ← High parallelism
    enrichment  = False,    # ← Skip SNMP/mDNS/NetBIOS
    stealth_auto = False,
)
```

**Technique Sequence:**
1. **ARP Broadcast** (L2) — LAN only, very fast, no root needed in many cases
2. **TCP Connect** (L4 fallback) — If ARP fails, tries TCP connect on ports 80/443/22

**Characteristics:**
- ✅ Fastest: ~0.8s timeout per probe
- ✅ Minimal retries → quick results
- ✅ No service enrichment (no SNMP/mDNS/NetBIOS)
- ✅ High concurrency (256 parallel streams)
- ⚠️ May miss hosts behind strict firewalls

---

### BALANCED Profile (Asset Discovery)
**Used by:** `pipeline_mode="asset"`

```python
BALANCED = DiscoveryProfile(
    name        = "BALANCED",
    description = "Asset Discovery — Phase 1+2 pipeline.",
    techniques  = [
        Technique.ARP,
        Technique.ICMP,
        Technique.TCP_SYN,     # ← More techniques
        Technique.UDP_PROBE
    ],
    timeout     = 1.5,      # ← Moderate timeout
    retries     = 1,        # ← One retry
    concurrency = 100,      # ← Moderate parallelism
    enrichment  = False,    # ← Enrichment skipped (Phase 2 Nmap does this)
    stealth_auto = False,
)
```

**Technique Sequence:**
1. **ARP Broadcast** (L2) — LAN only
2. **ICMP Echo + Timestamp** (L3) — Cross-LAN, gets TTL for OS hint
3. **TCP SYN** (Raw) — Scapy-based, better accuracy
4. **UDP Probes** (DNS/SNMP/NTP/DHCP) — Service discovery

**Characteristics:**
- ✅ Good balance: ~1.5s timeout per probe
- ✅ Retry once for failed probes
- ✅ Moderate parallelism (100 streams)
- ✅ Combines L2, L3, L4, UDP techniques
- ✅ Works routed (internet) and LAN
- ⚠️ Slower than FAST but more thorough

---

### AGGRESSIVE Profile (Advanced Scan)
**Used by:** `pipeline_mode="advanced"`

```python
AGGRESSIVE = DiscoveryProfile(
    name        = "AGGRESSIVE",
    description = "Advanced Scan — Full Phase 1+2+3+4 pipeline.",
    techniques  = [
        Technique.ARP,
        Technique.ICMP,
        Technique.TCP_SYN,
        Technique.UDP_PROBE,
        Technique.NBNS,        # ← NetBIOS name resolution added
    ],
    timeout     = 2.0,      # ← Longest timeout
    retries     = 2,        # ← Two retries
    concurrency = 50,       # ← Lower parallelism, more thorough
    enrichment  = True,     # ← SNMP/mDNS/NetBIOS enrichment ON
    stealth_auto = True,    # ← Auto-escalate to stealth if IDS detected
)
```

**Technique Sequence:**
1. **ARP Broadcast** (L2)
2. **ICMP Echo + Timestamp** (L3)
3. **TCP SYN** (Raw, all management ports)
4. **UDP Probes** (full range)
5. **NetBIOS Name Service** (UDP 137, device naming)

**Post-Discovery Enrichment:**
- SNMP community string probing
- mDNS service enumeration
- NetBIOS device classification

**Characteristics:**
- ✅ Most thorough: 2.0s timeout, 2 retries
- ✅ Includes all 5 techniques
- ✅ Enrichment: SNMP + mDNS + NetBIOS
- ✅ Hostile-environment auto-escalation
- ⚠️ Slowest (~2-5x slower than FAST)
- ⚠️ May trigger IDS/IPS alarms

---

## 6. DATA FLOW DIAGRAM

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND (React)                         │
├─────────────────────────────────────────────────────────────────┤
│                     Dashboard.jsx                               │
│  • User selects scan template                                   │
│  • "Basic" → pipelineMode="basic"                               │
│  • "Asset" → pipelineMode="asset"                               │
│  • "Advanced" → pipelineMode="advanced"                         │
│                                                                 │
│            ↓ setPipelineMode() in ScanContext                   │
│                                                                 │
│                     NewScan.jsx                                 │
│  • User enters target (e.g., "192.168.1.0/24")                 │
│  • buildPhasePayload(pipelineMode, { targets, scan_type })     │
│  • Creates payload with phases array + pipeline_mode           │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│                   BACKEND (FastAPI)                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Phase 1: POST /scan/host-discovery                             │
│  ├─ Request: { pipeline_mode: "basic"|"asset"|"advanced",      │
│  │             targets: [...], scan_type: "..." }              │
│  ├─ resolve_pipeline_mode() → "basic"/"asset"/"advanced"       │
│  └─ orch.run_host_discovery_only(targets, scan_type, mode)     │
│                                                                 │
│     Phase 2: POST /scan/asset-discovery                         │
│     ├─ Request: { pipeline_mode: "asset"|"advanced",           │
│     │             hosts: [...], intensity: "..." }             │
│     ├─ Guard: phase 2 must be in pipeline                       │
│     └─ orch.run_asset_discovery_only(hosts, intensity)         │
│                                                                 │
│        Phase 3: POST /scan/advanced-scan                        │
│        ├─ Request: { pipeline_mode: "advanced",                │
│        │             hosts: [...] }                            │
│        ├─ Guard: only "advanced" allowed                        │
│        └─ orch.run_advanced_scan_only(hosts)                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│              ORCHESTRATOR (ScanOrchestrator)                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  run_host_discovery_only()                                      │
│  ├─ profile = profile_for_pipeline(pipeline_mode)              │
│  │  ├─ "basic"    → FAST                                       │
│  │  ├─ "asset"    → BALANCED                                   │
│  │  └─ "advanced" → AGGRESSIVE                                 │
│  │                                                              │
│  └─ DiscoveryEngine(profile=...) → runs discovery              │
│                                                                 │
│  run_asset_discovery_only()                                     │
│  └─ PortEngine() → NmapScanner (internal routing)              │
│                                                                 │
│  run_advanced_scan_only()                                       │
│  ├─ _nmap_pre_enrich() → OS fingerprinting                     │
│  └─ VulnerabilityEngine() → plugin-based scanning              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│          DISCOVERY PROFILES & TECHNIQUES                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  FAST (basic mode)                                              │
│  • Techniques: ARP → TCP Connect                                │
│  • Timeout: 0.8s | Retries: 0 | Concurrency: 256               │
│  • Enrichment: OFF                                              │
│                                                                 │
│  BALANCED (asset mode)                                          │
│  • Techniques: ARP → ICMP → TCP SYN → UDP                       │
│  • Timeout: 1.5s | Retries: 1 | Concurrency: 100               │
│  • Enrichment: OFF (Phase 2 Nmap covers this)                   │
│                                                                 │
│  AGGRESSIVE (advanced mode)                                     │
│  • Techniques: ARP → ICMP → TCP SYN → UDP → NetBIOS             │
│  • Timeout: 2.0s | Retries: 2 | Concurrency: 50                │
│  • Enrichment: ON (SNMP + mDNS + NetBIOS)                       │
│  • Stealth Auto: ON                                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. QUICK REFERENCE TABLE

| Aspect | Basic Network Scan | Asset Discovery | Advanced Scan |
|---|---|---|---|
| **Frontend Template** | "Basic Network Scan" | "Asset Discovery" | "Advanced Scan" |
| **pipelineMode** | `"basic"` | `"asset"` | `"advanced"` |
| **Phases** | [1] | [1, 2] | [1, 2, 3, 4] |
| **Discovery Profile** | **FAST** | **BALANCED** | **AGGRESSIVE** |
| **Techniques** | ARP + TCP | ARP + ICMP + TCP SYN + UDP | ARP + ICMP + TCP SYN + UDP + NetBIOS |
| **Timeout** | 0.8s | 1.5s | 2.0s |
| **Retries** | 0 | 1 | 2 |
| **Concurrency** | 256 | 100 | 50 |
| **Enrichment** | ❌ No | ❌ No | ✅ Yes (SNMP + mDNS + NetBIOS) |
| **Speed** | ⚡ Fastest | 🔶 Moderate | 🐢 Slowest |
| **Accuracy** | 🟡 Good | 🟢 Better | 🟢 Best |

---

## 8. HOW TO TRACE A SCAN REQUEST

### Scenario: User selects "Asset Discovery"

**Step 1: Frontend - Dashboard Selection**
```javascript
// User clicks "Asset Discovery" card
pipelineMode = "asset"
resetScan()
setPipelineMode("asset")  // → stored in ScanContext
navigate("/scan")         // → NewScan.jsx
```

**Step 2: Frontend - NewScan Entry**
```javascript
// User enters target: "192.168.1.0/24"
// User clicks "Start Scan"
const payload = buildPhasePayload("asset", {
  targets: ["192.168.1.0/24"],
  scan_type: "adaptive"
})
// payload = {
//   phases: [1, 2],
//   pipeline_mode: "asset",
//   targets: ["192.168.1.0/24"],
//   scan_type: "adaptive"
// }
api.post("/scan/host-discovery", payload)
```

**Step 3: Backend - Host Discovery Endpoint**
```python
@app.post("/scan/host-discovery")
async def scan_host_discovery(req: HostDiscoveryRequest, ...):
    mode = resolve_pipeline_mode(req.pipeline_mode)  # → "asset"
    orch = _get_api()._orch
    
    result = await orch.run_host_discovery_only(
        req.targets,    # ["192.168.1.0/24"]
        req.scan_type   # "adaptive"
        # pipeline_mode is used internally
    )
```

**Step 4: Orchestrator - Profile Resolution**
```python
async def run_host_discovery_only(self, targets, scan_type, pipeline_mode="basic"):
    # pipeline_mode comes from API (but often inferred from context)
    profile = profile_for_pipeline(pipeline_mode)  # "asset" → BALANCED
    
    discovery = DiscoveryEngine(profile=profile)
    results = await discovery.run(targets)
    
    # Returns with profile name
    return {
        "discovery_profile": "BALANCED",  # ← This tells frontend which profile was used
        ...
    }
```

**Step 5: Discovery Engine - Technique Execution**
```
For each IP in 192.168.1.0/24:
  1. Try ARP broadcast (L2)
  2. If ARP response → mark active, continue to next IP
  3. If no ARP → try ICMP echo (L3)
  4. If no ICMP → try TCP SYN (raw socket)
  5. If no TCP SYN → try UDP probes (DNS/SNMP/NTP)
  6. If any response → mark active
  
Timeout per probe: 1.5s (BALANCED)
Retry failed probes: once (BALANCED)
Parallel streams: 100 (BALANCED)
Enrichment: OFF (Phase 2 Nmap will handle service discovery)
```

**Step 6: Frontend - Next Phase Decision**
```javascript
// User sees Phase 1 results
// Click "Next Phase" (Asset Discovery button appears)
// Because pipelineMode="asset", frontend shows Phase 2 CTA
// POST /scan/asset-discovery with {
//   hosts: [...phase1_results],
//   intensity: "normal",
//   pipeline_mode: "asset",
//   scan_id: 123
// }
```

---

## 9. EDGE CASES & SPECIAL HANDLING

### Special Case 1: scan_type="fast" Always Forces FAST Profile
**(Backend/orchestrator/scan_orchestrator.py, line 108)**

```python
if scan_type == "fast":
    profile = FAST  # Override pipeline_mode mapping
else:
    profile = profile_for_pipeline(pipeline_mode)
```

**Impact:** Even if user selects "Advanced Scan" but sets `scan_type="fast"`, the backend will use **FAST** profile instead of **AGGRESSIVE**.

### Special Case 2: "asset" Pipeline Mode Skips Phase 1 Cache
**(Frontend/src/config/scanConfig.js, line 71)**

```javascript
asset: {
    alwaysRestart: true,  // ← Signal: never reuse Host Discovery cache
}
```

**Impact:** Asset Discovery always re-runs Phase 1 fresh, never jumps directly to asset-discovery endpoint with cached host data.

### Special Case 3: Nmap Pre-Enrichment in Phase 3
**(Backend/orchestrator/scan_orchestrator.py, line 280-310)**

```python
def _nmap_pre_enrich(hosts):
    # Before VulnerabilityEngine, optionally run Nmap on known open ports
    # to upgrade OS detection and service versions
    for host in hosts:
        result = scanner.full_scan(ip, ports=open_port_nums)
        # Upgrade service versions with Nmap's more accurate data
```

**Impact:** Advanced Scan (Phase 3) gets more accurate OS and service data before vulnerability plugins run.

---

## 10. KEY FILES TO UNDERSTAND

| File | Purpose |
|---|---|
| **Frontend/src/config/scanConfig.js** | Defines SCAN_PIPELINES → phases mapping |
| **Frontend/src/pages/Dashboard.jsx** | Scan template selection → setPipelineMode() |
| **Frontend/src/pages/scan/NewScan.jsx** | Target input → buildPhasePayload() → API call |
| **Backend/main.py** | Request models + 3 phase endpoints |
| **Backend/orchestrator/scan_orchestrator.py** | run_host_discovery_only() → profile mapping |
| **Backend/core/discovery/profiles.py** | FAST, BALANCED, AGGRESSIVE definitions |
| **Backend/core/discovery/engine.py** | Technique execution (ARP, ICMP, TCP, UDP, NetBIOS) |

---

## 11. TESTING: VERIFY WHICH PROFILE IS USED

### Method 1: Check Backend Response
When Phase 1 completes, look for `discovery_profile` in response:

```json
{
  "success": true,
  "summary": {
    "discovery_profile": "FAST",      // or "BALANCED" or "AGGRESSIVE"
    "active_hosts": 15,
    ...
  },
  "metadata": {
    "discovery_profile": "FAST"
  }
}
```

### Method 2: Check Backend Logs
Enable debug logging and search for:
```
DiscoveryEngine(profile=FAST)
DiscoveryEngine(profile=BALANCED)
DiscoveryEngine(profile=AGGRESSIVE)
```

### Method 3: Curl the Endpoints

**Test 1: Basic Network Scan**
```bash
curl -X POST http://localhost:8000/scan/host-discovery \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.0/24"],
    "scan_type": "adaptive",
    "pipeline_mode": "basic"
  }'
```
Expected: `"discovery_profile": "FAST"`

**Test 2: Asset Discovery**
```bash
curl -X POST http://localhost:8000/scan/host-discovery \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.0/24"],
    "scan_type": "adaptive",
    "pipeline_mode": "asset"
  }'
```
Expected: `"discovery_profile": "BALANCED"`

**Test 3: Advanced Scan**
```bash
curl -X POST http://localhost:8000/scan/host-discovery \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.0/24"],
    "scan_type": "adaptive",
    "pipeline_mode": "advanced"
  }'
```
Expected: `"discovery_profile": "AGGRESSIVE"`

---

## SUMMARY

| When You Select | Backend Gets | Maps To Profile | What Happens |
|---|---|---|---|
| **Basic Network Scan** | `pipeline_mode="basic"` | **FAST** | Quick ARP + TCP scan, 0.8s timeout |
| **Asset Discovery** | `pipeline_mode="asset"` | **BALANCED** | Medium scan: ARP + ICMP + TCP + UDP, 1.5s timeout |
| **Advanced Scan** | `pipeline_mode="advanced"` | **AGGRESSIVE** | Deep scan: all techniques + enrichment, 2.0s timeout |

