# Implementation Guide — Ccure Audit Pro

> Covers two things in one place:
> 1. **Setup & Integration** — how to plug in the phase-selective update (new backend files, CORS, frontend example)
> 2. **Developer Reference** — every module, class, design decision, and data contract in detail

---

## Part 1 — Setup & Integration

### What Changed

```
BEFORE (original):
├── scan_single_host()        ← Runs all 4 phases
├── scan_ip_range()           ← Phase 1 only
├── scan_subnet()             ← Phase 1 only
└── scan_subnets_of_subnet()  ← Phase 1 only

AFTER (updated):
├── [All above unchanged — fully backward compatible]
├── run_phase1_only()         ← NEW: Discovery on any targets
├── run_phase2_only()         ← NEW: Port scan on selected hosts
├── run_phase3_only()         ← NEW: Vulnerability scan on selected hosts
└── run_phases()              ← NEW: Flexible "1", "1+2", "1+2+3+4"
```

### Step 1 — Replace Two Backend Files

```bash
cp scan_orchestrator_updated.py Backend/orchestrator/scan_orchestrator.py
cp main_updated.py Backend/main.py
```

### Step 2 — Update CORS Origins

In `Backend/main.py`, find the CORS section (~line 30) and set your frontend URL:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",      # React dev
        "http://localhost:5173",      # Vite dev
        "https://yourdomain.com",     # Production
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Step 3 — Start and Test

```bash
cd Backend
python -m uvicorn main:app --reload

# In another terminal
python test_api.py          # should print: ✅ All tests passed
```

Or manually with curl:
```bash
curl http://localhost:8000/

curl -X POST http://localhost:8000/scan/phase1 \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.10"], "scan_type": "tcp"}'
```

### Integration Checklist

- [ ] Replaced `scan_orchestrator.py`
- [ ] Replaced `main.py`
- [ ] Updated `allow_origins` in `main.py` for your frontend URL
- [ ] Server starts without errors: `uvicorn main:app --reload`
- [ ] `python test_api.py` passes all 6 tests
- [ ] Interactive docs load at `http://localhost:8000/docs`
- [ ] No CORS errors in browser console

---

### API Usage: Phase-Selective Workflow

#### Phase 1 — Discovery

**Endpoint**: `POST /scan/phase1`

```json
{
  "targets": ["192.168.1.0/24"],
  "scan_type": "adaptive"
}
```

Response includes all discovered hosts. Filter `is_active == true` to get live hosts. Pass the full host objects to Phase 2 — don't strip fields.

#### Phase 2 — Port Scan Selected Hosts

**Endpoint**: `POST /scan/phase2`

```json
{
  "hosts": [ /* paste phase1 data[] here */ ],
  "intensity": "normal"
}
```

Pass the entire host objects from Phase 1 output, not just IPs. Intensity options: `light | normal | deep`.

#### Phase 3 — Vulnerability + Risk Scoring

**Endpoint**: `POST /scan/phase3`

```json
{
  "hosts": [ /* paste phase2 data[] here */ ]
}
```

Returns CVEs, TLS info, HTTP header audit, SSH algorithm info, and a risk score (0–100) per host.

#### Flexible Phases

**Endpoint**: `POST /scan/phases`

```json
{
  "targets": ["192.168.1.10"],
  "phases": "1+2+3+4",
  "scan_type": "adaptive",
  "intensity": "normal"
}
```

`phases` options: `"1"` | `"1+2"` | `"1+2+3+4"`

---

### React Component Example

Copy-paste this component as a starting point. It implements the full 3-step scanning flow.

```jsx
import { useState } from "react";

const API = "http://localhost:8000";

export default function CcureScanner() {
  const [subnet, setSubnet]           = useState("192.168.1.0/24");
  const [step, setStep]               = useState(0);
  const [loading, setLoading]         = useState(false);
  const [allHosts, setAllHosts]       = useState([]);
  const [selectedHosts, setSelectedHosts] = useState([]);
  const [phase2Results, setPhase2Results] = useState([]);
  const [phase3Results, setPhase3Results] = useState([]);

  async function handlePhase1() {
    setLoading(true);
    try {
      const res = await fetch(`${API}/scan/phase1`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targets: [subnet], scan_type: "adaptive" }),
      });
      const data = await res.json();
      if (data.success) {
        setAllHosts(data.data);
        setStep(1);
      } else {
        alert("Error: " + data.error);
      }
    } catch (err) {
      alert("Network error: " + err.message);
    } finally {
      setLoading(false);
    }
  }

  async function handlePhase2() {
    setLoading(true);
    try {
      const res = await fetch(`${API}/scan/phase2`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hosts: selectedHosts, intensity: "normal" }),
      });
      const data = await res.json();
      if (data.success) {
        setPhase2Results(data.data);
        setStep(2);
      } else {
        alert("Error: " + data.error);
      }
    } catch (err) {
      alert("Network error: " + err.message);
    } finally {
      setLoading(false);
    }
  }

  async function handlePhase3(hosts) {
    setLoading(true);
    try {
      const res = await fetch(`${API}/scan/phase3`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hosts }),
      });
      const data = await res.json();
      if (data.success) {
        setPhase3Results(data.data);
        setStep(3);
      } else {
        alert("Error: " + data.error);
      }
    } catch (err) {
      alert("Network error: " + err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ padding: "20px", fontFamily: "Arial" }}>
      <h1>Ccure Audit — Phase-Selective Scanner</h1>

      {/* Step 0: Input */}
      {step === 0 && (
        <div>
          <h2>Step 1: Discovery</h2>
          <input
            type="text"
            value={subnet}
            onChange={(e) => setSubnet(e.target.value)}
            placeholder="e.g., 192.168.1.0/24"
            style={{ padding: "8px", width: "300px" }}
          />
          <button
            onClick={handlePhase1}
            disabled={loading}
            style={{ marginLeft: "10px", padding: "8px 16px" }}
          >
            {loading ? "Scanning..." : "Discover Hosts"}
          </button>
        </div>
      )}

      {/* Step 1: Select hosts for port scan */}
      {step === 1 && (
        <div>
          <h2>{allHosts.filter((h) => h.is_active).length} Active Hosts Found</h2>
          <table style={{ width: "100%", borderCollapse: "collapse", marginTop: "20px" }}>
            <thead>
              <tr style={{ backgroundColor: "#f0f0f0" }}>
                <th style={{ padding: "10px", border: "1px solid #ddd" }}>
                  <input
                    type="checkbox"
                    onChange={(e) =>
                      setSelectedHosts(e.target.checked ? allHosts.filter((h) => h.is_active) : [])
                    }
                  />
                </th>
                <th style={{ padding: "10px", border: "1px solid #ddd" }}>IP</th>
                <th style={{ padding: "10px", border: "1px solid #ddd" }}>Hostname</th>
                <th style={{ padding: "10px", border: "1px solid #ddd" }}>OS</th>
              </tr>
            </thead>
            <tbody>
              {allHosts.filter((h) => h.is_active).map((host) => (
                <tr key={host.ip_address}>
                  <td style={{ padding: "10px", border: "1px solid #ddd" }}>
                    <input
                      type="checkbox"
                      checked={selectedHosts.some((h) => h.ip_address === host.ip_address)}
                      onChange={(e) =>
                        setSelectedHosts(
                          e.target.checked
                            ? [...selectedHosts, host]
                            : selectedHosts.filter((h) => h.ip_address !== host.ip_address)
                        )
                      }
                    />
                  </td>
                  <td style={{ padding: "10px", border: "1px solid #ddd" }}>{host.ip_address}</td>
                  <td style={{ padding: "10px", border: "1px solid #ddd" }}>{host.hostname}</td>
                  <td style={{ padding: "10px", border: "1px solid #ddd" }}>{host.os_guess}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div style={{ marginTop: "20px" }}>
            <p>{selectedHosts.length} host(s) selected</p>
            <button
              onClick={handlePhase2}
              disabled={loading || selectedHosts.length === 0}
              style={{ padding: "10px 20px" }}
            >
              {loading ? "Scanning..." : "Scan Ports on Selected Hosts"}
            </button>
          </div>
        </div>
      )}

      {/* Step 2: Show ports, pick host for deep audit */}
      {step === 2 && (
        <div>
          <h2>Open Ports Found</h2>
          {phase2Results.map((host) => (
            <div
              key={host.ip_address}
              style={{ border: "1px solid #ddd", padding: "15px", marginTop: "15px", borderRadius: "5px" }}
            >
              <h3>{host.ip_address}</h3>
              {host.open_ports && host.open_ports.length > 0 ? (
                <ul>
                  {host.open_ports.map((port, idx) => (
                    <li key={idx}>
                      {port.port}/{port.service} — {port.banner || "N/A"}
                    </li>
                  ))}
                </ul>
              ) : (
                <p>No open ports</p>
              )}
              <button onClick={() => handlePhase3([host])} style={{ marginTop: "10px", padding: "8px 16px" }}>
                {loading ? "Auditing..." : "Deep Audit This Host"}
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Step 3: Vulnerabilities */}
      {step === 3 && (
        <div>
          <h2>Vulnerability Report</h2>
          {phase3Results.map((host) => (
            <div
              key={host.ip_address}
              style={{
                border: `3px solid ${host.host_risk_level === "Critical" ? "#d32f2f" : "#f57c00"}`,
                padding: "15px",
                marginTop: "15px",
                borderRadius: "5px",
              }}
            >
              <h3>
                {host.ip_address} — {host.host_risk_level} (Score: {host.host_risk_score}/100)
              </h3>
              {host.cves && host.cves.length > 0 ? (
                <div>
                  <h4>🔴 {host.cves.length} CVEs found:</h4>
                  {host.cves.map((cve, idx) => (
                    <div
                      key={idx}
                      style={{ backgroundColor: "#fff3e0", padding: "10px", marginTop: "10px", borderLeft: "4px solid #f57c00" }}
                    >
                      <strong>{cve.cve_id}</strong> — {cve.description}
                      <br />
                      Severity: {cve.severity} (CVSS: {cve.cvss_score})
                    </div>
                  ))}
                </div>
              ) : (
                <p>✅ No known CVEs found</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
```

### Redux State Structure (Optional)

```javascript
// scanSlice.js
const initialState = {
  phase1Results: [],      // All discovered hosts
  selectedHosts: [],      // User-selected hosts for port scan
  phase2Results: [],      // Hosts with open port info
  phase3Results: [],      // Hosts with full vulnerability data
  currentStep: 0,         // 0: input, 1: phase1, 2: phase2, 3: phase3
  loading: false,
  error: null,
};
```

### Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| CORS blocked | Frontend URL not in `allow_origins` | Update `main.py`, restart server |
| Phase2 "hosts_list is empty" | Passing just IPs instead of full host objects | Pass entire host objects from Phase 1 `data[]` |
| Phase3 "No active hosts" | Hosts don't have `open_ports` | Run Phase 2 first; Phase 3 needs Phase 2 output |
| Slow port scan | Intensity set to `deep` | Use `normal` for balanced speed |

---

---

## Part 2 — Developer Reference

> Deep dive into every module, class, design decision, and data contract.

---

### Design Principles

**1. Layered architecture with strict import rules**  
Each layer may only import from layers below it.

```
api/ → orchestrator/ → engines/ → core/
                     → plugins/ → core/
```

**2. Plugins are self-contained**  
Every plugin in `engines/vulnerability/plugins/` is independently testable. It imports only from `core/` and Python stdlib.

**3. Silent failure by default**  
Network probes catch all exceptions silently. One unreachable host must never abort a subnet scan:

```python
try:
    # probe logic
except Exception:
    pass   # return empty / default result
```

**4. Mutable host dicts as shared state**  
Each host is a plain `dict` that phases enrich in-place. Avoids object conversion overhead across thousands of hosts.

**5. Stdlib-first, optional enhancements**  
Every feature works without Scapy or reportlab. `SCAPY_AVAILABLE` and `PDF_AVAILABLE` flags in `core/constants.py` gate all optional code paths.

---

### Dependency Rules (Import Graph)

```
cli.py          → api/
main.py         → api/

api/            → orchestrator/, core/

orchestrator/   → engines/discovery/
                → engines/port/
                → engines/vulnerability/
                → core/

engines/discovery/      → core/
engines/port/           → core/
engines/vulnerability/  → engines/vulnerability/plugins/, core/

plugins/*       → core/   (and stdlib only)

core/           → stdlib only  ← nothing imports from above here
```

---

### core/ Layer

The foundation layer. No file in `core/` may import from `engines/`, `orchestrator/`, or `api/`.

#### core/constants.py

Single source of truth for all lookup tables and numeric constants.

`SCAPY_AVAILABLE: bool` — Set at module load. All code that uses Scapy checks this flag.

`PDF_AVAILABLE: bool` — Same pattern for reportlab.

`CVE_HINTS: Dict[str, List[Dict]]` — Maps lowercase banner substrings → list of CVE dicts `{"cve": str, "cvss": float, "desc": str}`. Matching is done in `core/utils.py::lookup_cve()`.

`PORT_DB: Dict[int, Dict]` — Maps port → `{"service": str, "risk": str, "note": str}`. Risk values: `Critical | High | Medium | Low | Info`.

`SCAN_PORTS_QUICK` — 17 highest-risk ports (light intensity).  
`SCAN_PORTS_FULL` — All 31 ports in PORT_DB (normal/deep intensity).

`OS_TTL_MAP` — Ordered list of `(ttl_ceiling, os_label)` tuples.  
`TCP_WINDOW_OS` — Dict of `window_size → os_label` for TCP window fingerprinting.  
`VER_PATTERNS` — Compiled regex list for service version extraction.

#### core/models.py

All enums and dataclasses. No logic.

`DiscoveryScanType(Enum)` — `ping | arp | tcp | full | adaptive | stealth`

`ScanIntensity(Enum)` — `light | normal | deep`

`PortResult` (dataclass):
```
port: int, service: str, state: str, banner: str,
version: str, risk: str, cves: list
```

`TLSInfo` (dataclass):
```
enabled: bool, version: str, cipher: str, cert_subject: str,
cert_issuer: str, cert_expiry: str, cert_expired: bool,
cert_self_signed: bool, san_domains: list, weak_cipher: bool, score: str
```

`HTTPAudit` (dataclass):
```
status_code: int, server_header: str, hsts: bool, x_frame: str,
csp: bool, x_content_type: bool, x_xss: bool,
redirect_http: bool, issues: list
```

`HostResult` (dataclass) — The canonical final result for one host. `to_dict()` returns a JSON-serialisable dict.

`DiscoverySummary` (dataclass) — Aggregate stats: total/active/inactive hosts, scan duration, risk counts.

#### core/utils.py

**`PrivilegeManager`**
```python
PrivilegeManager.get_platform() → "linux" | "macos" | "windows" | "unknown"
PrivilegeManager.is_admin()     → bool
PrivilegeManager.info()         → {"platform", "has_privileges", "privilege_level"}
```

**`InputValidator`** — All methods are `@staticmethod`.
```python
InputValidator.is_safe(value)          → bool
InputValidator.validate_ip(ip)         → bool
InputValidator.validate_cidr(cidr)     → {valid, error?, network?}
InputValidator.validate_range(range)   → {valid, error?}
InputValidator.resolve_target(target)  → {resolved, type} | {error}
InputValidator.expand_ip_range(range)  → List[str]
InputValidator.expand_target(target)   → List[str]
```

`resolve_target()` handles CIDR, IP range, single IP, and hostname (DNS resolve).

**`TokenBucket`** — Classic token-bucket rate limiter. `consume(n=1.0)` blocks until a token is available.

**`lookup_cve(banner: str) → List[Dict]`** — Iterates `CVE_HINTS`, returns all matching CVE dicts.

**`extract_version(banner: str, service: str = "") → str`** — Applies `VER_PATTERNS` regexes in order.

#### core/risk.py

Pure functions — no I/O, no state.

**`fingerprint_os(ttl, window) → Tuple[str, str]`** — Two-stage packet fingerprint: TTL ceiling lookup, then TCP window lookup. Returns `(os_guess, confidence)`.

**`infer_os_from_host(host: Dict) → Tuple[str, str]`** — Fallback unauthenticated OS inference using open port combinations, service banners, and plugin output (SSH banner, SNMP sysDescr, HTTP Server header, etc.).

**`calculate_risk(open_ports, cves, http_audit, tls_info) → Tuple[int, str]`** — Weighted scoring capped at 100. Returns `(score, level)`. See scoring table in README.

**`deduplicate_cves(cves: List[Dict]) → List[Dict]`** — Deduplicates by `cve` key, preserving first occurrence.

---

### engines/ Layer

Each engine is a class with a `run()` method. Engines mutate host dicts in-place and return the modified list.

#### engines/discovery/discovery_engine.py

**Class: `DiscoveryEngine`**

```python
DiscoveryEngine(has_privileges=False, stealth_mode=False)
engine.run(ip_list: List[str], scan_type: DiscoveryScanType) → List[Dict]
```

Processes IPs in batches of 50. Returns one dict per IP (including inactive hosts).

Phase 1 dispatch logic:
- `adaptive`: LAN IPs → ARP (if scapy+root) else TCP; WAN IPs → SYN (if scapy+root) else TCP
- `full/stealth/arp/ping`: Use scapy if available, fall back silently
- `tcp`: Pure async TCP connect only

Key methods: `_scapy_arp()`, `_scapy_syn()`, `_scapy_layered()`, `async _async_tcp()`.

TCP connect uses `asyncio.Semaphore(50)`, timeout 0.8s normal / 1.5s on retry.

#### engines/port/port_engine.py

**Class: `PortEngine`**

```python
PortEngine(intensity=ScanIntensity.NORMAL)
engine.run(hosts: List[Dict]) → List[Dict]   # mutates in-place
```

Selects port list by intensity, then fires one async task per (ip × port). Bounded by `asyncio.Semaphore(50)`.

For each open port: TCP connect → banner grab → `lookup_cve(banner)` + `extract_version()` → build `PortResult` → append to `host["open_ports"]`.

#### engines/vulnerability/vulnerability_engine.py

**Class: `VulnerabilityEngine`**

```python
VulnerabilityEngine(rate_limit=200.0)
engine.run(hosts: List[Dict]) → List[Dict]   # mutates in-place
```

For each active host: `TokenBucket.consume()` → `_run_plugins(host)` → `_score_host(host)`.

Plugin execution order: `tls_scanner → http_analyzer → ssh_probe → smb_probe → snmp_probe → udp_scanner → icmp_probe → cve_engine`

`cve_engine` runs last because it benefits from banners populated by all earlier phases.

`_merge()`: `cves` and `udp_services` are list fields (extended, not replaced). All other keys replace existing values.

---

### Plugin Layer

#### Plugin Contract

```python
def run(ip: str, open_ports: List[int], **kwargs) -> Dict:
    """
    Returns a dict to be merged onto the host record.
    Keys: tls_info | http_audit | ssh_info | smb_info |
          snmp_info | udp_services | icmp_info | cves
    Return {} if not applicable. Never raise an exception.
    """
```

#### tls_scanner.py
Probes first open TLS port in `[443, 8443, 465, 993, 995]`. Uses `ssl.create_default_context()` with `CERT_NONE`. Grades: A (TLS 1.2/1.3, clean), B (TLS 1.1), C (TLS 1.0/SSL), F (expired/self-signed/weak).

#### http_analyzer.py
Sends `HEAD / HTTP/1.1`. Checks HSTS, X-Frame-Options, CSP, X-Content-Type-Options, X-XSS-Protection, HTTP→HTTPS redirect. Issues list populated for every missing header.

#### ssh_probe.py
Connects TCP port 22. Sends client banner to trigger `SSH_MSG_KEXINIT`. Parses binary KEXINIT packet to extract kex, host-key, encryption, and MAC algorithm lists. Checks against known weak sets. Calls `lookup_cve(banner)`.

#### smb_probe.py
Sends raw SMBv1 Negotiate Protocol Request (133 bytes) to port 445 (fallback 139). Checks for SMB magic bytes `\xff\x53\x4d\x42` in response. CVEs: EternalBlue + SMBGhost.

#### snmp_probe.py
Builds hand-crafted SNMPv1 GetRequest PDU in BER/DER encoding targeting OID `1.3.6.1.2.1.1.1.0` (sysDescr). Tests community strings `public → private → community → snmp` via UDP port 161.

#### udp_scanner.py
Three UDP probes using only stdlib: DNS A-record query (port 53), NTP mode-3 client packet (port 123), TFTP RRQ (port 69).

#### icmp_probe.py
Sends ICMP type 13 (Timestamp Request) via `scapy.sr()`. Returns `{}` immediately if Scapy not installed.

#### cve_engine.py
Runs last. For each open port's `PortResult`, calls `lookup_cve()` on `banner`, `version`, and `service`. Deduplication is handled by `VulnerabilityEngine._score_host()` after this runs.

---

### orchestrator/ Layer

#### orchestrator/scan_orchestrator.py

**Class: `ScanOrchestrator`** — The only class that knows about all three engines.

**`_run_pipeline(ips, st, scan_mode, meta) → Dict[str, Dict]`** — Core execution:
```
Phase 1: DiscoveryEngine.run(ips, st)             → List[Dict]
Phase 2: PortEngine.run(active_hosts)              → mutates in-place (if mode != "discovery")
Phase 3+4: VulnerabilityEngine.run(active_hosts)   → mutates in-place (if mode == "full")
```

`scan_mode` values: `"discovery"` | `"port"` | `"full"` (default)

**`_format_host(ip, data, input_hostname) → HostResult`** — Converts raw host dict to typed dataclass. Attempts reverse-DNS for active hosts. Calculates `confidence`:
- ARP in confirmations OR ≥2 confirmations → `"High"`
- 1 confirmation → `"Medium"`
- 0 → `"Low"`

**Standard response envelope:**
```python
{
    "success": True,
    "data": HostResult.to_dict() | List[HostResult.to_dict()],
    "summary": DiscoverySummary.to_dict(),
    "metadata": {
        "target": str,
        "scan_type": str,
        "timestamp": str,
        "privilege_warning"?: str,   # present if downgraded to TCP
    }
}
```

---

### api/ Layer

#### api/host_discovery_api.py

A thin facade over `ScanOrchestrator`. Exists for stability (callers import from `api/`, not `orchestrator/`) and backward compatibility. No scan logic lives here.

---

### Host Dict Schema

The internal host dict after all 4 phases:

```python
{
    # Phase 1
    "ip":            str,
    "is_active":     bool,
    "mac":           str,
    "method":        str,          # "ARP" | "ICMP" | "TCP SYN" | "TCP Connect" | "N/A"
    "elapsed_ms":    float | None,
    "os_guess":      str,
    "os_confidence": str,          # "Low" | "Medium" | "High"
    "confirmations": List[str],

    # Phase 2
    "open_ports": [
        {
            "port": int, "service": str, "state": "open",
            "banner": str, "version": str, "risk": str,
            "cves": List[{"cve": str, "cvss": float, "desc": str}]
        }
    ],
    "cves": List[Dict],            # aggregate, deduped in Phase 4

    # Phase 3 plugin fields
    "tls_info":      Dict,
    "http_audit":    Dict,
    "ssh_info":      Dict,
    "smb_info":      Dict,
    "snmp_info":     Dict,
    "udp_services":  List[Dict],
    "icmp_info":     Dict,

    # Phase 4
    "host_risk_score": int,        # 0–100
    "host_risk_level": str,        # Critical | High | Medium | Low | Info
}
```

---

### Concurrency Model

All TCP-level scanning is `asyncio`-based. No threads for network I/O.

```
asyncio.run(engine._scan_all(hosts))
    └─ asyncio.gather(*tasks)            # all (ip × port) tasks in parallel
        └─ asyncio.Semaphore(50)         # max 50 concurrent connections
            └─ asyncio.wait_for(conn, timeout=0.8s)
```

Scapy raw-packet scans (`sr()`, `srp()`) are synchronous and run before the asyncio event loop. Discovery is batched at 50 IPs per Scapy call.

Phase 3 (vulnerability plugins) is synchronous (per-host loop with rate-limiting). The rate limiter must be synchronous to be meaningful.

---

### Rate Limiting

`TokenBucket` is consumed once per host between Phase 3 plugin runs. Default: 200 tokens/second.

```python
bucket = TokenBucket(rate=200.0, capacity=200.0)
for host in active_hosts:
    bucket.consume()      # ≤ 200 hosts/second
    run_all_plugins(host)
```

For IDS evasion in high-security environments:
```python
api = HostDiscoveryAPI(rate_limit=10.0)
```

---

### Error Handling Strategy

| Layer | Strategy |
|---|---|
| Input validation | Return `{"error": str}` — never raise |
| Network probes (plugins, engines) | `try/except Exception: pass` — return empty dict |
| Orchestrator | Catches engine-level errors, returns `{"success": False, "error": str}` |
| FastAPI endpoints | Convert `success=False` to HTTP 400 |
| Plugin failure isolation | One plugin exception never aborts other plugins for same host |

---

### Extending the System

**Adding a new scan mode:** Add to `DiscoveryScanType` in `core/models.py`, handle in `DiscoveryEngine._phase1()`, add to `get_system_info()`.

**Adding a new port to PORT_DB:** Edit `core/constants.py`. It auto-appears in `SCAN_PORTS_FULL`.

**Adding a new CVE:** Edit `core/constants.py::CVE_HINTS`. Key is a lowercase substring of the banner.

**Adding a new plugin:** See Plugin Contract above and the worked FTP example in `README.md`.

**Adding a new API endpoint:** Add route to `main.py`. Call appropriate `HostDiscoveryAPI` method. If new scan logic is needed, add to `ScanOrchestrator` first.
