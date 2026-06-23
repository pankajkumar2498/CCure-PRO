# Ccure Audit Pro

> **Network security scanner built entirely on Python stdlib.**  
> Zero mandatory external dependencies. Drop-in plugin architecture. Production-ready.

---

## Table of Contents

1. [Overview](#overview)
2. [Feature Matrix](#feature-matrix)
3. [Project Structure](#project-structure)
4. [Architecture Diagram](#architecture-diagram)
5. [Quick Start](#quick-start)
6. [Running the CLI](#running-the-cli)
7. [Running the API Server](#running-the-api-server)
8. [Phase-Selective Scanning (New)](#phase-selective-scanning-new)
9. [API Reference](#api-reference)
10. [Scan Modes & Intensity](#scan-modes--intensity)
11. [Understanding Output](#understanding-output)
12. [Plugin System](#plugin-system)
13. [Adding a New Plugin](#adding-a-new-plugin)
14. [Configuration Reference](#configuration-reference)
15. [Privilege Requirements](#privilege-requirements)
16. [Troubleshooting](#troubleshooting)
17. [License & Ethics Notice](#license--ethics-notice)

---

## Overview

Ccure Audit Pro is a modular, layered network security scanner inspired by Nessus and OpenVAS. It performs host discovery, port scanning, service fingerprinting, vulnerability intelligence, and risk scoring — all using Python's standard library with optional enhancement via Scapy.

The monolithic `host_discovery_api.py` reference file has been refactored into a clean, scalable package structure where every concern lives in its own focused module. Teams can read, debug, test, and extend individual components without touching anything else.

---

## Feature Matrix

| Feature | Stdlib Only | With Scapy |
|---|:---:|:---:|
| TCP Connect host discovery | ✅ | ✅ |
| ARP scan (LAN) | ❌ | ✅ |
| ICMP ping sweep | ❌ | ✅ |
| TCP SYN stealth scan | ❌ | ✅ |
| ICMP Timestamp probe | ❌ | ✅ |
| Packet fragmentation (stealth) | ❌ | ✅ |
| Async port scanning | ✅ | ✅ |
| Banner grab + version extraction | ✅ | ✅ |
| TLS/SSL certificate analysis | ✅ | ✅ |
| HTTP security header audit | ✅ | ✅ |
| SSH algorithm negotiation | ✅ | ✅ |
| SMB/NetBIOS probe | ✅ | ✅ |
| SNMP community string check | ✅ | ✅ |
| UDP service discovery (DNS/NTP/TFTP) | ✅ | ✅ |
| OS identification (service inference / TTL + TCP window) | ✅ | ✅ |
| CVE hint intelligence (30+ mappings) | ✅ | ✅ |
| Port risk scoring (Critical → Info) | ✅ | ✅ |
| Host risk score (0–100, CVSS-weighted) | ✅ | ✅ |
| Token-bucket rate limiter | ✅ | ✅ |
| Phase-selective scanning (frontend orchestration) | ✅ | ✅ |
| PDF report generation | With `reportlab` | With `reportlab` |
| REST API | With `fastapi` | With `fastapi` |

---

## Project Structure

```
ccure_engine/
│
├── main.py                          FastAPI web server entry point
├── cli.py                           Interactive command-line interface
├── requirements.txt                 Dependency manifest
│
├── api/
│   └── host_discovery_api.py        Public API class — thin wrapper over orchestrator
│
├── core/                            Shared foundation — no engine imports allowed here
│   ├── constants.py                 CVE_HINTS, PORT_DB, port lists, OS maps, regex patterns
│   ├── models.py                    Enums (DiscoveryScanType, ScanIntensity) + dataclasses
│   ├── risk.py                      fingerprint_os(), calculate_risk(), deduplicate_cves()
│   └── utils.py                     PrivilegeManager, InputValidator, TokenBucket,
│                                    lookup_cve(), extract_version(), get_local_ips()
│
├── engines/
│   ├── discovery/
│   │   └── discovery_engine.py      Phase 1 — Host discovery (ARP/ICMP/SYN/TCP/adaptive)
│   │
│   ├── port/
│   │   └── port_engine.py           Phase 2 — Async TCP port scan + banner grab
│   │
│   └── vulnerability/
│       ├── vulnerability_engine.py  Phase 3+4 — Plugin runner + risk scorer
│       └── plugins/
│           ├── __init__.py          Plugin registry
│           ├── tls_scanner.py       TLS/SSL certificate inspector + cipher grading
│           ├── http_analyzer.py     HTTP security header audit
│           ├── ssh_probe.py         SSH algorithm negotiation parser
│           ├── smb_probe.py         SMB/NetBIOS TCP probe
│           ├── snmp_probe.py        SNMP community string check (UDP)
│           ├── udp_scanner.py       UDP service discovery (DNS / NTP / TFTP)
│           ├── icmp_probe.py        ICMP Timestamp probe (scapy)
│           └── cve_engine.py        CVE intelligence from banner/version/service
│
└── orchestrator/
    └── scan_orchestrator.py         Full 4-phase pipeline controller + host formatting
```

---

## Architecture Diagram

```
                      ┌─────────────────────────────┐
CLI / FastAPI / Code   │       HostDiscoveryAPI        │   api/host_discovery_api.py
─────────────────────► │  scan_single_host()           │
                       │  scan_subnet()                │
                       │  scan_ip_range()              │
                       │  scan_subnets_of_subnet()     │
                       └──────────────┬────────────────┘
                                      │
                       ┌──────────────▼────────────────┐
                       │       ScanOrchestrator         │   orchestrator/scan_orchestrator.py
                       │  run_host_discovery_only()  (NEW)      │
                       │  run_asset_discovery_only()  (NEW)      │
                       │  run_vulnerability_audit_only()  (NEW)      │
                       │  run_phases()       (NEW)      │
                       └──┬────────┬──────────┬────────┘
                          │        │           │
          ┌───────────────▼──┐  ┌──▼──────┐  ┌▼──────────────────────────┐
          │ DiscoveryEngine  │  │PortEngine│  │  VulnerabilityEngine       │
          │  Phase 1         │  │ Phase 2  │  │  Phase 3 (plugins)         │
          │  ARP/ICMP/SYN/   │  │ TCP async│  │  Phase 4 (risk scoring)    │
          │  TCP/Adaptive    │  │ Banner   │  └────────────────────────────┘
          └──────────────────┘  └──────────┘
```

### Data Flow

```
Target String
     │
     ▼
InputValidator.resolve_target()        Validate + normalise input
     │
     ▼
DiscoveryEngine.run()                  Phase 1 → List[{ip, is_active, mac, ...}]
     │
     ▼  (active hosts only)
PortEngine.run()                       Phase 2 → adds open_ports[], banners, versions
     │
     ▼
VulnerabilityEngine.run()              Phase 3 → each plugin enriches the host dict
     │  tls_scanner  → tls_info{}
     │  http_analyzer→ http_audit{}
     │  ssh_probe    → ssh_info{}
     │  smb_probe    → smb_info{}
     │  snmp_probe   → snmp_info{}
     │  udp_scanner  → udp_services[]
     │  icmp_probe   → icmp_info{}
     │  cve_engine   → cves[]
     │
     ▼  (still inside VulnerabilityEngine)
calculate_risk()                       Phase 4 → host_risk_score (0-100), host_risk_level
     │
     ▼
ScanOrchestrator._format_host()        Build HostResult dataclass
     │
     ▼
JSON Response                          {success, data, summary, metadata}
```

---

## Quick Start

### Minimum install (TCP scan, no raw packets)

```bash
git clone <repo>
cd ccure_engine
pip install reportlab          # optional — for PDF reports
python cli.py
```

### Full install (all scan modes)

```bash
python -m venv .venv
.venv\Scripts\activate   
pip install -r requirements.txt

python -m pip install --no-cache-dir -r requirements.txt

# On Linux/macOS: run as root for ARP/ICMP/SYN modes
sudo python cli.py
```

### Programmatic usage

```python
from api.host_discovery_api import HostDiscoveryAPI

api = HostDiscoveryAPI(silent=False, intensity="normal")

# Scan a single host (all 4 phases)
result = api.scan_single_host("10.180.6.14", scan_type="adaptive")
print(result["data"]["host_risk_level"])   # e.g. "High"
print(result["data"]["cves"])              # list of CVE dicts

# Scan a subnet (discovery only)
result = api.scan_subnet("10.180.6.0/24")
active = [h for h in result["data"] if h["is_active"]]
print(f"{len(active)} active hosts found")
```

---

## Running the CLI

```bash
python cli.py
```

Interactive prompts:

```
Choose operation:
  1. Scan single host / hostname
  2. Scan IP range  (e.g. 10.180.6.14-50)
  3. Scan full subnet  (e.g. 10.180.6.0/24)
  4. Scan subnets of a subnet

Enter choice (1-4): 1
Scan type [ping/arp/tcp/full/adaptive/stealth] (default: adaptive): adaptive
Intensity [light/normal/deep] (default: normal): normal
Enter IP or hostname: 10.180.6.14
```

Output is pretty-printed JSON.

---

## Running the API Server

```bash
pip install fastapi uvicorn
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Interactive docs at: `http://localhost:8000/docs`

---

## Phase-Selective Scanning (New)

The API now supports **frontend-orchestrated, phase-selective scanning** — the same workflow used by Nessus, Nmap, and Qualys. Instead of running all 4 phases on all hosts (which can take 20+ hours on a /24 subnet), the frontend drives each phase independently.

### Why This Matters

| Scenario | Old Approach | New Approach |
|----------|-------------|--------------|
| Discover 254 hosts | Buried inside full scan | Phase 1: ~45 seconds |
| Port scan 5 hosts | Must re-run full scan | Phase 2: ~10 seconds |
| Deep audit 1 host | Must re-run full scan | Phase 3: ~45 seconds |
| **Total** | **20+ hours** | **~2 minutes** |

### New Orchestrator Methods

```python
# These are added to ScanOrchestrator (scan_orchestrator.py)

orchestrator.run_host_discovery_only(targets, scan_type)          # Discovery only
orchestrator.run_asset_discovery_only(hosts, intensity)            # Port scan selected hosts
orchestrator.run_vulnerability_audit_only(hosts)                    # Vulnerability audit selected hosts
orchestrator.run_phases(targets, phases, scan_type, intensity)     # Flexible combinations
```

### New API Endpoints

```
POST /scan/host-discovery     →  Discovery only
POST /scan/asset-discovery    →  Port scan (pass hosts from host-discovery output)
POST /scan/vulnerability-audit →  Vulnerability + risk scoring (pass hosts from asset-discovery output)
POST /scan/phases             →  Flexible: specify "1", "1+2", or "1+2+3+4"
```

### Typical Frontend Workflow

```
1. POST /scan/host-discovery  →  254 hosts discovered (45 active) in 45s
   User selects 5 hosts they care about
2. POST /scan/asset-discovery  →  Open ports on 5 hosts in 10s
   User identifies 1 critical host
3. POST /scan/vulnerability-audit →  CVEs + risk score on 1 host in 45s
```

### CORS Configuration

The updated `main.py` includes CORS middleware. Update the `allow_origins` list for your frontend:

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

### Files to Replace

| File to replace | Source file |
|----------------|-------------|
| `Backend/orchestrator/scan_orchestrator.py` | `scan_orchestrator_updated.py` |
| `Backend/main.py` | `main_updated.py` |

All existing endpoints (`/scan/host`, `/scan/range`, `/scan/subnet`, `/scan/subnets`) remain unchanged and fully backward-compatible.

---

## API Reference

### `GET /`
Health check. Returns system info and capability flags.

### Legacy Endpoints (All Phases)

**`POST /scan/host`** — Single IP or hostname through all 4 phases.
```json
{ "target": "10.180.6.14", "scan_type": "adaptive" }
```

**`POST /scan/range`** — IP range, Phase 1 (discovery) only.
```json
{ "target": "10.180.6.14-50", "scan_type": "adaptive" }
```

**`POST /scan/subnet`** — CIDR subnet, Phase 1 only.
```json
{ "target": "10.180.6.0/24", "scan_type": "adaptive" }
```

**`POST /scan/subnets`** — Sub-networks within a parent CIDR, Phase 1 only.
```json
{ "target": "10.0.0.0/16", "subnet_prefix": 24, "scan_type": "adaptive" }
```

### Phase-Selective Endpoints (New)

See `API_QUICK_REFERENCE.md` for full request/response schemas, cURL examples, and field reference for all new phase endpoints.

---

## Scan Modes & Intensity

### Scan Types

| Mode | Technique | Requires Root | Requires Scapy |
|---|---|:---:|:---:|
| `tcp` | Async TCP connect | ❌ | ❌ |
| `adaptive` | LAN→ARP, WAN→SYN, fallback→TCP | Preferred | Preferred |
| `arp` | L2 ARP broadcast | ✅ | ✅ |
| `ping` | ICMP echo + timestamp | ✅ | ✅ |
| `full` | ARP + ICMP + SYN + UDP | ✅ | ✅ |
| `stealth` | Fragmented packets, low TTL | ✅ | ✅ |

> Without root or Scapy, all privileged modes auto-downgrade to `tcp`.

### Intensity

| Level | Port List | Use Case |
|---|---|---|
| `light` | 17 critical ports | Fast network triage |
| `normal` | 31 ports (full PORT_DB) | Default, balanced |
| `deep` | 31 ports + thorough probes | Detailed audit |

---

## Understanding Output

### Risk Levels

| Level | Score | Meaning |
|---|---|---|
| `Critical` | 75–100 | Immediate action required |
| `High` | 50–74 | Serious exposure |
| `Medium` | 25–49 | Notable risk |
| `Low` | 10–24 | Minor issues |
| `Info` | 0–9 | Informational |

### Risk Score Composition (0–100)

| Source | Points |
|---|---|
| Critical port open | +25 |
| High-risk port open | +10 |
| Medium-risk port | +5 |
| CVE with CVSS ≥ 9.0 | +20 |
| CVE with CVSS 7.0–8.9 | +10 |
| CVE with CVSS 4.0–6.9 | +5 |
| Each missing HTTP header | +2 |
| Expired TLS cert | +15 |
| Self-signed TLS cert | +10 |
| Weak TLS cipher | +10 |
| TLS grade F | +20 |

### TLS Grades

| Grade | Condition |
|---|---|
| `A` | TLS 1.2/1.3, valid cert, strong ciphers |
| `B` | TLS 1.1 in use |
| `C` | TLS 1.0 / SSLv3 |
| `F` | Expired cert, self-signed, or weak cipher (RC4/DES/NULL/EXPORT) |

---

## Plugin System

Each plugin is a standalone Python module in `engines/vulnerability/plugins/` with one required function:

```python
def run(ip: str, open_ports: List[int], **kwargs) -> Dict:
    ...
```

Return value is a dict whose keys are merged directly onto the host record. Recognised merge keys:

| Key | Type | Description |
|---|---|---|
| `tls_info` | dict | TLSInfo fields |
| `http_audit` | dict | HTTPAudit fields |
| `ssh_info` | dict | SSH negotiation result |
| `smb_info` | dict | SMB probe result |
| `snmp_info` | dict | SNMP community/sysDescr |
| `udp_services` | list | Discovered UDP services |
| `icmp_info` | dict | ICMP timestamp result |
| `cves` | list | CVE dicts from this plugin |

---

## Adding a New Plugin

**Step 1** — Create `engines/vulnerability/plugins/ftp_checker.py`

```python
import socket
from typing import Dict, List

def run(ip: str, open_ports: List[int], **kwargs) -> Dict:
    if 21 not in open_ports:
        return {}
    info = {"anonymous_login": False, "banner": ""}
    try:
        sock = socket.create_connection((ip, 21), timeout=3)
        banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
        info["banner"] = banner
        sock.sendall(b"USER anonymous\r\n")
        r1 = sock.recv(256).decode("utf-8", errors="ignore")
        if r1.startswith("331"):
            sock.sendall(b"PASS anonymous@\r\n")
            r2 = sock.recv(256).decode("utf-8", errors="ignore")
            info["anonymous_login"] = r2.startswith("230")
        sock.close()
    except Exception:
        pass
    return {"ftp_info": info}
```

**Step 2** — Register it in `engines/vulnerability/vulnerability_engine.py`

```python
from engines.vulnerability.plugins import ftp_checker   # add this import

PLUGINS = [
    tls_scanner,
    http_analyzer,
    ssh_probe,
    smb_probe,
    snmp_probe,
    udp_scanner,
    icmp_probe,
    ftp_checker,   # add here
]
```

---

## Configuration Reference

`HostDiscoveryAPI` constructor parameters:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `silent` | bool | `True` | Suppress log output |
| `reports_dir` | str | `"reports"` | PDF output directory |
| `intensity` | str | `"normal"` | `light` / `normal` / `deep` |
| `rate_limit` | float | `200.0` | Token-bucket: probes per second |
| `stealth_mode` | bool | `False` | Enable packet fragmentation evasion |

---

## Privilege Requirements

| Action | Linux/macOS | Windows |
|---|---|---|
| TCP Connect scan | Any user | Any user |
| ARP scan | `root` | Administrator |
| ICMP ping | `root` | Administrator |
| TCP SYN scan | `root` | Administrator + Npcap |
| Packet fragmentation | `root` | Administrator + Npcap |

Without the required privileges the scanner automatically falls back to TCP Connect mode and logs a `privilege_warning` in the metadata response field.

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'fastapi'`**
```bash
pip install fastapi uvicorn
```

**`WARNING: Scapy not found. Raw-socket scans disabled.`**  
Only `adaptive` and `tcp` modes work. Install Scapy if raw-packet scans are needed:
```bash
pip install scapy
# Linux/macOS: run as root
# Windows: also install Npcap from https://npcap.com
```

**OS detection stays unknown**  
The strongest OS fingerprints come from raw packets (ARP/ICMP/SYN via Scapy). In TCP-only mode the scanner falls back to service inference from open ports and banners, but ambiguous hosts may still remain unknown.

**All hosts showing as inactive**  
Check firewall is not blocking outbound TCP on the target ports. Try `scan_type="tcp"` explicitly. Increase timeout by using `intensity="deep"`.

**SNMP not detecting community strings**  
SNMP uses UDP — some firewalls silently drop UDP. Ensure UDP 161 is reachable.

**CORS error in browser console**  
Update `allow_origins` in `main.py` to include your frontend URL and restart the server.

**PDF report not generating**
```bash
pip install reportlab
```

---

## License & Ethics Notice

This tool is intended **exclusively for authorised security assessments** of networks and systems you own or have explicit written permission to test.

Scanning networks without authorisation violates the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), and equivalent laws worldwide.

**Always obtain written authorisation before scanning any network.**
