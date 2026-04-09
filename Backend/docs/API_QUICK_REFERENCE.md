# Ccure Audit Pro — API Quick Reference

## Quick Start

```bash
cd Backend
python -m uvicorn main:app --reload

# Server:      http://localhost:8000
# Swagger UI:  http://localhost:8000/docs
```

---

## All Endpoints at a Glance

### System
```
GET /                        Health check + system info + capability flags
GET /docs                    Swagger UI (interactive)
GET /redoc                   ReDoc (alternative docs)
GET /api/workflow-example    Workflow usage example
```

### Legacy Endpoints (All 4 Phases — Unchanged)
```
POST /scan/host              Single IP or hostname, all 4 phases
POST /scan/range             IP range, Phase 1 (discovery) only
POST /scan/subnet            CIDR subnet, Phase 1 only
POST /scan/subnets           Sub-networks grouped by subnet, Phase 1 only
```

### Phase-Selective Endpoints (New)
```
POST /scan/phase1            Phase 1 only — Discovery
POST /scan/phase2            Phase 2 only — Port Scanning
POST /scan/phase3            Phase 3 + 4 — Vulnerability + Risk Scoring
POST /scan/phases            Flexible — specify which phases to run
```

---

## Phase-Selective Endpoint Details

### POST /scan/phase1 — Discovery

**Request:**
```json
{
  "targets": ["192.168.1.0/24", "10.0.0.1-50", "192.168.2.10"],
  "scan_type": "adaptive"
}
```

Scan types: `ping | arp | tcp | full | adaptive | stealth`

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "ip_address": "192.168.1.10",
      "is_active": true,
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "status": "Active",
      "hostname": "server.local",
      "confidence": "High",
      "os_guess": "Linux",
      "os_confidence": "Medium",
      "open_ports": [],
      "host_risk_score": 0,
      "host_risk_level": "Info"
    }
  ],
  "summary": {
    "total_hosts": 254,
    "active_hosts": 45,
    "inactive_hosts": 209,
    "phase": 1,
    "scan_duration": 35.2
  }
}
```

---

### POST /scan/phase2 — Port Scanning

**Request** (pass host objects from Phase 1 `data[]`):
```json
{
  "hosts": [
    {
      "ip_address": "192.168.1.10",
      "is_active": true,
      "mac_address": "aa:bb:cc:dd:ee:ff"
    }
  ],
  "intensity": "normal"
}
```

Intensities: `light | normal | deep`

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "ip_address": "192.168.1.10",
      "is_active": true,
      "open_ports": [
        { "port": 22, "service": "ssh", "banner": "OpenSSH 7.4 (protocol 2.0)" },
        { "port": 80, "service": "http", "banner": "Apache/2.4.6" }
      ],
      "host_risk_score": 45,
      "host_risk_level": "Medium"
    }
  ],
  "summary": {
    "total_hosts": 5,
    "hosts_with_ports": 5,
    "phase": 2,
    "scan_duration": 8.5
  }
}
```

---

### POST /scan/phase3 — Vulnerability + Risk Scoring

**Request** (pass host objects from Phase 2 `data[]`):
```json
{
  "hosts": [
    {
      "ip_address": "192.168.1.10",
      "is_active": true,
      "open_ports": [
        { "port": 22, "service": "ssh", "banner": "OpenSSH 7.4" }
      ]
    }
  ]
}
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "ip_address": "192.168.1.10",
      "is_active": true,
      "open_ports": ["..."],
      "tls_info": { "version": "TLSv1.2", "cipher": "ECDHE-RSA-AES256-GCM-SHA384", "score": "A" },
      "ssh_info": { "version": "2.0", "banner": "OpenSSH 7.4", "algorithms": {} },
      "http_audit": { "hsts": true, "csp": false, "issues": ["Missing Content-Security-Policy"] },
      "cves": [
        {
          "cve_id": "CVE-2018-15473",
          "severity": "High",
          "description": "OpenSSH username enumeration",
          "cvss_score": 7.5
        }
      ],
      "host_risk_score": 82,
      "host_risk_level": "Critical"
    }
  ],
  "summary": {
    "total_hosts": 1,
    "critical_hosts": 1,
    "phase": 3,
    "scan_duration": 45.2
  }
}
```

---

### POST /scan/phases — Flexible

```json
{
  "targets": ["192.168.1.0/24"],
  "phases": "1+2+3+4",
  "scan_type": "adaptive",
  "intensity": "deep"
}
```

`phases` options: `"1"` | `"1+2"` | `"1+2+3+4"`

---

## Legacy Endpoint Details

### POST /scan/host — Single host, all 4 phases

```json
{ "target": "192.168.1.1", "scan_type": "adaptive" }
```

### POST /scan/range

```json
{ "target": "192.168.1.1-50", "scan_type": "adaptive" }
```

### POST /scan/subnet

```json
{ "target": "192.168.1.0/24", "scan_type": "adaptive" }
```

### POST /scan/subnets

```json
{ "target": "10.0.0.0/16", "subnet_prefix": 24, "scan_type": "adaptive" }
```

---

## cURL Examples

```bash
# Health check
curl http://localhost:8000/

# Phase 1: Discover hosts
curl -X POST http://localhost:8000/scan/phase1 \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.0/24"], "scan_type": "adaptive"}'

# Phase 2: Port scan (paste Phase 1 data[] as hosts value)
curl -X POST http://localhost:8000/scan/phase2 \
  -H "Content-Type: application/json" \
  -d '{"hosts": [...], "intensity": "normal"}'

# Phase 3: Vulnerability scan (paste Phase 2 data[] as hosts value)
curl -X POST http://localhost:8000/scan/phase3 \
  -H "Content-Type: application/json" \
  -d '{"hosts": [...]}'

# Full scan in one call
curl -X POST http://localhost:8000/scan/phases \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.10"], "phases": "1+2+3+4", "scan_type": "adaptive", "intensity": "normal"}'
```

---

## JavaScript Integration

```javascript
const API = 'http://localhost:8000';

async function discover(targets) {
  const res = await fetch(`${API}/scan/phase1`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ targets, scan_type: 'adaptive' })
  });
  return res.json();
}

async function portScan(hosts, intensity = 'normal') {
  const res = await fetch(`${API}/scan/phase2`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hosts, intensity })
  });
  return res.json();
}

async function vulnScan(hosts) {
  const res = await fetch(`${API}/scan/phase3`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hosts })
  });
  return res.json();
}

// Typical flow
const phase1 = await discover(['192.168.1.0/24']);
const active = phase1.data.filter(h => h.is_active);
const phase2 = await portScan(active.slice(0, 5), 'normal');
const phase3 = await vulnScan([phase2.data[0]]);
```

---

## Error Responses

```json
{ "success": false, "error": "Invalid target format: 'example.local' not found" }
{ "success": false, "error": "Invalid phases: 5. Use '1', '1+2', '1+2+3+4', etc." }
{ "success": false, "error": "No valid targets to scan." }
```

| HTTP Code | Meaning |
|-----------|---------|
| 200 | Success |
| 400 | Bad request — invalid target, empty hosts, malformed JSON |
| 503 | API not initialised yet — wait a moment and retry |

---

## Field Reference

### Host Object (Phase 1 output)
```
ip_address       string    IP address
is_active        bool      Host is responding
mac_address      string    MAC (ARP scan only; "N/A" otherwise)
status           string    "Active" | "Inactive"
hostname         string    Reverse DNS result
confidence       string    "High" | "Medium" | "Low"
os_guess         string    OS identification
os_confidence    string    "High" | "Medium" | "Low"
open_ports       array     Empty at Phase 1
host_risk_score  int       0–100 (0 at Phase 1)
host_risk_level  string    "Critical" | "High" | "Medium" | "Low" | "Info"
```

### Port Object (Phase 2 output)
```
port     int     Port number
service  string  Service name from PORT_DB
banner   string  Raw banner grabbed during scan
```

### CVE Object (Phase 3 output)
```
cve_id       string  CVE identifier, e.g. "CVE-2018-15473"
severity     string  "Critical" | "High" | "Medium" | "Low"
description  string  Short description
cvss_score   float   CVSS score (0.0–10.0)
```

---

## Typical Scan Times

| Phase | Target | Time |
|-------|--------|------|
| Phase 1 (Discovery) | /24 subnet (254 hosts) | 30–60 seconds |
| Phase 2 (Ports) | 5 hosts, normal intensity | 8–15 seconds |
| Phase 3 (Vuln) | 1 host | 30–90 seconds |
| **Total** | 5 hosts, 1 deep audit | **~2 minutes** |

---

## Valid Target Formats

| Format | Example |
|--------|---------|
| Single IP | `192.168.1.10` |
| CIDR | `192.168.1.0/24`, `10.0.0.0/16` |
| Range | `192.168.1.1-50` |
| Hostname | `server.local` (resolved via DNS) |

---

## CORS Setup

```python
# main.py
allow_origins=[
    "http://localhost:3000",      # React dev
    "http://localhost:5173",      # Vite dev
    "https://yourdomain.com",     # Production
]
```

---

## Tips

- Phase 1 is fast — always run it first to get the host list before committing to deeper scans
- Phase 2 is selective — only port scan the hosts you actually care about
- Phase 3 is expensive — reserve for 1–3 critical hosts at a time
- Use `light` intensity for speed, `deep` for thoroughness, `normal` for balanced results
- Interactive docs at `http://localhost:8000/docs` let you test all endpoints in the browser
