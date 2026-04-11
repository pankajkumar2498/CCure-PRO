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

### Phase-Selective Endpoints
```
POST /scan/host-discovery    Host Discovery only — Discovery
POST /scan/asset-discovery   Asset Discovery only — Port Scanning
POST /scan/advanced-scan     Advanced Scan only — Vulnerability + Risk Scoring
POST /scan/phases            Flexible — specify which phases to run
```

### Credentialed Scan Endpoint (NEW)
```
POST /scan/credentialed      SSH login → full system collection → package CVE matching
```

---

## Credentialed Scan — POST /scan/credentialed

### Overview

| Attribute          | Unauthenticated         | Credentialed SSH         |
|--------------------|-------------------------|--------------------------|
| OS Name            | TTL guess (~"Linux")    | Exact: Ubuntu 22.04.3 LTS |
| Kernel             | Unknown                 | Exact: 5.15.0-91-generic  |
| Open Ports         | TCP connect scan        | Live socket table via ss  |
| Running Services   | Banner grab only        | Full systemctl list       |
| Installed Packages | Unknown                 | Full dpkg/rpm list        |
| CVE Accuracy       | ~30% (banner guessing)  | ~90% (real pkg versions)  |
| Users              | Unknown                 | /etc/passwd analysis      |
| Sudo Rules         | Unknown                 | sudo -l output            |
| SUID Binaries      | Unknown                 | find / -perm -4000        |

**Security model: Option A — credentials are NEVER stored.**
They are transmitted in the request, used for the SSH session lifetime, and
immediately discarded. Nothing is saved to the database except the scan results.

### Request

```json
POST /scan/credentialed
Authorization: Bearer <token>

{
  "ip":          "192.168.1.10",
  "username":    "root",
  "password":    "mysecretpass",
  "port":        22,
  "auth_method": "password",
  "sections":    null
}
```

| Field         | Type             | Required | Description |
|---------------|------------------|----------|-------------|
| `ip`          | string           | ✓        | Target IP or hostname |
| `username`    | string           | ✓        | SSH username |
| `password`    | string           | if auth_method=password | SSH password (discarded after use) |
| `key_path`    | string           | if auth_method=key | Path to SSH private key |
| `port`        | int (1–65535)    | –        | SSH port (default: 22) |
| `auth_method` | "password"/"key" | –        | Auth method (default: "password") |
| `sections`    | string[] / null  | –        | Data categories to collect. null = all |

**sections values:** `system_info` | `packages` | `services` | `ports` | `users` | `security` | `network` | `history`

### Response

```json
{
  "success":     true,
  "scan_id":     42,
  "scan_type":   "credentialed",
  "target":      "192.168.1.10",
  "username":    "root",

  "system_info": {
    "os_name":        "Ubuntu 22.04.3 LTS",
    "os_version_id":  "22.04",
    "kernel_version": "5.15.0-91-generic",
    "hostname":       "webserver-01.local",
    "uptime":         "up 14 days, 3 hours",
    "cpu_model":      "Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz",
    "cpu_count":      "4",
    "cpu_arch":       "x86_64",
    "memory_summary": { "total": "8.0G", "used": "2.1G", "free": "5.9G" },
    "disk_usage": [
      { "filesystem": "/dev/sda1", "size": "100G", "used": "62G", "use_pct": "63%", "mounted_on": "/" }
    ]
  },

  "packages":     [ { "name": "openssl", "version": "1.1.1f", "manager": "dpkg" }, "..." ],
  "package_count": 247,

  "running_services": [
    { "name": "nginx.service",      "description": "A high performance web server" },
    { "name": "postgresql.service", "description": "PostgreSQL RDBMS" }
  ],

  "open_ports_credentialed": [
    { "state": "LISTEN", "local_addr": "0.0.0.0:22",  "port": "22",  "process": "sshd" },
    { "state": "LISTEN", "local_addr": "0.0.0.0:80",  "port": "80",  "process": "nginx" },
    { "state": "LISTEN", "local_addr": "0.0.0.0:443", "port": "443", "process": "nginx" }
  ],

  "users": [
    { "username": "root", "uid": "0", "shell": "/bin/bash", "is_root": true },
    { "username": "deploy", "uid": "1001", "shell": "/bin/bash", "is_root": false }
  ],

  "suid_binaries":       [ "/usr/bin/sudo", "/usr/bin/passwd", "..." ],
  "world_writable_dirs": [ "/tmp", "/var/tmp" ],
  "sudo_nopasswd":       false,
  "sudo_rules_raw":      "User root may run the following commands:\n    (ALL : ALL) ALL",
  "security_issues":     [],

  "failed_login_count":   847,
  "brute_force_warning":  true,
  "failed_logins_recent": [ "root     ssh:notty    192.168.50.10  Thu Apr 10 14:22 - 14:22", "..." ],

  "cves": [
    {
      "cve_id":        "CVE-2022-0778",
      "severity":      "High",
      "cvss_score":    7.5,
      "description":   "Infinite loop in BN_mod_sqrt() allows denial of service via crafted certificate.",
      "package":       "openssl",
      "installed_ver": "1.1.1f",
      "fixed_ver":     "1.1.1o",
      "source":        "package_version_match"
    }
  ],
  "cve_count":    3,
  "severity_summary": { "Critical": 0, "High": 2, "Medium": 1, "Low": 0, "Info": 0 },

  "scan_duration": 18.4
}
```

### Error Responses

```json
{ "detail": "Cannot reach 192.168.1.10:22 — host is down or port is closed." }
{ "detail": "SSH authentication failed for root@192.168.1.10: Authentication failed." }
{ "detail": "Credentialed scanning requires paramiko. Run: pip install paramiko==3.4.0" }
```

| HTTP Code | Cause |
|-----------|-------|
| 200 | Success |
| 400 | SSH auth failed, host unreachable, invalid target |
| 401 | Not logged in (missing/invalid JWT) |
| 503 | paramiko not installed |

---

## Phase-Selective Endpoint Details (unchanged)

### POST /scan/host-discovery — Discovery

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
  "scan_id": 1,
  "data": [
    {
      "ip_address": "192.168.1.10",
      "is_active": true,
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "hostname": "server.local",
      "os_guess": "Linux",
      "open_ports": [],
      "host_risk_score": 0,
      "host_risk_level": "Info"
    }
  ],
  "summary": { "total_hosts": 254, "active_hosts": 45, "scan_duration": 35.2 }
}
```

### POST /scan/asset-discovery — Port Scanning

```json
{
  "hosts": [ { "ip_address": "192.168.1.10", "is_active": true } ],
  "intensity": "normal",
  "scan_id": 1
}
```

Intensities: `light | normal | deep`

### POST /scan/advanced-scan — Vulnerability + Risk Scoring

```json
{
  "hosts": [ { "ip_address": "192.168.1.10", "open_ports": [ { "port": 22, "service": "ssh" } ] } ],
  "scan_id": 1
}
```

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

## cURL Examples

```bash
# Health check
curl http://localhost:8000/

# Credentialed scan — password auth
curl -X POST http://localhost:8000/scan/credentialed \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "ip": "192.168.1.10",
    "username": "root",
    "password": "mysecretpass",
    "port": 22
  }'

# Credentialed scan — specific sections only
curl -X POST http://localhost:8000/scan/credentialed \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "ip": "192.168.1.10",
    "username": "ubuntu",
    "password": "pass",
    "sections": ["system_info", "packages", "security"]
  }'

# Phase 1: Discover hosts
curl -X POST http://localhost:8000/scan/host-discovery \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"targets": ["192.168.1.0/24"], "scan_type": "adaptive"}'
```

---

## JavaScript Integration

```javascript
const API   = 'http://localhost:8000';
const TOKEN = localStorage.getItem('token');
const hdrs  = { 'Content-Type': 'application/json', 'Authorization': `Bearer ${TOKEN}` };

// Credentialed scan
async function credentialedScan(ip, username, password) {
  const res = await fetch(`${API}/scan/credentialed`, {
    method:  'POST',
    headers: hdrs,
    body:    JSON.stringify({ ip, username, password, port: 22 }),
  });
  return res.json();
}

// Unauthenticated workflow
async function discover(targets) {
  const res = await fetch(`${API}/scan/host-discovery`, {
    method: 'POST', headers: hdrs,
    body: JSON.stringify({ targets, scan_type: 'adaptive' })
  });
  return res.json();
}
```

---

## Typical Scan Times

| Scan Type           | Target              | Time           |
|---------------------|---------------------|----------------|
| Host Discovery      | /24 subnet (254 hosts) | 30–60 seconds |
| Asset Discovery     | 5 hosts, normal     | 8–15 seconds   |
| Advanced Scan       | 1 host              | 30–90 seconds  |
| **Credentialed**    | **1 host**          | **15–45 seconds** |

Credentialed scans are always single-host (SSH is inherently one machine at a time).

---

## Field Reference

### Credentialed CVE Object
```
cve_id        string    CVE identifier e.g. "CVE-2022-0778"
severity      string    "Critical" | "High" | "Medium" | "Low" | "Info"
cvss_score    float     CVSS score (0.0–10.0)
description   string    Short description
package       string    Package name where vulnerability was found
installed_ver string    Installed version on the scanned host
fixed_ver     string    Version that fixes the CVE (upgrade target)
source        string    "package_version_match" (for credentialed) vs "banner_match"
```

### Host Object (Phase 1 output)
```
ip_address       string    IP address
is_active        bool      Host is responding
mac_address      string    MAC (ARP scan only)
hostname         string    Reverse DNS result
os_guess         string    OS identification
open_ports       array     Empty at Phase 1
host_risk_score  int       0–100
host_risk_level  string    "Critical" | "High" | "Medium" | "Low" | "Info"
```

---

## Tips

- **Credentialed scan first, network scan second** — use `/scan/host-discovery` to find hosts, then pick one for a credentialed deep dive
- Use `sections: ["packages", "security"]` for a targeted package + CVE check without collecting everything
- Host discovery is fast — always run it first to get the host list before committing to deeper scans
- Advanced scan is expensive — reserve it for 1–3 critical hosts at a time
- Interactive docs at `http://localhost:8000/docs` let you test all endpoints in the browser

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
