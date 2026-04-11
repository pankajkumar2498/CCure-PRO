# CCure Audit PRO — Quick Reference

## Starting the App

```bash
# Backend
cd Backend && uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Frontend (separate terminal)
cd Frontend && npm run dev

# URLs
Backend API:   http://localhost:8000
Swagger UI:    http://localhost:8000/docs
Frontend:      http://localhost:5173
```

---

## All API Endpoints

```
GET  /                          Health check + system info
POST /auth/register             Register new user
POST /auth/login                Login → returns JWT token

# Network scan (unauthenticated — banner-based, ~30% CVE accuracy)
POST /scan/host-discovery      Host Discovery: discover active hosts
POST /scan/asset-discovery     Asset Discovery: port scanning
POST /scan/advanced-scan       Advanced Scan: vulnerability audit + risk scoring
POST /scan/phases               Flexible: run any phase combination
POST /scan/host                 Legacy: all 4 phases on single host
POST /scan/range                Legacy: IP range discovery
POST /scan/subnet               Legacy: CIDR subnet discovery
POST /scan/subnets              Legacy: sub-networks of a parent CIDR

# Credentialed scan (SSH-based, ~90% CVE accuracy) — NEW
POST /scan/credentialed         SSH login → full system info + package CVEs

# Scan history
GET  /scans                     List user's past scans
GET  /scans/{id}                Get single scan with full results
DELETE /scans/{id}              Delete a scan

# Reports
GET  /reports/download/{scan_id}   Download PDF report
```

All scan and history endpoints require `Authorization: Bearer <token>`.

---

## Credentialed Scan — Quick Usage

```bash
curl -X POST http://localhost:8000/scan/credentialed \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "ip":       "192.168.1.10",
    "username": "root",
    "password": "mysecretpass"
  }'
```

Sections (all collected by default, can limit):
`system_info | packages | services | ports | users | security | network | history`

**Credentials are never stored.** Used for SSH session only, then discarded.

---

## Network Scan — Typical Flow

```bash
# 1. Discover hosts
POST /scan/host-discovery  {"targets": ["192.168.1.0/24"], "scan_type": "adaptive"}

# 2. Port scan selected hosts (use host objects from host-discovery data[])
POST /scan/asset-discovery  {"hosts": [...], "intensity": "normal", "scan_id": 1}

# 3. Vulnerability audit (use host objects from asset-discovery data[])
POST /scan/advanced-scan  {"hosts": [...], "scan_id": 1}
```

---

## Frontend Pages

| URL | Page | Purpose |
|-----|------|---------|
| `/scan` | Network Scan | Enter target subnet, start scan wizard |
| `/scan/host-discovery` | Discovery Results | View discovered hosts, select for port scan |
| `/scan/asset-discovery` | Port Results | View open ports, select for deep audit |
| `/scan/advanced-scan` | Vulnerability Audit | CVEs, TLS, SSH, HTTP header audit |
| `/scan/credentialed` | Credentialed Scan | SSH scan form — IP, username, password |
| `/scan/credentialed/results` | SSH Results | Full system info, package CVEs, security audit |
| `/history` | Scan History | Past scans with delete |

---

## Scan Mode Comparison

| | Network Scan | Credentialed Scan |
|--|-------------|------------------|
| Target | Subnet/range/IP | Single Linux host |
| Auth needed on target | No | Yes (SSH) |
| CVE accuracy | ~30% | ~90% |
| OS detection | Guessed (TTL) | Exact |
| Packages | Unknown | Full list |
| Services | Port banners | systemctl list |
| Security audit | No | SUID, sudo, cron |
| Scan time | 30s–2min | 15–45s |

---

## Key Files (New / Changed)

```
Backend/engines/credentialed/
  ssh_scanner.py              ← NEW: Paramiko SSH wrapper
  linux_collector.py          ← NEW: Linux system data collector
  vuln_matcher.py             ← NEW: Package → CVE matching

Backend/main_credentialed_additions.py
                              ← NEW: Exact code to paste into main.py

Frontend/src/pages/scan/
  CredentialedScan.jsx        ← NEW: Scan form page
  CredentialedResults.jsx     ← NEW: Results display page

Frontend/src/api/
  credentialedScan.js         ← NEW: API wrapper

Frontend/src/App.jsx          ← UPDATED: +2 routes
Frontend/src/components/layout/AppShell.jsx
                              ← UPDATED: +1 nav link
Frontend/src/credentialed_styles_append.css
                              ← NEW: Append to index.css
```

---

## Requirements

### Backend

```
paramiko==3.4.0    # ADD THIS — SSH client for credentialed scanning
```

Full list in `Backend/requirements.txt`.

### Frontend

No new npm packages needed. Uses existing React + React Router.

---

## Common Errors

| Error | Fix |
|-------|-----|
| `503 paramiko not installed` | `pip install paramiko==3.4.0` |
| `400 Cannot reach X:22` | Host down or SSH port blocked; try `nc -zv <ip> 22` |
| `400 Authentication failed` | Wrong username/password; test with `ssh user@host` manually |
| `401 Unauthorized` | JWT expired; log in again |
| Empty packages in results | Try as root — some package managers need elevated access |
| CORS errors in browser | Add your frontend URL to `allow_origins` in `main.py` |
