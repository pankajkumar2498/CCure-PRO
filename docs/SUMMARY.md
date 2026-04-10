# CCure Audit PRO — Project Summary

## What This Is

CCure Audit PRO is a full-stack network vulnerability scanner with:
- **React frontend** (Vite) — multi-step scan wizard, results dashboard, history
- **FastAPI backend** — phase-selective scanning, credentialed SSH scanning, JWT auth, SQLite persistence

---

## Feature Overview

### Scan Modes

| Mode | How | Accuracy | Target |
|------|-----|----------|--------|
| Network Scan — Discovery | ICMP/ARP/TCP | OS: guessed from TTL | Subnet, range, or single IP |
| Network Scan — Port Scan | TCP connect | Banner-based service ID | Selected hosts from Phase 1 |
| Network Scan — Vuln Audit | Banner matching + CVEs | ~30% CVE accuracy | Selected hosts from Phase 2 |
| **Credentialed Scan** | **SSH login** | **~90% CVE accuracy** | **Single Linux host** |

### Scan Pipeline (Network)

```
Phase 1 — Discovery     → /scan/phase1  → finds active hosts on subnet
Phase 2 — Port Scan     → /scan/phase2  → scans selected hosts for open ports
Phase 3 — Vuln Audit    → /scan/phase3  → CVEs, TLS, SSH, HTTP headers, risk score
```

### Credentialed Scan Pipeline (NEW)

```
POST /scan/credentialed →  SSH connect
                        →  Collect: OS, kernel, packages, services, ports,
                                    users, sudo rules, SUID, cron, disk, RAM
                        →  Match packages to CVE database (~90% accuracy)
                        →  Disconnect + wipe credentials
                        →  Return full report
```

---

## Architecture

```
Backend/
├── main.py                      ← FastAPI app, all routes
├── auth/                        ← JWT + bcrypt auth, SQLAlchemy User model
├── scans/                       ← Scan history DB model + router
├── api/                         ← Thin facade over orchestrator
├── orchestrator/                ← Combines engines into scan pipelines
├── engines/
│   ├── discovery/               ← Phase 1: host discovery
│   ├── port/                    ← Phase 2: port scanning
│   ├── vulnerability/           ← Phase 3: CVE + TLS + HTTP + SSH audit
│   │   └── plugins/             ← tls_scanner, http_analyzer, ssh_probe, etc.
│   └── credentialed/            ← NEW: SSH-based deep scanning
│       ├── ssh_scanner.py       ← Paramiko SSH wrapper
│       ├── linux_collector.py   ← 20+ system info collectors
│       └── vuln_matcher.py      ← Package→CVE database matching
└── core/                        ← Constants, models, risk scoring, utils

Frontend/
├── src/
│   ├── pages/
│   │   ├── scan/
│   │   │   ├── NewScan.jsx            ← Network scan form
│   │   │   ├── Phase1Results.jsx      ← Host discovery results
│   │   │   ├── Phase2Results.jsx      ← Port scan results
│   │   │   ├── Phase3Results.jsx      ← Vulnerability audit results
│   │   │   ├── CredentialedScan.jsx   ← NEW: SSH scan form
│   │   │   └── CredentialedResults.jsx ← NEW: SSH scan results
│   │   ├── Login.jsx
│   │   ├── Register.jsx
│   │   └── ScanHistory.jsx
│   ├── components/
│   │   ├── layout/
│   │   │   ├── AppShell.jsx           ← UPDATED: added Credentialed nav
│   │   │   └── ScanStepper.jsx
│   │   └── scan/
│   │       ├── RiskBadge.jsx
│   │       └── ExportPanel.jsx
│   ├── api/
│   │   ├── axiosInstance.js
│   │   ├── auth.js
│   │   ├── scans.js
│   │   └── credentialedScan.js        ← NEW: API wrapper
│   ├── context/
│   │   ├── AuthContext.jsx
│   │   └── ScanContext.jsx
│   ├── App.jsx                        ← UPDATED: new routes
│   └── index.css                      ← UPDATED: credentialed styles appended
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Vite, React Router v6 |
| Backend | FastAPI 0.111, Uvicorn, Pydantic v2 |
| Auth | JWT (python-jose), bcrypt (passlib) |
| Database | SQLite via SQLAlchemy 2.0 |
| Network scanning | asyncio, Scapy (optional), stdlib sockets |
| SSH scanning | Paramiko 3.4 (optional — only for credentialed) |
| PDF reports | ReportLab |
| Styling | Custom CSS (no framework), Share Tech Mono + Outfit fonts |

---

## Security Design

### Authentication
- JWT tokens (15 minute access + 7 day refresh)
- bcrypt password hashing
- All scan endpoints require valid JWT

### Credential Handling (Credentialed Scan)
- **Option A**: Credentials never stored
- Password exists only in request body and `SSHScanner._password` during connection
- `SSHScanner.disconnect()` zeroes `self._password = None`
- Nothing credential-related is written to DB, logs, or response

### Data Storage
- All scan results in `ccure_users.db` (SQLite)
- Users own their scans — cross-user access returns 404
- Credentials: zero persistence

---

## Running the Project

### Backend

```bash
cd Backend
pip install -r requirements.txt
pip install paramiko==3.4.0   # for credentialed scanning
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Swagger UI: http://localhost:8000/docs

### Frontend

```bash
cd Frontend
npm install
npm run dev
```

App: http://localhost:5173

---

## What Credentialed Scanning Gives You

| Data Point | Without SSH | With SSH (Credentialed) |
|-----------|-------------|------------------------|
| OS version | "Linux" (TTL guess) | "Ubuntu 22.04.3 LTS" |
| Kernel | Unknown | "5.15.0-91-generic" |
| Open ports | TCP connect scan | Real socket table |
| Installed packages | Unknown | Full dpkg/rpm list with versions |
| CVE accuracy | ~30% | ~90% |
| Running services | Banner grab only | Full systemctl list |
| Users | Unknown | /etc/passwd |
| Sudo config | Unknown | sudo -l output |
| SUID binaries | Unknown | find / -perm -4000 |
| Cron jobs | Unknown | crontab -l + /etc/cron* |
| Failed logins | Unknown | lastb / journald |
| World-writable dirs | Unknown | find / -perm -0002 |
