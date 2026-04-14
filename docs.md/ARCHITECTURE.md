# CCure Audit PRO — Architecture Overview

**Version:** 1.0.0  
**Classification:** Internal Technical Reference  
**Scope:** Full-stack network vulnerability scanning platform

---

## 1. System Philosophy

CCure Audit PRO is a **frontend-orchestrated, phase-selective vulnerability scanner**. Unlike monolithic scanners that execute a fixed pipeline per request, CCure decouples scan phases so the frontend drives execution order and the user decides which phases to run. This design mirrors the professional model used by tools like Nessus and CAST — where scan policies are selected before execution and results are progressively enriched.

The core principle is **progressive disclosure**: start fast with host discovery, then optionally deepen into port scanning, and finally into full vulnerability auditing — each phase building on the previous.

---

## 2. High-Level Component Map

```
┌──────────────────────────────────────────────────────────────────────┐
│                        CCure Audit PRO                               │
│                                                                      │
│  ┌─────────────────────────┐    ┌────────────────────────────────┐  │
│  │      Frontend (React)   │    │       Backend (FastAPI)         │  │
│  │                         │    │                                │  │
│  │  ┌──────────────────┐   │    │  ┌──────────────────────────┐  │  │
│  │  │   ScanContext    │◄──┼────┼─►│   ScanOrchestrator       │  │  │
│  │  │  (State Mgr)     │   │    │  │   (Phase Controller)     │  │  │
│  │  └──────────────────┘   │    │  └──────────────────────────┘  │  │
│  │                         │    │         │                       │  │
│  │  ┌──────────────────┐   │    │  ┌──────▼───────────────────┐  │  │
│  │  │   AuthContext    │◄──┼────┼─►│   DiscoveryEngine (Ph1)  │  │  │
│  │  │  (JWT Tokens)    │   │    │  └──────────────────────────┘  │  │
│  │  └──────────────────┘   │    │  ┌──────────────────────────┐  │  │
│  │                         │    │  │   PortEngine      (Ph2)  │  │  │
│  │  ┌──────────────────┐   │    │  └──────────────────────────┘  │  │
│  │  │   scanConfig.js  │   │    │  ┌──────────────────────────┐  │  │
│  │  │  (Pipeline Map)  │   │    │  │ VulnerabilityEngine(Ph3) │  │  │
│  │  └──────────────────┘   │    │  │   + Plugin Registry      │  │  │
│  │                         │    │  └──────────────────────────┘  │  │
│  │  Pages / Views:         │    │  ┌──────────────────────────┐  │  │
│  │  - Dashboard            │    │  │  CredentialedEngine(Ph4) │  │  │
│  │  - NewScan              │    │  │  SSHScanner+Collectors   │  │  │
│  │  - Phase1..4 Results   │    │  └──────────────────────────┘  │  │
│  │  - CredentialedResults  │    │                                │  │
│  │  - ScanHistory          │    │  ┌──────────────────────────┐  │  │
│  │  - ArchivedScans        │    │  │      Persistence Layer   │  │  │
│  │  - RecycleBin           │    │  │  SQLite (ccure_users.db) │  │  │
│  │  - SecurityReports      │    │  │  Scans + ScanPhaseResult │  │  │
│  └─────────────────────────┘    │  └──────────────────────────┘  │  │
│                                 │  ┌──────────────────────────┐  │  │
│                                 │  │      CVE Database        │  │  │
│                                 │  │  SQLite (cves.db)        │  │  │
│                                 │  │  NVD-sourced             │  │  │
│                                 │  └──────────────────────────┘  │  │
│                                 │  ┌──────────────────────────┐  │  │
│                                 │  │    PDF Report Generator  │  │  │
│                                 │  │  (reportlab — JSON/XML)  │  │  │
│                                 │  └──────────────────────────┘  │  │
│                                 └────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Pipeline Modes

Three scan templates are available. The `pipeline_mode` field is sent by the frontend with every request and controls backend phase validation and scan-record lifecycle.

| Mode       | Phases Executed | Terminal Phase | Use Case                                      |
|------------|-----------------|----------------|-----------------------------------------------|
| `basic`    | Phase 1         | Phase 1        | Fast host inventory — is it alive?            |
| `asset`    | Phase 1 → 2     | Phase 2        | Asset map with open ports and service banners |
| `advanced` | Phase 1 → 2 → 3 | Phase 3        | Full vulnerability audit with risk scoring    |

> **Note:** Phase 4 (Risk Report) is conceptually a sub-phase of Phase 3. The backend VulnerabilityEngine runs both vulnerability detection and CVSS-weighted risk scoring in the same execution step. The frontend renders Phase 4 as a separate results view.

---

## 4. Scan Pipeline Lifecycle

The following sequence describes an **Advanced Scan** (all phases) from browser click to stored report.

```
Browser                 Frontend (React)              Backend (FastAPI)
  │                           │                              │
  │  Click "Start Scan"       │                              │
  │──────────────────────────►│                              │
  │                           │  POST /scan/host-discovery   │
  │                           │  { targets, scan_type,       │
  │                           │    pipeline_mode: "advanced"}│
  │                           │─────────────────────────────►│
  │                           │                              │ DiscoveryEngine.run()
  │                           │                              │ ARP/ICMP/TCP probes
  │                           │                              │ → host dicts
  │                           │  200 { data, summary,        │
  │                           │        scan_id }             │
  │                           │◄─────────────────────────────│
  │  Phase 1 Results shown    │                              │
  │◄──────────────────────────│                              │
  │                           │                              │
  │  Click "Run Port Scan"    │                              │
  │──────────────────────────►│                              │
  │                           │  POST /scan/asset-discovery  │
  │                           │  { hosts, scan_id,           │
  │                           │    pipeline_mode: "advanced"}│
  │                           │─────────────────────────────►│
  │                           │                              │ PortEngine.run()
  │                           │                              │ TCP connect + banner grab
  │                           │                              │ UDP probe (DNS/SNMP/NTP)
  │                           │  200 { data, summary }       │
  │                           │◄─────────────────────────────│
  │  Phase 2 Results shown    │                              │
  │◄──────────────────────────│                              │
  │                           │                              │
  │  Click "Run Vuln Scan"    │                              │
  │──────────────────────────►│                              │
  │                           │  POST /scan/advanced-scan    │
  │                           │  { hosts, scan_id,           │
  │                           │    pipeline_mode: "advanced"}│
  │                           │─────────────────────────────►│
  │                           │                              │ VulnerabilityEngine.run()
  │                           │                              │ Plugins: TLS, HTTP, SSH,
  │                           │                              │ SMB, SNMP, UDP, ICMP, FTP
  │                           │                              │ CVE lookup via cves.db
  │                           │                              │ Risk scoring (0-100)
  │                           │                              │ PDF report generated
  │                           │  200 { data, summary,        │
  │                           │        reports }             │
  │                           │◄─────────────────────────────│
  │  Phase 3+4 Results shown  │                              │
  │◄──────────────────────────│                              │
```

---

## 5. Authentication Architecture

CCure uses a **stateless JWT access token + server-side refresh token** model.

- **Access Token:** Short-lived JWT (signed with HS256). Sent in `Authorization: Bearer <token>` header on every API call. Contains `sub` (user_id) and `username`.
- **Refresh Token:** Long-lived opaque token stored in the database. Delivered as an `HttpOnly` cookie named `ccure_refresh_token`. Used to rotate and obtain a new access token without re-login. Token rotation invalidates the previous refresh token on use.
- **Credential Security:** Passwords are hashed with bcrypt. Credentials for credentialed scans are **never persisted** — they are used only for the duration of the SSH session.

---

## 6. Data Storage

All persistent data lives in a single SQLite file: `Backend/ccure_users.db`.

| Table               | Purpose                                                   |
|---------------------|-----------------------------------------------------------|
| `users`             | Account records (id, username, email, password_hash)      |
| `refresh_tokens`    | Server-side refresh token store (for revocation)          |
| `scans`             | One row per scan session; tracks pipeline_mode, status    |
| `scan_phase_results`| One row per phase per scan; stores JSON payload per phase |

The CVE knowledge base is stored in a separate `Backend/cves.db` SQLite file, populated from the NVD (National Vulnerability Database) via `scripts/download_nvd.py`.

---

## 7. Report Generation

After each phase completes, the backend optionally generates a PDF report using `reportlab`. Two report formats are produced per scan:

- **JSON-style PDF** — structured tabular layout of scan results
- **XML-style PDF** — hierarchical layout reflecting raw scan data

Report files are written to `Backend/reports/` and their paths are stored in the `scans` table (`report_json_path`, `report_xml_path`). Reports are served via `GET /reports/download/{scan_id}?fmt=JSON|XML`.

---

## 8. Technology Stack

| Layer        | Technology                                  |
|--------------|---------------------------------------------|
| Frontend     | React 18, React Router v6, Axios, Vite      |
| Backend API  | FastAPI 0.111, Uvicorn, Python 3.12         |
| ORM / DB     | SQLAlchemy 2.0, SQLite                      |
| Auth         | python-jose (JWT), passlib + bcrypt         |
| Packet Craft | Scapy 2.5+ (ARP/ICMP/SYN — requires root)  |
| SSH          | Paramiko 3.4.0                              |
| PDF Reports  | reportlab 4.4.0                             |
| Port Scan    | asyncio TCP connect (unprivileged)          |

---

## 9. Privilege Requirements

| Scan Mode             | Root / Admin Required | Fallback Behaviour                      |
|-----------------------|-----------------------|-----------------------------------------|
| ARP Discovery         | Yes                   | Auto-switches to TCP connect            |
| ICMP Ping             | Yes                   | Auto-switches to TCP connect            |
| TCP Connect           | No                    | Full functionality                      |
| SYN Stealth / FULL    | Yes                   | Auto-switches to TCP connect            |
| Adaptive (LAN)        | Yes (for ARP leg)     | Degrades gracefully to TCP if no priv   |
| Credentialed SSH Scan | No (SSH creds only)   | Requires target SSH access              |
