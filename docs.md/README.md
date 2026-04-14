# CCure Audit PRO — Documentation Suite

**Version:** 1.1.0  
**Platform:** Network Vulnerability Scanner  
**Classification:** Internal Technical Reference

---

## About This Documentation

This documentation suite is generated from direct codebase analysis. Every fact, endpoint, data schema, and workflow described here reflects the actual implementation. Where existing documentation conflicted with code, the code is authoritative.

---

## Document Index

| Document | Description | Primary Audience |
|---|---|---|
| [ARCHITECTURE.md](./ARCHITECTURE.md) | System overview, component map, pipeline modes, auth design, tech stack | All engineers |
| [PROJECT_STRUCTURE.md](./PROJECT_STRUCTURE.md) | Folder-by-folder breakdown, module responsibilities | New team members |
| [SCAN_ENGINE_DESIGN.md](./SCAN_ENGINE_DESIGN.md) | Phase 1–4 engine internals, all vulnerability plugins, risk scoring algorithm | Security engineers |
| [SCAN_ORCHESTRATION.md](./SCAN_ORCHESTRATION.md) | Pipeline lifecycle, state transitions, error handling, phase validation | Backend engineers |
| [API_REFERENCE.md](./API_REFERENCE.md) | Every endpoint with request/response schemas and examples | Frontend engineers, API consumers |
| [CVE_INTEGRATION.md](./CVE_INTEGRATION.md) | CVE database schema, banner matching, package-version matching, scoring | Security engineers |
| [CREDENTIALED_SCANNING.md](./CREDENTIALED_SCANNING.md) | SSH auth, Linux/Windows collectors, credential security policy | Security engineers |
| [DATA_FLOW.md](./DATA_FLOW.md) | End-to-end data transformation from input to DB to PDF | All engineers |
| [SETUP_AND_INSTALLATION.md](./SETUP_AND_INSTALLATION.md) | Backend + frontend setup, environment vars, Docker, troubleshooting | DevOps, new team members |
| [DEVELOPER_GUIDE.md](./DEVELOPER_GUIDE.md) | Adding plugins, new endpoints, extending collectors, coding standards | Contributing engineers |

---

## Quick Reference

### Backend Start
```bash
cd Backend
pip install -r requirements.txt
python scripts/download_nvd.py      # one-time CVE database setup
python main.py                       # starts on http://0.0.0.0:8000
```

### Frontend Start
```bash
cd Frontend
npm install
npm run dev                          # starts on http://localhost:5173
```

### API Base URL
`http://localhost:8000`  
Interactive docs: `http://localhost:8000/docs`

---

## Scan Pipeline Summary

```
Pipeline Mode   Phases          Terminal   Use Case
─────────────   ──────          ────────   ────────
basic           Phase 1          Phase 1   Host inventory: which IPs are alive?
asset           Phase 1 → 2      Phase 2   Asset map: what ports/services are running?
advanced        Phase 1 → 2 → 3  Phase 3   Full audit: what vulnerabilities exist?

+ Credentialed  (independent)    instant   Deep dive: exact CVEs via package manager
```

### Phase Endpoints

| Phase | Endpoint                      | Engine              |
|-------|-------------------------------|---------------------|
| 1     | `POST /scan/host-discovery`   | DiscoveryEngine     |
| 2     | `POST /scan/asset-discovery`  | PortEngine          |
| 3     | `POST /scan/advanced-scan`    | VulnerabilityEngine |
| —     | `POST /scan/credentialed`     | SSHScanner + VulnMatcher |

---

## Authentication Flow

```
POST /auth/login  →  { access_token }  +  Set-Cookie: ccure_refresh_token
                           │
                    Authorization: Bearer <access_token>  on every request
                           │
                    Access token expires  →  POST /auth/refresh  →  new access_token
```

---

## Key Files at a Glance

| File | Purpose |
|------|---------|
| `Backend/main.py` | All scan + report endpoints; pipeline validation |
| `Backend/orchestrator/scan_orchestrator.py` | Phase pipeline controller |
| `Backend/engines/vulnerability/vulnerability_engine.py` | Plugin runner + Phase 4 risk scorer |
| `Backend/core/constants.py` | PORT_DB, CVE_HINTS, OS maps, risk weights |
| `Backend/core/risk.py` | OS fingerprinting, CVSS scoring, CVE normalization |
| `Backend/cves.db` | NVD CVE database (SQLite) |
| `Frontend/src/config/scanConfig.js` | Pipeline definitions — single source of truth |
| `Frontend/src/context/ScanContext.jsx` | Cross-page scan result state |
| `Frontend/src/api/axiosInstance.js` | JWT injection + auto-refresh interceptors |
