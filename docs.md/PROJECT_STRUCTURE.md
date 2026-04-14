# CCure Audit PRO — Project Structure

**Version:** 1.0.0

---

## Repository Layout

```
CCure-Audit-PRO/
├── Backend/                         # FastAPI application
│   ├── main.py                      # Application entry point, all scan endpoints
│   ├── pdf_generator.py             # ReportLab PDF report generator
│   ├── requirements.txt             # Python dependencies
│   ├── ccure_users.db               # SQLite: users, scans, tokens (auto-created)
│   ├── cves.db                      # SQLite: NVD CVE database (pre-populated)
│   ├── manuf.txt                    # IEEE OUI vendor lookup table
│   │
│   ├── api/
│   │   └── host_discovery_api.py    # HostDiscoveryAPI facade (wraps ScanOrchestrator)
│   │
│   ├── auth/
│   │   ├── models.py                # User + RefreshToken SQLAlchemy models; get_db()
│   │   ├── jwt_handler.py           # Token creation, rotation, revocation logic
│   │   ├── router.py                # /auth/* endpoints (register, login, logout, refresh, me)
│   │   └── dependencies.py          # get_current_user() FastAPI dependency
│   │
│   ├── core/
│   │   ├── constants.py             # PORT_DB, CVE_HINTS, OS maps, risk weights
│   │   ├── models.py                # Enums + dataclasses (HostResult, PortResult, etc.)
│   │   ├── risk.py                  # OS fingerprinting, CVSS risk scoring, CVE normalization
│   │   ├── cve_database.py          # CVEDatabase: query wrapper for cves.db
│   │   ├── oui_lookup.py            # MAC vendor resolution from manuf.txt
│   │   └── utils.py                 # InputValidator, TokenBucket, local IP/MAC helpers
│   │
│   ├── engines/
│   │   ├── discovery/
│   │   │   └── discovery_engine.py  # Phase 1: ARP / ICMP / TCP / FULL / ADAPTIVE / STEALTH
│   │   │
│   │   ├── port/
│   │   │   └── port_engine.py       # Phase 2: async TCP connect, banner grab, UDP probes
│   │   │
│   │   ├── vulnerability/
│   │   │   ├── vulnerability_engine.py  # Phase 3+4: plugin runner + risk scorer
│   │   │   └── plugins/
│   │   │       ├── tls_scanner.py       # TLS/SSL certificate and cipher audit
│   │   │       ├── http_analyzer.py     # HTTP security headers, redirect checks
│   │   │       ├── ssh_probe.py         # SSH version, key exchange algorithms
│   │   │       ├── smb_probe.py         # SMB version detection (v1/v2/v3)
│   │   │       ├── snmp_probe.py        # SNMP community string probe
│   │   │       ├── udp_scanner.py       # UDP service probes
│   │   │       ├── icmp_probe.py        # ICMP echo + TTL fingerprinting
│   │   │       ├── ftp_checker.py       # FTP anonymous access check
│   │   │       └── cve_engine.py        # Banner → CVE matching via cves.db
│   │   │
│   │   └── credentialed/
│   │       ├── ssh_scanner.py           # Paramiko SSH session manager
│   │       ├── linux_collector.py       # SSH command collection for Linux targets
│   │       ├── windows_collector.py     # SSH command collection for Windows targets
│   │       └── vuln_matcher.py          # Package-version → CVE matching via cves.db
│   │
│   ├── orchestrator/
│   │   └── scan_orchestrator.py         # Phase pipeline controller
│   │
│   ├── scans/
│   │   ├── models.py                    # Scan + ScanPhaseResult SQLAlchemy models
│   │   ├── db_helpers.py                # CRUD helpers (create_scan, update_scan_phase, etc.)
│   │   └── router.py                    # /scans/* endpoints (list, get, archive, delete, purge)
│   │
│   ├── scripts/
│   │   ├── download_nvd.py              # Populates cves.db from NVD JSON feeds
│   │   ├── cli.py                       # CLI wrapper for direct scan invocation
│   │   ├── verify_install.py            # Environment check (Scapy, Paramiko, etc.)
│   │   └── test-db/                     # Development utilities (user creation, login test)
│   │
│   ├── tests/
│   │   ├── check_db.py                  # DB schema inspection
│   │   ├── test_cve_db.py               # CVE database query tests
│   │   └── test_windows_collector.py    # Windows collector unit tests
│   │
│   ├── docs/                            # Legacy documentation (superseded by this suite)
│   └── reports/                         # PDF report output directory (auto-created)
│
├── Frontend/                            # React SPA
│   ├── index.html
│   ├── vite.config.js
│   ├── package.json
│   │
│   └── src/
│       ├── main.jsx                     # React DOM root
│       ├── App.jsx                      # Router definition (all routes)
│       │
│       ├── api/
│       │   ├── axiosInstance.js         # Axios instance with JWT interceptors
│       │   ├── auth.js                  # Auth API calls (login, register, refresh, logout)
│       │   ├── scans.js                 # Scan history API calls
│       │   ├── credentialedScan.js      # Credentialed scan API call
│       │   └── tokenStorage.js          # Access token read/write (memory + sessionStorage)
│       │
│       ├── config/
│       │   └── scanConfig.js            # Pipeline definitions, phase descriptors, helpers
│       │
│       ├── context/
│       │   ├── AuthContext.jsx          # Login state, token management, auto-refresh
│       │   └── ScanContext.jsx          # Cross-page scan result state (sessionStorage backed)
│       │
│       ├── components/
│       │   ├── PrivateRoute.jsx          # Auth guard wrapper
│       │   ├── layout/
│       │   │   ├── AppShell.jsx         # Sidebar nav + top bar layout
│       │   │   ├── AppLayout.jsx        # Page content wrapper
│       │   │   ├── ScanStepper.jsx      # Phase progress indicator component
│       │   │   └── Modal.jsx            # Generic modal component
│       │   └── scan/
│       │       ├── ExportPanel.jsx      # JSON/CSV/clipboard export + PDF download
│       │       └── RiskBadge.jsx        # Severity badge (Critical/High/Medium/Low/Info)
│       │
│       ├── pages/
│       │   ├── Dashboard.jsx            # Overview stats + quick-launch scan cards
│       │   ├── Login.jsx                # Login form
│       │   ├── Register.jsx             # Registration form
│       │   ├── ScanHistory.jsx          # Active scan list
│       │   ├── ArchivedScans.jsx        # Archived scan list
│       │   ├── RecycleBin.jsx           # Soft-deleted scans
│       │   ├── SecurityReports.jsx      # PDF report download page
│       │   └── scan/
│       │       ├── NewScan.jsx          # Scan template selector + target input
│       │       ├── Phase1Results.jsx    # Host Discovery results view
│       │       ├── Phase2Results.jsx    # Asset Discovery / Port Scan results view
│       │       ├── Phase3Results.jsx    # Advanced Scan / Vulnerability results view
│       │       ├── Phase4Results.jsx    # Risk Report view
│       │       ├── CredentialedScan.jsx # SSH credential input form
│       │       └── CredentialedResults.jsx # Credentialed scan results view
│       │
│       └── styles/
│           └── global.css
│
├── scripts/                             # Windows deployment helpers
│   ├── Prepare-WindowsForVulnScan.ps1   # Configure Windows target for remote scanning
│   ├── Deploy-ScanPrepToMultiple.ps1    # Bulk Windows target deployment
│   ├── Diagnose-WindowsScanIssues.ps1   # Windows scan troubleshooter
│   ├── Verify-WindowsScanReadiness.ps1  # Pre-scan target readiness check
│   └── *.md                             # Windows scanning guides
│
└── docs/                                # Project-level documentation (this suite)
```

---

## Module Responsibilities

### `main.py`
The FastAPI application entry point. Owns:
- All scan endpoints (`/scan/*`)
- Report download endpoint (`/reports/download/{scan_id}`)
- Pipeline mode validation and `pipeline_mode` resolution
- In-memory scan progress tracking (`_scan_progress`)
- Report context resolution (target string, scan method normalization)
- Lifecycle management (`lifespan` — creates DB tables on startup)

This file is intentionally large because it wires together every engine, database helper, and pipeline guard. Business logic lives in the engines; coordination logic lives here.

---

### `api/host_discovery_api.py`
A thin facade over `ScanOrchestrator`. Handles target input resolution for traditional scan endpoints (`/scan/host`, `/scan/range`, `/scan/subnet`, `/scan/subnets`). Exposes `get_system_info()` for the health endpoint.

---

### `core/constants.py`
The static knowledge base of the scanner:

| Constant         | Description                                                     |
|------------------|-----------------------------------------------------------------|
| `PORT_DB`        | Dict of port → `{service, risk, description}` for all known ports |
| `SCAN_PORTS_QUICK` | Top 68 high-value ports (used for LIGHT intensity)            |
| `SCAN_PORTS_FULL`  | All named ports in PORT_DB (NORMAL and DEEP intensity)        |
| `CVE_HINTS`      | Fallback hardcoded CVE mappings (used when cves.db is absent)  |
| `OS_TTL_MAP`     | TTL thresholds → OS label (e.g., TTL ≤ 64 → Linux)           |
| `TCP_WINDOW_OS`  | TCP window size → OS label (Windows-specific)                  |
| `RISK_WEIGHTS`   | Risk level → score contribution (Critical=25, High=15, etc.)  |
| `RISK_LEVELS`    | Score thresholds → risk level string                           |
| `SCAPY_AVAILABLE`| Runtime flag; False if Scapy/Npcap not installed               |
| `PDF_AVAILABLE`  | Runtime flag; False if reportlab not installed                  |

---

### `core/models.py`
Typed data containers with no logic. Defines:
- `DiscoveryScanType` — enum of discovery probe strategies
- `ScanIntensity` — enum of port scan depth (light/normal/deep)
- `PortResult` — per-port findings dataclass
- `TLSInfo` — TLS certificate and cipher details dataclass
- `HTTPAudit` — HTTP security header audit dataclass
- `HostResult` — complete per-host result container; exposes `to_phase1_dict()` and `to_clean_dict()` serializers
- `DiscoverySummary` — aggregate summary for a scan run

---

### `orchestrator/scan_orchestrator.py`
Central pipeline controller. Implements:
- `run_host_discovery_only()` — Phase 1 only
- `run_asset_discovery_only()` — Phase 2 only (requires Phase 1 output as input)
- `run_advanced_scan_only()` — Phase 3+4 (requires Phase 2 output as input)
- `run_phases()` — flexible combinator accepting phase string like `"1+2+3+4"`
- Traditional methods (`scan_single_host`, `scan_subnet`, etc.) for backward compatibility
- OS inference (`_apply_os_inference`) applied after both Phase 2 and Phase 3
- Report generation dispatch (`generate_phase_report`)

---

### `scans/db_helpers.py`
All database write operations:
- `create_scan()` — inserts a new Scan row with Phase 1 payload
- `create_completed_scan()` — inserts a complete Scan row (used for credentialed scans)
- `update_scan_phase()` — appends a ScanPhaseResult row and optionally marks the scan complete
- `mark_scan_failed()` — sets status=failed and records the failure reason
