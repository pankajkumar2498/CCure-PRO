# CCure Audit PRO — Windows Credentialed Scanning

## Overview

CCure Audit PRO provides credentialed vulnerability scanning for Windows targets. A credentialed scan authenticates to the target and retrieves system data (OS, CPU, installed packages, patches, CVEs) using WMI, Remote Registry, SMB admin shares, and WinRM.

**Common symptom:** Authentication succeeds but results are empty — no OS, no packages, no CVEs. This happens because the Windows target lacks the required service and firewall configuration. All scripts in this suite exist to solve that problem.

---

## Repository Layout

```
project/
├── Prepare-WindowsForVulnScan.ps1      Target-side: full PS setup (v1.1)
├── Prepare-WindowsForVulnScan.cmd      Target-side: legacy CMD fallback
├── Deploy-ScanPrepToMultiple.ps1       Scanner-side: bulk parallel deploy (v2.0)
├── Verify-WindowsScanReadiness.ps1     Scanner-side: pre-scan readiness check (v1.1)
├── Diagnose-WindowsScanIssues.ps1      Target-side: post-failure diagnostics (v1.1)
├── startup.ps1                         Dev: start Backend + Frontend
├── run_tests.ps1                       Dev: run pytest test suite
└── docs/
    ├── README.md                        ← you are here
    ├── SETUP_AND_DEPLOYMENT.md          Single-machine & bulk deployment guide
    ├── OPERATIONS_REFERENCE.md          Command cheat sheet + setup checklist
    └── DEVELOPER_GUIDE.md               startup.ps1, run_tests.ps1, project setup
```

---

## Script Map

| Script | Run on | Purpose |
|---|---|---|
| `Prepare-WindowsForVulnScan.ps1` | **Target** machine | Configure WMI, WinRM, registry, firewall |
| `Prepare-WindowsForVulnScan.cmd` | **Target** machine | Same, CMD-only fallback |
| `Deploy-ScanPrepToMultiple.ps1` | **Scanner** machine | Push configuration to many targets in parallel |
| `Verify-WindowsScanReadiness.ps1` | **Scanner** machine | Pre-flight test — confirms target is ready |
| `Diagnose-WindowsScanIssues.ps1` | **Target** machine | Deep read-only diagnostics when scans still fail |
| `startup.ps1` | Dev machine | Launch FastAPI backend + React frontend |
| `run_tests.ps1` | Dev machine | Run pytest suite against live backend |

---

## Workflow

### Single Machine

```
Target machine          Scanner machine
───────────────         ───────────────
Prepare-WindowsForVulnScan.ps1
→ Restart
                        Verify-WindowsScanReadiness.ps1 -TargetComputer <IP>
                        → All green → run scan
```

### Many Machines (Recommended)

```
Scanner machine only
────────────────────────────────────────────────────────
Deploy-ScanPrepToMultiple.ps1 -MachineList targets.csv
  ├─ parallel config push (WMI, registry, firewall)
  ├─ restart orchestration with adaptive polling
  └─ post-restart verification

→ All machines ready → run scan
```

### Troubleshooting Path

```
Scan returns empty results
→ Target machine: Diagnose-WindowsScanIssues.ps1
  - add -Detailed for WMI repository check
  - add -ExportReport report.html for shareable output
  - add -SkipSlowChecks on busy production servers
→ Fix issues reported
→ Scanner machine: Verify-WindowsScanReadiness.ps1 again
→ Retry scan
```

---

## What Gets Configured on Each Target

| Component | Registry / Service | Effect |
|---|---|---|
| `Winmgmt` | Service → Automatic/Running | Enables WMI queries |
| `RemoteRegistry` | Service → Automatic/Running | Enables registry read |
| `WinRM` | Service → Automatic + quickconfig | Enables PowerShell remoting |
| `LocalAccountTokenFilterPolicy` | `HKLM\...\Policies\System` → `1` | Allows remote local-admin token |
| `AutoShareServer` | `HKLM\...\LanmanServer\Parameters` → `1` | Re-enables C$, ADMIN$, IPC$ |
| WMI firewall rules | Inbound allow | Opens RPC/WMI traffic |
| SMB firewall rules | Inbound allow | Opens ports 139/445 |

---

## Security Posture

`LocalAccountTokenFilterPolicy=1` weakens the UAC remote boundary for all local-account remote sessions. Admin shares (C$, ADMIN$) are lateral-movement targets. **Revert both after scanning.**

`Prepare-WindowsForVulnScan.ps1` supports:
- `-ScanWindowMinutes N` — schedules automatic rollback via `schtasks` after N minutes
- `-DisableOnly` — prints the rollback block without making changes
- `-ScannerSourceIP <IP>` — scopes WinRM and its firewall rule to the scanner IP only
- `-AllowHttpOnDomain` — required override to allow HTTP WinRM on domain-joined machines

See `SETUP_AND_DEPLOYMENT.md` for full parameter reference.

---

## Documentation Index

| File | Contents |
|---|---|
| `SETUP_AND_DEPLOYMENT.md` | Single-machine setup, bulk deployment, parameters, CSV format, AD integration |
| `OPERATIONS_REFERENCE.md` | Cheat-sheet commands, required ports, per-symptom fix table, setup checklist |
| `DEVELOPER_GUIDE.md` | startup.ps1 modes, run_tests.ps1 selectors, venv setup, environment variables |
