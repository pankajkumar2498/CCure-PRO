# Setup and Deployment Guide

Covers target-machine preparation (`Prepare-WindowsForVulnScan.ps1` / `.cmd`) and bulk deployment (`Deploy-ScanPrepToMultiple.ps1`).

---

## 1. Single-Machine Setup

Run on the **target Windows machine** as Administrator.

### 1.1 PowerShell (Recommended)

```powershell
# Basic — interactive confirmation prompt, registry backup, full config
.\Prepare-WindowsForVulnScan.ps1

# With auto-rollback after 2 hours and scanner IP scoping
.\Prepare-WindowsForVulnScan.ps1 -ScanWindowMinutes 120 -ScannerSourceIP 10.0.0.50

# View rollback commands without making any changes
.\Prepare-WindowsForVulnScan.ps1 -DisableOnly

# Domain-joined machine — HTTP WinRM requires explicit override
.\Prepare-WindowsForVulnScan.ps1 -AllowHttpOnDomain -ScannerSourceIP 10.0.0.50

# Skip registry backup (use only if backup already exists)
.\Prepare-WindowsForVulnScan.ps1 -SkipBackup
```

**After the script completes, restart the machine:**

```powershell
Restart-Computer
```

### 1.2 Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-SkipBackup` | Switch | off | Skip registry backup before changes |
| `-DisableOnly` | Switch | off | Print rollback commands only; make no changes |
| `-ScanWindowMinutes` | Int | `0` | Auto-rollback after N minutes via scheduled task. `0` = no auto-rollback |
| `-ScannerSourceIP` | String | `""` | Scope WinRM listener and firewall rule to this IPv4 address |
| `-AllowHttpOnDomain` | Switch | off | Allow HTTP WinRM quickconfig on domain-joined machines |

### 1.3 What the Script Does (in order)

1. Confirm Administrator privileges
2. Show mandatory confirmation prompt listing every change
3. Back up registry keys to `C:\Windows\Temp\RegistryBackup_<timestamp>.reg`
4. Enable services: `WinRM`, `Winmgmt`, `RemoteRegistry` → Automatic/Running. Aborts if `Winmgmt` cannot start.
5. Enable WMI and SMB inbound firewall rules (locale-independent by internal Name + DisplayGroup fallback)
6. Set `LocalAccountTokenFilterPolicy = 1`; write audit entry to log; schedule rollback task if `-ScanWindowMinutes > 0`
7. Detect domain membership; refuse HTTP WinRM on domain machines unless `-AllowHttpOnDomain`; scope `TrustedHosts` if `-ScannerSourceIP` supplied
8. Enable admin shares (`AutoShareServer = 1`)
9. Verify WMI registry path and repository presence
10. Log firewall profile state
11. If `$ScannerAdminAccount` is set: print manual DCOM/WMI permission steps and exit 2 (not implemented programmatically)
12. Print verification summary
13. Print rollback block

**Log file:** `C:\Windows\Temp\VulnScanPrep_<timestamp>.log`

### 1.4 CMD Fallback

Use when PowerShell is unavailable or blocked.

```cmd
REM Interactive
Prepare-WindowsForVulnScan.cmd

REM Automated (called by Deploy-ScanPrepToMultiple.ps1 via WinRM)
Prepare-WindowsForVulnScan.cmd AUTO
```

The `AUTO` argument suppresses all interactive prompts and the final `pause`, so the script exits cleanly when called over WinRM. Registry backups, service configuration, firewall enablement (locale-independent), and UAC registry changes are all included. The calling deployment script handles restart orchestration.

---

## 2. Pre-Flight Verification

Run on the **scanner machine** as Administrator, before scheduling the scan.

```powershell
# Current-user credentials (ambient token)
.\Verify-WindowsScanReadiness.ps1 -TargetComputer 192.168.1.100

# With explicit username — prompts securely for password
.\Verify-WindowsScanReadiness.ps1 -TargetComputer WORKSTATION1 -Username "DOMAIN\scanner"

# With pre-built SecureString (never use -AsPlainText -Force on the command line)
$pw = Read-Host -AsSecureString "Password"
.\Verify-WindowsScanReadiness.ps1 -TargetComputer 192.168.1.100 -Username "admin" -Password $pw
```

**What it tests:**

1. Resolves hostname to IPv4 (explicitly filters `AddressFamily = InterNetwork`)
2. If a credential is supplied, validates it immediately with `Invoke-Command` — fails fast rather than running all tests with a broken credential (exit code 2 on auth failure)
3. TCP port reachability: 135, 139, 445, 5985, 5986
4. WMI connectivity (`Win32_ComputerSystem`)
5. Admin share access via `net use` with the supplied credential (not the caller's ambient token)
6. WinRM connectivity via `Invoke-Command`
7. Remote Registry read via `Invoke-Command` (credential-honoured)
8. UAC setting (`LocalAccountTokenFilterPolicy`)
9. OS, ComputerSystem, Processor WMI queries
10. Installed software count via Uninstall registry hive (not `Win32_Product`)

**Final verdict incorporates all six subsystems** (WMI, WinRM, RemoteRegistry, AdminShare, OS, Processor). A machine with broken WinRM and RemoteRegistry cannot receive a "Ready for basic scanning" verdict.

---

## 3. Diagnostics

Run on the **target machine** as Administrator when scans still fail after setup.

```powershell
# Standard 10-section run
.\Diagnose-WindowsScanIssues.ps1

# Include WMI repository size and permission checks
.\Diagnose-WindowsScanIssues.ps1 -Detailed

# Interactive — prompts Y/N before each of the 10 sections
.\Diagnose-WindowsScanIssues.ps1 -Interactive

# Skip software enumeration (safe on busy production servers)
.\Diagnose-WindowsScanIssues.ps1 -SkipSlowChecks

# Export sanitised HTML report (special characters are entity-encoded)
.\Diagnose-WindowsScanIssues.ps1 -ExportReport "C:\Reports\Diagnosis.html"

# Combine flags
.\Diagnose-WindowsScanIssues.ps1 -Detailed -SkipSlowChecks -ExportReport "C:\diag.html"
```

**The 10 sections:** Services → Registry Settings → Firewall Rules → Admin Shares → WMI State → WMI Repository (`-Detailed` only) → Network Services (port listeners) → Network Configuration → Credentials & Groups → System Information.

Software enumeration reads `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` directly — it never calls `Win32_Product`, which triggers Windows Installer MSI consistency checks that can take 10–60 minutes and destabilise running applications.

---

## 4. Bulk Deployment

Run on the **scanner machine** as Administrator to configure many Windows targets in parallel.

### 4.1 Basic Usage

```powershell
# Interactive — prompts for machine list, credentials, restart decision
.\Deploy-ScanPrepToMultiple.ps1

# Inline machine array
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray "SERVER1","SERVER2","192.168.1.10" `
    -AdminUsername "DOMAIN\scanadmin"

# From CSV file
.\Deploy-ScanPrepToMultiple.ps1 -MachineList "C:\targets.csv" `
    -AdminUsername "DOMAIN\scanadmin"

# Skip restart (apply config now, restart machines during a later maintenance window)
.\Deploy-ScanPrepToMultiple.ps1 -MachineList "C:\targets.csv" -SkipRestart

# Re-run verification only (machines already restarted manually)
.\Deploy-ScanPrepToMultiple.ps1 -MachineList "C:\targets.csv" -SkipRestart -AdminUsername "DOMAIN\scanadmin"

# Increase parallelism for large fast networks
.\Deploy-ScanPrepToMultiple.ps1 -MachineList "C:\targets.csv" -DeployThrottleLimit 25

# Extend timeout for slow hardware
.\Deploy-ScanPrepToMultiple.ps1 -MachineList "C:\targets.csv" -RestartTimeoutSeconds 900
```

### 4.2 Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-MachineList` | String | — | Path to CSV file. Must have a `ComputerName` header column |
| `-MachineArray` | String[] | — | Inline array of hostnames or IPs |
| `-AdminUsername` | String | — | Admin username for all targets. Prompted if omitted |
| `-AdminPassword` | SecureString | — | Password. Prompted via `Get-Credential` if omitted |
| `-SkipRestart` | Switch | off | Skip restart prompt. Verification runs against current state |
| `-SkipVerification` | Switch | off | Skip post-restart configuration verification |
| `-DeployThrottleLimit` | Int | `10` | Max simultaneous `Invoke-Command` sessions |
| `-RestartTimeoutSeconds` | Int | `600` | Per-machine timeout waiting for restart (adaptive polling) |

### 4.3 CSV Format

```csv
ComputerName
SERVER01
192.168.1.10
WORKSTATION-A
```

The `ComputerName` column is required. Extra columns (`Description`, `Location`, etc.) are silently ignored. The script validates the header and exits with an actionable error if the column is missing.

### 4.4 What the Deployment Configures on Each Target

Delivered via a single parallel `Invoke-Command` call (not a serial loop):

- `Winmgmt` → Automatic (not restarted — already running, restarting WinRM over its own session kills the channel)
- `RemoteRegistry` → Automatic/Running
- `WinRM` startup type → Automatic (service not restarted for the same reason)
- `LocalAccountTokenFilterPolicy = 1`
- `AutoShareServer = 1`
- WMI and SMB firewall rules (by stable internal `Name` + `DisplayGroup` keyword fallback for locale coverage)

### 4.5 Restart Orchestration

`Restart-Machines` sends `shutdown /r /t 120` to all machines, waits 45 seconds for shutdown to begin, then polls each machine independently with `Test-Connection` every 15 seconds until it responds or `RestartTimeoutSeconds` is reached. Only machines confirmed back online are passed to verification. Timed-out machines are reported without blocking the others.

Verification only runs against machines that were actually restarted and came back online. If the user answers N at the restart prompt, verification is deferred with an explanatory message — it does not run against pre-restart state and report false failures.

### 4.6 Active Directory Integration

```powershell
# All Windows servers in the domain
$targets = Get-ADComputer -Filter "OperatingSystem -like '*Server*'" |
    Select-Object -ExpandProperty Name
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray $targets -AdminUsername "DOMAIN\scanadmin"

# Specific OU
$targets = Get-ADComputer -SearchBase "OU=Servers,DC=corp,DC=example,DC=com" -Filter * |
    Select-Object -ExpandProperty Name
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray $targets -AdminUsername "DOMAIN\scanadmin"

# Specific department by naming pattern
$targets = Get-ADComputer -Filter "Name -like 'HR-*'" |
    Select-Object -ExpandProperty Name
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray $targets -AdminUsername "DOMAIN\scanadmin"
```

---

## 5. Rollback

### Automatic Rollback (Prepare-WindowsForVulnScan.ps1 only)

Pass `-ScanWindowMinutes N` at setup time. The script registers a scheduled task (`VulnScanRollback`) that fires N minutes later to:
- Remove `LocalAccountTokenFilterPolicy`
- Stop and disable `RemoteRegistry`
- Self-delete

Cancel early with:
```powershell
Unregister-ScheduledTask -TaskName 'VulnScanRollback' -Confirm:$false
```

### Manual Rollback

```powershell
# 1. Remove UAC relaxation
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'LocalAccountTokenFilterPolicy' -ErrorAction SilentlyContinue

# 2. Disable Remote Registry
Stop-Service  -Name RemoteRegistry -Force -ErrorAction SilentlyContinue
Set-Service   -Name RemoteRegistry -StartupType Disabled -ErrorAction SilentlyContinue

# 3. Disable admin share auto-creation
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
    -Name 'AutoShareServer' -Value 0 -ErrorAction SilentlyContinue

# 4. Disable WMI and SMB firewall rules
Disable-NetFirewallRule -DisplayName "Windows Management Instrumentation (WMI-In)"     -ErrorAction SilentlyContinue
Disable-NetFirewallRule -DisplayName "Windows Management Instrumentation (WINMGMT-In)" -ErrorAction SilentlyContinue
Disable-NetFirewallRule -DisplayName "Windows Management Instrumentation (ASYNC-In)"   -ErrorAction SilentlyContinue
Disable-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)"               -ErrorAction SilentlyContinue
Disable-NetFirewallRule -DisplayName "File and Printer Sharing (NB-Session-In)"        -ErrorAction SilentlyContinue

# 5. Remove scheduled rollback task if still present
Unregister-ScheduledTask -TaskName 'VulnScanRollback' -Confirm:$false -ErrorAction SilentlyContinue

# 6. Restart
Restart-Computer -Confirm
```

### Restore from Registry Backup

```powershell
# Backup is at C:\Windows\Temp\RegistryBackup_<timestamp>.reg
reg import "C:\Windows\Temp\RegistryBackup_<timestamp>.reg"
```

---

## 6. WinRM Bootstrap Prerequisite

The deployment script requires WinRM/PowerShell Remoting to be already active on each target. If it is not:

```powershell
# ON THAT TARGET (via RDP or local console), run once as Administrator:
Enable-PSRemoting -Force
winrm quickconfig -quiet
```

Once WinRM is active on any machine, the deployment script can be used to configure all remaining machines including re-configuring that first one.

---

## 7. Timing Reference

| Machines | Config deploy | Restart wait | Verification | Total |
|---|---|---|---|---|
| 1 | 15s | ~3 min | 30s | ~5 min |
| 10 | 20s | ~4 min | 45s | ~6 min |
| 50 | 30s | ~5 min | 2 min | ~8 min |
| 100 | 45s | ~5 min | 3 min | ~10 min |

Deployment is fully parallelised up to `DeployThrottleLimit`. Restart polling is per-machine and non-blocking.
