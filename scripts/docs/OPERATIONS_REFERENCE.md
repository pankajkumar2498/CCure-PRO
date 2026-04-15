# Operations Reference

Quick-reference commands, required ports, per-symptom fixes, and the step-by-step setup checklist.

---

## Quick Commands

### Target Machine (run as Administrator)

```powershell
# Prepare for scanning
.\Prepare-WindowsForVulnScan.ps1

# With 2-hour auto-rollback and scanner IP scoping
.\Prepare-WindowsForVulnScan.ps1 -ScanWindowMinutes 120 -ScannerSourceIP 10.0.0.50

# Print rollback commands only (no changes)
.\Prepare-WindowsForVulnScan.ps1 -DisableOnly

# Deep diagnostics (read-only)
.\Diagnose-WindowsScanIssues.ps1
.\Diagnose-WindowsScanIssues.ps1 -Detailed
.\Diagnose-WindowsScanIssues.ps1 -SkipSlowChecks -ExportReport "C:\diag.html"

# Check service status
Get-Service Winmgmt, RemoteRegistry, WinRM | Select-Object Name, Status, StartType

# Check registry settings
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" LocalAccountTokenFilterPolicy
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" AutoShareServer

# Check admin shares
Get-SmbShare -Special | Where-Object Name -match '^(C\$|ADMIN\$|IPC\$)$'

# Check WinRM
winrm get winrm/config
```

### Scanner Machine (run as Administrator)

```powershell
# Verify a single target
.\Verify-WindowsScanReadiness.ps1 -TargetComputer 192.168.1.100
.\Verify-WindowsScanReadiness.ps1 -TargetComputer WORKSTATION1 -Username "DOMAIN\scanner"

# Bulk deploy
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray "PC1","PC2","PC3" -AdminUsername "DOMAIN\admin"
.\Deploy-ScanPrepToMultiple.ps1 -MachineList "C:\targets.csv"   -AdminUsername "DOMAIN\admin"

# Manual WMI test
Get-WmiObject Win32_OperatingSystem -ComputerName 192.168.1.100 -Authentication PacketPrivacy

# Manual WinRM test
Invoke-Command -ComputerName 192.168.1.100 -ScriptBlock { $env:COMPUTERNAME }

# Manual Remote Registry test
$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", "192.168.1.100")
$key = $reg.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion")
$key.GetValue("ProductName")
$key.Close(); $reg.Close()
```

---

## Required Registry Settings

| Key name | Path | Required value |
|---|---|---|
| `LocalAccountTokenFilterPolicy` | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | `1` (DWORD) |
| `AutoShareServer` | `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | `1` (DWORD) |

---

## Required Services

| Service name | Display name | Startup type |
|---|---|---|
| `Winmgmt` | Windows Management Instrumentation | Automatic |
| `RemoteRegistry` | Remote Registry | Automatic |
| `WinRM` | Windows Remote Management | Automatic |

---

## Required Network Ports (inbound on target)

| Port | Protocol | Service |
|---|---|---|
| 135 | TCP | RPC Endpoint Mapper |
| 139 | TCP | NetBIOS Session |
| 445 | TCP | SMB/CIFS |
| 5985 | TCP | WinRM HTTP |
| 5986 | TCP | WinRM HTTPS (optional) |

---

## Symptom → Fix Matrix

| Symptom | First check | Fix |
|---|---|---|
| Scan connects but returns empty data | WMI service state | `Restart-Service Winmgmt -Force` |
| "Access Denied" on WMI | `LocalAccountTokenFilterPolicy` | Confirm value is `1`; run setup script |
| "RPC Server Unavailable" | Port 135 open; RpcSs running | `Restart-Service RpcSs -Force`; check firewall |
| Cannot access `C$` / `ADMIN$` | `AutoShareServer` value | Set to `1`; `Restart-Service LanmanServer` |
| WinRM connection fails | Port 5985 open; WinRM listener | `winrm quickconfig -quiet`; restart WinRM |
| Remote Registry access fails | `RemoteRegistry` service | Start service, set Automatic |
| WMI firewall rule missing | Locale-specific name issue | Use `Enable-NetFirewallRule -Name WMI-WINMGMT-In-TCP` (internal name) |
| Verification passes but scan still empty | Antivirus blocking WMI | Whitelist `wmiprvse.exe` in AV; check Windows Event log for WMI errors |

---

## Log Files

| Script | Log location |
|---|---|
| `Prepare-WindowsForVulnScan.ps1` | `C:\Windows\Temp\VulnScanPrep_<timestamp>.log` |
| `Prepare-WindowsForVulnScan.ps1` | `C:\Windows\Temp\RegistryBackup_<timestamp>.reg` (registry backup) |
| `Verify-WindowsScanReadiness.ps1` | `C:\Windows\Temp\VulnScanVerify_<timestamp>.log` |
| `Deploy-ScanPrepToMultiple.ps1` | `C:\temp\ScanPrepDeploy_<timestamp>.log` |

```powershell
# View most recent setup log
Get-Content (Get-ChildItem C:\Windows\Temp\VulnScanPrep_*.log | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName

# Search for errors
Select-String "ERROR" C:\Windows\Temp\VulnScanPrep_*.log
```

---

## Setup Checklist

Use this as a per-machine tracking form.

**Machine:** ______________________  
**IP / Hostname:** ______________________  
**Scanner account:** ______________________  
**Date:** ______________________  
**Operator:** ______________________  

### Phase 1 — Prerequisites

- [ ] Administrator access available on target machine
- [ ] Administrator access available on scanner machine
- [ ] Both machines can reach each other (ping passes)
- [ ] Windows Vista / Server 2008 or newer
- [ ] Scripts available on target (or accessible share)
- [ ] Acceptable to restart the target machine

### Phase 2 — Run Setup Script on Target

- [ ] Open PowerShell as Administrator
- [ ] Run `.\Prepare-WindowsForVulnScan.ps1`
  - If execution policy blocks: `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process`
- [ ] Type `YES` at the confirmation prompt
- [ ] Script completes without `[ERROR]` lines in console
- [ ] Registry backup confirmed at `C:\Windows\Temp\RegistryBackup_*.reg`
- [ ] Restart machine: `Restart-Computer`
- [ ] Wait for full startup (~3–5 minutes)

### Phase 3 — Local Verification (on Target, after restart)

- [ ] Services running and Automatic:
  ```powershell
  Get-Service Winmgmt, RemoteRegistry, WinRM | Format-Table Name, Status, StartType
  ```
- [ ] `LocalAccountTokenFilterPolicy = 1`
  ```powershell
  Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" LocalAccountTokenFilterPolicy
  ```
- [ ] Admin shares present (`C$`, `ADMIN$`, `IPC$`):
  ```powershell
  Get-SmbShare -Special | Where-Object Name -match '^(C\$|ADMIN\$|IPC\$)$'
  ```
- [ ] WinRM responds:
  ```powershell
  winrm get winrm/config
  ```

### Phase 4 — Remote Verification (on Scanner)

- [ ] Run `.\Verify-WindowsScanReadiness.ps1 -TargetComputer <IP>`
- [ ] Port 135 OPEN
- [ ] Port 445 OPEN
- [ ] Port 5985 OPEN
- [ ] WMI connectivity: SUCCESS
- [ ] Admin share access: SUCCESS (credential verified)
- [ ] WinRM connectivity: SUCCESS
- [ ] Remote Registry: SUCCESS
- [ ] OS information retrieved
- [ ] Processor information retrieved
- [ ] Final verdict: **READY FOR FULL SCANNING** (or BASIC SCANNING with noted limitations)

### Phase 5 — Scan

- [ ] Create credentialed scan in CCure Audit PRO (or Nessus / OpenVAS / Qualys)
- [ ] Target: the verified machine
- [ ] Scan type: Credentialed / Windows
- [ ] Credentials: account used during verification
- [ ] Scan starts without connection errors
- [ ] Results include OS, software, patches — not empty

### Phase 6 — Post-Scan Rollback (Recommended)

- [ ] Run rollback block (printed at script end, or `.\Prepare-WindowsForVulnScan.ps1 -DisableOnly`)
- [ ] Or let auto-rollback task fire if `-ScanWindowMinutes` was used
- [ ] Verify `RemoteRegistry` is stopped/disabled
- [ ] Verify `LocalAccountTokenFilterPolicy` key removed
- [ ] Restart machine

---

## Emergency Rollback (Fastest)

```powershell
Stop-Service RemoteRegistry -Force
Set-Service  RemoteRegistry -StartupType Disabled
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'LocalAccountTokenFilterPolicy' -Force -ErrorAction SilentlyContinue
Restart-Computer -Force
```

Restore from backup if needed:

```cmd
reg import C:\Windows\Temp\RegistryBackup_<timestamp>.reg
```

---

## Data Retrieved by a Successful Credentialed Scan

- OS name, version, build number, install date
- System manufacturer and model
- CPU name, cores, speed
- Total RAM
- Network configuration
- Installed software (from Uninstall registry hive — not Win32_Product)
- Windows patches / KB articles (`Win32_QuickFixEngineering`)
- Running services
- User accounts
- All CVEs matching the detected package versions
