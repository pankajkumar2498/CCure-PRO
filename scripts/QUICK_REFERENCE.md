# Windows Credentialed Scan Setup - Quick Reference

## Problem
Windows machines fail to return system information during credentialed scans, while Linux works fine.

## Solution (5 minutes)

### On Target Windows Machine (As Administrator)

```powershell
# Method 1: Automated (Recommended)
.\Prepare-WindowsForVulnScan.ps1
Restart-Computer

# Method 2: Manual Command-by-Command
# Run each line as Administrator in PowerShell

# 1. Enable Services
Set-Service Winmgmt -StartupType Automatic
Set-Service RemoteRegistry -StartupType Automatic  
Set-Service WinRM -StartupType Automatic
Start-Service Winmgmt, RemoteRegistry, WinRM

# 2. Disable UAC Remote Restrictions
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

# 3. Enable Admin Shares
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 1 /f

# 4. Configure Firewall (PowerShell, Vista+)
Enable-NetFirewallRule -DisplayName "Windows Management Instrumentation (WMI-In)"
Enable-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)"

# 5. Configure WinRM
winrm quickconfig -quiet

# 6. Restart
Restart-Computer -Force
```

### From Scanner Machine (Test)

```powershell
# Quick connectivity test
.\Verify-WindowsScanReadiness.ps1 -TargetComputer <IP_OR_HOSTNAME>

# Manual WMI test
$comp = "192.168.1.50"
Get-WmiObject Win32_OperatingSystem -ComputerName $comp -Authentication PacketPrivacy
```

## Critical Registry Settings

| Setting | Path | Value |
|---------|------|-------|
| **LocalAccountTokenFilterPolicy** | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | `1` (DWORD) |
| **AutoShareServer** | `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | `1` (DWORD) |

## Required Services (Must Be Running)

- **Winmgmt** (Windows Management Instrumentation)
- **RemoteRegistry** (Remote Registry Service)
- **WinRM** (Windows Remote Management)

```powershell
# Check status
Get-Service Winmgmt, RemoteRegistry, WinRM | Select Name, Status, StartType
```

## Required Firewall Rules (Must Be Enabled)

```powershell
# Check
Get-NetFirewallRule -DisplayName "*WMI*" | Where Enabled -eq $true
Get-NetFirewallRule -DisplayName "*SMB*" | Where Enabled -eq $true

# Enable
Enable-NetFirewallRule -DisplayName "Windows Management Instrumentation (WMI-In)"
Enable-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)"
```

## Verify Success

```powershell
# From scanner machine, test all components:

# 1. Network
Test-Connection -ComputerName 192.168.1.50 -Count 1

# 2. WMI
Get-WmiObject Win32_ComputerSystem -ComputerName 192.168.1.50 -Authentication PacketPrivacy

# 3. Admin Shares  
Test-Path "\\192.168.1.50\C$\Windows"

# 4. WinRM
Test-WSMan -ComputerName 192.168.1.50

# 5. Remote Registry
$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", "192.168.1.50")
$key = $reg.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion")
$key.GetValue("CurrentVersion")
```

## If Windows Firewall is Off

If Windows Firewall is disabled, most of this is automatic, but still run the scripts to ensure services, registry settings, and admin shares are configured.

## Common Issues & Quick Fixes

| Issue | Quick Fix |
|-------|-----------|
| "Access Denied on WMI" | Verify user has admin rights: `whoami /groups \| find Admin` |
| "RPC Server Unavailable" | Restart RPC: `Restart-Service RpcSs -Force` |
| "Permission Denied on Registry" | Check LocalAccountTokenFilterPolicy is set to 1 |
| "Can't access admin shares" | Set AutoShareServer = 1 and `Restart-Service LanmanServer` |
| "WinRM Won't Start" | Run `winrm quickconfig` then restart WinRM service |

## Disable Later (Security)

```powershell
# After scan completes (optional for security)

# Stop non-essential services
Stop-Service RemoteRegistry -Force
Set-Service RemoteRegistry -StartupType Disabled

# Restore UAC restriction (removes the policy)
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy

# Hide admin shares
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f

# Restart
Restart-Computer -Force
```

## One-Liner Setup (Dangerous - Use with Caution)

```powershell
# Quick setup for lab/testing environments only
Set-Service Winmgmt, RemoteRegistry, WinRM -StartupType Automatic -PassThru | Start-Service; reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f | Out-Null; winrm quickconfig -quiet; Restart-Computer -Force
```

## For Enterprise Deployments

Use Group Policy or Configuration Management tool to deploy:

```powershell
# Example: PowerShell cmdlet for remote deployment via PSSession
$servers = "SERVER1", "SERVER2", "SERVER3"

Invoke-Command -ComputerName $servers -ScriptBlock {
    # Services
    Set-Service Winmgmt, RemoteRegistry, WinRM -StartupType Automatic
    Start-Service Winmgmt, RemoteRegistry, WinRM
    
    # Registry
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 1 /f | Out-Null
    
    # Firewall (if enabled)
    Enable-NetFirewallRule -DisplayName "Windows Management Instrumentation (WMI-In)", "File and Printer Sharing (SMB-In)"
}

# Restart all
Restart-Computer -ComputerName $servers -Force -AsJob
```

## Ports That Must Be Open

| Port | Service | Direction |
|------|---------|-----------|
| 135 | RPC Endpoint Mapper | Inbound |
| 139 | NetBIOS/File Sharing | Inbound |
| 445 | SMB/CIFS | Inbound |
| 5985 | WinRM HTTP | Inbound |

## What Gets Retrieved After Setup

✓ OS Name & Version  
✓ Build Number  
✓ Installation Date  
✓ System Manufacturer  
✓ CPU Details  
✓ Memory Amount  
✓ Installed Patches/Hotfixes  
✓ Installed Software/Packages  
✓ User Accounts  
✓ Network Configuration  
✓ Running Services  
✓ Vulnerability Data  

## Links to Full Documentation

- `WINDOWS_SCAN_SETUP_GUIDE.md` - Complete detailed guide
- `Prepare-WindowsForVulnScan.ps1` - Main setup script
- `Verify-WindowsScanReadiness.ps1` - Verification/testing script
- `Prepare-WindowsForVulnScan.cmd` - Legacy CMD version

---

**TL;DR Version:**
1. Run `.\Prepare-WindowsForVulnScan.ps1` on Windows machine
2. Restart
3. Run `.\Verify-WindowsScanReadiness.ps1 -TargetComputer <IP>` from scanner
4. If all tests pass, run your vulnerability scan
5. Don't forget to disable remote access afterward if desired for security

---

**Last Updated:** April 2024  
**For:** Windows vulnerability scanning with CCure Audit PRO, Nessus, OpenVAS, etc.
