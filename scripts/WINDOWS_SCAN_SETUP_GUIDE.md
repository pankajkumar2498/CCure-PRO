# Windows Vulnerability Scan Preparation Guide

## Overview

This comprehensive guide explains how to prepare a Windows machine for credentialed vulnerability scanning using tools like CCure Audit PRO, Nessus, OpenVAS, or similar platforms.

**Problem Statement:** Credentialed scans can authenticate to Windows machines but fail to retrieve system information (OS, kernel, CPU, packages, CVEs), while the same scans work perfectly on Linux machines.

**Root Cause:** Missing WMI access, disabled services, UAC restrictions, or firewall rules blocking remote access.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [What Gets Configured](#what-gets-configured)
3. [Detailed Step-by-Step](#detailed-step-by-step)
4. [Verification & Testing](#verification--testing)
5. [Security Considerations](#security-considerations)
6. [Troubleshooting](#troubleshooting)
7. [Rollback Instructions](#rollback-instructions)

---

## Quick Start

### For Most Users

```powershell
# On the Windows machine to be scanned (as Administrator):
cd C:\script\location
.\Prepare-WindowsForVulnScan.ps1

# Then restart the machine
Restart-Computer
```

### For Basic Setup (If no PowerShell access)

```cmd
# As Administrator:
cd C:\script\location
Prepare-WindowsForVulnScan.cmd
```

### To Verify from Scanning Machine

```powershell
# On the SCANNING/SCANNER machine (as Administrator):
.\Verify-WindowsScanReadiness.ps1 -TargetComputer <IP or Hostname>

# With credentials if needed:
.\Verify-WindowsScanReadiness.ps1 -TargetComputer 192.168.1.100 -Username "DOMAIN\scanner"
```

---

## What Gets Configured

### 1. **Windows Management Instrumentation (WMI)**

**Why it matters:** WMI is the foundation for remote system queries. Scanners use WMI classes like:
- `Win32_OperatingSystem` - OS version, build, installation date
- `Win32_ComputerSystem` - Hardware info
- `Win32_Processor` - CPU details
- `Win32_Product` - Installed software/packages
- `Win32_QFE` - Windows patches/updates

**What's configured:**
- Service: `Winmgmt` set to Automatic startup
- Firewall rules enabled for WMI (ports 135, RPC dynamic ports)
- WMI namespace permissions verified

### 2. **Remote Registry Service**

**Why it matters:** Required to read registry information remotely, including:
- Installed software in `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall`
- System configuration details
- Security policies

**What's configured:**
- Service: `RemoteRegistry` set to Automatic startup
- Firewall: RPC and related port access

### 3. **UAC Remote Restrictions**

**What this does:** Modifies `LocalAccountTokenFilterPolicy` registry value
- **Default (0 or not set):** Local admins can only access with explicit elevation tokens
- **Set to 1:** Allows remote operations from network administrators

**Registry path:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy`

**Impact:** Critical for remote WMI queries to work

### 4. **Windows Remote Management (WinRM)**

**Why it matters:** Modern remote management and testing framework
- Used by PowerShell remoting
- Required for advanced scanning scenarios
- Encryption support for sensitive data

**What's configured:**
- Service: `WinRM` set to Automatic startup
- HTTP listener enabled (port 5985)
- Basic authentication enabled

### 5. **Admin Shares**

**What these are:** Hidden administrative shares
- `C$` - C: drive access
- `ADMIN$` - Windows system directory (%SystemRoot%)
- `IPC$` - Inter-process communication
- `D$`, `E$`, etc. - Other drives

**Why needed:** Scanners verify system files and configurations via SMB

**What's configured:**
- `AutoShareServer` registry value set to enable automatic sharing

### 6. **Firewall Rules**

**Enabled rules:**
- Windows Management Instrumentation (WMI)
- File and Printer Sharing (SMB/CIFS) - ports 139, 445
- Named Pipes Over TCP (port 445)
- RPC (port 135)
- WinRM HTTP/HTTPS (ports 5985, 5986)

---

## Detailed Step-by-Step

### Step 1: Run Setup Script on Target Machine

**Before you start:**
- [ ] Log in with an Administrator account
- [ ] If running setup over network/RDP, may need to restart
- [ ] Have a copy of the PowerShell script on the target

**Execute:**

```powershell
# Open PowerShell as Administrator
# (Right-click PowerShell, select "Run as Administrator")

# Navigate to script location
cd C:\path\to\scripts

# Run the preparation script
.\Prepare-WindowsForVulnScan.ps1

# If execution policy prevents running:
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\Prepare-WindowsForVulnScan.ps1

# Backup registry is created automatically
# Log file: C:\Windows\Temp\VulnScanPrep_*.log
```

**What the script does:**
1. Verifies Administrator privileges
2. Backs up registry keys (location shown in terminal)
3. Enables required services
4. Configures firewall rules
5. Sets UAC policy
6. Configures WinRM
7. Enables admin shares
8. Verifies configuration
9. Shows disable/rollback instructions

### Step 2: Restart the Computer

**Critical:** Some changes require restart to take full effect

```powershell
# Restart computer
Restart-Computer -Force

# Or with delay (300 seconds = 5 minutes):
Restart-Computer -Delay 300 -Force -Confirm:$false
```

**Or manually:** Start Menu > Shut down > Restart

### Step 3: Verify Configuration on Target

**After restart, confirm everything is working:**

```powershell
# Check service status
Get-Service Winmgmt, RemoteRegistry, WinRM | Format-Table Name, Status, StartType

# Check UAC setting
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" LocalAccountTokenFilterPolicy

# Check admin shares
Get-SmbShare -Special

# Check WinRM
winrm get winrm/config
```

### Step 4: Test from Scanning Machine

**Run on the SCANNER/SCANNING machine (not the target):**

```powershell
# Basic test - must resolve via DNS or hosts file
.\Verify-WindowsScanReadiness.ps1 -TargetComputer TARGET_HOSTNAME_OR_IP

# With username
.\Verify-WindowsScanReadiness.ps1 -TargetComputer 192.168.1.50 -Username "DOMAIN\ScannerAccount"

# The script tests:
# - Network connectivity (ping, ports)
# - WMI connectivity  
# - Admin share access
# - WinRM connectivity
# - Remote Registry access
# - System information retrieval
```

---

## Verification & Testing

### Manual WMI Test

```powershell
# Test from scanner machine to target
$computer = "192.168.1.100"  # Change to target IP/hostname
$credentials = Get-Credential  # If different user needed

# Simple test
$osInfo = Get-WmiObject Win32_OperatingSystem -ComputerName $computer `
   -Credential $credentials -Authentication PacketPrivacy

Write-Host "OS: $($osInfo.Caption)"
Write-Host "Build: $($osInfo.BuildNumber)"
Write-Host "Version: $($osInfo.Version)"
```

### Manual Admin Share Test

```powershell
# Test UNC path access
$uncPath = "\\192.168.1.100\C$\Windows\System32"

# If current user can access:
Test-Path $uncPath

# If specific credentials needed:
$credentials = Get-Credential
$null = New-PSDrive -Name TestDrive -PSProvider FileSystem -Root $uncPath -Credential $credentials
Get-PSDrive TestDrive
Remove-PSDrive TestDrive
```

### Manual WinRM Test

```powershell
# Test WinRM connectivity
$computer = "192.168.1.100"

Invoke-Command -ComputerName $computer -ScriptBlock {
    @{
        ComputerName = $env:COMPUTERNAME
        OS = (Get-WmiObject Win32_OperatingSystem).Caption
        Memory_GB = [math]::Round(((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB), 2)
        Processes = (Get-Process).Count
    }
}
```

### Manual Remote Registry Test

```powershell
# Open remote registry
$remoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", "192.168.1.100")

# Read Windows version
$versionKey = $remoteReg.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion")
$version = $versionKey.GetValue("CurrentVersion")
$build = $versionKey.GetValue("CurrentBuild")

Write-Host "Version: $version, Build: $build"

$versionKey.Close()
$remoteReg.Close()
```

---

## Security Considerations

### ⚠️ Important Security Notes

1. **LocalAccountTokenFilterPolicy is a security relaxation**
   - Only set this for trusted scanning networks
   - Consider using domain service accounts instead
   - Combine with restrictive firewall rules (firewall should only allow from scanner IPs)

2. **Remote Registry Service**
   - Only enable if necessary for non-server environments
   - Consider disabling for standalone workstations after scan
   - Ensure firewall restricts access by source IP

3. **Admin Shares**
   - Required for credentialed scanning
   - Can be selectively enabled/disabled
   - Monitor for unauthorized access attempts

4. **WinRM**
   - Modern alternative to legacy remote access
   - More secure with encryption support
   - Recommended over legacy methods

### Enterprise Security Best Practices

**Network Isolation:**
```cmd
REM Restrict WMI access to specific IPs only
netsh advfirewall firewall set rule name="Windows Management Instrumentation (WMI-In)" new remoteip=192.168.1.0/24
```

**Time-Limited Configuration:**
- Run scans during maintenance windows
- Disable non-essential remoting services afterward
- Use service-specific accounts with limited privileges

**Monitoring:**
- Monitor Remote Registry access logs
- Track WMI calls and data access
- Log administrative share access

**Alternative: Domain-Based Security**
If using domain service accounts:

```powershell
# Use domain service account instead of local admin
# Requires proper Kerberos delegation setup
# More secure than adjusting LocalAccountTokenFilterPolicy

# Run scanner with domain service account credentials
.\Verify-WindowsScanReadiness.ps1 -TargetComputer SERVER -Username "DOMAIN\ScanService"
```

---

## Troubleshooting

### Issue 1: "Access Denied" on WMI Queries

**Symptoms:** WMI test fails with "Access Denied" error

**Solutions:**

```powershell
# 1. Verify credentials have admin rights
whoami /groups | find "Administrator"

# 2. Check firewall rules specifically
Get-NetFirewallRule -DisplayName "*WMI*" | Format-Table Name, Enabled

# 3. Manually enable WMI firewall rules
Enable-NetFirewallRule -DisplayName "Windows Management Instrumentation (WMI-In)"

# 4. Verify WMI service is running
Get-Service Winmgmt | Format-Table Name, Status, StartType

# 5. Restart WMI service
Restart-Service Winmgmt -Force

# 6. Check WMI repository integrity
# (Can be repaired but requires special steps)
```

### Issue 2: "RPC Server Unavailable"

**Symptoms:** Connection fails with RPC errors

**Causes:** Usually firewall or RPC service issues

**Solutions:**

```powershell
# 1. Enable RPC-related firewall rules
netsh advfirewall firewall set rule group="Remote Event Log Management" new enable=yes
netsh advfirewall firewall set rule group="Remote Service Management" new enable=yes

# 2. Restart RPC service
Restart-Service RpcSs -Force

# 3. Check if port 135 is responding
Test-NetConnection -ComputerName 192.168.1.100 -Port 135

# 4. Verify Windows Firewall isn't blocking
Get-NetFirewallProfile | Format-Table Name, Enabled
```

### Issue 3: "LocalAccountTokenFilterPolicy" Not Working

**Symptoms:** UAC still blocking remote administrative operations

**Solutions:**

```powershell
# 1. Verify registry change applied
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" LocalAccountTokenFilterPolicy

# 2. Set explicitly
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -Value 1 -Force

# 3. Restart for changes to take effect
Restart-Computer -Force

# 4. Verify change persisted after restart
# Then test again
```

### Issue 4: Admin Shares Not Available

**Symptoms:** Cannot access C$, ADMIN$, IPC$ shares

**Solutions:**

```powershell
# 1. Check AutoShareServer setting
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" AutoShareServer

# 2. Enable if needed
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name AutoShareServer -Value 1 -Force

# 3. Restart file sharing service
Restart-Service LanmanServer -Force

# 4. Verify shares visible from another machine
Get-SmbShare -CimSession 192.168.1.100 -Special
```

### Issue 5: WinRM Not Responding

**Symptoms:** WinRM tests fail or timeout

**Solutions:**

```powershell
# 1. Check WinRM listener status
winrm enumerate winrm/config/listener

# 2. Reconfigure WinRM
winrm quickconfig

# 3. Check WinRM service
Get-Service WinRM | Format-Table Name, Status, StartType

# 4. Enable WinRM firewall rules
Enable-NetFirewallRule -DisplayName "*WinRM*"

# 5. Test connectivity
Test-WSMan -ComputerName 192.168.1.100

# 6. If still failing, restart
Restart-Service WinRM -Force
```

### Issue 6: "System Information Returns Empty"

**This is the primary issue this guide addresses**

**Checklist:**

- [ ] WMI service is running (`Get-Service Winmgmt`)
- [ ] RemoteRegistry service is running (`Get-Service RemoteRegistry`)
- [ ] Firewall rules enabled for WMI
- [ ] LocalAccountTokenFilterPolicy = 1
- [ ] Admin share is accessible
- [ ] Credentials provided have admin rights
- [ ] Network connectivity confirmed
- [ ] No antivirus blocking WMI access
- [ ] Restart completed after changes

**If still failing:**

```powershell
# Deep diagnostics
# 1. Check WMI repository
Get-WmiObject -Class __SystemSecurity -Namespace root\cimv2 -Authentication PacketPrivacy

# 2. Test specific WMI classes
Get-WmiObject Win32_OperatingSystem -ComputerName 192.168.1.100 -Credential $creds -Authentication PacketPrivacy

# 3. Check WMI event log for errors
Get-EventLog Application | Where-Object { $_.Source -like "*WMI*" } | Sort-Object Time -Descending | Select-Object -First 20

# 4. Rebuild WMI repository (advanced, may affect system)
# Stop Winmgmt service
# Delete C:\Windows\System32\wbem\Repository
# Restart Winmgmt
```

---

## Rollback Instructions

### To Disable Remote Scanning Capabilities

**Run these commands as Administrator to revert changes:**

```powershell
# ============================================================================
# STOP SERVICES
# ============================================================================

# Stop and disable Remote Registry (for security, if not needed)
Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue
Set-Service -Name RemoteRegistry -StartupType Disabled -ErrorAction SilentlyContinue

# Keep WMI running (needed for system diagnostics)
# Keep WinRM optional based on needs


# ============================================================================
# RESTORE UAC RESTRICTIONS
# ============================================================================

# Option 1: Delete the policy (full restriction on local admins)
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -ErrorAction SilentlyContinue

# Option 2: Set to 0 (domain users only, local admins still require elevation)
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 0 -ErrorAction SilentlyContinue


# ============================================================================
# DISABLE ADMIN SHARES
# ============================================================================

# This effectively "hides" admin shares from casual access
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareServer' -Value 0 -ErrorAction SilentlyContinue

# Restart service for share changes
Restart-Service LanmanServer -Force


# ============================================================================
# DISABLE FIREWALL RULES
# ============================================================================

# WMI rules
Disable-NetFirewallRule -DisplayName "Windows Management Instrumentation (WMI-In)" -ErrorAction SilentlyContinue
Disable-NetFirewallRule -DisplayName "Windows Management Instrumentation (WINMGMT-In)" -ErrorAction SilentlyContinue
Disable-NetFirewallRule -DisplayName "Windows Management Instrumentation (ASYNC-In)" -ErrorAction SilentlyContinue

# SMB/File Sharing rules (careful: may break file sharing)
Disable-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)" -ErrorAction SilentlyContinue

# ============================================================================
# RESTART REQUIRED
# ============================================================================

Restart-Computer -Force
```

### To Restore from Registry Backup

If a registry backup was created:

```cmd
REM The backup file is typically: C:\Windows\Temp\RegistryBackup_*.reg

REM To restore:
reg import C:\Windows\Temp\RegistryBackup_YYYYMMDD_HHMMSS.reg

REM Then verify and restart if needed
```

### To Test After Rollback

```powershell
# Verify services are disabled
Get-Service RemoteRegistry | Format-Table Name, Status, StartType

# Verify UAC is restored
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" LocalAccountTokenFilterPolicy

# Verify firewall rules
Get-NetFirewallRule -DisplayName "*WMI*" | Format-Table Name, Enabled

# Verify admin shares disabled
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" AutoShareServer
```

---

## Additional Resources

### Windows Security Documentation

- [Enable WMI through a Firewall](https://learn.microsoft.com/en-us/windows/win32/wmicore/setting-up-wmi)
- [Windows Remote Management (WinRM)](https://learn.microsoft.com/en-us/windows/win32/winrm/about-windows-remote-management)
- [Understanding User Account Control](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/)
- [Admin Shares](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/create-and-manage-hidden-shares)

### Vulnerability Scanning Tool Documentation

- CCure Audit PRO documentation
- Nessus - Windows Credentialed Scans
- OpenVAS - Windows Scanning
- Qualys - Windows Credentialed Scanning

### Network Ports Reference

| Service | Port(s) | Protocol | Purpose |
|---------|---------|----------|---------|
| RPC Endpoint Mapper | 135 | TCP | Maps RPC services to dynamic ports |
| NetBIOS Session | 139 | TCP | Legacy file/print sharing |
| SMB/CIFS | 445 | TCP | Modern file/print sharing |
| WinRM HTTP | 5985 | TCP | Remote management (unencrypted) |
| WinRM HTTPS | 5986 | TCP | Remote management (encrypted) |
| WMI | Dynamic | TCP | Queries via RPC endpoint mapper |

### Event Log Locations for Troubleshooting

- Windows Logs > System (service start/stop events)
- Windows Logs > Application (WMI events)
- Applications and Services > Microsoft > Windows > WMI-Activity
- Security log (if auditing enabled)

View with:
```powershell
Get-EventLog System -Newest 20 | Format-Table TimeGenerated, EventID, Message
Get-WinEvent -LogName "Microsoft-Windows-WMI-Activity/Operational" -MaxEvents 20
```

---

## Summary

| Component | Before | After | Purpose |
|-----------|--------|-------|---------|
| Winmgmt | May be Manual | Automatic | System information retrieval |
| RemoteRegistry | May be Disabled | Automatic | Registry query access |
| WinRM | May be Disabled | Automatic | Remote management |
| LocalAccountTokenFilterPolicy | 0 or unset | 1 | Enable remote admin queries |
| Firewall WMI rules | Blocked | Enabled | Allow WMI traffic |
| Firewall SMB rules | May be Blocked | Enabled | Allow file sharing |
| Admin Shares | AutoShareServer=0 | AutoShareServer=1 | Enable C$, ADMIN$, IPC$ |

---

## Support & Contact

For issues with:
- **The automated scripts:** Check logs in `C:\Windows\Temp\VulnScanPrep_*.log`
- **Specific scanning tool integration:** Consult CCure Audit PRO, Nessus, or OpenVAS documentation
- **Windows configuration:** Contact IT/System Administration
- **Network/Firewall:** Contact Network Administration team

---

**Last Updated:** April 2024  
**Tested On:** Windows Server 2016, 2019, 2022 | Windows 10, 11 Pro/Enterprise  
**Version:** 1.0
