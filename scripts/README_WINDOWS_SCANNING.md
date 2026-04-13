# Windows Credentialed Vulnerability Scanning - Setup & Troubleshooting

This collection of scripts solves the common problem: **credentialed scans can authenticate to Windows but fail to retrieve system information** (OS, kernel, CPU, installed packages, CVEs all show empty).

## The Problem

When using vulnerability scanning tools (CCure Audit PRO, Nessus, OpenVAS, Qualys, etc.):
- ✓ Authentication succeeds
- ✓ Initial connection works
- ✗ System information is empty/null
- ✗ No OS version, packages, patches found
- ✓ But same scan works fine on Linux machines

**Root Causes:**
1. WMI (Windows Management Instrumentation) service not running or inaccessible
2. Remote Registry service disabled
3. UAC (User Account Control) blocking remote admin queries
4. Firewall rules blocking WMI/SMB ports
5. Admin shares (C$, ADMIN$) not available
6. WinRM not configured

## Solutions Provided

### Quick Start (Most Users)

1. **On Windows machine to be scanned** (as Administrator):
   ```powershell
   .\Prepare-WindowsForVulnScan.ps1
   Restart-Computer
   ```

2. **Verify from scanning machine**:
   ```powershell
   .\Verify-WindowsScanReadiness.ps1 -TargetComputer <IP_or_Hostname>
   ```

3. **If tests pass:** Run your vulnerability scan
4. **When done:** (Optional) Run disable commands to secure the machine

---

## Script Guide

### 1. `Prepare-WindowsForVulnScan.ps1`
**Use this to SET UP a Windows machine for scanning**

**Run on:** The Windows MACHINE TO BE SCANNED (target)

**Requires:** Administrator privileges

**What it does:**
- ✓ Enables WMI service (Winmgmt)
- ✓ Enables Remote Registry service
- ✓ Configures Windows Firewall rules (WMI, SMB)
- ✓ Disables UAC remote restrictions via registry
- ✓ Enables admin shares (C$, ADMIN$, IPC$)
- ✓ Configures Windows Remote Management (WinRM)
- ✓ Backs up registry automatically
- ✓ Generates verification report

**Time:** ~2-3 minutes + restart

**Example:**
```powershell
cd C:\scripts
.\Prepare-WindowsForVulnScan.ps1
# Review log: C:\Windows\Temp\VulnScanPrep_*.log
Restart-Computer
```

**Output:**
- Scan-ready Windows machine
- Registry backup in C:\Windows\Temp\
- Detailed log file

---

### 2. `Verify-WindowsScanReadiness.ps1`
**Use this to TEST a Windows machine from the scanner/scanning tool machine**

**Run on:** The SCANNING MACHINE (not the target)

**Requires:** Administrator privileges on scanning machine

**What it does:**
- ✓ Resolves hostname to IP
- ✓ Tests network connectivity (ping, ports)
- ✓ Tests WMI connectivity
- ✓ Tests admin share access
- ✓ Tests WinRM connectivity
- ✓ Tests Remote Registry access
- ✓ Retrieves actual system information
- ✓ Generates verification report

**Time:** ~1-2 minutes

**Examples:**
```powershell
# Basic test
.\Verify-WindowsScanReadiness.ps1 -TargetComputer 192.168.1.100

# With specific credentials
.\Verify-WindowsScanReadiness.ps1 -TargetComputer WORKSTATION1 -Username "DOMAIN\scanner"

# With password
$pass = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
.\Verify-WindowsScanReadiness.ps1 -TargetComputer 192.168.1.50 -Username "admin" -Password $pass
```

**Success Criteria:**
- ✓ Network connectivity: OPEN (ports 135, 445, 5985)
- ✓ WMI Connection: Successful
- ✓ OS information retrieved
- ✓ Admin Shares accessible
- ✓ Remote Registry accessible
- ✓ System Information Retrieval: All categories retrieved

---

### 3. `Prepare-WindowsForVulnScan.cmd`
**Use this as LEGACY alternative if PowerShell is unavailable**

**Run on:** The Windows machine to be scanned

**Requires:** Administrator Command Prompt

**What it does:**
- ✓ Same as PowerShell version but using cmd/batch
- ✓ Enables services via `net` and `sc` commands
- ✓ Modifies registry via `reg` command
- ✓ Configures firewall via `netsh`
- ✓ Generates log file

**Note:** Less sophisticated than PowerShell version; lacks some error handling

**Example:**
```cmd
REM Run as Administrator
cd C:\scripts
Prepare-WindowsForVulnScan.cmd
```

---

### 4. `Diagnose-WindowsScanIssues.ps1`
**Use this to TROUBLESHOOT if basic setup doesn't work**

**Run on:** The Windows machine having problems (target)

**Requires:** Administrator privileges

**What it does:**
- ✓ Comprehensive diagnostic of all 10 critical areas
- ✓ Tests each service individually
- ✓ Checks registry settings
- ✓ Verifies firewall rules
- ✓ Tests WMI queryability
- ✓ Checks network configuration
- ✓ Validates user credentials/groups
- ✓ Optional HTML report export

**Time:** 3-5 minutes (depending on WMI repository size)

**Examples:**
```powershell
# Run full diagnostics
.\Diagnose-WindowsScanIssues.ps1

# With detailed WMI repository analysis
.\Diagnose-WindowsScanIssues.ps1 -Detailed

# Generate HTML report
.\Diagnose-WindowsScanIssues.ps1 -ExportReport "C:\Reports\Diagnosis.html"

# Interactive mode (prompts for each section)
.\Diagnose-WindowsScanIssues.ps1 -Interactive
```

**Output:**
- Screen report with color-coded results
- 10-point diagnostic checklist
- Specific recommendations for fixes
- Optional HTML file

---

## Decision Tree

```
┌─ Problem: Credentialed scan sees no system info
│
├─ Never set up this Windows machine before
│  └─> Run: Prepare-WindowsForVulnScan.ps1
│
├─ Setup script ran, but verification fails
│  ├─> Check logs: C:\Windows\Temp\VulnScanPrep_*.log
│  └─> Run: Diagnose-WindowsScanIssues.ps1 (on target)
│
├─ Verification from scanner machine shows errors
│  └─> Run: Verify-WindowsScanReadiness.ps1 -TargetComputer X (on scanner)
│
├─ Some tests pass, some fail
│  └─> Run: Diagnose-WindowsScanIssues.ps1 -Detailed
│
├─ Don't have PowerShell or execution policy issues
│  └─> Run: Prepare-WindowsForVulnScan.cmd
│
└─ Everything setup but still no data from scanner
   ├─> Check if Windows Firewall actually disabled services
   ├─> Check if antivirus is blocking WMI/registry access
   ├─> Check network firewall (external to Windows)
   ├─> Verify scanning account has admin rights on target
   └─> Run: Diagnose-WindowsScanIssues.ps1 -ExportReport
```

---

## Complete Workflow

### For First-Time Setup

**1. ON THE WINDOWS TARGET MACHINE:**

```powershell
# Step 1: Run setup
.\Prepare-WindowsForVulnScan.ps1

# Step 2: Restart (critical!)
Restart-Computer

# Step 3: Wait for reboot (2-5 minutes)
# Then continue to step 4...
```

**2. FROM THE SCANNING MACHINE:**

```powershell
# Step 4: Verify everything works
.\Verify-WindowsScanReadiness.ps1 -TargetComputer 192.168.1.50

# Step 5: Check results:
#   - All green/OK = ready to scan
#   - Some yellow/warnings = may still work but check them
#   - Any red/errors = run diagnostics on target
```

**3. BACK ON WINDOWS TARGET IF NEEDED:**

```powershell
# Step 6: If errors, run diagnostics
.\Diagnose-WindowsScanIssues.ps1

# Step 7: Address any issues found (script provides guidance)
# Then repeat verification from scanning machine
```

**4. OPTIONAL - AFTER SCAN COMPLETES:**

```powershell
# Step 8: Disable scanning capabilities for security
# Run the disable commands from: Prepare-WindowsForVulnScan.ps1 -DisableOnly
# OR manually:

# Stop non-essential services
Stop-Service RemoteRegistry -Force
Set-Service RemoteRegistry -StartupType Disabled

# Restore UAC restriction
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy

# Hide admin shares
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f

# Restart
Restart-Computer -Force
```

---

## For Enterprise Deployments

Deploy to multiple machines via GPO or configuration management:

```powershell
# PowerShell Remoting
$servers = "SERVER1", "SERVER2", "SERVER3"

Invoke-Command -ComputerName $servers -ScriptBlock {
    Set-Service Winmgmt, RemoteRegistry, WinRM -StartupType Automatic
    Start-Service Winmgmt, RemoteRegistry, WinRM
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 1 /f | Out-Null
}

# Restart all
Restart-Computer -ComputerName $servers -Force -AsJob
```

---

## Documentation Files

- **`WINDOWS_SCAN_SETUP_GUIDE.md`** - Comprehensive detailed guide
  - Problem explanation
  - Step-by-step instructions
  - Security considerations
  - Troubleshooting for each issue
  - Rollback procedures
  - Network ports reference

- **`QUICK_REFERENCE.md`** - One-page cheat sheet
  - 5-minute quick setup
  - Command-by-command execution
  - Quick verification tests
  - Common issues & fixes
  - Enterprise deployment examples

---

## What Gets Configured

| Component | Before | After | Why |
|-----------|--------|-------|-----|
| **Winmgmt** | Varies | Automatic/Running | Provides WMI queries for system info |
| **RemoteRegistry** | Varies | Automatic/Running | Allows registry access for software list |
| **WinRM** | Varies | Automatic/Running | Remote management and testing |
| **LocalAccountTokenFilterPolicy** | 0 or unset | 1 | Enables remote admin operations |
| **AutoShareServer** | Varies | 1 | Enables C$, ADMIN$, IPC$ shares |
| **Firewall - WMI** | Blocked | Enabled | Allows WMI queries |
| **Firewall - SMB** | May be blocked | Enabled | Allows file sharing queries |

---

## What Information Gets Retrieved

After successful setup, credentialed scans can retrieve:

✓ Operating System (name, version, build, release)  
✓ Installation date and uptime  
✓ System manufacturer and model  
✓ CPU name, cores, speed  
✓ RAM/Memory amount  
✓ Network configuration  
✓ Installed software (from registry and WMI)  
✓ Windows patches (KB articles)  
✓ Running services  
✓ User accounts  
✓ System drivers  
✓ All CVE/vulnerability data based on packages  

---

## Environment Requirements

### On Target Windows Machine

- **OS:** Windows Vista, Server 2008, or newer (tested on Win10, 11, Server 2016/2019/2022)
- **PowerShell:** 3.0+ (for PS script) or PowerShell 2.0+ (basic features)
- **Permissions:** Local Administrator rights
- **Network:** Internet not required; LAN connectivity only
- **Antivirus:** May need to add WMI/registry access to whitelist

### On Scanning Machine

- **OS:** Any modern OS with scanning tool (Windows, Linux, macOS)
- **Network:** LAN connectivity to target machine
- **Permissions:** Administrator/root rights on scanning machine
- **PowerShell:** 3.0+ (for verification script)

---

## Security Notes

### ⚠️ Important

1. **LocalAccountTokenFilterPolicy=1** relaxes UAC security
   - Only set this for scanning networks
   - Consider domain service accounts instead (more secure)
   - Reset to 0 or delete after scanning

2. **Remote Registry Service**
   - Provides registry file access
   - Disable after scanning if not needed long-term
   - Restrict via firewall to scanner IPs only

3. **Admin Shares**
   - Required for scanning
   - Can be selectively disabled
   - Monitor access via logs

4. **WinRM**
   - More secure alternative to legacy methods
   - Supports encryption (HTTPS)
   - Can disable basic auth if needed

### Best Practices

- [ ] Use separate scanner service account (not domain admin)
- [ ] Configure firewall rules to restrict access by source IP
- [ ] Scan during maintenance windows
- [ ] Disable remote access after scans complete
- [ ] Monitor and log all remote registry/WMI access
- [ ] Use enterprise firewall to restrict scanner IPs only
- [ ] Test in non-production environment first

---

## Logs & Output

### Generated Files

**Setup Script:**
- `C:\Windows\Temp\VulnScanPrep_YYYYMMDD_HHMMSS.log` - Detailed execution log
- `C:\Windows\Temp\RegistryBackup_YYYYMMDD_HHMMSS.reg` - Registry backup (if backup enabled)

**Verification Script:**
- `C:\Windows\Temp\VulnScanVerify_YYYYMMDD_HHMMSS.log` - Test results log

**Diagnostic Script:**
- `C:\Windows\Temp\Diagnosis_YYYYMMDD_HHMMSS.html` - HTML report (if export requested)

### Viewing Logs

```powershell
# View setup log
Get-Content C:\Windows\Temp\VulnScanPrep_*.log

# Real-time monitoring
Get-Content C:\Windows\Temp\VulnScanPrep_*.log -Wait

# Search for errors
Select-String "ERROR" C:\Windows\Temp\VulnScanPrep_*.log
```

---

## Troubleshooting Quick Links

**Symptom → Solution:**

| Symptom | Try First | Then Try |
|---------|-----------|----------|
| "Access Denied" | Verify admin rights | Run Diagnose script |
| "RPC Unavailable" | Restart RpcSs service | Check firewall |
| "Can't access shares" | Restart LanmanServer | Check AutoShareServer setting |
| "WMI fails" | Restart Winmgmt | Check WMI repository |
| "Still empty results" | Run full diagnostics | Check network firewall |

See **`WINDOWS_SCAN_SETUP_GUIDE.md`** for detailed troubleshooting.

---

## Support Resources

### Integration with Common Scanning Tools

- **CCure Audit PRO** - Uses WMI, admin shares, remote registry
- **Nessus** - Credentialed scans require WMI + registry/SMB access
- **OpenVAS** - WMI scanning for Windows vulnerability detection
- **Qualys** - Credentialed Windows scanning via WMI
- **Rapid7 Nexpose/InsightVM** - Uses WMI for Windows assessments
- **Microsoft Defender for Endpoint** - Uses WMI for system queries

### Microsoft Documentation

- [WMI Setup Guide](https://learn.microsoft.com/en-us/windows/win32/wmicore/setting-up-wmi)
- [Windows Remote Management](https://learn.microsoft.com/en-us/windows/win32/winrm/about-windows-remote-management)
- [User Account Control](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/)
- [Remote Registry Service](https://learn.microsoft.com/en-us/windows-server/administration/remote-server-administration-tools/remote-server-administration-tools)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Apr 2024 | Initial release with PowerShell, CMD, verification, and diagnostic scripts |

---

## License & Disclaimer

These scripts are provided as-is for legitimate security testing and vulnerability scanning purposes only. 

**Usage Responsibility:**
- Obtain proper authorization before scanning any system
- Use only on systems you own or have explicit permission to test
- Modify firewall/security settings only with organizational approval
- Follow your enterprise security policies

---

## Quick Command Reference

```powershell
# Setup
.\Prepare-WindowsForVulnScan.ps1

# Verify
.\Verify-WindowsScanReadiness.ps1 -TargetComputer 192.168.1.100

# Diagnose
.\Diagnose-WindowsScanIssues.ps1

# Check status
Get-Service Winmgmt, RemoteRegistry, WinRM | Select Name, Status, StartType
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" LocalAccountTokenFilterPolicy
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" AutoShareServer

# Disable (security)
Set-Service RemoteRegistry -StartupType Disabled
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy

# Restart
Restart-Computer -Force
```

---

**For questions or issues, consult the full documentation files or run the diagnostic script.**
