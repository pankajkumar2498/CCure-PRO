# Windows Credentialed Scanning - Setup Checklist

**Target Machine:** ________________  
**Target IP/Hostname:** ________________  
**Scanner Tool:** ________________ (e.g., CCure Audit PRO)  
**Scanning Account:** ________________  
**Date:** ________________  
**Completed By:** ________________  

---

## PRE-SETUP VERIFICATION

- [ ] Have Administrator access to target Windows machine
- [ ] Have Administrator access to scanning machine
- [ ] Both machines can reach each other on network
- [ ] Windows machine is a supported version (Vista/Server 2008 or newer)
- [ ] Have a copy of the setup scripts available
- [ ] Ready to restart the Windows machine
- [ ] Backup completed (if required)

---

## STEP 1: PREPARE TARGET WINDOWS MACHINE

**Time Required:** 2-3 minutes + 5 minute restart

### Run Setup Script

- [ ] Log in as Administrator to target Windows machine
- [ ] Open PowerShell as Administrator
- [ ] Navigate to script folder: `cd C:\scripts`
- [ ] Run: `.\Prepare-WindowsForVulnScan.ps1`
- [ ] Wait for script to complete (watch for completion message)
- [ ] Review log file location (should be `C:\Windows\Temp\VulnScanPrep_*.log`)
- [ ] Verify registry backup was created

**If errors occur:**
- [ ] Check log file for specific errors: `Get-Content C:\Windows\Temp\VulnScanPrep_*.log`
- [ ] Verify running as Administrator
- [ ] If execution policy blocks: `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process`
- [ ] Try again

### Post-Setup Restart

- [ ] Restart the Windows machine
  ```powershell
  Restart-Computer -Force
  ```
- [ ] Wait 5 minutes for full startup
- [ ] Log back in as Administrator

### Verify Setup on Target

After reboot, verify locally on the Windows machine:

- [ ] Services are running:
  ```powershell
  Get-Service Winmgmt, RemoteRegistry, WinRM | Format-Table Name, Status, StartType
  ```
  **Expected:** All three "Running" and "Automatic"

- [ ] Registry settings correct:
  ```powershell
  Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" LocalAccountTokenFilterPolicy
  ```
  **Expected:** Value = 1

- [ ] Admin shares enabled:
  ```powershell
  Get-SmbShare -Special | Format-Table Name, Path
  ```
  **Expected:** See C$, ADMIN$, IPC$ in list

- [ ] WinRM configured:
  ```powershell
  winrm get winrm/config
  ```
  **Expected:** No errors, shows WinRM configuration

---

## STEP 2: VERIFY FROM SCANNING MACHINE

**Time Required:** 1-2 minutes

**Run on the SCANNING MACHINE (not the target)**

### Network Connectivity

- [ ] Ping target machine:
  ```powershell
  Test-Connection -ComputerName 192.168.1.100
  ```
  **Result:** [___] Ping ✓ / ! / ✗

- [ ] Resolve hostname:
  ```powershell
  [System.Net.Dns]::GetHostAddresses("targetname")
  ```
  **Result:** [___] Resolves to IP ✓ / ! / ✗

### Run Verification Script

- [ ] Open PowerShell as Administrator on scanning machine
- [ ] Copy verification script to accessible location
- [ ] Run verification:
  ```powershell
  .\Verify-WindowsScanReadiness.ps1 -TargetComputer 192.168.1.100
  ```
  Or with credentials:
  ```powershell
  .\Verify-WindowsScanReadiness.ps1 -TargetComputer 192.168.1.100 -Username "DOMAIN\scanner"
  ```

### Check Results

**On successful output, verify these checks passed:**

- [ ] Network Connectivity: Port 135 OPEN
- [ ] Network Connectivity: Port 445 OPEN  
- [ ] Network Connectivity: Port 5985 OPEN
- [ ] WMI Connectivity: ✓ Connected Successfully
- [ ] WMI Connectivity: Computer Name retrieved
- [ ] Admin Share Access: ✓ Access granted
- [ ] WinRM Connectivity: ✓ Connected
- [ ] Remote Registry Access: ✓ Successful
- [ ] System Information Retrieval: OS Information ✓
- [ ] System Information Retrieval: Computer System ✓
- [ ] System Information Retrieval: Processor ✓

**Result:** All green ✓ / Some warnings ! / Some errors ✗

---

## STEP 3: TROUBLESHOOTING (IF NEEDED)

**If verification had errors or warnings:**

### Option A: Run Full Diagnostics on Target

- [ ] Go back to target Windows machine
- [ ] Open PowerShell as Administrator
- [ ] Run:
  ```powershell
  .\Diagnose-WindowsScanIssues.ps1
  ```
- [ ] Review output for specific issues
- [ ] Check Severity column:
  - [ ] Green ✓ = OK
  - [ ] Yellow ! = Fix if possible
  - [ ] Red ✗ = Must fix before scanning

### Option B: Manual Checks

**If WMI test failed:**

- [ ] Check WMI service on target:
  ```powershell
  Get-Service Winmgmt
  ```
  - [ ] If not running: `Start-Service Winmgmt`

- [ ] Restart WMI:
  ```powershell
  Restart-Service Winmgmt -Force
  ```

- [ ] Check firewall rules for WMI:
  ```powershell
  Get-NetFirewallRule -DisplayName "*WMI*" | Format-Table Name, Enabled
  ```
  - [ ] If disabled: Enable them manually

**If RPC/Port 135 failed:**

- [ ] Check RPC service:
  ```powershell
  Get-Service RpcSs
  ```
  - [ ] Must be running

- [ ] Restart RPC:
  ```powershell
  Restart-Service RpcSs -Force
  ```

**If SMB/Port 445 failed:**

- [ ] Check file sharing service:
  ```powershell
  Get-Service LanmanServer
  ```
  - [ ] Must be running

- [ ] Verify admin shares:
  ```powershell
  Get-SmbShare -Special
  ```
  - [ ] Should see C$, ADMIN$, IPC$

**If all else fails:**

- [ ] Run setup script again:
  ```powershell
  .\Prepare-WindowsForVulnScan.ps1
  ```

- [ ] Restart machine again:
  ```powershell
  Restart-Computer -Force
  ```

- [ ] Run verification again

---

## STEP 4: RUN VULNERABILITY SCAN

**When all tests pass ✓**

### In Scanning Tool (e.g., CCure Audit PRO)

- [ ] Create new credentialed scan
- [ ] Target: [___________________]
- [ ] Scanning account: [___________________]
- [ ] Credentials: [___________________]
- [ ] Protocol: WMI / SMB (usually auto-detected)
- [ ] Port: 445 for SMB, 135 for RPC (usually auto)
- [ ] Start scan

### Monitor Results

- [ ] Scan starts without connection errors
- [ ] Progress shows data being retrieved:
  - [ ] ✓ OS Information
  - [ ] ✓ System Info
  - [ ] ✓ Software List
  - [ ] ✓ Patches
  - [ ] ✓ Services
  - [ ] ✓ Network Info

- [ ] Scan completes successfully
- [ ] Vulnerabilities/CVEs detected (should not be empty list)

**If scan still returns no data:**

- [ ] Check scan logs in CCure/Nessus for specific WMI errors
- [ ] Run diagnostic script again: `.\Diagnose-WindowsScanIssues.ps1 -Detailed`
- [ ] Check Windows Event Log for WMI errors
- [ ] Verify network firewall not blocking between machines
- [ ] Verify antivirus not blocking WMI/registry access

---

## STEP 5: COMPLETION & SECURITY (OPTIONAL)

**After scan completes - to improve security:**

### Disable Remote Access

- [ ] On target Windows machine as Administrator, run:
  ```powershell
  .\Prepare-WindowsForVulnScan.ps1 -DisableOnly
  ```

- [ ] Or manually disable:

  ```powershell
  # Stop Remote Registry
  Stop-Service RemoteRegistry -Force
  Set-Service RemoteRegistry -StartupType Disabled
  
  # Restore UAC restriction
  Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy
  
  # Hide admin shares
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name AutoShareServer -Value 0
  
  # Restart
  Restart-Computer -Force
  ```

- [ ] Restart machine for changes to take effect
- [ ] Verify disabled:
  - [ ] Remote Registry service: Disabled/Stopped
  - [ ] LocalAccountTokenFilterPolicy: Not present
  - [ ] Admin shares: Not visible

---

## FINAL VERIFICATION CHECKLIST

**Can check these off as you complete the setup:**

### On Target Machine

- [ ] Winmgmt service: Running, Automatic
- [ ] RemoteRegistry service: Running, Automatic  
- [ ] WinRM service: Running, Automatic
- [ ] LocalAccountTokenFilterPolicy: = 1
- [ ] AutoShareServer: = 1
- [ ] Firewall rules enabled for WMI/SMB
- [ ] Machine restarted at least once

### From Scanning Machine

- [ ] Network connectivity: All ports open
- [ ] WMI query: Successful
- [ ] Admin share: Accessible
- [ ] Remote Registry: Accessible
- [ ] System information: Retrieved (OS, CPU, memory, etc.)

### Scanning Tool

- [ ] Credentials accepted
- [ ] System information displayed (not empty)
- [ ] Packages/software list detected
- [ ] Vulnerabilities identified
- [ ] Scan completes without WMI errors

---

## DOCUMENTATION FILES

**For detailed information, see:**

- `README_WINDOWS_SCANNING.md` - Overview and quick start
- `WINDOWS_SCAN_SETUP_GUIDE.md` - Comprehensive guide with security details
- `QUICK_REFERENCE.md` - Command cheat sheet
- `Prepare-WindowsForVulnScan.ps1` - Main setup script
- `Verify-WindowsScanReadiness.ps1` - Verification from scanner
- `Diagnose-WindowsScanIssues.ps1` - Advanced troubleshooting

---

## QUICK TROUBLESHOOTING MATRIX

| Symptom | Check First | Then Try | Doc Reference |
|---------|-------------|----------|----------------|
| Scan connects but no data | Services running | Restart Winmgmt | GUIDE section 3 |
| "Access Denied" | Admin rights | Check UAC setting | GUIDE section 6 |
| "RPC Server Unavailable" | Firewall rules | Restart RpcSs | GUIDE section 7 |
| Can't access C$ share | AutoShareServer | Restart LanmanServer | GUIDE section 5 |
| "WMI Connection Failed" | Check if Winmgmt running | Run full diagnostic | Diagnose script |
| Port 445 not responding | SMB firewall rule | Restart LanmanServer | GUIDE section 5 |

---

## EMERGENCY ROLLBACK

**If you need to reverse all changes quickly:**

```powershell
# Fastest rollback
Stop-Service RemoteRegistry -Force
Set-Service RemoteRegistry -StartupType Disabled
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -Force
Restart-Computer -Force
```

**To restore from registry backup:**

```cmd
reg import C:\Windows\Temp\RegistryBackup_YYYYMMDD_HHMMSS.reg
```

---

## NOTES & OBSERVATIONS

**Setup Date:** ________________  

**Baseline Issues Found:**  
_________________________________________  
_________________________________________  

**Steps Taken to Resolve:**  
_________________________________________  
_________________________________________  

**Successful?** ☐ Yes ☐ No ☐ Partial  

**Scan Results Summary:**  
_________________________________________  
_________________________________________  

**Post-Scan Actions Taken:**  
_________________________________________  
_________________________________________  

**Follow-up Required?** ☐ Yes ☐ No  

**Follow-up Details:**  
_________________________________________  
_________________________________________  

---

**Completed By:** ________________  
**Date Completed:** ________________  
**Next Review Date:** ________________  

---

**For help:** See README_WINDOWS_SCANNING.md or run Diagnose-WindowsScanIssues.ps1
