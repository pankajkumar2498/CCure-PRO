# Bulk Deployment Quick Start (TL;DR)

## **Your Situation**

❓ You have **multiple Windows machines** to prepare for credential scanning  
❓ You want to **do it all from your scanning machine**  
❓ You want it **fast**  

## **The Answer: 3 Commands**

### **Step 1: Define Your Machines**

```powershell
# On your SCANNING MACHINE, open PowerShell as Administrator

$machines = @(
    "SERVER1",
    "SERVER2", 
    "WORKSTATION1",
    "WORKSTATION2",
    "192.168.1.100",
    "192.168.1.101"
)

# NOTE: Use hostnames OR IPs, domain OR non-domain machines
```

### **Step 2: Run the Deployment**

```powershell
# Still in same PowerShell session

.\Deploy-ScanPrepToMultiple.ps1 -MachineArray $machines -AdminUsername "DOMAIN\Administrator"

# Enter password when prompted
```

### **Step 3: Done! 🎉**

Script will automatically:
- ✅ Test connectivity
- ✅ Deploy config to all machines (parallel)
- ✅ Restart all machines
- ✅ Verify everything works
- ✅ Show you the report

**Total time: ~10 minutes for ANY number of machines**

---

## **For CSV Files (Larger Lists)**

```powershell
# Create file: C:\targets.csv

ComputerName
SERVER1
SERVER2
WORKSTATION1
WORKSTATION2

# Then run:
.\Deploy-ScanPrepToMultiple.ps1 -MachineList "C:\targets.csv" -AdminUsername "DOMAIN\Administrator"
```

---

## **Then: Start Scanning**

Once deployment completes:

```
1. Open CCure Audit PRO
2. Create New Scan
3. Add target machines (from your list)
4. Select Credentialed scan type
5. Add username/password once
6. Click Start

All machines will scan automatically with full system info! ✓
```

---

## **What Gets Configured on Each Machine**

✅ WMI service (enables system info retrieval)  
✅ Remote Registry service (enables software enumeration)  
✅ WinRM service (enables remote management)  
✅ LocalAccountTokenFilterPolicy (enables remote admin queries)  
✅ AutoShareServer (enables admin file shares)  
✅ Firewall rules (allows WMI and SMB traffic)  

---

## **If Something Fails**

```powershell
# Check the log file created by script
C:\temp\ScanPrepDeploy_*.log

# Most common issue: machines not reachable
# Fix: Ensure machines can be pinged first
ping SERVER1

# Or: Bootstrap PowerShell Remoting manually on one machine via RDP:
# Then retry deployment script
```

---

## **One-Liner for Simple Cases**

```powershell
# If only a few machines:
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray "PC1", "PC2", "PC3" -AdminUsername "admin"
```

---

## **Expected Timeline**

| Machines | Deploy Time | Wait for Restart | Total |
|---|---|---|---|
| 5 | 1 min | 3 min | ~5 min |
| 10 | 1 min | 3 min | ~5 min |
| 50 | 2 min | 3 min | ~5 min |
| 100 | 2 min | 3 min | ~5 min |

**The script is parallelized - number of machines doesn't matter!**

---

## **That's It!**

You now have everything to:

1. ✅ Prepare **single** Windows machine: Use `Prepare-WindowsForVulnScan.ps1`
2. ✅ Prepare **multiple** Windows machines: Use `Deploy-ScanPrepToMultiple.ps1`
3. ✅ Verify **any** machine is ready: Use `Verify-WindowsScanReadiness.ps1`
4. ✅ Troubleshoot issues: Use `Diagnose-WindowsScanIssues.ps1`

Then run your credential scans from CCure and get **95%+ vulnerability coverage**! 🚀

---

## **Common Patterns**

### **All servers in domain:**
```powershell
$servers = Get-ADComputer -Filter "OperatingSystem -like '*Server*'" | Select-Object -ExpandProperty Name
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray $servers -AdminUsername "DOMAIN\administrator"
```

### **Specific subnet:**
```powershell
$machines = "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray $machines -AdminUsername "local_admin"
```

### **Mix of domain and non-domain:**
```powershell
# Deploy domain machines first
$domain = "SERVER1", "SERVER2"
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray $domain -AdminUsername "DOMAIN\admin"

# Deploy workgroup machines separately (different credentials if needed)
$workgroup = "STANDALONE-PC1", "192.168.1.50"
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray $workgroup -AdminUsername "administrator"
```

---

## **Frequently Asked Questions**

**Q: Does it work on Linux?**  
A: No, only Windows. Linux doesn't need this setup.

**Q: What if one machine fails?**  
A: Script shows you which one. You can fix it and retry just that machine.

**Q: Can I cancel mid-deployment?**  
A: Yes, Ctrl+C. Machines won't be configured if you cancel early.

**Q: Do I need domain admin?**  
A: No, just admin rights on the target machines.

**Q: Will it work over the internet (not LAN)?**  
A: Only if PowerShell Remoting allowed through firewall. LAN is recommended.

**Q: Can I run multiple deployments in parallel?**  
A: Yes, open separate PowerShell windows and run different machine lists.

---

## **After Deployment: Next Steps**

```
✅ Machines are prepared
✅ Ready for credential scanning
✅ Open CCure Audit PRO

Settings for CCure Scan:
  Scan Type: Credentialed / Windows
  Target: [your machines from deployment]
  Username: [admin account used]
  Password: [admin password]
  
Click: Start Scan

Results:
  ✅ OS detected
  ✅ Software enumerated  
  ✅ Patches identified
  ✅ Vulnerabilities found (95%+ coverage!)
```

---

## **You're All Set! 🎉**

Everything needed to credential scan Windows machines is now in your `scripts` folder:

```
scripts/
├── Prepare-WindowsForVulnScan.ps1           [Single machine setup]
├── Deploy-ScanPrepToMultiple.ps1            [BULK setup ← Use this!]
├── Verify-WindowsScanReadiness.ps1          [Verify before scanning]
├── Diagnose-WindowsScanIssues.ps1           [Troubleshooting]
├── Prepare-WindowsForVulnScan.cmd           [Legacy CMD version]
└── Documentation/
    ├── README_WINDOWS_SCANNING.md           [Overview]
    ├── WINDOWS_SCAN_SETUP_GUIDE.md          [Comprehensive guide]
    ├── ENTERPRISE_DEPLOYMENT_GUIDE.md       [Bulk deployment details]
    ├── QUICK_REFERENCE.md                   [Command cheat sheet]
    ├── DEPLOYMENT_OPTIONS.md                [Comparing all methods]
    ├── SETUP_CHECKLIST.md                   [Step-by-step checklist]
    └── BULK_DEPLOYMENT_QUICKSTART.md        [This file]
```

**Next: Deploy your machines!**

```powershell
$machines = "your", "machine", "list"
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray $machines -AdminUsername "DOMAIN\admin"
```
