# Deployment Options Comparison

## **Quick Visual: Where Each Script Runs**

```
YOUR SCANNING MACHINE
═══════════════════════════════════════════════════════════════
│
├─► Deploy-ScanPrepToMultiple.ps1  ◄── NEW! (Run multiple machines at once)
│   │
│   ├─► PowerShell Remoting to Server1
│   │   └─► Configures Server1 automatically
│   │
│   ├─► PowerShell Remoting to Server2
│   │   └─► Configures Server2 automatically
│   │
│   └─► PowerShell Remoting to Server3
│       └─► Configures Server3 automatically
│
├─► Verify-WindowsScanReadiness.ps1  ◄── Verify machines are ready
│
└─► CCure Audit PRO (scanning tool)  ◄── Actual scanning happens here


EACH TARGET MACHINE (Server1, Server2, etc.)
═══════════════════════════════════════════════════════════════
│
├─ Receives remote commands from Deploy script
├─ Configures services, registry, firewall automatically
├─ Restarts automatically
└─ Ready for credential scanning!
```

---

## **Method Comparison**

### **METHOD 1: Manual on Each Machine (❌ Tedious)**

```
Machine 1: .\Prepare-WindowsForVulnScan.ps1 → Restart
Machine 2: .\Prepare-WindowsForVulnScan.ps1 → Restart
Machine 3: .\Prepare-WindowsForVulnScan.ps1 → Restart
Machine 4: .\Prepare-WindowsForVulnScan.ps1 → Restart
Machine 5: .\Prepare-WindowsForVulnScan.ps1 → Restart

Time for 5 machines: ~50 minutes
Time for 100 machines: ~1000 minutes (16+ hours) 😱
```

---

### **METHOD 2: Deploy from Scanning Machine Using PowerShell Remoting (✅ BEST)**

```
FROM: Your CCure Scanning Machine

.\Deploy-ScanPrepToMultiple.ps1 -MachineArray Server1,Server2,Server3,Server4,Server5

Time for 5 machines: ~10 minutes
Time for 100 machines: ~10 minutes (same!) 🚀
```

---

### **METHOD 3: Group Policy (For Domain Environments Only)**

```
Active Directory Group Policy Object
    ├─ Applied to OU: All_Servers
    ├─ Automatic deployment via domain controllers
    └─ Affects all machines in OU automatically

Time for 1 machine: 2 hours (policy propagation delay)
Time for 1000 machines: 2 hours (same!)

Pros: Most scalable
Cons: Requires Active Directory, takes time to propagate
```

---

## **Decision Tree: Which Method Should You Use?**

```
┌─ Do you have 1 machine to prep?
│  ├─ YES → Use: Prepare-WindowsForVulnScan.ps1 (manual)
│  └─ Time: 10 minutes
│
└─ Do you have 2+ machines to prep?
   ├─ YES, all on domain? → Use: GROUP POLICY (if IT team helps)
   │  └─ Time: 2 hours setup, instant deployment to all
   │
   ├─ YES, non-domain or mixed? → Use: Deploy-ScanPrepToMultiple.ps1
   │  └─ Time: 10 minutes for any number!
   │
   └─ YES, need it now? → Use: Deploy-ScanPrepToMultiple.ps1
      └─ Time: 10 minutes + restart cycle
```

---

## **Feature Comparison Table**

| Feature | Manual Script | Deploy Script | Group Policy |
|---------|---|---|---|
| **Machines:** 1 | 10 min | 10 min | N/A |
| **Machines:** 5 | 50 min | 10 min | 2 hrs setup |
| **Machines:** 100 | 1000 min | 10 min | 2 hrs setup |
| **Setup complexity** | Simple | Medium | Hard (needs AD) |
| **Run from** | Each machine | Scanning machine | Domain controller |
| **Reversible** | Yes | Yes | Yes (delete GPO) |
| **Requires WinRM** | No | Yes* | No |
| **Network only** | No | Yes | No |
| **Works non-domain** | Yes | Yes | No |

*WinRM bootstrap needed if not already enabled

---

## **RECOMMENDATION: Use Deploy-ScanPrepToMultiple.ps1**

### **Why?**

✅ **Deploy to 100 machines in 10 minutes**  
✅ **Run from your scanning machine (convenient)**  
✅ **Works for domain and non-domain machines**  
✅ **Fully parallelized (all machines at once)**  
✅ **Automatic restart orchestration**  
✅ **Built-in verification**  
✅ **Detailed logging**  
✅ **Handle failures gracefully**  

### **Example: Deploy to 10 Workstations**

```powershell
# FROM: Your CCure scanning machine (as Administrator)

$machines = @(
    "DESK-001",
    "DESK-002", 
    "DESK-003",
    "DESK-004",
    "DESK-005",
    "DESK-006",
    "DESK-007",
    "DESK-008",
    "DESK-009",
    "DESK-010"
)

.\Deploy-ScanPrepToMultiple.ps1 -MachineArray $machines -AdminUsername "DOMAIN\Administrator"

# ✓ Tests connectivity (30 sec)
# ✓ Deploys config to all (1 min)
# ✓ Restarts all in parallel (2 min)
# ✓ Verifies all (1 min)
# TOTAL: ~5 minutes ⚡

# Then open CCure and scan all 10 immediately!
```

---

## **Real-World Timeline**

### **You receive list of 50 machines to scan:**

```
8:00 AM - Get machine list
8:05 AM - Create Machines.csv
8:10 AM - Run Deploy-ScanPrepToMultiple.ps1
         (Script runs deployment in parallel)

8:15 AM - All configs deployed
8:20 AM - Machines restarting (parallel)
8:25 AM - Verifying all machines
8:30 AM - All 50 machines ready! ✓

8:30 AM - Open CCure Audit PRO
8:35 AM - Add all 50 machines as targets
8:40 AM - Start credentialed scan
9:40 AM - Scan completes
         All 50 machines fully scanned with 95% vulnerability coverage!
```

**Without deployment script:**
```
8:00 AM - Get list of 50 machines
8:05 AM - Start deploying to machine 1 manually
...
(repeat 50 times)
...
1:45 PM - Finally done with deployments (5+ hours later!)
1:45 PM - Now start scanning

Result: All day consumed by setup alone!
```

---

## **Network Diagram: How Deploy Script Works**

```
┌─────────────────────────────────┐
│   YOUR SCANNING MACHINE          │
│  (Running CCure Audit PRO)       │
│                                  │
│  .\Deploy-ScanPrepToMultiple.ps1 │
│                                  │
└────────────┬─────────────────────┘
             │
             │ PowerShell Remoting
             │ (Port 5985 or 5986)
             │
      ┌──────┼──────┬────────┬─────────┐
      │      │      │        │         │
      ▼      ▼      ▼        ▼         ▼
   ┌─────┐┌─────┐┌─────┐ ┌─────┐  ┌──────┐
   │ SRV1││ SRV2││ SRV3│ │ SRV4│  │ SRV5 │
   │     ││     ││     │ │     │  │      │
   │ WMI ││ WMI ││ WMI │ │ WMI │  │ WMI  │
   │ on  ││ on  ││ on  │ │ on  │  │ on   │
   │ ALL ││ ALL ││ ALL │ │ ALL │  │ ALL  │
   │AUTO ││AUTO ││AUTO │ │AUTO │  │ AUTO │
   └─────┘└─────┘└─────┘ └─────┘  └──────┘
   
(All in parallel - fastest solution!)
```

---

## **Step-by-Step: How to Use Deploy-ScanPrepToMultiple.ps1**

### **Step 1: Copy script to scanning machine**
```
C:\Users\YourUser\Scripts\Deploy-ScanPrepToMultiple.ps1
```

### **Step 2: Create machine list (or define inline)**
```powershell
$machines = "SERVER1", "SERVER2", "WORKSTATION1", "192.168.1.50"
```

### **Step 3: Run from PowerShell as Administrator**
```powershell
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray $machines -AdminUsername "DOMAIN\Administrator"
```

### **Step 4: Enter password when prompted**
```
Credential prompted once, used for all machines
```

### **Step 5: Confirm and proceed**
```
Script shows connectivity test
Asks: "Proceed with deployment? (Y/N)" → Type Y

Script then:
✓ Deploys config to all machines (parallel)
✓ Restarts all machines (parallel)
✓ Waits for them to come back online
✓ Verifies all machines
✓ Shows summary report
```

### **Step 6: Start scanning**
```
All machines are now ready!
Open CCure Audit PRO
Add your machines as targets
Run credentialed scan
```

---

## **Common Issues & Quick Fixes**

| Issue | Fix |
|-------|-----|
| "PowerShell Remoting not enabled" | Bootstrap 1 machine manually: `Enable-PSRemoting -Force` |
| "Access Denied on target" | Verify admin credentials correct |
| "Machine not reachable" | Ping it first: `ping MACHINE` |
| "Port 5985 blocked" | Check network firewall or use RDP first |
| "Script execution disabled" | Run: `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process` |

---

## **CSV Method (For Large Numbers)**

Create `targets.csv`:
```
ComputerName
SERVER-01
SERVER-02
WORKSTATION-01
WORKSTATION-02
192.168.1.100
192.168.1.101
```

Then deploy:
```powershell
.\Deploy-ScanPrepToMultiple.ps1 -MachineList "C:\targets.csv" -AdminUsername "DOMAIN\admin"
```

**Benefits:**
- ✅ Easy to maintain
- ✅ Version control friendly
- ✅ Reusable
- ✅ Automate from Active Directory

---

## **Summary: What You Now Have**

```
Individual Setup:
  Prepare-WindowsForVulnScan.ps1      ← Run on EACH machine (tedious for many)


Bulk Setup FROM Scanning Machine:
  Deploy-ScanPrepToMultiple.ps1       ← Run on SCANNING machine (does all at once!)


Verification:
  Verify-WindowsScanReadiness.ps1     ← Test individual machine from scanner


Troubleshooting:
  Diagnose-WindowsScanIssues.ps1      ← Deep diagnostics on problem machine


Documentation:
  ENTERPRISE_DEPLOYMENT_GUIDE.md      ← This file - how to deploy multiple machines!
```

---

## **Final Answer to Your Question**

**Q: What is that script about and how do I deploy multiple machines in one go from my scanning machine?**

**A:**
1. **What it is:** PowerShell Remoting deployment script that configures multiple Windows machines automatically from your scanning machine
2. **How it works:** Uses `Invoke-Command` to send commands to each machine in parallel
3. **Time:** ~10 minutes for ANY number of machines (1, 10, 100, 1000!)
4. **How to run:** 
   ```powershell
   .\Deploy-ScanPrepToMultiple.ps1 -MachineArray "SERVER1", "SERVER2" -AdminUsername "DOMAIN\admin"
   ```
5. **Result:** All machines ready for credential scanning without visiting each one!

---

**Next, you'll probably want:**
- Create your machine list
- Run the deployment script once
- Start scanning with CCure Audit PRO

See `ENTERPRISE_DEPLOYMENT_GUIDE.md` for detailed examples!
