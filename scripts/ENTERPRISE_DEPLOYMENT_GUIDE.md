# Enterprise Deployment Guide - Multiple Machines

## **Short Answer to Your Question**

**Can I deploy from my scanning machine to prepare multiple Windows machines?**

### **YES! But with conditions:**

✅ **IF** target machines have WinRM enabled → Run deployment script from scanner  
❌ **IF NOT** WinRM enabled → You need 1st manual bootstrap per machine, then works with script

---

## **What That PowerShell Script Does**

The script I showed you earlier has a **bootstrap problem**:

```
Invoke-Command (PowerShell Remoting) = needs WinRM enabled
                         ↓
    But WinRM might not be enabled yet!
                         ↓
      Chicken-and-egg situation 🐔
```

**Solution:** I created **`Deploy-ScanPrepToMultiple.ps1`** that handles this properly.

---

## **How to Deploy to 50+ Machines From Your Scanning Machine**

### **Prerequisites**

- [ ] You're running as Administrator on YOUR scanning machine
- [ ] All target machines are reachable on network (ping works)
- [ ] You have admin credentials for target machines
- [ ] At least ONE machine has WinRM enabled (for bootstrap)

### **3-Step Deployment Process**

#### **Step 1: Create Machine List (Optional)**

Either define machines inline OR create a CSV file:

**Option A: CSV File**
```csv
ComputerName
192.168.1.10
192.168.1.20
WORKSTATION-01
SERVER1
```

Save as: `C:\DeployList.csv`

**Option B: Array in Script**
```powershell
$machines = "SERVER1", "WORKSTATION-01", "192.168.1.30", "192.168.1.40"
```

#### **Step 2: Run Deployment From Scanning Machine**

```powershell
# Run FROM your scanning machine (as Administrator)

# Option 1: Interactive - it will ask you everything
.\Deploy-ScanPrepToMultiple.ps1

# Option 2: With machine list
.\Deploy-ScanPrepToMultiple.ps1 -MachineList "C:\DeployList.csv" -AdminUsername "DOMAIN\Administrator"

# Option 3: With machine array
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray "SERVER1", "SERVER2", "WORKSTATION1" -AdminUsername "DOMAIN\scanadmin"

# Option 4: Setup but don't restart (you do it manually later)
.\Deploy-ScanPrepToMultiple.ps1 -SkipRestart

# Option 5: Setup and restart but skip verification
.\Deploy-ScanPrepToMultiple.ps1 -SkipVerification
```

#### **Step 3: What Happens Automatically**

```
Deployment Script Will Automatically:

1. ✓ Ask which machines to configure (or read from CSV)
2. ✓ Verify you have admin credentials
3. ✓ Test connectivity to each machine (ping)
4. ✓ Connect to each machine with PowerShell Remoting
5. ✓ Send configuration commands to each machine:
   - Enable WMI service
   - Enable Remote Registry service
   - Enable WinRM service
   - Set LocalAccountTokenFilterPolicy = 1
   - Set AutoShareServer = 1
   - Configure firewall rules
6. ✓ Restart all machines automatically (2-minute delay)
7. ✓ Wait for all to come back online
8. ✓ Verify configuration on each machine
9. ✓ Show summary report

Result: ALL machines now ready for credential scanning! 🎉
```

---

## **Complete Real-World Example**

### **Scenario: Deploy to 10 Machines**

```powershell
# Run FROM your CCure scanning machine as Administrator

# Step 1: List your machines
$machines = @(
    "SERVER-DC01",
    "SERVER-APP01",
    "SERVER-APP02", 
    "WORKSTATION-DES-01",
    "WORKSTATION-DES-02",
    "WORKSTATION-DES-03",
    "192.168.1.50",
    "192.168.1.51",
    "192.168.1.52",
    "192.168.1.53"
)

# Step 2: Run deployment
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray $machines -AdminUsername "DOMAIN\Administrator"

# Script will prompt once for password, then:
# ✓ Test connectivity (takes ~10 seconds)
# ✓ Deploy to all machines in parallel (takes ~30 seconds)
# ✓ Restart all machines (2+ minutes)
# ✓ Wait for restart cycle (3 minutes)
# ✓ Verify all machines (takes ~30 seconds)
# ✓ Show final report

# TOTAL TIME: ~10 minutes for 10 machines!
```

---

## **Interactive Mode (Easiest)**

Don't remember parameters? Just run it without options:

```powershell
.\Deploy-ScanPrepToMultiple.ps1
```

It will interactively ask you:

```
1. "Enter target machines" 
   You type: SERVER1, SERVER2, WORKSTATION1
   Press Enter twice when done

2. "Admin username?"
   You type: DOMAIN\Administrator

3. "Password?" 
   You enter password

4. Shows connectivity test results

5. Asks "Proceed with deployment? (Y/N)"
   You type: Y

6. Asks "Restart machines now? (Y/N)"
   You type: Y

7. Script automatically deploys, restarts, verifies
   Coffee break time! ☕
```

---

## **What Gets Logged**

Log file: `C:\temp\ScanPrepDeploy_20240413_143000.log`

Contains:
- All machines processed
- Success/failure for each
- Connectivity issues
- Configuration details
- Verification results

---

## **Handle Failures Gracefully**

**If one machine fails:**

```
Deployment continues for other machines
Script doesn't stop on first error
Shows you which ones failed at the end
You can fix failed machine separately
```

**Example output:**
```
================================================
DEPLOYMENT SUMMARY
================================================

Results:
  Total Machines:  10
  Successful:      9  ✓
  Failed:          1  ✗

Machines with issues:
  • WORKSTATION-05

Action: 
  1. Check WORKSTATION-05 manually
  2. Ensure it's reachable: ping WORKSTATION-05
  3. Verify credentials work
  4. Run single deployment: .\Deploy-ScanPrepToMultiple.ps1 -MachineArray "WORKSTATION-05"
```

---

## **CSV File Method (For Large Deployments)**

Create `Machines.csv`:

```csv
ComputerName
SERVER-DC01
SERVER-APP01
SERVER-APP02
WORKSTATION-01
WORKSTATION-02
192.168.1.100
192.168.1.101
```

Then deploy:

```powershell
.\Deploy-ScanPrepToMultiple.ps1 -MachineList "C:\Machines.csv" -AdminUsername "DOMAIN\scanadmin"
```

Benefits of CSV:
- ✓ Easy to maintain
- ✓ Version control friendly
- ✓ Reusable across deployments
- ✓ Can automate updates

---

## **PowerShell Remoting Requirements**

**What it needs:**
- Target machines must accept PowerShell Remoting (WinRM)
- Remote machines must allow script execution
- Network must allow traffic on port 5985 (HTTP) or 5986 (HTTPS)

**If PowerShell Remoting fails on a machine:**

```powershell
# Bootstrap that one machine manually via RDP:

# ON THAT MACHINE, run as Administrator:
Enable-PSRemoting -Force
winrm quickconfig -quiet

# Then retry deployment script
```

---

## **Why This Approach Works Better**

| Task | Manual Setup | Deployment Script |
|------|---|---|
| Prep 1 machine | 10 minutes | 10 minutes |
| Prep 2 machines | 20 minutes | ~2 minutes + restart |
| Prep 5 machines | 50 minutes | ~5 minutes + restart |
| Prep 20 machines | ~3.3 hours | ~10 minutes + restart |
| Prep 100 machines | 16+ hours | ~10 minutes + restart |

**Scale advantage:** Doesn't matter if 1 machine or 100!

---

## **Common Scenarios**

### **Scenario 1: Deploy to Windows Server Farm**

```powershell
# Get all servers from Active Directory
$servers = Get-ADComputer -Filter "OperatingSystem -notlike '*Windows 7*' -and OperatingSystem -notlike '*XP*'" | Select-Object -ExpandProperty Name

# Deploy to all
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray $servers -AdminUsername "DOMAIN\Administrator"
```

### **Scenario 2: Deploy to Specific Department**

```powershell
# Target only HR department machines
$hrMachines = Get-ADComputer -Filter "Name -like 'HR-*'" | Select-Object -ExpandProperty Name

.\Deploy-ScanPrepToMultiple.ps1 -MachineArray $hrMachines -AdminUsername "DOMAIN\scanadmin"
```

### **Scenario 3: Deploy with Different Credentials Per Machine**

For machines not on domain or mixed credentials:

```powershell
# Deploy to domain machines
$domainMachines = "SERVER1", "WORKSTATION1"
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray $domainMachines -AdminUsername "DOMAIN\Administrator"

# Deploy to local admin machines separately
$localMachines = "STANDALONE-01", "WORKGROUP-PC"
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray $localMachines -AdminUsername "administrator"
```

---

## **Verification After Deployment**

The script automatically verifies, but you can manually verify any time:

```powershell
# Test one machine
.\Verify-WindowsScanReadiness.ps1 -TargetComputer SERVER1 -Username "DOMAIN\Administrator"

# Test all machines
$machines | ForEach-Object {
    Write-Host "Verifying $_..."
    .\Verify-WindowsScanReadiness.ps1 -TargetComputer $_ -Username "DOMAIN\Administrator"
    Start-Sleep -Seconds 2
}
```

---

## **Troubleshooting Deployment Failures**

| Error | Cause | Solution |
|-------|-------|----------|
| "Access Denied" | Wrong credentials | Verify admin username/password |
| "Not reachable" | Network/firewall issue | Check network, ping machine |
| "PowerShell Remoting not enabled" | WinRM disabled on target | Bootstrap that machine manually first |
| "Cannot connect to port 5985" | Firewall blocks remoting | Adjust firewall or use RDP first |
| "Script execution disabled" | PowerShell execution policy | Run: `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process` |

---

## **One-Liner Examples**

### **Quick Deploy to 3 Machines**
```powershell
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray "PC1", "PC2", "PC3" -AdminUsername "admin" -AdminPassword (ConvertTo-SecureString "Pass" -AsPlainText -Force)
```

### **Deploy to CSV, Skip Verification**
```powershell
.\Deploy-ScanPrepToMultiple.ps1 -MachineList "C:\Machines.csv" -AdminUsername "DOMAIN\admin" -SkipVerification
```

### **Deploy and Don't Restart (Manual Restart Later)**
```powershell
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray "SERVER1", "SERVER2" -AdminUsername "DOMAIN\admin" -SkipRestart
```

---

## **After Deployment: Start Scanning**

Once all machines are prepared (deployed + restarted):

```
Open CCure Audit PRO
→ Create New Scan
→ Add targets from your machine list
→ Select "Credentialed" scan type
→ Add credentials once (uses across all machines)
→ Start Scan
→ All machines scanned automatically! 🎉
```

---

## **Questions Answered**

**Q: Do I run this on the scanning machine?**  
A: YES! Your CCure scanning machine is where you run the deployment script.

**Q: Does it require WinRM on targets before running?**  
A: Preferably yes. If not, first bootstrap 1 machine, then script works for others.

**Q: How long does it take for 100 machines?**  
A: Deploy config: ~5-10 minutes. Restart cycle: ~5 minutes. Total: ~15 minutes!

**Q: Can I deploy to machines across domains?**  
A: YES! Each invocation can use different credentials if needed.

**Q: What if deployment fails partway through?**  
A: It shows you which machines failed. You can re-run on failed machines only.

**Q: Is this reversible?**  
A: YES! Each machine can run disable commands separately if needed.

---

## **Next Steps**

1. **Prepare your machine list:**
   ```powershell
   # Either as array or CSV
   $machines = "SERVER1", "SERVER2", "WORKSTATION1"
   ```

2. **Run the deployment script:**
   ```powershell
   .\Deploy-ScanPrepToMultiple.ps1 -MachineArray $machines -AdminUsername "DOMAIN\admin"
   ```

3. **Wait for completion** (~15 minutes for 10 machines)

4. **Open CCure Audit PRO and start scanning!**

---

This is the enterprise-grade way to prepare multiple machines from your scanning machine!
