# CCure-Audit-PRO
Network Scanning Tool

Inside /Backend Folder:

python -m venv .venv

.venv\Scripts\Activate.ps1

pip install -r requirements.txt




# Run all containers/Project
.\scripts\start_host_scan_stack.ps1

# Stop all containers
 .\scripts\stop_host_scan_stack.ps1


# For Running Worker for Nmap Scans locally
.\Backend\scripts\start_host_scanner_worker.ps1     // Run when all dockers are up and showing error in Nmap worker 

# Scanner worker concurrency
# Default is 20 parallel scan tasks. Override before starting the worker if needed:
$env:SCANNER_WORKER_CONCURRENCY="30"
$env:MAX_NMAP_PROCESSES="20"   # global Nmap process cap; raise only if the scanner host can handle it
.\Backend\scripts\start_host_scanner_worker.ps1









# Download next 1000 (offset 3300)
python scripts/download_nvd.py --limit 1000 --offset 3300

# Then next batch (offset shown in output)
python scripts/download_nvd.py --limit 1000 --offset 4300

# Then next batch (offset shown in output)
python scripts/download_nvd.py --limit 1000 --offset 12500
# And so on...

python test_cve_db.py    # Quick test









 # On Windows target machine
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Prepare-WindowsForVulnScan.ps1
Restart-Computer

# Wait 10 minutes for restart

# From scanner machine
.\Verify-WindowsScanReadiness.ps1 -TargetComputer 10.180.6.14
# Check: All tests pass ✓





Your Windows scanning will only work if the target has OpenSSH Server configured correctly. You should surface this to users in the UI and/or docs. The target Windows machine needs:
powershell# Install OpenSSH Server (run as Administrator on target)
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# Set PowerShell as default shell (required for your PS commands to work)
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" `
    -Name DefaultShell `
    -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -PropertyType String -Force


