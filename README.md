# CCure-Audit-PRO
Network Scanning Tool



python scripts/download_nvd.py --limit 1000 --offset 5300





Set-ExecutionPolicy Bypass -Scope Process -Force

 # On Windows target machine
.\Prepare-WindowsForVulnScan.ps1
Restart-Computer

# Wait 10 minutes for restart

# From scanner machine
.\Verify-WindowsScanReadiness.ps1 -TargetComputer 192.168.1.100
# Check: All tests pass ✓