# CCure-Audit-PRO
Network Scanning Tool




# Download next 1000 (offset 3300)
python scripts/download_nvd.py --limit 1000 --offset 3300

# Then next batch (offset shown in output)
python scripts/download_nvd.py --limit 1000 --offset 4300

# Then next batch (offset shown in output)
python scripts/download_nvd.py --limit 1000 --offset 5300
# And so on...

python test_cve_db.py    # Quick test







Set-ExecutionPolicy Bypass -Scope Process -Force

 # On Windows target machine
.\Prepare-WindowsForVulnScan.ps1
Restart-Computer

# Wait 10 minutes for restart

# From scanner machine
.\Verify-WindowsScanReadiness.ps1 -TargetComputer 10.180.5.109
# Check: All tests pass ✓