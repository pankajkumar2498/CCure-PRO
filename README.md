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









 # On Windows target machine
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Prepare-WindowsForVulnScan.ps1
Restart-Computer

# Wait 10 minutes for restart

# From scanner machine
.\Verify-WindowsScanReadiness.ps1 -TargetComputer 10.180.5.109
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


