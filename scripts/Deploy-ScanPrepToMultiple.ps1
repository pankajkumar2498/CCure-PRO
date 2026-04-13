#Requires -RunAsAdministrator
<#
.SYNOPSIS
Enterprise deployment script for credential scanning preparation across multiple Windows machines

.DESCRIPTION
Deploys credential scanning configuration to multiple machines from a central scanner machine
using PowerShell Remoting (WinRM).

This script:
1. Enables necessary services on target machines
2. Configures registry settings for remote access
3. Enables firewall rules
4. Orchestrates restarts
5. Verifies all machines are ready for scanning

.PARAMETER MachineList
Path to CSV file with target machines (optional - can edit list inline)

.PARAMETER MachineArray
Array of IP addresses or hostnames to configure

.PARAMETER AdminUsername
Username for remote access (should have admin rights on targets)

.PARAMETER AdminPassword
Password (will prompt if not provided)

.PARAMETER SkipRestart
If specified, doesn't restart machines. You'll do it manually later.

.PARAMETER SkipVerification
If specified, doesn't verify after setup

.EXAMPLE
# Interactive mode
.\Deploy-ScanPrepToMultiple.ps1

# Batch mode with list
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray "SERVER1", "SERVER2", "WORKSTATION1" -AdminUsername "DOMAIN\scanadmin"

# From CSV file
.\Deploy-ScanPrepToMultiple.ps1 -MachineList "C:\Machines.csv" -AdminUsername "DOMAIN\scanadmin"

.NOTES
Requires:
- Administrator privileges on this scanning machine
- PowerShell Remoting (WinRM) enabled on target machines OR RDP access to first bootstrap
- Network connectivity to all target machines
- Valid admin credentials on target machines
#>

param(
    [string]$MachineList,
    [string[]]$MachineArray,
    [string]$AdminUsername,
    [SecureString]$AdminPassword,
    [switch]$SkipRestart,
    [switch]$SkipVerification
)

# ============================================================================
# CONFIGURATION & SETUP
# ============================================================================

$ScriptVersion = "1.0"
$LogFile = "C:\temp\ScanPrepDeploy_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$DeploymentResults = @()

# Ensure temp log directory exists
$logDir = Split-Path $LogFile
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "INFO" { Write-Host $logEntry -ForegroundColor Gray }
        default { Write-Host $logEntry }
    }
    
    Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
}

function Test-AdminRights {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Log "This script requires Administrator privileges on the scanning machine." "ERROR"
        exit 1
    }
    
    Write-Log "Scanner machine: Administrator privileges confirmed" "SUCCESS"
}

function Get-MachineList {
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "MACHINE CONFIGURATION" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($MachineArray -and $MachineArray.Count -gt 0) {
        Write-Log "Using provided machine array: $($MachineArray -join ', ')" "INFO"
        return $MachineArray
    }
    
    if ($MachineList -and (Test-Path $MachineList)) {
        Write-Log "Reading machines from CSV: $MachineList" "INFO"
        $machines = Import-Csv -Path $MachineList | Select-Object -ExpandProperty ComputerName
        return $machines
    }
    
    # Interactive input
    Write-Host "Enter target machines (IP or hostname, one per line)" -ForegroundColor Yellow
    Write-Host "Examples: SERVER1, 192.168.1.10, WORKSTATION-01" -ForegroundColor Gray
    Write-Host "Press Enter twice when done:" -ForegroundColor Yellow
    Write-Host ""
    
    $machines = @()
    while ($true) {
        $machine = Read-Host "Machine"
        if ([string]::IsNullOrWhiteSpace($machine)) {
            if ($machines.Count -gt 0) { break }
            Write-Host "Please enter at least one machine" -ForegroundColor Yellow
            continue
        }
        $machines += $machine
    }
    
    return $machines
}

function Get-Credentials {
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "AUTHENTICATION" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($AdminPassword) {
        return New-Object System.Management.Automation.PSCredential($AdminUsername, $AdminPassword)
    }
    
    if (-not $AdminUsername) {
        $AdminUsername = Read-Host "Admin username (e.g., DOMAIN\scanadmin or local admin name)"
    }
    
    $credential = Get-Credential -UserName $AdminUsername -Message "Enter password for admin account"
    
    if ($null -eq $credential) {
        Write-Log "Credentials cancelled by user" "ERROR"
        exit 1
    }
    
    return $credential
}

function Test-MachineConnectivity {
    param([string[]]$Machines, [PSCredential]$Credential)
    
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "TESTING CONNECTIVITY" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""
    
    $reachable = @()
    $unreachable = @()
    
    foreach ($machine in $Machines) {
        Write-Host "Testing $machine..." -NoNewline
        
        $ping = Test-Connection -ComputerName $machine -Count 1 -Quiet -ErrorAction SilentlyContinue
        
        if ($ping) {
            Write-Host " ✓ Reachable" -ForegroundColor Green
            $reachable += $machine
            Write-Log "$machine : Reachable" "INFO"
        } else {
            Write-Host " ✗ NOT reachable" -ForegroundColor Red
            $unreachable += $machine
            Write-Log "$machine : NOT reachable" "WARNING"
        }
    }
    
    if ($unreachable.Count -gt 0) {
        Write-Host ""
        Write-Host "Warning: $($unreachable.Count) machine(s) not reachable:" -ForegroundColor Yellow
        $unreachable | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
        Write-Host ""
        
        $continue = Read-Host "Continue with reachable machines only? (Y/N)"
        if ($continue -ne "Y") {
            Write-Log "Deployment cancelled by user" "ERROR"
            exit 1
        }
    }
    
    if ($reachable.Count -eq 0) {
        Write-Log "No machines are reachable" "ERROR"
        exit 1
    }
    
    return $reachable
}

function Deploy-Configuration {
    param([string[]]$Machines, [PSCredential]$Credential)
    
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "DEPLOYING CONFIGURATION" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""
    
    $deployScript = {
        # This code runs ON EACH TARGET MACHINE
        
        try {
            # Enable services
            Write-Output "  Setting WMI service..."
            Set-Service -Name Winmgmt -StartupType Automatic -ErrorAction Stop
            Start-Service -Name Winmgmt -ErrorAction Stop
            
            Write-Output "  Setting Remote Registry service..."
            Set-Service -Name RemoteRegistry -StartupType Automatic -ErrorAction Stop
            Start-Service -Name RemoteRegistry -ErrorAction Stop
            
            Write-Output "  Setting WinRM service..."
            Set-Service -Name WinRM -StartupType Automatic -ErrorAction Stop
            Start-Service -Name WinRM -ErrorAction Stop
            
            # Configure registry - UAC
            Write-Output "  Configuring LocalAccountTokenFilterPolicy..."
            $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Set-ItemProperty -Path $uacPath -Name LocalAccountTokenFilterPolicy -Value 1 -ErrorAction Stop
            
            # Configure registry - Admin Shares
            Write-Output "  Configuring AutoShareServer..."
            $sharePath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
            Set-ItemProperty -Path $sharePath -Name AutoShareServer -Value 1 -ErrorAction Stop
            
            # Configure firewall rules
            Write-Output "  Enabling firewall rules..."
            Enable-NetFirewallRule -DisplayName "Windows Management Instrumentation (WMI-In)" -ErrorAction SilentlyContinue
            Enable-NetFirewallRule -DisplayName "Windows Management Instrumentation (WINMGMT-In)" -ErrorAction SilentlyContinue
            Enable-NetFirewallRule -DisplayName "Windows Management Instrumentation (ASYNC-In)" -ErrorAction SilentlyContinue
            Enable-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)" -ErrorAction SilentlyContinue
            Enable-NetFirewallRule -DisplayName "File and Printer Sharing (NB-Session-In)" -ErrorAction SilentlyContinue
            
            Write-Output "SUCCESS: Configuration completed on $env:COMPUTERNAME"
        } catch {
            Write-Output "ERROR: Configuration failed - $_"
        }
    }
    
    foreach ($machine in $Machines) {
        Write-Host "Configuring $machine..." -ForegroundColor Cyan
        
        try {
            $result = Invoke-Command -ComputerName $machine -Credential $Credential -ScriptBlock $deployScript -ErrorAction Stop
            
            foreach ($line in $result) {
                if ($line -like "*SUCCESS*") {
                    Write-Host "  ✓ $line" -ForegroundColor Green
                    Write-Log "$machine : $line" "SUCCESS"
                    $script:DeploymentResults += @{Machine = $machine; Status = "SUCCESS"; Message = $line}
                } else {
                    Write-Host "  • $line" -ForegroundColor Gray
                    Write-Log "$machine : $line" "INFO"
                }
            }
        } catch {
            Write-Host "  ✗ FAILED: $_" -ForegroundColor Red
            Write-Log "$machine : FAILED - $_" "ERROR"
            $script:DeploymentResults += @{Machine = $machine; Status = "FAILED"; Message = $_.Exception.Message}
        }
    }
}

function Restart-Machines {
    param([string[]]$Machines, [PSCredential]$Credential)
    
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "RESTART ORCHESTRATION" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Machines will restart in 2 minutes. Use Ctrl+C to cancel now." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    
    foreach ($machine in $Machines) {
        Write-Host "Sending restart signal to $machine..."
        
        try {
            Invoke-Command -ComputerName $machine -Credential $Credential -ScriptBlock {
                shutdown /r /t 120 /c "Restarting for credential scanning configuration"
            } -ErrorAction Stop
            
            Write-Host "  ✓ Restart command sent" -ForegroundColor Green
            Write-Log "$machine : Restart command sent" "INFO"
        } catch {
            Write-Host "  ✗ Failed to send restart: $_" -ForegroundColor Red
            Write-Log "$machine : Restart failed - $_" "ERROR"
        }
    }
    
    Write-Host ""
    Write-Host "Restart commands sent to all machines. They will reboot in 2 minutes." -ForegroundColor Yellow
    Write-Host "Waiting for machines to come back online..." -ForegroundColor Gray
    
    # Wait for restart
    $waitSeconds = 180
    Write-Host "Waiting $waitSeconds seconds for restart cycle..."
    
    for ($i = $waitSeconds; $i -gt 0; $i--) {
        Write-Progress -Activity "Waiting for restart" -SecondsRemaining $i -PercentComplete (100 - ($i / $waitSeconds * 100))
        Start-Sleep -Seconds 1
    }
    
    Write-Host "Machines should now be back online with new configuration." -ForegroundColor Green
}

function Verify-Configuration {
    param([string[]]$Machines, [PSCredential]$Credential)
    
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "VERIFICATION" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""
    
    $verifyScript = {
        $results = @{
            ComputerName = $env:COMPUTERNAME
            WinmgmtRunning = (Get-Service Winmgmt -ErrorAction SilentlyContinue).Status -eq "Running"
            RemoteRegistryRunning = (Get-Service RemoteRegistry -ErrorAction SilentlyContinue).Status -eq "Running"
            WinRMRunning = (Get-Service WinRM -ErrorAction SilentlyContinue).Status -eq "Running"
            UACSetting = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy
            AutoShareServer = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name AutoShareServer -ErrorAction SilentlyContinue).AutoShareServer
        }
        return $results
    }
    
    foreach ($machine in $Machines) {
        Write-Host "Verifying $machine..." -ForegroundColor Yellow
        
        try {
            $result = Invoke-Command -ComputerName $machine -Credential $Credential -ScriptBlock $verifyScript -ErrorAction Stop
            
            Write-Host "  Winmgmt:        $(if ($result.WinmgmtRunning) { '✓ Running' } else { '✗ NOT Running' })" -ForegroundColor $(if ($result.WinmgmtRunning) { 'Green' } else { 'Red' })
            Write-Host "  Remote Registry: $(if ($result.RemoteRegistryRunning) { '✓ Running' } else { '✗ NOT Running' })" -ForegroundColor $(if ($result.RemoteRegistryRunning) { 'Green' } else { 'Red' })
            Write-Host "  WinRM:          $(if ($result.WinRMRunning) { '✓ Running' } else { '✗ NOT Running' })" -ForegroundColor $(if ($result.WinRMRunning) { 'Green' } else { 'Red' })
            Write-Host "  UAC Policy:     $(if ($result.UACSetting -eq 1) { '✓ Enabled (1)' } else { '⚠ Not set or other value' })" -ForegroundColor $(if ($result.UACSetting -eq 1) { 'Green' } else { 'Yellow' })
            Write-Host "  Admin Shares:   $(if ($result.AutoShareServer -eq 1) { '✓ Enabled (1)' } else { '⚠ Not set or other value' })" -ForegroundColor $(if ($result.AutoShareServer -eq 1) { 'Green' } else { 'Yellow' })
            
        } catch {
            Write-Host "  ✗ Could not verify: $_" -ForegroundColor Red
            Write-Log "$machine : Verification failed - $_" "ERROR"
        }
    }
}

function Show-Summary {
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "DEPLOYMENT SUMMARY" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""
    
    $successful = @($DeploymentResults | Where-Object Status -eq "SUCCESS")
    $failed = @($DeploymentResults | Where-Object Status -eq "FAILED")
    
    Write-Host "Results:" -ForegroundColor Yellow
    Write-Host "  Total Machines:  $($DeploymentResults.Count)"
    Write-Host "  Successful:      $($successful.Count)" -ForegroundColor Green
    Write-Host "  Failed:          $($failed.Count)" -ForegroundColor Red
    
    if ($failed.Count -gt 0) {
        Write-Host ""
        Write-Host "Machines with issues:" -ForegroundColor Yellow
        $failed | ForEach-Object {
            Write-Host "  • $($_.Machine)" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "Log file: $LogFile" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    Clear-Host
    
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "Enterprise Credential Scanning Deployment" -ForegroundColor Cyan
    Write-Host "Version: $ScriptVersion" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    
    Write-Log "Deployment script started" "INFO"
    
    # Validate admin rights
    Test-AdminRights
    
    # Get machine list
    $machines = Get-MachineList
    Write-Log "Machines to configure: $($machines -join ', ')" "INFO"
    
    # Get credentials
    $credential = Get-Credentials
    Write-Log "Credentials obtained for: $($credential.UserName)" "INFO"
    
    # Test connectivity
    $reachableMachines = Test-MachineConnectivity -Machines $machines -Credential $credential
    
    if ($reachableMachines.Count -eq 0) {
        Write-Log "No machines are reachable. Deployment aborted." "ERROR"
        exit 1
    }
    
    # Show summary before deploying
    Write-Host ""
    Write-Host "Ready to deploy to $($reachableMachines.Count) machine(s):" -ForegroundColor Cyan
    $reachableMachines | ForEach-Object { Write-Host "  • $_" }
    Write-Host ""
    
    $proceed = Read-Host "Proceed with deployment? (Y/N)"
    if ($proceed -ne "Y") {
        Write-Log "User cancelled deployment" "WARNING"
        exit 0
    }
    
    # Deploy configuration
    Deploy-Configuration -Machines $reachableMachines -Credential $credential
    
    # Restart (if not skipped)
    if (-not $SkipRestart) {
        Write-Host ""
        $doRestart = Read-Host "Restart machines now? (Y/N)"
        if ($doRestart -eq "Y") {
            Restart-Machines -Machines $reachableMachines -Credential $credential
        } else {
            Write-Host "Restart skipped. You must restart machines manually for changes to take effect." -ForegroundColor Yellow
        }
    }
    
    # Verify (if not skipped)
    if (-not $SkipVerification -and -not $SkipRestart) {
        Start-Sleep -Seconds 30
        Verify-Configuration -Machines $reachableMachines -Credential $credential
    }
    
    # Show summary
    Show-Summary
    
    Write-Log "Deployment script completed" "SUCCESS"
}

# Run main function
Main
