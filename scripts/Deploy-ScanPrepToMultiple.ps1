#Requires -RunAsAdministrator
<#
.SYNOPSIS
Enterprise deployment script for credential scanning preparation across multiple Windows machines.

.DESCRIPTION
Deploys credential scanning configuration to multiple machines from a central scanner machine
using PowerShell Remoting (WinRM). Runs deployments in PARALLEL (up to ThrottleLimit machines
simultaneously) and uses adaptive polling to detect when machines return after restart.

This script:
1. Enables necessary services on target machines
2. Configures registry settings for remote access
3. Enables firewall rules (locale-independent)
4. Orchestrates restarts with adaptive polling (no fixed sleep)
5. Verifies only machines that were actually restarted and came back online

.PARAMETER MachineList
Path to CSV file with target machines.
Required column: ComputerName
Optional columns: Description, Location (ignored, but allowed)

Expected CSV format:
  ComputerName
  SERVER01
  192.168.1.10
  WORKSTATION-A

.PARAMETER MachineArray
Array of IP addresses or hostnames to configure directly.

.PARAMETER AdminUsername
Username for remote access. Must have local administrator rights on all targets.
If omitted, you will be prompted interactively.

.PARAMETER AdminPassword
Password as a SecureString. If omitted, you will be prompted via Get-Credential.

.PARAMETER SkipRestart
If specified, suppresses the restart prompt entirely. Verification is still run
against current machine state (useful for re-runs where machines are already up).

.PARAMETER SkipVerification
If specified, skips post-restart configuration verification.

.PARAMETER DeployThrottleLimit
Maximum number of machines to configure simultaneously. Default: 10.
Increase for large environments with fast networks; decrease if WinRM sessions
are throttled by target-side session limits.

.PARAMETER RestartTimeoutSeconds
Maximum seconds to wait for each machine to come back online after restart.
Default: 600 (10 minutes). Machines that exceed this are reported as timed out
but do not block verification of machines that did come back.

.EXAMPLE
# Interactive mode - prompts for everything
.\Deploy-ScanPrepToMultiple.ps1

# Batch mode with inline list and explicit credentials
.\Deploy-ScanPrepToMultiple.ps1 -MachineArray "SERVER1","SERVER2","WORKSTATION1" `
    -AdminUsername "DOMAIN\scanadmin"

# From CSV file, skip restart for a re-verification run
.\Deploy-ScanPrepToMultiple.ps1 -MachineList "C:\Machines.csv" `
    -AdminUsername "DOMAIN\scanadmin" -SkipRestart

.NOTES
Requires:
- Administrator privileges on the scanner machine running this script
- PowerShell Remoting (WinRM) enabled on target machines, OR RDP access to bootstrap the first machine
- Network connectivity to all target machines
- Valid local or domain administrator credentials on all targets
#>

param(
    [string]$MachineList,
    [string[]]$MachineArray,
    [string]$AdminUsername,
    [SecureString]$AdminPassword,
    [switch]$SkipRestart,
    [switch]$SkipVerification,
    [int]$DeployThrottleLimit = 10,
    [int]$RestartTimeoutSeconds = 600
)

# ============================================================================
# CONFIGURATION & SETUP
# ============================================================================

$ScriptVersion  = "2.0"
$LogFile        = "C:\temp\ScanPrepDeploy_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$DeploymentResults = [System.Collections.ArrayList]@()

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
    $logEntry  = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green  }
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red    }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "INFO"    { Write-Host $logEntry -ForegroundColor Gray   }
        default   { Write-Host $logEntry }
    }

    Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
}

function Test-AdminRights {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Log "This script requires Administrator privileges on the scanner machine." "ERROR"
        exit 1
    }

    Write-Log "Scanner machine: Administrator privileges confirmed." "SUCCESS"
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

    if ($MachineList) {
        # ----------------------------------------------------------------
        # BUG FIX #5 - No CSV schema validation.
        # The original Import-Csv silently returned empty results (or threw)
        # if the ComputerName column was absent or the CSV had a different
        # header. There was no error message, no example format, and the
        # script would proceed with zero machines.
        # Fix: Validate that the file exists, is parseable, and contains
        # the required ComputerName column. Print the expected format on error.
        # ----------------------------------------------------------------
        if (-not (Test-Path $MachineList)) {
            Write-Log "CSV file not found: $MachineList" "ERROR"
            exit 1
        }

        $csvData = Import-Csv -Path $MachineList -ErrorAction Stop

        # Check for required column
        $columns = ($csvData | Get-Member -MemberType NoteProperty).Name
        if ('ComputerName' -notin $columns) {
            Write-Log "CSV file is missing the required 'ComputerName' column." "ERROR"
            Write-Host ""
            Write-Host "Expected CSV format (first row must be the header):" -ForegroundColor Yellow
            Write-Host "  ComputerName" -ForegroundColor Gray
            Write-Host "  SERVER01" -ForegroundColor Gray
            Write-Host "  192.168.1.10" -ForegroundColor Gray
            Write-Host "  WORKSTATION-A" -ForegroundColor Gray
            Write-Host ""
            Write-Host "Columns found in your file: $($columns -join ', ')" -ForegroundColor Red
            exit 1
        }

        $machines = $csvData |
            Select-Object -ExpandProperty ComputerName |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        if ($machines.Count -eq 0) {
            Write-Log "CSV file was valid but contained no non-empty ComputerName entries." "ERROR"
            exit 1
        }

        Write-Log "Loaded $($machines.Count) machine(s) from CSV: $MachineList" "INFO"
        return $machines
    }

    # Interactive input
    Write-Host "Enter target machines (IP or hostname, one per line)." -ForegroundColor Yellow
    Write-Host "Examples: SERVER1, 192.168.1.10, WORKSTATION-01" -ForegroundColor Gray
    Write-Host "Press Enter on a blank line when done." -ForegroundColor Yellow
    Write-Host ""

    $machines = @()
    while ($true) {
        $machine = Read-Host "Machine"
        if ([string]::IsNullOrWhiteSpace($machine)) {
            if ($machines.Count -gt 0) { break }
            Write-Host "Please enter at least one machine." -ForegroundColor Yellow
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
        $cred = New-Object System.Management.Automation.PSCredential($AdminUsername, $AdminPassword)
        # BUG FIX #6 - Do not log the username to the plaintext log file.
        # The original wrote: Write-Log "Credentials obtained for: $($credential.UserName)"
        # This records the scan account username (and by proximity, signals the
        # account to target) in a world-readable log at C:\temp\*.log.
        # Fix: Log only a neutral confirmation. The username is available in the
        # PSCredential object throughout the session without being persisted.
        Write-Log "Credentials supplied via parameter - collection skipped." "INFO"
        return $cred
    }

    if (-not $AdminUsername) {
        $AdminUsername = Read-Host "Admin username (e.g., DOMAIN\scanadmin or local admin)"
    }

    $credential = Get-Credential -UserName $AdminUsername -Message "Enter password for remote admin account"

    if ($null -eq $credential) {
        Write-Log "Credential entry cancelled by user." "ERROR"
        exit 1
    }

    # BUG FIX #6 (continued) - username not logged.
    Write-Log "Credentials collected successfully." "INFO"
    return $credential
}

function Test-MachineConnectivity {
    param([string[]]$Machines, [PSCredential]$Credential)

    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "TESTING CONNECTIVITY" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""

    $reachable   = [System.Collections.ArrayList]@()
    $unreachable = [System.Collections.ArrayList]@()

    foreach ($machine in $Machines) {
        Write-Host "  Testing $machine ..." -NoNewline
        $ping = Test-Connection -ComputerName $machine -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($ping) {
            Write-Host " OK" -ForegroundColor Green
            [void]$reachable.Add($machine)
            Write-Log "$machine : Reachable" "INFO"
        } else {
            Write-Host " UNREACHABLE" -ForegroundColor Red
            [void]$unreachable.Add($machine)
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
            Write-Log "Deployment cancelled by user after connectivity check." "WARNING"
            exit 1
        }
    }

    if ($reachable.Count -eq 0) {
        Write-Log "No machines are reachable. Deployment aborted." "ERROR"
        exit 1
    }

    return [string[]]$reachable
}

function Deploy-Configuration {
    param([string[]]$Machines, [PSCredential]$Credential)

    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "DEPLOYING CONFIGURATION (parallel, ThrottleLimit: $DeployThrottleLimit)" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""

    # -------------------------------------------------------------------------
    # Remote scriptblock that runs ON EACH TARGET MACHINE
    # -------------------------------------------------------------------------
    $deployScript = {
        try {
            # --- Services ---
            Write-Output "  Setting WMI service startup type..."
            Set-Service -Name Winmgmt -StartupType Automatic -ErrorAction Stop
            # Only start if not already running (avoids noisy error on Start-Service)
            if ((Get-Service Winmgmt).Status -ne 'Running') {
                Start-Service -Name Winmgmt -ErrorAction Stop
            }

            Write-Output "  Setting Remote Registry service startup type..."
            Set-Service -Name RemoteRegistry -StartupType Automatic -ErrorAction Stop
            if ((Get-Service RemoteRegistry).Status -ne 'Running') {
                Start-Service -Name RemoteRegistry -ErrorAction Stop
            }

            # BUG FIX #4 (PS1 side) - Start-Service WinRM over WinRM kills the session.
            # The original scriptblock called "Start-Service -Name WinRM -ErrorAction Stop"
            # inside an Invoke-Command session. Restarting the WinRM service through an
            # active WinRM session terminates the very channel delivering the command.
            # The session appears to succeed (no exception reaches the caller) but the
            # WinRM service on the target ends up in an inconsistent state.
            # Fix: Set the startup type only (Set-Service writes registry, no restart).
            # WinRM is already running (that is how we connected). We do NOT restart it.
            Write-Output "  Setting WinRM service startup type (service NOT restarted - see notes)..."
            Set-Service -Name WinRM -StartupType Automatic -ErrorAction Stop

            # --- Registry ---
            Write-Output "  Configuring LocalAccountTokenFilterPolicy..."
            $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Set-ItemProperty -Path $uacPath -Name LocalAccountTokenFilterPolicy -Value 1 -ErrorAction Stop

            Write-Output "  Configuring AutoShareServer..."
            $sharePath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
            Set-ItemProperty -Path $sharePath -Name AutoShareServer -Value 1 -ErrorAction Stop

            # --- Firewall (locale-independent - by internal rule Name) ---
            Write-Output "  Enabling firewall rules (locale-independent)..."
            $wmiNames = @(
                'WMI-WINMGMT-In-TCP-NoScope',
                'WMI-WINMGMT-In-TCP',
                'WMI-ASYNC-In-TCP-NoScope',
                'WMI-ASYNC-In-TCP'
            )
            $smbNames = @('FPS-SMB-In-TCP', 'FPS-NB-Session-In-TCP')

            # Strategy A: by stable internal Name
            ($wmiNames + $smbNames) | ForEach-Object {
                $r = Get-NetFirewallRule -Name $_ -ErrorAction SilentlyContinue
                if ($r) { Enable-NetFirewallRule -Name $_ -ErrorAction SilentlyContinue }
            }
            # Strategy B: by DisplayGroup keyword (handles OS versions with different internal names)
            Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayGroup -match 'WMI|File.+Print' } |
                Enable-NetFirewallRule -ErrorAction SilentlyContinue

            Write-Output "SUCCESS: Configuration completed on $env:COMPUTERNAME"
        } catch {
            Write-Output "ERROR: Configuration failed on $env:COMPUTERNAME - $_"
        }
    }

    # -------------------------------------------------------------------------
    # BUG FIX #1 - Sequential deployment (foreach loop).
    # The original looped over $Machines one at a time with a serial
    # Invoke-Command. On 50 machines at 5-10s each = 250-500s wall time.
    # Invoke-Command natively supports an array for -ComputerName and runs
    # them in parallel up to -ThrottleLimit. This is the idiomatic fix.
    # Fix: Pass the full $Machines array to a single Invoke-Command call with
    # -ThrottleLimit. Collect per-machine results via the PSComputerName
    # property that PowerShell automatically stamps on each returned object.
    # -------------------------------------------------------------------------
    Write-Log "Deploying to $($Machines.Count) machine(s) in parallel (ThrottleLimit: $DeployThrottleLimit)..." "INFO"

    $allResults = $null
    try {
        $allResults = Invoke-Command `
            -ComputerName $Machines `
            -Credential $Credential `
            -ScriptBlock $deployScript `
            -ThrottleLimit $DeployThrottleLimit `
            -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Invoke-Command encountered a top-level error: $_" "ERROR"
    }

    # Build a lookup of which machines returned any output
    $respondedSet = @{}
    if ($allResults) {
        $allResults | ForEach-Object {
            $respondedSet[$_.PSComputerName.ToLower()] = $true
        }
    }

    # Process per-machine output
    foreach ($machine in $Machines) {
        $machineOutput = $allResults | Where-Object { $_.PSComputerName -eq $machine }

        Write-Host "  [$machine]" -ForegroundColor Cyan

        if (-not $respondedSet.ContainsKey($machine.ToLower())) {
            Write-Host "    X No response - WinRM connection failed or machine unreachable" -ForegroundColor Red
            Write-Log "$machine : FAILED - No response from machine" "ERROR"
            [void]$script:DeploymentResults.Add(@{Machine = $machine; Status = "FAILED"; Message = "No response - WinRM connection failed"})
            continue
        }

        $deployFailed = $false
        foreach ($line in $machineOutput) {
            if ($line -like "*SUCCESS*") {
                Write-Host "    OK $line" -ForegroundColor Green
                Write-Log "$machine : $line" "SUCCESS"
                if (-not $deployFailed) {
                    [void]$script:DeploymentResults.Add(@{Machine = $machine; Status = "SUCCESS"; Message = $line})
                }
            } elseif ($line -like "*ERROR*") {
                Write-Host "    X  $line" -ForegroundColor Red
                Write-Log "$machine : $line" "ERROR"
                [void]$script:DeploymentResults.Add(@{Machine = $machine; Status = "FAILED"; Message = $line})
                $deployFailed = $true
            } else {
                Write-Host "    -  $line" -ForegroundColor Gray
                Write-Log "$machine : $line" "INFO"
            }
        }
    }
}

function Restart-Machines {
    <#
    .SYNOPSIS
    Sends restart commands to all machines, then polls each one until it
    comes back online or times out. Returns the list of machines that
    successfully came back within RestartTimeoutSeconds.

    BUG FIX #2 - Fixed start-sleep restart wait.
    The original used "Start-Sleep -Seconds 180" (3 minutes fixed).
    On slow machines (large Windows Update pending, slow HDD, long POST)
    3 minutes is not enough. On fast VMs 3 minutes is wasted. And there
    was no per-machine differentiation - a single slow machine held up all
    verification.
    Fix: Replace fixed sleep with an adaptive polling loop using Test-Connection.
    Each machine is polled independently. The function returns only the machines
    that actually came back online, so verification targets only confirmed-up hosts.
    #>
    param([string[]]$Machines, [PSCredential]$Credential)

    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "RESTART ORCHESTRATION" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "Machines will restart in 2 minutes. Use Ctrl+C to cancel now." -ForegroundColor Yellow
    Start-Sleep -Seconds 5

    # Send restart commands (still sequential - restart commands are fast)
    foreach ($machine in $Machines) {
        Write-Host "  Sending restart to $machine ..." -NoNewline
        try {
            Invoke-Command -ComputerName $machine -Credential $Credential -ScriptBlock {
                shutdown /r /t 120 /c "Restarting for credential scanning configuration"
            } -ErrorAction Stop
            Write-Host " Sent" -ForegroundColor Green
            Write-Log "$machine : Restart command sent" "INFO"
        } catch {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Log "$machine : Restart command failed - $_" "ERROR"
        }
    }

    Write-Host ""
    Write-Host "Waiting 45 seconds for machines to begin shutdown..." -ForegroundColor Gray
    Start-Sleep -Seconds 45  # Give machines time to start shutting down before we poll

    # Adaptive polling loop
    Write-Log "Polling for machines to come back online (timeout: $RestartTimeoutSeconds seconds per machine)..." "INFO"

    $deadline  = (Get-Date).AddSeconds($RestartTimeoutSeconds)
    $pending   = [System.Collections.ArrayList]@($Machines)
    $online    = [System.Collections.ArrayList]@()
    $timedOut  = [System.Collections.ArrayList]@()

    while ($pending.Count -gt 0 -and (Get-Date) -lt $deadline) {
        $stillPending = [System.Collections.ArrayList]@()

        foreach ($machine in $pending) {
            if (Test-Connection -ComputerName $machine -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                Write-Host "  OK $machine is back online" -ForegroundColor Green
                Write-Log "$machine : Back online" "SUCCESS"
                [void]$online.Add($machine)
            } else {
                [void]$stillPending.Add($machine)
            }
        }

        $pending = $stillPending

        if ($pending.Count -gt 0) {
            $elapsed = [int]($RestartTimeoutSeconds - ($deadline - (Get-Date)).TotalSeconds)
            Write-Host "  Waiting... ($($pending.Count) machine(s) still offline, ${elapsed}s elapsed)" -ForegroundColor Gray
            Start-Sleep -Seconds 15
        }
    }

    # Anything still pending after timeout
    foreach ($machine in $pending) {
        Write-Host "  TIMEOUT: $machine did not respond within $RestartTimeoutSeconds seconds" -ForegroundColor Yellow
        Write-Log "$machine : Timed out waiting for restart" "WARNING"
        [void]$timedOut.Add($machine)
    }

    Write-Host ""
    Write-Log "Restart polling complete. Online: $($online.Count)  Timed out: $($timedOut.Count)" "INFO"

    return [string[]]$online
}

function Verify-Configuration {
    param([string[]]$Machines, [PSCredential]$Credential)

    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "VERIFICATION" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""

    $verifyScript = {
        @{
            ComputerName            = $env:COMPUTERNAME
            WinmgmtRunning          = (Get-Service Winmgmt       -ErrorAction SilentlyContinue).Status -eq "Running"
            RemoteRegistryRunning   = (Get-Service RemoteRegistry -ErrorAction SilentlyContinue).Status -eq "Running"
            WinRMRunning            = (Get-Service WinRM          -ErrorAction SilentlyContinue).Status -eq "Running"
            UACSetting              = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                                        -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy
            AutoShareServer         = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
                                        -Name AutoShareServer -ErrorAction SilentlyContinue).AutoShareServer
        }
    }

    foreach ($machine in $Machines) {
        Write-Host "  Verifying $machine ..." -ForegroundColor Yellow
        try {
            $r = Invoke-Command -ComputerName $machine -Credential $Credential `
                -ScriptBlock $verifyScript -ErrorAction Stop

            $svcColor = { param($ok) if ($ok) { 'Green' } else { 'Red' } }

            Write-Host "    Winmgmt:         $(if ($r.WinmgmtRunning)        { 'OK Running' } else { 'NOT Running' })" `
                -ForegroundColor (& $svcColor $r.WinmgmtRunning)
            Write-Host "    Remote Registry: $(if ($r.RemoteRegistryRunning) { 'OK Running' } else { 'NOT Running' })" `
                -ForegroundColor (& $svcColor $r.RemoteRegistryRunning)
            Write-Host "    WinRM:           $(if ($r.WinRMRunning)          { 'OK Running' } else { 'NOT Running' })" `
                -ForegroundColor (& $svcColor $r.WinRMRunning)
            Write-Host "    UAC Policy:      $(if ($r.UACSetting -eq 1)      { 'OK Set (1)' } else { 'WARNING Not set' })" `
                -ForegroundColor (if ($r.UACSetting -eq 1) { 'Green' } else { 'Yellow' })
            Write-Host "    Admin Shares:    $(if ($r.AutoShareServer -eq 1) { 'OK Set (1)' } else { 'WARNING Not set' })" `
                -ForegroundColor (if ($r.AutoShareServer -eq 1) { 'Green' } else { 'Yellow' })

        } catch {
            Write-Host "    Could not verify: $_" -ForegroundColor Red
            Write-Log "$machine : Verification connection failed - $_" "ERROR"
        }
    }
}

function Show-Summary {
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "DEPLOYMENT SUMMARY" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""

    $successful = @($DeploymentResults | Where-Object { $_.Status -eq "SUCCESS" })
    $failed     = @($DeploymentResults | Where-Object { $_.Status -eq "FAILED"  })

    Write-Host "Results:" -ForegroundColor Yellow
    Write-Host "  Total targeted:   $($DeploymentResults.Count)"
    Write-Host "  Successful:       $($successful.Count)" -ForegroundColor Green
    Write-Host "  Failed:           $($failed.Count)"     -ForegroundColor $(if ($failed.Count -gt 0) { 'Red' } else { 'Gray' })

    if ($failed.Count -gt 0) {
        Write-Host ""
        Write-Host "Machines that failed deployment:" -ForegroundColor Yellow
        $failed | ForEach-Object { Write-Host "  - $($_.Machine): $($_.Message)" -ForegroundColor Red }
    }

    Write-Host ""
    Write-Host "Full log: $LogFile" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    Clear-Host

    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host " Enterprise Credential Scanning Deployment v$ScriptVersion"       -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Log "Deployment script started (v$ScriptVersion)" "INFO"

    Test-AdminRights

    $machines   = Get-MachineList
    Write-Log "Machines to configure: $($machines -join ', ')" "INFO"

    $credential = Get-Credentials
    # BUG FIX #6 - username NOT logged here (see Get-Credentials for full note)

    $reachableMachines = Test-MachineConnectivity -Machines $machines -Credential $credential

    Write-Host ""
    Write-Host "Ready to deploy to $($reachableMachines.Count) machine(s):" -ForegroundColor Cyan
    $reachableMachines | ForEach-Object { Write-Host "  - $_" }
    Write-Host ""

    $proceed = Read-Host "Proceed with deployment? (Y/N)"
    if ($proceed -ne "Y") {
        Write-Log "User cancelled deployment before it started." "WARNING"
        exit 0
    }

    # --- Deploy ---
    Deploy-Configuration -Machines $reachableMachines -Credential $credential

    # -------------------------------------------------------------------------
    # BUG FIX #3 - Verification runs even when machines have not restarted.
    # The original logic:
    #   if (-not $SkipVerification -and -not $SkipRestart) {
    #       Start-Sleep -Seconds 30
    #       Verify-Configuration ...
    #   }
    # $SkipRestart is a PARAMETER switch, not a record of whether the user
    # actually chose to restart at the interactive prompt. If the user answered
    # "N" at "Restart machines now?", $SkipRestart was still $false, so
    # verification ran anyway - 30 seconds after the NO answer - against
    # machines that had not restarted. This produced false failures that made
    # operators believe the deployment itself had failed.
    # Fix: Track whether the user actually triggered a restart in $didRestart.
    # Only run verification against $restartedMachines (machines confirmed back
    # online by the polling loop). If the user skipped restart interactively,
    # print a clear message explaining verification was deferred.
    # -------------------------------------------------------------------------

    $didRestart        = $false
    $restartedMachines = @()

    if (-not $SkipRestart) {
        Write-Host ""
        $doRestart = Read-Host "Restart machines now? (Y/N)"
        if ($doRestart -eq "Y") {
            $restartedMachines = Restart-Machines -Machines $reachableMachines -Credential $credential
            $didRestart        = $true
        } else {
            Write-Log "User chose not to restart machines now. Changes will not be fully active until each machine is restarted." "WARNING"
            Write-Host ""
            Write-Host "IMPORTANT: Registry and service changes are applied, but a restart" -ForegroundColor Yellow
            Write-Host "           is required before running the vulnerability scan." -ForegroundColor Yellow
        }
    }

    if (-not $SkipVerification) {
        if ($didRestart -and $restartedMachines.Count -gt 0) {
            # Verify only machines confirmed back online after restart
            Write-Log "Verifying $($restartedMachines.Count) machine(s) that came back online after restart." "INFO"
            Verify-Configuration -Machines $restartedMachines -Credential $credential

        } elseif ($SkipRestart) {
            # Caller explicitly passed -SkipRestart; they know no restart happened.
            # Run verification against current state as a baseline check.
            Write-Log "Running verification without restart (-SkipRestart specified)." "WARNING"
            Verify-Configuration -Machines $reachableMachines -Credential $credential

        } else {
            # User said "N" at the interactive restart prompt.
            # Do NOT run verification - machines have not restarted yet and
            # results would be misleading (services still in pre-config state).
            Write-Log "Verification skipped - machines were not restarted. Re-run this script with -SkipRestart after manual restarts to verify." "WARNING"
        }
    }

    Show-Summary
    Write-Log "Deployment script completed." "SUCCESS"
}

Main
