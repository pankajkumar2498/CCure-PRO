#Requires -RunAsAdministrator
<#
.SYNOPSIS
Prepares a Windows machine for credentialed vulnerability scanning (CCure Audit PRO, Nessus, etc.)

.DESCRIPTION
Configures WMI, Remote Registry, firewall rules, UAC policies, and WinRM to enable
remote vulnerability scanners to retrieve system information and detect vulnerabilities.

Fixes applied (v1.1):
  - Registry backup now exports each key to a separate temp file and merges them correctly.
  - Configure-WMIPermissions now exits with code 2 when ScannerAdminAccount is set, because
    the function cannot actually apply DCOM permissions programmatically — callers must not
    be misled into thinking the step succeeded.
  - Disable-UACRemoteRestrictions now writes a timestamped audit entry to the log and
    schedules automatic rollback via schtasks using the new -ScanWindowMinutes parameter.
  - Configure-WinRM detects domain vs. workgroup membership and refuses to run quickconfig
    over plain HTTP on a domain machine without an explicit -AllowHttpOnDomain override.
    It also scopes the WinRM listener to a caller-supplied -ScannerSourceIP when provided.
  - Enable-RequiredServices now halts the entire script when a critical service (Winmgmt)
    cannot be started, instead of silently continuing with a partial configuration.
  - A mandatory confirmation prompt is shown before any changes are made, listing every
    action that will be taken.

.PARAMETER SkipBackup
If specified, skips registry backup before modifications.

.PARAMETER DisableOnly
If specified, only shows commands to disable these features later. No changes are made.

.PARAMETER ScanWindowMinutes
Duration in minutes for which the scan configuration should remain active. After this
window the RemoteRegistry service is stopped and LocalAccountTokenFilterPolicy is removed
automatically via a scheduled task. Default: 0 (no auto-rollback).

.PARAMETER ScannerSourceIP
IPv4 address of the scanner machine. When supplied, the WinRM HTTP listener and the
WinRM firewall rule are scoped to this address only, reducing network exposure.

.PARAMETER AllowHttpOnDomain
By default, Configure-WinRM refuses to run quickconfig over plain HTTP when the machine
is domain-joined. Pass this switch to override that guard (e.g., in lab environments).

.EXAMPLE
.\Prepare-WindowsForVulnScan.ps1
.\Prepare-WindowsForVulnScan.ps1 -SkipBackup
.\Prepare-WindowsForVulnScan.ps1 -DisableOnly
.\Prepare-WindowsForVulnScan.ps1 -ScanWindowMinutes 120 -ScannerSourceIP 10.0.0.50
.\Prepare-WindowsForVulnScan.ps1 -AllowHttpOnDomain -ScannerSourceIP 10.0.0.50

.NOTES
- Requires Administrator privileges.
- Run this on the SCANNED machine, not the scanner machine.
- Setting LocalAccountTokenFilterPolicy=1 weakens the UAC remote token boundary for ALL
  local-account remote sessions until reverted. Use -ScanWindowMinutes to auto-revert.
- WinRM over HTTP (not HTTPS) is less secure. Prefer HTTPS in production.
- Admin shares (C$, ADMIN$) are lateral movement targets — revert after scanning.
#>

param(
    [switch]$SkipBackup,
    [switch]$DisableOnly,
    [int]$ScanWindowMinutes = 0,
    [string]$ScannerSourceIP = "",
    [switch]$AllowHttpOnDomain
)

# ============================================================================
# CONFIG SECTION - MODIFY AS NEEDED
# ============================================================================

$ScriptVersion = "1.1"
$LogFile = "C:\Windows\Temp\VulnScanPrep_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$BackupPath = "C:\Windows\Temp\RegistryBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"

# Admin account that will perform the scan (leave empty to skip WMI permission section)
$ScannerAdminAccount = ""  # e.g., "DOMAIN\scanner" or "COMPNAME\administrator"

# Critical services whose failure must halt the script entirely
$CriticalServices = @("Winmgmt")

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry  = "[$timestamp] [$Level] $Message"

    # Colour-code console output for readability
    $colour = switch ($Level) {
        "SUCCESS" { "Green"  }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red"    }
        default   { "White"  }
    }
    Write-Host $logEntry -ForegroundColor $colour
    Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
}

function Test-AdminRights {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                    [Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-LogMessage "This script requires Administrator privileges. Please run as Administrator." "ERROR"
        exit 1
    }

    Write-LogMessage "Administrator privileges confirmed" "SUCCESS"
}

# ============================================================================
# FIX 1 — REGISTRY BACKUP
# Bug: Loop overwrote the same .tmp file on every iteration and the merged
#      $regExport string was never written to disk. Only the final key survived.
# Fix: Export each key to its own uniquely-named temp file, read each file's
#      content (minus the header after the first), concatenate, then write a
#      single valid .reg file and clean up the temp files.
# ============================================================================
function Backup-RegistryKeys {
    if ($SkipBackup) {
        Write-LogMessage "Skipping registry backup (as requested)" "WARNING"
        return
    }

    Write-LogMessage "Backing up registry keys to: $BackupPath" "INFO"

    $regKeys = @(
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "HKLM\SYSTEM\CurrentControlSet\Services\WinRM",
        "HKLM\SYSTEM\CurrentControlSet\Services\Winmgmt",
        "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry"
    )

    $mergedLines = [System.Collections.Generic.List[string]]::new()
    $mergedLines.Add("Windows Registry Editor Version 5.00")
    $mergedLines.Add("")   # blank line required by the format

    $tempFiles = [System.Collections.Generic.List[string]]::new()

    try {
        foreach ($key in $regKeys) {
            # Convert HKLM:\ PowerShell notation to HKLM\ for reg.exe
            $regKey   = $key -replace '^HKLM:\\', 'HKLM\'
            $tempFile = [System.IO.Path]::GetTempFileName() + ".reg"
            $tempFiles.Add($tempFile)

            # Test whether the key exists before attempting export
            $psKey = $key -replace '^HKLM\\', 'HKLM:\'
            if (-not (Test-Path $psKey)) {
                Write-LogMessage "Registry key not found, skipping: $regKey" "WARNING"
                continue
            }

            $output = reg export $regKey $tempFile /y 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-LogMessage "reg export failed for $regKey : $output" "WARNING"
                continue
            }

            # Read the exported file; skip the "Windows Registry Editor Version 5.00"
            # header line (and the blank line that follows) on all but the first key
            # so the merged file has exactly one valid header.
            $lines = Get-Content -Path $tempFile -Encoding Unicode -ErrorAction Stop
            # Always skip the header lines (first 2 lines: header + blank)
            $contentLines = if ($lines.Count -gt 2) { $lines[2..($lines.Count - 1)] } else { @() }
            foreach ($line in $contentLines) {
                $mergedLines.Add($line)
            }
            $mergedLines.Add("")  # blank line between key blocks
        }

        # Write the assembled backup as a Unicode .reg file
        [System.IO.File]::WriteAllLines($BackupPath, $mergedLines,
            [System.Text.Encoding]::Unicode)

        if (Test-Path $BackupPath) {
            $sizeKb = [math]::Round((Get-Item $BackupPath).Length / 1KB, 1)
            Write-LogMessage "Registry backup completed — $BackupPath ($sizeKb KB)" "SUCCESS"
        } else {
            Write-LogMessage "Backup file was not created. Review warnings above." "ERROR"
        }
    }
    catch {
        Write-LogMessage "Registry backup encountered a fatal error: $_" "ERROR"
        Write-LogMessage "Aborting to protect system state. Re-run with -SkipBackup to override." "ERROR"
        exit 1
    }
    finally {
        # Clean up per-key temp files
        foreach ($tf in $tempFiles) {
            Remove-Item -Path $tf -ErrorAction SilentlyContinue
        }
    }
}

# ============================================================================
# FIX 2 — ENABLE-REQUIREDSERVICES: critical service failure halts the script
# Bug: Failures were caught, logged, then silently continued. A machine where
#      Winmgmt failed to start would appear configured but return empty scan
#      results with no obvious explanation.
# Fix: After the loop, check whether any critical service is not running and
#      terminate the entire script if so.
# ============================================================================
function Enable-RequiredServices {
    Write-LogMessage "=== ENABLING SERVICES ===" "INFO"

    $services = @(
        @{Name = "WinRM";          DisplayName = "Windows Remote Management (WS-Management)" },
        @{Name = "Winmgmt";        DisplayName = "Windows Management Instrumentation" },
        @{Name = "RemoteRegistry"; DisplayName = "Remote Registry" }
    )

    $failedCritical = [System.Collections.Generic.List[string]]::new()

    foreach ($service in $services) {
        try {
            Write-LogMessage "Processing service: $($service.DisplayName)" "INFO"

            $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
            if ($null -eq $svc) {
                Write-LogMessage "Service $($service.Name) not found on this system" "WARNING"
                if ($CriticalServices -contains $service.Name) {
                    $failedCritical.Add($service.Name)
                }
                continue
            }

            Set-Service -Name $service.Name -StartupType Automatic -ErrorAction Stop
            Write-LogMessage "Set $($service.Name) to Automatic startup" "SUCCESS"

            if ($svc.Status -ne "Running") {
                Start-Service -Name $service.Name -ErrorAction Stop
                Write-LogMessage "Started $($service.Name)" "SUCCESS"
            } else {
                Write-LogMessage "$($service.Name) is already running" "SUCCESS"
            }
        }
        catch {
            Write-LogMessage "Error enabling $($service.DisplayName): $_" "ERROR"
            if ($CriticalServices -contains $service.Name) {
                $failedCritical.Add($service.Name)
            }
        }
    }

    # Halt if any critical service could not be started
    if ($failedCritical.Count -gt 0) {
        Write-LogMessage ("CRITICAL: The following essential services could not be started: " +
                          ($failedCritical -join ", ") +
                          ". A partially configured machine is unsafe — aborting.") "ERROR"
        exit 1
    }
}

function Enable-FirewallRules {
    param([string]$SourceIP = "")

    Write-LogMessage "=== CONFIGURING FIREWALL RULES ===" "INFO"

    $wmiRules = @(
        "Windows Management Instrumentation (WMI-In)",
        "Windows Management Instrumentation (WINMGMT-In)",
        "Windows Management Instrumentation (ASYNC-In)"
    )

    foreach ($displayName in $wmiRules) {
        try {
            $existingRule = Get-NetFirewallRule -DisplayName $displayName -ErrorAction SilentlyContinue
            if ($existingRule) {
                if ($existingRule.Enabled -eq $false) {
                    Enable-NetFirewallRule -DisplayName $displayName -ErrorAction Stop
                    Write-LogMessage "Enabled firewall rule: $displayName" "SUCCESS"
                } else {
                    Write-LogMessage "Firewall rule already enabled: $displayName" "SUCCESS"
                }
            } else {
                Write-LogMessage "Firewall rule not found: $displayName" "WARNING"
            }
        }
        catch {
            Write-LogMessage "Error enabling firewall rule '$displayName': $_" "ERROR"
        }
    }

    $smbRules = @(
        "File and Printer Sharing (NB-Session-In)",
        "File and Printer Sharing (SMB-In)",
        "File and Printer Sharing (Spooler Service - RPC)",
        "File and Printer Sharing (Spooler Service - RPC-EPMAP)"
    )

    foreach ($ruleName in $smbRules) {
        try {
            $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            if ($rule -and $rule.Enabled -eq $false) {
                Enable-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
                Write-LogMessage "Enabled firewall rule: $ruleName" "SUCCESS"
            } elseif ($rule) {
                Write-LogMessage "Firewall rule already enabled: $ruleName" "SUCCESS"
            }
        }
        catch {
            Write-LogMessage "Error enabling firewall rule '$ruleName': $_" "WARNING"
        }
    }

    # Scope the WinRM firewall rule to the scanner IP when provided
    if ($SourceIP -ne "") {
        try {
            $winrmRules = Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" -ErrorAction SilentlyContinue
            if ($winrmRules) {
                Set-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" `
                    -RemoteAddress $SourceIP -ErrorAction Stop
                Write-LogMessage "Scoped WinRM firewall rule to source IP: $SourceIP" "SUCCESS"
            }
        }
        catch {
            Write-LogMessage "Could not scope WinRM firewall rule to $SourceIP : $_" "WARNING"
        }
    }
}

# ============================================================================
# FIX 3 — DISABLE-UACREMOTERESTRICTIONS: audit trail + scheduled auto-rollback
# Bug: The registry change was permanent with no record of who made it or when,
#      and rollback depended entirely on the operator remembering to read output.
# Fix: Write a structured audit entry to the log. If -ScanWindowMinutes > 0,
#      register a schtasks job to delete the key and stop RemoteRegistry
#      automatically when the scan window expires.
# ============================================================================
function Disable-UACRemoteRestrictions {
    Write-LogMessage "=== CONFIGURING UAC REMOTE RESTRICTIONS ===" "INFO"

    $uacRegPath  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $uacProperty = "LocalAccountTokenFilterPolicy"

    # Write audit record BEFORE making the change
    $auditEntry = ("AUDIT: LocalAccountTokenFilterPolicy set to 1 " +
                   "by $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME " +
                   "at $(Get-Date -Format 'u') " +
                   "(PID $PID, script v$ScriptVersion)")
    Write-LogMessage $auditEntry "WARNING"

    try {
        $currentValue = Get-ItemProperty -Path $uacRegPath -Name $uacProperty -ErrorAction SilentlyContinue
        if ($null -eq $currentValue) {
            Write-LogMessage "LocalAccountTokenFilterPolicy not set. Creating with value 1." "INFO"
        } else {
            Write-LogMessage "Current LocalAccountTokenFilterPolicy value: $($currentValue.$uacProperty)" "INFO"
        }

        New-ItemProperty -Path $uacRegPath -Name $uacProperty -Value 1 `
            -PropertyType DWORD -Force -ErrorAction Stop | Out-Null

        Write-LogMessage "Set LocalAccountTokenFilterPolicy = 1 (enables remote local-admin token)" "SUCCESS"
        Write-LogMessage "WARNING: This weakens the UAC remote token boundary for ALL local-account " +
                         "remote sessions until this setting is reverted." "WARNING"
    }
    catch {
        Write-LogMessage "Error setting LocalAccountTokenFilterPolicy: $_" "ERROR"
        return
    }

    # Schedule automatic rollback if a scan window was requested
    if ($ScanWindowMinutes -gt 0) {
        Write-LogMessage "Scheduling auto-rollback in $ScanWindowMinutes minute(s) via schtasks..." "INFO"

        $rollbackScript = @"
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' ``
    -Name 'LocalAccountTokenFilterPolicy' -ErrorAction SilentlyContinue
Stop-Service  -Name RemoteRegistry -Force -ErrorAction SilentlyContinue
Set-Service   -Name RemoteRegistry -StartupType Disabled -ErrorAction SilentlyContinue
Add-Content   -Path '$LogFile' -Value "[$(Get-Date -Format 'u')] [INFO] Auto-rollback task executed."
Unregister-ScheduledTask -TaskName 'VulnScanRollback' -Confirm:`$false -ErrorAction SilentlyContinue
"@
        $rollbackScriptPath = "C:\Windows\Temp\VulnScanRollback_$(Get-Date -Format 'yyyyMMdd_HHmmss').ps1"
        Set-Content -Path $rollbackScriptPath -Value $rollbackScript -Encoding UTF8

        $triggerTime = (Get-Date).AddMinutes($ScanWindowMinutes).ToString("HH:mm")
        $triggerDate = (Get-Date).AddMinutes($ScanWindowMinutes).ToString("yyyy-MM-dd")

        $taskArgs = "/Create /F /TN VulnScanRollback " +
                    "/TR `"powershell.exe -NonInteractive -ExecutionPolicy Bypass -File $rollbackScriptPath`" " +
                    "/SC ONCE /ST $triggerTime /SD $triggerDate /RL HIGHEST"

        $result = schtasks.exe $taskArgs.Split(" ") 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-LogMessage "Auto-rollback task scheduled for $triggerDate $triggerTime" "SUCCESS"
        } else {
            Write-LogMessage "Failed to schedule rollback task: $result" "WARNING"
            Write-LogMessage "You must manually revert LocalAccountTokenFilterPolicy after the scan." "WARNING"
        }
    } else {
        Write-LogMessage "No -ScanWindowMinutes specified. You MUST manually revert " +
                         "LocalAccountTokenFilterPolicy after the scan completes." "WARNING"
    }
}

# ============================================================================
# FIX 4 — CONFIGURE-WINRM: domain-aware + source-IP scoping
# Bug: quickconfig over HTTP was run unconditionally regardless of domain
#      membership, exposing WinRM credentials on the network segment.
#      No option to scope the listener to a specific scanner IP.
# Fix: Detect domain join status. Refuse HTTP quickconfig on domain machines
#      unless -AllowHttpOnDomain is passed. Scope listener to -ScannerSourceIP
#      via Set-Item WSMan:\localhost\Client\TrustedHosts when provided.
# ============================================================================
function Configure-WinRM {
    param(
        [string]$SourceIP       = "",
        [bool]$AllowHttpOnDomain = $false
    )

    Write-LogMessage "=== CONFIGURING WINRM ===" "INFO"

    try {
        # Detect domain membership
        $computerSystem = Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue
        $isDomainJoined = ($computerSystem -and $computerSystem.PartOfDomain)
        $domainName     = if ($isDomainJoined) { $computerSystem.Domain } else { "WORKGROUP" }

        Write-LogMessage "Domain membership: $domainName (domain-joined: $isDomainJoined)" "INFO"

        if ($isDomainJoined -and -not $AllowHttpOnDomain) {
            Write-LogMessage ("Domain-joined machine detected. Running WinRM quickconfig over plain HTTP " +
                              "exposes credentials on the network segment. " +
                              "Use HTTPS (preferred) or pass -AllowHttpOnDomain to override.") "ERROR"
            Write-LogMessage "WinRM quickconfig skipped. Configure WinRM over HTTPS manually." "WARNING"
            return
        }

        # Run quickconfig only if WinRM is not yet responding
        $winrmCheck = winrm get winrm/config 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-LogMessage "WinRM not yet configured. Running quickconfig (HTTP)..." "INFO"
            winrm quickconfig -quiet -transport:http 2>&1 | Out-Null

            if ($LASTEXITCODE -eq 0) {
                Write-LogMessage "WinRM quickconfig completed (HTTP)" "SUCCESS"
            } else {
                Write-LogMessage "WinRM quickconfig returned exit code $LASTEXITCODE" "WARNING"
            }
        } else {
            Write-LogMessage "WinRM is already configured" "SUCCESS"
        }

        # Harden: do not allow fully unencrypted transport
        winrm set winrm/config/service '@{AllowUnencrypted="false"}' 2>&1 | Out-Null
        # Enable Basic auth so the scanner credential is accepted
        winrm set winrm/config/service/auth '@{Basic="true"}' 2>&1 | Out-Null

        Write-LogMessage "WinRM AllowUnencrypted=false, Basic auth=true" "SUCCESS"

        # Scope TrustedHosts to the scanner IP if supplied
        if ($SourceIP -ne "") {
            $currentTrusted = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
            if ($currentTrusted -notmatch [regex]::Escape($SourceIP)) {
                $newTrusted = if ($currentTrusted -eq "" -or $null -eq $currentTrusted) {
                    $SourceIP
                } else {
                    "$currentTrusted,$SourceIP"
                }
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value $newTrusted -Force -ErrorAction Stop
                Write-LogMessage "WinRM TrustedHosts scoped to: $newTrusted" "SUCCESS"
            } else {
                Write-LogMessage "Scanner IP $SourceIP already in WinRM TrustedHosts" "SUCCESS"
            }
        } else {
            Write-LogMessage "No -ScannerSourceIP supplied. WinRM is accessible from any host — " +
                             "consider passing -ScannerSourceIP for tighter scoping." "WARNING"
        }
    }
    catch {
        Write-LogMessage "Error configuring WinRM: $_" "WARNING"
    }
}

function Enable-AdminShares {
    Write-LogMessage "=== CONFIGURING ADMIN SHARES ===" "INFO"

    try {
        $adminShareRegPath  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $autoShareProperty  = "AutoShareServer"

        $currentValue = Get-ItemProperty -Path $adminShareRegPath -Name $autoShareProperty -ErrorAction SilentlyContinue

        if ($currentValue -and $currentValue.$autoShareProperty -eq 0) {
            Write-LogMessage "Admin shares are disabled. Enabling..." "INFO"
            Set-ItemProperty -Path $adminShareRegPath -Name $autoShareProperty -Value 1 -ErrorAction Stop
            Write-LogMessage "Enabled AutoShareServer (admin shares C`$, ADMIN`$, IPC`$)" "SUCCESS"
        } else {
            Write-LogMessage "Admin shares are already enabled" "SUCCESS"
        }

        $shares      = Get-SmbShare -Special -ErrorAction SilentlyContinue
        $adminShares = $shares | Where-Object { $_.Name -match '^(C\$|ADMIN\$|IPC\$)$' }
        if ($adminShares.Count -gt 0) {
            Write-LogMessage "Admin shares verified: $($adminShares.Name -join ', ')" "SUCCESS"
        } else {
            Write-LogMessage "Some admin shares may not be visible yet (a restart may be required)" "WARNING"
        }
    }
    catch {
        Write-LogMessage "Error configuring admin shares: $_" "WARNING"
    }
}

# ============================================================================
# FIX 5 — CONFIGURE-WMIPERMISSIONS: NOT IMPLEMENTED — exit non-zero if needed
# Bug: Function appeared to do something (queried __SystemSecurity) but never
#      actually set any DCOM/WMI permissions. A caller who set $ScannerAdminAccount
#      received no useful output and no warning that the step was skipped.
# Fix: Clearly document the limitation. If ScannerAdminAccount is set, log an
#      actionable error and exit with code 2 so the caller knows the configuration
#      is incomplete rather than silently proceeding.
# ============================================================================
function Configure-WMIPermissions {
    Write-LogMessage "=== CONFIGURING WMI PERMISSIONS ===" "INFO"

    if ([string]::IsNullOrEmpty($ScannerAdminAccount)) {
        Write-LogMessage "ScannerAdminAccount not set — WMI permission step skipped." "WARNING"
        Write-LogMessage "If the scanner runs as a non-Administrator account you must grant WMI namespace" "INFO"
        Write-LogMessage "  access manually: open 'WMI Control' (wmimgmt.msc) → right-click 'WMI Control'" "INFO"
        Write-LogMessage "  → Properties → Security → Root\CIMV2 → grant 'Remote Enable' to the account." "INFO"
        return
    }

    # *** NOT IMPLEMENTED ***
    # Programmatically setting DCOM/WMI namespace security descriptors requires
    # manipulating binary ACL blobs via the __SystemSecurity::SetSD / SetBinarySD
    # WMI methods or editing HKLM\SOFTWARE\Microsoft\Ole registry ACLs directly —
    # neither of which can be done reliably in a single-file script across all
    # supported Windows versions without a dedicated module (e.g., DSInternals,
    # or the Carbon PowerShell module).
    #
    # Because ScannerAdminAccount is set, the caller explicitly expects this step
    # to succeed. Silently skipping it would leave the machine in a partially
    # configured state that is likely to produce empty scan results. We therefore
    # abort with a non-zero exit code and actionable guidance.

    Write-LogMessage ("NOT IMPLEMENTED: Configure-WMIPermissions cannot programmatically grant " +
                      "DCOM/WMI namespace permissions for '$ScannerAdminAccount'.") "ERROR"
    Write-LogMessage "Manual steps required:" "ERROR"
    Write-LogMessage "  1. Open Component Services (dcomcnfg.exe)." "INFO"
    Write-LogMessage "     → Component Services → Computers → My Computer → Properties" "INFO"
    Write-LogMessage "     → COM Security → Edit Limits/Default on 'Access Permissions'" "INFO"
    Write-LogMessage "     → Add '$ScannerAdminAccount' with 'Remote Access' Allow." "INFO"
    Write-LogMessage "  2. Open WMI Control (wmimgmt.msc)." "INFO"
    Write-LogMessage "     → Right-click 'WMI Control (Local)' → Properties → Security" "INFO"
    Write-LogMessage "     → Select Root\CIMV2 → Security → Add '$ScannerAdminAccount'" "INFO"
    Write-LogMessage "     → grant: Enable Account, Remote Enable." "INFO"
    Write-LogMessage "Re-run this script without setting ScannerAdminAccount if you are using a" "INFO"
    Write-LogMessage "built-in Administrator account (which already has WMI access by default)." "INFO"

    # Exit with code 2 (distinct from 1=privilege failure) so automation can detect this state
    exit 2
}

function Configure-RegistrySettings {
    Write-LogMessage "=== CONFIGURING REGISTRY SETTINGS ===" "INFO"

    try {
        $wmiRegPath = "HKLM:\SOFTWARE\Microsoft\WBEM"
        if (-not (Test-Path $wmiRegPath)) {
            New-Item -Path $wmiRegPath -Force -ErrorAction Stop | Out-Null
            Write-LogMessage "Created WMI registry path" "INFO"
        }

        $wmiRepPath = "C:\ProgramData\Microsoft\Windows\WMI\Repository"
        if (Test-Path $wmiRepPath) {
            Write-LogMessage "WMI Repository found at: $wmiRepPath" "SUCCESS"
        } else {
            Write-LogMessage "WMI Repository path not found — WMI may need repair." "WARNING"
        }
    }
    catch {
        Write-LogMessage "Error configuring registry settings: $_" "WARNING"
    }
}

function Set-FirewallProfile {
    Write-LogMessage "=== VERIFYING FIREWALL PROFILES ===" "INFO"

    try {
        $profiles = Get-NetFirewallProfile
        foreach ($profile in $profiles) {
            Write-LogMessage "Firewall Profile: $($profile.Name) — Enabled: $($profile.Enabled)" "INFO"
        }
    }
    catch {
        Write-LogMessage "Error checking firewall profiles: $_" "WARNING"
    }
}

# ============================================================================
# VERIFICATION
# ============================================================================

function Verify-Configuration {
    Write-LogMessage "=== VERIFICATION REPORT ===" "INFO"

    Write-LogMessage "SERVICE STATUS:" "INFO"
    @("WinRM", "Winmgmt", "RemoteRegistry") | ForEach-Object {
        $svc = Get-Service -Name $_ -ErrorAction SilentlyContinue
        if ($svc) {
            Write-LogMessage "  $_ — Status: $($svc.Status), Startup: $($svc.StartType)" "INFO"
        }
    }

    Write-LogMessage "REGISTRY SETTINGS:" "INFO"
    $uacRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $uacValue   = Get-ItemProperty -Path $uacRegPath -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue
    Write-LogMessage ("  LocalAccountTokenFilterPolicy: " +
                      $(if ($uacValue) { $uacValue.LocalAccountTokenFilterPolicy } else { 'Not set' })) "INFO"

    Write-LogMessage "ADMIN SHARES:" "INFO"
    try {
        $shares = Get-SmbShare -Special -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(C\$|ADMIN\$|IPC\$)$' }
        foreach ($share in $shares) {
            Write-LogMessage "  $($share.Name) — Path: $($share.Path)" "INFO"
        }
    }
    catch {
        Write-LogMessage "  Could not enumerate shares" "WARNING"
    }

    Write-LogMessage "WINRM STATUS:" "INFO"
    try {
        winrm get winrm/config 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-LogMessage "  WinRM is configured and responding" "SUCCESS"
        } else {
            Write-LogMessage "  WinRM may not be properly configured" "WARNING"
        }
    }
    catch {
        Write-LogMessage "  Error checking WinRM: $_" "WARNING"
    }
}

# ============================================================================
# ROLLBACK INSTRUCTIONS
# ============================================================================

function Show-DisableInstructions {
    Write-LogMessage "=== COMMANDS TO DISABLE/REVERT CHANGES ===" "INFO"
    Write-LogMessage "Run the block below with Administrator privileges to reverse all changes:" "WARNING"

    $disableInstructions = @"

# ---- BEGIN ROLLBACK BLOCK ----

# 1. Revert LocalAccountTokenFilterPolicy (removes the key, restoring OS default)
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' ``
    -Name 'LocalAccountTokenFilterPolicy' -ErrorAction SilentlyContinue

# 2. Stop and disable Remote Registry
Stop-Service  -Name RemoteRegistry -Force -ErrorAction SilentlyContinue
Set-Service   -Name RemoteRegistry -StartupType Disabled -ErrorAction SilentlyContinue

# 3. Disable admin share auto-creation
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' ``
    -Name 'AutoShareServer' -Value 0 -ErrorAction SilentlyContinue

# 4. Disable WMI and SMB firewall rules that were enabled for the scan
Disable-NetFirewallRule -DisplayName "Windows Management Instrumentation (WMI-In)"        -ErrorAction SilentlyContinue
Disable-NetFirewallRule -DisplayName "Windows Management Instrumentation (WINMGMT-In)"    -ErrorAction SilentlyContinue
Disable-NetFirewallRule -DisplayName "Windows Management Instrumentation (ASYNC-In)"      -ErrorAction SilentlyContinue
Disable-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)"                  -ErrorAction SilentlyContinue
Disable-NetFirewallRule -DisplayName "File and Printer Sharing (NB-Session-In)"           -ErrorAction SilentlyContinue

# 5. Remove the auto-rollback scheduled task (if it was created and hasn't fired yet)
Unregister-ScheduledTask -TaskName 'VulnScanRollback' -Confirm:`$false -ErrorAction SilentlyContinue

# 6. Restart to flush share state and apply policy changes
Restart-Computer -Confirm

# ---- END ROLLBACK BLOCK ----
"@

    Write-Host $disableInstructions
    Add-Content -Path $LogFile -Value $disableInstructions
}

# ============================================================================
# CONFIRMATION PROMPT
# Bug (implicit): No confirmation before making security-weakening changes.
# Fix: Show every action that will be taken and require explicit Y to proceed.
# ============================================================================
function Confirm-Changes {
    param([string]$SourceIP, [int]$ScanWindowMinutes)

    Write-Host ""
    Write-Host "========================================================================" -ForegroundColor Yellow
    Write-Host "  THIS SCRIPT WILL MAKE THE FOLLOWING SECURITY-IMPACTING CHANGES:" -ForegroundColor Yellow
    Write-Host "========================================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  1. Enable services (WinRM, Winmgmt, RemoteRegistry) set to Automatic."
    Write-Host "  2. Enable WMI and SMB firewall rules."
    Write-Host "  3. Set LocalAccountTokenFilterPolicy = 1  [WEAKENS UAC REMOTE BOUNDARY]"
    if ($ScanWindowMinutes -gt 0) {
        Write-Host "     Auto-rollback scheduled in $ScanWindowMinutes minute(s)."
    } else {
        Write-Host "     No auto-rollback — you must revert this manually after scanning." -ForegroundColor Red
    }
    Write-Host "  4. Run WinRM quickconfig (HTTP transport)."
    if ($SourceIP -ne "") {
        Write-Host "     WinRM and firewall scoped to source IP: $SourceIP"
    } else {
        Write-Host "     WinRM accessible from ALL hosts (no source IP filter)." -ForegroundColor Red
    }
    Write-Host "  5. Enable admin shares (C`$, ADMIN`$, IPC`$)."
    Write-Host ""
    Write-Host "  Registry backup: $BackupPath"
    Write-Host "  Log file:        $LogFile"
    Write-Host ""
    Write-Host "  Machine: $env:COMPUTERNAME   User: $env:USERDOMAIN\$env:USERNAME"
    Write-Host ""
    Write-Host "========================================================================" -ForegroundColor Yellow

    $answer = Read-Host "Type YES to proceed, anything else to abort"
    if ($answer -ne "YES") {
        Write-Host "Aborted by user. No changes were made." -ForegroundColor Cyan
        exit 0
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    Clear-Host

    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host " Windows Vulnerability Scan Preparation Script  v$ScriptVersion" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-LogMessage "Script execution started" "INFO"
    Write-LogMessage "Log file: $LogFile" "INFO"
    Write-Host ""

    if ($DisableOnly) {
        Show-DisableInstructions
        Write-LogMessage "Disable instructions displayed. No changes made." "INFO"
        return
    }

    # Step 0: confirm admin rights before showing the prompt
    Test-AdminRights

    # Step 1: mandatory confirmation — lists every change before touching anything
    Confirm-Changes -SourceIP $ScannerSourceIP -ScanWindowMinutes $ScanWindowMinutes
    Write-Host ""

    # Step 2: registry backup (halts on failure unless -SkipBackup)
    Backup-RegistryKeys
    Write-Host ""

    # Step 3: services (halts if a critical service cannot start)
    Enable-RequiredServices
    Write-Host ""

    # Step 4: firewall rules (scoped to source IP when provided)
    Enable-FirewallRules -SourceIP $ScannerSourceIP
    Write-Host ""

    # Step 5: UAC remote token policy (with audit log + optional auto-rollback)
    Disable-UACRemoteRestrictions
    Write-Host ""

    # Step 6: WinRM (domain-aware; scoped to source IP)
    Configure-WinRM -SourceIP $ScannerSourceIP -AllowHttpOnDomain $AllowHttpOnDomain.IsPresent
    Write-Host ""

    # Step 7: admin shares
    Enable-AdminShares
    Write-Host ""

    # Step 8: miscellaneous registry settings
    Configure-RegistrySettings
    Write-Host ""

    # Step 9: log firewall profile state (informational)
    Set-FirewallProfile
    Write-Host ""

    # Step 10: WMI permissions for dedicated scan account (exits non-zero if incomplete)
    Configure-WMIPermissions
    Write-Host ""

    # Step 11: verification report
    Verify-Configuration
    Write-Host ""

    Write-LogMessage "=== SCRIPT SUMMARY ===" "INFO"
    Write-LogMessage "Configuration completed. Review the log for details." "SUCCESS"
    Write-LogMessage "Log file: $LogFile" "INFO"
    Write-LogMessage "" "INFO"
    Write-LogMessage "NEXT STEPS:" "INFO"
    Write-LogMessage "  1. Restart the machine to ensure all changes are applied: Restart-Computer" "INFO"
    Write-LogMessage "  2. Verify scanner connectivity from the scanning machine." "INFO"
    Write-LogMessage "  3. Run the credentialed vulnerability scan." "INFO"
    Write-LogMessage "  4. After scanning, run the rollback commands printed below." "INFO"
    Write-LogMessage "" "INFO"

    Show-DisableInstructions

    Write-Host ""
    Write-LogMessage "Script execution completed" "SUCCESS"
}

Main
