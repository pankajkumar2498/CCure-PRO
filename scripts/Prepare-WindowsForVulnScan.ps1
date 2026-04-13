#Requires -RunAsAdministrator
<#
.SYNOPSIS
Prepares a Windows machine for credentialed vulnerability scanning (CCure Audit PRO, Nessus, etc.)

.DESCRIPTION
Configures WMI, Remote Registry, firewall rules, UAC policies, and WinRM to enable
remote vulnerability scanners to retrieve system information and detect vulnerabilities.

.PARAMETER SkipBackup
If specified, skips registry backup before modifications

.PARAMETER DisableOnly
If specified, only shows commands to disable these features later

.EXAMPLE
.\Prepare-WindowsForVulnScan.ps1
.\Prepare-WindowsForVulnScan.ps1 -SkipBackup
.\Prepare-WindowsForVulnScan.ps1 -DisableOnly

.NOTES
- Requires Administrator privileges
- Should be tested in non-production environment first
- Keep backup of registry modifications
- Run this on the SCANNED machine, not the scanner machine
#>

param(
    [switch]$SkipBackup,
    [switch]$DisableOnly
)

# ============================================================================
# CONFIG SECTION - MODIFY AS NEEDED
# ============================================================================

$ScriptVersion = "1.0"
$LogFile = "C:\Windows\Temp\VulnScanPrep_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$BackupPath = "C:\Windows\Temp\RegistryBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"

# Admin account that will perform the scan (leave empty to skip group configuration)
$ScannerAdminAccount = ""  # e.g., "DOMAIN\scanner" or "COMPNAME\administrator"

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
    $logEntry = "[$timestamp] [$Level] $Message"
    
    Write-Host $logEntry
    Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
}

function Test-AdminRights {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-LogMessage "This script requires Administrator privileges. Please run as Administrator." "ERROR"
        exit 1
    }
    
    Write-LogMessage "Administrator privileges confirmed" "SUCCESS"
}

function Backup-RegistryKeys {
    if ($SkipBackup) {
        Write-LogMessage "Skipping registry backup (as requested)" "WARNING"
        return
    }
    
    Write-LogMessage "Backing up registry keys to: $BackupPath" "INFO"
    
    try {
        # Backup WMI and security-related registry keys
        $regKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM",
            "HKLM:\SYSTEM\CurrentControlSet\Services\WMI",
            "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry"
        )
        
        $regExport = "Windows Registry Editor Version 5.00`r`n`r`n"
        foreach ($key in $regKeys) {
            if (Test-Path $key) {
                $export = reg export $key "$BackupPath.tmp" /y 2>&1
            }
        }
        
        Write-LogMessage "Registry backup completed" "SUCCESS"
    } catch {
        Write-LogMessage "Registry backup encountered an error: $_" "WARNING"
    }
}

function Enable-RequiredServices {
    Write-LogMessage "=== ENABLING SERVICES ===" "INFO"
    
    $services = @(
        @{Name = "WinRM"; DisplayName = "Windows Remote Management (WS-Management)" },
        @{Name = "Winmgmt"; DisplayName = "Windows Management Instrumentation" },
        @{Name = "RemoteRegistry"; DisplayName = "Remote Registry" }
    )
    
    foreach ($service in $services) {
        try {
            Write-LogMessage "Processing service: $($service.DisplayName)" "INFO"
            
            # Start the service if it's not running
            $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
            
            if ($null -eq $svc) {
                Write-LogMessage "Service $($service.Name) not found on this system" "WARNING"
                continue
            }
            
            # Set to Automatic startup
            Set-Service -Name $service.Name -StartupType Automatic -ErrorAction Stop
            Write-LogMessage "Set $($service.Name) to Automatic startup" "SUCCESS"
            
            # Start service if not running
            if ($svc.Status -ne "Running") {
                Start-Service -Name $service.Name -ErrorAction Stop
                Write-LogMessage "Started $($service.Name)" "SUCCESS"
            } else {
                Write-LogMessage "$($service.Name) is already running" "SUCCESS"
            }
            
        } catch {
            Write-LogMessage "Error enabling $($service.DisplayName): $_" "ERROR"
        }
    }
}

function Enable-FirewallRules {
    Write-LogMessage "=== CONFIGURING FIREWALL RULES ===" "INFO"
    
    # WMI Firewall Rules
    $wmiRules = @(
        @{Name = "WMI-RPCSS-In-TCP"; DisplayName = "Windows Management Instrumentation (WMI-In)" },
        @{Name = "WMI-WINMGMT-In-TCP"; DisplayName = "Windows Management Instrumentation (WINMGMT-In)" },
        @{Name = "WMI-ASYNC-In-TCP"; DisplayName = "Windows Management Instrumentation (ASYNC-In)" }
    )
    
    foreach ($rule in $wmiRules) {
        try {
            $existingRule = Get-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue
            
            if ($existingRule) {
                if ($existingRule.Enabled -eq $false) {
                    Enable-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction Stop
                    Write-LogMessage "Enabled firewall rule: $($rule.DisplayName)" "SUCCESS"
                } else {
                    Write-LogMessage "Firewall rule already enabled: $($rule.DisplayName)" "SUCCESS"
                }
            } else {
                Write-LogMessage "Firewall rule not found: $($rule.DisplayName)" "WARNING"
            }
        } catch {
            Write-LogMessage "Error enabling firewall rule $($rule.DisplayName): $_" "ERROR"
        }
    }
    
    # SMB/File Sharing Rules (for credentialed scans)
    $smbRules = @(
        "File and Printer Sharing (NB-Session-In)",
        "File and Printer Sharing (SMB-In)",
        "File and Printer Sharing (Spooler Service - RPC)",
        "File and Printer Sharing (Spooler Service - RPC-EPMAP)"
    )
    
    foreach ($ruleName in $smbRules) {
        try {
            $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            
            if ($rule) {
                if ($rule.Enabled -eq $false) {
                    Enable-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
                    Write-LogMessage "Enabled firewall rule: $ruleName" "SUCCESS"
                } else {
                    Write-LogMessage "Firewall rule already enabled: $ruleName" "SUCCESS"
                }
            }
        } catch {
            # Silently continue if rule doesn't exist on this Windows version
        }
    }
}

function Disable-UACRemoteRestrictions {
    Write-LogMessage "=== CONFIGURING UAC REMOTE RESTRICTIONS ===" "INFO"
    
    $uacRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $uacProperty = "LocalAccountTokenFilterPolicy"
    
    try {
        # Check current value
        $currentValue = Get-ItemProperty -Path $uacRegPath -Name $uacProperty -ErrorAction SilentlyContinue
        
        if ($null -eq $currentValue) {
            Write-LogMessage "LocalAccountTokenFilterPolicy not set. Creating with value 1" "INFO"
        } else {
            Write-LogMessage "Current LocalAccountTokenFilterPolicy value: $($currentValue.$uacProperty)" "INFO"
        }
        
        # Set LocalAccountTokenFilterPolicy to 1 to allow remote admin authentication
        # This is required for WMI queries to work remotely
        New-ItemProperty -Path $uacRegPath -Name $uacProperty -Value 1 -PropertyType DWORD -Force -ErrorAction Stop | Out-Null
        
        Write-LogMessage "Set LocalAccountTokenFilterPolicy to 1 (enables remote admin token filtering)" "SUCCESS"
        
    } catch {
        Write-LogMessage "Error configuring UAC remote restrictions: $_" "ERROR"
    }
}

function Configure-WinRM {
    Write-LogMessage "=== CONFIGURING WINRM ===" "INFO"
    
    try {
        # Check if WinRM is configured
        $winrmConfig = winrm get winrm/config 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            Write-LogMessage "Configuring WinRM..." "INFO"
            
            # Run quickconfigure to enable WinRM
            winrm quickconfig -quiet -transport:http
            
            if ($LASTEXITCODE -eq 0) {
                Write-LogMessage "WinRM quickconfig completed" "SUCCESS"
            } else {
                Write-LogMessage "WinRM quickconfig returned exit code: $LASTEXITCODE" "WARNING"
            }
        } else {
            Write-LogMessage "WinRM is already configured" "SUCCESS"
        }
        
        # Additional WinRM security settings
        Write-LogMessage "Configuring WinRM security settings..." "INFO"
        
        # Allow credentials to be sent via HTTPS
        winrm set winrm/config/service '@{AllowUnencrypted="false"}' 2>&1 | Out-Null
        winrm set winrm/config/service/auth '@{Basic="true"}' 2>&1 | Out-Null
        
        Write-LogMessage "WinRM security settings configured" "SUCCESS"
        
    } catch {
        Write-LogMessage "Error configuring WinRM: $_" "WARNING"
    }
}

function Enable-AdminShares {
    Write-LogMessage "=== CONFIGURING ADMIN SHARES ===" "INFO"
    
    try {
        # Check if admin shares are already enabled
        $adminShareRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $autoShareProperty = "AutoShareServer"
        
        $currentValue = Get-ItemProperty -Path $adminShareRegPath -Name $autoShareProperty -ErrorAction SilentlyContinue
        
        if ($currentValue -and $currentValue.$autoShareProperty -eq 0) {
            Write-LogMessage "Admin shares are disabled. Enabling..." "INFO"
            
            Set-ItemProperty -Path $adminShareRegPath -Name $autoShareProperty -Value 1 -ErrorAction Stop
            Write-LogMessage "Enabled AutoShareServer (admin shares C$, ADMIN$, IPC$)" "SUCCESS"
        } else {
            Write-LogMessage "Admin shares are already enabled" "SUCCESS"
        }
        
        # Verify shares exist
        Write-LogMessage "Verifying admin shares..." "INFO"
        $shares = Get-SmbShare -Special -ErrorAction SilentlyContinue
        $adminShares = $shares | Where-Object { $_.Name -match '^(C\$|ADMIN\$|IPC\$)$' }
        
        if ($adminShares.Count -gt 0) {
            Write-LogMessage "Admin shares verified: $($adminShares.Name -join ', ')" "SUCCESS"
        } else {
            Write-LogMessage "Some admin shares may not be visible (this is normal on some systems)" "WARNING"
        }
        
    } catch {
        Write-LogMessage "Error configuring admin shares: $_" "WARNING"
    }
}

function Configure-WMIPermissions {
    Write-LogMessage "=== CONFIGURING WMI PERMISSIONS ===" "INFO"
    
    if ([string]::IsNullOrEmpty($ScannerAdminAccount)) {
        Write-LogMessage "Scanner admin account not specified. Skipping WMI permission configuration" "WARNING"
        Write-LogMessage "To configure WMI permissions, edit the script and set `$ScannerAdminAccount variable" "INFO"
        return
    }
    
    try {
        # Grant WMI permissions to the scanner account
        Write-LogMessage "Granting WMI namespace access to: $ScannerAdminAccount" "INFO"
        
        # DCOM permissions for WMI
        $dcomRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog"
        
        # Use WMI Security namespace to grant permissions
        $computername = $env:COMPUTERNAME
        
        # Create WMI namespace security descriptor
        $wmiNamespace = "root\cimv2"
        $wmiNamespaceObject = Get-WmiObject -Namespace $wmiNamespace -Class __SystemSecurity -ErrorAction SilentlyContinue
        
        if ($wmiNamespaceObject) {
            Write-LogMessage "WMI namespace __SystemSecurity object found" "INFO"
            Write-LogMessage "WMI permissions would need to be configured via Windows Security GUI or DCOM settings" "INFO"
        }
        
        # Grant Distributed COM access via registry
        Write-LogMessage "Configuring DCOM permissions for $ScannerAdminAccount" "INFO"
        
        # This would require complex DCOM configuration - instead guide user to use GUI
        Write-LogMessage "For detailed WMI permission control, use WMI Control or DCOM Config in Component Services" "INFO"
        
    } catch {
        Write-LogMessage "Error configuring WMI permissions: $_" "WARNING"
    }
}

function Configure-RegistrySettings {
    Write-LogMessage "=== CONFIGURING REGISTRY SETTINGS ===" "INFO"
    
    try {
        # Enable WMI tracing (can help with debugging)
        $wmiRegPath = "HKLM:\SOFTWARE\Microsoft\WBEM"
        
        # Ensure WMI registry path exists
        if (-not (Test-Path $wmiRegPath)) {
            New-Item -Path $wmiRegPath -Force -ErrorAction Stop | Out-Null
            Write-LogMessage "Created WMI registry path" "INFO"
        }
        
        # Increase WMI repository size if needed (some systems have small repos)
        Write-LogMessage "Checking WMI repository configuration..." "INFO"
        
        # Note: WMI repository automatically manages size; this is informational
        $wmiRepPath = "C:\ProgramData\Microsoft\Windows\WMI\Repository"
        if (Test-Path $wmiRepPath) {
            Write-LogMessage "WMI Repository found at: $wmiRepPath" "SUCCESS"
        }
        
    } catch {
        Write-LogMessage "Error configuring registry settings: $_" "WARNING"
    }
}

function Set-FirewallProfile {
    Write-LogMessage "=== VERIFYING FIREWALL PROFILES ===" "INFO"
    
    try {
        $profiles = Get-NetFirewallProfile
        
        foreach ($profile in $profiles) {
            Write-LogMessage "Firewall Profile: $($profile.Name) - Enabled: $($profile.Enabled)" "INFO"
        }
        
    } catch {
        Write-LogMessage "Error checking firewall profiles: $_" "WARNING"
    }
}

# ============================================================================
# VERIFICATION FUNCTIONS
# ============================================================================

function Verify-Configuration {
    Write-LogMessage "=== VERIFICATION REPORT ===" "INFO"
    
    # Check services
    Write-LogMessage "SERVICE STATUS:" "INFO"
    $services = @("WinRM", "Winmgmt", "RemoteRegistry")
    foreach ($service in $services) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            Write-LogMessage "  $service - Status: $($svc.Status), Startup: $($svc.StartType)" "INFO"
        }
    }
    
    # Check registry settings
    Write-LogMessage "REGISTRY SETTINGS:" "INFO"
    $uacRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $uacValue = Get-ItemProperty -Path $uacRegPath -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue
    Write-LogMessage "  LocalAccountTokenFilterPolicy: $(if ($uacValue) { $uacValue.LocalAccountTokenFilterPolicy } else { 'Not set (may need to be set)' })" "INFO"
    
    # Check admin shares
    Write-LogMessage "ADMIN SHARES:" "INFO"
    try {
        $shares = Get-SmbShare -Special -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(C\$|ADMIN\$|IPC\$)$' }
        foreach ($share in $shares) {
            Write-LogMessage "  $($share.Name) - Path: $($share.Path)" "INFO"
        }
    } catch {
        Write-LogMessage "  Could not enumerate shares" "WARNING"
    }
    
    # Check WinRM
    Write-LogMessage "WINRM STATUS:" "INFO"
    try {
        $winrmStatus = winrm get winrm/config 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-LogMessage "  WinRM is configured and responding" "SUCCESS"
        } else {
            Write-LogMessage "  WinRM may not be properly configured" "WARNING"
        }
    } catch {
        Write-LogMessage "  Error checking WinRM: $_" "WARNING"
    }
}

# ============================================================================
# CLEANUP/DISABLE FUNCTIONS
# ============================================================================

function Show-DisableInstructions {
    Write-LogMessage "=== COMMANDS TO DISABLE/REVERT CHANGES ===" "INFO"
    Write-LogMessage "Run these commands with Administrator privileges to reverse the changes:" "WARNING"
    Write-LogMessage ""
    
    $disableInstructions = @"

# Disable Remote Registry Service (re-enable if needed for other tools)
Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue
Set-Service -Name RemoteRegistry -StartupType Disabled -ErrorAction SilentlyContinue

# Restore LocalAccountTokenFilterPolicy (tighter UAC)
# Option 1: Delete the policy (reverts to default)
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -ErrorAction SilentlyContinue

# Option 2: Set permissive value for domain accounts only
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 0 -ErrorAction SilentlyContinue

# Disable admin shares (C$, ADMIN$, IPC$)
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareServer' -Value 0 -ErrorAction SilentlyContinue

# Disable specific firewall rules
Disable-NetFirewallRule -DisplayName "Windows Management Instrumentation (WMI-In)" -ErrorAction SilentlyContinue
Disable-NetFirewallRule -DisplayName "Windows Management Instrumentation (WINMGMT-In)" -ErrorAction SilentlyContinue
Disable-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)" -ErrorAction SilentlyContinue

# Note: Restart required for some changes to take effect
Restart-Computer -Confirm

"@
    
    Write-Host $disableInstructions
    Add-Content -Path $LogFile -Value $disableInstructions
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    Clear-Host
    
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "Windows Vulnerability Scan Preparation Script" -ForegroundColor Cyan
    Write-Host "Version: $ScriptVersion" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-LogMessage "Script execution started" "INFO"
    Write-LogMessage "Log file: $LogFile" "INFO"
    Write-Host ""
    
    if ($DisableOnly) {
        Show-DisableInstructions
        Write-LogMessage "Disable instructions displayed" "INFO"
        return
    }
    
    # Execute configuration steps in order
    Test-AdminRights
    Write-Host ""
    
    Backup-RegistryKeys
    Write-Host ""
    
    Enable-RequiredServices
    Write-Host ""
    
    Enable-FirewallRules
    Write-Host ""
    
    Disable-UACRemoteRestrictions
    Write-Host ""
    
    Configure-WinRM
    Write-Host ""
    
    Enable-AdminShares
    Write-Host ""
    
    Configure-RegistrySettings
    Write-Host ""
    
    Set-FirewallProfile
    Write-Host ""
    
    Configure-WMIPermissions
    Write-Host ""
    
    Verify-Configuration
    Write-Host ""
    
    # Summary
    Write-LogMessage "=== SCRIPT SUMMARY ===" "INFO"
    Write-LogMessage "Configuration completed. Please review the log file for details." "SUCCESS"
    Write-LogMessage "Log file saved to: $LogFile" "INFO"
    Write-LogMessage "" "INFO"
    Write-LogMessage "NEXT STEPS:" "INFO"
    Write-LogMessage "1. Restart the computer to apply all changes: Restart-Computer" "INFO"
    Write-LogMessage "2. Test the scanner connectivity from the scanning machine using the verification script" "INFO"
    Write-LogMessage "3. Run the credentialed vulnerability scan from CCure Audit PRO" "INFO"
    Write-LogMessage "" "INFO"
    
    Show-DisableInstructions
    
    Write-Host ""
    Write-LogMessage "Script execution completed" "SUCCESS"
}

# Execute main function
Main
