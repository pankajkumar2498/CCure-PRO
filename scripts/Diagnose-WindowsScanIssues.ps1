#Requires -RunAsAdministrator
<#
.SYNOPSIS
Advanced diagnostic and troubleshooting script for Windows credentialed scanning issues

.DESCRIPTION
Comprehensive diagnostics tool for troubleshooting why credentialed scans fail to retrieve data.
Generates detailed reports and suggests fixes.

.PARAMETER Detailed
If present, runs additional deep diagnostic tests

.PARAMETER Interactive
If present, prompts for each major section

.PARAMETER ExportReport
If present, exports results to HTML file

.EXAMPLE
.\Diagnose-WindowsScanIssues.ps1
.\Diagnose-WindowsScanIssues.ps1 -Detailed
.\Diagnose-WindowsScanIssues.ps1 -ExportReport "C:\Reports\Diagnosis.html"

.NOTES
Useful when basic verification script doesn't reveal the problem
#>

param(
    [switch]$Detailed,
    [switch]$Interactive,
    [string]$ExportReport
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$ScriptVersion = "1.0"
$ReportData = @()
$errors = @()
$warnings = @()

# ============================================================================
# UTILITY FUNCTIONS  
# ============================================================================

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
}

function Write-Result {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Details = "",
        [ValidateSet("OK", "WARNING", "ERROR", "INFO")]
        [string]$Severity = "INFO"
    )
    
    $statusColor = switch ($Severity) {
        "OK" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        default { "White" }
    }
    
    $statusSymbol = switch ($Severity) {
        "OK" { "✓" }
        "ERROR" { "✗" }
        "WARNING" { "!" }
        default { "•" }
    }
    
    Write-Host ("  {0} {1,-50} {2}" -f $statusSymbol, $Name, $Status) -ForegroundColor $statusColor
    
    if ($Details) {
        Write-Host ("    └─ {0}" -f $Details) -ForegroundColor Gray
    }
    
    $script:ReportData += @{
        Check = $Name
        Status = $Status
        Details = $Details
        Severity = $Severity
    }
    
    if ($Severity -eq "ERROR") {
        $script:errors += $Name
    } elseif ($Severity -eq "WARNING") {
        $script:warnings += $Name
    }
}

function Test-AdminRights {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "ERROR: This script requires Administrator privileges." -ForegroundColor Red
        exit 1
    }
}

# ============================================================================
# DIAGNOSTIC FUNCTIONS
# ============================================================================

function Diagnose-Services {
    Write-Section "1. WINDOWS SERVICES DIAGNOSTIC"
    
    $criticalServices = @(
        @{Name = "Winmgmt"; Display = "Windows Management Instrumentation" },
        @{Name = "WinRM"; Display = "Windows Remote Management" },
        @{Name = "RemoteRegistry"; Display = "Remote Registry" },
        @{Name = "RpcSs"; Display = "Remote Procedure Call (RPC)" },
        @{Name = "LanmanServer"; Display = "Server (File/Print Sharing)" }
    )
    
    foreach ($service in $criticalServices) {
        try {
            $svc = Get-Service -Name $service.Name -ErrorAction Stop
            
            if ($svc.Status -eq "Running") {
                Write-Result "$($service.Display)" "Running" "Startup: $($svc.StartType)" "OK"
            } else {
                Write-Result "$($service.Display)" "STOPPED" "Startup: $($svc.StartType)" "ERROR"
            }
            
            if ($svc.StartType -notin @("Automatic", "AutomaticDelayedStart")) {
                Write-Result "$($service.Display) Startup" "Not Automatic" "Consider setting to Automatic" "WARNING"
            }
            
        } catch {
            Write-Result "$($service.Display)" "NOT FOUND" $_.Exception.Message "ERROR"
        }
    }
}

function Diagnose-RegistrySettings {
    Write-Section "2. REGISTRY SETTINGS DIAGNOSTIC"
    
    # UAC Policy
    try {
        $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $uacValue = Get-ItemProperty -Path $uacPath -Name LocalAccountTokenFilterPolicy -ErrorAction Stop
        
        Write-Result "LocalAccountTokenFilterPolicy" "Set to $($uacValue.LocalAccountTokenFilterPolicy)" "" `
            $(if ($uacValue.LocalAccountTokenFilterPolicy -eq 1) { "OK" } else { "WARNING" })
    } catch {
        Write-Result "LocalAccountTokenFilterPolicy" "NOT SET" "Should be 1 for remote admin operations" "WARNING"
    }
    
    # AutoShareServer
    try {
        $sharePath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $shareValue = Get-ItemProperty -Path $sharePath -Name AutoShareServer -ErrorAction Stop
        
        Write-Result "AutoShareServer" "Set to $($shareValue.AutoShareServer)" "" `
            $(if ($shareValue.AutoShareServer -eq 1) { "OK" } else { "WARNING" })
    } catch {
        Write-Result "AutoShareServer" "DEFAULT" "Should be explicitly set to 1" "INFO"
    }
    
    # Check for RPC configuration
    $rpcPath = "HKLM:\SOFTWARE\Microsoft\RPC"
    if (Test-Path $rpcPath) {
        Write-Result "RPC Configuration" "Registry Path Found" "" "OK"
    } else {
        Write-Result "RPC Configuration" "Default" "Using system defaults" "INFO"
    }
}

function Diagnose-FirewallRules {
    Write-Section "3. FIREWALL RULES DIAGNOSTIC"
    
    $criticalRules = @(
        "Windows Management Instrumentation (WMI-In)",
        "Windows Management Instrumentation (WINMGMT-In)",
        "File and Printer Sharing (SMB-In)",
        "Remote Event Log Management (RPC)",
        "Remote Service Management (RPC)"
    )
    
    # Check if firewall is enabled
    $fwProfiles = Get-NetFirewallProfile
    $fwEnabled = $fwProfiles | Where-Object Enabled -eq $true
    
    if ($fwEnabled) {
        Write-Result "Windows Firewall" "ENABLED" "Profiles: $(($fwEnabled.Name) -join ', ')" "INFO"
    } else {
        Write-Result "Windows Firewall" "DISABLED" "All rules allowed through" "WARNING"
        return
    }
    
    Write-Host ""
    Write-Host "Checking critical rules:" -ForegroundColor Yellow
    
    foreach ($ruleName in $criticalRules) {
        try {
            $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            
            if ($rule) {
                if ($rule.Enabled) {
                    Write-Result $ruleName "Enabled" "" "OK"
                } else {
                    Write-Result $ruleName "DISABLED" "Should be enabled" "ERROR"
                }
            } else {
                Write-Result $ruleName "NOT FOUND" "May not exist on this Windows version" "WARNING"
            }
        } catch {
            Write-Result $ruleName "ERROR" $_.Exception.Message "ERROR"
        }
    }
}

function Diagnose-AdminShares {
    Write-Section "4. ADMIN SHARES DIAGNOSTIC"
    
    try {
        $shares = Get-SmbShare -Special -ErrorAction Stop | Where-Object { $_.Name -match '^(C\$|ADMIN\$|IPC\$|D\$|E\$)$' }
        
        if ($shares) {
            foreach ($share in $shares) {
                Write-Result "Share: $($share.Name)" "Present" "Path: $($share.Path)" "OK"
            }
        } else {
            Write-Result "Admin Shares" "NOT VISIBLE" "May need to set AutoShareServer = 1" "ERROR"
        }
    } catch {
        Write-Result "Admin Shares Enumeration" "ERROR" $_.Exception.Message "ERROR"
    }
}

function Diagnose-WMIState {
    Write-Section "5. WMI STATE DIAGNOSTIC"
    
    Write-Host "Testing basic WMI queries..." -ForegroundColor Yellow
    
    # Test Win32_ComputerSystem
    try {
        $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
        Write-Result "Win32_ComputerSystem" "Queryable" "Name: $($cs.Name), Domain: $($cs.Domain)" "OK"
    } catch {
        Write-Result "Win32_ComputerSystem" "FAILED" $_.Exception.Message "ERROR"
    }
    
    # Test Win32_OperatingSystem
    try {
        $os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
        Write-Result "Win32_OperatingSystem" "Queryable" "Caption: $($os.Caption)" "OK"
    } catch {
        Write-Result "Win32_OperatingSystem" "FAILED" $_.Exception.Message "ERROR"
    }
    
    # Test Win32_Processor
    try {
        $proc = Get-WmiObject Win32_Processor -ErrorAction Stop | Select-Object -First 1
        Write-Result "Win32_Processor" "Queryable" "Name: $($proc.Name)" "OK"
    } catch {
        Write-Result "Win32_Processor" "FAILED" $_.Exception.Message "ERROR"
    }
    
    # Test Win32_Product (This can be slow!)
    Write-Host "  (Testing Win32_Product - this may take a minute...)" -ForegroundColor Gray
    try {
        $products = Get-WmiObject Win32_Product -ErrorAction Stop | Measure-Object
        Write-Result "Win32_Product" "Queryable" "Count: $($products.Count). This query can be slow on some systems" "OK"
    } catch {
        Write-Result "Win32_Product" "FAILED" $_.Exception.Message "ERROR"
    }
    
    # Test Win32_QuickFixEngineering (patches)
    try {
        $patches = Get-WmiObject Win32_QuickFixEngineering -ErrorAction Stop | Measure-Object
        Write-Result "Win32_QuickFixEngineering (Patches)" "Queryable" "Count: $($patches.Count)" "OK"
    } catch {
        Write-Result "Win32_QuickFixEngineering" "FAILED" $_.Exception.Message "ERROR"
    }
}

function Diagnose-WMIRepository {
    Write-Section "6. WMI REPOSITORY DIAGNOSTIC"
    
    $wmiRepPath = "C:\ProgramData\Microsoft\Windows\WMI\Repository"
    
    if (Test-Path $wmiRepPath) {
        Write-Result "WMI Repository Path" "EXISTS" $wmiRepPath "OK"
        
        try {
            $repSize = (Get-Item $wmiRepPath | Measure-Object -Sum -Property Length).Sum / 1MB
            Write-Result "WMI Repository Size" "$([math]::Round($repSize, 2)) MB" "" "OK"
            
            if ($repSize -gt 500) {
                Write-Result "WMI Repository Size" "LARGE" "Consider cleanup if experiencing issues" "WARNING"
            }
        } catch {
            Write-Result "WMI Repository Size" "CANNOT DETERMINE" $_.Exception.Message "WARNING"
        }
    } else {
        Write-Result "WMI Repository Path" "NOT FOUND" "May indicate WMI installation issue" "ERROR"
    }
    
    # Try to verify repository health (advanced check)
    Write-Host ""
    Write-Host "Testing WMI security permissions..." -ForegroundColor Yellow
    try {
        $secDesc = Get-WmiObject -Class __SystemSecurity -Namespace root\cimv2 -ErrorAction Stop
        if ($secDesc) {
            Write-Result "WMI Namespace Permissions" "Accessible" "Can read security descriptor" "OK"
        }
    } catch {
        Write-Result "WMI Namespace Permissions" "WARNING" $_.Exception.Message "WARNING"
    }
}

function Diagnose-NetworkServices {
    Write-Section "7. NETWORK SERVICES DIAGNOSTIC"
    
    # Check port availability
    $ports = @(
        @{Port = 135; Service = "RPC Endpoint Mapper"; Protocol = "TCP" },
        @{Port = 445; Service = "SMB/CIFS"; Protocol = "TCP" },
        @{Port = 139; Service = "NetBIOS Session"; Protocol = "TCP" },
        @{Port = 5985; Service = "WinRM HTTP"; Protocol = "TCP" },
        @{Port = 5986; Service = "WinRM HTTPS"; Protocol = "TCP" }
    )
    
    Write-Host "Checking network port listeners..." -ForegroundColor Yellow
    
    foreach ($portInfo in $ports) {
        try {
            $netstat = Get-NetTCPConnection -LocalPort $portInfo.Port -State Listen -ErrorAction SilentlyContinue
            
            if ($netstat) {
                Write-Result "Port $($portInfo.Port) ($($portInfo.Service))" "LISTENING" "State: $($netstat.State)" "OK"
            } else {
                Write-Result "Port $($portInfo.Port) ($($portInfo.Service))" "NOT LISTENING" "May need service restart" "WARNING"
            }
        } catch {
            Write-Result "Port $($portInfo.Port) ($($portInfo.Service))" "ERROR" $_.Exception.Message "ERROR"
        }
    }
}

function Diagnose-NetworkConfiguration {
    Write-Section "8. NETWORK CONFIGURATION DIAGNOSTIC"
    
    # Get system hostname
    $hostname = $env:COMPUTERNAME
    Write-Result "Computer Name" $hostname "" "OK"
    
    # Get networks
    Write-Host ""
    Write-Host "Network adapters:" -ForegroundColor Yellow
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object Status -eq "Up"
        
        foreach ($adapter in $adapters) {
            Write-Result $adapter.Name "$($adapter.LinkSpeed)" "Status: $($adapter.InterfaceDescription)" "OK"
            
            # Get IP addresses
            $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
            foreach ($ipAddr in $ipConfig) {
                Write-Host "    ├─ $($ipAddr.IPAddress) ($($ipAddr.AddressFamily))" -ForegroundColor Gray
            }
        }
    } catch {
        Write-Result "Network Adapters" "ERROR" $_.Exception.Message "ERROR"
    }
    
    # Check DNS resolution
    Write-Host ""
    Write-Host "DNS Configuration:" -ForegroundColor Yellow
    try {
        $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object ServerAddresses
        foreach ($dns in $dnsServers) {
            Write-Host "  Interface: $($dns.InterfaceAlias)" -ForegroundColor Gray
            foreach ($server in $dns.ServerAddresses) {
                Write-Host "    ├─ $server" -ForegroundColor Gray
            }
        }
    } catch {
        Write-Result "DNS Configuration" "ERROR" $_.Exception.Message "ERROR"
    }
}

function Diagnose-Credentials {
    Write-Section "9. CURRENT USER & CREDENTIALS DIAGNOSTIC"
    
    # Current user
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Result "Current User" $currentUser "" "OK"
    
    # Check if admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Result "Administrator Privileges" $(if ($isAdmin) { "YES" } else { "NO" }) "" $(if ($isAdmin) { "OK" } else { "ERROR" })
    
    # Get user groups
    Write-Host ""
    Write-Host "User Group Memberships:" -ForegroundColor Yellow
    try {
        $groups = [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object {
            try {
                $_.Translate([System.Security.Principal.NTAccount]).Value
            } catch {
                $_.Value
            }
        }
        
        foreach ($group in $groups) {
            Write-Host "  ├─ $group" -ForegroundColor Gray
        }
    } catch {
        Write-Result "Group Enumeration" "ERROR" $_.Exception.Message "ERROR"
    }
}

function Diagnose-SystemInfo {
    Write-Section "10. SYSTEM INFORMATION SUMMARY"
    
    try {
        $cs = Get-WmiObject Win32_ComputerSystem
        $os = Get-WmiObject Win32_OperatingSystem
        
        Write-Result "OS Name" $os.Caption "" "OK"
        Write-Result "OS Version" "$($os.Version) Build $($os.BuildNumber)" "" "OK"
        Write-Result "Install Date" $os.InstallDate "" "OK"
        Write-Result "System Manufacturer" $cs.Manufacturer "" "OK"
        Write-Result "System Model" $cs.Model "" "OK"
        Write-Result "Domain" $cs.Domain "" "OK"
        Write-Result "Owner" $cs.OwnerName "" "OK"
        Write-Result "Last Boot" $os.LastBootUpTime "" "OK"
        
    } catch {
        Write-Result "System Information" "FAILED" $_.Exception.Message "ERROR"
    }
}

# ============================================================================
# REPORT GENERATION
# ============================================================================

function Generate-Report {
    Clear-Host
    
    Write-Host "Windows Credentialed Scan Diagnostic Report" -ForegroundColor Cyan
    Write-Host "Generated: $(Get-Date)" -ForegroundColor Gray
    Write-Host ""
    
    if ($Interactive) {
        foreach ($section in 1..10) {
            $response = Read-Host "Run diagnostic section $section ? (Y/N/Q)"
            if ($response -eq "Q") { break }
            if ($response -ne "Y") { continue }
        }
    }
    
    # Run all diagnostic functions
    Diagnose-Services
    Diagnose-RegistrySettings
    Diagnose-FirewallRules
    Diagnose-AdminShares
    Diagnose-WMIState
    
    if ($Detailed) {
        Diagnose-WMIRepository
    }
    
    Diagnose-NetworkServices
    Diagnose-NetworkConfiguration
    Diagnose-Credentials
    Diagnose-SystemInfo
    
    # Summary
    Write-Section "SUMMARY"
    
    Write-Host "Total Checks Performed: $($script:ReportData.Count)" -ForegroundColor Cyan
    Write-Host "  ✓ Passed: $(($script:ReportData | Where-Object Severity -eq "OK").Count)" -ForegroundColor Green
    Write-Host "  ! Warnings: $(($script:ReportData | Where-Object Severity -eq "WARNING").Count)" -ForegroundColor Yellow
    Write-Host "  ✗ Errors: $(($script:ReportData | Where-Object Severity -eq "ERROR").Count)" -ForegroundColor Red
    Write-Host ""
    
    if ($script:errors.Count -gt 0) {
        Write-Host "CRITICAL ISSUES:" -ForegroundColor Red
        foreach ($error in $script:errors) {
            Write-Host "  ✗ $error" -ForegroundColor Red
        }
        Write-Host ""
    }
    
    if ($script:warnings.Count -gt 0) {
        Write-Host "WARNINGS:" -ForegroundColor Yellow
        foreach ($warning in $script:warnings) {
            Write-Host "  ! $warning" -ForegroundColor Yellow
        }
        Write-Host ""
    }
    
    Write-Host "RECOMMENDATIONS:" -ForegroundColor Cyan
    Write-Host ""
    
    if ($script:errors.Count -gt 0) {
        Write-Host "1. Address critical errors first - these prevent scanning" -ForegroundColor White
    }
    
    if ($script:warnings.Count -gt 0) {
        Write-Host "2. Review warnings - may cause partial failures or slow scans" -ForegroundColor White
    }
    
    Write-Host ""
    Write-Host "3. Run 'Prepare-WindowsForVulnScan.ps1' to auto-fix issues" -ForegroundColor White
    Write-Host "4. Run 'Verify-WindowsScanReadiness.ps1' from scanner machine to test end-to-end" -ForegroundColor White
    
    if ($ExportReport) {
        Export-HtmlReport
    }
}

function Export-HtmlReport {
    Write-Host ""
    Write-Host "Exporting HTML report to: $ExportReport" -ForegroundColor Yellow
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Windows Scan Diagnostic Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #333; border-bottom: 3px solid #0078d4; }
        table { border-collapse: collapse; width: 100%; background: white; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background: #0078d4; color: white; }
        tr:nth-child(even) { background: #f9f9f9; }
        .ok { color: green; font-weight: bold; }
        .warning { color: orange; font-weight: bold; }
        .error { color: red; font-weight: bold; }
        .summary { background: #f0f0f0; padding: 15px; border-left: 4px solid #0078d4; margin-bottom: 20px; }
        .timestamp { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <h1>Windows Credentialed Scan Diagnostic Report</h1>
    <p class="timestamp">Generated: $(Get-Date)</p>
    <p class="timestamp">Computer: $env:COMPUTERNAME</p>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Checks:</strong> $($script:ReportData.Count)</p>
        <p><strong>Passed:</strong> <span class="ok">$(($script:ReportData | Where-Object Severity -eq "OK").Count)</span></p>
        <p><strong>Warnings:</strong> <span class="warning">$(($script:ReportData | Where-Object Severity -eq "WARNING").Count)</span></p>
        <p><strong>Errors:</strong> <span class="error">$(($script:ReportData | Where-Object Severity -eq "ERROR").Count)</span></p>
    </div>
    
    <h2>Diagnostic Results</h2>
    <table>
        <tr>
            <th>Check</th>
            <th>Status</th>
            <th>Details</th>
            <th>Severity</th>
        </tr>
"@
    
    foreach ($item in $script:ReportData) {
        $severityClass = $item.Severity.ToLower()
        $html += @"
        <tr>
            <td>$($item.Check)</td>
            <td class="$severityClass">$($item.Status)</td>
            <td>$($item.Details)</td>
            <td class="$severityClass">$($item.Severity)</td>
        </tr>
"@
    }
    
    $html += @"
    </table>
</body>
</html>
"@
    
    $html | Out-File -FilePath $ExportReport -Encoding UTF8
    Write-Host "Report saved successfully!" -ForegroundColor Green
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Test-AdminRights
Generate-Report
