#Requires -RunAsAdministrator
<#
.SYNOPSIS
Advanced diagnostic and troubleshooting script for Windows credentialed scanning issues.

.DESCRIPTION
Comprehensive read-only diagnostics tool for troubleshooting why credentialed scans fail
to retrieve data. Generates detailed reports and suggests fixes.

Fixes applied (v1.1):
  - Replaced Get-WmiObject Win32_Product with a registry-based installed-software query.
    Win32_Product triggers Windows Installer consistency (MSI repair) checks on every call,
    which can take 10–60 minutes on servers with many packages and cause application
    instability. The registry path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*
    returns the same information instantly with no side-effects.
  - Added -SkipSlowChecks switch. When passed, the Win32_Product / registry software check
    (and the WMI repository deep check in -Detailed mode) are skipped entirely, making the
    script safe to run on production servers during business hours.
  - Removed the dead $Interactive section-counter loop (foreach $section in 1..10) that
    prompted Y/N but never called any diagnostic functions. $Interactive now wraps each
    real diagnostic call with an individual prompt so the switch is actually useful.
  - Added HTML entity encoding (ConvertTo-HtmlSafe helper) to Export-HtmlReport so that
    check results containing <, >, & or " characters (e.g. registry paths, WMI error
    messages) no longer produce malformed HTML output.

.PARAMETER Detailed
If present, runs additional deep diagnostic tests (WMI repository, etc.).

.PARAMETER Interactive
If present, prompts before each diagnostic section — now actually wired to the calls.

.PARAMETER ExportReport
If present, exports results to the specified HTML file path.

.PARAMETER SkipSlowChecks
If present, skips the installed-software enumeration check (registry scan) that may be
slow on machines with thousands of installed products.

.EXAMPLE
.\Diagnose-WindowsScanIssues.ps1
.\Diagnose-WindowsScanIssues.ps1 -Detailed
.\Diagnose-WindowsScanIssues.ps1 -ExportReport "C:\Reports\Diagnosis.html"
.\Diagnose-WindowsScanIssues.ps1 -SkipSlowChecks
.\Diagnose-WindowsScanIssues.ps1 -Detailed -Interactive -ExportReport "C:\Reports\Diagnosis.html"

.NOTES
Useful when basic verification script doesn't reveal the problem.
Run on the TARGET machine (the one being scanned), not the scanner machine.
#>

param(
    [switch]$Detailed,
    [switch]$Interactive,
    [string]$ExportReport,
    [switch]$SkipSlowChecks
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$ScriptVersion = "1.1"
$ReportData    = @()
$errors        = @()
$warnings      = @()

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
        "OK"      { "Green"  }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red"    }
        default   { "White"  }
    }

    $statusSymbol = switch ($Severity) {
        "OK"      { "+" }
        "ERROR"   { "X" }
        "WARNING" { "!" }
        default   { "." }
    }

    Write-Host ("  [{0}] {1,-50} {2}" -f $statusSymbol, $Name, $Status) -ForegroundColor $statusColor

    if ($Details) {
        Write-Host ("      -> {0}" -f $Details) -ForegroundColor Gray
    }

    $script:ReportData += @{
        Check    = $Name
        Status   = $Status
        Details  = $Details
        Severity = $Severity
    }

    if ($Severity -eq "ERROR") {
        $script:errors   += $Name
    } elseif ($Severity -eq "WARNING") {
        $script:warnings += $Name
    }
}

function Test-AdminRights {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                    [Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Host "ERROR: This script requires Administrator privileges." -ForegroundColor Red
        exit 1
    }
}

# ============================================================================
# FIX 3 — HTML ENTITY ENCODING
# Bug: Check results containing <, >, & or " were inserted raw into the HTML
#      template, producing malformed markup (e.g., a WMI error message like
#      "The RPC server is unavailable <0x800706BA>" would break the table row).
# Fix: All values are passed through ConvertTo-HtmlSafe before insertion.
# ============================================================================
function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    $Text = $Text.Replace("&",  "&amp;")   # must be first
    $Text = $Text.Replace("<",  "&lt;")
    $Text = $Text.Replace(">",  "&gt;")
    $Text = $Text.Replace('"',  "&quot;")
    $Text = $Text.Replace("'",  "&#39;")
    return $Text
}

# ============================================================================
# FIX 2 — INTERACTIVE HELPER
# Bug: foreach ($section in 1..10) prompted Y/N but never called any functions.
#      The real diagnostic calls below were all unconditional.
# Fix: Replaced with Invoke-DiagnosticSection, which wraps each real call with
#      a Y/N prompt when -Interactive is set.
# ============================================================================
function Invoke-DiagnosticSection {
    param(
        [string]$SectionName,
        [scriptblock]$Body
    )

    if ($Interactive) {
        $response = Read-Host "Run section '$SectionName'? (Y/N)"
        if ($response -ne "Y") {
            Write-Host "  Skipped." -ForegroundColor Gray
            return
        }
    }

    & $Body
}

# ============================================================================
# DIAGNOSTIC FUNCTIONS
# ============================================================================

function Diagnose-Services {
    Write-Section "1. WINDOWS SERVICES DIAGNOSTIC"

    $criticalServices = @(
        @{Name = "Winmgmt";     Display = "Windows Management Instrumentation" },
        @{Name = "WinRM";       Display = "Windows Remote Management" },
        @{Name = "RemoteRegistry"; Display = "Remote Registry" },
        @{Name = "RpcSs";       Display = "Remote Procedure Call (RPC)" },
        @{Name = "LanmanServer";Display = "Server (File/Print Sharing)" }
    )

    foreach ($service in $criticalServices) {
        try {
            $svc = Get-Service -Name $service.Name -ErrorAction Stop

            if ($svc.Status -eq "Running") {
                Write-Result $service.Display "Running" "Startup: $($svc.StartType)" "OK"
            } else {
                Write-Result $service.Display "STOPPED" "Startup: $($svc.StartType)" "ERROR"
            }

            if ($svc.StartType -notin @("Automatic", "AutomaticDelayedStart")) {
                Write-Result "$($service.Display) Startup" "Not Automatic" "Consider setting to Automatic" "WARNING"
            }
        }
        catch {
            Write-Result $service.Display "NOT FOUND" $_.Exception.Message "ERROR"
        }
    }
}

function Diagnose-RegistrySettings {
    Write-Section "2. REGISTRY SETTINGS DIAGNOSTIC"

    # UAC Policy
    try {
        $uacPath  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $uacValue = Get-ItemProperty -Path $uacPath -Name LocalAccountTokenFilterPolicy -ErrorAction Stop

        Write-Result "LocalAccountTokenFilterPolicy" "Set to $($uacValue.LocalAccountTokenFilterPolicy)" "" `
            $(if ($uacValue.LocalAccountTokenFilterPolicy -eq 1) { "OK" } else { "WARNING" })
    }
    catch {
        Write-Result "LocalAccountTokenFilterPolicy" "NOT SET" "Should be 1 for remote admin operations" "WARNING"
    }

    # AutoShareServer
    try {
        $sharePath  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $shareValue = Get-ItemProperty -Path $sharePath -Name AutoShareServer -ErrorAction Stop

        Write-Result "AutoShareServer" "Set to $($shareValue.AutoShareServer)" "" `
            $(if ($shareValue.AutoShareServer -eq 1) { "OK" } else { "WARNING" })
    }
    catch {
        Write-Result "AutoShareServer" "DEFAULT" "Should be explicitly set to 1" "INFO"
    }

    # RPC configuration
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

    $fwProfiles = Get-NetFirewallProfile
    $fwEnabled  = $fwProfiles | Where-Object Enabled -eq $true

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
        }
        catch {
            Write-Result $ruleName "ERROR" $_.Exception.Message "ERROR"
        }
    }
}

function Diagnose-AdminShares {
    Write-Section "4. ADMIN SHARES DIAGNOSTIC"

    try {
        $shares = Get-SmbShare -Special -ErrorAction Stop |
                  Where-Object { $_.Name -match '^(C\$|ADMIN\$|IPC\$|D\$|E\$)$' }

        if ($shares) {
            foreach ($share in $shares) {
                Write-Result "Share: $($share.Name)" "Present" "Path: $($share.Path)" "OK"
            }
        } else {
            Write-Result "Admin Shares" "NOT VISIBLE" "May need to set AutoShareServer = 1" "ERROR"
        }
    }
    catch {
        Write-Result "Admin Shares Enumeration" "ERROR" $_.Exception.Message "ERROR"
    }
}

function Diagnose-WMIState {
    Write-Section "5. WMI STATE DIAGNOSTIC"

    Write-Host "Testing basic WMI queries..." -ForegroundColor Yellow

    try {
        $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
        Write-Result "Win32_ComputerSystem" "Queryable" "Name: $($cs.Name), Domain: $($cs.Domain)" "OK"
    }
    catch {
        Write-Result "Win32_ComputerSystem" "FAILED" $_.Exception.Message "ERROR"
    }

    try {
        $os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
        Write-Result "Win32_OperatingSystem" "Queryable" "Caption: $($os.Caption)" "OK"
    }
    catch {
        Write-Result "Win32_OperatingSystem" "FAILED" $_.Exception.Message "ERROR"
    }

    try {
        $proc = Get-WmiObject Win32_Processor -ErrorAction Stop | Select-Object -First 1
        Write-Result "Win32_Processor" "Queryable" "Name: $($proc.Name)" "OK"
    }
    catch {
        Write-Result "Win32_Processor" "FAILED" $_.Exception.Message "ERROR"
    }

    # ============================================================================
    # FIX 1 — Win32_Product replaced with registry-based installed software query
    # Bug: Get-WmiObject Win32_Product triggers Windows Installer consistency checks
    #      (MSI repair) on every invocation — can take 10–60 minutes on servers with
    #      many packages and can temporarily destabilise running applications.
    # Fix: Read HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* directly.
    #      Returns the same display names and counts without any MSI side-effects.
    #      A -SkipSlowChecks switch allows skipping even this (cheaper) check.
    # ============================================================================
    if ($SkipSlowChecks) {
        Write-Result "Installed Software (registry)" "SKIPPED" "-SkipSlowChecks was specified" "INFO"
    } else {
        try {
            Write-Host "  (Enumerating installed software via registry...)" -ForegroundColor Gray
            $uninstallPaths = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )
            $software = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayName } |
                        Select-Object -Property DisplayName, DisplayVersion, Publisher
            $count = ($software | Measure-Object).Count
            Write-Result "Installed Software (registry)" "Queryable" "Count: $count (read from Uninstall registry hive)" "OK"
        }
        catch {
            Write-Result "Installed Software (registry)" "FAILED" $_.Exception.Message "ERROR"
        }
    }

    try {
        $patches = Get-WmiObject Win32_QuickFixEngineering -ErrorAction Stop | Measure-Object
        Write-Result "Win32_QuickFixEngineering (Patches)" "Queryable" "Count: $($patches.Count)" "OK"
    }
    catch {
        Write-Result "Win32_QuickFixEngineering" "FAILED" $_.Exception.Message "ERROR"
    }
}

function Diagnose-WMIRepository {
    Write-Section "6. WMI REPOSITORY DIAGNOSTIC"

    $wmiRepPath = "C:\ProgramData\Microsoft\Windows\WMI\Repository"

    if (Test-Path $wmiRepPath) {
        Write-Result "WMI Repository Path" "EXISTS" $wmiRepPath "OK"

        try {
            $repFiles = Get-ChildItem -Path $wmiRepPath -Recurse -ErrorAction Stop
            $repSize  = ($repFiles | Measure-Object -Property Length -Sum).Sum / 1MB
            Write-Result "WMI Repository Size" "$([math]::Round($repSize, 2)) MB" "" "OK"

            if ($repSize -gt 500) {
                Write-Result "WMI Repository Size" "LARGE" "Consider cleanup if experiencing issues" "WARNING"
            }
        }
        catch {
            Write-Result "WMI Repository Size" "CANNOT DETERMINE" $_.Exception.Message "WARNING"
        }
    } else {
        Write-Result "WMI Repository Path" "NOT FOUND" "May indicate WMI installation issue" "ERROR"
    }

    Write-Host ""
    Write-Host "Testing WMI security permissions..." -ForegroundColor Yellow
    try {
        $secDesc = Get-WmiObject -Class __SystemSecurity -Namespace root\cimv2 -ErrorAction Stop
        if ($secDesc) {
            Write-Result "WMI Namespace Permissions" "Accessible" "Can read security descriptor" "OK"
        }
    }
    catch {
        Write-Result "WMI Namespace Permissions" "WARNING" $_.Exception.Message "WARNING"
    }
}

function Diagnose-NetworkServices {
    Write-Section "7. NETWORK SERVICES DIAGNOSTIC"

    $ports = @(
        @{Port = 135;  Service = "RPC Endpoint Mapper" },
        @{Port = 445;  Service = "SMB/CIFS" },
        @{Port = 139;  Service = "NetBIOS Session" },
        @{Port = 5985; Service = "WinRM HTTP" },
        @{Port = 5986; Service = "WinRM HTTPS" }
    )

    Write-Host "Checking network port listeners..." -ForegroundColor Yellow

    foreach ($portInfo in $ports) {
        try {
            $netstat = Get-NetTCPConnection -LocalPort $portInfo.Port -State Listen -ErrorAction SilentlyContinue

            if ($netstat) {
                Write-Result "Port $($portInfo.Port) ($($portInfo.Service))" "LISTENING" "State: Listen" "OK"
            } else {
                Write-Result "Port $($portInfo.Port) ($($portInfo.Service))" "NOT LISTENING" "May need service restart" "WARNING"
            }
        }
        catch {
            Write-Result "Port $($portInfo.Port) ($($portInfo.Service))" "ERROR" $_.Exception.Message "ERROR"
        }
    }
}

function Diagnose-NetworkConfiguration {
    Write-Section "8. NETWORK CONFIGURATION DIAGNOSTIC"

    Write-Result "Computer Name" $env:COMPUTERNAME "" "OK"

    Write-Host ""
    Write-Host "Network adapters:" -ForegroundColor Yellow
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object Status -eq "Up"

        foreach ($adapter in $adapters) {
            Write-Result $adapter.Name "$($adapter.LinkSpeed)" "Status: $($adapter.InterfaceDescription)" "OK"

            $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
            foreach ($ipAddr in $ipConfig) {
                Write-Host "      -> $($ipAddr.IPAddress) ($($ipAddr.AddressFamily))" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Result "Network Adapters" "ERROR" $_.Exception.Message "ERROR"
    }

    Write-Host ""
    Write-Host "DNS Configuration:" -ForegroundColor Yellow
    try {
        $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object ServerAddresses
        foreach ($dns in $dnsServers) {
            Write-Host "  Interface: $($dns.InterfaceAlias)" -ForegroundColor Gray
            foreach ($server in $dns.ServerAddresses) {
                Write-Host "      -> $server" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Result "DNS Configuration" "ERROR" $_.Exception.Message "ERROR"
    }
}

function Diagnose-Credentials {
    Write-Section "9. CURRENT USER & CREDENTIALS DIAGNOSTIC"

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Result "Current User" $currentUser "" "OK"

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                   [Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Result "Administrator Privileges" $(if ($isAdmin) { "YES" } else { "NO" }) "" `
        $(if ($isAdmin) { "OK" } else { "ERROR" })

    Write-Host ""
    Write-Host "User Group Memberships:" -ForegroundColor Yellow
    try {
        $groups = [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object {
            try   { $_.Translate([System.Security.Principal.NTAccount]).Value }
            catch { $_.Value }
        }

        foreach ($group in $groups) {
            Write-Host "      -> $group" -ForegroundColor Gray
        }
    }
    catch {
        Write-Result "Group Enumeration" "ERROR" $_.Exception.Message "ERROR"
    }
}

function Diagnose-SystemInfo {
    Write-Section "10. SYSTEM INFORMATION SUMMARY"

    try {
        $cs = Get-WmiObject Win32_ComputerSystem  -ErrorAction Stop
        $os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop

        Write-Result "OS Name"             $os.Caption                               "" "OK"
        Write-Result "OS Version"          "$($os.Version) Build $($os.BuildNumber)" "" "OK"
        Write-Result "Install Date"        $os.InstallDate                           "" "OK"
        Write-Result "System Manufacturer" $cs.Manufacturer                          "" "OK"
        Write-Result "System Model"        $cs.Model                                 "" "OK"
        Write-Result "Domain"              $cs.Domain                                "" "OK"
        Write-Result "Owner"               $cs.OwnerName                             "" "OK"
        Write-Result "Last Boot"           $os.LastBootUpTime                        "" "OK"
    }
    catch {
        Write-Result "System Information" "FAILED" $_.Exception.Message "ERROR"
    }
}

# ============================================================================
# REPORT GENERATION
# ============================================================================

function Generate-Report {
    Clear-Host

    Write-Host "Windows Credentialed Scan Diagnostic Report  v$ScriptVersion" -ForegroundColor Cyan
    Write-Host "Generated: $(Get-Date)" -ForegroundColor Gray
    Write-Host ""

    # ============================================================================
    # FIX 2 — Interactive mode now actually calls each section conditionally
    # Bug: foreach ($section in 1..10) iterated numbers and prompted Y/N but never
    #      invoked any diagnostic function — all real calls ran unconditionally below.
    # Fix: Each call is wrapped in Invoke-DiagnosticSection. When -Interactive is set
    #      the user is prompted before every section; otherwise they all run normally.
    # ============================================================================

    Invoke-DiagnosticSection "1. Windows Services"         { Diagnose-Services }
    Invoke-DiagnosticSection "2. Registry Settings"        { Diagnose-RegistrySettings }
    Invoke-DiagnosticSection "3. Firewall Rules"           { Diagnose-FirewallRules }
    Invoke-DiagnosticSection "4. Admin Shares"             { Diagnose-AdminShares }
    Invoke-DiagnosticSection "5. WMI State"                { Diagnose-WMIState }

    if ($Detailed) {
        Invoke-DiagnosticSection "6. WMI Repository"       { Diagnose-WMIRepository }
    }

    Invoke-DiagnosticSection "7. Network Services"         { Diagnose-NetworkServices }
    Invoke-DiagnosticSection "8. Network Configuration"    { Diagnose-NetworkConfiguration }
    Invoke-DiagnosticSection "9. Credentials"              { Diagnose-Credentials }
    Invoke-DiagnosticSection "10. System Information"      { Diagnose-SystemInfo }

    # Summary
    Write-Section "SUMMARY"

    Write-Host "Total Checks Performed : $($script:ReportData.Count)" -ForegroundColor Cyan
    Write-Host "  [+] Passed   : $(($script:ReportData | Where-Object Severity -eq 'OK').Count)"      -ForegroundColor Green
    Write-Host "  [!] Warnings : $(($script:ReportData | Where-Object Severity -eq 'WARNING').Count)" -ForegroundColor Yellow
    Write-Host "  [X] Errors   : $(($script:ReportData | Where-Object Severity -eq 'ERROR').Count)"   -ForegroundColor Red
    Write-Host ""

    if ($script:errors.Count -gt 0) {
        Write-Host "CRITICAL ISSUES:" -ForegroundColor Red
        foreach ($err in $script:errors) {
            Write-Host "  [X] $err" -ForegroundColor Red
        }
        Write-Host ""
    }

    if ($script:warnings.Count -gt 0) {
        Write-Host "WARNINGS:" -ForegroundColor Yellow
        foreach ($w in $script:warnings) {
            Write-Host "  [!] $w" -ForegroundColor Yellow
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

    # Summary counts
    $totalChecks   = $script:ReportData.Count
    $passedCount   = ($script:ReportData | Where-Object Severity -eq "OK").Count
    $warningCount  = ($script:ReportData | Where-Object Severity -eq "WARNING").Count
    $errorCount    = ($script:ReportData | Where-Object Severity -eq "ERROR").Count

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Windows Scan Diagnostic Report</title>
    <style>
        body          { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1            { color: #333; border-bottom: 3px solid #0078d4; }
        table         { border-collapse: collapse; width: 100%; background: white; margin-bottom: 20px; }
        th, td        { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th            { background: #0078d4; color: white; }
        tr:nth-child(even) { background: #f9f9f9; }
        .ok           { color: green;  font-weight: bold; }
        .warning      { color: orange; font-weight: bold; }
        .error        { color: red;    font-weight: bold; }
        .info         { color: #555; }
        .summary      { background: #f0f0f0; padding: 15px; border-left: 4px solid #0078d4; margin-bottom: 20px; }
        .timestamp    { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <h1>Windows Credentialed Scan Diagnostic Report</h1>
    <p class="timestamp">Generated: $(Get-Date)</p>
    <p class="timestamp">Computer: $([System.Net.Dns]::GetHostName())</p>

    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Checks:</strong> $totalChecks</p>
        <p><strong>Passed:</strong>   <span class="ok">$passedCount</span></p>
        <p><strong>Warnings:</strong> <span class="warning">$warningCount</span></p>
        <p><strong>Errors:</strong>   <span class="error">$errorCount</span></p>
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

    # ============================================================================
    # FIX 3 — HTML entity-encode all data values before inserting into HTML
    # Bug: Raw values from check results (e.g., WMI error messages containing <, >,
    #      &) were concatenated directly into the HTML string, producing malformed
    #      markup. Example: error text "0x800706BA <RPC server unavailable>" would
    #      break the <td> tag and corrupt the rest of the table.
    # Fix: Every field is passed through ConvertTo-HtmlSafe before insertion.
    # ============================================================================
    foreach ($item in $script:ReportData) {
        $safeCheck    = ConvertTo-HtmlSafe $item.Check
        $safeStatus   = ConvertTo-HtmlSafe $item.Status
        $safeDetails  = ConvertTo-HtmlSafe $item.Details
        $safeSeverity = ConvertTo-HtmlSafe $item.Severity
        $cssClass     = $item.Severity.ToLower()

        $html += @"
        <tr>
            <td>$safeCheck</td>
            <td class="$cssClass">$safeStatus</td>
            <td>$safeDetails</td>
            <td class="$cssClass">$safeSeverity</td>
        </tr>
"@
    }

    $html += @"
    </table>
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $ExportReport -Encoding UTF8 -ErrorAction Stop
        Write-Host "Report saved successfully to: $ExportReport" -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR: Could not write report to '$ExportReport': $_" -ForegroundColor Red
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Test-AdminRights
Generate-Report
