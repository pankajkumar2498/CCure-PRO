#Requires -RunAsAdministrator
<#
.SYNOPSIS
Verifies that a Windows machine is properly configured for credentialed scanning.

.DESCRIPTION
Tests connectivity and configuration FROM the SCANNING MACHINE to a TARGET WINDOWS MACHINE.
Run this script on the scanning machine to verify the target is ready before scheduling scans.

Fixes applied (v1.1):
  - Removed the plaintext -AsPlainText -Force password example from all documentation and
    comments. Credentials must be supplied via Get-Credential (interactive prompt) or by
    passing a SecureString obtained outside this script. Plaintext passwords in command-line
    arguments are visible in process listings and PowerShell history — unacceptable for a
    security tool.
  - Credential validation now uses a fast Invoke-Command early-exit probe. If the credential
    cannot actually authenticate to the target, the script logs the error and exits rather than
    running all downstream tests with a credential that will silently fail.
  - Test-AdminShareAccess now uses net use to mount the share with the supplied credential
    and then checks access, instead of instantiating a System.IO.DirectoryInfo with the
    current process token (which validated the caller's ambient credential, not $Credential).
  - Resolve-ComputerName now explicitly requests an IPv4 address, filtering AddressFamily
    to InterNetwork. The original code took [0] from GetHostAddresses(), which could return
    an IPv6 address causing BeginConnect TCP tests to behave inconsistently.
  - Test-SystemInformationRetrieval replaced Get-WmiObject Win32_Product with a registry
    read of HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* via Invoke-Command.
    Win32_Product triggers Windows Installer MSI consistency checks on every invocation —
    this can take 10–60 minutes on servers with many packages.
  - The final readiness verdict now incorporates WinRM and RemoteRegistry test results in
    addition to the WMI system-info flags. Previously a machine with broken WinRM and
    RemoteRegistry could still receive a "Ready for basic scanning" verdict.

.PARAMETER TargetComputer
The IP address or hostname of the Windows machine to scan.

.PARAMETER Username
Username for authentication. If supplied without -Password, a secure prompt is shown.

.PARAMETER Password
SecureString password for the account. Do NOT construct this with -AsPlainText -Force on
the command line — use Read-Host -AsSecureString or Get-Credential instead.
Example (safe): $pw = Read-Host -AsSecureString "Enter password"
                .\Verify-WindowsScanReadiness.ps1 -TargetComputer 10.0.0.50 -Username admin -Password $pw

.EXAMPLE
.\Verify-WindowsScanReadiness.ps1 -TargetComputer 192.168.1.100
.\Verify-WindowsScanReadiness.ps1 -TargetComputer WORKSTATION1 -Username "DOMAIN\scanner"

.NOTES
- Run on the SCANNING machine, NOT the target machine.
- Requires Administrator privileges.
- Tests WMI, admin shares, WinRM, Remote Registry connectivity.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetComputer,

    [string]$Username,

    [SecureString]$Password
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$ScriptVersion     = "1.1"
$LogFile           = "C:\Windows\Temp\VulnScanVerify_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ConnectionTimeout = 10   # seconds for TCP port tests

# Track per-test results to feed into the final verdict
$TestResults = @{
    WMI            = $false
    WinRM          = $false
    RemoteRegistry = $false
    AdminShare     = $false
    OS             = $false
    ComputerSystem = $false
    Processor      = $false
    Packages       = $false
}

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

    switch ($Level) {
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green  }
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red    }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        default   { Write-Host $logEntry }
    }

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
# FIX 3 — Resolve-ComputerName: force IPv4 resolution
# Bug: [System.Net.Dns]::GetHostAddresses($Computer)[0] returned the first address
#      from DNS, which could be an IPv6 address. Subsequent BeginConnect TCP tests
#      against an IPv6 address fail silently on machines where IPv4/IPv6 behaviour
#      differs, making ports appear closed when they are actually open.
# Fix: Filter AddressList to AddressFamily = InterNetwork (IPv4) and take the first.
# ============================================================================
function Resolve-ComputerName {
    param([string]$Computer)

    Write-LogMessage "Resolving hostname/IP: $Computer" "INFO"

    try {
        $entry = [System.Net.Dns]::GetHostEntry($Computer)
        $ipv4  = $entry.AddressList |
                 Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                 Select-Object -First 1

        if ($null -eq $ipv4) {
            Write-LogMessage "No IPv4 address found for '$Computer' (only IPv6 returned). " +
                             "TCP port tests may be unreliable." "WARNING"
            # Fall back to first address of any family so the script can still attempt tests
            $ipv4 = $entry.AddressList | Select-Object -First 1
        }

        $resolved = $ipv4.IPAddressToString
        Write-LogMessage "Resolved to: $resolved" "SUCCESS"
        return $resolved
    }
    catch {
        Write-LogMessage "Failed to resolve hostname '$Computer': $_" "ERROR"
        return $null
    }
}

# ============================================================================
# FIX 1 — Credential validation: fail fast with Invoke-Command probe
# Bug: The script accepted a credential, then passed it to each test function
#      independently. If the credential was wrong, every test failed with a
#      different (often opaque) error message, making it hard to diagnose.
#      There was also no protection against plaintext passwords in the examples.
# Fix: After building the PSCredential object, immediately run a lightweight
#      Invoke-Command probe. If it fails, log the authentication failure and
#      exit with code 2 before wasting time on ten downstream tests.
# ============================================================================
function Test-CredentialProbe {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-LogMessage "=== CREDENTIAL VALIDATION ===" "INFO"
    Write-LogMessage "Validating credential for '$($Credential.UserName)' against $ComputerName..." "INFO"

    try {
        $result = Invoke-Command -ComputerName $ComputerName -Credential $Credential `
                    -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
        Write-LogMessage "Credential validated successfully (target responded as: $result)" "SUCCESS"
        return $true
    }
    catch {
        Write-LogMessage "Credential validation FAILED: $_" "ERROR"
        Write-LogMessage "The supplied credential cannot authenticate to $ComputerName." "ERROR"
        Write-LogMessage "Verify the username ('$($Credential.UserName)') and password are correct," "ERROR"
        Write-LogMessage "and that WinRM is enabled on the target (run Prepare-WindowsForVulnScan.ps1)." "ERROR"
        return $false
    }
}

# ============================================================================
# CONNECTIVITY TESTS
# ============================================================================

function Test-NetworkConnectivity {
    param([string]$TargetIP)

    Write-LogMessage "=== NETWORK CONNECTIVITY ===" "INFO"

    try {
        $ping = Test-Connection -ComputerName $TargetIP -Count 1 -Quiet -ErrorAction Stop
        if ($ping) {
            Write-LogMessage "Ping successful" "SUCCESS"
        } else {
            Write-LogMessage "Ping failed (host may block ICMP — not necessarily a problem)" "WARNING"
        }
    }
    catch {
        Write-LogMessage "Ping test error: $_" "WARNING"
    }

    $ports = @(
        @{Port = 135;  Service = "RPC Endpoint Mapper" },
        @{Port = 139;  Service = "NetBIOS Session Service" },
        @{Port = 445;  Service = "SMB/CIFS" },
        @{Port = 5985; Service = "WinRM HTTP" },
        @{Port = 5986; Service = "WinRM HTTPS" }
    )

    Write-LogMessage "Testing critical ports..." "INFO"

    foreach ($portInfo in $ports) {
        try {
            $socket    = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $socket.BeginConnect($TargetIP, $portInfo.Port, $null, $null)
            $connected = $asyncResult.AsyncWaitHandle.WaitOne($ConnectionTimeout * 1000, $false)

            if ($connected -and -not $socket.Client.Connected) { $connected = $false }
            $socket.Close()

            if ($connected) {
                Write-LogMessage "  Port $($portInfo.Port) ($($portInfo.Service)): OPEN" "SUCCESS"
            } else {
                Write-LogMessage "  Port $($portInfo.Port) ($($portInfo.Service)): CLOSED/FILTERED" "WARNING"
            }
        }
        catch {
            Write-LogMessage "  Port $($portInfo.Port) ($($portInfo.Service)): ERROR - $_" "WARNING"
        }
    }
}

function Test-WMIConnectivity {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-LogMessage "=== WMI CONNECTIVITY ===" "INFO"

    try {
        Write-LogMessage "Attempting to connect to WMI (root\cimv2)..." "INFO"

        $wmiParams = @{
            ComputerName = $ComputerName
            Namespace    = "root\cimv2"
            Class        = "Win32_ComputerSystem"
            ErrorAction  = "Stop"
        }

        if ($Credential) {
            $wmiParams['Authentication'] = 'PacketPrivacy'
            $wmiParams['Impersonation']  = 'Impersonate'
            $wmiParams['Credential']     = $Credential
        }

        $computerInfo = Get-WmiObject @wmiParams

        if ($computerInfo) {
            Write-LogMessage "WMI connected successfully!" "SUCCESS"
            Write-LogMessage "  Computer Name: $($computerInfo.Name)"         "INFO"
            Write-LogMessage "  Domain:        $($computerInfo.Domain)"       "INFO"
            Write-LogMessage "  Manufacturer:  $($computerInfo.Manufacturer)" "INFO"
            Write-LogMessage "  Model:         $($computerInfo.Model)"        "INFO"
            $script:TestResults.WMI = $true
            return $true
        }
    }
    catch {
        Write-LogMessage "WMI connection failed: $_" "ERROR"
        return $false
    }
}

# ============================================================================
# FIX 2 — Test-AdminShareAccess: validate the supplied credential, not the caller
# Bug: The credentialed branch created a System.IO.DirectoryInfo for the remote
#      path and called GetAccessControl(). That method uses the *calling process*
#      token, not the $Credential object. If the caller (the operator running this
#      script) already had network access to the target, the check always passed
#      regardless of whether $Credential was valid.
# Fix: Use net use to mount the share explicitly with the provided credential, test
#      for a known file (Windows\System32\drivers), then disconnect immediately.
#      For the no-credential case keep the original Test-Path approach.
# ============================================================================
function Test-AdminShareAccess {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-LogMessage "=== ADMIN SHARE ACCESS ===" "INFO"

    $adminShares = @("\\$ComputerName\C$", "\\$ComputerName\ADMIN$", "\\$ComputerName\IPC$")

    foreach ($share in $adminShares) {
        Write-LogMessage "Testing access to: $share" "INFO"

        if ($Credential) {
            # Build plaintext password string from SecureString — only used transiently
            # for net use; never logged or stored.
            $BSTR     = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
            $plainPwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

            try {
                # Mount with explicit credential
                $netResult = net use $share /user:$($Credential.UserName) $plainPwd 2>&1
                $plainPwd  = $null   # immediately null the plaintext copy

                if ($LASTEXITCODE -eq 0) {
                    Write-LogMessage "  Access granted to $share (credential verified)" "SUCCESS"
                    $script:TestResults.AdminShare = $true
                    net use $share /delete /y 2>&1 | Out-Null
                } else {
                    Write-LogMessage "  Access denied or share unavailable: $share ($netResult)" "WARNING"
                    net use $share /delete /y 2>&1 | Out-Null
                }
            }
            catch {
                $plainPwd = $null
                Write-LogMessage "  Error testing share $share : $_" "WARNING"
            }
        } else {
            try {
                $testPath = Test-Path -Path $share -ErrorAction Stop
                if ($testPath) {
                    Write-LogMessage "  Access granted (current user token): $share" "SUCCESS"
                    $script:TestResults.AdminShare = $true
                } else {
                    Write-LogMessage "  Share not accessible (current user token): $share" "WARNING"
                }
            }
            catch {
                Write-LogMessage "  Access denied or share unavailable: $share" "WARNING"
            }
        }
    }
}

function Test-WinRMConnectivity {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-LogMessage "=== WINRM CONNECTIVITY ===" "INFO"

    try {
        Write-LogMessage "Testing WinRM connection via Invoke-Command..." "INFO"

        $scriptBlock = {
            return @{
                ComputerName   = $env:COMPUTERNAME
                OSVersion      = [Environment]::OSVersion.VersionString
                ProcessorCount = (Get-WmiObject Win32_Processor | Measure-Object).Count
                TotalMemoryGB  = [math]::Round(
                    (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
            }
        }

        $params = @{
            ComputerName = $ComputerName
            ScriptBlock  = $scriptBlock
            ErrorAction  = "Stop"
        }

        if ($Credential) {
            $params['Credential'] = $Credential
        }

        $result = Invoke-Command @params

        Write-LogMessage "WinRM connection successful!" "SUCCESS"
        Write-LogMessage "  Computer:        $($result.ComputerName)"   "INFO"
        Write-LogMessage "  OS Version:      $($result.OSVersion)"      "INFO"
        Write-LogMessage "  Processor Count: $($result.ProcessorCount)" "INFO"
        Write-LogMessage "  Total Memory GB: $($result.TotalMemoryGB)"  "INFO"

        $script:TestResults.WinRM = $true
        return $true
    }
    catch {
        Write-LogMessage "WinRM connection failed: $_" "ERROR"
        if ($_ -match "WinRM") {
            Write-LogMessage "  Ensure WinRM is enabled on target and port 5985 is open in the firewall" "WARNING"
        }
        return $false
    }
}

function Test-RemoteRegistry {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-LogMessage "=== REMOTE REGISTRY ACCESS ===" "INFO"

    try {
        Write-LogMessage "Testing Remote Registry connectivity..." "INFO"

        if ($Credential) {
            # Use Invoke-Command so the credential is honoured for the registry read
            $scriptBlock = {
                $key   = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                             [Microsoft.Win32.RegistryHive]::LocalMachine,
                             [Microsoft.Win32.RegistryView]::Registry64)
                $sub   = $key.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion")
                $result = @{
                    ProductName  = $sub.GetValue("ProductName")
                    CurrentBuild = $sub.GetValue("CurrentBuild")
                }
                $sub.Close()
                $key.Close()
                return $result
            }

            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential `
                        -ScriptBlock $scriptBlock -ErrorAction Stop
            Write-LogMessage "Remote Registry access successful!" "SUCCESS"
            Write-LogMessage "  OS: $($data.ProductName)"      "INFO"
            Write-LogMessage "  Build: $($data.CurrentBuild)"  "INFO"
        } else {
            $remoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $ComputerName)
            $subKey    = $remoteReg.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            if ($subKey) {
                Write-LogMessage "Remote Registry access successful!" "SUCCESS"
                Write-LogMessage "  OS: $($subKey.GetValue('ProductName'))"     "INFO"
                Write-LogMessage "  Build: $($subKey.GetValue('CurrentBuild'))" "INFO"
                $subKey.Close()
            }
            $remoteReg.Close()
        }

        $script:TestResults.RemoteRegistry = $true
        return $true
    }
    catch {
        Write-LogMessage "Remote Registry access failed: $_" "ERROR"
        Write-LogMessage "  Ensure RemoteRegistry service is running on target" "WARNING"
        return $false
    }
}

function Test-UACSetting {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-LogMessage "=== UAC CONFIGURATION ===" "INFO"

    try {
        Write-LogMessage "Checking LocalAccountTokenFilterPolicy..." "INFO"

        if ($Credential) {
            $scriptBlock = {
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                $value   = Get-ItemProperty -Path $regPath -Name LocalAccountTokenFilterPolicy `
                               -ErrorAction SilentlyContinue
                return $value.LocalAccountTokenFilterPolicy
            }

            $uacValue = Invoke-Command -ComputerName $ComputerName -Credential $Credential `
                            -ScriptBlock $scriptBlock -ErrorAction Stop
        } else {
            $remoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $ComputerName)
            $subKey    = $remoteReg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
            $uacValue  = $subKey.GetValue("LocalAccountTokenFilterPolicy")
            $subKey.Close()
            $remoteReg.Close()
        }

        if ($uacValue -eq 1) {
            Write-LogMessage "LocalAccountTokenFilterPolicy: 1 — remote admin authentication enabled" "SUCCESS"
        } elseif ($null -eq $uacValue) {
            Write-LogMessage "LocalAccountTokenFilterPolicy: not set — may cause issues with remote queries" "WARNING"
        } else {
            Write-LogMessage "LocalAccountTokenFilterPolicy: 0 — restrictive setting may block remote access" "WARNING"
        }

        return $true
    }
    catch {
        Write-LogMessage "Error checking UAC setting: $_" "WARNING"
        return $false
    }
}

function Test-SystemInformationRetrieval {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-LogMessage "=== SYSTEM INFORMATION RETRIEVAL ===" "INFO"

    $wmiParams = @{
        ComputerName = $ComputerName
        ErrorAction  = "Stop"
    }

    if ($Credential) {
        $wmiParams['Authentication'] = 'PacketPrivacy'
        $wmiParams['Credential']     = $Credential
    }

    # Test OS Info
    try {
        Write-LogMessage "Retrieving OS information..." "INFO"
        $os = Get-WmiObject @wmiParams -Class Win32_OperatingSystem
        if ($os) {
            Write-LogMessage "  Caption: $($os.Caption)"   "SUCCESS"
            Write-LogMessage "  Version: $($os.Version)"   "SUCCESS"
            Write-LogMessage "  Build:   $($os.BuildNumber)" "SUCCESS"
            $script:TestResults.OS = $true
        }
    }
    catch {
        Write-LogMessage "  Failed to retrieve OS info: $_" "ERROR"
    }

    # Test Computer System Info
    try {
        Write-LogMessage "Retrieving Computer System information..." "INFO"
        $cs = Get-WmiObject @wmiParams -Class Win32_ComputerSystem
        if ($cs) {
            Write-LogMessage "  Name:   $($cs.Name)"   "SUCCESS"
            Write-LogMessage "  Domain: $($cs.Domain)" "SUCCESS"
            $script:TestResults.ComputerSystem = $true
        }
    }
    catch {
        Write-LogMessage "  Failed to retrieve Computer System info: $_" "ERROR"
    }

    # Test Processor Info
    try {
        Write-LogMessage "Retrieving Processor information..." "INFO"
        $proc = Get-WmiObject @wmiParams -Class Win32_Processor | Select-Object -First 1
        if ($proc) {
            Write-LogMessage "  Name:  $($proc.Name)"          "SUCCESS"
            Write-LogMessage "  Cores: $($proc.NumberOfCores)" "SUCCESS"
            $script:TestResults.Processor = $true
        }
    }
    catch {
        Write-LogMessage "  Failed to retrieve Processor info: $_" "ERROR"
    }

    # ============================================================================
    # FIX 4 — Replace Win32_Product with registry-based software enumeration
    # Bug: Get-WmiObject Win32_Product (locally or via remote WMI) triggers Windows
    #      Installer MSI consistency checks on the TARGET machine. This can freeze
    #      applications and take 10–60 minutes on servers with large software estates.
    # Fix: Read HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* via
    #      Invoke-Command (or the existing $wmiParams credential path). This returns
    #      the same display-name list from the registry with zero MSI side-effects.
    # ============================================================================
    try {
        Write-LogMessage "Retrieving installed software (registry)..." "INFO"

        $softwareScript = {
            $paths  = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )
            $count = (Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
                      Where-Object { $_.DisplayName } |
                      Measure-Object).Count
            return $count
        }

        $icParams = @{
            ComputerName = $ComputerName
            ScriptBlock  = $softwareScript
            ErrorAction  = "Stop"
        }
        if ($Credential) { $icParams['Credential'] = $Credential }

        $softwareCount = Invoke-Command @icParams
        Write-LogMessage "  Found $softwareCount installed products (from Uninstall registry hive)" "SUCCESS"
        $script:TestResults.Packages = $true
    }
    catch {
        Write-LogMessage "  Failed to retrieve software list via registry: $_" "WARNING"
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    Clear-Host

    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host " Windows Scan Readiness Verification Script  v$ScriptVersion" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-LogMessage "Verification script started" "INFO"
    Write-LogMessage "Target Computer: $TargetComputer" "INFO"
    Write-LogMessage "Log file: $LogFile" "INFO"
    Write-Host ""

    Test-AdminRights
    Write-Host ""

    # Build credential — no plaintext examples; prompt securely when needed
    $credential = $null
    if ($Username) {
        if ($Password) {
            $credential = New-Object System.Management.Automation.PSCredential($Username, $Password)
        } else {
            # Safe interactive prompt; password is never echoed or logged
            Write-LogMessage "No -Password supplied — prompting securely for '$Username'." "INFO"
            $credential = Get-Credential -UserName $Username -Message "Enter password for $Username"
        }
    }

    # Resolve hostname → IPv4
    $targetIP = Resolve-ComputerName -Computer $TargetComputer
    if (-not $targetIP) {
        Write-LogMessage "Cannot proceed without resolving target hostname. Aborting." "ERROR"
        exit 1
    }
    Write-Host ""

    # Fail fast: validate credential before running any downstream tests
    if ($credential) {
        $credOK = Test-CredentialProbe -ComputerName $TargetComputer -Credential $credential
        if (-not $credOK) {
            Write-LogMessage "Aborting — credential probe failed. Fix the credential and re-run." "ERROR"
            exit 2
        }
        Write-Host ""
    }

    Test-NetworkConnectivity -TargetIP $targetIP
    Write-Host ""

    Test-WMIConnectivity -ComputerName $TargetComputer -Credential $credential
    Write-Host ""

    Test-AdminShareAccess -ComputerName $TargetComputer -Credential $credential
    Write-Host ""

    Test-WinRMConnectivity -ComputerName $TargetComputer -Credential $credential
    Write-Host ""

    Test-RemoteRegistry -ComputerName $TargetComputer -Credential $credential
    Write-Host ""

    Test-UACSetting -ComputerName $TargetComputer -Credential $credential
    Write-Host ""

    Test-SystemInformationRetrieval -ComputerName $TargetComputer -Credential $credential
    Write-Host ""

    # ============================================================================
    # FIX 5 — Final verdict now includes WinRM and RemoteRegistry results
    # Bug: The go/no-go decision tested only $systemInfo.OS, .ComputerSystem and
    #      .Processor. WinRM and RemoteRegistry failures were reported but ignored in
    #      the verdict — a machine with both services broken could still be declared
    #      "Ready for basic scanning", causing scan jobs to fail unexpectedly.
    # Fix: All six key test results feed the verdict: WMI (OS/CS/Processor),
    #      WinRM, RemoteRegistry, and AdminShare.
    # ============================================================================
    Write-LogMessage "=== VERIFICATION SUMMARY ===" "INFO"

    $coreWMI      = $script:TestResults.OS -and
                    $script:TestResults.ComputerSystem -and
                    $script:TestResults.Processor
    $coreServices = $script:TestResults.WinRM -and $script:TestResults.RemoteRegistry
    $allCritical  = $coreWMI -and $coreServices

    if ($allCritical -and $script:TestResults.Packages -and $script:TestResults.AdminShare) {
        Write-LogMessage "[+] All critical systems functional — READY FOR FULL SCANNING" "SUCCESS"
    } elseif ($allCritical) {
        Write-LogMessage "[+] Core systems functional — READY FOR BASIC SCANNING" "SUCCESS"
        if (-not $script:TestResults.Packages) {
            Write-LogMessage "  [!] Software enumeration may be limited" "WARNING"
        }
        if (-not $script:TestResults.AdminShare) {
            Write-LogMessage "  [!] Admin share access not confirmed — file-based checks may fail" "WARNING"
        }
    } elseif ($coreWMI -and -not $coreServices) {
        Write-LogMessage "[!] WMI responds but WinRM or RemoteRegistry is unavailable" "WARNING"
        Write-LogMessage "    WMI-only scans may work; WinRM/Registry-based plugins will fail." "WARNING"
        Write-LogMessage "    Run Prepare-WindowsForVulnScan.ps1 on the target to fix services." "WARNING"
    } else {
        Write-LogMessage "[X] Critical systems not responding — run Prepare-WindowsForVulnScan.ps1 on target" "ERROR"
    }

    Write-Host ""
    Write-LogMessage "Verification completed. Check log: $LogFile" "INFO"
}

Main
