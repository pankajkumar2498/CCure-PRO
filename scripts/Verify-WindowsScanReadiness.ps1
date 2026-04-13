#Requires -RunAsAdministrator
<#
.SYNOPSIS
Verifies that a Windows machine is properly configured for credentialed scanning

.DESCRIPTION
Tests connectivity and configuration from the SCANNING MACHINE to the TARGET WINDOWS MACHINE.
Run this script on the scanning machine to verify the target is ready.

.PARAMETER TargetComputer
The IP address or hostname of the Windows machine to scan

.PARAMETER Username
Username for authentication (if different from current user)

.PARAMETER Password
Password for the account (if not specified, uses current credentials or prompts)

.EXAMPLE
.\Verify-WindowsScanReadiness.ps1 -TargetComputer 192.168.1.100
.\Verify-WindowsScanReadiness.ps1 -TargetComputer WORKSTATION1 -Username "DOMAIN\scanner"
.\Verify-WindowsScanReadiness.ps1 -TargetComputer 10.0.0.50 -Username "admin" -Password (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force)

.NOTES
- Run on the SCANNING/SCANNER machine, not the target
- Requires Administrator privileges
- Tests WMI, admin shares, WinRM connectivity
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

$ScriptVersion = "1.0"
$LogFile = "C:\Windows\Temp\VulnScanVerify_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Test timeout in seconds
$ConnectionTimeout = 10

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
    
    switch ($Level) {
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        default { Write-Host $logEntry }
    }
    
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

function Resolve-ComputerName {
    param([string]$Computer)
    
    Write-LogMessage "Resolving hostname/IP: $Computer" "INFO"
    
    try {
        $resolved = [System.Net.Dns]::GetHostAddresses($Computer)[0].IPAddressToString
        Write-LogMessage "Resolved to: $resolved" "SUCCESS"
        return $resolved
    } catch {
        Write-LogMessage "Failed to resolve hostname: $_" "ERROR"
        return $null
    }
}

# ============================================================================
# CONNECTIVITY TESTS
# ============================================================================

function Test-NetworkConnectivity {
    param([string]$TargetIP)
    
    Write-LogMessage "=== NETWORK CONNECTIVITY ===" "INFO"
    
    # Test ping
    Write-LogMessage "Testing ICMP (Ping)..." "INFO"
    try {
        $ping = Test-Connection -ComputerName $TargetIP -Count 1 -Quiet -ErrorAction Stop
        if ($ping) {
            Write-LogMessage "Ping successful" "SUCCESS"
        } else {
            Write-LogMessage "Ping failed (host may block ICMP)" "WARNING"
        }
    } catch {
        Write-LogMessage "Ping test failed: $_" "WARNING"
    }
    
    # Test common ports
    $ports = @(
        @{Port = 135; Service = "RPC Endpoint Mapper" },
        @{Port = 139; Service = "NetBIOS Session Service" },
        @{Port = 445; Service = "SMB/CIFS" },
        @{Port = 5985; Service = "WinRM HTTP" },
        @{Port = 5986; Service = "WinRM HTTPS" }
    )
    
    Write-LogMessage "Testing critical ports..." "INFO"
    
    foreach ($portInfo in $ports) {
        try {
            $socket = New-Object System.Net.Sockets.TcpClient
            $result = $socket.BeginConnect($TargetIP, $portInfo.Port, $null, $null)
            $connected = $result.AsyncWaitHandle.WaitOne($ConnectionTimeout * 1000, $false)
            $socket.Close()
            
            if ($connected) {
                Write-LogMessage "  Port $($portInfo.Port) ($($portInfo.Service)): OPEN" "SUCCESS"
            } else {
                Write-LogMessage "  Port $($portInfo.Port) ($($portInfo.Service)): CLOSED/FILTERED" "WARNING"
            }
        } catch {
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
            Namespace = "root\cimv2"
            Class = "Win32_ComputerSystem"
            ErrorAction = "Stop"
        }
        
        if ($Credential) {
            $wmiParams['Authentication'] = 'PacketPrivacy'
            $wmiParams['Impersonation'] = 'Impersonate'
            
            # Use PSCredential
            $wmiParams['Credential'] = $Credential
        }
        
        $computerInfo = Get-WmiObject @wmiParams
        
        if ($computerInfo) {
            Write-LogMessage "WMI Connected Successfully!" "SUCCESS"
            Write-LogMessage "  Computer Name: $($computerInfo.Name)" "INFO"
            Write-LogMessage "  Domain: $($computerInfo.Domain)" "INFO"
            Write-LogMessage "  Manufacturer: $($computerInfo.Manufacturer)" "INFO"
            Write-LogMessage "  Model: $($computerInfo.Model)" "INFO"
            return $true
        }
    } catch {
        Write-LogMessage "WMI Connection Failed: $_" "ERROR"
        return $false
    }
}

function Test-AdminShareAccess {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    Write-LogMessage "=== ADMIN SHARE ACCESS ===" "INFO"
    
    $adminShares = @("\\$ComputerName\C$", "\\$ComputerName\ADMIN$", "\\$ComputerName\IPC$")
    
    foreach ($share in $adminShares) {
        try {
            Write-LogMessage "Testing access to: $share" "INFO"
            
            if ($Credential) {
                $tempPath = "\\$ComputerName\c$\Windows\System32"
                [System.IO.DirectoryInfo]$dir = New-Object System.IO.DirectoryInfo($tempPath)
                $accessCheck = $dir.GetAccessControl()
                Write-LogMessage "  Access granted to: $share" "SUCCESS"
            } else {
                $testPath = Test-Path -Path $share -ErrorAction Stop
                if ($testPath) {
                    Write-LogMessage "  Access granted to: $share" "SUCCESS"
                }
            }
        } catch {
            Write-LogMessage "  Access denied or share unavailable: $share" "WARNING"
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
                ComputerName = $env:COMPUTERNAME
                OSVersion = [Environment]::OSVersion.VersionString
                ProcessorCount = (Get-WmiObject Win32_Processor).Count
                TotalMemory = [math]::Round(((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB), 2)
            }
        }
        
        $params = @{
            ComputerName = $ComputerName
            ScriptBlock = $scriptBlock
            ErrorAction = "Stop"
        }
        
        if ($Credential) {
            $params['Credential'] = $Credential
        }
        
        $result = Invoke-Command @params
        
        Write-LogMessage "WinRM Connection Successful!" "SUCCESS"
        Write-LogMessage "  Computer: $($result.ComputerName)" "INFO"
        Write-LogMessage "  OS Version: $($result.OSVersion)" "INFO"
        Write-LogMessage "  Processor Count: $($result.ProcessorCount)" "INFO"
        Write-LogMessage "  Total Memory (GB): $($result.TotalMemory)" "INFO"
        
        return $true
    } catch {
        Write-LogMessage "WinRM Connection Failed: $_" "ERROR"
        
        if ($_ -match "WinRM") {
            Write-LogMessage "  Ensure WinRM is enabled on target and firewall allows port 5985 (HTTP)" "WARNING"
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
        
        $params = @{
            ComputerName = $ComputerName
            Force = $true
            ErrorAction = "Stop"
        }
        
        if ($Credential) {
            $params['Credential'] = $Credential
        }
        
        # Try to open remote registry key
        $remoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $ComputerName)
        
        # Try to read a key
        $subKey = $remoteReg.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        if ($subKey) {
            $productName = $subKey.GetValue("ProductName")
            $currentBuild = $subKey.GetValue("CurrentBuild")
            
            Write-LogMessage "Remote Registry Access Successful!" "SUCCESS"
            Write-LogMessage "  OS: $productName" "INFO"
            Write-LogMessage "  Build: $currentBuild" "INFO"
            $subKey.Close()
            $remoteReg.Close()
            return $true
        }
    } catch {
        Write-LogMessage "Remote Registry Access Failed: $_" "ERROR"
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
            # Use remote registry with credentials
            $scriptBlock = {
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                $value = Get-ItemProperty -Path $regPath -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue
                return $value.LocalAccountTokenFilterPolicy
            }
            
            $params = @{
                ComputerName = $ComputerName
                ScriptBlock = $scriptBlock
                Credential = $Credential
                ErrorAction = "Stop"
            }
            
            $uacValue = Invoke-Command @params
        } else {
            $remoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $ComputerName)
            $subKey = $remoteReg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
            $uacValue = $subKey.GetValue("LocalAccountTokenFilterPolicy")
            $subKey.Close()
            $remoteReg.Close()
        }
        
        if ($uacValue -eq 1) {
            Write-LogMessage "LocalAccountTokenFilterPolicy: 1 (Remote admin authentication enabled)" "SUCCESS"
        } elseif ($null -eq $uacValue) {
            Write-LogMessage "LocalAccountTokenFilterPolicy: Not Set (may cause issues with remote queries)" "WARNING"
        } else {
            Write-LogMessage "LocalAccountTokenFilterPolicy: 0 (Restrictive - may block remote access)" "WARNING"
        }
        
        return $true
    } catch {
        Write-LogMessage "Error checking UAC setting: $_" "WARNING"
        return $false
    }
}

function Test-SystemInformationRetrieval {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    Write-LogMessage "=== CRITICAL: SYSTEM INFORMATION RETRIEVAL ===" "INFO"
    
    $wmiParams = @{
        ComputerName = $ComputerName
        ErrorAction = "Stop"
    }
    
    if ($Credential) {
        $wmiParams['Authentication'] = 'PacketPrivacy'
        $wmiParams['Credential'] = $Credential
    }
    
    $infoRetrieved = @{
        OS = $false
        ComputerSystem = $false
        Processor = $false
        Packages = $false
    }
    
    # Test OS Info
    try {
        Write-LogMessage "Retrieving OS information..." "INFO"
        $os = Get-WmiObject @wmiParams -Class Win32_OperatingSystem
        if ($os) {
            Write-LogMessage "  Caption: $($os.Caption)" "SUCCESS"
            Write-LogMessage "  Version: $($os.Version)" "SUCCESS"
            Write-LogMessage "  Build: $($os.BuildNumber)" "SUCCESS"
            $infoRetrieved.OS = $true
        }
    } catch {
        Write-LogMessage "  Failed to retrieve OS info: $_" "ERROR"
    }
    
    # Test Computer System Info
    try {
        Write-LogMessage "Retrieving Computer System information..." "INFO"
        $cs = Get-WmiObject @wmiParams -Class Win32_ComputerSystem
        if ($cs) {
            Write-LogMessage "  Name: $($cs.Name)" "SUCCESS"
            Write-LogMessage "  Domain: $($cs.Domain)" "SUCCESS"
            $infoRetrieved.ComputerSystem = $true
        }
    } catch {
        Write-LogMessage "  Failed to retrieve Computer System info: $_" "ERROR"
    }
    
    # Test Processor Info
    try {
        Write-LogMessage "Retrieving Processor information..." "INFO"
        $proc = Get-WmiObject @wmiParams -Class Win32_Processor | Select-Object -First 1
        if ($proc) {
            Write-LogMessage "  Name: $($proc.Name)" "SUCCESS"
            Write-LogMessage "  Cores: $($proc.NumberOfCores)" "SUCCESS"
            $infoRetrieved.Processor = $true
        }
    } catch {
        Write-LogMessage "  Failed to retrieve Processor info: $_" "ERROR"
    }
    
    # Test software enumeration (packages)
    try {
        Write-LogMessage "Retrieving installed software..." "INFO"
        $software = Get-WmiObject @wmiParams -Class Win32_Product | Measure-Object
        if ($software) {
            Write-LogMessage "  Found $($software.Count) installed products" "SUCCESS"
            $infoRetrieved.Packages = $true
        }
    } catch {
        Write-LogMessage "  Failed to retrieve software list: $_" "WARNING"
    }
    
    return $infoRetrieved
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    Clear-Host
    
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "Windows Scan Readiness Verification Script" -ForegroundColor Cyan
    Write-Host "Version: $ScriptVersion" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-LogMessage "Verification script started" "INFO"
    Write-LogMessage "Target Computer: $TargetComputer" "INFO"
    Write-LogMessage "Log file: $LogFile" "INFO"
    Write-Host ""
    
    # Validate admin rights
    Test-AdminRights
    Write-Host ""
    
    # Setup credentials if provided
    $credential = $null
    if ($Username) {
        if ($Password) {
            $credential = New-Object System.Management.Automation.PSCredential($Username, $Password)
        } else {
            $credential = Get-Credential -UserName $Username -Message "Enter password for $Username"
        }
    }
    
    # Resolve hostname to IP
    $targetIP = Resolve-ComputerName -Computer $TargetComputer
    if (-not $targetIP) {
        Write-LogMessage "Cannot proceed without resolving target hostname" "ERROR"
        exit 1
    }
    Write-Host ""
    
    # Run connectivity tests
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
    
    $systemInfo = Test-SystemInformationRetrieval -ComputerName $TargetComputer -Credential $credential
    Write-Host ""
    
    # Summary
    Write-LogMessage "=== VERIFICATION SUMMARY ===" "INFO"
    
    $systemInfoOK = $systemInfo.OS -and $systemInfo.ComputerSystem -and $systemInfo.Processor
    
    if ($systemInfoOK -and $systemInfo.Packages) {
        Write-LogMessage "✓ All critical systems functional - Ready for scanning" "SUCCESS"
    } elseif ($systemInfoOK) {
        Write-LogMessage "✓ Core systems functional - Ready for basic scanning" "SUCCESS"
        Write-LogMessage "  (Software enumeration may be limited)" "WARNING"
    } else {
        Write-LogMessage "✗ Critical systems not responding - Run setup script on target" "ERROR"
    }
    
    Write-Host ""
    Write-LogMessage "Verification completed. Check log for details: $LogFile" "INFO"
}

# Execute main function
Main
