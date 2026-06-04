<#
.SYNOPSIS
    Installs and configures Nginx on the Windows host as a reverse proxy
    for CCure Audit PRO. Captures real client IPs for audit logging.

.DESCRIPTION
    - Downloads Nginx stable for Windows from nginx.org
    - Extracts to C:\nginx
    - Copies the custom CCure proxy config
    - Downloads NSSM and registers Nginx as a Windows Service
    - Service auto-starts on boot and auto-restarts on crash
    - Stops and disables IIS to prevent port 80 conflicts on reboot

.NOTES
    Run this script with Administrator privileges.
    Port 80 must be available (not used by IIS, Apache, etc.)
#>

param(
    [string]$NginxVersion = "1.26.3",
    [string]$InstallDir   = "C:\nginx"
)

$ErrorActionPreference = "Stop"

# ── Colors ────────────────────────────────────────────────────────────────────
function Write-Step  { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err   { param($msg) Write-Host "[ERR] $msg" -ForegroundColor Red }

# ── Check Admin ───────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Err "This script must be run as Administrator."
    Write-Host "Right-click PowerShell → Run as Administrator, then run this script again."
    exit 1
}

# ── Stop IIS if it is holding port 80 ────────────────────────────────────────
Write-Step "Checking for IIS on port 80..."
$iisRunning = Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
if ($iisRunning) {
    Write-Warn "IIS (W3SVC) is running and likely owns port 80. Stopping it now..."
    Stop-Service -Name "WAS"  -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "W3SVC" -Force -ErrorAction SilentlyContinue
    # Disable IIS autostart so it does not reclaim port 80 on next reboot
    Set-Service -Name "W3SVC" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "WAS"   -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Ok "IIS stopped and disabled from autostart."
} else {
    Write-Ok "IIS is not running."
}

# ── Final port 80 check ───────────────────────────────────────────────────────
Start-Sleep -Seconds 1
$port80 = Get-NetTCPConnection -LocalPort 80 -ErrorAction SilentlyContinue
if ($port80) {
    $pid80  = $port80 | Select-Object -First 1 -ExpandProperty OwningProcess
    $proc80 = Get-Process -Id $pid80 -ErrorAction SilentlyContinue
    Write-Err "Port 80 is still in use by: $($proc80.ProcessName) (PID: $pid80)"
    Write-Host "Please stop that process manually, then re-run this script."
    exit 1
}
Write-Ok "Port 80 is available."

# ── Download Nginx ────────────────────────────────────────────────────────────
$zipUrl  = "http://nginx.org/download/nginx-$NginxVersion.zip"
$zipPath = "$env:TEMP\nginx-$NginxVersion.zip"

if (Test-Path "$InstallDir\nginx.exe") {
    Write-Warn "Nginx already installed at $InstallDir. Skipping download."
} else {
    Write-Step "Downloading Nginx $NginxVersion from nginx.org..."
    try {
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
        Write-Ok "Downloaded to $zipPath"
    } catch {
        Write-Err "Failed to download Nginx: $_"
        Write-Host "You can manually download from: $zipUrl"
        exit 1
    }

    # ── Extract ───────────────────────────────────────────────────────────────
    Write-Step "Extracting to $InstallDir..."
    $extractDir = "$env:TEMP\nginx-extract"
    if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }

    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

    # The zip contains a folder like nginx-1.26.3/
    $innerDir = Get-ChildItem $extractDir | Where-Object { $_.PSIsContainer } | Select-Object -First 1

    if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
    Move-Item $innerDir.FullName $InstallDir
    Write-Ok "Extracted to $InstallDir"

    # Cleanup
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
}

# ── Copy config ───────────────────────────────────────────────────────────────
$scriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$configSrc  = Join-Path $scriptDir "nginx-host.conf"
$configDest = Join-Path $InstallDir "conf\nginx.conf"

if (-not (Test-Path $configSrc)) {
    Write-Err "Config file not found at: $configSrc"
    exit 1
}

Write-Step "Copying CCure proxy config..."
Copy-Item $configSrc $configDest -Force
Write-Ok "Config installed to $configDest"

# ── Ensure logs directory ─────────────────────────────────────────────────────
$logsDir = Join-Path $InstallDir "logs"
if (-not (Test-Path $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
}

# ── Test Nginx config ─────────────────────────────────────────────────────────
Write-Step "Testing Nginx configuration..."
$oldPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$testResult = & "$InstallDir\nginx.exe" -t -p "$InstallDir" -c "$configDest" 2>&1
$ErrorActionPreference = $oldPreference

if ($LASTEXITCODE -ne 0) {
    Write-Err "Nginx config test failed:"
    Write-Host $testResult
    exit 1
}
Write-Ok "Config test passed."

# ── Download NSSM (Windows Service Manager) ───────────────────────────────────
# NSSM allows any .exe to run as a proper Windows Service with auto-restart
# and boot-time start — the standard approach on Windows servers.
$nssmDir  = "C:\nssm"
$nssmExe  = "$nssmDir\nssm.exe"
$nssmUrl  = "https://nssm.cc/release/nssm-2.24.zip"
$nssmZip  = "$env:TEMP\nssm.zip"

if (Test-Path $nssmExe) {
    Write-Warn "NSSM already present at $nssmExe. Skipping download."
} else {
    Write-Step "Downloading NSSM (Windows Service Manager)..."
    try {
        Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing
    } catch {
        Write-Err "Failed to download NSSM: $_"
        Write-Host "Download manually from https://nssm.cc and place nssm.exe at $nssmExe"
        exit 1
    }

    $nssmExtract = "$env:TEMP\nssm-extract"
    if (Test-Path $nssmExtract) { Remove-Item $nssmExtract -Recurse -Force }
    Expand-Archive -Path $nssmZip -DestinationPath $nssmExtract -Force

    # NSSM zip contains win32 and win64 folders — prefer win64
    $nssmBin = Get-ChildItem "$nssmExtract" -Recurse -Filter "nssm.exe" |
               Where-Object { $_.FullName -match "win64" } |
               Select-Object -First 1

    if (-not $nssmBin) {
        $nssmBin = Get-ChildItem "$nssmExtract" -Recurse -Filter "nssm.exe" | Select-Object -First 1
    }

    if (-not (Test-Path $nssmDir)) { New-Item -ItemType Directory -Path $nssmDir | Out-Null }
    Copy-Item $nssmBin.FullName $nssmExe -Force
    Remove-Item $nssmZip -Force -ErrorAction SilentlyContinue
    Remove-Item $nssmExtract -Recurse -Force -ErrorAction SilentlyContinue
    Write-Ok "NSSM installed to $nssmExe"
}

# ── Register Nginx as a Windows Service via NSSM ─────────────────────────────
$serviceName = "CCureNginx"

Write-Step "Registering Nginx as Windows Service '$serviceName'..."

# Remove existing service registration for a clean reinstall
$existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Warn "Service '$serviceName' already exists. Removing old registration..."
    if ($existingService.Status -eq "Running") {
        & $nssmExe stop $serviceName | Out-Null
        Start-Sleep -Seconds 2
    }
    & $nssmExe remove $serviceName confirm | Out-Null
    Write-Ok "Old service removed."
}

# Register Nginx as a service
& $nssmExe install $serviceName "$InstallDir\nginx.exe"

# Set working directory — Nginx resolves relative paths (logs/, conf/) from here
& $nssmExe set $serviceName AppDirectory $InstallDir

# Crash recovery: restart Nginx automatically after a 3-second delay
& $nssmExe set $serviceName AppExit Default Restart
& $nssmExe set $serviceName AppRestartDelay 3000

# Route stdout/stderr to log files for diagnostics
& $nssmExe set $serviceName AppStdout "$InstallDir\logs\service-stdout.log"
& $nssmExe set $serviceName AppStderr "$InstallDir\logs\service-stderr.log"
& $nssmExe set $serviceName AppRotateFiles 1
& $nssmExe set $serviceName AppRotateOnline 1
& $nssmExe set $serviceName AppRotateBytes 10485760   # Rotate at 10 MB

# Ensure the service starts automatically at boot
Set-Service -Name $serviceName -StartupType Automatic

Write-Ok "Nginx registered as Windows Service '$serviceName' (Startup: Automatic)."

# ── Start the service ─────────────────────────────────────────────────────────
Write-Step "Starting $serviceName service..."
Start-Service -Name $serviceName
Start-Sleep -Seconds 3

$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Ok "Service is RUNNING."
} else {
    Write-Err "Service failed to start. Check logs at $InstallDir\logs\"
    Write-Host "Run: Get-EventLog -LogName System -Source $serviceName -Newest 5"
    exit 1
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  Nginx Host Proxy is RUNNING on port 80" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "  Access the app:  http://$($env:COMPUTERNAME):80/" -ForegroundColor White
Write-Host "  Or by IP:        http://$(hostname):80/" -ForegroundColor White
Write-Host ""
Write-Host "  Audit logs will now show REAL client IPs." -ForegroundColor Cyan
Write-Host ""
Write-Host "  Management commands:" -ForegroundColor Yellow
Write-Host "    Stop:    $InstallDir\nginx.exe -s stop"
Write-Host "    Reload:  $InstallDir\nginx.exe -s reload"
Write-Host "    Test:    $InstallDir\nginx.exe -t"
Write-Host "    Logs:    $InstallDir\logs\"
Write-Host ""
