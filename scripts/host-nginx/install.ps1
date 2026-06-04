<#
.SYNOPSIS
    Installs and configures Nginx on the Windows host as a reverse proxy
    for CCure Audit PRO. Captures real client IPs for audit logging.

.DESCRIPTION
    - Downloads Nginx stable for Windows from nginx.org
    - Extracts to C:\nginx
    - Copies the custom CCure proxy config
    - Starts Nginx

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

# ── Check port 80 ─────────────────────────────────────────────────────────────
Write-Step "Checking if port 80 is available..."
$port80 = Get-NetTCPConnection -LocalPort 80 -ErrorAction SilentlyContinue
if ($port80) {
    $pid80 = $port80 | Select-Object -First 1 -ExpandProperty OwningProcess
    $proc80 = Get-Process -Id $pid80 -ErrorAction SilentlyContinue
    Write-Err "Port 80 is already in use by: $($proc80.ProcessName) (PID: $pid80)"
    Write-Host "Stop that process first, or change the listen port in nginx-host.conf."
    exit 1
}
Write-Ok "Port 80 is available"

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

# ── Test config ───────────────────────────────────────────────────────────────
Write-Step "Testing Nginx configuration..."
try {
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $testResult = & "$InstallDir\nginx.exe" -t -p "$InstallDir" -c "$configDest" 2>&1
} finally {
    $ErrorActionPreference = $oldPreference
}

if ($LASTEXITCODE -ne 0) {
    Write-Err "Nginx config test failed:"
    Write-Host $testResult
    exit 1
}
Write-Ok "Config test passed"

# ── Start Nginx ───────────────────────────────────────────────────────────────
Write-Step "Starting Nginx..."
Push-Location $InstallDir
Start-Process -FilePath "$InstallDir\nginx.exe" -WindowStyle Hidden
Pop-Location

Start-Sleep -Seconds 2

# Verify it's running
$nginxProc = Get-Process -Name "nginx" -ErrorAction SilentlyContinue
if ($nginxProc) {
    Write-Ok "Nginx is running (PID: $($nginxProc.Id -join ', '))"
} else {
    Write-Err "Nginx failed to start. Check $InstallDir\logs\error.log"
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
