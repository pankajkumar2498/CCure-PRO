<#
.SYNOPSIS
    Removes the CCureNginx Windows Service registered by install.ps1.

.DESCRIPTION
    - Stops and removes the CCureNginx service via NSSM
    - Optionally re-enables and restarts IIS (W3SVC)

.NOTES
    Run this script with Administrator privileges.
#>

$ErrorActionPreference = "Stop"

function Write-Step  { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err   { param($msg) Write-Host "[ERR] $msg" -ForegroundColor Red }

# ── Check Admin ───────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Err "This script must be run as Administrator."
    exit 1
}

$serviceName = "CCureNginx"
$nssmExe     = "C:\nssm\nssm.exe"

# ── Stop and remove the service ───────────────────────────────────────────────
Write-Step "Stopping service '$serviceName'..."
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq "Running") {
        if (Test-Path $nssmExe) {
            & $nssmExe stop $serviceName | Out-Null
        } else {
            Stop-Service -Name $serviceName -Force
        }
        Start-Sleep -Seconds 2
    }

    Write-Step "Removing service '$serviceName'..."
    if (Test-Path $nssmExe) {
        & $nssmExe remove $serviceName confirm | Out-Null
    } else {
        sc.exe delete $serviceName | Out-Null
    }
    Write-Ok "Service '$serviceName' removed."
} else {
    Write-Warn "Service '$serviceName' not found. Nothing to remove."
}

# ── Optionally re-enable IIS ──────────────────────────────────────────────────
$restoreIIS = Read-Host "`nDo you want to re-enable and start IIS? (y/N)"
if ($restoreIIS -match "^[Yy]$") {
    Write-Step "Re-enabling IIS (W3SVC, WAS)..."
    Set-Service -Name "WAS"   -StartupType Automatic -ErrorAction SilentlyContinue
    Set-Service -Name "W3SVC" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "WAS"   -ErrorAction SilentlyContinue
    Start-Service -Name "W3SVC" -ErrorAction SilentlyContinue
    Write-Ok "IIS re-enabled and started."
} else {
    Write-Warn "IIS remains disabled. Port 80 is free."
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "  CCureNginx service has been removed." -ForegroundColor Yellow
Write-Host "  To reinstall, run: .\install.ps1" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""
