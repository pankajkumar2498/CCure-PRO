$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$backendDir = Join-Path $repoRoot "Backend"
$workerScript = Join-Path $backendDir "scripts\scan\start_host_scanner_worker.ps1"

if (-not (Test-Path $workerScript)) {
    throw "Worker script not found at $workerScript"
}

Push-Location $repoRoot
try {
    Write-Host "============================================================"
    Write-Host " CCure Audit PRO - Starting Ultimate Hybrid Stack "
    Write-Host "============================================================"
    Write-Host ""
    Write-Host "[1/2] Starting Docker Services..."
    Write-Host "      - Includes: Redis, API, Frontend"
    Write-Host "      - Includes: Web Application Worker (Linux-based)"
    Write-Host ""
    
    # We start only the services that should live in Docker.
    # We explicitly include 'web-worker' but EXCLUDE 'worker' (network).
    docker compose up -d --build redis api frontend web-worker
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "[2/2] Starting Network Scanner Worker on Windows Host..."
Write-Host "      - Allows Nmap full Admin access to physical network."
Write-Host ""

# Start the network worker in the current window (or use Start-Process to pop a new one)
& $workerScript

Write-Host "============================================================"
