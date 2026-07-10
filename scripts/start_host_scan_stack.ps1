param(
    [switch]$Rebuild,
    [switch]$Recreate,
    [string]$Service
)

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
    if ($Service) {
        Write-Host "      - Targeting service: $Service"
    } else {
        Write-Host "      - Includes: Redis, API, Frontend"
        Write-Host "      - Includes: Web Application Worker (Linux-based)"
    }
    Write-Host ""
    
    $composeArgs = @("compose", "up", "-d")
    if ($Rebuild) {
        $composeArgs += "--build"
        if ($Service) {
            Write-Host "Rebuild mode enabled for service: $Service"
        } else {
            Write-Host "Rebuild mode enabled for api/frontend/web-worker"
        }
    }
    elseif ($Recreate) {
        $composeArgs += "--force-recreate"
        Write-Host "Force recreate mode enabled"
    }
    else {
        $composeArgs += "--no-recreate"
        Write-Host "Reuse existing containers and images"
    }

    if ($Service) {
        $composeArgs += $Service
    } else {
        $composeArgs += @("redis", "api", "frontend", "web-worker")
    }
    docker @composeArgs
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
