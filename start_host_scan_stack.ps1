$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendDir = Join-Path $repoRoot "Backend"
$workerScript = Join-Path $backendDir "scripts\start_host_scanner_worker.ps1"

if (-not (Test-Path $workerScript)) {
    throw "Worker script not found at $workerScript"
}

Push-Location $repoRoot
try {
    Write-Host "Starting Docker services: redis, api, frontend"
    Write-Host "Rebuilding API image so backend code changes are picked up"
    docker compose up -d --build redis api frontend
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "Starting scanner worker on this Windows machine"
& $workerScript
