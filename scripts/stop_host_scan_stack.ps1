$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

Push-Location $repoRoot
try {
    Write-Host "============================================================"
    Write-Host " CCure Audit PRO - Stopping Full Security Stack "
    Write-Host "============================================================"
    Write-Host ""
    Write-Host "Stopping all containers including Web and Network workers..."

    # --profile container-scanner ensures the workers are also stopped
    docker compose --profile container-scanner down --remove-orphans
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "SUCCESS: All services have been stopped and removed."
Write-Host "============================================================"
