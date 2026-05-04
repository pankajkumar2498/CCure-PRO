$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendDir = Split-Path -Parent $scriptDir
$venvPython = Join-Path $backendDir ".venv\Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    throw "Backend virtual environment not found at $venvPython. Create it first with: py -3.11 -m venv .venv"
}

# Clear any stale shell-level app DB override so Backend/config.py
# reliably loads DATABASE_URL from Backend/.env for the worker.
if (Test-Path Env:DATABASE_URL) {
    Remove-Item Env:DATABASE_URL
}

$env:CELERY_BROKER_URL = "redis://localhost:6379/0"
$env:CELERY_RESULT_BACKEND = "redis://localhost:6379/0"

$env:SCANNER_RUNTIME = "host"

Write-Host "Starting host scanner worker from $backendDir"
Write-Host "DATABASE_URL is loaded from Backend/.env via Backend/config.py"
Write-Host "CELERY_BROKER_URL=$env:CELERY_BROKER_URL"

Push-Location $backendDir
try {
    & $venvPython -m celery -A core.celery_app worker --loglevel=info --queues=scanner --concurrency=1 --pool=solo
}
finally {
    Pop-Location
}
