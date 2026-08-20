[CmdletBinding()]
param(
    # Replace an already-running host worker instead of refusing to start.
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendDir = Split-Path -Parent (Split-Path -Parent $scriptDir)
$venvPython = Join-Path $backendDir ".venv\Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    throw "Backend virtual environment not found at $venvPython. Create it first with: py -3.11 -m venv .venv"
}

# --- Refuse to start a second worker -----------------------------------------
# Two workers consuming the `scanner` queue is a real hazard: tasks go to
# whichever grabs them first, and if the two were started from different working
# directories they can be running different code, so editing Backend/ and
# restarting "the" worker would silently leave the other serving stale code.
#
# Only top-level workers are counted. A single Celery worker also shows a child
# python.exe running under the venv's base interpreter
# (AppData\...\Python312\python.exe, per Backend\.venv\pyvenv.cfg) -- that is
# one worker, not two, and counting it would make this guard refuse to start
# whenever a worker is running normally.
$celeryProcs = @(Get-CimInstance Win32_Process -Filter "Name like '%python%'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and $_.CommandLine -like '*celery*' -and $_.CommandLine -like '*core.celery_app*' })
$celeryPids = $celeryProcs | ForEach-Object { $_.ProcessId }
$existing = @($celeryProcs | Where-Object { $celeryPids -notcontains $_.ParentProcessId })

if ($existing) {
    Write-Host "A host scanner worker is already running:" -ForegroundColor Yellow
    foreach ($p in $existing) {
        $exe = ($p.CommandLine -split '"')[1]
        Write-Host ("  PID {0}  {1}" -f $p.ProcessId, $exe)
    }
    Write-Host ""
    Write-Host "Only one host worker may consume the 'scanner' queue. Stop the" -ForegroundColor Yellow
    Write-Host "existing one first, or re-run with -Force to replace it:" -ForegroundColor Yellow
    Write-Host "  .\Backend\scripts\scan\start_host_scanner_worker.ps1 -Force"
    if (-not $Force) { exit 1 }

    Write-Host "-Force given - stopping the existing worker(s)..." -ForegroundColor Cyan
    $existing | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 3
}

# Clear any stale shell-level app DB override so Backend/config.py
# reliably loads DATABASE_URL from Backend/.env for the worker.
if (Test-Path Env:DATABASE_URL) {
    Remove-Item Env:DATABASE_URL
}

$env:CELERY_BROKER_URL = "redis://localhost:6379/0"
$env:CELERY_RESULT_BACKEND = "redis://localhost:6379/0"

$env:SCANNER_RUNTIME = "host"
if (-not $env:SCANNER_WORKER_CONCURRENCY) {
    $env:SCANNER_WORKER_CONCURRENCY = "30"
}
if (-not $env:MAX_NMAP_PROCESSES) {
    $env:MAX_NMAP_PROCESSES = $env:SCANNER_WORKER_CONCURRENCY
}

Write-Host "Starting host scanner worker from $backendDir"
Write-Host "DATABASE_URL is loaded from Backend/.env via Backend/config.py"
Write-Host "CELERY_BROKER_URL=$env:CELERY_BROKER_URL"
Write-Host "SCANNER_WORKER_CONCURRENCY=$env:SCANNER_WORKER_CONCURRENCY"
Write-Host "MAX_NMAP_PROCESSES=$env:MAX_NMAP_PROCESSES"

Push-Location $backendDir
try {
    # An explicit node name makes a duplicate visible to `celery inspect`
    # instead of letting a second worker hide behind the same default name.
    # Logging to a file as well as the console means a scan failure stays
    # diagnosable after the window is closed. Previously the worker's only
    # output was the console it happened to be started in, so a failed scan
    # left nothing behind to read.
    $logDir = Join-Path $backendDir "logs"
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
    $logFile = Join-Path $logDir "host_scanner_worker.log"
    Write-Host "Logging to $logFile"

    # `compliance` is on this list deliberately. The only container that
    # subscribed to it sits behind the `container-scanner` profile and is not
    # started in this deployment, while Celery beat publishes
    # `compliance.run_scheduled_scans` into that queue every sixty seconds — so
    # the queue grew by 1,440 messages a day with nothing consuming it, and the
    # backlog would all fire at once whenever a worker did appear. Compliance
    # evaluation is database work with no raw-socket requirement, so it is safe
    # on the host worker alongside the scanner queues.
    & $venvPython -m celery -A core.celery_app worker --loglevel=info --queues=scanner,default,compliance --pool=threads --concurrency=$env:SCANNER_WORKER_CONCURRENCY --prefetch-multiplier=1 --hostname="host-scanner@%h" --logfile="$logFile"
}
finally {
    Pop-Location
}
