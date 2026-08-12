param(
    [switch]$Rebuild,
    [switch]$Recreate,
    [string]$Service
)

$ErrorActionPreference = "Stop"

function Ensure-UnpausedContainers {
    param(
        [string[]]$ContainerNames
    )

    if (-not $ContainerNames) {
        return
    }

    $pausedContainers = docker ps -a --filter "status=paused" --format "{{.Names}}" | ForEach-Object { $_.Trim() }
    $toUnpause = $pausedContainers | Where-Object { $ContainerNames -contains $_ }
    if ($toUnpause) {
        Write-Host "Detected paused containers: $($toUnpause -join ', '). Unpausing..."
        foreach ($container in $toUnpause) {
            docker unpause $container | Out-Null
        }
    }
}

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
        # Four services by name, deliberately — NOT a bare `docker compose up -d`.
        #
        # Two services in docker-compose.yml must not start here, and neither
        # exclusion is obvious from reading that file:
        #
        #   worker  - the containerised scanner. It consumes the same Celery
        #             queues as the host worker started in step 2 below
        #             (scanner, default), so running both means each scan task
        #             goes to whichever grabs it first. Roughly half would land
        #             in a container that cannot reach the physical LAN with
        #             raw sockets, producing empty or wrong results
        #             intermittently, with nothing in the logs to explain it.
        #             Running the scanner on the host is the entire reason this
        #             stack is hybrid.
        #
        #   gateway - an optional nginx reverse proxy publishing port 80. The
        #             API (8000) and frontend (3200) are reachable directly, so
        #             it is not needed for scanning and only adds a port
        #             binding that can collide with whatever else uses 80.
        #
        # `db` is absent because PostgreSQL runs on the Windows host. It still
        # starts as an api dependency, which is harmless — the application
        # connects to the host server, not to that container.
        #
        # Before changing this to a bare `up -d`, read the note on `worker`:
        # it will silently corrupt scan results.
        $composeArgs += @("redis", "api", "frontend", "web-worker")
    }

    $serviceContainers = if ($Service) { @($Service) } else { @("ccure-redis", "ccure-api", "ccure-frontend", "ccure-web-worker") }
    Ensure-UnpausedContainers -ContainerNames $serviceContainers

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
