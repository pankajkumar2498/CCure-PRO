# ============================================================================
# Ccure Audit PRO - Startup Script
# ============================================================================
# Launches both Backend (FastAPI) and Frontend (React) in parallel by spawning
# separate PowerShell child windows, with optional dependency installation
# and browser auto-open.
#
# Usage:
#   # Development (default) — uvicorn with --reload, Vite dev server
#   PowerShell -ExecutionPolicy Bypass -File startup.ps1
#
#   # Production/staging — uvicorn without --reload, Vite preview build
#   PowerShell -ExecutionPolicy Bypass -File startup.ps1 -Prod
#
#   # Skip browser auto-open
#   PowerShell -ExecutionPolicy Bypass -File startup.ps1 -NoOpen
# ============================================================================

param(
    [switch]$SkipBackend,
    [switch]$SkipFrontend,
    [switch]$NoOpen,

    # BUG FIX #4 - --reload was unconditionally baked into the uvicorn
    # launch command. A developer could accidentally use this script to
    # stand up a staging or demo environment with --reload active, causing
    # real performance and stability implications.
    # Fix: Add a -Prod switch. When absent, --reload is used (dev default).
    # When -Prod is set, --reload is omitted and the frontend runs a Vite
    # preview build instead of the hot-reload dev server.
    [switch]$Prod
)

# ============================================================================
# BUG FIX #2 - Global $ErrorActionPreference = "Stop" with no error handling
# around temp file writes. If $env:TEMP is on a restricted path or the write
# fails, the script crashes with an unhandled exception.
# Fix: Drop the global Stop preference. Use localised -ErrorAction Stop only
# on operations that genuinely warrant a hard abort (directory checks, venv
# creation). Temp file writes are wrapped in their own try/catch blocks with
# a clear, actionable error message.
# ============================================================================
$ErrorActionPreference = "Continue"

# ============================================================================
# HELPERS
# ============================================================================
function Write-Info         { Write-Host "[INFO]  $args" -ForegroundColor Cyan }
function Write-OK           { Write-Host "[OK]    $args" -ForegroundColor Green }
function Write-Warning-Custom { Write-Host "[WARN]  $args" -ForegroundColor Yellow }
function Write-Error-Custom { Write-Host "[ERR]   $args" -ForegroundColor Red }
function Write-Section      { Write-Host "`n$args" -ForegroundColor Yellow -BackgroundColor Black }

Write-Section "=================================="
Write-Section "Ccure Audit PRO Startup"
if ($Prod) { Write-Section "Mode: PRODUCTION  (no --reload)" }
else       { Write-Section "Mode: DEVELOPMENT (--reload on)" }
Write-Section "=================================="

# ============================================================================
# PATH RESOLUTION
# ============================================================================
$scriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendDir  = Join-Path $scriptDir "Backend"
$frontendDir = Join-Path $scriptDir "Frontend"

if (-not (Test-Path $backendDir)) {
    Write-Error-Custom "Backend directory not found at: $backendDir"
    exit 1
}
if (-not (Test-Path $frontendDir)) {
    Write-Error-Custom "Frontend directory not found at: $frontendDir"
    exit 1
}

Write-OK "Project root: $scriptDir"

# ============================================================================
# RESOLVE VITE PORT
#
# BUG FIX #1 - Hardcoded port 3000 is wrong. Vite defaults to 5173, not 3000.
# Every new developer would open a blank browser tab and spend time debugging
# before noticing. The script also printed "http://localhost:3000" in the
# summary, spreading the wrong URL into documentation and onboarding notes.
# Fix: Attempt to parse the port from vite.config.js (or vite.config.ts).
# If found, use it. If not found (no config, or config has no explicit port),
# fall back to the documented Vite default of 5173. The resolved port is used
# consistently for the browser open call and all printed URLs.
# ============================================================================
function Get-VitePort {
    param([string]$FrontendDir)

    $configCandidates = @(
        (Join-Path $FrontendDir "vite.config.js"),
        (Join-Path $FrontendDir "vite.config.ts"),
        (Join-Path $FrontendDir "vite.config.mjs")
    )

    foreach ($cfg in $configCandidates) {
        if (Test-Path $cfg) {
            $content = Get-Content $cfg -Raw -ErrorAction SilentlyContinue
            # Match: port: 3000  or  port:3000  (with or without quotes/spaces)
            if ($content -match 'port\s*:\s*[''"]?(\d{4,5})[''"]?') {
                $parsedPort = [int]$Matches[1]
                Write-Info "Vite port resolved from $(Split-Path $cfg -Leaf): $parsedPort"
                return $parsedPort
            }
        }
    }

    Write-Info "No explicit Vite port in config — using Vite default: 5173"
    return 5173
}

$vitePort    = Get-VitePort -FrontendDir $frontendDir
$frontendUrl = "http://localhost:$vitePort"

# ============================================================================
# REQUIREMENTS HASH HELPER (used by backend startup to skip pip when unchanged)
#
# BUG FIX #3 - pip install -q -r requirements.txt runs on every single backend
# start, adding 20-30 seconds on slow networks for a 40-package requirements.txt.
# Fix: Cache a SHA256 hash of requirements.txt next to the venv. On the next
# start, compare the current hash to the cached one. Only run pip install if
# the file changed (or the cache doesn't exist yet). The hash file is written
# after a successful install so a failed partial install always retriggers.
# ============================================================================
function Get-RequirementsHash {
    param([string]$BackendDir)
    $reqFile = Join-Path $BackendDir "requirements.txt"
    if (-not (Test-Path $reqFile)) { return $null }
    $hashObj = Get-FileHash -Path $reqFile -Algorithm SHA256
    return $hashObj.Hash
}

# ============================================================================
# UNIQUE TEMP FILE NAMES
#
# BUG FIX #6 - The temp launcher scripts were written to fixed names
# (ccure_backend_startup.ps1 / ccure_frontend_startup.ps1) in $env:TEMP.
# Concurrent invocations of startup.ps1 (e.g., two developers sharing a
# dev box, or a rapid restart) would silently overwrite each other's temp
# scripts, causing one or both child processes to run the wrong commands.
# Fix: Use New-TemporaryFile to obtain a uniquely-named file guaranteed by
# the OS, then rename it with a .ps1 extension. Each invocation gets its
# own paths that cannot collide.
# ============================================================================
function New-TempPs1 {
    param([string]$Label)
    $base = [System.IO.Path]::Combine($env:TEMP, "ccure_${Label}_$([System.Guid]::NewGuid().ToString('N')).ps1")
    return $base
}

# ============================================================================
# BACKEND STARTUP
# ============================================================================
if (-not $SkipBackend) {
    Write-Section "[1/2] Starting Backend (FastAPI)..."

    # Ensure venv exists
    $venvPath       = Join-Path $backendDir ".venv"
    $activateScript = Join-Path $backendDir ".venv\Scripts\Activate.ps1"

    if (-not (Test-Path $venvPath)) {
        Write-Info "Virtual environment not found - creating..."
        Push-Location $backendDir
        python -m venv .venv
        if ($LASTEXITCODE -ne 0) {
            Write-Error-Custom "python -m venv failed (exit $LASTEXITCODE). Is Python on your PATH?"
            Pop-Location; exit 1
        }
        Write-OK "Virtual environment created at $venvPath"
        Pop-Location
    }

    if (-not (Test-Path $activateScript)) {
        Write-Error-Custom "Activation script missing: $activateScript"
        exit 1
    }

    # BUG FIX #4 (continued) - Build uvicorn flags based on -Prod switch.
    $uvicornFlags = if ($Prod) {
        "--host 127.0.0.1 --port 8000"
    } else {
        "--reload --host 127.0.0.1 --port 8000"
    }

    # BUG FIX #3 (continued) - Conditional pip install via hash check.
    # The hash cache file lives next to the venv and is only updated after
    # a successful pip install, so an interrupted install always retriggers.
    $hashCacheFile  = Join-Path $backendDir ".venv\.requirements_hash"
    $currentHash    = Get-RequirementsHash -BackendDir $backendDir
    $cachedHash     = if (Test-Path $hashCacheFile) { Get-Content $hashCacheFile -Raw } else { "" }
    $needsInstall   = ($currentHash -ne $cachedHash.Trim()) -or (-not (Test-Path $hashCacheFile))

    $pipBlock = if ($needsInstall) {
        @"
Write-Host "[Backend] requirements.txt changed - installing dependencies..." -ForegroundColor Cyan
pip install -q -r requirements.txt
if (`$LASTEXITCODE -eq 0) {
    "$currentHash" | Set-Content -Path '$hashCacheFile' -NoNewline
    Write-Host "[Backend] Dependencies installed and hash cached." -ForegroundColor Green
} else {
    Write-Host "[Backend] pip install failed - server may not start correctly." -ForegroundColor Red
}
"@
    } else {
        'Write-Host "[Backend] requirements.txt unchanged - skipping pip install." -ForegroundColor Green'
    }

    # BUG FIX #2 (continued) - Wrap temp file write in try/catch.
    $tempBackendScript = New-TempPs1 "backend"
    try {
        @"
Set-Location '$backendDir'
& '$activateScript'
$pipBlock
Write-Host "[Backend] Starting FastAPI (uvicorn $uvicornFlags)..." -ForegroundColor Cyan
uvicorn main:app $uvicornFlags
"@ | Out-File -FilePath $tempBackendScript -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Error-Custom "Failed to write backend launcher script to temp: $_"
        Write-Info "Check that $env:TEMP is writable."
        exit 1
    }

    Start-Process powershell -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$tempBackendScript`""
    Write-OK "Backend process spawned (new window)"

    # -----------------------------------------------------------------------
    # BUG FIX #5 - No health check after spawning.
    # The original Start-Sleep -Seconds 3 was a blind wait with no feedback.
    # If Python failed to import a module on startup, the child window closed
    # immediately and the parent reported everything as fine.
    # Fix: Poll http://127.0.0.1:8000/ in a retry loop (up to 30 attempts,
    # 2 seconds apart = 60s total). Report each attempt so the developer can
    # see progress. Warn clearly if the backend never responds, but do not
    # abort — the frontend can still start and the developer can diagnose
    # from the backend window.
    # -----------------------------------------------------------------------
    Write-Info "Waiting for backend to become ready (up to 60s)..."
    $backendReady  = $false
    $maxAttempts   = 30
    $pollIntervalS = 2

    for ($i = 1; $i -le $maxAttempts; $i++) {
        Start-Sleep -Seconds $pollIntervalS
        try {
            $null = Invoke-WebRequest -Uri "http://127.0.0.1:8000/" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
            $backendReady = $true
            break
        } catch {
            Write-Info "  Backend not yet responding... ($i/$maxAttempts)"
        }
    }

    if ($backendReady) {
        Write-OK "Backend is healthy at http://127.0.0.1:8000"
    } else {
        Write-Warning-Custom "Backend did not respond within $($maxAttempts * $pollIntervalS)s."
        Write-Warning-Custom "Check the backend PowerShell window for error output."
        Write-Warning-Custom "Common causes: Python import error, port 8000 already in use."
    }
}

# ============================================================================
# FRONTEND STARTUP
# ============================================================================
if (-not $SkipFrontend) {
    Write-Section "[2/2] Starting Frontend (React)..."

    $nodeModules = Join-Path $frontendDir "node_modules"
    if (-not (Test-Path $nodeModules)) {
        Write-Info "node_modules not found - running npm install..."
        Push-Location $frontendDir
        npm install --silent
        if ($LASTEXITCODE -ne 0) {
            Write-Error-Custom "npm install failed (exit $LASTEXITCODE). Is Node.js on your PATH?"
            Pop-Location; exit 1
        }
        Write-OK "npm packages installed"
        Pop-Location
    }

    # BUG FIX #1 (continued) + BUG FIX #4 (frontend side):
    # In Prod mode run "npm run build && npm run preview" instead of "npm run dev".
    # "npm run dev" starts the hot-reload Vite server (correct for development).
    # "npm run preview" serves the compiled production build (correct for staging/demo).
    $npmCommand = if ($Prod) {
        @"
Write-Host "[Frontend] Building production bundle..." -ForegroundColor Cyan
npm run build
if (`$LASTEXITCODE -ne 0) { Write-Host "[Frontend] Build failed." -ForegroundColor Red; Read-Host "Press Enter to close"; exit 1 }
Write-Host "[Frontend] Serving production preview on $frontendUrl ..." -ForegroundColor Cyan
npm run preview
"@
    } else {
        "npm run dev"
    }

    Write-Info "Starting Vite server on $frontendUrl"
    Write-Info "Opening new PowerShell window for frontend..."

    # BUG FIX #2 (continued) + BUG FIX #6 (continued): unique name + try/catch.
    $tempFrontendScript = New-TempPs1 "frontend"
    try {
        @"
Set-Location '$frontendDir'
Write-Host "[Frontend] Starting development server..." -ForegroundColor Cyan
$npmCommand
"@ | Out-File -FilePath $tempFrontendScript -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Error-Custom "Failed to write frontend launcher script to temp: $_"
        Write-Info "Check that $env:TEMP is writable."
        exit 1
    }

    Start-Process powershell -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$tempFrontendScript`""
    Write-OK "Frontend process spawned (new window)"
    Start-Sleep -Seconds 2
}

# ============================================================================
# SUMMARY
# ============================================================================
Write-Section "=================================="
Write-Section "Startup Complete!"
Write-Section "=================================="

if (-not $SkipBackend) {
    Write-OK "Backend :  http://127.0.0.1:8000"
    Write-Info "  API docs : http://127.0.0.1:8000/docs"
    Write-Info "  ReDoc    : http://127.0.0.1:8000/redoc"
    if ($Prod) {
        Write-Warning-Custom "  --reload is DISABLED (production mode)"
    } else {
        Write-Info "  --reload is ENABLED (development mode)"
    }
}

if (-not $SkipFrontend) {
    # BUG FIX #1 (continued) - Use resolved $frontendUrl everywhere in summary.
    Write-OK "Frontend : $frontendUrl"
}

Write-Section "Quick Links:"
Write-Info "Register : $frontendUrl/register"
Write-Info "Login    : $frontendUrl/login"
Write-Info "Scan UI  : $frontendUrl/scan"

if (-not $NoOpen) {
    Write-Section "Opening browser..."
    Start-Sleep -Seconds 2
    # BUG FIX #1 (continued) - open $frontendUrl, not hardcoded localhost:3000.
    Start-Process $frontendUrl
}

Write-Section "To stop the servers:"
Write-Info "Close the PowerShell windows or press Ctrl+C in each window"

Write-Section "Database info:"
$backendEnvFile = Join-Path $backendDir ".env"
$configuredDatabaseUrl = $env:DATABASE_URL

if (-not $configuredDatabaseUrl -and (Test-Path $backendEnvFile)) {
    $dbLine = Get-Content $backendEnvFile |
        Where-Object { $_ -match '^\s*DATABASE_URL\s*=' } |
        Select-Object -First 1

    if ($dbLine) {
        $configuredDatabaseUrl = ($dbLine -split '=', 2)[1].Trim()
    }
}

if ($configuredDatabaseUrl -like "postgresql://*") {
    Write-Info "Configured database: PostgreSQL (from Backend/.env or current shell)"
} elseif ($configuredDatabaseUrl -like "sqlite:///*") {
    Write-Info "Configured database: SQLite"
    Write-Info "SQLite file: Backend/ccure_users.db"
} else {
    Write-Info "Configured database: fallback to SQLite"
    Write-Info "Set DATABASE_URL in Backend/.env to switch between SQLite and PostgreSQL"
}

Write-Info "Backend/.env controls the app database unless DATABASE_URL is already set in the current shell"

Write-Section "=================================="
