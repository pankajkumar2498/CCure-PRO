# ============================================================================
# Ccure Audit PRO - Startup Script
# ============================================================================
# Launches both Backend (FastAPI) and Frontend (React) in parallel
# Usage:
#   PowerShell -ExecutionPolicy Bypass -File startup.ps1
# ============================================================================

param(
    [switch]$SkipBackend,
    [switch]$SkipFrontend,
    [switch]$NoOpen
)

$ErrorActionPreference = "Stop"

# Colors for console output
function Write-Info { Write-Host "[INFO]  $args" -ForegroundColor Cyan }
function Write-Success { Write-Host "[✓]    $args" -ForegroundColor Green }
function Write-Error-Custom { Write-Host "[✗]    $args" -ForegroundColor Red }
function Write-Section { Write-Host "`n$args" -ForegroundColor Yellow -BackgroundColor Black }

Write-Section "=================================="
Write-Section "Ccure Audit PRO Startup"
Write-Section "=================================="

# Get script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendDir = Join-Path $scriptDir "Backend"
$frontendDir = Join-Path $scriptDir "Frontend"

# Verify directories exist
if (-not (Test-Path $backendDir)) {
    Write-Error-Custom "Backend directory not found at $backendDir"
    exit 1
}

if (-not (Test-Path $frontendDir)) {
    Write-Error-Custom "Frontend directory not found at $frontendDir"
    exit 1
}

Write-Success "Project root: $scriptDir"

# ============================================================================
# BACKEND STARTUP
# ============================================================================
if (-not $SkipBackend) {
    Write-Section "[1/2] Starting Backend (FastAPI)..."
    
    # Check if venv exists
    $venvPath = Join-Path $backendDir ".venv"
    if (-not (Test-Path $venvPath)) {
        Write-Info "Virtual environment not found. Creating one..."
        Push-Location $backendDir
        python -m venv .venv
        Write-Success "Virtual environment created"
        Pop-Location
    }
    
    # Activate venv and check dependencies
    $activateScript = Join-Path $backendDir ".venv\Scripts\Activate.ps1"
    if (-not (Test-Path $activateScript)) {
        Write-Error-Custom "Could not find activation script at $activateScript"
        exit 1
    }
    
    # Create temporary backend startup script
    Write-Info "Starting FastAPI server on http://127.0.0.1:8000"
    Write-Info "Opening new PowerShell window for backend..."
    
    $tempBackendScript = Join-Path $env:TEMP "ccure_backend_startup.ps1"
    
    @"
Set-Location '$backendDir'
& '$activateScript'
Write-Host "[Backend] Installing/verifying dependencies..." -ForegroundColor Cyan
pip install -q -r requirements.txt
Write-Host "[Backend] Dependencies ready" -ForegroundColor Green
Write-Host "[Backend] Starting FastAPI server..." -ForegroundColor Cyan
uvicorn main:app --reload --host 127.0.0.1 --port 8000
"@ | Out-File -FilePath $tempBackendScript -Encoding UTF8
    
    Start-Process powershell -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$tempBackendScript`""
    Write-Success "Backend process started (new window will open)"
    Start-Sleep -Seconds 3
}

# ============================================================================
# FRONTEND STARTUP
# ============================================================================
if (-not $SkipFrontend) {
    Write-Section "[2/2] Starting Frontend (React)..."
    
    # Check if node_modules exists
    $nodeModules = Join-Path $frontendDir "node_modules"
    if (-not (Test-Path $nodeModules)) {
        Write-Info "Dependencies not installed. Installing npm packages..."
        Push-Location $frontendDir
        npm install --silent
        Write-Success "npm packages installed"
        Pop-Location
    }
    
    Write-Info "Starting Vite development server on http://localhost:3000"
    Write-Info "Opening new PowerShell window for frontend..."
    
    $tempFrontendScript = Join-Path $env:TEMP "ccure_frontend_startup.ps1"
    
    @"
Set-Location '$frontendDir'
Write-Host "[Frontend] Starting development server..." -ForegroundColor Cyan
npm run dev
"@ | Out-File -FilePath $tempFrontendScript -Encoding UTF8
    
    Start-Process powershell -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$tempFrontendScript`""
    Write-Success "Frontend process started (new window will open)"
    Start-Sleep -Seconds 2
}

# ============================================================================
# SUMMARY & NEXT STEPS
# ============================================================================
Write-Section "=================================="
Write-Section "Startup Complete!"
Write-Section "=================================="

if (-not $SkipBackend) {
    Write-Success "Backend running at: http://127.0.0.1:8000"
    Write-Info "  API docs:  http://127.0.0.1:8000/docs"
    Write-Info "  ReDoc:     http://127.0.0.1:8000/redoc"
}

if (-not $SkipFrontend) {
    Write-Success "Frontend running at: http://localhost:3000"
}

Write-Section "Quick Links:"
Write-Info "Register:  http://localhost:3000/register"
Write-Info "Login:     http://localhost:3000/login"
Write-Info "Scan UI:   http://localhost:3000/scan"

if (-not $NoOpen) {
    Write-Section "Opening browser..."
    Start-Sleep -Seconds 2
    Start-Process "http://localhost:3000"
}

Write-Section "To test the API:"
Write-Info "1. Register a new account at /register"
Write-Info "2. Login with your credentials at /login"
Write-Info "3. Navigate to /scan to perform scans"
Write-Info "4. Check backend logs in the backend PowerShell window"

Write-Section "To stop the servers:"
Write-Info "Close the PowerShell windows or press Ctrl+C in each window"

Write-Section "Database info:"
Write-Info "SQLite database: Backend/ccure_users.db"
Write-Info "To switch to PostgreSQL, set: `$env:DATABASE_URL='postgresql://user:password@localhost:5432/ccure_db'"

Write-Section "=================================="
