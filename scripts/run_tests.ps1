# ============================================================================
# Ccure Audit PRO - Quick Test Runner
# ============================================================================

param(
    [ValidateSet("all", "auth", "phase1", "phase2", "phase3", "legacy", "errors", "coverage")]
    [string]$TestType = "all"
)

$ErrorActionPreference = "Stop"

$backendDir = Join-Path $PSScriptRoot "Backend"
$venvPython = Join-Path $backendDir ".venv\Scripts\python.exe"

function Write-Info { Write-Host "[INFO]  $args" -ForegroundColor Cyan }
function Write-Success { Write-Host "[OK]    $args" -ForegroundColor Green }
function Write-Error-Custom { Write-Host "[ERR]   $args" -ForegroundColor Red }
function Write-Section { Write-Host "`n$args" -ForegroundColor Yellow -BackgroundColor Black }

Write-Section "=================================="
Write-Section "Ccure Audit PRO - Test Suite"
Write-Section "=================================="

Write-Info "Checking if API is running at http://127.0.0.1:8000..."
try {
    $null = Invoke-WebRequest -Uri "http://127.0.0.1:8000/" -UseBasicParsing -TimeoutSec 2
    Write-Success "API is accessible"
}
catch {
    Write-Error-Custom "API is not running"
    Write-Info "Start the backend with:"
    Write-Info "  cd Backend"
    Write-Info "  .\.venv\Scripts\python.exe -m uvicorn main:app --reload --host 127.0.0.1 --port 8000"
    Write-Info "Or use startup.ps1 to launch everything automatically"
    exit 1
}

if (-not (Test-Path $venvPython)) {
    Write-Error-Custom "Backend virtual environment not found at $venvPython"
    Write-Info "Create it with:"
    Write-Info "  cd Backend"
    Write-Info "  python -m venv .venv"
    Write-Info "  .\.venv\Scripts\python.exe -m pip install -r requirements.txt"
    exit 1
}

Write-Info "Checking pytest installation in Backend\.venv..."
try {
    & $venvPython -m pytest --version | Out-Null
}
catch {
    Write-Error-Custom "pytest is not installed in Backend\.venv"
    Write-Info "Install backend dependencies with:"
    Write-Info "  .\.venv\Scripts\python.exe -m pip install -r requirements.txt"
    exit 1
}

Push-Location $backendDir

Write-Section "Running Tests: $TestType"

$testArgs = switch ($TestType) {
    "all" {
        @("-m", "pytest", "test_integration.py", "-v")
    }
    "auth" {
        Write-Info "Running Authentication Tests..."
        @("-m", "pytest", "test_integration.py::TestAuth", "-v")
    }
    "phase1" {
        Write-Info "Running Phase 1 Tests..."
        @("-m", "pytest", "test_integration.py::TestScansPhase1", "-v")
    }
    "phase2" {
        Write-Info "Running Phase 2 Tests..."
        @("-m", "pytest", "test_integration.py::TestScansPhase2", "-v")
    }
    "phase3" {
        Write-Info "Running Phase 3 Tests..."
        @("-m", "pytest", "test_integration.py::TestScansPhase3", "-v")
    }
    "legacy" {
        Write-Info "Running Legacy Endpoint Tests..."
        @("-m", "pytest", "test_integration.py::TestLegacyEndpoints", "-v")
    }
    "errors" {
        Write-Info "Running Error Handling Tests..."
        @("-m", "pytest", "test_integration.py::TestErrorHandling", "-v")
    }
    "coverage" {
        Write-Info "Running Tests with Coverage Report..."
        @("-m", "pytest", "test_integration.py", "-v", "--cov=.", "--cov-report=html", "--cov-report=term")
    }
}

Write-Info "$venvPython $($testArgs -join ' ')"
& $venvPython @testArgs

$exitCode = $LastExitCode

Pop-Location

Write-Section "Test Run Complete"

if ($exitCode -eq 0) {
    Write-Success "All tests passed"

    if ($TestType -eq "coverage") {
        Write-Info "Coverage report generated - open Backend\htmlcov\index.html to view"
    }
}
else {
    Write-Error-Custom "Some tests failed (exit code: $exitCode)"
    Write-Info "To debug, run with -v -s flags:"
    Write-Info "  cd Backend"
    Write-Info "  .\.venv\Scripts\python.exe -m pytest test_integration.py::TestClassName::test_name -v -s"
}

exit $exitCode
