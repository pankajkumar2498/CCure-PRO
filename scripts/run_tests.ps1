# ============================================================================
# Ccure Audit PRO - Test Runner
# ============================================================================
# Invokes pytest against the Backend test suite inside the project's virtual
# environment. Supports selective test-class execution and coverage reporting.
#
# Usage:
#   # Run all tests
#   PowerShell -ExecutionPolicy Bypass -File run_tests.ps1
#
#   # Run a specific test group
#   PowerShell -ExecutionPolicy Bypass -File run_tests.ps1 -TestType auth
#
#   # Run with HTML coverage report
#   PowerShell -ExecutionPolicy Bypass -File run_tests.ps1 -TestType coverage
#
# Valid -TestType values:
#   all      - Entire test suite (default)
#   auth     - TestAuth class
#   phase1   - TestScansPhase1 class
#   phase2   - TestScansPhase2 class
#   phase3   - TestScansPhase3 class
#   legacy   - TestLegacyEndpoints class
#   errors   - TestErrorHandling class
#   coverage - Full suite + HTML + terminal coverage report
# ============================================================================

param(
    [ValidateSet("all", "auth", "phase1", "phase2", "phase3", "legacy", "errors", "coverage")]
    [string]$TestType = "all"
)

$ErrorActionPreference = "Stop"

# ============================================================================
# PATHS
# ============================================================================
$backendDir  = Join-Path $PSScriptRoot "Backend"
$venvPython  = Join-Path $backendDir ".venv\Scripts\python.exe"

# BUG FIX #1 - test_integration.py does not exist in Backend/.
# The test files live in Backend/tests/ (e.g. test_cve_db.py,
# test_windows_collector.py). Pointing pytest at the non-existent
# test_integration.py made this script dead code — it always exited with a
# pytest "file not found" error, but the parent process misread it as a
# test failure rather than a configuration error, creating a false sense of
# a running (but failing) test suite.
# Fix: Point all test paths at the correct tests/ subdirectory. Each class
# selector also targets tests/ so selective runs resolve correctly.
$testsDir = Join-Path $backendDir "tests"

# ============================================================================
# HELPERS
# ============================================================================
function Write-Info         { Write-Host "[INFO]  $args" -ForegroundColor Cyan }
function Write-OK           { Write-Host "[OK]    $args" -ForegroundColor Green }
function Write-Warning-Custom { Write-Host "[WARN]  $args" -ForegroundColor Yellow }
function Write-Error-Custom { Write-Host "[ERR]   $args" -ForegroundColor Red }
function Write-Section      { Write-Host "`n$args" -ForegroundColor Yellow -BackgroundColor Black }

Write-Section "=================================="
Write-Section "Ccure Audit PRO - Test Suite"
Write-Section "=================================="

# ============================================================================
# API HEALTH CHECK
#
# BUG FIX #3 - Invoke-WebRequest -TimeoutSec 2 is too short.
# The backend may legitimately take 5-15s on cold start (database migrations,
# CVE database load). A 2s timeout caused the test runner to abort with
# "API is not running" during normal startup, forcing developers to manually
# wait and re-run.
# Fix: Retry the health check up to $maxHealthAttempts times with a
# $healthPollS-second gap (default: 10 attempts x 3s = 30s total). Each
# attempt is reported so the developer sees progress rather than a dead cursor.
# If the backend is genuinely down after all retries, the error message and
# startup instructions are still printed.
# ============================================================================
$maxHealthAttempts = 10
$healthPollS       = 3

Write-Info "Checking API at http://127.0.0.1:8000/ (up to $($maxHealthAttempts * $healthPollS)s)..."

$apiReady = $false
for ($attempt = 1; $attempt -le $maxHealthAttempts; $attempt++) {
    try {
        $null = Invoke-WebRequest -Uri "http://127.0.0.1:8000/" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        $apiReady = $true
        break
    } catch {
        if ($attempt -lt $maxHealthAttempts) {
            Write-Info "  API not responding yet... ($attempt/$maxHealthAttempts) - retrying in ${healthPollS}s"
            Start-Sleep -Seconds $healthPollS
        }
    }
}

if (-not $apiReady) {
    Write-Error-Custom "API did not respond after $($maxHealthAttempts * $healthPollS)s."
    Write-Info "Start the backend with:"
    Write-Info "  cd Backend"
    Write-Info "  .\.venv\Scripts\python.exe -m uvicorn main:app --reload --host 127.0.0.1 --port 8000"
    Write-Info "Or use startup.ps1 to launch everything automatically."
    exit 1
}

Write-OK "API is accessible at http://127.0.0.1:8000/"

# ============================================================================
# VIRTUAL ENVIRONMENT CHECK
# ============================================================================
if (-not (Test-Path $venvPython)) {
    Write-Error-Custom "Backend venv not found at: $venvPython"
    Write-Info "Create it with:"
    Write-Info "  cd Backend"
    Write-Info "  python -m venv .venv"
    Write-Info "  .\.venv\Scripts\python.exe -m pip install -r requirements.txt"
    exit 1
}

Write-Info "Checking pytest installation in Backend\.venv..."
try {
    & $venvPython -m pytest --version | Out-Null
} catch {
    Write-Error-Custom "pytest is not installed in the venv."
    Write-Info "Install dependencies:"
    Write-Info "  .\.venv\Scripts\python.exe -m pip install -r requirements.txt"
    exit 1
}

# ============================================================================
# TEST DIRECTORY VALIDATION
#
# BUG FIX #1 (continued) + BUG FIX #2 - No Test-Path validation.
# The original script passed the test path straight to pytest without checking
# whether it existed. A missing or misnamed path produced a cryptic pytest
# "no tests ran" or "ERROR collecting" output rather than a clear error.
# Fix: Validate tests/ exists before building $testArgs. If any test class
# selector resolves to a file that doesn't exist, print the expected layout
# and exit cleanly rather than letting pytest produce a misleading error.
# ============================================================================
if (-not (Test-Path $testsDir)) {
    Write-Error-Custom "Test directory not found at: $testsDir"
    Write-Info "Expected layout:"
    Write-Info "  Backend/"
    Write-Info "  └── tests/"
    Write-Info "      ├── test_cve_db.py"
    Write-Info "      ├── test_windows_collector.py"
    Write-Info "      └── ... (other test_*.py files)"
    exit 1
}

Write-OK "Tests directory found: $testsDir"

# ============================================================================
# ENVIRONMENT VARIABLE INJECTION FOR TEST ISOLATION
#
# BUG FIX #4 - No env var injection before the test run.
# Without it, integration tests read and write the same ccure_users.db used
# by the running development backend. Test data pollutes the dev database and
# tests can interfere with each other (e.g., a user created in TestAuth
# clashes with a pre-existing user from an earlier dev session).
# Fix: Set DATABASE_URL to a separate SQLite file (test_ccure.db) before
# invoking pytest and restore the original value (or unset it) afterward.
# TEST_MODE=1 can be read by the FastAPI app to skip production-only startup
# side-effects (e.g., CVE DB preload) when running under the test runner.
#
# Note: These env vars affect the IN-PROCESS pytest execution only. They do
# NOT reach the already-running backend (which uses its own DB). Integration
# tests that talk to the live API surface will still hit the real backend;
# these vars protect tests that instantiate the app directly (e.g., via
# httpx.AsyncClient / TestClient with app=app).
# ============================================================================
$savedDatabaseUrl = $env:DATABASE_URL
$savedTestMode    = $env:TEST_MODE

$env:DATABASE_URL = "sqlite:///./test_ccure.db"
$env:TEST_MODE    = "1"

Write-Info "Test env: DATABASE_URL=sqlite:///./test_ccure.db  TEST_MODE=1"

# ============================================================================
# BUILD TEST ARGUMENTS
# ============================================================================
Write-Section "Running Tests: $TestType"

# BUG FIX #5 - "--cov=." points coverage at the entire working directory,
# including the tests/ folder itself. pytest, __pycache__, and test helper
# code are counted in the denominator, skewing coverage percentages downward
# and making 80% real coverage look like 55%.
# Fix: Scope coverage to the source packages only: engines, core, auth, scans.
# These match the module structure of Ccure Audit PRO.
$coverageFlags = @(
    "--cov=engines",
    "--cov=core",
    "--cov=auth",
    "--cov=scans",
    "--cov-report=html",
    "--cov-report=term"
)

# BUG FIX #2 (continued) - Validate per-selector file existence.
# For class-specific runs we check that the resolved test file actually exists
# before handing the path to pytest, so the error is ours (clear) not pytest's
# (ambiguous "no tests ran / ERROR collecting").
function Assert-TestFile {
    param([string]$RelPath)
    $fullPath = Join-Path $testsDir $RelPath
    if (-not (Test-Path $fullPath)) {
        Write-Error-Custom "Test file not found: $fullPath"
        Write-Info "Update the -TestType selector in run_tests.ps1 to match an existing file in:"
        Write-Info "  $testsDir"
        # Restore env before exiting
        $env:DATABASE_URL = $savedDatabaseUrl
        $env:TEST_MODE    = $savedTestMode
        Pop-Location
        exit 1
    }
    return $fullPath
}

# BUG FIX #1 (continued) - All selectors now target tests/ directory.
# Class names are preserved so selective runs still work once the actual
# test files use those class names. Update the filenames below to match
# the real test files as the test suite grows.
$testArgs = switch ($TestType) {
    "all" {
        # Run every test_*.py file in the tests/ directory
        @("-m", "pytest", $testsDir, "-v")
    }
    "auth" {
        Write-Info "Running Authentication Tests..."
        $f = Assert-TestFile "test_auth.py"
        @("-m", "pytest", "${f}::TestAuth", "-v")
    }
    "phase1" {
        Write-Info "Running Phase 1 Scan Tests..."
        $f = Assert-TestFile "test_scans.py"
        @("-m", "pytest", "${f}::TestScansPhase1", "-v")
    }
    "phase2" {
        Write-Info "Running Phase 2 Scan Tests..."
        $f = Assert-TestFile "test_scans.py"
        @("-m", "pytest", "${f}::TestScansPhase2", "-v")
    }
    "phase3" {
        Write-Info "Running Phase 3 Scan Tests..."
        $f = Assert-TestFile "test_scans.py"
        @("-m", "pytest", "${f}::TestScansPhase3", "-v")
    }
    "legacy" {
        Write-Info "Running Legacy Endpoint Tests..."
        $f = Assert-TestFile "test_scans.py"
        @("-m", "pytest", "${f}::TestLegacyEndpoints", "-v")
    }
    "errors" {
        Write-Info "Running Error Handling Tests..."
        $f = Assert-TestFile "test_scans.py"
        @("-m", "pytest", "${f}::TestErrorHandling", "-v")
    }
    "coverage" {
        Write-Info "Running full suite with coverage report..."
        @("-m", "pytest", $testsDir, "-v") + $coverageFlags
    }
}

# ============================================================================
# INVOKE PYTEST
# ============================================================================
Push-Location $backendDir

Write-Info "Command: $venvPython $($testArgs -join ' ')"
Write-Host ""

& $venvPython @testArgs

$exitCode = $LASTEXITCODE

Pop-Location

# ============================================================================
# RESTORE ENVIRONMENT VARIABLES
# BUG FIX #4 (continued) - Always restore original env state after the run,
# even if pytest failed, so the caller's session is not permanently mutated.
# ============================================================================
$env:DATABASE_URL = $savedDatabaseUrl
$env:TEST_MODE    = $savedTestMode

# Clean up the isolated test database if tests passed cleanly.
# Leave it on failure so developers can inspect state post-mortem.
if ($exitCode -eq 0) {
    $testDb = Join-Path $backendDir "test_ccure.db"
    if (Test-Path $testDb) {
        Remove-Item $testDb -Force -ErrorAction SilentlyContinue
        Write-Info "Cleaned up isolated test database: test_ccure.db"
    }
}

# ============================================================================
# RESULT SUMMARY
# ============================================================================
Write-Section "Test Run Complete"

if ($exitCode -eq 0) {
    Write-OK "All tests passed."

    if ($TestType -eq "coverage") {
        Write-Info "HTML coverage report: Backend\htmlcov\index.html"
        Write-Info "Coverage scope      : engines, core, auth, scans"
    }
} else {
    Write-Error-Custom "One or more tests failed (pytest exit code: $exitCode)."
    Write-Info ""
    Write-Info "To debug a specific failing test:"
    Write-Info "  cd Backend"
    Write-Info "  .\.venv\Scripts\python.exe -m pytest tests\<file>::<Class>::<test_name> -v -s"
    Write-Info ""
    Write-Info "Isolated test database left in place for inspection: Backend\test_ccure.db"
}

exit $exitCode
