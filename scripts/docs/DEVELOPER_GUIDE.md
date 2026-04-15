# Developer Guide

Covers the development environment scripts: `startup.ps1` (launches backend + frontend) and `run_tests.ps1` (runs the pytest suite). Neither script existed in the original documentation.

---

## Project Structure

```
project/
├── Backend/
│   ├── main.py                 FastAPI application entry point
│   ├── requirements.txt        Python dependencies
│   ├── .venv/                  Python virtual environment (created on first start)
│   ├── .venv/.requirements_hash  SHA256 of requirements.txt (pip-install cache key)
│   ├── ccure_users.db          SQLite development database
│   └── tests/
│       ├── test_auth.py        Authentication tests (TestAuth)
│       ├── test_scans.py       Scan phase tests (TestScansPhase1/2/3, TestLegacyEndpoints, TestErrorHandling)
│       └── test_*.py           Other test files
└── Frontend/
    ├── vite.config.js          Vite config (port resolved automatically by startup.ps1)
    ├── node_modules/           npm packages (installed on first start)
    └── src/
```

---

## startup.ps1 — Development Launcher

Spawns the FastAPI backend and React/Vite frontend in separate PowerShell windows, with optional dependency installation and browser auto-open.

### Usage

```powershell
# Development mode (default) — uvicorn with --reload, Vite dev server
PowerShell -ExecutionPolicy Bypass -File startup.ps1

# Production/staging — uvicorn without --reload, Vite preview build
PowerShell -ExecutionPolicy Bypass -File startup.ps1 -Prod

# Skip browser auto-open
PowerShell -ExecutionPolicy Bypass -File startup.ps1 -NoOpen

# Start backend only
PowerShell -ExecutionPolicy Bypass -File startup.ps1 -SkipFrontend

# Start frontend only (backend already running)
PowerShell -ExecutionPolicy Bypass -File startup.ps1 -SkipBackend
```

### Parameters

| Parameter | Type | Description |
|---|---|---|
| `-Prod` | Switch | Use `uvicorn` without `--reload`; run `npm run build && npm run preview` instead of `npm run dev` |
| `-NoOpen` | Switch | Do not open the browser automatically |
| `-SkipBackend` | Switch | Skip backend startup (frontend only) |
| `-SkipFrontend` | Switch | Skip frontend startup (backend only) |

### What It Does

**Backend startup:**
1. Creates `.venv` if missing: `python -m venv .venv`
2. Checks SHA256 of `requirements.txt` against `.venv/.requirements_hash`. Runs `pip install -q -r requirements.txt` only if the hash changed or the cache file is absent. Updates the cache after a successful install.
3. Writes a uniquely-named temp launcher script (`$env:TEMP\ccure_backend_<guid>.ps1`) — unique names prevent concurrent startup collisions.
4. Spawns the script in a new PowerShell window.
5. Polls `http://127.0.0.1:8000/` up to 30 times at 2-second intervals (60s total). Reports each attempt. Warns clearly but does not abort if the backend is slow to start.

**Frontend startup:**
1. Runs `npm install --silent` if `node_modules/` is missing.
2. Reads `vite.config.js` / `vite.config.ts` / `vite.config.mjs` to extract the configured port. Falls back to Vite's default of **5173** (not 3000) if no port is specified.
3. In `-Prod` mode runs `npm run build` then `npm run preview`. In dev mode runs `npm run dev`.
4. Writes a uniquely-named temp launcher script and spawns it in a new PowerShell window.

**Summary output:**

```
Backend :  http://127.0.0.1:8000
  API docs : http://127.0.0.1:8000/docs
  ReDoc    : http://127.0.0.1:8000/redoc
Frontend : http://localhost:5173      ← resolved from vite.config, not hardcoded
```

### URLs

| Endpoint | URL |
|---|---|
| Frontend (dev) | `http://localhost:5173` (or as configured in `vite.config.js`) |
| Backend API | `http://127.0.0.1:8000` |
| Swagger UI | `http://127.0.0.1:8000/docs` |
| ReDoc | `http://127.0.0.1:8000/redoc` |
| Register | `http://localhost:<vitePort>/register` |
| Login | `http://localhost:<vitePort>/login` |
| Scan UI | `http://localhost:<vitePort>/scan` |

### Databases

| Mode | Database |
|---|---|
| Development | `Backend/ccure_users.db` (SQLite, created automatically) |
| PostgreSQL | Set `$env:DATABASE_URL = 'postgresql://user:password@localhost:5432/ccure_db'` before starting |

### Manual Backend Start (without startup.ps1)

```powershell
cd Backend
.\.venv\Scripts\python.exe -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

---

## run_tests.ps1 — Test Runner

Invokes pytest against `Backend/tests/` inside the project's virtual environment. Validates that the API is reachable before running, injects a separate test database to avoid polluting the development database, and supports selective test-class execution.

### Prerequisites

- Backend virtual environment created (`Backend/.venv/`)
- `pytest` installed (`pip install -r requirements.txt`)
- Backend running at `http://127.0.0.1:8000/` (start with `startup.ps1` or manually)

### Usage

```powershell
# All tests
PowerShell -ExecutionPolicy Bypass -File run_tests.ps1

# Specific test group
PowerShell -ExecutionPolicy Bypass -File run_tests.ps1 -TestType auth
PowerShell -ExecutionPolicy Bypass -File run_tests.ps1 -TestType phase1
PowerShell -ExecutionPolicy Bypass -File run_tests.ps1 -TestType coverage
```

### Test Types

| `-TestType` | File | Class | Description |
|---|---|---|---|
| `all` (default) | `tests/` (all files) | — | Entire suite |
| `auth` | `test_auth.py` | `TestAuth` | Authentication endpoints |
| `phase1` | `test_scans.py` | `TestScansPhase1` | Scan phase 1 endpoints |
| `phase2` | `test_scans.py` | `TestScansPhase2` | Scan phase 2 endpoints |
| `phase3` | `test_scans.py` | `TestScansPhase3` | Scan phase 3 endpoints |
| `legacy` | `test_scans.py` | `TestLegacyEndpoints` | Legacy endpoint compatibility |
| `errors` | `test_scans.py` | `TestErrorHandling` | Error handling |
| `coverage` | `tests/` (all files) | — | Full suite + HTML + terminal coverage |

### What It Does

1. **API health check with retry.** Polls `http://127.0.0.1:8000/` up to 10 times at 3-second intervals (30s total) before giving up. The backend may take several seconds to start (migrations, CVE DB load).

2. **venv and pytest validation.** Confirms `Backend/.venv/Scripts/python.exe` exists and `python -m pytest --version` succeeds. Prints actionable install commands if either check fails.

3. **Test directory validation.** Confirms `Backend/tests/` exists. For class-specific selectors, confirms the target `.py` file exists before invoking pytest, so errors are clear rather than cryptic pytest collection failures.

4. **Environment variable injection (test isolation).**
   ```
   DATABASE_URL = sqlite:///./test_ccure.db
   TEST_MODE    = 1
   ```
   These apply only to the pytest process, not to the already-running backend. They protect tests that instantiate the app directly (e.g., via `TestClient(app=app)`). The original environment is restored after the run, even if tests fail.

5. **Isolated database cleanup.** On a clean pass (`pytest` exit code 0) the runner removes `Backend/test_ccure.db`. On failure, it is left for post-mortem inspection.

6. **Coverage scope (for `-TestType coverage`).** Coverage is scoped to `engines`, `core`, `auth`, and `scans` modules only — not the `tests/` directory itself, which would inflate the denominator and underreport real coverage.

### Coverage Report

```powershell
PowerShell -ExecutionPolicy Bypass -File run_tests.ps1 -TestType coverage

# HTML report
Start-Process "Backend\htmlcov\index.html"
```

Coverage is written to `Backend/htmlcov/index.html` and also printed as a terminal summary.

### Debugging a Failing Test

```powershell
# Run one specific test with full output (from project root)
cd Backend
.\.venv\Scripts\python.exe -m pytest tests\test_scans.py::TestScansPhase1::test_create_scan -v -s
```

### Environment Variables Reference

| Variable | Set by runner | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./test_ccure.db` | Separate DB for tests that use `TestClient(app=app)` |
| `TEST_MODE` | `1` | Lets the FastAPI app skip production startup side-effects (e.g., CVE DB preload) |

---

## First-Time Setup

```powershell
# 1. Clone the repository and navigate to it

# 2. Start everything (creates venv and installs dependencies automatically)
PowerShell -ExecutionPolicy Bypass -File startup.ps1

# 3. In a separate terminal, run the test suite (requires backend to be running)
PowerShell -ExecutionPolicy Bypass -File run_tests.ps1
```

No manual `pip install` or `npm install` is needed — both scripts handle dependency installation automatically on first run, and skip it on subsequent runs when nothing has changed.
