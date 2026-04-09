# 🎯 Ccure Audit PRO - Quick Reference Card

## One-Command Startup
```powershell
PowerShell -ExecutionPolicy Bypass -File startup.ps1
```
✅ Launches backend + frontend + opens browser

---

## Quick Test Commands

| Task | Command |
|------|---------|
| **Run all tests** | `PowerShell -ExecutionPolicy Bypass -File run_tests.ps1` |
| **Run auth tests** | `run_tests.ps1 -TestType auth` |
| **Run phase1 tests** | `run_tests.ps1 -TestType phase1` |
| **Run phase2 tests** | `run_tests.ps1 -TestType phase2` |
| **Run phase3 tests** | `run_tests.ps1 -TestType phase3` |
| **Run legacy tests** | `run_tests.ps1 -TestType legacy` |
| **Run with coverage** | `run_tests.ps1 -TestType coverage` |

---

## Manual Test Execution

```powershell
cd Backend
.\.venv\Scripts\activate

# All tests
pytest test_integration.py -v

# Specific class
pytest test_integration.py::TestAuth -v

# Specific test
pytest test_integration.py::TestAuth::test_3_login_success -v

# Pattern matching
pytest test_integration.py -k "auth" -v

# With coverage
pytest test_integration.py -v --cov=. --cov-report=html
```

---

## First Time Setup (5 minutes)

```powershell
# 1. Backend dependencies
cd Backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt

# 2. Frontend dependencies
cd ..\Frontend
npm install

# 3. Start everything
cd ..
PowerShell -ExecutionPolicy Bypass -File startup.ps1

# 4. Register account at http://localhost:3000/register
# 5. Login and start using
```

---

## Access Points

| Service | URL | Purpose |
|---------|-----|---------|
| **Frontend** | http://localhost:3000 | Web UI |
| **API Docs** | http://127.0.0.1:8000/docs | Interactive documentation |
| **ReDoc** | http://127.0.0.1:8000/redoc | Alternative API docs |
| **Login** | http://localhost:3000/login | User login |
| **Register** | http://localhost:3000/register | New account |
| **Scan UI** | http://localhost:3000/scan | Main scanning UI |

---

## Test Suite Overview

**Total Tests: 25**

```
TestAuth                  [10 tests] ✓
├─ API Health
├─ Register User
├─ Login (valid/invalid)
├─ Get Current User
├─ Token Refresh
└─ Error Cases

TestScansPhase1           [3 tests] ✓
├─ Without Auth (expect 403/401)
├─ With Invalid Token (expect 401)
└─ With Valid Token (expect 200)

TestScansPhase2           [3 tests] ✓
├─ Without Auth
├─ Invalid Token
└─ Valid Token

TestScansPhase3           [3 tests] ✓
├─ Without Auth
├─ Invalid Token
└─ Valid Token

TestLegacyEndpoints       [4 tests] ✓
├─ /scan/host
├─ /scan/range
└─ /scan/subnet

TestErrorHandling         [2 tests] ✓
├─ Malformed JSON
└─ Missing Fields
```

---

## Environment Setup

### Backend
```powershell
cd Backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### Frontend
```powershell
cd Frontend
npm install
```

### Test Dependencies
```powershell
cd Backend
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

---

## Manual Backend Startup
```powershell
cd Backend
.\.venv\Scripts\activate
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

---

## Manual Frontend Startup
```powershell
cd Frontend
npm run dev
```

---

## Troubleshooting

### API Not Running
```powershell
cd Backend
.\.venv\Scripts\activate
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

### Port 8000 Already in Use
```powershell
# Find process
netstat -ano | findstr :8000

# Kill process (replace PID)
taskkill /PID <PID> /F

# Or use different port
uvicorn main:app --reload --port 8001
```

### pytest Not Found
```powershell
cd Backend
.\.venv\Scripts\activate
pip install pytest pytest-cov requests
```

### Clear Database
```powershell
# Remove SQLite file
Remove-Item Backend\ccure_users.db

# Backend recreates on startup
```

---

## API Endpoints (All Protected with JWT)

### Authentication
- `POST /auth/register` - Create account
- `POST /auth/login` - Get tokens
- `GET /auth/me` - Current user
- `POST /auth/refresh` - New access token
- `POST /auth/logout` - Logout

### Scans
- `POST /scan/phase1` - Discovery
- `POST /scan/phase2` - Port scanning
- `POST /scan/phase3` - Vulnerability audit
- `POST /scan/phases` - Multi-phase
- `POST /scan/host` - Single host (legacy)
- `POST /scan/range` - IP range (legacy)
- `POST /scan/subnet` - CIDR subnet (legacy)
- `POST /scan/subnets` - Multiple subnets (legacy)

---

## Test A Feature

### Test Auth Flow
```powershell
run_tests.ps1 -TestType auth
```

### Test Phase 1
```powershell
run_tests.ps1 -TestType phase1
```

### Test All Protected Endpoints
```powershell
cd Backend
.\.venv\Scripts\activate
pytest test_integration.py -k "phase" -v
```

### Test Authorization (401/403)
```powershell
cd Backend
.\.venv\Scripts\activate
pytest test_integration.py -k "without_auth or invalid_token" -v
```

---

## Documentation Files

| File | Purpose |
|------|---------|
| **SUMMARY.md** | Overview of everything created |
| **GETTING_STARTED.md** | Complete setup guide (read first) |
| **TEST_GUIDE.md** | Detailed testing documentation |
| **startup.ps1** | Auto-start script (run this) |
| **run_tests.ps1** | Test runner with options |

---

## Key Test Files

| File | Location |
|------|----------|
| Test Suite | `Backend/test_integration.py` |
| Test Dependencies | `Backend/requirements.txt` |
| Test Runner | `run_tests.ps1` (root) |

---

## Expected Test Output

### All Passing (25/25)
```
======================== 25 passed in 15.23s ==========================
```

### Individual Test Passing
```
test_integration.py::TestAuth::test_3_login_success PASSED [12%]
  → POST /auth/login with valid credentials
✓ Login successful - User: test_12345@example.com
```

### All Tests Summary
```
test_integration.py::TestAuth (10 tests) ✓
test_integration.py::TestScansPhase1 (3 tests) ✓
test_integration.py::TestScansPhase2 (3 tests) ✓
test_integration.py::TestScansPhase3 (3 tests) ✓
test_integration.py::TestLegacyEndpoints (4 tests) ✓
test_integration.py::TestErrorHandling (2 tests) ✓
```

---

## Git Commands (If Using Version Control)

```powershell
# Initialize repo
git init
git add .
git commit -m "Initial commit with test suite"

# Create test branch
git checkout -b add-tests
git push origin add-tests
```

---

## Performance Notes

- **Auth endpoints**: ~50-100ms
- **Phase 1 scan**: Variable (depends on network)
- **Phase 2 scan**: Variable (depends on ports)
- **Phase 3 audit**: Variable (depends on targets)
- **Test suite**: ~15-20 seconds for all 25 tests

---

## Database

### Development
```
Backend/ccure_users.db  (SQLite - auto-created)
```

### Production
```powershell
$env:DATABASE_URL = 'postgresql://user:password@localhost:5432/ccure_db'
```

---

## Useful Keyboard Shortcuts

| Action | Command |
|--------|---------|
| Stop backend | `Ctrl+C` in backend terminal |
| Stop frontend | `Ctrl+C` in frontend terminal |
| Clear terminal | `clear` or `cls` |
| Stop tests | `Ctrl+C` |

---

## Browser DevTools Tricks

### Get Access Token
```javascript
console.log(localStorage.getItem('access_token'))
```

### Get Refresh Token
```javascript
console.log(localStorage.getItem('refresh_token'))
```

### Decode JWT
```javascript
const token = localStorage.getItem('access_token');
const [h, p, s] = token.split('.');
console.log(JSON.parse(atob(p)));
```

### Clear All Storage
```javascript
localStorage.clear();
```

---

## What's Included

✅ **startup.ps1** - One-command launcher
✅ **test_integration.py** - 25 comprehensive tests
✅ **run_tests.ps1** - Quick test runner
✅ **requirements.txt** - App and test dependencies
✅ **GETTING_STARTED.md** - Setup guide
✅ **TEST_GUIDE.md** - Testing guide
✅ **SUMMARY.md** - Overview document
✅ **QUICK_REFERENCE.md** - This file

---

## Next Steps

1. **Read GETTING_STARTED.md** - Complete guide
2. **Run startup.ps1** - Start everything
3. **Register account** - http://localhost:3000/register
4. **Run tests** - `run_tests.ps1`
5. **Check API docs** - http://127.0.0.1:8000/docs

---

## Support Resources

Looking for help?

- **Setup Issues**: See GETTING_STARTED.md
- **Testing Issues**: See TEST_GUIDE.md
- **API Issues**: Check http://127.0.0.1:8000/docs
- **Authentication**: Review test_integration.py TestAuth class
- **Protected Endpoints**: Review TestScansPhase* classes

---

**Ready? Start with:**
```powershell
PowerShell -ExecutionPolicy Bypass -File startup.ps1
```

Then visit http://localhost:3000 🚀
