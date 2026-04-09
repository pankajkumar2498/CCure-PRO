# ============================================================================
# Ccure Audit PRO - Test Suite Documentation
# ============================================================================

## Overview

This document explains how to run the comprehensive test suite for Ccure Audit PRO.

The test suite covers:
- ✅ **Authentication** (register, login, logout, token refresh)
- ✅ **Protected Endpoints** (phase1, phase2, phase3, phases)
- ✅ **Legacy Endpoints** (scan_host, scan_range, scan_subnet)
- ✅ **Authorization** (token validation, 401/403 errors)
- ✅ **Error Handling** (malformed requests, missing fields)

## Prerequisites

1. **Backend API Running**
   - Start the backend server: `uvicorn main:app --reload --host 127.0.0.1 --port 8000`
   - Verify it's running at: http://127.0.0.1:8000

2. **Python Virtual Environment**
   - Create venv in Backend folder: `python -m venv .venv`
   - Activate: `.\.venv\Scripts\activate` (Windows)

3. **Install Test Dependencies**
   - Install pytest: `pip install pytest pytest-cov requests`
   - Or use provided file: `pip install -r test-requirements.txt`

## Quick Start - Run All Tests

### Option 1: Automatic Startup (Recommended)

```powershell
# From project root, run startup script (both backend and frontend)
PowerShell -ExecutionPolicy Bypass -File startup.ps1

# Then in another PowerShell window, run tests
cd Backend
.\.venv\Scripts\activate
pytest test_integration.py -v
```

### Option 2: Manual Backend Start

```powershell
# Terminal 1: Start Backend
cd Backend
.\.venv\Scripts\activate
uvicorn main:app --reload --host 127.0.0.1 --port 8000

# Terminal 2: Run Tests
cd Backend
.\.venv\Scripts\activate
pytest test_integration.py -v
```

## Test Suite Details

### Test Classes & Coverage

#### 1. TestAuth (10 tests)
Authentication and token management tests:

```
✓ test_1_api_health              → Verify API is running
✓ test_2_register_success         → User registration works
✓ test_3_login_success            → Valid login returns tokens
✓ test_4_login_invalid_password   → Invalid credentials rejected (401)
✓ test_5_login_nonexistent_user   → Nonexistent user rejected (401)
✓ test_6_get_current_user         → GET /auth/me with valid token
✓ test_7_me_without_token         → Missing token rejected (403/401)
✓ test_8_me_with_invalid_token    → Invalid token rejected (401)
✓ test_9_refresh_token            → Token refresh works
✓ test_10_refresh_with_invalid_token → Invalid refresh token rejected (401)
```

#### 2. TestScansPhase1 (3 tests)
Phase 1 (Discovery) endpoint authorization:

```
✓ test_1_phase1_without_auth      → No token returns 403/401
✓ test_2_phase1_with_invalid_token → Invalid token returns 401
✓ test_3_phase1_with_auth         → Valid token accepted
```

#### 3. TestScansPhase2 (3 tests)
Phase 2 (Port Scanning) endpoint authorization:

```
✓ test_1_phase2_without_auth      → No token returns 403/401
✓ test_2_phase2_with_invalid_token → Invalid token returns 401
✓ test_3_phase2_with_auth         → Valid token accepted
```

#### 4. TestScansPhase3 (3 tests)
Phase 3 (Vulnerability Audit) endpoint authorization:

```
✓ test_1_phase3_without_auth      → No token returns 403/401
✓ test_2_phase3_with_invalid_token → Invalid token returns 401
✓ test_3_phase3_with_auth         → Valid token accepted
```

#### 5. TestLegacyEndpoints (4 tests)
Backward compatibility for traditional scan endpoints:

```
✓ test_1_scan_host_without_auth   → /scan/host protected
✓ test_2_scan_host_with_auth      → /scan/host accessible with token
✓ test_3_scan_range_without_auth  → /scan/range protected
✓ test_4_scan_subnet_without_auth → /scan/subnet protected
```

#### 6. TestErrorHandling (2 tests)
Error scenarios and edge cases:

```
✓ test_1_malformed_json           → Malformed JSON rejected (400/422)
✓ test_2_missing_required_fields  → Missing fields rejected (400/422)
```

**Total: 25 comprehensive tests**

## Running Tests

### Run All Tests (with output)
```powershell
pytest test_integration.py -v
```

Expected output:
```
test_integration.py::TestAuth::test_1_api_health PASSED              [4%]
test_integration.py::TestAuth::test_2_register_success PASSED        [8%]
test_integration.py::TestAuth::test_3_login_success PASSED           [12%]
...
========================= 25 passed in 15.23s ==========================
```

### Run Specific Test Class
```powershell
# Auth tests only
pytest test_integration.py::TestAuth -v

# Phase 1 tests only
pytest test_integration.py::TestScansPhase1 -v

# Legacy endpoints only
pytest test_integration.py::TestLegacyEndpoints -v
```

### Run Specific Test
```powershell
# Test token refresh
pytest test_integration.py::TestAuth::test_9_refresh_token -v

# Test Phase 1 without auth
pytest test_integration.py::TestScansPhase1::test_1_phase1_without_auth -v
```

### Run Tests Matching Pattern
```powershell
# All tests with "auth" in name
pytest test_integration.py -k "auth" -v

# All tests with "phase1" in name
pytest test_integration.py -k "phase1" -v

# All tests with "without" in name
pytest test_integration.py -k "without" -v
```

### Run with Coverage Report
```powershell
pytest test_integration.py -v --cov=. --cov-report=html
```

This generates `htmlcov/index.html` with detailed coverage info.

### Run with Short Traceback
```powershell
pytest test_integration.py -v --tb=short
```

### Run Tests Silently (just summary)
```powershell
pytest test_integration.py --quiet
```

### Run with Markers
```powershell
# Run tests marked as "auth"
pytest test_integration.py -m auth -v

# Run tests marked as "scan"
pytest test_integration.py -m scan -v
```

## Test Output Interpretation

### ✅ Successful Test Run
```
test_integration.py::TestAuth::test_3_login_success PASSED [12%]

  → POST /auth/login with valid credentials
✓ Login successful - User: test_12345@example.com
```

**Meaning**: The endpoint accepted the request with valid credentials and returned tokens.

### ❌ Authentication Test Failed
```
test_integration.py::TestScansPhase1::test_1_phase1_without_auth FAILED [25%]

AssertionError: Expected 403 or 401, got 200
✗ Unauthenticated request rejected with 403/401
```

**Meaning**: The endpoint returned 200 (success) when it should have rejected the request (403/401).
**Action**: Check that `Depends(get_current_user)` is present in the endpoint decorator.

### ❌ Token Validation Failed
```
test_integration.py::TestAuth::test_9_refresh_token FAILED [52%]

AssertionError: Expected 200, got 401
✗ Token refresh
  Expected: 200
  Got: 401
  Response: {"detail": "Invalid or expired token"}
```

**Meaning**: Token refresh failed. JWT secret might be mismatched.
**Action**: Verify SECRET_KEY in `auth/jwt_handler.py` is consistent.

### ❌ API Not Accessible
```
ERROR test_integration.py - API not available at http://127.0.0.1:8000: ...
```

**Meaning**: The backend server is not running.
**Action**: 
1. Start backend with: `uvicorn main:app --reload --host 127.0.0.1 --port 8000`
2. Verify it prints: "Uvicorn running on http://127.0.0.1:8000"

## Debugging Failed Tests

### Step 1: Run Backend in Debug Mode
```powershell
# Terminal 1: Backend with detailed logging
cd Backend
.\.venv\Scripts\activate
$env:PYTHONUNBUFFERED = 1
uvicorn main:app --reload --host 127.0.0.1 --port 8000 --log-level debug
```

### Step 2: Run Single Failing Test
```powershell
# Terminal 2: Run the failing test with verbose output
cd Backend
.\.venv\Scripts\activate
pytest test_integration.py::TestAuth::test_9_refresh_token -v -s
```

The `-s` flag shows print statements and full output.

### Step 3: Check Backend Logs
Look for errors in the backend terminal when the test runs.

### Step 4: Verify Token Content
Add this to test for debugging:
```python
def test_debug_token(auth_tokens):
    """Debug: Print token parts"""
    token = auth_tokens['access_token']
    parts = token.split('.')
    print(f"Token parts: {len(parts)}")  # Should be 3
    print(f"Header: {parts[0]}")
    print(f"Payload: {parts[1]}")
    print(f"Signature: {parts[2]}")
```

## Common Issues & Solutions

### Issue: "Connection refused" or "Unable to connect"
**Cause**: Backend not running
**Solution**: 
```powershell
cd Backend
.\.venv\Scripts\activate
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

### Issue: "Test passed but endpoint still unprotected"
**Cause**: Test uses valid token, endpoint returns 200
**Solution**: 
- Verify `Depends(get_current_user)` is in endpoint signature
- Check imports in main.py

### Issue: "40 ModuleNotFoundError: No module named 'pytest'"
**Cause**: pytest not installed
**Solution**: 
```powershell
pip install pytest pytest-cov requests
```

### Issue: "401 Unauthorized" on refresh token
**Cause**: JWT SECRET_KEY mismatch or token expired
**Solution**: 
- Check `auth/jwt_handler.py` SECRET_KEY matches across backend
- Increase token expiration time for testing

### Issue: Tests pass locally but CI/CD fails
**Cause**: Different database or environment
**Solution**: 
- Set `DATABASE_URL` environment variable
- Use PostgreSQL instead of SQLite for test environment

## Continuous Integration (GitHub Actions)

Example `.github/workflows/test.yml`:

```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          cd Backend
          pip install -r requirements.txt
          pip install -r test-requirements.txt
      
      - name: Start API in background
        run: |
          cd Backend
          uvicorn main:app --host 127.0.0.1 --port 8000 &
          sleep 2
      
      - name: Run tests
        run: |
          cd Backend
          pytest test_integration.py -v --tb=short
```

## Test Maintenance

### Adding New Tests

1. Add a new test method to appropriate class:
   ```python
   def test_new_feature(self, headers):
       """Test description"""
       print_test_step("Description of what we're testing")
       
       response = requests.post(
           f"{BASE_URL}/scan/newfeature",
           json={"param": "value"},
           headers=headers,
           timeout=TIMEOUT
       )
       
       assert response.status_code == 200
       print("✓ Feature working correctly")
   ```

2. Run the new test:
   ```powershell
   pytest test_integration.py::TestClassName::test_new_feature -v
   ```

### Updating Test Data

Edit constants at top of file:
```python
TEST_USER = {
    "username": f"testuser_{int(__import__('time').time() * 1000) % 10000}",
    "email": f"test_{int(__import__('time').time() * 1000) % 10000}@example.com",
    "password": "TestPassword123!",
}
```

## Performance Testing

### Load Testing
```powershell
# Install locust
pip install locust

# Create locustfile.py and run
locust -f locustfile.py --host=http://127.0.0.1:8000
```

### Timeout Testing
Tests have 10-second timeouts. To change:
```python
TIMEOUT = 30  # Change from 10
```

## Reporting Issues

When reporting test failures, include:

1. **Full error output**:
   ```powershell
   pytest test_integration.py::FailingTest -v --tb=long > error.log
   ```

2. **System info**:
   ```powershell
   python --version
   pip show pytest requests
   ```

3. **Backend logs** (from uvicorn output)

4. **Steps to reproduce**

## Summary

✅ **25 comprehensive tests** covering authentication, protected endpoints, and error handling
✅ **Simple one-command startup** for backend and frontend
✅ **Flexible test running** - run all tests or specific subsets
✅ **Clear test output** with debugging info
✅ **CI/CD ready** with example GitHub Actions workflow

Run tests regularly to ensure all features are working correctly!
