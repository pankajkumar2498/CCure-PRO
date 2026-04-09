# Ccure Audit PRO - Getting Started Guide

## 📋 Quick Navigation

- **[Getting Started](#getting-started)** - First time setup
- **[Running the Application](#running-the-application)** - Start servers
- **[Testing](#testing)** - Run test suite
- **[Architecture](#architecture)** - System overview
- **[Documentation](#documentation)** - Detailed guides

---

## 🚀 Getting Started

### System Requirements

- **Python 3.9+** (for backend)
- **Node.js 16+** (for frontend)
- **Windows PowerShell 5.0+** (recommended) or PowerShell Core

### Installation Steps

#### Step 1: Install Backend Dependencies

```powershell
cd Backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

#### Step 2: Install Frontend Dependencies

```powershell
cd Frontend
npm install
```

#### Step 3: Install Test Dependencies (Optional but Recommended)

```powershell
cd Backend
pip install -r test-requirements.txt
```

---

## 🎯 Running the Application

### Option 1: Automatic Startup (Recommended)

Use the startup script to launch both backend and frontend automatically:

```powershell
# From project root
PowerShell -ExecutionPolicy Bypass -File startup.ps1
```

This will:
- ✅ Create Python virtual environment if needed
- ✅ Install backend dependencies
- ✅ Start FastAPI server on `http://127.0.0.1:8000`
- ✅ Install frontend dependencies if needed
- ✅ Start React development server on `http://localhost:5173`
- ✅ Open your browser to the application

### Option 2: Manual Startup

**Terminal 1: Start Backend**

```powershell
cd Backend
.\.venv\Scripts\activate
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Expected output:
```
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete
```

**Terminal 2: Start Frontend**

```powershell
cd Frontend
npm run dev
```

Expected output:
```
➜  Frontend ready in 500ms
➜  Local:   http://localhost:5173/
```

### Accessing the Application

- **Frontend**: http://localhost:5173
- **API Docs**: http://127.0.0.1:8000/docs (Swagger UI)
- **ReDoc**: http://127.0.0.1:8000/redoc (Alternative API docs)

---

## 🧪 Testing

### Quick Test Run

Run all tests with one command:

```powershell
PowerShell -ExecutionPolicy Bypass -File run_tests.ps1
```

### Test Options

```powershell
# Run all tests
PowerShell -ExecutionPolicy Bypass -File run_tests.ps1 -TestType all

# Run only authentication tests
PowerShell -ExecutionPolicy Bypass -File run_tests.ps1 -TestType auth

# Run only Phase 1 tests
PowerShell -ExecutionPolicy Bypass -File run_tests.ps1 -TestType phase1

# Run only Phase 2 tests
PowerShell -ExecutionPolicy Bypass -File run_tests.ps1 -TestType phase2

# Run only Phase 3 tests
PowerShell -ExecutionPolicy Bypass -File run_tests.ps1 -TestType phase3

# Run only legacy endpoint tests
PowerShell -ExecutionPolicy Bypass -File run_tests.ps1 -TestType legacy

# Run only error handling tests
PowerShell -ExecutionPolicy Bypass -File run_tests.ps1 -TestType errors

# Run with coverage report
PowerShell -ExecutionPolicy Bypass -File run_tests.ps1 -TestType coverage
```

### Manual Test Execution

```powershell
# Prerequisites: Backend must be running
cd Backend
.\.venv\Scripts\activate

# Run all tests
pytest test_integration.py -v

# Run specific test class
pytest test_integration.py::TestAuth -v

# Run specific test
pytest test_integration.py::TestAuth::test_3_login_success -v

# Run tests matching pattern
pytest test_integration.py -k "auth" -v

# Run with coverage
pytest test_integration.py -v --cov=. --cov-report=html
```

### Test Coverage

The test suite includes **25 comprehensive tests**:

- ✅ **10 Authentication Tests** - Register, login, token refresh, validation
- ✅ **3 Phase 1 Tests** - Discovery endpoint authorization
- ✅ **3 Phase 2 Tests** - Port scanning endpoint authorization
- ✅ **3 Phase 3 Tests** - Vulnerability audit endpoint authorization
- ✅ **4 Legacy Endpoint Tests** - Backward compatibility
- ✅ **2 Error Handling Tests** - Malformed requests, missing fields

For detailed test documentation, see [TEST_GUIDE.md](TEST_GUIDE.md)

---

## 🔄 First Time User Workflow

### 1. Start the Application

```powershell
PowerShell -ExecutionPolicy Bypass -File startup.ps1
```

### 2. Register Account

- Navigate to http://localhost:5173/register
- Enter:
  - **Username**: anything (min 3 chars)
  - **Email**: your@email.com
  - **Password**: your_password (min 6 chars)
- Click **Register**

### 3. Login

- Navigate to http://localhost:5173/login
- Enter your email and password
- Click **Login**
- You'll be redirected to the dashboard

### 4. Run a Scan

**Phase 1 - Discovery:**
- Enter target IP/range/CIDR (e.g., `192.168.1.1` or `192.168.1.0/24`)
- Select scan type (ping, arp, tcp, etc.)
- Click **Discover**
- Wait for results

**Phase 2 - Port Scanning:**
- Select hosts from Phase 1 results
- Choose intensity (light, normal, deep)
- Click **Scan for Ports**
- Wait for results

**Phase 3 - Vulnerability Audit:**
- Phase 2 hosts automatically selected
- Click **Run Audit**
- View CVEs, TLS info, SSH banners, etc.

### 5. Test API Directly

Use the interactive API docs:

```
http://127.0.0.1:8000/docs
```

1. Click **Authorize**
2. Login through the UI (or manually paste `access_token` from browser storage)
3. Try endpoints with **"Try it out"** button

---

## 🏗️ Architecture

### Backend Stack

```
FastAPI + Uvicorn
    ↓
SQLAlchemy ORM (User persistent storage)
    ↓
JWT Authentication (python-jose + passlib bcrypt)
    ↓
Scanning Engines (scapy for network scanning)
```

### Frontend Stack

```
React 18 (UI framework)
    ↓
React Router (Client-side routing)
    ↓
Axios (HTTP client with auto token attachment)
    ↓
CSS (Dark cyber theme)
```

### Authentication Flow

```
1. User registers with username/email/password
   → Password hashed with bcrypt
   → User stored in SQLite database

2. User logs in with email/password
   → Credentials validated
   → JWT tokens generated (access + refresh)
   → Tokens stored in localStorage

3. Frontend makes API request
   → Axios interceptor attaches Bearer token
   → Backend validates token via get_current_user dependency
   → Request succeeds or fails with 401/403

4. Token expires (1 hour)
   → Axios interceptor detects 401
   → Automatically calls /auth/refresh
   → Gets new access_token
   → Retries original request
   → User doesn't notice anything
```

### Database

- **Development**: SQLite (`Backend/ccure_users.db`)
- **Production**: PostgreSQL (via `DATABASE_URL` environment variable)

### API Endpoints

#### Authentication
- `POST /auth/register` - Create new user
- `POST /auth/login` - Get tokens
- `GET /auth/me` - Get current user
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - Logout user

#### Scan Endpoints (All Protected)
- `POST /scan/phase1` - Discovery scan
- `POST /scan/phase2` - Port scan
- `POST /scan/phase3` - Vulnerability audit
- `POST /scan/phases` - Multi-phase scan
- `POST /scan/host` - Single host scan (legacy)
- `POST /scan/range` - IP range scan (legacy)
- `POST /scan/subnet` - CIDR subnet scan (legacy)
- `POST /scan/subnets` - Multiple subnets scan (legacy)

---

## 📁 Project Structure

```
Backend/
├── main.py                    # FastAPI application
├── requirements.txt           # Dependencies
├── test-requirements.txt      # Test dependencies
├── test_integration.py        # Comprehensive test suite
├── ccure_users.db            # SQLite database (auto-created)
├── auth/
│   ├── models.py             # User model + DB config
│   ├── jwt_handler.py        # JWT token generation
│   ├── dependencies.py       # get_current_user dependency
│   └── router.py             # Auth endpoints
├── api/
│   └── host_discovery_api.py # Discovery engine
├── engines/
│   ├── discovery/            # Host discovery
│   ├── port/                 # Port scanning
│   └── vulnerability/        # Vuln detection
└── orchestrator/             # Scan orchestration

Frontend/
├── package.json              # npm dependencies
├── vite.config.js           # Vite configuration
├── index.html               # Entry HTML
└── src/
    ├── main.jsx             # React entry
    ├── App.jsx              # Router
    ├── index.css            # All styling
    ├── api/
    │   ├── auth.js          # Auth API calls
    │   └── axiosInstance.js # Token auto-attach
    ├── context/
    │   └── AuthContext.jsx  # Global auth state
    ├── components/
    │   ├── PrivateRoute.jsx # Protected routes
    │   └── scan/
    │       ├── PhaseOne.jsx # Discovery UI
    │       ├── PhaseTwo.jsx # Port scan UI
    │       ├── PhaseThree.jsx # Vuln audit UI
    │       └── RiskBadge.jsx # Risk severity badge
    └── pages/
        ├── Login.jsx        # Login page
        ├── Register.jsx     # Registration page
        └── Dashboard.jsx    # Main dashboard

Root/
├── startup.ps1              # Auto-start script
├── run_tests.ps1           # Quick test runner
├── TEST_GUIDE.md           # Complete test documentation
└── GETTING_STARTED.md      # This file
```

---

## 🔧 Environment Configuration

### SQLite (Default for Development)

Already configured - just run:
```powershell
PowerShell -ExecutionPolicy Bypass -File startup.ps1
```

### PostgreSQL (For Production)

1. Set environment variable:

```powershell
$env:DATABASE_URL = 'postgresql://user:password@localhost:5432/ccure_db'
```

2. Restart backend:

```powershell
cd Backend
.\.venv\Scripts\activate
uvicorn main:app --reload
```

Database will auto-create tables on first run.

### Other Environment Variables

```powershell
# Backend
$env:SECRET_KEY = "your-secret-key"  # Defaults to auto-generated
$env:DATABASE_URL = "sqlite:///./ccure_users.db"  # Defaults shown

# Frontend (built into vite.config.js)
# Proxy: /auth → http://localhost:8000
# Proxy: /scan → http://localhost:8000
```

---

## 🐛 Troubleshooting

### API Not Running

**Error**: `Connection refused at 127.0.0.1:8000`

**Solution**:
```powershell
cd Backend
.\.venv\Scripts\activate
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

### Tests Not Found

**Error**: `ModuleNotFoundError: No module named 'pytest'`

**Solution**:
```powershell
cd Backend
.\.venv\Scripts\activate
pip install pytest pytest-cov requests
```

### Frontend Not Loading

**Error**: `http://localhost:5173 refused to connect`

**Solution**:
```powershell
cd Frontend
npm install
npm run dev
```

### Port Already in Use

**Error**: `Address already in use`

**Solution**:
```powershell
# Find process using port 8000
netstat -ano | findstr :8000

# Kill process (replace PID)
taskkill /PID <PID> /F

# Or use different port
uvicorn main:app --reload --host 127.0.0.1 --port 8001
```

### Login Not Working

**Check**:
1. Backend running and database accessible
2. User registered with correct email
3. Password typed correctly
4. Check backend logs for errors

**Debug**:
```powershell
cd Backend
.\.venv\Scripts\activate
pytest test_integration.py::TestAuth::test_3_login_success -v -s
```

---

## 📚 Documentation

- **[TEST_GUIDE.md](TEST_GUIDE.md)** - Comprehensive testing documentation
- **[Backend/README.md](Backend/README.md)** - Backend API details
- **[Frontend/package.json](Frontend/package.json)** - Frontend dependencies
- **[Backend/API_QUICK_REFERENCE.md](Backend/API_QUICK_REFERENCE.md)** - API endpoint reference

---

## 📊 Verification Checklist

Use this to verify your setup is complete:

- [ ] Backend virtual environment created
- [ ] Backend dependencies installed (`pip list` shows fastapi, sqlalchemy, etc.)
- [ ] Frontend npm packages installed (`npm list` shows react, etc.)
- [ ] Backend starts without errors
- [ ] Frontend starts without errors
- [ ] Can register new account
- [ ] Can login with new account
- [ ] Dashboard loads after login
- [ ] API docs accessible at http://127.0.0.1:8000/docs
- [ ] All tests pass: `pytest test_integration.py -v`

---

## 🎓 Learning Resources

### Backend Development
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [SQLAlchemy ORM](https://docs.sqlalchemy.org/)
- [Python-jose (JWT)](https://github.com/mpdavis/python-jose)

### Frontend Development
- [React Documentation](https://react.dev)
- [React Router](https://reactrouter.com/)
- [Axios Documentation](https://axios-http.com/)

### Testing
- [Pytest Documentation](https://docs.pytest.org/)
- [Requests Library](https://docs.python-requests.org/)

---

## 💡 Tips & Tricks

### Enable Debug Logging

```powershell
# Backend with debug logging
$env:PYTHONUNBUFFERED = 1
uvicorn main:app --reload --log-level debug
```

### Clear Database and Start Fresh

```powershell
# Remove SQLite database
Remove-Item Backend\ccure_users.db

# Backend will recreate it on startup
uvicorn main:app --reload
```

### View Token Contents

In browser DevTools Console:
```javascript
// Get access token
const token = localStorage.getItem('access_token');
console.log(token);

// Decode JWT (header.payload.signature)
const [header, payload, signature] = token.split('.');
console.log(atob(payload));
```

### Test API Directly

```powershell
# Get access token first (from login or browser storage)
$token = "your_access_token_here"

# Make API request
$headers = @{Authorization = "Bearer $token"}
Invoke-RestMethod -Uri "http://127.0.0.1:8000/auth/me" -Headers $headers
```

---

## 📞 Support

For issues or questions:

1. Check [TEST_GUIDE.md](TEST_GUIDE.md) for testing help
2. Review troubleshooting section above
3. Check backend logs (uvicorn output)
4. Check browser DevTools Console for frontend errors
5. Run tests to identify specific component failures

---

## 📝 Version Info

- **Python**: 3.9+
- **Node.js**: 16+
- **FastAPI**: 0.111.0
- **React**: 18.x
- **pytest**: 7.4.4

---

**Ready to get started?** 🚀

```powershell
PowerShell -ExecutionPolicy Bypass -File startup.ps1
```

Then navigate to **http://localhost:5173** and register your first account!
