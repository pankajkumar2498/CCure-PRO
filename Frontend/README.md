# CCure Audit PRO — Unified Frontend

React + Vite frontend unified from the CAST Dashboard design system and CCure Audit PRO backend.

## Design System
- **Sidebar**: `#1a2332` dark navy
- **Accent**: `#0ea5e9` sky blue
- **Background**: `#f8fafc` light gray
- All CSS lives in `src/styles/global.css` with CSS variables

## Project Structure
```
src/
├── api/                     # Axios wrappers for every backend endpoint
│   ├── axiosInstance.js     # Base Axios with auth token + auto-refresh
│   ├── auth.js              # POST /auth/login, /register, /logout, GET /auth/me
│   ├── scans.js             # GET /scans, GET /scans/{id}, DELETE /scans/{id}
│   └── credentialedScan.js  # POST /scan/credentialed
│
├── context/
│   ├── AuthContext.jsx      # User session, login/register/logout
│   └── ScanContext.jsx      # Wizard state (persisted in sessionStorage)
│
├── components/
│   ├── PrivateRoute.jsx     # Redirects unauthenticated users to /login
│   ├── layout/
│   │   ├── AppLayout.jsx    # CAST sidebar + top header (all protected pages)
│   │   ├── AppShell.jsx     # Re-exports AppLayout (backward compat)
│   │   └── ScanStepper.jsx  # Phase 1 → 2 → 3 progress indicator
│   └── scan/
│       ├── RiskBadge.jsx    # Critical/High/Medium/Low/Info colored badge
│       └── ExportPanel.jsx  # JSON/CSV/PDF/Copy export buttons
│
├── pages/
│   ├── Login.jsx            # POST /auth/login
│   ├── Register.jsx         # POST /auth/register
│   ├── Dashboard.jsx        # Scan template grid (CAST design)
│   ├── ScanHistory.jsx      # GET /scans + view/re-run/delete
│   └── scan/
│       ├── NewScan.jsx          # POST /scan/phase1
│       ├── Phase1Results.jsx    # Discovery results + host selection
│       ├── Phase2Results.jsx    # POST /scan/phase2 + port results
│       ├── Phase3Results.jsx    # POST /scan/phase3 + CVE/TLS/SSH/HTTP
│       ├── CredentialedScan.jsx # POST /scan/credentialed (form)
│       └── CredentialedResults.jsx  # Full SSH scan report
│
└── styles/
    └── global.css           # Unified design system (1,130 lines)
```

## API Endpoints Used
| Endpoint | Method | Used By |
|---|---|---|
| `/auth/login` | POST | Login.jsx |
| `/auth/register` | POST | Register.jsx |
| `/auth/logout` | POST | AppLayout (sign out) |
| `/auth/me` | GET | AuthContext (session restore) |
| `/auth/refresh` | POST | axiosInstance (auto-refresh) |
| `/scan/phase1` | POST | NewScan.jsx, ScanHistory (re-run) |
| `/scan/phase2` | POST | Phase2Results.jsx |
| `/scan/phase3` | POST | Phase3Results.jsx |
| `/scan/credentialed` | POST | CredentialedScan.jsx |
| `/scans` | GET | ScanHistory.jsx |
| `/scans/{id}` | GET | ScanHistory modal, CredentialedResults |
| `/scans/{id}` | DELETE | ScanHistory.jsx |
| `/reports/download/{id}` | GET | ExportPanel.jsx (PDF) |

## Setup & Run

### Prerequisites
- Node.js 18+
- Backend running on `http://localhost:8000`

### Install & Start
```bash
npm install
npm run dev
```

Opens at **http://localhost:3000**

### Backend
```bash
cd Backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Build for Production
```bash
npm run build
# Output in dist/
```

## Authentication Flow
1. User logs in → receives `access_token` + `refresh_token`
2. Tokens stored in `localStorage`
3. Every API request has `Authorization: Bearer <access_token>` header
4. On 401 → auto-refresh with `refresh_token`, retry once
5. Logout → tokens cleared, redirect to `/login`

## Scan Wizard Flow
```
/dashboard  →  /scan  →  /scan/phase1  →  /scan/phase2  →  /scan/phase3
                                                              ↓
                                                          /history
```
All intermediate state is persisted in `sessionStorage` — browser refresh restores progress.
