# CCure Audit PRO — Setup and Installation

**Version:** 1.0.0  
**Supported Platforms:** Linux (recommended), Windows 10/11 with Npcap

---

## Prerequisites

| Component             | Version     | Notes                                              |
|-----------------------|-------------|----------------------------------------------------|
| Python                | 3.12+       | Required                                           |
| Node.js               | 18+         | Required for frontend                              |
| Nmap                  | 7.x+        | Optional — not directly invoked but useful for validation |
| Npcap (Windows only)  | Latest      | Required for Scapy raw packet operations on Windows |
| Root / Admin access   | —           | Required for ARP, ICMP, SYN/stealth scan modes     |

---

## Backend Setup

### 1. Clone and Install Dependencies

```bash
cd Backend
pip install -r requirements.txt
```

Key packages installed:
- `fastapi`, `uvicorn[standard]` — API server
- `sqlalchemy` — ORM
- `python-jose[cryptography]`, `passlib[bcrypt]` — authentication
- `scapy` — raw packet operations
- `paramiko` — SSH credentialed scanning
- `reportlab` — PDF report generation

### 2. Environment Verification

Run the install verifier to check that all optional components are available:

```bash
python scripts/verify_install.py
```

This checks for:
- Scapy availability and Npcap (Windows)
- Paramiko for credentialed scanning
- reportlab for PDF generation
- Root/admin privileges

### 3. Database Initialization

The SQLite database (`ccure_users.db`) is created automatically on first server start. No manual schema creation is required — the `lifespan` handler in `main.py` calls:
- `create_tables()` — creates `users` and `refresh_tokens` tables
- `ensure_scan_schema()` — creates/migrates `scans` and `scan_phase_results` tables

### 4. CVE Database Setup

Populate the CVE database from the NVD:

```bash
python scripts/download_nvd.py
```

This downloads NVD JSON feeds and populates `cves.db`. Without this step, the scanner falls back to a limited hardcoded CVE set. Allow 5–15 minutes for the initial download depending on network speed.

### 5. Start the Backend Server

```bash
python main.py
```

Or with uvicorn directly:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The server will log:
```
[HH:MM:SS] INFO ccure.api - HostDiscoveryAPI initialised
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

Interactive API docs are available at `http://localhost:8000/docs`.

### 6. CORS Configuration

By default, the backend allows requests from:
- `http://localhost:3000`
- `http://localhost:5173` (Vite dev server)
- `http://localhost:8080`

To configure for a production deployment:

```bash
CORS_ALLOW_ORIGINS="https://ccure.company.com" uvicorn main:app ...
```

Multiple origins are comma-separated.

---

## Frontend Setup

### 1. Install Dependencies

```bash
cd Frontend
npm install
```

### 2. Configure API Base URL

The frontend communicates with the backend via Axios. The API base URL is configured in `src/api/axiosInstance.js`. By default it targets `http://localhost:8000`. Update this for production deployment.

### 3. Development Server

```bash
npm run dev
```

Starts Vite dev server at `http://localhost:5173`.

### 4. Production Build

```bash
npm run build
```

Output is written to `Frontend/dist/`. Serve the `dist/` directory with any static file server (nginx, Apache, or the Vite preview command).

---

## Running with Elevated Privileges

ARP, ICMP, and stealth scan modes require root on Linux or Administrator on Windows.

### Linux

```bash
sudo python main.py
# or
sudo -E uvicorn main:app --host 0.0.0.0 --port 8000
```

The `-E` flag preserves environment variables (including virtual environment paths).

### Windows

Run the terminal as Administrator. Npcap must be installed with the "WinPcap API-compatible mode" option enabled.

---

## Environment Variables

| Variable                  | Default         | Description                                 |
|---------------------------|-----------------|---------------------------------------------|
| `CORS_ALLOW_ORIGINS`      | (dev defaults)  | Comma-separated list of allowed origins      |
| `REFRESH_COOKIE_NAME`     | `ccure_refresh_token` | Cookie name for refresh tokens         |
| `REFRESH_COOKIE_PATH`     | `/auth`         | Cookie scope path                            |
| `REFRESH_COOKIE_SAMESITE` | `lax`           | SameSite cookie policy                       |
| `REFRESH_COOKIE_SECURE`   | `false`         | Set to `true` in HTTPS production deployments|
| `REFRESH_COOKIE_DOMAIN`   | (unset)         | Cookie domain for cross-subdomain access     |

---

## Creating the First User

Use the API or the test helper script:

```bash
python scripts/test-db/create_test_user.py
```

Or register via the frontend at `/register`, or directly via the API:

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "email": "admin@example.com", "password": "changeme"}'
```

---

## Verifying the Installation

```bash
# 1. Health check
curl http://localhost:8000/

# 2. Login and get token
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"changeme"}' \
  | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 3. Run a quick scan
curl -X POST http://localhost:8000/scan/host-discovery \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"targets":["127.0.0.1"],"scan_type":"tcp","pipeline_mode":"basic"}'
```

---

## Windows-Specific Notes

### Npcap Installation
Download from https://npcap.com and install with **WinPcap API-compatible mode** enabled. Without Npcap, Scapy is unavailable and all privileged scan modes (ARP, ICMP, SYN, stealth) fall back to TCP connect.

### Firewall
Windows Defender Firewall may block TCP connect scan attempts for localhost probes. Disable or configure rules for the scanner process during testing.

### PowerShell Execution Policy
When using the Windows preparation scripts in `scripts/`:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## Docker Deployment (Manual)

There is no pre-built `Dockerfile` included. A basic containerization approach:

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY Backend/ /app/
RUN pip install -r requirements.txt

# Note: Privileged scan modes (ARP/ICMP) require --cap-add NET_RAW or --network host
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

For raw packet capabilities:

```bash
docker run --cap-add NET_RAW --cap-add NET_ADMIN -p 8000:8000 ccure-backend
```

The frontend can be served from the same container or a separate nginx container pointing to the built `dist/` directory.

---

## Troubleshooting

| Symptom                                | Cause / Fix                                                              |
|----------------------------------------|--------------------------------------------------------------------------|
| `503 API not initialised yet`          | Backend startup still in progress — wait and retry                       |
| All hosts show inactive on ARP/ICMP    | Running without root/admin. Use `tcp` or `adaptive` scan_type            |
| CVE results sparse / missing           | `cves.db` absent or empty. Run `python scripts/download_nvd.py`          |
| `503 paramiko required`                | Install paramiko: `pip install paramiko==3.4.0`                          |
| PDF reports not generated              | reportlab missing: `pip install reportlab==4.4.0`                        |
| CORS errors from frontend              | Set `CORS_ALLOW_ORIGINS` to include the frontend origin                  |
| Scapy import errors on Windows         | Npcap not installed or WinPcap compat mode not enabled                   |
| `jwt.ExpiredSignatureError`            | Access token expired — frontend should call `/auth/refresh` automatically |
