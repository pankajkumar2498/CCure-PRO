# CCure Audit PRO — Getting Started

> From zero to your first credentialed scan in 10 minutes.

---

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Python      | 3.8     | 3.11+       |
| Node.js     | 16      | 20 LTS      |
| npm         | 7       | latest      |
| OS          | Windows 10+ / Linux / macOS | Ubuntu 22.04 |
| Network     | Outbound TCP | Root + raw sockets for ARP/ICMP scans |

---

## 1. Backend Setup

```bash
cd "CCure Audit PRO - Copy/Backend"

# Create virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt

# NEW: Install paramiko for credentialed (SSH) scanning
pip install paramiko==3.4.0

# Start the API server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Verify:
- `http://localhost:8000` → JSON health response
- `http://localhost:8000/docs` → Swagger UI

---

## 2. Frontend Setup

```bash
cd "CCure Audit PRO - Copy/Frontend"
npm install
npm run dev
```

App loads at `http://localhost:5173`

---

## 3. Integrating the Credentialed Scan Feature

The credentialed scan feature ships as separate files — drop them in:

### Backend

```bash
# Copy engine directory
cp -r path/to/new_files/Backend/engines/credentialed/  Backend/engines/credentialed/

# Open main.py and add (see main_credentialed_additions.py for exact code):
#   Section A: 3 import lines
#   Section B: CredentialedScanRequest model
#   Section C: POST /scan/credentialed route
```

### Frontend

```bash
# New pages
cp CredentialedScan.jsx    Frontend/src/pages/scan/
cp CredentialedResults.jsx Frontend/src/pages/scan/

# New API wrapper
cp credentialedScan.js     Frontend/src/api/

# Replace files with updated versions
cp App.jsx                 Frontend/src/
cp AppShell.jsx            Frontend/src/components/layout/

# Append CSS
cat credentialed_styles_append.css >> Frontend/src/index.css
```

---

## 4. Create an Account

1. Open `http://localhost:5173/register`
2. Create a username + password
3. You're automatically logged in

---

## 5. Run Your First Network Scan

1. Go to **Network Scan** (⊕ in the top nav)
2. Enter a target: `192.168.1.0/24` or a single IP like `192.168.1.1`
3. Choose scan type: `adaptive` (recommended)
4. Click **Discover Hosts** → Phase 1 runs
5. Select active hosts → Click **Scan Ports** → Phase 2 runs
6. Pick a host → Click **Run Vulnerability Audit** → Phase 3 runs

---

## 6. Run Your First Credentialed Scan

1. Click **Credentialed** (🔐) in the top nav
2. Enter the target IP of a Linux host you have SSH access to
3. Enter SSH credentials (username + password or key path)
4. Choose what to collect (or leave all checked)
5. Click **Start Credentialed Scan**
6. Results appear in ~15–45 seconds

**What you get:**
- Exact OS and kernel version
- Full installed package list with CVE matches (~90% accuracy)
- Running services
- Security audit: SUID binaries, sudo rules, world-writable dirs
- Failed login history (brute force detection)

**Credentials are never stored** — used only during the SSH session.

---

## 7. View Scan History

Click **History** (◧) in the top nav to see all past scans.
You can delete individual scans or download PDF reports.

---

## Scan Type Quick Reference

| Scan Type | Target | Use When |
|-----------|--------|----------|
| Network Scan | Subnet or IP range | Map what's on the network |
| Credentialed Scan | Single Linux host | Deep audit with exact CVEs |

---

## Troubleshooting

**Backend won't start:**
```bash
# Check Python version
python --version  # must be 3.8+

# Check for missing modules
pip install -r requirements.txt
pip install paramiko==3.4.0
```

**"paramiko not installed" error:**
```bash
pip install paramiko==3.4.0
# Then restart uvicorn
```

**SSH scan fails — "Authentication failed":**
```bash
# Test SSH manually first
ssh username@target-ip
# If this fails, the credentials or SSH config on the target are the issue
```

**SSH scan fails — "Cannot reach X:22":**
```bash
# Test TCP connectivity
nc -zv target-ip 22
# Or: telnet target-ip 22
# If this fails, the host is down or a firewall is blocking port 22
```

**Frontend CORS errors:**
Open `Backend/main.py`, find `allow_origins`, add your frontend URL:
```python
allow_origins=[
    "http://localhost:5173",
    "http://your-server-ip:5173",
]
```
Then restart uvicorn.

**ARP/ICMP scans not working:**
These require root/admin. Either:
```bash
sudo uvicorn main:app --reload   # Linux/macOS
# or: run as Administrator       # Windows
```
Or use `scan_type="tcp"` which requires no privileges.

---

## Environment

No environment variables are required. Optional ones:

| Variable | Default | Description |
|----------|---------|-------------|
| `CCURE_RATE_LIMIT` | `200.0` | Probe rate (req/sec) |
| `CCURE_INTENSITY` | `normal` | `light / normal / deep` |
| `CCURE_REPORTS_DIR` | `reports` | PDF output directory |

---

## What's Next

- **Add more CVEs** — edit `CVE_DATABASE` in `Backend/engines/credentialed/vuln_matcher.py`
- **Windows targets** — Phase 2 of credentialed scanning (WinRM via pywinrm)
- **Scheduled scans** — add APScheduler + cron to re-scan hosts automatically
- **Export** — PDF reports already available via `/reports/download/{scan_id}`
