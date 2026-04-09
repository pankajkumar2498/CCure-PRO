# Setup Guide — Ccure Audit

> **Complete environment setup from zero to running scan.**  
> Covers all platforms, dev environment, Docker, and CI.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation — Minimum (TCP Scan Only)](#installation--minimum-tcp-scan-only)
3. [Installation — Full (All Scan Modes)](#installation--full-all-scan-modes)
4. [Platform-Specific Notes](#platform-specific-notes)
   - [Linux](#linux)
   - [macOS](#macos)
   - [Windows](#windows)
5. [Running the CLI](#running-the-cli)
6. [Running the API Server](#running-the-api-server)
7. [Running as Root / Administrator](#running-as-root--administrator)
8. [Development Setup](#development-setup)
9. [Running Tests](#running-tests)
10. [Docker Setup](#docker-setup)
11. [Environment Variables](#environment-variables)
12. [Verifying Your Install](#verifying-your-install)
13. [Common Setup Errors](#common-setup-errors)

---

## Prerequisites

| Requirement | Minimum | Recommended |
|---|---|---|
| Python | 3.8 | 3.11+ |
| pip | Any | Latest (`pip install -U pip`) |
| OS | Linux / macOS / Windows 10+ | Ubuntu 22.04 LTS |
| RAM | 256 MB | 1 GB |
| Network | Outbound TCP | Outbound TCP + raw sockets (root) |

Check your Python version:
```bash
# On Linux / macOS:
python3 --version

# On Windows:
python --version

# Must be 3.8 or higher
```

---

## Installation — Minimum (TCP Scan Only)

This install works on any machine without root or admin rights.
All TCP-based scanning features are fully available.

```bash
# 1. Clone or extract the project
cd backend

# 2. Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install reportlab              # optional — PDF reports only
# That's it. All scan features use stdlib.

# 4. Run
python cli.py
```

---

## Installation — Full (All Scan Modes)

Includes the FastAPI web server and Scapy for raw-packet scans.

```bash
# 1. Activate your virtual environment (from above)

# 2. Install everything from requirements.txt
pip install -r requirements.txt

# requirements.txt includes:
#   reportlab   — PDF reports
#   fastapi     — REST API
#   uvicorn     — ASGI server
#   pydantic    — request validation

# 3. Scapy (only if you want ARP/ICMP/SYN/stealth modes)
pip install scapy
```

---

## Platform-Specific Notes

### Linux

```bash
# Verify Python
python3 --version

# Install pip if missing
sudo apt install python3-pip       # Debian / Ubuntu
sudo dnf install python3-pip       # RHEL / Fedora

# For raw-packet scans (ARP, ICMP, SYN, stealth):
# Run the scanner as root
sudo python3 cli.py

# Or grant capability to Python binary (no full root needed):
sudo setcap cap_net_raw+ep $(which python3)
python3 cli.py    # works without sudo
```

### macOS

```bash
# Install Python via Homebrew (recommended)
brew install python

# Create venv and install
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
pip install scapy

# For raw-packet scans:
sudo python3 cli.py
# macOS may require granting terminal Full Disk Access in System Settings > Privacy
```

### Windows

```powershell
# 1. Download Python from https://python.org (add to PATH during install)
python --version

# 2. Create venv
python -m venv .venv
.venv\Scripts\activate

# 3. Install
pip install -r requirements.txt

# 4. For Scapy raw-packet scans on Windows:
#    a. Install Npcap from https://npcap.com (WinPcap-compatible mode)
#    b. Install scapy
pip install scapy
#    c. Run as Administrator (right-click PowerShell → Run as Administrator)
python cli.py
```

> **Note:** On Windows, all privileged scan modes (ARP, ICMP, SYN, stealth) require
> both Administrator privileges AND Npcap installed. Without these, the scanner
> auto-downgrades to TCP mode.

---

## Running the CLI

```bash
# Activate venv first
source .venv/bin/activate

# Start interactive CLI
python cli.py
```

Example session:
```
================================================================================
  CCURE AUDIT
================================================================================
{
  "platform": "linux",
  "privileges": {"has_privileges": false, "privilege_level": "Limited"},
  ...
}

Choose operation:
  1. Scan single host / hostname
  2. Scan IP range  (e.g. 192.168.1.1-50)
  3. Scan full subnet  (e.g. 192.168.1.0/24)
  4. Scan subnets of a subnet

Enter choice (1-4): 1
Scan type [ping/arp/tcp/full/adaptive/stealth] (default: adaptive):
Intensity [light/normal/deep] (default: normal):
Enter IP or hostname: 192.168.1.1
```

---

## Running the API Server

```bash
# Requires fastapi + uvicorn
pip install fastapi uvicorn

# Start the server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The server is now available at:
- API base: `http://localhost:8000`
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

**Example curl request:**
```bash
curl -X POST http://localhost:8000/scan/host \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "scan_type": "adaptive"}'
```

**Example Python client:**
```python
import requests

resp = requests.post(
    "http://localhost:8000/scan/subnet",
    json={"target": "192.168.1.0/24", "scan_type": "adaptive"},
    timeout=120,
)
data = resp.json()
print(f"Active hosts: {data['summary']['active_hosts']}")
```

**Production server (multiple workers):**
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

---

## Running as Root / Administrator

Raw-packet scan modes (ARP, ICMP, SYN, FULL, STEALTH) require elevated privileges.

### Linux — run with sudo
```bash
sudo .venv/bin/python cli.py
# or
sudo .venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

### Linux — set capability (no full sudo)
```bash
# Grant raw-socket capability once, persistently
sudo setcap cap_net_raw+ep .venv/bin/python3
python3 cli.py    # now works without sudo
```

### macOS
```bash
sudo python3 cli.py
```

### Windows
Right-click on PowerShell → **Run as Administrator**, then:
```powershell
python cli.py
```

---

## Development Setup

```bash
# Clone / extract
cd ccure_engine

# Create dev venv
python3 -m venv .venv-dev
source .venv-dev/bin/activate

# Install all deps including dev tools
pip install -r requirements.txt
pip install scapy pytest

# Verify everything imports cleanly
python3 -c "from api.host_discovery_api import HostDiscoveryAPI; print('OK')"
```

**Project layout for IDE:**
Set your IDE's Python interpreter to `.venv-dev/bin/python`.
Set the project root (`ccure_engine/`) as the source root so that
`from core.constants import ...` resolves correctly.

**VS Code settings (`.vscode/settings.json`):**
```json
{
    "python.defaultInterpreterPath": "${workspaceFolder}/.venv-dev/bin/python",
    "python.analysis.extraPaths": ["${workspaceFolder}"]
}
```

**PyCharm:**
`File → Settings → Project → Python Interpreter` → select `.venv-dev`.
`File → Settings → Project → Project Structure` → mark `ccure_engine/` as Sources Root.

---

## Running Tests

```bash
# Quick sanity check (no external network required)
python3 -c "
import sys; sys.path.insert(0, '.')
from core.utils import lookup_cve, extract_version
from core.risk import fingerprint_os, calculate_risk
from api.host_discovery_api import HostDiscoveryAPI

cves = lookup_cve('vsftpd 2.3.4')
assert cves[0]['cve'] == 'CVE-2011-2523'

ver = extract_version('Apache/2.4.51 (Ubuntu)')
assert 'Apache' in ver

guess, conf = fingerprint_os(64, 29200)
assert 'Linux' in guess

api = HostDiscoveryAPI(silent=True)
info = api.get_system_info()
assert info['version'] == '2.0-pro'

print('All checks passed.')
"
```

**Full test run with pytest (if tests/ directory is added):**
```bash
pytest tests/ -v
```

---

## Docker Setup

**`Dockerfile`** (place in `ccure_engine/`):
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir reportlab fastapi uvicorn pydantic

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Build and run:**
```bash
docker build -t ccure-audit .
docker run -p 8000:8000 ccure-audit
```

**With raw-packet support (Scapy + host networking):**
```bash
docker run --rm \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  ccure-audit
```

> `--network host` is required for ARP scans.
> `--cap-add NET_RAW` grants raw-socket access.

**Docker Compose (`docker-compose.yml`):**
```yaml
version: "3.9"
services:
  ccure:
    build: .
    ports:
      - "8000:8000"
    environment:
      - CCURE_RATE_LIMIT=100
      - CCURE_INTENSITY=normal
    restart: unless-stopped
```

---

## Environment Variables

The API reads these from the environment at startup. All are optional.

| Variable | Default | Description |
|---|---|---|
| `CCURE_RATE_LIMIT` | `200.0` | Token-bucket probes per second |
| `CCURE_INTENSITY` | `normal` | `light` / `normal` / `deep` |
| `CCURE_STEALTH` | `false` | `true` to enable packet fragmentation |
| `CCURE_REPORTS_DIR` | `reports` | PDF output directory |
| `CCURE_SILENT` | `false` | `true` to suppress log output |

To use these in `main.py`, read them in the `lifespan` function:
```python
import os
rate  = float(os.getenv("CCURE_RATE_LIMIT", "200.0"))
inten = os.getenv("CCURE_INTENSITY", "normal")
_api_instance = HostDiscoveryAPI(rate_limit=rate, intensity=inten)
```

---

## Verifying Your Install

Run this script to confirm every layer is working:

```bash
python3 verify_install.py
```

Create `verify_install.py` in the project root:
```python
import sys
sys.path.insert(0, ".")

CHECKS = []

def check(name, fn):
    try:
        fn()
        print(f"  [PASS] {name}")
        CHECKS.append(True)
    except Exception as e:
        print(f"  [FAIL] {name}: {e}")
        CHECKS.append(False)

check("core.constants imports",
    lambda: __import__("core.constants", fromlist=["CVE_HINTS"]))

check("core.models imports",
    lambda: __import__("core.models", fromlist=["HostResult"]))

check("core.utils imports",
    lambda: __import__("core.utils", fromlist=["lookup_cve"]))

check("core.risk imports",
    lambda: __import__("core.risk", fromlist=["calculate_risk"]))

check("engines.discovery imports",
    lambda: __import__("engines.discovery.discovery_engine", fromlist=["DiscoveryEngine"]))

check("engines.port imports",
    lambda: __import__("engines.port.port_engine", fromlist=["PortEngine"]))

check("engines.vulnerability imports",
    lambda: __import__("engines.vulnerability.vulnerability_engine", fromlist=["VulnerabilityEngine"]))

check("all plugins import",
    lambda: __import__("engines.vulnerability.plugins", fromlist=["tls_scanner"]))

check("orchestrator imports",
    lambda: __import__("orchestrator.scan_orchestrator", fromlist=["ScanOrchestrator"]))

check("api imports",
    lambda: __import__("api.host_discovery_api", fromlist=["HostDiscoveryAPI"]))

check("HostDiscoveryAPI instantiation", lambda: (
    __import__("api.host_discovery_api", fromlist=["HostDiscoveryAPI"])
    .HostDiscoveryAPI(silent=True)
))

check("CVE lookup works", lambda: (
    __import__("core.utils", fromlist=["lookup_cve"])
    .lookup_cve("vsftpd 2.3.4")
    .__len__() > 0
))

print()
passed = sum(CHECKS)
total  = len(CHECKS)
print(f"{'All checks passed!' if passed == total else f'{total - passed} check(s) failed.'} ({passed}/{total})")
sys.exit(0 if passed == total else 1)
```

Expected output:
```
  [PASS] core.constants imports
  [PASS] core.models imports
  [PASS] core.utils imports
  [PASS] core.risk imports
  [PASS] engines.discovery imports
  [PASS] engines.port imports
  [PASS] engines.vulnerability imports
  [PASS] all plugins import
  [PASS] orchestrator imports
  [PASS] api imports
  [PASS] HostDiscoveryAPI instantiation
  [PASS] CVE lookup works

All checks passed! (12/12)
```

---

## Common Setup Errors

**`ModuleNotFoundError: No module named 'core'`**
You're not running from the project root. Always `cd ccure_engine` first, or add it to `sys.path`:
```bash
cd ccure_engine && python cli.py
# or
PYTHONPATH=/path/to/ccure_engine python -m cli
```

**`ModuleNotFoundError: No module named 'fastapi'`**
```bash
pip install fastapi uvicorn pydantic
```

**`ModuleNotFoundError: No module named 'scapy'`**
This warning is expected. TCP mode still works fully. To install:
```bash
pip install scapy
```

**`ImportError: No module named 'reportlab'`**
PDF reports are disabled. Install with:
```bash
pip install reportlab
```

**`PermissionError` during ARP or SYN scan**
You need root/admin. Either:
```bash
sudo python3 cli.py
```
or switch to `scan_type="tcp"` which requires no privileges.

**`OSError: [Errno 1] Operation not permitted` on Linux**
Raw socket permission denied. Options:
```bash
# Option A — run as root
sudo python3 cli.py

# Option B — grant capability (survives reboots only if set on the binary, not venv)
sudo setcap cap_net_raw+ep $(which python3)

# Option C — use tcp mode (no root needed)
# In CLI, enter: tcp  when asked for scan type
```

**Scan returns all hosts as inactive**
- Target might be on a different network segment. Verify with `ping <ip>`.
- Firewall may block the scanner's outbound connections.
- Try increasing intensity to `deep` for longer timeouts.
- Try `scan_type="tcp"` to rule out raw-packet issues.

**API server returns `503 Service Unavailable`**
The `lifespan` startup hasn't completed. Wait 1–2 seconds and retry.
Check the uvicorn log output for startup errors.

**Windows: Scapy not detecting interfaces**
Ensure Npcap is installed (not WinPcap). Download from `https://npcap.com`.
Run PowerShell as Administrator and verify:
```powershell
python -c "from scapy.all import conf; print(conf.iface)"
```
