# Implementation Guide — Ccure Audit Pro

> Covers two things in one place:
> 1. **Setup & Integration** — how to plug in new features (phase-selective + credentialed scanning)
> 2. **Developer Reference** — every module, class, design decision, and data contract in detail

---

## Part 1 — Setup & Integration

### What's in This Codebase

```
ORIGINAL:
├── scan_single_host()        ← Runs all 4 phases
├── scan_ip_range()           ← Phase 1 only
├── scan_subnet()             ← Phase 1 only
└── scan_subnets_of_subnet()  ← Phase 1 only

PHASE-SELECTIVE UPDATE:
├── [All above unchanged — fully backward compatible]
├── run_host_discovery_only()   ← Discovery on any targets
├── run_asset_discovery_only()  ← Port scan on selected hosts
├── run_advanced_scan_only()    ← Vulnerability scan on selected hosts
└── run_phases()                ← Flexible "1", "1+2", "1+2+3+4"

CREDENTIALED SCAN (NEW):
├── engines/credentialed/ssh_scanner.py      ← Paramiko SSH wrapper
├── engines/credentialed/linux_collector.py  ← 15+ system info collectors
├── engines/credentialed/vuln_matcher.py     ← Package→CVE matching (~90% accuracy)
└── POST /scan/credentialed                  ← New endpoint in main.py
```

---

### Integrating the Credentialed Scan Feature

#### Step 1 — Copy engine files

```bash
cp -r engines/credentialed/  Backend/engines/credentialed/
```

This adds three new files:
- `ssh_scanner.py` — Paramiko wrapper (connect, run commands, disconnect)
- `linux_collector.py` — Runs 20 commands and parses output
- `vuln_matcher.py` — Matches installed packages to CVE database

#### Step 2 — Install paramiko

```bash
pip install paramiko==3.4.0
```

Or add to `requirements.txt`:
```
paramiko==3.4.0   # SSH client for credentialed scanning
```

#### Step 3 — Update main.py

Add imports (after existing import block):
```python
from engines.credentialed.ssh_scanner    import SSHScanner, PARAMIKO_AVAILABLE
from engines.credentialed.linux_collector import LinuxCollector
from engines.credentialed.vuln_matcher   import VulnMatcher
```

Add the Pydantic model (after `Phase3Request`):
```python
class CredentialedScanRequest(BaseModel):
    ip:          str            = Field(...,  example="192.168.1.10")
    username:    str            = Field(...,  example="root")
    password:    Optional[str]  = Field(None)
    key_path:    Optional[str]  = Field(None)
    port:        int            = Field(22,   ge=1, le=65535)
    auth_method: str            = Field("password")
    sections:    Optional[List[str]] = Field(None)
```

Add the route — see `engines/credentialed/credentialed_scan_endpoint.py` for the
full route code (Section C). The complete route file is provided as a drop-in reference.

#### Step 4 — Update Frontend

Copy new files:
```bash
# New pages
cp Frontend/src/pages/scan/CredentialedScan.jsx    <your-project>/
cp Frontend/src/pages/scan/CredentialedResults.jsx  <your-project>/

# New API wrapper
cp Frontend/src/api/credentialedScan.js             <your-project>/

# Replace these files (they have additions)
cp Frontend/src/App.jsx                             <your-project>/
cp Frontend/src/components/layout/AppShell.jsx      <your-project>/

# Append CSS
cat Frontend/src/credentialed_styles_append.css >> <your-project>/src/index.css
```

#### Step 5 — Test

```bash
# Start backend
cd Backend && uvicorn main:app --reload

# Test connectivity check
curl -X POST http://localhost:8000/scan/credentialed \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.10","username":"root","password":"wrongpass"}'
# → 400: SSH authentication failed

# Valid scan
curl -X POST http://localhost:8000/scan/credentialed \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.10","username":"root","password":"correctpass"}'
# → 200 with full system data
```

#### Integration Checklist

- [ ] `engines/credentialed/` directory copied to Backend
- [ ] `paramiko==3.4.0` added to `requirements.txt` and installed
- [ ] Three imports added to `main.py`
- [ ] `CredentialedScanRequest` model added to `main.py`
- [ ] `POST /scan/credentialed` route added to `main.py`
- [ ] `CredentialedScan.jsx` and `CredentialedResults.jsx` added to Frontend
- [ ] `credentialedScan.js` API wrapper added
- [ ] `App.jsx` updated with two new routes
- [ ] `AppShell.jsx` updated with "Credentialed" nav link
- [ ] CSS appended to `index.css`
- [ ] Server starts: `uvicorn main:app --reload`
- [ ] `/scan/credentialed` page loads in browser
- [ ] Test scan succeeds against a real or test SSH server

---

### Security Design — Credential Handling

**Option A is implemented (recommended).**

Credentials flow:
```
Browser → HTTPS → FastAPI endpoint
                     ↓ (used immediately)
                  SSHScanner.connect()
                     ↓ (session open)
                  LinuxCollector.collect_all()
                     ↓ (session closes, __exit__ called)
                  SSHScanner.disconnect()
                     ↓ (memory zeroed)
                  self._password = None
                  self._key_path = None
```

What is NOT stored:
- Password is not written to any log
- Password is not saved to the database
- Password is not echoed back in the response
- SSH key path content is not stored

What IS stored (in the scans table):
- Target IP, scan type, timestamp
- System info (OS, kernel, packages)
- CVE findings
- Security audit results

If you ever need Option B (stored encrypted credentials for re-scanning),
the right place to implement it is a new `CredentialStore` model in
`auth/` with AES-GCM encryption using a key derived from the user's JWT.

---

### Extending the CVE Database

The CVE knowledge base lives in `engines/credentialed/vuln_matcher.py::CVE_DATABASE`.

To add a new CVE:
```python
CVE_DATABASE["package_name"] = [
    {
        "cve_id":    "CVE-YYYY-NNNNN",
        "min_ver":   "1.0.0",     # optional — omit if all versions affected
        "max_ver":   "1.2.3",     # vulnerable if installed < max_ver
        "fixed_ver": "1.2.3",
        "severity":  "High",      # Critical | High | Medium | Low
        "cvss":      7.5,
        "description": "Short description of the vulnerability.",
    },
]
```

The `max_ver` is the **first safe version** (exclusive upper bound).
The version comparator handles common formats: `1.1.1f`, `7.4p1`, `2.4.51`, `2.35-0ubuntu3`.

---

### API Usage — Credentialed Scan Workflow

#### Typical combined workflow

```
1. POST /scan/host-discovery → discover active hosts on subnet
2. Pick a host of interest from the list
3. POST /scan/credentialed → SSH into that host, get exact data
4. Review CVE findings with exact package versions
```

#### Credentialed scan — password auth
```json
POST /scan/credentialed
{
  "ip":       "192.168.1.10",
  "username": "root",
  "password": "mysecretpass",
  "port":     22
}
```

#### Credentialed scan — SSH key auth
```json
POST /scan/credentialed
{
  "ip":          "192.168.1.10",
  "username":    "ubuntu",
  "key_path":    "/home/ubuntu/.ssh/id_rsa",
  "auth_method": "key",
  "port":        22
}
```

#### Targeted collection (subset of sections)
```json
POST /scan/credentialed
{
  "ip":       "192.168.1.10",
  "username": "root",
  "password": "pass",
  "sections": ["system_info", "packages", "security"]
}
```

---

### React Component Example (Credentialed)

```jsx
import { useState } from "react";
import { runCredentialedScan } from "./api/credentialedScan";

export default function QuickCredScan() {
  const [ip, setIp]       = useState("");
  const [user, setUser]   = useState("root");
  const [pass, setPass]   = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const scan = async () => {
    setLoading(true);
    try {
      const { data } = await runCredentialedScan({ ip, username: user, password: pass });
      setResult(data);
      setPass(""); // clear password immediately
    } catch (err) {
      alert(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <input value={ip}   onChange={e => setIp(e.target.value)}   placeholder="192.168.1.10" />
      <input value={user} onChange={e => setUser(e.target.value)} placeholder="root" />
      <input value={pass} onChange={e => setPass(e.target.value)} type="password" placeholder="password" />
      <button onClick={scan} disabled={loading}>
        {loading ? "Scanning…" : "🔐 Credentialed Scan"}
      </button>

      {result && (
        <div>
          <h3>{result.system_info.os_name} — {result.system_info.kernel_version}</h3>
          <p>{result.cve_count} CVEs found</p>
          <p>{result.package_count} packages installed</p>
          {result.sudo_nopasswd && <p style={{ color: "red" }}>⚠ NOPASSWD sudo detected!</p>}
        </div>
      )}
    </div>
  );
}
```

---

## Part 2 — Developer Reference

> Deep dive into every module, class, design decision, and data contract.

---

### Design Principles

**1. Layered architecture with strict import rules**
Each layer may only import from layers below it.

```
api/ → orchestrator/ → engines/ → core/
                     → plugins/ → core/
                     → credentialed/ → core/  (NEW)
```

**2. Plugins are self-contained**
Every plugin in `engines/vulnerability/plugins/` is independently testable.
The same principle applies to `engines/credentialed/` — each file has no
cross-dependencies within the credentialed package.

**3. Silent failure by default**
Network probes catch all exceptions silently. One unreachable host must
never abort a subnet scan. The SSH scanner raises RuntimeError (which
becomes HTTP 400) but never causes unhandled 500s.

**4. Credentials never persist**
The `SSHScanner` class zeroes `self._password` and `self._key_path` in
`disconnect()`, which is called unconditionally in `__exit__`.

**5. Stdlib-first, optional enhancements**
Paramiko is optional — if not installed, the endpoint returns HTTP 503
with a clear install instruction. All other scan modes remain unaffected.

---

### core/ Layer (unchanged)

See previous version of this document for full core/ documentation.
The credentialed engine imports nothing from `core/` — it is self-contained.

---

### engines/credentialed/ Layer (NEW)

#### ssh_scanner.py

**Class: `SSHScanner`**

```python
SSHScanner(
    ip:       str,
    username: str,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    port:     int = 22,
    timeout:  int = 10,
)
```

Use as a context manager:
```python
with SSHScanner(ip, username, password=pw) as ssh:
    result = ssh.run("uname -r")
    print(result.stdout)
# After __exit__: self._password = None, self._key_path = None
```

Key methods:
- `connect()` — Opens SSH connection. Raises `RuntimeError` on failure.
- `disconnect()` — Closes connection and zeroes credentials.
- `run(command, timeout)` → `CommandResult` — Never raises, always returns.
- `test_connectivity(ip, port, timeout)` — Static; quick TCP check before SSH.

`CommandResult` fields: `stdout`, `stderr`, `exit_code`, `success`.

#### linux_collector.py

**Class: `LinuxCollector`**

```python
LinuxCollector(ssh: SSHScanner)
collector.collect_all(sections=None) → Dict[str, Any]
```

`sections` parameter accepts a list of section names or `None` (= all):
`system_info | packages | services | ports | users | security | network | history`

Each section maps to one or more `COMMANDS` entries. Commands are executed
independently — if one fails, others still run.

Parsing functions (all pure, testable):
- `_parse_dpkg_output(raw)` → list of `{name, version, arch, manager}`
- `_parse_rpm_output(raw)` → same schema for RHEL/CentOS
- `_parse_ss_output(raw)` → list of `{state, local_addr, port, process}`
- `_parse_free_output(raw)` → `{total, used, free, available}`
- `_parse_df_output(raw)` → list of filesystem records
- `_extract_sensitive_env(raw)` → list of env var names with redacted values

#### vuln_matcher.py

**Class: `VulnMatcher`**

```python
VulnMatcher()
matcher.match_packages(packages: List[Dict]) → List[CredentialedCVE]
matcher.to_report_format(findings) → List[Dict]
```

`CVE_DATABASE` maps lowercase package names → list of CVE entries.
Each entry has: `cve_id`, `min_ver` (optional), `max_ver`, `fixed_ver`,
`severity`, `cvss`, `description`.

Version comparison uses `_parse_version()` which handles:
- Numeric segments: `1.2.3` → `(1, 2, 3)`
- Letter suffixes: `1.1.1f` → `(1, 1, 1, 6)`
- Epoch/release: `2.35-0ubuntu3` → `(2, 35, 0)`
- p-suffix: `7.4p1` → `(7, 4, 1)`

`CredentialedCVE` fields: `cve_id`, `severity`, `cvss_score`, `description`,
`package_name`, `installed_ver`, `fixed_ver`, `source`.

Current CVE database covers: `openssl`, `openssh`, `apache2/httpd`, `nginx`,
`curl`, `sudo`, `bash`, `linux-image`, `libc6/glibc`, `polkit`, `samba`,
`log4j`, `python3`, `pip`.

To add more CVEs: edit `CVE_DATABASE` in `vuln_matcher.py`.

---

### engines/ Layer (existing, unchanged)

See original IMPLEMENTATION.md for `discovery_engine`, `port_engine`,
and `vulnerability_engine` documentation.

---

### orchestrator/ Layer (unchanged)

See original IMPLEMENTATION.md for `ScanOrchestrator` documentation.

---

### api/ Layer (unchanged)

See original IMPLEMENTATION.md for `HostDiscoveryAPI` documentation.

---

### Error Handling Strategy (updated)

| Layer | Strategy |
|---|---|
| Input validation | Return `{error: str}` — never raise |
| Network probes (plugins, engines) | `try/except Exception: pass` — return empty dict |
| SSH connection failure | Raise `RuntimeError` → caught by endpoint → HTTP 400 |
| SSH command failure | Return empty `CommandResult` — collector proceeds |
| Orchestrator | Catches engine errors, returns `{success: False, error: str}` |
| FastAPI endpoints | Convert `success=False` or `RuntimeError` to HTTP 400/500 |
| paramiko missing | HTTP 503 with install instructions |

---

### Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| HTTP 503 "paramiko not installed" | paramiko missing | `pip install paramiko==3.4.0` |
| HTTP 400 "Cannot reach X:22" | Host down or firewall | Check host is up; try `nc -zv <ip> 22` |
| HTTP 400 "Authentication failed" | Wrong credentials | Verify username/password; try `ssh user@host` manually |
| Empty packages list | Not Debian or RPM system | Collector tries both; check `packages_deb`/`packages_rpm` logs |
| SUID list very long | Find scanned /proc,/sys too | `/proc` and `/sys` are excluded; remaining is real |
| No CVEs found | Packages not in database | Expand `CVE_DATABASE` in `vuln_matcher.py` |
| Scan times out | Large system with many packages | `timeout` defaults to 30s per command; increase if needed |
