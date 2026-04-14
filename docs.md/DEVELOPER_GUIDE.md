# CCure Audit PRO — Developer Guide

**Version:** 1.0.0  
**Audience:** Engineers extending the scanner with new plugins, engines, or API endpoints

---

## Adding a New Vulnerability Plugin

Vulnerability plugins are the primary extension point. Each plugin targets one specific protocol or security check. Adding a plugin takes under 30 lines of code.

### Step 1: Create the Plugin Module

Create a new file in `Backend/engines/vulnerability/plugins/`:

```python
# Backend/engines/vulnerability/plugins/my_service.py
"""
my_service.py
Checks for <MY_SERVICE> vulnerabilities on the target host.
"""

from typing import Dict, List


def run(ip: str, open_ports: List[int], **kwargs) -> Dict:
    """
    Plugin contract:
      - ip: target IP address
      - open_ports: list of open TCP port numbers for this host
      - Returns: dict of findings to merge into the host record
      - Raise nothing — caller catches all exceptions
    """
    # Skip hosts that don't have our target port open
    if 12345 not in open_ports:
        return {}

    result = {}

    try:
        # Your detection logic here
        finding = _check_my_service(ip)
        if finding:
            result["my_service_info"] = finding

            # Emit CVEs if applicable
            if finding.get("vulnerable"):
                result["cves"] = [
                    {
                        "cve_id": "CVE-2024-XXXXX",
                        "severity": "High",
                        "cvss_score": 8.1,
                        "description": "...",
                    }
                ]
    except Exception:
        pass  # Never let a plugin failure propagate

    return result


def _check_my_service(ip: str) -> dict:
    import socket
    try:
        with socket.create_connection((ip, 12345), timeout=3) as sock:
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return {"banner": banner, "vulnerable": "version 1.0" in banner}
    except Exception:
        return {}
```

### Step 2: Register the Plugin

Add it to the `PLUGINS` list in `vulnerability_engine.py`:

```python
# Backend/engines/vulnerability/vulnerability_engine.py

from engines.vulnerability.plugins import (
    tls_scanner,
    http_analyzer,
    ssh_probe,
    smb_probe,
    snmp_probe,
    udp_scanner,
    icmp_probe,
    ftp_checker,
    my_service,   # ← Add your plugin here
)

PLUGINS = [
    tls_scanner,
    http_analyzer,
    ssh_probe,
    smb_probe,
    snmp_probe,
    udp_scanner,
    icmp_probe,
    ftp_checker,
    my_service,   # ← And here
]
```

That's all. The `VulnerabilityEngine` will automatically run your plugin concurrently with all others.

### Plugin Contract Rules

| Rule | Reason |
|------|--------|
| Never raise exceptions from `run()` | One plugin failure must not abort the entire host scan |
| Return empty dict `{}` if nothing found | Merge logic skips empty dicts silently |
| Use `cves` key (list) for vulnerabilities | The engine extends this list, not replaces it |
| Use short socket timeouts (≤ 5s) | Plugins run concurrently; a slow plugin blocks its thread |
| Do not access the database | Plugins are stateless; CVE lookup uses `core.cve_database` |
| CVE engine runs after all other plugins | If your plugin needs banner data from other plugins, it cannot be a standard plugin — extend `cve_engine.py` instead |

### Recognized Result Keys

| Key              | Type     | Description                                    |
|------------------|----------|------------------------------------------------|
| `tls_info`       | dict     | TLS/SSL findings (TLSInfo schema)              |
| `http_audit`     | dict     | HTTP header findings (HTTPAudit schema)         |
| `ssh_info`       | dict     | SSH banner and algorithm findings              |
| `smb_info`       | dict     | SMB version and detection findings             |
| `snmp_info`      | dict     | SNMP community string response                 |
| `udp_services`   | list     | Discovered UDP services                        |
| `icmp_info`      | dict     | ICMP probe results                             |
| `ftp_info`       | dict     | FTP anonymous access findings                  |
| `cves`           | list     | CVE findings (normalized CVE dict schema)      |
| Any other key    | any      | Merged directly onto the host dict — use unique names |

---

## Adding a New Scan Endpoint

To expose a new scan type through the API:

### Step 1: Define the Request Model

```python
# In main.py
class MyNewScanRequest(BaseModel):
    targets: List[str] = Field(..., example=["192.168.1.0/24"])
    my_option: str = Field("default", example="value")
    pipeline_mode: Optional[str] = Field("basic")
```

### Step 2: Add the Endpoint

```python
@app.post("/scan/my-new-scan", tags=["Phase-Selective Scans"])
async def scan_my_new_scan(
    req: MyNewScanRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    orch = _get_api()._orch
    result = await orch.run_my_new_scan(req.targets, req.my_option)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    # Persist, generate PDF, etc.
    return result
```

### Step 3: Add the Orchestrator Method

```python
# In orchestrator/scan_orchestrator.py
async def run_my_new_scan(self, targets: List[str], option: str) -> Dict:
    # Your orchestration logic here
    ...
```

---

## Adding a New Discovery Scan Mode

To add a new host discovery strategy:

1. Add the new mode to the `DiscoveryScanType` enum in `core/models.py`:
```python
class DiscoveryScanType(Enum):
    ...
    MY_PROTOCOL = "my_protocol"
```

2. Implement the probe in `engines/discovery/discovery_engine.py` — add a method like `_probe_my_protocol()` and call it from `run()` when `st == DiscoveryScanType.MY_PROTOCOL`.

3. Update the privilege downgrade logic in `ScanOrchestrator._resolve()` if your mode requires elevated privileges.

4. Update `scanConfig.js` if the frontend `scan_type` selector should expose the new mode.

---

## Extending the Credentialed Scanner

### Adding a New Linux Collection Section

1. Add commands to the `COMMANDS` dict in `linux_collector.py`:
```python
COMMANDS = {
    ...
    "my_data": "my-command --output json 2>/dev/null",
}
```

2. Add a section collector method to `LinuxCollector`:
```python
def _collect_my_data(self) -> dict:
    result = self._ssh.run(COMMANDS["my_data"], timeout=10)
    if not result.success:
        return {}
    return {"my_data_field": self._parse_my_data(result.stdout)}
```

3. Call it from `collect_all()`:
```python
if run_all or "my_data" in sections:
    result.update(self._collect_my_data())
```

4. Add the new section name to the API docs in `API_REFERENCE.md`.

---

## Data Flow Reference

When a Phase 3 scan completes, data flows as follows:

```
POST /scan/advanced-scan
    │
    ├── ScanOrchestrator.run_advanced_scan_only(hosts)
    │       │
    │       ├── _normalize_host_record(h) for each h         # key aliasing
    │       ├── filter active hosts
    │       ├── VulnerabilityEngine.run(active_hosts)
    │       │       │
    │       │       ├── for each host:
    │       │       │     TokenBucket.consume()
    │       │       │     _run_plugins(host)
    │       │       │         │
    │       │       │         ├── ThreadPoolExecutor
    │       │       │         │     ├── tls_scanner.run(ip, ports)
    │       │       │         │     ├── http_analyzer.run(ip, ports)
    │       │       │         │     ├── ssh_probe.run(ip, ports)
    │       │       │         │     ├── smb_probe.run(ip, ports)
    │       │       │         │     ├── snmp_probe.run(ip, ports)
    │       │       │         │     ├── udp_scanner.run(ip, ports)
    │       │       │         │     ├── icmp_probe.run(ip, ports)
    │       │       │         │     └── ftp_checker.run(ip, ports)
    │       │       │         │
    │       │       │         └── cve_engine.run(ip, ports, port_dets)  [serial, last]
    │       │       │
    │       │       └── _score_host(host)
    │       │               │
    │       │               ├── deduplicate_cves(host["cves"])
    │       │               └── calculate_risk(ports, cves, http, tls)
    │       │                     → host["host_risk_score"], host["host_risk_level"]
    │       │
    │       ├── _apply_os_inference(active_hosts)
    │       └── format + return result dict
    │
    ├── _resolve_report_context(db, user.id, ...)             # metadata enrichment
    ├── _apply_phase1_summary_hints(result, db, ...)          # backfill Phase 1 counts
    ├── orch.generate_phase_report(result, "phase_selective_scan")  # PDF
    ├── update_scan_phase(db, scan_id, phase=3, is_final=True, ...)  # DB write
    └── return result + scan_id + reports
```

---

## Coding Standards

### Python
- **Type hints everywhere.** Function signatures must use `List`, `Dict`, `Optional`, etc. from `typing` (Python 3.12 supports the native generics too).
- **Dataclasses for data containers.** New result types should be `@dataclass` in `core/models.py`, not dicts.
- **No raw SQL.** Use SQLAlchemy ORM or `text()` for migrations in `ensure_scan_schema()`.
- **Logging.** Use `logging.getLogger("ccure.<module_name>")`. Never use `print()` in production code.
- **No secrets in logs.** Never log passwords, keys, or tokens.

### Error Handling
- Plugin errors: caught silently by `VulnerabilityEngine._run_plugins()`. Log at DEBUG level if needed.
- Scan errors: endpoints use try/except; failed scans call `mark_scan_failed()` before re-raising.
- DB errors: the database is SQLite — no connection pooling is needed, but all DB access should be within a `Session` context from `get_db()`.

### Frontend
- **ScanContext** is the state store for active scan results. Write new result pages to read from `ScanContext` and use `sessionStorage` persistence for browser refresh survival.
- **scanConfig.js** is the canonical pipeline definition. Do not hardcode phase lists in component code.
- **axiosInstance.js** handles JWT injection and token refresh automatically. All API calls should go through this instance.

---

## Running Tests

```bash
cd Backend
pytest tests/ -v
```

Test files:
- `tests/test_cve_db.py` — CVE database query correctness
- `tests/test_windows_collector.py` — Windows collector unit tests
- `tests/check_db.py` — Schema inspection utility (not a pytest test)

The test suite uses `pytest` with optional coverage:
```bash
pytest tests/ --cov=. --cov-report=html
```

---

## Key Design Decisions

### Why frontend-driven orchestration?
The frontend holds phase results in React state (ScanContext). This allows the user to inspect Phase 1 results before committing to Phase 2, or abort after Phase 2 without running Phase 3. It also means the frontend can re-run any phase independently with different parameters. Backend phases are stateless — they accept input and return output without needing to know what came before.

### Why SQLite instead of PostgreSQL?
SQLite simplifies deployment (single file, no DB server) for the current scope. The SQLAlchemy ORM abstracts the database, so migrating to PostgreSQL is a `create_engine()` URL change and a `--env` variable update. The `scans.models.ensure_scan_schema()` migration approach would need replacement with Alembic for PostgreSQL.

### Why not async throughout?
The DiscoveryEngine and PortEngine are async (`await`-able) because they do high-concurrency network I/O. The VulnerabilityEngine is sync (uses `ThreadPoolExecutor`) because plugins do blocking socket operations that are better managed with a thread pool than asyncio tasks. Mixing both models in the orchestrator is intentional.
