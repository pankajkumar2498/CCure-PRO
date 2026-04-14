# CCure Audit PRO — Scan Orchestration Flow

**Version:** 2.2.0

---

## Overview

The `ScanOrchestrator` is the single coordination layer between the HTTP API and the scan engines. It holds no HTTP context (no `Request`, no `Response`, no DB session) — those stay in `main.py`. Its job is to:

1. Accept high-level scan parameters
2. Route them to the correct engine sequence
3. Format and return structured result dicts
4. Optionally generate PDF reports

---

## Pipeline Mode Resolution

Every API request that carries a `pipeline_mode` field goes through `resolve_pipeline_mode()` before any scan logic executes:

```python
PIPELINE_PHASES = {
    "basic":    [1],
    "asset":    [1, 2],
    "advanced": [1, 2, 3, 4],
}

def resolve_pipeline_mode(raw: Optional[str]) -> str:
    if raw and raw.lower() in VALID_PIPELINE_MODES:
        return raw.lower()
    return "basic"   # safe default on unknown input
```

This ensures the backend never acts on an unrecognized pipeline mode. Unknown values are logged as warnings and default to `"basic"`.

---

## Phase Validation Guards

Each phase endpoint validates that the requested phase is part of the declared pipeline before executing any scan logic. These guards prevent misuse (e.g., calling `/scan/advanced-scan` with `pipeline_mode="basic"`):

```
POST /scan/asset-discovery  +  pipeline_mode="basic"
    │
    ▼
is_phase_in_pipeline("basic", 2)
    → PIPELINE_PHASES["basic"] = [1]
    → 2 not in [1]
    → HTTPException(400, "Asset Discovery is not part of the 'basic' pipeline")
```

```
POST /scan/advanced-scan  +  pipeline_mode="asset"
    │
    ▼
is_phase_in_pipeline("asset", 3)
    → PIPELINE_PHASES["asset"] = [1, 2]
    → 3 not in [1, 2]
    → HTTPException(400, "Advanced Scan is not part of the 'asset' pipeline")
```

---

## Terminal Phase Logic

Each pipeline has a terminal phase — the phase that closes the scan record (sets `status="complete"`):

```
pipeline_mode="basic"    → terminal_phase=1  → scan closed after Host Discovery
pipeline_mode="asset"    → terminal_phase=2  → scan closed after Asset Discovery
pipeline_mode="advanced" → terminal_phase=3  → scan closed after Advanced Scan
```

The backend determines `is_final` for each `update_scan_phase()` call:

```python
terminal = get_terminal_phase(mode)       # 1, 2, or 3
is_final  = (current_phase == terminal)   # True only for the last phase of the pipeline
```

This means:
- In `advanced` mode: Phase 1 and Phase 2 calls set `is_final=False` → scan stays `"running"`
- Phase 3 call sets `is_final=True` → scan transitions to `"complete"`

---

## State Transitions

```
Scan record lifecycle:

CREATE (via create_scan)
    status = "running"
    phase  = 1
        │
        │   (for basic mode only)
        ├── is_final=True → status = "complete"
        │
        │   (for asset/advanced mode)
        ▼
    POST /scan/asset-discovery (update_scan_phase phase=2)
    status = "running"  (asset: is_final=True → "complete")
    phase  = 2
        │
        │   (for advanced mode only)
        ▼
    POST /scan/advanced-scan (update_scan_phase phase=3, is_final=True)
    status = "complete"
    phase  = 3
        │
        ▼
    User can: archive → is_archived=True
              delete  → is_deleted=True  (soft delete → Recycle Bin)
              purge   → physical DELETE from DB
```

If any phase fails:

```
Exception caught in endpoint
    │
    ▼
mark_scan_failed(db, scan_id, user_id, error_message)
    status = "failed"
    failure_reason = error_message
```

---

## Error Handling Strategy

### Engine-Level Errors
- Plugin exceptions are silently caught by `VulnerabilityEngine._run_plugins()`
- One failing plugin never aborts the host scan or other plugins

### Phase-Level Errors
```python
try:
    result = await orch.run_asset_discovery_only(...)
    ...
except HTTPException:
    mark_scan_failed(db, req.scan_id, ...)
    raise                              # re-raise to return HTTP error to client
except Exception as exc:
    mark_scan_failed(db, req.scan_id, ...)
    raise HTTPException(500, "Scan failed")
```

Every phase endpoint wraps its scan call in this pattern. The scan record is always updated to `failed` status before the exception propagates, so the history page never shows a permanently `running` scan.

### Scan Not Found
`update_scan_phase()` returns `None` if the scan_id doesn't exist or doesn't belong to the user. The endpoint checks this and returns `404`:
```python
if not updated:
    raise HTTPException(404, "Scan not found.")
```

---

## Progress Tracking

For large subnet scans, real-time progress is tracked in an in-memory dict (`_scan_progress`) keyed by `scan_id`:

```python
_scan_progress: dict[int, dict] = {}
_progress_lock = Lock()             # thread-safe updates from concurrent scan workers
```

Progress is written by the scan engine as hosts are processed. The frontend polls `GET /scan/progress/{scan_id}` during long-running scans to display a progress bar.

Progress data is cleared after the scan completes. If `GET /scan/progress/{scan_id}` returns `{"status": "not_found"}`, the scan has finished and results should be read from `GET /scans/{scan_id}`.

---

## Report Context Resolution

Before generating a PDF report or storing metadata, `_resolve_report_context()` builds a human-readable context dict with:
- `target` — the original user-input target string (not an IP list)
- `scan_method` — the normalized discovery method (ADAPTIVE, ARP, TCP, etc.)

This context is merged into `result["metadata"]` so reports display meaningful information like `"Target: 192.168.1.0/24"` rather than a list of 254 individual IPs.

Priority chain for target resolution:
1. `request.targets` — what the user typed
2. `scan.target` from DB — stored during Phase 1
3. `summary.original_targets` from Phase 1 payload
4. IP list extracted from the `hosts` array

---

## Phase 1 Summary Backfill

Phases 2 and 3 receive only the active host subset as input (inactive hosts are filtered out before port scanning). This means their result `summary` would show incorrect `total_hosts` and `active_hosts` counts without a correction.

`_apply_phase1_summary_hints()` reads the Phase 1 payload from the `ScanPhaseResult` table and backfills these counts into the Phase 2/3 summary:

```python
# Phase 3 summary without backfill:
{"total_hosts": 38, "active_hosts": 38, ...}   # only active hosts counted

# Phase 3 summary with backfill from Phase 1:
{"total_hosts": 254, "active_hosts": 38, "inactive_hosts": 216, ...}   # correct
```

This ensures the final report accurately reflects the entire scanned subnet, not just the hosts that reached Phase 3.

---

## Adaptive Scan Mode — Decision Tree

When `scan_type="adaptive"`, the DiscoveryEngine selects its probe strategy at runtime:

```
Is the target in the same /24 subnet as the scanner?
    │
    ├── YES (LAN)
    │       │
    │       ├── Has root/admin privileges?
    │       │       ├── YES → Use ARP (fastest, most reliable on LAN)
    │       │       └── NO  → Use TCP connect (fallback)
    │       │
    │       └── ARP scan complete
    │
    └── NO (WAN / remote subnet)
            │
            ├── Has root/admin privileges?
            │       ├── YES → Use TCP SYN (stealthy, no full connection)
            │       └── NO  → Use TCP connect
            │
            └── TCP probe complete
```

The adaptive decision is logged in `metadata.privilege_warning` if a downgrade occurred.

---

## Concurrent Execution Model

| Engine          | Concurrency Model    | Reason                                                |
|-----------------|----------------------|-------------------------------------------------------|
| DiscoveryEngine | asyncio tasks        | High IP count; pure I/O wait; async ideal             |
| PortEngine      | asyncio tasks        | High port count per host; pure I/O wait               |
| VulnerabilityEngine | ThreadPoolExecutor | Plugins do blocking socket I/O; threads avoid GIL issues with socket timeouts |
| CVE Engine      | Serial (after pool)  | Needs all plugin banner data; one call per host       |

Each host in `VulnerabilityEngine.run()` is processed serially (with rate limiting via `TokenBucket`), but all plugins for a single host run concurrently.

---

## OS Inference Application Points

OS inference (`_apply_os_inference`) runs at two points in the pipeline:

1. **After Phase 2 (Port Engine)** — port-level evidence (open ports, banners) used to infer OS
2. **After Phase 3 (Vulnerability Engine)** — service-level evidence (SSH banner, HTTP server header, SNMP sysDescr) used to refine OS guess

The Phase 1 OS guess (from TTL/TCP window) is preserved if Phase 2/3 inference produces "Unknown". A definitive Phase 3 service-level result overwrites the less certain Phase 1 TTL guess.
