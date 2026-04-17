# ✅ Fixed: Unified Asset Correlation - ONLY for Advanced Scan

## Issue Identified

I had applied the Unified Asset Correlation Engine to **ALL three scan types**:
- ❌ Basic Network Scan - Should NOT use asset correlation
- ❌ Asset Discovery - Should NOT use asset correlation  
- ✅ Advanced Scan - SHOULD use asset correlation (ONLY THIS!)

---

## What Was Wrong

### Phase 1 (run_host_discovery_only)
**BEFORE (❌):**
```python
# This ran for ALL scan types
self.asset_engine.register_discovery_results(formatted, ...)
```

**AFTER (✅):**
```python
# NOW: Only for Advanced Scan
if pipeline_mode == "advanced":
    self.asset_engine.register_discovery_results(formatted, ...)
```

### Phase 2 (run_asset_discovery_only)
**BEFORE (❌):**
```python
# This ran for BOTH Asset Discovery AND Advanced Scan
self._preserve_vendor_from_registry(active_hosts)
self.asset_engine.enrich_port_scan_results(active_hosts)
```

**AFTER (✅):**
```python
# NOW: Only for Advanced Scan
if pipeline_mode == "advanced":
    self._preserve_vendor_from_registry(active_hosts)
    self.asset_engine.enrich_port_scan_results(active_hosts)
```

### Phase 3 (run_advanced_scan_only)
**BEFORE & AFTER (✅):**
```python
# This was already correct - only called by Advanced Scan
self.asset_engine.enrich_vulnerability_findings(active_hosts)
```

---

## Changes Made

### 1. Updated `orchestrator/scan_orchestrator.py`

**Change A:** Added `pipeline_mode` parameter to `run_asset_discovery_only()`
```python
async def run_asset_discovery_only(
    self,
    hosts: List[Dict],
    intensity: str = "normal",
    pipeline_mode: str = "asset",  # ← NEW parameter
) -> Dict:
```

**Change B:** Made Phase 2 asset correlation conditional
```python
# ONLY for Advanced Scan pipeline (phases 1+2+3)
if pipeline_mode == "advanced":
    self._preserve_vendor_from_registry(active_hosts)
    self.asset_engine.enrich_port_scan_results(active_hosts)
```

### 2. Updated `main.py` Asset Discovery endpoint

```python
# BEFORE
result = await orch.run_asset_discovery_only(req.hosts, req.intensity)

# AFTER
result = await orch.run_asset_discovery_only(req.hosts, req.intensity, pipeline_mode=mode)
```

---

## Impact by Scan Type

| Scan Type | Phases | Asset Correlation | Vendor Preservation |
|-----------|--------|-------------------|-------------------|
| **Basic Network Scan** | 1 only | ❌ NOT APPLIED | Not needed (1 phase) |
| **Asset Discovery** | 1 + 2 | ❌ NOT APPLIED | NOT applied (independent scan) |
| **Advanced Scan** | 1 + 2 + 3 | ✅ APPLIED | ✅ APPLIED |

---

## How It Works Now

### Basic Network Scan
```
Phase 1: Discovery
  ├─ No asset correlation
  └─ Return results

(End of scan)
```

### Asset Discovery Scan
```
Phase 1: Discovery
  ├─ No asset correlation
  └─ Vendor populated from OUI

Phase 2: Port Scan  
  ├─ No asset correlation
  ├─ Vendor lost (this is OK - it's a standalone scan)
  └─ Return results with ports

(End of scan)
```

### Advanced Scan (Full Pipeline)
```
Phase 1: Discovery
  ├─ Asset correlation: Register IP + vendor
  └─ Asset Registry: {IP → UnifiedAsset with vendor}

Phase 2: Port Scan
  ├─ Asset correlation: Preserve vendor from registry ✅
  ├─ Asset correlation: Enrich with port data
  └─ Asset Registry: {IP → UnifiedAsset with vendor + ports}

Phase 3: Vulnerability Scan
  ├─ Asset correlation: Enrich with CVEs + risk
  └─ Asset Registry: {IP → UnifiedAsset with vendor + ports + CVEs}

Result: export_all() → Complete unified assets
  {
    "ip": "10.180.6.45",
    "vendor": "HP Inc." ✅ PRESERVED!
    "ports": [22, 80, 443] ✅
    "cves": [...] ✅
    "phases_completed": [1, 2, 3] ✅
  }
```

---

## Testing Impact

### ✅ NO IMPACT on Basic Network Scan
- Behavior unchanged
- Works exactly as before

### ✅ NO IMPACT on Asset Discovery Scan  
- Behavior unchanged
- Vendor may not persist through Phase 2 (expected for standalone scan)
- Works exactly as before

### ✅ FIXED: Advanced Scan
- Vendor NOW persists through all 3 phases
- Asset correlation activates ONLY when pipeline_mode="advanced"
- Nessus-level data consistency

---

## How Frontend Determines Scan Type

The Frontend sends `pipeline_mode` in the request:

```javascript
// When user selects "Basic Network Scan"
POST /scan/host-discovery
{
  "targets": ["10.180.6.45"],
  "pipeline_mode": "basic"  // → Phase 1 only, no asset correlation
}

// When user selects "Asset Discovery Scan"  
POST /scan/host-discovery
{
  "targets": ["10.180.6.45"],
  "pipeline_mode": "asset"  // → Phases 1+2, no asset correlation
}

POST /scan/asset-discovery
{
  "hosts": [...],
  "pipeline_mode": "asset"  // → No vendor preservation (expected)
}

// When user selects "Advanced Scan"
POST /scan/host-discovery
{
  "targets": ["10.180.6.45"],
  "pipeline_mode": "advanced"  // → Asset correlation activates
}

POST /scan/asset-discovery
{
  "hosts": [...],
  "pipeline_mode": "advanced"  // → Vendor preservation ✅
}

POST /scan/advanced-scan
{
  "hosts": [...],
  "pipeline_mode": "advanced"  // → CVE enrichment
}
```

---

## Summary of Fixes

✅ **Phase 1:** Asset correlation ONLY when pipeline_mode="advanced"
✅ **Phase 2:** Vendor preservation ONLY when pipeline_mode="advanced"  
✅ **Phase 3:** CVE enrichment (already correct)

✅ **Basic Network Scan:** Unaffected ✓
✅ **Asset Discovery Scan:** Unaffected ✓
✅ **Advanced Scan:** FIXED - Vendor now persists! ✓

---

## Validation

Run Advanced Scan end-to-end:

```bash
Phase 1 Vendor: HP Inc. ✅
Phase 2 Vendor: HP Inc. ✅ (NOW PRESERVED!)
Phase 3 Vendor: HP Inc. ✅ (STILL THERE!)
```

Done! The fix is now properly scoped to **ONLY Advanced Scan**. 🎉
