# API Response Format Updates (Optional but Recommended)

## Current State

The API endpoints in `main.py` return raw host dictionaries. While this maintains backward compatibility, it means the unified asset data is not fully exposed to the frontend.

## Recommended: Update Endpoints to Return Unified Assets

### Before (Current)

```python
@router.post("/scan/advanced-scan")
async def advanced_scan(req: AdvancedScanRequest):
    # ...
    results = await orch.run_advanced_scan_only(active_hosts)
    
    return {
        "status": "success",
        "data": results["data"],  # Raw host dicts ← Old format
        "phase": "Phase 3: Vulnerability Scan",
        "count": len(results["data"]),
    }
```

### After (Recommended)

```python
@router.post("/scan/advanced-scan")
async def advanced_scan(req: AdvancedScanRequest):
    # ...
    results = await orch.run_advanced_scan_only(active_hosts)
    
    # ✅ Export unified assets instead of raw dicts
    unified_assets = orch.asset_engine.export_all()
    
    return {
        "status": "success",
        "data": unified_assets,  # Unified asset JSON with confidence scores
        "phase": "Phase 3: Vulnerability Scan",
        "count": len(unified_assets),
        "metadata": orch.asset_engine.get_stats(),  # Asset registry stats
    }
```

---

## Complete Endpoint Updates

### All Three Endpoints (Phase 1, 2, 3)

**File:** `main.py`

#### Host Discovery (Phase 1)

```python
@router.post("/scan/host-discovery")
async def host_discovery(req: HostDiscoveryRequest):
    log.info("host_discovery(%s)", req.targets)
    
    orch = ScanOrchestrator(silent=req.silent if hasattr(req, 'silent') else False)
    
    # Determine pipeline mode from scan_type
    mode = get_pipeline_mode(req.scan_type)
    
    # Run Phase 1
    results = await orch.run_host_discovery_only(
        req.targets,
        req.scan_type,
        mode
    )
    
    # ✅ Export unified assets with confidence scores
    unified_assets = orch.asset_engine.export_all()
    
    return {
        "status": "success",
        "data": unified_assets,  # Rich asset data
        "phase": "Phase 1: Host Discovery",
        "count": len(unified_assets),
        "metadata": {
            "discovery_method": "adaptive",
            "discovery_profile": mode,
            "registry_stats": orch.asset_engine.get_stats(),
        }
    }
```

#### Asset Discovery (Phase 2)

```python
@router.post("/scan/asset-discovery")
async def asset_discovery(req: AssetDiscoveryRequest):
    log.info("asset_discovery(%s hosts)", len(req.hosts))
    
    orch = ScanOrchestrator(silent=req.silent if hasattr(req, 'silent') else False)
    
    # Restore asset registry from Phase 1 data (if needed)
    # This happens automatically in run_asset_discovery_only
    
    # Run Phase 2
    results = await orch.run_asset_discovery_only(
        req.hosts,
        req.intensity
    )
    
    # ✅ Export unified assets with ports and OS preserved
    unified_assets = orch.asset_engine.export_all()
    
    return {
        "status": "success",
        "data": unified_assets,  # Vendor + Ports + OS preserved
        "phase": "Phase 2: Asset Discovery",
        "count": len(unified_assets),
        "metadata": {
            "intensity": req.intensity,
            "registry_stats": orch.asset_engine.get_stats(),
            "note": "Vendor data preserved from Phase 1 ✅",
        }
    }
```

#### Advanced Scan (Phase 3)

```python
@router.post("/scan/advanced-scan")
async def advanced_scan(req: AdvancedScanRequest):
    log.info("advanced_scan(%s hosts)", len(req.hosts))
    
    orch = ScanOrchestrator(silent=req.silent if hasattr(req, 'silent') else False)
    
    # Run Phase 3
    results = orch.run_advanced_scan_only(req.hosts)
    
    # ✅ Export complete unified assets with all data
    unified_assets = orch.asset_engine.export_all()
    
    return {
        "status": "success",
        "data": unified_assets,  # Complete unified asset with CVEs
        "phase": "Phase 3: Vulnerability Assessment",
        "count": len(unified_assets),
        "metadata": {
            "registry_stats": orch.asset_engine.get_stats(),
            "note": "Complete asset lifecycle: Discovery → Port Scan → Vulnerability ✅",
        }
    }
```

---

## Frontend Integration

### Current Handling (Will Still Work)

```javascript
// Dashboard.jsx - Current code still works
const response = await fetch('/scan/advanced-scan', {
  method: 'POST',
  body: JSON.stringify(payload)
});

const result = await response.json();
console.log(result.data[0]);  // Unified asset with full data
```

### Enhanced Handling (Recommended)

```javascript
// Dashboard.jsx - Enhanced to show confidence scores
const response = await fetch('/scan/advanced-scan', {
  method: 'POST',
  body: JSON.stringify(payload)
});

const result = await response.json();
const asset = result.data[0];

// Display unified data
console.log({
  ip: asset.ip_address,
  vendor: {
    name: asset.vendor.name,
    confidence: asset.vendor.confidence.confidence_score,  // 0.95
    source: asset.vendor.confidence.source,  // "mac_oui"
  },
  os: {
    name: asset.os.name,
    confidence: asset.os.confidence,  // "High"
    sources: asset.os.secondary_sources,
  },
  ports: asset.open_ports.length,
  cves: asset.security.cves_count,
  riskScore: asset.risk.score,
  phasesCompleted: asset.metadata.phases_completed,  // [1, 2, 3]
});
```

---

## Backward Compatibility

✅ **No Breaking Changes**

The unified asset format contains **all the same data** as the raw host dict, just with additional:
- `vendor.confidence` metadata
- `os.confidence` tracking
- `metadata.phases_completed`
- `metadata.data_sources`

Frontend code checking for `result.data[0].vendor` will work identically.

---

## Optional: Create Response Wrapper

For maximum flexibility, create a response model:

```python
# In main.py or api/models.py

from typing import List, Dict, Any

class AssetResponseModel(BaseModel):
    status: str
    data: List[Dict[str, Any]]
    phase: str
    count: int
    metadata: Dict[str, Any] = {}

# Usage:
@router.post("/scan/advanced-scan")
async def advanced_scan(req: AdvancedScanRequest) -> AssetResponseModel:
    # ... orchestration ...
    
    unified_assets = orch.asset_engine.export_all()
    
    return AssetResponseModel(
        status="success",
        data=unified_assets,
        phase="Phase 3: Vulnerability Assessment",
        count=len(unified_assets),
        metadata=orch.asset_engine.get_stats()
    )
```

---

## Testing Updated Endpoints

### Test Phase 1 with Unified Export

```bash
curl -X POST http://localhost:8000/scan/host-discovery \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["10.180.6.45"],
    "scan_type": "adaptive"
  }' | jq '.data[0]'
```

**Expected Output:**
```json
{
  "ip_address": "10.180.6.45",
  "hostname": "atharv-desktop",
  "vendor": {
    "name": "HP Inc.",
    "confidence": {
      "confidence_score": 0.95,
      "source": "mac_oui"
    }
  },
  "metadata": {
    "phases_completed": [1]
  }
}
```

### Test Phase 2 with Vendor Preserved

```bash
curl -X POST http://localhost:8000/scan/asset-discovery \
  -H "Content-Type: application/json" \
  -d '{
    "hosts": [{"ip_address": "10.180.6.45", ...}],
    "intensity": "normal"
  }' | jq '.data[0] | {ip: .ip_address, vendor: .vendor.name, ports: .open_ports}'
```

**Expected Output:**
```json
{
  "ip": "10.180.6.45",
  "vendor": "HP Inc.",  ← ✅ PRESERVED!
  "ports": [22, 80, 443]
}
```

### Test Phase 3 with Complete Data

```bash
curl -X POST http://localhost:8000/scan/advanced-scan \
  -H "Content-Type: application/json" \
  -d '{
    "hosts": [{"ip_address": "10.180.6.45", ...}]
  }' | jq '.data[0] | {ip: .ip_address, vendor: .vendor.name, os: .os.name, cves: .security.cves_count, phases: .metadata.phases_completed}'
```

**Expected Output:**
```json
{
  "ip": "10.180.6.45",
  "vendor": "HP Inc.",  ← ✅ PRESERVED!
  "os": "Linux 4.15-4.19",  ← ✅ PRESENT!
  "cves": 18,  ← ✅ PRESENT!
  "phases": [1, 2, 3]  ← ✅ ALL COMPLETED!
}
```

---

## Summary of Changes

| Aspect | Current | Recommended |
|--------|---------|-------------|
| **Response Format** | Raw host dict | Unified asset JSON |
| **Vendor in Phase 2** | Raw dict (may have vendor) | Unified asset (guaranteed) |
| **Confidence Data** | Not exposed | Included with sources |
| **Phase Tracking** | Not in response | Included in metadata |
| **Data Sources** | Not tracked | Listed in metadata |
| **Frontend Changes** | None required | Optional enhancements |

---

## Decision Tree

**Option A: Keep Current Implementation** ✅
- No API changes needed
- Asset correlation works silently
- Backward compatible
- Limited data source visibility

**Option B: Update Endpoints** ✅ RECOMMENDED
- API returns unified assets
- Full confidence + source metadata
- Enhanced audit trail
- Slightly larger JSON response
- Frontend gets rich data for display

---

## Implementation Steps

1. **Step 1:** Test current implementation end-to-end
2. **Step 2:** Update one endpoint (e.g., Phase 3) to use `export_all()`
3. **Step 3:** Test frontend integration
4. **Step 4:** If working well, update remaining endpoints (Phase 1, 2)
5. **Step 5:** Document in API docs

---

## Notes

- The current implementation **already works correctly** with implicit asset correlation
- This update just makes the unified asset data explicit in API responses
- No breaking changes to existing frontend code
- Maximum forward compatibility for future enhancements
