"""
scans/legacy_json_builder.py
───────────────────────────────────────────────────────────────────────────────
Dynamically reconstructs the legacy JSON payload from the normalized 
relational database tables (Assets, Services, Vulnerabilities).
Ensures the frontend UI requires no changes to display newly stored scans.
"""

from sqlalchemy.orm import Session
from sqlalchemy import or_

from db.models.assets import Asset
from db.models.findings import Service, AssetVulnerability, VulnerabilityDefinition
from db.models.scans import Scan, ScanPhase

def build_legacy_scan_results(db: Session, scan_id: str) -> dict:
    """
    Reconstructs the multi-phase JSON blob shape expected by the React frontend:
    {
      "phase1": { "data": [...], "summary": {...} },
      "phase2": { "data": [...], "summary": {...} },
      ...
    }
    """
    results_out = {}
    
    # 1. Fetch all phases for this scan
    phases = db.query(ScanPhase).filter(ScanPhase.scan_id == scan_id).order_by(ScanPhase.phase_order.asc()).all()
    
    if not phases:
        return results_out

    # 2. Gather assets related to this scan
    # We find assets where last_scan_id == scan_id OR they have services/vulns from this scan
    # For a perfect historical record, AssetChangeLog should be joined, but this is a solid approximation.
    assets = db.query(Asset).outerjoin(Service, Service.asset_id == Asset.id).outerjoin(
        AssetVulnerability, AssetVulnerability.asset_id == Asset.id
    ).filter(
        or_(
            Asset.last_scan_id == scan_id,
            Service.scan_id == scan_id,
            AssetVulnerability.scan_id == scan_id
        )
    ).all()

    # Pre-fetch normalized services & vulns for these assets for this specific scan
    services_by_asset = {}
    db_services = db.query(Service).filter(Service.scan_id == scan_id).all()
    for db_svc in db_services:
        services_by_asset.setdefault(db_svc.asset_id, []).append(db_svc)

    vulns_by_asset = {}
    db_vulns = db.query(
        AssetVulnerability, VulnerabilityDefinition
    ).join(
        VulnerabilityDefinition, AssetVulnerability.vuln_id == VulnerabilityDefinition.id
    ).filter(AssetVulnerability.scan_id == scan_id).all()
    
    for av, vdef in db_vulns:
        vulns_by_asset.setdefault(av.asset_id, []).append({
            "cve_id": vdef.cve_id,
            "title": vdef.title,
            "description": vdef.description,
            "severity": vdef.severity,
            "cvss": vdef.base_score,
            "remediation": vdef.remediation,
            "status": av.status
        })

    # 3. Reconstruct Phase payloads based on the actual DB records
    for p in phases:
        phase_key = p.phase_key
        # Convert modern names back to frontend expected legacy names
        legacy_key_map = {
            "host_discovery": "phase1",
            "asset_discovery": "phase2",
            "vulnerability_assessment": "phase3",
            "credentialed": "credentialed"
        }
        out_key = legacy_key_map.get(phase_key, phase_key)
        
        phase_dict = {
            "summary": p.summary or {},
            "data": []
        }

        for asset in assets:
            if out_key == "phase1":
                phase_dict["data"].append({
                    "ip": asset.ip_address,
                    "mac": asset.mac_address,
                    "hostname": asset.hostname,
                    "vendor": asset.operating_system or "Unknown",
                    "state": "up" if asset.is_active else "down"
                })
            
            elif out_key == "phase2":
                asset_services = services_by_asset.get(asset.id, [])
                if asset_services or asset.last_scan_id == scan_id: 
                    # Include if it had services or was active in this scan
                    ports_list = []
                    for svc in asset_services:
                        ports_list.append({
                            "port": svc.port,
                            "protocol": svc.protocol,
                            "service": svc.service_name,
                            "version": svc.version_info,
                            "state": "open" if svc.is_open else "closed"
                        })
                    
                    if ports_list:
                        phase_dict["data"].append({
                            "ip": asset.ip_address,
                            "mac": asset.mac_address,
                            "os_guess": asset.operating_system,
                            "ports": ports_list
                        })

            elif out_key == "phase3":
                asset_vulns = vulns_by_asset.get(asset.id, [])
                if asset_vulns:
                    phase_dict["data"].append({
                        "ip": asset.ip_address,
                        "vulnerabilities": asset_vulns
                    })

        results_out[out_key] = phase_dict

    return results_out
