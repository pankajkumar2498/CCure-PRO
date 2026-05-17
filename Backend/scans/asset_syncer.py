"""
scans/asset_syncer.py
───────────────────────────────────────────────────────────────────────────────
Performs "Identity Resolution" and synchronizes scanner payload blobs
into their respective normalized PostgreSQL rows (assets, services, findings).
"""

import logging
from typing import Optional, Any, List
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert

from db.models.assets import Asset
from db.models.findings import Service, AssetVulnerability, VulnerabilityDefinition
from db.models.rbac import Organization
from db.base import utcnow, gen_asset_id, gen_service_id

logger = logging.getLogger(__name__)

def _resolve_ip(host_data: dict) -> str:
    return str(host_data.get("ip_address") or host_data.get("ip") or "0.0.0.0").strip()

def _resolve_mac(host_data: dict) -> Optional[str]:
    mac = host_data.get("mac_address") or host_data.get("mac")
    if not mac: return None
    mac_str = str(mac).strip().upper()
    if mac_str in ["N/A", "UNKNOWN", "00:00:00:00:00:00", ""]:
        return None
    return mac_str

def _resolve_asset(host_data: dict, mac_map: dict, ip_map: dict) -> Optional[Asset]:
    """Helper to resolve asset identity using the same waterfall as Phase 1."""
    ip = _resolve_ip(host_data)
    mac = _resolve_mac(host_data)
    
    # Priority 1: MAC
    if mac and mac in mac_map:
        return mac_map[mac]
    
    # Priority 2: IP
    if ip != "0.0.0.0" and ip in ip_map:
        return ip_map[ip]
        
    return None


def sync_host_discovery(db: Session, scan_id: str, org_id: str, user_id: Optional[str], hosts: List[dict]):
    """
    Called after Phase 1 (Host Discovery).
    Performs Identity Resolution (MAC-first) and upserts hosts into the Asset Registry.
    """
    if not hosts:
        return

    logger.info(f"Syncing {len(hosts)} discovered hosts to Asset Registry for scan: {scan_id}")

    # 1. Prepare unique lookups for this batch
    batch_ips = set()
    batch_macs = set()
    for h in hosts:
        ip = _resolve_ip(h)
        mac = _resolve_mac(h)
        if ip != "0.0.0.0": batch_ips.add(ip)
        if mac: batch_macs.add(mac)

    # 2. Pre-fetch ALL candidate assets in one query
    existing_assets = []
    if batch_ips or batch_macs:
        from sqlalchemy import or_
        filters = []
        if batch_ips: filters.append(Asset.ip_address.in_(list(batch_ips)))
        if batch_macs: filters.append(Asset.mac_address.in_(list(batch_macs)))
        
        existing_assets = db.query(Asset).filter(
            Asset.org_id == org_id, 
            or_(*filters)
        ).all()

    # Create maps for quick resolution
    # Note: If multiple rows have same MAC (shouldn't happen but...) or same IP, we take the latest
    db_by_mac = {a.mac_address: a for a in existing_assets if a.mac_address}
    db_by_ip = {a.ip_address: a for a in existing_assets if a.ip_address}

    to_update = []
    to_create = []

    # 3. Resolve Identity Host-by-Host
    for host in hosts:
        ip = _resolve_ip(host)
        mac = _resolve_mac(host)
        hostname = host.get("hostname") or host.get("hostnames", [None])[0] if isinstance(host.get("hostnames"), list) else host.get("hostname")
        vendor = host.get("vendor", "Unknown")
        is_active = host.get("is_active") or host.get("state") == "up"
        discovery_method = host.get("discovery_method") or host.get("method")
        response_time_ms = host.get("response_time_ms") or host.get("elapsed_ms")

        # Identity Resolution Waterfall
        target_asset = None
        
        # Priority 1: Match by MAC
        if mac:
            target_asset = db_by_mac.get(mac)
        
        # Priority 2: Match by IP (only if MAC didn't find anything)
        if not target_asset and ip != "0.0.0.0":
            target_asset = db_by_ip.get(ip)

        if target_asset:
            # We found an identity! Update it.
            # IMPORTANT: If we found it by MAC but it has a DIFFERENT IP now, 
            # we update the IP. This handles DHCP changes perfectly.
            target_asset.ip_address = ip if ip != "0.0.0.0" else target_asset.ip_address
            if mac: target_asset.mac_address = mac
            if hostname: target_asset.hostname = hostname
            if vendor and vendor != "Unknown": target_asset.vendor = vendor
            
            target_asset.last_seen_at = utcnow()
            target_asset.last_scan_id = scan_id
            target_asset.is_active = is_active
            target_asset.discovery_method = discovery_method
            target_asset.response_time_ms = response_time_ms
            target_asset.updated_at = utcnow()
            
            # If the IP changed, update the lookup map to prevent other hosts in this batch
            # from accidentally matching the 'old' IP of this asset.
            db_by_ip[ip] = target_asset
        elif is_active:
            # New Asset Discovery — ONLY if host is actually live.
            # We do NOT insert inactive IPs that are not already in the registry.
            asset_id = gen_asset_id(org_id, ip if ip != "0.0.0.0" else (mac or "unknown"))
            
            new_asset = Asset(
                id=asset_id,
                org_id=org_id,
                ip_address=ip if ip != "0.0.0.0" else None,
                mac_address=mac,
                hostname=hostname,
                vendor=vendor if vendor != "Unknown" else None,
                is_active=is_active,
                discovery_method=discovery_method,
                response_time_ms=response_time_ms,
                last_scan_id=scan_id,
                last_seen_at=utcnow(),
                created_at=utcnow(),
                updated_at=utcnow(),
            )
            db.add(new_asset)
            to_create.append(new_asset)
            
            # Add to maps so subsequent hosts in this same batch can correlate
            if mac: db_by_mac[mac] = new_asset
            if ip != "0.0.0.0": db_by_ip[ip] = new_asset

    # 4. Final Safety: If two hosts in the DB share a MAC/IP due to previous bugs, 
    # the flush might still hit a constraint. We use a try/except or flush carefully.
    try:
        db.flush()
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Asset Sync Phase 1 Failed: {str(e)}")
        # In a real SaaS, we might want to retry with a more aggressive de-duplication script here
        raise


def sync_asset_discovery(db: Session, scan_id: str, org_id: str, user_id: Optional[str], hosts: List[dict]):
    """
    Called after Phase 2 (Asset Discovery / Port Scan).
    Upserts open ports mapping to the newly registered assets using batch operations.
    """
    if not hosts:
        return

    logger.info(f"Syncing Phase 2 asset features (ports/services) for scan: {scan_id}")

    batch_macs = [m for h in hosts if (m := _resolve_mac(h))]
    batch_ips = [i for h in hosts if (i := _resolve_ip(h)) != "0.0.0.0"]

    # Pre-fetch existing assets
    existing_assets = []
    if batch_macs or batch_ips:
        from sqlalchemy import or_
        filters = []
        if batch_macs: filters.append(Asset.mac_address.in_(batch_macs))
        if batch_ips: filters.append(Asset.ip_address.in_(batch_ips))
        
        existing_assets = db.query(Asset).filter(Asset.org_id == org_id, or_(*filters)).all()

    db_by_mac = {a.mac_address: a for a in existing_assets if a.mac_address}
    db_by_ip = {a.ip_address: a for a in existing_assets if a.ip_address}

    # Pre-fetch services for these assets
    asset_ids = [a.id for a in existing_assets]
    existing_services = []
    if asset_ids:
        existing_services = db.query(Service).filter(Service.asset_id.in_(asset_ids)).all()

    service_map = {(s.asset_id, s.port, s.protocol): s for s in existing_services}
    new_services = []

    for host in hosts:
        # Resolve asset using standardized waterfall
        asset = _resolve_asset(host, db_by_mac, db_by_ip)

        if not asset:
            continue

        ports = host.get("open_ports") or host.get("ports") or []
        for p in ports:
            port_num = p.get("port")
            if not port_num:
                continue
            
            proto = p.get("protocol", "tcp").lower()
            service_name = p.get("service") or p.get("name", "unknown")
            product = p.get("product") or ""
            version = p.get("version") or ""
            extra = p.get("extrainfo") or p.get("extra") or ""
            banner = p.get("banner") or ""
            state = p.get("state") or "open"

            # Check if this precise service runs on this asset
            svc = service_map.get((asset.id, int(port_num), proto))

            if svc:
                svc.service_name = service_name
                svc.service_product = product or None
                svc.service_version = version or None
                svc.service_extra = extra or None
                svc.banner = banner or None
                svc.state = state
                svc.scan_id = scan_id
            else:
                svc = Service(
                    id=gen_service_id(asset.id, int(port_num), proto),
                    asset_id=asset.id,
                    scan_id=scan_id,
                    port=int(port_num),
                    protocol=proto,
                    state=state,
                    service_name=service_name,
                    service_product=product or None,
                    service_version=version or None,
                    service_extra=extra or None,
                    banner=banner or None,
                )
                new_services.append(svc)
                service_map[(asset.id, int(port_num), proto)] = svc

        # Update Asset OS fingerprint
        os_match = host.get("os_match") or host.get("os_guess")
        if os_match:
            asset.os_name = os_match

    if new_services:
        db.add_all(new_services)

    db.commit()


def sync_advanced_scan(db: Session, scan_id: str, org_id: str, user_id: Optional[str], hosts: List[dict]):
    """
    Called after Phase 3 (Advanced Scan / Vulnerability Assessment).
    Upserts CVEs and binds them to Assets using batch operations.
    """
    if not hosts:
        return

    logger.info(f"Syncing Phase 3 vulnerabilities for scan: {scan_id}")

    batch_macs = [m for h in hosts if (m := _resolve_mac(h))]
    batch_ips = [i for h in hosts if (i := _resolve_ip(h)) != "0.0.0.0"]

    # Pre-fetch existing assets
    existing_assets = []
    if batch_macs or batch_ips:
        from sqlalchemy import or_
        filters = []
        if batch_macs: filters.append(Asset.mac_address.in_(batch_macs))
        if batch_ips: filters.append(Asset.ip_address.in_(batch_ips))
        
        existing_assets = db.query(Asset).filter(Asset.org_id == org_id, or_(*filters)).all()

    db_by_mac = {a.mac_address: a for a in existing_assets if a.mac_address}
    db_by_ip = {a.ip_address: a for a in existing_assets if a.ip_address}

    # Collect all unique CVE IDs from payload
    all_cve_ids = set()
    for host in hosts:
        vulns = host.get("vulnerabilities") or host.get("cves") or []
        for v in vulns:
            cve_id = v.get("cve_id") or v.get("cve") or v.get("id")
            if cve_id:
                all_cve_ids.add(cve_id)

    # Pre-fetch existing CVE definitions
    existing_cves = []
    if all_cve_ids:
        existing_cves = db.query(VulnerabilityDefinition).filter(VulnerabilityDefinition.cve_id.in_(list(all_cve_ids))).all()
    cve_def_map = {c.cve_id: c for c in existing_cves}

    # Collect asset IDs for findings
    asset_ids = [a.id for a in existing_assets]
    existing_findings = []
    if asset_ids:
        existing_findings = db.query(AssetVulnerability).filter(AssetVulnerability.asset_id.in_(asset_ids)).all()
    finding_map = {(f.asset_id, f.vuln_id): f for f in existing_findings}

    new_cve_defs = []
    new_findings = []

    for host in hosts:
        # Resolve asset using standardized waterfall
        asset = _resolve_asset(host, db_by_mac, db_by_ip)

        vulns = host.get("vulnerabilities") or host.get("cves") or []
        for v in vulns:
            cve_id = v.get("cve_id") or v.get("cve") or v.get("id")
            if not cve_id:
                continue

            # Upsert into CVE Catalog (VulnerabilityDefinition)
            cve_def = cve_def_map.get(cve_id)
            if not cve_def:
                cve_def = VulnerabilityDefinition(
                    id=cve_id,
                    cve_id=cve_id,
                    title=v.get("title", f"Vulnerability {cve_id}"),
                    description=v.get("description", ""),
                    severity=str(v.get("severity", "Medium")).title(),
                    cvss_v3_score=float(v.get("cvss", v.get("cvss_score", 0.0)) or 0.0),
                    references=[],
                    affected_software=[],
                )
                new_cve_defs.append(cve_def)
                cve_def_map[cve_id] = cve_def

    if new_cve_defs:
        db.add_all(new_cve_defs)
        db.flush() # Ensure we have IDs for new definitions

    for host in hosts:
        # Resolve asset
        asset = _resolve_asset(host, db_by_mac, db_by_ip)
        if not asset: continue

        vulns = host.get("vulnerabilities") or host.get("cves") or []
        for v in vulns:
            cve_id = v.get("cve_id") or v.get("cve") or v.get("id")
            if not cve_id: continue
            
            cve_def = cve_def_map.get(cve_id)
            if not cve_def: continue

            # Link vulnerability to asset in AssetVulnerability
            finding = finding_map.get((asset.id, cve_def.id))

            if finding:
                finding.last_seen_at = utcnow()
                finding.scan_id = scan_id
            else:
                finding = AssetVulnerability(
                    id=f"fnd_{asset.id}_{cve_def.id}",
                    org_id=org_id,
                    scan_id=scan_id,
                    asset_id=asset.id,
                    vuln_id=cve_def.id,
                    severity=str(v.get("severity", cve_def.severity or "Medium")).title(),
                    cvss_score=float(v.get("cvss", v.get("cvss_score", 0.0)) or 0.0),
                    status="open",
                    proof=v.get("proof") or v.get("evidence"),
                    plugin_output=v.get("plugin_output") or v.get("description"),
                    first_found_at=utcnow(),
                    last_found_at=utcnow()
                )
                new_findings.append(finding)
                finding_map[(asset.id, cve_def.id)] = finding

        asset.risk_score = int(float(host.get("host_risk_score", 0.0) or 0.0))
        asset.risk_level = str(host.get("host_risk_level", "Info") or "Info").title()
        asset.device_category = host.get("device_category") or asset.device_category
        asset.os_name = host.get("os_guess") or asset.os_name

    if new_findings:
        db.add_all(new_findings)

    db.commit()
