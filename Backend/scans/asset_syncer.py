"""
scans/asset_syncer.py
───────────────────────────────────────────────────────────────────────────────
Performs "Identity Resolution" and synchronizes scanner payload blobs
into their respective normalized PostgreSQL rows (assets, services, findings).
"""

import logging
from typing import Optional, Any
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert

from db.models.assets import Asset
from db.models.findings import Service, AssetVulnerability, VulnerabilityDefinition
from db.base import utcnow

logger = logging.getLogger(__name__)

def _resolve_ip(host_data: dict) -> str:
    return host_data.get("ip_address") or host_data.get("ip") or "0.0.0.0"

def _resolve_mac(host_data: dict) -> str:
    mac = host_data.get("mac_address") or host_data.get("mac")
    return mac if mac and str(mac).upper() != "N/A" and str(mac).upper() != "UNKNOWN" else "00:00:00:00:00:00"


def sync_host_discovery(db: Session, scan_id: str, org_id: str, user_id: Optional[str], hosts: list[dict]):
    """
    Called after Phase 1 (Host Discovery).
    Upserts IPs and MAC addresses into the Asset registry.
    """
    if not hosts:
        return

    logger.info(f"Syncing {len(hosts)} discovered hosts to Asset Registry for scan: {scan_id}")

    for host in hosts:
        ip = _resolve_ip(host)
        mac = _resolve_mac(host)
        hostname = host.get("hostname") or host.get("hostnames", [None])[0] if isinstance(host.get("hostnames"), list) else host.get("hostname")
        vendor = host.get("vendor", "Unknown")

        # Identity Resolution: Look up primarily by MAC (if we have it), fallback to IP
        asset = None
        if mac and mac != "00:00:00:00:00:00":
            asset = db.query(Asset).filter(Asset.org_id == org_id, Asset.mac_address == mac).first()
        
        if not asset and ip and ip != "0.0.0.0":
            asset = db.query(Asset).filter(Asset.org_id == org_id, Asset.ip_address == ip).first()

        if asset:
            # Update existing asset
            if mac and mac != "00:00:00:00:00:00":
                asset.mac_address = mac
            if ip and ip != "0.0.0.0":
                asset.ip_address = ip
            if hostname:
                asset.hostname = hostname
            if vendor and vendor != "Unknown":
                asset.vendor = vendor
            
            asset.last_seen_at = utcnow()
            asset.last_scan_id = scan_id
            asset.is_active = host.get("state") == "up"

        else:
            # Insert new asset
            asset = Asset(
                org_id=org_id,
                ip_address=ip if ip != "0.0.0.0" else None,
                mac_address=mac if mac != "00:00:00:00:00:00" else None,
                hostname=hostname,
                vendor=vendor if vendor != "Unknown" else None,
                is_active=host.get("state") == "up",
                last_scan_id=scan_id
            )
            db.add(asset)
            
    db.commit()


def sync_asset_discovery(db: Session, scan_id: str, org_id: str, user_id: Optional[str], hosts: list[dict]):
    """
    Called after Phase 2 (Asset Discovery / Port Scan).
    Upserts open ports mapping to the newly registered assets.
    """
    if not hosts:
        return

    logger.info(f"Syncing Phase 2 asset features (ports/services) for scan: {scan_id}")

    for host in hosts:
        ip = _resolve_ip(host)
        mac = _resolve_mac(host)

        # Resolve asset again
        asset = None
        if mac and mac != "00:00:00:00:00:00":
            asset = db.query(Asset).filter(Asset.org_id == org_id, Asset.mac_address == mac).first()
        if not asset and ip and ip != "0.0.0.0":
            asset = db.query(Asset).filter(Asset.org_id == org_id, Asset.ip_address == ip).first()

        if not asset:
            continue # If no asset found, we can't tie ports to it.

        ports = host.get("ports", [])
        for p in ports:
            port_num = p.get("port")
            if not port_num:
                continue
            
            proto = p.get("protocol", "tcp").lower()
            service_name = p.get("service") or p.get("name", "unknown")
            version = p.get("version") or p.get("product") or ""

            # Check if this precise service runs on this asset
            svc = db.query(Service).filter(
                Service.asset_id == asset.id,
                Service.port == int(port_num),
                Service.protocol == proto
            ).first()

            if svc:
                svc.service_name = service_name
                svc.version_info = version
                svc.is_open = True
                svc.scan_id = scan_id
                svc.updated_at = utcnow()
            else:
                svc = Service(
                    asset_id=asset.id,
                    scan_id=scan_id,
                    port=int(port_num),
                    protocol=proto,
                    service_name=service_name,
                    version_info=version,
                    is_open=True
                )
                db.add(svc)

        # Update Asset OS fingerprint if we received a deep NMAP scan result
        os_match = host.get("os_match") or host.get("os_guess")
        if os_match:
            asset.os_name = os_match

    db.commit()


def sync_advanced_scan(db: Session, scan_id: str, org_id: str, user_id: Optional[str], hosts: list[dict]):
    """
    Called after Phase 3 (Advanced Scan / Vulnerability Assessment).
    Upserts CVEs and binds them to Assets.
    """
    if not hosts:
        return

    logger.info(f"Syncing Phase 3 vulnerabilities for scan: {scan_id}")

    for host in hosts:
        ip = _resolve_ip(host)
        asset = db.query(Asset).filter(Asset.org_id == org_id, Asset.ip_address == ip).first()

        if not asset:
            continue

        vulns = host.get("vulnerabilities", [])
        for v in vulns:
            cve_id = v.get("cve_id") or v.get("cve") or v.get("id")
            if not cve_id:
                continue

            # Upsert into CVE Catalog (VulnerabilityDefinition)
            cve_def = db.query(VulnerabilityDefinition).filter(VulnerabilityDefinition.cve_id == cve_id).first()
            if not cve_def:
                cve_def = VulnerabilityDefinition(
                    cve_id=cve_id,
                    title=v.get("title", f"Vulnerability {cve_id}"),
                    description=v.get("description", ""),
                    severity=v.get("severity", "medium").lower(),
                    base_score=float(v.get("cvss", v.get("cvss_score", 0.0))),
                    remediation=v.get("remediation") or v.get("solution") or ""
                )
                db.add(cve_def)
                db.flush()

            # Link vulnerability to asset in AssetVulnerability
            finding = db.query(AssetVulnerability).filter(
                AssetVulnerability.asset_id == asset.id,
                AssetVulnerability.vuln_id == cve_def.id
            ).first()

            if finding:
                finding.last_seen_at = utcnow()
                finding.scan_id = scan_id
            else:
                finding = AssetVulnerability(
                    scan_id=scan_id,
                    asset_id=asset.id,
                    vuln_id=cve_def.id,
                    status="open",
                    discovered_at=utcnow(),
                    last_seen_at=utcnow()
                )
                db.add(finding)

    db.commit()
