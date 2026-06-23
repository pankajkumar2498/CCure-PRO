"""
Module: core.amt_reconciliation
Purpose: Reconciliation engine matching scanned assets with AMT inventory.
Author:  Pair Engineer
"""

import logging
from datetime import datetime
from typing import Dict, Optional
from sqlalchemy import or_
from sqlalchemy.orm import Session

from db.models.assets import Asset, AssetChangeLog
from db.models.amt import AMTInventoryRecord
from core.utils import normalize_mac

log = logging.getLogger("ccure.amt_reconciliation")


def normalize_category(asset_type: str) -> Optional[str]:
    """Normalize corporate AMT asset types to standard categories."""
    if not asset_type:
        return None
    val = asset_type.lower()
    if "laptop" in val:
        return "laptop"
    if "desktop" in val:
        return "desktop"
    if "server" in val:
        return "server"
    if "tablet" in val or "mobile" in val or "phone" in val:
        return "tablet / mobile"
    if "printer" in val:
        return "printer"
    return "workstation"


def reconcile_amt_inventory(db: Session, org_id: str) -> Dict:
    """
    Reconcile active scanned assets with optional AMT inventory records.
    Enriches scanned assets, tracks provenance, and logs changes.
    """
    now_str = datetime.utcnow().isoformat()
    stats = {"matched": 0, "shadow_it": 0, "updated": 0}

    # Fetch all scanned assets with a non-null MAC
    scanned_assets = db.query(Asset).filter(
        Asset.org_id == org_id,
        Asset.mac_address != None
    ).all()

    if not scanned_assets:
        log.info(f"No scanned assets with MAC addresses found for org {org_id}. Skipping reconciliation.")
        return stats

    # Batch-fetch all AMT reference records for this organization to match by MAC address
    amt_records = db.query(AMTInventoryRecord).filter(AMTInventoryRecord.org_id == org_id).all()

    # Map both primary and secondary MAC addresses to their respective AMT record
    amt_map = {}
    for rec in amt_records:
        if rec.mac_address_1:
            amt_map[normalize_mac(str(rec.mac_address_1))] = rec
        if rec.mac_address_2:
            amt_map[normalize_mac(str(rec.mac_address_2))] = rec

    for asset in scanned_assets:
        norm_mac = normalize_mac(str(asset.mac_address))
        if not norm_mac:
            continue

        amt_record = amt_map.get(norm_mac)

        if not amt_record:
            stats["shadow_it"] += 1
            # If the asset was previously matched, flag it as stale
            custom_attrs = dict(asset.custom_attributes or {})
            if "correlation" in custom_attrs:
                correlation = dict(custom_attrs["correlation"])
                if correlation.get("status") != "stale":
                    correlation["status"] = "stale"
                    correlation["de-correlated_at"] = now_str
                    custom_attrs["correlation"] = correlation
                    asset.custom_attributes = custom_attrs
                    asset.updated_at = datetime.utcnow()
                    db.add(AssetChangeLog(
                        asset_id=asset.id,
                        change_type="amt_correlation_stale",
                        field_name="custom_attributes",
                        old_value="active",
                        new_value="stale",
                        detected_at=datetime.utcnow()
                    ))
                    stats["updated"] += 1
            continue

        stats["matched"] += 1
        updated_any = False
        provenance = dict(asset.provenance or {})

        # 1. Reconcile Owner (respect manual overrides)
        owner_prov = provenance.get("owner", {})
        if owner_prov.get("source") != "analyst":
            new_owner = amt_record.asset_user.strip() if amt_record.asset_user else None
            if asset.owner != new_owner:
                # Log the change
                db.add(AssetChangeLog(
                    asset_id=asset.id,
                    change_type="owner_reassigned",
                    field_name="owner",
                    old_value=asset.owner,
                    new_value=new_owner,
                    detected_at=datetime.utcnow()
                ))
                asset.owner = new_owner
                provenance["owner"] = {
                    "source": "amt_import",
                    "updated_at": now_str
                }
                updated_any = True

        # 2. Reconcile Device Category
        cat_prov = provenance.get("device_category", {})
        if cat_prov.get("source") != "analyst":
            new_cat = normalize_category(amt_record.asset_type)
            if asset.device_category != new_cat:
                asset.device_category = new_cat
                provenance["device_category"] = {
                    "source": "amt_import",
                    "updated_at": now_str
                }
                updated_any = True

        # 3. Reconcile Vendor
        vendor_prov = provenance.get("vendor", {})
        if vendor_prov.get("source") != "analyst":
            new_vendor = amt_record.vendor.strip() if amt_record.vendor else None
            if asset.vendor != new_vendor:
                asset.vendor = new_vendor
                provenance["vendor"] = {
                    "source": "amt_import",
                    "updated_at": now_str
                }
                updated_any = True

        # 4. Enrich custom JSONB attributes
        custom_attrs = dict(asset.custom_attributes or {})
        custom_attrs.update({
            "amt_asset_tag": amt_record.asset_tag,
            "amt_asset_name": amt_record.asset_name,
            "serial_number": amt_record.serial,
            "owner_employee_id": amt_record.emp_id,
            "amt_status": amt_record.status,
            "amt_location": amt_record.location,
            "amt_location_id": amt_record.location_id,
            "amt_company_name": amt_record.company_name,
            "correlation": {
                "matched_by": "mac_address",
                "matched_at": now_str,
                "confidence": 1.0,
                "status": "active"
            }
        })
        asset.custom_attributes = custom_attrs
        asset.provenance = provenance

        if updated_any:
            stats["updated"] += 1
            asset.updated_at = datetime.utcnow()

    db.commit()
    log.info(f"AMT Reconciliation complete for org {org_id}: {stats}")
    return stats
