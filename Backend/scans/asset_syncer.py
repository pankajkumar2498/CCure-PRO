"""
scans/asset_syncer.py
───────────────────────────────────────────────────────────────────────────────
Performs "Identity Resolution" and synchronizes scanner payload blobs
into their respective normalized PostgreSQL rows (assets, services, findings).
"""

import logging
from typing import Dict, Optional, Any, List
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy import func, text

from db.models import (
    Asset, AssetChangeLog,
    Service, AssetVulnerability, VulnerabilityDefinition
)
from db.models.rbac import Organization
from db.base import utcnow, gen_asset_id, gen_service_id

logger = logging.getLogger(__name__)

# Signal priority for device_classifier — used to prevent low-confidence
# classifications from overwriting high-confidence ones.
# Matches the priority chain in core/device_classifier.py classify_device():
#   1. snmp       (highest — active OID interrogation)
#   2. l2_sniffer (high — passive CDP/LLDP/STP multicast)
#   3. mdns       (high — mDNS service records)
#   4. netbios    (high — NetBIOS suffix roles)
#   5. nmap_cpe   (medium-high — active OS stack detection)
#   6. port_profile (medium-high — port set hints)
#   7. banner     (medium — service banner keywords)
#   8. oui        (medium — vendor substring match)
#   9. ttl        (low — OS family heuristic)
#   10. none      (fallback — unknown)
_DEVICE_SIGNAL_PRIORITY = {
    "credentialed": 110,
    "snmp": 100,
    "l2_sniffer": 95,
    "mdns": 90,
    "netbios": 85,
    "nmap_cpe": 80,
    "port_profile": 70,
    "banner": 50,
    "oui": 40,
    "ttl": 20,
    "none": 0,
}


def _get_device_signal_priority(host: Dict) -> int:
    """
    Extract the device classification signal from a host dict and return its
    numeric priority.  Higher = more reliable (e.g. SNMP OID).
    """
    signal = host.get("device_category_signal") or "none"
    return _DEVICE_SIGNAL_PRIORITY.get(signal, 0)


def _get_stored_device_signal(asset: Asset) -> Optional[str]:
    """
    Read the stored device classification signal from the asset's custom_attributes.
    Returns None if no previous classification exists.
    """
    attrs = dict(asset.custom_attributes or {})
    provenance = dict(attrs.get("provenance") or {})
    dev_prov = provenance.get("device_category") or {}
    return dev_prov.get("signal")


SOURCE_PRIORITY = {
    "legacy": 5,
    "discovery": 10,
    "basic": 10,
    "host_discovery": 10,
    "asset_discovery": 20,
    "fingerprinting": 20,
    "advanced": 30,
    "vulnerability_audit": 30,
    "scanner": 30,
    "scanner_network": 30,
    "credentialed": 40,
    "credentialed_package": 40,
}

FINDING_SOURCE_FAMILY = {
    "advanced": "network_service",
    "vulnerability_audit": "network_service",
    "scanner": "network_service",
    "scanner_network": "network_service",
    "credentialed": "credentialed_package",
    "credentialed_package": "credentialed_package",
}

EMPTY_VALUES = {None, "", "Unknown", "unknown", "UNKNOWN", "N/A", "n/a", "None", "00:00:00:00:00:00"}

def _resolve_ip(host_data: dict) -> str:
    return str(host_data.get("ip_address") or host_data.get("ip") or "0.0.0.0").strip()

def _resolve_mac(host_data: dict) -> Optional[str]:
    mac = host_data.get("mac_address") or host_data.get("mac")
    if not mac: return None
    mac_str = str(mac).strip().upper()
    if mac_str in ["N/A", "UNKNOWN", "00:00:00:00:00:00", ""]:
        return None
    return mac_str

def _existing_assets_for_hosts(db: Session, org_id: str, hosts: List[dict]):
    batch_ids = [
        gen_asset_id(org_id, _resolve_ip(h) if _resolve_ip(h) != "0.0.0.0" else (_resolve_mac(h) or "unknown"))
        for h in hosts
    ]
    batch_ips = [_resolve_ip(h) for h in hosts if _resolve_ip(h) != "0.0.0.0"]
    query = db.query(Asset).filter(Asset.org_id == org_id)
    assets = query.filter((Asset.id.in_(batch_ids)) | (Asset.ip_address.in_(batch_ips))).all()
    return (
        {a.id: a for a in assets},
        {str(a.ip_address): a for a in assets if a.ip_address},
    )

def _should_update(current, incoming) -> bool:
    """Enterprise merge rule: Only update if the new value is non-empty and non-trivial."""
    return _has_value(incoming)

def _has_value(value) -> bool:
    if value in EMPTY_VALUES:
        return False
    if isinstance(value, str) and value.strip() in EMPTY_VALUES:
        return False
    if value in ([], {}):
        return False
    return True

def _looks_like_fqdn(value) -> bool:
    if not _has_value(value) or not isinstance(value, str):
        return False
    text_value = value.strip().rstrip(".")
    if "." not in text_value:
        return False
    labels = [label for label in text_value.split(".") if label]
    if len(labels) < 2:
        return False
    return not all(label.isdigit() for label in labels)

def _fqdn_label_count(value) -> int:
    if not _looks_like_fqdn(value):
        return 0
    return len([label for label in str(value).strip().rstrip(".").split(".") if label])

def _first_text(*values) -> Optional[str]:
    for value in values:
        if isinstance(value, list):
            for item in value:
                text = _first_text(item)
                if text:
                    return text
            continue
        if isinstance(value, dict):
            text = _first_text(value.get("name"), value.get("hostname"))
            if text:
                return text
            continue
        if _has_value(value):
            return str(value).strip()
    return None

def _first_fqdn(*values) -> Optional[str]:
    for value in values:
        if isinstance(value, list):
            nested = _first_fqdn(*value)
            if nested:
                return nested
            continue
        if isinstance(value, dict):
            nested = _first_fqdn(value.get("name"), value.get("hostname"))
            if nested:
                return nested
            continue
        text_value = str(value).strip().rstrip(".") if _has_value(value) else ""
        if _looks_like_fqdn(text_value):
            return text_value
    return None

def _extract_netbios_name(host_data: dict) -> Optional[str]:
    netbios_name = _first_text(host_data.get("netbios_computer"), host_data.get("netbios_name"))
    if netbios_name:
        return netbios_name
    for entry in host_data.get("netbios_names") or []:
        if isinstance(entry, dict) and entry.get("name"):
            t = entry.get("type")
            s = entry.get("suffix")
            if t is not None:
                if t in (0, 32):  # 0x00 / 0x20
                    return str(entry.get("name")).strip()
            elif s is not None:
                if s in ("00", "20"):
                    return str(entry.get("name")).strip()
            else:
                flags = entry.get("flags")
                if flags is not None:
                    if not (flags & 0x8000):
                        return str(entry.get("name")).strip()
                else:
                    return str(entry.get("name")).strip()
    return None

def _extract_dns_identity(host_data: dict) -> tuple[Optional[str], Optional[str]]:
    dns_name = _first_fqdn(
        host_data.get("dns_name"),
        host_data.get("ptr_hostname"),
        host_data.get("fqdn"),
        host_data.get("hostname"),
        host_data.get("hostnames"),
    )
    fqdn = _first_fqdn(
        dns_name,
        host_data.get("fqdn"),
        host_data.get("ptr_hostname"),
        host_data.get("dns_name"),
        host_data.get("hostname"),
        host_data.get("hostnames"),
        host_data.get("mdns_name"),
    )
    return dns_name, fqdn

def _confidence_to_percent(value) -> Optional[int]:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return max(0, min(100, int(value)))
    label = str(value).strip().lower()
    if label.endswith("%"):
        label = label[:-1]
    try:
        return max(0, min(100, int(float(label))))
    except ValueError:
        return {"high": 90, "medium": 60, "low": 30, "n/a": None}.get(label)


# OS guess → (os_family, manufacturer) lookup table.
# Keys are lowercase substrings; evaluated in order, first match wins.
_OS_GUESS_META: list = [
    # (substring_match,       os_family,       manufacturer)
    ("windows server 2022",   "Windows Server", "Microsoft Corporation"),
    ("windows server 2019",   "Windows Server", "Microsoft Corporation"),
    ("windows server 2016",   "Windows Server", "Microsoft Corporation"),
    ("windows server 2012",   "Windows Server", "Microsoft Corporation"),
    ("windows server 2008",   "Windows Server", "Microsoft Corporation"),
    ("windows server",        "Windows Server", "Microsoft Corporation"),
    ("windows 11",            "Windows",        "Microsoft Corporation"),
    ("windows 10",            "Windows",        "Microsoft Corporation"),
    ("windows 8",             "Windows",        "Microsoft Corporation"),
    ("windows 7",             "Windows",        "Microsoft Corporation"),
    ("windows xp",            "Windows",        "Microsoft Corporation"),   
    ("windows vista",         "Windows",        "Microsoft Corporation"),
    ("windows (winrm)",       "Windows",        "Microsoft Corporation"),
    ("windows (iis)",         "Windows",        "Microsoft Corporation"),
    ("windows (service fingerprint)", "Windows", "Microsoft Corporation"),
    ("windows",               "Windows",        "Microsoft Corporation"),
    ("ubuntu",                "Linux",          "Canonical"),
    ("debian",                "Linux",          "Debian Project"),
    ("centos",                "Linux",          "Red Hat / CentOS"),
    ("red hat",               "Linux",          "Red Hat"),
    ("rhel",                  "Linux",          "Red Hat"),
    ("rocky linux",           "Linux",          "Rocky Enterprise Software Foundation"),
    ("alma linux",            "Linux",          "AlmaLinux OS Foundation"),
    ("alpine",                "Linux",          "Alpine Linux"),
    ("arch linux",            "Linux",          "Arch Linux"),
    ("fedora",                "Linux",          "Red Hat"),
    ("suse",                  "Linux",          "SUSE"),
    ("opensuse",              "Linux",          "SUSE"),
    ("linux/unix (service fingerprint)", "Linux", None),
    ("linux",                 "Linux",          None),
    ("freebsd",               "BSD",            "FreeBSD Project"),
    ("openbsd",               "BSD",            "OpenBSD Project"),
    ("netbsd",                "BSD",            "NetBSD Foundation"),
    ("bsd/macos (service fingerprint)", "macOS / BSD", None),
    ("macos",                 "macOS",          "Apple"),
    ("mac os x",              "macOS",          "Apple"),
    ("darwin",                "macOS",          "Apple"),
    ("cisco ios",             "Cisco IOS",      "Cisco"),
    ("cisco",                 "Cisco IOS",      "Cisco"),
    ("junos",                 "Junos OS",       "Juniper Networks"),
    ("fortios",               "FortiOS",        "Fortinet"),
    ("routeros",              "RouterOS",       "MikroTik"),
    ("network appliance (service fingerprint)", "Network OS", None),
]


def _derive_os_meta(os_guess: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """
    Derive (os_family, manufacturer) from a raw os_guess string.

    Returns (None, None) if os_guess is empty or "Unknown".
    This is intentionally conservative — only returns values when confidence
    is high enough to avoid misleading the analyst.
    """
    if not os_guess or str(os_guess).strip().lower() in ("unknown", "n/a", ""):
        return None, None
    needle = os_guess.lower()
    for substr, family, manufacturer in _OS_GUESS_META:
        if substr in needle:
            return family, manufacturer
    # Generic fallback: if the guess text is non-trivial but unrecognized,
    # still don't make up a manufacturer — just skip both.
    return None, None


def _to_int(value) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        return int(round(float(value)))
    except (TypeError, ValueError):
        return None

def _normalize_source(source: Optional[str]) -> str:
    source = str(source or "legacy").strip().lower()
    return {
        "phase1": "discovery",
        "phase2": "asset_discovery",
        "phase3": "vulnerability_audit",
        "vulnerability_assessment": "vulnerability_audit",
        "advanced": "vulnerability_audit",
        "port_scan": "asset_discovery",
    }.get(source, source)

def _source_rank(source: Optional[str]) -> int:
    return SOURCE_PRIORITY.get(_normalize_source(source), SOURCE_PRIORITY["legacy"])

def _current_source(asset: Asset, field: str) -> str:
    attrs = dict(asset.custom_attributes or {})
    provenance = dict(attrs.get("provenance") or {})
    source = (provenance.get(field) or {}).get("source")
    if source:
        return _normalize_source(source)
    return _normalize_source(asset.discovery_method or "legacy")

def _can_update_field(asset: Asset, field: str, incoming, incoming_source: str) -> bool:
    if not _has_value(incoming):
        return False
    if field in ("fqdn", "dns_name") and not _looks_like_fqdn(str(incoming)):
        return False
    incoming_source = _normalize_source(incoming_source)
    if field in ("fqdn", "dns_name") and incoming_source == "credentialed":
        return False
    current = getattr(asset, field, None)
    if not _has_value(current):
        return True
    if field in ("fqdn", "dns_name"):
        current_source = _current_source(asset, field)
        current_is_fqdn = _looks_like_fqdn(str(current))
        if not current_is_fqdn:
            return True
        if _source_rank(incoming_source) < _source_rank(current_source):
            return False
        if _fqdn_label_count(str(incoming)) < _fqdn_label_count(str(current)):
            return False
        return True
    return _source_rank(incoming_source) >= _source_rank(_current_source(asset, field))

def _set_asset_field(
    db: Session,
    asset: Asset,
    scan_id: str,
    field: str,
    incoming,
    source: str,
    max_len: Optional[int] = None,
) -> bool:
    if not _can_update_field(asset, field, incoming, source):
        return False
    value = str(incoming).strip() if isinstance(incoming, str) else incoming
    if isinstance(value, str) and max_len:
        value = value[:max_len]
    old_value = getattr(asset, field, None)
    if old_value != value:
        _record_asset_change(db, asset.id, scan_id, field, old_value, value)
        setattr(asset, field, value)
    _update_provenance(asset, field, source, scan_id)
    return True

def _finding_family(source: str) -> str:
    return FINDING_SOURCE_FAMILY.get(_normalize_source(source), "unknown")

def _finding_source_from_record(finding: AssetVulnerability) -> str:
    source_family = getattr(finding, "source_family", None)
    if _has_value(source_family) and source_family != "unknown":
        return "credentialed_package" if source_family == "credentialed_package" else "vulnerability_audit"
    text = " ".join(str(v or "") for v in (finding.proof, finding.plugin_output)).lower()
    if "source_family:credentialed_package" in text or "package:" in text:
        return "credentialed_package"
    if "source_family:network_service" in text:
        return "vulnerability_audit"
    return "vulnerability_audit"

def _source_specific_finding_id(asset_id: str, cve_id: str, source_family: str) -> str:
    return f"fnd_{asset_id}_{source_family}_{cve_id}"

def _resolve_finding_id(db: Session, org_id: str, asset_id: str, cve_id: str, source_family: str) -> str:
    legacy_id = f"fnd_{asset_id}_{cve_id}"
    existing = db.query(AssetVulnerability).filter(
        AssetVulnerability.id == legacy_id,
        AssetVulnerability.org_id == org_id,
    ).first()
    if existing and _finding_family(_finding_source_from_record(existing)) == source_family:
        return legacy_id
    return _source_specific_finding_id(asset_id, cve_id, source_family)

def _recalculate_asset_risk(db: Session, asset_id: str):
    sev_rows = (
        db.query(AssetVulnerability.severity, func.count(AssetVulnerability.id).label("cnt"))
        .filter(AssetVulnerability.asset_id == asset_id, AssetVulnerability.status == "open")
        .group_by(AssetVulnerability.severity)
        .all()
    )
    sev_map = {str(r.severity).title(): r.cnt for r in sev_rows} if sev_rows else {}
    counts = {
        "critical": sev_map.get("Critical", 0),
        "high":     sev_map.get("High", 0),
        "medium":   sev_map.get("Medium", 0),
        "low":      sev_map.get("Low", 0),
    }
    computed = min(
        100,
        counts["critical"] * 25
        + counts["high"] * 15
        + counts["medium"] * 8
        + counts["low"] * 3,
    )
    return counts, computed, "Critical" if computed >= 90 else "High" if computed >= 70 else "Medium" if computed >= 40 else "Low" if computed > 0 else "Info"

def _record_asset_change(db: Session, asset_id: str, scan_id: str, field: str, old_val: Any, new_val: Any):
    """Logs a specific field change to the AssetChangeLog."""
    if old_val == new_val or (not old_val and not new_val):
        return
    db.add(AssetChangeLog(
        asset_id=asset_id,
        scan_id=scan_id,
        change_type="field_update",
        field_name=field,
        old_value={"val": old_val},
        new_value={"val": new_val},
        detected_at=utcnow()
    ))

def _update_provenance(asset: Asset, field: str, source: str, scan_id: str):
    """Tracks which scan type provided which piece of data."""
    attrs = dict(asset.custom_attributes or {})
    prov = dict(attrs.get("provenance") or {})
    prov[field] = {
        "source": source,
        "scan_id": scan_id,
        "at": utcnow().isoformat()
    }
    attrs["provenance"] = prov
    asset.custom_attributes = attrs

def sync_host_discovery(db: Session, scan_id: str, org_id: str, user_id: Optional[str], hosts: List[dict]):
    """
    Called after Phase 1 (Host Discovery).
    Phase 4: Adds Change Auditing and Provenance.
    """
    if not hosts: return

    logger.info(f"Syncing {len(hosts)} hosts with Phase 4 Change Auditing")

    # Pre-fetch existing assets for comparison (Selective Select-then-Update for Change Log accuracy)
    existing, existing_by_ip = _existing_assets_for_hosts(db, org_id, hosts)

    for host in hosts:
        ip = _resolve_ip(host)
        mac = _resolve_mac(host)
        hostname = (host.get("hostname") or host.get("hostnames", [None])[0]) if isinstance(host.get("hostnames"), list) else host.get("hostname")
        netbios_name = _extract_netbios_name(host)
        dns_name, fqdn = _extract_dns_identity(host)
        vendor = host.get("vendor", "Unknown")
        is_active = host.get("is_active") or host.get("state") == "up"
        response_time = _to_int(host.get("response_time_ms") or host.get("response_time"))
        os_confidence = _confidence_to_percent(host.get("os_confidence") or host.get("confidence"))

        os_match = host.get("os_match") or host.get("os_guess")
        derived_os_family, derived_manufacturer = _derive_os_meta(os_match)
        os_family_val     = host.get("os_family")   or derived_os_family
        device_category   = host.get("device_category")

        asset_id = gen_asset_id(org_id, ip if ip != "0.0.0.0" else (mac or "unknown"))
        asset = existing.get(asset_id) or existing_by_ip.get(ip)
        if asset:
            asset_id = asset.id

        if asset:
            # PHASE 4: CHANGE AUDITING
            _set_asset_field(db, asset, scan_id, "hostname", hostname, "discovery", max_len=255)
            _set_asset_field(db, asset, scan_id, "fqdn", fqdn, "discovery", max_len=512)
            _set_asset_field(db, asset, scan_id, "dns_name", dns_name, "discovery", max_len=512)
            _set_asset_field(db, asset, scan_id, "netbios_name", netbios_name, "discovery", max_len=255)
            _set_asset_field(db, asset, scan_id, "vendor", vendor, "discovery", max_len=255)
            _set_asset_field(db, asset, scan_id, "mac_address", mac, "discovery")
            _set_asset_field(db, asset, scan_id, "response_time_ms", response_time, "discovery")
            _set_asset_field(db, asset, scan_id, "os_confidence", os_confidence, "discovery")
            _set_asset_field(db, asset, scan_id, "os_name", os_match, "discovery", max_len=255)
            _set_asset_field(db, asset, scan_id, "os_family", os_family_val, "discovery", max_len=100)
            _set_asset_field(db, asset, scan_id, "device_category", device_category, "discovery", max_len=100)
            _set_asset_field(db, asset, scan_id, "discovery_method", "discovery", "discovery", max_len=50)

            if asset.ip_address != ip and ip != "0.0.0.0":
                _record_asset_change(db, asset_id, scan_id, "ip_address", str(asset.ip_address), ip)
                asset.ip_address = ip

            asset.last_seen_at = utcnow()
            asset.last_scan_id = scan_id
            asset.is_active = is_active
            asset.updated_at = utcnow()
        elif is_active:
            # New Asset
            new_asset = Asset(
                id=asset_id, org_id=org_id, ip_address=ip if ip != "0.0.0.0" else None,
                mac_address=mac, hostname=hostname, vendor=vendor if vendor != "Unknown" else None,
                response_time_ms=response_time, os_confidence=os_confidence,
                is_active=True, discovery_method="discovery",
                last_scan_id=scan_id, last_seen_at=utcnow(), created_at=utcnow(), updated_at=utcnow(),
                os_name=os_match, os_family=os_family_val, device_category=device_category
            )
            db.add(new_asset)
            if _has_value(hostname):
                _update_provenance(new_asset, "hostname", "discovery", scan_id)
            if _has_value(vendor):
                _update_provenance(new_asset, "vendor", "discovery", scan_id)
            if _has_value(mac):
                _update_provenance(new_asset, "mac_address", "discovery", scan_id)
            if _has_value(response_time):
                _update_provenance(new_asset, "response_time_ms", "discovery", scan_id)
            if _has_value(os_confidence):
                _update_provenance(new_asset, "os_confidence", "discovery", scan_id)
            if _has_value(os_match):
                _update_provenance(new_asset, "os_name", "discovery", scan_id)
            if _has_value(os_family_val):
                _update_provenance(new_asset, "os_family", "discovery", scan_id)
            if _has_value(device_category):
                _update_provenance(new_asset, "device_category", "discovery", scan_id)
            if _looks_like_fqdn(str(fqdn)):
                new_asset.fqdn = str(fqdn)[:512]
                _update_provenance(new_asset, "fqdn", "discovery", scan_id)
            if _looks_like_fqdn(str(dns_name)):
                new_asset.dns_name = str(dns_name)[:512]
                _update_provenance(new_asset, "dns_name", "discovery", scan_id)
            if _has_value(netbios_name):
                new_asset.netbios_name = str(netbios_name)[:255]
                _update_provenance(new_asset, "netbios_name", "discovery", scan_id)
            _record_asset_change(db, asset_id, scan_id, "lifecycle", None, "discovered")

    db.commit()


def sync_asset_discovery(db: Session, scan_id: str, org_id: str, user_id: Optional[str], hosts: List[dict]):
    """
    Called after Phase 2 (Asset Discovery / Port Scan).
    Phase 4: Provenance tracking for fingerprinting.
    """
    if not hosts: return

    existing, existing_by_ip = _existing_assets_for_hosts(db, org_id, hosts)

    for host in hosts:
        ip = _resolve_ip(host)
        asset_id = gen_asset_id(org_id, ip if ip != "0.0.0.0" else (_resolve_mac(host) or "unknown"))
        asset = existing.get(asset_id) or existing_by_ip.get(ip)
        if not asset: continue
        asset_id = asset.id
        dns_name, fqdn = _extract_dns_identity(host)
        netbios_name = _extract_netbios_name(host)

        ports = host.get("open_ports") or host.get("ports") or []
        for p in ports:
            port_num = p.get("port")
            if not port_num: continue
            proto = p.get("protocol", "tcp").lower()
            service_id = gen_service_id(asset_id, int(port_num), proto)

            # Use UPSERT for services (high volume), but selective update for asset enrichment
            db.execute(insert(Service).values(
                id=service_id, asset_id=asset_id, scan_id=scan_id,
                port=int(port_num), protocol=proto, state="open",
                service_name=p.get("service") or "unknown",
                service_product=p.get("product") or None,
                service_version=p.get("version") or None,
                banner=p.get("banner"),
                created_at=utcnow(), updated_at=utcnow()
            ).on_conflict_do_update(
                index_elements=["id"],
                set_={
                    "state": "open",
                    "scan_id": scan_id,
                    "updated_at": utcnow(),
                    "service_name": func.coalesce(
                        func.nullif(Service.service_name, "unknown"),
                        func.nullif(p.get("service") or "", ""),
                        Service.service_name,
                    ),
                    # Preserve richer data on conflict — never overwrite a non-null value with null
                    "service_product": func.coalesce(
                        Service.service_product,
                        func.nullif(p.get("product") or "", ""),
                    ),
                    "service_version": func.coalesce(
                        Service.service_version,
                        func.nullif(p.get("version") or "", ""),
                    ),
                    "banner": func.coalesce(Service.banner, func.nullif(p.get("banner") or "", "")),
                }
            ))

        os_match = host.get("os_match") or host.get("os_guess")
        incoming_os_confidence = _confidence_to_percent(host.get("os_confidence"))

        # Derive os_family and manufacturer from the os_guess string so that the
        # Asset Registry can display these fields after an Asset Discovery scan,
        # without waiting for a full Vulnerability Audit or Credentialed scan.
        derived_os_family, derived_manufacturer = _derive_os_meta(os_match)

        # Prefer explicitly provided values (e.g. from Nmap -O) over derived ones.
        os_family_val     = host.get("os_family")   or derived_os_family
        manufacturer_val  = host.get("manufacturer") or derived_manufacturer
        device_category   = host.get("device_category")

        # ── Confidence-aware OS field merge ─────────────────────────────────
        # AssetCorrelationEngine cross-phase principle: if Phase 2 produced a
        # high-confidence OS detection (e.g. from Nmap -O at ≥90% accuracy), but
        # Phase 3 later provides a lower-confidence guess (e.g. from banner/TTL
        # heuristics at ≤30%), we should keep the Phase 2 value.
        #
        # The _can_update_field() check already handles source priority (asset_discovery
        # priority=20, vulnerability_audit=30). However when both come from the same
        # phase, we use the OS confidence score as a tiebreaker so that a well-detected
        # Nmap fingerprint is not overwritten by a poorer detection later.
        current_os_confidence = _confidence_to_percent(asset.os_confidence)
        if incoming_os_confidence is not None and current_os_confidence is not None:
            # Read the current os_name to decide whether to keep or replace
            current_os_name = getattr(asset, "os_name", None)
            if _has_value(current_os_name) and incoming_os_confidence < current_os_confidence:
                # Incoming OS data is lower confidence — skip os_name and os_family
                # but still write manufacturer and device_category.
                _set_asset_field(db, asset, scan_id, "hostname",         host.get("hostname"),   "asset_discovery", max_len=255)
                _set_asset_field(db, asset, scan_id, "fqdn",             fqdn,                   "asset_discovery", max_len=512)
                _set_asset_field(db, asset, scan_id, "dns_name",         dns_name,               "asset_discovery", max_len=512)
                _set_asset_field(db, asset, scan_id, "netbios_name",     netbios_name,           "asset_discovery", max_len=255)
                _set_asset_field(db, asset, scan_id, "manufacturer",     manufacturer_val,       "asset_discovery", max_len=255)
                _set_asset_field(db, asset, scan_id, "device_category",  device_category,        "asset_discovery", max_len=100)
                _set_asset_field(db, asset, scan_id, "os_confidence",    incoming_os_confidence,  "asset_discovery")
                _set_asset_field(db, asset, scan_id, "discovery_method", "asset_discovery",      "asset_discovery", max_len=50)
                # Skip os_name and os_family — preserve the higher-confidence value
                db.commit()
                continue

        _set_asset_field(db, asset, scan_id, "hostname",         host.get("hostname"),   "asset_discovery", max_len=255)
        _set_asset_field(db, asset, scan_id, "fqdn",             fqdn,                   "asset_discovery", max_len=512)
        _set_asset_field(db, asset, scan_id, "dns_name",         dns_name,               "asset_discovery", max_len=512)
        _set_asset_field(db, asset, scan_id, "netbios_name",     netbios_name,           "asset_discovery", max_len=255)
        _set_asset_field(db, asset, scan_id, "os_name",          os_match,               "asset_discovery", max_len=255)
        _set_asset_field(db, asset, scan_id, "os_family",        os_family_val,          "asset_discovery", max_len=100)
        _set_asset_field(db, asset, scan_id, "manufacturer",     manufacturer_val,       "asset_discovery", max_len=255)
        _set_asset_field(db, asset, scan_id, "device_category",  device_category,        "asset_discovery", max_len=100)
        _set_asset_field(db, asset, scan_id, "os_confidence",    incoming_os_confidence,  "asset_discovery")
        _set_asset_field(db, asset, scan_id, "discovery_method", "asset_discovery",      "asset_discovery", max_len=50)

    db.commit()


def sync_vulnerability_audit(db: Session, scan_id: str, org_id: str, user_id: Optional[str], hosts: List[dict]):
    """
    Called after Phase 3 (Vulnerability Audit).
    Phase 4: Vulnerability Status Auditing (History).
    """
    if not hosts: return

    existing_assets, existing_by_ip = _existing_assets_for_hosts(db, org_id, hosts)

    touched_asset_ids = set()
    for host in hosts:
        ip = _resolve_ip(host)
        asset_id = gen_asset_id(org_id, ip if ip != "0.0.0.0" else (_resolve_mac(host) or "unknown"))
        asset = existing_assets.get(asset_id) or existing_by_ip.get(ip)
        if not asset: continue
        asset_id = asset.id
        touched_asset_ids.add(asset_id)
        dns_name, fqdn = _extract_dns_identity(host)
        netbios_name = _extract_netbios_name(host)

        _set_asset_field(db, asset, scan_id, "hostname", host.get("hostname"), "vulnerability_audit", max_len=255)
        _set_asset_field(db, asset, scan_id, "fqdn", fqdn, "vulnerability_audit", max_len=512)
        _set_asset_field(db, asset, scan_id, "dns_name", dns_name, "vulnerability_audit", max_len=512)
        _set_asset_field(db, asset, scan_id, "netbios_name", netbios_name, "vulnerability_audit", max_len=255)
        _set_asset_field(db, asset, scan_id, "os_name", host.get("os_match") or host.get("os_guess"), "vulnerability_audit", max_len=255)
        _set_asset_field(db, asset, scan_id, "os_family", host.get("os_family"), "vulnerability_audit", max_len=100)
        _set_asset_field(db, asset, scan_id, "os_confidence", _confidence_to_percent(host.get("os_confidence")), "vulnerability_audit")

        # ── Device classification signal priority check ────────────────────
        # Prevents a low-confidence classification (e.g. TTL heuristic at
        # priority=20) from overwriting a high-confidence one (e.g. SNMP OID
        # at priority=100) across scan phases.
        incoming_device_cat = host.get("device_category")
        if _has_value(incoming_device_cat):
            incoming_signal = host.get("device_category_signal") or "none"
            incoming_priority = _DEVICE_SIGNAL_PRIORITY.get(incoming_signal, 0)
            stored_signal = _get_stored_device_signal(asset)
            stored_priority = _DEVICE_SIGNAL_PRIORITY.get(stored_signal or "none", 0)
            if stored_signal is not None and incoming_priority < stored_priority:
                # Incoming signal is weaker — preserve the stored classification
                logger.debug(
                    "Skipping device_category update for %s: stored signal '%s' (pri=%d) "
                    "> incoming '%s' (pri=%d)",
                    _resolve_ip(host), stored_signal, stored_priority,
                    incoming_signal, incoming_priority,
                )
            else:
                _set_asset_field(db, asset, scan_id, "device_category", incoming_device_cat, "vulnerability_audit", max_len=100)
                # Also store the signal name in provenance for future comparisons
                attrs = dict(asset.custom_attributes or {})
                prov = dict(attrs.get("provenance") or {})
                dev_prov = dict(prov.get("device_category") or {})
                dev_prov["signal"] = incoming_signal
                prov["device_category"] = dev_prov
                attrs["provenance"] = prov
                asset.custom_attributes = attrs
        # If no incoming device_category, don't overwrite anything

        source_family = _finding_family("vulnerability_audit")
        found_in_this_scan = set()
        vulns = host.get("vulnerabilities") or host.get("cves") or []
        for v in vulns:
            cve_id = v.get("cve_id") or v.get("cve") or v.get("id")
            if not cve_id: continue
            found_in_this_scan.add(cve_id)

            # Get enriched details from local CVE database if available
            description = None
            cvss_vector = None
            cwe_ids = []
            references = []
            published_at = None
            
            try:
                from core.cve_database import get_cve_database
                cve_db = get_cve_database()
                if cve_db.db_available:
                    details = cve_db.get_cve_details(cve_id)
                    if details:
                        description = details.get("description")
                        cvss_vector = details.get("cvss_vector") or details.get("cvss_v3_vector")
                        cwe_ids = details.get("cwe_ids") or []
                        
                        raw_refs = details.get("references") or []
                        clean_refs = []
                        for ref in raw_refs:
                            if isinstance(ref, str):
                                clean_refs.append(ref)
                            elif isinstance(ref, dict) and ref.get("url"):
                                clean_refs.append(ref["url"])
                        references = clean_refs

                        from datetime import datetime, date
                        pub = details.get("published")
                        if isinstance(pub, str):
                            try:
                                published_at = datetime.fromisoformat(pub).date()
                            except ValueError:
                                pass
                        elif isinstance(pub, (datetime, date)):
                            published_at = pub
            except Exception as e:
                logger.warning("Failed to lookup CVE details for %s during sync: %s", cve_id, e)

            # UPSERT Catalog
            db.execute(insert(VulnerabilityDefinition).values(
                id=cve_id, cve_id=cve_id, title=v.get("title", f"Vuln {cve_id}"),
                description=description, cvss_vector=cvss_vector,
                cwe_ids=cwe_ids, references=references, published_at=published_at,
                severity=str(v.get("severity", "Medium")).title(), cvss_v3_score=float(v.get("cvss", 0.0)),
                source="scanner", created_at=utcnow(), updated_at=utcnow()
            ).on_conflict_do_nothing(index_elements=["id"]))

            # PHASE 4: Detect Reopened Vulnerabilities
            finding_id = _resolve_finding_id(db, org_id, asset_id, cve_id, source_family)
            existing_fnd = db.query(AssetVulnerability).filter(AssetVulnerability.id == finding_id).first()

            if existing_fnd and existing_fnd.status == "fixed":
                _record_asset_change(db, asset_id, scan_id, "vulnerability_reopened", cve_id, "open")

            # UPSERT Finding
            proof = f"Source_Family:network_service\n{v.get('proof') or v.get('evidence') or ''}".strip()
            plugin_output = v.get("plugin_output") or v.get("description") or v.get("title")
            db.execute(insert(AssetVulnerability).values(
                id=finding_id, org_id=org_id, scan_id=scan_id, asset_id=asset_id, vuln_id=cve_id,
                severity=str(v.get("severity", "Medium")).title(), cvss_score=float(v.get("cvss", 0.0)),
                status="open", proof=proof, plugin_output=plugin_output,
                source_family=source_family, evidence_source="vulnerability_audit",
                first_found_at=utcnow(), last_found_at=utcnow()
            ).on_conflict_do_update(
                index_elements=["id", "org_id"],
                set_={
                    "last_found_at": utcnow(),
                    "scan_id": scan_id,
                    "status": "open",
                    "severity": str(v.get("severity", "Medium")).title(),
                    "cvss_score": float(v.get("cvss", 0.0)),
                    "source_family": source_family,
                    "evidence_source": "vulnerability_audit",
                    "proof": func.coalesce(func.nullif(proof, ""), AssetVulnerability.proof),
                    "plugin_output": func.coalesce(func.nullif(plugin_output or "", ""), AssetVulnerability.plugin_output),
                }
            ))

        # PHASE 4: Targeted Remediation with History
        open_findings = db.query(AssetVulnerability).filter(
            AssetVulnerability.asset_id == asset_id, AssetVulnerability.status == "open"
        ).all()

        for f in open_findings:
            if _finding_family(_finding_source_from_record(f)) != source_family:
                continue
            if f.vuln_id not in found_in_this_scan:
                f.status = "fixed"
                f.fixed_at = utcnow()
                _record_asset_change(db, asset_id, scan_id, "vulnerability_fixed", f.vuln_id, "fixed")

        asset.last_scan_id = scan_id
        asset.last_seen_at = utcnow()
        asset.updated_at = utcnow()
        _set_asset_field(db, asset, scan_id, "discovery_method", "vulnerability_audit", "vulnerability_audit", max_len=50)

        # Upsert TLS Details if present
        tls_info = host.get("tls_info")
        if tls_info and tls_info.get("enabled"):
            open_ports = [p.get("port") for p in host.get("open_ports", []) if p.get("port")]
            tls_port = None
            for p in [443, 8443, 465, 993, 995]:
                if p in open_ports:
                    tls_port = p
                    break
            
            if tls_port:
                service_id = gen_service_id(asset.id, tls_port, "tcp")
                
                # Parse expiration datetime
                cert_expiry_raw = tls_info.get("cert_expiry")
                cert_not_after = None
                if cert_expiry_raw:
                    try:
                        from datetime import datetime, timezone
                        clean_expiry = " ".join(cert_expiry_raw.split())
                        cert_not_after = datetime.strptime(clean_expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    except Exception:
                        try:
                            # Fallback if cert_expiry is written in ISO format or another standard format
                            cert_not_after = datetime.fromisoformat(cert_expiry_raw.replace("Z", "+00:00"))
                        except Exception:
                            pass
                
                cert_subject = {"common_name": tls_info.get("cert_subject") or ""}
                cert_issuer = {"common_name": tls_info.get("cert_issuer") or ""}

                from db.models.findings import TLSDetail
                
                tls_insert = insert(TLSDetail).values(
                    service_id=service_id,
                    is_enabled=True,
                    protocol_version=tls_info.get("version"),
                    cipher_suite=tls_info.get("cipher"),
                    grade=tls_info.get("score") or "N/A",
                    is_weak_cipher=tls_info.get("weak_cipher") or False,
                    cert_is_expired=tls_info.get("cert_expired") or False,
                    cert_is_self_signed=tls_info.get("cert_self_signed") or False,
                    cert_not_after=cert_not_after,
                    cert_subject=cert_subject,
                    cert_issuer=cert_issuer,
                    issues=tls_info.get("issues") or [],
                    created_at=utcnow(),
                )
                
                tls_upsert = tls_insert.on_conflict_do_update(
                    index_elements=["service_id"],
                    set_={
                        "protocol_version": tls_info.get("version"),
                        "cipher_suite": tls_info.get("cipher"),
                        "grade": tls_info.get("score") or "N/A",
                        "is_weak_cipher": tls_info.get("weak_cipher") or False,
                        "cert_is_expired": tls_info.get("cert_expired") or False,
                        "cert_is_self_signed": tls_info.get("cert_self_signed") or False,
                        "cert_not_after": cert_not_after,
                        "cert_subject": cert_subject,
                        "cert_issuer": cert_issuer,
                        "issues": tls_info.get("issues") or [],
                    }
                )
                db.execute(tls_upsert)

    db.commit()

    # 4. Final aggregation (This could also be moved to a background trigger later)
    # Keeping the existing recalculation logic but using more efficient queries if possible
    # (Leaving it as is for Step 3 to ensure stability)
    try:
        # Simplified batch recalculation for assets in this scan
        for a_id in touched_asset_ids:
            counts, computed, level = _recalculate_asset_risk(db, a_id)
            db.query(Asset).filter(Asset.id == a_id).update({
                "vuln_counts": counts,
                "risk_score": computed,
                "risk_level": level,
                "updated_at": utcnow(),
            })
        db.commit()
    except Exception:
        db.rollback()


# Backward compatibility alias for legacy callers.
sync_advanced_scan = sync_vulnerability_audit
