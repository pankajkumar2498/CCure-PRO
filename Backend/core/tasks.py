"""
core/tasks.py
─────────────
Celery background tasks for long-running network scans.
"""

import logging
import os
import asyncio
import time
from typing import List, Optional, Dict
from sqlalchemy import func, text
from sqlalchemy.dialects.postgresql import insert

from core.celery_app import celery_app
from db.base import SessionLocal, gen_service_id, gen_asset_id, utcnow
from db.models import (
    Asset,
    AssetVulnerability,
    Service,
    Scan,
    User,
    VulnerabilityDefinition,
    Organization,
)
from orchestrator.scan_orchestrator import ScanOrchestrator
from scans.db_helpers import create_scan, update_scan_phase, mark_scan_failed, create_completed_scan
from scan_helpers import (
    resolve_pipeline_mode,
    get_terminal_phase,
    resolve_report_context,
    phase1_summary_from_scan,
)

log = logging.getLogger("ccure.tasks")


def _new_orchestrator() -> ScanOrchestrator:
    """Create one orchestrator per task so parallel scans do not share mutable state."""
    return ScanOrchestrator(silent=False)


def _run_async(coro):
    """Run async scanner code safely from Celery worker threads or eager contexts."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import threading
        from concurrent.futures import Future

        future = Future()

        def run_in_thread():
            try:
                result = asyncio.run(coro)
                future.set_result(result)
            except BaseException as e:
                future.set_exception(e)

        thread = threading.Thread(target=run_in_thread)
        thread.start()
        return future.result()
    else:
        return asyncio.run(coro)



def _check_cancelled(db: SessionLocal, scan_id: str) -> bool:
    """Check if the scan has been marked as cancelled in the DB."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    return scan and scan.status == "cancelled"


def _update_task_id(db: SessionLocal, scan_id: str, task_id: str):
    """Update the current active task ID for the scan."""
    db.query(Scan).filter(Scan.id == scan_id).update({"current_task_id": task_id})
    db.commit()


def _merge_host_identity(enriched_hosts: List[dict], source_hosts: List[dict]) -> List[dict]:
    """
    Preserve identity/context fields from the previous phase when the next phase
    returns only partial host records.
    """
    by_ip: Dict[str, dict] = {}
    for host in source_hosts or []:
        ip = host.get("ip_address") or host.get("ip")
        if ip:
            by_ip[ip] = host

    merged: List[dict] = []
    for idx, host in enumerate(enriched_hosts or []):
        base = {}
        ip = host.get("ip_address") or host.get("ip")
        if ip and ip in by_ip:
            base = dict(by_ip[ip])
        elif idx < len(source_hosts or []):
            base = dict(source_hosts[idx])

        combined = dict(base)
        combined.update(host or {})

        # Restore important phase-1/2 identity if phase-3 output omitted it.
        for key in (
            "ip", "ip_address", "hostname", "mac", "mac_address", "vendor",
            "is_active", "status", "open_ports", "os_guess", "os_confidence",
            "device_category", "snmp_device_type", "mdns_name", "netbios_names",
            "os_fingerprint_full", "tcp_fingerprint", "port_states",
        ):
            if combined.get(key) in (None, "", [], {}):
                if key in base:
                    combined[key] = base.get(key)

        merged.append(combined)
    return merged


def _sync_credentialed_asset_identity(
    db,
    *,
    user_id: str,
    ip: str,
    scan_id: str,
    os_type: str,
    system_data: Dict,
    stored_report: Dict,
    cve_list: List[Dict],
    severity_counts: Dict[str, int],
) -> None:
    """
    Promote trusted credentialed scan identity into the Asset Registry.
    Phase 4: Adds forensic logging and provenance.
    """
    from scans.asset_syncer import (
        _finding_family,
        _finding_source_from_record,
        _confidence_to_percent,
        _has_value,
        _record_asset_change,
        _recalculate_asset_risk,
        _set_asset_field,
        _to_int,
    )
    from core.oui_lookup import lookup_vendor

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        log.warning("Credentialed asset sync skipped: user %s not found", user_id)
        return

    asset = (
        db.query(Asset)
        .filter(Asset.org_id == str(user.org_id), Asset.ip_address == ip)
        .first()
    )
    if not asset:
        log.info("Asset not found for ip=%s. Bootstrapping new asset record.", ip)
        org = db.query(Organization).filter(Organization.id == str(user.org_id)).first()
        org_slug = org.slug if org else str(user.org_id)

        asset = Asset(
            id=gen_asset_id(org_slug, ip),
            org_id=str(user.org_id),
            ip_address=ip,
            is_active=True,
            discovery_method="credentialed",
            first_seen_at=utcnow(),
            last_seen_at=utcnow(),
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(asset)
        db.flush()
        _record_asset_change(db, asset.id, scan_id, "lifecycle", None, "bootstrapped_via_credentialed")

    os_name = _clean_text(system_data.get("os_name"))
    os_version = _clean_text(system_data.get("os_version_id"))
    hostname, fqdn, raw_hostname_fqdn = _extract_credentialed_identity_names(system_data)
    os_build = _clean_text(system_data.get("os_build"))
    kernel_version = _clean_text(system_data.get("kernel_version"))
    netbios_name = _clean_text(system_data.get("netbios_name") or system_data.get("netbios_computer"))
    normalized_os_type = _clean_text(system_data.get("detected_os") or os_type).lower()
    manufacturer = _clean_text(system_data.get("manufacturer"))
    mac_address = _normalize_mac(system_data.get("mac_address"))
    mac_vendor = _clean_text(system_data.get("mac_vendor") or (lookup_vendor(mac_address) if mac_address else ""))
    vendor = mac_vendor or (manufacturer if not _has_value(asset.vendor) else "")
    os_family = _clean_text(system_data.get("os_family") or ("Windows" if normalized_os_type == "windows" else "Linux" if normalized_os_type == "linux" else ""))
    os_confidence = _confidence_to_percent(system_data.get("os_confidence") or 100)
    subnet = _clean_text(system_data.get("subnet"))
    credentialed_response_time = _to_int(system_data.get("credentialed_response_time_ms"))

    # PHASE 4: FORENSIC CHANGE LOGGING
    _set_asset_field(db, asset, scan_id, "os_name", os_name, "credentialed", max_len=255)
    _set_asset_field(db, asset, scan_id, "os_family", os_family, "credentialed", max_len=100)
    _set_asset_field(db, asset, scan_id, "os_version", os_version, "credentialed", max_len=100)
    _set_asset_field(db, asset, scan_id, "os_confidence", os_confidence, "credentialed")
    _set_asset_field(db, asset, scan_id, "hostname", hostname, "credentialed", max_len=255)
    _set_asset_field(db, asset, scan_id, "fqdn", fqdn, "credentialed", max_len=512)
    _set_asset_field(db, asset, scan_id, "netbios_name", netbios_name, "credentialed", max_len=255)
    _set_asset_field(db, asset, scan_id, "mac_address", mac_address, "credentialed")
    _set_asset_field(db, asset, scan_id, "vendor", vendor, "credentialed", max_len=255)
    _set_asset_field(db, asset, scan_id, "subnet", subnet, "credentialed", max_len=50)
    _set_asset_field(db, asset, scan_id, "manufacturer", manufacturer, "credentialed", max_len=255)
    _set_asset_field(db, asset, scan_id, "discovery_method", "credentialed", "credentialed", max_len=50)
    if credentialed_response_time and not _has_value(asset.response_time_ms):
        _set_asset_field(db, asset, scan_id, "response_time_ms", credentialed_response_time, "credentialed")

    # Classify device category using the credentialed OS/identity details
    from core.device_classifier import classify_device
    c_host = {
        "discovery_method": "credentialed",
        "os_name": os_name,
        "os_family": os_family,
        "hostname": hostname,
        "vendor": vendor,
        "custom_attributes": asset.custom_attributes or {}
    }
    category = classify_device(c_host)
    _set_asset_field(db, asset, scan_id, "device_category", category, "credentialed", max_len=100)

    # Store the signal name ("credentialed") in provenance for future priority comparisons
    attrs = dict(asset.custom_attributes or {})
    prov = dict(attrs.get("provenance") or {})
    dev_prov = dict(prov.get("device_category") or {})
    dev_prov["signal"] = "credentialed"
    prov["device_category"] = dev_prov
    attrs["provenance"] = prov
    asset.custom_attributes = attrs

    _sync_credentialed_services(db, asset, scan_id, stored_report.get("open_ports_credentialed", []), stored_report.get("packages", []))

    # 1. Sync Vulnerabilities (Marks as open/reopened)
    _sync_credentialed_vulnerabilities(db, asset, str(user.org_id), scan_id, cve_list)

    # 2. PHASE 4: VULNERABILITY STATUS HISTORY
    found_cve_ids = { _clean_text(v.get("cve_id") or v.get("cve") or v.get("id")) for v in (cve_list or []) }
    found_cve_ids = { cid for cid in found_cve_ids if cid }

    current_open = db.query(AssetVulnerability).filter(
        AssetVulnerability.asset_id == asset.id,
        AssetVulnerability.status == "open"
    ).all()

    for f in current_open:
        if _finding_family(_finding_source_from_record(f)) != "credentialed_package":
            continue
        if f.vuln_id not in found_cve_ids:
            f.status = "fixed"
            f.fixed_at = utcnow()
            _record_asset_change(db, asset.id, scan_id, "vulnerability_fixed", f.vuln_id, "fixed")

    db.flush()

    # Recalculate aggregate vuln_counts
    counts, agg_score, agg_level = _recalculate_asset_risk(db, asset.id)
    asset.vuln_counts = counts
    asset.risk_score = agg_score
    asset.risk_level = agg_level

    # Custom attributes merge
    attrs = dict(asset.custom_attributes or {})
    credentialed_attrs = dict(attrs.get("credentialed_system_info") or {})
    credentialed_attrs.update({
        "os_name": os_name,
        "os_version_id": os_version,
        "os_family": os_family,
        "os_build": os_build,
        "kernel_version": kernel_version,
        "hardware_model": _clean_text(system_data.get("hardware_model")),
        "cpu_model": _clean_text(system_data.get("cpu_model")),
        "cpu_count": _clean_text(system_data.get("cpu_count")),
        "uptime": _clean_text(system_data.get("uptime")),
        "hostname": hostname,
        "hostname_short": _clean_text(system_data.get("hostname_short")),
        "hostname_fqdn_raw": raw_hostname_fqdn,
        "netbios_name": netbios_name,
        "fqdn": fqdn,
        "serial_number": _clean_text(system_data.get("serial_number")),
        "bios_version": _clean_text(system_data.get("bios_version")),
        "local_groups": system_data.get("local_groups", []),
        "mac_address": mac_address,
        "mac_vendor": mac_vendor,
        "vendor": vendor,
        "domain": _clean_text(system_data.get("domain")),
        "subnet": subnet,
        "manufacturer": manufacturer,
        "credentialed_response_time_ms": credentialed_response_time,
        "detected_os": normalized_os_type or os_type,
        "source_scan_id": scan_id,
        "synced_at": utcnow().isoformat(),
    })
    attrs["credentialed_system_info"] = {
        key: value for key, value in credentialed_attrs.items() if value
    }
    asset.custom_attributes = attrs
    asset.last_scan_id = scan_id
    asset.last_seen_at = utcnow()
    asset.updated_at = utcnow()
    log.info("Credentialed asset sync updated asset=%s ip=%s os=%s", asset.id, ip, asset.os_name)


def _extract_credentialed_identity_names(system_data: Dict) -> tuple[str, str, str]:
    raw_hostname_fqdn = _clean_text(system_data.get("hostname_fqdn"))
    explicit_fqdn = _clean_text(system_data.get("fqdn"))
    hostname_short = _clean_text(system_data.get("hostname_short"))
    hostname = _clean_text(
        system_data.get("hostname")
        or hostname_short
        or (raw_hostname_fqdn.split(".")[0] if raw_hostname_fqdn else "")
    )
    fqdn = explicit_fqdn if "." in explicit_fqdn else (raw_hostname_fqdn if "." in raw_hostname_fqdn else "")
    return hostname, fqdn, raw_hostname_fqdn


def _clean_text(value) -> str:
    return str(value or "").strip()


def _normalize_mac(value) -> str:
    text = _clean_text(value).lower().replace("-", ":")
    if not text or text in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
        return ""
    compact = text.replace(":", "").replace(".", "")
    if len(compact) == 12 and all(ch in "0123456789abcdef" for ch in compact):
        return ":".join(compact[i:i + 2] for i in range(0, 12, 2))
    return text if len(text.split(":")) == 6 else ""


def _credentialed_sections_with_identity(sections: Optional[List[str]]) -> Optional[List[str]]:
    if sections is None:
        return None
    required = ["system_info", "network"]
    merged = list(sections)
    for section in required:
        if section not in merged:
            merged.append(section)
    return merged


def _compact_dict(data: Dict) -> Dict:
    return {
        key: value
        for key, value in data.items()
        if value not in (None, "", [], {})
    }


def _normalized_severity_counts(counts: Dict[str, int]) -> Dict[str, int]:
    normalized = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for key, value in (counts or {}).items():
        label = str(key or "Info").title()
        if label not in normalized:
            label = "Info"
        normalized[label] += int(value or 0)
    return normalized


def _credentialed_risk_from_counts(counts: Dict[str, int]) -> tuple[int, str]:
    score = min(
        100,
        counts.get("Critical", 0) * 25
        + counts.get("High", 0) * 15
        + counts.get("Medium", 0) * 8
        + counts.get("Low", 0) * 3,
    )
    if score >= 90:
        return score, "Critical"
    if score >= 70:
        return score, "High"
    if score >= 40:
        return score, "Medium"
    if score > 0:
        return score, "Low"
    return 0, "Info"


def _port_int(value) -> Optional[int]:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if 1 <= port <= 65535:
        return port
    return None


def _sync_credentialed_services(db, asset: Asset, scan_id: str, ports: List[Dict], packages: List[Dict] = None) -> None:
    import re
    # De-duplicate ports by ID
    unique_ports = {}
    for port_data in ports or []:
        port_num = _port_int(port_data.get("port"))
        if not port_num: continue
        protocol = _clean_text(port_data.get("protocol") or "tcp").lower()[:10]
        service_id = gen_service_id(asset.id, port_num, protocol)
        if service_id not in unique_ports:
            unique_ports[service_id] = (port_num, protocol, port_data)

    for service_id, (port, protocol, port_data) in unique_ports.items():
        state = _clean_text(port_data.get("state") or "open").lower()
        state = "open" if state in {"listen", "listening"} else state[:20]
        
        raw_process = port_data.get("process") or ""
        service_name = _clean_text(port_data.get("service") or port_data.get("name") or raw_process or "unknown")[:100]
        banner = _clean_text(port_data.get("banner")) or None

        # Extract product & version from process name & packages if possible
        service_product = None
        service_version = None

        process_name = ""
        if raw_process:
            raw_process = raw_process.strip()
            # Linux ss -tlnp: users:(("sshd",pid=1142,fd=3))
            match = re.search(r'"([^"]+)"', raw_process)
            if match:
                process_name = match.group(1).split("/")[-1].split("\\")[-1]
            elif not raw_process.upper().startswith("PID "):
                process_name = raw_process.split("/")[-1].split("\\")[-1].split()[0].strip("(),;\"'")

        if process_name:
            service_product = process_name
            proc_lower = process_name.lower()
            if packages:
                # 1. Exact match
                for pkg in packages:
                    pkg_name = pkg.get("name", "").lower()
                    if pkg_name == proc_lower:
                        service_product = pkg.get("name")
                        service_version = pkg.get("version")
                        break
                else:
                    # 2. Fuzzy match
                    best_match = None
                    for pkg in packages:
                        pkg_name = pkg.get("name", "").lower()
                        if proc_lower in pkg_name or pkg_name in proc_lower:
                            if not best_match or len(pkg_name) < len(best_match.get("name", "")):
                                best_match = pkg
                    if best_match:
                        service_product = best_match.get("name")
                        service_version = best_match.get("version")

        svc_insert = insert(Service).values(
            id=service_id, asset_id=asset.id, scan_id=scan_id,
            port=port, protocol=protocol, state=state,
            service_name=service_name,
            service_product=service_product,
            service_version=service_version,
            banner=banner,
            created_at=utcnow(), updated_at=utcnow()
        )

        svc_upsert = svc_insert.on_conflict_do_update(
            index_elements=["id"],
            set_={
                "state": state, "scan_id": scan_id,
                "updated_at": utcnow(),
                "service_name": func.coalesce(
                    func.nullif(Service.service_name, "unknown"),
                    func.nullif(service_name, ""),
                    Service.service_name,
                ),
                "service_product": func.coalesce(
                    Service.service_product,
                    func.nullif(service_product or "", ""),
                ),
                "service_version": func.coalesce(
                    Service.service_version,
                    func.nullif(service_version or "", ""),
                ),
                "banner": func.coalesce(Service.banner, func.nullif(banner, "")),
            }
        )
        db.execute(svc_upsert)


def _sync_credentialed_vulnerabilities(
    db,
    asset: Asset,
    org_id: str,
    scan_id: str,
    cve_list: List[Dict],
) -> None:
    from scans.asset_syncer import _resolve_finding_id

    source_family = "credentialed_package"
    for vuln in cve_list or []:
        cve_id = _clean_text(vuln.get("cve_id") or vuln.get("cve") or vuln.get("id"))
        if not cve_id: continue

        severity = _clean_text(vuln.get("severity") or "Medium").title()
        cvss = float(vuln.get("cvss_score", vuln.get("cvss", 0.0)) or 0.0)
        description = _clean_text(vuln.get("description") or vuln.get("desc"))
        package_name = _clean_text(vuln.get("package"))
        installed_ver = _clean_text(vuln.get("installed_ver"))
        fixed_ver = _clean_text(vuln.get("fixed_ver"))

        proof = _clean_text(f"Source_Family:credentialed_package\nPackage: {package_name} {installed_ver}".strip())
        plugin_output = _clean_text(f"{description}\nFixed version: {fixed_ver or 'N/A'}\nPriority: {vuln.get('priority_level') or 'N/A'} ({vuln.get('priority_score') or 0})")

        # Get enriched details from local CVE database if available
        cvss_vector = vuln.get("cvss_vector")
        cwe_ids = []
        references = []
        
        try:
            from core.cve_database import get_cve_database
            cve_db = get_cve_database()
            if cve_db.db_available:
                details = cve_db.get_cve_details(cve_id)
                if details:
                    description = details.get("description") or description
                    cvss_vector = details.get("cvss_vector") or details.get("cvss_v3_vector") or cvss_vector
                    cwe_ids = details.get("cwe_ids") or []
                    
                    raw_refs = details.get("references") or []
                    clean_refs = []
                    for ref in raw_refs:
                        if isinstance(ref, str):
                            clean_refs.append(ref)
                        elif isinstance(ref, dict) and ref.get("url"):
                            clean_refs.append(ref["url"])
                    references = clean_refs
        except Exception as e:
            log.warning("Failed to lookup CVE details for %s during credentialed sync: %s", cve_id, e)

        # 1. UPSERT CVE Definition
        cve_insert = insert(VulnerabilityDefinition).values(
            id=cve_id, cve_id=cve_id,
            title=f"{cve_id} in {package_name}" if package_name else f"Vulnerability {cve_id}",
            description=description, cvss_vector=cvss_vector,
            cwe_ids=cwe_ids, references=references,
            severity=severity, cvss_v3_score=cvss,
            source="credentialed", created_at=utcnow(), updated_at=utcnow()
        )
        db.execute(cve_insert.on_conflict_do_nothing(index_elements=["id"]))

        # 2. UPSERT Finding
        finding_id = _resolve_finding_id(db, org_id, asset.id, cve_id, source_family)
        fnd_insert = insert(AssetVulnerability).values(
            id=finding_id, org_id=org_id, scan_id=scan_id, asset_id=asset.id, vuln_id=cve_id,
            severity=severity, cvss_score=cvss, status="open",
            source_family=source_family, evidence_source="credentialed",
            proof=proof, plugin_output=plugin_output,
            first_found_at=utcnow(), last_found_at=utcnow()
        )

        fnd_upsert = fnd_insert.on_conflict_do_update(
            index_elements=["id", "org_id"],
            set_={
                "last_found_at": utcnow(),
                "scan_id": scan_id,
                "status": "open",
                "severity": severity,
                "cvss_score": cvss,
                "source_family": source_family,
                "evidence_source": "credentialed",
                "proof": func.coalesce(func.nullif(proof, ""), AssetVulnerability.proof),
                "plugin_output": func.coalesce(func.nullif(plugin_output, ""), AssetVulnerability.plugin_output),
            }
        )
        db.execute(fnd_upsert)


@celery_app.task(name="ccure.tasks.sync_asset_discovery_task", queue="scanner")
def sync_asset_discovery_task(scan_id: str, org_id: str, user_id: Optional[str], hosts: List[dict]):
    db = SessionLocal()
    try:
        from scans.asset_syncer import sync_asset_discovery
        sync_asset_discovery(db, scan_id, org_id, user_id, hosts)
        # Automatically reconcile newly synced scan discoveries against AMT inventory ONLY IF this is the terminal phase
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan and scan.pipeline_mode == "asset_discovery":
                from core.amt_reconciliation import reconcile_amt_inventory
                reconcile_amt_inventory(db, org_id)
        except Exception as amt_exc:
            log.warning("Post-scan AMT reconciliation failed for org %s: %s", org_id, amt_exc)
    except Exception as exc:
        log.exception("Asset Sync Phase 2 Failed")
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.sync_vulnerability_audit_task", queue="scanner")
def sync_vulnerability_audit_task(scan_id: str, org_id: str, user_id: Optional[str], hosts: List[dict]):
    db = SessionLocal()
    try:
        from scans.asset_syncer import sync_vulnerability_audit
        sync_vulnerability_audit(db, scan_id, org_id, user_id, hosts)
    except Exception as exc:
        log.exception("Asset Sync Phase 3 Failed")
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.sync_host_discovery_task", queue="scanner")
def sync_host_discovery_task(scan_id: str, org_id: str, user_id: Optional[str], hosts: List[dict]):
    db = SessionLocal()
    try:
        from scans.asset_syncer import sync_host_discovery
        sync_host_discovery(db, scan_id, org_id, user_id, hosts)
        # Automatically reconcile newly synced scan discoveries against AMT inventory ONLY IF this is the terminal phase
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan and scan.pipeline_mode == "host_discovery":
                from core.amt_reconciliation import reconcile_amt_inventory
                reconcile_amt_inventory(db, org_id)
        except Exception as amt_exc:
            log.warning("Post-scan AMT reconciliation failed for org %s: %s", org_id, amt_exc)
    except Exception as exc:
        log.exception("Asset Sync Phase 1 Failed")
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.run_host_discovery", queue="scanner", bind=True)
def run_host_discovery_task(
    self,
    user_id:             str,
    targets:             List[str],
    scan_type:           str,
    pipeline_mode:       str,
    discovery_intensity: str,
    scan_id:             str,
    rate_limit:          Optional[float] = None,
    max_concurrency:     Optional[int]   = None,
    os_detection:        bool            = True,
    port_scan_intensity: str             = "normal",
    custom_ports:        Optional[str]   = None,
):
    """Phase 1 Background Task."""
    import datetime
    def ts(): return datetime.datetime.now().isoformat()

    log.info("[TRACE][TASK][%s] Starting run_host_discovery_task", ts())
    db = SessionLocal()
    try:
        _update_task_id(db, scan_id, self.request.id)
        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled before host discovery", scan_id)
            return {"success": False, "error": "Scan cancelled"}

        from scans.db_helpers import update_scan_phase1
        mode = resolve_pipeline_mode(pipeline_mode)
        terminal = get_terminal_phase(mode)
        
        # Check if execution mode is interactive
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        is_interactive = False
        if scan_row and scan_row.options:
            is_interactive = (scan_row.options.get("execution_mode") == "interactive")
            
        is_final = (terminal == 1) or is_interactive

        # 1. Run Discovery
        log.info("[TRACE][ENGINE][%s] Calling run_host_discovery_only", ts())
        orch = _new_orchestrator()
        result = _run_async(orch.run_host_discovery_only(
            targets=targets, scan_type=scan_type, pipeline_mode=mode,
            discovery_intensity=discovery_intensity, scan_id=scan_id,
            rate_limit=rate_limit, max_concurrency=max_concurrency
        ))
        log.info("[TRACE][ENGINE][%s] run_host_discovery_only finished", ts())

        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled after host discovery", scan_id)
            return {"success": False, "error": "Scan cancelled"}

        if not result.get("success"):
            mark_scan_failed(db, scan_id, user_id, result.get("error", "Host Discovery failed"))
            return result

        # 2. Metadata & Reports
        context = resolve_report_context(db, user_id, hosts=result.get("data", []),
                                         requested_targets=targets, requested_scan_type=scan_type)
        result.setdefault("metadata", {}).update(context)

        report_paths = {}
        if is_final:
            raw_paths = orch.generate_phase_report(result, "host_discovery")
            report_paths = {k: v for k, v in raw_paths.items() if v and os.path.isfile(v)}

        # 3. Update Scan (updates Scan and Phase 1 rows in DB)
        log.info("[TRACE][DB][%s] Updating scan phase 1 in DB", ts())
        scan = update_scan_phase1(
            db=db, scan_id=scan_id, user_id=user_id, phase1_data=result,
            is_final=is_final,
            report_json_path=report_paths.get("json_pdf"),
            report_xml_path=report_paths.get("xml_pdf")
        )

        # 4. Final Progress Push (Post-Commit)
        from core.redis_client import publish_progress_sync

        # If there's another phase to run, trigger it asynchronously
        if not is_final and result.get("success") and result.get("data"):
            active_hosts = [h for h in result["data"] if h.get("is_active")]
            if active_hosts:
                log.info("[TRACE][TASK][%s] Chaining next phase (Asset Discovery) for scan_id=%s", ts(), scan_id)
                
                # Fetch custom ports from the scan row if not explicitly passed
                resolved_custom_ports = custom_ports
                if not resolved_custom_ports and scan_row and scan_row.options:
                    resolved_custom_ports = scan_row.options.get("custom_ports")

                # Dispatch Phase 2 (Asset Discovery) directly
                from core.tasks import run_asset_discovery_task
                next_task = run_asset_discovery_task.delay(
                    user_id=user_id,
                    hosts=active_hosts,
                    intensity=port_scan_intensity,  # Dedicated port scan intensity (separate from discovery intensity)
                    scan_id=scan_id,
                    pipeline_mode=pipeline_mode,
                    os_detection=os_detection,      # Forward os_detection from the original request
                    custom_ports=resolved_custom_ports,  # Forward custom_ports
                )
                db.query(Scan).filter(Scan.id == scan_id).update({"current_task_id": next_task.id})
                db.commit()

                # Publish progress to let UI know we are moving to next phase
                publish_progress_sync(scan_id, 1, {
                    "discovered": scan.active_hosts,
                    "total_ips": scan.total_hosts,
                    "status": "complete"
                })

                return {"success": True, "scan_id": scan_id, "chained_task": next_task.id}
            else:
                log.info("[TRACE][TASK][%s] No active hosts found, terminating pipeline early for scan_id=%s", ts(), scan_id)

        # Ensure scan is marked complete if no next phase is chained
        if is_final or not result.get("data") or not any(h.get("is_active") for h in result.get("data", [])):
            log.info("[TRACE][TASK][%s] Scan %s pipeline complete", ts(), scan_id)
            from db.base import utcnow

            db.refresh(scan)
            if scan.status != "unreachable":
                db.query(Scan).filter(Scan.id == scan_id).update({
                    "status": "complete",
                    "completed_at": utcnow()
                })
                db.commit()
                db.refresh(scan)
            else:
                log.info("[TRACE][TASK][%s] Scan %s remains 'unreachable' as expected", ts(), scan_id)

            # FINAL PROGRESS PUSH: Use the actual scan status (could be complete or unreachable)
            publish_progress_sync(scan_id, 1, {
                "discovered": scan.active_hosts,
                "total_ips": scan.total_hosts,
                "status": scan.status
            })

        log.info("[TRACE][TASK][%s] run_host_discovery_task finished", ts())
        return {"success": True, "scan_id": scan_id}
    except Exception as exc:
        log.exception("Host Discovery Task Failed")
        mark_scan_failed(db, scan_id, user_id, str(exc))
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.run_asset_discovery", queue="scanner", bind=True)
def run_asset_discovery_task(
    self,
    user_id:       str,
    hosts:         List[dict],
    intensity:     str,
    scan_id:       str,
    pipeline_mode: str,
    os_detection:  bool = True,
    custom_ports:  Optional[str] = None,
):
    """Phase 2 Background Task."""
    import datetime
    def ts(): return datetime.datetime.now().isoformat()

    db = SessionLocal()
    try:
        _update_task_id(db, scan_id, self.request.id)
        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled before asset discovery", scan_id)
            return {"success": False, "error": "Scan cancelled"}

        mode = resolve_pipeline_mode(pipeline_mode)
        
        # Check if execution mode is interactive
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        is_interactive = False
        if scan_row and scan_row.options:
            is_interactive = (scan_row.options.get("execution_mode") == "interactive")
            
        is_final = (get_terminal_phase(mode) == 2) or is_interactive

        # Fetch custom ports from the scan row options if not explicitly passed as task parameter
        resolved_custom_ports = custom_ports
        if not resolved_custom_ports and scan_row and scan_row.options:
            resolved_custom_ports = scan_row.options.get("custom_ports")

        orch = _new_orchestrator()
        result = _run_async(orch.run_asset_discovery_only(
            hosts=hosts, intensity=intensity, pipeline_mode=mode,
            scan_id=scan_id, os_detection=os_detection,
            custom_ports=resolved_custom_ports
        ))

        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled after asset discovery", scan_id)
            return {"success": False, "error": "Scan cancelled"}

        if not result.get("success"):
            mark_scan_failed(db, scan_id, user_id, result.get("error", "Asset Discovery failed"))
            return result

        context = resolve_report_context(db, user_id, scan_id=scan_id, hosts=hosts)
        result.setdefault("metadata", {}).update(context)

        # Apply Phase 1 hints manually for the summary
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan_row:
            p1_sum = phase1_summary_from_scan(scan_row)
            if p1_sum:
                for k in ("total_hosts", "active_hosts", "inactive_hosts"):
                    if p1_sum.get(k) is not None: result["summary"][k] = p1_sum[k]

        report_paths = {}
        if is_final:
            raw_paths = orch.generate_phase_report(result, "asset_discovery")
            report_paths = {k: v for k, v in raw_paths.items() if v and os.path.isfile(v)}

        update_scan_phase(
            db=db, scan_id=scan_id, user_id=user_id, phase=2,
            phase_data={"data": result["data"], "summary": result["summary"], "metadata": result["metadata"]},
            is_final=is_final, pipeline_mode=mode,
            report_json_path=report_paths.get("json_pdf"), report_xml_path=report_paths.get("xml_pdf")
        )

        # Final Progress Push
        from core.redis_client import publish_progress_sync

        # If there's another phase to run, trigger it asynchronously
        if not is_final and result.get("success") and result.get("data"):
            active_hosts = [h for h in result["data"] if h.get("is_active")]
            if active_hosts:
                log.info("[TRACE][TASK][%s] Chaining next phase (Vulnerability Audit) for scan_id=%s", ts(), scan_id)
                # Dispatch Phase 3 (Vulnerability Audit) directly
                from core.tasks import run_vulnerability_audit_task
                next_task = run_vulnerability_audit_task.delay(
                    user_id=user_id,
                    hosts=active_hosts,
                    scan_id=scan_id,
                    pipeline_mode=pipeline_mode
                )
                db.query(Scan).filter(Scan.id == scan_id).update({"current_task_id": next_task.id})
                db.commit()

                publish_progress_sync(scan_id, 2, {
                    "scanned_hosts": result["summary"].get("total_hosts", 0),
                    "total_hosts": result["summary"].get("total_hosts", 0),
                    "status": "complete"
                })
                return {"success": True, "scan_id": scan_id, "chained_task": next_task.id}
            else:
                log.info("[TRACE][TASK][%s] No active hosts found, terminating pipeline early for scan_id=%s", ts(), scan_id)

        publish_progress_sync(scan_id, 2, {
            "scanned_hosts": result["summary"].get("total_hosts", 0),
            "total_hosts": result["summary"].get("total_hosts", 0),
            "status": "complete"
        })

        # Ensure scan is marked complete if no next phase is chained
        if is_final or not result.get("data") or not any(h.get("is_active") for h in result.get("data", [])):
            log.info("[TRACE][TASK][%s] Scan %s pipeline complete", ts(), scan_id)
            db.refresh(scan_row)
            if scan_row.status != "unreachable":
                db.query(Scan).filter(Scan.id == scan_id).update({
                    "status": "complete",
                    "completed_at": utcnow()
                })
                db.commit()
            else:
                log.info("[TRACE][TASK][%s] Scan %s remains 'unreachable' as expected", ts(), scan_id)

        return {"success": True, "scan_id": scan_id}
    except Exception as exc:
        log.exception("Asset Discovery Task Failed")
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.run_vulnerability_audit", queue="scanner", bind=True)
def run_vulnerability_audit_task(
    self,
    user_id:       str,
    hosts:         List[dict],
    scan_id:       str,
    pipeline_mode: str,
):
    """Phase 3 Background Task."""
    db = SessionLocal()
    try:
        _update_task_id(db, scan_id, self.request.id)
        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled before vulnerability audit", scan_id)
            return {"success": False, "error": "Scan cancelled"}

        mode = resolve_pipeline_mode(pipeline_mode)
        orch = _new_orchestrator()
        result = orch.run_vulnerability_audit_only(hosts=hosts, scan_id=scan_id)

        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled after vulnerability audit", scan_id)
            return {"success": False, "error": "Scan cancelled"}

        if not result.get("success"):
            mark_scan_failed(db, scan_id, user_id, result.get("error", "Vulnerability Audit failed"))
            return result

        result["data"] = _merge_host_identity(result.get("data", []), hosts)

        context = resolve_report_context(db, user_id, scan_id=scan_id, hosts=hosts)
        result.setdefault("metadata", {}).update(context)

        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan_row:
            p1_sum = phase1_summary_from_scan(scan_row)
            if p1_sum:
                for k in ("total_hosts", "active_hosts", "inactive_hosts"):
                    if p1_sum.get(k) is not None: result["summary"][k] = p1_sum[k]

        raw_paths = orch.generate_phase_report(result, "phase_selective_scan")
        report_paths = {k: v for k, v in raw_paths.items() if v and os.path.isfile(v)}

        update_scan_phase(
            db=db, scan_id=scan_id, user_id=user_id, phase=3,
            phase_data={"data": result["data"], "summary": result["summary"], "metadata": result["metadata"]},
            is_final=True, pipeline_mode=mode,
            report_json_path=report_paths.get("json_pdf"), report_xml_path=report_paths.get("xml_pdf")
        )

        # Final Progress Push
        from core.redis_client import publish_progress_sync
        publish_progress_sync(scan_id, 3, {
            "scanned_hosts": result["summary"].get("total_hosts", 0),
            "total_hosts": result["summary"].get("total_hosts", 0),
            "status": "complete"
        })

        return {"success": True, "scan_id": scan_id}
    except Exception as exc:
        log.exception("Vulnerability Audit Task Failed")
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.run_traditional_scan", queue="scanner")
def run_traditional_scan_task(
    user_id:   str,
    targets:   List[str],
    phases:    str,
    scan_type: str,
    intensity: str,
):
    """Traditional Scan Task."""
    db = SessionLocal()
    try:
        orch = _new_orchestrator()
        result = _run_async(orch.run_phases(
            targets=targets, phases=phases, scan_type=scan_type, intensity=intensity
        ))
        return result
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.run_credentialed_scan", queue="scanner")
def run_credentialed_scan_task(
    user_id:     str,
    ip:          str,
    username:    str,
    password:    Optional[str],
    key_path:    Optional[str],
    port:        int,
    auth_method: str,
    sections:    Optional[List[str]],
    os_type_req: str,
    scan_id:     Optional[str] = None,
):
    """Phase 5 Credentialed Scan Task."""
    from engines.credentialed.ssh_scanner     import SSHScanner
    from engines.credentialed.linux_collector import LinuxCollector
    from engines.credentialed.windows_collector import WindowsCollector
    from engines.credentialed.vuln_matcher    import VulnMatcher
    from routers.credentialed import _detect_os
    from core.redis_client import publish_progress_sync

    db = SessionLocal()
    start_time = time.time()

    def emit(status, message, percentage=0, stage=None):
        if not scan_id: return
        publish_progress_sync(scan_id, 5, {
            "status": status,
            "message": message,
            "percentage": percentage,
            "stage": stage,
            "target": ip,
            "timestamp": utcnow().isoformat()
        })

    try:
        # 1. Connecting
        emit("running", f"Connecting to {ip}:{port}...", 10, "connecting")

        connect_started = time.perf_counter()
        credentialed_response_time_ms = None
        with SSHScanner(ip=ip, username=username, password=password, key_path=key_path, port=port, timeout=20) as ssh:
            credentialed_response_time_ms = int(round((time.perf_counter() - connect_started) * 1000))
            # 2. OS Detection
            emit("running", "Detecting Operating System...", 20, "detection")
            os_type = os_type_req if os_type_req != "auto" else _detect_os(ssh)

            # 3. Data Collection
            emit("running", f"Collecting system data ({os_type})...", 30, "collection")
            collector = WindowsCollector(ssh) if os_type == "windows" else LinuxCollector(ssh)

            def on_section(name):
                # Map internal section names to friendly display names
                friendly = {
                    "system_info": "System Profile",
                    "packages":    "Software Inventory",
                    "services":    "Running Services",
                    "ports":       "Network Sockets",
                    "users":       "User Accounts",
                    "security":    "Security Policies",
                    "network":     "Interface Config",
                    "history":     "Login Events"
                }.get(name, name)
                emit("running", f"Collected {friendly}", 50, "collection")

            system_data = collector.collect_all(
                sections=_credentialed_sections_with_identity(sections),
                on_section_complete=on_section,
            )
            system_data["detected_os"] = os_type
            system_data["credentialed_response_time_ms"] = credentialed_response_time_ms

        # 4. Vulnerability Matching
        emit("running", "Analyzing packages for vulnerabilities...", 70, "analysis")
        packages     = system_data.get("packages", [])
        matcher      = VulnMatcher()
        raw_findings = matcher.match_packages(packages)
        cve_list     = matcher.to_report_format(raw_findings)

        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for cve in cve_list:
            sev = cve.get("severity", "Info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        scan_duration = round(time.time() - start_time, 2)

        # 5. Finalizing
        emit("running", "Generating report and syncing assets...", 90, "syncing")

        from core.oui_lookup import lookup_vendor

        hostname, fqdn, raw_hostname_fqdn = _extract_credentialed_identity_names(system_data)
        mac_address = _normalize_mac(system_data.get("mac_address"))
        mac_vendor = _clean_text(system_data.get("mac_vendor") or (lookup_vendor(mac_address) if mac_address else ""))

        stored_report = {
            "scan_type": "credentialed",
            "target": ip,
            "username": username,
            "detected_os": os_type,
            "os_type_was_auto": (os_type_req == "auto"),
            "system_info": {
                "os_name":        system_data.get("os_name", ""),
                "os_family":      system_data.get("os_family", ""),
                "os_version_id":  system_data.get("os_version_id", ""),
                "os_confidence":  system_data.get("os_confidence", ""),
                "os_build":       system_data.get("os_build", ""),
                "kernel_version": system_data.get("kernel_version", ""),
                "hostname":       hostname,
                "hostname_short": system_data.get("hostname_short", ""),
                "hostname_fqdn_raw": raw_hostname_fqdn,
                "fqdn":           fqdn,
                "domain":         system_data.get("domain", ""),
                "manufacturer":   system_data.get("manufacturer", ""),
                "hardware_model": system_data.get("hardware_model", ""),
                "mac_address":    mac_address,
                "mac_vendor":     mac_vendor,
                "cpu_model":      system_data.get("cpu_model", ""),
                "cpu_count":      system_data.get("cpu_count", ""),
                "cpu_arch":       system_data.get("cpu_arch", ""),
                "uptime":         system_data.get("uptime", ""),
                "memory_summary": system_data.get("memory_summary", {}),
                "disk_usage":     system_data.get("disk_usage", []),
                "subnet":         system_data.get("subnet", ""),
                "credentialed_response_time_ms": system_data.get("credentialed_response_time_ms", ""),
                "serial_number":  system_data.get("serial_number", ""),
                "bios_version":   system_data.get("bios_version", ""),
            },
            "packages":                packages,
            "package_count":           len(packages),
            "running_services":        system_data.get("running_services", []),
            "open_ports_credentialed": system_data.get("open_ports_credentialed", []),
            "users":                   system_data.get("users", []),
            "local_groups":            system_data.get("local_groups", []),
            "suid_binaries":           system_data.get("suid_binaries", []),
            "world_writable_dirs":     system_data.get("world_writable_dirs", []),
            "sudo_nopasswd":           system_data.get("sudo_nopasswd", False),
            "sudo_rules_raw":          system_data.get("sudo_rules_raw", ""),
            "security_issues":         system_data.get("security_issues", []),
            "failed_login_count":      system_data.get("failed_login_count", 0),
            "brute_force_warning":     system_data.get("brute_force_warning", False),
            "failed_logins_recent":    system_data.get("failed_logins_recent", []),
            "network_interfaces_raw":  system_data.get("network_interfaces_raw", ""),
            "env_vars_flagged":        system_data.get("env_vars_summary", []),
            "cves":                    cve_list,
            "cve_count":               len(cve_list),
            "severity_summary":        severity_counts,
            "scan_duration":           scan_duration,
        }
        report_result = {
            "success": True, "data": {"credentialed": {"report": stored_report}},
            "summary": {
                "scan_type": "credentialed",
                "cve_count": len(cve_list),
                "scan_duration": scan_duration,
                "critical_count": severity_counts["Critical"],
                "high_count": severity_counts["High"],
                "medium_count": severity_counts["Medium"],
                "low_count": severity_counts["Low"],
                "info_count": severity_counts["Info"],
                "total_vulns": len(cve_list),
            },
            "metadata": {"target": ip, "scan_type": "credentialed"},
        }
        orch = _new_orchestrator()
        report_paths = orch.generate_phase_report(report_result, "credentialed_scan")
        scan = create_completed_scan(
            db=db, user_id=user_id, target=ip, targets=[ip], scan_type="credentialed", phase=3,
            results={"credentialed": {"report": stored_report}}, summary=report_result["summary"],
            scan_duration=scan_duration, report_json_path=report_paths.get("json_pdf"), report_xml_path=report_paths.get("xml_pdf"),
            scan_id=scan_id,
            commit=False, # ENTERPRISE FIX: Do not commit yet
        )

        # Sync to Asset Registry within the same transaction
        _sync_credentialed_asset_identity(
            db,
            user_id=user_id,
            ip=ip,
            scan_id=str(scan.id),
            os_type=os_type,
            system_data=system_data,
            stored_report=stored_report,
            cve_list=cve_list,
            severity_counts=severity_counts,
        )

        # ATOMIC COMMIT: Final persistence of everything
        db.commit()

        # 6. Complete
        emit("complete", "Scan completed successfully.", 100, "complete")
        return {"success": True, "scan_id": str(scan.id)}
    except Exception as exc:
        db.rollback() # Rollback everything if any step fails

        reason = str(exc)
        status = "failed"
        if any(msg in reason.lower() for msg in ["reach", "timeout", "no route", "connection refused", "down"]):
            status = "unreachable"

        # Suppress stack trace for expected network/credentials errors
        if "ssh authentication failed" in reason.lower() or "cannot reach" in reason.lower() or "ssh connection error" in reason.lower():
            log.error(f"Credentialed Scan Task Failed: {reason}")
        else:
            log.exception("Credentialed Scan Task Failed")

        emit(status, f"Scan {status}: {reason}", 0, "error")
        if scan_id:
            mark_scan_failed(db, scan_id, user_id, reason, status=status)
        return {"success": False, "error": reason}
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.send_password_reset_email", queue="default")
def send_password_reset_email_task(email_to: str, username: str, reset_link: str) -> None:
    """Async background task to dispatch password reset emails."""
    from auth.mail_service import send_password_reset_email as _send
    _send(email_to, username, reset_link)


@celery_app.task(name="ccure.tasks.send_mfa_otp", queue="default")
def send_mfa_otp_task(email_to: str, username: str, code: str) -> None:
    """Async background task to dispatch MFA OTP emails."""
    try:
        from auth.mail_service import send_mfa_otp_email as _send
        _send(email_to, username, code)
    except Exception as exc:
        log.error(f"Failed to dispatch MFA OTP email to {email_to}: {exc}", exc_info=True)



@celery_app.task(name="ccure.tasks.reconcile_amt_inventory_task", queue="scanner")
def reconcile_amt_inventory_task(org_id: str) -> dict:
    """Async background task to run AMT reconciliation for an organization."""
    db = SessionLocal()
    try:
        from core.amt_reconciliation import reconcile_amt_inventory
        return reconcile_amt_inventory(db, org_id)
    except Exception as exc:
        log.exception(f"AMT Reconciliation background task failed for org {org_id}")
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.update_mac_vendor_registry", queue="default")
def update_mac_vendor_registry_task() -> dict:
    """
    Downloads the latest raw OUI manufacturer registry from Wireshark
    and updates the local manuf.txt file.
    """
    import requests
    from core.oui_lookup import get_oui_db

    url = "https://www.wireshark.org/download/automated/data/manuf"
    log.info("Starting MAC vendor registry update from %s", url)

    try:
        db_path = get_oui_db().db_path
        if not db_path:
            log.warning("OUI database path is not defined. Skipping registry update.")
            return {"success": False, "error": "No database path configured"}

        # 1. Fetch from URL with a reasonable timeout
        response = requests.get(url, timeout=30.0)
        if response.status_code != 200:
            log.warning("Failed to fetch OUI registry. HTTP Status: %d", response.status_code)
            return {"success": False, "error": f"HTTP status {response.status_code}"}

        content = response.text

        # 2. Basic validation: ensure the file contains comments and some common MAC prefixes
        if not content.startswith("#") or "00:00:00" not in content:
            log.warning("Fetched OUI registry failed validation checks. Update aborted.")
            return {"success": False, "error": "Invalid file format"}

        # 3. Write to a temporary file first to prevent corruption on write failure
        temp_path = db_path + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(content)

        # 4. Safely rename/overwrite target file
        if os.path.exists(db_path):
            os.remove(db_path)
        os.rename(temp_path, db_path)

        # 5. Reload the OUIDatabase mapping dict in memory
        get_oui_db()._loaded = False
        get_oui_db()._database.clear()
        get_oui_db()._load()

        log.info("MAC vendor registry updated successfully. Loaded %d entries.", len(get_oui_db()._database))
        return {"success": True, "entries": len(get_oui_db()._database)}

    except Exception as exc:
        log.exception("MAC vendor registry background update task failed")
        return {"success": False, "error": str(exc)}



