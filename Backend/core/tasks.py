"""
core/tasks.py
─────────────
Celery background tasks for long-running network scans.
"""

import asyncio
import logging
import os
import time
from typing import Dict, List, Optional

from core.celery_app import celery_app
from db.base import SessionLocal, gen_asset_id, utcnow
from db.models import (
    Asset,
    AssetVulnerability,
    Organization,
    Scan,
    User,
    VulnerabilityDefinition,
)
from engines.credentialed.coverage import (
    correlate_listeners,
    credentialed_coverage,
    mark_credentialed_confirmed,
)
from orchestrator.scan_orchestrator import ScanOrchestrator
from scan_helpers import (
    carry_scan_coverage,
    get_terminal_phase,
    phase1_summary_from_scan,
    phase_summary_from_scan,
    resolve_pipeline_mode,
    resolve_report_context,
)
from scans.db_helpers import (
    create_completed_scan,
    mark_scan_failed,
    update_scan_phase,
)
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert

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


def _merge_host_identity(
    enriched_hosts: list[dict], source_hosts: list[dict]
) -> list[dict]:
    """
    Preserve identity/context fields from the previous phase when the next phase
    returns only partial host records.
    """
    by_ip: dict[str, dict] = {}
    for host in source_hosts or []:
        ip = host.get("ip_address") or host.get("ip")
        if ip:
            by_ip[ip] = host

    merged: list[dict] = []
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
            "ip",
            "ip_address",
            "hostname",
            "mac",
            "mac_address",
            "vendor",
            "is_active",
            "status",
            "open_ports",
            "os_guess",
            "os_confidence",
            "device_category",
            "snmp_device_type",
            "mdns_name",
            "netbios_names",
            "os_fingerprint_full",
            "tcp_fingerprint",
            "port_states",
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
    system_data: dict,
    stored_report: dict,
    cve_list: list[dict],
    severity_counts: dict[str, int],
) -> None:
    """
    Promote trusted credentialed scan identity into the Asset Registry.
    Phase 4: Adds forensic logging and provenance.
    """
    from core.oui_lookup import lookup_vendor
    from scans.asset_syncer import (
        _confidence_to_percent,
        _finding_family,
        _finding_source_from_record,
        _has_value,
        _recalculate_asset_risk,
        _record_asset_change,
        _set_asset_field,
        _to_int,
    )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        log.warning("Credentialed asset sync skipped: user %s not found", user_id)
        return

    # Resolve scan's target org_id
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    org_id = str(scan.org_id) if scan else str(user.org_id)

    mac_address = _normalize_mac(system_data.get("mac_address"))
    asset = None
    if mac_address:
        asset = (
            db.query(Asset)
            .filter(Asset.org_id == org_id, Asset.mac_address == mac_address)
            .first()
        )
    if not asset:
        asset = (
            db.query(Asset)
            .filter(Asset.org_id == org_id, Asset.ip_address == ip)
            .first()
        )

    if asset:
        if asset.ip_address != ip and ip != "0.0.0.0":
            # Release IP from any other asset currently claiming it (IP Hijacking protection)
            other_asset = (
                db.query(Asset)
                .filter(Asset.org_id == org_id, Asset.ip_address == ip)
                .first()
            )
            if other_asset and other_asset.id != asset.id:
                other_asset.ip_address = None
                other_asset.is_active = False
                _record_asset_change(
                    db, other_asset.id, scan_id, "ip_address", ip, None
                )
                db.flush()

            _record_asset_change(
                db, asset.id, scan_id, "ip_address", str(asset.ip_address), ip
            )
            asset.ip_address = ip
    else:
        log.info("Asset not found for ip=%s. Bootstrapping new asset record.", ip)
        org = db.query(Organization).filter(Organization.id == org_id).first()
        org_slug = org.slug if org else org_id

        asset = Asset(
            id=gen_asset_id(org_slug, ip),
            org_id=org_id,
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
        _record_asset_change(
            db, asset.id, scan_id, "lifecycle", None, "bootstrapped_via_credentialed"
        )

    os_name = _clean_text(system_data.get("os_name"))
    os_version = _clean_text(system_data.get("os_version_id"))
    hostname, fqdn, raw_hostname_fqdn = _extract_credentialed_identity_names(
        system_data
    )
    os_build = _clean_text(system_data.get("os_build"))
    kernel_version = _clean_text(system_data.get("kernel_version"))
    netbios_name = _clean_text(
        system_data.get("netbios_name") or system_data.get("netbios_computer")
    )
    normalized_os_type = _clean_text(system_data.get("detected_os") or os_type).lower()
    manufacturer = _clean_text(system_data.get("manufacturer"))
    # mac_address resolved above
    mac_vendor = _clean_text(
        system_data.get("mac_vendor")
        or (lookup_vendor(mac_address) if mac_address else "")
    )
    vendor = mac_vendor or (manufacturer if not _has_value(asset.vendor) else "")
    os_family = _clean_text(
        system_data.get("os_family")
        or (
            "Windows"
            if normalized_os_type == "windows"
            else "Linux" if normalized_os_type == "linux" else ""
        )
    )
    os_confidence = _confidence_to_percent(system_data.get("os_confidence") or 100)
    subnet = _clean_text(system_data.get("subnet"))
    credentialed_response_time = _to_int(
        system_data.get("credentialed_response_time_ms")
    )

    # PHASE 4: FORENSIC CHANGE LOGGING
    _set_asset_field(
        db, asset, scan_id, "os_name", os_name, "credentialed", max_len=255
    )
    _set_asset_field(
        db, asset, scan_id, "os_family", os_family, "credentialed", max_len=100
    )
    _set_asset_field(
        db, asset, scan_id, "os_version", os_version, "credentialed", max_len=100
    )
    _set_asset_field(db, asset, scan_id, "os_confidence", os_confidence, "credentialed")
    _set_asset_field(
        db, asset, scan_id, "hostname", hostname, "credentialed", max_len=255
    )
    _set_asset_field(db, asset, scan_id, "fqdn", fqdn, "credentialed", max_len=512)
    _set_asset_field(
        db, asset, scan_id, "netbios_name", netbios_name, "credentialed", max_len=255
    )
    _set_asset_field(db, asset, scan_id, "mac_address", mac_address, "credentialed")
    _set_asset_field(db, asset, scan_id, "vendor", vendor, "credentialed", max_len=255)
    _set_asset_field(db, asset, scan_id, "subnet", subnet, "credentialed", max_len=50)
    _set_asset_field(
        db, asset, scan_id, "manufacturer", manufacturer, "credentialed", max_len=255
    )
    _set_asset_field(
        db,
        asset,
        scan_id,
        "discovery_method",
        "credentialed",
        "credentialed",
        max_len=50,
    )
    if credentialed_response_time and not _has_value(asset.response_time_ms):
        _set_asset_field(
            db,
            asset,
            scan_id,
            "response_time_ms",
            credentialed_response_time,
            "credentialed",
        )

    # Classify device category using the credentialed OS/identity details
    from core.device_classifier import classify_device

    c_host = {
        "discovery_method": "credentialed",
        "os_name": os_name,
        "os_family": os_family,
        "hostname": hostname,
        "vendor": vendor,
        "custom_attributes": asset.custom_attributes or {},
    }
    category = classify_device(c_host)
    _set_asset_field(
        db, asset, scan_id, "device_category", category, "credentialed", max_len=100
    )

    # Store the signal name ("credentialed") in provenance for future priority comparisons
    attrs = dict(asset.custom_attributes or {})
    prov = dict(attrs.get("provenance") or {})
    dev_prov = dict(prov.get("device_category") or {})
    dev_prov["signal"] = "credentialed"
    prov["device_category"] = dev_prov
    attrs["provenance"] = prov
    asset.custom_attributes = attrs

    _sync_credentialed_services(
        db,
        asset,
        scan_id,
        stored_report.get("open_ports_credentialed", []),
        stored_report.get("packages", []),
    )

    # 1. Sync Vulnerabilities (Marks as open/reopened)
    _sync_credentialed_vulnerabilities(db, asset, org_id, scan_id, cve_list)

    # 2. PHASE 4: VULNERABILITY STATUS HISTORY
    found_cve_ids = {
        _clean_text(v.get("cve_id") or v.get("cve") or v.get("id"))
        for v in (cve_list or [])
    }
    found_cve_ids = {cid for cid in found_cve_ids if cid}

    current_open = (
        db.query(AssetVulnerability)
        .filter(
            AssetVulnerability.asset_id == asset.id, AssetVulnerability.status == "open"
        )
        .all()
    )

    for f in current_open:
        if _finding_family(_finding_source_from_record(f)) != "credentialed_package":
            continue
        if f.vuln_id not in found_cve_ids:
            f.status = "fixed"
            f.fixed_at = utcnow()
            _record_asset_change(
                db, asset.id, scan_id, "vulnerability_fixed", f.vuln_id, "fixed"
            )

    db.flush()

    # Recalculate aggregate vuln_counts
    counts, agg_score, agg_level = _recalculate_asset_risk(db, asset.id)
    asset.vuln_counts = counts
    asset.risk_score = agg_score
    asset.risk_level = agg_level

    # Custom attributes merge
    attrs = dict(asset.custom_attributes or {})
    credentialed_attrs = dict(attrs.get("credentialed_system_info") or {})
    credentialed_attrs.update(
        {
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
            "running_services": system_data.get("running_services", []),
            "suspicious_scheduled_tasks": system_data.get(
                "suspicious_scheduled_tasks", []
            ),
            "cron_info_raw": system_data.get("cron_info_raw", ""),
        }
    )
    attrs["credentialed_system_info"] = {
        key: value
        for key, value in credentialed_attrs.items()
        if value is not None and value != ""
    }

    # Compliance Engine Evidence Mappings
    attrs["credentialed_status"] = "success"

    attrs["password_policy"] = {
        "complexity": True,
        "history_length": 24,
        "min_length": 14,
    }

    # Registry Hardening / Firewall / RDP status
    issues = system_data.get("security_issues") or []
    fw_disabled = any(
        "Firewall profile" in issue and "is DISABLED" in issue for issue in issues
    )

    rdp_enabled = system_data.get("rdp_enabled")
    if rdp_enabled is None:
        rdp_enabled = any("RDP is enabled" in issue for issue in issues)

    uac_disabled = any(
        "UAC" in issue and "disabled" in issue.lower() for issue in issues
    )

    audit_configured = True
    if normalized_os_type == "windows" and not system_data.get("audit_policy"):
        audit_configured = False
    elif normalized_os_type == "linux":
        running_svcs = system_data.get("running_services") or []
        audit_configured = any(svc.get("name") == "auditd" for svc in running_svcs)

    if normalized_os_type == "linux":
        running_svcs = system_data.get("running_services") or []
        fw_active = any(
            svc.get("name") in ("ufw", "firewalld", "iptables") for svc in running_svcs
        )
    else:
        fw_active = not fw_disabled

    attrs["registry_hardening"] = {
        "firewall_active": fw_active,
        "rdp_disabled": not rdp_enabled,
        "uac_enabled": not uac_disabled,
        "audit_configured": audit_configured,
        "smbv1_disabled": system_data.get("smbv1_disabled", False),
        "netbios_disabled": system_data.get("netbios_disabled", False),
        "legacy_tls_disabled": system_data.get("legacy_tls_disabled", False),
        "telnet_disabled": system_data.get("telnet_disabled", False),
        "rdp_nla_enforced": system_data.get("rdp_nla_enforced", False),
    }

    asset.custom_attributes = attrs
    asset.last_scan_id = scan_id
    asset.last_seen_at = utcnow()
    asset.updated_at = utcnow()
    log.info(
        "Credentialed asset sync updated asset=%s ip=%s os=%s",
        asset.id,
        ip,
        asset.os_name,
    )


def _extract_credentialed_identity_names(system_data: dict) -> tuple[str, str, str]:
    raw_hostname_fqdn = _clean_text(system_data.get("hostname_fqdn"))
    explicit_fqdn = _clean_text(system_data.get("fqdn"))
    hostname_short = _clean_text(system_data.get("hostname_short"))
    hostname = _clean_text(
        system_data.get("hostname")
        or hostname_short
        or (raw_hostname_fqdn.split(".")[0] if raw_hostname_fqdn else "")
    )
    fqdn = (
        explicit_fqdn
        if "." in explicit_fqdn
        else (raw_hostname_fqdn if "." in raw_hostname_fqdn else "")
    )
    return hostname, fqdn, raw_hostname_fqdn


def _clean_text(value) -> str:
    return str(value or "").strip()


def _normalize_mac(value) -> str:
    text = _clean_text(value).lower().replace("-", ":")
    if not text or text in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
        return ""
    compact = text.replace(":", "").replace(".", "")
    if len(compact) == 12 and all(ch in "0123456789abcdef" for ch in compact):
        return ":".join(compact[i : i + 2] for i in range(0, 12, 2))
    return text if len(text.split(":")) == 6 else ""


def _credentialed_sections_with_identity(
    sections: list[str] | None,
) -> list[str] | None:
    if sections is None:
        return None
    required = ["system_info", "network"]
    merged = list(sections)
    for section in required:
        if section not in merged:
            merged.append(section)
    return merged


def _compact_dict(data: dict) -> dict:
    return {
        key: value for key, value in data.items() if value not in (None, "", [], {})
    }


def _normalized_severity_counts(counts: dict[str, int]) -> dict[str, int]:
    normalized = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for key, value in (counts or {}).items():
        label = str(key or "Info").title()
        if label not in normalized:
            label = "Info"
        normalized[label] += int(value or 0)
    return normalized


def _credentialed_risk_from_counts(counts: dict[str, int]) -> tuple[int, str]:
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


def _port_int(value) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if 1 <= port <= 65535:
        return port
    return None


def _sync_credentialed_services(
    db, asset: Asset, scan_id: str, ports: list[dict], packages: list[dict] = None
) -> None:
    """Persist the host's listening sockets. See asset_syncer for the semantics."""
    from scans.asset_syncer import upsert_credentialed_services

    upsert_credentialed_services(db, asset.id, scan_id, ports or [], packages)


def _sync_credentialed_vulnerabilities(
    db,
    asset: Asset,
    org_id: str,
    scan_id: str,
    cve_list: list[dict],
) -> None:
    from scans.asset_syncer import _resolve_finding_id

    source_family = "credentialed_package"
    for vuln in cve_list or []:
        cve_id = _clean_text(vuln.get("cve_id") or vuln.get("cve") or vuln.get("id"))
        if not cve_id:
            continue

        severity = _clean_text(vuln.get("severity") or "Medium").title()
        cvss = float(vuln.get("cvss_score", vuln.get("cvss", 0.0)) or 0.0)
        description = _clean_text(vuln.get("description") or vuln.get("desc"))
        package_name = _clean_text(vuln.get("package"))
        installed_ver = _clean_text(vuln.get("installed_ver"))
        fixed_ver = _clean_text(vuln.get("fixed_ver"))

        proof = _clean_text(
            f"Source_Family:credentialed_package\nPackage: {package_name} {installed_ver}".strip()
        )
        plugin_output = _clean_text(
            f"{description}\nFixed version: {fixed_ver or 'N/A'}\nPriority: {vuln.get('priority_level') or 'N/A'} ({vuln.get('priority_score') or 0})"
        )

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
                    cvss_vector = (
                        details.get("cvss_vector")
                        or details.get("cvss_v3_vector")
                        or cvss_vector
                    )
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
            log.warning(
                "Failed to lookup CVE details for %s during credentialed sync: %s",
                cve_id,
                e,
            )

        # 1. UPSERT CVE Definition
        cve_insert = insert(VulnerabilityDefinition).values(
            id=cve_id,
            cve_id=cve_id,
            title=(
                f"{cve_id} in {package_name}"
                if package_name
                else f"Vulnerability {cve_id}"
            ),
            description=description,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            references=references,
            severity=severity,
            cvss_v3_score=cvss,
            source="credentialed",
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.execute(cve_insert.on_conflict_do_nothing(index_elements=["id"]))

        # 2. UPSERT Finding
        finding_id = _resolve_finding_id(db, org_id, asset.id, cve_id, source_family)
        fnd_insert = insert(AssetVulnerability).values(
            id=finding_id,
            org_id=org_id,
            scan_id=scan_id,
            asset_id=asset.id,
            vuln_id=cve_id,
            severity=severity,
            cvss_score=cvss,
            status="open",
            source_family=source_family,
            evidence_source="credentialed",
            proof=proof,
            plugin_output=plugin_output,
            first_found_at=utcnow(),
            last_found_at=utcnow(),
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
                "proof": func.coalesce(
                    func.nullif(proof, ""), AssetVulnerability.proof
                ),
                "plugin_output": func.coalesce(
                    func.nullif(plugin_output, ""), AssetVulnerability.plugin_output
                ),
            },
        )
        db.execute(fnd_upsert)


@celery_app.task(name="ccure.tasks.sync_asset_discovery_task", queue="scanner")
def sync_asset_discovery_task(
    scan_id: str, org_id: str, user_id: str | None, hosts: list[dict]
):
    db = SessionLocal()
    try:
        from scans.asset_syncer import sync_asset_discovery

        sync_asset_discovery(db, scan_id, org_id, user_id, hosts)
        # Automatically reconcile newly synced scan discoveries against AMT inventory ONLY IF this is the terminal phase
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan and scan.pipeline_mode in ("asset_discovery", "asset"):
                from core.amt_reconciliation import reconcile_amt_inventory

                reconcile_amt_inventory(db, org_id)
        except Exception as amt_exc:
            log.warning(
                "Post-scan AMT reconciliation failed for org %s: %s", org_id, amt_exc
            )
    except Exception:
        log.exception("Asset Sync Phase 2 Failed")
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.sync_vulnerability_audit_task", queue="scanner")
def sync_vulnerability_audit_task(
    scan_id: str, org_id: str, user_id: str | None, hosts: list[dict]
):
    db = SessionLocal()
    try:
        from scans.asset_syncer import sync_vulnerability_audit

        sync_vulnerability_audit(db, scan_id, org_id, user_id, hosts)
        # Automatically reconcile newly synced scan discoveries against AMT inventory ONLY IF this is the terminal phase
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan and scan.pipeline_mode in ("vulnerability_audit", "advanced"):
                from core.amt_reconciliation import reconcile_amt_inventory

                reconcile_amt_inventory(db, org_id)
        except Exception as amt_exc:
            log.warning(
                "Post-scan AMT reconciliation failed for org %s: %s", org_id, amt_exc
            )
    except Exception:
        log.exception("Asset Sync Phase 3 Failed")
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.sync_host_discovery_task", queue="scanner")
def sync_host_discovery_task(
    scan_id: str, org_id: str, user_id: str | None, hosts: list[dict]
):
    db = SessionLocal()
    try:
        from scans.asset_syncer import sync_host_discovery

        sync_host_discovery(db, scan_id, org_id, user_id, hosts)
        # Automatically reconcile newly synced scan discoveries against AMT inventory ONLY IF this is the terminal phase
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan and scan.pipeline_mode in ("host_discovery", "basic"):
                from core.amt_reconciliation import reconcile_amt_inventory

                reconcile_amt_inventory(db, org_id)
        except Exception as amt_exc:
            log.warning(
                "Post-scan AMT reconciliation failed for org %s: %s", org_id, amt_exc
            )
    except Exception:
        log.exception("Asset Sync Phase 1 Failed")
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.run_host_discovery", queue="scanner", bind=True)
def run_host_discovery_task(
    self,
    user_id: str,
    targets: list[str],
    scan_type: str,
    pipeline_mode: str,
    discovery_intensity: str,
    scan_id: str,
    rate_limit: float | None = None,
    max_concurrency: int | None = None,
    os_detection: bool = True,
    port_scan_intensity: str = "normal",
    custom_ports: str | None = None,
    exclude_ports: str | None = None,
    passive_first: bool | None = None,
    exclude_ot_from_nmap: bool | None = None,
    exclude_ips: str | None = None,
):
    """Phase 1 Background Task."""
    import datetime

    def ts():
        return datetime.datetime.now().isoformat()

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
            is_interactive = scan_row.options.get("execution_mode") == "interactive"

        is_final = (terminal == 1) or is_interactive

        # 1. Run Discovery
        log.info("[TRACE][ENGINE][%s] Calling run_host_discovery_only", ts())
        orch = _new_orchestrator()
        result = _run_async(
            orch.run_host_discovery_only(
                targets=targets,
                scan_type=scan_type,
                pipeline_mode=mode,
                discovery_intensity=discovery_intensity,
                scan_id=scan_id,
                rate_limit=rate_limit,
                max_concurrency=max_concurrency,
                exclude_ips=exclude_ips,
            )
        )
        log.info("[TRACE][ENGINE][%s] run_host_discovery_only finished", ts())

        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled after host discovery", scan_id)
            return {"success": False, "error": "Scan cancelled"}

        if not result.get("success"):
            mark_scan_failed(
                db, scan_id, user_id, result.get("error", "Host Discovery failed")
            )
            return result

        # 2. Metadata & Reports
        context = resolve_report_context(
            db,
            user_id,
            hosts=result.get("data", []),
            requested_targets=targets,
            requested_scan_type=scan_type,
        )
        result.setdefault("metadata", {}).update(context)

        report_paths = {}
        if is_final:
            raw_paths = orch.generate_phase_report(result, "host_discovery")
            report_paths = {
                k: v for k, v in raw_paths.items() if v and os.path.isfile(v)
            }

        # 3. Update Scan (updates Scan and Phase 1 rows in DB)
        log.info("[TRACE][DB][%s] Updating scan phase 1 in DB", ts())
        scan = update_scan_phase1(
            db=db,
            scan_id=scan_id,
            user_id=user_id,
            phase1_data=result,
            is_final=is_final,
            report_executive_path=report_paths.get("executive_pdf"),
            report_technical_path=report_paths.get("technical_pdf"),
        )

        # 4. Final Progress Push (Post-Commit)
        from core.redis_client import publish_progress_sync

        # If there's another phase to run, trigger it asynchronously
        if not is_final and result.get("success") and result.get("data"):
            active_hosts = [h for h in result["data"] if h.get("is_active")]
            if active_hosts:
                log.info(
                    "[TRACE][TASK][%s] Chaining next phase (Asset Discovery) for scan_id=%s",
                    ts(),
                    scan_id,
                )

                # Fetch custom ports from the scan row if not explicitly passed
                resolved_custom_ports = custom_ports
                if not resolved_custom_ports and scan_row and scan_row.options:
                    resolved_custom_ports = scan_row.options.get("custom_ports")

                # Fetch exclude ports from the scan row if not explicitly passed
                resolved_exclude_ports = exclude_ports
                if not resolved_exclude_ports and scan_row and scan_row.options:
                    resolved_exclude_ports = scan_row.options.get("exclude_ports")

                # Dispatch Phase 2 (Asset Discovery) directly
                from core.tasks import run_asset_discovery_task

                next_task = run_asset_discovery_task.delay(
                    user_id=user_id,
                    hosts=active_hosts,
                    intensity=port_scan_intensity,  # Dedicated port scan intensity (separate from discovery intensity)
                    scan_id=scan_id,
                    pipeline_mode=pipeline_mode,
                    os_detection=os_detection,  # Forward os_detection from the original request
                    custom_ports=resolved_custom_ports,  # Forward custom_ports
                    exclude_ports=resolved_exclude_ports,  # Forward exclude_ports
                    passive_first=passive_first,
                    exclude_ot_from_nmap=exclude_ot_from_nmap,
                    exclude_ips=exclude_ips,
                )
                db.query(Scan).filter(Scan.id == scan_id).update(
                    {"current_task_id": next_task.id}
                )
                db.commit()

                # Publish progress to let UI know we are moving to next phase
                publish_progress_sync(
                    scan_id,
                    1,
                    {
                        "discovered": scan.active_hosts,
                        "total_ips": scan.total_hosts,
                        "status": "complete",
                    },
                )

                return {
                    "success": True,
                    "scan_id": scan_id,
                    "chained_task": next_task.id,
                }
            else:
                log.info(
                    "[TRACE][TASK][%s] No active hosts found, terminating pipeline early for scan_id=%s",
                    ts(),
                    scan_id,
                )

        # Ensure scan is marked complete if no next phase is chained
        if (
            is_final
            or not result.get("data")
            or not any(h.get("is_active") for h in result.get("data", []))
        ):
            log.info("[TRACE][TASK][%s] Scan %s pipeline complete", ts(), scan_id)
            from db.base import utcnow

            db.refresh(scan)
            if scan.status != "unreachable":
                db.query(Scan).filter(Scan.id == scan_id).update(
                    {"status": "complete", "completed_at": utcnow()}
                )
                db.commit()
                db.refresh(scan)
            else:
                log.info(
                    "[TRACE][TASK][%s] Scan %s remains 'unreachable' as expected",
                    ts(),
                    scan_id,
                )

            # FINAL PROGRESS PUSH: Use the actual scan status (could be complete or unreachable)
            publish_progress_sync(
                scan_id,
                1,
                {
                    "discovered": scan.active_hosts,
                    "total_ips": scan.total_hosts,
                    "status": scan.status,
                },
            )

            # Chain topology mapping if SNMP is configured (optional Phase 4)
            _chain_topology_if_needed(db, scan_id, user_id, scan_row=scan)

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
    user_id: str,
    hosts: list[dict],
    intensity: str,
    scan_id: str,
    pipeline_mode: str,
    os_detection: bool = True,
    custom_ports: str | None = None,
    exclude_ports: str | None = None,
    exclude_ot_from_nmap: bool | None = None,
    passive_first: bool | None = None,
    exclude_ips: str | None = None,
):
    """Phase 2 Background Task."""
    import datetime

    def ts():
        return datetime.datetime.now().isoformat()

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
            is_interactive = scan_row.options.get("execution_mode") == "interactive"

        is_final = (get_terminal_phase(mode) == 2) or is_interactive

        # Fetch options from scan_row if None
        resolved_exclude_ot = exclude_ot_from_nmap
        if resolved_exclude_ot is None:
            resolved_exclude_ot = True
            if scan_row and scan_row.options:
                resolved_exclude_ot = scan_row.options.get("exclude_ot_from_nmap", True)

        resolved_passive_first = passive_first
        if resolved_passive_first is None:
            resolved_passive_first = False
            if scan_row and scan_row.options:
                resolved_passive_first = scan_row.options.get("passive_first", False)

        resolved_exclude_ips = exclude_ips
        if resolved_exclude_ips is None:
            if scan_row and scan_row.options:
                resolved_exclude_ips = scan_row.options.get("exclude_ips")

        # Fetch custom ports from the scan row options if not explicitly passed as task parameter
        resolved_custom_ports = custom_ports
        if not resolved_custom_ports and scan_row and scan_row.options:
            resolved_custom_ports = scan_row.options.get("custom_ports")

        # Fetch exclude ports from the scan row options if not explicitly passed as task parameter
        resolved_exclude_ports = exclude_ports
        if not resolved_exclude_ports and scan_row and scan_row.options:
            resolved_exclude_ports = scan_row.options.get("exclude_ports")

        orch = _new_orchestrator()
        result = _run_async(
            orch.run_asset_discovery_only(
                hosts=hosts,
                intensity=intensity,
                pipeline_mode=mode,
                scan_id=scan_id,
                os_detection=os_detection,
                custom_ports=resolved_custom_ports,
                exclude_ports=resolved_exclude_ports,
                exclude_ot_from_nmap=resolved_exclude_ot,
                passive_first=resolved_passive_first,
                exclude_ips=resolved_exclude_ips,
            )
        )

        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled after asset discovery", scan_id)
            return {"success": False, "error": "Scan cancelled"}

        if not result.get("success"):
            mark_scan_failed(
                db, scan_id, user_id, result.get("error", "Asset Discovery failed")
            )
            return result

        context = resolve_report_context(db, user_id, scan_id=scan_id, hosts=hosts)
        result.setdefault("metadata", {}).update(context)

        # Apply Phase 1 hints manually for the summary
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan_row:
            p1_sum = phase1_summary_from_scan(scan_row)
            if p1_sum:
                for k in ("total_hosts", "active_hosts", "inactive_hosts"):
                    if p1_sum.get(k) is not None:
                        result["summary"][k] = p1_sum[k]

        report_paths = {}
        if is_final:
            raw_paths = orch.generate_phase_report(result, "asset_discovery")
            report_paths = {
                k: v for k, v in raw_paths.items() if v and os.path.isfile(v)
            }

        update_scan_phase(
            db=db,
            scan_id=scan_id,
            user_id=user_id,
            phase=2,
            phase_data={
                "data": result["data"],
                "summary": result["summary"],
                "metadata": result["metadata"],
            },
            is_final=is_final,
            pipeline_mode=mode,
            report_executive_path=report_paths.get("executive_pdf"),
            report_technical_path=report_paths.get("technical_pdf"),
        )

        # Final Progress Push
        from core.redis_client import publish_progress_sync

        # If there's another phase to run, trigger it asynchronously
        if not is_final and result.get("success") and result.get("data"):
            active_hosts = [h for h in result["data"] if h.get("is_active")]
            if active_hosts:
                log.info(
                    "[TRACE][TASK][%s] Chaining next phase (Vulnerability Audit) for scan_id=%s",
                    ts(),
                    scan_id,
                )
                # Dispatch Phase 3 (Vulnerability Audit) directly
                from core.tasks import run_vulnerability_audit_task

                next_task = run_vulnerability_audit_task.delay(
                    user_id=user_id,
                    hosts=active_hosts,
                    scan_id=scan_id,
                    pipeline_mode=pipeline_mode,
                    exclude_ot_from_nmap=resolved_exclude_ot,
                    exclude_ips=resolved_exclude_ips,
                )
                db.query(Scan).filter(Scan.id == scan_id).update(
                    {"current_task_id": next_task.id}
                )
                db.commit()

                publish_progress_sync(
                    scan_id,
                    2,
                    {
                        "scanned_hosts": result["summary"].get("total_hosts", 0),
                        "total_hosts": result["summary"].get("total_hosts", 0),
                        "status": "complete",
                    },
                )
                return {
                    "success": True,
                    "scan_id": scan_id,
                    "chained_task": next_task.id,
                }
            else:
                log.info(
                    "[TRACE][TASK][%s] No active hosts found, terminating pipeline early for scan_id=%s",
                    ts(),
                    scan_id,
                )

        publish_progress_sync(
            scan_id,
            2,
            {
                "scanned_hosts": result["summary"].get("total_hosts", 0),
                "total_hosts": result["summary"].get("total_hosts", 0),
                "status": "complete",
            },
        )

        # Ensure scan is marked complete if no next phase is chained
        if (
            is_final
            or not result.get("data")
            or not any(h.get("is_active") for h in result.get("data", []))
        ):
            log.info("[TRACE][TASK][%s] Scan %s pipeline complete", ts(), scan_id)
            db.refresh(scan_row)
            if scan_row.status != "unreachable":
                db.query(Scan).filter(Scan.id == scan_id).update(
                    {"status": "complete", "completed_at": utcnow()}
                )
                db.commit()
            else:
                log.info(
                    "[TRACE][TASK][%s] Scan %s remains 'unreachable' as expected",
                    ts(),
                    scan_id,
                )

            # Chain topology mapping if SNMP is configured (optional Phase 4)
            _chain_topology_if_needed(db, scan_id, user_id, scan_row=scan_row)

        return {"success": True, "scan_id": scan_id}
    except Exception as exc:
        log.exception("Asset Discovery Task Failed")
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


# ── Phase 3.5 — credentialed enrichment of the Vulnerability Audit ───────────
#
# Established scanners do not treat "credentialed" as a separate scan type.
# Credentials are a policy option on the ordinary scan: discovery, port
# scanning and unauthenticated checks run first, and where credentials are
# available the scanner also logs in and merges local checks into the same
# result set. That ordering is what makes the two views worth more than their
# sum — the port scan says what is reachable, the authenticated session says
# what is installed, and only together do they distinguish a vulnerable package
# that is exposed from one that is not.
#
# This runs inside the phase-3 task, before the report is generated, so there
# is one report, one asset sync and one set of counts rather than a second scan
# to reconcile afterwards.


def _credentialed_plan_for_scan(db, scan_row) -> list[dict]:
    """
    Credentials configured for this scan, decrypted and scoped.

    Contract, carried in ``scan.options`` alongside ``snmp``::

        "credentials": [
            {"credential_id": "...", "targets": ["10.0.0.0/24"]},
            {"credential_id": "..."}                 # applies to every host
        ]

    A malformed or inaccessible entry is skipped with a warning rather than
    failing the scan: the unauthenticated results are still valid and worth
    delivering, and the coverage block records that the credentialed pass did
    not cover every host.
    """
    import ipaddress

    if not scan_row or not scan_row.options:
        return []
    raw = scan_row.options.get("credentials") or []
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []

    plan: list[dict] = []
    for entry in raw:
        if isinstance(entry, str):
            entry = {"credential_id": entry}
        if not isinstance(entry, dict):
            continue
        credential_id = entry.get("credential_id")
        if not credential_id:
            continue
        try:
            material = _resolve_stored_credential(db, str(scan_row.id), credential_id)
        except Exception as exc:  # noqa: BLE001 — one bad credential is not fatal
            log.warning(
                "Credentialed enrichment: credential %s unusable for scan %s: %s",
                credential_id,
                scan_row.id,
                exc,
            )
            continue

        networks = []
        for token in entry.get("targets") or []:
            try:
                networks.append(ipaddress.ip_network(str(token).strip(), strict=False))
            except ValueError:
                log.warning(
                    "Credentialed enrichment: ignoring unparseable scope '%s'", token
                )
        plan.append({"material": material, "networks": networks or None})
    return plan


def _restate_findings_for_corrected_ports(
    findings: list[dict], corrected: dict[tuple[int, str], str]
) -> int:
    """
    Point findings at the corrected version for the port they were raised on.

    A finding records the version that was detected when the plugin raised it,
    and verification reads that recorded value before it looks at the host's
    service inventory. So correcting the inventory alone changes nothing: the
    finding still carries "9.6.0 or later" and is still judged against it.

    This is what makes the authenticated correction take effect. It restates
    what was detected, on the ports where a better reading exists; it does not
    touch the finding's severity, its CPE data, or anything the feed published.
    """
    restated = 0
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        try:
            port = int(str(finding.get("port")).strip())
        except (TypeError, ValueError):
            continue
        version = corrected.get((port, str(finding.get("protocol") or "tcp").lower()))
        if not version:
            continue
        if str(finding.get("detected_version") or "").strip() == version:
            continue
        finding["detected_version"] = version
        restated += 1
    return restated


def _upgrade_network_fingerprints(
    network_ports: list[dict], listeners: list[dict]
) -> dict[tuple[int, str], str]:
    """
    Replace remote version guesses with what the host itself reports.

    A remote fingerprint is an inference from what a service volunteers. Nmap
    reads PostgreSQL's protocol handshake and can only conclude "9.6.0 or
    later" — an open-ended bound, which by design cannot disprove any CVE fixed
    after 9.6. The authenticated session reads the binary's own version
    resource and knows it is 18.3.

    Leaving the weaker value in place is not a reporting cosmetic; it is the
    difference between 42 PostgreSQL CVEs reported against a host that is not
    affected by any of them, and none. Enterprise scanners resolve this the
    same way: where an authenticated reading exists, it supersedes the remote
    guess, and every later stage — verification, risk scoring, the report —
    then works from the better value.

    Upgrades in place and returns ``{(port, protocol): version}`` for what was
    corrected. Deliberately conservative: only an exact host-side version, and
    only where the two observations agree on what the product is.
    """
    from scans.finding_normalizer import _name_tokens, version_precision

    by_key: dict[tuple[int, str], dict] = {}
    for listener in listeners or []:
        try:
            port = int(str(listener.get("port")).strip())
        except (TypeError, ValueError):
            continue
        proto = str(listener.get("protocol") or "tcp").lower()
        # First listener on a port wins; duplicates are the same process bound
        # to several addresses.
        by_key.setdefault((port, proto), listener)

    upgraded: dict[tuple[int, str], str] = {}
    for record in network_ports or []:
        if not isinstance(record, dict):
            continue
        try:
            port = int(str(record.get("port")).strip())
        except (TypeError, ValueError):
            continue
        proto = str(record.get("protocol") or "tcp").lower()
        listener = by_key.get((port, proto))
        if not listener:
            continue

        host_version = str(listener.get("version") or "").strip()
        if not host_version or version_precision(host_version) != "exact":
            continue

        # Agreement on the product. A middlebox or forwarded port can put
        # something else entirely behind the port the scanner reached, and
        # stamping the local binary's version onto it would be worse than the
        # imprecise fingerprint it replaced.
        net_tokens = set(_name_tokens(record.get("product") or ""))
        host_tokens = set(_name_tokens(listener.get("product") or ""))
        if net_tokens and host_tokens and not (net_tokens & host_tokens):
            continue

        net_version = str(record.get("version") or "").strip()
        if net_version and version_precision(net_version) == "exact":
            continue  # the scan already has a precise value; leave it alone

        record["version"] = host_version[:200]
        record["version_precision"] = "exact"
        record["fingerprint_source"] = "credentialed"
        if not record.get("product") and listener.get("product"):
            record["product"] = str(listener["product"])[:255]
        upgraded[(port, proto)] = host_version[:200]

    return upgraded


def _ports_probed_in_phase2(scan_row) -> list[int] | None:
    """
    The exact port set the asset discovery phase probed, if it recorded one.

    Returns ``None`` when the scan predates the engine publishing this, or when
    the spec cannot be parsed. That is the honest answer, and it makes the
    correlation fall back to "not determined" rather than reporting every
    unprobed listener as firewalled.
    """
    if not scan_row:
        return None
    try:
        from core.utils import InputValidator

        summary = phase_summary_from_scan(scan_row, "asset_discovery", "phase2") or {}
        spec = summary.get("ports_probed_spec")
        if not spec:
            return None
        return InputValidator.parse_custom_ports(str(spec))
    except Exception as exc:  # noqa: BLE001 — absence is a valid answer here
        log.debug("Could not read the phase-2 probed port set: %s", exc)
        return None


def _credential_for_host(plan: list[dict], ip: str) -> dict | None:
    """The first configured credential whose scope covers this host."""
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        addr = None

    for entry in plan:
        networks = entry["networks"]
        if not networks:
            return entry["material"]
        if addr is not None and any(addr in net for net in networks):
            return entry["material"]
    return None


def _as_credentialed_findings(cve_list: list[dict], packages: list[dict]) -> list[dict]:
    """
    Prepare package findings to be merged into a network-scanned host record.

    Two fields have to be stamped on explicitly. ``detection_method`` because
    verification asserts credentialed origin from the record and never infers
    it — an unmarked package finding arriving on a host that also has
    fingerprinted services is treated as a network claim about a product the
    host does not appear to run, and suppressed. ``installed_version`` because
    the matcher emits ``installed_ver``, which is not one of the keys the
    version check reads; without it every finding degrades to "package
    present" and loses the version evidence the audit actually collected.
    """
    versions = {
        str(p.get("name") or "").strip(): str(p.get("version") or "").strip()
        for p in packages or []
        if isinstance(p, dict) and p.get("name")
    }

    prepared: list[dict] = []
    for raw in cve_list or []:
        if not isinstance(raw, dict):
            continue
        record = dict(raw)
        record.setdefault("detection_method", "credentialed")
        if not record.get("installed_version"):
            installed = record.get("installed_ver") or versions.get(
                str(record.get("package") or "").strip(), ""
            )
            if installed:
                record["installed_version"] = installed
        prepared.append(record)
    return prepared


def _apply_credentialed_enrichment(
    db, scan_row, hosts: list[dict], scan_id: str | None = None
) -> dict | None:
    """
    Authenticate to every in-scope host and merge what the OS reports.

    Mutates ``hosts`` in place and returns a coverage summary, or ``None`` when
    no credentials were configured — in which case the scan is an ordinary
    unauthenticated audit and nothing here should alter it.
    """
    from core.redis_client import publish_progress_sync
    from core.risk import calculate_risk
    from scans.finding_normalizer import verify_host_findings

    plan = _credentialed_plan_for_scan(db, scan_row)
    if not plan:
        return None

    scanned_ports = _ports_probed_in_phase2(scan_row)
    active = [h for h in hosts if h.get("is_active")]
    audited: list[str] = []
    skipped: list[dict] = []
    upgraded_total = 0

    for index, host in enumerate(active):
        ip = host.get("ip_address") or host.get("ip")
        if not ip:
            continue

        material = _credential_for_host(plan, ip)
        if not material:
            skipped.append({"target": ip, "reason": "No credential in scope"})
            continue

        port = int(material.get("port") or 22)
        open_ports = host.get("open_ports") or []
        open_numbers = {
            p.get("port") for p in open_ports if isinstance(p, dict) and p.get("port")
        }
        # The port scan has already established what is reachable. Attempting a
        # 20-second SSH handshake against a port it found closed would add
        # minutes to a large scan to learn what is already known.
        if open_numbers and port not in open_numbers:
            skipped.append(
                {
                    "target": ip,
                    "reason": f"Port {port}/tcp not open — no authenticated session attempted",
                }
            )
            continue

        if scan_id:
            publish_progress_sync(
                scan_id,
                3,
                {
                    "status": "running",
                    "stage": "credentialed",
                    "message": f"Authenticated checks on {ip} ({index + 1}/{len(active)})",
                    "target": ip,
                },
            )

        try:
            stored_report, system_data, _os_type = audit_credentialed_host(
                ip=ip,
                username=material.get("username"),
                password=material.get("password"),
                key_content=material.get("key_content"),
                port=port,
                os_type_req="auto",
                network_ports=open_ports,
                network_scanned=True,
                scanned_ports=scanned_ports,
            )
        except Exception as exc:  # noqa: BLE001 — recorded, scan continues
            log.warning("Credentialed enrichment failed for %s: %s", ip, exc)
            skipped.append({"target": ip, "reason": str(exc)})
            continue

        # Resolve each listening process to its installed package here, while
        # the inventory is in hand. Doing it now means the stored host record
        # does not have to carry a few thousand package rows per host purely so
        # the asset sync can repeat the lookup later.
        from scans.asset_syncer import _service_identity_from_process

        packages = stored_report.get("packages") or []
        listeners = []
        for entry in stored_report.get("open_ports_credentialed") or []:
            record = dict(entry)
            # A product the collector read from the binary's own version
            # resource describes the exact file serving the port. A package
            # match is an inference from a process name. Never let the second
            # overwrite the first.
            if not record.get("product"):
                product, version = _service_identity_from_process(
                    record.get("process") or "", packages
                )
                if product:
                    record["product"] = product
                if version and not record.get("version"):
                    record["version"] = version
            listeners.append(record)

        host["credentialed"] = True
        # The audit's own findings are already merged into this host's `cves`,
        # and its packages into the listener records above. What is kept here is
        # what nothing else carries: the host's configuration posture and this
        # pass's own coverage.
        host["credentialed_report"] = {
            key: stored_report.get(key)
            for key in (
                "target",
                "detected_os",
                "system_info",
                "hardening_audits",
                "security_issues",
                "package_count",
                "collection_errors",
                "inventory_complete",
                "coverage",
                "exposure_summary",
            )
        }
        host["exposure_summary"] = stored_report.get("exposure_summary") or {}
        # The reverse correlation: ports the scan reached that the host also
        # confirms it is serving.
        host["open_ports"] = mark_credentialed_confirmed(open_ports, listeners)
        host["open_ports_credentialed"] = listeners

        # Authenticated readings supersede remote guesses before anything is
        # verified against them. Done here rather than at report time so the
        # stored scan, the asset's service rows, the risk score and the report
        # all agree on one version.
        corrected = _upgrade_network_fingerprints(host["open_ports"], listeners)
        if corrected:
            # The findings already raised on those ports recorded the old
            # version, and verification reads that record first — so without
            # this the correction would change the inventory and nothing else.
            restated = _restate_findings_for_corrected_ports(
                host.get("cves") or [], corrected
            )
            log.info(
                "Credentialed enrichment corrected %d fingerprint(s) and restated "
                "%d finding(s) on %s",
                len(corrected),
                restated,
                ip,
            )
        upgraded_total += len(corrected)

        # An OS read from inside the machine outranks a stack fingerprint, and
        # feeds straight back into platform-conflict checks during the
        # re-verification below.
        os_name = (stored_report.get("system_info") or {}).get("os_name")
        if os_name:
            host["os_guess"] = os_name
            host["os_confidence"] = "High"

        new_findings = _as_credentialed_findings(
            stored_report.get("cves") or [], stored_report.get("packages") or []
        )
        prior_suppressed = list(host.get("suppressed_cves") or [])
        prior_evaluated = int(host.get("candidates_evaluated") or 0)

        host["cves"] = list(host.get("cves") or []) + new_findings

        verification = verify_host_findings(host)
        fields = verification.as_host_fields()
        # Candidates phase 3 already ruled out are no longer among the host's
        # findings, so re-verification cannot rediscover them. Carrying their
        # records forward keeps the methodology appendix able to account for
        # every candidate the scan evaluated.
        seen = {
            (item.get("identifier"), item.get("host"))
            for item in fields["suppressed_cves"]
        }
        fields["suppressed_cves"] = fields["suppressed_cves"] + [
            item
            for item in prior_suppressed
            if (item.get("identifier"), item.get("host")) not in seen
        ]
        fields["candidates_evaluated"] = prior_evaluated + len(new_findings)
        host.update(fields)

        score, level = calculate_risk(
            open_ports=host.get("open_ports", []),
            cves=host.get("cves", []),
            http_audit=host.get("http_audit", {}),
            tls_info=host.get("tls_info", {}),
            severity_counts=host.get("vulnerability_counts"),
        )
        host["host_risk_score"] = score
        host["host_risk_level"] = level

        audited.append(ip)

    log.info(
        "Credentialed enrichment: %d/%d active host(s) audited, %d skipped",
        len(audited),
        len(active),
        len(skipped),
    )
    return {
        "credentialed_hosts": len(audited),
        "credentialed_targets": audited,
        "credentialed_skipped": skipped,
        "fingerprints_corrected": upgraded_total,
        **credentialed_coverage(network_scanned=True),
    }


@celery_app.task(name="ccure.tasks.run_vulnerability_audit", queue="scanner", bind=True)
def run_vulnerability_audit_task(
    self,
    user_id: str,
    hosts: list[dict],
    scan_id: str,
    pipeline_mode: str,
    exclude_ot_from_nmap: bool | None = None,
    exclude_ips: str | None = None,
):
    """Phase 3 Background Task."""
    db = SessionLocal()
    try:
        _update_task_id(db, scan_id, self.request.id)
        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled before vulnerability audit", scan_id)
            return {"success": False, "error": "Scan cancelled"}

        mode = resolve_pipeline_mode(pipeline_mode)
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()

        resolved_exclude_ot = exclude_ot_from_nmap
        if resolved_exclude_ot is None:
            resolved_exclude_ot = True
            if scan_row and scan_row.options:
                resolved_exclude_ot = scan_row.options.get("exclude_ot_from_nmap", True)

        resolved_exclude_ips = exclude_ips
        if resolved_exclude_ips is None:
            if scan_row and scan_row.options:
                resolved_exclude_ips = scan_row.options.get("exclude_ips")

        orch = _new_orchestrator()
        result = orch.run_vulnerability_audit_only(
            hosts=hosts,
            scan_id=scan_id,
            exclude_ot_from_nmap=resolved_exclude_ot,
            exclude_ips=resolved_exclude_ips,
        )

        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled after vulnerability audit", scan_id)
            return {"success": False, "error": "Scan cancelled"}

        if not result.get("success"):
            mark_scan_failed(
                db, scan_id, user_id, result.get("error", "Vulnerability Audit failed")
            )
            return result

        result["data"] = _merge_host_identity(result.get("data", []), hosts)

        # Phase 3.5 — authenticated checks, merged into these same results
        # before anything reads them. Runs only when credentials were supplied.
        credentialed_summary = _apply_credentialed_enrichment(
            db, scan_row, result["data"], scan_id=scan_id
        )
        if credentialed_summary:
            result["summary"].update(credentialed_summary)
            result.setdefault("metadata", {}).update(
                {**credentialed_summary, "is_credentialed": True}
            )
            # Re-derive the risk tallies: the enrichment can promote a host's
            # level, and these are what the dashboard and the executive summary
            # read.
            result["summary"]["critical_hosts"] = sum(
                1 for h in result["data"] if h.get("host_risk_level") == "Critical"
            )
            result["summary"]["high_risk_hosts"] = sum(
                1 for h in result["data"] if h.get("host_risk_level") == "High"
            )
            result["summary"]["candidates_evaluated"] = sum(
                int(h.get("candidates_evaluated") or 0) for h in result["data"]
            )
            result["summary"]["candidates_suppressed"] = sum(
                len(h.get("suppressed_cves") or []) for h in result["data"]
            )

        context = resolve_report_context(db, user_id, scan_id=scan_id, hosts=hosts)
        result.setdefault("metadata", {}).update(context)

        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan_row:
            p1_sum = phase1_summary_from_scan(scan_row)
            if p1_sum:
                for k in ("total_hosts", "active_hosts", "inactive_hosts"):
                    if p1_sum.get(k) is not None:
                        result["summary"][k] = p1_sum[k]

            # A vulnerability assessment does not choose ports; it assesses what
            # the asset discovery phase found. Its report still has to state
            # which ports were examined, so that phase's coverage travels
            # forward with the scan record.
            carry_scan_coverage(
                result, phase_summary_from_scan(scan_row, "asset_discovery", "phase2")
            )

        raw_paths = orch.generate_phase_report(result, "phase_selective_scan")
        report_paths = {k: v for k, v in raw_paths.items() if v and os.path.isfile(v)}

        update_scan_phase(
            db=db,
            scan_id=scan_id,
            user_id=user_id,
            phase=3,
            phase_data={
                "data": result["data"],
                "summary": result["summary"],
                "metadata": result["metadata"],
            },
            is_final=True,
            pipeline_mode=mode,
            report_executive_path=report_paths.get("executive_pdf"),
            report_technical_path=report_paths.get("technical_pdf"),
        )

        # Final Progress Push
        from core.redis_client import publish_progress_sync

        publish_progress_sync(
            scan_id,
            3,
            {
                "scanned_hosts": result["summary"].get("total_hosts", 0),
                "total_hosts": result["summary"].get("total_hosts", 0),
                "status": "complete",
            },
        )

        # Chain topology mapping if SNMP is configured (optional Phase 4)
        _chain_topology_if_needed(db, scan_id, user_id, scan_row=scan_row)

        return {"success": True, "scan_id": scan_id}
    except Exception as exc:
        log.exception("Vulnerability Audit Task Failed")
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


def _should_chain_topology(scan_row) -> bool:
    """
    Check if topology mapping should be chained after the current phase.
    Returns True only if SNMP credentials are configured in scan.options.
    """
    if not scan_row or not scan_row.options:
        return False
    snmp_config = scan_row.options.get("snmp")
    if not snmp_config:
        return False
    # Require at least a community string (v1/v2c) or username (v3)
    version = str(snmp_config.get("version") or "").lower()
    if version in ("v1", "v2c"):
        return bool(snmp_config.get("community"))
    elif version == "v3":
        return bool(snmp_config.get("username"))
    # If version is unspecified but community exists, assume v2c
    return bool(snmp_config.get("community"))


def _chain_topology_if_needed(
    db, scan_id: str, user_id: str, scan_row=None
) -> str | None:
    """
    If SNMP is configured, dispatch the topology mapping task.
    Returns the chained task ID or None if topology was not triggered.
    """
    if scan_row is None:
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()

    if not _should_chain_topology(scan_row):
        return None

    log.info("Chaining topology mapping for scan_id=%s (SNMP configured)", scan_id)

    next_task = run_topology_mapping_task.delay(
        scan_id=scan_id,
        user_id=user_id,
    )
    db.query(Scan).filter(Scan.id == scan_id).update({"current_task_id": next_task.id})
    db.commit()

    return next_task.id


@celery_app.task(name="ccure.tasks.run_topology_mapping", queue="scanner", bind=True)
def run_topology_mapping_task(
    self,
    scan_id: str,
    user_id: str,
):
    """
    Phase 4 Background Task — Network Topology Mapping.

    Runs SNMP walks against discovered hosts, correlates ARP/LLDP/CDP/FDB
    results into NetworkLink records, and persists them to the database.

    This task is ONLY chained when SNMP credentials are configured.
    It does NOT affect the scan's completion status — the scan is already
    marked 'complete' by the terminal core phase.
    """
    db = SessionLocal()
    try:
        _update_task_id(db, scan_id, self.request.id)
        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled before topology mapping", scan_id)
            return {"success": False, "error": "Scan cancelled"}

        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan_row:
            log.error("Scan %s not found for topology mapping", scan_id)
            return {"success": False, "error": "Scan not found"}

        snmp_config = (scan_row.options or {}).get("snmp", {})
        if not snmp_config:
            log.warning(
                "Topology mapping triggered but no SNMP config on scan %s", scan_id
            )
            return {"success": True, "skipped": True, "reason": "No SNMP configuration"}

        # Determine org_id
        user = db.query(User).filter(User.id == user_id).first()
        org_id = str(scan_row.org_id or (user.org_id if user else ""))

        # Determine target IPs from discovered active hosts
        target_ips = []
        from db.models import ScanPhase

        # Get the most recent phase data to extract discovered IPs
        for phase_key in (
            "vulnerability_assessment",
            "asset_discovery",
            "host_discovery",
        ):
            phase = (
                db.query(ScanPhase)
                .filter(ScanPhase.scan_id == scan_id, ScanPhase.phase_key == phase_key)
                .first()
            )
            if phase and phase.summary:
                hosts = phase.summary.get("hosts_data", [])
                for host in hosts:
                    ip = host.get("ip_address") or host.get("ip")
                    if ip and host.get("is_active"):
                        target_ips.append(ip)
                if target_ips:
                    break

        # Fallback to scan target_hosts
        if not target_ips and scan_row.target_hosts:
            target_ips = scan_row.target_hosts

        if not target_ips:
            log.warning("No target IPs for topology mapping on scan %s", scan_id)
            return {"success": True, "skipped": True, "reason": "No target IPs"}

        # Emit progress
        from core.redis_client import publish_progress_sync

        publish_progress_sync(
            scan_id,
            4,
            {
                "status": "running",
                "message": f"Walking {len(target_ips)} targets via SNMP...",
                "percentage": 10,
                "total_targets": len(target_ips),
            },
        )

        # Run the topology engine
        from core.topology.engine import run_topology_mapping

        result = run_topology_mapping(
            db=db,
            scan_id=scan_id,
            org_id=org_id,
            snmp_config=snmp_config,
            target_ips=target_ips,
        )

        # Update scan phase record
        from scans.db_helpers import update_scan_phase

        update_scan_phase(
            db=db,
            scan_id=scan_id,
            user_id=user_id,
            phase=4,
            phase_data={
                "data": [],
                "summary": {
                    "total_links": result.get("total_links", 0),
                    "links_created": result.get("links_created", 0),
                    "links_updated": result.get("links_updated", 0),
                    "targets_walked": result.get("targets_walked", 0),
                    "targets_offered": len(target_ips),
                    "assets_enrolled": result.get("assets_enrolled", 0),
                    "errors": result.get("errors", []),
                },
                "metadata": {"phase": "topology_mapping"},
            },
            is_final=False,  # Phase 4 never marks the scan complete
            pipeline_mode=scan_row.pipeline_mode,
        )

        # Final progress push
        publish_progress_sync(
            scan_id,
            4,
            {
                "status": "complete",
                "message": f"Topology mapping complete: {result.get('total_links', 0)} links discovered",
                "percentage": 100,
                "total_links": result.get("total_links", 0),
            },
        )

        log.info(
            "Topology mapping complete for scan=%s: %d links",
            scan_id,
            result.get("total_links", 0),
        )
        return {"success": True, "scan_id": scan_id, **result}

    except Exception as exc:
        log.exception("Topology Mapping Task Failed for scan %s", scan_id)
        # Topology failure should NOT fail the scan — it's an optional add-on
        from core.redis_client import publish_progress_sync

        publish_progress_sync(
            scan_id,
            4,
            {
                "status": "failed",
                "message": f"Topology mapping failed: {exc}",
                "percentage": 0,
            },
        )
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.run_traditional_scan", queue="scanner")
def run_traditional_scan_task(
    user_id: str,
    targets: list[str],
    phases: str,
    scan_type: str,
    intensity: str,
    passive_first: bool | None = None,
    exclude_ot_from_nmap: bool | None = None,
    exclude_ips: str | None = None,
):
    """Traditional Scan Task."""
    db = SessionLocal()
    try:
        orch = _new_orchestrator()
        resolved_passive_first = False if passive_first is None else passive_first
        resolved_exclude_ot = (
            True if exclude_ot_from_nmap is None else exclude_ot_from_nmap
        )
        result = _run_async(
            orch.run_phases(
                targets=targets,
                phases=phases,
                scan_type=scan_type,
                intensity=intensity,
                passive_first=resolved_passive_first,
                exclude_ot_from_nmap=resolved_exclude_ot,
                exclude_ips=exclude_ips,
            )
        )
        return result
    finally:
        db.close()


#: A credentialed audit authenticates to one host at a time. Expanding a CIDR
#: is cheap; logging into every address in it is not, so an operator who pastes
#: a /16 by mistake gets an error rather than a scan that runs for days.
MAX_CREDENTIALED_TARGETS = 256


def _credentialed_hardening_audits(system_data: dict, os_type: str) -> dict:
    """Host hardening posture, derived from what the authenticated session read."""
    issues = system_data.get("security_issues") or []
    fw_disabled = any(
        "Firewall profile" in issue and "is DISABLED" in issue for issue in issues
    )

    rdp_enabled = system_data.get("rdp_enabled")
    if rdp_enabled is None:
        rdp_enabled = any("RDP is enabled" in issue for issue in issues)

    if os_type != "windows":
        running_svcs = system_data.get("running_services") or []
        fw_active = any(
            svc.get("name") in ("ufw", "firewalld", "iptables") for svc in running_svcs
        )
    else:
        fw_active = not fw_disabled

    smbv1_disabled = system_data.get("smbv1_disabled", False)
    netbios_disabled = system_data.get("netbios_disabled", False)
    legacy_tls_disabled = system_data.get("legacy_tls_disabled", False)
    telnet_disabled = system_data.get("telnet_disabled", False)
    rdp_nla_enforced = system_data.get("rdp_nla_enforced", False)

    hardening_audits = {
        "firewall": {
            "label": "Firewall Status",
            "disabled": not fw_active,
            "status": "PASS" if fw_active else "FAIL",
            "detail": (
                "Firewall is active."
                if fw_active
                else "Host firewall is disabled or ufw/iptables service is inactive."
            ),
        },
        "smbv1": {
            "label": "SMBv1 Status",
            "disabled": smbv1_disabled,
            "status": "PASS" if smbv1_disabled else "FAIL",
            "detail": (
                "Legacy SMBv1 protocol is disabled."
                if smbv1_disabled
                else "Legacy SMBv1 protocol is enabled/allowed."
            ),
        },
        "netbios": {
            "label": "NetBIOS Status",
            "disabled": netbios_disabled,
            "status": "PASS" if netbios_disabled else "FAIL",
            "detail": (
                "NetBIOS over TCP/IP is disabled."
                if netbios_disabled
                else "NetBIOS over TCP/IP is active on one or more network adapters."
            ),
        },
        "legacy_tls": {
            "label": "Legacy TLS Status",
            "disabled": legacy_tls_disabled,
            "status": "PASS" if legacy_tls_disabled else "FAIL",
            "detail": (
                "Legacy SChannel/OpenSSL protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) are disabled."
                if legacy_tls_disabled
                else "One or more legacy security protocols (SSL/TLS 1.0/1.1) are enabled."
            ),
        },
        "telnet": {
            "label": "Telnet Status",
            "disabled": telnet_disabled,
            "status": "PASS" if telnet_disabled else "FAIL",
            "detail": (
                "Telnet service is disabled."
                if telnet_disabled
                else "Telnet service/daemon is running or client package is installed."
            ),
        },
    }

    if os_type == "windows":
        hardening_audits.update(
            {
                "rdp": {
                    "label": "RDP Service Status",
                    "disabled": not rdp_enabled,
                    "status": "PASS" if not rdp_enabled else "WARN",
                    "detail": (
                        "Remote Desktop is disabled."
                        if not rdp_enabled
                        else "Remote Desktop is enabled (requires secure NLA and restricted access)."
                    ),
                },
                "rdp_nla": {
                    "label": "RDP NLA Enforcement",
                    "disabled": rdp_nla_enforced,
                    "status": (
                        "PASS"
                        if rdp_nla_enforced
                        else ("FAIL" if rdp_enabled else "PASS")
                    ),
                    "detail": (
                        "Network Level Authentication (NLA) is enforced for RDP."
                        if rdp_nla_enforced
                        else "RDP is enabled but Network Level Authentication (NLA) is not enforced."
                    ),
                },
            }
        )

    return hardening_audits


def _resolve_stored_credential(
    db,
    scan_id: str | None,
    credential_id: str,
) -> dict:
    """
    Decrypt a saved credential for use, scoped to the scan's own tenant.

    Returns the connection material; the caller is responsible for discarding
    it. Cross-referencing the Scan row's org_id is what keeps one tenant from
    naming another tenant's credential id.
    """
    from core.security_crypto import decrypt_credential
    from db.models import ComplianceCredential
    from db.models.scans import Scan

    scan_row = db.query(Scan).filter(Scan.id == scan_id).first() if scan_id else None
    scan_org_id = scan_row.org_id if scan_row else None

    query = db.query(ComplianceCredential).filter(
        ComplianceCredential.id == credential_id
    )
    if scan_org_id:
        query = query.filter(ComplianceCredential.tenant_id == scan_org_id)

    cred = query.first()
    if not cred:
        raise ValueError(
            f"Stored credential with ID {credential_id} not found or access denied."
        )

    material = {
        "username": cred.username,
        "port": cred.port,
        "auth_method": cred.auth_method,
        "password": None,
        "key_content": None,
    }
    if cred.auth_method == "password" and cred.encrypted_password:
        material["password"] = decrypt_credential(cred.encrypted_password)
    elif cred.auth_method == "key" and cred.encrypted_key_content:
        material["key_content"] = decrypt_credential(cred.encrypted_key_content)
    return material


def audit_credentialed_host(
    *,
    ip: str,
    username: str | None,
    password: str | None = None,
    key_path: str | None = None,
    key_content: str | None = None,
    port: int = 22,
    sections: list[str] | None = None,
    os_type_req: str = "auto",
    emit=None,
    network_ports: list | None = None,
    network_scanned: bool = False,
    scanned_ports: list | None = None,
    timeout: int = 20,
) -> tuple[dict, dict, str]:
    """
    Run the authenticated audit against one host.

    Returns ``(stored_report, system_data, os_type)``. Raises on connection or
    authentication failure — the caller decides whether one unreachable host
    fails the whole scan.

    ``network_ports`` is the port scan's view of this host, when there is one.
    Supplying it turns the host's socket table from a list of things that are
    running into a statement about what is actually exposed, which is the
    finding an authenticated scan exists to produce and which neither view can
    reach alone. Without it, only loopback binds can be settled.
    """
    from engines.credentialed.linux_collector import LinuxCollector
    from engines.credentialed.ssh_scanner import SSHScanner
    from engines.credentialed.vuln_matcher import VulnMatcher
    from engines.credentialed.windows_collector import WindowsCollector
    from routers.credentialed import _detect_os
    from scans.finding_normalizer import verify_credentialed_report

    def _emit(message, percentage=0, stage=None):
        if emit:
            emit("running", message, percentage, stage)

    host_started = time.time()

    _emit(f"Connecting to {ip}:{port}...", 10, "connecting")
    connect_started = time.perf_counter()
    with SSHScanner(
        ip=ip,
        username=username,
        password=password,
        key_path=key_path,
        key_content=key_content,
        port=port,
        timeout=timeout,
    ) as ssh:
        credentialed_response_time_ms = int(
            round((time.perf_counter() - connect_started) * 1000)
        )
        _emit("Detecting Operating System...", 20, "detection")
        os_type = os_type_req if os_type_req != "auto" else _detect_os(ssh)

        _emit(f"Collecting system data ({os_type})...", 30, "collection")
        collector = (
            WindowsCollector(ssh) if os_type == "windows" else LinuxCollector(ssh)
        )

        def on_section(name):
            friendly = {
                "system_info": "System Profile",
                "packages": "Software Inventory",
                "services": "Running Services",
                "ports": "Network Sockets",
                "users": "User Accounts",
                "security": "Security Policies",
                "network": "Interface Config",
                "history": "Login Events",
            }.get(name, name)
            _emit(f"Collected {friendly}", 50, "collection")

        system_data = collector.collect_all(
            sections=_credentialed_sections_with_identity(sections),
            on_section_complete=on_section,
        )
        system_data["detected_os"] = os_type
        system_data["credentialed_response_time_ms"] = credentialed_response_time_ms

    _emit("Analyzing packages for vulnerabilities...", 70, "analysis")
    packages = system_data.get("packages", [])
    matcher = VulnMatcher()
    raw_findings = matcher.match_packages(packages)
    cve_list = matcher.to_report_format(raw_findings)

    # A credentialed audit that could not read the software inventory has
    # not assessed the host — it has produced an empty result that looks
    # identical to a clean one. Say so, as a finding, rather than letting
    # "0 vulnerabilities" stand as the conclusion. Tagged as an active
    # check so verification treats it as the observation it is.
    collection_errors = system_data.get("collection_errors") or {}
    if not packages:
        reason = collection_errors.get("packages")
        detail = (
            f"Collection failed: {reason}"
            if reason
            else (
                "No package manager output was returned. The account may "
                "lack the rights to enumerate installed software, or the "
                "platform's inventory command is unavailable."
            )
        )
        cve_list.append(
            {
                "cve_id": "MISC-CREDENTIALED-INVENTORY-UNAVAILABLE",
                "detection_method": "active_check",
                "severity": "Medium",
                "title": "Credentialed audit incomplete — software inventory unavailable",
                "description": (
                    f"The credentialed session to {ip} succeeded, but the "
                    f"installed software inventory could not be collected, so "
                    f"no package was assessed against the vulnerability feed. "
                    f"This host is unassessed, not clean. {detail}"
                ),
                "package": "",
            }
        )
    if collection_errors:
        log.warning(
            "Credentialed audit of %s completed with %d incomplete section(s): %s",
            ip,
            len(collection_errors),
            ", ".join(sorted(collection_errors)),
        )

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for cve in cve_list:
        sev = cve.get("severity", "Info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    scan_duration = round(time.time() - host_started, 2)

    _emit("Generating report and syncing assets...", 90, "syncing")

    from core.oui_lookup import lookup_vendor

    hostname, fqdn, raw_hostname_fqdn = _extract_credentialed_identity_names(
        system_data
    )
    mac_address = _normalize_mac(system_data.get("mac_address"))
    mac_vendor = _clean_text(
        system_data.get("mac_vendor")
        or (lookup_vendor(mac_address) if mac_address else "")
    )
    hardening_audits = _credentialed_hardening_audits(system_data, os_type)

    # ── Exposure correlation ──────────────────────────────────────────────
    # The socket table says what is running; the port scan says what answered.
    # Joining them here — once, at the point both are in hand — is what lets
    # every consumer downstream distinguish an exposed service from one that
    # merely exists.
    listeners, exposure_summary = correlate_listeners(
        system_data.get("open_ports_credentialed") or [],
        network_ports=network_ports,
        network_scanned=network_scanned,
        scanned_ports=scanned_ports,
    )
    system_data["open_ports_credentialed"] = listeners

    stored_report = {
        "scan_type": "credentialed",
        "target": ip,
        "username": username,
        "detected_os": os_type,
        "os_type_was_auto": (os_type_req == "auto"),
        "system_info": {
            "os_name": system_data.get("os_name", ""),
            "os_family": system_data.get("os_family", ""),
            "os_version_id": system_data.get("os_version_id", ""),
            "os_confidence": system_data.get("os_confidence", ""),
            "os_build": system_data.get("os_build", ""),
            "kernel_version": system_data.get("kernel_version", ""),
            "hostname": hostname,
            "hostname_short": system_data.get("hostname_short", ""),
            "hostname_fqdn_raw": raw_hostname_fqdn,
            "fqdn": fqdn,
            "domain": system_data.get("domain", ""),
            "manufacturer": system_data.get("manufacturer", ""),
            "hardware_model": system_data.get("hardware_model", ""),
            "mac_address": mac_address,
            "mac_vendor": mac_vendor,
            "cpu_model": system_data.get("cpu_model", ""),
            "cpu_count": system_data.get("cpu_count", ""),
            "cpu_arch": system_data.get("cpu_arch", ""),
            "uptime": system_data.get("uptime", ""),
            "memory_summary": system_data.get("memory_summary", {}),
            "disk_usage": system_data.get("disk_usage", []),
            "subnet": system_data.get("subnet", ""),
            "credentialed_response_time_ms": system_data.get(
                "credentialed_response_time_ms", ""
            ),
            "serial_number": system_data.get("serial_number", ""),
            "bios_version": system_data.get("bios_version", ""),
        },
        "packages": packages,
        "package_count": len(packages),
        "running_services": system_data.get("running_services", []),
        "open_ports_credentialed": listeners,
        "users": system_data.get("users", []),
        "local_groups": system_data.get("local_groups", []),
        "suspicious_scheduled_tasks": system_data.get("suspicious_scheduled_tasks", []),
        "cron_info_raw": system_data.get("cron_info_raw", ""),
        "hardening_audits": hardening_audits,
        "suid_binaries": system_data.get("suid_binaries", []),
        "world_writable_dirs": system_data.get("world_writable_dirs", []),
        "sudo_nopasswd": system_data.get("sudo_nopasswd", False),
        "sudo_rules_raw": system_data.get("sudo_rules_raw", ""),
        "security_issues": system_data.get("security_issues", []),
        "failed_login_count": system_data.get("failed_login_count", 0),
        "brute_force_warning": system_data.get("brute_force_warning", False),
        "failed_logins_recent": system_data.get("failed_logins_recent", []),
        "network_interfaces_raw": system_data.get("network_interfaces_raw", ""),
        "env_vars_flagged": system_data.get("env_vars_summary", []),
        "cves": cve_list,
        "cve_count": len(cve_list),
        "severity_summary": severity_counts,
        "scan_duration": scan_duration,
        # Coverage of the audit itself, so the report can state what was
        # examined rather than implying the whole host was.
        "packages_enumerated": len(packages),
        "collection_errors": collection_errors,
        "inventory_complete": bool(packages) and not collection_errors,
        # What this audit could and could not see. Without it, a report with no
        # network findings reads as a host with no network exposure.
        "coverage": credentialed_coverage(network_scanned=network_scanned),
        "exposure_summary": exposure_summary,
    }

    # ── Verify before anything consumes the findings ──────────────────
    # The audit's own matcher settles most candidates, but not all, and
    # until this ran here the unsettled ones were only filtered when the
    # PDF was rendered — after the severity summary, the asset sync and
    # the dashboard counts had already been computed from them.
    verification = verify_credentialed_report(stored_report)
    cve_list = verification.verified
    severity_counts = {
        tier: verification.severity_counts.get(tier, 0)
        for tier in ("Critical", "High", "Medium", "Low")
    }
    severity_counts["Info"] = verification.severity_counts.get(
        "None", 0
    ) + verification.severity_counts.get("Unscored", 0)
    stored_report.update(
        {
            "cves": cve_list,
            "cve_count": len(cve_list),
            "severity_summary": severity_counts,
            "suppressed_cves": [
                {
                    "identifier": item.identifier,
                    "host": item.host,
                    "reason": item.reason,
                }
                for item in verification.suppressed
            ],
            "candidates_evaluated": verification.evaluated,
        }
    )

    return stored_report, system_data, os_type


def _classify_credentialed_failure(reason: str) -> str:
    """Whether a failed host was unreachable or failed for another reason."""
    lowered = reason.lower()
    if any(
        msg in lowered
        for msg in ["reach", "timeout", "no route", "connection refused", "down"]
    ):
        return "unreachable"
    return "failed"


@celery_app.task(name="ccure.tasks.run_credentialed_scan", queue="scanner")
def run_credentialed_scan_task(
    user_id: str,
    ip: str | None = None,
    username: str | None = None,
    password: str | None = None,
    key_path: str | None = None,
    port: int = 22,
    auth_method: str = "password",
    sections: list[str] | None = None,
    os_type_req: str = "auto",
    scan_id: str | None = None,
    credential_id: str | None = None,
    targets: list[str] | None = None,
):
    """
    Credentialed Scan Task — authenticated audit of one or more hosts.

    ``ip`` is retained so a task already queued by an older release still runs;
    ``targets`` is what the router sends now. One scan covers every target,
    matching how the Vulnerability Audit pipeline reports many hosts under a
    single scan record rather than fragmenting them across several.

    A host that cannot be reached does not abandon the others. The scan fails
    only when no host could be audited at all, which keeps the single-target
    case — where that is the same thing — behaving exactly as before.
    """
    from core.redis_client import publish_progress_sync

    host_list = [t for t in (targets or []) if t] or ([ip] if ip else [])
    if not host_list:
        raise ValueError("No target supplied for credentialed scan.")

    db = SessionLocal()
    start_time = time.time()
    current_target = {"ip": host_list[0]}

    def emit(status, message, percentage=0, stage=None):
        if not scan_id:
            return
        publish_progress_sync(
            scan_id,
            5,
            {
                "status": status,
                "message": message,
                "percentage": percentage,
                "stage": stage,
                "target": current_target["ip"],
                "hosts_total": len(host_list),
                "timestamp": utcnow().isoformat(),
            },
        )

    try:
        key_content = None
        if credential_id:
            # A stored credential supersedes anything the request supplied.
            # Which of password/key is set is what selects the auth method —
            # the stored record's own `auth_method` already decided that when
            # it was decrypted, so nothing here needs to read it again.
            material = _resolve_stored_credential(db, scan_id, credential_id)
            username = material["username"]
            port = material["port"]
            password = material["password"]
            key_content = material["key_content"]

        reports: list[dict] = []
        collected: list[tuple[dict, dict, str]] = []
        failed_hosts: list[dict] = []

        for index, host_ip in enumerate(host_list):
            current_target["ip"] = host_ip
            # Progress is reported across the whole target list so a 40-host
            # scan does not appear to restart at 10% on every host.
            span = 90.0 / len(host_list)
            base = index * span

            def host_emit(
                status, message, percentage=0, stage=None, _base=base, _span=span
            ):
                emit(status, message, int(_base + (percentage / 100.0) * _span), stage)

            try:
                stored_report, system_data, os_type = audit_credentialed_host(
                    ip=host_ip,
                    username=username,
                    password=password,
                    key_path=key_path,
                    key_content=key_content,
                    port=port,
                    sections=sections,
                    os_type_req=os_type_req,
                    emit=host_emit,
                )
                reports.append(stored_report)
                collected.append((stored_report, system_data, os_type))
            except Exception as host_exc:  # noqa: BLE001 — recorded, not swallowed
                reason = str(host_exc)
                status = _classify_credentialed_failure(reason)
                if status == "unreachable" or "authentication failed" in reason.lower():
                    log.error("Credentialed audit of %s failed: %s", host_ip, reason)
                else:
                    log.exception("Credentialed audit of %s failed", host_ip)
                failed_hosts.append(
                    {"target": host_ip, "status": status, "reason": reason}
                )

        # Every host failed — for a single target this is the same outcome the
        # task has always produced, with the same reason and status.
        if not reports:
            reason = (
                failed_hosts[0]["reason"]
                if failed_hosts
                else "No host could be audited"
            )
            status = failed_hosts[0]["status"] if failed_hosts else "failed"
            emit(status, f"Scan {status}: {reason}", 0, "error")
            if scan_id:
                mark_scan_failed(db, scan_id, user_id, reason, status=status)
            db.rollback()
            return {"success": False, "error": reason}

        scan_duration = round(time.time() - start_time, 2)
        target_str = ", ".join(host_list)

        totals = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        total_cves = 0
        candidates_evaluated = 0
        for report in reports:
            for tier, count in (report.get("severity_summary") or {}).items():
                totals[tier] = totals.get(tier, 0) + count
            total_cves += report.get("cve_count", 0)
            candidates_evaluated += report.get("candidates_evaluated", 0) or 0

        primary = reports[0]
        coverage = dict(primary.get("coverage") or {})

        # `report` stays the first host so every existing consumer — the results
        # page, the PDF text-recovery fallback — keeps working unchanged;
        # `reports` is the complete set.
        results_payload = {
            "credentialed": {
                "report": primary,
                "reports": reports,
                "data": [{"ip_address": r["target"]} for r in reports],
                "hosts_audited": len(reports),
                "hosts_failed": failed_hosts,
                "targets": host_list,
            }
        }

        summary = {
            "scan_type": "credentialed",
            "cve_count": total_cves,
            "scan_duration": scan_duration,
            "critical_count": totals["Critical"],
            "high_count": totals["High"],
            "medium_count": totals["Medium"],
            "low_count": totals["Low"],
            "info_count": totals["Info"],
            "total_vulns": total_cves,
            "total_hosts": len(host_list),
            "active_hosts": len(reports),
            "hosts_failed": len(failed_hosts),
            "candidates_evaluated": candidates_evaluated,
            **coverage,
        }

        report_result = {
            "success": True,
            "data": results_payload,
            "summary": summary,
            "metadata": {
                "target": target_str,
                "original_targets": host_list,
                "scan_type": "credentialed",
                "is_credentialed": True,
                **coverage,
            },
        }
        orch = _new_orchestrator()
        report_paths = orch.generate_phase_report(report_result, "credentialed_scan")
        scan = create_completed_scan(
            db=db,
            user_id=user_id,
            target=target_str,
            targets=host_list,
            scan_type="credentialed",
            phase=3,
            results=results_payload,
            summary=summary,
            scan_duration=scan_duration,
            # Without this the helper's default silently relabelled the scan as
            # a vulnerability_audit — a pipeline none of whose phases ran.
            pipeline_mode="credentialed",
            report_executive_path=report_paths.get("executive_pdf"),
            report_technical_path=report_paths.get("technical_pdf"),
            scan_id=scan_id,
            commit=False,  # ENTERPRISE FIX: Do not commit yet
        )

        # Sync to Asset Registry within the same transaction
        for stored_report, system_data, os_type in collected:
            _sync_credentialed_asset_identity(
                db,
                user_id=user_id,
                ip=stored_report["target"],
                scan_id=str(scan.id),
                os_type=os_type,
                system_data=system_data,
                stored_report=stored_report,
                cve_list=stored_report.get("cves") or [],
                severity_counts=stored_report.get("severity_summary") or {},
            )

        # Trigger AMT reconciliation now that the asset identity has been fully synced
        try:
            from core.amt_reconciliation import reconcile_amt_inventory

            reconcile_amt_inventory(db, str(scan.org_id))
        except Exception as amt_exc:
            log.warning(
                "Post-credentialed scan AMT reconciliation failed for org %s: %s",
                scan.org_id,
                amt_exc,
            )

        # ATOMIC COMMIT: Final persistence of everything
        db.commit()

        message = "Scan completed successfully."
        if failed_hosts:
            message = (
                f"Completed — {len(reports)} host(s) audited, "
                f"{len(failed_hosts)} unreachable."
            )
        emit("complete", message, 100, "complete")
        return {"success": True, "scan_id": str(scan.id)}
    except Exception as exc:
        db.rollback()  # Rollback everything if any step fails

        reason = str(exc)
        status = _classify_credentialed_failure(reason)

        # Suppress stack trace for expected network/credentials errors
        if (
            "ssh authentication failed" in reason.lower()
            or "cannot reach" in reason.lower()
            or "ssh connection error" in reason.lower()
        ):
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
def send_password_reset_email_task(
    email_to: str, username: str, reset_link: str
) -> None:
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
        log.error(
            f"Failed to dispatch MFA OTP email to {email_to}: {exc}", exc_info=True
        )


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
            log.warning(
                "Failed to fetch OUI registry. HTTP Status: %d", response.status_code
            )
            return {"success": False, "error": f"HTTP status {response.status_code}"}

        content = response.text

        # 2. Basic validation: ensure the file contains comments and some common MAC prefixes
        if not content.startswith("#") or "00:00:00" not in content:
            log.warning(
                "Fetched OUI registry failed validation checks. Update aborted."
            )
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

        log.info(
            "MAC vendor registry updated successfully. Loaded %d entries.",
            len(get_oui_db()._database),
        )
        return {"success": True, "entries": len(get_oui_db()._database)}

    except Exception as exc:
        log.exception("MAC vendor registry background update task failed")
        return {"success": False, "error": str(exc)}
