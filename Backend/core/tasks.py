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

from core.celery_app import celery_app
from db.base import SessionLocal, gen_service_id, utcnow
from db.models import (
    Asset,
    AssetVulnerability,
    Service,
    Scan,
    User,
    VulnerabilityDefinition,
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
    """Run async scanner code safely from Celery worker threads."""
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

    Nmap OS matches are unauthenticated fingerprints; credentialed collection is
    the source of truth when it provides OS details for an existing asset.
    """
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
        log.warning(
            "Credentialed asset sync skipped: no asset found for org=%s ip=%s",
            user.org_id,
            ip,
        )
        return

    os_name = _clean_text(system_data.get("os_name"))
    os_version = _clean_text(system_data.get("os_version_id"))
    os_build = _clean_text(system_data.get("os_build"))
    kernel_version = _clean_text(system_data.get("kernel_version"))
    hostname = _clean_text(system_data.get("hostname_fqdn"))

    has_os_identity = bool(os_name or os_version or os_build or kernel_version)
    normalized_os_type = (os_type or "").strip().lower()

    if os_name:
        asset.os_name = os_name[:255]
    if os_version:
        asset.os_version = os_version[:100]
    elif kernel_version:
        asset.os_version = kernel_version[:100]

    if has_os_identity:
        family = "Windows" if normalized_os_type == "windows" else "Linux"
        asset.os_family = family
        asset.os_confidence = 100

    if hostname:
        asset.hostname = hostname[:255]
        asset.fqdn = hostname[:512] if "." in hostname else asset.fqdn

    _sync_credentialed_services(db, asset, scan_id, stored_report.get("open_ports_credentialed", []))
    _sync_credentialed_vulnerabilities(db, asset, str(user.org_id), scan_id, cve_list)

    counts = _normalized_severity_counts(severity_counts)
    asset.vuln_counts = {
        "critical": counts["Critical"],
        "high": counts["High"],
        "medium": counts["Medium"],
        "low": counts["Low"],
    }
    credentialed_score, credentialed_level = _credentialed_risk_from_counts(counts)
    if credentialed_score >= int(asset.risk_score or 0):
        asset.risk_score = credentialed_score
        asset.risk_level = credentialed_level

    attrs = dict(asset.custom_attributes or {})
    credentialed_attrs = dict(attrs.get("credentialed_system_info") or {})
    credentialed_attrs.update({
        "os_name": os_name,
        "os_version_id": os_version,
        "os_build": os_build,
        "kernel_version": kernel_version,
        "hostname": hostname,
        "detected_os": normalized_os_type or os_type,
        "source_scan_id": scan_id,
        "synced_at": utcnow().isoformat(),
    })
    attrs["credentialed_system_info"] = {
        key: value for key, value in credentialed_attrs.items() if value
    }
    attrs["credentialed_hardware"] = _compact_dict({
        "cpu_model": system_data.get("cpu_model"),
        "cpu_count": system_data.get("cpu_count"),
        "cpu_arch": system_data.get("cpu_arch"),
        "memory_summary": system_data.get("memory_summary"),
        "disk_usage": system_data.get("disk_usage"),
        "uptime": system_data.get("uptime"),
    })
    attrs["credentialed_security"] = _compact_dict({
        "security_issues": stored_report.get("security_issues"),
        "failed_login_count": stored_report.get("failed_login_count"),
        "brute_force_warning": stored_report.get("brute_force_warning"),
        "sudo_nopasswd": stored_report.get("sudo_nopasswd"),
        "rdp_enabled": system_data.get("rdp_enabled"),
        "package_count": stored_report.get("package_count"),
        "running_service_count": len(stored_report.get("running_services") or []),
        "credentialed_open_port_count": len(stored_report.get("open_ports_credentialed") or []),
        "credentialed_cve_count": len(cve_list or []),
        "severity_summary": counts,
    })
    asset.custom_attributes = attrs

    asset.last_scan_id = scan_id
    asset.last_seen_at = utcnow()
    asset.updated_at = utcnow()
    db.commit()
    log.info("Credentialed asset sync updated asset=%s ip=%s os=%s", asset.id, ip, asset.os_name)


def _clean_text(value) -> str:
    return str(value or "").strip()


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


def _sync_credentialed_services(db, asset: Asset, scan_id: str, ports: List[Dict]) -> None:
    for port_data in ports or []:
        port = _port_int(port_data.get("port"))
        if not port:
            continue

        protocol = _clean_text(port_data.get("protocol") or "tcp").lower()[:10]
        service_id = gen_service_id(asset.id, port, protocol)
        service = db.query(Service).filter(Service.id == service_id).first()
        if not service:
            service = Service(
                id=service_id,
                scan_id=scan_id,
                asset_id=asset.id,
                port=port,
                protocol=protocol,
            )
            db.add(service)

        service.scan_id = scan_id
        state = _clean_text(port_data.get("state") or "open").lower()
        service.state = "open" if state in {"listen", "listening"} else state[:20]
        service.service_name = _clean_text(
            port_data.get("service")
            or port_data.get("name")
            or port_data.get("process")
            or "unknown"
        )[:100]
        service.banner = _clean_text(port_data.get("local_addr") or port_data.get("banner")) or None


def _sync_credentialed_vulnerabilities(
    db,
    asset: Asset,
    org_id: str,
    scan_id: str,
    cve_list: List[Dict],
) -> None:
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

        cve_def = db.query(VulnerabilityDefinition).filter(
            VulnerabilityDefinition.id == cve_id
        ).first()
        if not cve_def:
            cve_def = VulnerabilityDefinition(
                id=cve_id,
                cve_id=cve_id,
                title=f"{cve_id} in {package_name}" if package_name else f"Vulnerability {cve_id}",
                description=description,
                severity=severity,
                cvss_v3_score=cvss,
                cvss_vector=_clean_text(vuln.get("cvss_vector")) or None,
                source=_clean_text(vuln.get("source") or "credentialed"),
                references=[],
                affected_software=[],
            )
            db.add(cve_def)

        affected = list(cve_def.affected_software or [])
        if package_name and not any(
            isinstance(item, dict) and item.get("package") == package_name
            for item in affected
        ):
            affected.append({
                "package": package_name,
                "installed_version": installed_ver,
                "fixed_version": fixed_ver,
                "matched_by": _clean_text(vuln.get("matched_by")),
            })
            cve_def.affected_software = affected

        finding_id = f"fnd_{asset.id}_{cve_id}"
        finding = db.query(AssetVulnerability).filter(
            AssetVulnerability.org_id == org_id,
            AssetVulnerability.id == finding_id,
        ).first()
        proof = _clean_text(f"Package: {package_name} {installed_ver}".strip())
        plugin_output = _clean_text(
            f"{description}\nFixed version: {fixed_ver or 'N/A'}\n"
            f"Priority: {vuln.get('priority_level') or 'N/A'} "
            f"({vuln.get('priority_score') or 0})"
        )
        if finding:
            finding.scan_id = scan_id
            finding.severity = severity
            finding.cvss_score = cvss
            finding.proof = proof or finding.proof
            finding.plugin_output = plugin_output or finding.plugin_output
            finding.last_found_at = utcnow()
            finding.status = "open"
        else:
            db.add(AssetVulnerability(
                id=finding_id,
                org_id=org_id,
                scan_id=scan_id,
                asset_id=asset.id,
                vuln_id=cve_id,
                severity=severity,
                cvss_score=cvss,
                status="open",
                proof=proof,
                plugin_output=plugin_output,
                first_found_at=utcnow(),
                last_found_at=utcnow(),
            ))


@celery_app.task(name="ccure.tasks.sync_asset_discovery_task", queue="scanner")
def sync_asset_discovery_task(scan_id: str, org_id: str, user_id: Optional[str], hosts: List[dict]):
    db = SessionLocal()
    try:
        from scans.asset_syncer import sync_asset_discovery
        sync_asset_discovery(db, scan_id, org_id, user_id, hosts)
    except Exception as exc:
        log.exception("Asset Sync Phase 2 Failed")
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.sync_advanced_scan_task", queue="scanner")
def sync_advanced_scan_task(scan_id: str, org_id: str, user_id: Optional[str], hosts: List[dict]):
    db = SessionLocal()
    try:
        from scans.asset_syncer import sync_advanced_scan
        sync_advanced_scan(db, scan_id, org_id, user_id, hosts)
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
        is_final = (terminal == 1)

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
        publish_progress_sync(scan_id, 1, {
            "discovered": scan.active_hosts,
            "total_ips": scan.total_hosts,
            "status": "complete"
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
):
    """Phase 2 Background Task."""
    db = SessionLocal()
    try:
        _update_task_id(db, scan_id, self.request.id)
        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled before asset discovery", scan_id)
            return {"success": False, "error": "Scan cancelled"}

        mode = resolve_pipeline_mode(pipeline_mode)
        is_final = (get_terminal_phase(mode) == 2)

        orch = _new_orchestrator()
        result = _run_async(orch.run_asset_discovery_only(
            hosts=hosts, intensity=intensity, pipeline_mode=mode, scan_id=scan_id
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
        publish_progress_sync(scan_id, 2, {
            "scanned_hosts": result["summary"].get("total_hosts", 0),
            "total_hosts": result["summary"].get("total_hosts", 0),
            "status": "complete"
        })

        return {"success": True, "scan_id": scan_id}
    except Exception as exc:
        log.exception("Asset Discovery Task Failed")
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.run_advanced_scan", queue="scanner", bind=True)
def run_advanced_scan_task(
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
            log.info("Scan %s cancelled before advanced scan", scan_id)
            return {"success": False, "error": "Scan cancelled"}

        mode = resolve_pipeline_mode(pipeline_mode)
        orch = _new_orchestrator()
        result = orch.run_advanced_scan_only(hosts=hosts, scan_id=scan_id)

        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled after advanced scan", scan_id)
            return {"success": False, "error": "Scan cancelled"}

        if not result.get("success"):
            mark_scan_failed(db, scan_id, user_id, result.get("error", "Advanced Scan failed"))
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
        log.exception("Advanced Scan Task Failed")
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
        
        with SSHScanner(ip=ip, username=username, password=password, key_path=key_path, port=port, timeout=20) as ssh:
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

            system_data = collector.collect_all(sections=sections, on_section_complete=on_section)
            system_data["detected_os"] = os_type
            
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
        
        stored_report = {
            "scan_type": "credentialed",
            "target": ip,
            "username": username,
            "detected_os": os_type,
            "os_type_was_auto": (os_type_req == "auto"),
            "system_info": {
                "os_name":        system_data.get("os_name", ""),
                "os_version_id":  system_data.get("os_version_id", ""),
                "os_build":       system_data.get("os_build", ""),
                "kernel_version": system_data.get("kernel_version", ""),
                "hostname":       system_data.get("hostname_fqdn", ""),
                "cpu_model":      system_data.get("cpu_model", ""),
                "cpu_count":      system_data.get("cpu_count", ""),
                "cpu_arch":       system_data.get("cpu_arch", ""),
                "uptime":         system_data.get("uptime", ""),
                "memory_summary": system_data.get("memory_summary", {}),
                "disk_usage":     system_data.get("disk_usage", []),
            },
            "packages":                packages,
            "package_count":           len(packages),
            "running_services":        system_data.get("running_services", []),
            "open_ports_credentialed": system_data.get("open_ports_credentialed", []),
            "users":                   system_data.get("users", []),
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
        )
        try:
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
        except Exception:
            db.rollback()
            log.exception("Credentialed asset sync failed for %s", ip)

        # 6. Complete
        emit("complete", "Scan completed successfully.", 100, "complete")
        return {"success": True, "scan_id": str(scan.id)}
    except Exception as exc:
        log.exception("Credentialed Scan Task Failed")
        emit("failed", f"Scan failed: {str(exc)}", 0, "error")
        if scan_id:
            mark_scan_failed(db, scan_id, user_id, str(exc))
        return {"success": False, "error": str(exc)}
    finally:
        db.close()

