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
from db.base import SessionLocal
from db.models import Scan
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


@celery_app.task(name="ccure.tasks.run_host_discovery", queue="scanner")
def run_host_discovery_task(
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


@celery_app.task(name="ccure.tasks.run_asset_discovery", queue="scanner")
def run_asset_discovery_task(
    user_id:       str,
    hosts:         List[dict],
    intensity:     str,
    scan_id:       str,
    pipeline_mode: str,
):
    """Phase 2 Background Task."""
    db = SessionLocal()
    try:
        mode = resolve_pipeline_mode(pipeline_mode)
        is_final = (get_terminal_phase(mode) == 2)

        orch = _new_orchestrator()
        result = _run_async(orch.run_asset_discovery_only(
            hosts=hosts, intensity=intensity, pipeline_mode=mode, scan_id=scan_id
        ))

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


@celery_app.task(name="ccure.tasks.run_advanced_scan", queue="scanner")
def run_advanced_scan_task(
    user_id:       str,
    hosts:         List[dict],
    scan_id:       str,
    pipeline_mode: str,
):
    """Phase 3 Background Task."""
    db = SessionLocal()
    try:
        mode = resolve_pipeline_mode(pipeline_mode)
        orch = _new_orchestrator()
        result = orch.run_advanced_scan_only(hosts=hosts, scan_id=scan_id)

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
    
    db = SessionLocal()
    start_time = time.time()
    try:
        with SSHScanner(ip=ip, username=username, password=password, key_path=key_path, port=port, timeout=20) as ssh:
            os_type = os_type_req if os_type_req != "auto" else _detect_os(ssh)
            collector = WindowsCollector(ssh) if os_type == "windows" else LinuxCollector(ssh)
            system_data = collector.collect_all(sections=sections)
            system_data["detected_os"] = os_type

        packages     = system_data.get("packages", [])
        matcher      = VulnMatcher()
        raw_findings = matcher.match_packages(packages)
        cve_list     = matcher.to_report_format(raw_findings)
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for cve in cve_list:
            sev = cve.get("severity", "Info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        scan_duration = round(time.time() - start_time, 2)
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
        return {"success": True, "scan_id": str(scan.id)}
    except Exception as exc:
        log.exception("Credentialed Scan Task Failed")
        return {"success": False, "error": str(exc)}
    finally:
        db.close()
