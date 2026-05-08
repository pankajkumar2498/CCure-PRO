"""
scans/db_helpers.py
───────────────────────────────────────────────────────────────────────────────
Functions called from main.py endpoints to create / update Scan rows 
and track execution phases natively in the production PostgreSQL schema.

Automatically runs Identity Resolution (AssetSyncer) internally.
"""

from datetime import datetime
from typing import Optional, List, Any
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from db.models.users import User
from db.models.rbac import Organization
from db.models.scans import Scan, ScanPhase
from scans.asset_syncer import sync_host_discovery, sync_asset_discovery, sync_advanced_scan
from db.base import utcnow, gen_scan_id, gen_scan_phase_id


_UNSAFE_JSONB_CHARS = {
    codepoint: None
    for codepoint in range(32)
    if codepoint not in (9, 10, 13)
}


def _sanitize_jsonb_value(value: Any) -> Any:
    """
    Network probe output can contain NUL/binary control bytes from SNMP, banners,
    or service scripts. PostgreSQL JSONB rejects those characters, so clean the
    payload at the persistence boundary without changing scan execution.
    """
    if isinstance(value, str):
        return value.translate(_UNSAFE_JSONB_CHARS)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").translate(_UNSAFE_JSONB_CHARS)
    if isinstance(value, dict):
        return {
            _sanitize_jsonb_value(key): _sanitize_jsonb_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_jsonb_value(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_jsonb_value(item) for item in value]
    if isinstance(value, set):
        return [_sanitize_jsonb_value(item) for item in value]
    return value


def _phase_summary_payload(summary: dict, hosts_data: list) -> dict:
    return _sanitize_jsonb_value({**(summary or {}), "_phase_data": hosts_data or []})


def _public_phase_summary(summary: Any) -> dict:
    if not isinstance(summary, dict):
        return {}
    return {
        key: value
        for key, value in summary.items()
        if not str(key).startswith("_")
    }


def _get_org_scoped_scan(db: Session, scan_id: str, user_id: str) -> Optional[Scan]:
    org_id = _get_org_id(db, user_id)
    return db.query(Scan).filter(Scan.id == scan_id, Scan.org_id == org_id).first()


def read_scan_full(db: Session, scan_id: str, user_id: str) -> dict:
    """
    Load a scan and all its phase results into a single dictionary.
    """
    scan = _get_org_scoped_scan(db, scan_id, user_id)
    if not scan:
        return {}

    # Map phases to friendly keys for the frontend
    phases_data = {}
    for phase in scan.phases:
        key = "phase1" if phase.phase_order == 1 else \
              "phase2" if phase.phase_order == 2 else \
              "phase3" if phase.phase_order == 3 else f"phase{phase.phase_order}"
        
        # Identity resolve phase data (this recreates the 'data' field from Assets)
        # For performance, in production we'd use the legacy_json_builder
        phases_data[key] = {
            "status": phase.status,
            "summary": _public_phase_summary(phase.summary),
            # 'data' is usually populated via legacy_json_builder or asset_syncer
        }

    # Use the existing legacy builder to get the 'data' (hosts list) correctly
    from scans.legacy_json_builder import build_legacy_scan_results
    full_results = build_legacy_scan_results(db, scan_id)

    return {
        "id":               str(scan.id),
        "scan_no":          scan.scan_no,
        "status":           scan.status,
        "pipeline_mode":    scan.pipeline_mode,
        "report_json_path": scan.report_json_path,
        "report_xml_path":  scan.report_xml_path,
        "phase1":           {**phases_data.get("phase1", {}), "data": full_results.get("phase1", {}).get("data", [])},
        "phase2":           {**phases_data.get("phase2", {}), "data": full_results.get("phase2", {}).get("data", [])},
        "phase3":           {**phases_data.get("phase3", {}), "data": full_results.get("phase3", {}).get("data", [])},
    }
def _get_org_id(db: Session, user_id: str) -> str:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise ValueError(f"User {user_id} not found in DB")
    return str(user.org_id)


def _next_scan_no(db: Session, org_id: str, user_id: str) -> int:
    """
    Return the next human-facing scan number for this user inside the org.

    UUID remains the real object identity; scan_no is only for display,
    support, reports, and database lookups by humans.
    """
    if db.bind and db.bind.dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
            {"lock_key": f"scan_no:{org_id}:{user_id}"},
        )

    current = (
        db.query(func.max(Scan.scan_no))
        .filter(Scan.org_id == org_id, Scan.created_by == user_id)
        .scalar()
    )
    return int(current or 0) + 1


def create_scan(
    db: Session,
    user_id: str,
    target: str,
    targets: List[str],
    scan_type: str,
    pipeline_mode: str = "basic",
) -> Scan:
    """Create an empty running scan before Phase 1 starts."""
    org_id = _get_org_id(db, user_id)
    org = db.query(Organization).filter(Organization.id == org_id).first()
    org_slug = org.slug if org else org_id
    
    scan = Scan(
        id=gen_scan_id(org_slug),
        org_id=org_id,
        created_by=user_id,
        scan_no=_next_scan_no(db, org_id, user_id),
        target_str=target,
        target_hosts=targets,
        scan_type=scan_type,
        pipeline_mode=pipeline_mode,
        status="running",
        started_at=utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def update_scan_phase1(
    db:                Session,
    scan_id:           str,
    user_id:           str,
    phase1_data:       dict,
    is_final:          bool = False,
    report_json_path:  Optional[str] = None,
    report_xml_path:   Optional[str] = None,
) -> Optional[Scan]:
    """
    Called right after /scan/host-discovery succeeds. Updates the existing scan.
    """
    scan = _get_org_scoped_scan(db, scan_id, user_id)
    if not scan:
        return None

    org_id = _get_org_id(db, user_id)
    summary = phase1_data.get("summary", {})
    duration = summary.get("scan_duration", 0.0)
    hosts_data = phase1_data.get("data", [])

    scan.status = "complete" if is_final else "running"
    if is_final:
        scan.completed_at = utcnow()
    scan.duration_seconds = duration
    scan.total_hosts = summary.get("total_hosts", 0)
    scan.active_hosts = summary.get("active_hosts", 0)
    if report_json_path: scan.report_json_path = report_json_path
    if report_xml_path: scan.report_xml_path = report_xml_path

    # Full payload embedded in summary
    full_summary = _phase_summary_payload(summary, hosts_data)

    phase_row = ScanPhase(
        id=gen_scan_phase_id(scan.id, "host_discovery"),
        scan_id=scan.id,
        phase_key="host_discovery",
        phase_order=1,
        status="complete",
        duration_seconds=duration,
        hosts_processed=len(hosts_data),
        summary=full_summary,
        started_at=utcnow(),
        completed_at=utcnow()
    )
    db.add(phase_row)
    db.flush()

    db.commit()
    db.refresh(scan)

    # Asset Sync in background (AFTER commit to avoid FK race condition)
    from core.tasks import sync_host_discovery_task
    sync_host_discovery_task.delay(str(scan.id), org_id, user_id, hosts_data)

    if is_final:
        try:
            from routers.notifications import create_notification, NotificationType, NotificationCategory
            create_notification(
                db=db,
                user_id=scan.created_by,
                notification_type=NotificationType.SCAN_COMPLETED,
                category=NotificationCategory.SCAN,
                title=f"Scan {scan.scan_no} Completed",
                message=f"Host Discovery scan on {scan.target_str} has finished. Found {scan.active_hosts} active hosts.",
                related_scan_id=str(scan.id)
            )
        except Exception as e:
            pass # Silent fail for notifications

    return scan


def update_scan_phase(
    db:               Session,
    scan_id:          str,
    user_id:          str,
    phase:            int,
    phase_data:       dict,
    is_final:         bool          = False,
    pipeline_mode:    Optional[str] = None,
    report_json_path: Optional[str] = None,
    report_xml_path:  Optional[str] = None,
) -> Optional[Scan]:
    """
    Called after /scan/asset-discovery (phase=2) or /scan/advanced-scan (phase=3).
    """
    scan = _get_org_scoped_scan(db, scan_id, user_id)
    if not scan:
        return None

    org_id = _get_org_id(db, user_id)
    summary = phase_data.get("summary", {})
    duration = summary.get("scan_duration", 0.0)
    hosts_data = phase_data.get("data", [])

    if pipeline_mode:
        scan.pipeline_mode = pipeline_mode
    if report_json_path:
        scan.report_json_path = report_json_path
    if report_xml_path:
        scan.report_xml_path = report_xml_path

    # Keep duration rolling
    scan.duration_seconds = (scan.duration_seconds or 0.0) + duration
    scan.status = "complete" if is_final else "running"
    
    if is_final:
        scan.completed_at = utcnow()

    # Track phase
    phase_key_map = {2: "asset_discovery", 3: "vulnerability_assessment", 4: "credentialed"}
    phase_key = phase_key_map.get(phase, f"phase{phase}")

    # Embed raw data into summary to ensure 100% historical fidelity without schema changes
    full_summary_payload = _phase_summary_payload(summary, hosts_data)

    phase_row = (
        db.query(ScanPhase)
        .filter(ScanPhase.scan_id == scan.id, ScanPhase.phase_key == phase_key)
        .first()
    )
    now = utcnow()
    if phase_row:
        phase_row.phase_order = phase
        phase_row.status = "complete"
        phase_row.duration_seconds = duration
        phase_row.hosts_processed = len(hosts_data)
        phase_row.summary = full_summary_payload
        phase_row.completed_at = now
        phase_row.updated_at = now
        if not phase_row.started_at:
            phase_row.started_at = now
    else:
        phase_row = ScanPhase(
            id=gen_scan_phase_id(scan.id, phase_key),
            scan_id=scan.id,
            phase_key=phase_key,
            phase_order=phase,
            status="complete",
            duration_seconds=duration,
            hosts_processed=len(hosts_data),
            summary=full_summary_payload,
            started_at=now,
            completed_at=now
        )
        db.add(phase_row)
        db.flush()

    if phase >= 3:
        # Update denormalized vuln counts on Scan row for dashboard performance
        all_vulns = []
        for h in hosts_data:
            all_vulns.extend(h.get("vulnerabilities") or h.get("cves") or [])

        critical_count = sum(1 for v in all_vulns if str(v.get("severity", "")).lower() == "critical")
        high_count = sum(1 for v in all_vulns if str(v.get("severity", "")).lower() == "high")
        medium_count = sum(1 for v in all_vulns if str(v.get("severity", "")).lower() == "medium")
        low_count = sum(1 for v in all_vulns if str(v.get("severity", "")).lower() == "low")
        
        scan.critical_count = critical_count
        scan.high_count = high_count
        scan.medium_count = medium_count
        scan.low_count = low_count
        scan.total_vulns = critical_count + high_count + medium_count + low_count

    db.commit()
    db.refresh(scan)

    # Synchronization (AFTER commit to avoid FK race condition)
    if phase == 2:
        from core.tasks import sync_asset_discovery_task
        sync_asset_discovery_task.delay(str(scan.id), org_id, user_id, hosts_data)
    elif phase >= 3:
        from core.tasks import sync_advanced_scan_task
        sync_advanced_scan_task.delay(str(scan.id), org_id, user_id, hosts_data)

    if is_final:
        try:
            from routers.notifications import create_notification, fan_out_notification, NotificationType, NotificationCategory
            
            # Additional logic: if critical vulns were found, send a Security notification
            if getattr(scan, "critical_count", 0) > 0:
                create_notification(
                    db=db,
                    user_id=scan.created_by,
                    notification_type=NotificationType.VULNERABILITY_FOUND,
                    category=NotificationCategory.SECURITY,
                    title=f"Critical Vulnerabilities Found",
                    message=f"Scan {scan.scan_no} on {scan.target_str} discovered {scan.critical_count} critical vulnerabilities.",
                    related_scan_id=str(scan.id)
                )
                
                # ESCALATION RULE: Fan-out to leadership
                fan_out_notification(
                    db=db,
                    org_id=str(scan.org_id),
                    target_roles=["superadmin", "org_admin"],
                    notification_type=NotificationType.VULNERABILITY_FOUND,
                    category=NotificationCategory.SECURITY,
                    title=f"Critical Vulnerabilities Found",
                    message=f"Scan {scan.scan_no} on {scan.target_str} discovered {scan.critical_count} critical vulnerabilities.",
                    related_scan_id=str(scan.id),
                    exclude_user_id=str(scan.created_by)
                )
            else:
                create_notification(
                    db=db,
                    user_id=scan.created_by,
                    notification_type=NotificationType.SCAN_COMPLETED,
                    category=NotificationCategory.SCAN,
                    title=f"Scan {scan.scan_no} Completed",
                    message=f"Scan on {scan.target_str} has finished successfully.",
                    related_scan_id=str(scan.id)
                )
        except Exception as e:
            pass

    return scan


def mark_scan_failed(
    db:      Session,
    scan_id: str,
    user_id: str,
    reason:  str,
) -> Optional[Scan]:
    scan = _get_org_scoped_scan(db, scan_id, user_id)
    if not scan:
        return None

    scan.status = "failed"
    scan.failure_reason = reason
    scan.completed_at = utcnow()

    db.commit()
    db.refresh(scan)

    try:
        from routers.notifications import create_notification, NotificationType, NotificationCategory
        create_notification(
            db=db,
            user_id=scan.created_by,
            notification_type=NotificationType.SCAN_FAILED,
            category=NotificationCategory.SCAN,
            title=f"Scan {scan.scan_no} Failed",
            message=f"Scan on {scan.target_str} failed: {reason}",
            related_scan_id=str(scan.id)
        )
    except Exception:
        pass

    return scan


def create_completed_scan(
    db:               Session,
    user_id:          str,
    target:           str,
    targets:          Optional[List[str]],
    scan_type:        str,
    phase:            int,
    results:          dict,
    summary:          dict,
    scan_duration:    Optional[float] = None,
    report_json_path: Optional[str]   = None,
    report_xml_path:  Optional[str]   = None,
    pipeline_mode:    str             = "advanced",
) -> Scan:
    """Fallback capability for bulk-loading a fully complete scan (used by credentialed scans)."""
    org_id = _get_org_id(db, user_id)
    org = db.query(Organization).filter(Organization.id == org_id).first()
    org_slug = org.slug if org else org_id
    base_targets = targets or [target]
    
    scan = Scan(
        id=gen_scan_id(org_slug),
        org_id=org_id,
        created_by=user_id,
        scan_no=_next_scan_no(db, org_id, user_id),
        target_str=target,
        target_hosts=base_targets,
        scan_type=scan_type,
        pipeline_mode=pipeline_mode,
        status="complete",
        started_at=utcnow(),
        completed_at=utcnow(),
        duration_seconds=scan_duration or summary.get("scan_duration", 0.0),
        total_hosts=summary.get("total_hosts", 0),
        active_hosts=summary.get("active_hosts", 0),
        report_json_path=report_json_path,
        report_xml_path=report_xml_path,
    )

    credentialed_report = (results or {}).get("credentialed", {}).get("report")
    if credentialed_report:
        scan.options = {
            **(scan.options or {}),
            "credentialed_report": credentialed_report,
        }

    db.add(scan)
    db.flush()

    for phase_key, payload in (results or {}).items():
        phase_order = 3 if phase_key == "credentialed" else int(phase_key.replace("phase", "") or 0)
        phase_summary = payload.get("summary", {})
        hosts_data = payload.get("data", [])
        if phase_key == "credentialed" and payload.get("report"):
            phase_summary = {
                **summary,
                **phase_summary,
            }
            hosts_data = hosts_data or [{"ip_address": target}]

        phase_row = ScanPhase(
            id=gen_scan_phase_id(scan.id, phase_key),
            scan_id=scan.id,
            phase_key=phase_key,
            phase_order=phase_order,
            status="complete",
            duration_seconds=phase_summary.get("scan_duration", 0.0),
            hosts_processed=len(hosts_data),
            summary=_phase_summary_payload(phase_summary, hosts_data),
            started_at=utcnow(),
            completed_at=utcnow()
        )
        db.add(phase_row)
        if phase_key == "credentialed":
            continue
        
        # Apply sync manually
        if phase_order == 1:
            sync_host_discovery(db, str(scan.id), org_id, user_id, hosts_data)
        elif phase_order == 2:
            sync_asset_discovery(db, str(scan.id), org_id, user_id, hosts_data)
        elif phase_order >= 3:
            sync_advanced_scan(db, str(scan.id), org_id, user_id, hosts_data)

    db.commit()
    db.refresh(scan)

    try:
        from routers.notifications import create_notification, fan_out_notification, NotificationType, NotificationCategory
        
        # Check if credentialed report has criticals
        vulns = (scan.options or {}).get("credentialed_report", {}).get("vulnerabilities", [])
        critical_count = sum(1 for v in vulns if str(v.get("severity", "")).lower() == "critical")
        
        if critical_count > 0:
            create_notification(
                db=db,
                user_id=scan.created_by,
                notification_type=NotificationType.VULNERABILITY_FOUND,
                category=NotificationCategory.SECURITY,
                title=f"Critical Vulnerabilities Found",
                message=f"Credentialed scan {scan.scan_no} on {scan.target_str} discovered {critical_count} critical vulnerabilities.",
                related_scan_id=str(scan.id)
            )
            
            # ESCALATION RULE: Fan-out to leadership
            fan_out_notification(
                db=db,
                org_id=str(scan.org_id),
                target_roles=["superadmin", "org_admin"],
                notification_type=NotificationType.VULNERABILITY_FOUND,
                category=NotificationCategory.SECURITY,
                title=f"Critical Vulnerabilities Found",
                message=f"Credentialed scan {scan.scan_no} on {scan.target_str} discovered {critical_count} critical vulnerabilities.",
                related_scan_id=str(scan.id),
                exclude_user_id=str(scan.created_by)
            )
        else:
            create_notification(
                db=db,
                user_id=scan.created_by,
                notification_type=NotificationType.SCAN_COMPLETED,
                category=NotificationCategory.SCAN,
                title=f"Scan {scan.scan_no} Completed",
                message=f"Credentialed scan on {scan.target_str} has finished successfully.",
                related_scan_id=str(scan.id)
            )
    except Exception:
        pass

    return scan
