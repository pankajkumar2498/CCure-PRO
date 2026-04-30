"""
scans/db_helpers.py
───────────────────────────────────────────────────────────────────────────────
Functions called from main.py endpoints to create / update Scan rows 
and track execution phases natively in the production PostgreSQL schema.

Automatically runs Identity Resolution (AssetSyncer) internally.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from db.models.users import User
from db.models.scans import Scan, ScanPhase
from scans.asset_syncer import sync_host_discovery, sync_asset_discovery, sync_advanced_scan
from db.base import utcnow


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
    db:                Session,
    user_id:           str,
    target:            str,
    targets:           list[str],
    scan_type:         str,
    phase1_data:       dict,
    pipeline_mode:     str  = "basic",
    is_final:          bool = False,
    report_json_path:  Optional[str] = None,
    report_xml_path:   Optional[str] = None,
) -> Scan:
    """
    Called right after /scan/host-discovery succeeds.
    """
    org_id = _get_org_id(db, user_id)
    summary = phase1_data.get("summary", {})
    duration = summary.get("scan_duration", 0.0)
    hosts_data = phase1_data.get("data", [])

    scan = Scan(
        org_id=org_id,
        created_by=user_id,
        scan_no=_next_scan_no(db, org_id, user_id),
        target_str=target,
        target_hosts=targets,
        scan_type=scan_type,
        pipeline_mode=pipeline_mode,
        status="complete" if is_final else "running",
        started_at=utcnow(),
        completed_at=utcnow() if is_final else None,
        duration_seconds=duration,
        total_hosts=summary.get("total_hosts", 0),
        active_hosts=summary.get("active_hosts", 0),
        report_json_path=report_json_path,
        report_xml_path=report_xml_path,
    )
    db.add(scan)
    db.flush()

    phase_row = ScanPhase(
        scan_id=scan.id,
        phase_key="host_discovery",
        phase_order=1,
        status="complete",
        duration_seconds=duration,
        hosts_processed=len(hosts_data),
        summary=summary,
        started_at=utcnow(),
        completed_at=utcnow()
    )
    db.add(phase_row)
    db.flush()

    # Asset Sync: Identity Resolution
    sync_host_discovery(db, str(scan.id), org_id, user_id, hosts_data)

    db.commit()
    db.refresh(scan)
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
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.created_by == user_id).first()
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

    phase_row = ScanPhase(
        scan_id=scan.id,
        phase_key=phase_key,
        phase_order=phase,
        status="complete",
        duration_seconds=duration,
        hosts_processed=len(hosts_data),
        summary=summary,
        started_at=utcnow(),
        completed_at=utcnow()
    )
    db.add(phase_row)
    db.flush()

    # Synchronization
    if phase == 2:
        sync_asset_discovery(db, str(scan.id), org_id, user_id, hosts_data)
    elif phase >= 3:
        sync_advanced_scan(db, str(scan.id), org_id, user_id, hosts_data)

        # Update denormalized vuln counts on Scan row for dashboard performance
        critical_count = sum(1 for h in hosts_data for v in h.get("vulnerabilities", []) if v.get("severity", "").lower() == "critical")
        high_count = sum(1 for h in hosts_data for v in h.get("vulnerabilities", []) if v.get("severity", "").lower() == "high")
        medium_count = sum(1 for h in hosts_data for v in h.get("vulnerabilities", []) if v.get("severity", "").lower() == "medium")
        low_count = sum(1 for h in hosts_data for v in h.get("vulnerabilities", []) if v.get("severity", "").lower() == "low")
        
        scan.critical_count = critical_count
        scan.high_count = high_count
        scan.medium_count = medium_count
        scan.low_count = low_count
        scan.total_vulns = critical_count + high_count + medium_count + low_count

    db.commit()
    db.refresh(scan)
    return scan


def mark_scan_failed(
    db:      Session,
    scan_id: str,
    user_id: str,
    reason:  str,
) -> Optional[Scan]:
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.created_by == user_id).first()
    if not scan:
        return None

    scan.status = "failed"
    scan.failure_reason = reason
    scan.completed_at = utcnow()

    db.commit()
    db.refresh(scan)
    return scan


def create_completed_scan(
    db:               Session,
    user_id:          str,
    target:           str,
    targets:          Optional[list[str]],
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
    base_targets = targets or [target]
    
    scan = Scan(
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
    db.add(scan)
    db.flush()

    for phase_key, payload in (results or {}).items():
        phase_order = 3 if phase_key == "credentialed" else int(phase_key.replace("phase", "") or 0)
        phase_row = ScanPhase(
            scan_id=scan.id,
            phase_key=phase_key,
            phase_order=phase_order,
            status="complete",
            duration_seconds=payload.get("summary", {}).get("scan_duration", 0.0),
            hosts_processed=len(payload.get("data", [])),
            summary=payload.get("summary", {}),
            started_at=utcnow(),
            completed_at=utcnow()
        )
        db.add(phase_row)
        
        # Apply sync manually
        hosts_data = payload.get("data", [])
        if phase_order == 1:
            sync_host_discovery(db, str(scan.id), org_id, user_id, hosts_data)
        elif phase_order == 2:
            sync_asset_discovery(db, str(scan.id), org_id, user_id, hosts_data)
        elif phase_order >= 3:
            sync_advanced_scan(db, str(scan.id), org_id, user_id, hosts_data)

    db.commit()
    db.refresh(scan)
    return scan
