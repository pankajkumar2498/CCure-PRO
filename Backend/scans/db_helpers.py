"""
scans/db_helpers.py
-------------------
Pure functions called from main.py phase endpoints to
create / update Scan rows without duplicating DB logic.
"""

import json
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session

from scans.models import Scan, ScanPhaseResult


def _json_text(value) -> str:
    return json.dumps(value if value is not None else {})


def _upsert_phase_result(
    db: Session,
    scan: Scan,
    phase_key: str,
    phase_order: int,
    payload: dict,
) -> None:
    phase_row = next((row for row in scan.phase_results if row.phase_key == phase_key), None)
    if not phase_row:
        phase_row = (
            db.query(ScanPhaseResult)
            .filter(ScanPhaseResult.scan_id == scan.id, ScanPhaseResult.phase_key == phase_key)
            .first()
        )

    if not phase_row:
        phase_row = ScanPhaseResult(
            scan_id=scan.id,
            phase_key=phase_key,
            phase_order=phase_order,
        )
        db.add(phase_row)
        scan.phase_results.append(phase_row)

    phase_row.phase_order = phase_order
    phase_row.payload = _json_text(payload)
    phase_row.updated_at = datetime.utcnow()


def create_scan(
    db: Session,
    user_id: int,
    target: str,
    targets: list[str],
    scan_type: str,
    phase1_data: dict,
) -> Scan:
    """
    Called right after /scan/phase1 succeeds.
    Creates a new Scan row and returns it (with .id populated).
    """
    summary = phase1_data.get("summary", {})
    summary = {**summary, "original_targets": targets}
    duration = summary.get("scan_duration", 0.0)

    scan = Scan(
        user_id=user_id,
        target=target,
        targets_json=json.dumps(targets),
        scan_type=scan_type,
        phase=1,
        status="running",
        results="{}",
        summary=json.dumps(summary),
        scan_duration=duration,
        failure_reason=None,
    )
    db.add(scan)
    db.commit()
    _upsert_phase_result(db, scan, "phase1", 1, phase1_data)
    db.commit()
    db.refresh(scan)
    return scan


def create_completed_scan(
    db: Session,
    user_id: int,
    target: str,
    targets: Optional[list[str]],
    scan_type: str,
    phase: int,
    results: dict,
    summary: dict,
    scan_duration: Optional[float] = None,
    report_json_path: Optional[str] = None,
    report_xml_path: Optional[str] = None,
) -> Scan:
    """
    Create a scan row that is already complete.

    Used for scan types that do not progress through the normal
    phase1 -> phase2 -> phase3 workflow but should still appear in
    history as finished with their full report persisted.
    """
    base_targets = targets or [target]
    summary = {**summary, "original_targets": base_targets}
    duration = summary.get("scan_duration", 0.0) if scan_duration is None else scan_duration

    scan = Scan(
        user_id=user_id,
        target=target,
        targets_json=json.dumps(base_targets),
        scan_type=scan_type,
        phase=phase,
        status="complete",
        results="{}",
        summary=json.dumps(summary),
        report_json_path=report_json_path,
        report_xml_path=report_xml_path,
        failure_reason=None,
        scan_duration=duration,
    )
    db.add(scan)
    db.commit()
    for phase_key, payload in (results or {}).items():
        phase_order = 3 if phase_key == "credentialed" else int(phase_key.replace("phase", "") or 0)
        _upsert_phase_result(db, scan, phase_key, phase_order, payload)
    db.commit()
    db.refresh(scan)
    return scan


def update_scan_phase(
    db: Session,
    scan_id: int,
    user_id: int,
    phase: int,
    phase_data: dict,
    is_final: bool = False,
    report_json_path: Optional[str] = None,
    report_xml_path: Optional[str] = None,
) -> Optional[Scan]:
    """
    Called after /scan/phase2 or /scan/phase3.
    Merges new phase results into the existing Scan row.
    Returns None if scan_id not found or doesn't belong to user.
    """
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.user_id == user_id)
        .first()
    )
    if not scan:
        return None

    key = f"phase{phase}"

    new_summary = phase_data.get("summary", {})
    existing_summary = json.loads(scan.summary or "{}")
    original_targets = existing_summary.get("original_targets") or json.loads(scan.targets_json or "[]")
    if original_targets:
        new_summary = {**new_summary, "original_targets": original_targets}
    add_duration = new_summary.get("scan_duration", 0.0)

    scan.summary = json.dumps(new_summary)
    scan.phase = phase
    scan.scan_duration = (scan.scan_duration or 0.0) + add_duration
    scan.status = "complete" if is_final else "running"
    scan.failure_reason = None
    scan.updated_at = datetime.utcnow()

    if report_json_path:
        scan.report_json_path = report_json_path
    if report_xml_path:
        scan.report_xml_path = report_xml_path

    _upsert_phase_result(db, scan, key, phase, phase_data)
    db.commit()
    db.refresh(scan)
    return scan


def mark_scan_failed(
    db: Session,
    scan_id: int,
    user_id: int,
    reason: str,
) -> Optional[Scan]:
    """
    Mark an existing scan as failed and persist a failure reason.
    Returns None if scan_id not found or doesn't belong to user.
    """
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.user_id == user_id)
        .first()
    )
    if not scan:
        return None

    scan.status = "failed"
    scan.failure_reason = reason
    scan.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(scan)
    return scan
