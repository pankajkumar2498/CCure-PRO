"""
routers/reports.py
─────────────────────────────────────────────────────────────────────────────
PDF report download endpoint.

Endpoints
─────────
  GET /reports/download/{scan_id} → Download JSON or XML PDF report
"""

import os
import time
from typing import Optional

from auth.dependencies import get_current_user_flexible
from db.base import get_db
from db.models import Permission, RolePermission, Scan, User
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pdf_generator import ScanReportGenerator
from scan_helpers import (
    apply_phase1_summary_hints,
    log,
    resolve_report_context,
)
from scans.legacy_json_builder import build_legacy_scan_results
from sqlalchemy.orm import Session

router = APIRouter(tags=["Reports"])

_REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports"
)
# Fallback: if routers/ is directly under Backend/, go up one level
if not os.path.isdir(_REPORTS_DIR):
    _REPORTS_DIR = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "reports"
    )
    _REPORTS_DIR = os.path.abspath(_REPORTS_DIR)


def cleanup_old_reports(days_old: int = 7) -> None:
    """Delete PDF files in the reports directory older than `days_old`."""
    if not os.path.isdir(_REPORTS_DIR):
        return

    cutoff_time = time.time() - (days_old * 86400)
    count = 0
    for filename in os.listdir(_REPORTS_DIR):
        if not filename.lower().endswith(".pdf"):
            continue

        file_path = os.path.join(_REPORTS_DIR, filename)
        try:
            if os.path.getmtime(file_path) < cutoff_time:
                os.remove(file_path)
                count += 1
        except Exception as e:
            log.warning(f"Failed to delete old report {filename}: {e}")

    if count > 0:
        log.info(f"Cleaned up {count} report(s) older than {days_old} days.")


def _load_scan_report_paths(db: Session, scan: Scan) -> dict:
    """Generate report PDFs from stored scan phase payloads when no file path exists."""
    if not scan.phases:
        return {}

    payloads = build_legacy_scan_results(db, str(scan.id))

    # Prefer the most complete phase available.
    for key in ("credentialed", "phase3", "phase2", "phase1"):
        if key in payloads and isinstance(payloads[key], dict):
            payload = payloads[key]
            break
    else:
        return {}

    if not payload.get("data") and not (
        key == "credentialed" and payload.get("report")
    ):
        return {}

    payload_data = payload.get("data", [])
    if key == "credentialed" and payload.get("report"):
        payload_data = {"credentialed": {"report": payload.get("report")}}

    payload_meta = (
        payload.get("metadata", {}) if isinstance(payload.get("metadata"), dict) else {}
    )

    hosts_list = []
    if isinstance(payload_data, list):
        hosts_list = payload_data
    elif isinstance(payload_data, dict) and "credentialed" in payload_data:
        rep = payload_data["credentialed"].get("report", {})
        hosts_list = [{"ip_address": rep.get("target")}] if rep.get("target") else []

    context_meta = resolve_report_context(
        db,
        str(scan.created_by),
        scan_id=scan.id,
        hosts=hosts_list,
    )

    # Feed age is a material caveat on any vulnerability report: findings can
    # only be as current as the CVE data behind them. Recording it here means
    # the report states the feed date instead of implying it is current.
    feed = {}
    try:
        from core.vuln_intel import get_feed_freshness

        freshness = get_feed_freshness()
        if freshness.get("last_modified"):
            feed["cve_feed_updated"] = freshness["last_modified"]
        if freshness.get("cve_count"):
            feed["cve_feed_size"] = freshness["cve_count"]
    except Exception as exc:  # never block report generation on this
        log.debug("Feed freshness unavailable for scan %s: %s", scan.id, exc)

    result = {
        "success": True,
        "data": payload_data,
        "summary": payload.get("summary", {}),
        "metadata": {
            "scan_no": scan.scan_no,
            "scan_id": scan.id,
            **feed,
            **payload_meta,
            **context_meta,
        },
    }
    apply_phase1_summary_hints(result, db, str(scan.created_by), scan.id)

    report_paths = ScanReportGenerator(output_dir=_REPORTS_DIR).generate(result, key)
    report_paths = {k: v for k, v in report_paths.items() if v and os.path.isfile(v)}
    if report_paths:
        if report_paths.get("executive_pdf"):
            scan.report_executive_path = report_paths["executive_pdf"]
        if report_paths.get("technical_pdf"):
            scan.report_technical_path = report_paths["technical_pdf"]
        db.commit()
        db.refresh(scan)

    return report_paths


def _require_reports_read(user: User, db: Session) -> None:
    role = getattr(user, "role", None)
    role_name = (getattr(role, "name", "") or "").lower()

    # Keep parity with global RBAC behavior: superadmin bypass.
    if role_name == "superadmin":
        return

    if not role:
        raise HTTPException(
            status_code=403, detail="Your account does not have a role assigned."
        )

    has_reports_read = (
        db.query(RolePermission)
        .join(Permission, Permission.id == RolePermission.permission_id)
        .filter(
            RolePermission.role_id == role.id,
            Permission.resource == "reports",
            Permission.action == "read",
        )
        .first()
    ) is not None

    if not has_reports_read:
        raise HTTPException(
            status_code=403,
            detail="Insufficient privileges. Your role does not have 'reports:read' permission.",
        )


def _require_reports_delete(user: User, db: Session) -> None:
    role = getattr(user, "role", None)
    role_name = (getattr(role, "name", "") or "").lower()

    if role_name == "superadmin":
        return

    if not role:
        raise HTTPException(
            status_code=403, detail="Your account does not have a role assigned."
        )

    has_reports_delete = (
        db.query(RolePermission)
        .join(Permission, Permission.id == RolePermission.permission_id)
        .filter(
            RolePermission.role_id == role.id,
            Permission.resource == "reports",
            Permission.action == "delete",
        )
        .first()
    ) is not None

    if not has_reports_delete:
        raise HTTPException(
            status_code=403,
            detail="Insufficient privileges. Your role does not have 'reports:delete' permission.",
        )


def _is_superadmin(user: User) -> bool:
    return (
        getattr(getattr(user, "role", None), "name", "") or ""
    ).lower() == "superadmin"


def _can_read_all_org_scans(user: User, db: Session) -> bool:
    if _is_superadmin(user):
        return True
    return (
        db.query(RolePermission)
        .join(Permission, Permission.id == RolePermission.permission_id)
        .filter(
            RolePermission.role_id == user.role_id,
            Permission.resource == "scans",
            Permission.action == "read_all",
        )
        .first()
    ) is not None


@router.get("/reports/download/{scan_id}")
def download_report(
    scan_id: str,
    fmt: str = "JSON",
    type: Optional[str] = None,
    min_severity: str = "Info",
    ticket: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user_flexible),
):
    _require_reports_read(user, db)

    query = db.query(Scan).filter(Scan.id == scan_id)
    if not _is_superadmin(user):
        query = query.filter(Scan.org_id == user.org_id)
        if not _can_read_all_org_scans(user, db):
            query = query.filter(Scan.created_by == user.id)

    scan = query.first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    fmt_upper = fmt.upper()
    type_upper = (type or "").upper()

    # Determine target report format and media type
    if fmt_upper == "CSV" or type_upper == "CSV":
        # CSV Export Generation
        payloads = build_legacy_scan_results(db, str(scan.id))
        key = (
            "credentialed"
            if "credentialed" in payloads
            else "phase3" if "phase3" in payloads else "phase1"
        )
        payload = payloads.get(key, {})
        csv_filename = f"scan_{scan.scan_no}_{scan_id[:8]}.csv"
        csv_path = os.path.join(_REPORTS_DIR, csv_filename)
        from csv_generator import generate_scan_csv

        generate_scan_csv(payload, csv_path, scan_type="network")

        # Record Audit Log
        try:
            audit_entry = AuditLog(
                user_id=user.id,
                action="REPORT_DOWNLOAD",
                target=f"Scan {scan.scan_no} (CSV)",
                details=f"Downloaded CSV report for scan_id {scan_id}",
            )
            db.add(audit_entry)
            db.commit()
        except Exception:
            pass

        return FileResponse(path=csv_path, media_type="text/csv", filename=csv_filename)

    # Standard PDF Report Generation (Executive vs Technical Audit)
    is_technical = fmt_upper == "XML" or type_upper in ("TECHNICAL", "XML")
    report_paths = _load_scan_report_paths(db, scan)
    pdf_path = report_paths.get("technical_pdf" if is_technical else "executive_pdf")

    if not pdf_path or not os.path.isfile(os.path.abspath(pdf_path)):
        pdf_path = (
            scan.report_technical_path if is_technical else scan.report_executive_path
        )

    if not pdf_path:
        raise HTTPException(
            status_code=404,
            detail=f"No {'Technical' if is_technical else 'Executive'} PDF report is available for this scan.",
        )

    pdf_path = os.path.abspath(pdf_path)
    reports_root = os.path.abspath(_REPORTS_DIR)
    if not os.path.isfile(pdf_path):
        raise HTTPException(status_code=404, detail="Report file not found on disk.")
    if os.path.commonpath([reports_root, pdf_path]) != reports_root:
        raise HTTPException(status_code=400, detail="Stored report path is invalid.")

    # Record Audit Log
    try:
        audit_entry = AuditLog(
            user_id=user.id,
            action="REPORT_DOWNLOAD",
            target=f"Scan {scan.scan_no} ({'Technical' if is_technical else 'Executive'} PDF)",
            details=f"Downloaded PDF report for scan_id {scan_id}",
        )
        db.add(audit_entry)
        db.commit()
    except Exception:
        pass

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=os.path.basename(pdf_path),
    )


@router.delete("/reports/{scan_id}")
def delete_report(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user_flexible),
):
    _require_reports_delete(user, db)

    query = db.query(Scan).filter(Scan.id == scan_id)
    if not _is_superadmin(user):
        query = query.filter(Scan.org_id == user.org_id)
        if not _can_read_all_org_scans(user, db):
            query = query.filter(Scan.created_by == user.id)

    scan = query.first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    deleted_files = 0
    for path_attr in (
        "report_executive_path",
        "report_technical_path",
        "report_pdf_path",
    ):
        report_path = getattr(scan, path_attr, None)
        if not report_path:
            continue

        abs_path = os.path.abspath(report_path)
        if os.path.isfile(abs_path):
            try:
                if os.path.commonpath(
                    [os.path.abspath(_REPORTS_DIR), abs_path]
                ) == os.path.abspath(_REPORTS_DIR):
                    os.remove(abs_path)
                    deleted_files += 1
            except Exception as exc:
                log.warning("Failed to delete report file '%s': %s", abs_path, exc)

        setattr(scan, path_attr, None)

    db.add(scan)
    db.commit()
    return {
        "detail": f"Report artifacts deleted for scan {scan_id}",
        "deleted_files": deleted_files,
    }
