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

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from db.base import get_db
from db.models import Scan, User, RolePermission, Permission
from auth.dependencies import get_current_user_flexible
from scans.legacy_json_builder import build_legacy_scan_results
from pdf_generator import ScanReportGenerator
from scan_helpers import (
    resolve_report_context,
    apply_phase1_summary_hints,
    log,
)

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

    result = {
        "success": True,
        "data": payload_data,
        "summary": payload.get("summary", {}),
        "metadata": {"scan_no": scan.scan_no, **payload_meta, **context_meta},
    }
    apply_phase1_summary_hints(result, db, str(scan.created_by), scan.id)

    report_paths = ScanReportGenerator(output_dir=_REPORTS_DIR).generate(result, key)
    report_paths = {k: v for k, v in report_paths.items() if v and os.path.isfile(v)}
    if report_paths:
        if report_paths.get("json_pdf"):
            scan.report_json_path = report_paths["json_pdf"]
        if report_paths.get("xml_pdf"):
            scan.report_xml_path = report_paths["xml_pdf"]
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
    ticket: Optional[str] = Query(None),
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
    if fmt_upper not in ("JSON", "XML"):
        raise HTTPException(status_code=400, detail="fmt must be 'JSON' or 'XML'.")

    pdf_path = scan.report_json_path if fmt_upper == "JSON" else scan.report_xml_path
    if not pdf_path or not os.path.isfile(os.path.abspath(pdf_path)):
        report_paths = _load_scan_report_paths(db, scan)
        pdf_path = report_paths.get("json_pdf" if fmt_upper == "JSON" else "xml_pdf")

    if not pdf_path:
        raise HTTPException(
            status_code=404,
            detail=f"No {fmt_upper} PDF report is attached to this scan.",
        )

    pdf_path = os.path.abspath(pdf_path)
    reports_root = os.path.abspath(_REPORTS_DIR)
    if not os.path.isfile(pdf_path):
        raise HTTPException(status_code=404, detail="Report file not found on disk.")
    if os.path.commonpath([reports_root, pdf_path]) != reports_root:
        raise HTTPException(status_code=400, detail="Stored report path is invalid.")

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
    for path_attr in ("report_json_path", "report_xml_path", "report_pdf_path"):
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
