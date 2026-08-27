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
from core.audit import log_audit_event
from db.base import get_db
from db.models import Permission, RolePermission, Scan, User
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from scan_helpers import limiter
from fastapi.responses import FileResponse
from reporting.pdf_generator import ScanReportGenerator
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


def _attach_asset_lifecycle_dates(db: Session, scan: Scan, payload: dict) -> None:
    """
    Fill each exported host's ``first_seen_at`` / ``last_seen_at`` from the registry.

    The scan payload only knows about this run, so "First Seen" was blank even
    though the registry has tracked the host since its first sighting — and that
    is exactly the field that distinguishes a newly-appeared host from a
    long-known one.

    Both dates are taken from the registry deliberately. Sourcing first-seen
    from the asset row while last-seen fell back to the probe timestamp meant
    two different clocks: the asset row is written a couple of seconds after the
    probe, so a host discovered for the first time exported a First Seen that
    postdated its Last Seen.
    """
    hosts = payload.get("data")
    if not isinstance(hosts, list) or not hosts:
        return

    ips = {
        str(h.get("ip_address") or h.get("ip"))
        for h in hosts
        if isinstance(h, dict) and (h.get("ip_address") or h.get("ip"))
    }
    if not ips:
        return

    try:
        from db.models.assets import Asset

        rows = (
            db.query(Asset.ip_address, Asset.first_seen_at, Asset.last_seen_at)
            .filter(Asset.org_id == scan.org_id, Asset.ip_address.in_(ips))
            .all()
        )
        lifecycle = {str(ip): (first, last) for ip, first, last in rows}
    except Exception as exc:  # an export must not fail over an enrichment
        log.debug("Could not attach lifecycle dates for scan %s: %s", scan.id, exc)
        return

    for host in hosts:
        if not isinstance(host, dict):
            continue
        ip = str(host.get("ip_address") or host.get("ip") or "")
        first, last = lifecycle.get(ip, (None, None))
        # A host seen for the first time on this scan has first == last; never
        # let rounding or write ordering print first-seen after last-seen.
        if first and last and first > last:
            first = last
        if first and not host.get("first_seen_at"):
            host["first_seen_at"] = first.isoformat()
        if last:
            host["last_seen_at"] = last.isoformat()


def _resolve_report_path(stored: str | None) -> str | None:
    """
    Find a stored report on disk regardless of which runtime recorded it.

    The scanner worker runs on the Windows host and writes
    ``C:\\...\\Backend\\reports\\x.pdf``; the API serves the same directory from
    a container as ``/app/reports/x.pdf``. A stored path from one is never
    ``os.path.isfile()`` in the other, so the API treated every worker-generated
    report as missing and rebuilt it. Both agree on the file *name*, so resolve
    by basename inside the API's own reports directory before giving up.
    """
    if not stored:
        return None
    if os.path.isfile(os.path.abspath(stored)):
        return os.path.abspath(stored)

    basename = os.path.basename(stored.replace("\\", "/"))
    if not basename:
        return None
    candidate = os.path.join(_REPORTS_DIR, basename)
    return candidate if os.path.isfile(candidate) else None


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


def _audit_report_download(db: Session, user: User, request, scan, report_format: str):
    """
    Record that a report left the platform.

    This used to construct ``AuditLog(...)`` inline — a name never imported
    into this module, so every call raised ``NameError`` before it could even
    reach the three other defects in the same statement (``target`` and
    ``details`` are not columns, and ``org_id`` is NOT NULL *and* part of the
    primary key but was never set). A bare ``except Exception: pass`` swallowed
    it, so **no report download ever produced an audit row**.

    The exception guard stays, because failing to audit must not deny a caller
    a file they are entitled to — but it now logs instead of discarding, which
    is the part that let the original defect survive.
    """
    try:
        log_audit_event(
            db=db,
            user=user,
            action="report.downloaded",
            resource_type="scan",
            resource_id=str(scan.id),
            changes={"scan_no": scan.scan_no, "format": report_format},
            request=request,
        )
        db.commit()
    except Exception as exc:
        db.rollback()
        log.warning(
            "Could not audit report download for scan %s: %s",
            scan.id,
            exc.__class__.__name__,
        )


@router.get("/reports/download/{scan_id}")
# Normally this streams a file that already exists, which is cheap. It
# regenerates when the stored PDF is missing, and that path renders the whole
# report inside the request — so the cost of a call is not something the caller
# can see and is not something this endpoint can predict. Bounded accordingly.
# 20/minute clears the real pattern, which is a user pulling the executive PDF,
# the technical PDF and the CSV for a couple of scans in a row.
@limiter.limit("20/minute")
def download_report(
    request: Request,
    scan_id: str,
    fmt: str = "JSON",
    type: Optional[str] = None,
    min_severity: str = "Info",
    ticket: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user_flexible),
):
    _require_reports_read(user, db)

    # `fmt=JSON` returning the executive PDF and `fmt=XML` returning the
    # technical one is a historical quirk the frontend still relies on. Accept
    # names that say what they mean, and keep the old ones working.
    _FORMAT_ALIASES = {
        "EXECUTIVE": "JSON",
        "EXECUTIVE_PDF": "JSON",
        "PDF": "JSON",
        "JSON": "JSON",
        "TECHNICAL": "XML",
        "TECHNICAL_PDF": "XML",
        "XML": "XML",
        "CSV": "CSV",
    }
    requested_fmt = str(fmt or "").strip().upper()
    resolved = _FORMAT_ALIASES.get(requested_fmt)
    if resolved is None:
        # Anything unrecognised used to fall through to the executive PDF with
        # HTTP 200, so `?fmt=XLSX` returned a PDF and looked like a successful
        # Excel export. There is no Excel exporter; say so.
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported report format '{fmt}'. Supported formats: "
                "executive (PDF), technical (PDF), CSV."
            ),
        )
    fmt = resolved

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

    # A scan that never produced results has nothing to export. Returning a
    # 200 with an empty file made a failed scan look like a successful download.
    if (scan.status or "").lower() in ("failed", "cancelled", "canceled"):
        raise HTTPException(
            status_code=404,
            detail=(
                f"Scan {scan.scan_no} {scan.status} and produced no results to export."
                + (f" Reason: {scan.failure_reason}" if scan.failure_reason else "")
            ),
        )

    # Determine target report format and media type
    if fmt_upper == "CSV" or type_upper == "CSV":
        # CSV Export Generation
        payloads = build_legacy_scan_results(db, str(scan.id))
        # Prefer the richest phase actually present. phase2 was previously
        # skipped entirely, so an Asset Discovery scan exported its Phase 1
        # payload and silently dropped every port and service it had found.
        key = next(
            (
                k
                for k in ("credentialed", "phase3", "phase2", "phase1")
                if isinstance(payloads.get(k), dict)
            ),
            None,
        )
        if key is None:
            raise HTTPException(
                status_code=404, detail="No results are available for this scan."
            )
        payload = payloads.get(key, {})
        _attach_asset_lifecycle_dates(db, scan, payload)
        csv_filename = f"scan_{scan.scan_no}_{scan_id[:8]}.csv"
        csv_path = os.path.join(_REPORTS_DIR, csv_filename)
        from reporting.csv_generator import (
            generate_host_inventory_csv,
            generate_scan_csv,
            scan_has_findings,
        )

        # Host discovery produces hosts and no findings by design. Running the
        # findings exporter over it wrote a header row and nothing else, so the
        # CSV export returned zero of the hosts the scan had just discovered.
        if scan_has_findings(payload):
            generate_scan_csv(payload, csv_path, scan_type="network")
        else:
            generate_host_inventory_csv(payload, csv_path)

        _audit_report_download(db, user, request, scan, "CSV")

        return FileResponse(path=csv_path, media_type="text/csv", filename=csv_filename)

    # Standard PDF Report Generation (Executive vs Technical Audit)
    is_technical = fmt_upper == "XML" or type_upper in ("TECHNICAL", "XML")

    # Serve the report the scan already produced. Regenerating unconditionally
    # rebuilt *both* PDFs on every download, orphaned the previous pair on disk
    # with no cleanup, and bumped scans.updated_at — which made Scan History
    # display the download time as the scan date. Generation is now the
    # fallback it was always documented to be.
    pdf_path = _resolve_report_path(
        scan.report_technical_path if is_technical else scan.report_executive_path
    )

    if not pdf_path:
        report_paths = _load_scan_report_paths(db, scan)
        pdf_path = _resolve_report_path(
            report_paths.get("technical_pdf" if is_technical else "executive_pdf")
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

    _audit_report_download(
        db, user, request, scan, "technical_pdf" if is_technical else "executive_pdf"
    )

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
