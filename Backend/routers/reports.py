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

from ccure_platform.api import CurrentUser, current_user_flexible
from ccure_platform.api import log_audit_event
from db.base import get_db
from ccure_platform import api as platform_api
from db.models import Scan
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
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

#: Every download format this endpoint serves, and what it resolves to.
#:
#: ``fmt=JSON`` returning the executive PDF and ``fmt=XML`` returning the
#: technical one is a historical quirk the frontend still relies on; the names
#: that say what they mean are aliases onto the same two.
#:
#: **Anything not in this table is a 400.** It used to fall through to the
#: executive PDF with HTTP 200, so ``?fmt=XLSX`` returned a PDF and looked like
#: a successful Excel export - a caller writing the bytes to a .xlsx file got
#: something Excel refuses to open, with nothing anywhere saying why. XLSX is a
#: real workbook now; the refusal for everything else stays.
_FORMAT_ALIASES = {
    "EXECUTIVE": "JSON",
    "EXECUTIVE_PDF": "JSON",
    "PDF": "JSON",
    "JSON": "JSON",
    "TECHNICAL": "XML",
    "TECHNICAL_PDF": "XML",
    "XML": "XML",
    "CSV": "CSV",
    "XLSX": "XLSX",
    "EXCEL": "XLSX",
    "WORKBOOK": "XLSX",
}

#: What a caller may ask the export endpoint for. Separate from the table above
#: because that one carries the PDF aliases and this one does not: the export
#: endpoint produces data files, and a PDF is a document.
EXPORT_FORMATS = ("xlsx", "csv", "json")

#: Which datasets the export endpoint can assemble. ``all`` is the workbook an
#: auditor wants; the individual names are for a pipeline that wants one table.
EXPORT_DATASETS = ("all", "compliance", "findings", "comparison")

#: Read by scripts/measure_export_coverage.py. A route that is deleted loses
#: its coverage credit rather than continuing to be claimed by a hand-kept list.
ROUTE_AREAS = {
    ("/reports/download/{scan_id}", "GET"): "exp.api.format_param",
    ("/reports/export/{scan_id}", "GET"): "exp.api.filters",
}

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


def _flatten_credentialed_payload(key: str, payload: dict) -> dict:
    """
    Move a credentialed scan's findings where the exporters look for them.

    ``build_legacy_scan_results`` renders the credentialed phase as
    ``{"data": [{"ip_address": ...}], "report": {...,"cves": [...]}}`` — the
    host list and the audit's own report side by side. ``build_scan_report``
    reads findings off the entries in ``data``, so on this shape it finds an
    entry carrying nothing but an address and returns **zero findings**.

    The consequence was not an empty file. ``scan_has_findings`` answered False,
    the CSV branch fell through to ``generate_host_inventory_csv``, and a
    credentialed scan's CSV download returned the *host inventory* — one row
    naming the machine — in place of the findings the scan reported. Measured
    on a real audit: 45 findings in the database, 45 in the workbook, 0 in the
    CSV, HTTP 200 either way.

    The PDF path never hit it because ``_load_scan_report_paths`` above already
    reshapes the payload before generating; this is the same reshape, applied
    where the CSV branch needs it. Any other phase is returned untouched.
    """
    if key != "credentialed" or not isinstance(payload, dict):
        return payload

    report = payload.get("report")
    if not isinstance(report, dict):
        return payload

    hosts = payload.get("data")
    hosts = list(hosts) if isinstance(hosts, list) else []

    # `reports` carries every host on a multi-host credentialed scan; `report`
    # is the first of them, kept for the consumers that predate multi-host
    # support. Prefer the complete set, and fall back to the one.
    reports = payload.get("reports")
    reports = (
        [r for r in reports if isinstance(r, dict)] if isinstance(reports, list) else []
    )
    if not reports:
        reports = [report]

    merged = []
    by_target = {str(r.get("target") or ""): r for r in reports}
    for host in hosts:
        if not isinstance(host, dict):
            continue
        # A host entry that already carries its own findings is left exactly as
        # it is. The vulnerability-audit pipeline writes them there, and
        # `build_legacy_scan_results` synthesises a *stub* report when it can
        # find no stored one — a stub whose `cves` is empty. Merging that over
        # a populated host entry deletes every finding the scan reported, which
        # is the failure this helper exists to prevent, arriving from the other
        # direction. A test pins it.
        if host.get("cves"):
            merged.append(host)
            continue

        address = str(host.get("ip_address") or host.get("ip") or "")
        host_report = by_target.get(address) or (
            reports[0] if len(reports) == 1 else None
        )
        if host_report is None or not host_report.get("cves"):
            merged.append(host)
            continue
        merged.append(
            {
                **host,
                "cves": host_report.get("cves") or [],
                "credentialed_report": host_report,
                "credentialed": True,
            }
        )

    if not merged:
        # No host list at all — synthesise one entry per report so the findings
        # are still exported rather than lost to a missing address.
        merged = [
            {
                "ip_address": r.get("target") or "",
                "cves": r.get("cves") or [],
                "credentialed_report": r,
                "credentialed": True,
            }
            for r in reports
        ]

    return {**payload, "data": merged}


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


def _require_reports_read(user: CurrentUser, db: Session) -> None:
    role = getattr(user, "role", None)
    role_name = (getattr(role, "name", "") or "").lower()

    # Keep parity with global RBAC behavior: superadmin bypass.
    if role_name == "superadmin":
        return

    if not role:
        raise HTTPException(
            status_code=403, detail="Your account does not have a role assigned."
        )

    has_reports_read = platform_api.user_has_permission(db, user, "reports", "read")

    if not has_reports_read:
        raise HTTPException(
            status_code=403,
            detail="Insufficient privileges. Your role does not have 'reports:read' permission.",
        )


def _require_reports_delete(user: CurrentUser, db: Session) -> None:
    role = getattr(user, "role", None)
    role_name = (getattr(role, "name", "") or "").lower()

    if role_name == "superadmin":
        return

    if not role:
        raise HTTPException(
            status_code=403, detail="Your account does not have a role assigned."
        )

    has_reports_delete = platform_api.user_has_permission(db, user, "reports", "delete")

    if not has_reports_delete:
        raise HTTPException(
            status_code=403,
            detail="Insufficient privileges. Your role does not have 'reports:delete' permission.",
        )


def _is_superadmin(user: CurrentUser) -> bool:
    return (
        getattr(getattr(user, "role", None), "name", "") or ""
    ).lower() == "superadmin"


def _can_read_all_org_scans(user: CurrentUser, db: Session) -> bool:
    return platform_api.user_has_permission(db, user, "scans", "read_all")


def _audit_report_download(
    db: Session, user: CurrentUser, request, scan, report_format: str
):
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
    user: CurrentUser = Depends(current_user_flexible),
):
    _require_reports_read(user, db)

    requested_fmt = str(fmt or "").strip().upper()
    resolved = _FORMAT_ALIASES.get(requested_fmt)
    if resolved is None:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported report format '{fmt}'. Supported formats: "
                "executive (PDF), technical (PDF), CSV, XLSX."
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
        payload = _flatten_credentialed_payload(key, payloads.get(key, {}))
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
            # The GAP-14 record for exactly the findings this scan reported, in
            # one query. Looked up here rather than inside the generator: the
            # generator is also called from the scan pipeline, which has no
            # session to read it with, and a report produced there must stay
            # byte-identical to the one it produced before this phase.
            from reporting.exports import finding_context_map

            try:
                context = finding_context_map(db, scan)
            except Exception as exc:  # never fail an export over an enrichment
                log.warning(
                    "Could not attach the remediation record to the CSV for "
                    "scan %s: %s",
                    scan.id,
                    exc,
                )
                context = {}
            generate_scan_csv(
                payload, csv_path, scan_type="network", remediation_context=context
            )
        else:
            generate_host_inventory_csv(payload, csv_path)

        _audit_report_download(db, user, request, scan, "CSV")

        return FileResponse(path=csv_path, media_type="text/csv", filename=csv_filename)

    if fmt_upper == "XLSX" or type_upper == "XLSX":
        # The whole scan as one workbook: benchmark verdicts, findings with
        # their remediation record, and the GAP-13 comparison against the
        # previous scan of the same shape. Filters live on /reports/export;
        # this is the unfiltered deliverable, so its counts are the scan's own.
        workbook_path, filename = _build_scan_workbook(db, scan, user=user)
        _audit_report_download(db, user, request, scan, "XLSX")
        return FileResponse(
            path=workbook_path,
            media_type=_XLSX_MEDIA_TYPE,
            filename=filename,
        )

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


# ─────────────────────────────────────────────────────────────────────────────
# Export
# ─────────────────────────────────────────────────────────────────────────────

_XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

#: Anything outside this set is dropped from a generated filename.
#:
#: The name is built from the scan number and the scan id, both of which this
#: product mints, so nothing a caller controls reaches it. The filter is here
#: anyway because "the input is trusted" is how a path separator eventually
#: gets into a Content-Disposition header, and because `filename=` on a
#: FileResponse is written into a response header where a quote or a newline is
#: a header-injection primitive rather than a cosmetic problem.
_SAFE_NAME_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
)


def _safe_export_name(*parts: str) -> str:
    """A filename built from product-minted identifiers only."""
    cleaned = []
    for part in parts:
        text = "".join(c if c in _SAFE_NAME_CHARS else "_" for c in str(part or ""))
        text = text.strip("._")
        if text:
            cleaned.append(text[:64])
    return "_".join(cleaned) or "export"


def _scan_for_user(
    db: Session, user: CurrentUser, scan_id: str, org_id: str | None = None
) -> Scan:
    """
    The scan, or 404 — under this caller's own visibility rules.

    Exactly the scoping the download endpoint has always applied: a superadmin
    sees any organisation, everybody else is confined to their own, and a user
    without ``scans:read_all`` sees only the scans they started. Expressed once
    so an export route cannot drift from it, which is the shape a cross-tenant
    export takes: not a missing check, a second copy of one that fell behind.

    404 rather than 403 for a scan in another organisation, deliberately — a
    403 would confirm the id exists.
    """
    query = db.query(Scan).filter(Scan.id == scan_id)
    if _is_superadmin(user):
        if org_id:
            query = query.filter(Scan.org_id == org_id)
    else:
        query = query.filter(Scan.org_id == user.org_id)
        if not _can_read_all_org_scans(user, db):
            query = query.filter(Scan.created_by == user.id)

    scan = query.first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


def _comparison_for(
    db: Session, scan: Scan, baseline_id: str | None, user: CurrentUser | None
):
    """
    The GAP-13 comparison for this scan, or None.

    Reuses ``compare_scans`` and ``previous_scan_for`` exactly as the comparison
    endpoint does — there is no second classification anywhere in the export
    path, so a finding cannot be exported as FIXED by a scan that did not assess
    it. That refusal lives in ``core/findings/comparison.py`` and is not
    repeated here, because a repeated rule is a rule that eventually disagrees
    with itself.

    A named baseline goes through ``_scan_for_user``: a caller must not be able
    to reach another organisation's findings by naming its scan as a baseline.

    ``limit_findings=None`` because an export is not a page. The comparison
    endpoint bounds its rows at 500 and says the counts are unbounded; a file
    that dropped every finding after the five-hundredth would be the silent
    truncation the reconciliation requirement exists to catch.
    """
    from core.findings import compare_scans
    from core.findings.comparison import previous_scan_for

    if baseline_id:
        if user is None:
            # A named baseline has to be checked against somebody's visibility.
            # No caller means no check is possible, so the baseline is refused
            # rather than resolved unchecked.
            raise HTTPException(
                status_code=400,
                detail="A baseline scan can only be named by an authenticated caller.",
            )
        baseline = _scan_for_user(db, user, baseline_id)
    else:
        baseline = previous_scan_for(db, scan)
    if baseline is None:
        return None
    return compare_scans(db, current=scan, baseline=baseline, limit_findings=None)


def _build_scan_workbook(
    db: Session, scan: Scan, *, user: CurrentUser | None = None, **filters
) -> tuple[str, str]:
    """
    Assemble the whole-scan workbook and return ``(path, filename)``.

    The comparison is against the scan's own previous run of the same shape, so
    no caller-supplied baseline is involved and no second visibility check is
    needed — ``previous_scan_for`` filters on the scan's own organisation. A
    comparison that cannot be built is logged and omitted: a workbook without a
    Scan Comparison sheet is still the benchmark verdicts and the findings, and
    losing those to a comparison failure would be the worse outcome.
    """
    from reporting.exports import export_payload, workbook_sheets
    from reporting.xlsx_generator import XlsxUnavailable, write_workbook

    try:
        comparison = _comparison_for(db, scan, None, user)
    except Exception as exc:
        log.warning(
            "Could not build the comparison for the workbook of scan %s: %s",
            scan.id,
            exc,
        )
        comparison = None

    payload = export_payload(db, scan, comparison=comparison, **filters)
    filename = _safe_export_name("scan", scan.scan_no, str(scan.id)[:12]) + ".xlsx"
    path = os.path.join(_REPORTS_DIR, filename)
    try:
        write_workbook(workbook_sheets(payload), path)
    except XlsxUnavailable as exc:
        # 503, not 500 and emphatically not a PDF. The request was valid and
        # the data exists; this deployment is missing a declared dependency,
        # and saying which one is the difference between a five-minute fix and
        # an afternoon.
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return path, filename


@router.get("/reports/export/{scan_id}")
# Heavier than a download: this assembles the verdict rows, the finding rows
# and — when asked — a full unbounded comparison, then writes a file. 10/minute
# clears the real pattern, which is an auditor pulling a workbook and then one
# or two filtered CSVs from the same scan.
@limiter.limit("10/minute")
def export_scan_dataset(
    # `request` and `response` are both required rather than decorative. The
    # limiter is built headers_enabled=True and writes X-RateLimit-* after the
    # handler returns; a handler that returns a dict — which the JSON format
    # here does — and declares neither hands slowapi None and raises on every
    # request to the route. CLAUDE.md records twenty-one routes that shipped in
    # exactly that state.
    request: Request,
    response: Response,
    scan_id: str,
    fmt: str = Query(
        "xlsx",
        description="xlsx, csv or json. An unsupported value is refused, never swapped.",
    ),
    dataset: str = Query(
        "all",
        description="all, compliance, findings or comparison.",
    ),
    asset_id: str | None = Query(None),
    host: str | None = Query(None),
    framework_id: str | None = Query(None),
    profile: str | None = Query(None),
    severity: list[str] | None = Query(None),
    verdict: list[str] | None = Query(None),
    status: list[str] | None = Query(None),
    remediation_state: list[str] | None = Query(None),
    overdue_only: bool = Query(False),
    scope: str = Query(
        "scan",
        description=(
            "scan — the findings this scan reported; asset — every finding "
            "currently held against the assets it touched."
        ),
    ),
    baseline: str | None = Query(
        None,
        description=(
            "Scan to compare against for the comparison dataset. Defaults to "
            "the most recent completed scan of the same pipeline_mode."
        ),
    ),
    include_comparison: bool = Query(True),
    org_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(current_user_flexible),
):
    """
    Export one scan's assessment results as a workbook, a CSV or JSON.

    **What the export represents.** The benchmark verdicts are the per-check
    results the Phase 3 engine produced during this scan and stored, read back
    unchanged. Nothing is re-evaluated at export time, so a control that was not
    assessed, could not be assessed, or does not apply is never rendered as
    passed or failed — the six states stay six states. The scan's own immutable
    GAP-12 policy snapshot travels on every row, so a reader can tell what was
    in scope; the *current* policy row is deliberately not consulted, because
    the policy may since have been edited and that changes nothing about what
    this scan did.

    **Filters narrow, never widen.** A framework the scan's policy excluded
    cannot be named back into the export, because the rest of that framework was
    never assessed and a partial score reads as a complete one.

    **``csv`` needs one dataset.** A CSV is one table; ``dataset=all`` with
    ``fmt=csv`` is refused rather than silently exporting whichever table
    happened to be first.
    """
    _require_reports_read(user, db)

    requested_fmt = str(fmt or "").strip().lower()
    if requested_fmt not in EXPORT_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported export format '{fmt}'. Supported formats: "
                + ", ".join(EXPORT_FORMATS)
                + "."
            ),
        )

    requested_dataset = str(dataset or "").strip().lower()
    if requested_dataset not in EXPORT_DATASETS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown dataset '{dataset}'. Available datasets: "
                + ", ".join(EXPORT_DATASETS)
                + "."
            ),
        )

    if requested_fmt == "csv" and requested_dataset == "all":
        raise HTTPException(
            status_code=400,
            detail=(
                "A CSV holds one table. Name a dataset — compliance, findings "
                "or comparison — or ask for xlsx, which carries all three as "
                "separate worksheets."
            ),
        )

    scan = _scan_for_user(db, user, scan_id, org_id)

    if (scan.status or "").lower() in ("failed", "cancelled", "canceled"):
        raise HTTPException(
            status_code=404,
            detail=(
                f"Scan {scan.scan_no} {scan.status} and produced no results to "
                "export."
                + (f" Reason: {scan.failure_reason}" if scan.failure_reason else "")
            ),
        )

    datasets = (
        ("compliance", "findings", "comparison")
        if requested_dataset == "all"
        else (requested_dataset,)
    )

    comparison = None
    if "comparison" in datasets and include_comparison:
        try:
            comparison = _comparison_for(db, scan, baseline, user)
        except HTTPException:
            raise
        except Exception as exc:  # a comparison failure must not lose the rest
            log.warning(
                "Could not build the comparison for the export of scan %s: %s",
                scan.id,
                exc,
            )
            comparison = None

    from reporting.exports import export_payload, workbook_sheets

    payload = export_payload(
        db,
        scan,
        comparison=comparison,
        datasets=datasets,
        asset_id=asset_id,
        host=host,
        framework_id=framework_id,
        profile=profile,
        severity=severity,
        verdict=verdict,
        status=status,
        remediation_state=remediation_state,
        overdue_only=overdue_only,
        scope=scope,
    )

    _audit_report_download(
        db, user, request, scan, f"export:{requested_dataset}:{requested_fmt}"
    )

    if requested_fmt == "json":
        return payload

    stem = _safe_export_name("scan", scan.scan_no, str(scan.id)[:12], requested_dataset)

    if requested_fmt == "csv":
        import csv as _csv

        block = payload["datasets"][requested_dataset]
        filename = f"{stem}.csv"
        path = os.path.join(_REPORTS_DIR, filename)
        os.makedirs(_REPORTS_DIR, exist_ok=True)
        # utf-8-sig for the same reason the findings CSV uses it: Excel reads a
        # UTF-8 file without the BOM as the local code page and renders every
        # non-ASCII character in a host name or a benchmark title as mojibake.
        with open(path, "w", newline="", encoding="utf-8-sig") as handle:
            writer = _csv.writer(handle)
            writer.writerow(block["columns"])
            for row in block["rows"]:
                writer.writerow(_csv_safe(cell) for cell in row)
        return FileResponse(path=path, media_type="text/csv", filename=filename)

    from reporting.xlsx_generator import XlsxUnavailable, write_workbook

    filename = f"{stem}.xlsx"
    path = os.path.join(_REPORTS_DIR, filename)
    try:
        write_workbook(workbook_sheets(payload), path)
    except XlsxUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return FileResponse(path=path, media_type=_XLSX_MEDIA_TYPE, filename=filename)


#: Leading characters a spreadsheet reads as the start of a formula.
_CSV_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value) -> str:
    """
    One cell, safe to open in a spreadsheet.

    The XLSX writer owns this for its own format; a CSV is opened by the same
    programs and needs the same defence. The text here is a host's own
    configuration, a benchmark title from loaded content and a note somebody
    typed, so a value beginning ``=`` is executed on open unless it is marked
    as text.

    Note this is the *new* export endpoint only. `reporting/csv_generator.py`
    is deliberately untouched on this point: changing what it writes would
    change every existing findings CSV, and altering an existing deliverable
    was not this phase's business. It is recorded in the tracker as a finding
    rather than fixed in passing.
    """
    text = "" if value is None else str(value)
    if text[:1] in _CSV_FORMULA_LEADERS:
        return "'" + text
    return text


@router.delete("/reports/{scan_id}")
def delete_report(
    scan_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(current_user_flexible),
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
