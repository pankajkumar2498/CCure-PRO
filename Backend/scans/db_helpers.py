"""
scans/db_helpers.py
───────────────────────────────────────────────────────────────────────────────
Functions called from main.py endpoints to create / update Scan rows
and track execution phases natively in the production PostgreSQL schema.

Automatically runs Identity Resolution (AssetSyncer) internally.
"""

import logging
from datetime import timedelta
from typing import Any, List, Optional

from ccure_platform.api import log_audit_event
from db.base import gen_scan_id, gen_scan_phase_id, utcnow
from ccure_platform import api as platform_api
from db.models.scans import Scan, ScanPhase
from scans.notification_vocabulary import (
    AuditNotificationCategory,
    AuditNotificationType,
)
from scans.db_text import sanitize_for_db
from scans.asset_syncer import (
    sync_asset_discovery,
    sync_host_discovery,
    sync_vulnerability_audit,
)
from sqlalchemy import func, text
from sqlalchemy.orm import Session

log = logging.getLogger("ccure.scans.db_helpers")


def _sanitize_jsonb_value(value: Any) -> Any:
    """
    Network probe output can contain NUL/binary control bytes from SNMP, banners,
    or service scripts. PostgreSQL JSONB rejects those characters, so clean the
    payload at the persistence boundary without changing scan execution.

    The finding sync applies the same rule to the host records it writes
    (``scans.db_text``); both must agree on what is unsafe.
    """
    return sanitize_for_db(value)


def _phase_summary_payload(summary: dict, hosts_data: list) -> dict:
    return _sanitize_jsonb_value({**(summary or {}), "_phase_data": hosts_data or []})


def _public_phase_summary(summary: Any) -> dict:
    if not isinstance(summary, dict):
        return {}
    return {
        key: value for key, value in summary.items() if not str(key).startswith("_")
    }


def _get_org_scoped_scan(db: Session, scan_id: str, user_id: str) -> Scan | None:
    org_id = _get_org_id(db, user_id)
    return db.query(Scan).filter(Scan.id == scan_id, Scan.org_id == org_id).first()


def _get_org_id(db: Session, user_id: str) -> str:
    user = platform_api.user(db, user_id)
    if not user:
        raise ValueError(f"User {user_id} not found in DB")
    return str(user.org_id)


def _next_scan_no(db: Session, org_id: str, user_id: str) -> int:
    """
    Return the next human-facing scan number for the organization.

    UUID remains the real object identity; scan_no is only for display,
    support, reports, and database lookups by humans. Numbers are global
    within an org so different users cannot produce duplicate scan numbers.
    """
    if db.bind and db.bind.dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
            {"lock_key": f"scan_no:{org_id}"},
        )

    current = db.query(func.max(Scan.scan_no)).filter(Scan.org_id == org_id).scalar()
    return int(current or 0) + 1


def create_scan(
    db: Session,
    user_id: str,
    target: str,
    targets: list[str],
    scan_type: str,
    pipeline_mode: str = "basic",
    current_task_id: str | None = None,
    org_id: str | None = None,
) -> Scan:
    """Create an empty running scan before Phase 1 starts."""
    if not org_id:
        org_id = _get_org_id(db, user_id)
    org = platform_api.organisation(db, org_id)
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
        current_task_id=current_task_id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    user = platform_api.user(db, user_id)
    if user:
        log_audit_event(
            db=db,
            user=user,
            action="scan.created",
            resource_type="scan",
            resource_id=str(scan.id),
            changes={
                "scan_no": scan.scan_no,
                "pipeline_mode": pipeline_mode,
                "targets": targets,
            },
        )
        db.commit()

    return scan


def update_scan_phase1(
    db: Session,
    scan_id: str,
    user_id: str,
    phase1_data: dict,
    is_final: bool = False,
    report_executive_path: str | None = None,
    report_technical_path: str | None = None,
) -> Scan | None:
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

    total = summary.get("total_hosts", 0)
    active = summary.get("active_hosts", 0)

    scan.total_hosts = total
    scan.active_hosts = active

    # A user cancellation that lands while this phase is being written back must
    # win: recording 'complete' here would overwrite what the user asked for and
    # make the Stop button look like it did nothing.
    was_cancelled = scan.status in ("cancelled", "canceled", "cancelling")

    if not was_cancelled:
        # Default terminal status
        scan.status = "complete" if is_final else "running"

        # ATOMIC UNREACHABLE DETECTION
        if active == 0 and total > 0:
            scan.status = "unreachable"
            scan.completed_at = utcnow()

    if was_cancelled or is_final or scan.status == "unreachable":
        scan.completed_at = utcnow()

    scan.duration_seconds = duration
    if report_executive_path:
        scan.report_executive_path = report_executive_path
    if report_technical_path:
        scan.report_technical_path = report_technical_path

    # Full payload embedded in summary
    full_summary = _phase_summary_payload(summary, hosts_data)

    # This row is written after the phase has already run, so utcnow() is the
    # completion time. Deriving the start from the measured duration keeps
    # started_at meaningful instead of making every phase look instantaneous.
    phase_completed_at = utcnow()
    phase_started_at = phase_completed_at - timedelta(seconds=duration or 0.0)

    phase_row = ScanPhase(
        id=gen_scan_phase_id(scan.id, "host_discovery"),
        scan_id=scan.id,
        phase_key="host_discovery",
        phase_order=1,
        status="cancelled" if was_cancelled else "complete",
        duration_seconds=duration,
        hosts_processed=len(hosts_data),
        summary=full_summary,
        started_at=phase_started_at,
        completed_at=phase_completed_at,
    )
    db.add(phase_row)
    db.flush()

    db.commit()
    db.refresh(scan)

    if is_final:
        user = platform_api.user(db, scan.created_by)
        if user:
            log_audit_event(
                db=db,
                user=user,
                action="scan.completed",
                resource_type="scan",
                resource_id=str(scan.id),
                changes={
                    "scan_no": scan.scan_no,
                    "target": scan.target_str,
                    "duration_seconds": duration,
                    "phase": 1,
                },
            )
            db.commit()

    # Asset Sync in background (AFTER commit to avoid FK race condition)
    from core.celery_app import registered_task
    from core.task_names import SYNC_HOST_DISCOVERY

    registered_task(SYNC_HOST_DISCOVERY).delay(
        str(scan.id), org_id, user_id, hosts_data
    )

    if is_final:
        try:
            from ccure_platform.api import (
                NotificationCategory,
                create_notification,
            )

            create_notification(
                db=db,
                user_id=scan.created_by,
                notification_type=AuditNotificationType.SCAN_COMPLETED,
                category=AuditNotificationCategory.SCAN,
                title=f"Scan {scan.scan_no} Completed",
                message=f"Host Discovery scan on {scan.target_str} has finished. Found {scan.active_hosts} active hosts.",
                related_scan_id=str(scan.id),
            )
        except Exception:
            pass  # Silent fail for notifications

    return scan


def update_scan_phase(
    db: Session,
    scan_id: str,
    user_id: str,
    phase: int,
    phase_data: dict,
    is_final: bool = False,
    pipeline_mode: str | None = None,
    report_executive_path: str | None = None,
    report_technical_path: str | None = None,
) -> Scan | None:
    """
    Called after /scan/asset-discovery (phase=2) or /scan/vulnerability-audit (phase=3).
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
    if report_executive_path:
        scan.report_executive_path = report_executive_path
    if report_technical_path:
        scan.report_technical_path = report_technical_path

    # Keep duration rolling
    scan.duration_seconds = (scan.duration_seconds or 0.0) + duration

    # ENTERPRISE FIX: Preserve 'unreachable' status if already set by Phase 1
    if is_final:
        if scan.status != "unreachable":
            scan.status = "complete"
        scan.completed_at = utcnow()
    else:
        # Do not revert a terminal scan status (complete, unreachable, failed, cancelled) back to running
        if scan.status not in ("complete", "unreachable", "failed", "cancelled"):
            scan.status = "running"

    # Track phase
    phase_key_map = {
        2: "asset_discovery",
        3: "vulnerability_assessment",
        4: "topology_mapping",
        5: "credentialed",
    }
    phase_key = phase_key_map.get(phase, f"phase{phase}")

    # Embed raw data into summary to ensure 100% historical fidelity without schema changes
    full_summary_payload = _phase_summary_payload(summary, hosts_data)

    # SaaS Stability: Use a robust Upsert-style logic to prevent crash on redundant triggers
    try:
        phase_row = (
            db.query(ScanPhase)
            .filter(ScanPhase.scan_id == scan.id, ScanPhase.phase_key == phase_key)
            .first()
        )
        now = utcnow()
        # This row is written once the phase has finished, so now() is the
        # completion time. Writing it to started_at as well made every phase
        # look instantaneous — wall-clock delta 0 against a duration of two
        # minutes. Derive the start from the measured duration, matching
        # update_scan_phase1().
        phase_started_at = now - timedelta(seconds=duration or 0.0)
        if phase_row:
            # Update existing row
            phase_row.phase_order = phase
            phase_row.status = "complete"
            phase_row.duration_seconds = duration
            phase_row.hosts_processed = len(hosts_data)
            phase_row.summary = full_summary_payload
            phase_row.completed_at = now
            phase_row.updated_at = now
            if not phase_row.started_at or phase_row.started_at >= now:
                phase_row.started_at = phase_started_at
            db.commit()
        else:
            # Try to insert new row
            phase_row = ScanPhase(
                id=gen_scan_phase_id(scan.id, phase_key),
                scan_id=scan.id,
                phase_key=phase_key,
                phase_order=phase,
                status="complete",
                duration_seconds=duration,
                hosts_processed=len(hosts_data),
                summary=full_summary_payload,
                started_at=phase_started_at,
                completed_at=now,
            )
            db.add(phase_row)
            db.commit()
    except Exception:
        # If a collision occurred (another worker finished first), just update the existing one
        db.rollback()
        db.query(ScanPhase).filter(
            ScanPhase.scan_id == scan.id, ScanPhase.phase_key == phase_key
        ).update(
            {
                "status": "complete",
                "duration_seconds": duration,
                "hosts_processed": len(hosts_data),
                "summary": full_summary_payload,
                "updated_at": utcnow(),
            }
        )
        db.commit()

    findings_synced = False

    if is_final:
        from scan_helpers import resolve_pipeline_mode

        current_mode = resolve_pipeline_mode(pipeline_mode or scan.pipeline_mode)

        if current_mode == "vulnerability_audit":
            # Update denormalized vuln counts on Scan row for dashboard performance.
            #
            # Verification records a severity breakdown per host, computed from
            # each CVE's published vector — the same numbers the report prints.
            # Tallying the raw ``severity`` field here instead produced a
            # dashboard that disagreed with the report for any record whose
            # feed-supplied rating differs from its vector, and counted nothing
            # at all for records that carry a vector but no severity string.
            counted_from_verification = False
            critical_count = high_count = medium_count = low_count = info_count = 0
            for h in hosts_data:
                counts = h.get("vulnerability_counts")
                if not isinstance(counts, dict) or not counts:
                    continue
                counted_from_verification = True
                critical_count += int(counts.get("Critical") or 0)
                high_count += int(counts.get("High") or 0)
                medium_count += int(counts.get("Medium") or 0)
                low_count += int(counts.get("Low") or 0)
                # "None" is a published score of 0.0; "Unscored" is a CVE the
                # feed carries no score for at all. Both are findings on the
                # host and both were being dropped from the scan's total, so
                # `scans.total_vulns` read lower than the number of rows the
                # same scan wrote — a CVE with no published CVSS is still a CVE.
                info_count += int(counts.get("None") or 0) + int(
                    counts.get("Unscored") or 0
                )

            if not counted_from_verification:
                # Payload from before verification recorded counts, or a scan
                # type that does not produce them.
                all_vulns = []
                for h in hosts_data:
                    all_vulns.extend(h.get("vulnerabilities") or h.get("cves") or [])

                def _tally(tier: str) -> int:
                    return sum(
                        1
                        for v in all_vulns
                        if str(v.get("severity", "")).lower() == tier
                    )

                critical_count = _tally("critical")
                high_count = _tally("high")
                medium_count = _tally("medium")
                low_count = _tally("low")
                info_count = _tally("none") + _tally("unscored") + _tally("info")

            scan.critical_count = critical_count
            scan.high_count = high_count
            scan.medium_count = medium_count
            scan.low_count = low_count
            scan.info_count = info_count
            scan.total_vulns = (
                critical_count + high_count + medium_count + low_count + info_count
            )
        else:
            scan.critical_count = 0
            scan.high_count = 0
            scan.medium_count = 0
            scan.low_count = 0
            scan.total_vulns = 0

        # The tally is committed before the sync runs, so a sync failure cannot
        # roll the counts back out with it.
        db.commit()

        # ── Persist findings before the scan is called complete ───────────────
        # The asset sync used to be dispatched asynchronously *after* the status
        # was committed as "complete". Anything reading on that signal — the
        # dashboard, the findings API, an integration polling for the terminal
        # state — saw the previous scan's rows for as long as the sync took,
        # which on a credentialed scan of a few thousand findings is many
        # seconds. "Complete" has to mean the results are queryable.
        #
        # Placed *after* the severity tally above, and deliberately so: the sync
        # mutates the host records it is given, and running it first left the
        # tally reading hosts whose ``vulnerability_counts`` had already been
        # consumed, so a scan that wrote 2,674 findings reported a total of 0.
        # The phase row is committed further up, so the foreign-key targets this
        # needs already exist.
        if phase >= 3:
            try:
                sync_vulnerability_audit(db, str(scan.id), org_id, user_id, hosts_data)
                findings_synced = True
            except Exception:
                db.rollback()
                log.exception(
                    "Inline finding sync failed for scan %s; falling back to the "
                    "asynchronous path",
                    scan.id,
                )

        # ENTERPRISE FIX: Do not overwrite 'unreachable' status with 'complete'
        if scan.status != "unreachable":
            scan.status = "complete"

    db.commit()
    db.refresh(scan)

    if is_final:
        user = platform_api.user(db, scan.created_by)
        if user:
            log_audit_event(
                db=db,
                user=user,
                action="scan.completed",
                resource_type="scan",
                resource_id=str(scan.id),
                changes={
                    "scan_no": scan.scan_no,
                    "target": scan.target_str,
                    "duration_seconds": scan.duration_seconds,
                    "phase": phase,
                },
            )
            db.commit()

    # Synchronization (AFTER commit to avoid FK race condition)
    if phase == 2:
        from core.celery_app import registered_task
        from core.task_names import SYNC_ASSET_DISCOVERY

        registered_task(SYNC_ASSET_DISCOVERY).delay(
            str(scan.id), org_id, user_id, hosts_data
        )
    elif phase >= 3 and not findings_synced:
        # Reached only for a non-final phase-3 update, or when the inline sync
        # above failed and the work still has to happen.
        from core.celery_app import registered_task
        from core.task_names import SYNC_VULNERABILITY_AUDIT

        registered_task(SYNC_VULNERABILITY_AUDIT).delay(
            str(scan.id), org_id, user_id, hosts_data
        )

    if is_final:
        try:
            from ccure_platform.api import (
                NotificationCategory,
                create_notification,
                fan_out_notification,
            )

            # Additional logic: if critical vulns were found, send a Security notification
            if getattr(scan, "critical_count", 0) > 0:
                create_notification(
                    db=db,
                    user_id=scan.created_by,
                    notification_type=AuditNotificationType.VULNERABILITY_FOUND,
                    category=NotificationCategory.SECURITY,
                    title="Critical Vulnerabilities Found",
                    message=f"Scan {scan.scan_no} on {scan.target_str} discovered {scan.critical_count} critical vulnerabilities.",
                    related_scan_id=str(scan.id),
                )

                # ESCALATION RULE: Fan-out to leadership
                fan_out_notification(
                    db=db,
                    org_id=str(scan.org_id),
                    permission_key="audit.scan.lifecycle",
                    notification_type=AuditNotificationType.VULNERABILITY_FOUND,
                    category=NotificationCategory.SECURITY,
                    title="Critical Vulnerabilities Found",
                    message=f"Scan {scan.scan_no} on {scan.target_str} discovered {scan.critical_count} critical vulnerabilities.",
                    related_scan_id=str(scan.id),
                    exclude_user_id=str(scan.created_by),
                )
            else:
                create_notification(
                    db=db,
                    user_id=scan.created_by,
                    notification_type=AuditNotificationType.SCAN_COMPLETED,
                    category=AuditNotificationCategory.SCAN,
                    title=f"Scan {scan.scan_no} Completed",
                    message=f"Scan on {scan.target_str} has finished successfully.",
                    related_scan_id=str(scan.id),
                )
        except Exception:
            pass

    return scan


def mark_scan_cancelled(
    db: Session,
    scan_id: str,
    user_id: str,
    phase_key: str | None = None,
) -> Scan | None:
    """
    Settle a scan that the user cancelled while it was running.

    The stop endpoint already flipped ``status`` to ``cancelled``; this records
    when it actually stopped and closes any phase row still marked running, so
    a cancelled scan does not leave a phase that looks stuck forever.
    """
    scan = _get_org_scoped_scan(db, scan_id, user_id)
    if not scan:
        return None

    scan.status = "cancelled"
    if not scan.completed_at:
        scan.completed_at = utcnow()
    if scan.started_at and scan.duration_seconds is None:
        scan.duration_seconds = (scan.completed_at - scan.started_at).total_seconds()
    scan.updated_at = utcnow()

    for phase in scan.phases:
        if phase.status not in ("complete", "failed", "skipped", "cancelled"):
            if phase_key and phase.phase_key != phase_key:
                continue
            phase.status = "cancelled"
            phase.completed_at = utcnow()
            if phase.started_at and phase.duration_seconds is None:
                phase.duration_seconds = (
                    phase.completed_at - phase.started_at
                ).total_seconds()

    db.commit()
    db.refresh(scan)
    return scan


def mark_scan_failed(
    db: Session,
    scan_id: str,
    user_id: str,
    reason: str,
    status: str = "failed",
) -> Scan | None:
    scan = _get_org_scoped_scan(db, scan_id, user_id)
    if not scan:
        return None

    scan.status = status
    scan.failure_reason = reason
    scan.completed_at = utcnow()

    db.commit()
    db.refresh(scan)

    user = platform_api.user(db, scan.created_by)
    if user:
        log_audit_event(
            db=db,
            user=user,
            action=f"scan.{status}",
            resource_type="scan",
            resource_id=str(scan.id),
            changes={
                "reason": reason,
            },
            status="failure",
        )
        db.commit()

    try:
        from ccure_platform.api import (
            NotificationCategory,
            create_notification,
        )

        ntype = AuditNotificationType.SCAN_FAILED
        title = f"Scan {scan.scan_no} Failed"
        if status == "unreachable":
            title = f"Scan {scan.scan_no} Unreachable"

        create_notification(
            db=db,
            user_id=scan.created_by,
            notification_type=ntype,
            category=AuditNotificationCategory.SCAN,
            title=title,
            message=f"Scan on {scan.target_str} {status}: {reason}",
            related_scan_id=str(scan.id),
        )
    except Exception:
        pass

    return scan


def create_completed_scan(
    db: Session,
    user_id: str,
    target: str,
    targets: list[str] | None,
    scan_type: str,
    phase: int,
    results: dict,
    summary: dict,
    scan_duration: float | None = None,
    report_executive_path: str | None = None,
    report_technical_path: str | None = None,
    pipeline_mode: str = "vulnerability_audit",
    scan_id: str | None = None,
    commit: bool = True,
) -> Scan:
    """Fallback capability for bulk-loading a fully complete scan (used by credentialed scans)."""
    base_targets = targets or [target]

    if scan_id:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        org_id = str(scan.org_id)
        org = platform_api.organisation(db, org_id)
        org_slug = org.slug if org else org_id

        if scan.status != "unreachable":
            scan.status = "complete"
        scan.completed_at = utcnow()
        scan.duration_seconds = scan_duration or summary.get("scan_duration", 0.0)
        scan.total_hosts = summary.get("total_hosts", 0)
        scan.active_hosts = summary.get("active_hosts", 0)
        scan.report_executive_path = report_executive_path
        scan.report_technical_path = report_technical_path
        scan.pipeline_mode = pipeline_mode or scan.pipeline_mode
        scan.total_vulns = summary.get("total_vulns", scan.total_vulns or 0)
        scan.critical_count = summary.get("critical_count", scan.critical_count or 0)
        scan.high_count = summary.get("high_count", scan.high_count or 0)
        scan.medium_count = summary.get("medium_count", scan.medium_count or 0)
        scan.low_count = summary.get("low_count", scan.low_count or 0)
        scan.info_count = summary.get("info_count", scan.info_count or 0)
    else:
        org_id = _get_org_id(db, user_id)
        org = platform_api.organisation(db, org_id)
        org_slug = org.slug if org else org_id

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
            total_vulns=summary.get("total_vulns", 0),
            critical_count=summary.get("critical_count", 0),
            high_count=summary.get("high_count", 0),
            medium_count=summary.get("medium_count", 0),
            low_count=summary.get("low_count", 0),
            info_count=summary.get("info_count", 0),
            report_executive_path=report_executive_path,
            report_technical_path=report_technical_path,
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
        phase_order = (
            3
            if phase_key == "credentialed"
            else int(phase_key.replace("phase", "") or 0)
        )
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
            completed_at=utcnow(),
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
            sync_vulnerability_audit(db, str(scan.id), org_id, user_id, hosts_data)

    if commit:
        db.commit()
        db.refresh(scan)

    user = platform_api.user(db, scan.created_by)
    if user:
        log_audit_event(
            db=db,
            user=user,
            action="scan.created",
            resource_type="scan",
            resource_id=str(scan.id),
            changes={
                "scan_no": scan.scan_no,
                "pipeline_mode": pipeline_mode,
                "targets": base_targets,
            },
        )
        log_audit_event(
            db=db,
            user=user,
            action="scan.completed",
            resource_type="scan",
            resource_id=str(scan.id),
            changes={
                "scan_no": scan.scan_no,
                "target": scan.target_str,
                "duration_seconds": scan.duration_seconds,
                "phase": phase,
            },
        )
        if commit:
            db.commit()

    try:
        from ccure_platform.api import (
            NotificationCategory,
            create_notification,
            fan_out_notification,
        )

        # Check if credentialed report has criticals
        vulns = (
            (scan.options or {})
            .get("credentialed_report", {})
            .get("vulnerabilities", [])
        )
        critical_count = sum(
            1 for v in vulns if str(v.get("severity", "")).lower() == "critical"
        )

        if critical_count > 0:
            create_notification(
                db=db,
                user_id=scan.created_by,
                notification_type=AuditNotificationType.VULNERABILITY_FOUND,
                category=NotificationCategory.SECURITY,
                title="Critical Vulnerabilities Found",
                message=f"Credentialed scan {scan.scan_no} on {scan.target_str} discovered {critical_count} critical vulnerabilities.",
                related_scan_id=str(scan.id),
            )

            # ESCALATION RULE: Fan-out to leadership
            fan_out_notification(
                db=db,
                org_id=str(scan.org_id),
                permission_key="audit.scan.lifecycle",
                notification_type=AuditNotificationType.VULNERABILITY_FOUND,
                category=NotificationCategory.SECURITY,
                title="Critical Vulnerabilities Found",
                message=f"Credentialed scan {scan.scan_no} on {scan.target_str} discovered {critical_count} critical vulnerabilities.",
                related_scan_id=str(scan.id),
                exclude_user_id=str(scan.created_by),
            )
        else:
            create_notification(
                db=db,
                user_id=scan.created_by,
                notification_type=AuditNotificationType.SCAN_COMPLETED,
                category=AuditNotificationCategory.SCAN,
                title=f"Scan {scan.scan_no} Completed",
                message=f"Credentialed scan on {scan.target_str} has finished successfully.",
                related_scan_id=str(scan.id),
            )
    except Exception:
        pass

    # Automatically reconcile newly synced scan discoveries against AMT inventory
    if commit:
        try:
            from core.amt_reconciliation import reconcile_amt_inventory

            reconcile_amt_inventory(db, org_id)
        except Exception as amt_exc:
            import logging

            logging.getLogger("ccure.scans.db_helpers").warning(
                "Post-scan AMT reconciliation failed for org %s: %s", org_id, amt_exc
            )

    return scan
