"""
SNMP topology mapping: the task, and the rule deciding when a finished scan
chains it.

Split from core/tasks.py in G1 (C2, docs/architecture/MODULAR_REFACTORING_LOG.md
§6), unchanged. Logs under ``ccure.tasks``, as the hub did.
"""

import logging
from config import AppConfig
from core.celery_app import celery_app
from db.base import SessionLocal
from db.models import Scan
from ccure_platform import api as platform_api
from scans.tasks.common import _check_cancelled, _finalize_cancelled, _update_task_id

log = logging.getLogger("ccure.tasks")


def _should_chain_topology(scan_row) -> bool:
    """
    Check if topology mapping should be chained after the current phase.
    Returns True only if SNMP credentials are configured in scan.options.
    """
    if not scan_row or not scan_row.options:
        return False
    snmp_config = scan_row.options.get("snmp")
    if not snmp_config:
        return False
    # Require at least a community string (v1/v2c) or username (v3)
    version = str(snmp_config.get("version") or "").lower()
    if version in ("v1", "v2c"):
        return bool(snmp_config.get("community"))
    elif version == "v3":
        return bool(snmp_config.get("username"))
    # If version is unspecified but community exists, assume v2c
    return bool(snmp_config.get("community"))


def _chain_topology_if_needed(
    db, scan_id: str, user_id: str, scan_row=None
) -> str | None:
    """
    If SNMP is configured, dispatch the topology mapping task.
    Returns the chained task ID or None if topology was not triggered.
    """
    if scan_row is None:
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()

    if not _should_chain_topology(scan_row):
        return None

    log.info("Chaining topology mapping for scan_id=%s (SNMP configured)", scan_id)

    next_task = run_topology_mapping_task.delay(
        scan_id=scan_id,
        user_id=user_id,
    )
    db.query(Scan).filter(Scan.id == scan_id).update({"current_task_id": next_task.id})
    db.commit()

    return next_task.id


@celery_app.task(
    name="ccure.tasks.run_topology_mapping",
    queue="scanner",
    bind=True,
    soft_time_limit=AppConfig.SCAN_TIME_LIMIT_TOPOLOGY,
    time_limit=AppConfig.SCAN_TIME_LIMIT_TOPOLOGY
    + AppConfig.SCAN_TIME_LIMIT_HARD_MARGIN,
)
def run_topology_mapping_task(
    self,
    scan_id: str,
    user_id: str,
):
    """
    Phase 4 Background Task — Network Topology Mapping.

    Runs SNMP walks against discovered hosts, correlates ARP/LLDP/CDP/FDB
    results into NetworkLink records, and persists them to the database.

    This task is ONLY chained when SNMP credentials are configured.
    It does NOT affect the scan's completion status — the scan is already
    marked 'complete' by the terminal core phase.
    """
    db = SessionLocal()
    try:
        _update_task_id(db, scan_id, self.request.id)
        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled before topology mapping", scan_id)
            _finalize_cancelled(db, scan_id, user_id, phase="topology_mapping")
            return {"success": False, "cancelled": True, "error": "Scan cancelled"}

        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan_row:
            log.error("Scan %s not found for topology mapping", scan_id)
            return {"success": False, "error": "Scan not found"}

        snmp_config = (scan_row.options or {}).get("snmp", {})
        if not snmp_config:
            log.warning(
                "Topology mapping triggered but no SNMP config on scan %s", scan_id
            )
            return {"success": True, "skipped": True, "reason": "No SNMP configuration"}

        # Determine org_id
        user = platform_api.user(db, user_id)
        org_id = str(scan_row.org_id or (user.org_id if user else ""))

        # Determine target IPs from discovered active hosts
        target_ips = []
        from db.models import ScanPhase

        # Get the most recent phase data to extract discovered IPs
        for phase_key in (
            "vulnerability_assessment",
            "asset_discovery",
            "host_discovery",
        ):
            phase = (
                db.query(ScanPhase)
                .filter(ScanPhase.scan_id == scan_id, ScanPhase.phase_key == phase_key)
                .first()
            )
            if phase and phase.summary:
                hosts = phase.summary.get("hosts_data", [])
                for host in hosts:
                    ip = host.get("ip_address") or host.get("ip")
                    if ip and host.get("is_active"):
                        target_ips.append(ip)
                if target_ips:
                    break

        # Fallback to scan target_hosts
        if not target_ips and scan_row.target_hosts:
            target_ips = scan_row.target_hosts

        if not target_ips:
            log.warning("No target IPs for topology mapping on scan %s", scan_id)
            return {"success": True, "skipped": True, "reason": "No target IPs"}

        # Emit progress
        from core.redis_client import publish_progress_sync

        publish_progress_sync(
            scan_id,
            4,
            {
                "status": "running",
                "message": f"Walking {len(target_ips)} targets via SNMP...",
                "percentage": 10,
                "total_targets": len(target_ips),
            },
        )

        # Run the topology engine. Link ids are derived from the organisation's
        # slug, which the task looks up so the engine needs no platform import
        # (B6). An organisation that no longer exists falls back to its id, as
        # the engine did before.
        from core.topology.engine import run_topology_mapping

        organisation = platform_api.organisation(db, org_id)
        result = run_topology_mapping(
            db=db,
            scan_id=scan_id,
            org_id=org_id,
            snmp_config=snmp_config,
            target_ips=target_ips,
            org_slug=organisation.slug if organisation else org_id,
        )

        # Update scan phase record
        from scans.db_helpers import update_scan_phase

        update_scan_phase(
            db=db,
            scan_id=scan_id,
            user_id=user_id,
            phase=4,
            phase_data={
                "data": [],
                "summary": {
                    "total_links": result.get("total_links", 0),
                    "links_created": result.get("links_created", 0),
                    "links_updated": result.get("links_updated", 0),
                    "targets_walked": result.get("targets_walked", 0),
                    "targets_offered": len(target_ips),
                    "assets_enrolled": result.get("assets_enrolled", 0),
                    "errors": result.get("errors", []),
                },
                "metadata": {"phase": "topology_mapping"},
            },
            is_final=False,  # Phase 4 never marks the scan complete
            pipeline_mode=scan_row.pipeline_mode,
        )

        # Final progress push
        publish_progress_sync(
            scan_id,
            4,
            {
                "status": "complete",
                "message": f"Topology mapping complete: {result.get('total_links', 0)} links discovered",
                "percentage": 100,
                "total_links": result.get("total_links", 0),
            },
        )

        log.info(
            "Topology mapping complete for scan=%s: %d links",
            scan_id,
            result.get("total_links", 0),
        )
        return {"success": True, "scan_id": scan_id, **result}

    except Exception as exc:
        log.exception("Topology Mapping Task Failed for scan %s", scan_id)
        # Topology failure should NOT fail the scan — it's an optional add-on
        from core.redis_client import publish_progress_sync

        publish_progress_sync(
            scan_id,
            4,
            {
                "status": "failed",
                "message": f"Topology mapping failed: {exc}",
                "percentage": 0,
            },
        )
        return {"success": False, "error": str(exc)}
    finally:
        db.close()
