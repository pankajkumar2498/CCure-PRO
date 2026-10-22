"""
The network scan pipeline's tasks: host discovery (phase 1), asset discovery
(phase 2) and the vulnerability audit (phase 3, with the credentialed
enrichment of phase 3.5), each starting the next; the three tasks that sync a
phase's results into the asset registry; and the traditional scan.

Split from core/tasks.py in G1 (C2, docs/architecture/MODULAR_REFACTORING_LOG.md
§6), unchanged. Every task keeps its registered name, queue and limits
(scripts/architecture/task_registry.json). Logs under ``ccure.tasks``, as the
hub did.
"""

import logging
import os
from config import AppConfig
from core import task_names
from core.candidate_enumeration import searches_run, truncated_searches
from core.celery_app import celery_app
from core.scan_control import ScanCancelled
from db.base import SessionLocal, utcnow
from db.models import Scan
from scan_helpers import (
    carry_scan_coverage,
    get_terminal_phase,
    phase1_summary_from_scan,
    phase_summary_from_scan,
    resolve_pipeline_mode,
    resolve_report_context,
)
from scans.db_helpers import update_scan_phase
from scans.tasks.common import (
    _check_cancelled,
    _finalize_cancelled,
    _new_orchestrator,
    _run_async,
    _settle_failure,
    _update_task_id,
)
from scans.tasks.credentialed import _apply_credentialed_enrichment
from scans.tasks.topology import _chain_topology_if_needed

log = logging.getLogger("ccure.tasks")


def _merge_host_identity(
    enriched_hosts: list[dict], source_hosts: list[dict]
) -> list[dict]:
    """
    Preserve identity/context fields from the previous phase when the next phase
    returns only partial host records.
    """
    by_ip: dict[str, dict] = {}
    for host in source_hosts or []:
        ip = host.get("ip_address") or host.get("ip")
        if ip:
            by_ip[ip] = host

    merged: list[dict] = []
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
            "ip",
            "ip_address",
            "hostname",
            "mac",
            "mac_address",
            "vendor",
            "is_active",
            "status",
            "open_ports",
            "os_guess",
            "os_confidence",
            "device_category",
            "snmp_device_type",
            "mdns_name",
            "netbios_names",
            "os_fingerprint_full",
            "tcp_fingerprint",
            "port_states",
        ):
            if combined.get(key) in (None, "", [], {}):
                if key in base:
                    combined[key] = base.get(key)

        merged.append(combined)
    return merged


@celery_app.task(
    name=task_names.SYNC_ASSET_DISCOVERY,
    queue="scanner",
    soft_time_limit=AppConfig.SCAN_TIME_LIMIT_DISCOVERY,
    time_limit=AppConfig.SCAN_TIME_LIMIT_DISCOVERY
    + AppConfig.SCAN_TIME_LIMIT_HARD_MARGIN,
)
def sync_asset_discovery_task(
    scan_id: str, org_id: str, user_id: str | None, hosts: list[dict]
):
    db = SessionLocal()
    try:
        from scans.asset_syncer import sync_asset_discovery

        sync_asset_discovery(db, scan_id, org_id, user_id, hosts)
        # Automatically reconcile newly synced scan discoveries against AMT inventory ONLY IF this is the terminal phase
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan and scan.pipeline_mode in ("asset_discovery", "asset"):
                from core.amt_reconciliation import reconcile_amt_inventory

                reconcile_amt_inventory(db, org_id)
        except Exception as amt_exc:
            log.warning(
                "Post-scan AMT reconciliation failed for org %s: %s", org_id, amt_exc
            )
    except Exception:
        log.exception("Asset Sync Phase 2 Failed")
    finally:
        db.close()


@celery_app.task(
    name=task_names.SYNC_VULNERABILITY_AUDIT,
    queue="scanner",
    soft_time_limit=AppConfig.SCAN_TIME_LIMIT_DISCOVERY,
    time_limit=AppConfig.SCAN_TIME_LIMIT_DISCOVERY
    + AppConfig.SCAN_TIME_LIMIT_HARD_MARGIN,
)
def sync_vulnerability_audit_task(
    scan_id: str, org_id: str, user_id: str | None, hosts: list[dict]
):
    db = SessionLocal()
    try:
        from scans.asset_syncer import sync_vulnerability_audit

        sync_vulnerability_audit(db, scan_id, org_id, user_id, hosts)
        # Automatically reconcile newly synced scan discoveries against AMT inventory ONLY IF this is the terminal phase
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan and scan.pipeline_mode in ("vulnerability_audit", "advanced"):
                from core.amt_reconciliation import reconcile_amt_inventory

                reconcile_amt_inventory(db, org_id)
        except Exception as amt_exc:
            log.warning(
                "Post-scan AMT reconciliation failed for org %s: %s", org_id, amt_exc
            )
    except Exception as exc:
        log.exception("Asset Sync Phase 3 Failed")
        # This task is the retry of the inline sync, so a failure here means
        # nothing was stored. Say so on the scan rather than leave it reading
        # "complete" over an empty findings list.
        from core.scan_control import record_findings_sync_failure

        record_findings_sync_failure(
            scan_id,
            "Findings were collected but could not be saved "
            f"({type(exc).__name__}: {str(exc)[:200]}). The results are kept "
            "with the scan and can be re-synced once the cause is fixed.",
        )
    finally:
        db.close()


@celery_app.task(
    name=task_names.SYNC_HOST_DISCOVERY,
    queue="scanner",
    soft_time_limit=AppConfig.SCAN_TIME_LIMIT_DISCOVERY,
    time_limit=AppConfig.SCAN_TIME_LIMIT_DISCOVERY
    + AppConfig.SCAN_TIME_LIMIT_HARD_MARGIN,
)
def sync_host_discovery_task(
    scan_id: str, org_id: str, user_id: str | None, hosts: list[dict]
):
    db = SessionLocal()
    try:
        from scans.asset_syncer import sync_host_discovery

        sync_host_discovery(db, scan_id, org_id, user_id, hosts)
        # Automatically reconcile newly synced scan discoveries against AMT inventory ONLY IF this is the terminal phase
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan and scan.pipeline_mode in ("host_discovery", "basic"):
                from core.amt_reconciliation import reconcile_amt_inventory

                reconcile_amt_inventory(db, org_id)
        except Exception as amt_exc:
            log.warning(
                "Post-scan AMT reconciliation failed for org %s: %s", org_id, amt_exc
            )
    except Exception:
        log.exception("Asset Sync Phase 1 Failed")
    finally:
        db.close()


@celery_app.task(
    name=task_names.RUN_HOST_DISCOVERY,
    queue="scanner",
    bind=True,
    soft_time_limit=AppConfig.SCAN_TIME_LIMIT_DISCOVERY,
    time_limit=AppConfig.SCAN_TIME_LIMIT_DISCOVERY
    + AppConfig.SCAN_TIME_LIMIT_HARD_MARGIN,
)
def run_host_discovery_task(
    self,
    user_id: str,
    targets: list[str],
    scan_type: str,
    pipeline_mode: str,
    discovery_intensity: str,
    scan_id: str,
    rate_limit: float | None = None,
    max_concurrency: int | None = None,
    os_detection: bool = True,
    port_scan_intensity: str = "normal",
    custom_ports: str | None = None,
    exclude_ports: str | None = None,
    passive_first: bool | None = None,
    exclude_ot_from_nmap: bool | None = None,
    exclude_ips: str | None = None,
):
    """Phase 1 Background Task."""
    import datetime

    def ts():
        return datetime.datetime.now().isoformat()

    log.info("[TRACE][TASK][%s] Starting run_host_discovery_task", ts())
    db = SessionLocal()
    try:
        _update_task_id(db, scan_id, self.request.id)
        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled before host discovery", scan_id)
            _finalize_cancelled(db, scan_id, user_id, phase="host_discovery")
            return {"success": False, "cancelled": True, "error": "Scan cancelled"}

        from scans.db_helpers import update_scan_phase1

        mode = resolve_pipeline_mode(pipeline_mode)
        terminal = get_terminal_phase(mode)

        # Check if execution mode is interactive
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        is_interactive = False
        if scan_row and scan_row.options:
            is_interactive = scan_row.options.get("execution_mode") == "interactive"

        is_final = (terminal == 1) or is_interactive

        # 1. Run Discovery
        log.info("[TRACE][ENGINE][%s] Calling run_host_discovery_only", ts())
        orch = _new_orchestrator(db, scan_id=scan_id)
        result = _run_async(
            orch.run_host_discovery_only(
                targets=targets,
                scan_type=scan_type,
                pipeline_mode=mode,
                discovery_intensity=discovery_intensity,
                scan_id=scan_id,
                rate_limit=rate_limit,
                max_concurrency=max_concurrency,
                exclude_ips=exclude_ips,
            )
        )
        log.info("[TRACE][ENGINE][%s] run_host_discovery_only finished", ts())

        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled after host discovery", scan_id)
            _finalize_cancelled(db, scan_id, user_id, phase="host_discovery")
            return {"success": False, "cancelled": True, "error": "Scan cancelled"}

        if not result.get("success"):
            _settle_failure(
                db, scan_id, user_id, result.get("error", "Host Discovery failed")
            )
            return result

        # 2. Metadata & Reports
        context = resolve_report_context(
            db,
            user_id,
            scan_id=scan_id,
            hosts=result.get("data", []),
            requested_targets=targets,
            requested_scan_type=scan_type,
        )
        result.setdefault("metadata", {}).update(context)

        report_paths = {}
        if is_final:
            raw_paths = orch.generate_phase_report(result, "host_discovery")
            report_paths = {
                k: v for k, v in raw_paths.items() if v and os.path.isfile(v)
            }

        # 3. Update Scan (updates Scan and Phase 1 rows in DB)
        log.info("[TRACE][DB][%s] Updating scan phase 1 in DB", ts())
        scan = update_scan_phase1(
            db=db,
            scan_id=scan_id,
            user_id=user_id,
            phase1_data=result,
            is_final=is_final,
            report_executive_path=report_paths.get("executive_pdf"),
            report_technical_path=report_paths.get("technical_pdf"),
        )

        # 4. Final Progress Push (Post-Commit)
        from core.redis_client import publish_progress_sync

        # If there's another phase to run, trigger it asynchronously
        if not is_final and result.get("success") and result.get("data"):
            active_hosts = [h for h in result["data"] if h.get("is_active")]
            if active_hosts:
                log.info(
                    "[TRACE][TASK][%s] Chaining next phase (Asset Discovery) for scan_id=%s",
                    ts(),
                    scan_id,
                )

                # Fetch custom ports from the scan row if not explicitly passed
                resolved_custom_ports = custom_ports
                if not resolved_custom_ports and scan_row and scan_row.options:
                    resolved_custom_ports = scan_row.options.get("custom_ports")

                # Fetch exclude ports from the scan row if not explicitly passed
                resolved_exclude_ports = exclude_ports
                if not resolved_exclude_ports and scan_row and scan_row.options:
                    resolved_exclude_ports = scan_row.options.get("exclude_ports")

                # Dispatch Phase 2 (Asset Discovery) directly
                next_task = run_asset_discovery_task.delay(
                    user_id=user_id,
                    hosts=active_hosts,
                    intensity=port_scan_intensity,  # Dedicated port scan intensity (separate from discovery intensity)
                    scan_id=scan_id,
                    pipeline_mode=pipeline_mode,
                    os_detection=os_detection,  # Forward os_detection from the original request
                    custom_ports=resolved_custom_ports,  # Forward custom_ports
                    exclude_ports=resolved_exclude_ports,  # Forward exclude_ports
                    passive_first=passive_first,
                    exclude_ot_from_nmap=exclude_ot_from_nmap,
                    exclude_ips=exclude_ips,
                )
                db.query(Scan).filter(Scan.id == scan_id).update(
                    {"current_task_id": next_task.id}
                )
                db.commit()

                # Publish progress to let UI know we are moving to next phase
                publish_progress_sync(
                    scan_id,
                    1,
                    {
                        "discovered": scan.active_hosts,
                        "total_ips": scan.total_hosts,
                        "status": "complete",
                    },
                )

                return {
                    "success": True,
                    "scan_id": scan_id,
                    "chained_task": next_task.id,
                }
            else:
                log.info(
                    "[TRACE][TASK][%s] No active hosts found, terminating pipeline early for scan_id=%s",
                    ts(),
                    scan_id,
                )

        # Ensure scan is marked complete if no next phase is chained
        if (
            is_final
            or not result.get("data")
            or not any(h.get("is_active") for h in result.get("data", []))
        ):
            log.info("[TRACE][TASK][%s] Scan %s pipeline complete", ts(), scan_id)
            from db.base import utcnow

            db.refresh(scan)
            if scan.status != "unreachable":
                db.query(Scan).filter(Scan.id == scan_id).update(
                    {"status": "complete", "completed_at": utcnow()}
                )
                db.commit()
                db.refresh(scan)
            else:
                log.info(
                    "[TRACE][TASK][%s] Scan %s remains 'unreachable' as expected",
                    ts(),
                    scan_id,
                )

            # FINAL PROGRESS PUSH: Use the actual scan status (could be complete or unreachable)
            publish_progress_sync(
                scan_id,
                1,
                {
                    "discovered": scan.active_hosts,
                    "total_ips": scan.total_hosts,
                    "status": scan.status,
                },
            )

            # Chain topology mapping if SNMP is configured (optional Phase 4)
            _chain_topology_if_needed(db, scan_id, user_id, scan_row=scan)

        log.info("[TRACE][TASK][%s] run_host_discovery_task finished", ts())
        return {"success": True, "scan_id": scan_id}
    except ScanCancelled:
        # A cancelled scan is not a failure: record it as cancelled so the
        # history shows what the user actually did, not a spurious error.
        log.info("Host Discovery cancelled by user for scan %s", scan_id)
        _finalize_cancelled(db, scan_id, user_id, phase="host_discovery")
        return {"success": False, "cancelled": True, "error": "Scan cancelled"}
    except Exception as exc:
        log.exception("Host Discovery Task Failed")
        _settle_failure(db, scan_id, user_id, f"{type(exc).__name__}: {exc}")
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@celery_app.task(
    name=task_names.RUN_ASSET_DISCOVERY,
    queue="scanner",
    bind=True,
    soft_time_limit=AppConfig.SCAN_TIME_LIMIT_PORT_SCAN,
    time_limit=AppConfig.SCAN_TIME_LIMIT_PORT_SCAN
    + AppConfig.SCAN_TIME_LIMIT_HARD_MARGIN,
)
def run_asset_discovery_task(
    self,
    user_id: str,
    hosts: list[dict],
    intensity: str,
    scan_id: str,
    pipeline_mode: str,
    os_detection: bool = True,
    custom_ports: str | None = None,
    exclude_ports: str | None = None,
    exclude_ot_from_nmap: bool | None = None,
    passive_first: bool | None = None,
    exclude_ips: str | None = None,
):
    """Phase 2 Background Task."""
    import datetime

    def ts():
        return datetime.datetime.now().isoformat()

    db = SessionLocal()
    try:
        _update_task_id(db, scan_id, self.request.id)
        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled before asset discovery", scan_id)
            _finalize_cancelled(db, scan_id, user_id, phase="port_scan")
            return {"success": False, "cancelled": True, "error": "Scan cancelled"}

        mode = resolve_pipeline_mode(pipeline_mode)

        # Check if execution mode is interactive
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        is_interactive = False
        if scan_row and scan_row.options:
            is_interactive = scan_row.options.get("execution_mode") == "interactive"

        is_final = (get_terminal_phase(mode) == 2) or is_interactive

        # Fetch options from scan_row if None
        resolved_exclude_ot = exclude_ot_from_nmap
        if resolved_exclude_ot is None:
            resolved_exclude_ot = True
            if scan_row and scan_row.options:
                resolved_exclude_ot = scan_row.options.get("exclude_ot_from_nmap", True)

        resolved_passive_first = passive_first
        if resolved_passive_first is None:
            resolved_passive_first = False
            if scan_row and scan_row.options:
                resolved_passive_first = scan_row.options.get("passive_first", False)

        resolved_exclude_ips = exclude_ips
        if resolved_exclude_ips is None:
            if scan_row and scan_row.options:
                resolved_exclude_ips = scan_row.options.get("exclude_ips")

        # Fetch custom ports from the scan row options if not explicitly passed as task parameter
        resolved_custom_ports = custom_ports
        if not resolved_custom_ports and scan_row and scan_row.options:
            resolved_custom_ports = scan_row.options.get("custom_ports")

        # Fetch exclude ports from the scan row options if not explicitly passed as task parameter
        resolved_exclude_ports = exclude_ports
        if not resolved_exclude_ports and scan_row and scan_row.options:
            resolved_exclude_ports = scan_row.options.get("exclude_ports")

        orch = _new_orchestrator(db, scan_id=scan_id)
        result = _run_async(
            orch.run_asset_discovery_only(
                hosts=hosts,
                intensity=intensity,
                pipeline_mode=mode,
                scan_id=scan_id,
                os_detection=os_detection,
                custom_ports=resolved_custom_ports,
                exclude_ports=resolved_exclude_ports,
                exclude_ot_from_nmap=resolved_exclude_ot,
                passive_first=resolved_passive_first,
                exclude_ips=resolved_exclude_ips,
            )
        )

        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled after asset discovery", scan_id)
            _finalize_cancelled(db, scan_id, user_id, phase="port_scan")
            return {"success": False, "cancelled": True, "error": "Scan cancelled"}

        if not result.get("success"):
            _settle_failure(
                db, scan_id, user_id, result.get("error", "Asset Discovery failed")
            )
            return result

        context = resolve_report_context(db, user_id, scan_id=scan_id, hosts=hosts)
        result.setdefault("metadata", {}).update(context)

        # Apply Phase 1 hints manually for the summary
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan_row:
            p1_sum = phase1_summary_from_scan(scan_row)
            if p1_sum:
                for k in ("total_hosts", "active_hosts", "inactive_hosts"):
                    if p1_sum.get(k) is not None:
                        result["summary"][k] = p1_sum[k]
                # How the hosts were found, for the report's methodology
                # appendix. It printed "Discovery profile: Not recorded" while
                # the stored summary said FAST+BALANCED_FALLBACK, because the
                # report was rendered before that value was merged in.
                for k in (
                    "discovery_profile",
                    "discovery_intensity",
                    "discovery_scan_method",
                ):
                    if p1_sum.get(k) and not result["summary"].get(k):
                        result["summary"][k] = p1_sum[k]

        report_paths = {}
        if is_final:
            raw_paths = orch.generate_phase_report(result, "asset_discovery")
            report_paths = {
                k: v for k, v in raw_paths.items() if v and os.path.isfile(v)
            }

        update_scan_phase(
            db=db,
            scan_id=scan_id,
            user_id=user_id,
            phase=2,
            phase_data={
                "data": result["data"],
                "summary": result["summary"],
                "metadata": result["metadata"],
            },
            is_final=is_final,
            pipeline_mode=mode,
            report_executive_path=report_paths.get("executive_pdf"),
            report_technical_path=report_paths.get("technical_pdf"),
        )

        # Final Progress Push
        from core.redis_client import publish_progress_sync

        # If there's another phase to run, trigger it asynchronously
        if not is_final and result.get("success") and result.get("data"):
            active_hosts = [h for h in result["data"] if h.get("is_active")]
            if active_hosts:
                log.info(
                    "[TRACE][TASK][%s] Chaining next phase (Vulnerability Audit) for scan_id=%s",
                    ts(),
                    scan_id,
                )
                # Dispatch Phase 3 (Vulnerability Audit) directly
                next_task = run_vulnerability_audit_task.delay(
                    user_id=user_id,
                    hosts=active_hosts,
                    scan_id=scan_id,
                    pipeline_mode=pipeline_mode,
                    exclude_ot_from_nmap=resolved_exclude_ot,
                    exclude_ips=resolved_exclude_ips,
                )
                db.query(Scan).filter(Scan.id == scan_id).update(
                    {"current_task_id": next_task.id}
                )
                db.commit()

                publish_progress_sync(
                    scan_id,
                    2,
                    {
                        "scanned_hosts": result["summary"].get("total_hosts", 0),
                        "total_hosts": result["summary"].get("total_hosts", 0),
                        "status": "complete",
                    },
                )
                return {
                    "success": True,
                    "scan_id": scan_id,
                    "chained_task": next_task.id,
                }
            else:
                log.info(
                    "[TRACE][TASK][%s] No active hosts found, terminating pipeline early for scan_id=%s",
                    ts(),
                    scan_id,
                )

        publish_progress_sync(
            scan_id,
            2,
            {
                "scanned_hosts": result["summary"].get("total_hosts", 0),
                "total_hosts": result["summary"].get("total_hosts", 0),
                "status": "complete",
            },
        )

        # Ensure scan is marked complete if no next phase is chained
        if (
            is_final
            or not result.get("data")
            or not any(h.get("is_active") for h in result.get("data", []))
        ):
            log.info("[TRACE][TASK][%s] Scan %s pipeline complete", ts(), scan_id)
            db.refresh(scan_row)
            if scan_row.status != "unreachable":
                db.query(Scan).filter(Scan.id == scan_id).update(
                    {"status": "complete", "completed_at": utcnow()}
                )
                db.commit()
            else:
                log.info(
                    "[TRACE][TASK][%s] Scan %s remains 'unreachable' as expected",
                    ts(),
                    scan_id,
                )

            # Chain topology mapping if SNMP is configured (optional Phase 4)
            _chain_topology_if_needed(db, scan_id, user_id, scan_row=scan_row)

        return {"success": True, "scan_id": scan_id}
    except ScanCancelled:
        log.info("Asset Discovery cancelled by user for scan %s", scan_id)
        _finalize_cancelled(db, scan_id, user_id, phase="port_scan")
        return {"success": False, "cancelled": True, "error": "Scan cancelled"}
    except Exception as exc:
        # The scan row has to be closed out here, for the same reason the
        # Vulnerability Audit handler below says so: returning the failure
        # without recording it left the scan 'running' for ever. Phase 2 was
        # missed when that was fixed for phase 3, so an Asset Discovery or
        # Vulnerability Audit pipeline that died in its port-scan phase
        # stranded the scan exactly as phase 3 used to.
        log.exception("Asset Discovery Task Failed")
        _settle_failure(db, scan_id, user_id, f"{type(exc).__name__}: {exc}")
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@celery_app.task(
    name=task_names.RUN_VULNERABILITY_AUDIT,
    queue="scanner",
    bind=True,
    soft_time_limit=AppConfig.SCAN_TIME_LIMIT_VULN_AUDIT,
    time_limit=AppConfig.SCAN_TIME_LIMIT_VULN_AUDIT
    + AppConfig.SCAN_TIME_LIMIT_HARD_MARGIN,
)
def run_vulnerability_audit_task(
    self,
    user_id: str,
    hosts: list[dict],
    scan_id: str,
    pipeline_mode: str,
    exclude_ot_from_nmap: bool | None = None,
    exclude_ips: str | None = None,
):
    """Phase 3 Background Task."""
    db = SessionLocal()
    try:
        _update_task_id(db, scan_id, self.request.id)
        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled before vulnerability audit", scan_id)
            _finalize_cancelled(db, scan_id, user_id, phase="vulnerability_audit")
            return {"success": False, "cancelled": True, "error": "Scan cancelled"}

        mode = resolve_pipeline_mode(pipeline_mode)
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()

        resolved_exclude_ot = exclude_ot_from_nmap
        if resolved_exclude_ot is None:
            resolved_exclude_ot = True
            if scan_row and scan_row.options:
                resolved_exclude_ot = scan_row.options.get("exclude_ot_from_nmap", True)

        resolved_exclude_ips = exclude_ips
        if resolved_exclude_ips is None:
            if scan_row and scan_row.options:
                resolved_exclude_ips = scan_row.options.get("exclude_ips")

        orch = _new_orchestrator(db, scan_id=scan_id)

        # GAP-12. Whether a probe may *write* to a scanned host is a per-scan
        # decision now, not only a deployment-wide one. `core/checks/intrusive`
        # was built as the seam for exactly this and nothing else moves: the
        # override is process-wide rather than thread-local, deliberately,
        # because the vulnerability engine runs its plugins in a thread pool
        # that does not propagate context.
        #
        # The default is still off. A policy that says nothing leaves
        # `SCAN_ALLOW_INTRUSIVE` in force, so a scan with no policy behaves
        # exactly as it did — and a policy can only ever turn this *on*
        # deliberately, never inherit it.
        from core.checks.intrusive import allow_intrusive_probes
        from core.scan_policy import read_policy_snapshot

        _policy = read_policy_snapshot(scan_row)
        if _policy is not None and _policy.allow_intrusive:
            log.warning(
                "Scan %s runs under policy %r, which permits intrusive probes: "
                "a probe may write to a target to establish a finding.",
                scan_id,
                _policy.policy_name or _policy.fingerprint()[:16],
            )
            with allow_intrusive_probes(True):
                result = orch.run_vulnerability_audit_only(
                    hosts=hosts,
                    scan_id=scan_id,
                    exclude_ot_from_nmap=resolved_exclude_ot,
                    exclude_ips=resolved_exclude_ips,
                )
        else:
            result = orch.run_vulnerability_audit_only(
                hosts=hosts,
                scan_id=scan_id,
                exclude_ot_from_nmap=resolved_exclude_ot,
                exclude_ips=resolved_exclude_ips,
            )

        if _check_cancelled(db, scan_id):
            log.info("Scan %s cancelled after vulnerability audit", scan_id)
            _finalize_cancelled(db, scan_id, user_id, phase="vulnerability_audit")
            return {"success": False, "cancelled": True, "error": "Scan cancelled"}

        if not result.get("success"):
            _settle_failure(
                db, scan_id, user_id, result.get("error", "Vulnerability Audit failed")
            )
            return result

        result["data"] = _merge_host_identity(result.get("data", []), hosts)

        # Phase 3.5 — authenticated checks, merged into these same results
        # before anything reads them. Runs only when credentials were supplied.
        credentialed_summary = _apply_credentialed_enrichment(
            db, scan_row, result["data"], scan_id=scan_id
        )
        if credentialed_summary:
            # `is_credentialed` comes from the enrichment itself. Forcing it True
            # here labelled a scan authenticated even when every credential had
            # failed to resolve and nothing had been authenticated to.
            authenticated = bool(credentialed_summary.get("credentialed_hosts"))
            result["summary"].update(credentialed_summary)
            result.setdefault("metadata", {}).update(
                {**credentialed_summary, "is_credentialed": authenticated}
            )
            # Re-derive the risk tallies: the enrichment can promote a host's
            # level, and these are what the dashboard and the executive summary
            # read.
            result["summary"]["critical_hosts"] = sum(
                1 for h in result["data"] if h.get("host_risk_level") == "Critical"
            )
            result["summary"]["high_risk_hosts"] = sum(
                1 for h in result["data"] if h.get("host_risk_level") == "High"
            )
            result["summary"]["candidates_evaluated"] = sum(
                int(h.get("candidates_evaluated") or 0) for h in result["data"]
            )
            result["summary"]["candidates_suppressed"] = sum(
                len(h.get("suppressed_cves") or []) for h in result["data"]
            )
            result["summary"]["candidate_searches"] = searches_run(result["data"])
            result["summary"]["candidate_searches_truncated"] = truncated_searches(
                result["data"]
            )

        context = resolve_report_context(db, user_id, scan_id=scan_id, hosts=hosts)
        result.setdefault("metadata", {}).update(context)

        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()

        # Report the whole scan's elapsed time, not this phase's. The executive
        # PDF read `summary.scan_duration`, which is the vulnerability phase
        # alone, and printed "83 seconds" for a scan that Scan History and the
        # scan record both showed as 3m 36s.
        if scan_row and scan_row.started_at:
            from db.base import utcnow as _utcnow

            elapsed = (_utcnow() - scan_row.started_at).total_seconds()
            if elapsed > 0:
                result["metadata"]["duration_seconds"] = round(elapsed, 2)
                result["summary"]["total_scan_duration"] = round(elapsed, 2)

        if scan_row:
            p1_sum = phase1_summary_from_scan(scan_row)
            if p1_sum:
                for k in ("total_hosts", "active_hosts", "inactive_hosts"):
                    if p1_sum.get(k) is not None:
                        result["summary"][k] = p1_sum[k]

            # A vulnerability assessment does not choose ports; it assesses what
            # the asset discovery phase found. Its report still has to state
            # which ports were examined, so that phase's coverage travels
            # forward with the scan record.
            carry_scan_coverage(
                result, phase_summary_from_scan(scan_row, "asset_discovery", "phase2")
            )

        raw_paths = orch.generate_phase_report(result, "phase_selective_scan")
        report_paths = {k: v for k, v in raw_paths.items() if v and os.path.isfile(v)}

        update_scan_phase(
            db=db,
            scan_id=scan_id,
            user_id=user_id,
            phase=3,
            phase_data={
                "data": result["data"],
                "summary": result["summary"],
                "metadata": result["metadata"],
            },
            is_final=True,
            pipeline_mode=mode,
            report_executive_path=report_paths.get("executive_pdf"),
            report_technical_path=report_paths.get("technical_pdf"),
        )

        # Final Progress Push
        from core.redis_client import publish_progress_sync

        publish_progress_sync(
            scan_id,
            3,
            {
                "scanned_hosts": result["summary"].get("total_hosts", 0),
                "total_hosts": result["summary"].get("total_hosts", 0),
                "status": "complete",
            },
        )

        # Chain topology mapping if SNMP is configured (optional Phase 4)
        _chain_topology_if_needed(db, scan_id, user_id, scan_row=scan_row)

        return {"success": True, "scan_id": scan_id}
    except ScanCancelled:
        log.info("Vulnerability Audit cancelled by user for scan %s", scan_id)
        _finalize_cancelled(db, scan_id, user_id, phase="vulnerability_audit")
        return {"success": False, "cancelled": True, "error": "Scan cancelled"}
    except Exception as exc:
        # The scan row has to be closed out here. Returning the failure without
        # marking it left the scan "running" for ever: the UI showed a spinner
        # with no terminal state, the concurrency slot was never released, and
        # nothing told the operator the audit had died.
        log.exception("Vulnerability Audit Task Failed")
        _settle_failure(db, scan_id, user_id, f"{type(exc).__name__}: {exc}")
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@celery_app.task(
    name=task_names.RUN_TRADITIONAL_SCAN,
    queue="scanner",
    soft_time_limit=AppConfig.SCAN_TIME_LIMIT_PORT_SCAN,
    time_limit=AppConfig.SCAN_TIME_LIMIT_PORT_SCAN
    + AppConfig.SCAN_TIME_LIMIT_HARD_MARGIN,
)
def run_traditional_scan_task(
    user_id: str,
    targets: list[str],
    phases: str,
    scan_type: str,
    intensity: str,
    passive_first: bool | None = None,
    exclude_ot_from_nmap: bool | None = None,
    exclude_ips: str | None = None,
):
    """Traditional Scan Task."""
    db = SessionLocal()
    try:
        orch = _new_orchestrator(db, user_id=user_id)
        resolved_passive_first = False if passive_first is None else passive_first
        resolved_exclude_ot = (
            True if exclude_ot_from_nmap is None else exclude_ot_from_nmap
        )
        result = _run_async(
            orch.run_phases(
                targets=targets,
                phases=phases,
                scan_type=scan_type,
                intensity=intensity,
                passive_first=resolved_passive_first,
                exclude_ot_from_nmap=resolved_exclude_ot,
                exclude_ips=exclude_ips,
            )
        )
        return result
    finally:
        db.close()
