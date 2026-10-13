"""
core/tasks.py
─────────────
Celery background tasks for long-running network scans.
"""

import asyncio
import logging
import os
import time
from typing import Dict, List, Optional

from config import AppConfig
from core import task_names
from core.celery_app import celery_app
from core.mac import mac_identity
from core.scan_control import ScanCancelled
from db.base import SessionLocal, gen_asset_id, utcnow
from db.models import (
    Asset,
    AssetVulnerability,
    Scan,
    VulnerabilityDefinition,
)
from ccure_platform import api as platform_api
from db.models.compliance import CREDENTIAL_TYPE_DATABASE, CREDENTIAL_TYPE_SSH
from engines.credentialed.coverage import (
    correlate_listeners,
    credentialed_coverage,
    mark_credentialed_confirmed,
)
from engines.credentialed.transport_resolver import (
    DEFAULT_PORT as DEFAULT_TRANSPORT_PORT,
)
from engines.credentialed.transport_resolver import (
    resolve_access,
    resolve_endpoint,
)
from orchestrator.scan_orchestrator import ScanOrchestrator
from scan_helpers import (
    carry_scan_coverage,
    get_terminal_phase,
    phase1_summary_from_scan,
    phase_summary_from_scan,
    resolve_pipeline_mode,
    resolve_report_context,
)
from scans.db_helpers import (
    create_completed_scan,
    mark_scan_failed,
    update_scan_phase,
)
from sqlalchemy import func, text
from sqlalchemy.dialects.postgresql import insert

log = logging.getLogger("ccure.tasks")


def _strip_nul(value):
    """Recursively remove NUL (U+0000) from every string in a nested structure.

    Windows collectors read version-resource and registry values that are
    UTF-16LE and occasionally carry an embedded NUL — a truncated
    ``"Microsoft\\x00..."`` publisher string, for instance. PostgreSQL's
    ``jsonb``/``text`` cannot store U+0000, so one such byte anywhere in a
    credentialed report aborts the whole result commit
    (``UntranslatableCharacter: \\u0000 cannot be converted to text``): the scan
    is marked ``failed`` and every finding it produced is lost on the rollback.
    Scrub at the point the report is produced, before anything derived from it
    is persisted or merged into ``scans.options``.
    """
    if isinstance(value, str):
        return value.replace("\x00", "") if "\x00" in value else value
    if isinstance(value, dict):
        return {k: _strip_nul(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_strip_nul(v) for v in value]
    return value


def _new_orchestrator(
    db=None, scan_id: str | None = None, user_id: str | None = None
) -> ScanOrchestrator:
    """
    Create one orchestrator per task so parallel scans do not share mutable state.

    When `db` plus either `scan_id` or `user_id` are supplied, the orchestrator
    is bound to the owning organisation's authorised scan scope, so target
    expansion drops anything outside it. Callers that omit them get an unscoped
    orchestrator — acceptable only for paths that never expand targets, such as
    report generation.
    """
    orch = ScanOrchestrator(silent=False)
    if db is not None and (scan_id or user_id):
        try:
            _bind_scan_scope(db, orch, scan_id=scan_id, user_id=user_id)
        except Exception:
            # A scope that cannot be loaded must not silently become
            # "unrestricted". Deny-all is the safe failure here: the scan ends
            # with "no valid targets" rather than scanning whatever it likes.
            log.exception(
                "Could not load scan scope for scan=%s user=%s; denying all targets",
                scan_id,
                user_id,
            )
            orch.scan_scope = []
    return orch


def _bind_scan_scope(
    db,
    orch: ScanOrchestrator,
    scan_id: str | None = None,
    user_id: str | None = None,
) -> None:
    """
    Bind an orchestrator to an organisation's authorised scan scope.

    The scan row is the preferred source because it records the org the scan
    was admitted for. Falling back to the user's current org covers the
    traditional-scan path, which carries no scan id.
    """
    from core.scan_scope import org_scan_scope

    org_id = None
    if scan_id:
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        org_id = getattr(scan_row, "org_id", None) if scan_row is not None else None
    if not org_id and user_id:
        owner = platform_api.user(db, user_id)
        org_id = owner.org_id if owner is not None else None

    orch.apply_scan_scope(org_scan_scope(db, org_id) if org_id else None)


def _run_async(coro):
    """Run async scanner code safely from Celery worker threads or eager contexts."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import threading
        from concurrent.futures import Future

        future = Future()

        def run_in_thread():
            try:
                result = asyncio.run(coro)
                future.set_result(result)
            except BaseException as e:
                future.set_exception(e)

        thread = threading.Thread(target=run_in_thread)
        thread.start()
        return future.result()
    else:
        return asyncio.run(coro)


def _finalize_cancelled(
    db: SessionLocal, scan_id: str, user_id: str, phase: str
) -> None:
    """
    Settle a scan the user cancelled mid-flight.

    The API has already set status='cancelled'; what is left is to stamp the
    completion time, close out any phase row still marked running, and push a
    final progress frame so watching clients stop showing a live scan.
    """
    from core.redis_client import publish_progress_sync
    from scans.db_helpers import mark_scan_cancelled

    try:
        mark_scan_cancelled(db, scan_id, user_id, phase_key=phase)
    except Exception:
        log.exception("Could not finalize cancelled scan %s", scan_id)
        db.rollback()

    try:
        publish_progress_sync(scan_id, 1, {"status": "cancelled"})
    except Exception:
        log.debug("Could not publish cancellation for %s", scan_id, exc_info=True)


def _settle_failure(
    db: SessionLocal,
    scan_id: str,
    user_id: str,
    reason: str,
    status: str = "failed",
) -> None:
    """
    Record a scan failure, and guarantee that *something* is recorded.

    `mark_scan_failed` goes through the ORM — it loads the `Scan`, writes an
    audit event and raises a notification. That is the right thing to do and it
    shares a dependency with the code path that just failed.

    On 4 Sep 2026 a worker holding a stale `Scan` mapper raised
    `InvalidRequestError` on `run_host_discovery_task`'s first query. The
    `except` handler called `mark_scan_failed`, whose own first query raised the
    identical error, so the handler died too and the scan row was never touched.
    Three scans sat in 'running' forever while the target host was up the whole
    time — visible in the UI as a live scan stuck at 10%.

    So the ORM attempt is made first, because a proper failure carries the audit
    entry and the user's notification. If it raises for *any* reason, the scan
    is still settled through `force_terminal_status`, which issues plain SQL and
    touches no mapper. A worse-quality record beats no record: an unsettled scan
    is indistinguishable from a running one, and nothing downstream — the
    watchdog aside — will ever revisit it.
    """
    from core.redis_client import publish_progress_sync
    from core.scan_control import force_terminal_status

    try:
        mark_scan_failed(db, scan_id, user_id, reason, status=status)
    except Exception:
        log.exception(
            "mark_scan_failed could not settle scan %s — falling back to SQL",
            scan_id,
        )
        try:
            db.rollback()
        except Exception:
            pass
        force_terminal_status(scan_id, status=status, reason=reason)

    # Whichever route settled it, tell anyone watching. Without this a browser
    # on the live scan screen keeps showing a scan that is over until its own
    # client-side timeout fires.
    try:
        publish_progress_sync(
            scan_id, 1, {"status": status, "error": reason, "reason": reason}
        )
    except Exception:
        log.debug("Could not publish failure for scan %s", scan_id, exc_info=True)


def _check_cancelled(db: SessionLocal, scan_id: str) -> bool:
    """
    Check if the scan has been marked as cancelled in the DB.

    The ``db`` argument is accepted for call-site compatibility but deliberately
    unused: reading through the caller's session returns the status from that
    session's identity map, which is the snapshot taken when the task first
    loaded the row. That is what made Stop a no-op. ``is_cancelled`` opens its
    own session so it sees what the API actually committed.
    """
    from core.scan_control import is_cancelled

    return is_cancelled(scan_id)


def _update_task_id(db: SessionLocal, scan_id: str, task_id: str):
    """Update the current active task ID for the scan."""
    db.query(Scan).filter(Scan.id == scan_id).update({"current_task_id": task_id})
    db.commit()


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


def _assessed_config_definition_ids(config_summary) -> set:
    """
    Catalogue ids of the configuration checks this scan reached a *verdict* on.

    Only PASS and FAIL count. A check that errored, was not applicable or could
    not be collected established nothing about the host, and a finding it did
    not report is not a finding that went away.

    This is what stops the sweep below turning an unreachable session into a
    page of remediated controls: 126 Windows STIG findings on one measured host
    are absent from `cve_list` when the audit passes *and* when the audit never
    ran, and only this set tells the two apart.
    """
    ids: set = set()
    if not isinstance(config_summary, dict) or not config_summary.get("assessed"):
        return ids
    from core.config_audit.findings import config_definition_id

    for result in config_summary.get("results") or []:
        if not isinstance(result, dict):
            continue
        if str(result.get("outcome") or "").strip().lower() not in ("pass", "fail"):
            continue
        check_id = str(result.get("check_id") or "").strip()
        if not check_id:
            continue
        finding_type = str(
            (result.get("metadata") or {}).get("finding_type") or "config_check"
        )
        ids.add(config_definition_id(check_id, finding_type))
    return ids


def _sync_credentialed_asset_identity(
    db,
    *,
    user_id: str,
    ip: str,
    scan_id: str,
    os_type: str,
    system_data: dict,
    stored_report: dict,
    cve_list: list[dict],
    severity_counts: dict[str, int],
) -> None:
    """
    Promote trusted credentialed scan identity into the Asset Registry.
    Phase 4: Adds forensic logging and provenance.
    """
    from core.oui_lookup import lookup_vendor
    from scans.asset_syncer import (
        CREDENTIALED_STATUS_SUCCESS,
        _confidence_to_percent,
        _finding_family,
        _finding_source_from_record,
        _has_value,
        _recalculate_asset_risk,
        _record_asset_change,
        _set_asset_field,
        _to_int,
    )

    user = platform_api.user(db, user_id)
    if not user:
        log.warning("Credentialed asset sync skipped: user %s not found", user_id)
        return

    # Resolve scan's target org_id
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    org_id = str(scan.org_id) if scan else str(user.org_id)

    mac_address = _normalize_mac(system_data.get("mac_address"))
    asset = None
    if mac_address:
        asset = (
            db.query(Asset)
            .filter(Asset.org_id == org_id, Asset.mac_address == mac_address)
            .first()
        )
    if not asset:
        asset = (
            db.query(Asset)
            .filter(Asset.org_id == org_id, Asset.ip_address == ip)
            .first()
        )

    if asset:
        if asset.ip_address != ip and ip != "0.0.0.0":
            # Release IP from any other asset currently claiming it (IP Hijacking protection)
            other_asset = (
                db.query(Asset)
                .filter(Asset.org_id == org_id, Asset.ip_address == ip)
                .first()
            )
            if other_asset and other_asset.id != asset.id:
                other_asset.ip_address = None
                other_asset.is_active = False
                _record_asset_change(
                    db, other_asset.id, scan_id, "ip_address", ip, None
                )
                db.flush()

            _record_asset_change(
                db, asset.id, scan_id, "ip_address", str(asset.ip_address), ip
            )
            asset.ip_address = ip
    else:
        log.info("Asset not found for ip=%s. Bootstrapping new asset record.", ip)
        org = platform_api.organisation(db, org_id)
        org_slug = org.slug if org else org_id

        asset = Asset(
            id=gen_asset_id(org_slug, ip),
            org_id=org_id,
            ip_address=ip,
            is_active=True,
            discovery_method="credentialed",
            first_seen_at=utcnow(),
            last_seen_at=utcnow(),
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(asset)
        db.flush()
        _record_asset_change(
            db, asset.id, scan_id, "lifecycle", None, "bootstrapped_via_credentialed"
        )

    os_name = _clean_text(system_data.get("os_name"))
    os_version = _clean_text(system_data.get("os_version_id"))
    hostname, fqdn, raw_hostname_fqdn = _extract_credentialed_identity_names(
        system_data
    )
    os_build = _clean_text(system_data.get("os_build"))
    kernel_version = _clean_text(system_data.get("kernel_version"))
    netbios_name = _clean_text(
        system_data.get("netbios_name") or system_data.get("netbios_computer")
    )
    normalized_os_type = _clean_text(system_data.get("detected_os") or os_type).lower()
    manufacturer = _clean_text(system_data.get("manufacturer"))
    # mac_address resolved above
    mac_vendor = _clean_text(
        system_data.get("mac_vendor")
        or (lookup_vendor(mac_address) if mac_address else "")
    )
    vendor = mac_vendor or (manufacturer if not _has_value(asset.vendor) else "")
    os_family = _clean_text(
        system_data.get("os_family")
        or (
            "Windows"
            if normalized_os_type == "windows"
            else "Linux" if normalized_os_type == "linux" else ""
        )
    )
    os_confidence = _confidence_to_percent(system_data.get("os_confidence") or 100)
    subnet = _clean_text(system_data.get("subnet"))
    credentialed_response_time = _to_int(
        system_data.get("credentialed_response_time_ms")
    )

    # PHASE 4: FORENSIC CHANGE LOGGING
    _set_asset_field(
        db, asset, scan_id, "os_name", os_name, "credentialed", max_len=255
    )
    _set_asset_field(
        db, asset, scan_id, "os_family", os_family, "credentialed", max_len=100
    )
    _set_asset_field(
        db, asset, scan_id, "os_version", os_version, "credentialed", max_len=100
    )
    _set_asset_field(db, asset, scan_id, "os_confidence", os_confidence, "credentialed")
    _set_asset_field(
        db, asset, scan_id, "hostname", hostname, "credentialed", max_len=255
    )
    _set_asset_field(db, asset, scan_id, "fqdn", fqdn, "credentialed", max_len=512)
    _set_asset_field(
        db, asset, scan_id, "netbios_name", netbios_name, "credentialed", max_len=255
    )
    _set_asset_field(db, asset, scan_id, "mac_address", mac_address, "credentialed")
    _set_asset_field(db, asset, scan_id, "vendor", vendor, "credentialed", max_len=255)
    _set_asset_field(db, asset, scan_id, "subnet", subnet, "credentialed", max_len=50)
    _set_asset_field(
        db, asset, scan_id, "manufacturer", manufacturer, "credentialed", max_len=255
    )
    _set_asset_field(
        db,
        asset,
        scan_id,
        "discovery_method",
        "credentialed",
        "credentialed",
        max_len=50,
    )
    if credentialed_response_time and not _has_value(asset.response_time_ms):
        _set_asset_field(
            db,
            asset,
            scan_id,
            "response_time_ms",
            credentialed_response_time,
            "credentialed",
        )

    # Classify device category using the credentialed OS/identity details
    from core.device_classifier import classify_device

    c_host = {
        "discovery_method": "credentialed",
        "os_name": os_name,
        "os_family": os_family,
        "hostname": hostname,
        "vendor": vendor,
        "custom_attributes": asset.custom_attributes or {},
    }
    category = classify_device(c_host)
    _set_asset_field(
        db, asset, scan_id, "device_category", category, "credentialed", max_len=100
    )

    # Store the signal name ("credentialed") in provenance for future priority comparisons
    attrs = dict(asset.custom_attributes or {})
    prov = dict(attrs.get("provenance") or {})
    dev_prov = dict(prov.get("device_category") or {})
    dev_prov["signal"] = "credentialed"
    prov["device_category"] = dev_prov
    attrs["provenance"] = prov
    asset.custom_attributes = attrs

    _sync_credentialed_services(
        db,
        asset,
        scan_id,
        stored_report.get("open_ports_credentialed", []),
        stored_report.get("packages", []),
    )

    # 1. Sync Vulnerabilities (Marks as open/reopened)
    _sync_credentialed_vulnerabilities(db, asset, org_id, scan_id, cve_list)

    # 2. PHASE 4: VULNERABILITY STATUS HISTORY
    found_cve_ids = {
        _clean_text(v.get("cve_id") or v.get("cve") or v.get("id"))
        for v in (cve_list or [])
    }
    found_cve_ids = {cid for cid in found_cve_ids if cid}

    current_open = (
        db.query(AssetVulnerability)
        .filter(
            AssetVulnerability.asset_id == asset.id, AssetVulnerability.status == "open"
        )
        .all()
    )

    # Which configuration checks actually produced a verdict this run, and
    # therefore which absent configuration findings are genuinely gone.
    _config_summary = (stored_report or {}).get("config_audit") or {}
    _assessed_checks = _assessed_config_definition_ids(_config_summary)

    from core.checks.definitions import DEFINITION_TYPE_CVE, definition_type_for_id

    for f in current_open:
        if _finding_family(_finding_source_from_record(f)) != "credentialed_package":
            continue
        if f.vuln_id in found_cve_ids:
            continue
        # A configuration or privilege finding is only fixed if its check ran
        # and answered. Package findings keep the previous behaviour: the
        # matcher runs over the whole installed inventory, so a CVE it does not
        # report on a host it inventoried really is gone.
        if definition_type_for_id(f.vuln_id) != DEFINITION_TYPE_CVE:
            if f.vuln_id not in _assessed_checks:
                # Not assessed is not fixed. Left open, and the scan's recorded
                # assessment scope is what lets a comparison say so out loud
                # rather than silently carrying it forward.
                continue
        f.status = "fixed"
        f.fixed_at = utcnow()
        _record_asset_change(
            db, asset.id, scan_id, "vulnerability_fixed", f.vuln_id, "fixed"
        )

    # What this scan looked at, so a later comparison can tell "gone" from
    # "nobody looked". Smallest clean record: merged into `scans.options`,
    # which is JSONB and already carries `options.origin`. GAP-12's policy
    # engine is where this eventually belongs; it is deliberately not built here.
    try:
        from core.findings import record_assessment_scope
        from db.models.scans import Scan as _Scan

        _scan_row = db.query(_Scan).filter(_Scan.id == scan_id).first()
        if _scan_row is not None:
            record_assessment_scope(
                _scan_row,
                assets=[asset.id],
                families=["credentialed_package"],
                detail={
                    "config_audit_assessed": bool(_config_summary.get("assessed")),
                    "checks_assessed": len(_assessed_checks),
                    # The set itself, not only its size. The sweep above uses
                    # it to decide which absent configuration findings are
                    # genuinely gone; without it recorded, a later comparison
                    # has only the *family* to go on — and every credentialed
                    # finding shares one family, so a scan narrowed by a GAP-12
                    # policy reported the checks it stopped selecting as fixed.
                    # Measured on a real target: five controls reported
                    # remediated on a host where nothing had changed, while
                    # this same sweep had correctly left them open.
                    #
                    # Only checks that reached a verdict are in it, so it is
                    # tens of ids rather than the whole selected set.
                    "assessed_checks": sorted(_assessed_checks),
                },
            )
    except Exception as exc:  # never fail a scan over its own bookkeeping
        log.warning("Could not record assessment scope for scan %s: %s", scan_id, exc)

    db.flush()

    # Recalculate aggregate vuln_counts
    counts, agg_score, agg_level = _recalculate_asset_risk(db, asset.id)
    asset.vuln_counts = counts
    asset.risk_score = agg_score
    asset.risk_level = agg_level

    # Custom attributes merge
    attrs = dict(asset.custom_attributes or {})
    credentialed_attrs = dict(attrs.get("credentialed_system_info") or {})
    credentialed_attrs.update(
        {
            "os_name": os_name,
            "os_version_id": os_version,
            "os_family": os_family,
            "os_build": os_build,
            "kernel_version": kernel_version,
            "hardware_model": _clean_text(system_data.get("hardware_model")),
            "cpu_model": _clean_text(system_data.get("cpu_model")),
            "cpu_count": _clean_text(system_data.get("cpu_count")),
            "uptime": _clean_text(system_data.get("uptime")),
            "hostname": hostname,
            "hostname_short": _clean_text(system_data.get("hostname_short")),
            "hostname_fqdn_raw": raw_hostname_fqdn,
            "netbios_name": netbios_name,
            "fqdn": fqdn,
            "serial_number": _clean_text(system_data.get("serial_number")),
            "bios_version": _clean_text(system_data.get("bios_version")),
            "local_groups": system_data.get("local_groups", []),
            "mac_address": mac_address,
            "mac_vendor": mac_vendor,
            "vendor": vendor,
            "domain": _clean_text(system_data.get("domain")),
            "subnet": subnet,
            "manufacturer": manufacturer,
            "credentialed_response_time_ms": credentialed_response_time,
            "detected_os": normalized_os_type or os_type,
            "source_scan_id": scan_id,
            "synced_at": utcnow().isoformat(),
            "running_services": system_data.get("running_services", []),
            "suspicious_scheduled_tasks": system_data.get(
                "suspicious_scheduled_tasks", []
            ),
            "cron_info_raw": system_data.get("cron_info_raw", ""),
        }
    )
    attrs["credentialed_system_info"] = {
        key: value
        for key, value in credentialed_attrs.items()
        if value is not None and value != ""
    }

    # Compliance Engine Evidence Mappings. The literal used to live here and
    # only here, which is why the Vulnerability Audit's credentialed pass never
    # set it — there was nothing to call.
    attrs["credentialed_status"] = CREDENTIALED_STATUS_SUCCESS

    # Password policy is *collected*, never assumed. This used to be a
    # hard-coded {complexity: True, history_length: 24, min_length: 14}
    # regardless of the host, so every rule reading it passed unconditionally
    # on every machine — a fabricated value presented to an auditor as
    # evidence. Keys the collector could not determine are omitted entirely,
    # which the compliance engine renders as "not assessed" rather than as a
    # pass or a fail.
    collected_pwd = system_data.get("password_policy") or {}
    password_policy = {
        k: v
        for k, v in {
            "complexity": collected_pwd.get("complexity"),
            "history_length": collected_pwd.get("history_length"),
            "min_length": collected_pwd.get("min_length"),
            "max_age_days": collected_pwd.get("max_age_days"),
            "lockout_threshold": collected_pwd.get("lockout_threshold"),
        }.items()
        if v is not None
    }
    if password_policy:
        attrs["password_policy"] = password_policy
    else:
        attrs.pop("password_policy", None)
        log.info(
            "No password policy collected for asset=%s; compliance controls "
            "depending on it will report as not assessed.",
            asset.id,
        )

    # Registry Hardening / Firewall / RDP status
    issues = system_data.get("security_issues") or []
    fw_disabled = any(
        "Firewall profile" in issue and "is DISABLED" in issue for issue in issues
    )

    rdp_enabled = system_data.get("rdp_enabled")
    if rdp_enabled is None:
        rdp_enabled = any("RDP is enabled" in issue for issue in issues)

    uac_disabled = any(
        "UAC" in issue and "disabled" in issue.lower() for issue in issues
    )

    audit_configured = True
    if normalized_os_type == "windows" and not system_data.get("audit_policy"):
        audit_configured = False
    elif normalized_os_type == "linux":
        running_svcs = system_data.get("running_services") or []
        audit_configured = any(svc.get("name") == "auditd" for svc in running_svcs)

    if normalized_os_type == "linux":
        running_svcs = system_data.get("running_services") or []
        fw_active = any(
            svc.get("name") in ("ufw", "firewalld", "iptables") for svc in running_svcs
        )
    else:
        fw_active = not fw_disabled

    attrs["registry_hardening"] = {
        "firewall_active": fw_active,
        "rdp_disabled": not rdp_enabled,
        "uac_enabled": not uac_disabled,
        "audit_configured": audit_configured,
        # No ``False`` default: an absent key means the collector did not read
        # the setting, and defaulting it asserts the insecure state as fact —
        # a FAIL nothing established, which is the same defect as the PASS the
        # collector used to synthesise, pointing the other way. ``None`` travels
        # to the evidence adapter, which drops it, and a dropped key routes the
        # rule to manual review.
        "smbv1_disabled": system_data.get("smbv1_disabled"),
        "netbios_disabled": system_data.get("netbios_disabled"),
        "legacy_tls_disabled": system_data.get("legacy_tls_disabled"),
        "telnet_disabled": system_data.get("telnet_disabled"),
        "rdp_nla_enforced": system_data.get("rdp_nla_enforced"),
    }

    asset.custom_attributes = attrs
    asset.last_scan_id = scan_id
    asset.last_seen_at = utcnow()
    asset.updated_at = utcnow()
    log.info(
        "Credentialed asset sync updated asset=%s ip=%s os=%s",
        asset.id,
        ip,
        asset.os_name,
    )


def _extract_credentialed_identity_names(system_data: dict) -> tuple[str, str, str]:
    raw_hostname_fqdn = _clean_text(system_data.get("hostname_fqdn"))
    explicit_fqdn = _clean_text(system_data.get("fqdn"))
    hostname_short = _clean_text(system_data.get("hostname_short"))
    hostname = _clean_text(
        system_data.get("hostname")
        or hostname_short
        or (raw_hostname_fqdn.split(".")[0] if raw_hostname_fqdn else "")
    )
    fqdn = (
        explicit_fqdn
        if "." in explicit_fqdn
        else (raw_hostname_fqdn if "." in raw_hostname_fqdn else "")
    )
    return hostname, fqdn, raw_hostname_fqdn


def _unique_lines(text) -> str:
    """
    Collapse repeated lines, keeping order and every distinct one.

    A SCAP rule evaluates one object per branch of its criteria and each
    contributes a line to the raw reading, so a rule with seven registry
    objects that all found nothing produces the same sentence seven times.
    The distinct lines are what a reader needs; the repeats push them off
    the page.
    """
    seen = []
    for line in str(text or "").splitlines():
        if line not in seen:
            seen.append(line)
    return "\n".join(seen)


def _clean_text(value) -> str:
    return str(value or "").strip()


def _normalize_mac(value) -> str:
    """
    Canonical ``aa:bb:cc:dd:ee:ff`` for asset identity, or ``""``.

    The parsing is ``core.mac.mac_colon``; the policy — that a reserved address
    is not an identity — is applied here, because it is this caller's. It is
    applied to the *normalized* value, and the order is the whole point.

    The reserved check used to run against the raw text, so it only recognised
    the two addresses spelled exactly as they appear in ``RESERVED_MACS``.
    ``000000000000``, ``0:0:0:0:0:0`` and ``0000.0000.0000`` are the same
    all-zero address written differently; every one of them slipped past and
    was returned as ``00:00:00:00:00:00``. ``ffffffffffff`` did the same for
    broadcast.

    That matters because ``assets`` is keyed on ``(org_id, mac_address)``. Any
    number of hosts can report an all-zero MAC — it is what a NIC with no
    hardware address, some hypervisor interfaces and a failed read all produce —
    and each one that got through claimed the same asset row, so they collapsed
    into a single host that appeared to change identity on every scan. Returning
    ``""`` instead sends the caller down the IP-based identity path, which is
    what it already does for a host whose MAC could not be read at all.

    Reserved addresses are compared after normalization for the same reason the
    hex check happens after it: a value is only comparable once it is in one
    form.
    """
    return mac_identity(value) or ""


def _credentialed_sections_with_identity(
    sections: list[str] | None,
) -> list[str] | None:
    if sections is None:
        return None
    required = ["system_info", "network"]
    merged = list(sections)
    for section in required:
        if section not in merged:
            merged.append(section)
    return merged


def _port_int(value) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if 1 <= port <= 65535:
        return port
    return None


def _sync_credentialed_services(
    db, asset: Asset, scan_id: str, ports: list[dict], packages: list[dict] = None
) -> None:
    """Persist the host's listening sockets. See asset_syncer for the semantics."""
    from scans.asset_syncer import upsert_credentialed_services

    upsert_credentialed_services(db, asset.id, scan_id, ports or [], packages)


def _first_advisory(vuln: dict, key: str) -> str | None:
    """The first vendor advisory's field, when the finding carries any."""
    advisories = vuln.get("vendor_advisories") or []
    if not isinstance(advisories, list):
        return None
    for entry in advisories:
        if isinstance(entry, dict) and entry.get(key):
            return str(entry[key])[:2000]
    return None


def _sync_credentialed_vulnerabilities(
    db,
    asset: Asset,
    org_id: str,
    scan_id: str,
    cve_list: list[dict],
) -> None:
    from core.checks.definitions import (
        DEFINITION_TYPE_CVE,
        definition_type_for_id,
    )
    from scans.asset_syncer import _catalog_title, _resolve_finding_id

    source_family = "credentialed_package"
    for vuln in cve_list or []:
        cve_id = _clean_text(vuln.get("cve_id") or vuln.get("cve") or vuln.get("id"))
        if not cve_id:
            continue

        # What kind of catalogue row this identifier names. `cve_list` carries
        # configuration and privilege findings alongside package CVEs — that is
        # deliberate, and `_run_configuration_audit` documents it — so not every
        # entry here is a CVE. This function assumed they all were: it wrote the
        # identifier into `cve_id` and let `definition_type` take its 'cve'
        # default.
        #
        # Two consequences, one loud and one silent. `cve_id` is varchar(30) and
        # a minted id is longer — CCURE-CFG-CCURE-LINUX-AUDITD-RUNNING is 37 —
        # so the INSERT raised StringDataRightTruncation and **aborted the
        # finding sync for the entire scan**, losing the package findings with
        # it. Where the id did fit, the row inherited everything a CVE row
        # means: KEV lookups, EPSS scores, CVSS bands, and an NVD link that
        # resolves to nothing.
        #
        # Recovered from the identifier rather than trusted from the finding,
        # exactly as `asset_syncer` does on the network path, because the
        # finding is built by a plugin and the catalogue's CHECK constraint
        # `ck_vuln_def_cve_id_matches_type` is what has to hold.
        definition_type = definition_type_for_id(cve_id)
        is_real_cve = definition_type == DEFINITION_TYPE_CVE

        cvss = float(vuln.get("cvss_score", vuln.get("cvss", 0.0)) or 0.0)
        # Derived from the score and stored in the one canonical (lower) case.
        #
        # This wrote `.title()` of whatever the matcher supplied, which is how
        # "High" and "high" came to coexist in the same column — the split that
        # made GROUP BY return two rows for one severity and cost the dashboard
        # 100 of 146 findings. Deriving from the score also stops a feed's
        # textual rating disagreeing with the vector it published.
        from scans.cvss import canonical_severity, severity_from_score

        severity = (
            severity_from_score(cvss).lower()
            if cvss
            else canonical_severity(vuln.get("severity"))
        )
        description = _clean_text(vuln.get("description") or vuln.get("desc"))
        package_name = _clean_text(vuln.get("package"))
        installed_ver = _clean_text(vuln.get("installed_ver"))
        fixed_ver = _clean_text(vuln.get("fixed_ver"))

        proof = _clean_text(
            f"Source_Family:credentialed_package\nPackage: {package_name} {installed_ver}".strip()
        )
        plugin_output = _clean_text(
            f"{description}\nFixed version: {fixed_ver or 'N/A'}\nPriority: {vuln.get('priority_level') or 'N/A'} ({vuln.get('priority_score') or 0})"
        )

        # Get enriched details from local CVE database if available
        cvss_vector = vuln.get("cvss_vector")
        cwe_ids = []
        references = []

        try:
            from core.cve_database import get_cve_database

            cve_db = get_cve_database() if is_real_cve else None
            if cve_db is not None and cve_db.db_available:
                details = cve_db.get_cve_details(cve_id)
                if details:
                    description = details.get("description") or description
                    cvss_vector = (
                        details.get("cvss_vector")
                        or details.get("cvss_v3_vector")
                        or cvss_vector
                    )
                    cwe_ids = details.get("cwe_ids") or []

                    raw_refs = details.get("references") or []
                    clean_refs = []
                    for ref in raw_refs:
                        if isinstance(ref, str):
                            clean_refs.append(ref)
                        elif isinstance(ref, dict) and ref.get("url"):
                            clean_refs.append(ref["url"])
                    references = clean_refs
        except Exception as e:
            log.warning(
                "Failed to lookup CVE details for %s during credentialed sync: %s",
                cve_id,
                e,
            )

        # 1. UPSERT CVE Definition
        cve_insert = insert(VulnerabilityDefinition).values(
            id=cve_id,
            # NULL for anything that is not a published CVE. This is the column
            # every join to the vulnerability feeds runs through, so a check row
            # carrying a CVE-shaped string here is how a configuration weakness
            # acquires an exploit record, a KEV due date and a CVSS band that
            # belong to nothing.
            cve_id=cve_id if is_real_cve else None,
            definition_type=definition_type,
            title=(
                f"{cve_id} in {package_name}"
                if (is_real_cve and package_name)
                else _catalog_title(vuln, cve_id, description)
            ),
            description=description,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            references=references,
            severity=severity,
            cvss_v3_score=cvss,
            source="credentialed",
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.execute(cve_insert.on_conflict_do_nothing(index_elements=["id"]))

        # 2. UPSERT Finding
        finding_id = _resolve_finding_id(db, org_id, asset.id, cve_id, source_family)
        evidence_text = (
            (
                f"Source           : authenticated package query\n"
                f"Package          : {package_name or 'unknown'}\n"
                f"Installed version: {installed_ver or 'not reported'}\n"
                f"Fixed in         : {fixed_ver or 'no fixed version published'}\n"
                f"Reference        : https://nvd.nist.gov/vuln/detail/{cve_id}"
            )
            if is_real_cve
            # A configuration or privilege check has no package and no fixed
            # version, so three of those lines would read 'unknown' or 'not
            # reported', and it has no NVD record, so the reference would be
            # a link to a page that does not exist. The check's own
            # expected-versus-observed reading is the evidence here.
            else (
                "Source           : authenticated configuration check\n"
                + (
                    _clean_text(vuln.get("evidence"))
                    or (
                        f"Expected: {vuln.get('expected_state') or 'not stated'}\n"
                        f"Observed: {vuln.get('observed_state') or 'not stated'}"
                    )
                )
            )
        )

        fnd_insert = insert(AssetVulnerability).values(
            id=finding_id,
            org_id=org_id,
            scan_id=scan_id,
            asset_id=asset.id,
            vuln_id=cve_id,
            severity=severity,
            cvss_score=cvss,
            status="open",
            source_family=source_family,
            evidence_source="credentialed",
            proof=proof,
            plugin_output=plugin_output,
            # An authenticated package match is the strongest evidence this
            # product produces: the version came from the host's own package
            # manager, not from a banner.
            evidence=evidence_text,
            confidence="Confirmed",
            qod=97,
            detection_method="credentialed_package",
            detected_version=installed_ver or None,
            cvss_vector=_clean_text(cvss_vector) or None,
            component=(package_name or None),
            component_version=(installed_ver or None),
            component_fixed_version=(fixed_ver or None),
            in_kev=bool(vuln.get("in_kev")),
            has_exploit=bool(vuln.get("has_exploit")),
            # Exploitation provenance and the vendor's advisory, both joined on
            # the CVE upstream. Stored so triage can separate a weaponised
            # exploit from a proof of concept without re-querying the feeds.
            exploit_sources=(list(vuln.get("exploit_sources") or []) or None),
            verified_exploit=bool(vuln.get("verified_exploit")),
            canary_confirmed=bool(vuln.get("canary_confirmed")),
            ransomware_linked=bool(vuln.get("ransomware_linked")),
            vendor_advisory_id=_first_advisory(vuln, "advisory_id"),
            vendor_advisory_url=_first_advisory(vuln, "url"),
            vendor_remediation=_clean_text(vuln.get("vendor_remediation")) or None,
            first_scan_id=scan_id,
            first_found_at=utcnow(),
            last_found_at=utcnow(),
        )

        fnd_upsert = fnd_insert.on_conflict_do_update(
            index_elements=["id", "org_id"],
            set_={
                "last_found_at": utcnow(),
                "scan_id": scan_id,
                "status": "open",
                "severity": severity,
                "cvss_score": cvss,
                "source_family": source_family,
                "evidence_source": "credentialed",
                # Refreshed for the same reason the version fields below are.
                # Evidence describes what *this* scan observed; a finding that
                # stays open otherwise reports the reading from the day it was
                # first seen. On a configuration check that is the whole
                # content of the finding — "Observed: 0" survives a partial
                # remediation to 8 — and the report then argues from a
                # measurement the host has already moved past.
                "evidence": func.coalesce(
                    func.nullif(evidence_text, ""), AssetVulnerability.evidence
                ),
                "proof": func.coalesce(
                    func.nullif(proof, ""), AssetVulnerability.proof
                ),
                "plugin_output": func.coalesce(
                    func.nullif(plugin_output, ""), AssetVulnerability.plugin_output
                ),
                # What this scan observed, refreshed on every re-scan.
                #
                # These were previously written only on first insert, so a
                # finding that stayed open kept the version from the day it was
                # first seen: a host upgraded from Chrome 138 to 139 with the
                # CVE still unfixed went on reporting 138 indefinitely, and the
                # grouped row would have advised an upgrade already performed.
                "component": (package_name or None),
                "component_version": (installed_ver or None),
                "component_fixed_version": (fixed_ver or None),
                "detected_version": (installed_ver or None),
                # Exploit corpora and vendor advisories change between scans:
                # an exploit gets published, a vendor issues an advisory. A
                # finding that keeps its first-seen provenance forever would
                # under-report both.
                "exploit_sources": (list(vuln.get("exploit_sources") or []) or None),
                "verified_exploit": bool(vuln.get("verified_exploit")),
                "canary_confirmed": bool(vuln.get("canary_confirmed")),
                "ransomware_linked": bool(vuln.get("ransomware_linked")),
                "vendor_advisory_id": _first_advisory(vuln, "advisory_id"),
                "vendor_advisory_url": _first_advisory(vuln, "url"),
                "vendor_remediation": _clean_text(vuln.get("vendor_remediation"))
                or None,
            },
        )
        db.execute(fnd_upsert)


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
                from core.tasks import run_asset_discovery_task

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
    name="ccure.tasks.run_asset_discovery",
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
                from core.tasks import run_vulnerability_audit_task

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


# ── Phase 3.5 — credentialed enrichment of the Vulnerability Audit ───────────
#
# Established scanners do not treat "credentialed" as a separate scan type.
# Credentials are a policy option on the ordinary scan: discovery, port
# scanning and unauthenticated checks run first, and where credentials are
# available the scanner also logs in and merges local checks into the same
# result set. That ordering is what makes the two views worth more than their
# sum — the port scan says what is reachable, the authenticated session says
# what is installed, and only together do they distinguish a vulnerable package
# that is exposed from one that is not.
#
# This runs inside the phase-3 task, before the report is generated, so there
# is one report, one asset sync and one set of counts rather than a second scan
# to reconcile afterwards.


def _credentialed_plan_for_scan(db, scan_row) -> list[dict]:
    """
    Credentials configured for this scan, decrypted and scoped.

    Contract, carried in ``scan.options`` alongside ``snmp``::

        "credentials": [
            {"credential_id": "...", "targets": ["10.0.0.0/24"]},
            {"credential_id": "..."}                 # applies to every host
        ]

    A malformed or inaccessible entry is skipped with a warning rather than
    failing the scan: the unauthenticated results are still valid and worth
    delivering, and the coverage block records that the credentialed pass did
    not cover every host.
    """
    import ipaddress

    if not scan_row or not scan_row.options:
        return []
    raw = scan_row.options.get("credentials") or []
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []

    plan: list[dict] = []
    for entry in raw:
        if isinstance(entry, str):
            entry = {"credential_id": entry}
        if not isinstance(entry, dict):
            continue
        credential_id = entry.get("credential_id")
        if not credential_id:
            continue
        try:
            material = _resolve_stored_credential(db, str(scan_row.id), credential_id)
        except Exception as exc:  # noqa: BLE001 — one bad credential is not fatal
            log.warning(
                "Credentialed enrichment: credential %s unusable for scan %s: %s",
                credential_id,
                scan_row.id,
                exc,
            )
            continue

        networks = []
        for token in entry.get("targets") or []:
            try:
                networks.append(ipaddress.ip_network(str(token).strip(), strict=False))
            except ValueError:
                log.warning(
                    "Credentialed enrichment: ignoring unparseable scope '%s'", token
                )
        plan.append({"material": material, "networks": networks or None})
    return plan


def _restate_findings_for_corrected_ports(
    findings: list[dict], corrected: dict[tuple[int, str], str]
) -> int:
    """
    Point findings at the corrected version for the port they were raised on.

    A finding records the version that was detected when the plugin raised it,
    and verification reads that recorded value before it looks at the host's
    service inventory. So correcting the inventory alone changes nothing: the
    finding still carries "9.6.0 or later" and is still judged against it.

    This is what makes the authenticated correction take effect. It restates
    what was detected, on the ports where a better reading exists; it does not
    touch the finding's severity, its CPE data, or anything the feed published.
    """
    restated = 0
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        try:
            port = int(str(finding.get("port")).strip())
        except (TypeError, ValueError):
            continue
        version = corrected.get((port, str(finding.get("protocol") or "tcp").lower()))
        if not version:
            continue
        if str(finding.get("detected_version") or "").strip() == version:
            continue
        finding["detected_version"] = version
        # What the previous verification pass derived from the superseded
        # version goes with it. Left in place, "fixed in 14.23" — the first
        # branch's boundary, chosen while the version was only "9.6.0 or
        # later" — was read back as if the feed had published it, and an 18.3
        # server was told to upgrade to 14.23. Nothing a plugin or feed
        # supplied is touched: derived evidence is marked as such.
        finding.pop("fixed_version", None)
        finding.pop("last_affected_version", None)
        if finding.get("evidence_captured") is False:
            finding.pop("evidence", None)
        restated += 1
    return restated


def _upgrade_network_fingerprints(
    network_ports: list[dict], listeners: list[dict]
) -> dict[tuple[int, str], str]:
    """
    Replace remote version guesses with what the host itself reports.

    A remote fingerprint is an inference from what a service volunteers. Nmap
    reads PostgreSQL's protocol handshake and can only conclude "9.6.0 or
    later" — an open-ended bound, which by design cannot disprove any CVE fixed
    after 9.6. The authenticated session reads the binary's own version
    resource and knows it is 18.3.

    Leaving the weaker value in place is not a reporting cosmetic; it is the
    difference between 42 PostgreSQL CVEs reported against a host that is not
    affected by any of them, and none. Enterprise scanners resolve this the
    same way: where an authenticated reading exists, it supersedes the remote
    guess, and every later stage — verification, risk scoring, the report —
    then works from the better value.

    Upgrades in place and returns ``{(port, protocol): version}`` for what was
    corrected. Deliberately conservative: only an exact host-side version, and
    only where the two observations agree on what the product is.
    """
    from scans.finding_normalizer import (
        _name_tokens,
        vendor_build_for,
        version_precision,
    )

    by_key: dict[tuple[int, str], dict] = {}
    for listener in listeners or []:
        try:
            port = int(str(listener.get("port")).strip())
        except (TypeError, ValueError):
            continue
        proto = str(listener.get("protocol") or "tcp").lower()
        # First listener on a port wins; duplicates are the same process bound
        # to several addresses.
        by_key.setdefault((port, proto), listener)

    upgraded: dict[tuple[int, str], str] = {}
    for record in network_ports or []:
        if not isinstance(record, dict):
            continue
        try:
            port = int(str(record.get("port")).strip())
        except (TypeError, ValueError):
            continue
        proto = str(record.get("protocol") or "tcp").lower()
        listener = by_key.get((port, proto))
        if not listener:
            continue

        host_version = str(listener.get("version") or "").strip()
        if not host_version or version_precision(host_version) != "exact":
            continue

        # Agreement on the product. A middlebox or forwarded port can put
        # something else entirely behind the port the scanner reached, and
        # stamping the local binary's version onto it would be worse than the
        # imprecise fingerprint it replaced.
        net_tokens = set(_name_tokens(record.get("product") or ""))
        host_tokens = set(_name_tokens(listener.get("product") or ""))
        if net_tokens and host_tokens and not (net_tokens & host_tokens):
            continue

        net_version = str(record.get("version") or "").strip()
        # A vendor's build reports a floor, and the host's own reading of it is
        # the vendor's file or package version — Microsoft's sshd.exe 9.5.6.3,
        # Ubuntu's 1:8.9p1-3ubuntu0.10 — which no upstream range describes.
        # Substituting it dropped the marker that says so, and twenty upstream
        # OpenSSH CVEs came back as Confirmed (10.180.6.30, scan #11).
        if vendor_build_for(
            net_version,
            record.get("product"),
            record.get("banner"),
            record.get("extra"),
            listener.get("product"),
        ):
            continue
        if net_version and version_precision(net_version) == "exact":
            continue  # the scan already has a precise value; leave it alone

        record["version"] = host_version[:200]
        record["version_precision"] = "exact"
        record["fingerprint_source"] = "credentialed"
        if not record.get("product") and listener.get("product"):
            record["product"] = str(listener["product"])[:255]
        upgraded[(port, proto)] = host_version[:200]

    return upgraded


def _ports_probed_in_phase2(scan_row) -> list[int] | None:
    """
    The exact port set the asset discovery phase probed, if it recorded one.

    Returns ``None`` when the scan predates the engine publishing this, or when
    the spec cannot be parsed. That is the honest answer, and it makes the
    correlation fall back to "not determined" rather than reporting every
    unprobed listener as firewalled.
    """
    if not scan_row:
        return None
    try:
        from core.utils import InputValidator

        summary = phase_summary_from_scan(scan_row, "asset_discovery", "phase2") or {}
        spec = summary.get("ports_probed_spec")
        if not spec:
            return None
        return InputValidator.parse_custom_ports(str(spec))
    except Exception as exc:  # noqa: BLE001 — absence is a valid answer here
        log.debug("Could not read the phase-2 probed port set: %s", exc)
        return None


def _credential_for_host(plan: list[dict], ip: str) -> dict | None:
    """The first configured credential whose scope covers this host."""
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        addr = None

    for entry in plan:
        networks = entry["networks"]
        if not networks:
            return entry["material"]
        if addr is not None and any(addr in net for net in networks):
            return entry["material"]
    return None


def _as_credentialed_findings(cve_list: list[dict], packages: list[dict]) -> list[dict]:
    """
    Prepare package findings to be merged into a network-scanned host record.

    Two fields have to be stamped on explicitly. ``detection_method`` because
    verification asserts credentialed origin from the record and never infers
    it — an unmarked package finding arriving on a host that also has
    fingerprinted services is treated as a network claim about a product the
    host does not appear to run, and suppressed. ``installed_version`` because
    the matcher emits ``installed_ver``, which is not one of the keys the
    version check reads; without it every finding degrades to "package
    present" and loses the version evidence the audit actually collected.
    """
    versions = {
        str(p.get("name") or "").strip(): str(p.get("version") or "").strip()
        for p in packages or []
        if isinstance(p, dict) and p.get("name")
    }

    prepared: list[dict] = []
    for raw in cve_list or []:
        if not isinstance(raw, dict):
            continue
        record = dict(raw)
        record.setdefault("detection_method", "credentialed")
        if not record.get("installed_version"):
            installed = record.get("installed_ver") or versions.get(
                str(record.get("package") or "").strip(), ""
            )
            if installed:
                record["installed_version"] = installed
        prepared.append(record)
    return prepared


def _apply_credentialed_enrichment(
    db, scan_row, hosts: list[dict], scan_id: str | None = None
) -> dict | None:
    """
    Authenticate to every in-scope host and merge what the OS reports.

    Mutates ``hosts`` in place and returns a coverage summary, or ``None`` when
    no credentials were configured — in which case the scan is an ordinary
    unauthenticated audit and nothing here should alter it.
    """
    from core.redis_client import publish_progress_sync
    from core.risk import calculate_risk
    from scans.asset_syncer import CREDENTIALED_STATUS_FAILED
    from scans.finding_normalizer import verify_host_findings

    plan = _credentialed_plan_for_scan(db, scan_row)
    if not plan:
        # Distinguish "no credentials were configured" from "credentials were
        # configured and none of them could be used".
        #
        # Both used to return None, so a scan whose credentials failed to
        # decrypt completed as an ordinary unauthenticated audit with nothing
        # anywhere to say the authenticated pass had been skipped — same status,
        # same counts, no warning in the summary or the report. An operator who
        # asked for a credentialed audit had no way to tell they had not got
        # one.
        requested = (scan_row.options or {}).get("credentials") if scan_row else None
        if requested:
            count = len(requested) if isinstance(requested, list) else 1
            log.error(
                "Scan %s requested credentialed enrichment with %d credential(s) "
                "but none could be resolved — continuing as an unauthenticated "
                "audit. Check that COMPLIANCE_ENCRYPTION_KEY is identical for the "
                "API and the scanner worker.",
                getattr(scan_row, "id", "?"),
                count,
            )
            return {
                "is_credentialed": False,
                "credentialed_requested": count,
                "credentialed_hosts": 0,
                "credentialed_skipped": [
                    {
                        "target": "all",
                        "reason": (
                            "Configured credentials could not be decrypted or "
                            "resolved. Results below are unauthenticated."
                        ),
                    }
                ],
                "credentialed_error": (
                    "Credentialed enrichment was requested but no credential "
                    "could be used; these results are unauthenticated."
                ),
            }
        return None

    scanned_ports = _ports_probed_in_phase2(scan_row)
    active = [h for h in hosts if h.get("is_active")]
    audited: list[str] = []
    skipped: list[dict] = []
    upgraded_total = 0

    # Benchmark content this organisation has installed, resolved once for the
    # whole scan rather than per host: the same query per target repeats work
    # and could disagree between hosts if content were loaded mid-scan.
    #
    # Resolved *here* rather than at the top of the function so a scan with no
    # credentials configured — which returns long before this point — does not
    # pay for a query whose results it will never use.
    #
    # `getattr` rather than `scan_row.org_id`: a caller that hands this a row
    # with no organisation has a defect worth a warning, but not one worth
    # failing an entire scan whose findings are already collected. Without an
    # organisation there is no installed content to resolve, so the audit falls
    # back to the built-in rules and says so.
    #
    # GAP-12: the scan's effective policy decides *which* installed content is
    # resolved and at what severity floor. It is read from the scan's own row
    # rather than passed in, because that row is the immutable record the
    # report and the comparison read — so what executed and what is recorded
    # cannot disagree. A scan with no snapshot resolves everything installed,
    # which is exactly the pre-policy behaviour.
    from core.scan_policy import read_policy_snapshot

    _policy = read_policy_snapshot(scan_row)
    _org_id = getattr(scan_row, "org_id", None)
    _benchmark_checks: list = []
    if _org_id:
        from core.benchmarks.selection import benchmark_checks_for_org

        _benchmark_checks = benchmark_checks_for_org(
            db,
            str(_org_id),
            profile=getattr(_policy, "benchmark_profile", None),
            platforms=list(getattr(_policy, "platforms", ()) or ()) or None,
            framework_ids=list(getattr(_policy, "framework_ids", ()) or ()) or None,
            min_severity=getattr(_policy, "min_severity", None),
            excluded_check_ids=list(getattr(_policy, "excluded_check_ids", ()) or ())
            or None,
            excluded_tags=list(getattr(_policy, "excluded_tags", ()) or ()) or None,
        )
    else:
        log.warning(
            "Credentialed enrichment has no organisation for scan %s; benchmark "
            "content will not be applied and only the built-in rules run.",
            getattr(scan_row, "id", "?"),
        )

    for index, host in enumerate(active):
        ip = host.get("ip_address") or host.get("ip")
        if not ip:
            continue

        material = _credential_for_host(plan, ip)
        if not material:
            skipped.append({"target": ip, "reason": "No credential in scope"})
            continue

        # A database credential names an instance, not a host. Handing one to
        # the host auditor opens an SSH session against a database port and
        # reports the machine as unreachable — the standalone task branches on
        # this and this path did not, so a scan carrying a mixed credential set
        # produced a spurious failure for every host the database credential
        # was in scope for.
        credential_type = material.get("credential_type") or CREDENTIAL_TYPE_SSH
        if credential_type == CREDENTIAL_TYPE_DATABASE:
            skipped.append(
                {
                    "target": ip,
                    "reason": (
                        "Credential in scope is a database credential; host "
                        "enrichment needs an SSH or WinRM credential"
                    ),
                }
            )
            continue

        transport = material.get("transport") or "ssh"
        credential_options = dict(material.get("options") or {})
        open_ports = host.get("open_ports") or []

        # Where to authenticate is resolved from the port scan's own service
        # identification, not from a constant. This used to be
        # ``int(material.get("port") or 22)`` — an SSH port for every credential
        # type — and the host was then skipped whenever the port scan did not
        # find that exact number open. A host running sshd on 2222 was skipped
        # on a scan that had already identified sshd on 2222.
        #
        # The port scan's view stays authoritative: a candidate it found closed
        # is still not attempted, because a 20-second handshake per host to
        # learn what is already known is minutes across a large scan.
        resolution = resolve_endpoint(
            ip=ip,
            transport=transport,
            stated_port=material.get("port"),
            use_tls=credential_options.get("use_tls"),
            open_ports=open_ports,
        )
        if not resolution.resolved:
            skipped.append({"target": ip, "reason": resolution.reason})
            continue

        endpoint = resolution.endpoint
        port = endpoint.port
        if endpoint.use_tls is not None:
            credential_options["use_tls"] = endpoint.use_tls
        if endpoint.source != "credential":
            log.info(
                "Credentialed enrichment: %s resolved to port %s over %s — %s",
                ip,
                port,
                transport.upper(),
                endpoint.evidence,
            )

        if scan_id:
            publish_progress_sync(
                scan_id,
                3,
                {
                    "status": "running",
                    "stage": "credentialed",
                    "message": f"Authenticated checks on {ip} ({index + 1}/{len(active)})",
                    "target": ip,
                },
            )

        try:
            stored_report, system_data, _os_type = audit_credentialed_host(
                config_checks=_benchmark_checks,
                policy=_policy,
                ip=ip,
                username=material.get("username"),
                password=material.get("password"),
                key_content=material.get("key_content"),
                key_passphrase=material.get("key_passphrase"),
                nt_hash=material.get("nt_hash"),
                port=port,
                os_type_req="auto",
                network_ports=open_ports,
                network_scanned=True,
                scanned_ports=scanned_ports,
                # Carried through so a Windows credential reaches its host over
                # WinRM. Without these four this path defaulted every credential
                # to SSH whatever the stored record said, so a Windows
                # credential opened an SSH handshake against a WinRM listener
                # and the host was recorded as a connection failure.
                transport=transport,
                auth_method=material.get("auth_method") or "password",
                domain=material.get("domain"),
                credential_options=credential_options,
            )
            # See _strip_nul: one NUL in a collected UTF-16LE string aborts the
            # whole result commit and loses every finding.
            stored_report = _strip_nul(stored_report)
            system_data = _strip_nul(system_data)
        except Exception as exc:  # noqa: BLE001 — recorded, scan continues
            log.warning("Credentialed enrichment failed for %s: %s", ip, exc)
            skipped.append({"target": ip, "reason": str(exc)})
            # An attempt that was made and refused is a different fact from one
            # that was never made, and the asset sync writes both distinctly.
            # Reading either as "success" would let the compliance engine turn
            # a host nobody could authenticate to into a passing verdict.
            host["credentialed_status"] = CREDENTIALED_STATUS_FAILED
            continue

        # Resolve each listening process to its installed package here, while
        # the inventory is in hand. Doing it now means the stored host record
        # does not have to carry a few thousand package rows per host purely so
        # the asset sync can repeat the lookup later.
        from scans.asset_syncer import _service_identity_from_process

        packages = stored_report.get("packages") or []
        listeners = []
        for entry in stored_report.get("open_ports_credentialed") or []:
            record = dict(entry)
            # A product the collector read from the binary's own version
            # resource describes the exact file serving the port. A package
            # match is an inference from a process name. Never let the second
            # overwrite the first.
            if not record.get("product"):
                product, version = _service_identity_from_process(
                    record.get("process") or "", packages
                )
                if product:
                    record["product"] = product
                if version and not record.get("version"):
                    record["version"] = version
            listeners.append(record)

        host["credentialed"] = True
        # The audit's own findings are already merged into this host's `cves`,
        # and its packages into the listener records above. What is kept here is
        # what nothing else carries: the host's configuration posture and this
        # pass's own coverage.
        host["credentialed_report"] = {
            key: stored_report.get(key)
            for key in (
                "target",
                "detected_os",
                "system_info",
                "hardening_audits",
                "config_audit",
                "security_issues",
                "package_count",
                "collection_errors",
                "inventory_complete",
                "coverage",
                # What share of the collected inventory could be evaluated at
                # all — see VulnMatcher.coverage().
                "package_coverage",
                "exposure_summary",
            )
        }
        host["exposure_summary"] = stored_report.get("exposure_summary") or {}
        # The reverse correlation: ports the scan reached that the host also
        # confirms it is serving.
        host["open_ports"] = mark_credentialed_confirmed(open_ports, listeners)
        host["open_ports_credentialed"] = listeners

        # Authenticated readings supersede remote guesses before anything is
        # verified against them. Done here rather than at report time so the
        # stored scan, the asset's service rows, the risk score and the report
        # all agree on one version.
        corrected = _upgrade_network_fingerprints(host["open_ports"], listeners)
        if corrected:
            # The findings already raised on those ports recorded the old
            # version, and verification reads that record first — so without
            # this the correction would change the inventory and nothing else.
            restated = _restate_findings_for_corrected_ports(
                host.get("cves") or [], corrected
            )
            log.info(
                "Credentialed enrichment corrected %d fingerprint(s) and restated "
                "%d finding(s) on %s",
                len(corrected),
                restated,
                ip,
            )
        upgraded_total += len(corrected)

        # An OS read from inside the machine outranks a stack fingerprint, and
        # feeds straight back into platform-conflict checks during the
        # re-verification below.
        os_name = (stored_report.get("system_info") or {}).get("os_name")
        if os_name:
            host["os_guess"] = os_name
            host["os_confidence"] = "High"

        new_findings = _as_credentialed_findings(
            stored_report.get("cves") or [], stored_report.get("packages") or []
        )
        prior_suppressed = list(host.get("suppressed_cves") or [])
        prior_evaluated = int(host.get("candidates_evaluated") or 0)

        host["cves"] = list(host.get("cves") or []) + new_findings

        verification = verify_host_findings(host)
        fields = verification.as_host_fields()
        # Candidates phase 3 already ruled out are no longer among the host's
        # findings, so re-verification cannot rediscover them. Carrying their
        # records forward keeps the methodology appendix able to account for
        # every candidate the scan evaluated.
        #
        # The same holds for what the credentialed audit ruled out when it
        # verified its own findings: only its survivors arrive in new_findings.
        # Its suppressed list was dropped here, so a vulnerability audit's
        # appendix never named a single credentialed candidate it withheld —
        # on 10.180.6.30 (scan #10, 12 Oct 2026) that was 410 Chrome CVEs
        # published for other platforms, removed without a trace.
        seen = {
            (item.get("identifier"), item.get("host"))
            for item in fields["suppressed_cves"]
        }
        carried = []
        for item in prior_suppressed + list(stored_report.get("suppressed_cves") or []):
            key = (item.get("identifier"), item.get("host"))
            if key not in seen:
                seen.add(key)
                carried.append(item)
        fields["suppressed_cves"] = fields["suppressed_cves"] + carried
        # Everything the audit evaluated, not only what it kept.
        fields["candidates_evaluated"] = prior_evaluated + int(
            stored_report.get("candidates_evaluated") or len(new_findings)
        )
        host.update(fields)

        score, level = calculate_risk(
            open_ports=host.get("open_ports", []),
            cves=host.get("cves", []),
            http_audit=host.get("http_audit", {}),
            tls_info=host.get("tls_info", {}),
            severity_counts=host.get("vulnerability_counts"),
        )
        host["host_risk_score"] = score
        host["host_risk_level"] = level

        audited.append(ip)

    log.info(
        "Credentialed enrichment: %d/%d active host(s) audited, %d skipped",
        len(audited),
        len(active),
        len(skipped),
    )
    return {
        "credentialed_hosts": len(audited),
        "credentialed_targets": audited,
        "credentialed_skipped": skipped,
        "fingerprints_corrected": upgraded_total,
        **credentialed_coverage(network_scanned=True),
    }


@celery_app.task(
    name="ccure.tasks.run_vulnerability_audit",
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

        # Run the topology engine
        from core.topology.engine import run_topology_mapping

        result = run_topology_mapping(
            db=db,
            scan_id=scan_id,
            org_id=org_id,
            snmp_config=snmp_config,
            target_ips=target_ips,
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


@celery_app.task(
    name="ccure.tasks.run_traditional_scan",
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


#: A credentialed audit authenticates to one host at a time. Expanding a CIDR
#: is cheap; logging into every address in it is not, so an operator who pastes
#: a /16 by mistake gets an error rather than a scan that runs for days.
MAX_CREDENTIALED_TARGETS = 256


def _run_configuration_audit(
    *,
    executor,
    ip: str,
    os_type: str,
    system_data: dict,
    asset_id: str | None = None,
    org_id: str | None = None,
    timeout: int = 45,
    extra_checks: list | None = None,
    policy=None,
) -> tuple[dict, list[dict]]:
    """
    Run the Phase 3 configuration audit over the session that is already open.

    Returns ``(summary, findings)`` where *findings* are shaped like the other
    entries in ``cve_list`` so they travel the existing finding → risk →
    reporting path. There is no second finding list and no second report
    section for configuration results; that is the point of the phase.

    **Called inside the ``with connection`` block, deliberately.** These checks
    read the host, so they need a live executor — and running them on the
    session the collectors just used costs no second authentication. Moving
    this after the block would leave every check reporting "no authenticated
    session", which the engine renders as ERROR: correct, and uselessly so.

    ``system_data`` is passed as well as the executor because several
    collectors answer from the inventory already in hand rather than re-reading
    it. A benchmark with fifty package rules would otherwise enumerate
    installed software fifty times.
    """
    from core.checks.contract import CheckOutcome
    from core.config_audit import CollectionContext, ConfigAuditEngine, select_checks
    from core.config_audit.builtin import builtin_checks
    from core.checks.definitions import DEFINITION_TYPE_CONFIG_CHECK
    from core.config_audit.findings import config_definition_id

    platform = "windows" if os_type == "windows" else "linux"
    # Built-ins plus whatever benchmark content the organisation has loaded.
    # `select_checks` applies platform targeting to both, so a Windows
    # benchmark rule cannot be dispatched at a Linux host — the same filter
    # that already governed the built-ins, rather than a second one.
    builtin = builtin_checks()
    _builtin_ids = {c.check_id for c in builtin}

    # GAP-12. The policy narrows the candidate set before the engine sees it;
    # it never widens it. `policy is None` is the pre-policy path and must stay
    # byte-identical, so every branch here is guarded on a policy being present
    # *and* naming the setting.
    #
    # The benchmark content in `extra_checks` was already narrowed by
    # `benchmark_checks_for_org`, which applied the framework, profile,
    # severity and exclusion settings while it had a database session. What is
    # left to apply here is what only the built-ins need — because they never
    # go through that query — plus the family filter, which `select_checks`
    # owns for both.
    include_builtin = True
    families: list[str] = []
    excluded_ids: set[str] = set()
    excluded_tags: set[str] = set()
    min_severity = None
    if policy is not None:
        include_builtin = bool(getattr(policy, "include_builtin_checks", True))
        families = list(getattr(policy, "check_families", ()) or ())
        excluded_ids = {
            str(c) for c in (getattr(policy, "excluded_check_ids", ()) or ())
        }
        excluded_tags = {
            str(t).lower() for t in (getattr(policy, "excluded_tags", ()) or ())
        }
        min_severity = getattr(policy, "min_severity", None)

    if include_builtin:
        from core.scan_policy.spec import severity_at_least

        selected_builtin = [
            c
            for c in builtin
            if c.check_id not in excluded_ids
            and not (excluded_tags & {t.lower() for t in c.tags})
            and severity_at_least(c.severity, min_severity)
        ]
    else:
        # Excluding the built-ins is only reachable with a framework named —
        # `validate_policy` refuses the combination that would leave nothing —
        # so this cannot silently empty the audit.
        selected_builtin = []

    candidates = [*selected_builtin, *(extra_checks or [])]
    checks = select_checks(candidates, platform=platform, domains=families or None)
    if not checks:
        # Distinguished from "no checks defined for this platform", because a
        # policy that selected nothing on this host is a decision an operator
        # made and needs to see, while an empty platform is a product gap.
        reason = (
            f"no checks selected for {platform} under the effective policy"
            if policy is not None and (families or excluded_ids or not include_builtin)
            else f"no checks defined for {platform}"
        )
        return {"assessed": False, "reason": reason}, []

    # The host's own OS string, so a benchmark published for one distribution
    # is not dispatched at another. The collectors merge system info into the
    # top level rather than nesting it, so read there first and fall back.
    _nested = (system_data or {}).get("system_info") or {}
    context = CollectionContext(
        target=ip,
        platform=platform,
        os_name=str((system_data or {}).get("os_name") or _nested.get("os_name") or ""),
        os_version_id=str(
            (system_data or {}).get("os_version_id")
            or _nested.get("os_version_id")
            or ""
        ),
        executor=executor,
        system_data=system_data,
        asset_id=asset_id,
        org_id=org_id,
        timeout=timeout,
    )
    report = ConfigAuditEngine().run(checks, context)

    findings: list[dict] = []
    for result in report.results:
        if result.outcome is not CheckOutcome.FAIL:
            continue
        observation = result.evidence[0] if result.evidence else None
        # The check declares whether its failure is a hardening deviation or a
        # local privilege condition, and the engine carries that onto the
        # result. Defaulting instead of reading it would file every privilege
        # finding as CCURE-CFG- — the wrong pile for a reader triaging a path
        # to SYSTEM.
        finding_type = str(
            result.metadata.get("finding_type") or DEFINITION_TYPE_CONFIG_CHECK
        )
        definition_id = config_definition_id(result.check_id, finding_type)
        findings.append(
            {
                # The minted catalogue identifier, not a CVE. The `CCURE-`
                # prefix tells a reader the id is ours and that NVD has never
                # heard of it; the segment after it — CFG or PRV — says which
                # kind of finding it is.
                "cve_id": definition_id,
                "cve": definition_id,
                "definition_type": finding_type,
                "title": result.title,
                "severity": result.severity.capitalize(),
                "description": result.title,
                "desc": result.title,
                "detection_method": "config_check",
                "confidence": "Confirmed",
                "qod": result.qod,
                "remediation": result.remediation or "",
                "evidence": (
                    (
                        f"Expected: {observation.expected}\n"
                        f"Observed: {observation.observed}"
                        # The reading that makes the finding actionable. For
                        # a SCAP rule `observed` is only the verdict word —
                        # "non_compliant" — while `raw` names the OVAL object
                        # and the existence check it failed, e.g.
                        # "windows:registry_object: 0 item(s) collected,
                        # which does not satisfy at_least_one_exists".
                        # Without it a reader has to re-run the scan by hand
                        # to learn what was actually wrong.
                        + (
                            f"\n{_unique_lines(observation.raw)}"
                            if observation.raw
                            else ""
                        )
                    )
                    if observation
                    else ""
                ),
                "expected_state": observation.expected if observation else "",
                "observed_state": observation.observed if observation else "",
                "package": "",
                "installed_ver": "",
                "fixed_ver": "",
                "source": "config_audit",
                "matched_by": result.metadata.get("check_type", ""),
                "cvss_score": 0.0,
                "cvss": 0.0,
                "epss_score": 0.0,
                "epss_percentile": 0.0,
                "in_kev": False,
                "kev_due_date": "",
                "has_exploit": False,
                "exploit_sources": [],
                "cpe_uri": "",
                "cvss_version": "",
                "cvss_vector": "",
                "affected_software": [],
                "references": list(result.references),
            }
        )

    summary = {
        "assessed": True,
        "platform": platform,
        # Which configuration governed this audit. Carried on the phase summary
        # as well as on the scan, because `scan_phases.summary` is what the scan
        # detail API and the reports read back, and a reader looking at one
        # host's configuration results should not have to fetch the scan row to
        # learn what was in scope.
        "policy_fingerprint": (policy.fingerprint() if policy is not None else None),
        "policy_name": (getattr(policy, "policy_name", "") or None) if policy else None,
        "checks_run": len(report.results),
        # How many of the checks came from loaded benchmark content rather than
        # the built-in pack. A benchmark that loaded but resolved to nothing
        # executable would otherwise look identical to one nobody installed.
        "benchmark_checks": sum(1 for c in checks if c.check_id not in _builtin_ids),
        # Verdicts only. A configuration score computed over checks that
        # errored or did not apply would move when the network did.
        "checks_assessed": len(report.assessed),
        "score_pct": report.compliance_score(),
        "counts": report.counts,
        "results": [r.as_dict() for r in report.results],
    }
    return summary, findings


def _sync_configuration_compliance(
    db,
    *,
    org_id: str,
    ip: str,
    system_data: dict,
    scan_id: str | None = None,
    policy=None,
) -> dict | None:
    """
    Turn this host's configuration verdicts into compliance findings.

    Runs inside the scan's own transaction, immediately after the asset it
    describes was synced, so a finding cannot outlive a rolled-back scan.

    Returns the sync summary, or None where there was nothing to sync. Failures
    are logged and swallowed: a compliance-mapping problem must not fail a scan
    that has already collected its results and written its findings — those are
    the customer's actual deliverable, and losing them to a benchmark mapping
    error would be a far worse outcome than a missing compliance row. The
    exception is logged with its traceback so it is fixable.
    """
    from db.models.assets import Asset

    summary = (system_data or {}).get("config_audit") or {}
    results = summary.get("results") or []
    if not results:
        return None

    asset = (
        db.query(Asset).filter(Asset.org_id == org_id, Asset.ip_address == ip).first()
    )
    if asset is None:
        # The asset sync runs immediately before this and creates the row, so
        # reaching here means that sync did not produce one. Recorded rather
        # than guessed at: a finding needs an asset to hang off.
        log.warning(
            "Configuration verdicts for %s could not be mapped to compliance: "
            "no asset row for org %s",
            ip,
            org_id,
        )
        return None

    try:
        from core.compliance_sync import sync_config_audit_findings

        return sync_config_audit_findings(
            db,
            org_id=org_id,
            asset_id=str(asset.id),
            results=results,
            scan_run_id=None,
            # The policy's framework selection. Without it a scan narrowed to
            # one benchmark still writes verdicts onto every framework a rule
            # is crosswalked into, from an assessment that covered none of the
            # rest of them — a score computed over a handful of controls that
            # reads as a near-complete one.
            framework_ids=list(getattr(policy, "framework_ids", ()) or ()) or None,
        ).as_dict()
    except Exception:  # noqa: BLE001
        log.exception(
            "Configuration compliance sync failed for %s (org %s); the scan's "
            "own findings are unaffected",
            ip,
            org_id,
        )
        return None


def _hardening_row(label: str, good: bool | None, pass_detail: str, fail_detail: str):
    """
    One hardening row, with a third state for "nobody looked".

    ``good is None`` means the collector did not read the setting — the SMB
    transport serves a subset of the Windows inventory, so this is a normal
    outcome rather than a fault. It renders as NOT_ASSESSED, never as PASS or
    FAIL: a report claiming a control passed on evidence it never gathered is
    the failure mode this whole distinction exists to prevent.
    """
    if good is None:
        return {
            "label": label,
            "disabled": None,
            "status": "NOT_ASSESSED",
            "detail": "Not assessed — this scan did not read the setting.",
        }
    return {
        "label": label,
        "disabled": bool(good),
        "status": "PASS" if good else "FAIL",
        "detail": pass_detail if good else fail_detail,
    }


def _credentialed_hardening_audits(system_data: dict, os_type: str) -> dict:
    """Host hardening posture, derived from what the authenticated session read."""
    issues = system_data.get("security_issues") or []
    fw_disabled = any(
        "Firewall profile" in issue and "is DISABLED" in issue for issue in issues
    )

    rdp_enabled = system_data.get("rdp_enabled")
    if rdp_enabled is None:
        rdp_enabled = any("RDP is enabled" in issue for issue in issues)

    if os_type != "windows":
        running_svcs = system_data.get("running_services") or []
        fw_active = any(
            svc.get("name") in ("ufw", "firewalld", "iptables") for svc in running_svcs
        )
    else:
        fw_active = not fw_disabled

    # ``None`` where the collector did not read the setting. The rows below use
    # `_hardening_row`, which renders that as NOT ASSESSED — a report that
    # prints PASS or FAIL for a control nothing examined is worse than one that
    # says it looked at less.
    smbv1_disabled = system_data.get("smbv1_disabled")
    netbios_disabled = system_data.get("netbios_disabled")
    legacy_tls_disabled = system_data.get("legacy_tls_disabled")
    telnet_disabled = system_data.get("telnet_disabled")
    rdp_nla_enforced = system_data.get("rdp_nla_enforced")

    hardening_audits = {
        "firewall": {
            "label": "Firewall Status",
            "disabled": not fw_active,
            "status": "PASS" if fw_active else "FAIL",
            "detail": (
                "Firewall is active."
                if fw_active
                else "Host firewall is disabled or ufw/iptables service is inactive."
            ),
        },
        "smbv1": _hardening_row(
            "SMBv1 Status",
            smbv1_disabled,
            "Legacy SMBv1 protocol is disabled.",
            "Legacy SMBv1 protocol is enabled/allowed.",
        ),
        "netbios": _hardening_row(
            "NetBIOS Status",
            netbios_disabled,
            "NetBIOS over TCP/IP is disabled.",
            "NetBIOS over TCP/IP is active on one or more network adapters.",
        ),
        "legacy_tls": _hardening_row(
            "Legacy TLS Status",
            legacy_tls_disabled,
            "Legacy SChannel/OpenSSL protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) "
            "are disabled.",
            "One or more legacy security protocols (SSL/TLS 1.0/1.1) are enabled.",
        ),
        "telnet": _hardening_row(
            "Telnet Status",
            telnet_disabled,
            "Telnet service is disabled.",
            "Telnet service/daemon is running or client package is installed.",
        ),
    }

    if os_type == "windows":
        hardening_audits.update(
            {
                "rdp": {
                    "label": "RDP Service Status",
                    "disabled": not rdp_enabled,
                    "status": "PASS" if not rdp_enabled else "WARN",
                    "detail": (
                        "Remote Desktop is disabled."
                        if not rdp_enabled
                        else "Remote Desktop is enabled (requires secure NLA and restricted access)."
                    ),
                },
                # A host with RDP switched off passes whatever the NLA setting
                # says, so that answer needs no reading. Only when RDP *is*
                # enabled does an unread NLA setting leave the control
                # unassessed rather than breached.
                "rdp_nla": _hardening_row(
                    "RDP NLA Enforcement",
                    True if not rdp_enabled else rdp_nla_enforced,
                    "Network Level Authentication (NLA) is enforced for RDP.",
                    "RDP is enabled but Network Level Authentication (NLA) is "
                    "not enforced.",
                ),
            }
        )

    return hardening_audits


def _resolve_stored_credential(
    db,
    scan_id: str | None,
    credential_id: str,
) -> dict:
    """
    Decrypt a saved credential for use, scoped to the scan's own tenant.

    Returns the connection material; the caller is responsible for discarding
    it. Cross-referencing the Scan row's org_id is what keeps one tenant from
    naming another tenant's credential id.
    """
    from core.security_crypto import decrypt_credential
    from db.models import ComplianceCredential
    from db.models.scans import Scan

    scan_row = db.query(Scan).filter(Scan.id == scan_id).first() if scan_id else None
    scan_org_id = scan_row.org_id if scan_row else None

    query = db.query(ComplianceCredential).filter(
        ComplianceCredential.id == credential_id
    )
    if scan_org_id:
        query = query.filter(ComplianceCredential.tenant_id == scan_org_id)

    cred = query.first()
    if not cred:
        raise ValueError(
            f"Stored credential with ID {credential_id} not found or access denied."
        )

    from db.models.compliance import (
        AUTH_METHOD_NTLM_HASH,
        AUTH_REQUIRES_KEY,
        AUTH_REQUIRES_PASSWORD,
    )

    material = {
        # The username in the form this credential's auth method expects.
        # NTLM wants DOMAIN\user, Kerberos wants user@REALM, SSH wants the bare
        # name — `principal()` owns that mapping so the two callers of this
        # function cannot disagree about it.
        "username": cred.principal(),
        "port": cred.port,
        "auth_method": cred.auth_method,
        "credential_type": cred.credential_type,
        "transport": cred.transport,
        "domain": cred.domain,
        "options": dict(cred.options or {}),
        "password": None,
        "key_content": None,
        #: Unlocks an encrypted private key. Separate from ``password``: the two
        #: unlock different things and a key credential may carry only this one.
        "key_passphrase": None,
        #: Pass-the-Hash material. Kept out of ``password`` deliberately — every
        #: transport that receives a password would present this as one, and
        #: only the SMB executor knows how to send a hash.
        "nt_hash": None,
    }
    # Driven by the shared AUTH_REQUIRES_* sets rather than an if/elif on two
    # literal method names. The literal form is what made ``ntlm`` and
    # ``kerberos`` resolve to a credential with no material at all: both
    # present a password, neither matched ``== "password"``, so the connection
    # was attempted with None and failed as "authentication rejected" — a
    # misleading message for a credential that was never actually sent.
    if cred.auth_method == AUTH_METHOD_NTLM_HASH and cred.encrypted_password:
        # The hash is stored in the password column and must not leave this
        # function as one: handing it to a transport that expects a password
        # would present the hash as plaintext against the account.
        material["nt_hash"] = decrypt_credential(cred.encrypted_password)
    elif cred.auth_method in AUTH_REQUIRES_PASSWORD and cred.encrypted_password:
        material["password"] = decrypt_credential(cred.encrypted_password)
    elif cred.auth_method in AUTH_REQUIRES_KEY and cred.encrypted_key_content:
        material["key_content"] = decrypt_credential(cred.encrypted_key_content)
        if cred.encrypted_key_passphrase:
            material["key_passphrase"] = decrypt_credential(
                cred.encrypted_key_passphrase
            )
    return material


def audit_credentialed_host(
    *,
    ip: str,
    username: str | None,
    password: str | None = None,
    key_path: str | None = None,
    key_content: str | None = None,
    key_passphrase: str | None = None,
    nt_hash: str | None = None,
    port: int | None = None,
    sections: list[str] | None = None,
    os_type_req: str = "auto",
    emit=None,
    network_ports: list | None = None,
    network_scanned: bool = False,
    scanned_ports: list | None = None,
    timeout: int = 20,
    transport: str = "ssh",
    auth_method: str = "password",
    domain: str | None = None,
    credential_options: dict | None = None,
    config_checks: list | None = None,
    policy=None,
) -> tuple[dict, dict, str]:
    """
    Run the authenticated audit against one host.

    Returns ``(stored_report, system_data, os_type)``. Raises on connection or
    authentication failure — the caller decides whether one unreachable host
    fails the whole scan.

    ``network_ports`` is the port scan's view of this host, when there is one.
    Supplying it turns the host's socket table from a list of things that are
    running into a statement about what is actually exposed, which is the
    finding an authenticated scan exists to produce and which neither view can
    reach alone. Without it, only loopback binds can be settled.

    ``transport`` selects how the commands get there — ``ssh`` (the original
    path, and still the only one for Linux) or ``winrm`` (native Windows,
    added in Phase 2). Both satisfy the same ``BaseExecutor`` protocol and both
    drive the *same* collectors, so nothing downstream of this function knows
    or cares which was used. That is the point: Windows over WinRM produces
    findings through the identical evidence → matching → finding → risk →
    reporting path, not a parallel one.

    ``domain`` and ``auth_method`` are carried through for Windows: the caller
    resolves them from the stored credential, because the username form NTLM
    wants (``DOMAIN\\user``) differs from the one Kerberos wants
    (``user@REALM``) and guessing between them is how a credential silently
    fails to authenticate.
    """
    from engines.credentialed.linux_collector import LinuxCollector
    from engines.credentialed.ssh_scanner import SSHScanner
    from engines.credentialed.vuln_matcher import VulnMatcher
    from engines.credentialed.windows_collector import WindowsCollector
    from engines.credentialed.os_detection import detect_os
    from scans.finding_normalizer import verify_credentialed_report

    def _emit(message, percentage=0, stage=None):
        if emit:
            emit("running", message, percentage, stage)

    host_started = time.time()

    resolved_transport = (transport or "ssh").strip().lower()
    # ``port`` used to default to 22 in this signature, which is an SSH port
    # standing in for every transport. A WinRM caller that named no port got 22
    # and opened a WS-Management request against sshd. Each transport now
    # supplies its own default, and WinRM's is left to the executor because it
    # is TLS-dependent: 5986 when ``use_tls`` is set, 5985 otherwise.
    if resolved_transport != "winrm" and not port:
        port = DEFAULT_TRANSPORT_PORT.get(resolved_transport, 22)
    _emit(
        f"Connecting to {ip}:{port or 'default port'} over "
        f"{resolved_transport.upper()}...",
        10,
        "connecting",
    )
    connect_started = time.perf_counter()

    if resolved_transport == "smb":
        # The second Windows transport. Same collector, same checks, same
        # findings — it answers ``WindowsCollector``'s named items from WMI and
        # the registry instead of from PowerShell. It exists because WinRM is
        # off by default on Windows client editions, so an estate of
        # workstations is reachable through this and not through that.
        from engines.credentialed.smb_executor import SMBExecutor

        connection = SMBExecutor(
            ip=ip,
            username=username,
            password=password,
            nt_hash=nt_hash,
            port=port or None,
            domain=domain,
            timeout=timeout,
        )
    elif resolved_transport == "winrm":
        from engines.credentialed.winrm_executor import WinRMExecutor

        winrm_options = dict(credential_options or {})
        connection = WinRMExecutor(
            ip=ip,
            username=username,
            password=password,
            port=port or None,
            auth_method=auth_method or "ntlm",
            use_tls=winrm_options.get("use_tls"),
            verify_cert=bool(winrm_options.get("verify_cert", False)),
            timeout=timeout,
            read_timeout=int(winrm_options.get("read_timeout", 60)),
            winrm_path=winrm_options.get("winrm_path", "/wsman"),
            allow_basic_over_http=bool(
                winrm_options.get("allow_basic_over_http", False)
            ),
        )
    else:
        connection = SSHScanner(
            ip=ip,
            username=username,
            password=password,
            key_path=key_path,
            key_content=key_content,
            key_passphrase=key_passphrase,
            port=port,
            timeout=timeout,
            # Which program elevates on this host. It lives in ``options``
            # rather than a column because it is a setting, not a secret, and
            # ``options`` is already the place for per-credential transport
            # settings that need no migration to add.
            elevation_method=str(
                (credential_options or {}).get("elevation_method") or "sudo"
            ),
        )

    with connection as ssh:
        credentialed_response_time_ms = int(
            round((time.perf_counter() - connect_started) * 1000)
        )
        if resolved_transport in ("winrm", "smb"):
            # Both are Windows-only protocols, so the operating system is
            # established by the fact that the connection succeeded. Running
            # detect_os here would spend a round trip re-deriving something
            # already known, and its probes are written for a POSIX shell — on
            # the SMB transport they would not run at all, since it executes no
            # commands, and the host would be misread as Linux.
            os_type = "windows"
            _emit(
                f"Windows confirmed by {resolved_transport.upper()} transport",
                20,
                "detection",
            )
        else:
            _emit("Detecting Operating System...", 20, "detection")
            os_type = os_type_req if os_type_req != "auto" else detect_os(ssh)

        _emit(f"Collecting system data ({os_type})...", 30, "collection")
        collector = (
            WindowsCollector(ssh) if os_type == "windows" else LinuxCollector(ssh)
        )

        def on_section(name):
            friendly = {
                "system_info": "System Profile",
                "packages": "Software Inventory",
                "services": "Running Services",
                "ports": "Network Sockets",
                "users": "User Accounts",
                "security": "Security Policies",
                "network": "Interface Config",
                "history": "Login Events",
            }.get(name, name)
            _emit(f"Collected {friendly}", 50, "collection")

        system_data = collector.collect_all(
            sections=_credentialed_sections_with_identity(sections),
            on_section_complete=on_section,
        )
        system_data["detected_os"] = os_type
        system_data["credentialed_response_time_ms"] = credentialed_response_time_ms

        # Configuration audit, on the session that is still open.
        #
        # A wholesale failure here must not read as "the host is correctly
        # configured". The engine already reports per-check errors rather than
        # verdicts, so the only way to reach this handler is a defect in our
        # own code — and the honest result of that is a recorded gap, not an
        # empty pass list. `config_audit_error` travels into the stored report
        # so the omission is visible to a reader rather than only to the log.
        _emit("Auditing host configuration...", 60, "configuration")
        try:
            config_summary, config_findings = _run_configuration_audit(
                executor=ssh,
                ip=ip,
                os_type=os_type,
                system_data=system_data,
                timeout=max(timeout, 45),
                extra_checks=config_checks,
                # The scan's effective policy, resolved before dispatch and
                # read back from the scan row. It narrows the built-in pack and
                # the check families; the benchmark content in `config_checks`
                # was already narrowed by `benchmark_checks_for_org`, which had
                # a database session to do it with. This function deliberately
                # opens none.
                policy=policy,
            )
        except Exception as exc:  # noqa: BLE001
            log.exception("Configuration audit failed for %s", ip)
            config_summary = {
                "assessed": False,
                "reason": f"{type(exc).__name__}: {exc}",
            }
            config_findings = []
        system_data["config_audit"] = config_summary

    _emit("Analyzing packages for vulnerabilities...", 70, "analysis")
    packages = system_data.get("packages", [])
    matcher = VulnMatcher()
    # The host's own /etc/os-release, so OSV advisories are matched against the
    # release the packages were actually installed from. Without it every
    # distribution in the database was in scope and a 24.04 host was assessed
    # against 14.04, Debian and Mageia advisories.
    # The collectors merge their system-info section into the top level rather
    # than nesting it, so read there first and fall back to a nested shape.
    _nested = system_data.get("system_info") or {}
    _os_id = str(system_data.get("os_id") or _nested.get("os_id") or "")
    _os_ver = str(
        system_data.get("os_version_id") or _nested.get("os_version_id") or ""
    )
    raw_findings = matcher.match_packages(packages, os_id=_os_id, os_version_id=_os_ver)
    # How much of the inventory was actually assessable travels with the result.
    # On a Windows host only the packages carrying a recognised CPE identity can
    # be evaluated at all — 13 of 192 on the host audited during testing — and a
    # report that does not say so presents a 7% assessment as a complete one.
    system_data["package_coverage"] = matcher.coverage()
    cve_list = matcher.to_report_format(raw_findings)

    # Attach the vendor's own advisory where one exists for the same CVE.
    #
    # Joined on the CVE alone, so it cannot introduce a finding or change a
    # verdict — it adds what the vendor wrote about a vulnerability already
    # established by other means. The gain is remediation quality: NVD offers a
    # version boundary inferred from a CPE range, while Siemens writes "Update
    # to V2606 or later version". On OT products the vendor advisory is often
    # the only place a remediation is stated at all.
    try:
        from core.vuln_intel import csaf_advisories_for, exploit_intel_for

        cve_ids = [f.get("cve_id") for f in cve_list]

        # Exploitation provenance. The matcher's own query supplies
        # `exploit_sources`, but not whether an exploit was reproduced, seen
        # against a honeypot, or used in ransomware — and those are the
        # distinctions triage acts on.
        intel = exploit_intel_for(cve_ids)
        promoted = 0
        for finding in cve_list:
            entry = intel.get(str(finding.get("cve_id") or "").upper())
            if not entry:
                continue
            finding.update(entry)
            finding["has_exploit"] = True
            promoted += 1
        if promoted:
            log.info("Exploit provenance attached to %d finding(s)", promoted)

        advisories = csaf_advisories_for(cve_ids)
        enriched = 0
        for finding in cve_list:
            matches = advisories.get(str(finding.get("cve_id") or "").upper())
            if not matches:
                continue
            finding["vendor_advisories"] = matches
            source = next((m for m in matches if m.get("remediation")), None)
            if source:
                # Attributed, always. The advisory covers the same CVE but not
                # necessarily the same product: a Chrome CVE turns up in a CISA
                # ICS advisory because an ICS product embeds Chrome, and its
                # mitigation is written for that context — "block access to
                # untrusted web content from sensitive systems". That is sound
                # advice about the CVE and misleading if it appears to be the
                # vendor's guidance for the desktop browser this host runs.
                # Naming the advisory keeps the reader able to judge which.
                finding["vendor_remediation"] = (
                    f"{source['provider'].upper()} {source['advisory_id']}: "
                    f"{source['remediation']}"
                )
            enriched += 1
        if enriched:
            log.info("Vendor advisories attached to %d finding(s)", enriched)
    except Exception as exc:  # noqa: BLE001 - enrichment must never fail a scan
        log.warning("Vendor advisory enrichment skipped: %s", exc)

    # Vendor advisories for software NVD does not index.
    #
    # OT products — TIA Portal, WinCC, SIMATIC — either have no CPE or have one
    # nobody publishes against, so the CPE path that carries every other
    # finding sees nothing on an engineering station. The vendor's CSAF
    # advisory is the only structured source, and on the audited host it
    # produced 14 findings the rest of the pipeline could not reach.
    try:
        from engines.credentialed.csaf_matcher import CsafProductMatcher

        csaf_matcher = CsafProductMatcher()
        csaf_findings = csaf_matcher.match(packages)
        system_data["csaf_coverage"] = csaf_matcher.coverage()
        for finding in csaf_findings:
            cve_list.append(
                {
                    "cve_id": finding["cve_id"],
                    "cve": finding["cve_id"],
                    "severity": finding["severity"],
                    "cvss_score": finding["cvss_score"],
                    "cvss": finding["cvss_score"],
                    "description": finding["description"],
                    "desc": finding["description"],
                    "package": finding["package_name"],
                    "installed_ver": finding["installed_ver"],
                    "installed_version_precision": finding.get(
                        "installed_version_precision", ""
                    ),
                    "fixed_ver": finding["fixed_ver"],
                    "source": finding["source"],
                    "matched_by": finding["matched_by"],
                    "detection_method": "credentialed_package",
                    "confidence": "Confirmed",
                    "epss_score": 0.0,
                    "epss_percentile": 0.0,
                    "in_kev": False,
                    "kev_due_date": "",
                    "has_exploit": False,
                    "exploit_sources": [],
                    "cpe_uri": "",
                    "cvss_version": "",
                    "cvss_vector": "",
                    "affected_software": [],
                    "vendor_advisories": finding["vendor_advisories"],
                    "vendor_remediation": finding["vendor_remediation"],
                }
            )
        if csaf_findings:
            log.info(
                "CSAF vendor advisories produced %d finding(s) for software "
                "with no CPE identity",
                len(csaf_findings),
            )
    except Exception as exc:  # noqa: BLE001 - must never fail the scan
        log.warning("CSAF product matching skipped: %s", exc)

    # The operating system itself, which package matching cannot reach.
    #
    # Windows is not listed in the uninstall registry, so the inventory pass
    # never sees it and the largest piece of software on the host went
    # unassessed while the report still read as a completed audit. Microsoft
    # publishes the build number that carries each fix; the host reports its
    # own build; comparing them settles it without inferring anything from a
    # software name. Linux distributions need none of this — their kernel and
    # userland are packages, and OSV already covers them.
    if os_type == "windows":
        from engines.credentialed.windows_patch import (
            MicrosoftApplicationMatcher,
            WindowsPatchMatcher,
        )

        os_result = WindowsPatchMatcher().match(
            {
                "version": _os_ver or system_data.get("kernel_version"),
                "ubr": system_data.get("os_ubr") or _nested.get("os_ubr"),
                "architecture": system_data.get("cpu_arch") or _nested.get("cpu_arch"),
                "caption": system_data.get("os_name") or _nested.get("os_name"),
            }
        )
        system_data["os_patch_coverage"] = os_result.coverage()

        for finding in os_result.findings:
            cve_list.append(
                {
                    "cve_id": finding["cve_id"],
                    "cve": finding["cve_id"],
                    "severity": finding["severity"],
                    "cvss_score": finding["cvss_score"],
                    "cvss": finding["cvss_score"],
                    "description": finding["description"],
                    "desc": finding["description"],
                    "package": finding["package_name"],
                    "installed_ver": finding["installed_ver"],
                    "installed_version_precision": finding.get(
                        "installed_version_precision", ""
                    ),
                    "fixed_ver": finding["fixed_ver"],
                    "source": finding["source"],
                    "matched_by": finding["matched_by"],
                    "epss_score": finding["epss_score"],
                    "epss_percentile": finding["epss_percentile"],
                    "in_kev": finding["in_kev"],
                    "kev_due_date": "",
                    "has_exploit": False,
                    "exploit_sources": [],
                    "priority_score": 0.0,
                    "priority_level": "P4",
                    "cpe_uri": "",
                    "cvss_version": finding["cvss_version"],
                    "cvss_vector": finding["cvss_vector"],
                    "affected_software": [],
                    "remediation": finding["remediation"],
                    "kb_ids": finding["kb_ids"],
                }
            )

        if not os_result.assessed:
            # Same reasoning as the empty-inventory finding below: an OS that
            # could not be evaluated must not be indistinguishable from one
            # that was evaluated and found clean.
            cve_list.append(
                {
                    "cve_id": "MISC-CREDENTIALED-OS-NOT-ASSESSED",
                    "detection_method": "active_check",
                    "severity": "Medium",
                    "title": "Operating system not assessed for missing patches",
                    "description": (
                        f"The credentialed session to {ip} succeeded and the "
                        f"software inventory was assessed, but the Windows "
                        f"operating system itself was not. {os_result.reason} "
                        f"Missing operating-system patches would not appear in "
                        f"this report."
                    ),
                }
            )
        else:
            log.info(
                "Windows OS patch assessment: build %s, %d missing patch(es)",
                os_result.build,
                len(os_result.findings),
            )

        # Microsoft applications — Edge, Office, SQL Server — are numbered in
        # build space and so are refused by CPE version comparison even when
        # their identity resolves correctly. MSRC publishes them in the same
        # space the host reports, so they are assessable here and nowhere else.
        app_findings, app_coverage = MicrosoftApplicationMatcher().match(packages)
        system_data["ms_app_coverage"] = app_coverage

        # Fold MSRC-assessed software into the headline coverage figure.
        #
        # package_coverage counts only what resolved to a CPE identity, which
        # understates what the audit actually examined now that MSRC assesses
        # Microsoft products by build. Edge and its WebView2 runtime are
        # evaluated against 385 published fixes and were still being counted as
        # unassessed, because they reach the feed by build line rather than by
        # CPE. A coverage number that ignores a whole matcher is as misleading
        # as one that counts software it never looked at.
        coverage = system_data.get("package_coverage") or {}
        assessable = coverage.get("packages_assessable_software") or 0
        if assessable:
            combined = min(
                coverage.get("packages_cpe_resolved", 0)
                + (app_coverage.get("apps_assessed") or 0),
                assessable,
            )
            coverage["packages_assessed_total"] = combined
            coverage["coverage_pct_assessed"] = round(100.0 * combined / assessable, 1)
            system_data["package_coverage"] = coverage
        for finding in app_findings:
            cve_list.append(
                {
                    "cve_id": finding["cve_id"],
                    "cve": finding["cve_id"],
                    "severity": finding["severity"],
                    "cvss_score": finding["cvss_score"],
                    "cvss": finding["cvss_score"],
                    "description": finding["description"],
                    "desc": finding["description"],
                    "package": finding["package_name"],
                    "installed_ver": finding["installed_ver"],
                    "installed_version_precision": finding.get(
                        "installed_version_precision", ""
                    ),
                    "fixed_ver": finding["fixed_ver"],
                    "source": finding["source"],
                    "matched_by": finding["matched_by"],
                    "epss_score": finding["epss_score"],
                    "epss_percentile": finding["epss_percentile"],
                    "in_kev": finding["in_kev"],
                    "kev_due_date": "",
                    "has_exploit": False,
                    "exploit_sources": [],
                    "priority_score": 0.0,
                    "priority_level": "P4",
                    "cpe_uri": "",
                    "cvss_version": finding["cvss_version"],
                    "cvss_vector": finding["cvss_vector"],
                    "affected_software": [],
                    "remediation": finding["remediation"],
                }
            )

    # A credentialed audit that could not read the software inventory has
    # not assessed the host — it has produced an empty result that looks
    # identical to a clean one. Say so, as a finding, rather than letting
    # "0 vulnerabilities" stand as the conclusion. Tagged as an active
    # check so verification treats it as the observation it is.
    collection_errors = system_data.get("collection_errors") or {}
    if not packages:
        reason = collection_errors.get("packages")
        detail = (
            f"Collection failed: {reason}"
            if reason
            else (
                "No package manager output was returned. The account may "
                "lack the rights to enumerate installed software, or the "
                "platform's inventory command is unavailable."
            )
        )
        cve_list.append(
            {
                "cve_id": "MISC-CREDENTIALED-INVENTORY-UNAVAILABLE",
                "detection_method": "active_check",
                "severity": "Medium",
                "title": "Credentialed audit incomplete — software inventory unavailable",
                "description": (
                    f"The credentialed session to {ip} succeeded, but the "
                    f"installed software inventory could not be collected, so "
                    f"no package was assessed against the vulnerability feed. "
                    f"This host is unassessed, not clean. {detail}"
                ),
                "package": "",
            }
        )
    if collection_errors:
        log.warning(
            "Credentialed audit of %s completed with %d incomplete section(s): %s",
            ip,
            len(collection_errors),
            ", ".join(sorted(collection_errors)),
        )

    # Configuration findings join the same list the CVE findings are in, so
    # they are severity-ranked, risk-scored and reported beside them rather
    # than in a section of their own. A failing hardening control is a security
    # finding; splitting the two lists is what produces a second risk model and
    # a second report generator behind it.
    cve_list.extend(config_findings)
    if config_findings:
        log.info(
            "Configuration audit produced %d finding(s) on %s",
            len(config_findings),
            ip,
        )
    if not config_summary.get("assessed"):
        # Same reasoning as the OS and inventory branches above: a dimension
        # that could not be assessed must not be indistinguishable from one
        # assessed and found clean.
        cve_list.append(
            {
                "cve_id": "MISC-CREDENTIALED-CONFIG-NOT-ASSESSED",
                "detection_method": "active_check",
                "severity": "Medium",
                "title": "Host configuration not assessed",
                "description": (
                    f"The credentialed session to {ip} succeeded, but the host "
                    f"configuration audit did not run, so no hardening control "
                    f"was evaluated. "
                    f"{config_summary.get('reason', 'No reason was recorded.')} "
                    f"Configuration weaknesses would not appear in this report."
                ),
                "package": "",
            }
        )

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for cve in cve_list:
        sev = cve.get("severity", "Info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    scan_duration = round(time.time() - host_started, 2)

    _emit("Generating report and syncing assets...", 90, "syncing")

    from core.oui_lookup import lookup_vendor

    hostname, fqdn, raw_hostname_fqdn = _extract_credentialed_identity_names(
        system_data
    )
    mac_address = _normalize_mac(system_data.get("mac_address"))
    mac_vendor = _clean_text(
        system_data.get("mac_vendor")
        or (lookup_vendor(mac_address) if mac_address else "")
    )
    hardening_audits = _credentialed_hardening_audits(system_data, os_type)

    # ── Exposure correlation ──────────────────────────────────────────────
    # The socket table says what is running; the port scan says what answered.
    # Joining them here — once, at the point both are in hand — is what lets
    # every consumer downstream distinguish an exposed service from one that
    # merely exists.
    listeners, exposure_summary = correlate_listeners(
        system_data.get("open_ports_credentialed") or [],
        network_ports=network_ports,
        network_scanned=network_scanned,
        scanned_ports=scanned_ports,
    )
    system_data["open_ports_credentialed"] = listeners

    stored_report = {
        "scan_type": "credentialed",
        "target": ip,
        "username": username,
        "detected_os": os_type,
        "os_type_was_auto": (os_type_req == "auto"),
        "system_info": {
            "os_name": system_data.get("os_name", ""),
            "os_family": system_data.get("os_family", ""),
            "os_version_id": system_data.get("os_version_id", ""),
            "os_confidence": system_data.get("os_confidence", ""),
            "os_build": system_data.get("os_build", ""),
            "kernel_version": system_data.get("kernel_version", ""),
            "hostname": hostname,
            "hostname_short": system_data.get("hostname_short", ""),
            "hostname_fqdn_raw": raw_hostname_fqdn,
            "fqdn": fqdn,
            "domain": system_data.get("domain", ""),
            "manufacturer": system_data.get("manufacturer", ""),
            "hardware_model": system_data.get("hardware_model", ""),
            "mac_address": mac_address,
            "mac_vendor": mac_vendor,
            "cpu_model": system_data.get("cpu_model", ""),
            "cpu_count": system_data.get("cpu_count", ""),
            "cpu_arch": system_data.get("cpu_arch", ""),
            "uptime": system_data.get("uptime", ""),
            "memory_summary": system_data.get("memory_summary", {}),
            "disk_usage": system_data.get("disk_usage", []),
            "subnet": system_data.get("subnet", ""),
            "credentialed_response_time_ms": system_data.get(
                "credentialed_response_time_ms", ""
            ),
            "serial_number": system_data.get("serial_number", ""),
            "bios_version": system_data.get("bios_version", ""),
            # What privilege the session held. Windows only, and absent on
            # Linux, where elevation is per-command through sudo rather than a
            # property of the whole session. The same Windows check set gives
            # different answers to an administrator and to a standard user, and
            # without this the result carries nothing to say which produced it.
            "privilege_context": system_data.get("privilege_context") or {},
        },
        "packages": packages,
        "package_count": len(packages),
        # How much of that inventory could actually be evaluated. A Windows
        # audit that resolved 13 of 192 packages has assessed 7% of the host,
        # and a report carrying only "package_count: 192" presents that as a
        # complete audit.
        "package_coverage": system_data.get("package_coverage") or {},
        "running_services": system_data.get("running_services", []),
        "open_ports_credentialed": listeners,
        "users": system_data.get("users", []),
        "local_groups": system_data.get("local_groups", []),
        "suspicious_scheduled_tasks": system_data.get("suspicious_scheduled_tasks", []),
        "cron_info_raw": system_data.get("cron_info_raw", ""),
        "hardening_audits": hardening_audits,
        # Phase 3 configuration audit: per-check verdicts, the counts
        # behind them, and the score computed over verdicts only.
        "config_audit": config_summary,
        "suid_binaries": system_data.get("suid_binaries", []),
        "world_writable_dirs": system_data.get("world_writable_dirs", []),
        "sudo_nopasswd": system_data.get("sudo_nopasswd", False),
        "sudo_rules_raw": system_data.get("sudo_rules_raw", ""),
        "security_issues": system_data.get("security_issues", []),
        "failed_login_count": system_data.get("failed_login_count", 0),
        "brute_force_warning": system_data.get("brute_force_warning", False),
        "failed_logins_recent": system_data.get("failed_logins_recent", []),
        "network_interfaces_raw": system_data.get("network_interfaces_raw", ""),
        "env_vars_flagged": system_data.get("env_vars_summary", []),
        "cves": cve_list,
        "cve_count": len(cve_list),
        "severity_summary": severity_counts,
        "scan_duration": scan_duration,
        # Coverage of the audit itself, so the report can state what was
        # examined rather than implying the whole host was.
        "packages_enumerated": len(packages),
        "collection_errors": collection_errors,
        "inventory_complete": bool(packages) and not collection_errors,
        # What this audit could and could not see. Without it, a report with no
        # network findings reads as a host with no network exposure.
        "coverage": credentialed_coverage(
            network_scanned=network_scanned, transport=resolved_transport
        ),
        "exposure_summary": exposure_summary,
    }

    # ── Verify before anything consumes the findings ──────────────────
    # The audit's own matcher settles most candidates, but not all, and
    # until this ran here the unsettled ones were only filtered when the
    # PDF was rendered — after the severity summary, the asset sync and
    # the dashboard counts had already been computed from them.
    verification = verify_credentialed_report(stored_report)
    cve_list = verification.verified
    severity_counts = {
        tier: verification.severity_counts.get(tier, 0)
        for tier in ("Critical", "High", "Medium", "Low")
    }
    severity_counts["Info"] = verification.severity_counts.get(
        "None", 0
    ) + verification.severity_counts.get("Unscored", 0)
    stored_report.update(
        {
            "cves": cve_list,
            "cve_count": len(cve_list),
            "severity_summary": severity_counts,
            "suppressed_cves": [
                {
                    "identifier": item.identifier,
                    "host": item.host,
                    "reason": item.reason,
                }
                for item in verification.suppressed
            ],
            "candidates_evaluated": verification.evaluated,
        }
    )

    return stored_report, system_data, os_type


def audit_database_target(
    *,
    host: str,
    engine: str,
    username: str,
    password: str | None = None,
    port: int | None = None,
    database: str | None = None,
    timeout: int = 20,
    emit=None,
    credential_options: dict | None = None,
    config_checks: list | None = None,
    policy=None,
) -> tuple[dict, dict, str]:
    """
    Run the authenticated configuration audit against one database instance.

    The database counterpart of :func:`audit_credentialed_host`, and
    deliberately a sibling of it rather than a branch inside it. That function
    is host-shaped from end to end — detect the operating system, enumerate
    packages, resolve listeners, match packages against advisories — and a
    database instance has none of those. Threading a second meaning through it
    would leave every one of those steps guarded by ``if not database``.

    What it *does* share is everything downstream: the Phase 3 engine, the
    ``AbsencePolicy`` semantics, the evidence record, the ``CCURE-CFG-``
    identifier, and the ``cves`` list every report generator already reads. So
    a failing database check reaches the executive PDF, the risk score and the
    findings queue through exactly the path a failing Windows registry check
    does, with no second finding model behind it.

    Returns ``(stored_report, system_data, "database")``, matching the arity of
    ``audit_credentialed_host`` so the scan task's per-target loop keeps one
    shape.
    """
    from core.checks.contract import CheckOutcome
    from core.checks.definitions import DEFINITION_TYPE_CONFIG_CHECK
    from core.config_audit import CollectionContext, ConfigAuditEngine, select_checks
    from core.config_audit.builtin import builtin_checks
    from core.config_audit.collectors import register_builtin_collectors
    from core.config_audit.findings import config_definition_id
    from engines.credentialed.database_executor import (
        DEFAULT_PORTS,
        DatabaseSession,
        normalize_engine,
    )

    register_builtin_collectors()

    resolved_engine = normalize_engine(engine)
    if not resolved_engine:
        raise ValueError(f"database engine {engine!r} is not one this build can assess")

    options = dict(credential_options or {})
    started = time.time()

    def _emit(message, percentage=0, stage=None):
        if emit:
            emit("running", message, percentage, stage)

    resolved_port = int(port or DEFAULT_PORTS[resolved_engine])
    target = f"{host}:{resolved_port}"
    _emit(f"Connecting to {resolved_engine} at {target}...", 10, "connecting")

    connect_started = time.perf_counter()
    session = DatabaseSession(
        engine=resolved_engine,
        host=host,
        username=username,
        password=password,
        port=resolved_port,
        database=database or options.get("database"),
        timeout=timeout,
        use_tls=options.get("use_tls"),
        verify_cert=bool(options.get("verify_cert", False)),
        ca_cert=options.get("ca_cert"),
    )

    with session as db_session:
        response_ms = int(round((time.perf_counter() - connect_started) * 1000))
        product = db_session.product_name
        version = db_session.server_version
        tls_in_use = db_session.tls_in_use
        _emit(f"Authenticated to {product or resolved_engine}", 25, "detection")

        # The instance's own product string and version become os_name and
        # os_version_id, so the Phase 4 targeting written for "Ubuntu 22.04
        # versus RHEL 9" applies unchanged to "PostgreSQL 16 versus MySQL 8".
        # There is deliberately no second targeting mechanism.
        # GAP-12: the policy narrows the candidate set before the engine sees
        # it, never widens it. `policy is None` is the pre-policy path and is
        # byte-identical to what it was.
        _families = list(getattr(policy, "check_families", ()) or ()) if policy else []
        _builtin = builtin_checks()
        if policy is not None:
            from core.scan_policy.spec import severity_at_least

            _excluded = {
                str(c) for c in (getattr(policy, "excluded_check_ids", ()) or ())
            }
            _excluded_tags = {
                str(t).lower() for t in (getattr(policy, "excluded_tags", ()) or ())
            }
            _floor = getattr(policy, "min_severity", None)
            if not getattr(policy, "include_builtin_checks", True):
                _builtin = []
            else:
                _builtin = [
                    c
                    for c in _builtin
                    if c.check_id not in _excluded
                    and not (_excluded_tags & {t.lower() for t in c.tags})
                    and severity_at_least(c.severity, _floor)
                ]
        checks = select_checks(
            [*_builtin, *(config_checks or [])],
            platform="database",
            domains=_families or None,
        )
        _emit(f"Assessing {len(checks)} configuration checks...", 40, "configuration")

        context = CollectionContext(
            target=target,
            platform="database",
            os_name=product,
            os_version_id=version,
            executor=db_session,
            timeout=max(timeout, 30),
        )
        report = ConfigAuditEngine().run(checks, context)

    cve_list: list[dict] = []
    for result in report.results:
        if result.outcome is not CheckOutcome.FAIL:
            continue
        observation = result.evidence[0] if result.evidence else None
        finding_type = str(
            result.metadata.get("finding_type") or DEFINITION_TYPE_CONFIG_CHECK
        )
        definition_id = config_definition_id(result.check_id, finding_type)
        cve_list.append(
            {
                "cve_id": definition_id,
                "cve": definition_id,
                "definition_type": finding_type,
                "title": result.title,
                "severity": result.severity.capitalize(),
                "description": result.title,
                "desc": result.title,
                "detection_method": "config_check",
                "confidence": "Confirmed",
                "qod": result.qod,
                "remediation": result.remediation or "",
                "evidence": (
                    (
                        f"Expected: {observation.expected}\n"
                        f"Observed: {observation.observed}"
                        # The reading that makes the finding actionable. For
                        # a SCAP rule `observed` is only the verdict word —
                        # "non_compliant" — while `raw` names the OVAL object
                        # and the existence check it failed, e.g.
                        # "windows:registry_object: 0 item(s) collected,
                        # which does not satisfy at_least_one_exists".
                        # Without it a reader has to re-run the scan by hand
                        # to learn what was actually wrong.
                        + (
                            f"\n{_unique_lines(observation.raw)}"
                            if observation.raw
                            else ""
                        )
                    )
                    if observation
                    else ""
                ),
                "expected_state": observation.expected if observation else "",
                "observed_state": observation.observed if observation else "",
                "package": "",
                "installed_ver": "",
                "fixed_ver": "",
                "source": "database_audit",
                "host": target,
            }
        )

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in cve_list:
        tier = str(finding.get("severity") or "").capitalize()
        if tier not in severity_counts:
            tier = "Info"
        severity_counts[tier] += 1

    counts = report.counts
    config_summary = {
        "assessed": True,
        "platform": "database",
        "engine": resolved_engine,
        "counts": counts,
        "verdicts": len(report.assessed),
        "compliance_score": report.compliance_score(),
        "results": [r.as_dict() for r in report.results],
    }

    system_data = {
        "detected_os": "database",
        "db_engine": resolved_engine,
        "db_product": product,
        "db_version": version,
        "credentialed_response_time_ms": response_ms,
        "config_audit": config_summary,
    }

    stored_report = {
        "scan_type": "database",
        "target": target,
        "username": username,
        "detected_os": "database",
        "system_info": {
            "os_name": product,
            "os_family": "database",
            "os_version_id": version,
            "hostname": host,
            "credentialed_response_time_ms": response_ms,
        },
        "database": {
            "engine": resolved_engine,
            "product": product,
            "version": version,
            "host": host,
            "port": resolved_port,
            # Whether *this* session was encrypted. None where the instance
            # could not be asked, which is not the same as plaintext and is
            # deliberately not rendered as one.
            "tls_in_use": tls_in_use,
        },
        "packages": [],
        "package_count": 0,
        "config_audit": config_summary,
        "cves": cve_list,
        "cve_count": len(cve_list),
        "severity_summary": severity_counts,
        "scan_duration": round(time.time() - started, 2),
        # A database audit examines the instance's own configuration. It says
        # nothing about the operating system underneath it, the packages
        # installed there, or what else that host exposes — and a report which
        # does not say so reads as a complete audit of the machine.
        "coverage": {
            "credentialed": True,
            "network_scanned": False,
            "packages_assessed": False,
            "scope": (
                f"{resolved_engine} instance configuration only; the host "
                f"operating system was not assessed"
            ),
        },
        "checks_total": len(report.results),
        "checks_assessed": len(report.assessed),
        "checks_errored": counts.get("error", 0),
        "checks_not_applicable": counts.get("not_applicable", 0),
    }

    _emit(f"Database audit complete - {len(cve_list)} finding(s)", 90, "analysis")
    return stored_report, system_data, "database"


def _classify_credentialed_failure(reason: str) -> str:
    """Whether a failed host was unreachable or failed for another reason."""
    lowered = reason.lower()
    if any(
        msg in lowered
        for msg in ["reach", "timeout", "no route", "connection refused", "down"]
    ):
        return "unreachable"
    return "failed"


def _is_transport_failure(exc: Exception) -> bool:
    """
    Did nothing answer, as opposed to something answering and saying no?

    The distinction decides whether another port may be tried. A refused
    password means the credential reached a listener and was rejected, so
    repeating it elsewhere adds failed-logon events against an account this
    product must not lock out; nothing listening means the endpoint was wrong
    and resolution is exactly the right response.

    WinRM is settled by type, because its executor already separates the four
    cases. SSH raises ``RuntimeError`` with a message, so it is settled by the
    same classifier the scan record uses — one vocabulary, not two.
    """
    try:
        from engines.credentialed.winrm_executor import (
            WinRMAuthenticationError,
            WinRMConnectionError,
        )

        if isinstance(exc, WinRMAuthenticationError):
            return False
        if isinstance(exc, WinRMConnectionError):
            return True
    except ImportError:  # pragma: no cover - pywinrm is optional
        pass

    reason = str(exc).lower()
    if "authentication failed" in reason or "credentials were rejected" in reason:
        return False
    if "ssh connection error" in reason:
        return True
    return _classify_credentialed_failure(reason) == "unreachable"


def _audit_host_over_transport(**kwargs):
    """
    Audit one host, resolving the endpoint — and where asked, the transport.

    The stated port is attempted directly, so a scan against a conventionally
    configured host costs exactly what it always did — no probe, one
    authentication attempt. Resolution engages only after a *transport* failure,
    and then selects by TCP reachability, so the second attempt is made against
    a port something is actually listening on.

    **A rejected credential is never retried on another port or transport.**
    That would turn one failed logon into three against the same account, which
    is the lockout this product documents as a control it must not trip. Only a
    transport failure — nothing answered — advances, which is what
    ``_is_transport_failure`` decides.

    ``discover_transport`` is the Nessus-shaped entry point: the caller supplies
    a credential and no port, and the engine establishes which authentication
    service the host actually offers. It is opt-in rather than the default for
    a stored credential, because ``compliance_credentials.transport`` is NOT
    NULL and an operator who deliberately chose SMB — on a host where WinRM is
    listening but misconfigured — would otherwise have that choice silently
    overridden by a probe that only knows which ports are open.

    Either way the resolved mechanism is recorded in
    ``kwargs["access"]["resolved"]`` for the caller to put in the scan record,
    because "which service accepted this credential" is an answer the operator
    needs and could not previously get.
    """
    ip = kwargs["ip"]
    transport = (kwargs.get("transport") or "ssh").strip().lower()
    stated_port = kwargs.get("port")
    discover = bool(kwargs.pop("discover_transport", False))
    record = kwargs.pop("access", None)

    def _remember(resolution, how):
        if record is None or resolution is None:
            return
        payload = resolution.as_dict()
        payload["how"] = how
        record["resolved"] = payload

    if discover:
        # Reachability only. No credential is presented here, so an unreachable
        # host costs a connect timeout rather than a failed logon.
        try:
            access = resolve_access(
                ip=ip,
                credential_type=kwargs.get("credential_type") or "auto",
                prefer=kwargs.get("stated_transport"),
                stated_port=stated_port,
                use_tls=(kwargs.get("credential_options") or {}).get("use_tls"),
                open_ports=kwargs.get("open_ports"),
                include_fallbacks=True,
            )
        except Exception:  # noqa: BLE001 — discovery must never be the error
            log.debug("Transport discovery for %s failed", ip, exc_info=True)
            access = None
        if access is not None and access.resolved:
            transport = access.transport
            kwargs["transport"] = transport
            kwargs["port"] = access.endpoint.port
            if access.endpoint.use_tls is not None:
                options = dict(kwargs.get("credential_options") or {})
                options["use_tls"] = access.endpoint.use_tls
                kwargs["credential_options"] = options
            stated_port = kwargs["port"]
            _remember(access, "discovered")
            log.info("Credentialed scan: %s — %s", ip, access.describe())
        elif access is not None:
            # Nothing was listening for any transport this build supports. Say
            # so rather than falling through to an attempt that can only fail
            # with a less useful message.
            _remember(access, "unresolved")
            raise ConnectionError(access.reason)

    kwargs.pop("credential_type", None)
    kwargs.pop("stated_transport", None)
    kwargs.pop("open_ports", None)

    try:
        return audit_credentialed_host(**kwargs)
    except Exception as first_exc:  # noqa: BLE001 — re-raised unless resolvable
        if not _is_transport_failure(first_exc):
            raise
        options = dict(kwargs.get("credential_options") or {})
        # Resolution is a best-effort second look, so it must never become the
        # error the operator sees. A fault in here would otherwise replace
        # "Cannot reach 10.0.0.6:22 — host is down" with something about the
        # resolver, and the scan record's unreachable/failed distinction — which
        # drives different UI — would be decided by the wrong exception.
        try:
            resolution = resolve_endpoint(
                ip=ip,
                transport=transport,
                stated_port=None,
                use_tls=options.get("use_tls"),
                include_fallbacks=True,
                exclude_ports=[stated_port] if stated_port else None,
            )
        except Exception:  # noqa: BLE001 — the original failure is the answer
            log.debug("Endpoint resolution for %s failed", ip, exc_info=True)
            raise first_exc from None
        if not resolution.resolved:
            raise
        endpoint = resolution.endpoint
        if endpoint.use_tls is not None:
            options["use_tls"] = endpoint.use_tls
        log.info(
            "Credentialed scan: %s did not answer on port %s; retrying on %s "
            "over %s — %s",
            ip,
            stated_port,
            endpoint.port,
            transport.upper(),
            endpoint.evidence,
        )
        retry = dict(kwargs)
        retry["port"] = endpoint.port
        retry["credential_options"] = options
        return audit_credentialed_host(**retry)


@celery_app.task(
    name=task_names.RUN_CREDENTIALED_SCAN,
    queue="scanner",
    soft_time_limit=AppConfig.SCAN_TIME_LIMIT_CREDENTIALED,
    time_limit=AppConfig.SCAN_TIME_LIMIT_CREDENTIALED
    + AppConfig.SCAN_TIME_LIMIT_HARD_MARGIN,
)
def run_credentialed_scan_task(
    user_id: str,
    ip: str | None = None,
    username: str | None = None,
    password: str | None = None,
    key_path: str | None = None,
    port: int | None = None,
    auth_method: str = "password",
    sections: list[str] | None = None,
    os_type_req: str = "auto",
    scan_id: str | None = None,
    credential_id: str | None = None,
    targets: list[str] | None = None,
    discover_transport: bool | None = None,
):
    """
    Credentialed Scan Task — authenticated audit of one or more hosts.

    ``ip`` is retained so a task already queued by an older release still runs;
    ``targets`` is what the router sends now. One scan covers every target,
    matching how the Vulnerability Audit pipeline reports many hosts under a
    single scan record rather than fragmenting them across several.

    A host that cannot be reached does not abandon the others. The scan fails
    only when no host could be audited at all, which keeps the single-target
    case — where that is the same thing — behaving exactly as before.
    """
    from core.redis_client import publish_progress_sync

    host_list = [t for t in (targets or []) if t] or ([ip] if ip else [])
    if not host_list:
        raise ValueError("No target supplied for credentialed scan.")

    db = SessionLocal()
    start_time = time.time()
    current_target = {"ip": host_list[0]}

    # Benchmark content this organisation has installed, resolved once for the
    # whole scan rather than per host — the same query per target would repeat
    # work and could disagree between hosts if content were loaded mid-scan.
    # Resolved here because `audit_credentialed_host` deliberately opens no
    # database session: it runs on the host worker while a WinRM connection is
    # held open, and a round trip inside that window is a round trip too many.
    #
    # GAP-12: read the scan's effective policy from its own row — the record
    # written before dispatch — so the worker, the report and the comparison
    # all read one source. A scan with no snapshot (an older release's task
    # still in the queue, or a caller that named no policy) resolves everything
    # installed, which is the pre-policy behaviour unchanged.
    from core.scan_policy import read_policy_snapshot

    _scan_row = db.query(Scan).filter(Scan.id == scan_id).first() if scan_id else None
    policy = read_policy_snapshot(_scan_row)
    benchmark_checks: list = []
    _scan_owner = platform_api.user(db, user_id)
    if _scan_owner is not None:
        from core.benchmarks.selection import benchmark_checks_for_org

        benchmark_checks = benchmark_checks_for_org(
            db,
            str(_scan_owner.org_id),
            profile=getattr(policy, "benchmark_profile", None),
            platforms=list(getattr(policy, "platforms", ()) or ()) or None,
            framework_ids=list(getattr(policy, "framework_ids", ()) or ()) or None,
            min_severity=getattr(policy, "min_severity", None),
            excluded_check_ids=list(getattr(policy, "excluded_check_ids", ()) or ())
            or None,
            excluded_tags=list(getattr(policy, "excluded_tags", ()) or ()) or None,
        )

    def emit(status, message, percentage=0, stage=None):
        if not scan_id:
            return
        publish_progress_sync(
            scan_id,
            5,
            {
                "status": status,
                "message": message,
                "percentage": percentage,
                "stage": stage,
                "target": current_target["ip"],
                "hosts_total": len(host_list),
                "timestamp": utcnow().isoformat(),
            },
        )

    try:
        key_content = None
        key_passphrase = None
        nt_hash = None
        # Defaults for the direct-material path (a request that supplied a
        # username and password rather than naming a stored credential). SSH
        # keeps its existing behaviour: nothing about the ad-hoc path changes.
        transport = "ssh"
        domain = None
        credential_type = CREDENTIAL_TYPE_SSH
        credential_options: dict = {}
        if credential_id:
            # A stored credential supersedes anything the request supplied.
            # Which of password/key is set is what selects the auth method —
            # the stored record's own `auth_method` already decided that when
            # it was decrypted, so nothing here needs to read it again.
            material = _resolve_stored_credential(db, scan_id, credential_id)
            username = material["username"]
            port = material["port"]
            password = material["password"]
            key_content = material["key_content"]
            key_passphrase = material["key_passphrase"]
            nt_hash = material["nt_hash"]
            # A stored credential also decides *how* to reach the host. Without
            # this the transport stayed "ssh" for every credential, so a
            # Windows credential on port 5985 attempted SSH against a WinRM
            # listener and failed as a connection error.
            transport = material.get("transport") or "ssh"
            auth_method = material.get("auth_method") or auth_method
            domain = material.get("domain")
            credential_options = material.get("options") or {}
            # What *kind* of target this credential is for. Without it a
            # database credential would be handed to the host auditor, which
            # would open an SSH connection to a database port and report the
            # instance as unreachable.
            credential_type = material.get("credential_type") or CREDENTIAL_TYPE_SSH

        # Which authentication service to use is the engine's job unless the
        # caller pinned a port. `None` means "decide": discovery runs exactly
        # when no port was stated, which is what the UI now sends by default.
        #
        # The credential's own transport becomes a *preference*, not a pin --
        # `compliance_credentials.transport` is NOT NULL, so it cannot express
        # "I do not mind", and reading it as a decision would override an
        # operator who never made one. See resolve_access.
        stated_transport = transport
        # `None` means "no opinion", and the task's answer to that is **no
        # discovery** -- deliberately, because this task is also reached from
        # the schedule dispatcher and the main pipeline, and turning a TCP
        # probe on for every one of their callers is not a change this feature
        # asked for. The HTTP route decides the question there, where "the
        # operator stated no port" is still knowable; by the time it reaches
        # here `port` has already fallen back to the stored credential's.
        discover_transport = bool(discover_transport) and (
            credential_type != CREDENTIAL_TYPE_DATABASE
        )

        reports: list[dict] = []
        collected: list[tuple[dict, dict, str]] = []
        failed_hosts: list[dict] = []

        for index, host_ip in enumerate(host_list):
            current_target["ip"] = host_ip
            # Progress is reported across the whole target list so a 40-host
            # scan does not appear to restart at 10% on every host.
            span = 90.0 / len(host_list)
            base = index * span

            def host_emit(
                status, message, percentage=0, stage=None, _base=base, _span=span
            ):
                emit(status, message, int(_base + (percentage / 100.0) * _span), stage)

            try:
                if credential_type == CREDENTIAL_TYPE_DATABASE:
                    # A database credential names an instance, not a host, and
                    # `transport` carries which engine it speaks. Dispatched to
                    # the sibling auditor rather than through a flag on the
                    # host one — see audit_database_target for why.
                    stored_report, system_data, os_type = audit_database_target(
                        host=host_ip,
                        engine=transport,
                        username=username,
                        password=password,
                        port=port,
                        emit=host_emit,
                        credential_options=credential_options,
                        config_checks=benchmark_checks,
                        policy=policy,
                    )
                else:
                    # Where the caller stated no port, the engine establishes
                    # which authentication service the host actually offers
                    # rather than making the operator know. `access_record` is
                    # filled in by the resolver and reported below, because
                    # "credentialed access succeeded" is not a useful answer on
                    # its own -- the operator needs to know *what* accepted it.
                    access_record: dict = {}
                    stored_report, system_data, os_type = _audit_host_over_transport(
                        config_checks=benchmark_checks,
                        policy=policy,
                        ip=host_ip,
                        username=username,
                        password=password,
                        key_path=key_path,
                        key_content=key_content,
                        key_passphrase=key_passphrase,
                        nt_hash=nt_hash,
                        port=port,
                        sections=sections,
                        os_type_req=os_type_req,
                        emit=host_emit,
                        transport=transport,
                        auth_method=auth_method,
                        domain=domain,
                        credential_options=credential_options,
                        discover_transport=discover_transport,
                        credential_type=credential_type,
                        stated_transport=stated_transport,
                        access=access_record,
                    )
                    if access_record.get("resolved"):
                        stored_report["access"] = access_record["resolved"]
                # A single embedded NUL in any collected string (a UTF-16LE
                # registry or version-resource value) makes the final
                # `scans.options` commit unstorable and loses every finding.
                stored_report = _strip_nul(stored_report)
                system_data = _strip_nul(system_data)
                reports.append(stored_report)
                collected.append((stored_report, system_data, os_type))
            except Exception as host_exc:  # noqa: BLE001 — recorded, not swallowed
                reason = str(host_exc)
                status = _classify_credentialed_failure(reason)
                if status == "unreachable" or "authentication failed" in reason.lower():
                    log.error("Credentialed audit of %s failed: %s", host_ip, reason)
                else:
                    log.exception("Credentialed audit of %s failed", host_ip)
                failed_hosts.append(
                    {"target": host_ip, "status": status, "reason": reason}
                )

        # Every host failed — for a single target this is the same outcome the
        # task has always produced, with the same reason and status.
        if not reports:
            reason = (
                failed_hosts[0]["reason"]
                if failed_hosts
                else "No host could be audited"
            )
            status = failed_hosts[0]["status"] if failed_hosts else "failed"
            emit(status, f"Scan {status}: {reason}", 0, "error")
            if scan_id:
                _settle_failure(db, scan_id, user_id, reason, status=status)
            db.rollback()
            return {"success": False, "error": reason}

        scan_duration = round(time.time() - start_time, 2)
        target_str = ", ".join(host_list)

        totals = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        total_cves = 0
        candidates_evaluated = 0
        for report in reports:
            for tier, count in (report.get("severity_summary") or {}).items():
                totals[tier] = totals.get(tier, 0) + count
            total_cves += report.get("cve_count", 0)
            candidates_evaluated += report.get("candidates_evaluated", 0) or 0

        primary = reports[0]
        coverage = dict(primary.get("coverage") or {})

        # `report` stays the first host so every existing consumer — the results
        # page, the PDF text-recovery fallback — keeps working unchanged;
        # `reports` is the complete set.
        results_payload = {
            "credentialed": {
                "report": primary,
                "reports": reports,
                "data": [{"ip_address": r["target"]} for r in reports],
                "hosts_audited": len(reports),
                "hosts_failed": failed_hosts,
                "targets": host_list,
            }
        }

        summary = {
            "scan_type": "credentialed",
            "cve_count": total_cves,
            "scan_duration": scan_duration,
            "critical_count": totals["Critical"],
            "high_count": totals["High"],
            "medium_count": totals["Medium"],
            "low_count": totals["Low"],
            "info_count": totals["Info"],
            "total_vulns": total_cves,
            "total_hosts": len(host_list),
            "active_hosts": len(reports),
            "hosts_failed": len(failed_hosts),
            "candidates_evaluated": candidates_evaluated,
            **coverage,
        }

        report_result = {
            "success": True,
            "data": results_payload,
            "summary": summary,
            "metadata": {
                "target": target_str,
                "original_targets": host_list,
                "scan_type": "credentialed",
                "is_credentialed": True,
                **coverage,
            },
        }
        # The report is generated *after* the findings are synced, further down.
        # It used to be built here, before a single finding had been written,
        # which is why it could not carry a comparison against the previous
        # scan: at this point the current scan's findings do not yet exist to
        # be compared. The scan row is created first with no report paths and
        # they are set once the files exist, all inside the same transaction.
        scan = create_completed_scan(
            db=db,
            user_id=user_id,
            target=target_str,
            targets=host_list,
            scan_type="credentialed",
            phase=3,
            results=results_payload,
            summary=summary,
            scan_duration=scan_duration,
            # Without this the helper's default silently relabelled the scan as
            # a vulnerability_audit — a pipeline none of whose phases ran.
            pipeline_mode="credentialed",
            report_executive_path=None,
            report_technical_path=None,
            scan_id=scan_id,
            commit=False,  # ENTERPRISE FIX: Do not commit yet
        )

        # Sync to Asset Registry within the same transaction.
        #
        # Database targets are deliberately excluded. Both helpers below are
        # host-shaped: they write an operating system, a package inventory,
        # listener correlation and a MAC-based identity onto an Asset row. A
        # database instance has none of those, and letting it through would
        # overwrite the asset record of the machine hosting it with an audit
        # that never looked at the machine — turning a correctly inventoried
        # server into one reporting no packages and an OS of "database".
        for stored_report, system_data, os_type in collected:
            if os_type == "database":
                continue
            _sync_credentialed_asset_identity(
                db,
                user_id=user_id,
                ip=stored_report["target"],
                scan_id=str(scan.id),
                os_type=os_type,
                system_data=system_data,
                stored_report=stored_report,
                cve_list=stored_report.get("cves") or [],
                severity_counts=stored_report.get("severity_summary") or {},
            )
            _sync_configuration_compliance(
                db,
                org_id=str(scan.org_id),
                ip=stored_report["target"],
                system_data=system_data,
                scan_id=str(scan.id),
                policy=policy,
            )

        # ── Remediation SLA (GAP-14) ────────────────────────────────────
        # Due dates are materialised on the finding rather than computed on
        # read, because "everything overdue in this organisation" is a WHERE
        # clause over thousands of rows and deriving it per row is the N+1
        # this column exists to avoid. Recomputed here so a finding whose
        # severity was re-rated, or whose organisation changed its policy,
        # picks up the new deadline on the next scan.
        #
        # `apply_sla` is idempotent and writes an event only when the deadline
        # actually moves, so a scan that changes nothing adds no history.
        try:
            from core.remediation import apply_sla, sla_policy_for_org_id

            # One lookup for the scan's organisation; with no org on the scan,
            # each finding's own organisation is looked up, as before.
            _sla_policy = (
                sla_policy_for_org_id(db, scan.org_id) if scan.org_id else None
            )
            _sla_rows = (
                db.query(AssetVulnerability)
                .filter(
                    AssetVulnerability.org_id == scan.org_id,
                    AssetVulnerability.scan_id == scan.id,
                )
                .all()
            )
            for _finding in _sla_rows:
                apply_sla(db, _finding, policy=_sla_policy)
            if _sla_rows:
                log.info(
                    "Scan %s: remediation SLA applied to %d finding(s)",
                    scan.id,
                    len(_sla_rows),
                )
        except Exception as sla_exc:  # noqa: BLE001
            log.warning(
                "Could not apply remediation SLA for scan %s: %s",
                scan.id,
                sla_exc,
                exc_info=True,
            )

        # ── Assessment policy (GAP-12) ──────────────────────────────────
        # Read back from the scan's own snapshot rather than from the `policy`
        # local, so the report shows what is *recorded* against the scan. If
        # those two ever disagree the record is the one an auditor will read,
        # and a report that showed the other would be describing a scan that
        # does not exist.
        try:
            from core.findings.comparison import policy_context

            _policy_ctx = policy_context(scan)
            if _policy_ctx.get("recorded"):
                report_result.setdefault("metadata", {})["scan_policy"] = _policy_ctx
                summary["scan_policy"] = _policy_ctx
        except Exception as pol_exc:  # noqa: BLE001
            log.warning(
                "Could not attach the policy record to the report for %s: %s",
                scan.id,
                pol_exc,
            )

        # ── Change since the previous scan ──────────────────────────────
        # Computed here because the findings this scan wrote have to exist
        # before they can be compared, and flushed first so the comparison
        # reads them. A failure here costs the delta section and nothing else:
        # the report is still generated, without it.
        try:
            db.flush()
            from core.findings import compare_scans
            from core.findings.comparison import previous_scan_for

            _baseline = previous_scan_for(db, scan)
            if _baseline is not None:
                _comparison = compare_scans(
                    db, current=scan, baseline=_baseline, limit_findings=200
                )
                report_result["scan_comparison"] = _comparison.as_dict()
                summary["scan_comparison"] = _comparison.as_dict(include_findings=False)
                log.info(
                    "Scan %s vs baseline %s: %s",
                    scan.id,
                    _baseline.id,
                    _comparison.summary_line(),
                )

                # ── Remediation verification (GAP-14) ───────────────────
                # The one path by which a remediation becomes *verified
                # fixed*, and it consumes the comparison above rather than
                # deciding for itself. A finding classified NOT_ASSESSED —
                # open at the baseline and not looked at by this scan —
                # cannot verify anything, which is the whole reason GAP-13
                # introduced that class.
                #
                # A comparison computed with `limit_findings=200` would
                # verify only the first 200 rows, so this recomputes
                # unbounded. The report's copy stays bounded: a report is a
                # sample, a verification pass must not be.
                try:
                    from core.remediation import verify_from_comparison

                    _full = compare_scans(
                        db, current=scan, baseline=_baseline, limit_findings=None
                    )
                    _verification = verify_from_comparison(
                        db,
                        _full,
                        scan_id=str(scan.id),
                        org_id=str(scan.org_id),
                    )
                    summary["remediation_verification"] = _verification.as_dict()
                    report_result["remediation_verification"] = _verification.as_dict()

                    # The remediation payload the report renders. Built from
                    # the same aggregates the summary API runs, so a report
                    # and a dashboard cannot disagree about how many findings
                    # are overdue.
                    from core.remediation import remediation_report_payload

                    _rem_payload = remediation_report_payload(
                        db,
                        org_id=str(scan.org_id),
                        verification=_verification.as_dict(),
                    )
                    if _rem_payload:
                        report_result.setdefault("metadata", {})[
                            "remediation"
                        ] = _rem_payload
                        summary["remediation"] = {
                            k: v for k, v in _rem_payload.items() if k != "findings"
                        }
                    log.info(
                        "Scan %s remediation: %s",
                        scan.id,
                        _verification.summary_line(),
                    )
                except Exception as ver_exc:  # noqa: BLE001
                    # A verification failure must not cost the scan its
                    # findings. Recorded rather than swallowed: a remediation
                    # that silently stopped being verified would look exactly
                    # like an estate where nobody fixes anything.
                    log.warning(
                        "Remediation verification failed for scan %s: %s",
                        scan.id,
                        ver_exc,
                        exc_info=True,
                    )
        except Exception as cmp_exc:
            log.warning(
                "Could not compute the scan comparison for %s: %s", scan.id, cmp_exc
            )

        orch = _new_orchestrator()
        # The scan row exists by now; the report names it ("Scan reference").
        report_result.setdefault("metadata", {}).update(
            {"scan_no": getattr(scan, "scan_no", None), "scan_id": str(scan.id)}
        )
        report_paths = orch.generate_phase_report(report_result, "credentialed_scan")
        scan.report_executive_path = report_paths.get("executive_pdf")
        scan.report_technical_path = report_paths.get("technical_pdf")
        # Stamped *after* the findings are written, not before.
        #
        # `create_completed_scan` sets this when the scan row is built, which is
        # before the sync runs — so every finding a scan produced carried a
        # `first_found_at` a second or two *later* than the scan's own
        # `completed_at`. Measured on a real target: baseline completed 18:48:44,
        # its earliest finding first seen 18:48:45. A comparison anchored on that
        # boundary therefore judged every finding the baseline itself wrote to be
        # newer than the baseline, and reported 50 new / 0 unchanged on two scans
        # of an almost unchanged host.
        scan.completed_at = utcnow()
        # No `db.add`: `create_completed_scan` already put this instance in the
        # session, so assigning the attributes is enough. Re-adding also breaks
        # any caller that hands back a stand-in rather than a mapped instance,
        # which is what `test_an_unreachable_host_does_not_abandon_the_others`
        # does — and it failed the whole task, not just the bookkeeping.

        # Trigger AMT reconciliation now that the asset identity has been fully synced
        try:
            from core.amt_reconciliation import reconcile_amt_inventory

            reconcile_amt_inventory(db, str(scan.org_id))
        except Exception as amt_exc:
            log.warning(
                "Post-credentialed scan AMT reconciliation failed for org %s: %s",
                scan.org_id,
                amt_exc,
            )

        # ATOMIC COMMIT: Final persistence of everything
        db.commit()

        message = "Scan completed successfully."
        if failed_hosts:
            message = (
                f"Completed — {len(reports)} host(s) audited, "
                f"{len(failed_hosts)} unreachable."
            )
        emit("complete", message, 100, "complete")
        return {"success": True, "scan_id": str(scan.id)}
    except Exception as exc:
        db.rollback()  # Rollback everything if any step fails

        reason = str(exc)
        status = _classify_credentialed_failure(reason)

        # Suppress stack trace for expected network/credentials errors
        if (
            "ssh authentication failed" in reason.lower()
            or "cannot reach" in reason.lower()
            or "ssh connection error" in reason.lower()
        ):
            log.error(f"Credentialed Scan Task Failed: {reason}")
        else:
            log.exception("Credentialed Scan Task Failed")

        emit(status, f"Scan {status}: {reason}", 0, "error")
        if scan_id:
            _settle_failure(db, scan_id, user_id, reason, status=status)
        return {"success": False, "error": reason}
    finally:
        db.close()


# ── Outgoing mail ─────────────────────────────────────────────────────────────
#
# The mail tasks live in auth/mail_tasks.py. Re-exported so existing callers
# and patch targets (`core.tasks.send_*_task`) keep resolving to the same
# task objects.
from auth.mail_tasks import (  # noqa: E402,F401
    send_account_approved_email_task,
    send_mfa_otp_task,
    send_password_changed_email_task,
    send_password_reset_email_task,
    send_verification_email_task,
)


@celery_app.task(name="ccure.tasks.expire_risk_acceptances", queue="default")
def expire_risk_acceptances() -> dict:
    """
    Return findings whose risk acceptance has run out to the remediation queue.

    GAP-14. An acceptance with an expiry is a decision with a shelf life: when
    it lapses the finding is outstanding again, and it goes back to
    ``assigned`` if it still has an owner or ``open`` if it does not. Not to
    ``verified_fixed`` and not to an "expired" state of its own — the finding
    is simply un-dealt-with, and the remediation queue is where un-dealt-with
    findings belong.

    ``status`` returns to ``open`` alongside ``remediation_state``, so the
    dashboard and the asset risk score stop treating it as handled. Those two
    disagreeing is the confusion the two-column split exists to avoid.

    An acceptance with **no** expiry is untouched. That is a legitimate
    decision for a permanent compensating control, and expiring it because
    nobody set a date would silently overrule somebody's judgement.

    Every expiry writes a ``FindingRemediationEvent`` carrying the original
    reason and the date it lapsed, so the trail shows what the acceptance was
    for and that it ended on its own rather than being withdrawn.
    """
    from core.remediation import expire_due_exceptions

    db = SessionLocal()
    try:
        expired = expire_due_exceptions(db)
        db.commit()
        if expired:
            log.info("Expired %d risk acceptance(s)", expired)
        return {"success": True, "expired": expired}
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        # Recorded with its traceback rather than swallowed. A silently failing
        # expiry leaves lapsed acceptances suppressing findings indefinitely,
        # which looks exactly like an estate with nothing outstanding.
        log.exception("Risk-acceptance expiry failed")
        return {"success": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.reconcile_amt_inventory_task", queue="scanner")
def reconcile_amt_inventory_task(org_id: str) -> dict:
    """Async background task to run AMT reconciliation for an organization."""
    db = SessionLocal()
    try:
        from core.amt_reconciliation import reconcile_amt_inventory

        return reconcile_amt_inventory(db, org_id)
    except Exception as exc:
        log.exception(f"AMT Reconciliation background task failed for org {org_id}")
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.update_mac_vendor_registry", queue="default")
def update_mac_vendor_registry_task() -> dict:
    """
    Downloads the latest raw OUI manufacturer registry from Wireshark
    and updates the local manuf.txt file.
    """
    import requests
    from core.oui_lookup import get_oui_db

    url = "https://www.wireshark.org/download/automated/data/manuf"
    log.info("Starting MAC vendor registry update from %s", url)

    try:
        db_path = get_oui_db().db_path
        if not db_path:
            log.warning("OUI database path is not defined. Skipping registry update.")
            return {"success": False, "error": "No database path configured"}

        # 1. Fetch from URL with a reasonable timeout
        response = requests.get(url, timeout=30.0)
        if response.status_code != 200:
            log.warning(
                "Failed to fetch OUI registry. HTTP Status: %d", response.status_code
            )
            return {"success": False, "error": f"HTTP status {response.status_code}"}

        content = response.text

        # 2. Basic validation: ensure the file contains comments and some common MAC prefixes
        if not content.startswith("#") or "00:00:00" not in content:
            log.warning(
                "Fetched OUI registry failed validation checks. Update aborted."
            )
            return {"success": False, "error": "Invalid file format"}

        # 3. Write to a temporary file first to prevent corruption on write failure
        temp_path = db_path + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(content)

        # 4. Safely rename/overwrite target file
        if os.path.exists(db_path):
            os.remove(db_path)
        os.rename(temp_path, db_path)

        # 5. Reload the OUIDatabase mapping dict in memory
        get_oui_db()._loaded = False
        get_oui_db()._database.clear()
        get_oui_db()._load()

        log.info(
            "MAC vendor registry updated successfully. Loaded %d entries.",
            len(get_oui_db()._database),
        )
        return {"success": True, "entries": len(get_oui_db()._database)}

    except Exception as exc:
        log.exception("MAC vendor registry background update task failed")
        return {"success": False, "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# Scan scheduling (Phase 1 — Nessus capability gap closure)
# ─────────────────────────────────────────────────────────────────────────────

#: Advisory-lock key for the scheduler. Any 64-bit constant works; this one is
#: recorded here so a future lock does not collide with it by accident.
_SCAN_SCHEDULER_LOCK_KEY = 0x5CA45CED


@celery_app.task(name="ccure.tasks.run_due_scan_schedules", queue="scanner")
def run_due_scan_schedules() -> dict:
    """
    Dispatch every scan schedule whose next run has arrived.

    Runs on beat every minute. One minute is the resolution of the feature —
    a schedule set for 09:00 fires between 09:00 and 09:01 — and is cheap
    because the due query is one indexed lookup that returns nothing on almost
    every tick.

    **Duplicate execution is prevented by a transaction-scoped advisory lock,
    not by hope.** Exactly one beat process is supposed to run, but two is the
    classic operational mistake (CLAUDE.md records that this deployment had
    *zero* for a long time, which is the same class of error pointed the other
    way), and a Celery task can also be redelivered after a worker dies
    mid-execution. ``pg_try_advisory_xact_lock`` returns false rather than
    waiting, so a second concurrent tick exits immediately instead of queueing
    up behind the first and dispatching everything twice a minute later.

    Transaction-scoped, never session-scoped: ``pg_advisory_lock`` releases
    when the *connection* closes, and SQLAlchemy pools connections, so a
    session-scoped lock leaks onto the next unrelated request that draws the
    same connection. Same reasoning as ``core/audit_retention.py``.

    Each schedule is committed independently. One tenant's broken schedule must
    not roll back another tenant's successful dispatch.
    """
    from core.scheduling.dispatcher import due_schedules, dispatch_schedule
    from db.models.scan_schedules import RUN_STATUS_DISPATCHED

    db = SessionLocal()
    dispatched = 0
    failed = 0
    skipped = 0
    try:
        got_lock = db.execute(
            text("SELECT pg_try_advisory_xact_lock(:k)"),
            {"k": _SCAN_SCHEDULER_LOCK_KEY},
        ).scalar()
        if not got_lock:
            log.info(
                "run_due_scan_schedules: another scheduler tick holds the lock; "
                "skipping this one."
            )
            db.rollback()
            return {"success": True, "skipped_locked": True, "dispatched": 0}

        due = due_schedules(db)
        if not due:
            db.rollback()
            return {"success": True, "dispatched": 0, "due": 0}

        # The lock is transaction-scoped, so it is released by the first commit
        # below. That is acceptable and deliberate: its job is to stop two
        # ticks *starting* the same sweep, and by the time the first schedule
        # commits, `next_run_at` has already moved past due for it.
        for schedule in due:
            run = dispatch_schedule(db, schedule)
            db.commit()
            if run.status == RUN_STATUS_DISPATCHED:
                dispatched += 1
            elif run.status == "failed":
                failed += 1
            else:
                skipped += 1

        log.info(
            "Scan schedules: %d due, %d dispatched, %d failed, %d skipped.",
            len(due),
            dispatched,
            failed,
            skipped,
        )
        return {
            "success": True,
            "due": len(due),
            "dispatched": dispatched,
            "failed": failed,
            "skipped": skipped,
        }
    except Exception as exc:
        # Recorded with its traceback, not reduced to success:False with the
        # reason discarded — the failure mode that hid a TypeError on every
        # compliance beat tick for months.
        db.rollback()
        log.exception("run_due_scan_schedules failed")
        return {"success": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.reap_stalled_scans", queue="default")
def reap_stalled_scans() -> dict:
    """
    Settle scans that are still 'running' or 'queued' with nothing working on
    them, and tell whoever is watching why.

    This is the deployment's actual scan timeout. `task_time_limit` in
    `core/celery_app.py` reads like one and is not:

    * Celery's hard time limit is delivered by signalling a **billiard worker
      process**, so it does nothing under the `--pool=threads` worker this
      deployment runs on Windows.
    * Even where it does fire, it acts on a *running task*. It cannot settle a
      scan whose worker died, was restarted mid-scan, or — the case that
      produced this task — failed inside its own `except` handler and so never
      recorded an outcome at all.

    On 4 Sep 2026 a worker holding a stale `Scan` mapper raised
    `InvalidRequestError` on every scan task's first query, and again inside
    `mark_scan_failed`. Two scans against a host that was up the whole time sat
    in 'running' indefinitely, and the UI showed a live scan for both. Nothing
    in the system would ever have settled them.

    Deliberately conservative in three ways:

    * It only ever moves a scan **out of** a non-terminal state, through
      `force_terminal_status`, which no-ops on anything already settled. A
      real outcome written by a task always wins.
    * It writes plain SQL, so it still works when the fault that stranded the
      scan is the ORM itself.
    * A queued scan and a running scan get different deadlines and different
      messages, because "no scanner is running" and "the scan hung" send the
      operator to different places.
    """
    from datetime import timedelta, timezone

    from config import AppConfig
    from core.redis_client import publish_progress_sync
    from core.scan_control import force_terminal_status

    running_minutes = int(getattr(AppConfig, "SCAN_STALL_TIMEOUT_MINUTES", 90) or 0)
    queued_minutes = int(getattr(AppConfig, "SCAN_QUEUE_TIMEOUT_MINUTES", 15) or 0)
    if running_minutes <= 0 and queued_minutes <= 0:
        return {"success": True, "disabled": True, "reaped": 0}

    now = utcnow()
    reaped: list[dict] = []

    db = SessionLocal()
    try:
        # Read with plain SQL for the same reason the writer uses it: a mapper
        # failure is one of the conditions this task exists to clean up after,
        # and a reaper that cannot run during that failure is no reaper.
        rows = db.execute(
            text(
                """
                SELECT id, scan_no, status, started_at, queued_at, created_at
                  FROM scans
                 WHERE status IN ('running', 'queued', 'pending', 'cancelling')
                """
            )
        ).fetchall()
    except Exception as exc:
        log.exception("reap_stalled_scans could not list scans")
        return {"success": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        db.close()

    for scan_id, scan_no, status, started_at, queued_at, created_at in rows:
        is_running = (status or "").lower() in ("running", "cancelling")
        limit_minutes = running_minutes if is_running else queued_minutes
        if limit_minutes <= 0:
            continue

        # Fall back down the chain: a scan with no started_at never got that
        # far, and one with no timestamps at all is old enough to reap on any
        # reading.
        anchor = started_at if is_running else (queued_at or created_at)
        anchor = anchor or created_at or started_at
        if anchor is None:
            continue
        if anchor.tzinfo is None:
            anchor = anchor.replace(tzinfo=timezone.utc)

        age = now - anchor
        if age < timedelta(minutes=limit_minutes):
            continue

        minutes = int(age.total_seconds() // 60)
        if is_running:
            reason = (
                f"Scan timed out: no progress recorded for {minutes} minutes "
                f"(limit {limit_minutes}). The scanner task stopped responding "
                f"or the scanner worker is no longer running."
            )
        else:
            reason = (
                f"Scan was never picked up by a scanner worker after "
                f"{minutes} minutes (limit {limit_minutes}). Check that the "
                f"host scanner worker is running."
            )

        if not force_terminal_status(scan_id, status="failed", reason=reason):
            continue

        reaped.append({"scan_id": scan_id, "scan_no": scan_no, "reason": reason})

        # Push a terminal frame so a browser sitting on the live scan screen
        # stops showing a scan that is over. Without this the only thing that
        # ends that view is its own client-side timeout, which is the symptom
        # this task was written to remove.
        try:
            publish_progress_sync(
                scan_id, 1, {"status": "failed", "error": reason, "reason": reason}
            )
        except Exception:
            log.debug("Could not publish timeout for scan %s", scan_id, exc_info=True)

    if reaped:
        log.warning(
            "reap_stalled_scans settled %d stalled scan(s): %s",
            len(reaped),
            ", ".join(str(r["scan_no"]) for r in reaped),
        )
    return {"success": True, "reaped": len(reaped), "scans": reaped}


@celery_app.task(name="ccure.tasks.reap_stalled_web_scans", queue="default")
def reap_stalled_web_scans() -> dict:
    """
    Settle web-application scans stranded in a non-terminal state.

    The network reaper (`reap_stalled_scans`) only knows about the `scans`
    table; web scans live in `web_scans` with a four-phase lifecycle of their
    own, and until this task existed nothing settled one whose worker died, was
    restarted mid-phase, or failed inside its own `except` handler. Twelve web
    scans sat 'running'/'queued' for weeks because of that gap, each showing a
    live scan in the UI that would never end.

    Deliberately conservative, exactly like the network reaper:

    * It only ever moves a scan **out of** a non-terminal state, through
      `force_terminal_web_scan_status`, which no-ops on anything already
      settled — a real outcome written by a task always wins.
    * It reads and writes plain SQL, so it still works when the fault that
      stranded the scan is the ORM itself.
    * A queued scan and a running scan get different deadlines and different
      messages, because "no web-worker is running" and "a phase hung" send the
      operator to different places.

    The running-scan deadline is **per phase**, set just above each phase task's
    own Celery hard `time_limit`. So a scan is reaped only once the phase's task
    is genuinely gone (the hard limit SIGKILLs the worker process, which skips
    the task's `except` handler and orphans the row) — never while a phase is
    doing legitimate work inside its budget. A long DETECT running at 100
    minutes is within its 140-minute limit and is left alone.
    """
    from datetime import timedelta, timezone

    from config import WebScanConfig
    from core.scan_control import force_terminal_web_scan_status

    # Just above each phase task's hard `time_limit` (recon/audit 2400s,
    # crawl 4200s, detect 8400s), plus grace so the tick and the phase-start
    # stamp need not be perfectly aligned.
    grace = 10
    phase_limits = {
        "recon": 40 + grace,
        "crawl": 70 + grace,
        "detect": 140 + grace,
        "audit": 40 + grace,
    }
    queued_minutes = int(
        getattr(WebScanConfig, "WEB_SCAN_QUEUE_TIMEOUT_MINUTES", 15) or 0
    )
    # Global wall-clock cap (Phase 12). The in-task enforcement
    # (core/web/timeout.enforce_global_timeout) fires at exactly
    # WEB_SCAN_TIMEOUT from execution start; this reaper is the backstop for a
    # worker that has died and cannot self-enforce, so it waits a grace beyond
    # the cap before stepping in. 0 disables the global cap — the per-phase
    # deadlines above still apply.
    _web_timeout = int(getattr(WebScanConfig, "WEB_SCAN_TIMEOUT", 14400) or 0)
    overall_seconds = (_web_timeout + grace * 60) if _web_timeout > 0 else 0

    non_terminal = (
        "queued",
        "running",
        "pending",
        "recon",
        "crawl",
        "detect",
        "audit",
        "cancelling",
    )

    now = utcnow()
    reaped: list[dict] = []

    db = SessionLocal()
    try:
        rows = db.execute(
            text(
                """
                SELECT id, status, pipeline_phase, queued_at, created_at,
                       started_at, recon_started_at, crawl_started_at,
                       detect_started_at, audit_started_at, updated_at
                  FROM web_scans
                 WHERE status = ANY(:statuses)
                   AND is_deleted IS NOT TRUE
                """
            ),
            {"statuses": list(non_terminal)},
        ).fetchall()
    except Exception as exc:
        log.exception("reap_stalled_web_scans could not list web scans")
        return {"success": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        db.close()

    def _aware(dt):
        if dt is None:
            return None
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt

    for r in rows:
        (
            scan_id,
            status,
            phase,
            queued_at,
            created_at,
            started_at,
            recon_at,
            crawl_at,
            detect_at,
            audit_at,
            updated_at,
        ) = r
        status_l = (status or "").lower()
        phase = (phase or "queued").lower()

        # A scan that never left the queue: recon never stamped a start, so no
        # phase deadline applies — only the queue deadline does.
        never_started = phase in ("queued", "") or recon_at is None
        if never_started:
            if queued_minutes <= 0:
                continue
            anchor = _aware(queued_at) or _aware(created_at)
            limit_minutes = queued_minutes
            kind = "queued"
        else:
            phase_start = {
                "recon": recon_at,
                "crawl": crawl_at,
                "detect": detect_at,
                "audit": audit_at,
            }.get(phase)
            anchor = _aware(phase_start) or _aware(updated_at) or _aware(started_at)
            limit_minutes = phase_limits.get(phase, 140 + grace)
            kind = "running"

        if anchor is None:
            # No timestamp to reason from: fall back to the absolute backstop
            # against created_at, which every row has.
            anchor = _aware(created_at)
            if anchor is None:
                continue

        age = now - anchor
        over_phase = age >= timedelta(minutes=limit_minutes)

        # Independent global wall-clock backstop off the scan's own start.
        start_anchor = _aware(started_at) or _aware(created_at)
        over_overall = (
            overall_seconds > 0
            and start_anchor is not None
            and (now - start_anchor) >= timedelta(seconds=overall_seconds)
        )

        if not (over_phase or over_overall):
            continue

        minutes = int(age.total_seconds() // 60)
        if kind == "queued":
            reason = (
                f"Web scan was never picked up by a web-scanner worker after "
                f"{minutes} minutes (limit {limit_minutes}). Check that the "
                f"web-worker (queues web_recon,web_crawl,web_dast,web_audit) "
                f"is running."
            )
        elif over_overall and not over_phase:
            total_min = int((now - start_anchor).total_seconds() // 60)
            reason = (
                f"Web scan exceeded the global time limit "
                f"({overall_seconds // 60} min): running for {total_min} minutes "
                f"since it started. Settled by the watchdog because the worker "
                f"did not self-enforce the timeout (it may have died)."
            )
        else:
            reason = (
                f"Web scan timed out in the {phase.upper()} phase: no progress "
                f"for {minutes} minutes (limit {limit_minutes}). The phase task "
                f"stopped responding or the web-worker is no longer running."
            )

        if not force_terminal_web_scan_status(scan_id, status="failed", reason=reason):
            continue

        reaped.append({"web_scan_id": scan_id, "phase": phase, "reason": reason})

        # Push a terminal frame on the same Redis channel the web progress
        # WebSocket subscribes to, so a browser sitting on the live scan screen
        # stops showing a scan that is over.
        try:
            import json as _json

            from core.redis_client import get_redis_client

            get_redis_client().publish(
                f"scan_progress:{scan_id}",
                _json.dumps(
                    {
                        "scan_id": scan_id,
                        "scan_type": "web",
                        "phase": "failed",
                        "progress": {
                            "status": "failed",
                            "message": reason,
                            "error": reason,
                            "reason": reason,
                        },
                    }
                ),
            )
        except Exception:
            log.debug(
                "Could not publish timeout for web scan %s", scan_id, exc_info=True
            )

    if reaped:
        log.warning(
            "reap_stalled_web_scans settled %d stalled web scan(s): %s",
            len(reaped),
            ", ".join(r["web_scan_id"] for r in reaped),
        )
    return {"success": True, "reaped": len(reaped), "web_scans": reaped}
